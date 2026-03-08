mod bundle_runtime;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::crypto::{self, CryptoProvider};
use tracing::{info, warn};

use soth_proxy::{config::ProxyConfig, db, ProxyHandler};

const DISCOVERY_TLS_WILDCARD_DESTINATION: &str = "*:443";

#[tokio::main]
async fn main() -> Result<()> {
    init_rustls_provider();
    init_tracing();

    let config = ProxyConfig::from_env_or_default().context("load proxy config")?;
    let db_conn = db::open(config.db_path.as_path())?;
    let db = Arc::new(Mutex::new(db_conn));

    let vendor_pubkey = config
        .bundle_vendor_pubkey()
        .context("parse bundle vendor pubkey")?;
    let org_config = Arc::new(config.org_signed_config());
    let bundle_verification = config
        .bundle_verification_options()
        .context("parse bundle verification options")?;

    let (bundle_watcher, bundle_handle, startup_bundle_source) =
        bundle_runtime::init_bundle_watcher_with_fallback(
            config.bundle.bundle_dir.as_path(),
            &vendor_pubkey,
            org_config,
            db.clone(),
            bundle_verification,
        )
        .with_context(|| {
            format!(
                "load initial bundle from {}",
                config.bundle.bundle_dir.display()
            )
        })?;

    let bundle_watcher = Arc::new(bundle_watcher);

    let (sync_agent, sync_telemetry_sink) = if config.sync.enabled {
        let sync_config = config.sync_config();
        let (agent, telemetry_sink) =
            soth_sync::SyncAgent::new(sync_config, db.clone()).context("initialize sync agent")?;
        let allow_registry_projection_install = !bundle_verification.verify_vendor_signature
            && !bundle_verification.require_verified_bundle;
        let install_hook = Arc::new(bundle_runtime::BundleWatcherInstallHook::new(
            bundle_watcher.clone(),
            allow_registry_projection_install,
            config.bundle.bundle_dir.clone(),
            startup_bundle_source,
        ));
        agent.set_bundle_watcher(install_hook);
        (Some(Arc::new(agent)), Some(Arc::new(telemetry_sink)))
    } else {
        (None, None)
    };

    let telemetry_pipeline = if config.telemetry.enabled {
        let telemetry_cfg = config
            .telemetry_config(bundle_handle.current().version.clone())?
            .context("telemetry enabled but no telemetry config available")?;

        let sink: Arc<dyn soth_telemetry::TelemetrySink> = match &sync_telemetry_sink {
            Some(sink) => sink.clone(),
            None => anyhow::bail!(
                "telemetry.enabled=true requires sync.enabled=true for durable telemetry queueing"
            ),
        };

        Some(Arc::new(soth_telemetry::TelemetryPipeline::new(
            telemetry_cfg,
            Arc::new(soth_telemetry::SqlitePool::from_connection(
                db.clone(),
                config.db_path.clone(),
            )),
            sink,
        )))
    } else {
        None
    };

    let handler = ProxyHandler::new(
        bundle_handle.clone(),
        telemetry_pipeline.clone(),
        db,
        config.pipeline.clone(),
        config.classify_config(),
        config.classify_runtime_config(),
        config.org_id.clone(),
        config.team_id.clone(),
        config.device_id_hash.clone(),
        config.user_hmac_secret.clone(),
    );

    let handler_for_bundle_watch = handler.clone();
    let mut bundle_watch_handle = bundle_handle.clone();
    let bundle_watch_task = tokio::spawn(async move {
        loop {
            if bundle_watch_handle.changed().await.is_err() {
                break;
            }
            let bundle = bundle_watch_handle.current();
            handler_for_bundle_watch.on_bundle_updated(bundle.as_ref());
        }
    });

    let mut sync_task = None;
    if let Some(agent) = sync_agent.clone() {
        agent
            .verify_bundle_source_ready()
            .await
            .context("sync startup bundle source readiness check failed")?;
        sync_task = Some(tokio::spawn(async move { agent.run().await }));
    }

    let maintenance_handler = handler.clone();
    let maintenance_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            maintenance_handler.maintenance_tick();
        }
    });

    let mut mitm_config = config.mitm_config()?;
    if mitm_config.interception.destinations.is_empty()
        || mitm_config
            .interception
            .destinations
            .iter()
            .any(|destination| destination.trim() == "*")
    {
        let derived_destinations =
            derive_interception_destinations_from_bundle(bundle_handle.current().as_ref());
        if derived_destinations.is_empty() {
            anyhow::bail!(
                "mitm.interception.destinations is empty/wildcard and bundle-derived destinations are empty"
            );
        }
        info!(
            destination_count = derived_destinations.len(),
            "using bundle-derived mitm interception destinations"
        );
        mitm_config.interception.destinations = derived_destinations;
    }

    let proxy = soth_mitm::MitmProxyBuilder::new(mitm_config, handler)
        .build()
        .context("build mitm proxy")?;
    let proxy_handle = proxy.start().await.context("start mitm proxy")?;

    info!("soth-proxy started; press Ctrl+C to stop");
    tokio::signal::ctrl_c().await.context("wait for Ctrl+C")?;

    info!("shutdown requested");
    proxy_handle
        .shutdown(Duration::from_secs(30))
        .await
        .context("shutdown mitm proxy")?;

    if let Some(task) = sync_task {
        task.abort();
    }
    maintenance_task.abort();
    bundle_watch_task.abort();

    if let Some(agent) = sync_agent {
        if let Err(error) = agent.flush_for_shutdown(3).await {
            warn!(error = %error, "sync shutdown flush failed");
        }
    }

    if let Some(pipeline) = telemetry_pipeline {
        if let Err(error) = pipeline.flush().await {
            warn!(error = %error, "telemetry flush failed during shutdown");
        }
        if let Err(error) = pipeline.shutdown().await {
            warn!(error = %error, "telemetry shutdown failed");
        }
    }
    Ok(())
}

fn init_tracing() {
    // When RUST_LOG is set, honour it exactly. Otherwise apply sensible defaults
    // so that soth crates log at INFO while noisy dependencies stay quiet.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "warn,\
             soth_proxy=info,\
             soth_detect=info,\
             soth_bundle=info,\
             soth_sync=info,\
             soth_classify=info,\
             soth_telemetry=info,\
             soth_core=info,\
             soth_mitm=info,\
             mitm_sidecar=info,\
             hudsucker::proxy::internal=off",
        )
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init();
}

fn init_rustls_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn derive_interception_destinations_from_bundle(bundle: &soth_bundle::LoadedBundle) -> Vec<String> {
    let mut hosts = BTreeSet::new();

    for host in bundle.detect.domain_index.keys() {
        maybe_insert_destination_host_pattern(host.as_str(), &mut hosts);
    }
    for pattern in &bundle.gating.gates.stage0_tls.tls_intercept_hosts {
        maybe_insert_destination_host_pattern(pattern.as_str(), &mut hosts);
    }
    for pattern in &bundle.gating.gates.stage0_tls.passthrough_domains {
        maybe_insert_destination_host_pattern(pattern.as_str(), &mut hosts);
    }
    for entity in bundle
        .gating
        .entities
        .providers
        .iter()
        .chain(bundle.gating.entities.web_apps.iter())
        .chain(bundle.gating.entities.native_apps.iter())
    {
        for rule in &entity.hosts {
            maybe_insert_destination_host_pattern(rule.pattern.as_str(), &mut hosts);
        }
    }

    let mut destinations = Vec::with_capacity(hosts.len() * 2 + 1);
    for host in hosts {
        destinations.push(format!("{host}:443"));
        destinations.push(format!("{host}:80"));
    }
    add_discovery_tls_wildcard_destination(
        &mut destinations,
        bundle.gating.gates.stage0_tls.enable_discovery,
    );
    destinations
}

fn add_discovery_tls_wildcard_destination(destinations: &mut Vec<String>, discovery_enabled: bool) {
    if !discovery_enabled {
        return;
    }
    if destinations
        .iter()
        .any(|destination| destination == DISCOVERY_TLS_WILDCARD_DESTINATION)
    {
        return;
    }
    destinations.push(DISCOVERY_TLS_WILDCARD_DESTINATION.to_string());
}

fn maybe_insert_destination_host_pattern(candidate: &str, out: &mut BTreeSet<String>) {
    let mut host = candidate.trim().to_ascii_lowercase();
    if host.is_empty() {
        return;
    }
    if let Some(stripped) = host.strip_prefix('=') {
        host = stripped.to_string();
    }

    if let Some((left, right)) = host.rsplit_once(':') {
        let is_ipv6 = left.contains(':');
        if !is_ipv6 && right.chars().all(|ch| ch.is_ascii_digit()) {
            host = left.to_string();
        }
    }

    host = host.trim_matches('.').to_string();
    if host.is_empty() {
        return;
    }
    if !is_supported_destination_host_pattern(host.as_str()) {
        return;
    }
    if !host.chars().any(|ch| ch.is_ascii_alphanumeric()) {
        return;
    }
    out.insert(host);
}

fn is_supported_destination_host_pattern(host: &str) -> bool {
    host.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '*'))
}

#[cfg(test)]
mod tests {
    use super::{
        add_discovery_tls_wildcard_destination, maybe_insert_destination_host_pattern,
        DISCOVERY_TLS_WILDCARD_DESTINATION,
    };
    use std::collections::BTreeSet;

    #[test]
    fn destination_pattern_keeps_wildcard_hosts() {
        let mut hosts = BTreeSet::new();
        maybe_insert_destination_host_pattern("bedrock-runtime*.amazonaws.com", &mut hosts);
        assert!(hosts.contains("bedrock-runtime*.amazonaws.com"));
    }

    #[test]
    fn destination_pattern_keeps_exact_hosts_without_equals_prefix() {
        let mut hosts = BTreeSet::new();
        maybe_insert_destination_host_pattern("=accounts.google.com", &mut hosts);
        assert!(hosts.contains("accounts.google.com"));
    }

    #[test]
    fn destination_pattern_strips_numeric_port_suffix() {
        let mut hosts = BTreeSet::new();
        maybe_insert_destination_host_pattern("api.openai.com:443", &mut hosts);
        assert!(hosts.contains("api.openai.com"));
        assert!(!hosts.contains("api.openai.com:443"));
    }

    #[test]
    fn destination_pattern_rejects_invalid_non_host_shapes() {
        let mut hosts = BTreeSet::new();
        maybe_insert_destination_host_pattern("/v1/chat/*", &mut hosts);
        maybe_insert_destination_host_pattern("https://api.openai.com", &mut hosts);
        maybe_insert_destination_host_pattern("*", &mut hosts);
        assert!(hosts.is_empty());
    }

    #[test]
    fn discovery_wildcard_added_when_enabled() {
        let mut destinations = vec!["api.openai.com:443".to_string()];
        add_discovery_tls_wildcard_destination(&mut destinations, true);
        assert!(destinations
            .iter()
            .any(|destination| destination == DISCOVERY_TLS_WILDCARD_DESTINATION));
    }

    #[test]
    fn discovery_wildcard_not_added_when_disabled() {
        let mut destinations = vec!["api.openai.com:443".to_string()];
        add_discovery_tls_wildcard_destination(&mut destinations, false);
        assert!(!destinations
            .iter()
            .any(|destination| destination == DISCOVERY_TLS_WILDCARD_DESTINATION));
    }

    #[test]
    fn discovery_wildcard_is_not_duplicated() {
        let mut destinations = vec![DISCOVERY_TLS_WILDCARD_DESTINATION.to_string()];
        add_discovery_tls_wildcard_destination(&mut destinations, true);
        assert_eq!(
            destinations
                .iter()
                .filter(|destination| *destination == DISCOVERY_TLS_WILDCARD_DESTINATION)
                .count(),
            1
        );
    }
}
