mod bundle_runtime;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustls::crypto::{self, CryptoProvider};
use tracing::{info, warn};

use soth_proxy::{config::ProxyConfig, db, ProxyHandler};

#[cfg(feature = "extensions")]
use soth_extensions::{ExtensionRegistry, ExtensionRuntimeContext, MigrationRunner};

const DISCOVERY_TLS_WILDCARD_DESTINATION: &str = "*:443";

#[tokio::main]
async fn main() -> Result<()> {
    init_rustls_provider();

    // ── Extension registry (built early so tracing picks up extension targets) ──
    #[cfg(feature = "extensions")]
    let ext_registry = {
        let mut registry = ExtensionRegistry::empty();
        registry.register(Arc::new(soth_historian::HistorianExtension::with_defaults()));
        registry
    };

    #[cfg(feature = "extensions")]
    let ext_tracing_targets = ext_registry.tracing_targets();
    #[cfg(not(feature = "extensions"))]
    let ext_tracing_targets: Vec<&str> = Vec::new();

    init_tracing(&ext_tracing_targets);

    let config = ProxyConfig::from_env_or_default().context("load proxy config")?;

    if config.user_hmac_secret.as_str() == "local-dev-secret" {
        warn!(
            "user_hmac_secret is set to the insecure default value \"local-dev-secret\"; \
             all proxies sharing this value will produce identical user pseudonyms, \
             defeating pseudonymization — set a unique secret in your config file"
        );
    }

    if !config.mitm.verify_upstream_tls {
        tracing::warn!(
            "SECURITY WARNING: upstream TLS verification is DISABLED. \
             The proxy will not verify AI provider certificates. \
             Set forward_proxy.tls.verify_upstream_tls: true in production."
        );
    }

    let db_conn = db::open(config.db_path.as_path())?;
    let db = Arc::new(Mutex::new(db_conn));

    ensure_classify_models(&config).await;

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
        // Allow registry projection installs when verified bundles are not
        // strictly required.  Registry-projected bundles don't carry a vendor
        // signature, so they can't pass signature verification — but they are
        // still useful for hot-reloading format/entity updates from the cloud.
        let allow_registry_projection_install = !bundle_verification.require_verified_bundle;
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

    // ── Extension lifecycle ─────────────────────────────────────────────
    #[cfg(feature = "extensions")]
    let (observer_broadcast, observation_queue_dir, governance_queue_dir) = {
        let ext_ctx = Arc::new(ExtensionRuntimeContext::from_defaults());

        let all_migrations = ext_registry.all_migrations();
        if let Err(error) = MigrationRunner::run_all(ext_ctx.db_path.as_path(), all_migrations) {
            warn!(error = %error, "extension migration runner failed; continuing");
        }

        let broadcast = ext_registry.build_observer_broadcast(ext_ctx.clone());
        let queue_dir = Some(ext_ctx.queue_dir.clone());

        // Start all extension lifecycles (historian backfill + watch, etc.)
        ext_registry.start_all(ext_ctx).await;

        (broadcast, queue_dir.clone(), queue_dir)
    };

    #[cfg(not(feature = "extensions"))]
    let (observer_broadcast, observation_queue_dir, governance_queue_dir): (
        Option<soth_core::ObserverBroadcast>,
        Option<std::path::PathBuf>,
        Option<std::path::PathBuf>,
    ) = (None, None, None);

    // ── Telemetry pipeline ────────────────────────────────────────────────
    let telemetry_pipeline = if config.telemetry.enabled {
        let mut telemetry_cfg = config
            .telemetry_config(bundle_handle.current().version.clone())?
            .context("telemetry enabled but no telemetry config available")?;

        telemetry_cfg.observation_queue_dir = observation_queue_dir;
        telemetry_cfg.governance_queue_dir = governance_queue_dir;

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
        observer_broadcast,
        db,
        config.pipeline.clone(),
        config.classify_config(),
        config.classify_runtime_config(),
        config.org_id.clone(),
        config.team_id.clone(),
        config.device_id_hash.clone(),
        config.user_hmac_secret.as_str().to_string(),
    );

    // ── Ops HTTP server ───────────────────────────────────────────────────────
    // Runs on a separate port from the MITM proxy. A bind failure is non-fatal:
    // we log a warning and continue so the proxy itself is never blocked.
    let ops_task = {
        let ops_bind = config.pipeline.ops_bind.clone();
        let ops_state = Arc::new(soth_proxy::ops_server::OpsState {
            startup_time: Instant::now(),
            db_path: config.db_path.clone(),
        });
        tokio::spawn(async move {
            if ops_bind.is_empty() {
                tracing::info!("ops server disabled (pipeline.ops_bind is empty)");
                return;
            }
            match tokio::net::TcpListener::bind(&ops_bind).await {
                Ok(listener) => {
                    tracing::info!(bind = %ops_bind, "ops server started");
                    if let Err(e) =
                        axum::serve(listener, soth_proxy::ops_server::build_router(ops_state)).await
                    {
                        tracing::warn!(error = %e, "ops server exited unexpectedly");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        bind = %ops_bind,
                        "ops server failed to bind; continuing without ops endpoint"
                    );
                }
            }
        })
    };

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
        match agent.verify_bundle_source_ready().await {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "sync startup bundle source readiness check failed; starting in degraded mode"
                );
            }
        }
        sync_task = Some(tokio::spawn(async move { agent.run().await }));
    }

    let maintenance_handler = handler.clone();
    let maintenance_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let handler = maintenance_handler.clone();
            // Run on a blocking thread so DashMap scans don't starve the
            // async listener accept loop and cause health-check failures.
            let _ = tokio::task::spawn_blocking(move || {
                handler.maintenance_tick();
            })
            .await;
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
            warn!(
                "no bundle-derived interception destinations; starting in tunnel-only mode \
                 (all TLS traffic will be forwarded without inspection)"
            );
            mitm_config
                .interception
                .destinations
                .push(DISCOVERY_TLS_WILDCARD_DESTINATION.to_string());
        } else {
            info!(
                destination_count = derived_destinations.len(),
                "using bundle-derived mitm interception destinations"
            );
            mitm_config.interception.destinations = derived_destinations;
        }
    }

    let proxy = soth_mitm::MitmProxyBuilder::new(mitm_config, handler)
        .build()
        .context("build mitm proxy")?;
    let proxy_handle = match inherited_listener()? {
        Some(listener) => {
            info!("using inherited listener from supervisor");
            proxy
                .start_with_listener(listener)
                .await
                .context("start mitm proxy with inherited listener")?
        }
        None => proxy.start().await.context("start mitm proxy")?,
    };

    info!("soth-proxy started; press Ctrl+C to stop");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut usr1 = signal(SignalKind::user_defined1()).expect("listen for SIGUSR1");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested (Ctrl+C)");
            }
            _ = usr1.recv() => {
                info!("graceful drain requested (SIGUSR1)");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("wait for Ctrl+C")?;
        info!("shutdown requested");
    }
    proxy_handle
        .shutdown(Duration::from_secs(30))
        .await
        .context("shutdown mitm proxy")?;

    ops_task.abort();
    if let Some(task) = sync_task {
        task.abort();
    }
    maintenance_task.abort();
    bundle_watch_task.abort();

    // Shut down all extension lifecycles.
    #[cfg(feature = "extensions")]
    ext_registry.shutdown_all().await;

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

#[cfg(unix)]
fn inherited_listener() -> Result<Option<tokio::net::TcpListener>> {
    let fd_str = match std::env::var("SOTH_LISTENER_FD") {
        Ok(val) => val,
        Err(_) => return Ok(None),
    };
    let fd: i32 = fd_str
        .trim()
        .parse()
        .context("SOTH_LISTENER_FD is not a valid fd number")?;

    use std::os::unix::io::FromRawFd;
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    std_listener
        .set_nonblocking(true)
        .context("set inherited listener to non-blocking")?;
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .context("convert inherited listener to tokio")?;
    Ok(Some(listener))
}

#[cfg(not(unix))]
fn inherited_listener() -> Result<Option<tokio::net::TcpListener>> {
    Ok(None)
}

/// When the classify model directory is missing, fetch the classify bundle
/// from the cloud and extract it. This is non-fatal — the proxy will start
/// with a fallback classifier if this fails.
async fn ensure_classify_models(config: &soth_proxy::config::ProxyConfig) {
    let classify_dir = config.bundle.bundle_dir.join("classify");
    if classify_dir.join("manifest.json").exists() {
        return;
    }

    if !config.sync.enabled {
        tracing::warn!(
            classify_dir = %classify_dir.display(),
            "classify models missing and sync disabled — using fallback classifier"
        );
        return;
    }

    tracing::info!(
        classify_dir = %classify_dir.display(),
        "classify models missing — downloading from cloud"
    );

    let sync_cfg = config.sync_config();
    let endpoint = sync_cfg.endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/v1/edge/classify/current");

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build HTTP client for classify download");
            return;
        }
    };

    let response = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", sync_cfg.api_key))
        .header("x-soth-agent-instance-id", &sync_cfg.agent_instance_id)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, url = %url, "classify bundle download failed");
            return;
        }
    };

    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "classify bundle not available from cloud — using fallback classifier"
        );
        return;
    }

    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed reading classify bundle response body");
            return;
        }
    };

    if let Err(e) = extract_classify_tar_gz(&classify_dir, &bytes) {
        tracing::warn!(error = %e, "failed extracting classify bundle — using fallback classifier");
        return;
    }

    tracing::info!(
        classify_dir = %classify_dir.display(),
        size_bytes = bytes.len(),
        "classify models downloaded and extracted"
    );
}

fn extract_classify_tar_gz(
    target_dir: &std::path::Path,
    gz_bytes: &[u8],
) -> anyhow::Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    std::fs::create_dir_all(target_dir)
        .with_context(|| format!("create classify dir {}", target_dir.display()))?;

    let decoder = GzDecoder::new(gz_bytes);
    let mut archive = Archive::new(decoder);
    archive
        .unpack(target_dir)
        .context("unpack classify tar.gz")?;

    Ok(())
}

fn init_tracing(extension_targets: &[&str]) {
    // When RUST_LOG is set, honour it exactly. Otherwise apply sensible defaults
    // so that soth crates log at INFO while noisy dependencies stay quiet.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let mut base = String::from(
            "warn,\
             soth_proxy=info,\
             soth_detect=info,\
             soth_bundle=info,\
             soth_sync=info,\
             soth_classify=info,\
             soth_telemetry=info,\
             soth_core=info,\
             soth_mitm=info,\
             soth_extensions=info,\
             mitm_sidecar=info,\
             soth_mitm::proxy::internal=off,\
             hyper_util=warn,\
             hyper=warn,\
             rustls=warn,\
             reqwest=warn",
        );
        // Append extension tracing targets discovered from the registry.
        for target in extension_targets {
            base.push(',');
            base.push_str(target);
            base.push_str("=info");
        }
        tracing_subscriber::EnvFilter::new(base)
    });

    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
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
