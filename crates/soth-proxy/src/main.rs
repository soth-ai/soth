use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::crypto::{self, CryptoProvider};
use tracing::{info, warn};

use soth_proxy::{config::ProxyConfig, db, ProxyHandler};

#[derive(Clone)]
struct BundleWatcherInstallHook {
    watcher: Arc<soth_bundle::BundleWatcher>,
}

impl BundleWatcherInstallHook {
    fn new(watcher: Arc<soth_bundle::BundleWatcher>) -> Self {
        Self { watcher }
    }
}

impl soth_sync::BundleWatcher for BundleWatcherInstallHook {
    fn install_bundle(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String> {
        self.watcher
            .install(manifest_bytes, assets)
            .map_err(anyhow::Error::from)
    }
}

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
    let bundle_verification = config.bundle_verification_options();

    let (bundle_watcher, bundle_handle) = soth_bundle::init_with_options(
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
        let install_hook = Arc::new(BundleWatcherInstallHook::new(bundle_watcher.clone()));
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        maybe_insert_exact_host(host.as_str(), &mut hosts);
    }
    for pattern in &bundle.gating.gates.stage0_tls.tls_intercept_hosts {
        maybe_insert_exact_host(pattern.as_str(), &mut hosts);
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
            maybe_insert_exact_host(rule.pattern.as_str(), &mut hosts);
        }
    }

    let mut destinations = Vec::with_capacity(hosts.len() * 2);
    for host in hosts {
        destinations.push(format!("{host}:443"));
        destinations.push(format!("{host}:80"));
    }
    destinations
}

fn maybe_insert_exact_host(candidate: &str, out: &mut BTreeSet<String>) {
    let mut host = candidate.trim().to_ascii_lowercase();
    if host.is_empty() {
        return;
    }
    if let Some(stripped) = host.strip_prefix('=') {
        host = stripped.to_string();
    }

    if host.contains('*')
        || host.contains('/')
        || host.contains('?')
        || host.contains('#')
        || host.contains(' ')
        || host.contains('\t')
    {
        return;
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
    out.insert(host);
}
