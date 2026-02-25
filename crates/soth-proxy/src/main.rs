use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{info, warn};

use soth_proxy::{config::ProxyConfig, db, ProxyHandler};

struct NoopTelemetrySink;

#[async_trait]
impl soth_telemetry::TelemetrySink for NoopTelemetrySink {
    async fn send(
        &self,
        _batch: soth_telemetry::TransmittedBatch,
    ) -> Result<(), soth_telemetry::SinkError> {
        Ok(())
    }
}

#[derive(Clone)]
struct BundleWatcherInstallHook {
    watcher: Arc<soth_bundle::BundleWatcher>,
}

impl BundleWatcherInstallHook {
    fn new(watcher: Arc<soth_bundle::BundleWatcher>) -> Self {
        Self { watcher }
    }
}

impl soth_sync::BundleInstallHook for BundleWatcherInstallHook {
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
    init_tracing();

    let config = ProxyConfig::from_env_or_default().context("load proxy config")?;
    let db_conn = db::open(config.db_path.as_path())?;
    let db = Arc::new(Mutex::new(db_conn));

    let vendor_pubkey = config
        .bundle_vendor_pubkey()
        .context("parse bundle vendor pubkey")?;
    let org_config = Arc::new(config.org_signed_config());

    let (bundle_watcher, bundle_handle) = soth_bundle::init(
        config.bundle.bundle_dir.as_path(),
        &vendor_pubkey,
        org_config,
        db.clone(),
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
        let sync_db = Arc::new(
            rusqlite::Connection::open(config.db_path.as_path())
                .context("open sync sqlite handle")?,
        );
        let (agent, telemetry_sink) =
            soth_sync::SyncAgent::new(sync_config, sync_db).context("initialize sync agent")?;
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
            None => Arc::new(NoopTelemetrySink),
        };

        Some(Arc::new(soth_telemetry::TelemetryPipeline::new(
            telemetry_cfg,
            Arc::new(soth_telemetry::SqlitePool::new(config.db_path.clone())),
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

    let mitm_config = config.mitm_config()?;
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
