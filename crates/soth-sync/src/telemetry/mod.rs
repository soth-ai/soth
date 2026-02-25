mod outbox;
mod replay_worker;
mod sender;
mod sink;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};

use crate::agent::SyncAgentConfig;
use crate::config::TelemetrySyncConfig;

pub use outbox::{TelemetryOutbox, TelemetryOutboxRecord};
pub use replay_worker::TelemetryReplayWorker;
pub use sender::{TelemetrySendOutcome, TelemetrySender};
pub use sink::SyncTelemetrySink;

pub struct TelemetryRuntimeConfig {
    pub endpoint: String,
    pub api_key: String,
    pub event_db_path: PathBuf,
    pub telemetry: TelemetrySyncConfig,
}

impl TelemetryRuntimeConfig {
    pub fn from_sync_agent_config(config: &SyncAgentConfig) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            api_key: config.api_key.clone(),
            event_db_path: config.event_db_path.clone(),
            telemetry: config.telemetry.clone().sanitize(),
        }
    }
}

pub struct TelemetrySyncRuntime {
    sink: Arc<SyncTelemetrySink>,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl TelemetrySyncRuntime {
    pub fn start(config: TelemetryRuntimeConfig) -> Result<Self> {
        let telemetry = config.telemetry.sanitize();
        let (tx, rx) = mpsc::unbounded_channel::<String>();
        let outbox = Arc::new(TelemetryOutbox::new(config.event_db_path, tx.clone())?);
        let sink = Arc::new(SyncTelemetrySink::new(outbox.clone()));
        let sender = TelemetrySender::new(
            config.endpoint,
            config.api_key,
            telemetry.endpoint_path.clone(),
        )?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker =
            TelemetryReplayWorker::new(outbox.clone(), sender, telemetry, rx, tx, shutdown_rx);

        let startup_replayed = outbox
            .drain_on_startup()
            .context("drain telemetry outbox on startup")?;
        if startup_replayed > 0 {
            tracing::info!(
                replayed = startup_replayed,
                "queued telemetry batches for replay"
            );
        }

        let join = tokio::spawn(async move {
            worker.run().await;
        });
        Ok(Self {
            sink,
            shutdown_tx,
            join,
        })
    }

    pub fn sink(&self) -> Arc<SyncTelemetrySink> {
        self.sink.clone()
    }

    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        self.join
            .await
            .map_err(|error| anyhow::anyhow!("telemetry replay worker join failed: {error}"))?;
        Ok(())
    }
}
