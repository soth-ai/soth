mod outbox;
mod replay_worker;
mod sender;
mod sink;

use std::sync::Arc;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;
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
    pub device_id_hash: String,
    pub telemetry_signing_key_hex: Option<String>,
    pub db: Arc<Mutex<Connection>>,
    pub telemetry: TelemetrySyncConfig,
    pub local_secret: Vec<u8>,
}

impl TelemetryRuntimeConfig {
    pub fn from_sync_agent_config(config: &SyncAgentConfig, db: Arc<Mutex<Connection>>) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            api_key: config.api_key.clone(),
            device_id_hash: config.device_id_hash.clone(),
            telemetry_signing_key_hex: config.telemetry_signing_key_hex.clone(),
            db,
            telemetry: config.telemetry.clone().sanitize(),
            local_secret: config.local_secret.clone(),
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
        let outbox = Arc::new(TelemetryOutbox::new_with_connection(config.db, tx.clone())?);
        let sink = Arc::new(SyncTelemetrySink::new(outbox.clone()));
        let sender = TelemetrySender::new(
            config.endpoint,
            config.api_key,
            telemetry.endpoint_path.clone(),
            config.device_id_hash,
            config.telemetry_signing_key_hex,
            &config.local_secret,
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
