use std::sync::Arc;

use chrono::Utc;
use soth_core::{ClassificationFlag, TelemetryEvent, TelemetryPolicyKind};
use tokio::sync::{mpsc, oneshot};

use crate::config::{EncryptionMode, TelemetryConfig};
use crate::db::{self, SqlitePool};
use crate::encryption;
use crate::signing;
use crate::types::{TelemetryBatch, TransmittedBatch};
use crate::{TelemetryError, TelemetrySink};

pub(crate) enum BatcherMessage {
    Event(TelemetryEvent),
    FlushNow(oneshot::Sender<Result<(), TelemetryError>>),
    Shutdown(oneshot::Sender<Result<(), TelemetryError>>),
}

pub(crate) async fn run_batcher(
    mut rx: mpsc::UnboundedReceiver<BatcherMessage>,
    config: TelemetryConfig,
    db_pool: Arc<SqlitePool>,
    sink: Arc<dyn TelemetrySink>,
) {
    let mut batch = Vec::with_capacity(config.max_batch_size);
    let mut interval = tokio::time::interval(config.batch_window);
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if !batch.is_empty() {
                    if let Err(error) = flush_batch(&mut batch, &config, db_pool.as_ref(), sink.as_ref()).await {
                        tracing::warn!(error = %error, "telemetry timer flush failed");
                    }
                }
            }
            message = rx.recv() => {
                match message {
                    Some(BatcherMessage::Event(event)) => {
                        let is_threshold = is_threshold_event(&event, &config);
                        batch.push(event);
                        if is_threshold || batch.len() >= config.max_batch_size {
                            if let Err(error) = flush_batch(&mut batch, &config, db_pool.as_ref(), sink.as_ref()).await {
                                tracing::warn!(error = %error, "telemetry threshold flush failed");
                            }
                            interval.reset();
                        }
                    }
                    Some(BatcherMessage::FlushNow(response)) => {
                        let result = flush_batch(&mut batch, &config, db_pool.as_ref(), sink.as_ref()).await;
                        let _ = response.send(result);
                    }
                    Some(BatcherMessage::Shutdown(response)) => {
                        let result = flush_batch(&mut batch, &config, db_pool.as_ref(), sink.as_ref()).await;
                        let _ = response.send(result);
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

fn is_threshold_event(event: &TelemetryEvent, config: &TelemetryConfig) -> bool {
    let anomaly_threshold = event
        .anomaly_score
        .map(|score| score > config.anomaly_threshold)
        .unwrap_or_else(|| {
            event
                .classification_flags
                .contains(&ClassificationFlag::HighAnomaly)
        });

    let policy_threshold = match event.policy_kind {
        Some(TelemetryPolicyKind::Block)
        | Some(TelemetryPolicyKind::Redact)
        | Some(TelemetryPolicyKind::Flag) => true,
        Some(TelemetryPolicyKind::Allow) | Some(TelemetryPolicyKind::Reroute) => false,
        None => event
            .classification_flags
            .contains(&ClassificationFlag::PolicyTriggered),
    };

    anomaly_threshold || policy_threshold
}

pub(crate) async fn flush_batch(
    batch: &mut Vec<TelemetryEvent>,
    config: &TelemetryConfig,
    db_pool: &SqlitePool,
    sink: &dyn TelemetrySink,
) -> Result<(), TelemetryError> {
    if batch.is_empty() {
        return Ok(());
    }

    let events = std::mem::take(batch);
    let event_ids = events
        .iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    let telemetry_batch = build_telemetry_batch(events, config);
    let signed = signing::build_signed_batch(telemetry_batch, &config.signing_key)?;
    let transmitted = match &config.encryption {
        EncryptionMode::None => TransmittedBatch::Signed(signed),
        EncryptionMode::Ecies { vendor_pubkey } => {
            TransmittedBatch::Encrypted(encryption::encrypt_batch(&signed, vendor_pubkey)?)
        }
    };

    db::write_queued(db_pool, &transmitted, &event_ids).await?;

    match sink.send(transmitted.clone()).await {
        Ok(()) => {
            // Leave rows in QUEUED. Cloud ack and final status transitions are owned by soth-sync.
        }
        Err(error) => {
            tracing::warn!(
                batch_id = %transmitted.batch_id(),
                error = %error,
                "sink rejected telemetry batch; keeping rows QUEUED for sync replay"
            );
        }
    }

    Ok(())
}

fn build_telemetry_batch(events: Vec<TelemetryEvent>, config: &TelemetryConfig) -> TelemetryBatch {
    TelemetryBatch {
        batch_id: uuid::Uuid::new_v4(),
        org_id: config.org_id.clone(),
        proxy_version: config.proxy_version.clone(),
        bundle_version: config.bundle_version.clone(),
        event_count: events.len() as u32,
        events,
        timestamp_utc: Utc::now().timestamp(),
    }
}
