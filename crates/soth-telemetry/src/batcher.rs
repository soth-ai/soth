use std::sync::Arc;

use chrono::Utc;
use soth_core::{ClassificationFlag, GovernableEvent, PolicyDecision, PolicyDecisionKind, TelemetryEvent, TelemetryPolicyKind};
use tokio::sync::{mpsc, oneshot};

use crate::config::{EncryptionMode, TelemetryConfig};
use crate::db::{self, SqlitePool};
use crate::encryption;
use crate::signing;
use crate::types::{ObservationTelemetryRecord, TelemetryBatch, TransmittedBatch};
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
                // Flush on timer: either live events in batch or governance queue files pending.
                let has_governance = config.governance_queue_dir.as_deref()
                    .map(|d| d.exists())
                    .unwrap_or(false);
                if !batch.is_empty() || has_governance {
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
    // Drain governance queue files (historian etc.) and merge as TelemetryEvents.
    let governance_events = drain_governance_queues(config.governance_queue_dir.as_deref());

    let events = std::mem::take(batch);
    if events.is_empty() && governance_events.is_empty() {
        return Ok(());
    }

    let event_ids = events
        .iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();

    let mut all_events = events;
    if !governance_events.is_empty() {
        tracing::info!(count = governance_events.len(), "drained governance queue events");
        all_events.extend(governance_events);
    }

    // Drain observation queue files if configured.
    let observations = drain_observation_queues(config.observation_queue_dir.as_deref());

    let telemetry_batch = build_telemetry_batch(all_events, observations, config);
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

fn build_telemetry_batch(
    events: Vec<TelemetryEvent>,
    observations: Vec<ObservationTelemetryRecord>,
    config: &TelemetryConfig,
) -> TelemetryBatch {
    TelemetryBatch {
        batch_id: uuid::Uuid::new_v4(),
        org_id: config.org_id.clone(),
        proxy_version: config.proxy_version.clone(),
        bundle_version: config.bundle_version.clone(),
        event_count: events.len() as u32,
        events,
        timestamp_utc: Utc::now().timestamp(),
        observation_records: if observations.is_empty() {
            None
        } else {
            Some(observations)
        },
    }
}

/// Read and drain all `*.obs.queue` (or legacy `*.observations.ndjson`) queue files from the given directory.
///
/// Each file is read line-by-line, parsed as `OwnedObservationQueueRecord`, and
/// the underlying `ObservationEvent` is wrapped in `ObservationTelemetryRecord`.
/// Successfully drained files are truncated to zero bytes.
fn drain_observation_queues(
    dir: Option<&std::path::Path>,
) -> Vec<ObservationTelemetryRecord> {
    let dir = match dir {
        Some(d) if d.exists() => d,
        _ => return Vec::new(),
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(error = %e, dir = %dir.display(), "cannot read observation queue dir");
            return Vec::new();
        }
    };

    let mut records = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".obs.queue") || n.ends_with(".observations.ndjson"))
            .unwrap_or(false)
        {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) if !c.is_empty() => c,
            _ => continue,
        };

        let mut drained = 0u64;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<soth_core::ObservationEvent>(trimmed) {
                Ok(event) => {
                    records.push(ObservationTelemetryRecord {
                        schema_version: 1,
                        event,
                    });
                    drained += 1;
                }
                Err(e) => {
                    // Try the queue record wrapper format
                    #[derive(serde::Deserialize)]
                    struct QueueRecord {
                        event: soth_core::ObservationEvent,
                    }
                    if let Ok(rec) = serde_json::from_str::<QueueRecord>(trimmed) {
                        records.push(ObservationTelemetryRecord {
                            schema_version: 1,
                            event: rec.event,
                        });
                        drained += 1;
                    } else {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "skipping unparseable observation queue line"
                        );
                    }
                }
            }
        }

        // Truncate the file after successful drain
        if drained > 0 {
            if let Err(e) = std::fs::write(&path, b"") {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to truncate drained observation queue file"
                );
            } else {
                tracing::debug!(
                    path = %path.display(),
                    records = drained,
                    "drained observation queue file"
                );
            }
        }
    }

    records
}

/// Convert a `PolicyDecisionKind` into the telemetry-level `TelemetryPolicyKind`.
fn decision_to_telemetry_policy(decision: &PolicyDecision) -> Option<TelemetryPolicyKind> {
    match &decision.kind {
        PolicyDecisionKind::Allow => Some(TelemetryPolicyKind::Allow),
        PolicyDecisionKind::Block { .. } => Some(TelemetryPolicyKind::Block),
        PolicyDecisionKind::Redact { .. } => Some(TelemetryPolicyKind::Redact),
        PolicyDecisionKind::Reroute { .. } => Some(TelemetryPolicyKind::Reroute),
        PolicyDecisionKind::Flag { .. } => Some(TelemetryPolicyKind::Flag),
    }
}

/// Read and drain all `*.queue` files (governance queue, written by historian
/// and other governance extensions). Each line is a `GovernableQueueRecord`
/// containing a `GovernableEvent` + `PolicyDecision`. We convert each into a
/// `TelemetryEvent` via `TelemetryEvent::from_governable()`.
fn drain_governance_queues(dir: Option<&std::path::Path>) -> Vec<TelemetryEvent> {
    let dir = match dir {
        Some(d) if d.exists() => d,
        _ => return Vec::new(),
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(error = %e, dir = %dir.display(), "cannot read governance queue dir");
            return Vec::new();
        }
    };

    /// Owned record matching the format written by `TelemetryQueueWriter`.
    #[derive(serde::Deserialize)]
    struct GovernanceQueueRecord {
        #[allow(dead_code)]
        schema_version: u8,
        #[allow(dead_code)]
        extension: String,
        event: GovernableEvent,
        decision: PolicyDecision,
    }

    let mut events = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Match *.queue but NOT *.obs.queue (which is observation queue)
        let is_governance = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".queue") && !n.ends_with(".obs.queue"))
            .unwrap_or(false);
        if !is_governance {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) if !c.is_empty() => c,
            _ => continue,
        };

        let mut drained = 0u64;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<GovernanceQueueRecord>(trimmed) {
                Ok(rec) => {
                    let policy_kind = decision_to_telemetry_policy(&rec.decision);
                    events.push(TelemetryEvent::from_governable(&rec.event, policy_kind));
                    drained += 1;
                }
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "skipping unparseable governance queue line"
                    );
                }
            }
        }

        if drained > 0 {
            if let Err(e) = std::fs::write(&path, b"") {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to truncate drained governance queue file"
                );
            } else {
                tracing::debug!(
                    path = %path.display(),
                    records = drained,
                    "drained governance queue file"
                );
            }
        }
    }

    events
}
