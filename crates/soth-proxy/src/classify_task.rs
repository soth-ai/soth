use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db;
use crate::session::SessionStore;

const DEFAULT_CLASSIFY_MAX_IN_FLIGHT: usize = 8;
const DEFAULT_DB_WRITE_QUEUE_CAPACITY: usize = 4_096;
const DEFAULT_CLASSIFY_SLOT_ACQUIRE_TIMEOUT_MS: u64 = 250;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub max_in_flight: usize,
    pub slot_acquire_timeout_ms: u64,
    pub db_write_queue_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_CLASSIFY_MAX_IN_FLIGHT,
            slot_acquire_timeout_ms: DEFAULT_CLASSIFY_SLOT_ACQUIRE_TIMEOUT_MS,
            db_write_queue_capacity: DEFAULT_DB_WRITE_QUEUE_CAPACITY,
        }
    }
}

#[derive(Clone)]
pub struct Runtime {
    classify_slots: Arc<Semaphore>,
    classify_slot_acquire_timeout: Duration,
    db_write_tx: mpsc::SyncSender<DbWriteJob>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
}

impl Runtime {
    pub fn new(db_conn: Arc<Mutex<rusqlite::Connection>>, config: RuntimeConfig) -> Arc<Self> {
        let classify_max_in_flight = config.max_in_flight.max(1);
        let classify_slot_acquire_timeout =
            Duration::from_millis(config.slot_acquire_timeout_ms.max(1));
        let db_write_queue_capacity = config.db_write_queue_capacity.max(16);
        let (db_write_tx, db_write_rx) = mpsc::sync_channel(db_write_queue_capacity);

        let runtime = Arc::new(Self {
            classify_slots: Arc::new(Semaphore::new(classify_max_in_flight)),
            classify_slot_acquire_timeout,
            db_write_tx,
            db_conn,
        });

        let writer_runtime = runtime.clone();
        let _ = std::thread::Builder::new()
            .name("soth-proxy-db-writer".to_string())
            .spawn(move || {
                while let Ok(job) = db_write_rx.recv() {
                    writer_runtime.write_db_job_sync(job);
                }
            });

        info!(
            classify_max_in_flight,
            classify_slot_acquire_timeout_ms = classify_slot_acquire_timeout.as_millis() as u64,
            db_write_queue_capacity,
            "initialized classify runtime"
        );
        runtime
    }

    async fn acquire_classify_slot(&self) -> Option<InFlightPermit> {
        match tokio::time::timeout(
            self.classify_slot_acquire_timeout,
            self.classify_slots.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => {
                crate::heartbeat_telemetry::record_classify_in_flight_started();
                Some(InFlightPermit { _permit: permit })
            }
            Err(_) => None,
            Ok(Err(_)) => None,
        }
    }

    fn enqueue_db_write(&self, job: DbWriteJob) {
        let connection_id = job.connection_id;
        let event_id = job.result.telemetry_event.event_id;
        match self.db_write_tx.try_send(job) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(job)) => {
                crate::heartbeat_telemetry::record_db_write_queue_fallback();
                warn!(
                    connection_id = %connection_id,
                    event_id = %event_id,
                    "db writer queue full; falling back to inline db write"
                );
                self.write_db_job_sync(job);
            }
            Err(mpsc::TrySendError::Disconnected(job)) => {
                crate::heartbeat_telemetry::record_db_write_queue_fallback();
                warn!(
                    connection_id = %connection_id,
                    event_id = %event_id,
                    "db writer queue closed; falling back to inline db write"
                );
                self.write_db_job_sync(job);
            }
        }
    }

    fn write_db_job_sync(&self, job: DbWriteJob) {
        let connection_id = job.connection_id;
        let event_id = job.result.telemetry_event.event_id;
        match db::write_intercept_record(
            &self.db_conn,
            job.connection_id,
            &job.result,
            job.result.embedding.as_deref(),
            &job.detect_result,
            &job.proxy_ctx,
            job.raw_body_for_commitment.as_deref(),
            job.capture_mode,
            job.matched_provider.as_deref(),
            job.matched_application.as_deref(),
        ) {
            Ok(()) => crate::trace::db_write_ok(connection_id, event_id),
            Err(error) => {
                crate::trace::db_write_err(connection_id, event_id, error.to_string().as_str());
                warn!(
                    connection_id = %connection_id,
                    event_id = %event_id,
                    error = %error,
                    "failed writing intercept record"
                );
                crate::heartbeat_telemetry::record_runtime_error_if_emfile(
                    error.to_string().as_str(),
                );
            }
        }
    }
}

struct InFlightPermit {
    _permit: OwnedSemaphorePermit,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        crate::heartbeat_telemetry::record_classify_in_flight_finished();
    }
}

struct DbWriteJob {
    connection_id: Uuid,
    result: soth_classify::ClassifiedResult,
    detect_result: soth_core::DetectResult,
    proxy_ctx: soth_core::ProxyContext,
    raw_body_for_commitment: Option<Bytes>,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<String>,
    matched_application: Option<String>,
}

pub fn spawn_classify_task(
    connection_id: Uuid,
    detect_result: soth_core::DetectResult,
    content_for_embedding: Option<String>,
    proxy_ctx: soth_core::ProxyContext,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<String>,
    matched_application: Option<String>,
    raw_body_for_commitment: Option<Bytes>,
    classify_bundle: Arc<soth_classify::ClassifyBundle>,
    policy_bundle: Arc<soth_policy::PolicyBundle>,
    bundle_trust_level: soth_core::BundleTrustLevel,
    classify_config: Arc<soth_classify::ClassifyConfig>,
    policy_block_enforced: Arc<AtomicBool>,
    session_store: Arc<SessionStore>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    runtime: Arc<Runtime>,
) -> oneshot::Receiver<soth_core::PolicyDecisionKind> {
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut block_signal_tx = Some(tx);
        crate::trace::classify_started(
            connection_id,
            capture_mode,
            matched_provider.as_deref(),
            matched_application.as_deref(),
        );

        if let Some(kind) = fast_block_decision(&detect_result, &proxy_ctx, policy_bundle.as_ref())
        {
            crate::trace::classify_fast_block(connection_id, &kind);
            emit_block_signal(&mut block_signal_tx, kind);
        }

        let mut result = {
            let Some(_permit) = runtime.acquire_classify_slot().await else {
                crate::heartbeat_telemetry::record_classify_overload_drop();
                tracing::debug!(
                    connection_id = %connection_id,
                    "classification slot unavailable; dropping semantic classify task"
                );
                return;
            };

            let detect_for_classify = detect_result.clone();
            let proxy_ctx_for_classify = proxy_ctx.clone();
            let content_for_classify = content_for_embedding.clone();
            let classify_bundle_for_classify = classify_bundle.clone();
            let classify_config_for_classify = classify_config.clone();

            match tokio::task::spawn_blocking(move || {
                soth_classify::classify(
                    &detect_for_classify,
                    content_for_classify.as_deref(),
                    &proxy_ctx_for_classify,
                    classify_bundle_for_classify.as_ref(),
                    classify_config_for_classify.as_ref(),
                )
            })
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    warn!(
                        connection_id = %connection_id,
                        error = %error,
                        "classification worker failed before completion"
                    );
                    return;
                }
            }
        };

        result.telemetry_event.bundle_trust_level = Some(bundle_trust_level);

        if let soth_core::PolicyDecisionKind::Block { .. } = &result.policy_decision.kind {
            emit_block_signal(&mut block_signal_tx, result.policy_decision.kind.clone());
            if !policy_block_enforced.load(Ordering::Relaxed) {
                result.policy_enforced = false;
                crate::heartbeat_telemetry::record_policy_enforced_false();
            }
        }
        crate::trace::classify_result(connection_id, &result);

        session_store.apply_classification(connection_id, &result, &detect_result.normalized);

        if let Some(pipeline) = telemetry {
            pipeline.push(result.telemetry_event.clone());
        }

        runtime.enqueue_db_write(DbWriteJob {
            connection_id,
            result,
            detect_result,
            proxy_ctx,
            raw_body_for_commitment,
            capture_mode,
            matched_provider,
            matched_application,
        });
    });

    rx
}

fn fast_block_decision(
    detect_result: &soth_core::DetectResult,
    proxy_ctx: &soth_core::ProxyContext,
    policy_bundle: &soth_policy::PolicyBundle,
) -> Option<soth_core::PolicyDecisionKind> {
    let context = soth_core::PolicyContext {
        process_resolution: proxy_ctx.process_resolution.clone(),
        capture_mode: proxy_ctx.capture_mode,
        traffic_classification: proxy_ctx.traffic_classification,
        deployment: deployment_from_source(proxy_ctx.classification_source),
        skip_org_rules: true,
        semantic: None,
        session: proxy_ctx.session_snapshot.clone().unwrap_or_default(),
    };

    let decision = soth_policy::evaluate(
        &detect_result.normalized,
        &detect_result.artifacts,
        &context,
        policy_bundle,
    );

    if let kind @ soth_core::PolicyDecisionKind::Block { .. } = decision.kind {
        Some(kind)
    } else {
        None
    }
}

fn deployment_from_source(source: soth_core::ClassificationSource) -> soth_core::DeploymentModel {
    match source {
        soth_core::ClassificationSource::Proxy => soth_core::DeploymentModel::Proxy,
        soth_core::ClassificationSource::Sidecar => soth_core::DeploymentModel::Sidecar {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
        soth_core::ClassificationSource::Sdk => soth_core::DeploymentModel::Sdk {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
    }
}

fn emit_block_signal(
    tx: &mut Option<oneshot::Sender<soth_core::PolicyDecisionKind>>,
    kind: soth_core::PolicyDecisionKind,
) {
    if let Some(sender) = tx.take() {
        let _ = sender.send(kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn test_runtime(classify_permits: usize, timeout_ms: u64) -> Runtime {
        let (tx, _rx) = mpsc::sync_channel::<DbWriteJob>(1);
        Runtime {
            classify_slots: Arc::new(Semaphore::new(classify_permits)),
            classify_slot_acquire_timeout: Duration::from_millis(timeout_ms),
            db_write_tx: tx,
            db_conn: Arc::new(Mutex::new(
                Connection::open_in_memory().expect("open in-memory sqlite"),
            )),
        }
    }

    #[test]
    fn runtime_new_is_runtime_agnostic() {
        let db = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let _runtime = Runtime::new(db, RuntimeConfig::default());
    }

    #[tokio::test]
    async fn acquire_classify_slot_succeeds_when_permit_available() {
        let runtime = test_runtime(1, 50);
        let permit = runtime.acquire_classify_slot().await;
        assert!(permit.is_some());
        drop(permit);
    }

    #[tokio::test]
    async fn acquire_classify_slot_times_out_when_no_permits() {
        let runtime = test_runtime(0, 5);
        let started = std::time::Instant::now();
        let permit = runtime.acquire_classify_slot().await;
        assert!(permit.is_none());
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn runtime_config_default_is_valid() {
        let cfg = RuntimeConfig::default();
        assert!(cfg.max_in_flight >= 1);
        assert!(cfg.slot_acquire_timeout_ms >= 1);
        assert!(cfg.db_write_queue_capacity >= 16);
    }
}
