#![forbid(unsafe_code)]

mod batcher;
mod config;
mod db;
mod encryption;
mod signing;
#[cfg(test)]
mod test_utils;
mod types;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex};

pub use config::{EncryptionMode, TelemetryConfig};
pub use db::SqlitePool;
pub use types::{
    EncryptedBatch, ObservationTelemetryRecord, SignedBatch, TelemetryBatch, TransmittedBatch,
};

pub const TELEMETRY_VERSION: &str = "1.0.0";

#[derive(Debug, Error, Clone)]
pub enum SinkError {
    #[error("{message}")]
    Rejected { message: String },
}

impl SinkError {
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected {
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry pipeline channel is closed")]
    ChannelClosed,
    #[error("telemetry pipeline response channel dropped")]
    ResponseDropped,
    #[error("telemetry batcher join failed: {0}")]
    BatcherJoin(String),
    #[error(transparent)]
    Signing(#[from] signing::SigningError),
    #[error(transparent)]
    Encryption(#[from] encryption::EncryptionError),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

#[async_trait]
pub trait TelemetrySink: Send + Sync {
    /// Returns `Ok` once the batch is durably queued for async delivery.
    /// Final cloud-ack status transitions are owned by soth-sync replay workers.
    async fn send(&self, batch: TransmittedBatch) -> Result<(), SinkError>;
}

pub struct TelemetryPipeline {
    tx: mpsc::UnboundedSender<batcher::BatcherMessage>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TelemetryPipeline {
    pub fn new(config: TelemetryConfig, db: Arc<SqlitePool>, sink: Arc<dyn TelemetrySink>) -> Self {
        let config = config.sanitize();
        let (tx, rx) = mpsc::unbounded_channel();
        let join = tokio::spawn(async move {
            batcher::run_batcher(rx, config, db, sink).await;
        });
        Self {
            tx,
            join: Mutex::new(Some(join)),
        }
    }

    pub fn push(&self, event: soth_core::TelemetryEvent) {
        if self.tx.send(batcher::BatcherMessage::Event(event)).is_err() {
            tracing::warn!("telemetry event dropped because batcher channel is closed");
        }
    }

    pub async fn flush(&self) -> Result<(), TelemetryError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(batcher::BatcherMessage::FlushNow(response_tx))
            .map_err(|_| TelemetryError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| TelemetryError::ResponseDropped)?
    }

    pub async fn shutdown(&self) -> Result<(), TelemetryError> {
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.tx.send(batcher::BatcherMessage::Shutdown(response_tx));
        let flush_result = response_rx
            .await
            .map_err(|_| TelemetryError::ResponseDropped)?;

        if let Some(join) = self.join.lock().await.take() {
            join.await
                .map_err(|error| TelemetryError::BatcherJoin(error.to_string()))?;
        }

        flush_result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use tokio::sync::Mutex;
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

    use super::*;
    use crate::db;
    use crate::signing;
    use crate::test_utils;

    #[derive(Clone)]
    struct MockSink {
        db: Arc<SqlitePool>,
        batches: Arc<Mutex<Vec<TransmittedBatch>>>,
        should_fail: Arc<AtomicBool>,
        delay_ms: Arc<AtomicU64>,
        assert_queued_before_send: bool,
    }

    impl MockSink {
        fn new(db: Arc<SqlitePool>) -> Self {
            Self {
                db,
                batches: Arc::new(Mutex::new(Vec::new())),
                should_fail: Arc::new(AtomicBool::new(false)),
                delay_ms: Arc::new(AtomicU64::new(0)),
                assert_queued_before_send: false,
            }
        }

        fn with_queued_assertion(mut self) -> Self {
            self.assert_queued_before_send = true;
            self
        }

        fn set_fail(&self, value: bool) {
            self.should_fail.store(value, Ordering::SeqCst);
        }

        fn set_delay_ms(&self, delay_ms: u64) {
            self.delay_ms.store(delay_ms, Ordering::SeqCst);
        }

        async fn batch_count(&self) -> usize {
            self.batches.lock().await.len()
        }

        async fn batches(&self) -> Vec<TransmittedBatch> {
            self.batches.lock().await.clone()
        }

        async fn yield_until_batches(&self, expected: usize) {
            for _ in 0..500 {
                if self.batch_count().await >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }

    #[async_trait]
    impl TelemetrySink for MockSink {
        async fn send(&self, batch: TransmittedBatch) -> Result<(), SinkError> {
            if self.assert_queued_before_send {
                let queued = db::count_by_status(self.db.as_ref(), batch.batch_id(), "QUEUED")
                    .await
                    .map_err(|error| SinkError::rejected(error.to_string()))?;
                if queued <= 0 {
                    return Err(SinkError::rejected(
                        "queued row was not persisted before sink.send",
                    ));
                }
            }

            let delay_ms = self.delay_ms.load(Ordering::SeqCst);
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            self.batches.lock().await.push(batch);

            if self.should_fail.load(Ordering::SeqCst) {
                Err(SinkError::rejected("mock sink failure"))
            } else {
                Ok(())
            }
        }
    }

    fn test_vendor_pubkey() -> [u8; 32] {
        x25519([42u8; 32], X25519_BASEPOINT_BYTES)
    }

    fn config(max_batch_size: usize, batch_window_secs: u64) -> TelemetryConfig {
        config_with_encryption(
            max_batch_size,
            batch_window_secs,
            EncryptionMode::Ecies {
                vendor_pubkey: test_vendor_pubkey(),
            },
        )
    }

    fn config_with_encryption(
        max_batch_size: usize,
        batch_window_secs: u64,
        encryption: EncryptionMode,
    ) -> TelemetryConfig {
        TelemetryConfig {
            batch_window: Duration::from_secs(batch_window_secs),
            max_batch_size,
            anomaly_threshold: 0.8,
            signing_key: SigningKey::from_bytes(&[3u8; 32]),
            encryption,
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            org_id: "org-test".to_string(),
            observation_queue_dir: None,
            governance_queue_dir: None,
        }
    }

    async fn in_memory_db() -> Arc<SqlitePool> {
        let db_path =
            std::env::temp_dir().join(format!("soth-telemetry-{}.db", uuid::Uuid::new_v4()));
        Arc::new(SqlitePool::new(db_path))
    }

    async fn count_status(db: &SqlitePool, batch_id: uuid::Uuid, status: &str) -> i64 {
        match db::count_by_status(db, batch_id, status).await {
            Ok(count) => count,
            Err(error) => panic!("failed to query {status} rows: {error}"),
        }
    }

    #[tokio::test]
    async fn push_is_non_blocking() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        sink.set_delay_ms(200);
        let pipeline = TelemetryPipeline::new(config(1, 30), db, Arc::new(sink.clone()));

        let start = std::time::Instant::now();
        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_millis(50));
        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn timer_flushes_only_after_batch_window() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db, Arc::new(sink.clone()));

        for _ in 0..3 {
            pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        }

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(sink.batch_count().await, 0);

        tokio::time::advance(Duration::from_secs(29)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(sink.batch_count().await, 0);

        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(sink.batch_count().await, 1);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn anomaly_threshold_triggers_immediate_flush() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db, Arc::new(sink.clone()));

        let mut event = test_utils::sample_event(uuid::Uuid::new_v4());
        event.anomaly_score = Some(0.81);
        pipeline.push(event);

        sink.yield_until_batches(1).await;
        assert_eq!(sink.batch_count().await, 1);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn policy_threshold_triggers_immediate_flush() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db, Arc::new(sink.clone()));

        let mut event = test_utils::sample_event(uuid::Uuid::new_v4());
        event.policy_kind = Some(soth_core::TelemetryPolicyKind::Block);
        pipeline.push(event);

        sink.yield_until_batches(1).await;
        assert_eq!(sink.batch_count().await, 1);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn max_batch_size_triggers_flush() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db, Arc::new(sink.clone()));

        for event in test_utils::sample_events(500) {
            pipeline.push(event);
        }

        sink.yield_until_batches(1).await;
        let batches = sink.batches().await;
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].batch_id().is_nil(), false);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn queued_row_is_written_before_sink_send() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone()).with_queued_assertion();
        let pipeline = TelemetryPipeline::new(config(1, 30), db, Arc::new(sink.clone()));

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));

        sink.yield_until_batches(1).await;
        assert_eq!(sink.batch_count().await, 1);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn sink_failure_keeps_rows_queued_and_pipeline_continues() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        sink.set_fail(true);
        let pipeline = TelemetryPipeline::new(config(1, 30), db.clone(), Arc::new(sink.clone()));

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        sink.yield_until_batches(1).await;
        let first_batches = sink.batches().await;
        assert_eq!(first_batches.len(), 1);
        let first_batch_id = first_batches[0].batch_id();
        let failed = count_status(db.as_ref(), first_batch_id, "FAILED").await;
        assert_eq!(failed, 0);
        let queued = count_status(db.as_ref(), first_batch_id, "QUEUED").await;
        assert_eq!(queued, 1);

        sink.set_fail(false);
        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        sink.yield_until_batches(2).await;
        let all_batches = sink.batches().await;
        assert_eq!(all_batches.len(), 2);
        let second_batch_id = all_batches[1].batch_id();
        let queued = count_status(db.as_ref(), second_batch_id, "QUEUED").await;
        assert_eq!(queued, 1);
        let total_queued = db::count_total_by_status(db.as_ref(), "QUEUED").await;
        match total_queued {
            Ok(count) => assert_eq!(count, 2),
            Err(error) => panic!("failed to query total queued rows: {error}"),
        }

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn flush_waits_for_sink_and_leaves_rows_queued() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db.clone(), Arc::new(sink.clone()));

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));

        let flushed = pipeline.flush().await;
        assert!(flushed.is_ok());

        let batches = sink.batches().await;
        assert_eq!(batches.len(), 1);
        let queued = count_status(db.as_ref(), batches[0].batch_id(), "QUEUED").await;
        assert_eq!(queued, 2);

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn shutdown_drains_remaining_batch() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db.clone(), Arc::new(sink.clone()));

        for _ in 0..3 {
            pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        }

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
        assert_eq!(sink.batch_count().await, 1);
        let batches = sink.batches().await;
        let queued = count_status(db.as_ref(), batches[0].batch_id(), "QUEUED").await;
        assert_eq!(queued, 3);
    }

    #[tokio::test]
    async fn integration_push_ten_then_flush_marks_all_queued() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db.clone(), Arc::new(sink.clone()));

        for _ in 0..10 {
            pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        }

        let flushed = pipeline.flush().await;
        assert!(flushed.is_ok());

        let batches = sink.batches().await;
        assert_eq!(batches.len(), 1);
        let queued = count_status(db.as_ref(), batches[0].batch_id(), "QUEUED").await;
        assert_eq!(queued, 10);
        let queued = db::count_total_by_status(db.as_ref(), "QUEUED").await;
        match queued {
            Ok(count) => assert_eq!(count, 10),
            Err(error) => panic!("failed to query total queued rows: {error}"),
        }

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn integration_threshold_flush_then_manual_flush_two_batches() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(500, 30), db.clone(), Arc::new(sink.clone()));

        for _ in 0..9 {
            pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        }

        let mut threshold = test_utils::sample_event(uuid::Uuid::new_v4());
        threshold.anomaly_score = Some(0.95);
        pipeline.push(threshold);

        sink.yield_until_batches(1).await;

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        let flushed = pipeline.flush().await;
        assert!(flushed.is_ok());

        let batches = sink.batches().await;
        assert_eq!(batches.len(), 2);
        let first_queued = count_status(db.as_ref(), batches[0].batch_id(), "QUEUED").await;
        let second_queued = count_status(db.as_ref(), batches[1].batch_id(), "QUEUED").await;
        assert_eq!(first_queued, 10);
        assert_eq!(second_queued, 1);

        let queued = db::count_total_by_status(db.as_ref(), "QUEUED").await;
        match queued {
            Ok(count) => assert_eq!(count, 11),
            Err(error) => panic!("failed to query total queued rows: {error}"),
        }

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn encryption_none_produces_signed_variant() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(
            config_with_encryption(1, 30, EncryptionMode::None),
            db,
            Arc::new(sink.clone()),
        );

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        sink.yield_until_batches(1).await;

        let batches = sink.batches().await;
        assert_eq!(batches.len(), 1);
        assert!(matches!(&batches[0], TransmittedBatch::Signed(_)));
        assert!(!batches[0].is_encrypted());

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[tokio::test]
    async fn encryption_ecies_produces_encrypted_variant() {
        let db = in_memory_db().await;
        let sink = MockSink::new(db.clone());
        let pipeline = TelemetryPipeline::new(config(1, 30), db, Arc::new(sink.clone()));

        pipeline.push(test_utils::sample_event(uuid::Uuid::new_v4()));
        sink.yield_until_batches(1).await;

        let batches = sink.batches().await;
        assert_eq!(batches.len(), 1);
        assert!(matches!(&batches[0], TransmittedBatch::Encrypted(_)));
        assert!(batches[0].is_encrypted());

        let shutdown = pipeline.shutdown().await;
        assert!(shutdown.is_ok());
    }

    #[test]
    fn signed_variant_decodes_without_vendor_key() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let event = test_utils::sample_event(uuid::Uuid::new_v4());
        let batch = TelemetryBatch {
            batch_id: uuid::Uuid::new_v4(),
            org_id: "org-test".to_string(),
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            events: vec![event],
            event_count: 1,
            timestamp_utc: 1_700_000_000,
            observation_records: None,
        };
        let signed = match signing::build_signed_batch(batch, &signing_key) {
            Ok(value) => value,
            Err(error) => panic!("expected signed batch: {error}"),
        };
        let transmitted = TransmittedBatch::Signed(signed);

        assert!(!transmitted.batch_id().is_nil());
        assert_eq!(transmitted.org_id(), "org-test");
        assert!(!transmitted.payload_hash().is_empty());
        assert!(!transmitted.is_encrypted());
    }
}
