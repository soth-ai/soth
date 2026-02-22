use crate::body_uploader::BodyUploader;
use crate::cache;
use crate::config_puller::ConfigPuller;
use crate::heartbeat::HeartbeatSender;
use crate::metadata_pusher::{
    estimate_gzip_exchange_batch_size, ExchangeBatchRoute, ExchangePushResult, MetadataPusher,
};
use crate::retry_queue::BodyRetryQueue;
use anyhow::Context;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use soth_core::api::{
    BlobUploadRequest, EventClientMetadata, EventEnvelopeMetadata, ExchangeBatchRequest,
    ExchangeMetadata, HeartbeatHostDetails, HeartbeatRegistryDetails, HeartbeatRequest,
    HeartbeatTelemetry,
};
use soth_core::event_logger::{SYNC_KEY_LAST_SYNC_TIMESTAMP, SYNC_KEY_SYNC_ERRORS};
use soth_core::storage::{open_sqlite_read_only, open_sqlite_read_write, write_sync_state};
use soth_core::types::exchange::{
    ExchangeBodyMode, ExchangeEvent, EXCHANGE_CLIENT_APP_TYPE_HOST,
    EXCHANGE_CLIENT_APP_TYPE_NON_HOST, EXCHANGE_CLIENT_APP_TYPE_UNKNOWN,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, warn};
use uuid::Uuid;

const MAX_METADATA_BATCH_EVENTS_HARD_CAP: usize = 200;
const MAX_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP: usize = 5 * 1024 * 1024;
const DEFAULT_FRONTLOAD_METADATA_BATCH_EVENTS: usize = 1500;
const DEFAULT_FRONTLOAD_METADATA_BATCH_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MAX_FRONTLOAD_METADATA_BATCH_EVENTS_HARD_CAP: usize = 5000;
const MAX_FRONTLOAD_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP: usize = 64 * 1024 * 1024;
const MAX_EXCHANGE_RETRY_BACKOFF_SECS: u64 = 15 * 60;
const EXCHANGE_RETRY_BASE_SECS: u64 = 2;
const SYNC_KEY_EXCHANGE_UUID_CLEANUP_V1: &str = "migration_exchange_uuid_cleanup_v1";
const EXCHANGE_SPOOL_STALE_MAX_AGE_SECS: u64 = 6 * 60 * 60;
const EXCHANGE_SPOOL_STALE_CLEANUP_LIMIT: usize = 10_000;
const EXCHANGE_SPOOL_CLEANUP_LOCK_RETRY_MAX: u32 = 4;
const EXCHANGE_SPOOL_CLEANUP_LOCK_RETRY_BASE_MS: u64 = 50;
const SYNC_TELEMETRY_EXCHANGE_SENT: &str = "sync.exchange.sent";
const SYNC_TELEMETRY_EXCHANGE_BLOB_UPLOADED: &str = "sync.exchange.blob_uploaded";
const SYNC_TELEMETRY_EXCHANGE_RETRY_DEFERRED: &str = "sync.exchange.retry_deferred";
const SYNC_TELEMETRY_EXCHANGE_DROPPED: &str = "sync.exchange.dropped";
const SYNC_TELEMETRY_EXCHANGE_QUEUE_DEPTH: &str = "sync.exchange.queue_depth";
const SYNC_TELEMETRY_EXCHANGE_BATCH_SENT: &str = "sync.exchange.batch.sent";
const SYNC_TELEMETRY_EXCHANGE_BATCH_EVENTS: &str = "sync.exchange.batch.events";
const SYNC_TELEMETRY_EXCHANGE_BATCH_COMPRESSED_BYTES: &str = "sync.exchange.batch.compressed_bytes";
const SYNC_TELEMETRY_EXCHANGE_BATCH_SPLIT_COUNT: &str = "sync.exchange.batch.split_count";
const SYNC_TELEMETRY_EXCHANGE_FRONTLOAD_SENT: &str = "sync.exchange.frontload.sent";
const SYNC_TELEMETRY_EXCHANGE_LIVE_SENT: &str = "sync.exchange.live.sent";
const SYNC_TELEMETRY_REGISTRY_CACHE_PRESENT: &str = "sync.registry.cache_present";
const SYNC_TELEMETRY_REGISTRY_BUNDLE_AGE_SECS: &str = "sync.registry.bundle_age_seconds";
const SYNC_TELEMETRY_REGISTRY_DEGRADED_STALE: &str = "sync.registry.degraded_stale";
const SYNC_TELEMETRY_REGISTRY_VALIDATION_FAILED: &str = "sync.registry.validation_failed";
const REGISTRY_BUNDLE_DEGRADED_AGE_SECS: u64 = 24 * 60 * 60;

const MIN_LIVE_EVENTS: usize = 25;
const MIN_LIVE_COMPRESSED_BYTES: usize = 1 * 1024 * 1024;
const MIN_FRONTLOAD_EVENTS: usize = 50;
const MIN_FRONTLOAD_COMPRESSED_BYTES: usize = 2 * 1024 * 1024;

pub type HeartbeatTelemetryProvider =
    Arc<dyn Fn() -> Option<HeartbeatTelemetry> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct SyncAgentConfig {
    pub endpoint: String,
    pub api_key: String,
    pub event_db_path: PathBuf,
    pub cache_path: PathBuf,
    pub registry_cache_path: Option<PathBuf>,
    pub agent_instance_id: String,
    pub proxy_version: String,
    pub retry_queue_dir: PathBuf,
    pub retry_queue_max_bytes: u64,
    pub sync_interval: Duration,
    pub batch_size: usize,
    pub body_batch_size: usize,
    pub body_upload_enabled: bool,
    pub metadata_max_events_per_batch: usize,
    pub metadata_max_compressed_batch_bytes: usize,
    pub frontload_enabled: bool,
    pub frontload_max_events_per_batch: usize,
    pub frontload_max_compressed_batch_bytes: usize,
    pub frontload_hard_events_cap: usize,
    pub frontload_hard_compressed_cap_bytes: usize,
    pub frontload_exchange_upload_path: Option<String>,
    pub body_upload_max_bytes: usize,
    pub global_tags: BTreeMap<String, String>,
    pub heartbeat_telemetry: Option<HeartbeatTelemetryProvider>,
}

pub struct SyncAgent {
    pub config: SyncAgentConfig,
    pub metadata_pusher: MetadataPusher,
    pub body_uploader: BodyUploader,
    pub heartbeat_sender: HeartbeatSender,
    pub retry_queue: BodyRetryQueue,
    pub config_puller: Option<ConfigPuller>,
    sync_exchange_sent_total: AtomicU64,
    sync_exchange_blob_uploaded_total: AtomicU64,
    sync_exchange_retry_deferred_total: AtomicU64,
    sync_exchange_dropped_total: AtomicU64,
    sync_exchange_batch_sent_total: AtomicU64,
    sync_exchange_batch_events_total: AtomicU64,
    sync_exchange_batch_compressed_bytes_total: AtomicU64,
    sync_exchange_batch_split_total: AtomicU64,
    sync_exchange_frontload_sent_total: AtomicU64,
    sync_exchange_live_sent_total: AtomicU64,
    adaptive_batch_state: Mutex<AdaptiveBatchState>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncTickSummary {
    pub exchange_sent: usize,
    pub exchange_blob_uploaded: usize,
    pub exchange_retry_deferred: usize,
    pub exchange_dropped: usize,
}

#[derive(Debug, Clone)]
struct ExchangeQueueRow {
    exchange_id: String,
    payload_json: String,
    blobs_json: Option<String>,
    attempt_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeSyncMode {
    Live,
    Frontload,
}

#[derive(Debug, Clone, Copy)]
struct ExchangeBatchLimits {
    max_events: usize,
    max_compressed_bytes: usize,
}

#[derive(Debug, Clone)]
struct PreparedExchangeQueueRow {
    row: ExchangeQueueRow,
    metadata: ExchangeMetadata,
    mode: ExchangeSyncMode,
    blob_uploaded: usize,
}

#[derive(Debug, Clone, Copy)]
struct BatchFit {
    len: usize,
    compressed_bytes: usize,
    split_count: u64,
}

#[derive(Debug, Clone, Copy)]
enum PressureKind {
    HardLimit,
    RetryableStatus,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeRejectionDisposition {
    Retry,
    Drop,
}

#[derive(Debug, Clone, Copy)]
struct AdaptiveModeState {
    max_events: usize,
    max_compressed_bytes: usize,
    success_streak: u32,
}

#[derive(Debug)]
struct AdaptiveBatchState {
    live: AdaptiveModeState,
    frontload: AdaptiveModeState,
}

impl AdaptiveBatchState {
    fn new(config: &SyncAgentConfig) -> Self {
        Self {
            live: AdaptiveModeState {
                max_events: config.metadata_max_events_per_batch.max(1),
                max_compressed_bytes: config.metadata_max_compressed_batch_bytes.max(1),
                success_streak: 0,
            },
            frontload: AdaptiveModeState {
                max_events: config.frontload_max_events_per_batch.max(1),
                max_compressed_bytes: config.frontload_max_compressed_batch_bytes.max(1),
                success_streak: 0,
            },
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ExchangeBlobQueueItem {
    side: String,
    reference: String,
    content_encoding: String,
    content_type: Option<String>,
    sha256: String,
    bytes_raw: u64,
    bytes_gzip: u64,
    payload_gzip_b64: String,
}

#[derive(Debug, Clone)]
enum PreparedRowResult {
    Prepared(PreparedExchangeQueueRow),
    Retry { reason: String },
    Drop { reason: String },
}

#[derive(Debug, Clone, Default)]
struct ExchangeQueueStats {
    exchange_sent: usize,
    exchange_blob_uploaded: usize,
    exchange_retry_deferred: usize,
    exchange_dropped: usize,
    exchange_batch_sent: usize,
    exchange_batch_events: usize,
    exchange_batch_compressed_bytes: usize,
    exchange_batch_split_count: u64,
    exchange_frontload_sent: usize,
    exchange_live_sent: usize,
}

impl SyncAgent {
    pub fn new(
        mut config: SyncAgentConfig,
        config_puller: Option<ConfigPuller>,
    ) -> anyhow::Result<Self> {
        config.batch_size = config.batch_size.max(1);
        config.body_batch_size = config.body_batch_size.max(1);
        config.metadata_max_events_per_batch = config
            .metadata_max_events_per_batch
            .max(1)
            .min(MAX_METADATA_BATCH_EVENTS_HARD_CAP);
        config.metadata_max_compressed_batch_bytes = config
            .metadata_max_compressed_batch_bytes
            .max(1)
            .min(MAX_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP);
        if config.frontload_max_events_per_batch == 0 {
            config.frontload_max_events_per_batch = DEFAULT_FRONTLOAD_METADATA_BATCH_EVENTS;
        }
        if config.frontload_max_compressed_batch_bytes == 0 {
            config.frontload_max_compressed_batch_bytes =
                DEFAULT_FRONTLOAD_METADATA_BATCH_COMPRESSED_BYTES;
        }
        if config.frontload_hard_events_cap == 0 {
            config.frontload_hard_events_cap = MAX_FRONTLOAD_METADATA_BATCH_EVENTS_HARD_CAP;
        }
        if config.frontload_hard_compressed_cap_bytes == 0 {
            config.frontload_hard_compressed_cap_bytes =
                MAX_FRONTLOAD_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP;
        }
        config.frontload_max_events_per_batch = config.frontload_max_events_per_batch.max(1).min(
            config
                .frontload_hard_events_cap
                .max(1)
                .min(MAX_FRONTLOAD_METADATA_BATCH_EVENTS_HARD_CAP),
        );
        config.frontload_max_compressed_batch_bytes =
            config.frontload_max_compressed_batch_bytes.max(1).min(
                config
                    .frontload_hard_compressed_cap_bytes
                    .max(1)
                    .min(MAX_FRONTLOAD_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP),
            );
        let metadata_pusher = MetadataPusher::new(
            &config.endpoint,
            &config.api_key,
            config.frontload_exchange_upload_path.clone(),
        );
        let body_uploader = BodyUploader::new(&config.endpoint, &config.api_key);
        let heartbeat_sender = HeartbeatSender::new(&config.endpoint, &config.api_key);
        let retry_queue =
            BodyRetryQueue::new(&config.retry_queue_dir, config.retry_queue_max_bytes)?;
        ensure_exchange_sync_schema(config.event_db_path.as_path())?;
        if let Err(error) = run_exchange_uuid_cleanup_migration(config.event_db_path.as_path()) {
            warn!(
                error = %error,
                "Failed one-time exchange UUID cleanup migration; continuing"
            );
        }
        if let Err(error) = run_exchange_spool_stale_cleanup(
            config.event_db_path.as_path(),
            Duration::from_secs(EXCHANGE_SPOOL_STALE_MAX_AGE_SECS),
            EXCHANGE_SPOOL_STALE_CLEANUP_LIMIT,
        ) {
            if is_sqlite_lock_anyhow(&error) {
                debug!(
                    error = %error,
                    "Exchange spool stale cleanup skipped due to sqlite lock; continuing"
                );
            } else {
                warn!(
                    error = %error,
                    "Failed exchange spool stale cleanup; continuing"
                );
            }
        }
        let adaptive_batch_state = Mutex::new(AdaptiveBatchState::new(&config));

        Ok(Self {
            config,
            metadata_pusher,
            body_uploader,
            heartbeat_sender,
            retry_queue,
            config_puller,
            sync_exchange_sent_total: AtomicU64::new(0),
            sync_exchange_blob_uploaded_total: AtomicU64::new(0),
            sync_exchange_retry_deferred_total: AtomicU64::new(0),
            sync_exchange_dropped_total: AtomicU64::new(0),
            sync_exchange_batch_sent_total: AtomicU64::new(0),
            sync_exchange_batch_events_total: AtomicU64::new(0),
            sync_exchange_batch_compressed_bytes_total: AtomicU64::new(0),
            sync_exchange_batch_split_total: AtomicU64::new(0),
            sync_exchange_frontload_sent_total: AtomicU64::new(0),
            sync_exchange_live_sent_total: AtomicU64::new(0),
            adaptive_batch_state,
        })
    }

    pub async fn tick(&self) -> anyhow::Result<SyncTickSummary> {
        let stats = self.sync_exchange_queue_once().await?;
        self.sync_exchange_sent_total
            .fetch_add(stats.exchange_sent as u64, Ordering::Relaxed);
        self.sync_exchange_blob_uploaded_total
            .fetch_add(stats.exchange_blob_uploaded as u64, Ordering::Relaxed);
        self.sync_exchange_retry_deferred_total
            .fetch_add(stats.exchange_retry_deferred as u64, Ordering::Relaxed);
        self.sync_exchange_dropped_total
            .fetch_add(stats.exchange_dropped as u64, Ordering::Relaxed);
        self.sync_exchange_batch_sent_total
            .fetch_add(stats.exchange_batch_sent as u64, Ordering::Relaxed);
        self.sync_exchange_batch_events_total
            .fetch_add(stats.exchange_batch_events as u64, Ordering::Relaxed);
        self.sync_exchange_batch_compressed_bytes_total.fetch_add(
            stats.exchange_batch_compressed_bytes as u64,
            Ordering::Relaxed,
        );
        self.sync_exchange_batch_split_total
            .fetch_add(stats.exchange_batch_split_count, Ordering::Relaxed);
        self.sync_exchange_frontload_sent_total
            .fetch_add(stats.exchange_frontload_sent as u64, Ordering::Relaxed);
        self.sync_exchange_live_sent_total
            .fetch_add(stats.exchange_live_sent as u64, Ordering::Relaxed);

        Ok(SyncTickSummary {
            exchange_sent: stats.exchange_sent,
            exchange_blob_uploaded: stats.exchange_blob_uploaded,
            exchange_retry_deferred: stats.exchange_retry_deferred,
            exchange_dropped: stats.exchange_dropped,
        })
    }

    /// Run a bounded best-effort sync drain during shutdown.
    ///
    /// This repeatedly runs normal sync ticks and exits early once a round
    /// produces no forward progress.
    pub async fn flush_for_shutdown(&self, max_rounds: usize) -> anyhow::Result<SyncTickSummary> {
        let rounds = max_rounds.max(1);
        let mut total = SyncTickSummary::default();

        for _ in 0..rounds {
            let summary = self.tick().await?;
            total.exchange_sent += summary.exchange_sent;
            total.exchange_blob_uploaded += summary.exchange_blob_uploaded;
            total.exchange_retry_deferred += summary.exchange_retry_deferred;
            total.exchange_dropped += summary.exchange_dropped;

            if summary.exchange_sent == 0
                && summary.exchange_blob_uploaded == 0
                && summary.exchange_retry_deferred == 0
                && summary.exchange_dropped == 0
            {
                break;
            }
        }

        Ok(total)
    }

    pub async fn send_heartbeat(&self) -> anyhow::Result<bool> {
        let config_version = self.cached_config_version();
        let registry = self.collect_registry_heartbeat_details();
        let telemetry = self.compose_heartbeat_telemetry(registry.as_ref());
        let host_details = collect_heartbeat_host_details();
        let heartbeat_os = host_details
            .platform
            .clone()
            .or_else(|| Some(std::env::consts::OS.to_string()));
        let heartbeat_hostname = host_details.hostname.clone();
        let request = HeartbeatRequest {
            agent_instance_id: self.config.agent_instance_id.clone(),
            proxy_version: self.config.proxy_version.clone(),
            config_version,
            os: heartbeat_os,
            hostname: heartbeat_hostname,
            active_connections: None,
            host_details: Some(host_details),
            registry,
            telemetry,
        };

        match self.heartbeat_sender.send(&request).await {
            Ok(Some(response)) => {
                if response.config_changed {
                    if let Some(puller) = &self.config_puller {
                        if let Err(error) = puller.pull_once().await {
                            warn!(
                                "Cloud config refresh after heartbeat hint failed: {}",
                                error
                            );
                        }
                    }
                }
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                self.set_sync_error(&format!("heartbeat_error: {error}"))?;
                Err(error)
            }
        }
    }

    fn compose_heartbeat_telemetry(
        &self,
        registry: Option<&HeartbeatRegistryDetails>,
    ) -> Option<HeartbeatTelemetry> {
        let mut telemetry = self
            .config
            .heartbeat_telemetry
            .as_ref()
            .and_then(|provider| provider())
            .unwrap_or_default();
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_SENT.to_string(),
            self.sync_exchange_sent_total.load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_BLOB_UPLOADED.to_string(),
            self.sync_exchange_blob_uploaded_total
                .load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_RETRY_DEFERRED.to_string(),
            self.sync_exchange_retry_deferred_total
                .load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_DROPPED.to_string(),
            self.sync_exchange_dropped_total.load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_QUEUE_DEPTH.to_string(),
            self.load_exchange_queue_depth().unwrap_or(0),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_BATCH_SENT.to_string(),
            self.sync_exchange_batch_sent_total.load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_BATCH_EVENTS.to_string(),
            self.sync_exchange_batch_events_total
                .load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_BATCH_COMPRESSED_BYTES.to_string(),
            self.sync_exchange_batch_compressed_bytes_total
                .load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_BATCH_SPLIT_COUNT.to_string(),
            self.sync_exchange_batch_split_total.load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_FRONTLOAD_SENT.to_string(),
            self.sync_exchange_frontload_sent_total
                .load(Ordering::Relaxed),
        );
        telemetry.counters.insert(
            SYNC_TELEMETRY_EXCHANGE_LIVE_SENT.to_string(),
            self.sync_exchange_live_sent_total.load(Ordering::Relaxed),
        );
        if let Some(registry) = registry {
            telemetry
                .counters
                .insert(SYNC_TELEMETRY_REGISTRY_CACHE_PRESENT.to_string(), 1);
            telemetry.counters.insert(
                SYNC_TELEMETRY_REGISTRY_BUNDLE_AGE_SECS.to_string(),
                registry.bundle_age_seconds.unwrap_or(0),
            );
            telemetry.counters.insert(
                SYNC_TELEMETRY_REGISTRY_DEGRADED_STALE.to_string(),
                if registry.degraded_stale.unwrap_or(false) {
                    1
                } else {
                    0
                },
            );
            telemetry.counters.insert(
                SYNC_TELEMETRY_REGISTRY_VALIDATION_FAILED.to_string(),
                if registry.validation_status.as_deref() == Some("failed")
                    || registry.validation_failed_reason.is_some()
                {
                    1
                } else {
                    0
                },
            );
        } else {
            telemetry
                .counters
                .insert(SYNC_TELEMETRY_REGISTRY_CACHE_PRESENT.to_string(), 0);
            telemetry
                .counters
                .insert(SYNC_TELEMETRY_REGISTRY_BUNDLE_AGE_SECS.to_string(), 0);
            telemetry
                .counters
                .insert(SYNC_TELEMETRY_REGISTRY_DEGRADED_STALE.to_string(), 1);
            telemetry
                .counters
                .insert(SYNC_TELEMETRY_REGISTRY_VALIDATION_FAILED.to_string(), 0);
        }
        if telemetry.counters.is_empty() {
            None
        } else {
            Some(telemetry)
        }
    }

    fn collect_registry_heartbeat_details(&self) -> Option<HeartbeatRegistryDetails> {
        let registry_cache_path = self
            .config
            .registry_cache_path
            .clone()
            .unwrap_or_else(|| resolve_registry_cache_path(&self.config.cache_path));
        let status = cache::registry_bundle_runtime_status(
            &registry_cache_path,
            Duration::from_secs(REGISTRY_BUNDLE_DEGRADED_AGE_SECS),
        );
        let has_validation_signal =
            status.validation_status.is_some() || status.validation_failed_reason.is_some();
        if !status.cache_present && !has_validation_signal {
            return None;
        }
        Some(HeartbeatRegistryDetails {
            bundle_hash: status.bundle_hash,
            bundle_version: status.bundle_version,
            fetched_at: status.fetched_at,
            bundle_age_seconds: status.bundle_age_seconds,
            validation_status: status.validation_status,
            validation_failed_reason: status.validation_failed_reason,
            degraded_stale: Some(status.stale || !status.cache_present),
        })
    }

    async fn sync_exchange_queue_once(&self) -> anyhow::Result<ExchangeQueueStats> {
        let rows = self.load_exchange_queue_ready(self.ready_queue_load_limit())?;
        if rows.is_empty() {
            return Ok(ExchangeQueueStats::default());
        }

        let mut stats = ExchangeQueueStats::default();
        let config_version = self.cached_config_version();
        let mut live_rows = Vec::new();
        let mut frontload_rows = Vec::new();

        for row in rows {
            match self.prepare_exchange_queue_row(row.clone()).await {
                Ok(PreparedRowResult::Prepared(prepared)) => match prepared.mode {
                    ExchangeSyncMode::Live => live_rows.push(prepared),
                    ExchangeSyncMode::Frontload => frontload_rows.push(prepared),
                },
                Ok(PreparedRowResult::Retry { reason }) => {
                    self.defer_exchange_row_with_retry(&row, &reason, &mut stats)?;
                }
                Ok(PreparedRowResult::Drop { reason }) => {
                    self.drop_exchange_row(&row, &reason, &mut stats)?;
                }
                Err(error) => {
                    self.mark_exchange_queue_attempt(&row.exchange_id, row.attempt_count)?;
                    self.set_sync_error(&format!(
                        "exchange_upload_error:{}:{}",
                        row.exchange_id, error
                    ))?;
                    return Err(error);
                }
            }
        }

        self.flush_prepared_rows(
            ExchangeSyncMode::Live,
            live_rows,
            config_version.as_ref(),
            &mut stats,
        )
        .await?;
        self.flush_prepared_rows(
            ExchangeSyncMode::Frontload,
            frontload_rows,
            config_version.as_ref(),
            &mut stats,
        )
        .await?;

        if stats.exchange_sent > 0 {
            self.mark_sync_success()?;
        }
        Ok(stats)
    }

    fn ready_queue_load_limit(&self) -> usize {
        let live_limit = self
            .config
            .metadata_max_events_per_batch
            .max(self.config.batch_size)
            .max(1);
        let mut load_limit = if self.config.frontload_enabled {
            live_limit.max(self.config.frontload_max_events_per_batch.max(1))
        } else {
            live_limit
        };
        if self.config.body_upload_enabled {
            load_limit = load_limit.min(self.config.body_batch_size.max(1));
        }
        load_limit
    }

    async fn prepare_exchange_queue_row(
        &self,
        row: ExchangeQueueRow,
    ) -> anyhow::Result<PreparedRowResult> {
        let mut event = match serde_json::from_str::<ExchangeEvent>(&row.payload_json) {
            Ok(value) => value,
            Err(error) => {
                return Ok(PreparedRowResult::Drop {
                    reason: format!("invalid_exchange_payload:{error}"),
                });
            }
        };
        let exchange_id = event.exchange_id.trim().to_string();
        if Uuid::parse_str(&exchange_id).is_err() {
            return Ok(PreparedRowResult::Drop {
                reason: format!("invalid_exchange_id:{exchange_id}"),
            });
        }
        event.exchange_id = exchange_id.clone();

        let blobs = match row.blobs_json.as_deref() {
            Some(raw) if !raw.trim().is_empty() => {
                match serde_json::from_str::<Vec<ExchangeBlobQueueItem>>(raw) {
                    Ok(items) => items,
                    Err(error) => {
                        return Ok(PreparedRowResult::Drop {
                            reason: format!("invalid_blob_payload:{error}"),
                        });
                    }
                }
            }
            _ => Vec::new(),
        };

        let mut blob_uploaded = 0usize;
        for blob in blobs {
            let request = BlobUploadRequest {
                exchange_id: exchange_id.clone(),
                side: blob.side.clone(),
                reference: Some(blob.reference.clone()),
                content_encoding: Some(blob.content_encoding.clone()),
                content_type: blob.content_type.clone(),
                sha256: Some(blob.sha256.clone()),
                bytes_raw: Some(blob.bytes_raw),
                bytes_gzip: Some(blob.bytes_gzip),
                payload_gzip_b64: Some(blob.payload_gzip_b64.clone()),
            };
            match self.body_uploader.upload_blob(&request).await? {
                Some(response) if response.stored => {
                    blob_uploaded += 1;
                    let resolved_reference = response
                        .key
                        .or(response.blob_key)
                        .unwrap_or(blob.reference.clone());
                    match blob.side.to_ascii_lowercase().as_str() {
                        "request" => event.request.body.reference = Some(resolved_reference),
                        "response" => event.response.body.reference = Some(resolved_reference),
                        _ => {}
                    }
                }
                Some(_) => {
                    return Ok(PreparedRowResult::Retry {
                        reason: "blob_upload_rejected".to_string(),
                    });
                }
                None => {
                    return Ok(PreparedRowResult::Retry {
                        reason: "blob_upload_non_success_status".to_string(),
                    });
                }
            }
        }

        let global_device_id = normalized_global_device_id(&self.config.global_tags);
        let mut metadata = exchange_event_to_metadata(&event, global_device_id.as_deref());
        metadata.tags = merge_tags_for_exchange(&self.config.global_tags, event.tags.as_ref());
        let mode = exchange_sync_mode(metadata.tags.as_ref(), self.config.frontload_enabled);
        Ok(PreparedRowResult::Prepared(PreparedExchangeQueueRow {
            row,
            metadata,
            mode,
            blob_uploaded,
        }))
    }

    fn target_limits_for_mode(&self, mode: ExchangeSyncMode) -> ExchangeBatchLimits {
        match mode {
            ExchangeSyncMode::Live => ExchangeBatchLimits {
                max_events: self.config.metadata_max_events_per_batch.max(1),
                max_compressed_bytes: self.config.metadata_max_compressed_batch_bytes.max(1),
            },
            ExchangeSyncMode::Frontload if self.config.frontload_enabled => ExchangeBatchLimits {
                max_events: self.config.frontload_max_events_per_batch.max(1),
                max_compressed_bytes: self.config.frontload_max_compressed_batch_bytes.max(1),
            },
            ExchangeSyncMode::Frontload => ExchangeBatchLimits {
                max_events: self.config.metadata_max_events_per_batch.max(1),
                max_compressed_bytes: self.config.metadata_max_compressed_batch_bytes.max(1),
            },
        }
    }

    fn minimum_limits_for_mode(&self, mode: ExchangeSyncMode) -> ExchangeBatchLimits {
        match mode {
            ExchangeSyncMode::Live => ExchangeBatchLimits {
                max_events: MIN_LIVE_EVENTS.min(self.config.metadata_max_events_per_batch.max(1)),
                max_compressed_bytes: MIN_LIVE_COMPRESSED_BYTES
                    .min(self.config.metadata_max_compressed_batch_bytes.max(1)),
            },
            ExchangeSyncMode::Frontload => ExchangeBatchLimits {
                max_events: MIN_FRONTLOAD_EVENTS
                    .min(self.config.frontload_max_events_per_batch.max(1)),
                max_compressed_bytes: MIN_FRONTLOAD_COMPRESSED_BYTES
                    .min(self.config.frontload_max_compressed_batch_bytes.max(1)),
            },
        }
    }

    fn limits_for_mode(&self, mode: ExchangeSyncMode) -> ExchangeBatchLimits {
        let target = self.target_limits_for_mode(mode);
        let minimum = self.minimum_limits_for_mode(mode);
        match self.adaptive_batch_state.lock() {
            Ok(state) => {
                let adaptive = match mode {
                    ExchangeSyncMode::Live => state.live,
                    ExchangeSyncMode::Frontload => state.frontload,
                };
                ExchangeBatchLimits {
                    max_events: adaptive
                        .max_events
                        .clamp(minimum.max_events, target.max_events),
                    max_compressed_bytes: adaptive
                        .max_compressed_bytes
                        .clamp(minimum.max_compressed_bytes, target.max_compressed_bytes),
                }
            }
            Err(_) => target,
        }
    }

    fn adaptive_record_success(&self, mode: ExchangeSyncMode) {
        let target = self.target_limits_for_mode(mode);
        if let Ok(mut state) = self.adaptive_batch_state.lock() {
            let entry = match mode {
                ExchangeSyncMode::Live => &mut state.live,
                ExchangeSyncMode::Frontload => &mut state.frontload,
            };
            entry.success_streak = entry.success_streak.saturating_add(1);
            if entry.success_streak < 4 {
                return;
            }
            entry.success_streak = 0;
            let grow_events = (entry.max_events / 4).max(1);
            let grow_bytes = (entry.max_compressed_bytes / 5).max(64 * 1024);
            entry.max_events = entry
                .max_events
                .saturating_add(grow_events)
                .min(target.max_events);
            entry.max_compressed_bytes = entry
                .max_compressed_bytes
                .saturating_add(grow_bytes)
                .min(target.max_compressed_bytes);
        }
    }

    fn adaptive_record_pressure(&self, mode: ExchangeSyncMode, pressure: PressureKind) {
        let minimum = self.minimum_limits_for_mode(mode);
        if let Ok(mut state) = self.adaptive_batch_state.lock() {
            let entry = match mode {
                ExchangeSyncMode::Live => &mut state.live,
                ExchangeSyncMode::Frontload => &mut state.frontload,
            };
            entry.success_streak = 0;
            let divisor = match pressure {
                PressureKind::HardLimit => 3,
                PressureKind::RetryableStatus | PressureKind::Timeout => 2,
            };
            entry.max_events = (entry.max_events / divisor).max(minimum.max_events);
            entry.max_compressed_bytes =
                (entry.max_compressed_bytes / divisor).max(minimum.max_compressed_bytes);
        }
    }

    async fn flush_prepared_rows(
        &self,
        mode: ExchangeSyncMode,
        mut rows: Vec<PreparedExchangeQueueRow>,
        config_version: Option<&String>,
        stats: &mut ExchangeQueueStats,
    ) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }

        while !rows.is_empty() {
            let limits = self.limits_for_mode(mode);
            let fit = self.batch_len_under_limits(&rows, limits, config_version)?;
            if fit.split_count > 0 {
                stats.exchange_batch_split_count = stats
                    .exchange_batch_split_count
                    .saturating_add(fit.split_count);
            }
            if fit.len == 0 {
                self.adaptive_record_pressure(mode, PressureKind::HardLimit);
                let row = rows.remove(0);
                self.defer_exchange_row_with_retry(&row.row, "compressed_single_too_large", stats)?;
                continue;
            }
            let batch = rows.drain(0..fit.len).collect::<Vec<_>>();
            let request = ExchangeBatchRequest {
                agent_instance_id: self.config.agent_instance_id.clone(),
                config_version: config_version.cloned(),
                batch: batch.iter().map(|value| value.metadata.clone()).collect(),
            };
            match self
                .metadata_pusher
                .push_exchange_batch(&request, exchange_batch_route_for_mode(mode))
                .await
            {
                Ok(ExchangePushResult::Success(response)) if response.rejected == 0 => {
                    for item in batch {
                        self.delete_exchange_queue_entry(&item.row.exchange_id)?;
                        stats.exchange_sent += 1;
                        stats.exchange_blob_uploaded += item.blob_uploaded;
                        match mode {
                            ExchangeSyncMode::Live => stats.exchange_live_sent += 1,
                            ExchangeSyncMode::Frontload => stats.exchange_frontload_sent += 1,
                        }
                    }
                    stats.exchange_batch_sent += 1;
                    stats.exchange_batch_events += request.batch.len();
                    stats.exchange_batch_compressed_bytes += fit.compressed_bytes;
                    self.adaptive_record_success(mode);
                }
                Ok(ExchangePushResult::Success(response)) => {
                    let mut rejected = HashMap::new();
                    for error in &response.errors {
                        rejected.insert(
                            error.event_id.clone(),
                            (error.reason.clone(), error.code.clone()),
                        );
                    }
                    let mut accepted_in_batch = 0usize;
                    let mut retryable_rejections = 0usize;
                    for item in batch {
                        if let Some((reason, code)) = rejected.get(&item.row.exchange_id) {
                            let token = code.as_deref().unwrap_or(reason.as_str());
                            match classify_exchange_rejection(reason.as_str(), code.as_deref()) {
                                ExchangeRejectionDisposition::Drop => self.drop_exchange_row(
                                    &item.row,
                                    &format!("exchange_rejected:{token}"),
                                    stats,
                                )?,
                                ExchangeRejectionDisposition::Retry => {
                                    retryable_rejections += 1;
                                    self.defer_exchange_row_with_retry(
                                        &item.row,
                                        &format!("exchange_rejected:{token}"),
                                        stats,
                                    )?
                                }
                            }
                        } else if response.errors.is_empty() {
                            retryable_rejections += 1;
                            self.defer_exchange_row_with_retry(
                                &item.row,
                                &format!("exchange_rejected_count={}", response.rejected),
                                stats,
                            )?;
                        } else {
                            self.delete_exchange_queue_entry(&item.row.exchange_id)?;
                            stats.exchange_sent += 1;
                            stats.exchange_blob_uploaded += item.blob_uploaded;
                            accepted_in_batch += 1;
                            match mode {
                                ExchangeSyncMode::Live => stats.exchange_live_sent += 1,
                                ExchangeSyncMode::Frontload => stats.exchange_frontload_sent += 1,
                            }
                        }
                    }
                    if accepted_in_batch > 0 {
                        stats.exchange_batch_sent += 1;
                        stats.exchange_batch_events += accepted_in_batch;
                        stats.exchange_batch_compressed_bytes += fit.compressed_bytes;
                        self.adaptive_record_success(mode);
                    } else if retryable_rejections > 0 {
                        self.adaptive_record_pressure(mode, PressureKind::RetryableStatus);
                    } else {
                        // All rejections were terminal (e.g. duplicates), so avoid shrinking limits.
                        self.adaptive_record_success(mode);
                    }
                }
                Ok(ExchangePushResult::NonSuccessStatus(status)) => {
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error()
                        || status == reqwest::StatusCode::PAYLOAD_TOO_LARGE
                    {
                        let pressure = if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
                            PressureKind::HardLimit
                        } else {
                            PressureKind::RetryableStatus
                        };
                        self.adaptive_record_pressure(mode, pressure);
                    }
                    for item in batch {
                        self.defer_exchange_row_with_retry(
                            &item.row,
                            &format!("exchange_upload_status_{}", status.as_u16()),
                            stats,
                        )?;
                    }
                }
                Err(error) => {
                    if is_timeout_error(&error) {
                        self.adaptive_record_pressure(mode, PressureKind::Timeout);
                    }
                    for item in batch {
                        self.mark_exchange_queue_attempt(
                            &item.row.exchange_id,
                            item.row.attempt_count,
                        )?;
                    }
                    self.set_sync_error(&format!("exchange_upload_error:{}", error))?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn batch_len_under_limits(
        &self,
        rows: &[PreparedExchangeQueueRow],
        limits: ExchangeBatchLimits,
        config_version: Option<&String>,
    ) -> anyhow::Result<BatchFit> {
        if rows.is_empty() {
            return Ok(BatchFit {
                len: 0,
                compressed_bytes: 0,
                split_count: 0,
            });
        }
        let max_events = rows.len().min(limits.max_events.max(1));
        let mut candidate = max_events;
        let mut split_count = 0u64;

        loop {
            let request = ExchangeBatchRequest {
                agent_instance_id: self.config.agent_instance_id.clone(),
                config_version: config_version.cloned(),
                batch: rows
                    .iter()
                    .take(candidate)
                    .map(|value| value.metadata.clone())
                    .collect(),
            };
            let compressed_size = estimate_gzip_exchange_batch_size(&request)?;
            if compressed_size <= limits.max_compressed_bytes {
                return Ok(BatchFit {
                    len: candidate,
                    compressed_bytes: compressed_size,
                    split_count,
                });
            }
            if candidate <= 1 {
                return Ok(BatchFit {
                    len: 0,
                    compressed_bytes: compressed_size,
                    split_count,
                });
            }
            candidate = (candidate / 2).max(1);
            split_count = split_count.saturating_add(1);
        }
    }

    fn defer_exchange_row_with_retry(
        &self,
        row: &ExchangeQueueRow,
        reason: &str,
        stats: &mut ExchangeQueueStats,
    ) -> anyhow::Result<()> {
        self.mark_exchange_queue_attempt(&row.exchange_id, row.attempt_count)?;
        stats.exchange_retry_deferred += 1;
        warn!(
            exchange_id = %row.exchange_id,
            attempt = row.attempt_count.saturating_add(1),
            reason = %reason,
            "Exchange upload deferred with retry backoff"
        );
        Ok(())
    }

    fn drop_exchange_row(
        &self,
        row: &ExchangeQueueRow,
        reason: &str,
        stats: &mut ExchangeQueueStats,
    ) -> anyhow::Result<()> {
        stats.exchange_dropped += 1;
        warn!(
            exchange_id = %row.exchange_id,
            reason = %reason,
            "Dropping malformed exchange upload entry"
        );
        self.delete_exchange_queue_entry(&row.exchange_id)
    }

    fn load_exchange_queue_ready(&self, limit: usize) -> anyhow::Result<Vec<ExchangeQueueRow>> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT exchange_id, payload_json, blobs_json, attempt_count
                FROM exchange_upload_queue
                WHERE next_attempt_at IS NULL
                   OR next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                ORDER BY updated_at ASC
                LIMIT ?1
                "#,
            )
            .with_context(|| {
                format!(
                    "failed preparing exchange upload queue read {}",
                    self.config.event_db_path.display()
                )
            })?;

        let mut rows = stmt.query([limit.max(1) as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let attempt_count_i64: i64 = row.get(3)?;
            out.push(ExchangeQueueRow {
                exchange_id: row.get(0)?,
                payload_json: row.get(1)?,
                blobs_json: row.get(2)?,
                attempt_count: attempt_count_i64.max(0) as u32,
            });
        }
        Ok(out)
    }

    fn load_exchange_queue_depth(&self) -> anyhow::Result<u64> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let depth = conn
            .query_row("SELECT COUNT(*) FROM exchange_upload_queue", [], |row| {
                row.get::<_, i64>(0)
            })
            .with_context(|| {
                format!(
                    "failed reading exchange upload queue depth {}",
                    self.config.event_db_path.display()
                )
            })?;
        Ok(depth.max(0) as u64)
    }

    fn mark_exchange_queue_attempt(
        &self,
        exchange_id: &str,
        attempt_count: u32,
    ) -> anyhow::Result<()> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        let shift = attempt_count.min(20);
        let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let retry_secs = EXCHANGE_RETRY_BASE_SECS
            .saturating_mul(multiplier)
            .min(MAX_EXCHANGE_RETRY_BACKOFF_SECS)
            .max(1);

        conn.execute(
            r#"
            UPDATE exchange_upload_queue
            SET attempt_count = attempt_count + 1,
                next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?2)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE exchange_id = ?1
            "#,
            params![exchange_id, retry_secs as i64],
        )
        .with_context(|| {
            format!(
                "failed updating exchange upload queue attempt {} ({})",
                exchange_id,
                self.config.event_db_path.display()
            )
        })?;
        Ok(())
    }

    fn delete_exchange_queue_entry(&self, exchange_id: &str) -> anyhow::Result<()> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        conn.execute(
            "DELETE FROM exchange_upload_queue WHERE exchange_id = ?1",
            [exchange_id],
        )
        .with_context(|| {
            format!(
                "failed deleting exchange upload queue entry {} ({})",
                exchange_id,
                self.config.event_db_path.display()
            )
        })?;
        Ok(())
    }

    fn cached_config_version(&self) -> Option<String> {
        cache::load_config_cache(&self.config.cache_path)
            .ok()
            .flatten()
            .map(|config| config.config_version)
    }

    fn write_sync_value(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        write_sync_state(&conn, key, value)?;
        Ok(())
    }

    fn mark_sync_success(&self) -> anyhow::Result<()> {
        self.write_sync_value(SYNC_KEY_LAST_SYNC_TIMESTAMP, &Utc::now().to_rfc3339())?;
        self.write_sync_value(SYNC_KEY_SYNC_ERRORS, "")?;
        Ok(())
    }

    fn set_sync_error(&self, error: &str) -> anyhow::Result<()> {
        self.write_sync_value(SYNC_KEY_SYNC_ERRORS, error)
    }
}

fn ensure_exchange_sync_schema(path: &Path) -> anyhow::Result<()> {
    let conn = open_rw_conn(path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS exchange_upload_queue (
            exchange_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            blobs_json TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_exchange_upload_queue_next_attempt
            ON exchange_upload_queue(next_attempt_at);
        CREATE INDEX IF NOT EXISTS idx_exchange_upload_queue_updated_at
            ON exchange_upload_queue(updated_at);
        "#,
    )
    .with_context(|| {
        format!(
            "failed initializing exchange upload queue schema {}",
            path.display()
        )
    })?;

    if let Err(error) = conn.execute(
        "ALTER TABLE exchange_upload_queue ADD COLUMN blobs_json TEXT",
        [],
    ) {
        let message = error.to_string().to_ascii_lowercase();
        if !message.contains("duplicate column name") {
            return Err(error).with_context(|| {
                format!(
                    "failed applying exchange_upload_queue blobs_json migration {}",
                    path.display()
                )
            });
        }
    }

    Ok(())
}

fn run_exchange_uuid_cleanup_migration(path: &Path) -> anyhow::Result<()> {
    let conn = open_rw_conn(path)?;
    if !sqlite_table_exists(&conn, "sync_state")? {
        return Ok(());
    }
    let already_done: Option<String> = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = ?1 LIMIT 1",
            [SYNC_KEY_EXCHANGE_UUID_CLEANUP_V1],
            |row| row.get(0),
        )
        .optional()?;
    if already_done.is_some() {
        return Ok(());
    }

    let mut deleted_total = 0usize;
    for table in ["exchange_upload_queue", "exchange_events", "exchange_spool"] {
        if sqlite_table_exists(&conn, table)? {
            deleted_total += prune_non_uuid_exchange_ids(&conn, table)?;
        }
    }

    write_sync_state(
        &conn,
        SYNC_KEY_EXCHANGE_UUID_CLEANUP_V1,
        &format!("deleted={deleted_total}"),
    )?;

    if deleted_total > 0 {
        warn!(
            deleted_rows = deleted_total,
            "Pruned legacy non-UUID exchange rows from local event database"
        );
    }
    Ok(())
}

fn run_exchange_spool_stale_cleanup(
    path: &Path,
    max_age: Duration,
    limit: usize,
) -> anyhow::Result<()> {
    for retry in 0..=EXCHANGE_SPOOL_CLEANUP_LOCK_RETRY_MAX {
        match run_exchange_spool_stale_cleanup_once(path, max_age, limit) {
            Ok(()) => return Ok(()),
            Err(error)
                if retry < EXCHANGE_SPOOL_CLEANUP_LOCK_RETRY_MAX
                    && is_sqlite_lock_anyhow(&error) =>
            {
                std::thread::sleep(exchange_spool_cleanup_retry_backoff(retry));
            }
            Err(error) => return Err(error),
        }
    }
    Err(anyhow::anyhow!(
        "exchange spool stale cleanup retry loop exited unexpectedly"
    ))
}

fn run_exchange_spool_stale_cleanup_once(
    path: &Path,
    max_age: Duration,
    limit: usize,
) -> anyhow::Result<()> {
    let conn = open_rw_conn(path)?;
    if !sqlite_table_exists(&conn, "exchange_spool")? {
        return Ok(());
    }

    let age_secs = max_age.as_secs().max(1) as i64;
    let deleted = conn.execute(
        r#"
        DELETE FROM exchange_spool
        WHERE exchange_id IN (
            SELECT exchange_id
            FROM exchange_spool
            WHERE finalized_at IS NULL
              AND updated_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('-%d seconds', ?1))
            ORDER BY updated_at ASC
            LIMIT ?2
        )
        "#,
        params![age_secs, limit.max(1) as i64],
    )?;
    if deleted > 0 {
        warn!(
            deleted_rows = deleted,
            age_secs = age_secs,
            "Pruned stale in-flight exchange spool rows during sync startup"
        );
    }
    Ok(())
}

fn exchange_spool_cleanup_retry_backoff(retry: u32) -> Duration {
    let shift = retry.min(10);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    Duration::from_millis(
        EXCHANGE_SPOOL_CLEANUP_LOCK_RETRY_BASE_MS
            .saturating_mul(multiplier)
            .min(1_000),
    )
}

fn is_sqlite_lock_anyhow(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("database is locked")
            || message.contains("database table is locked")
            || message.contains("database busy")
    })
}

fn sqlite_table_exists(conn: &Connection, table_name: &str) -> anyhow::Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
            [table_name],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn prune_non_uuid_exchange_ids(conn: &Connection, table: &str) -> anyhow::Result<usize> {
    let select_sql = format!("SELECT exchange_id FROM {table}");
    let mut stmt = conn.prepare(&select_sql)?;
    let mut invalid_ids = Vec::new();
    for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
        let exchange_id = row?;
        if Uuid::parse_str(exchange_id.trim()).is_err() {
            invalid_ids.push(exchange_id);
        }
    }
    drop(stmt);

    let delete_sql = format!("DELETE FROM {table} WHERE exchange_id = ?1");
    let mut deleted = 0usize;
    for exchange_id in invalid_ids {
        deleted += conn.execute(&delete_sql, [exchange_id])?;
    }
    Ok(deleted)
}

fn open_read_conn(path: &Path) -> anyhow::Result<Connection> {
    let conn = open_sqlite_read_only(path)
        .with_context(|| format!("failed opening sqlite read connection {}", path.display()))?;
    Ok(conn)
}

fn open_rw_conn(path: &Path) -> anyhow::Result<Connection> {
    let conn = open_sqlite_read_write(path)
        .with_context(|| format!("failed opening sqlite rw connection {}", path.display()))?;
    Ok(conn)
}

fn merge_tags(
    global_tags: &BTreeMap<String, String>,
    event_tags: Option<&BTreeMap<String, String>>,
) -> Option<HashMap<String, String>> {
    if global_tags.is_empty() && event_tags.map(|m| m.is_empty()).unwrap_or(true) {
        return None;
    }

    let mut merged = HashMap::new();
    for (key, value) in global_tags {
        merged.insert(key.clone(), value.clone());
    }
    if let Some(event_tags) = event_tags {
        for (key, value) in event_tags {
            merged.insert(key.clone(), value.clone());
        }
    }
    Some(merged)
}

fn exchange_event_to_metadata(
    event: &ExchangeEvent,
    global_device_id: Option<&str>,
) -> ExchangeMetadata {
    let policy_allowed = event
        .tags
        .as_ref()
        .and_then(|tags| tags.get("policy.allowed"))
        .and_then(|value| {
            if value.eq_ignore_ascii_case("true") {
                Some(true)
            } else if value.eq_ignore_ascii_case("false") {
                Some(false)
            } else {
                None
            }
        });
    let policy_version = event
        .tags
        .as_ref()
        .and_then(|tags| tags.get("policy.version"))
        .cloned();
    let mcp_tool_name = event
        .tags
        .as_ref()
        .and_then(|tags| tags.get("mcp.tool_name"))
        .cloned();
    let graphql_operation = event
        .tags
        .as_ref()
        .and_then(|tags| tags.get("graphql.operation"))
        .cloned();

    ExchangeMetadata {
        exchange_id: event.exchange_id.clone(),
        schema_version: event.schema_version.clone(),
        session_id: event.session_id.clone(),
        edge_session_id: event.edge_session_id.clone(),
        provider_session_id: event.provider_session_id.clone(),
        session_is_synthetic: event.session_is_synthetic,
        observed_at: event.observed_at.to_rfc3339(),
        started_at: event.started_at.map(|value| value.to_rfc3339()),
        completed_at: event.completed_at.map(|value| value.to_rfc3339()),
        duration_ms: event.duration_ms,
        ttfb_ms: event.ttfb_ms,
        trace_id: event.trace_id.clone(),
        span_id: event.span_id.clone(),
        parent_span_id: event.parent_span_id.clone(),
        source_class: exchange_source_class_to_str(event.source_class).to_string(),
        transport: exchange_transport_to_str(event.transport).to_string(),
        provider: event.provider.clone(),
        agent: event.agent.clone(),
        model: event.model.clone(),
        endpoint: event.endpoint.clone(),
        method: event.method.clone(),
        detection_id: event.effective_detection_id().map(ToString::to_string),
        detection_bundle_version: event
            .effective_detection_bundle_version()
            .map(ToString::to_string),
        tool_identity_key: event.tool_identity_key.clone(),
        status_code: event.status_code,
        client_device_id: event
            .client_device_id
            .clone()
            .or_else(|| {
                event
                    .client
                    .as_ref()
                    .and_then(|value| value.device_id.clone())
            })
            .or_else(|| global_device_id.map(str::to_string)),
        input_tokens: event.usage.input_tokens,
        output_tokens: event.usage.output_tokens,
        cache_read_tokens: event.usage.cache_read_tokens,
        cache_write_tokens: event.usage.cache_write_tokens,
        reasoning_tokens: event.usage.reasoning_tokens,
        cost_usd: event.cost.as_ref().map(|cost| cost.estimated_usd),
        cost_currency: event.cost.as_ref().map(|cost| cost.currency.clone()),
        pricing_version: event
            .cost
            .as_ref()
            .and_then(|cost| cost.pricing_version.clone()),
        request_size_bytes: event.request.body.bytes_raw,
        response_size_bytes: event.response.body.bytes_raw,
        request_body_mode: Some(exchange_body_mode_to_str(event.request.body.mode).to_string()),
        response_body_mode: Some(exchange_body_mode_to_str(event.response.body.mode).to_string()),
        request_body_ref: event.request.body.reference.clone(),
        response_body_ref: event.response.body.reference.clone(),
        request_body_sha256: event.request.body.sha256.clone(),
        response_body_sha256: event.response.body.sha256.clone(),
        request_body_preview: event.request.body.preview.clone(),
        response_body_preview: event.response.body.preview.clone(),
        request_truncated_reason: event.request.body.truncated_reason.clone(),
        response_truncated_reason: event.response.body.truncated_reason.clone(),
        truncated: event.flags.truncated,
        metadata_only: event.flags.metadata_only,
        discovery_capture: event.flags.discovery_capture,
        blacklist_match: event.flags.blacklist_match,
        pii_detected: event.flags.pii_detected,
        pii_types: event.pii_types.clone(),
        policy_allowed,
        policy_version,
        mcp_tool_name,
        graphql_operation,
        event_hash: event
            .integrity
            .as_ref()
            .and_then(|value| value.event_hash.clone()),
        integrity_status: event
            .integrity
            .as_ref()
            .and_then(|value| value.status.clone()),
        signature: event
            .integrity
            .as_ref()
            .and_then(|value| value.signature.clone()),
        signature_key_id: event
            .integrity
            .as_ref()
            .and_then(|value| value.signature_key_id.clone()),
        parser_version: event
            .parse
            .as_ref()
            .and_then(|value| value.parser_version.clone()),
        bundle_version: event
            .parse
            .as_ref()
            .and_then(|value| value.bundle_version.clone()),
        parse_confidence: event
            .parse
            .as_ref()
            .and_then(|value| value.parse_confidence),
        detection_reason: event
            .parse
            .as_ref()
            .and_then(|value| value.detection_reason.clone()),
        detection_source: event
            .parse
            .as_ref()
            .and_then(|value| value.detection_source.clone()),
        decision_step: event
            .parse
            .as_ref()
            .and_then(|value| value.decision_step.clone()),
        decision_outcome: event
            .parse
            .as_ref()
            .and_then(|value| value.decision_outcome.clone()),
        skip_reason: event
            .parse
            .as_ref()
            .and_then(|value| value.skip_reason.clone()),
        discovery_kind: event
            .parse
            .as_ref()
            .and_then(|value| value.discovery_kind.clone()),
        client_app_type: normalize_client_app_type_for_contract(
            event
                .client
                .as_ref()
                .and_then(|value| value.app_type.as_deref()),
        ),
        client_host_origin: event
            .client
            .as_ref()
            .and_then(|value| value.host_origin.clone()),
        client_referrer_origin: event
            .client
            .as_ref()
            .and_then(|value| value.referrer_origin.clone()),
        tags: event.tags.as_ref().map(tree_to_hash),
        event_envelope: build_exchange_event_envelope_metadata(event),
    }
}

fn normalized_global_device_id(tags: &BTreeMap<String, String>) -> Option<String> {
    tags.get("device_id").and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn merge_tags_for_exchange(
    global_tags: &BTreeMap<String, String>,
    event_tags: Option<&BTreeMap<String, String>>,
) -> Option<HashMap<String, String>> {
    merge_tags(global_tags, event_tags)
}

fn exchange_sync_mode(
    tags: Option<&HashMap<String, String>>,
    frontload_enabled: bool,
) -> ExchangeSyncMode {
    if !frontload_enabled {
        return ExchangeSyncMode::Live;
    }
    let mode = tags
        .and_then(|value| value.get("collector.ingest_mode"))
        .map(|value| value.trim().to_ascii_lowercase());
    if matches!(mode.as_deref(), Some("frontload")) {
        ExchangeSyncMode::Frontload
    } else {
        ExchangeSyncMode::Live
    }
}

fn exchange_batch_route_for_mode(mode: ExchangeSyncMode) -> ExchangeBatchRoute {
    match mode {
        ExchangeSyncMode::Live => ExchangeBatchRoute::Live,
        ExchangeSyncMode::Frontload => ExchangeBatchRoute::Frontload,
    }
}

fn classify_exchange_rejection(reason: &str, code: Option<&str>) -> ExchangeRejectionDisposition {
    let candidate = code.unwrap_or(reason).trim().to_ascii_lowercase();
    match candidate.as_str() {
        "duplicate" => ExchangeRejectionDisposition::Drop,
        value if is_terminal_contract_rejection_code(value) => ExchangeRejectionDisposition::Drop,
        _ => ExchangeRejectionDisposition::Retry,
    }
}

fn is_terminal_contract_rejection_code(code: &str) -> bool {
    if code.is_empty() {
        return false;
    }

    matches!(
        code,
        "invalid_exchange_id"
            | "invalid_observed_at"
            | "invalid_schema_version"
            | "invalid_source_class"
            | "invalid_decision_contract"
            | "detection_id_invalid"
            | "detection_id_required"
            | "detection_bundle_version_required"
            | "validation_failed"
    ) || code.starts_with("invalid_")
        || code.ends_with("_required")
        || code.contains("validation")
}

fn build_exchange_event_envelope_metadata(event: &ExchangeEvent) -> Option<EventEnvelopeMetadata> {
    let (host, path) = split_endpoint_host_path(event.endpoint.as_deref());
    let tags = event.tags.as_ref();
    let process_executable = tags
        .and_then(|value| value.get("client.process_executable"))
        .cloned();
    let client = event.client.as_ref().map(|value| EventClientMetadata {
        pid: value.pid,
        device_id: value.device_id.clone(),
        bundle_id: value.bundle_id.clone(),
        process_name: value.process_name.clone(),
        process_executable,
        app_type: normalize_client_app_type_for_contract(value.app_type.as_deref()),
        host_origin: value.host_origin.clone(),
        referrer_origin: value.referrer_origin.clone(),
    });
    let headers = event
        .request
        .headers
        .as_ref()
        .or(event.response.headers.as_ref())
        .map(tree_to_hash);

    if host.is_none() && path.is_none() && client.is_none() && headers.is_none() {
        return None;
    }

    Some(EventEnvelopeMetadata {
        envelope_id: None,
        request_id: event.trace_id.clone(),
        capture_source: Some(match event.source_class {
            soth_core::types::exchange::ExchangeSourceClass::Mcp => "wrap".to_string(),
            _ => "proxy".to_string(),
        }),
        source: Some(exchange_transport_to_str(event.transport).to_string()),
        captured_at: Some(event.observed_at.to_rfc3339()),
        method: event.method.clone(),
        provider: event.provider.clone(),
        host,
        path,
        model: event.model.clone(),
        agent: event.agent.clone(),
        did: tags.and_then(|value| value.get("identity.did")).cloned(),
        key_id: event
            .integrity
            .as_ref()
            .and_then(|value| value.signature_key_id.clone()),
        signature_alg: tags
            .and_then(|value| value.get("identity.signature_alg"))
            .cloned(),
        signed_fields_version: tags
            .and_then(|value| value.get("identity.signed_fields_version"))
            .cloned(),
        signature: event
            .integrity
            .as_ref()
            .and_then(|value| value.signature.clone()),
        body_hash: event
            .integrity
            .as_ref()
            .and_then(|value| value.event_hash.clone()),
        headers,
        client,
        collector_source: tags
            .and_then(|value| value.get("collector.source"))
            .cloned(),
        collector_offset: tags
            .and_then(|value| value.get("collector.offset"))
            .and_then(|value| value.parse::<u64>().ok()),
    })
}

fn split_endpoint_host_path(endpoint: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(endpoint) = endpoint.map(str::trim) else {
        return (None, None);
    };
    if endpoint.is_empty() {
        return (None, None);
    }

    if endpoint.starts_with('/') {
        return (None, Some(endpoint.to_string()));
    }

    if let Some((_, rest)) = endpoint.split_once("://") {
        if let Some((host, path)) = rest.split_once('/') {
            let path = if path.is_empty() {
                None
            } else {
                Some(format!("/{}", path))
            };
            return (Some(host.to_string()), path);
        }
        return (Some(rest.to_string()), None);
    }

    if endpoint.contains('/') {
        let mut parts = endpoint.splitn(2, '/');
        let host = parts.next().unwrap_or_default();
        let path = parts.next().map(|value| format!("/{}", value));
        let host = if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        };
        return (host, path);
    }

    (Some(endpoint.to_string()), None)
}

fn exchange_source_class_to_str(
    source: soth_core::types::exchange::ExchangeSourceClass,
) -> &'static str {
    match source {
        soth_core::types::exchange::ExchangeSourceClass::AiInference => "ai_inference",
        soth_core::types::exchange::ExchangeSourceClass::AgentApp => "agent_app",
        soth_core::types::exchange::ExchangeSourceClass::Mcp => "mcp",
        soth_core::types::exchange::ExchangeSourceClass::Collector => "collector",
    }
}

fn exchange_transport_to_str(
    transport: soth_core::types::exchange::ExchangeTransport,
) -> &'static str {
    match transport {
        soth_core::types::exchange::ExchangeTransport::Http => "http",
        soth_core::types::exchange::ExchangeTransport::Https => "https",
        soth_core::types::exchange::ExchangeTransport::Http2 => "http2",
        soth_core::types::exchange::ExchangeTransport::Ws => "ws",
        soth_core::types::exchange::ExchangeTransport::Sse => "sse",
        soth_core::types::exchange::ExchangeTransport::Ndjson => "ndjson",
        soth_core::types::exchange::ExchangeTransport::Stdio => "stdio",
        soth_core::types::exchange::ExchangeTransport::Jsonrpc => "jsonrpc",
    }
}

fn exchange_body_mode_to_str(mode: ExchangeBodyMode) -> &'static str {
    match mode {
        ExchangeBodyMode::Inline => "inline",
        ExchangeBodyMode::Offloaded => "offloaded",
        // Cloud contract freeze only accepts inline|offloaded|metadata_only.
        // Legacy local events may still carry PreviewOnly; normalize on upload.
        ExchangeBodyMode::PreviewOnly => "metadata_only",
        ExchangeBodyMode::MetadataOnly => "metadata_only",
    }
}

fn normalize_client_app_type_for_contract(raw: Option<&str>) -> Option<String> {
    let normalized = raw
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())?;
    if normalized == EXCHANGE_CLIENT_APP_TYPE_HOST {
        return Some(EXCHANGE_CLIENT_APP_TYPE_HOST.to_string());
    }
    if normalized == EXCHANGE_CLIENT_APP_TYPE_NON_HOST {
        return Some(EXCHANGE_CLIENT_APP_TYPE_NON_HOST.to_string());
    }
    if normalized == EXCHANGE_CLIENT_APP_TYPE_UNKNOWN {
        return Some(EXCHANGE_CLIENT_APP_TYPE_UNKNOWN.to_string());
    }
    Some(EXCHANGE_CLIENT_APP_TYPE_UNKNOWN.to_string())
}

fn is_timeout_error(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            if reqwest_error.is_timeout() {
                return true;
            }
        }
    }
    false
}

fn tree_to_hash(map: &BTreeMap<String, String>) -> HashMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn resolve_registry_cache_path(config_cache_path: &Path) -> PathBuf {
    if let Some(parent) = config_cache_path.parent() {
        return parent.join("registry_bundle_cache.json");
    }
    cache::default_registry_cache_path()
}

fn resolve_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| run_trimmed_command_output(hostname_resolution_command()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct HostOsIdentity {
    platform: String,
    family: String,
    version: Option<String>,
}

fn collect_heartbeat_host_details() -> HeartbeatHostDetails {
    let identity = detect_host_os_identity();
    HeartbeatHostDetails {
        platform: Some(identity.platform),
        os_family: Some(identity.family),
        os_version: identity.version,
        hostname: resolve_hostname(),
        arch: Some(std::env::consts::ARCH.to_string()),
        cpu_logical_cores: std::thread::available_parallelism()
            .ok()
            .map(|value| value.get() as u64),
    }
}

#[cfg(target_os = "macos")]
fn detect_host_os_identity() -> HostOsIdentity {
    HostOsIdentity {
        platform: "macos".to_string(),
        family: "unix".to_string(),
        // Mirrors os_info macOS strategy: parse ProductVersion from sw_vers output.
        version: detect_macos_version(),
    }
}

#[cfg(windows)]
fn detect_host_os_identity() -> HostOsIdentity {
    HostOsIdentity {
        platform: "windows".to_string(),
        family: "windows".to_string(),
        // Keep a lightweight subset of os_info behavior by extracting the semantic version
        // from `cmd /C ver` output.
        version: detect_windows_version(),
    }
}

#[cfg(target_os = "linux")]
fn detect_host_os_identity() -> HostOsIdentity {
    detect_linux_identity()
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn detect_host_os_identity() -> HostOsIdentity {
    HostOsIdentity {
        platform: std::env::consts::OS.to_string(),
        family: std::env::consts::FAMILY.to_string(),
        version: None,
    }
}

fn normalize_os_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn detect_macos_version() -> Option<String> {
    let output = run_trimmed_command_output(("sw_vers", &[]))?;
    parse_prefixed_word(&output, "ProductVersion:")
}

#[cfg(windows)]
fn detect_windows_version() -> Option<String> {
    let output = run_trimmed_command_output(("cmd", &["/C", "ver"]))?;
    parse_windows_ver_output(&output)
}

#[cfg(target_os = "linux")]
fn detect_linux_identity() -> HostOsIdentity {
    let release = std::fs::read_to_string("/etc/os-release").ok();
    let distro_id = release
        .as_deref()
        .and_then(|contents| parse_os_release_key(contents, "ID"));
    let distro_version = release
        .as_deref()
        .and_then(|contents| parse_os_release_key(contents, "VERSION_ID"));
    if distro_id
        .as_deref()
        .map(|id| id.eq_ignore_ascii_case("ubuntu"))
        .unwrap_or(false)
    {
        HostOsIdentity {
            platform: "ubuntu".to_string(),
            family: "unix".to_string(),
            version: distro_version,
        }
    } else {
        HostOsIdentity {
            platform: std::env::consts::OS.to_string(),
            family: std::env::consts::FAMILY.to_string(),
            version: distro_version,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_prefixed_word(text: &str, prefix: &str) -> Option<String> {
    let prefix_start = text.find(prefix)?;
    let suffix = text[prefix_start + prefix.len()..].trim_start();
    let word_end = suffix
        .find(|ch: char| ch.is_whitespace())
        .unwrap_or(suffix.len());
    normalize_os_text(&suffix[..word_end])
}

#[cfg(any(windows, test))]
fn parse_windows_ver_output(text: &str) -> Option<String> {
    let marker = "Version ";
    let start = text.find(marker)?;
    let suffix = &text[start + marker.len()..];
    let end = suffix
        .find(']')
        .or_else(|| suffix.find(|ch: char| ch.is_whitespace()))
        .unwrap_or(suffix.len());
    normalize_os_text(&suffix[..end])
}

#[cfg(any(target_os = "linux", test))]
fn parse_os_release_key(contents: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    contents.lines().find_map(|line| {
        let raw = line.strip_prefix(&prefix)?;
        normalize_os_text(raw.trim_matches(|ch: char| ch == '"' || ch.is_whitespace()))
    })
}

fn run_trimmed_command_output(command: (&'static str, &'static [&'static str])) -> Option<String> {
    let output = std::process::Command::new(command.0)
        .args(command.1.iter().copied())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn hostname_resolution_command() -> (&'static str, &'static [&'static str]) {
    ("hostname", &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::{tempdir, TempDir};

    fn create_test_agent_with_tempdir() -> (TempDir, SyncAgent) {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("events.db");
        let retry_dir = dir.path().join("retry");
        std::fs::create_dir_all(&retry_dir).expect("retry dir");

        let config = SyncAgentConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            api_key: "test-key".to_string(),
            event_db_path: db_path,
            cache_path: dir.path().join("cache.json"),
            registry_cache_path: None,
            agent_instance_id: "agent-test".to_string(),
            proxy_version: "test".to_string(),
            retry_queue_dir: retry_dir,
            retry_queue_max_bytes: 10 * 1024 * 1024,
            sync_interval: Duration::from_secs(1),
            batch_size: 200,
            body_batch_size: 50,
            body_upload_enabled: false,
            metadata_max_events_per_batch: 200,
            metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
            frontload_enabled: true,
            frontload_max_events_per_batch: 1500,
            frontload_max_compressed_batch_bytes: 8 * 1024 * 1024,
            frontload_hard_events_cap: 5000,
            frontload_hard_compressed_cap_bytes: 16 * 1024 * 1024,
            frontload_exchange_upload_path: None,
            body_upload_max_bytes: 15 * 1024 * 1024,
            global_tags: BTreeMap::new(),
            heartbeat_telemetry: None,
        };
        let agent = SyncAgent::new(config, None).expect("sync agent");
        (dir, agent)
    }

    fn create_test_agent() -> SyncAgent {
        let (_dir, agent) = create_test_agent_with_tempdir();
        agent
    }

    #[test]
    fn ready_queue_load_limit_respects_body_batch_size_when_body_upload_enabled() {
        let (_dir, mut agent) = create_test_agent_with_tempdir();
        agent.config.frontload_enabled = false;
        agent.config.batch_size = 200;
        agent.config.metadata_max_events_per_batch = 200;
        agent.config.body_upload_enabled = true;
        agent.config.body_batch_size = 7;
        assert_eq!(agent.ready_queue_load_limit(), 7);
    }

    fn noisy_text(len: usize, seed: u64) -> String {
        let mut value = seed;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            value = value.wrapping_mul(6364136223846793005).wrapping_add(1);
            let ch = b'a' + ((value >> 32) % 26) as u8;
            out.push(ch as char);
        }
        out
    }

    fn build_prepared_row(exchange_id: &str, preview_len: usize) -> PreparedExchangeQueueRow {
        let mut event = ExchangeEvent::new(
            exchange_id,
            soth_core::types::exchange::ExchangeSourceClass::Collector,
            soth_core::types::exchange::ExchangeTransport::Https,
            ExchangeBodyMode::MetadataOnly,
            ExchangeBodyMode::MetadataOnly,
        );
        event.request.body.preview = Some(noisy_text(preview_len, 7));
        event.response.body.preview = Some(noisy_text(preview_len, 13));
        let metadata = exchange_event_to_metadata(&event, None);
        PreparedExchangeQueueRow {
            row: ExchangeQueueRow {
                exchange_id: exchange_id.to_string(),
                payload_json: "{}".to_string(),
                blobs_json: None,
                attempt_count: 0,
            },
            metadata,
            mode: ExchangeSyncMode::Live,
            blob_uploaded: 0,
        }
    }

    #[test]
    fn heartbeat_host_details_include_platform_arch_and_cores() {
        let details = collect_heartbeat_host_details();
        assert!(!details.platform.unwrap_or_default().is_empty());
        assert!(!details.os_family.unwrap_or_default().is_empty());
        assert!(!details.arch.unwrap_or_default().is_empty());
        assert!(details.cpu_logical_cores.unwrap_or(0) > 0);
    }

    #[test]
    fn parse_prefixed_word_extracts_macos_product_version() {
        let sw_vers = "ProductName:\tmacOS\nProductVersion:\t14.6.1\nBuildVersion:\t23G93";
        assert_eq!(
            parse_prefixed_word(sw_vers, "ProductVersion:").as_deref(),
            Some("14.6.1")
        );
    }

    #[test]
    fn parse_windows_ver_output_extracts_version() {
        let ver = "Microsoft Windows [Version 10.0.22631.3296]";
        assert_eq!(
            parse_windows_ver_output(ver).as_deref(),
            Some("10.0.22631.3296")
        );
    }

    #[test]
    fn parse_os_release_key_extracts_quoted_values() {
        let os_release = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(
            parse_os_release_key(os_release, "ID").as_deref(),
            Some("ubuntu")
        );
        assert_eq!(
            parse_os_release_key(os_release, "VERSION_ID").as_deref(),
            Some("24.04")
        );
    }

    #[test]
    fn collect_registry_heartbeat_details_reports_validation_failure_without_cache() {
        let (_dir, agent) = create_test_agent_with_tempdir();
        let registry_cache_path = resolve_registry_cache_path(&agent.config.cache_path);
        cache::mark_registry_validation_failed(
            &registry_cache_path,
            "integrity_verification_failed:sha_mismatch",
        )
        .unwrap();

        let details = agent
            .collect_registry_heartbeat_details()
            .expect("registry details");
        assert_eq!(details.validation_status.as_deref(), Some("failed"));
        assert_eq!(
            details.validation_failed_reason.as_deref(),
            Some("integrity_verification_failed:sha_mismatch")
        );
        assert!(details.bundle_hash.is_none());
        assert!(details.bundle_version.is_none());
        assert_eq!(details.degraded_stale, Some(true));
    }

    #[test]
    fn exchange_sync_mode_defaults_to_live() {
        assert!(matches!(
            exchange_sync_mode(None, true),
            ExchangeSyncMode::Live
        ));
    }

    #[test]
    fn exchange_sync_mode_frontload_tag_respected_when_enabled() {
        let tags = HashMap::from([("collector.ingest_mode".to_string(), "frontload".to_string())]);
        assert!(matches!(
            exchange_sync_mode(Some(&tags), true),
            ExchangeSyncMode::Frontload
        ));
    }

    #[test]
    fn exchange_sync_mode_frontload_tag_ignored_when_disabled() {
        let tags = HashMap::from([("collector.ingest_mode".to_string(), "frontload".to_string())]);
        assert!(matches!(
            exchange_sync_mode(Some(&tags), false),
            ExchangeSyncMode::Live
        ));
    }

    #[test]
    fn exchange_event_to_metadata_normalizes_preview_only_body_mode() {
        let event = ExchangeEvent::new(
            "123e4567-e89b-42d3-a456-426614174000",
            soth_core::types::exchange::ExchangeSourceClass::AgentApp,
            soth_core::types::exchange::ExchangeTransport::Https,
            ExchangeBodyMode::PreviewOnly,
            ExchangeBodyMode::PreviewOnly,
        );

        let metadata = exchange_event_to_metadata(&event, None);
        assert_eq!(metadata.request_body_mode.as_deref(), Some("metadata_only"));
        assert_eq!(
            metadata.response_body_mode.as_deref(),
            Some("metadata_only")
        );
    }

    #[test]
    fn exchange_event_to_metadata_normalizes_legacy_client_app_type() {
        let mut event = ExchangeEvent::new(
            "123e4567-e89b-42d3-a456-426614174001",
            soth_core::types::exchange::ExchangeSourceClass::AgentApp,
            soth_core::types::exchange::ExchangeTransport::Https,
            ExchangeBodyMode::Inline,
            ExchangeBodyMode::MetadataOnly,
        );
        event.client = Some(soth_core::types::exchange::ExchangeClient {
            pid: None,
            device_id: Some("device_local_01".to_string()),
            bundle_id: Some("agent.codex".to_string()),
            process_name: Some("codex".to_string()),
            app_type: Some("collector".to_string()),
            host_origin: None,
            referrer_origin: None,
        });

        let metadata = exchange_event_to_metadata(&event, None);
        assert_eq!(metadata.client_app_type.as_deref(), Some("unknown"));
        let envelope = metadata.event_envelope.expect("event_envelope");
        let client = envelope.client.expect("event_envelope.client");
        assert_eq!(client.app_type.as_deref(), Some("unknown"));
    }

    #[test]
    fn normalize_client_app_type_maps_browser_to_unknown() {
        assert_eq!(
            normalize_client_app_type_for_contract(Some("browser")).as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn normalize_client_app_type_maps_editor_to_unknown() {
        assert_eq!(
            normalize_client_app_type_for_contract(Some("editor")).as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn classify_exchange_rejection_drops_terminal_reasons() {
        assert!(matches!(
            classify_exchange_rejection("duplicate", None),
            ExchangeRejectionDisposition::Drop
        ));
    }

    #[test]
    fn classify_exchange_rejection_classifies_terminal_and_retryable_reasons() {
        assert!(matches!(
            classify_exchange_rejection("rate_limited", None),
            ExchangeRejectionDisposition::Retry
        ));
        assert!(matches!(
            classify_exchange_rejection("payload_too_large", None),
            ExchangeRejectionDisposition::Retry
        ));
        assert!(matches!(
            classify_exchange_rejection("validation_failed", None),
            ExchangeRejectionDisposition::Drop
        ));
        assert!(matches!(
            classify_exchange_rejection("invalid_exchange_id", None),
            ExchangeRejectionDisposition::Drop
        ));
        assert!(matches!(
            classify_exchange_rejection("detection_id_required", None),
            ExchangeRejectionDisposition::Drop
        ));
        assert!(matches!(
            classify_exchange_rejection("detection_id_invalid", None),
            ExchangeRejectionDisposition::Drop
        ));
        assert!(matches!(
            classify_exchange_rejection("invalid_source_class", None),
            ExchangeRejectionDisposition::Drop
        ));
    }

    #[test]
    fn is_sqlite_lock_anyhow_detects_lock_errors() {
        let locked = anyhow::anyhow!("database is locked");
        assert!(is_sqlite_lock_anyhow(&locked));
        let busy = anyhow::anyhow!("database busy");
        assert!(is_sqlite_lock_anyhow(&busy));
        let other = anyhow::anyhow!("connection refused");
        assert!(!is_sqlite_lock_anyhow(&other));
    }

    #[test]
    fn batch_fit_splits_when_compressed_limit_is_tight() {
        let agent = create_test_agent();
        let rows = vec![
            build_prepared_row("11111111-1111-4111-8111-111111111111", 4096),
            build_prepared_row("22222222-2222-4222-8222-222222222222", 4096),
            build_prepared_row("33333333-3333-4333-8333-333333333333", 4096),
            build_prepared_row("44444444-4444-4444-8444-444444444444", 4096),
        ];
        let generous = ExchangeBatchLimits {
            max_events: 4,
            max_compressed_bytes: 64 * 1024,
        };
        let full_fit = agent
            .batch_len_under_limits(&rows, generous, None)
            .expect("full fit");
        assert_eq!(full_fit.len, rows.len());

        let limits = ExchangeBatchLimits {
            max_events: 4,
            max_compressed_bytes: full_fit.compressed_bytes.saturating_sub(1).max(1),
        };
        let fit = agent
            .batch_len_under_limits(&rows, limits, None)
            .expect("fit");
        assert!(fit.len >= 1);
        assert!(fit.len < rows.len());
        assert!(fit.split_count >= 1);
        assert!(fit.compressed_bytes <= limits.max_compressed_bytes);
    }

    #[test]
    fn batch_fit_returns_zero_for_oversized_single_exchange() {
        let agent = create_test_agent();
        let rows = vec![build_prepared_row(
            "55555555-5555-4555-8555-555555555555",
            4096,
        )];
        let limits = ExchangeBatchLimits {
            max_events: 1,
            max_compressed_bytes: 64,
        };
        let fit = agent
            .batch_len_under_limits(&rows, limits, None)
            .expect("fit");
        assert_eq!(fit.len, 0);
        assert!(fit.compressed_bytes > limits.max_compressed_bytes);
    }
}
