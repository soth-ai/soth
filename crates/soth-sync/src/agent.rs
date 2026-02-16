use crate::body_uploader::BodyUploader;
use crate::cache;
use crate::config_puller::ConfigPuller;
use crate::heartbeat::HeartbeatSender;
use crate::metadata_pusher::{estimate_gzip_exchange_batch_size, MetadataPusher};
use crate::retry_queue::BodyRetryQueue;
use anyhow::Context;
use chrono::Utc;
use rusqlite::{params, Connection};
use soth_core::api::{
    BlobUploadRequest, EventClientMetadata, EventEnvelopeMetadata, ExchangeBatchRequest,
    ExchangeMetadata, HeartbeatRequest, HeartbeatTelemetry,
};
use soth_core::event_logger::{SYNC_KEY_LAST_SYNC_TIMESTAMP, SYNC_KEY_SYNC_ERRORS};
use soth_core::types::exchange_v2::{ExchangeBodyMode, ExchangeEventV2};
use soth_storage::{open_sqlite_read_only, open_sqlite_read_write, write_sync_state};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

const MAX_METADATA_BATCH_EVENTS_HARD_CAP: usize = 200;
const MAX_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP: usize = 5 * 1024 * 1024;
const MAX_EXCHANGE_RETRY_BACKOFF_SECS: u64 = 15 * 60;
const EXCHANGE_RETRY_BASE_SECS: u64 = 2;

pub type HeartbeatTelemetryProvider =
    Arc<dyn Fn() -> Option<HeartbeatTelemetry> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct SyncAgentConfig {
    pub endpoint: String,
    pub api_key: String,
    pub event_db_path: PathBuf,
    pub cache_path: PathBuf,
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
}

#[derive(Debug, Clone, Default)]
pub struct SyncTickSummary {
    pub metadata_sent: usize,
    pub body_uploaded: usize,
    pub retry_uploaded: usize,
    pub exchange_sent: usize,
    pub exchange_blob_uploaded: usize,
}

#[derive(Debug, Clone)]
struct ExchangeQueueRow {
    exchange_id: String,
    payload_json: String,
    blobs_json: Option<String>,
    attempt_count: u32,
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
enum ExchangeQueueOutcome {
    Synced { blob_uploaded: usize },
    Retry { reason: String },
    Drop { reason: String },
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
        let metadata_pusher = MetadataPusher::new(&config.endpoint, &config.api_key);
        let body_uploader = BodyUploader::new(&config.endpoint, &config.api_key);
        let heartbeat_sender = HeartbeatSender::new(&config.endpoint, &config.api_key);
        let retry_queue =
            BodyRetryQueue::new(&config.retry_queue_dir, config.retry_queue_max_bytes)?;
        Ok(Self {
            config,
            metadata_pusher,
            body_uploader,
            heartbeat_sender,
            retry_queue,
            config_puller,
        })
    }

    pub async fn tick(&self) -> anyhow::Result<SyncTickSummary> {
        let metadata_sent = 0;
        let (exchange_sent, exchange_blob_uploaded) = self.sync_exchange_queue_once().await?;

        let retry_uploaded = 0;
        let body_uploaded = 0;

        Ok(SyncTickSummary {
            metadata_sent,
            body_uploaded,
            retry_uploaded,
            exchange_sent,
            exchange_blob_uploaded,
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
            total.metadata_sent += summary.metadata_sent;
            total.body_uploaded += summary.body_uploaded;
            total.retry_uploaded += summary.retry_uploaded;
            total.exchange_sent += summary.exchange_sent;
            total.exchange_blob_uploaded += summary.exchange_blob_uploaded;

            if summary.metadata_sent == 0
                && summary.body_uploaded == 0
                && summary.retry_uploaded == 0
                && summary.exchange_sent == 0
                && summary.exchange_blob_uploaded == 0
            {
                break;
            }
        }

        Ok(total)
    }

    pub async fn send_heartbeat(&self) -> anyhow::Result<bool> {
        let config_version = self.cached_config_version();
        let request = HeartbeatRequest {
            agent_instance_id: self.config.agent_instance_id.clone(),
            proxy_version: self.config.proxy_version.clone(),
            config_version,
            os: Some(std::env::consts::OS.to_string()),
            hostname: resolve_hostname(),
            active_connections: None,
            telemetry: self
                .config
                .heartbeat_telemetry
                .as_ref()
                .and_then(|provider| provider()),
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

    async fn sync_exchange_queue_once(&self) -> anyhow::Result<(usize, usize)> {
        let rows = self.load_exchange_queue_ready(self.config.metadata_max_events_per_batch)?;
        if rows.is_empty() {
            return Ok((0, 0));
        }

        let mut exchange_sent = 0usize;
        let mut blob_uploaded = 0usize;
        let config_version = self.cached_config_version();

        for row in rows {
            match self
                .process_exchange_queue_row(&row, config_version.as_ref())
                .await
            {
                Ok(ExchangeQueueOutcome::Synced {
                    blob_uploaded: uploaded,
                }) => {
                    self.delete_exchange_queue_entry(&row.exchange_id)?;
                    exchange_sent += 1;
                    blob_uploaded += uploaded;
                }
                Ok(ExchangeQueueOutcome::Retry { reason }) => {
                    self.mark_exchange_queue_attempt(&row.exchange_id, row.attempt_count)?;
                    warn!(
                        exchange_id = %row.exchange_id,
                        attempt = row.attempt_count.saturating_add(1),
                        reason = %reason,
                        "Exchange upload deferred with retry backoff"
                    );
                }
                Ok(ExchangeQueueOutcome::Drop { reason }) => {
                    warn!(
                        exchange_id = %row.exchange_id,
                        reason = %reason,
                        "Dropping malformed exchange upload entry"
                    );
                    self.delete_exchange_queue_entry(&row.exchange_id)?;
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

        if exchange_sent > 0 {
            self.mark_sync_success()?;
        }
        Ok((exchange_sent, blob_uploaded))
    }

    async fn process_exchange_queue_row(
        &self,
        row: &ExchangeQueueRow,
        config_version: Option<&String>,
    ) -> anyhow::Result<ExchangeQueueOutcome> {
        let mut event = match serde_json::from_str::<ExchangeEventV2>(&row.payload_json) {
            Ok(value) => value,
            Err(error) => {
                return Ok(ExchangeQueueOutcome::Drop {
                    reason: format!("invalid_exchange_payload:{error}"),
                });
            }
        };
        let exchange_id = event.exchange_id.trim().to_string();
        if Uuid::parse_str(&exchange_id).is_err() {
            return Ok(ExchangeQueueOutcome::Drop {
                reason: format!("invalid_exchange_id:{exchange_id}"),
            });
        }
        event.exchange_id = exchange_id.clone();

        let blobs = match row.blobs_json.as_deref() {
            Some(raw) if !raw.trim().is_empty() => {
                match serde_json::from_str::<Vec<ExchangeBlobQueueItem>>(raw) {
                    Ok(items) => items,
                    Err(error) => {
                        return Ok(ExchangeQueueOutcome::Drop {
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
                    return Ok(ExchangeQueueOutcome::Retry {
                        reason: "blob_upload_rejected".to_string(),
                    });
                }
                None => {
                    return Ok(ExchangeQueueOutcome::Retry {
                        reason: "blob_upload_non_success_status".to_string(),
                    });
                }
            }
        }

        let mut metadata = exchange_event_to_metadata(&event);
        metadata.tags = merge_tags_for_exchange(&self.config.global_tags, event.tags.as_ref());

        let request = ExchangeBatchRequest {
            agent_instance_id: self.config.agent_instance_id.clone(),
            config_version: config_version.cloned(),
            batch: vec![metadata],
        };
        let compressed_size = estimate_gzip_exchange_batch_size(&request)?;
        if compressed_size > self.config.metadata_max_compressed_batch_bytes {
            return Ok(ExchangeQueueOutcome::Retry {
                reason: format!(
                    "compressed_batch_limit:{}>{}",
                    compressed_size, self.config.metadata_max_compressed_batch_bytes
                ),
            });
        }

        match self.metadata_pusher.push_exchange_batch(&request).await? {
            Some(response) if response.rejected == 0 => {
                Ok(ExchangeQueueOutcome::Synced { blob_uploaded })
            }
            Some(response) => Ok(ExchangeQueueOutcome::Retry {
                reason: format!("exchange_rejected_count={}", response.rejected),
            }),
            None => Ok(ExchangeQueueOutcome::Retry {
                reason: "exchange_upload_non_success_status".to_string(),
            }),
        }
    }

    fn load_exchange_queue_ready(&self, limit: usize) -> anyhow::Result<Vec<ExchangeQueueRow>> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let mut stmt = match conn.prepare(
            r#"
            SELECT exchange_id, payload_json, blobs_json, attempt_count
            FROM exchange_upload_queue
            WHERE next_attempt_at IS NULL
               OR next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            ORDER BY updated_at ASC
            LIMIT ?1
            "#,
        ) {
            Ok(stmt) => stmt,
            Err(error) if is_missing_table_error(&error, "exchange_upload_queue") => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };

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

        match conn.execute(
            r#"
            UPDATE exchange_upload_queue
            SET attempt_count = attempt_count + 1,
                next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?2)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE exchange_id = ?1
            "#,
            params![exchange_id, retry_secs as i64],
        ) {
            Ok(_) => Ok(()),
            Err(error) if is_missing_table_error(&error, "exchange_upload_queue") => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn delete_exchange_queue_entry(&self, exchange_id: &str) -> anyhow::Result<()> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        match conn.execute(
            "DELETE FROM exchange_upload_queue WHERE exchange_id = ?1",
            [exchange_id],
        ) {
            Ok(_) => Ok(()),
            Err(error) if is_missing_table_error(&error, "exchange_upload_queue") => Ok(()),
            Err(error) => Err(error.into()),
        }
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

fn exchange_event_to_metadata(event: &ExchangeEventV2) -> ExchangeMetadata {
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
        status_code: event.status_code,
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
        target_entity_id: event
            .parse
            .as_ref()
            .and_then(|value| value.target_entity_id.clone()),
        detection_source: event
            .parse
            .as_ref()
            .and_then(|value| value.detection_source.clone()),
        tags: event.tags.as_ref().map(tree_to_hash),
        event_envelope: build_exchange_event_envelope_metadata(event),
    }
}

fn merge_tags_for_exchange(
    global_tags: &BTreeMap<String, String>,
    event_tags: Option<&BTreeMap<String, String>>,
) -> Option<HashMap<String, String>> {
    merge_tags(global_tags, event_tags)
}

fn build_exchange_event_envelope_metadata(
    event: &ExchangeEventV2,
) -> Option<EventEnvelopeMetadata> {
    let (host, path) = split_endpoint_host_path(event.endpoint.as_deref());
    let tags = event.tags.as_ref();
    let process_executable = tags
        .and_then(|value| value.get("client.process_executable"))
        .cloned();
    let client = event.client.as_ref().map(|value| EventClientMetadata {
        pid: value.pid,
        bundle_id: value.bundle_id.clone(),
        process_name: value.process_name.clone(),
        process_executable,
        app_type: value.app_type.clone(),
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
            soth_core::types::exchange_v2::ExchangeSourceClass::Mcp => "wrap".to_string(),
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
    source: soth_core::types::exchange_v2::ExchangeSourceClass,
) -> &'static str {
    match source {
        soth_core::types::exchange_v2::ExchangeSourceClass::AiInference => "ai_inference",
        soth_core::types::exchange_v2::ExchangeSourceClass::AgentApp => "agent_app",
        soth_core::types::exchange_v2::ExchangeSourceClass::Mcp => "mcp",
        soth_core::types::exchange_v2::ExchangeSourceClass::Collector => "collector",
    }
}

fn exchange_transport_to_str(
    transport: soth_core::types::exchange_v2::ExchangeTransport,
) -> &'static str {
    match transport {
        soth_core::types::exchange_v2::ExchangeTransport::Http => "http",
        soth_core::types::exchange_v2::ExchangeTransport::Https => "https",
        soth_core::types::exchange_v2::ExchangeTransport::Ws => "ws",
        soth_core::types::exchange_v2::ExchangeTransport::Sse => "sse",
        soth_core::types::exchange_v2::ExchangeTransport::Ndjson => "ndjson",
        soth_core::types::exchange_v2::ExchangeTransport::Stdio => "stdio",
        soth_core::types::exchange_v2::ExchangeTransport::Jsonrpc => "jsonrpc",
    }
}

fn exchange_body_mode_to_str(mode: ExchangeBodyMode) -> &'static str {
    match mode {
        ExchangeBodyMode::Inline => "inline",
        ExchangeBodyMode::Offloaded => "offloaded",
        ExchangeBodyMode::PreviewOnly => "preview_only",
        ExchangeBodyMode::MetadataOnly => "metadata_only",
    }
}

fn is_missing_table_error(error: &rusqlite::Error, table: &str) -> bool {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = error {
        return message
            .to_ascii_lowercase()
            .contains(&format!("no such table: {}", table.to_ascii_lowercase()));
    }
    false
}

fn tree_to_hash(map: &BTreeMap<String, String>) -> HashMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn resolve_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}
