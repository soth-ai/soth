use crate::body_uploader::BodyUploader;
use crate::cache;
use crate::config_puller::ConfigPuller;
use crate::heartbeat::HeartbeatSender;
use crate::metadata_pusher::{estimate_gzip_batch_size, MetadataPusher};
use crate::retry_queue::{BodyRetryQueue, RetryQueueEntry};
use anyhow::Context;
use base64::Engine as _;
use chrono::Utc;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use soth_core::api::{
    EventBatchRequest, EventClientMetadata, EventEnvelopeMetadata, EventError, EventMetadata,
    HeartbeatRequest,
};
use soth_core::event_logger::{
    SYNC_KEY_LAST_BODY_SYNCED_SEQ, SYNC_KEY_LAST_SYNCED_SEQ, SYNC_KEY_LAST_SYNC_TIMESTAMP,
    SYNC_KEY_SYNC_ERRORS,
};
use soth_core::types::{CaptureSource, EventSource, TrafficSource, WrapDirection, WrapEvent};
use soth_observe::PiiRedactor;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;
const MAX_RETRY_UPLOADS_PER_TICK: usize = 32;
const MAX_METADATA_BATCH_EVENTS_HARD_CAP: usize = 200;
const MAX_METADATA_BATCH_COMPRESSED_BYTES_HARD_CAP: usize = 5 * 1024 * 1024;
const DEFAULT_BODY_UPLOAD_MAX_BYTES: usize = 15 * 1024 * 1024;

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
}

pub struct SyncAgent {
    pub config: SyncAgentConfig,
    pub metadata_pusher: MetadataPusher,
    pub body_uploader: BodyUploader,
    pub heartbeat_sender: HeartbeatSender,
    pub retry_queue: BodyRetryQueue,
    pub config_puller: Option<ConfigPuller>,
    pii_redactor: PiiRedactor,
}

#[derive(Debug, Clone, Default)]
pub struct SyncTickSummary {
    pub metadata_sent: usize,
    pub body_uploaded: usize,
    pub retry_uploaded: usize,
}

#[derive(Debug, Clone)]
struct SyncedEventRow {
    seq: i64,
    event: WrapEvent,
}

#[derive(Debug, Clone)]
struct BodySyncRow {
    seq: i64,
    event_id: String,
    request_body: Option<Vec<u8>>,
    response_body: Option<Vec<u8>>,
    metadata_only_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct LoadedRows<T> {
    rows: Vec<T>,
    max_seq_seen: Option<i64>,
}

#[derive(Debug, Clone, Default)]
struct MetadataPushResult {
    ack_seq: Option<i64>,
    sent: usize,
    config_changed: bool,
    fully_processed: bool,
}

impl MetadataPushResult {
    fn merge(mut self, other: MetadataPushResult) -> MetadataPushResult {
        self.ack_seq = other.ack_seq.or(self.ack_seq);
        self.sent += other.sent;
        self.config_changed = self.config_changed || other.config_changed;
        self.fully_processed = self.fully_processed && other.fully_processed;
        self
    }
}

impl<T> Default for LoadedRows<T> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            max_seq_seen: None,
        }
    }
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
        if config.body_upload_max_bytes == 0 {
            config.body_upload_max_bytes = DEFAULT_BODY_UPLOAD_MAX_BYTES;
        }
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
            pii_redactor: PiiRedactor::new().with_preserve_length(false),
        })
    }

    pub async fn tick(&self) -> anyhow::Result<SyncTickSummary> {
        let metadata_sent = self.sync_metadata_once().await?;

        let mut retry_uploaded = 0;
        let mut body_uploaded = 0;
        if self.body_upload_allowed() {
            retry_uploaded = self.process_retry_queue_once().await?;
            body_uploaded = self.sync_bodies_once().await?;
        }

        Ok(SyncTickSummary {
            metadata_sent,
            body_uploaded,
            retry_uploaded,
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

            if summary.metadata_sent == 0
                && summary.body_uploaded == 0
                && summary.retry_uploaded == 0
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

    async fn sync_metadata_once(&self) -> anyhow::Result<usize> {
        let last_seq = self.read_cursor(SYNC_KEY_LAST_SYNCED_SEQ)?;
        let fetch_limit = self
            .config
            .batch_size
            .max(1)
            .min(self.config.metadata_max_events_per_batch);
        let loaded = self.load_event_rows(last_seq, fetch_limit)?;
        let Some(max_seq_seen) = loaded.max_seq_seen else {
            return Ok(0);
        };

        if loaded.rows.is_empty() {
            self.write_cursor(SYNC_KEY_LAST_SYNCED_SEQ, max_seq_seen)?;
            return Ok(0);
        }

        let config_version = self.cached_config_version();
        match self
            .push_rows_with_size_limits(&loaded.rows, config_version.as_ref())
            .await
        {
            Ok(push) => {
                if push.config_changed {
                    if let Some(puller) = &self.config_puller {
                        if let Err(error) = puller.pull_once().await {
                            warn!("Cloud config refresh after metadata hint failed: {}", error);
                        }
                    }
                }

                if let Some(ack_seq) = push.ack_seq {
                    self.write_cursor(SYNC_KEY_LAST_SYNCED_SEQ, ack_seq)?;
                    self.mark_sync_success()?;
                    Ok(push.sent)
                } else {
                    self.set_sync_error("metadata_push_rejected_initial_event")?;
                    Ok(0)
                }
            }
            Err(error) => {
                self.set_sync_error(&format!("metadata_push_error: {error}"))?;
                Err(error)
            }
        }
    }

    async fn push_rows_with_size_limits(
        &self,
        rows: &[SyncedEventRow],
        config_version: Option<&String>,
    ) -> anyhow::Result<MetadataPushResult> {
        if rows.is_empty() {
            return Ok(MetadataPushResult::default());
        }
        let mut overall = MetadataPushResult {
            fully_processed: true,
            ..MetadataPushResult::default()
        };
        let mut stack: Vec<&[SyncedEventRow]> = vec![rows];
        while let Some(chunk) = stack.pop() {
            if chunk.is_empty() {
                continue;
            }

            if chunk.len() > self.config.metadata_max_events_per_batch {
                let split = self.config.metadata_max_events_per_batch.min(chunk.len());
                stack.push(&chunk[split..]);
                stack.push(&chunk[..split]);
                continue;
            }

            let batch = chunk
                .iter()
                .map(|row| self.wrap_event_to_metadata_with_sync_tags(&row.event))
                .collect::<Vec<_>>();
            let request = EventBatchRequest {
                agent_instance_id: self.config.agent_instance_id.clone(),
                config_version: config_version.cloned(),
                batch,
            };
            let compressed_size = estimate_gzip_batch_size(&request)?;
            if compressed_size > self.config.metadata_max_compressed_batch_bytes {
                if chunk.len() == 1 {
                    let mut fallback = self.wrap_event_to_metadata_with_sync_tags(&chunk[0].event);
                    mark_metadata_only_fallback(
                        &mut fallback,
                        "compressed_batch_limit",
                        self.config.metadata_max_compressed_batch_bytes,
                    );
                    let fallback_request = EventBatchRequest {
                        agent_instance_id: self.config.agent_instance_id.clone(),
                        config_version: config_version.cloned(),
                        batch: vec![fallback],
                    };
                    let fallback_size = estimate_gzip_batch_size(&fallback_request)?;
                    if fallback_size > self.config.metadata_max_compressed_batch_bytes {
                        warn!(
                            event_id = %chunk[0].event.id,
                            compressed_size = fallback_size,
                            limit = self.config.metadata_max_compressed_batch_bytes,
                            "Metadata-only fallback still exceeds compressed batch limit; deferring event"
                        );
                        overall.fully_processed = false;
                        return Ok(overall);
                    }

                    let single = self.push_metadata_request(&fallback_request, chunk).await?;
                    overall = overall.merge(single.clone());
                    if !single.fully_processed {
                        overall.fully_processed = false;
                        return Ok(overall);
                    }
                    continue;
                }

                let mid = chunk.len() / 2;
                stack.push(&chunk[mid..]);
                stack.push(&chunk[..mid]);
                continue;
            }

            let result = self.push_metadata_request(&request, chunk).await?;
            overall = overall.merge(result.clone());
            if !result.fully_processed {
                overall.fully_processed = false;
                return Ok(overall);
            }
        }
        Ok(overall)
    }

    async fn push_metadata_request(
        &self,
        request: &EventBatchRequest,
        rows: &[SyncedEventRow],
    ) -> anyhow::Result<MetadataPushResult> {
        match self.metadata_pusher.push_batch(request).await? {
            Some(response) => {
                if let Some(ack_seq) = contiguous_ack_seq(rows, &response.errors) {
                    let sent = rows.iter().take_while(|row| row.seq <= ack_seq).count();
                    Ok(MetadataPushResult {
                        ack_seq: Some(ack_seq),
                        sent,
                        config_changed: response.config_changed,
                        fully_processed: sent == rows.len(),
                    })
                } else {
                    Ok(MetadataPushResult {
                        ack_seq: None,
                        sent: 0,
                        config_changed: response.config_changed,
                        fully_processed: false,
                    })
                }
            }
            None => Ok(MetadataPushResult::default()),
        }
    }

    async fn sync_bodies_once(&self) -> anyhow::Result<usize> {
        let last_seq = self.read_cursor(SYNC_KEY_LAST_BODY_SYNCED_SEQ)?;
        let loaded = self.load_body_rows(last_seq, self.config.body_batch_size)?;
        let Some(max_seq_seen) = loaded.max_seq_seen else {
            return Ok(0);
        };

        if loaded.rows.is_empty() {
            self.write_cursor(SYNC_KEY_LAST_BODY_SYNCED_SEQ, max_seq_seen)?;
            return Ok(0);
        }

        let mut ack_seq: Option<i64> = None;
        let mut uploaded = 0usize;

        for row in &loaded.rows {
            if row.metadata_only_reason.is_some() {
                ack_seq = Some(row.seq);
                continue;
            }

            let request_body = self.cap_payload_for_upload(
                &row.event_id,
                "request",
                self.redact_payload(row.request_body.clone()),
            );
            let response_body = self.cap_payload_for_upload(
                &row.event_id,
                "response",
                self.redact_payload(row.response_body.clone()),
            );

            if request_body.is_none() && response_body.is_none() {
                ack_seq = Some(row.seq);
                continue;
            }

            match self
                .body_uploader
                .upload(&row.event_id, request_body.clone(), response_body.clone())
                .await
            {
                Ok(Some(_)) => {
                    ack_seq = Some(row.seq);
                    uploaded += 1;
                }
                Ok(None) => {
                    let entry = RetryQueueEntry::from_payloads(
                        row.event_id.clone(),
                        request_body,
                        response_body,
                    );
                    self.retry_queue.enqueue(&entry)?;
                    ack_seq = Some(row.seq);
                }
                Err(error) => {
                    let entry = RetryQueueEntry::from_payloads(
                        row.event_id.clone(),
                        request_body,
                        response_body,
                    );
                    self.retry_queue.enqueue(&entry)?;
                    self.retry_queue
                        .mark_error(&row.event_id, error.to_string())?;
                    ack_seq = Some(row.seq);
                }
            }
        }

        if let Some(seq) = ack_seq {
            self.write_cursor(SYNC_KEY_LAST_BODY_SYNCED_SEQ, seq)?;
            self.mark_sync_success()?;
        }

        Ok(uploaded)
    }

    async fn process_retry_queue_once(&self) -> anyhow::Result<usize> {
        let entries = self.retry_queue.list()?;
        let mut uploaded = 0usize;
        for entry in entries.into_iter().take(MAX_RETRY_UPLOADS_PER_TICK) {
            if self
                .metadata_only_reason_for_event_id(&entry.event_id)?
                .is_some()
            {
                self.retry_queue.remove(&entry.event_id)?;
                continue;
            }

            let request_payload =
                load_retry_payload(&entry.request_body_b64, entry.request_body_path.as_ref());
            let response_payload =
                load_retry_payload(&entry.response_body_b64, entry.response_body_path.as_ref());

            if request_payload.is_none() && response_payload.is_none() {
                self.retry_queue.remove(&entry.event_id)?;
                continue;
            }

            let request_payload = self.cap_payload_for_upload(
                &entry.event_id,
                "request",
                self.redact_payload(request_payload),
            );
            let response_payload = self.cap_payload_for_upload(
                &entry.event_id,
                "response",
                self.redact_payload(response_payload),
            );
            if request_payload.is_none() && response_payload.is_none() {
                self.retry_queue.remove(&entry.event_id)?;
                continue;
            }

            match self
                .body_uploader
                .upload(&entry.event_id, request_payload, response_payload)
                .await
            {
                Ok(Some(_)) => {
                    self.retry_queue.remove(&entry.event_id)?;
                    uploaded += 1;
                }
                Ok(None) => {
                    self.retry_queue
                        .mark_error(&entry.event_id, "body_upload_non_success_status")?;
                }
                Err(error) => {
                    self.retry_queue
                        .mark_error(&entry.event_id, error.to_string())?;
                }
            }
        }
        Ok(uploaded)
    }

    fn wrap_event_to_metadata_with_sync_tags(&self, event: &WrapEvent) -> EventMetadata {
        let source = match event.source {
            EventSource::Mcp => "mcp",
            EventSource::AiProxy => "ai_proxy",
            EventSource::AgentApp => "agent_app",
        }
        .to_string();

        let direction = match event.direction {
            WrapDirection::In => "in",
            WrapDirection::Out => "out",
        }
        .to_string();

        let has_body = event.content_ref.is_some()
            || event.request_content_ref.is_some()
            || event.response_content_ref.is_some();

        let mut tags =
            merge_tags(&self.config.global_tags, event.tags.as_ref()).unwrap_or_default();
        if let Some(reason) = metadata_only_body_upload_reason(event) {
            tags.insert(
                "sync.body_upload_policy".to_string(),
                "metadata_only".to_string(),
            );
            tags.insert(
                "sync.body_upload_policy_reason".to_string(),
                reason.to_string(),
            );
        }
        if event.request_size_bytes.unwrap_or(0) as usize > self.config.body_upload_max_bytes
            || event.response_size_bytes.unwrap_or(0) as usize > self.config.body_upload_max_bytes
        {
            tags.insert(
                "sync.body_upload_fallback".to_string(),
                "metadata_only".to_string(),
            );
            tags.insert(
                "sync.body_upload_limit_bytes".to_string(),
                self.config.body_upload_max_bytes.to_string(),
            );
        }
        let tags = if tags.is_empty() { None } else { Some(tags) };
        let headers = event.headers.as_ref().map(tree_to_hash);
        let event_envelope = build_event_envelope_metadata(event, headers.as_ref());

        EventMetadata {
            id: event.id.clone(),
            timestamp: event.timestamp.to_rfc3339(),
            session_id: Some(event.session_id.clone()),
            source,
            direction,
            provider: event.provider.clone(),
            model: event.model.clone(),
            method: event.method.clone(),
            status_code: event.status_code,
            latency_ms: event.latency_ms,
            input_tokens: event.input_tokens,
            output_tokens: event.output_tokens,
            cache_read_tokens: event.cache_read_tokens,
            cache_write_tokens: event.cache_write_tokens,
            reasoning_tokens: event.reasoning_tokens,
            cost_usd: event.cost_usd,
            request_size_bytes: event.request_size_bytes,
            response_size_bytes: event.response_size_bytes,
            has_body,
            pii_detected: event.pii_detected,
            pii_types: event.pii_types.clone(),
            policy_allowed: event.policy_allowed,
            policy_version: event.policy_version.clone(),
            agent_name: Some(event.agent.name.clone()),
            server_name: Some(event.server_name.clone()),
            headers,
            mcp_tool_name: event.tool_name.clone(),
            mcp_body_truncated: event.source == EventSource::Mcp && has_body,
            mcp_body_preview: event
                .content_preview
                .clone()
                .or(event.request_preview.clone())
                .or(event.response_preview.clone()),
            tags,
            event_envelope,
        }
    }

    fn load_event_rows(
        &self,
        last_seq: i64,
        limit: usize,
    ) -> anyhow::Result<LoadedRows<SyncedEventRow>> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT seq, event_json
            FROM wrap_events
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;

        let mut loaded = LoadedRows::<SyncedEventRow>::default();
        let mut rows = stmt.query(params![last_seq, limit as i64])?;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            loaded.max_seq_seen = Some(seq);
            let event_json: String = row.get(1)?;
            match serde_json::from_str::<WrapEvent>(&event_json) {
                Ok(mut event) => {
                    event.seq = Some(seq);
                    loaded.rows.push(SyncedEventRow { seq, event });
                }
                Err(error) => {
                    warn!(
                        "Skipping malformed wrap_event seq={} during metadata sync: {}",
                        seq, error
                    );
                }
            }
        }

        Ok(loaded)
    }

    fn load_body_rows(
        &self,
        last_seq: i64,
        limit: usize,
    ) -> anyhow::Result<LoadedRows<BodySyncRow>> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                we.seq,
                we.id,
                we.event_json,
                req.payload AS request_payload,
                resp.payload AS response_payload,
                content.payload AS content_payload
            FROM wrap_events we
            LEFT JOIN wrap_event_payloads req
              ON req.event_id = we.id AND req.payload_kind = 'request'
            LEFT JOIN wrap_event_payloads resp
              ON resp.event_id = we.id AND resp.payload_kind = 'response'
            LEFT JOIN wrap_event_payloads content
              ON content.event_id = we.id AND content.payload_kind = 'content'
            WHERE we.seq > ?1
            ORDER BY we.seq ASC
            LIMIT ?2
            "#,
        )?;

        let mut loaded = LoadedRows::<BodySyncRow>::default();
        let mut rows = stmt.query(params![last_seq, limit as i64])?;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            loaded.max_seq_seen = Some(seq);

            let event_id: String = row.get(1)?;
            let event_json: String = row.get(2)?;
            let metadata_only_reason = serde_json::from_str::<WrapEvent>(&event_json)
                .ok()
                .and_then(|event| metadata_only_body_upload_reason(&event))
                .map(str::to_string);
            let request_payload: Option<Vec<u8>> = row.get(3)?;
            let response_payload: Option<Vec<u8>> = row.get(4)?;
            let content_payload: Option<Vec<u8>> = row.get(5)?;

            let inline = inline_payloads_from_event_json(&event_json);
            let request_body = request_payload
                .or_else(|| inline.request_payload.clone())
                .or_else(|| {
                    if inline.direction.as_deref() == Some("in") {
                        content_payload.clone().or(inline.content_payload.clone())
                    } else {
                        None
                    }
                });
            let response_body = response_payload
                .or_else(|| inline.response_payload)
                .or_else(|| {
                    if inline.direction.as_deref() == Some("out") {
                        content_payload.or(inline.content_payload)
                    } else {
                        None
                    }
                });
            if request_body.is_none() && response_body.is_none() {
                continue;
            }

            loaded.rows.push(BodySyncRow {
                seq,
                event_id,
                request_body,
                response_body,
                metadata_only_reason,
            });
        }

        Ok(loaded)
    }

    fn body_upload_allowed(&self) -> bool {
        if !self.config.body_upload_enabled {
            return false;
        }

        match cache::load_config_cache(&self.config.cache_path) {
            Ok(Some(config)) => config.body_sync_level != "metadata_only",
            Ok(None) => self.config.body_upload_enabled,
            Err(error) => {
                warn!("Failed reading cloud cache for body sync mode: {}", error);
                self.config.body_upload_enabled
            }
        }
    }

    fn cached_config_version(&self) -> Option<String> {
        cache::load_config_cache(&self.config.cache_path)
            .ok()
            .flatten()
            .map(|config| config.config_version)
    }

    fn metadata_only_reason_for_event_id(&self, event_id: &str) -> anyhow::Result<Option<String>> {
        let conn = open_read_conn(&self.config.event_db_path)?;
        let event_json: Option<String> = conn
            .query_row(
                "SELECT event_json FROM wrap_events WHERE id = ?1 LIMIT 1",
                [event_id],
                |row| row.get(0),
            )
            .optional()?;
        let reason = event_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<WrapEvent>(raw).ok())
            .and_then(|event| metadata_only_body_upload_reason(&event))
            .map(str::to_string);
        Ok(reason)
    }

    fn redact_payload(&self, payload: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let payload = payload?;
        if payload.is_empty() {
            return Some(payload);
        }

        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) {
            let (redacted, _) = self.pii_redactor.redact_json(&value);
            return serde_json::to_vec(&redacted).ok().or(Some(payload));
        }

        if let Ok(text) = std::str::from_utf8(&payload) {
            let redacted = self.pii_redactor.redact(text);
            return Some(redacted.text.into_bytes());
        }

        Some(payload)
    }

    fn cap_payload_for_upload(
        &self,
        event_id: &str,
        kind: &str,
        payload: Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let payload = payload?;
        if payload.len() > self.config.body_upload_max_bytes {
            warn!(
                event_id = %event_id,
                kind = kind,
                size = payload.len(),
                limit = self.config.body_upload_max_bytes,
                "Skipping oversized body payload upload"
            );
            return None;
        }
        Some(payload)
    }

    fn read_cursor(&self, key: &str) -> anyhow::Result<i64> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        ensure_sync_state_table(&conn)?;
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0))
    }

    fn write_cursor(&self, key: &str, seq: i64) -> anyhow::Result<()> {
        self.write_sync_value(key, &seq.to_string())
    }

    fn write_sync_value(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = open_rw_conn(&self.config.event_db_path)?;
        ensure_sync_state_table(&conn)?;
        conn.execute(
            r#"
            INSERT INTO sync_state (key, value, updated_at)
            VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
            params![key, value],
        )?;
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
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("failed opening sqlite read connection {}", path.display()))?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
    Ok(conn)
}

fn open_rw_conn(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed opening sqlite rw connection {}", path.display()))?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
    Ok(conn)
}

fn ensure_sync_state_table(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn contiguous_ack_seq(rows: &[SyncedEventRow], errors: &[EventError]) -> Option<i64> {
    if rows.is_empty() {
        return None;
    }
    let rejected = errors
        .iter()
        .map(|error| error.event_id.as_str())
        .collect::<HashSet<_>>();

    let mut ack_seq = None;
    for row in rows {
        if rejected.contains(row.event.id.as_str()) {
            break;
        }
        ack_seq = Some(row.seq);
    }
    ack_seq
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

fn mark_metadata_only_fallback(metadata: &mut EventMetadata, reason: &str, limit_bytes: usize) {
    metadata.headers = None;
    if let Some(ref mut envelope) = metadata.event_envelope {
        envelope.headers = None;
    }
    metadata.mcp_body_preview = metadata
        .mcp_body_preview
        .as_deref()
        .map(|value| value.chars().take(64).collect::<String>());
    let tags = metadata.tags.get_or_insert_with(HashMap::new);
    tags.insert(
        "sync.metadata_fallback".to_string(),
        "metadata_only".to_string(),
    );
    tags.insert(
        "sync.metadata_fallback_reason".to_string(),
        reason.to_string(),
    );
    tags.insert(
        "sync.metadata_limit_bytes".to_string(),
        limit_bytes.to_string(),
    );
}

fn metadata_only_body_upload_reason(event: &WrapEvent) -> Option<&'static str> {
    let method = event
        .method
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if method.starts_with("websocket ") {
        return Some("websocket_payload");
    }

    let provider = event
        .provider
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let model = event
        .model
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let agent = event.agent.name.to_ascii_lowercase();
    let path = event
        .traffic_envelope
        .as_ref()
        .and_then(|envelope| envelope.path.as_deref())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if provider == "chatgpt"
        && (method.contains("/backend-api/codex/")
            || path.contains("/backend-api/codex/")
            || model.contains("codex")
            || agent == "codex")
    {
        return Some("codex_payload");
    }

    None
}

fn tree_to_hash(map: &BTreeMap<String, String>) -> HashMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn build_event_envelope_metadata(
    event: &WrapEvent,
    headers: Option<&HashMap<String, String>>,
) -> Option<EventEnvelopeMetadata> {
    let envelope = event.traffic_envelope.as_ref();
    let process_pid = envelope.and_then(|value| value.process_pid);
    let process_name = envelope.and_then(|value| value.process_name.clone());
    let process_executable = envelope.and_then(|value| value.process_executable.clone());
    let client_bundle_id = infer_bundle_id(process_executable.as_deref());
    let client = build_client_metadata(
        process_pid,
        client_bundle_id,
        infer_app_type(process_name.as_deref(), process_executable.as_deref()),
        process_name,
        process_executable,
    );
    let collector_source = event.collector_source.clone();
    let collector_offset = event.collector_offset;

    if envelope.is_none()
        && client.is_none()
        && collector_source.is_none()
        && collector_offset.is_none()
    {
        return None;
    }

    Some(EventEnvelopeMetadata {
        envelope_id: envelope.map(|value| value.envelope_id.clone()),
        request_id: envelope.and_then(|value| value.request_id.clone()),
        capture_source: envelope.map(|value| match value.capture_source {
            CaptureSource::Proxy => "proxy".to_string(),
            CaptureSource::Wrap => "wrap".to_string(),
        }),
        source: envelope.map(|value| match value.source {
            TrafficSource::ProxyHudsucker => "proxy_hudsucker".to_string(),
            TrafficSource::McpStdio => "mcp_stdio".to_string(),
            TrafficSource::McpHttp => "mcp_http".to_string(),
        }),
        captured_at: envelope.map(|value| value.captured_at.to_rfc3339()),
        method: envelope.map(|value| value.method.clone()),
        provider: envelope.and_then(|value| value.provider.clone()),
        host: envelope.and_then(|value| value.host.clone()),
        path: envelope.and_then(|value| value.path.clone()),
        model: envelope.and_then(|value| value.model.clone()),
        agent: envelope.and_then(|value| value.agent.clone()),
        did: envelope.and_then(|value| value.did.clone()),
        key_id: envelope.and_then(|value| value.key_id.clone()),
        signature_alg: envelope.and_then(|value| value.signature_alg.clone()),
        signed_fields_version: envelope.and_then(|value| value.signed_fields_version.clone()),
        signature: envelope.and_then(|value| value.signature.clone()),
        body_hash: envelope.and_then(|value| value.body_hash.clone()),
        headers: headers.cloned(),
        client,
        collector_source,
        collector_offset,
    })
}

fn build_client_metadata(
    pid: Option<u32>,
    bundle_id: Option<String>,
    app_type: Option<String>,
    process_name: Option<String>,
    process_executable: Option<String>,
) -> Option<EventClientMetadata> {
    if pid.is_none()
        && bundle_id.is_none()
        && app_type.is_none()
        && process_name.is_none()
        && process_executable.is_none()
    {
        return None;
    }
    Some(EventClientMetadata {
        pid,
        bundle_id,
        process_name,
        process_executable,
        app_type,
    })
}

#[derive(Debug, Clone, Default)]
struct InlinePayloads {
    request_payload: Option<Vec<u8>>,
    response_payload: Option<Vec<u8>>,
    content_payload: Option<Vec<u8>>,
    direction: Option<String>,
}

fn inline_payloads_from_event_json(raw: &str) -> InlinePayloads {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return InlinePayloads::default();
    };
    InlinePayloads {
        request_payload: value
            .get("request_content")
            .and_then(serde_json::Value::as_str)
            .map(|text| text.as_bytes().to_vec()),
        response_payload: value
            .get("response_content")
            .and_then(serde_json::Value::as_str)
            .map(|text| text.as_bytes().to_vec()),
        content_payload: value
            .get("content")
            .and_then(serde_json::Value::as_str)
            .map(|text| text.as_bytes().to_vec()),
        direction: value
            .get("direction")
            .and_then(serde_json::Value::as_str)
            .map(|value| value.to_ascii_lowercase()),
    }
}

fn infer_bundle_id(process_executable: Option<&str>) -> Option<String> {
    let executable = process_executable?.trim();
    if executable.is_empty() {
        return None;
    }

    let lower = executable.to_ascii_lowercase();
    if let Some(idx) = lower.find(".app/") {
        let app_root = &executable[..idx + 4];
        let app_name = app_root
            .rsplit('/')
            .next()
            .unwrap_or(app_root)
            .trim_end_matches(".app")
            .trim();
        if app_name.is_empty() {
            return None;
        }
        return Some(format!("macos.{}", slug_token(app_name)));
    }

    if lower.ends_with(".app") {
        let app_name = executable
            .rsplit('/')
            .next()
            .unwrap_or(executable)
            .trim_end_matches(".app")
            .trim();
        if app_name.is_empty() {
            return None;
        }
        return Some(format!("macos.{}", slug_token(app_name)));
    }

    None
}

fn infer_app_type(process_name: Option<&str>, process_executable: Option<&str>) -> Option<String> {
    if process_name.is_none() && process_executable.is_none() {
        return None;
    }

    if infer_bundle_id(process_executable).is_some() {
        return Some("desktop_app".to_string());
    }

    let name_lc = process_name.unwrap_or("").to_ascii_lowercase();
    let exe_lc = process_executable.unwrap_or("").to_ascii_lowercase();
    if name_lc.contains("daemon")
        || name_lc.contains("service")
        || exe_lc.contains("/launchd")
        || exe_lc.contains("systemd")
    {
        return Some("service".to_string());
    }

    Some("cli".to_string())
}

fn slug_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn load_retry_payload(payload_b64: &Option<String>, path: Option<&PathBuf>) -> Option<Vec<u8>> {
    if let Some(encoded) = payload_b64.as_ref() {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
            return Some(bytes);
        }
    }
    let path = path?;
    std::fs::read(path).ok()
}

fn resolve_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, TrafficEnvelope};

    #[test]
    fn infer_bundle_and_app_type_for_macos_app_paths() {
        let executable = Some("/Applications/Cursor.app/Contents/MacOS/Cursor");
        assert_eq!(infer_bundle_id(executable).as_deref(), Some("macos.cursor"));
        assert_eq!(
            infer_app_type(Some("Cursor"), executable).as_deref(),
            Some("desktop_app")
        );
    }

    #[test]
    fn infer_app_type_for_cli_paths() {
        let executable = Some("/usr/local/bin/codex");
        assert_eq!(infer_bundle_id(executable), None);
        assert_eq!(
            infer_app_type(Some("codex"), executable).as_deref(),
            Some("cli")
        );
    }

    #[test]
    fn event_envelope_metadata_includes_client_and_headers() {
        let mut event = WrapEvent::new(
            "session-1",
            "chatgpt.com",
            WrapDirection::Out,
            AgentInfo::new("codex", DetectionSource::CommandLine),
        )
        .with_source(EventSource::AgentApp);
        let mut envelope = TrafficEnvelope::proxy(
            "session-1",
            "request-1",
            "chatgpt",
            "chatgpt.com",
            "POST",
            "/backend-api/codex/responses",
            Some("gpt-5.3-codex"),
            Some("codex"),
            None,
            None,
            None,
        );
        envelope.process_pid = Some(4242);
        envelope.process_name = Some("Cursor".to_string());
        envelope.process_executable = Some("/Applications/Cursor.app/Contents/MacOS/Cursor".into());
        event = event.with_traffic_envelope(envelope);

        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "req_123".to_string());
        let mapped = build_event_envelope_metadata(&event, Some(&headers)).expect("envelope");
        let client = mapped.client.expect("client");
        assert_eq!(client.pid, Some(4242));
        assert_eq!(client.bundle_id.as_deref(), Some("macos.cursor"));
        assert_eq!(client.app_type.as_deref(), Some("desktop_app"));
        assert_eq!(
            mapped
                .headers
                .as_ref()
                .and_then(|h| h.get("x-request-id"))
                .map(String::as_str),
            Some("req_123")
        );
    }

    #[test]
    fn event_envelope_metadata_includes_collector_fields_without_traffic_envelope() {
        let event = WrapEvent::new(
            "session-collector",
            "collector-source",
            WrapDirection::In,
            AgentInfo::new("collector", DetectionSource::Environment),
        )
        .with_source(EventSource::AgentApp)
        .with_collector_metadata("collector-file", 42);

        let mapped = build_event_envelope_metadata(&event, None).expect("envelope");
        assert_eq!(mapped.collector_source.as_deref(), Some("collector-file"));
        assert_eq!(mapped.collector_offset, Some(42));
        assert!(mapped.client.is_none());
        assert!(mapped.envelope_id.is_none());
    }

    #[test]
    fn metadata_only_body_upload_reason_flags_websocket_events() {
        let event = WrapEvent::new(
            "session-1",
            "ws.chatgpt.com",
            WrapDirection::Out,
            AgentInfo::new("chatgpt", DetectionSource::Environment),
        )
        .with_source(EventSource::AgentApp)
        .with_provider("chatgpt")
        .with_method("WebSocket /c2/ws/user/abc");

        assert_eq!(
            metadata_only_body_upload_reason(&event),
            Some("websocket_payload")
        );
    }

    #[test]
    fn metadata_only_body_upload_reason_flags_codex_payloads() {
        let event = WrapEvent::new(
            "session-1",
            "chatgpt.com",
            WrapDirection::Out,
            AgentInfo::new("codex", DetectionSource::Environment),
        )
        .with_source(EventSource::AgentApp)
        .with_provider("chatgpt")
        .with_model("gpt-5.3-codex")
        .with_method("POST /backend-api/codex/responses");

        assert_eq!(
            metadata_only_body_upload_reason(&event),
            Some("codex_payload")
        );
    }
}
