use crate::body_uploader::BodyUploader;
use crate::cache;
use crate::config_puller::ConfigPuller;
use crate::heartbeat::HeartbeatSender;
use crate::metadata_pusher::MetadataPusher;
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
}

#[derive(Debug, Clone)]
struct LoadedRows<T> {
    rows: Vec<T>,
    max_seq_seen: Option<i64>,
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
        let loaded = self.load_event_rows(last_seq, self.config.batch_size)?;
        let Some(max_seq_seen) = loaded.max_seq_seen else {
            return Ok(0);
        };

        if loaded.rows.is_empty() {
            self.write_cursor(SYNC_KEY_LAST_SYNCED_SEQ, max_seq_seen)?;
            return Ok(0);
        }

        let config_version = self.cached_config_version();
        let batch = loaded
            .rows
            .iter()
            .map(|row| self.wrap_event_to_metadata(&row.event))
            .collect::<Vec<_>>();

        let request = EventBatchRequest {
            agent_instance_id: self.config.agent_instance_id.clone(),
            config_version: config_version.clone(),
            batch,
        };

        match self.metadata_pusher.push_batch(&request).await {
            Ok(Some(response)) => {
                if response.config_changed {
                    if let Some(puller) = &self.config_puller {
                        if let Err(error) = puller.pull_once().await {
                            warn!("Cloud config refresh after metadata hint failed: {}", error);
                        }
                    }
                }

                if let Some(ack_seq) = contiguous_ack_seq(&loaded.rows, &response.errors) {
                    self.write_cursor(SYNC_KEY_LAST_SYNCED_SEQ, ack_seq)?;
                    self.mark_sync_success()?;
                    Ok(loaded.rows.iter().take_while(|r| r.seq <= ack_seq).count())
                } else {
                    self.set_sync_error("metadata_push_rejected_initial_event")?;
                    Ok(0)
                }
            }
            Ok(None) => {
                self.set_sync_error("metadata_push_non_success_status")?;
                Ok(0)
            }
            Err(error) => {
                self.set_sync_error(&format!("metadata_push_error: {error}"))?;
                Err(error)
            }
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
            let request_body = self.redact_payload(row.request_body.clone());
            let response_body = self.redact_payload(row.response_body.clone());

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
            let request_payload =
                load_retry_payload(&entry.request_body_b64, entry.request_body_path.as_ref());
            let response_payload =
                load_retry_payload(&entry.response_body_b64, entry.response_body_path.as_ref());

            if request_payload.is_none() && response_payload.is_none() {
                self.retry_queue.remove(&entry.event_id)?;
                continue;
            }

            match self
                .body_uploader
                .upload(
                    &entry.event_id,
                    self.redact_payload(request_payload),
                    self.redact_payload(response_payload),
                )
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

    fn wrap_event_to_metadata(&self, event: &WrapEvent) -> EventMetadata {
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

        let tags = merge_tags(&self.config.global_tags, event.tags.as_ref());
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
            let request_payload: Option<Vec<u8>> = row.get(2)?;
            let response_payload: Option<Vec<u8>> = row.get(3)?;
            let content_payload: Option<Vec<u8>> = row.get(4)?;

            let request_body = request_payload.or(content_payload);
            let response_body = response_payload;
            if request_body.is_none() && response_body.is_none() {
                continue;
            }

            loaded.rows.push(BodySyncRow {
                seq,
                event_id,
                request_body,
                response_body,
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

fn tree_to_hash(map: &BTreeMap<String, String>) -> HashMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn build_event_envelope_metadata(
    event: &WrapEvent,
    headers: Option<&HashMap<String, String>>,
) -> Option<EventEnvelopeMetadata> {
    let envelope = event.traffic_envelope.as_ref()?;
    let client_bundle_id = infer_bundle_id(envelope.process_executable.as_deref());
    let client = build_client_metadata(
        envelope.process_pid,
        client_bundle_id,
        infer_app_type(
            envelope.process_name.as_deref(),
            envelope.process_executable.as_deref(),
        ),
    );

    Some(EventEnvelopeMetadata {
        envelope_id: Some(envelope.envelope_id.clone()),
        request_id: envelope.request_id.clone(),
        capture_source: Some(match envelope.capture_source {
            CaptureSource::Proxy => "proxy".to_string(),
            CaptureSource::Wrap => "wrap".to_string(),
        }),
        source: Some(match envelope.source {
            TrafficSource::ProxyHudsucker => "proxy_hudsucker".to_string(),
            TrafficSource::McpStdio => "mcp_stdio".to_string(),
            TrafficSource::McpHttp => "mcp_http".to_string(),
        }),
        captured_at: Some(envelope.captured_at.to_rfc3339()),
        method: Some(envelope.method.clone()),
        provider: envelope.provider.clone(),
        host: envelope.host.clone(),
        path: envelope.path.clone(),
        model: envelope.model.clone(),
        agent: envelope.agent.clone(),
        did: envelope.did.clone(),
        key_id: envelope.key_id.clone(),
        signature_alg: envelope.signature_alg.clone(),
        signed_fields_version: envelope.signed_fields_version.clone(),
        signature: envelope.signature.clone(),
        body_hash: envelope.body_hash.clone(),
        headers: headers.cloned(),
        client,
    })
}

fn build_client_metadata(
    pid: Option<u32>,
    bundle_id: Option<String>,
    app_type: Option<String>,
) -> Option<EventClientMetadata> {
    if pid.is_none() && bundle_id.is_none() && app_type.is_none() {
        return None;
    }
    Some(EventClientMetadata {
        pid,
        bundle_id,
        app_type,
    })
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
        assert_eq!(
            infer_bundle_id(executable).as_deref(),
            Some("macos.cursor")
        );
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
}
