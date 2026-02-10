//! Event logger for writing `WrapEvent`s.
//!
//! The logger writes to SQLite (`events.db`) for low-latency durable writes.
//!
//! Used by both `soth wrap` (stdio interception) and soth proxy (HTTP interception)
//! to emit events that appear in the observability dashboard.

use crate::types::WrapEvent;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::warn;

pub const EVENT_LOG_SQLITE_FILE: &str = "events.db";
pub const SYNC_KEY_LAST_SYNCED_SEQ: &str = "last_synced_seq";
pub const SYNC_KEY_LAST_BODY_SYNCED_SEQ: &str = "last_body_synced_seq";
pub const SYNC_KEY_LAST_SYNC_TIMESTAMP: &str = "last_sync_timestamp";
pub const SYNC_KEY_SYNC_ERRORS: &str = "sync_errors";

const SQLITE_QUEUE_CAPACITY: usize = 4096;
const SQLITE_BATCH_SIZE: usize = 64;
const SQLITE_FLUSH_INTERVAL_MS: u64 = 20;
const INLINE_PAYLOAD_MAX_BYTES: usize = 16 * 1024;
const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;

enum EventLoggerStorage {
    SqliteAsync {
        tx: SyncSender<LoggerCommand>,
        worker: Option<JoinHandle<()>>,
    },
}

enum LoggerCommand {
    Event(WrapEvent),
    Flush(std::sync::mpsc::Sender<std::io::Result<()>>),
    Shutdown,
}

struct PayloadBlob {
    kind: &'static str,
    bytes: Vec<u8>,
}

/// Persistent sync cursors and status state for cloud synchronization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncCursorState {
    pub last_synced_seq: Option<i64>,
    pub last_body_synced_seq: Option<i64>,
    pub last_sync_timestamp: Option<String>,
    pub sync_errors: Option<String>,
}

/// Event logger that writes `WrapEvent`s to SQLite.
#[derive(Clone)]
pub struct EventLogger {
    inner: Arc<Mutex<Option<EventLoggerStorage>>>,
    path: PathBuf,
}

impl EventLogger {
    /// Create a new event logger that writes to the given path.
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        Self::new_with_inline_payload_max_bytes(path, INLINE_PAYLOAD_MAX_BYTES)
    }

    /// Create a new event logger that writes to the given path and applies a custom
    /// inline payload threshold before side-table offload.
    pub fn new_with_inline_payload_max_bytes(
        path: PathBuf,
        inline_payload_max_bytes: usize,
    ) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&path).map_err(to_io_err)?;
        init_sqlite_schema(&conn)?;
        drop(conn);

        let inline_payload_max_bytes = inline_payload_max_bytes.max(1);
        let (tx, rx) = mpsc::sync_channel(SQLITE_QUEUE_CAPACITY);
        let worker_path = path.clone();
        let worker = std::thread::Builder::new()
            .name("soth-event-sqlite-writer".to_string())
            .spawn(move || run_sqlite_writer(worker_path, rx, inline_payload_max_bytes))
            .map_err(std::io::Error::other)?;

        let storage = EventLoggerStorage::SqliteAsync {
            tx,
            worker: Some(worker),
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(Some(storage))),
            path,
        })
    }

    /// Create an event logger with the default write path (`~/.soth/logs/events.db`).
    pub fn with_default_path() -> std::io::Result<Self> {
        Self::with_default_path_with_inline_payload_max_bytes(INLINE_PAYLOAD_MAX_BYTES)
    }

    /// Create an event logger with the default write path and custom inline threshold.
    pub fn with_default_path_with_inline_payload_max_bytes(
        inline_payload_max_bytes: usize,
    ) -> std::io::Result<Self> {
        Self::new_with_inline_payload_max_bytes(
            default_event_log_write_path()?,
            inline_payload_max_bytes,
        )
    }

    /// Get the path this logger writes to.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Read a sync-state value from SQLite.
    pub fn get_sync_state(&self, key: &str) -> std::io::Result<Option<String>> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.query_row(
            "SELECT value FROM sync_state WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(to_io_err)
    }

    /// Upsert a sync-state value in SQLite.
    pub fn set_sync_state(&self, key: &str, value: &str) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.execute(
            r#"
            INSERT INTO sync_state (key, value, updated_at)
            VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
            params![key, value],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Read the current sync cursor snapshot.
    pub fn get_sync_cursor_state(&self) -> std::io::Result<SyncCursorState> {
        let mut state = SyncCursorState::default();
        state.last_synced_seq = self
            .get_sync_state(SYNC_KEY_LAST_SYNCED_SEQ)?
            .and_then(|value| value.parse::<i64>().ok());
        state.last_body_synced_seq = self
            .get_sync_state(SYNC_KEY_LAST_BODY_SYNCED_SEQ)?
            .and_then(|value| value.parse::<i64>().ok());
        state.last_sync_timestamp = self.get_sync_state(SYNC_KEY_LAST_SYNC_TIMESTAMP)?;
        state.sync_errors = self.get_sync_state(SYNC_KEY_SYNC_ERRORS)?;
        Ok(state)
    }

    /// Log an event.
    pub fn log(&self, event: &WrapEvent) {
        let _ = self.log_checked(event);
    }

    /// Log an event, returning any error.
    pub fn log_checked(&self, event: &WrapEvent) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        match guard.as_mut() {
            Some(EventLoggerStorage::SqliteAsync { tx, .. }) => {
                let command = LoggerCommand::Event(event.clone());
                match tx.try_send(command) {
                    Ok(()) => {}
                    Err(TrySendError::Full(command)) => tx.send(command).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "Event logger writer is disconnected",
                        )
                    })?,
                    Err(TrySendError::Disconnected(_)) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "Event logger writer is disconnected",
                        ));
                    }
                }
            }
            None => {}
        }

        Ok(())
    }

    /// Flush buffered events to durable storage.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        match guard.as_mut() {
            Some(EventLoggerStorage::SqliteAsync { tx, .. }) => {
                let (ack_tx, ack_rx) = mpsc::channel();
                tx.send(LoggerCommand::Flush(ack_tx)).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SQLite logger disconnected",
                    )
                })?;
                ack_rx.recv().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SQLite logger disconnected",
                    )
                })?
            }
            None => Ok(()),
        }
    }

    /// Close the logger.
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(storage) = guard.take() {
                match storage {
                    EventLoggerStorage::SqliteAsync { tx, mut worker } => {
                        let _ = tx.send(LoggerCommand::Shutdown);
                        if let Some(handle) = worker.take() {
                            let _ = handle.join();
                        }
                    }
                }
            }
        }
    }

    fn open_sqlite_metadata_conn(&self) -> std::io::Result<Connection> {
        let conn = Connection::open(&self.path).map_err(to_io_err)?;
        conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .map_err(to_io_err)?;
        init_sqlite_schema(&conn)?;
        Ok(conn)
    }
}

impl std::fmt::Debug for EventLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLogger")
            .field("path", &self.path)
            .finish()
    }
}

impl Drop for EventLogger {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.close();
        }
    }
}

/// Default path used for new event writes.
pub fn default_event_log_write_path() -> std::io::Result<PathBuf> {
    Ok(default_logs_dir()?.join(EVENT_LOG_SQLITE_FILE))
}

fn default_logs_dir() -> std::io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine home directory",
        )
    })?;
    Ok(home.join(".soth").join("logs"))
}

fn init_sqlite_schema(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-8000;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS wrap_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wrap_event_payloads (
            event_id TEXT NOT NULL,
            payload_kind TEXT NOT NULL,
            payload BLOB NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (event_id, payload_kind),
            FOREIGN KEY (event_id) REFERENCES wrap_events(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_wrap_events_session_ts
            ON wrap_events(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_wrap_events_ts
            ON wrap_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_wrap_event_payloads_event_id
            ON wrap_event_payloads(event_id);

        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn run_sqlite_writer(path: PathBuf, rx: Receiver<LoggerCommand>, inline_payload_max_bytes: usize) {
    let mut conn = match Connection::open(&path) {
        Ok(conn) => conn,
        Err(error) => {
            warn!(
                "Failed to open event logger sqlite at {:?}: {}",
                path, error
            );
            return;
        }
    };

    if let Err(error) = init_sqlite_schema(&conn) {
        warn!(
            "Failed to initialize event logger sqlite schema at {:?}: {}",
            path, error
        );
        return;
    }

    let mut pending = Vec::with_capacity(SQLITE_BATCH_SIZE);
    let flush_interval = Duration::from_millis(SQLITE_FLUSH_INTERVAL_MS);

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(LoggerCommand::Event(event)) => pending.push(event),
            Ok(LoggerCommand::Flush(ack)) => {
                let result = flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes);
                let _ = ack.send(result);
            }
            Ok(LoggerCommand::Shutdown) => {
                if let Err(error) =
                    flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
                {
                    warn!("Failed to flush events during logger shutdown: {}", error);
                }
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Time-based durability/visibility: flush partial batches regularly
                // so low-traffic sessions still appear in observability promptly.
                if !pending.is_empty() {
                    if let Err(error) =
                        flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
                    {
                        warn!("Failed to flush timed events: {}", error);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(error) =
                    flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
                {
                    warn!("Failed to flush events during logger shutdown: {}", error);
                }
                return;
            }
        }

        while pending.len() < SQLITE_BATCH_SIZE {
            match rx.try_recv() {
                Ok(LoggerCommand::Event(event)) => pending.push(event),
                Ok(LoggerCommand::Flush(ack)) => {
                    let result =
                        flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes);
                    let _ = ack.send(result);
                }
                Ok(LoggerCommand::Shutdown) => {
                    if let Err(error) =
                        flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
                    {
                        warn!("Failed to flush events during logger shutdown: {}", error);
                    }
                    return;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Err(error) =
                        flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
                    {
                        warn!("Failed to flush events during logger shutdown: {}", error);
                    }
                    return;
                }
            }
        }

        if pending.len() >= SQLITE_BATCH_SIZE {
            if let Err(error) =
                flush_sqlite_events(&mut conn, &mut pending, inline_payload_max_bytes)
            {
                warn!("Failed to flush batched events: {}", error);
            }
        }
    }
}

fn flush_sqlite_events(
    conn: &mut Connection,
    pending: &mut Vec<WrapEvent>,
    inline_payload_max_bytes: usize,
) -> std::io::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }

    let tx = conn.transaction().map_err(to_io_err)?;
    for event in pending.drain(..) {
        insert_sqlite_event(&tx, event, inline_payload_max_bytes)?;
    }
    tx.commit().map_err(to_io_err)?;
    Ok(())
}

fn insert_sqlite_event(
    tx: &rusqlite::Transaction<'_>,
    mut event: WrapEvent,
    inline_payload_max_bytes: usize,
) -> std::io::Result<()> {
    let mut payloads = Vec::new();
    offload_large_payloads(&mut event, &mut payloads, inline_payload_max_bytes);

    let json = serde_json::to_string(&event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    tx.execute(
        r#"
        INSERT OR REPLACE INTO wrap_events (id, session_id, timestamp, event_json)
        VALUES (?1, ?2, ?3, ?4)
        "#,
        params![
            &event.id,
            &event.session_id,
            event.timestamp.to_rfc3339(),
            &json
        ],
    )
    .map_err(to_io_err)?;

    for payload in payloads {
        tx.execute(
            r#"
            INSERT OR REPLACE INTO wrap_event_payloads (event_id, payload_kind, payload, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                &event.id,
                payload.kind,
                payload.bytes,
                event.timestamp.to_rfc3339()
            ],
        )
        .map_err(to_io_err)?;
    }

    Ok(())
}

fn offload_large_payloads(
    event: &mut WrapEvent,
    payloads: &mut Vec<PayloadBlob>,
    inline_payload_max_bytes: usize,
) {
    maybe_offload_payload(
        &event.id,
        "content",
        &mut event.content,
        &mut event.content_preview,
        &mut event.content_ref,
        payloads,
        inline_payload_max_bytes,
    );
    maybe_offload_payload(
        &event.id,
        "request",
        &mut event.request_content,
        &mut event.request_preview,
        &mut event.request_content_ref,
        payloads,
        inline_payload_max_bytes,
    );
    maybe_offload_payload(
        &event.id,
        "response",
        &mut event.response_content,
        &mut event.response_preview,
        &mut event.response_content_ref,
        payloads,
        inline_payload_max_bytes,
    );

    // Request bodies in traffic_envelope are only needed in-memory for enforcement.
    // Strip before persistence to reduce event_json size growth.
    if let Some(ref mut envelope) = event.traffic_envelope {
        envelope.request_body = None;
    }
}

fn maybe_offload_payload(
    event_id: &str,
    kind: &'static str,
    field: &mut Option<String>,
    preview: &mut Option<String>,
    reference: &mut Option<String>,
    payloads: &mut Vec<PayloadBlob>,
    inline_payload_max_bytes: usize,
) {
    let Some(content) = field.take() else {
        return;
    };

    if content.as_bytes().len() <= inline_payload_max_bytes {
        *field = Some(content);
        return;
    }

    if preview
        .as_ref()
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        *preview = Some(build_preview(&content));
    }
    *reference = Some(build_payload_reference(event_id, kind));
    payloads.push(PayloadBlob {
        kind,
        bytes: content.into_bytes(),
    });
}

fn build_payload_reference(event_id: &str, kind: &str) -> String {
    format!("sqlite://wrap_event_payloads/{event_id}/{kind}")
}

fn build_preview(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut preview = String::new();
    for ch in trimmed.chars().take(256) {
        preview.push(ch);
    }
    if trimmed.chars().count() > 256 {
        preview.push_str("...");
    }
    preview
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentInfo, DetectionSource, TrafficEnvelope, WrapDirection};
    use tempfile::tempdir;

    #[test]
    fn test_event_logger_sqlite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-1", "test-server", WrapDirection::In, agent)
            .with_method("test/method");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_event_logger_sqlite_flushes_partial_batch_on_timeout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-timeout", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/messages");

        logger.log(&event);

        let deadline = std::time::Instant::now() + Duration::from_millis(800);
        let mut observed = 0i64;
        while std::time::Instant::now() < deadline {
            let conn = Connection::open(&path).unwrap();
            observed = conn
                .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
                .unwrap_or(0);
            if observed >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        logger.close();
        assert!(
            observed >= 1,
            "expected timed flush to persist event without waiting for batch=64"
        );
    }

    #[test]
    fn test_large_payloads_offloaded_to_side_table() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let large_request = "r".repeat(INLINE_PAYLOAD_MAX_BYTES + 1024);
        let large_response = "s".repeat(INLINE_PAYLOAD_MAX_BYTES + 2048);
        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-large", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/chat/completions")
            .with_request(large_request.clone(), "")
            .with_response(large_response.clone(), "");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        assert!(stored_event.request_content.is_none());
        assert!(stored_event.response_content.is_none());
        assert!(stored_event.request_content_ref.is_some());
        assert!(stored_event.response_content_ref.is_some());

        let request_payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM wrap_event_payloads WHERE event_id = ?1 AND payload_kind = 'request'",
                [&event.id],
                |row| row.get(0),
            )
            .unwrap();
        let response_payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM wrap_event_payloads WHERE event_id = ?1 AND payload_kind = 'response'",
                [&event.id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(String::from_utf8(request_payload).unwrap(), large_request);
        assert_eq!(String::from_utf8(response_payload).unwrap(), large_response);
    }

    #[test]
    fn test_custom_inline_threshold_controls_offload_boundary() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let threshold = 256usize;
        let logger =
            EventLogger::new_with_inline_payload_max_bytes(path.clone(), threshold).unwrap();

        let request_payload = "x".repeat(threshold + 1);
        let response_payload = "y".repeat(threshold / 2);
        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-threshold", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/messages")
            .with_request(request_payload.clone(), "")
            .with_response(response_payload.clone(), "");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        // Request exceeds threshold and should be offloaded, response should stay inline.
        assert!(stored_event.request_content.is_none());
        assert!(stored_event.request_content_ref.is_some());
        assert_eq!(
            stored_event.response_content.as_deref(),
            Some(response_payload.as_str())
        );
    }

    #[test]
    fn test_persisted_event_strips_traffic_envelope_request_body() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let envelope_request_body = r#"{"secret":"sensitive payload"}"#.to_string();
        let envelope = TrafficEnvelope::proxy(
            "session-envelope",
            "req-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-5"),
            Some("codex"),
            None,
            None,
            Some(&envelope_request_body),
        );

        let event = WrapEvent::new(
            "session-envelope",
            "api.openai.com",
            WrapDirection::In,
            agent,
        )
        .with_method("POST /v1/chat/completions")
        .with_traffic_envelope(envelope);

        logger.log(&event);
        logger.close();

        // In-memory event still has request_body (required for runtime enforcement flow).
        assert_eq!(
            event
                .traffic_envelope
                .as_ref()
                .and_then(|value| value.request_body.as_deref()),
            Some(envelope_request_body.as_str())
        );

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        assert!(
            stored_event
                .traffic_envelope
                .as_ref()
                .and_then(|value| value.request_body.as_deref())
                .is_none(),
            "request_body should be stripped before persistence"
        );
    }

    #[test]
    fn test_sync_state_table_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let _logger = EventLogger::new(path.clone()).unwrap();
        let conn = Connection::open(path).unwrap();

        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn test_sync_cursor_state_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path).unwrap();

        logger
            .set_sync_state(SYNC_KEY_LAST_SYNCED_SEQ, "123")
            .unwrap();
        logger
            .set_sync_state(SYNC_KEY_LAST_BODY_SYNCED_SEQ, "77")
            .unwrap();
        logger
            .set_sync_state(SYNC_KEY_LAST_SYNC_TIMESTAMP, "2026-02-01T00:00:00Z")
            .unwrap();
        logger.set_sync_state(SYNC_KEY_SYNC_ERRORS, "none").unwrap();

        let snapshot = logger.get_sync_cursor_state().unwrap();
        assert_eq!(snapshot.last_synced_seq, Some(123));
        assert_eq!(snapshot.last_body_synced_seq, Some(77));
        assert_eq!(
            snapshot.last_sync_timestamp.as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
        assert_eq!(snapshot.sync_errors.as_deref(), Some("none"));
    }
}
