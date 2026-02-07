//! Event store - watches event logs and stores recent events for dashboard.
//!
//! Supports JSONL and SQLite wrap-event backends.
//! Provides real-time event streaming via broadcast channel.

use parking_lot::RwLock;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use soth_core::event_logger::{default_event_log_read_path, is_sqlite_event_log_path};
use soth_core::types::WrapEvent;
use soth_core::watch::{FileWatcher, WatchEvent};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Maximum number of events to keep in memory.
const MAX_EVENTS: usize = 1000;

/// Maximum number of agents to track.
const MAX_AGENTS: usize = 100;

#[derive(Clone, Debug)]
enum EventStoreBackend {
    Jsonl(PathBuf),
    Sqlite(PathBuf),
}

/// Event store that watches wrap events and provides real-time streaming.
#[derive(Clone)]
pub struct EventStore {
    inner: Arc<RwLock<EventStoreInner>>,
    backend: EventStoreBackend,
    event_tx: broadcast::Sender<WrapEvent>,
}

struct EventStoreInner {
    /// Recent events (newest first).
    events: VecDeque<WrapEvent>,
    /// Agent statistics.
    agents: HashMap<String, AgentStats>,
    /// File position for JSONL watching.
    file_position: u64,
    /// Last seen SQLite sequence number.
    sqlite_seq: i64,
}

/// Statistics for a detected agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStats {
    /// Agent name
    pub name: String,
    /// Agent version (if known)
    pub version: Option<String>,
    /// Detection source
    pub detected_from: String,
    /// Number of events from this agent
    pub event_count: u64,
    /// Last seen timestamp
    pub last_seen: String,
    /// Servers this agent has used
    pub servers: Vec<String>,
}

/// Summary of all agents
#[derive(Debug, Clone, Serialize)]
pub struct AgentsSummary {
    pub total_agents: usize,
    pub agents: Vec<AgentStats>,
}

/// Summary of recent events
#[derive(Debug, Clone, Serialize)]
pub struct EventsSummary {
    pub total_events: usize,
    pub events: Vec<WrapEvent>,
}

impl EventStore {
    /// Create a new event store.
    ///
    /// Backend is inferred from extension (`.db`, `.sqlite`, `.sqlite3` => sqlite).
    pub fn new(log_path: PathBuf) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let backend = if is_sqlite_event_log_path(&log_path) {
            EventStoreBackend::Sqlite(log_path)
        } else {
            EventStoreBackend::Jsonl(log_path)
        };

        Self {
            inner: Arc::new(RwLock::new(EventStoreInner {
                events: VecDeque::with_capacity(MAX_EVENTS),
                agents: HashMap::new(),
                file_position: 0,
                sqlite_seq: 0,
            })),
            backend,
            event_tx,
        }
    }

    /// Create with default log path (prefers `~/.soth/logs/events.db`, falls back to JSONL).
    pub fn with_default_path() -> Option<Self> {
        let log_path = default_event_log_read_path().ok()?;
        Some(Self::new(log_path))
    }

    /// Path currently used by this store.
    pub fn path(&self) -> &Path {
        match &self.backend {
            EventStoreBackend::Jsonl(path) => path.as_path(),
            EventStoreBackend::Sqlite(path) => path.as_path(),
        }
    }

    /// Subscribe to new events.
    pub fn subscribe(&self) -> broadcast::Receiver<WrapEvent> {
        self.event_tx.subscribe()
    }

    /// Get recent events.
    pub fn get_events(&self, limit: usize) -> EventsSummary {
        let inner = self.inner.read();
        let events: Vec<WrapEvent> = inner
            .events
            .iter()
            .take(limit.min(MAX_EVENTS))
            .cloned()
            .collect();

        EventsSummary {
            total_events: inner.events.len(),
            events,
        }
    }

    /// Get events strictly newer than a sqlite sequence cursor.
    ///
    /// For sqlite backends this queries durable storage (ordered ASC by sequence).
    /// For JSONL backends this falls back to in-memory filtering when sequence data exists.
    pub fn get_events_since_seq(&self, since_seq: i64, limit: usize) -> EventsSummary {
        if limit == 0 {
            return EventsSummary {
                total_events: self.inner.read().events.len(),
                events: Vec::new(),
            };
        }

        let capped_limit = limit.min(5_000);
        match &self.backend {
            EventStoreBackend::Sqlite(path) => {
                let rows = read_sqlite_events(path, Some(since_seq)).unwrap_or_default();
                let total_events = self.inner.read().events.len();

                let mut events: Vec<WrapEvent> = rows.into_iter().map(|(_, event)| event).collect();
                if events.len() > capped_limit {
                    let keep_from = events.len() - capped_limit;
                    events = events.split_off(keep_from);
                }

                EventsSummary {
                    total_events,
                    events,
                }
            }
            EventStoreBackend::Jsonl(_) => {
                let inner = self.inner.read();
                let mut events: Vec<WrapEvent> = inner
                    .events
                    .iter()
                    .rev()
                    .filter(|event| event.seq.map(|seq| seq > since_seq).unwrap_or(false))
                    .cloned()
                    .collect();

                if events.len() > capped_limit {
                    let keep_from = events.len() - capped_limit;
                    events = events.split_off(keep_from);
                }

                EventsSummary {
                    total_events: inner.events.len(),
                    events,
                }
            }
        }
    }

    /// Get agent statistics.
    pub fn get_agents(&self) -> AgentsSummary {
        let inner = self.inner.read();
        let mut agents: Vec<AgentStats> = inner.agents.values().cloned().collect();

        // Sort by event count (most active first)
        agents.sort_by(|a, b| b.event_count.cmp(&a.event_count));

        AgentsSummary {
            total_agents: agents.len(),
            agents,
        }
    }

    /// Get a full payload body for a specific event and part.
    pub fn get_event_payload(&self, event_id: &str, part: &str) -> Option<String> {
        match &self.backend {
            EventStoreBackend::Sqlite(path) => read_sqlite_event_payload(path, event_id, part)
                .ok()
                .flatten(),
            EventStoreBackend::Jsonl(_) => {
                let inner = self.inner.read();
                inner
                    .events
                    .iter()
                    .find(|event| event.id == event_id)
                    .and_then(|event| match part {
                        "request" => event.request_content.clone(),
                        "response" => event.response_content.clone(),
                        "content" => event.content.clone(),
                        _ => None,
                    })
            }
        }
    }

    /// Load initial events from storage.
    pub async fn load_initial(&self) -> std::io::Result<usize> {
        match &self.backend {
            EventStoreBackend::Jsonl(path) => self.load_initial_jsonl(path).await,
            EventStoreBackend::Sqlite(path) => self.load_initial_sqlite(path).await,
        }
    }

    async fn load_initial_jsonl(&self, log_path: &Path) -> std::io::Result<usize> {
        if !log_path.exists() {
            debug!("Event log does not exist yet: {:?}", log_path);
            return Ok(0);
        }

        let content = tokio::fs::read_to_string(log_path).await?;
        let mut count = 0;

        for line in content.lines() {
            if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
                self.add_event(event);
                count += 1;
            }
        }

        // Update file position
        {
            let mut inner = self.inner.write();
            inner.file_position = content.len() as u64;
        }

        info!("Loaded {} initial events from {:?}", count, log_path);
        Ok(count)
    }

    async fn load_initial_sqlite(&self, db_path: &Path) -> std::io::Result<usize> {
        if !db_path.exists() {
            debug!("Event log database does not exist yet: {:?}", db_path);
            return Ok(0);
        }

        let db_path = db_path.to_path_buf();
        let query_path = db_path.clone();
        let rows = tokio::task::spawn_blocking(move || read_sqlite_events(&query_path, None))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))??;

        let mut count = 0usize;
        let mut last_seq = 0i64;
        for (seq, event) in rows {
            self.add_event(event);
            count += 1;
            last_seq = seq;
        }

        {
            let mut inner = self.inner.write();
            inner.sqlite_seq = last_seq;
        }

        info!("Loaded {} initial events from {:?}", count, db_path);
        Ok(count)
    }

    /// Watch for new events.
    pub async fn watch(&self) {
        match &self.backend {
            EventStoreBackend::Jsonl(path) => self.watch_jsonl(path.clone()).await,
            EventStoreBackend::Sqlite(path) => self.watch_sqlite(path.clone()).await,
        }
    }

    async fn watch_jsonl(&self, log_path: PathBuf) {
        info!("Starting JSONL event watcher for {:?}", log_path);

        let watcher_result = FileWatcher::new(log_path.clone());
        let use_polling = watcher_result.is_err();
        if use_polling {
            warn!("File watcher unavailable, falling back to 100ms polling");
        } else {
            info!("Using notify-based file watching for instant events");
        }

        let mut watcher = watcher_result.ok();

        loop {
            if let Some(ref mut w) = watcher {
                let timeout_duration = tokio::time::Duration::from_millis(500);
                match tokio::time::timeout(timeout_duration, w.next()).await {
                    Ok(Some(WatchEvent::Modified)) | Ok(Some(WatchEvent::Created)) => {
                        debug!("File change detected via notify");
                    }
                    Ok(Some(WatchEvent::Removed)) => {
                        debug!("Log file removed, waiting for recreation...");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(Some(WatchEvent::Error(e))) => {
                        warn!("Watch error: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(None) => {
                        warn!("File watcher closed, falling back to polling");
                        watcher = None;
                        continue;
                    }
                    Err(_) => {}
                }
            } else {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if let Err(e) = self.check_for_new_jsonl_events(&log_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Error checking event log: {}", e);
                }
            }
        }
    }

    async fn watch_sqlite(&self, db_path: PathBuf) {
        info!("Starting SQLite event poller for {:?}", db_path);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if let Err(e) = self.check_for_new_sqlite_events(&db_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Error checking sqlite event log: {}", e);
                }
            }
        }
    }

    async fn check_for_new_jsonl_events(&self, log_path: &Path) -> std::io::Result<()> {
        if !log_path.exists() {
            return Ok(());
        }

        let metadata = tokio::fs::metadata(log_path).await?;
        let current_size = metadata.len();

        let file_position = {
            let inner = self.inner.read();
            inner.file_position
        };

        // Handle file truncation/recreation - reset position if file shrunk
        let effective_position = if current_size < file_position {
            debug!(
                "Log file was truncated/recreated, resetting position from {} to 0",
                file_position
            );
            let mut inner = self.inner.write();
            inner.file_position = 0;
            inner.events.clear(); // Clear stale events
            0u64 // Process from beginning
        } else if current_size == file_position {
            return Ok(()); // No new content
        } else {
            file_position
        };

        // Read new content
        let content = tokio::fs::read_to_string(log_path).await?;

        // Process lines after the effective position
        let mut bytes_read = 0u64;
        for line in content.lines() {
            let line_bytes = line.len() as u64 + 1; // +1 for newline
            bytes_read += line_bytes;

            if bytes_read <= effective_position {
                continue;
            }

            if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
                // Broadcast to subscribers
                let _ = self.event_tx.send(event.clone());

                // Store in memory
                self.add_event(event);
            }
        }

        // Update position
        {
            let mut inner = self.inner.write();
            inner.file_position = current_size;
        }

        Ok(())
    }

    async fn check_for_new_sqlite_events(&self, db_path: &Path) -> std::io::Result<()> {
        if !db_path.exists() {
            return Ok(());
        }

        let cursor = {
            let inner = self.inner.read();
            inner.sqlite_seq
        };

        let db_path = db_path.to_path_buf();
        let rows = tokio::task::spawn_blocking(move || read_sqlite_events(&db_path, Some(cursor)))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))??;

        if rows.is_empty() {
            return Ok(());
        }

        let mut last_seq = cursor;
        for (seq, event) in rows {
            last_seq = seq;
            let _ = self.event_tx.send(event.clone());
            self.add_event(event);
        }

        let mut inner = self.inner.write();
        inner.sqlite_seq = last_seq;

        Ok(())
    }

    fn add_event(&self, event: WrapEvent) {
        let mut inner = self.inner.write();

        // Update agent stats
        let agent_key = event.agent.name.clone();
        let stats = inner
            .agents
            .entry(agent_key.clone())
            .or_insert_with(|| AgentStats {
                name: event.agent.name.clone(),
                version: event.agent.version.clone(),
                detected_from: format!("{:?}", event.agent.detected_from),
                event_count: 0,
                last_seen: event.timestamp.to_rfc3339(),
                servers: Vec::new(),
            });

        stats.event_count += 1;
        stats.last_seen = event.timestamp.to_rfc3339();

        // Track servers
        if !stats.servers.contains(&event.server_name) {
            stats.servers.push(event.server_name.clone());
            // Limit servers list
            if stats.servers.len() > 10 {
                stats.servers.remove(0);
            }
        }

        // Limit agents
        if inner.agents.len() > MAX_AGENTS {
            // Remove least active agent
            if let Some(min_key) = inner
                .agents
                .iter()
                .min_by_key(|(_, s)| s.event_count)
                .map(|(k, _)| k.clone())
            {
                inner.agents.remove(&min_key);
            }
        }

        // Add event to front (newest first)
        inner.events.push_front(event);

        // Trim to max size
        while inner.events.len() > MAX_EVENTS {
            inner.events.pop_back();
        }
    }
}

fn read_sqlite_events(
    db_path: &Path,
    since_seq: Option<i64>,
) -> std::io::Result<Vec<(i64, WrapEvent)>> {
    let conn = Connection::open(db_path).map_err(to_io_err)?;
    ensure_wrap_events_schema(&conn)?;

    let mut events = Vec::new();
    if let Some(cursor) = since_seq {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM wrap_events
                WHERE seq > ?1
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([cursor], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            if let Ok(mut event) = serde_json::from_str::<WrapEvent>(&json) {
                event.seq = Some(seq);
                events.push((seq, event));
            }
        }
    } else {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM wrap_events
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            if let Ok(mut event) = serde_json::from_str::<WrapEvent>(&json) {
                event.seq = Some(seq);
                events.push((seq, event));
            }
        }
    }

    Ok(events)
}

fn ensure_wrap_events_schema(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
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
            PRIMARY KEY (event_id, payload_kind)
        );
        "#,
    )
    .map_err(to_io_err)?;
    Ok(())
}

fn read_sqlite_event_payload(
    db_path: &Path,
    event_id: &str,
    part: &str,
) -> std::io::Result<Option<String>> {
    let payload_kind = match part {
        "request" | "response" | "content" => part,
        _ => return Ok(None),
    };

    let conn = Connection::open(db_path).map_err(to_io_err)?;
    ensure_wrap_events_schema(&conn)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT payload
            FROM wrap_event_payloads
            WHERE event_id = ?1 AND payload_kind = ?2
            LIMIT 1
            "#,
        )
        .map_err(to_io_err)?;

    let blob_row = stmt.query_row([event_id, payload_kind], |row| row.get::<_, Vec<u8>>(0));
    match blob_row {
        Ok(bytes) => {
            let decoded = String::from_utf8_lossy(&bytes).to_string();
            return Ok(Some(decoded));
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(error) => return Err(to_io_err(error)),
    }

    let mut fallback_stmt = conn
        .prepare(
            r#"
            SELECT event_json
            FROM wrap_events
            WHERE id = ?1
            LIMIT 1
            "#,
        )
        .map_err(to_io_err)?;

    let event_json = fallback_stmt.query_row([event_id], |row| row.get::<_, String>(0));
    match event_json {
        Ok(json) => {
            let event = serde_json::from_str::<WrapEvent>(&json)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            Ok(match payload_kind {
                "request" => event.request_content,
                "response" => event.response_content,
                "content" => event.content,
                _ => None,
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(to_io_err(error)),
    }
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection};
    use soth_core::EventLogger;
    use tempfile::tempdir;

    fn make_event(agent_name: &str, server: &str) -> WrapEvent {
        let agent = AgentInfo::new(agent_name, DetectionSource::McpInitialize);
        WrapEvent::new("sess-123", server, WrapDirection::In, agent).with_method("tools/call")
    }

    #[test]
    fn test_add_event() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        let event = make_event("Claude Desktop", "postgres");
        store.add_event(event);

        let summary = store.get_events(10);
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.events[0].agent.name, "Claude Desktop");
    }

    #[test]
    fn test_agent_stats() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        store.add_event(make_event("Claude Desktop", "postgres"));
        store.add_event(make_event("Claude Desktop", "filesystem"));
        store.add_event(make_event("Cursor", "postgres"));

        let agents = store.get_agents();
        assert_eq!(agents.total_agents, 2);

        let claude = agents
            .agents
            .iter()
            .find(|a| a.name == "Claude Desktop")
            .unwrap();
        assert_eq!(claude.event_count, 2);
        assert_eq!(claude.servers.len(), 2);
    }

    #[test]
    fn test_event_limit() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        // Add more than MAX_EVENTS
        for i in 0..1100 {
            store.add_event(make_event(&format!("Agent{}", i % 10), "server"));
        }

        let summary = store.get_events(2000);
        assert_eq!(summary.total_events, MAX_EVENTS);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        let mut rx = store.subscribe();

        // Simulate broadcast
        let event = make_event("Test Agent", "test-server");
        store.event_tx.send(event.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.agent.name, "Test Agent");
    }

    #[tokio::test]
    async fn test_load_initial_from_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event("Claude Desktop", "postgres"));
        logger.log(&make_event("Cursor", "filesystem"));
        logger.close();

        let store = EventStore::new(db_path);
        let count = store.load_initial().await.unwrap();
        assert_eq!(count, 2);

        let summary = store.get_events(10);
        assert_eq!(summary.total_events, 2);
    }

    #[tokio::test]
    async fn test_get_events_since_seq_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event("Claude Desktop", "postgres"));
        logger.log(&make_event("Cursor", "filesystem"));
        logger.log(&make_event("Windsurf", "git"));
        logger.close();

        let store = EventStore::new(db_path);
        store.load_initial().await.unwrap();

        let replay = store.get_events_since_seq(1, 10);
        assert_eq!(replay.events.len(), 2);
        assert!(replay
            .events
            .iter()
            .all(|event| event.seq.map(|seq| seq > 1).unwrap_or(false)));
    }

    #[tokio::test]
    async fn test_get_event_payload_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let logger = EventLogger::new(db_path.clone()).unwrap();

        let agent = AgentInfo::new("Claude Desktop", DetectionSource::McpInitialize);
        let request_body = "x".repeat(20 * 1024);
        let event = WrapEvent::new("sess-123", "postgres", WrapDirection::In, agent)
            .with_source(soth_core::types::EventSource::AiProxy)
            .with_method("POST /v1/chat/completions")
            .with_request(request_body.clone(), "");

        let event_id = event.id.clone();
        logger.log(&event);
        logger.close();

        let store = EventStore::new(db_path);
        store.load_initial().await.unwrap();

        let payload = store.get_event_payload(&event_id, "request");
        assert_eq!(payload.as_deref(), Some(request_body.as_str()));
    }
}
