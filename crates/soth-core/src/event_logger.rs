//! Event logger for writing `WrapEvent`s.
//!
//! The logger supports two storage formats:
//! - JSONL (`*.jsonl`) for backward compatibility
//! - SQLite (`*.db`, `*.sqlite`, `*.sqlite3`) for low-latency durable writes
//!
//! Used by both `soth wrap` (stdio interception) and forward proxy (HTTP interception)
//! to emit events that appear in the observability dashboard.

use crate::types::WrapEvent;
use rusqlite::{params, Connection};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const EVENT_LOG_JSONL_FILE: &str = "events.jsonl";
pub const EVENT_LOG_SQLITE_FILE: &str = "events.db";

enum EventLoggerStorage {
    Jsonl(BufWriter<File>),
    Sqlite(Connection),
}

/// Event logger that writes `WrapEvent`s to JSONL or SQLite.
#[derive(Clone)]
pub struct EventLogger {
    inner: Arc<Mutex<Option<EventLoggerStorage>>>,
    path: PathBuf,
}

impl EventLogger {
    /// Create a new event logger that writes to the given path.
    ///
    /// Storage backend is inferred from file extension:
    /// `.db`, `.sqlite`, `.sqlite3` => SQLite, otherwise JSONL.
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let storage = if is_sqlite_event_log_path(&path) {
            let conn = Connection::open(&path).map_err(to_io_err)?;
            init_sqlite_schema(&conn)?;
            EventLoggerStorage::Sqlite(conn)
        } else {
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            EventLoggerStorage::Jsonl(BufWriter::new(file))
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(Some(storage))),
            path,
        })
    }

    /// Create an event logger with the default write path (`~/.soth/logs/events.db`).
    ///
    /// If this is the first SQLite startup and a legacy `events.jsonl` exists,
    /// events are imported once into SQLite.
    pub fn with_default_path() -> std::io::Result<Self> {
        let sqlite_path = default_event_log_write_path()?;
        let jsonl_path = default_event_log_jsonl_path()?;
        let sqlite_exists_before = sqlite_path.exists();

        let logger = Self::new(sqlite_path)?;
        if !sqlite_exists_before && jsonl_path.exists() {
            let _ = migrate_jsonl_to_logger(&jsonl_path, &logger);
        }
        Ok(logger)
    }

    /// Get the path this logger writes to.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Log an event.
    pub fn log(&self, event: &WrapEvent) {
        let _ = self.log_checked(event);
    }

    /// Log an event, returning any error.
    pub fn log_checked(&self, event: &WrapEvent) -> std::io::Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        match guard.as_mut() {
            Some(EventLoggerStorage::Jsonl(writer)) => {
                writeln!(writer, "{}", json)?;
                writer.flush()?;
            }
            Some(EventLoggerStorage::Sqlite(conn)) => {
                conn.execute(
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
            }
            None => {}
        }

        Ok(())
    }

    /// Close the logger.
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }
}

impl std::fmt::Debug for EventLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLogger")
            .field("path", &self.path)
            .finish()
    }
}

/// Default path used for new event writes.
pub fn default_event_log_write_path() -> std::io::Result<PathBuf> {
    Ok(default_logs_dir()?.join(EVENT_LOG_SQLITE_FILE))
}

/// Legacy JSONL path (`~/.soth/logs/events.jsonl`).
pub fn default_event_log_jsonl_path() -> std::io::Result<PathBuf> {
    Ok(default_logs_dir()?.join(EVENT_LOG_JSONL_FILE))
}

/// Resolve default path to read from.
///
/// Prefers SQLite when present, otherwise falls back to JSONL if present.
/// If neither exists, returns the preferred SQLite path.
pub fn default_event_log_read_path() -> std::io::Result<PathBuf> {
    let sqlite = default_event_log_write_path()?;
    if sqlite.exists() {
        return Ok(sqlite);
    }

    let jsonl = default_event_log_jsonl_path()?;
    if jsonl.exists() {
        return Ok(jsonl);
    }

    Ok(sqlite)
}

/// Return true if this path should use SQLite storage.
pub fn is_sqlite_event_log_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("db" | "sqlite" | "sqlite3")
    )
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

        CREATE TABLE IF NOT EXISTS wrap_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_wrap_events_session_ts
            ON wrap_events(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_wrap_events_ts
            ON wrap_events(timestamp);
        "#,
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn migrate_jsonl_to_logger(jsonl_path: &Path, logger: &EventLogger) -> std::io::Result<usize> {
    let content = std::fs::read_to_string(jsonl_path)?;
    let mut migrated = 0usize;

    for line in content.lines() {
        if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
            logger.log_checked(&event)?;
            migrated += 1;
        }
    }

    Ok(migrated)
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentInfo, DetectionSource, WrapDirection};
    use tempfile::tempdir;

    #[test]
    fn test_event_logger_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-1", "test-server", WrapDirection::In, agent)
            .with_method("test/method");

        logger.log(&event);
        logger.close();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("session-1"));
        assert!(content.contains("test-server"));
        assert!(content.contains("test/method"));
    }

    #[test]
    fn test_event_logger_multiple_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let logger = EventLogger::new(path.clone()).unwrap();

        for i in 0..5 {
            let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
            let event = WrapEvent::new(
                format!("session-{}", i),
                "test-server",
                WrapDirection::In,
                agent,
            );
            logger.log(&event);
        }
        logger.close();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
    }

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
    fn test_is_sqlite_event_log_path() {
        assert!(is_sqlite_event_log_path(Path::new("events.db")));
        assert!(is_sqlite_event_log_path(Path::new("events.sqlite")));
        assert!(is_sqlite_event_log_path(Path::new("events.sqlite3")));
        assert!(!is_sqlite_event_log_path(Path::new("events.jsonl")));
    }
}
