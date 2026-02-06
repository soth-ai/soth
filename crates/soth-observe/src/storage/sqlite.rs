//! SQLite storage backend for observation logs

use rusqlite::{params, Connection};
use soth_core::types::observation::ObservationEvent;
use std::path::Path;
use std::sync::Mutex;

/// SQLite storage backend
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Create a new SQLite storage
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path).map_err(to_io_err)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create in-memory storage (for tests)
    pub fn in_memory() -> std::io::Result<Self> {
        let conn = Connection::open_in_memory().map_err(to_io_err)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> std::io::Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA temp_store=MEMORY;
            PRAGMA cache_size=-8000;

            CREATE TABLE IF NOT EXISTS observation_events (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_observation_session_ts
                ON observation_events(session_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_observation_ts
                ON observation_events(timestamp);
            "#,
        )
        .map_err(to_io_err)?;

        Ok(())
    }

    /// Write an observation event
    pub fn write(&self, event: &ObservationEvent) -> std::io::Result<()> {
        let event_json = serde_json::to_string(event)?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO observation_events (id, session_id, timestamp, event_json)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                event.id,
                event.session_id,
                event.timestamp.to_rfc3339(),
                event_json
            ],
        )
        .map_err(to_io_err)?;

        Ok(())
    }

    /// Flush to disk.
    ///
    /// SQLite autocommit mode persists each statement, so this is a no-op.
    pub fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Read all stored events in timestamp order.
    pub fn read_all(&self) -> std::io::Result<Vec<ObservationEvent>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT event_json
                FROM observation_events
                ORDER BY timestamp ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(to_io_err)?;

        let mut events = Vec::new();
        for row in rows {
            let json = row.map_err(to_io_err)?;
            let event: ObservationEvent = serde_json::from_str(&json)?;
            events.push(event);
        }

        Ok(events)
    }
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::observation::{Direction, EventType};
    use tempfile::tempdir;

    #[test]
    fn test_sqlite_write_and_read() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("observations.db");
        let storage = SqliteStorage::new(&db_path).unwrap();

        let event1 = ObservationEvent::new("session-1", Direction::In, EventType::Request, "c1");
        let event2 = ObservationEvent::new("session-1", Direction::Out, EventType::Response, "c2");

        storage.write(&event1).unwrap();
        storage.write(&event2).unwrap();
        storage.flush().unwrap();

        let events = storage.read_all().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].content, "c1");
        assert_eq!(events[1].content, "c2");
    }

    #[test]
    fn test_sqlite_in_memory() {
        let storage = SqliteStorage::in_memory().unwrap();
        let event = ObservationEvent::new("session-x", Direction::In, EventType::Request, "ok");
        storage.write(&event).unwrap();
        let events = storage.read_all().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id, "session-x");
    }
}
