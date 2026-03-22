use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::types::TransmittedBatch;

const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;
const SQLITE_MMAP_SIZE_BYTES: i64 = 268_435_456; // 256 MB
const SQLITE_CACHE_SIZE_KIB: i64 = -64_000; // 64 MB

#[derive(Debug, Clone)]
pub struct SqlitePool {
    db_path: PathBuf,
    shared: Option<Arc<Mutex<Connection>>>,
}

impl SqlitePool {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            db_path: path.as_ref().to_path_buf(),
            shared: None,
        }
    }

    pub fn from_connection(db: Arc<Mutex<Connection>>, path: impl AsRef<Path>) -> Self {
        Self {
            db_path: path.as_ref().to_path_buf(),
            shared: Some(db),
        }
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn with_conn_mut<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, rusqlite::Error> {
        if let Some(shared) = &self.shared {
            let mut conn = self.lock_shared(shared)?;
            configure_connection(&conn)?;
            f(&mut conn)
        } else {
            let mut conn = Connection::open(&self.db_path)?;
            configure_connection(&conn)?;
            f(&mut conn)
        }
    }

    fn lock_shared<'a>(
        &self,
        shared: &'a Arc<Mutex<Connection>>,
    ) -> Result<MutexGuard<'a, Connection>, rusqlite::Error> {
        shared
            .lock()
            .map_err(|_| rusqlite::Error::InvalidParameterName("sqlite mutex poisoned".to_string()))
    }
}

fn configure_connection(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "mmap_size", SQLITE_MMAP_SIZE_BYTES)?;
    conn.pragma_update(None, "page_size", 4096_i64)?;
    conn.pragma_update(None, "cache_size", SQLITE_CACHE_SIZE_KIB)?;
    Ok(())
}

pub async fn ensure_schema(pool: &SqlitePool) -> Result<(), rusqlite::Error> {
    pool.with_conn_mut(|conn| {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transmitted_events (
                event_id TEXT PRIMARY KEY,
                transmitted_at INTEGER NOT NULL,
                batch_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                transmission_status TEXT NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_transmitted_events_event_id
             ON transmitted_events(event_id)",
            [],
        )?;

        if !column_exists(conn, "transmitted_events", "encrypted")? {
            conn.execute(
                "ALTER TABLE transmitted_events
                 ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        Ok(())
    })
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, rusqlite::Error> {
    let query = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&query)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn write_queued(
    pool: &SqlitePool,
    batch: &TransmittedBatch,
    event_ids: &[Uuid],
) -> Result<(), rusqlite::Error> {
    ensure_schema(pool).await?;
    pool.with_conn_mut(|conn| {
        let now = Utc::now().timestamp();
        let encrypted = if batch.is_encrypted() { 1 } else { 0 };
        let tx = conn.transaction()?;
        for event_id in event_ids {
            tx.execute(
                "INSERT INTO transmitted_events
                 (event_id, transmitted_at, batch_id, payload_hash, transmission_status, encrypted)
                 VALUES (?1, ?2, ?3, ?4, 'QUEUED', ?5)",
                params![
                    event_id.to_string(),
                    now,
                    batch.batch_id().to_string(),
                    batch.payload_hash(),
                    encrypted
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
}

#[cfg(test)]
pub async fn count_by_status(
    pool: &SqlitePool,
    batch_id: Uuid,
    status: &str,
) -> Result<i64, rusqlite::Error> {
    ensure_schema(pool).await?;
    pool.with_conn_mut(|conn| {
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM transmitted_events
             WHERE batch_id = ?1 AND transmission_status = ?2",
        )?;
        let count = stmt.query_row(params![batch_id.to_string(), status], |row| {
            row.get::<_, i64>(0)
        })?;
        Ok(count)
    })
}

#[cfg(test)]
pub async fn count_total_by_status(
    pool: &SqlitePool,
    status: &str,
) -> Result<i64, rusqlite::Error> {
    ensure_schema(pool).await?;
    pool.with_conn_mut(|conn| {
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM transmitted_events
             WHERE transmission_status = ?1",
        )?;
        let count = stmt.query_row(params![status], |row| row.get::<_, i64>(0))?;
        Ok(count)
    })
}
