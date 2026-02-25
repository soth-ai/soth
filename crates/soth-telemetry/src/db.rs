use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::types::TransmittedBatch;

#[derive(Debug, Clone)]
pub struct SqlitePool {
    db_path: PathBuf,
}

impl SqlitePool {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            db_path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn open(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(&self.db_path)
    }
}

pub async fn ensure_schema(pool: &SqlitePool) -> Result<(), rusqlite::Error> {
    let conn = pool.open()?;
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

    if !column_exists(&conn, "transmitted_events", "encrypted")? {
        conn.execute(
            "ALTER TABLE transmitted_events
             ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    Ok(())
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
    let mut conn = pool.open()?;
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
}

#[cfg(test)]
pub async fn count_by_status(
    pool: &SqlitePool,
    batch_id: Uuid,
    status: &str,
) -> Result<i64, rusqlite::Error> {
    ensure_schema(pool).await?;
    let conn = pool.open()?;
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM transmitted_events
         WHERE batch_id = ?1 AND transmission_status = ?2",
    )?;
    let count = stmt.query_row(params![batch_id.to_string(), status], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(count)
}

#[cfg(test)]
pub async fn count_total_by_status(
    pool: &SqlitePool,
    status: &str,
) -> Result<i64, rusqlite::Error> {
    ensure_schema(pool).await?;
    let conn = pool.open()?;
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM transmitted_events
         WHERE transmission_status = ?1",
    )?;
    let count = stmt.query_row(params![status], |row| row.get::<_, i64>(0))?;
    Ok(count)
}
