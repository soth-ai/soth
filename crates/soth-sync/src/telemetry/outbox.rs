use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use soth_telemetry::TransmittedBatch;
use uuid::Uuid;

const OUTBOX_STATUS_QUEUED: &str = "QUEUED";
const OUTBOX_STATUS_SENDING: &str = "SENDING";
const OUTBOX_STATUS_FAILED: &str = "FAILED";
const OUTBOX_STATUS_SENT: &str = "SENT";
const OUTBOX_STATUS_DEAD: &str = "DEAD";

#[derive(Debug, Clone)]
pub struct TelemetryOutboxRecord {
    pub batch_id: Uuid,
    pub batch: TransmittedBatch,
    pub attempts: u8,
    pub first_queued_at: i64,
}

#[derive(Clone)]
pub struct TelemetryOutbox {
    db_path: PathBuf,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl TelemetryOutbox {
    pub fn new(
        db_path: impl AsRef<Path>,
        tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Result<Self> {
        let outbox = Self {
            db_path: db_path.as_ref().to_path_buf(),
            tx,
        };
        outbox.ensure_schema()?;
        Ok(outbox)
    }

    pub fn enqueue(&self, batch: TransmittedBatch) -> Result<()> {
        self.ensure_schema()?;
        let mut conn = self.open_rw()?;
        let now = Utc::now().timestamp();
        let batch_id = batch.batch_id().to_string();
        let payload = serde_json::to_string(&batch).context("serialize transmitted batch")?;
        let encrypted = if batch.is_encrypted() { 1i64 } else { 0i64 };
        let tx = conn
            .transaction()
            .context("start telemetry outbox transaction")?;
        tx.execute(
            "INSERT INTO telemetry_outbox
             (batch_id, org_id, payload_json, payload_hash, encrypted, status, attempts, first_queued_at, next_attempt_at, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7, NULL)
             ON CONFLICT(batch_id) DO UPDATE SET
                 org_id = excluded.org_id,
                 payload_json = excluded.payload_json,
                 payload_hash = excluded.payload_hash,
                 encrypted = excluded.encrypted,
                 status = excluded.status,
                 next_attempt_at = excluded.next_attempt_at,
                 last_error = NULL",
            params![
                batch_id,
                batch.org_id(),
                payload,
                batch.payload_hash(),
                encrypted,
                OUTBOX_STATUS_QUEUED,
                now
            ],
        )
        .context("insert telemetry outbox row")?;
        tx.commit().context("commit telemetry outbox transaction")?;

        self.tx
            .send(batch.batch_id().to_string())
            .map_err(|_| anyhow::anyhow!("telemetry replay worker channel closed"))?;
        Ok(())
    }

    pub fn drain_on_startup(&self) -> Result<usize> {
        self.ensure_schema()?;
        let conn = self.open_ro()?;
        let now = Utc::now().timestamp();
        let mut stmt = conn.prepare(
            "SELECT batch_id
             FROM telemetry_outbox
             WHERE status IN (?1, ?2)
               AND COALESCE(next_attempt_at, 0) <= ?3
             ORDER BY first_queued_at ASC
             LIMIT 5000",
        )?;
        let mut rows = stmt.query(params![OUTBOX_STATUS_QUEUED, OUTBOX_STATUS_FAILED, now])?;
        let mut replayed = 0usize;
        while let Some(row) = rows.next().context("read telemetry outbox row")? {
            let batch_id: String = row.get(0).context("read telemetry outbox batch_id")?;
            self.tx
                .send(batch_id)
                .map_err(|_| anyhow::anyhow!("telemetry replay worker channel closed"))?;
            replayed = replayed.saturating_add(1);
        }
        Ok(replayed)
    }

    pub fn claim_for_send(
        &self,
        batch_id: &str,
        now_ts: i64,
    ) -> Result<Option<TelemetryOutboxRecord>> {
        self.ensure_schema()?;
        let mut conn = self.open_rw()?;
        let tx = conn
            .transaction()
            .context("start telemetry claim transaction")?;
        let row = tx
            .query_row(
                "SELECT payload_json, attempts, first_queued_at, status, next_attempt_at
                 FROM telemetry_outbox
                 WHERE batch_id = ?1",
                params![batch_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .context("query telemetry outbox row for claim")?;

        let Some((payload_json, attempts, first_queued_at, status, next_attempt_at)) = row else {
            tx.commit().context("commit telemetry claim transaction")?;
            return Ok(None);
        };

        let is_eligible_status = status == OUTBOX_STATUS_QUEUED || status == OUTBOX_STATUS_FAILED;
        if !is_eligible_status {
            tx.commit().context("commit telemetry claim transaction")?;
            return Ok(None);
        }
        if next_attempt_at.unwrap_or(0) > now_ts {
            tx.commit().context("commit telemetry claim transaction")?;
            return Ok(None);
        }

        tx.execute(
            "UPDATE telemetry_outbox
             SET status = ?1, last_attempt_at = ?2
             WHERE batch_id = ?3",
            params![OUTBOX_STATUS_SENDING, now_ts, batch_id],
        )
        .context("mark telemetry outbox row sending")?;
        tx.commit().context("commit telemetry claim transaction")?;

        let batch: TransmittedBatch =
            serde_json::from_str(payload_json.as_str()).context("decode transmitted batch")?;
        Ok(Some(TelemetryOutboxRecord {
            batch_id: batch.batch_id(),
            batch,
            attempts: attempts.clamp(0, i64::from(u8::MAX)) as u8,
            first_queued_at,
        }))
    }

    pub fn mark_sent(&self, batch_id: Uuid) -> Result<()> {
        self.ensure_schema()?;
        let mut conn = self.open_rw()?;
        let tx = conn
            .transaction()
            .context("start telemetry sent transaction")?;
        tx.execute(
            "UPDATE telemetry_outbox
             SET status = ?1, next_attempt_at = NULL, last_error = NULL
             WHERE batch_id = ?2",
            params![OUTBOX_STATUS_SENT, batch_id.to_string()],
        )
        .context("mark telemetry outbox row sent")?;
        self.update_transmitted_status_in_tx(&tx, batch_id, OUTBOX_STATUS_SENT)?;
        tx.commit().context("commit telemetry sent transaction")?;
        Ok(())
    }

    pub fn mark_failed(
        &self,
        batch_id: Uuid,
        attempts: u8,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        self.ensure_schema()?;
        let mut conn = self.open_rw()?;
        let tx = conn
            .transaction()
            .context("start telemetry failed transaction")?;
        tx.execute(
            "UPDATE telemetry_outbox
             SET status = ?1, attempts = ?2, next_attempt_at = ?3, last_error = ?4
             WHERE batch_id = ?5",
            params![
                OUTBOX_STATUS_FAILED,
                i64::from(attempts),
                next_attempt_at,
                error,
                batch_id.to_string()
            ],
        )
        .context("mark telemetry outbox row failed")?;
        self.update_transmitted_status_in_tx(&tx, batch_id, OUTBOX_STATUS_FAILED)?;
        tx.commit().context("commit telemetry failed transaction")?;
        Ok(())
    }

    pub fn mark_dead(&self, batch_id: Uuid, attempts: u8, reason: &str) -> Result<()> {
        self.ensure_schema()?;
        let mut conn = self.open_rw()?;
        let tx = conn
            .transaction()
            .context("start telemetry dead transaction")?;
        tx.execute(
            "UPDATE telemetry_outbox
             SET status = ?1, attempts = ?2, next_attempt_at = NULL, last_error = ?3
             WHERE batch_id = ?4",
            params![
                OUTBOX_STATUS_DEAD,
                i64::from(attempts),
                reason,
                batch_id.to_string()
            ],
        )
        .context("mark telemetry outbox row dead")?;
        self.update_transmitted_status_in_tx(&tx, batch_id, OUTBOX_STATUS_DEAD)?;
        tx.commit().context("commit telemetry dead transaction")?;
        Ok(())
    }

    fn ensure_schema(&self) -> Result<()> {
        let conn = self.open_rw()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS telemetry_outbox (
                batch_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_queued_at INTEGER NOT NULL,
                last_attempt_at INTEGER,
                next_attempt_at INTEGER,
                last_error TEXT
            )",
            [],
        )
        .context("create telemetry_outbox table")?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_telemetry_outbox_status_next_attempt
             ON telemetry_outbox(status, next_attempt_at)",
            [],
        )
        .context("create telemetry_outbox status index")?;

        self.ensure_transmitted_events_schema(&conn)?;
        Ok(())
    }

    fn ensure_transmitted_events_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transmitted_events (
                event_id TEXT NOT NULL,
                transmitted_at INTEGER NOT NULL,
                batch_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                transmission_status TEXT NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )
        .context("create transmitted_events table")?;

        if !column_exists(conn, "transmitted_events", "encrypted")
            .context("inspect transmitted_events columns")?
        {
            conn.execute(
                "ALTER TABLE transmitted_events
                 ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .context("add transmitted_events.encrypted column")?;
        }
        Ok(())
    }

    fn update_transmitted_status_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        batch_id: Uuid,
        status: &str,
    ) -> Result<()> {
        tx.execute(
            "UPDATE transmitted_events
             SET transmission_status = ?1
             WHERE batch_id = ?2",
            params![status, batch_id.to_string()],
        )
        .context("update transmitted_events status")?;
        Ok(())
    }

    fn open_ro(&self) -> Result<Connection> {
        Connection::open_with_flags(&self.db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .or_else(|_| {
                Connection::open_with_flags(
                    &self.db_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                )
            })
            .with_context(|| format!("open sqlite database {}", self.db_path.display()))
    }

    fn open_rw(&self) -> Result<Connection> {
        Connection::open(&self.db_path)
            .with_context(|| format!("open sqlite database {}", self.db_path.display()))
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let query = format!("PRAGMA table_info({table})");
    let mut stmt = conn
        .prepare(query.as_str())
        .with_context(|| format!("prepare PRAGMA table_info for {table}"))?;
    let mut rows = stmt.query([]).context("query table info rows")?;
    while let Some(row) = rows.next().context("read table info row")? {
        let name: String = row.get(1).context("read table info column name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}
