use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::params;
use soth_classify::ClassifiedResult;
use soth_core::CaptureMode;
use uuid::Uuid;

pub fn open(db_path: &Path) -> Result<rusqlite::Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create DB directory: {}", parent.display()))?;
    }

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("failed to open sqlite database: {}", db_path.display()))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .context("failed to enable WAL mode")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("failed to set sqlite synchronous mode")?;

    run_migrations(&conn)?;
    Ok(conn)
}

pub fn run_migrations(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS intercept_records (
            event_id              TEXT PRIMARY KEY,
            connection_id         TEXT NOT NULL,
            timestamp_epoch_ms    INTEGER NOT NULL,
            provider              TEXT,
            model                 TEXT,
            capture_mode          TEXT NOT NULL,
            policy_kind           TEXT,
            policy_enforced       INTEGER NOT NULL,
            anomaly_score         REAL,
            semantic_hash         TEXT,
            matched_provider      TEXT,
            matched_application   TEXT,
            telemetry_json        TEXT NOT NULL,
            created_at_epoch_ms   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_intercept_records_conn
            ON intercept_records (connection_id, timestamp_epoch_ms);
        ",
    )
    .context("failed to run proxy DB migrations")?;

    Ok(())
}

pub fn write_intercept_record(
    db: &Arc<Mutex<rusqlite::Connection>>,
    connection_id: Uuid,
    result: &ClassifiedResult,
    capture_mode: CaptureMode,
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
) -> Result<()> {
    let telemetry_json = serde_json::to_string(&result.telemetry_event)
        .context("failed to serialize telemetry event")?;

    let policy_kind = result
        .telemetry_event
        .policy_kind
        .map(|kind| format!("{:?}", kind));

    let conn = db
        .lock()
        .map_err(|_| anyhow::anyhow!("sqlite lock poisoned"))?;
    conn.execute(
        "
        INSERT OR IGNORE INTO intercept_records (
            event_id,
            connection_id,
            timestamp_epoch_ms,
            provider,
            model,
            capture_mode,
            policy_kind,
            policy_enforced,
            anomaly_score,
            semantic_hash,
            matched_provider,
            matched_application,
            telemetry_json,
            created_at_epoch_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, strftime('%s','now') * 1000)
        ",
        params![
            result.telemetry_event.event_id.to_string(),
            connection_id.to_string(),
            result.telemetry_event.timestamp_epoch_ms,
            format!("{:?}", result.telemetry_event.provider),
            result.telemetry_event.model,
            format!("{:?}", capture_mode),
            policy_kind,
            if result.policy_enforced { 1 } else { 0 },
            result.telemetry_event.anomaly_score,
            result.semantic_hash,
            matched_provider,
            matched_application,
            telemetry_json,
        ],
    )
    .context("failed to insert intercept record")?;

    Ok(())
}
