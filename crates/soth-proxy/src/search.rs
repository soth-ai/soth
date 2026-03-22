use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};

#[derive(Debug, Clone)]
pub struct SimilarEvent {
    pub event_id: String,
    pub distance: f32,
    pub use_case_label: String,
    pub timestamp_utc: i64,
    pub provider: String,
}

pub fn find_similar(
    conn: &Connection,
    query_embedding: &[f32],
    k: usize,
    since_days: u32,
) -> Result<Vec<SimilarEvent>> {
    let query_json =
        serde_json::to_string(query_embedding).context("failed to serialize query embedding")?;
    let since_epoch_ms = Utc::now()
        .timestamp_millis()
        .saturating_sub(i64::from(since_days).saturating_mul(86_400_000));

    let mut stmt = match conn.prepare(
        "
        SELECT
            ei.event_id,
            ei.distance,
            ir.use_case_label,
            ir.timestamp_utc,
            ir.provider
        FROM embedding_index ei
        JOIN intercept_records ir
          ON ir.event_id = ei.event_id
        WHERE ei.embedding MATCH ?1
          AND k = ?2
          AND ir.timestamp_utc > ?3
        ORDER BY ei.distance
        ",
    ) {
        Ok(stmt) => stmt,
        Err(error) if is_missing_table_error(&error, "embedding_index") => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let rows = stmt.query_map(params![query_json, k as i64, since_epoch_ms], |row| {
        Ok(SimilarEvent {
            event_id: row.get(0)?,
            distance: row.get(1)?,
            use_case_label: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            timestamp_utc: row.get(3)?,
            provider: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        })
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn is_missing_table_error(error: &rusqlite::Error, table: &str) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => {
            message.contains("no such table")
                && (message.contains(table) || message.contains(&format!("\"{table}\"")))
        }
        _ => false,
    }
}
