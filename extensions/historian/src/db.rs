use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::HistorianError;
use crate::types::{BackfillProgress, Cursor};

/// Initialize the historian.db schema. Safe to call multiple times (uses IF NOT EXISTS).
pub fn init_schema(conn: &Connection) -> Result<(), HistorianError> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS already_processed (
            tool_type     TEXT    NOT NULL,
            session_id    TEXT    NOT NULL,
            message_index INTEGER NOT NULL,
            event_id      TEXT    NOT NULL,
            content_hash  TEXT    NOT NULL DEFAULT '',
            semantic_hash TEXT    NOT NULL DEFAULT '',
            processed_at  INTEGER NOT NULL,
            PRIMARY KEY (tool_type, session_id, message_index)
        );

        CREATE INDEX IF NOT EXISTS idx_processed_content_hash
            ON already_processed(content_hash);

        CREATE INDEX IF NOT EXISTS idx_processed_semantic_hash
            ON already_processed(semantic_hash, processed_at);

        CREATE TABLE IF NOT EXISTS backfill_progress (
            tool_type      TEXT PRIMARY KEY,
            sessions_total INTEGER NOT NULL DEFAULT 0,
            sessions_done  INTEGER NOT NULL DEFAULT 0,
            started_at     INTEGER,
            completed_at   INTEGER,
            last_cursor    TEXT
        );

        CREATE TABLE IF NOT EXISTS discovery_report (
            tool_type     TEXT NOT NULL,
            root_path     TEXT NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_scan_at  INTEGER NOT NULL,
            session_count INTEGER NOT NULL DEFAULT 0,
            error_count   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (tool_type, root_path)
        );

        CREATE TABLE IF NOT EXISTS watch_state (
            root_path     TEXT PRIMARY KEY,
            last_event_at INTEGER,
            is_active     INTEGER NOT NULL DEFAULT 1,
            error_reason  TEXT
        );

        PRAGMA journal_mode = WAL;
        PRAGMA busy_timeout = 5000;
        ",
    )?;
    Ok(())
}

/// Open (or create) the historian database at the given path.
pub fn open_historian_db(path: &Path) -> Result<Connection, HistorianError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(conn)
}

/// Save backfill progress for a tool. Uses INSERT OR REPLACE.
pub fn save_backfill_progress(
    conn: &Connection,
    tool_key: &str,
    progress: &BackfillProgress,
    cursor: Option<&Cursor>,
) -> Result<(), HistorianError> {
    let cursor_json = cursor
        .map(|c| serde_json::to_string(c))
        .transpose()
        .map_err(|e| HistorianError::Json(e.to_string()))?;

    conn.execute(
        "INSERT OR REPLACE INTO backfill_progress
         (tool_type, sessions_total, sessions_done, started_at, completed_at, last_cursor)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tool_key,
            progress.sessions_total as i64,
            progress.sessions_done as i64,
            progress.started_at,
            progress.completed_at,
            cursor_json,
        ],
    )?;
    Ok(())
}

/// Load backfill progress for a tool. Returns None if no progress saved.
pub fn load_backfill_progress(
    conn: &Connection,
    tool_key: &str,
) -> Result<Option<(BackfillProgress, Option<Cursor>)>, HistorianError> {
    let row: Option<(i64, i64, Option<i64>, Option<i64>, Option<String>)> = conn
        .query_row(
            "SELECT sessions_total, sessions_done, started_at, completed_at, last_cursor
             FROM backfill_progress WHERE tool_type = ?1",
            params![tool_key],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    match row {
        None => Ok(None),
        Some((total, done, started, completed, cursor_json)) => {
            let cursor = cursor_json
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(serde_json::from_str::<Cursor>)
                .transpose()
                .map_err(|e| HistorianError::Json(e.to_string()))?;

            let progress = BackfillProgress {
                tool: None, // caller fills this
                sessions_total: total as u64,
                sessions_done: done as u64,
                started_at: started,
                completed_at: completed,
            };
            Ok(Some((progress, cursor)))
        }
    }
}

/// Update discovery report after backfill completes for a tool.
pub fn update_discovery_report(
    conn: &Connection,
    tool_key: &str,
    root_path: &str,
    session_count: u64,
    error_count: u64,
) -> Result<(), HistorianError> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO discovery_report (tool_type, root_path, first_seen_at, last_scan_at, session_count, error_count)
         VALUES (?1, ?2, ?3, ?3, ?4, ?5)
         ON CONFLICT(tool_type, root_path) DO UPDATE SET
           last_scan_at = ?3,
           session_count = ?4,
           error_count = ?5",
        params![tool_key, root_path, now, session_count as i64, error_count as i64],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_schema_creates_tables() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = open_historian_db(&db_path).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"already_processed".to_string()));
        assert!(tables.contains(&"backfill_progress".to_string()));
        assert!(tables.contains(&"discovery_report".to_string()));
        assert!(tables.contains(&"watch_state".to_string()));
    }

    #[test]
    fn init_schema_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = Connection::open(&db_path).unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap(); // second call should not fail
    }

    #[test]
    fn save_and_load_backfill_progress() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = open_historian_db(&db_path).unwrap();

        // Initially no progress
        assert!(load_backfill_progress(&conn, "claude_code").unwrap().is_none());

        // Save progress without cursor
        let progress = BackfillProgress {
            tool: None,
            sessions_total: 100,
            sessions_done: 42,
            started_at: Some(1700000000),
            completed_at: None,
        };
        save_backfill_progress(&conn, "claude_code", &progress, None).unwrap();

        let (loaded, cursor) = load_backfill_progress(&conn, "claude_code").unwrap().unwrap();
        assert_eq!(loaded.sessions_total, 100);
        assert_eq!(loaded.sessions_done, 42);
        assert_eq!(loaded.started_at, Some(1700000000));
        assert!(loaded.completed_at.is_none());
        assert!(cursor.is_none());
    }

    #[test]
    fn save_progress_with_cursor() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = open_historian_db(&db_path).unwrap();

        let cursor = Cursor::FileMtime {
            path: std::path::PathBuf::from("/tmp/test"),
            mtime: 1700000000000,
        };
        let progress = BackfillProgress {
            tool: None,
            sessions_total: 50,
            sessions_done: 50,
            started_at: Some(1700000000),
            completed_at: Some(1700000100),
        };
        save_backfill_progress(&conn, "gemini_cli", &progress, Some(&cursor)).unwrap();

        let (loaded, loaded_cursor) = load_backfill_progress(&conn, "gemini_cli").unwrap().unwrap();
        assert_eq!(loaded.sessions_done, 50);
        assert!(loaded.completed_at.is_some());
        let c = loaded_cursor.unwrap();
        assert!(matches!(c, Cursor::FileMtime { mtime: 1700000000000, .. }));
    }

    #[test]
    fn update_discovery_report_inserts_and_updates() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = open_historian_db(&db_path).unwrap();

        update_discovery_report(&conn, "claude_code", "/home/.claude/projects", 10, 1).unwrap();

        // Verify insert
        let count: i64 = conn
            .query_row(
                "SELECT session_count FROM discovery_report WHERE tool_type = 'claude_code'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 10);

        // Update same tool+root — should upsert
        update_discovery_report(&conn, "claude_code", "/home/.claude/projects", 25, 0).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT session_count FROM discovery_report WHERE tool_type = 'claude_code'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 25);
    }

    #[test]
    fn save_progress_replaces_on_conflict() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = open_historian_db(&db_path).unwrap();

        let p1 = BackfillProgress {
            tool: None,
            sessions_total: 100,
            sessions_done: 10,
            started_at: Some(1700000000),
            completed_at: None,
        };
        save_backfill_progress(&conn, "claude_code", &p1, None).unwrap();

        let p2 = BackfillProgress {
            tool: None,
            sessions_total: 100,
            sessions_done: 60,
            started_at: Some(1700000000),
            completed_at: None,
        };
        save_backfill_progress(&conn, "claude_code", &p2, None).unwrap();

        let (loaded, _) = load_backfill_progress(&conn, "claude_code").unwrap().unwrap();
        assert_eq!(loaded.sessions_done, 60, "should reflect latest save");
    }
}
