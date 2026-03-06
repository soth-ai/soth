use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags};
use tokio_stream::Stream;
use tracing::warn;

use crate::error::ReaderError;
use crate::reader::FormatReader;
use crate::session::estimate_tokens;
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

/// Reads Gemini CLI conversation history from `~/.gemini/antigravity` (SQLite).
///
/// Opens the database read-only. If the database is WAL-locked by the Gemini
/// process we skip and retry on the next cycle rather than blocking.
pub struct GeminiReader {
    cursor: Mutex<Option<Cursor>>,
}

impl GeminiReader {
    pub fn new() -> Self {
        Self {
            cursor: Mutex::new(None),
        }
    }

    pub fn with_cursor(cursor: Cursor) -> Self {
        Self {
            cursor: Mutex::new(Some(cursor)),
        }
    }

    /// Resolve the actual SQLite file within the root path.
    fn resolve_db_path(root: &Path) -> Option<PathBuf> {
        if root.is_file() {
            return Some(root.to_path_buf());
        }
        for name in &["db.sqlite", "data.db", "antigravity.db"] {
            let candidate = root.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }

    fn open_readonly(db_path: &Path) -> Result<Connection, ReaderError> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ReaderError::Reader {
            tool: "gemini_cli".into(),
            message: format!("open {}: {e}", db_path.display()),
        })?;

        // Set a short busy timeout — if WAL locked, we'd rather skip than block.
        conn.busy_timeout(std::time::Duration::from_millis(500))
            .ok();

        Ok(conn)
    }
}

/// Probe for a messages-like table. Gemini CLI's schema may vary.
fn find_messages_table(conn: &Connection) -> Option<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .ok()?;
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .ok()?
        .filter_map(|r| r.ok())
        .collect();

    for candidate in &["messages", "conversation_messages", "turns"] {
        if names.iter().any(|n| n == *candidate) {
            return Some((*candidate).to_string());
        }
    }
    None
}

fn get_column_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Vec::new();
    };
    stmt.query_map([], |row| row.get::<_, String>(1))
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
}

/// Read sessions from the Gemini SQLite database.
fn read_gemini_sessions(
    db_path: &Path,
    since: Option<i64>,
    since_rowid: Option<i64>,
) -> Result<(Vec<HistoricalSession>, Option<i64>), ReaderError> {
    let conn = GeminiReader::open_readonly(db_path)?;

    let table = find_messages_table(&conn).ok_or_else(|| ReaderError::Reader {
        tool: "gemini_cli".into(),
        message: "no recognized messages table in Gemini DB".into(),
    })?;

    let columns = get_column_names(&conn, &table);

    let session_col = if columns.contains(&"session_id".to_string()) {
        "session_id"
    } else if columns.contains(&"conversation_id".to_string()) {
        "conversation_id"
    } else {
        "rowid"
    };

    let role_col = if columns.contains(&"role".to_string()) {
        "role"
    } else {
        "'unknown'"
    };

    let content_col = if columns.contains(&"content".to_string()) {
        "content"
    } else if columns.contains(&"text".to_string()) {
        "text"
    } else if columns.contains(&"body".to_string()) {
        "body"
    } else {
        return Err(ReaderError::Reader {
            tool: "gemini_cli".into(),
            message: format!("no content column found in table {table}"),
        });
    };

    let ts_col = if columns.contains(&"created_at".to_string()) {
        Some("created_at")
    } else if columns.contains(&"timestamp".to_string()) {
        Some("timestamp")
    } else {
        None
    };

    let order_col = ts_col.unwrap_or("rowid");

    // Build WHERE clause from since timestamp and/or rowid cursor
    let mut where_parts = Vec::new();
    if let (Some(ts), Some(col)) = (since, ts_col) {
        where_parts.push(format!("{col} > {ts}"));
    }
    if let Some(rowid) = since_rowid {
        where_parts.push(format!("rowid > {rowid}"));
    }
    let where_clause = if where_parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_parts.join(" AND "))
    };

    let sql = format!(
        "SELECT {session_col}, {role_col}, {content_col}{ts_select}, rowid FROM {table} {where_clause} ORDER BY {order_col} ASC",
        ts_select = ts_col.map(|c| format!(", {c}")).unwrap_or_default(),
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| ReaderError::Reader {
        tool: "gemini_cli".into(),
        message: format!("prepare query: {e}"),
    })?;

    let mut sessions: std::collections::HashMap<String, HistoricalSession> =
        std::collections::HashMap::new();
    let mut max_rowid: Option<i64> = None;

    let col_offset = if ts_col.is_some() { 4 } else { 3 };

    let rows = stmt
        .query_map([], |row| {
            let sid: String = row.get(0)?;
            let role: String = row.get(1)?;
            let content: String = row.get(2)?;
            let ts: Option<i64> = if ts_col.is_some() {
                row.get(3).ok()
            } else {
                None
            };
            let rowid: i64 = row.get(col_offset)?;
            Ok((sid, role, content, ts, rowid))
        })
        .map_err(|e| ReaderError::Reader {
            tool: "gemini_cli".into(),
            message: format!("query: {e}"),
        })?;

    for row in rows {
        let (sid, role, content, ts, rowid) = row.map_err(|e| ReaderError::Reader {
            tool: "gemini_cli".into(),
            message: format!("row: {e}"),
        })?;

        if content.is_empty() {
            continue;
        }

        max_rowid = Some(max_rowid.map_or(rowid, |prev: i64| prev.max(rowid)));

        let token_estimate = estimate_tokens(&content);

        let session = sessions.entry(sid.clone()).or_insert_with(|| HistoricalSession {
            tool: AiTool::GeminiCli,
            session_id: sid,
            messages: Vec::new(),
            started_at: None,
            ended_at: None,
        });

        if let Some(t) = ts {
            session.started_at = Some(session.started_at.map_or(t, |s: i64| s.min(t)));
            session.ended_at = Some(session.ended_at.map_or(t, |e: i64| e.max(t)));
        }

        session.messages.push(HistoricalMessage {
            role,
            content,
            timestamp: ts,
            token_estimate,
        });
    }

    let mut result: Vec<_> = sessions.into_values().collect();
    result.sort_by_key(|s| s.started_at.unwrap_or(0));
    Ok((result, max_rowid))
}

#[async_trait]
impl FormatReader for GeminiReader {
    fn tool_type(&self) -> AiTool {
        AiTool::GeminiCli
    }

    fn detect(&self, root: &Path) -> bool {
        GeminiReader::resolve_db_path(root).is_some()
    }

    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        let root = root.to_path_buf();
        let since_rowid = self
            .cursor
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| match c {
                Cursor::SqliteRowId { last_rowid, .. } => Some(*last_rowid),
                _ => None,
            });

        Box::pin(async_stream::try_stream! {
            let db_path = GeminiReader::resolve_db_path(&root).ok_or_else(|| ReaderError::Reader {
                tool: "gemini_cli".into(),
                message: "no SQLite database found".into(),
            })?;

            match read_gemini_sessions(&db_path, since, since_rowid) {
                Ok((sessions, max_rowid)) => {
                    for session in sessions {
                        yield session;
                    }
                    // Update cursor with the last rowid we processed
                    if let Some(rowid) = max_rowid {
                        let mut cursor = self.cursor.lock().unwrap();
                        *cursor = Some(Cursor::SqliteRowId {
                            db_path: db_path.clone(),
                            last_rowid: rowid,
                        });
                    }
                }
                Err(e) => {
                    // If it's a DB lock error, warn and skip (WAL contention)
                    let msg = e.to_string();
                    if msg.contains("locked") || msg.contains("busy") {
                        warn!(err = %e, "Gemini DB locked (WAL contention), will retry next cycle");
                    } else {
                        warn!(err = %e, "failed to read Gemini sessions");
                        Err(e)?;
                    }
                }
            }
        })
    }

    fn last_cursor(&self) -> Option<Cursor> {
        self.cursor.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn create_gemini_db(dir: &Path) -> PathBuf {
        let db_path = dir.join("db.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER
            )",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('s1', 'user', 'hello gemini', 1700000000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('s1', 'model', 'hello!', 1700000001000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('s2', 'user', 'second session', 1700000010000)",
            [],
        )
        .unwrap();
        db_path
    }

    fn create_gemini_db_alt_schema(dir: &Path) -> PathBuf {
        // Simulate a different Gemini CLI version with different column names
        let db_path = dir.join("db.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp INTEGER
            )",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('c1', 'user', 'alt schema', 1700000000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('c1', 'model', 'alt reply', 1700000001000)",
            [],
        )
        .unwrap();
        db_path
    }

    #[test]
    fn detect_finds_sqlite() {
        let tmp = TempDir::new().unwrap();
        create_gemini_db(tmp.path());
        let reader = GeminiReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = GeminiReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[tokio::test]
    async fn reads_sessions_from_sqlite() {
        let tmp = TempDir::new().unwrap();
        create_gemini_db(tmp.path());
        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].messages.len(), 2);
        assert_eq!(sessions[0].messages[0].role, "user");
        assert_eq!(sessions[0].messages[1].role, "model");
        assert_eq!(sessions[1].messages.len(), 1);
    }

    #[tokio::test]
    async fn respects_since_filter() {
        let tmp = TempDir::new().unwrap();
        create_gemini_db(tmp.path());
        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), Some(1700000005000));

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "s2");
    }

    #[tokio::test]
    async fn adapts_to_alternative_schema() {
        let tmp = TempDir::new().unwrap();
        create_gemini_db_alt_schema(tmp.path());
        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "c1");
        assert_eq!(sessions[0].messages.len(), 2);
        assert_eq!(sessions[0].messages[0].content, "alt schema");
    }

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        create_gemini_db(tmp.path());
        let reader = GeminiReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
        match cursor.unwrap() {
            Cursor::SqliteRowId { last_rowid, .. } => {
                assert!(last_rowid >= 3, "should track the last rowid processed");
            }
            other => panic!("expected SqliteRowId cursor, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn cursor_enables_incremental_reads() {
        let tmp = TempDir::new().unwrap();
        let db_path = create_gemini_db(tmp.path());

        // First read: get all 3 rows
        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut count = 0;
        while let Some(Ok(s)) = stream.next().await {
            count += s.messages.len();
        }
        assert_eq!(count, 3);

        // Add a new row
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('s3', 'user', 'new message', 1700000020000)",
            [],
        )
        .unwrap();
        drop(conn);

        // Second read with cursor: should only get the new row
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut new_count = 0;
        while let Some(Ok(s)) = stream.next().await {
            new_count += s.messages.len();
        }
        assert_eq!(new_count, 1, "should only read rows after the cursor");
    }
}
