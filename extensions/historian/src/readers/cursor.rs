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

/// Reads Cursor IDE conversation history from its VSCode-style SQLite state DB.
///
/// Cursor stores all composer conversations in:
/// `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`
///
/// The `cursorDiskKV` table holds JSON blobs keyed `composerData:<uuid>`.
/// Each blob encodes a full conversation with typed bubbles (1=user, 2=assistant).
///
/// Opens the database read-only. If the WAL is locked by the running Cursor
/// process we skip and retry on the next cycle rather than blocking.
pub struct CursorReader {
    cursor: Mutex<Option<Cursor>>,
}

impl CursorReader {
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

    /// Return the canonical path to the Cursor state database on macOS.
    ///
    /// `root` is the path supplied by the caller — if it points directly to
    /// the `.vscdb` file we use it as-is; otherwise we resolve the standard
    /// macOS location beneath it (or beneath `$HOME`).
    fn resolve_db_path(root: &Path) -> Option<PathBuf> {
        // Direct file reference (e.g. from tests or explicit config).
        if root.is_file() {
            return Some(root.to_path_buf());
        }

        // Check for state.vscdb directly inside the supplied directory.
        let direct = root.join("state.vscdb");
        if direct.exists() {
            return Some(direct);
        }

        // Fall back to the standard macOS installation path relative to root.
        let nested = root
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("globalStorage")
            .join("state.vscdb");
        if nested.exists() {
            return Some(nested);
        }

        None
    }

    /// Canonical macOS path, resolved from the real home directory.
    ///
    /// Useful for callers that want to check the live Cursor installation
    /// without going through the `detect` / root-resolution path.
    #[allow(dead_code)]
    fn default_db_path() -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        let path = home
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("globalStorage")
            .join("state.vscdb");
        if path.exists() { Some(path) } else { None }
    }

    fn open_readonly(db_path: &Path) -> Result<Connection, ReaderError> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ReaderError::Reader {
            tool: "cursor".into(),
            message: format!("open {}: {e}", db_path.display()),
        })?;

        // Short busy timeout — WAL contention with a live Cursor process is
        // expected; we prefer a fast skip over a long stall.
        conn.busy_timeout(std::time::Duration::from_millis(500)).ok();

        Ok(conn)
    }
}

// ---------------------------------------------------------------------------
// Wire types for JSON deserialization
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComposerData {
    composer_id: String,
    #[serde(default)]
    created_at: Option<i64>,
    #[serde(default)]
    conversation: Vec<ComposerBubble>,
}

#[derive(Debug, serde::Deserialize)]
struct ComposerBubble {
    /// 1 = user, 2 = assistant.
    #[serde(rename = "type")]
    bubble_type: u8,
    #[serde(default)]
    text: Option<String>,
}

impl ComposerBubble {
    fn role(&self) -> &'static str {
        match self.bubble_type {
            1 => "user",
            2 => "assistant",
            _ => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Core query logic (pure fn, no self borrow — easier to test)
// ---------------------------------------------------------------------------

fn read_cursor_sessions(
    db_path: &Path,
    since_rowid: Option<i64>,
) -> Result<(Vec<HistoricalSession>, Option<i64>), ReaderError> {
    let conn = CursorReader::open_readonly(db_path)?;

    // Verify the expected table exists; surface a clear error if it does not.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cursorDiskKV'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);

    if !table_exists {
        return Err(ReaderError::Reader {
            tool: "cursor".into(),
            message: "cursorDiskKV table not found in state.vscdb".into(),
        });
    }

    let where_clause = if let Some(rowid) = since_rowid {
        format!("WHERE key LIKE 'composerData:%' AND rowid > {rowid}")
    } else {
        "WHERE key LIKE 'composerData:%'".to_string()
    };

    let sql = format!(
        "SELECT value, rowid FROM cursorDiskKV {where_clause} ORDER BY rowid ASC"
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| ReaderError::Reader {
        tool: "cursor".into(),
        message: format!("prepare query: {e}"),
    })?;

    let mut sessions: Vec<HistoricalSession> = Vec::new();
    let mut max_rowid: Option<i64> = None;

    let rows = stmt
        .query_map([], |row| {
            let value: String = row.get(0)?;
            let rowid: i64 = row.get(1)?;
            Ok((value, rowid))
        })
        .map_err(|e| ReaderError::Reader {
            tool: "cursor".into(),
            message: format!("query: {e}"),
        })?;

    for row in rows {
        let (value, rowid) = row.map_err(|e| ReaderError::Reader {
            tool: "cursor".into(),
            message: format!("row: {e}"),
        })?;

        max_rowid = Some(max_rowid.map_or(rowid, |prev: i64| prev.max(rowid)));

        let data: ComposerData = match serde_json::from_str(&value) {
            Ok(d) => d,
            Err(e) => {
                warn!(err = %e, "cursor: skipping unparseable composerData row");
                continue;
            }
        };

        let mut messages: Vec<HistoricalMessage> = Vec::new();
        for bubble in &data.conversation {
            let text = match bubble.text.as_deref() {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => continue, // skip null / empty bubbles
            };

            let token_estimate = estimate_tokens(&text);
            messages.push(HistoricalMessage {
                role: bubble.role().to_string(),
                content: text,
                timestamp: data.created_at,
                token_estimate,
            });
        }

        if messages.is_empty() {
            continue;
        }

        let started_at = data.created_at;
        let ended_at = data.created_at;

        sessions.push(HistoricalSession {
            tool: AiTool::Cursor,
            session_id: data.composer_id,
            messages,
            started_at,
            ended_at,
        });
    }

    // Yield sessions in chronological order where timestamps are available.
    sessions.sort_by_key(|s| s.started_at.unwrap_or(0));

    Ok((sessions, max_rowid))
}

// ---------------------------------------------------------------------------
// FormatReader impl
// ---------------------------------------------------------------------------

#[async_trait]
impl FormatReader for CursorReader {
    fn tool_type(&self) -> AiTool {
        AiTool::Cursor
    }

    /// Returns `true` when a `state.vscdb` file is reachable from `root`.
    ///
    /// During normal operation `root` is the user's home directory and this
    /// resolves to `~/Library/Application Support/Cursor/…/state.vscdb`.
    /// In tests, `root` can point directly at a temp directory that contains
    /// the file, or at the file itself.
    fn detect(&self, root: &Path) -> bool {
        CursorReader::resolve_db_path(root).is_some()
    }

    fn read_sessions(
        &self,
        root: &Path,
        _since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        let root = root.to_path_buf();

        // Snapshot the last rowid before we move into the async block.
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
            let db_path = CursorReader::resolve_db_path(&root).ok_or_else(|| ReaderError::Reader {
                tool: "cursor".into(),
                message: format!(
                    "state.vscdb not found at or beneath {}",
                    root.display()
                ),
            })?;

            match read_cursor_sessions(&db_path, since_rowid) {
                Ok((sessions, max_rowid)) => {
                    for session in sessions {
                        yield session;
                    }
                    if let Some(rowid) = max_rowid {
                        let mut guard = self.cursor.lock().unwrap();
                        *guard = Some(Cursor::SqliteRowId {
                            db_path: db_path.clone(),
                            last_rowid: rowid,
                        });
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("locked") || msg.contains("busy") {
                        warn!(
                            err = %e,
                            "Cursor state.vscdb locked (WAL contention), will retry next cycle"
                        );
                    } else {
                        warn!(err = %e, "failed to read Cursor sessions");
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    /// Create a `state.vscdb` with the `cursorDiskKV` schema and the supplied
    /// composer rows. Returns the path to the database file.
    fn create_cursor_db(dir: &Path, rows: &[(&str, &str)]) -> PathBuf {
        let db_path = dir.join("state.vscdb");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )
        .unwrap();
        for (key, value) in rows {
            conn.execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, value],
            )
            .unwrap();
        }
        db_path
    }

    fn composer_json(id: &str, created_at: i64, bubbles: &[(u8, &str)]) -> String {
        let conversation: Vec<serde_json::Value> = bubbles
            .iter()
            .map(|(t, text)| {
                serde_json::json!({
                    "type": t,
                    "bubbleId": format!("bubble-{t}-{id}"),
                    "text": text
                })
            })
            .collect();
        serde_json::json!({
            "composerId": id,
            "createdAt": created_at,
            "conversation": conversation
        })
        .to_string()
    }

    // ------------------------------------------------------------------
    // detect
    // ------------------------------------------------------------------

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = CursorReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_finds_sqlite_in_dir() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(tmp.path(), &[]);
        let reader = CursorReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_accepts_direct_file_path() {
        let tmp = TempDir::new().unwrap();
        let db_path = create_cursor_db(tmp.path(), &[]);
        let reader = CursorReader::new();
        assert!(reader.detect(&db_path));
    }

    // ------------------------------------------------------------------
    // read_sessions
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn reads_sessions_from_sqlite() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[
                (
                    "composerData:session-1",
                    &composer_json(
                        "session-1",
                        1732629531988,
                        &[(1, "hello cursor"), (2, "hello user")],
                    ),
                ),
                (
                    "composerData:session-2",
                    &composer_json("session-2", 1732629600000, &[(1, "second session")]),
                ),
            ],
        );

        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }

        assert_eq!(sessions.len(), 2);

        // Sorted chronologically — session-1 has the earlier createdAt.
        assert_eq!(sessions[0].session_id, "session-1");
        assert_eq!(sessions[0].messages.len(), 2);
        assert_eq!(sessions[0].messages[0].role, "user");
        assert_eq!(sessions[0].messages[0].content, "hello cursor");
        assert_eq!(sessions[0].messages[1].role, "assistant");
        assert_eq!(sessions[0].messages[1].content, "hello user");

        assert_eq!(sessions[1].session_id, "session-2");
        assert_eq!(sessions[1].messages.len(), 1);
        assert_eq!(sessions[1].messages[0].role, "user");
    }

    #[tokio::test]
    async fn skips_empty_conversations() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[
                // All bubbles have empty text — should be skipped entirely.
                (
                    "composerData:empty-session",
                    &serde_json::json!({
                        "composerId": "empty-session",
                        "createdAt": 1732629531988_i64,
                        "conversation": [
                            { "type": 1, "bubbleId": "b1", "text": "" },
                            { "type": 2, "bubbleId": "b2", "text": null }
                        ]
                    })
                    .to_string(),
                ),
                // One valid session alongside the empty one.
                (
                    "composerData:good-session",
                    &composer_json("good-session", 1732629532000, &[(1, "real message")]),
                ),
            ],
        );

        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }

        assert_eq!(sessions.len(), 1, "empty conversation must be skipped");
        assert_eq!(sessions[0].session_id, "good-session");
    }

    #[tokio::test]
    async fn skips_null_text_bubbles() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[(
                "composerData:mixed",
                &serde_json::json!({
                    "composerId": "mixed",
                    "createdAt": 1732629531988_i64,
                    "conversation": [
                        { "type": 1, "bubbleId": "b1", "text": null },
                        { "type": 1, "bubbleId": "b2", "text": "actual message" },
                        { "type": 2, "bubbleId": "b3", "text": "" }
                    ]
                })
                .to_string(),
            )],
        );

        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "actual message");
        assert!(stream.next().await.is_none());
    }

    // ------------------------------------------------------------------
    // cursor / incremental reads
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[(
                "composerData:s1",
                &composer_json("s1", 1732629531988, &[(1, "hi"), (2, "hello")]),
            )],
        );

        let reader = CursorReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some(), "cursor should be set after a successful read");
        match cursor.unwrap() {
            Cursor::SqliteRowId { last_rowid, .. } => {
                assert!(last_rowid >= 1, "rowid must be at least 1");
            }
            other => panic!("expected SqliteRowId cursor, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn cursor_enables_incremental_reads() {
        let tmp = TempDir::new().unwrap();
        let db_path = create_cursor_db(
            tmp.path(),
            &[
                (
                    "composerData:s1",
                    &composer_json("s1", 1732629531988, &[(1, "first")]),
                ),
                (
                    "composerData:s2",
                    &composer_json("s2", 1732629540000, &[(1, "second")]),
                ),
            ],
        );

        // First read: consume both sessions.
        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut count = 0usize;
        while let Some(Ok(_)) = stream.next().await {
            count += 1;
        }
        assert_eq!(count, 2);

        // Insert a third row after the cursor position.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                rusqlite::params![
                    "composerData:s3",
                    composer_json("s3", 1732629600000, &[(1, "third")])
                ],
            )
            .unwrap();
        }

        // Second read: should only yield the newly inserted session.
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut new_count = 0usize;
        while let Some(Ok(_)) = stream.next().await {
            new_count += 1;
        }
        assert_eq!(new_count, 1, "incremental read must skip already-seen rows");
    }

    #[tokio::test]
    async fn returns_error_when_table_missing() {
        let tmp = TempDir::new().unwrap();
        // Create a valid SQLite file but without cursorDiskKV.
        let db_path = tmp.path().join("state.vscdb");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE other (id INTEGER PRIMARY KEY)")
            .unwrap();
        drop(conn);

        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let result = stream.next().await;
        assert!(
            result.is_some(),
            "should yield at least one item (the error)"
        );
        assert!(result.unwrap().is_err(), "missing table must be an error");
    }

    #[tokio::test]
    async fn tool_type_is_cursor() {
        let reader = CursorReader::new();
        assert_eq!(reader.tool_type(), AiTool::Cursor);
    }

    #[tokio::test]
    async fn timestamps_propagated_from_created_at() {
        let tmp = TempDir::new().unwrap();
        let ts: i64 = 1732629531988;
        create_cursor_db(
            tmp.path(),
            &[(
                "composerData:ts-test",
                &composer_json("ts-test", ts, &[(1, "msg")]),
            )],
        );

        let reader = CursorReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(session.started_at, Some(ts));
        assert_eq!(session.ended_at, Some(ts));
        assert_eq!(session.messages[0].timestamp, Some(ts));
    }
}
