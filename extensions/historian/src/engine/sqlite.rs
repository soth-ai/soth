use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use rusqlite::{Connection, OpenFlags};
use tokio_stream::Stream;
use tracing::warn;

use crate::error::ReaderError;
use crate::playbook::{
    Playbook, PlaybookSource, RecordIterMethod, SessionIdConfig, SplitRecordSource,
};
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

use super::{
    extract_content, extract_role, extract_tokens, parse_timestamp, passes_filters, resolve_path,
    resolve_string,
};

/// Stream sessions from a SQLite key-value store using a playbook configuration.
///
/// `since` (epoch ms) drops sessions whose start timestamp is before the
/// cutoff. Applied in-process after row decode since the timestamp lives
/// inside a JSON value column. Used by watch mode to process only
/// recently-created composers and by backfill for time-bounded rescans.
pub fn read_sessions_sqlite<'a>(
    playbook: &'a Playbook,
    root: &Path,
    since: Option<i64>,
    cursor: &'a Mutex<Option<Cursor>>,
) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + 'a>> {
    let root = root.to_path_buf();

    let (db_file, table, key_prefix, value_column, split_source) = match &playbook.source {
        PlaybookSource::SqliteKv {
            db_file,
            table,
            key_prefix,
            value_column,
            split_record_source,
        } => (
            db_file.clone(),
            table.clone(),
            key_prefix.clone(),
            value_column.clone(),
            split_record_source.clone(),
        ),
        _ => return Box::pin(tokio_stream::empty()),
    };

    // Snapshot the last rowid for incremental reads.
    let since_rowid = match cursor.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::warn!("sqlite cursor mutex poisoned, recovering");
            poisoned.into_inner()
        }
    }
    .as_ref()
    .and_then(|c| match c {
        Cursor::SqliteRowId { last_rowid, .. } => Some(*last_rowid),
        _ => None,
    });

    Box::pin(async_stream::try_stream! {
        let db_path = resolve_db_path(&root, &db_file).ok_or_else(|| ReaderError::Reader {
            tool: playbook.tool.clone(),
            message: format!("{} not found at or beneath {}", db_file, root.display()),
        })?;

        match read_kv_sessions(&db_path, &table, &key_prefix, &value_column, since_rowid, since, split_source.as_ref(), playbook) {
            Ok((sessions, max_rowid)) => {
                for session in sessions {
                    yield session;
                }
                if let Some(rowid) = max_rowid {
                    let mut guard = match cursor.lock() {
                        Ok(g) => g,
                        Err(poisoned) => {
                            tracing::warn!("sqlite cursor mutex poisoned, recovering");
                            poisoned.into_inner()
                        }
                    };
                    *guard = Some(Cursor::SqliteRowId {
                        db_path: db_path.clone(),
                        last_rowid: rowid,
                    });
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("locked") || msg.contains("busy") {
                    warn!(err = %e, "SQLite DB locked, will retry next cycle");
                } else {
                    warn!(err = %e, "failed to read SQLite sessions");
                    Err(e)?;
                }
            }
        }
    })
}

/// Resolve the database file path, trying several locations.
fn resolve_db_path(root: &Path, db_file: &str) -> Option<PathBuf> {
    // Direct file reference.
    if root.is_file() {
        return Some(root.to_path_buf());
    }
    // Check in root directory.
    let direct = root.join(db_file);
    if direct.exists() {
        return Some(direct);
    }
    None
}

fn open_readonly(db_path: &Path, tool: &str) -> Result<Connection, ReaderError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| ReaderError::Reader {
        tool: tool.into(),
        message: format!("open {}: {e}", db_path.display()),
    })?;

    conn.busy_timeout(std::time::Duration::from_millis(500))
        .ok();
    Ok(conn)
}

fn read_kv_sessions(
    db_path: &Path,
    table: &str,
    key_prefix: &str,
    value_column: &str,
    since_rowid: Option<i64>,
    since_ms: Option<i64>,
    split_source: Option<&SplitRecordSource>,
    playbook: &Playbook,
) -> Result<(Vec<HistoricalSession>, Option<i64>), ReaderError> {
    let conn = open_readonly(db_path, &playbook.tool)?;

    // Verify the expected table exists.
    let table_exists: bool = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{}'",
                table.replace('\'', "''")
            ),
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);

    if !table_exists {
        return Err(ReaderError::Reader {
            tool: playbook.tool.clone(),
            message: format!("{table} table not found in {}", db_path.display()),
        });
    }

    let where_clause = if let Some(rowid) = since_rowid {
        format!(
            "WHERE key LIKE '{}%' AND rowid > {}",
            key_prefix.replace('\'', "''"),
            rowid
        )
    } else {
        format!("WHERE key LIKE '{}%'", key_prefix.replace('\'', "''"))
    };

    let sql =
        format!("SELECT {value_column}, rowid FROM {table} {where_clause} ORDER BY rowid ASC");

    let mut stmt = conn.prepare(&sql).map_err(|e| ReaderError::Reader {
        tool: playbook.tool.clone(),
        message: format!("prepare query: {e}"),
    })?;

    let tool = AiTool::from_key(&playbook.tool);
    let extraction = &playbook.extraction;
    let mut sessions = Vec::new();
    let mut max_rowid: Option<i64> = None;

    let rows = stmt
        .query_map([], |row| {
            let value: String = row.get(0)?;
            let rowid: i64 = row.get(1)?;
            Ok((value, rowid))
        })
        .map_err(|e| ReaderError::Reader {
            tool: playbook.tool.clone(),
            message: format!("query: {e}"),
        })?;

    for row in rows {
        let (value, rowid) = row.map_err(|e| ReaderError::Reader {
            tool: playbook.tool.clone(),
            message: format!("row: {e}"),
        })?;

        max_rowid = Some(max_rowid.map_or(rowid, |prev: i64| prev.max(rowid)));

        let doc: serde_json::Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "{}: skipping unparseable row", playbook.tool);
                continue;
            }
        };

        // Extract session_id.
        let session_id = match &extraction.session_id {
            SessionIdConfig::Field { path } => {
                resolve_string(&doc, path).unwrap_or_else(|| format!("row-{rowid}"))
            }
            _ => format!("row-{rowid}"),
        };

        // Get records array.
        let records = match &extraction.records.iterate {
            RecordIterMethod::Field { path } => match resolve_path(&doc, path) {
                Some(serde_json::Value::Array(arr)) if !arr.is_empty() => arr.clone(),
                _ => Vec::new(),
            },
            RecordIterMethod::Lines => vec![doc.clone()],
        };

        let mut messages = Vec::new();

        // Extract session-level timestamp if available.
        let session_ts = parse_timestamp(
            &doc,
            &extraction.timestamp.field,
            &extraction.timestamp.format,
        );

        // Skip sessions older than the since cutoff when both are known.
        if let (Some(cutoff), Some(ts)) = (since_ms, session_ts) {
            if ts < cutoff {
                continue;
            }
        }

        if records.is_empty() {
            // Declarative split-record fallback: the inline records array is
            // empty, so look up each record in a separate DB row using the
            // playbook-configured header list + key template. Used for
            // Cursor v14+ (`fullConversationHeadersOnly` → `bubbleId:*` rows).
            if let Some(split) = split_source {
                if let Some(serde_json::Value::Array(headers)) =
                    resolve_path(&doc, &split.headers_field)
                {
                    for header in headers {
                        let record_id = match header
                            .get(&split.header_id_field)
                            .and_then(|v| v.as_str())
                        {
                            Some(id) => id,
                            None => continue,
                        };

                        let record_key = split
                            .record_key_template
                            .replace("{session_id}", &session_id)
                            .replace("{record_id}", record_id);
                        let record_json: Option<String> = conn
                            .query_row(
                                &format!("SELECT {value_column} FROM {table} WHERE key = ?1"),
                                rusqlite::params![record_key],
                                |row| row.get(0),
                            )
                            .ok();

                        let Some(json_str) = record_json else {
                            continue;
                        };

                        let Ok(record_doc) = serde_json::from_str::<serde_json::Value>(&json_str)
                        else {
                            continue;
                        };

                        let role = match extract_role(&record_doc, &extraction.role) {
                            Some(r) => r,
                            None => continue,
                        };

                        let text = match extract_content(&record_doc, &extraction.content) {
                            Some(t) => t,
                            None => continue,
                        };

                        // Split-row timestamp: try the configured field/format
                        // first, then fall back to ISO-8601 parsing for record
                        // rows that use a different format than the session
                        // row (e.g. Cursor v14: composer=epoch_ms, bubble=iso8601),
                        // then to the session-level timestamp.
                        let ts = parse_timestamp(
                            &record_doc,
                            &extraction.timestamp.field,
                            &extraction.timestamp.format,
                        )
                        .or_else(|| {
                            record_doc
                                .get(&extraction.timestamp.field)
                                .and_then(|v| v.as_str())
                                .and_then(|s| {
                                    chrono::DateTime::parse_from_rfc3339(s)
                                        .ok()
                                        .map(|dt| dt.timestamp_millis())
                                })
                        })
                        .or(session_ts);

                        let token_estimate = extract_tokens(&record_doc, &extraction.tokens, &text);

                        messages.push(HistoricalMessage {
                            role,
                            content: text,
                            timestamp: ts,
                            token_estimate,
                        });
                    }
                }
            }
        } else {
            for record in &records {
                if !passes_filters(record, &extraction.records.filters) {
                    continue;
                }

                let role = match extract_role(record, &extraction.role) {
                    Some(r) => r,
                    None => continue,
                };

                let text = match extract_content(record, &extraction.content) {
                    Some(t) => t,
                    None => continue,
                };

                let ts = parse_timestamp(
                    record,
                    &extraction.timestamp.field,
                    &extraction.timestamp.format,
                )
                .or(session_ts);

                let token_estimate = extract_tokens(record, &extraction.tokens, &text);

                messages.push(HistoricalMessage {
                    role,
                    content: text,
                    timestamp: ts,
                    token_estimate,
                });
            }
        }

        if messages.is_empty() {
            continue;
        }

        let first_msg_ts = messages.first().and_then(|m| m.timestamp);
        let last_msg_ts = messages.last().and_then(|m| m.timestamp);

        sessions.push(HistoricalSession {
            tool: tool.clone(),
            session_id,
            messages,
            started_at: first_msg_ts.or(session_ts),
            ended_at: last_msg_ts.or(session_ts),
        });
    }

    // Sort chronologically.
    sessions.sort_by_key(|s| s.started_at.unwrap_or(0));

    Ok((sessions, max_rowid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn cursor_playbook() -> Playbook {
        Playbook {
            tool: "cursor".into(),
            version: 1,
            provider: "openai".into(),
            discovery: PlaybookDiscovery {
                roots: vec!["${HOME}/Library/Application Support/Cursor/User/globalStorage".into()],
                detect: PlaybookDetect::SqliteFile {
                    filename: "state.vscdb".into(),
                },
                exclude_dirs: vec![],
                exclude_file_patterns: vec![],
            },
            source: PlaybookSource::SqliteKv {
                db_file: "state.vscdb".into(),
                table: "cursorDiskKV".into(),
                key_prefix: "composerData:".into(),
                value_column: "value".into(),
                split_record_source: None,
            },
            extraction: PlaybookExtraction {
                session_id: SessionIdConfig::Field {
                    path: "composerId".into(),
                },
                records: RecordsConfig {
                    iterate: RecordIterMethod::Field {
                        path: "conversation".into(),
                    },
                    filters: vec![],
                },
                role: RoleConfig {
                    field: "type".into(),
                    value_map: [
                        ("1".to_string(), "user".to_string()),
                        ("2".to_string(), "assistant".to_string()),
                    ]
                    .into(),
                },
                content: ContentConfig::Plain {
                    field: "text".into(),
                },
                timestamp: TimestampConfig {
                    field: "createdAt".into(),
                    format: TimestampFormat::EpochMs,
                    session_start_field: None,
                    session_end_field: None,
                },
                tokens: None,
            },
        }
    }

    fn create_cursor_db(dir: &Path, rows: &[(&str, &str)]) -> PathBuf {
        let db_path = dir.join("state.vscdb");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
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
            .map(|(t, text)| serde_json::json!({"type": t, "text": text}))
            .collect();
        serde_json::json!({
            "composerId": id,
            "createdAt": created_at,
            "conversation": conversation
        })
        .to_string()
    }

    #[tokio::test]
    async fn cursor_playbook_reads_sessions() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[
                (
                    "composerData:s1",
                    &composer_json(
                        "s1",
                        1732629531988,
                        &[(1, "hello cursor"), (2, "hello user")],
                    ),
                ),
                (
                    "composerData:s2",
                    &composer_json("s2", 1732629600000, &[(1, "second session")]),
                ),
            ],
        );

        let pb = cursor_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);

        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }

        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].session_id, "s1");
        assert_eq!(sessions[0].tool, AiTool::Cursor);
        assert_eq!(sessions[0].messages.len(), 2);
        assert_eq!(sessions[0].messages[0].role, "user");
        assert_eq!(sessions[0].messages[0].content, "hello cursor");
        assert_eq!(sessions[0].messages[1].role, "assistant");
    }

    #[tokio::test]
    async fn skips_empty_conversations() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[
                (
                    "composerData:empty",
                    &serde_json::json!({
                        "composerId": "empty",
                        "createdAt": 1732629531988_i64,
                        "conversation": [
                            {"type": 1, "text": ""},
                            {"type": 2, "text": null}
                        ]
                    })
                    .to_string(),
                ),
                (
                    "composerData:good",
                    &composer_json("good", 1732629532000, &[(1, "real message")]),
                ),
            ],
        );

        let pb = cursor_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);

        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "good");
    }

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[(
                "composerData:s1",
                &composer_json("s1", 1732629531988, &[(1, "hi")]),
            )],
        );

        let pb = cursor_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        while stream.next().await.is_some() {}

        let c = cursor.lock().unwrap();
        assert!(c.is_some());
        match c.as_ref().unwrap() {
            Cursor::SqliteRowId { last_rowid, .. } => assert!(*last_rowid >= 1),
            other => panic!("expected SqliteRowId, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn incremental_reads_via_cursor() {
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

        let pb = cursor_playbook();
        let cursor = Mutex::new(None);

        // First read: both sessions.
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        let mut count = 0;
        while let Some(Ok(_)) = stream.next().await {
            count += 1;
        }
        assert_eq!(count, 2);

        // Insert a third row.
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

        // Second read: only new session.
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        let mut new_count = 0;
        while let Some(Ok(_)) = stream.next().await {
            new_count += 1;
        }
        assert_eq!(new_count, 1);
    }

    fn cursor_v14_playbook() -> Playbook {
        let mut pb = cursor_playbook();
        pb.version = 2;
        if let PlaybookSource::SqliteKv {
            ref mut split_record_source,
            ..
        } = pb.source
        {
            *split_record_source = Some(SplitRecordSource {
                headers_field: "fullConversationHeadersOnly".into(),
                header_id_field: "bubbleId".into(),
                record_key_template: "bubbleId:{session_id}:{record_id}".into(),
            });
        }
        pb
    }

    #[tokio::test]
    async fn cursor_v14_reads_split_bubble_rows() {
        // Simulates Cursor v14+: the composerData row has an empty inline
        // `conversation` and a `fullConversationHeadersOnly` pointer list.
        // Each bubble lives in its own `bubbleId:<session>:<bubble>` row.
        let tmp = TempDir::new().unwrap();
        let composer = serde_json::json!({
            "composerId": "sess1",
            "createdAt": 1732629531988_i64,
            "conversation": [],
            "fullConversationHeadersOnly": [
                {"bubbleId": "b1"},
                {"bubbleId": "b2"},
            ],
        })
        .to_string();
        let bubble1 = serde_json::json!({
            "type": 1,
            "text": "hello from v14",
            "createdAt": "2024-11-26T11:18:51.988Z",
        })
        .to_string();
        let bubble2 = serde_json::json!({
            "type": 2,
            "text": "hi — i'm the assistant",
            "createdAt": "2024-11-26T11:18:53.000Z",
        })
        .to_string();
        create_cursor_db(
            tmp.path(),
            &[
                ("composerData:sess1", &composer),
                ("bubbleId:sess1:b1", &bubble1),
                ("bubbleId:sess1:b2", &bubble2),
            ],
        );

        let pb = cursor_v14_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }

        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.session_id, "sess1");
        assert_eq!(s.messages.len(), 2, "both bubbles should resolve");
        assert_eq!(s.messages[0].role, "user");
        assert_eq!(s.messages[0].content, "hello from v14");
        assert_eq!(s.messages[1].role, "assistant");
        assert_eq!(s.messages[1].content, "hi — i'm the assistant");
        // ISO-8601 timestamp on the bubble resolved, not session's epoch-ms.
        assert_eq!(s.messages[0].timestamp, Some(1732619931988));
    }

    #[tokio::test]
    async fn cursor_v14_playbook_still_reads_legacy_inline_sessions() {
        // A playbook with split_record_source should still handle legacy rows
        // whose inline `conversation` array is populated.
        let tmp = TempDir::new().unwrap();
        create_cursor_db(
            tmp.path(),
            &[(
                "composerData:legacy",
                &composer_json("legacy", 1732629531988, &[(1, "inline hello")]),
            )],
        );

        let pb = cursor_v14_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].messages.len(), 1);
        assert_eq!(sessions[0].messages[0].content, "inline hello");
    }

    #[tokio::test]
    async fn cursor_v14_skips_bubbles_with_missing_rows() {
        // If a header points to a non-existent bubble row, it should be
        // skipped rather than failing the whole session.
        let tmp = TempDir::new().unwrap();
        let composer = serde_json::json!({
            "composerId": "sess1",
            "createdAt": 1732629531988_i64,
            "conversation": [],
            "fullConversationHeadersOnly": [
                {"bubbleId": "present"},
                {"bubbleId": "missing"},
            ],
        })
        .to_string();
        let bubble = serde_json::json!({
            "type": 1,
            "text": "only one survives",
            "createdAt": "2024-11-26T11:18:51.988Z",
        })
        .to_string();
        create_cursor_db(
            tmp.path(),
            &[
                ("composerData:sess1", &composer),
                ("bubbleId:sess1:present", &bubble),
            ],
        );

        let pb = cursor_v14_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);
        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].messages.len(), 1);
        assert_eq!(sessions[0].messages[0].content, "only one survives");
    }

    #[tokio::test]
    async fn returns_error_for_missing_table() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("state.vscdb");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE other (id INTEGER PRIMARY KEY)")
            .unwrap();
        drop(conn);

        let pb = cursor_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_sqlite(&pb, tmp.path(), None, &cursor);

        let result = stream.next().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }
}
