use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use tokio_stream::Stream;
use tracing::{trace, warn};

use crate::error::ReaderError;
use crate::playbook::{Playbook, PlaybookSource, RecordIterMethod, SessionIdConfig};
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

use super::{
    extract_content, extract_role, extract_tokens, file_mtime_millis, parse_iso_timestamp,
    parse_timestamp, passes_filters, resolve_path, resolve_string,
};

/// Stream sessions from JSON files using a playbook configuration.
pub fn read_sessions_json<'a>(
    playbook: &'a Playbook,
    root: &Path,
    since: Option<i64>,
    cursor: &'a Mutex<Option<Cursor>>,
) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + 'a>> {
    let root = root.to_path_buf();

    let glob_pattern = match &playbook.source {
        PlaybookSource::JsonFiles { glob } => glob.clone(),
        _ => return Box::pin(tokio_stream::empty()),
    };

    Box::pin(async_stream::try_stream! {
        let files = collect_json_files(
            &root,
            &glob_pattern,
            &playbook.discovery.exclude_dirs,
        );

        let mut latest_mtime: Option<i64> = None;

        for path in files {
            let file_mtime = file_mtime_millis(&path);

            match parse_json_file(&path, playbook, since) {
                Ok(Some(session)) => {
                    if let Some(mt) = file_mtime {
                        latest_mtime = Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
                    }
                    yield session;
                }
                Ok(None) => {
                    trace!(path = %path.display(), "no usable messages, skipping");
                }
                Err(e) => {
                    warn!(path = %path.display(), err = %e, "reader error, skipping file");
                }
            }
        }

        if let Some(mtime) = latest_mtime {
            let mut guard = cursor.lock().unwrap();
            *guard = Some(Cursor::FileMtime {
                path: root,
                mtime,
            });
        }
    })
}

/// Parse a single JSON file into a HistoricalSession.
fn parse_json_file(
    path: &Path,
    playbook: &Playbook,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: playbook.tool.clone(),
        message: format!("read {}: {e}", path.display()),
    })?;

    let doc: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        ReaderError::Reader {
            tool: playbook.tool.clone(),
            message: format!("parse {}: {e}", path.display()),
        }
    })?;

    let tool = AiTool::from_key(&playbook.tool);
    let extraction = &playbook.extraction;

    // Extract session_id.
    let session_id = match &extraction.session_id {
        SessionIdConfig::FileStem => path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string(),
        SessionIdConfig::Field { path: id_path } => {
            resolve_string(&doc, id_path).unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            })
        }
        SessionIdConfig::MetaLine { .. } => {
            // MetaLine doesn't apply to JSON files; fall back to file stem.
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string()
        }
    };

    // Get the records array.
    let records = match &extraction.records.iterate {
        RecordIterMethod::Field { path: field_path } => {
            match resolve_path(&doc, field_path) {
                Some(serde_json::Value::Array(arr)) => arr.clone(),
                _ => return Ok(None),
            }
        }
        RecordIterMethod::Lines => {
            // For JSON files with Lines iteration, treat the whole doc as a single record.
            vec![doc.clone()]
        }
    };

    let mut messages = Vec::new();
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    for record in &records {
        // Apply filters.
        if !passes_filters(record, &extraction.records.filters) {
            continue;
        }

        // Extract role.
        let role = match extract_role(record, &extraction.role) {
            Some(r) => r,
            None => continue,
        };

        // Extract content.
        let text = match extract_content(record, &extraction.content) {
            Some(t) => t,
            None => continue,
        };

        // Extract timestamp.
        let ts = parse_timestamp(record, &extraction.timestamp.field, &extraction.timestamp.format);

        // Apply `since` filter.
        if let (Some(since_ms), Some(msg_ts)) = (since, ts) {
            if msg_ts < since_ms {
                continue;
            }
        }

        if let Some(t) = ts {
            min_ts = Some(min_ts.map_or(t, |m: i64| m.min(t)));
            max_ts = Some(max_ts.map_or(t, |m: i64| m.max(t)));
        }

        let token_estimate = extract_tokens(record, &extraction.tokens, &text);

        messages.push(HistoricalMessage {
            role,
            content: text,
            timestamp: ts,
            token_estimate,
        });
    }

    if messages.is_empty() {
        return Ok(None);
    }

    // Session-level timestamp fallbacks.
    if min_ts.is_none() {
        if let Some(ref start_field) = extraction.timestamp.session_start_field {
            if let Some(v) = resolve_path(&doc, start_field).and_then(|v| v.as_str()) {
                min_ts = parse_iso_timestamp(v);
            }
        }
    }
    if max_ts.is_none() {
        if let Some(ref end_field) = extraction.timestamp.session_end_field {
            if let Some(v) = resolve_path(&doc, end_field).and_then(|v| v.as_str()) {
                max_ts = parse_iso_timestamp(v);
            }
        }
    }

    Ok(Some(HistoricalSession {
        tool,
        session_id,
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Collect JSON files matching the glob pattern structure.
/// Supports patterns like:
/// - `**/*.json` (recursive)
/// - `tmp/*/chats/*.json` (specific structure)
/// - `chats/*.json` (single level)
fn collect_json_files(
    root: &Path,
    glob_pattern: &str,
    exclude_dirs: &[String],
) -> Vec<PathBuf> {
    let mut files = Vec::new();

    // Parse the glob to determine search strategy.
    if glob_pattern.contains("**") {
        // Recursive search.
        collect_recursive_json(root, &mut files, exclude_dirs, true);
    } else {
        // Try to match the glob structure.
        // e.g. "tmp/*/chats/*.json" -> search tmp/*/chats/
        collect_glob_pattern(root, glob_pattern, &mut files);
    }

    // Sort by mtime ascending.
    files.sort_by(|a, b| {
        let ma = a.metadata().and_then(|m| m.modified()).ok();
        let mb = b.metadata().and_then(|m| m.modified()).ok();
        ma.cmp(&mb)
    });

    files
}

fn collect_recursive_json(dir: &Path, out: &mut Vec<PathBuf>, exclude_dirs: &[String], is_root: bool) {
    if !is_root {
        let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if exclude_dirs.iter().any(|e| e == dir_name) {
            return;
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive_json(&path, out, exclude_dirs, false);
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

/// Match a simple glob pattern with `*` wildcards.
/// e.g. "tmp/*/chats/*.json" or "chats/*.json"
fn collect_glob_pattern(root: &Path, pattern: &str, out: &mut Vec<PathBuf>) {
    let segments: Vec<&str> = pattern.split('/').collect();
    collect_glob_segments(root, &segments, out);
}

fn collect_glob_segments(dir: &Path, segments: &[&str], out: &mut Vec<PathBuf>) {
    if segments.is_empty() {
        return;
    }

    let segment = segments[0];
    let remaining = &segments[1..];

    if segment == "*" {
        // Wildcard: match any entry at this level.
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if remaining.is_empty() {
                // Last segment — this shouldn't happen with *.json
                if path.is_file() {
                    out.push(path);
                }
            } else if path.is_dir() {
                collect_glob_segments(&path, remaining, out);
            }
        }
    } else if segment.contains('*') {
        // Pattern like "*.json" — match files at this level.
        let ext = segment.rsplit('.').next().unwrap_or("");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some(ext) {
                out.push(path);
            }
        }
    } else {
        // Literal directory name.
        let next = dir.join(segment);
        if next.is_dir() {
            collect_glob_segments(&next, remaining, out);
        } else if next.is_file() && remaining.is_empty() {
            out.push(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }

    fn gemini_playbook() -> Playbook {
        Playbook {
            tool: "gemini_cli".into(),
            version: 1,
            provider: "gemini".into(),
            discovery: PlaybookDiscovery {
                roots: vec!["${HOME}/.gemini".into()],
                detect: PlaybookDetect::GlobExists { pattern: "tmp/*/chats/*.json".into() },
                exclude_dirs: vec!["antigravity".into()],
                exclude_file_patterns: vec![],
            },
            source: PlaybookSource::JsonFiles {
                glob: "tmp/*/chats/*.json".into(),
            },
            extraction: PlaybookExtraction {
                session_id: SessionIdConfig::Field { path: "sessionId".into() },
                records: RecordsConfig {
                    iterate: RecordIterMethod::Field { path: "messages".into() },
                    filters: vec![RecordFilter {
                        field: "type".into(),
                        include: vec!["user".into(), "gemini".into()],
                    }],
                },
                role: RoleConfig {
                    field: "type".into(),
                    value_map: [("gemini".to_string(), "assistant".to_string())].into(),
                },
                content: ContentConfig::PreferDisplay {
                    display_field: "displayContent".into(),
                    fallback_field: "content".into(),
                },
                timestamp: TimestampConfig {
                    field: "timestamp".into(),
                    format: TimestampFormat::Iso8601,
                    session_start_field: Some("startTime".into()),
                    session_end_field: Some("lastUpdated".into()),
                },
                tokens: Some(TokenConfig { field: "tokens.total".into() }),
            },
        }
    }

    fn sample_gemini_json(session_id: &str) -> String {
        serde_json::json!({
            "sessionId": session_id,
            "startTime": "2026-01-15T10:30:00.000Z",
            "lastUpdated": "2026-01-15T10:35:00.000Z",
            "messages": [
                {
                    "type": "user",
                    "timestamp": "2026-01-15T10:30:00.000Z",
                    "content": "explain async in rust"
                },
                {
                    "type": "gemini",
                    "timestamp": "2026-01-15T10:30:05.000Z",
                    "content": "Async uses futures and polling.",
                    "tokens": { "input": 12, "output": 45, "total": 57 }
                },
                {
                    "type": "info",
                    "content": "Context updated"
                },
                {
                    "type": "user",
                    "timestamp": "2026-01-15T10:32:00.000Z",
                    "content": "show me an example"
                },
                {
                    "type": "gemini",
                    "timestamp": "2026-01-15T10:32:10.000Z",
                    "displayContent": "Here is an example:\n```rust\nasync fn fetch() {}\n```",
                    "content": [{"text": "raw content"}],
                    "tokens": { "total": 50 }
                }
            ]
        })
        .to_string()
    }

    #[tokio::test]
    async fn gemini_playbook_reads_session() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "tmp/proj1/chats/session-1.json",
            &sample_gemini_json("gem-session-1"),
        );

        let pb = gemini_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_json(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "gem-session-1");
        assert_eq!(session.tool, AiTool::GeminiCli);
        assert_eq!(session.messages.len(), 4);

        // Info messages should be filtered out.
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[0].content, "explain async in rust");
        assert_eq!(session.messages[1].role, "assistant");
        assert!(session.messages[1].content.contains("futures"));

        // Gemini role mapped to assistant.
        assert_eq!(session.messages[2].role, "user");
        assert_eq!(session.messages[3].role, "assistant");

        // displayContent preferred over content.
        assert!(session.messages[3].content.contains("async fn fetch()"));

        // Token counts from JSON.
        assert_eq!(session.messages[1].token_estimate, 57);
        assert_eq!(session.messages[3].token_estimate, 50);
    }

    #[tokio::test]
    async fn reads_multiple_project_dirs() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "tmp/proj1/chats/session-a.json",
            &sample_gemini_json("s1"),
        );
        write_file(
            tmp.path(),
            "tmp/proj2/chats/session-b.json",
            &sample_gemini_json("s2"),
        );

        let pb = gemini_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_json(&pb, tmp.path(), None, &cursor);

        let mut sessions = Vec::new();
        while let Some(r) = stream.next().await {
            sessions.push(r.unwrap());
        }
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn session_level_timestamp_fallback() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "no-msg-ts",
            "startTime": "2026-01-15T10:00:00.000Z",
            "lastUpdated": "2026-01-15T10:05:00.000Z",
            "messages": [
                { "type": "user", "content": "no timestamp" },
                { "type": "gemini", "content": "reply" }
            ]
        })
        .to_string();
        write_file(tmp.path(), "tmp/p/chats/session-t.json", &json);

        let pb = gemini_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_json(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
    }

    #[tokio::test]
    async fn since_filter_works() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "filtered",
            "messages": [
                { "type": "user", "timestamp": "2025-01-01T00:00:00.000Z", "content": "old" },
                { "type": "user", "timestamp": "2026-06-01T00:00:00.000Z", "content": "new" }
            ]
        })
        .to_string();
        write_file(tmp.path(), "tmp/p/chats/session-f.json", &json);

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .timestamp_millis();

        let pb = gemini_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_json(&pb, tmp.path(), Some(since), &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "new");
    }
}
