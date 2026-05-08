use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::Deserialize;
use tokio_stream::Stream;
use tracing::{trace, warn};

use crate::error::ReaderError;
use crate::reader::FormatReader;
use crate::session::estimate_tokens;
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

/// Reads OpenAI Codex CLI conversation history from `~/.codex/`.
///
/// Two storage locations are read and merged:
///
/// 1. **Session JSONL files** at `~/.codex/sessions/**/*.jsonl`
///    Each file contains newline-delimited JSON objects describing a single
///    conversation session. Typical directory layout:
///    ```text
///    ~/.codex/sessions/
///      2025/11/30/
///        rollout-019ad3a5-....jsonl
///      2025/12/01/
///        rollout-....jsonl
///    ```
///
/// 2. **History JSONL** at `~/.codex/history.jsonl`
///    A flat log of user prompts (no assistant replies). Lines are grouped by
///    `session_id` into synthetic sessions.
///
/// ## Session JSONL line types
///
/// Only `response_item` lines where `payload.type == "message"` are used:
/// - `payload.role == "user"` — extract text from `payload.content` items
///   with `type: "input_text"`
/// - `payload.role == "assistant"` — extract text from `payload.content` items
///   with `type: "output_text"`
///
/// `session_meta` lines supply the canonical `session_id`; all other line
/// types (`event_msg`, `turn_context`, and non-message `response_item`s such
/// as `reasoning`, `function_call`, `function_call_output`) are skipped.
///
/// ## History JSONL line format
///
/// ```jsonl
/// {"session_id":"uuid","ts":1757962470,"text":"user prompt text"}
/// ```
///
/// `ts` is Unix epoch **seconds**.
pub struct CodexReader {
    cursor: Mutex<Option<Cursor>>,
}

impl Default for CodexReader {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexReader {
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
}

// ---------------------------------------------------------------------------
// Deserialization types — session JSONL
// ---------------------------------------------------------------------------

/// Top-level wrapper for every line in a session JSONL file.
#[derive(Debug, Deserialize)]
struct SessionLine {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Deserialization types — history.jsonl
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct HistoryLine {
    session_id: String,
    /// Unix epoch seconds.
    ts: i64,
    text: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse an ISO 8601 / RFC 3339 timestamp string into epoch milliseconds.
fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.fZ")
                .ok()
                .map(|dt| dt.and_utc().timestamp_millis())
        })
}

/// Return the mtime of `path` in epoch milliseconds, or `None` on error.
fn file_mtime_millis(path: &Path) -> Option<i64> {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

/// Extract user-visible text from a Codex `payload.content` array.
///
/// `accepted_type` is either `"input_text"` (user messages) or `"output_text"`
/// (assistant messages).
fn extract_content_text(content: &serde_json::Value, accepted_type: &str) -> String {
    let Some(arr) = content.as_array() else {
        // Fallback: if content is a plain string, return it directly.
        if let Some(s) = content.as_str() {
            return s.to_string();
        }
        return String::new();
    };

    arr.iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            let item_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if item_type == accepted_type {
                obj.get("text").and_then(|v| v.as_str()).map(str::to_string)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Session JSONL parser
// ---------------------------------------------------------------------------

/// Parse one session JSONL file into a `HistoricalSession`.
///
/// Returns `Ok(None)` if the file has no usable messages or all messages are
/// filtered by `since`.
fn parse_session_jsonl(
    path: &Path,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "openai_codex".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    // session_id is populated from the session_meta line; fall back to the
    // filename stem if no such line exists.
    let filename_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut session_id: Option<String> = None;

    let mut messages: Vec<HistoricalMessage> = Vec::new();
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    for (line_num, raw) in content.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let line: SessionLine = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                trace!(
                    path = %path.display(),
                    line = line_num + 1,
                    err = %e,
                    "skipping malformed session JSONL line"
                );
                continue;
            }
        };

        let line_type = line.r#type.as_deref().unwrap_or("");

        match line_type {
            "session_meta" => {
                // Extract canonical session id from payload.id
                if let Some(ref payload) = line.payload {
                    if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
                        session_id = Some(id.to_string());
                    }
                }
                continue;
            }
            "response_item" => {
                // Fall through to message processing below.
            }
            // Skip event_msg, turn_context, and any other line types.
            _ => continue,
        }

        // From here we are handling a response_item line.
        let payload = match &line.payload {
            Some(p) => p,
            None => continue,
        };

        let payload_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");

        // Only process message items; skip reasoning, function_call,
        // function_call_output, etc.
        if payload_type != "message" {
            continue;
        }

        let role = match payload.get("role").and_then(|v| v.as_str()) {
            Some(r) => r,
            None => continue,
        };

        // Determine accepted content type based on role.
        let accepted_content_type = match role {
            "user" => "input_text",
            "assistant" => "output_text",
            _ => continue,
        };

        let text = match payload.get("content") {
            Some(content_val) => extract_content_text(content_val, accepted_content_type),
            None => String::new(),
        };

        if text.is_empty() {
            continue;
        }

        let ts = line.timestamp.as_deref().and_then(parse_iso_timestamp);

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

        let token_estimate = estimate_tokens(&text);
        messages.push(HistoricalMessage {
            role: role.to_string(),
            content: text,
            timestamp: ts,
            token_estimate,
            usage: None,
        });
    }

    if messages.is_empty() {
        return Ok(None);
    }

    Ok(Some(HistoricalSession {
        tool: AiTool::OpenAiCodex,
        session_id: session_id.unwrap_or(filename_stem),
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

// ---------------------------------------------------------------------------
// history.jsonl parser
// ---------------------------------------------------------------------------

/// Parse `~/.codex/history.jsonl`, grouping consecutive lines with the same
/// `session_id` into synthetic sessions (user messages only).
///
/// Returns sessions in the order they are first encountered.
fn parse_history_jsonl(
    path: &Path,
    since: Option<i64>,
    seen_session_ids: &HashSet<String>,
) -> Result<Vec<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "openai_codex".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    // Accumulate lines grouped by session_id, preserving insertion order.
    // Using a Vec of (session_id, Vec<HistoryLine>) to keep ordering.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<HistoryLine>> =
        std::collections::HashMap::new();

    for (line_num, raw) in content.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let entry: HistoryLine = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                trace!(
                    path = %path.display(),
                    line = line_num + 1,
                    err = %e,
                    "skipping malformed history.jsonl line"
                );
                continue;
            }
        };

        // ts is epoch seconds; convert to millis for the since comparison.
        let ts_ms = entry.ts * 1000;
        if let Some(since_ms) = since {
            if ts_ms < since_ms {
                continue;
            }
        }

        // Skip sessions already emitted from session JSONL files.
        if seen_session_ids.contains(&entry.session_id) {
            continue;
        }

        if !groups.contains_key(&entry.session_id) {
            order.push(entry.session_id.clone());
        }
        groups
            .entry(entry.session_id.clone())
            .or_default()
            .push(entry);
    }

    let mut sessions = Vec::new();
    for sid in order {
        let lines = match groups.remove(&sid) {
            Some(l) => l,
            None => continue,
        };

        let mut messages = Vec::new();
        let mut min_ts: Option<i64> = None;
        let mut max_ts: Option<i64> = None;

        for entry in &lines {
            let ts_ms = entry.ts * 1000;
            min_ts = Some(min_ts.map_or(ts_ms, |m: i64| m.min(ts_ms)));
            max_ts = Some(max_ts.map_or(ts_ms, |m: i64| m.max(ts_ms)));

            if entry.text.is_empty() {
                continue;
            }
            let token_estimate = estimate_tokens(&entry.text);
            messages.push(HistoricalMessage {
                role: "user".to_string(),
                content: entry.text.clone(),
                timestamp: Some(ts_ms),
                token_estimate,
                usage: None,
            });
        }

        if messages.is_empty() {
            continue;
        }

        sessions.push(HistoricalSession {
            tool: AiTool::OpenAiCodex,
            session_id: sid,
            messages,
            started_at: min_ts,
            ended_at: max_ts,
        });
    }

    Ok(sessions)
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Recursively collect all `.jsonl` files under `sessions_dir`, sorted by
/// mtime ascending (oldest first).
fn collect_session_jsonl_files(sessions_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(sessions_dir, &mut files);
    files.sort_by(|a, b| {
        let ma = a.metadata().and_then(|m| m.modified()).ok();
        let mb = b.metadata().and_then(|m| m.modified()).ok();
        ma.cmp(&mb)
    });
    files
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// FormatReader impl
// ---------------------------------------------------------------------------

#[async_trait]
impl FormatReader for CodexReader {
    fn tool_type(&self) -> AiTool {
        AiTool::OpenAiCodex
    }

    /// Returns `true` if `root` contains a `sessions/` subdirectory or a
    /// `history.jsonl` file — the two canonical Codex storage locations.
    fn detect(&self, root: &Path) -> bool {
        if !root.is_dir() {
            return false;
        }
        root.join("sessions").is_dir() || root.join("history.jsonl").is_file()
    }

    /// Stream all sessions from `root`.
    ///
    /// Session JSONL files are processed first; their `session_id`s are
    /// recorded so that `history.jsonl` can skip duplicate entries.
    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        let root = root.to_path_buf();

        // Incorporate cursor mtime into the `since` filter.
        let cursor_mtime = match self.cursor.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("cursor mutex poisoned, recovering");
                poisoned.into_inner()
            }
        }
        .as_ref()
        .and_then(|c| match c {
            Cursor::FileMtime { mtime, .. } => Some(*mtime),
            _ => None,
        });

        let effective_since = match (since, cursor_mtime) {
            (Some(s), Some(c)) => Some(s.max(c)),
            (Some(s), None) => Some(s),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        };

        Box::pin(async_stream::try_stream! {
            let sessions_dir = root.join("sessions");
            let history_path = root.join("history.jsonl");

            let mut latest_mtime: Option<i64> = None;
            let mut seen_session_ids: HashSet<String> = HashSet::new();

            // ---------------------------------------------------------------
            // 1. Session JSONL files
            // ---------------------------------------------------------------
            if sessions_dir.is_dir() {
                let jsonl_files = collect_session_jsonl_files(&sessions_dir);

                for path in jsonl_files {
                    let file_mtime = file_mtime_millis(&path);

                    match parse_session_jsonl(&path, effective_since) {
                        Ok(Some(session)) => {
                            seen_session_ids.insert(session.session_id.clone());
                            if let Some(mt) = file_mtime {
                                latest_mtime =
                                    Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
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
            }

            // ---------------------------------------------------------------
            // 2. history.jsonl (prompt-only, deduped against session files)
            // ---------------------------------------------------------------
            if history_path.is_file() {
                let history_mtime = file_mtime_millis(&history_path);

                match parse_history_jsonl(&history_path, effective_since, &seen_session_ids) {
                    Ok(history_sessions) => {
                        for session in history_sessions {
                            if let Some(mt) = history_mtime {
                                latest_mtime =
                                    Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
                            }
                            yield session;
                        }
                    }
                    Err(e) => {
                        warn!(path = %history_path.display(), err = %e, "error reading history.jsonl");
                    }
                }
            }

            // ---------------------------------------------------------------
            // 3. Update cursor
            // ---------------------------------------------------------------
            if let Some(mtime) = latest_mtime {
                let mut guard = match self.cursor.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        tracing::warn!("cursor mutex poisoned, recovering");
                        poisoned.into_inner()
                    }
                };
                *guard = Some(Cursor::FileMtime {
                    path: root,
                    mtime,
                });
            }
        })
    }

    fn last_cursor(&self) -> Option<Cursor> {
        match self.cursor.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => {
                tracing::warn!("cursor mutex poisoned, recovering");
                poisoned.into_inner().clone()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A realistic session JSONL file with all common line types.
    const REALISTIC_SESSION_JSONL: &str = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"019ad3a5-beef-dead-cafe-000000000001","timestamp":"2025-11-30T07:23:26.312Z","cwd":"/home/user/project","originator":"codex_cli_rs","cli_version":"0.39.0"}}
{"timestamp":"2025-11-30T07:23:26.400Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"refactor the auth module to use middleware"}]}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"event_msg","payload":{"event":"thinking"}}
{"timestamp":"2025-11-30T07:23:28.000Z","type":"turn_context","payload":{"turn":1}}
{"timestamp":"2025-11-30T07:23:29.000Z","type":"response_item","payload":{"type":"reasoning","content":null}}
{"timestamp":"2025-11-30T07:23:30.000Z","type":"response_item","payload":{"type":"function_call","content":null}}
{"timestamp":"2025-11-30T07:23:31.000Z","type":"response_item","payload":{"type":"function_call_output","content":null}}
{"timestamp":"2025-11-30T07:23:32.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I'll refactor the auth module to use middleware.\n\n```rust\npub struct AuthMiddleware;\n```"}]}}
{"timestamp":"2025-11-30T07:24:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"also add rate limiting"}]}}
{"timestamp":"2025-11-30T07:24:10.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Added rate limiting middleware with configurable window."}]}}"#;

    /// A session JSONL that has no session_meta line (tests filename fallback).
    const NO_META_SESSION_JSONL: &str = r#"{"timestamp":"2025-12-01T10:00:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello from no-meta session"}]}}
{"timestamp":"2025-12-01T10:00:05.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello back"}]}}"#;

    /// history.jsonl with two sessions.
    const HISTORY_JSONL: &str =
        "{\"session_id\":\"hist-session-aaa\",\"ts\":1757962470,\"text\":\"first prompt\"}\n\
         {\"session_id\":\"hist-session-aaa\",\"ts\":1757962490,\"text\":\"second prompt\"}\n\
         {\"session_id\":\"hist-session-bbb\",\"ts\":1757962500,\"text\":\"other session prompt\"}\n";

    // -----------------------------------------------------------------------
    // detect() tests
    // -----------------------------------------------------------------------

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = CodexReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_false_for_nonexistent_path() {
        let reader = CodexReader::new();
        assert!(!reader.detect(Path::new("/nonexistent/path/that/does/not/exist")));
    }

    #[test]
    fn detect_returns_true_with_sessions_subdir() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("sessions")).unwrap();
        let reader = CodexReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_with_history_jsonl() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("history.jsonl"), "").unwrap();
        let reader = CodexReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_with_both_present() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("sessions")).unwrap();
        fs::write(tmp.path().join("history.jsonl"), "").unwrap();
        let reader = CodexReader::new();
        assert!(reader.detect(tmp.path()));
    }

    // -----------------------------------------------------------------------
    // Session JSONL parsing tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reads_realistic_codex_session_jsonl() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "sessions/2025/11/30/rollout-abc.jsonl",
            REALISTIC_SESSION_JSONL,
        );

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(
            session.session_id, "019ad3a5-beef-dead-cafe-000000000001",
            "session_id should come from session_meta payload.id"
        );
        assert_eq!(session.tool, AiTool::OpenAiCodex);
        assert_eq!(session.messages.len(), 4, "should have 4 messages");

        assert_eq!(session.messages[0].role, "user");
        assert_eq!(
            session.messages[0].content,
            "refactor the auth module to use middleware"
        );
        assert_eq!(session.messages[1].role, "assistant");
        assert!(
            session.messages[1].content.contains("AuthMiddleware"),
            "assistant content should contain code"
        );
        assert_eq!(session.messages[2].role, "user");
        assert_eq!(session.messages[2].content, "also add rate limiting");
        assert_eq!(session.messages[3].role, "assistant");

        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
        assert!(session.ended_at.unwrap() > session.started_at.unwrap());
    }

    #[tokio::test]
    async fn skips_non_message_response_items() {
        let tmp = TempDir::new().unwrap();
        // File contains only reasoning, function_call, function_call_output — no messages.
        let content = r#"{"timestamp":"2025-11-30T08:00:00.000Z","type":"session_meta","payload":{"id":"skip-test","timestamp":"...","cwd":"/","originator":"codex_cli_rs","cli_version":"0.1.0"}}
{"timestamp":"2025-11-30T08:00:01.000Z","type":"response_item","payload":{"type":"reasoning","content":null}}
{"timestamp":"2025-11-30T08:00:02.000Z","type":"response_item","payload":{"type":"function_call","content":null}}
{"timestamp":"2025-11-30T08:00:03.000Z","type":"response_item","payload":{"type":"function_call_output","content":null}}
{"timestamp":"2025-11-30T08:00:04.000Z","type":"event_msg","payload":{"event":"done"}}
{"timestamp":"2025-11-30T08:00:05.000Z","type":"turn_context","payload":{"turn":1}}"#;
        write_file(tmp.path(), "sessions/s.jsonl", content);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        // No message-type response_items → no session should be yielded.
        assert!(
            stream.next().await.is_none(),
            "should yield no sessions when only non-message items present"
        );
    }

    #[tokio::test]
    async fn skips_event_msg_and_turn_context_lines() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"timestamp":"2025-11-30T09:00:00.000Z","type":"event_msg","payload":{"event":"start"}}
{"timestamp":"2025-11-30T09:00:01.000Z","type":"turn_context","payload":{"turn":1}}
{"timestamp":"2025-11-30T09:00:02.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"ping"}]}}"#;
        write_file(tmp.path(), "sessions/s.jsonl", content);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "ping");
    }

    #[tokio::test]
    async fn falls_back_to_filename_when_no_session_meta() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "sessions/my-special-session.jsonl",
            NO_META_SESSION_JSONL,
        );

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(
            session.session_id, "my-special-session",
            "should fall back to filename stem when session_meta is absent"
        );
        assert_eq!(session.messages.len(), 2);
    }

    #[tokio::test]
    async fn skips_malformed_lines_in_session_jsonl() {
        let tmp = TempDir::new().unwrap();
        let content = "NOT JSON AT ALL\n\
            {\"timestamp\":\"2025-12-01T10:00:00.000Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"valid\"}]}}\n\
            ALSO NOT JSON";
        write_file(tmp.path(), "sessions/s.jsonl", content);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "valid");
    }

    #[tokio::test]
    async fn ignores_empty_text_content_items() {
        let tmp = TempDir::new().unwrap();
        // A message whose input_text is the empty string — should be skipped.
        let content = r#"{"timestamp":"2025-12-01T11:00:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":""}]}}"#;
        write_file(tmp.path(), "sessions/empty.jsonl", content);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        assert!(
            stream.next().await.is_none(),
            "empty text should not produce a session"
        );
    }

    #[tokio::test]
    async fn collects_sessions_from_nested_date_dirs() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "sessions/2025/11/30/rollout-aaa.jsonl",
            REALISTIC_SESSION_JSONL,
        );
        // A second session without metadata to use filename fallback.
        write_file(
            tmp.path(),
            "sessions/2025/12/01/rollout-bbb.jsonl",
            NO_META_SESSION_JSONL,
        );

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }
        assert_eq!(sessions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // history.jsonl parsing tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reads_history_jsonl_entries() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "history.jsonl", HISTORY_JSONL);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }

        assert_eq!(sessions.len(), 2, "two distinct session_ids in history");

        // First session should have both prompts grouped together.
        let aaa = sessions
            .iter()
            .find(|s| s.session_id == "hist-session-aaa")
            .expect("hist-session-aaa should be present");
        assert_eq!(aaa.messages.len(), 2);
        assert_eq!(aaa.messages[0].role, "user");
        assert_eq!(aaa.messages[0].content, "first prompt");
        assert_eq!(aaa.messages[1].content, "second prompt");

        let bbb = sessions
            .iter()
            .find(|s| s.session_id == "hist-session-bbb")
            .expect("hist-session-bbb should be present");
        assert_eq!(bbb.messages.len(), 1);
        assert_eq!(bbb.messages[0].content, "other session prompt");
    }

    #[tokio::test]
    async fn history_jsonl_dedupes_against_session_files() {
        let tmp = TempDir::new().unwrap();

        // Session JSONL with a known session_id.
        let session_content = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"already-seen-id","timestamp":"2025-11-30T07:23:26.312Z","cwd":"/","originator":"codex_cli_rs","cli_version":"0.39.0"}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"session file prompt"}]}}"#;
        write_file(tmp.path(), "sessions/s.jsonl", session_content);

        // history.jsonl with the same session_id — should be skipped.
        let history_content =
            "{\"session_id\":\"already-seen-id\",\"ts\":1757962470,\"text\":\"duplicate prompt\"}\n\
             {\"session_id\":\"new-history-id\",\"ts\":1757962500,\"text\":\"unique prompt\"}\n";
        write_file(tmp.path(), "history.jsonl", history_content);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }

        // Expect: "already-seen-id" from session JSONL + "new-history-id" from history.
        assert_eq!(sessions.len(), 2);
        assert!(
            sessions.iter().any(|s| s.session_id == "already-seen-id"),
            "session from JSONL file should be present"
        );
        assert!(
            sessions.iter().any(|s| s.session_id == "new-history-id"),
            "unique history session should be present"
        );
        assert!(
            !sessions.iter().any(|s| s.session_id == "already-seen-id"
                && s.messages.iter().any(|m| m.content == "duplicate prompt")),
            "history duplicate should not appear"
        );
    }

    #[tokio::test]
    async fn history_ts_is_epoch_seconds_not_millis() {
        let tmp = TempDir::new().unwrap();
        // ts = 1757962470 seconds → 1_757_962_470_000 ms
        let history = "{\"session_id\":\"ts-test\",\"ts\":1757962470,\"text\":\"check ts\"}\n";
        write_file(tmp.path(), "history.jsonl", history);

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        let ts = session.messages[0].timestamp.unwrap();
        // Should be in milliseconds range (>> 1e12), not seconds range (<< 1e12).
        assert!(ts > 1_000_000_000_000, "timestamp should be in millis");
        assert_eq!(ts, 1_757_962_470_000);
    }

    // -----------------------------------------------------------------------
    // Cursor tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "sessions/s.jsonl",
            r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
        );

        let reader = CodexReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some(), "cursor should be set after read");
        assert!(
            matches!(cursor.unwrap(), Cursor::FileMtime { .. }),
            "cursor should be FileMtime"
        );
    }

    #[tokio::test]
    async fn cursor_updated_from_history_jsonl_when_no_sessions_dir() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "history.jsonl",
            "{\"session_id\":\"c1\",\"ts\":1757962470,\"text\":\"hello\"}\n",
        );

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
    }

    #[tokio::test]
    async fn since_filter_applied_to_session_jsonl_timestamps() {
        let tmp = TempDir::new().unwrap();
        // Two messages: one old (2024), one new (2025).
        let content = r#"{"timestamp":"2024-01-01T00:00:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"old message"}]}}
{"timestamp":"2025-06-01T00:00:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"new message"}]}}"#;
        write_file(tmp.path(), "sessions/s.jsonl", content);

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000Z")
            .unwrap()
            .timestamp_millis();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), Some(since));
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "new message");
    }

    #[tokio::test]
    async fn since_filter_applied_to_history_jsonl() {
        let tmp = TempDir::new().unwrap();
        // ts values: 1_000_000 (year ~1970 + ~11 days) and 1_757_962_470 (~2025).
        let history = "{\"session_id\":\"old\",\"ts\":1000000,\"text\":\"ancient\"}\n\
                       {\"session_id\":\"new\",\"ts\":1757962470,\"text\":\"modern\"}\n";
        write_file(tmp.path(), "history.jsonl", history);

        // since = 2020 epoch ms
        let since: i64 = 1_577_836_800_000; // 2020-01-01T00:00:00Z in ms

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), Some(since));
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "new");
    }
}
