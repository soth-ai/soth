use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::Deserialize;
use tokio_stream::Stream;
use tracing::{debug, warn};

use crate::error::ReaderError;
use crate::reader::FormatReader;
use crate::session::estimate_tokens;
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

/// Reads OpenClaw conversation history from `~/.openclaw/agents/main/sessions/`.
///
/// Each `.jsonl` file is a single session with one JSON object per line.
/// Line types:
/// - `session_meta` — carries `payload.id` used as session_id (skipped for messages)
/// - `response_item` with `payload.type == "message"` — user/assistant turns
/// - `event_msg`, `turn_context` — internal state (skipped)
///
/// JSONL line format:
/// ```jsonl
/// {"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"uuid","timestamp":"...","cwd":"/path"}}
/// {"timestamp":"...","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"user message"}]}}
/// {"timestamp":"...","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"assistant response"}]}}
/// ```
pub struct OpenClawReader {
    cursor: Mutex<Option<Cursor>>,
}

impl OpenClawReader {
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
// Deserialization types — intentionally lenient, unknown fields are ignored.
// ---------------------------------------------------------------------------

/// Top-level JSONL line.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenClawLine {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

/// Payload of a `response_item` line when `payload.type == "message"`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MessagePayload {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
}

/// Payload of a `session_meta` line.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SessionMetaPayload {
    #[serde(default)]
    id: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract text from an OpenClaw content array.
///
/// Each element is a content block object. We extract text from:
/// - `{ "type": "input_text",  "text": "..." }` — user content
/// - `{ "type": "output_text", "text": "..." }` — assistant content
/// All other block types (tool calls, images, etc.) are skipped.
fn extract_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let block_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match block_type {
                    "input_text" | "output_text" => {
                        obj.get("text").and_then(|t| t.as_str()).map(String::from)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Parse an ISO 8601 timestamp string to epoch milliseconds.
fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
        .or_else(|| {
            // Tolerate timestamps that lack a timezone offset (e.g. "...Z" variants
            // that chrono's rfc3339 parser rejects on some platforms).
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.fZ")
                .ok()
                .map(|dt| dt.and_utc().timestamp_millis())
        })
}

/// Parse a single `.jsonl` file into a `HistoricalSession`.
///
/// Returns `Ok(None)` when the file contains no usable messages (e.g. only
/// `event_msg` lines), so callers can skip it silently.
fn parse_session(path: &Path, since: Option<i64>) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "openclaw".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    // Fall back to the filename stem if no session_meta line is found.
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

        let line: OpenClawLine = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    path = %path.display(),
                    line = line_num + 1,
                    err = %e,
                    "skipping malformed JSONL line"
                );
                continue;
            }
        };

        let line_type = line.r#type.as_deref().unwrap_or("");

        match line_type {
            "session_meta" => {
                // Extract session_id from payload.id — overrides filename stem.
                if let Some(ref payload_val) = line.payload {
                    if let Ok(meta) =
                        serde_json::from_value::<SessionMetaPayload>(payload_val.clone())
                    {
                        if let Some(id) = meta.id {
                            session_id = Some(id);
                        }
                    }
                }
                continue;
            }
            "response_item" => {
                // Only process lines where payload.type == "message".
                let payload_val = match &line.payload {
                    Some(v) => v,
                    None => continue,
                };
                let msg: MessagePayload =
                    match serde_json::from_value(payload_val.clone()) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                if msg.r#type.as_deref() != Some("message") {
                    continue;
                }

                let role = match msg.role.as_deref() {
                    Some(r) if !r.is_empty() => r.to_string(),
                    _ => continue,
                };

                let text = msg
                    .content
                    .as_ref()
                    .map(extract_text)
                    .unwrap_or_default();

                if text.is_empty() {
                    continue;
                }

                let ts = line.timestamp.as_deref().and_then(parse_iso_timestamp);

                // Apply the `since` filter on message timestamp.
                if let (Some(since_ms), Some(msg_ts)) = (since, ts) {
                    if msg_ts < since_ms {
                        continue;
                    }
                }

                if let Some(t) = ts {
                    min_ts = Some(min_ts.map_or(t, |m: i64| m.min(t)));
                    max_ts = Some(max_ts.map_or(t, |m: i64| m.max(t)));
                }

                messages.push(HistoricalMessage {
                    role,
                    content: text.clone(),
                    timestamp: ts,
                    token_estimate: estimate_tokens(&text),
                });
            }
            // Skip event_msg, turn_context, and anything else.
            _ => continue,
        }
    }

    if messages.is_empty() {
        return Ok(None);
    }

    Ok(Some(HistoricalSession {
        tool: AiTool::OpenClaw,
        session_id: session_id.unwrap_or(filename_stem),
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Recursively collect `.jsonl` files under `root`, sorted by mtime ascending.
///
/// Files whose name contains `.deleted.` are skipped (soft-deleted sessions).
fn collect_jsonl_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(root, &mut files);
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
            // Skip soft-deleted sessions.
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if file_name.contains(".deleted.") {
                continue;
            }
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// FormatReader impl
// ---------------------------------------------------------------------------

#[async_trait]
impl FormatReader for OpenClawReader {
    fn tool_type(&self) -> AiTool {
        AiTool::OpenClaw
    }

    /// Return `true` when `root` is a directory that contains at least one
    /// `.jsonl` file (at any depth).  A flat check on the immediate children
    /// is sufficient for the expected `sessions/` layout; the recursive case
    /// is handled as a fallback.
    fn detect(&self, root: &Path) -> bool {
        if !root.is_dir() {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                return true;
            }
            // One level of subdirectory (e.g. a `sessions/` subfolder).
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for sub_entry in sub.flatten() {
                        if sub_entry
                            .path()
                            .extension()
                            .and_then(|e| e.to_str())
                            == Some("jsonl")
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        let root = root.to_path_buf();

        Box::pin(async_stream::try_stream! {
            let jsonl_files = collect_jsonl_files(&root);
            let mut latest_mtime: Option<i64> = None;

            for path in jsonl_files {
                let file_mtime = path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64);

                match parse_session(&path, since) {
                    Ok(Some(session)) => {
                        if let Some(mt) = file_mtime {
                            latest_mtime =
                                Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
                        }
                        yield session;
                    }
                    Ok(None) => {
                        debug!(path = %path.display(), "no usable messages, skipping");
                    }
                    Err(e) => {
                        warn!(path = %path.display(), err = %e, "reader error, skipping file");
                    }
                }
            }

            // Advance the cursor to the highest mtime seen this run.
            if let Some(mtime) = latest_mtime {
                let mut cursor = self.cursor.lock().unwrap();
                *cursor = Some(Cursor::FileMtime {
                    path: root,
                    mtime,
                });
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

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }

    /// Realistic multi-turn OpenClaw session fixture.
    const REALISTIC_SESSION: &str = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"oc-session-abc","timestamp":"2025-11-30T07:23:26.312Z","cwd":"/home/user/project"}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"write a hello world in rust"}]}}
{"timestamp":"2025-11-30T07:23:28.500Z","type":"event_msg","payload":{"event":"thinking","data":"..."}}
{"timestamp":"2025-11-30T07:23:30.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Here is hello world:\n\n```rust\nfn main() { println!(\"Hello, world!\"); }\n```"}]}}
{"timestamp":"2025-11-30T07:23:31.000Z","type":"turn_context","payload":{"turn":1,"tool_calls":[]}}
{"timestamp":"2025-11-30T07:23:32.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"now add a name parameter"}]}}
{"timestamp":"2025-11-30T07:23:33.500Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"```rust\nfn hello(name: &str) { println!(\"Hello, {}!\", name); }\n```"}]}}"#;

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = OpenClawReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_with_jsonl_files() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "session-abc.jsonl", "{}");
        let reader = OpenClawReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_with_jsonl_in_subdir() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "sessions/session-abc.jsonl", "{}");
        let reader = OpenClawReader::new();
        assert!(reader.detect(tmp.path()));
    }

    // -----------------------------------------------------------------------
    // Realistic session parsing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reads_realistic_openclaw_session() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "oc-session-abc.jsonl", REALISTIC_SESSION);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(session.session_id, "oc-session-abc");
        assert_eq!(session.tool, AiTool::OpenClaw);
        assert_eq!(session.messages.len(), 4);

        // Roles
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[1].role, "assistant");
        assert_eq!(session.messages[2].role, "user");
        assert_eq!(session.messages[3].role, "assistant");

        // Content
        assert_eq!(session.messages[0].content, "write a hello world in rust");
        assert_eq!(session.messages[2].content, "now add a name parameter");
        assert!(session.messages[1].content.contains("fn main()"));
        assert!(session.messages[3].content.contains("fn hello(name"));

        // Timestamps parsed
        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
        assert!(session.ended_at.unwrap() > session.started_at.unwrap());
    }

    // -----------------------------------------------------------------------
    // Line-type filtering
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn skips_event_msg_and_turn_context_lines() {
        let tmp = TempDir::new().unwrap();
        // Only non-message lines — no session should be produced.
        let content = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"event_msg","payload":{"event":"thinking"}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"turn_context","payload":{"turn":1}}
{"timestamp":"2025-11-30T07:23:28.000Z","type":"session_meta","payload":{"id":"empty-session","cwd":"/"}}"#;
        write_file(tmp.path(), "empty.jsonl", content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn skips_response_item_lines_where_payload_type_is_not_message() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"response_item","payload":{"type":"tool_call","role":"assistant","content":[]}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}"#;
        write_file(tmp.path(), "mixed.jsonl", content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        // Only the message-type response_item should be included.
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "hello");
    }

    // -----------------------------------------------------------------------
    // session_id fallback
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn falls_back_to_filename_when_no_session_meta() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}"#;
        write_file(tmp.path(), "my-fallback-session.jsonl", content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "my-fallback-session");
    }

    #[tokio::test]
    async fn uses_session_id_from_session_meta() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"override-id","cwd":"/"}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}"#;
        write_file(tmp.path(), "random-filename.jsonl", content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "override-id");
    }

    // -----------------------------------------------------------------------
    // Soft-delete skip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn skips_deleted_files() {
        let tmp = TempDir::new().unwrap();
        // This file should be skipped entirely.
        let content = r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"should not appear"}]}}"#;
        write_file(tmp.path(), "session.deleted.20251130.jsonl", content);
        // This file should be read.
        write_file(
            tmp.path(),
            "live.jsonl",
            r#"{"timestamp":"2025-11-30T08:00:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"alive"}]}}"#,
        );

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages[0].content, "alive");
        assert!(stream.next().await.is_none());
    }

    // -----------------------------------------------------------------------
    // Cursor
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
        );

        let reader = OpenClawReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
        assert!(matches!(cursor.unwrap(), Cursor::FileMtime { .. }));
    }

    // -----------------------------------------------------------------------
    // Malformed / edge-case lines
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn skips_malformed_lines_gracefully() {
        let tmp = TempDir::new().unwrap();
        let content = format!(
            "NOT VALID JSON\n{}\nALSO NOT JSON",
            r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"valid"}]}}"#,
        );
        write_file(tmp.path(), "mixed.jsonl", &content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "valid");
    }

    #[tokio::test]
    async fn skips_content_blocks_that_are_not_text() {
        let tmp = TempDir::new().unwrap();
        // image block and tool_call block — neither should appear in content.
        let content = r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"image","url":"http://example.com/img.png"},{"type":"tool_call","name":"read_file"},{"type":"output_text","text":"actual text"}]}}"#;
        write_file(tmp.path(), "session.jsonl", content);

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages[0].content, "actual text");
    }

    // -----------------------------------------------------------------------
    // Token estimates
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn token_estimates_are_non_zero_for_non_empty_content() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"timestamp":"2025-11-30T07:23:27.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"this is a reasonably long message for token estimation"}]}}"#,
        );

        let reader = OpenClawReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert!(session.messages[0].token_estimate > 0);
    }
}
