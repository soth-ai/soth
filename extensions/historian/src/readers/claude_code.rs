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

/// Reads Claude Code conversation history from `~/.claude/projects/`.
///
/// Real directory layout:
/// ```text
/// ~/.claude/projects/
///   <project-hash>/
///     <conversation-uuid>.jsonl   — one JSON object per line
///     <conversation-uuid>/        — directory for conversation metadata
///       subagents/
///         agent-*.jsonl           — sub-agent conversation logs
///     memory/
///       MEMORY.md
/// ```
///
/// JSONL line types:
/// - `type: "user"` — user message with `message.role: "user"`, `message.content: "..."`
/// - `type: "assistant"` — assistant message with `message.role: "assistant"`, `message.content: [{ type: "text", text: "..." }, ...]`
/// - `type: "system"` — system/command metadata (skipped for conversation reconstruction)
/// - `type: "file-history-snapshot"` — file backup snapshots (skipped)
/// - `type: "progress"` / `type: "queue-operation"` — internal state (skipped)
pub struct ClaudeCodeReader {
    cursor: Mutex<Option<Cursor>>,
}

impl Default for ClaudeCodeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeReader {
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

/// Deserialization of a Claude Code JSONL line.
/// Intentionally lenient — unknown fields and shapes are ignored.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ConversationLine {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default, alias = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    message: Option<MessagePayload>,
    /// Some lines have content at the top level (system lines).
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MessagePayload {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    id: Option<String>,
}

/// Extract text from content which can be either:
/// - A plain string: `"hello"`
/// - An array of content blocks: `[{ "type": "text", "text": "..." }, { "type": "thinking", ... }]`
fn extract_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| {
                if let serde_json::Value::Object(obj) = v {
                    let block_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match block_type {
                        "text" => obj.get("text").and_then(|t| t.as_str()).map(String::from),
                        // Skip thinking blocks, tool_use, tool_result for content hashing.
                        // They contain internal reasoning not user-facing content.
                        _ => None,
                    }
                } else {
                    v.as_str().map(|s| s.to_string())
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Parse ISO 8601 timestamp to epoch milliseconds.
fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
        .or_else(|| {
            // Try without timezone (some versions omit it)
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.fZ")
                .ok()
                .map(|dt| dt.and_utc().timestamp_millis())
        })
}

fn parse_session(
    path: &Path,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "claude_code".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    let session_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut messages = Vec::new();
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;
    let mut _model: Option<String> = None;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parsed: ConversationLine = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                trace!(
                    path = %path.display(),
                    line = line_num + 1,
                    err = %e,
                    "skipping malformed JSONL line"
                );
                continue;
            }
        };

        // Only process user and assistant message types.
        let line_type = parsed.r#type.as_deref().unwrap_or("");
        match line_type {
            "user" | "assistant" => {}
            // Skip system, file-history-snapshot, progress, queue-operation, etc.
            _ => continue,
        }

        // Extract role and content from the message payload.
        let msg = match &parsed.message {
            Some(m) => m,
            None => {
                // Some user lines have content at top level
                if line_type == "user" {
                    if let Some(ref content_val) = parsed.content {
                        let text = extract_text(content_val);
                        if text.is_empty() {
                            continue;
                        }
                        let ts = parsed.timestamp.as_deref().and_then(parse_iso_timestamp);
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
                            role: "user".to_string(),
                            content: text.clone(),
                            timestamp: ts,
                            token_estimate: estimate_tokens(&text),
                        });
                    }
                    continue;
                }
                continue;
            }
        };

        let role = msg.role.as_deref().unwrap_or(line_type).to_string();
        let text = msg.content.as_ref().map(extract_text).unwrap_or_default();

        if text.is_empty() {
            continue;
        }

        // Capture model from assistant messages.
        if role == "assistant" {
            if let Some(ref m) = msg.model {
                _model = Some(m.clone());
            }
        }

        let ts = parsed.timestamp.as_deref().and_then(parse_iso_timestamp);

        // Apply `since` filter if set.
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
            role,
            content: text,
            timestamp: ts,
            token_estimate,
        });
    }

    if messages.is_empty() {
        return Ok(None);
    }

    Ok(Some(HistoricalSession {
        tool: AiTool::ClaudeCode,
        session_id,
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

#[async_trait]
impl FormatReader for ClaudeCodeReader {
    fn tool_type(&self) -> AiTool {
        AiTool::ClaudeCode
    }

    fn detect(&self, root: &Path) -> bool {
        if !root.is_dir() {
            return false;
        }
        // Claude Code projects root contains project directories with .jsonl files
        // directly in them (not nested in a conversations/ subfolder).
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Top-level .jsonl files (project root IS the conversation storage)
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                return true;
            }
            // Or check inside project subdirectories
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for sub_entry in sub.flatten() {
                        if sub_entry.path().extension().and_then(|e| e.to_str()) == Some("jsonl") {
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

            // Update cursor to latest file mtime
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

/// Recursively collect all `.jsonl` files under root, sorted by mtime (oldest first).
/// Skips `memory/` directories.
fn collect_jsonl_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(root, &mut files, true);
    // Sort by modification time ascending for chronological order.
    files.sort_by(|a, b| {
        let ma = a.metadata().and_then(|m| m.modified()).ok();
        let mb = b.metadata().and_then(|m| m.modified()).ok();
        ma.cmp(&mb)
    });
    files
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>, is_root: bool) {
    if !is_root {
        let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Skip memory directories — these contain MEMORY.md, not conversations
        if dir_name == "memory" {
            return;
        }
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, out, false);
        } else if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
}

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

    // Realistic Claude Code JSONL fixture
    const REALISTIC_SESSION: &str = r#"{"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/home/user/project","sessionId":"abc-123","version":"2.1.31","type":"system","subtype":"local_command","content":"<command-name>/help</command-name>","level":"info","timestamp":"2026-02-04T20:58:56.037Z","uuid":"sys-1"}
{"type":"file-history-snapshot","messageId":"msg-1","snapshot":{"messageId":"msg-1","trackedFileBackups":{},"timestamp":"2026-02-04T20:59:06.191Z"},"isSnapshotUpdate":false}
{"parentUuid":"sys-1","isSidechain":false,"userType":"external","cwd":"/home/user/project","sessionId":"abc-123","version":"2.1.31","type":"user","message":{"role":"user","content":"write a hello world function in rust"},"uuid":"msg-1","timestamp":"2026-02-04T20:59:06.190Z"}
{"parentUuid":"msg-1","isSidechain":false,"userType":"external","cwd":"/home/user/project","sessionId":"abc-123","version":"2.1.31","type":"assistant","message":{"model":"claude-opus-4-5-20251101","id":"msg_resp1","type":"message","role":"assistant","content":[{"type":"thinking","thinking":"The user wants a hello world in Rust."},{"type":"text","text":"Here is a simple hello world function:\n\n```rust\nfn hello() {\n    println!(\"Hello, world!\");\n}\n```"}]},"uuid":"msg-2","timestamp":"2026-02-04T21:00:01.500Z"}
{"parentUuid":"msg-2","isSidechain":false,"userType":"external","cwd":"/home/user/project","sessionId":"abc-123","version":"2.1.31","type":"user","message":{"role":"user","content":"now add a parameter for the name"},"uuid":"msg-3","timestamp":"2026-02-04T21:01:15.000Z"}
{"parentUuid":"msg-3","isSidechain":false,"userType":"external","cwd":"/home/user/project","sessionId":"abc-123","version":"2.1.31","type":"assistant","message":{"model":"claude-opus-4-5-20251101","id":"msg_resp2","type":"message","role":"assistant","content":[{"type":"text","text":"```rust\nfn hello(name: &str) {\n    println!(\"Hello, {}!\", name);\n}\n```"}]},"uuid":"msg-4","timestamp":"2026-02-04T21:01:30.000Z"}"#;

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = ClaudeCodeReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_when_jsonl_at_root() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "conv.jsonl", "{}");
        let reader = ClaudeCodeReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_when_jsonl_in_subdir() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "project-abc/conv.jsonl", "{}");
        let reader = ClaudeCodeReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[tokio::test]
    async fn reads_realistic_claude_code_conversation() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "abc-123.jsonl", REALISTIC_SESSION);

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(session.session_id, "abc-123");
        assert_eq!(session.tool, AiTool::ClaudeCode);
        assert_eq!(session.messages.len(), 4);

        // Verify message roles
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[1].role, "assistant");
        assert_eq!(session.messages[2].role, "user");
        assert_eq!(session.messages[3].role, "assistant");

        // Verify user content is preserved
        assert_eq!(
            session.messages[0].content,
            "write a hello world function in rust"
        );
        assert_eq!(
            session.messages[2].content,
            "now add a parameter for the name"
        );

        // Verify assistant text blocks are extracted (thinking blocks skipped)
        assert!(session.messages[1].content.contains("fn hello()"));
        assert!(!session.messages[1].content.contains("The user wants"));

        // Verify timestamps are parsed from ISO 8601
        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
        assert!(session.ended_at.unwrap() > session.started_at.unwrap());
    }

    #[tokio::test]
    async fn skips_system_and_snapshot_lines() {
        let tmp = TempDir::new().unwrap();
        // Only system + file-history-snapshot lines, no user/assistant
        let content = r#"{"type":"system","subtype":"local_command","content":"test","timestamp":"2026-01-01T00:00:00.000Z"}
{"type":"file-history-snapshot","messageId":"m1","snapshot":{},"isSnapshotUpdate":false}
{"type":"progress","content":"working...","timestamp":"2026-01-01T00:00:01.000Z"}"#;
        write_file(tmp.path(), "session.jsonl", content);

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        // Should produce no sessions (no user/assistant messages)
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn skips_malformed_lines_gracefully() {
        let tmp = TempDir::new().unwrap();
        let content = format!(
            "NOT VALID JSON\n{}\nALSO NOT JSON\n",
            r#"{"type":"user","message":{"role":"user","content":"hello"},"timestamp":"2026-01-01T00:00:00.000Z"}"#
        );
        write_file(tmp.path(), "session.jsonl", &content);

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "hello");
    }

    #[tokio::test]
    async fn respects_since_filter_with_iso_timestamps() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"type":"user","message":{"role":"user","content":"old message"},"timestamp":"2025-01-01T00:00:00.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"old reply"}]},"timestamp":"2025-01-01T00:00:01.000Z"}
{"type":"user","message":{"role":"user","content":"new message"},"timestamp":"2026-06-01T00:00:00.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"new reply"}]},"timestamp":"2026-06-01T00:00:01.000Z"}"#;
        write_file(tmp.path(), "session.jsonl", content);

        // since = 2026-01-01 in epoch ms
        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .timestamp_millis();

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), Some(since));
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[0].content, "new message");
    }

    #[tokio::test]
    async fn handles_content_as_array_of_blocks() {
        let tmp = TempDir::new().unwrap();
        let content = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"Let me think..."},{"type":"text","text":"First part"},{"type":"text","text":"Second part"},{"type":"tool_use","id":"t1","name":"read","input":{}}]},"timestamp":"2026-01-01T00:00:00.000Z"}"#;
        write_file(tmp.path(), "session.jsonl", content);

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        // Should contain both text blocks, skip thinking and tool_use
        assert!(session.messages[0].content.contains("First part"));
        assert!(session.messages[0].content.contains("Second part"));
        assert!(!session.messages[0].content.contains("Let me think"));
    }

    #[tokio::test]
    async fn skips_memory_directory() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "memory/MEMORY.md", "# Memory\nSome notes");
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"hello"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        // Only the session.jsonl should be read, not memory/
        assert_eq!(session.messages.len(), 1);
    }

    #[tokio::test]
    async fn reads_subagent_conversations() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "main-session/subagents/agent-abc.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"sub task"},"timestamp":"2026-01-01T00:00:00.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"done"}]},"timestamp":"2026-01-01T00:00:01.000Z"}"#,
        );

        let reader = ClaudeCodeReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "agent-abc");
        assert_eq!(session.messages.len(), 2);
    }

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"hi"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let reader = ClaudeCodeReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
        assert!(matches!(cursor.unwrap(), Cursor::FileMtime { .. }));
    }
}
