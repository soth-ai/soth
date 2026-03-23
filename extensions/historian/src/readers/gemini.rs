use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::Deserialize;
use tokio_stream::Stream;
use tracing::{info, trace, warn};

use crate::error::ReaderError;
use crate::reader::FormatReader;
use crate::session::estimate_tokens;
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

/// Reads Gemini conversation history from local storage.
///
/// Two Gemini products store data locally:
///
/// 1. **Gemini CLI** (open-source, `google-gemini/gemini-cli`):
///    Stores conversations as JSON files at:
///    `~/.gemini/tmp/<project_hash>/chats/session-<timestamp>-<id>.json`
///
///    Each file is a `ConversationRecord` JSON object containing a messages
///    array with typed entries (user, gemini, info, etc.).
///
/// 2. **Gemini Desktop App** (codename "antigravity"):
///    Stores conversations as **encrypted binary** `.pb` files at:
///    `~/.gemini/antigravity/conversations/<uuid>.pb`
///
///    These files have near-maximum entropy and are NOT decodable without
///    the app's decryption keys. They are **unsupported** by this reader.
///
/// This reader supports the Gemini CLI JSON format only.
pub struct GeminiReader {
    cursor: Mutex<Option<Cursor>>,
}

impl Default for GeminiReader {
    fn default() -> Self {
        Self::new()
    }
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
}

// ---------------------------------------------------------------------------
// Deserialization types for Gemini CLI JSON format
// ---------------------------------------------------------------------------

/// Top-level conversation record written by the Gemini CLI.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConversationRecord {
    session_id: String,
    #[serde(default)]
    start_time: Option<String>,
    #[serde(default)]
    last_updated: Option<String>,
    #[serde(default)]
    messages: Vec<MessageRecord>,
}

/// A single message within a Gemini CLI conversation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct MessageRecord {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    /// Content can be a plain string, an object, or an array of parts.
    #[serde(default)]
    content: Option<serde_json::Value>,
    /// Human-readable display content (preferred over raw content when present).
    #[serde(default)]
    display_content: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    tokens: Option<TokenUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct TokenUsage {
    #[serde(default)]
    input: Option<u32>,
    #[serde(default)]
    output: Option<u32>,
    #[serde(default)]
    total: Option<u32>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Extract text from Gemini CLI message content.
///
/// Content can be:
/// - A plain string
/// - An array of part objects with `{ text: "..." }` fields
/// - An object with a `text` field
fn extract_content_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                if let Some(obj) = item.as_object() {
                    obj.get("text").and_then(|v| v.as_str()).map(String::from)
                } else {
                    item.as_str().map(|s| s.to_string())
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Object(obj) => obj
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn file_mtime_millis(path: &Path) -> Option<i64> {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

// ---------------------------------------------------------------------------
// JSON conversation parser
// ---------------------------------------------------------------------------

fn parse_conversation_json(
    path: &Path,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "gemini_cli".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    let record: ConversationRecord =
        serde_json::from_str(&content).map_err(|e| ReaderError::Reader {
            tool: "gemini_cli".into(),
            message: format!("parse {}: {e}", path.display()),
        })?;

    let mut messages = Vec::new();
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    for msg in &record.messages {
        let msg_type = msg.r#type.as_deref().unwrap_or("");

        // Map Gemini CLI message types to standard roles.
        let role = match msg_type {
            "user" => "user",
            "gemini" => "assistant",
            // Skip system/info/error/warning messages.
            _ => continue,
        };

        // Prefer display_content, fall back to content.
        let text = if let Some(ref dc) = msg.display_content {
            if dc.is_empty() {
                continue;
            }
            dc.clone()
        } else if let Some(ref content_val) = msg.content {
            let t = extract_content_text(content_val);
            if t.is_empty() {
                continue;
            }
            t
        } else {
            continue;
        };

        let ts = msg.timestamp.as_deref().and_then(parse_iso_timestamp);

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

        let token_estimate = msg
            .tokens
            .as_ref()
            .and_then(|t| t.total)
            .unwrap_or_else(|| estimate_tokens(&text));

        messages.push(HistoricalMessage {
            role: role.to_string(),
            content: text,
            timestamp: ts,
            token_estimate,
        });
    }

    if messages.is_empty() {
        return Ok(None);
    }

    // Use session start_time for session-level timestamps if per-message
    // timestamps weren't available.
    if min_ts.is_none() {
        min_ts = record.start_time.as_deref().and_then(parse_iso_timestamp);
    }
    if max_ts.is_none() {
        max_ts = record.last_updated.as_deref().and_then(parse_iso_timestamp);
    }

    Ok(Some(HistoricalSession {
        tool: AiTool::GeminiCli,
        session_id: record.session_id,
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Collect all Gemini CLI JSON conversation files.
///
/// Searches for: `<root>/tmp/*/chats/session-*.json`
/// Also checks: `<root>/chats/session-*.json` (in case root IS a project dir)
fn collect_gemini_json_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    // Primary path: ~/.gemini/tmp/<project_hash>/chats/session-*.json
    let tmp_dir = root.join("tmp");
    if tmp_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&tmp_dir) {
            for entry in entries.flatten() {
                let chats_dir = entry.path().join("chats");
                if chats_dir.is_dir() {
                    collect_json_in_dir(&chats_dir, &mut files);
                }
            }
        }
    }

    // Fallback: root itself contains chats/ (e.g. test fixtures or direct project root)
    let direct_chats = root.join("chats");
    if direct_chats.is_dir() {
        collect_json_in_dir(&direct_chats, &mut files);
    }

    // Also check for any .json files directly in root that match the pattern
    // (some Gemini CLI versions may store differently)
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("session-") {
                        files.push(path);
                    }
                }
            }
        }
    }

    // Sort by mtime ascending (oldest first).
    files.sort_by(|a, b| {
        let ma = a.metadata().and_then(|m| m.modified()).ok();
        let mb = b.metadata().and_then(|m| m.modified()).ok();
        ma.cmp(&mb)
    });

    files
}

fn collect_json_in_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

/// Check if a directory contains encrypted antigravity .pb files.
fn has_encrypted_antigravity(root: &Path) -> bool {
    let conversations = root.join("antigravity").join("conversations");
    if !conversations.is_dir() {
        // Also check if root IS the antigravity dir
        let direct = root.join("conversations");
        if direct.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&direct) {
                return entries
                    .flatten()
                    .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pb"));
            }
        }
        return false;
    }
    if let Ok(entries) = std::fs::read_dir(&conversations) {
        return entries
            .flatten()
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pb"));
    }
    false
}

// ---------------------------------------------------------------------------
// FormatReader impl
// ---------------------------------------------------------------------------

#[async_trait]
impl FormatReader for GeminiReader {
    fn tool_type(&self) -> AiTool {
        AiTool::GeminiCli
    }

    /// Detects Gemini CLI data (JSON chat files) or Gemini Desktop App data
    /// (encrypted .pb files — detected but unsupported).
    fn detect(&self, root: &Path) -> bool {
        if !root.is_dir() {
            return false;
        }

        // Check for Gemini CLI JSON files.
        let json_files = collect_gemini_json_files(root);
        if !json_files.is_empty() {
            return true;
        }

        // Check for encrypted antigravity data (detected but unreadable).
        if has_encrypted_antigravity(root) {
            info!(
                root = %root.display(),
                "detected Gemini Desktop App (antigravity) encrypted conversations; \
                 these are not readable by the historian"
            );
            return true;
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
            // Warn about encrypted antigravity data if present.
            if has_encrypted_antigravity(&root) {
                warn!(
                    "Gemini Desktop App (antigravity) conversations are encrypted \
                     and cannot be read by the historian. Only Gemini CLI JSON \
                     conversations are supported."
                );
            }

            let json_files = collect_gemini_json_files(&root);

            if json_files.is_empty() {
                trace!(root = %root.display(), "no Gemini CLI JSON files found");
                return;
            }

            let mut latest_mtime: Option<i64> = None;

            for path in json_files {
                let file_mtime = file_mtime_millis(&path);

                match parse_conversation_json(&path, since) {
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

            // Update cursor to latest file mtime.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }

    /// Realistic Gemini CLI ConversationRecord JSON.
    fn sample_conversation_json(session_id: &str) -> String {
        serde_json::json!({
            "sessionId": session_id,
            "projectHash": "abc123def",
            "startTime": "2026-01-15T10:30:00.000Z",
            "lastUpdated": "2026-01-15T10:35:00.000Z",
            "messages": [
                {
                    "type": "user",
                    "timestamp": "2026-01-15T10:30:00.000Z",
                    "content": "explain how async works in rust"
                },
                {
                    "type": "gemini",
                    "timestamp": "2026-01-15T10:30:05.000Z",
                    "content": "Async in Rust uses a poll-based model with futures.",
                    "model": "gemini-2.5-pro",
                    "tokens": { "input": 12, "output": 45, "total": 57 }
                },
                {
                    "type": "info",
                    "timestamp": "2026-01-15T10:30:06.000Z",
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
                    "displayContent": "Here is an example:\n```rust\nasync fn fetch() { }\n```",
                    "content": [{ "text": "Here is an example:\n```rust\nasync fn fetch() { }\n```" }],
                    "model": "gemini-2.5-pro",
                    "tokens": { "input": 20, "output": 30, "total": 50 }
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = GeminiReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_finds_json_in_chats_dir() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "chats/session-2026-01-15T10-30-00abc.json",
            &sample_conversation_json("s1"),
        );
        let reader = GeminiReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_finds_json_in_tmp_project_chats() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "tmp/abc123/chats/session-s1.json",
            &sample_conversation_json("s1"),
        );
        let reader = GeminiReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[test]
    fn detect_finds_encrypted_antigravity_pb() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "antigravity/conversations/uuid-1.pb",
            "encrypted binary data",
        );
        let reader = GeminiReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[tokio::test]
    async fn reads_gemini_cli_json_conversation() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "chats/session-s1.json",
            &sample_conversation_json("gemini-session-1"),
        );

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert_eq!(session.session_id, "gemini-session-1");
        assert_eq!(session.tool, AiTool::GeminiCli);
        assert_eq!(session.messages.len(), 4);

        assert_eq!(session.messages[0].role, "user");
        assert_eq!(
            session.messages[0].content,
            "explain how async works in rust"
        );

        assert_eq!(session.messages[1].role, "assistant");
        assert!(session.messages[1].content.contains("poll-based model"));

        // Info messages should be skipped
        assert_eq!(session.messages[2].role, "user");
        assert_eq!(session.messages[2].content, "show me an example");

        // displayContent should be preferred
        assert_eq!(session.messages[3].role, "assistant");
        assert!(session.messages[3].content.contains("async fn fetch()"));

        // Token counts from JSON should be used
        assert_eq!(session.messages[1].token_estimate, 57);
        assert_eq!(session.messages[3].token_estimate, 50);

        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
    }

    #[tokio::test]
    async fn reads_from_tmp_project_chats() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "tmp/project1/chats/session-a.json",
            &sample_conversation_json("proj1-session"),
        );
        write_file(
            tmp.path(),
            "tmp/project2/chats/session-b.json",
            &sample_conversation_json("proj2-session"),
        );

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            sessions.push(result.unwrap());
        }

        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn skips_info_and_error_messages() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "info-only",
            "messages": [
                { "type": "info", "content": "session started" },
                { "type": "error", "content": "something failed" },
                { "type": "warning", "content": "watch out" }
            ]
        })
        .to_string();
        write_file(tmp.path(), "chats/session-info.json", &json);

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        assert!(
            stream.next().await.is_none(),
            "should yield no sessions when only info/error/warning"
        );
    }

    #[tokio::test]
    async fn respects_since_filter() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "filtered",
            "messages": [
                {
                    "type": "user",
                    "timestamp": "2025-01-01T00:00:00.000Z",
                    "content": "old message"
                },
                {
                    "type": "gemini",
                    "timestamp": "2025-01-01T00:00:01.000Z",
                    "content": "old reply"
                },
                {
                    "type": "user",
                    "timestamp": "2026-06-01T00:00:00.000Z",
                    "content": "new message"
                },
                {
                    "type": "gemini",
                    "timestamp": "2026-06-01T00:00:01.000Z",
                    "content": "new reply"
                }
            ]
        })
        .to_string();
        write_file(tmp.path(), "chats/session-f.json", &json);

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .timestamp_millis();

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), Some(since));
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[0].content, "new message");
    }

    #[tokio::test]
    async fn handles_content_as_array_of_parts() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "parts",
            "messages": [
                {
                    "type": "user",
                    "content": [
                        { "text": "first part" },
                        { "text": "second part" }
                    ]
                }
            ]
        })
        .to_string();
        write_file(tmp.path(), "chats/session-parts.json", &json);

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert!(session.messages[0].content.contains("first part"));
        assert!(session.messages[0].content.contains("second part"));
    }

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "chats/session-c.json",
            &sample_conversation_json("cursor-test"),
        );

        let reader = GeminiReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
        assert!(matches!(cursor.unwrap(), Cursor::FileMtime { .. }));
    }

    #[tokio::test]
    async fn encrypted_pb_produces_no_sessions() {
        let tmp = TempDir::new().unwrap();
        // Only encrypted .pb files, no JSON — should detect but yield nothing.
        write_file(
            tmp.path(),
            "antigravity/conversations/uuid-1.pb",
            "encrypted data here",
        );

        let reader = GeminiReader::new();
        assert!(reader.detect(tmp.path()));

        let mut stream = reader.read_sessions(tmp.path(), None);
        assert!(
            stream.next().await.is_none(),
            "encrypted .pb files should not produce sessions"
        );
    }

    #[tokio::test]
    async fn uses_session_timestamps_when_messages_lack_them() {
        let tmp = TempDir::new().unwrap();
        let json = serde_json::json!({
            "sessionId": "no-msg-ts",
            "startTime": "2026-01-15T10:00:00.000Z",
            "lastUpdated": "2026-01-15T10:05:00.000Z",
            "messages": [
                { "type": "user", "content": "no timestamp message" },
                { "type": "gemini", "content": "no timestamp reply" }
            ]
        })
        .to_string();
        write_file(tmp.path(), "chats/session-nots.json", &json);

        let reader = GeminiReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();

        assert!(session.started_at.is_some());
        assert!(session.ended_at.is_some());
        assert_eq!(session.messages.len(), 2);
    }
}
