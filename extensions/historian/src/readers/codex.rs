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

/// Reads OpenAI Codex CLI conversation history from `~/.codex/history/`.
///
/// Each JSON file is a single session object:
/// ```json
/// {
///   "id": "...",
///   "messages": [
///     { "role": "user", "content": "..." },
///     { "role": "assistant", "content": "..." }
///   ]
/// }
/// ```
pub struct CodexReader {
    cursor: Mutex<Option<Cursor>>,
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CodexSession {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    messages: Vec<CodexMessage>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodexMessage {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    timestamp: Option<i64>,
}

fn extract_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if let serde_json::Value::Object(obj) = v {
                    // Handle content block arrays: [{ "type": "text", "text": "..." }]
                    if obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                        obj.get("text").and_then(|t| t.as_str()).map(String::from)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
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

fn parse_codex_file(
    path: &Path,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: "openai_codex".into(),
        message: format!("read {}: {e}", path.display()),
    })?;

    let session: CodexSession = serde_json::from_str(&content).map_err(|e| ReaderError::Reader {
        tool: "openai_codex".into(),
        message: format!("parse {}: {e}", path.display()),
    })?;

    let mtime = file_mtime_millis(path);

    if let (Some(since_ms), Some(mt)) = (since, mtime) {
        if mt < since_ms {
            return Ok(None);
        }
    }

    let session_id = session.id.unwrap_or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    let mut messages = Vec::new();
    for msg in &session.messages {
        let role = msg.role.as_deref().unwrap_or("").to_string();
        let text = msg
            .content
            .as_ref()
            .map(extract_text)
            .unwrap_or_default();

        if role.is_empty() || text.is_empty() {
            continue;
        }

        let ts = msg.timestamp.or(mtime);
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

    // Use per-message timestamps if available, fallback to file mtime
    let started_at = messages.iter().filter_map(|m| m.timestamp).min().or(mtime);
    let ended_at = messages.iter().filter_map(|m| m.timestamp).max().or(mtime);

    Ok(Some(HistoricalSession {
        tool: AiTool::OpenAiCodex,
        session_id,
        messages,
        started_at,
        ended_at,
    }))
}

/// Collect all `.json` files under root, sorted by mtime ascending.
fn collect_json_files(root: &Path) -> Vec<PathBuf> {
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
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

#[async_trait]
impl FormatReader for CodexReader {
    fn tool_type(&self) -> AiTool {
        AiTool::OpenAiCodex
    }

    fn detect(&self, root: &Path) -> bool {
        if !root.is_dir() {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                == Some("json")
        })
    }

    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        let root = root.to_path_buf();

        // Use cursor mtime as additional since filter
        let cursor_mtime = self
            .cursor
            .lock()
            .unwrap()
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
            let json_files = collect_json_files(&root);
            let mut latest_mtime: Option<i64> = None;

            for path in json_files {
                match parse_codex_file(&path, effective_since) {
                    Ok(Some(session)) => {
                        if let Some(mt) = file_mtime_millis(&path) {
                            latest_mtime = Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
                        }
                        yield session;
                    }
                    Ok(None) => {
                        debug!(path = %path.display(), "no usable messages or filtered by since");
                    }
                    Err(e) => {
                        warn!(path = %path.display(), err = %e, "reader error, skipping file");
                    }
                }
            }

            // Update cursor
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    const REALISTIC_CODEX_SESSION: &str = r#"{
        "id": "codex-session-abc",
        "model": "o3-mini",
        "messages": [
            { "role": "user", "content": "refactor the auth module" },
            { "role": "assistant", "content": "I'll refactor the auth module to use middleware." },
            { "role": "user", "content": "also add rate limiting" },
            { "role": "assistant", "content": "Added rate limiting middleware with configurable window." }
        ]
    }"#;

    #[test]
    fn detect_returns_false_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let reader = CodexReader::new();
        assert!(!reader.detect(tmp.path()));
    }

    #[test]
    fn detect_returns_true_with_json_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("session1.json"), r#"{"messages":[]}"#).unwrap();
        let reader = CodexReader::new();
        assert!(reader.detect(tmp.path()));
    }

    #[tokio::test]
    async fn reads_realistic_codex_session() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sess.json"), REALISTIC_CODEX_SESSION).unwrap();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "codex-session-abc");
        assert_eq!(session.messages.len(), 4);
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[0].content, "refactor the auth module");
        assert_eq!(session.messages[1].role, "assistant");
    }

    #[tokio::test]
    async fn skips_invalid_json_continues_good_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("bad.json"), "NOT JSON").unwrap();
        std::fs::write(
            tmp.path().join("good.json"),
            r#"{"messages":[{"role":"user","content":"ok"}]}"#,
        )
        .unwrap();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            if let Ok(s) = result {
                sessions.push(s);
            }
        }
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn cursor_is_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("s.json"),
            r#"{"messages":[{"role":"user","content":"hi"}]}"#,
        )
        .unwrap();

        let reader = CodexReader::new();
        assert!(reader.last_cursor().is_none());

        let mut stream = reader.read_sessions(tmp.path(), None);
        while stream.next().await.is_some() {}

        let cursor = reader.last_cursor();
        assert!(cursor.is_some());
        assert!(matches!(cursor.unwrap(), Cursor::FileMtime { .. }));
    }

    #[tokio::test]
    async fn handles_content_block_arrays() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("s.json"),
            r#"{"messages":[{"role":"assistant","content":[{"type":"text","text":"hello"},{"type":"text","text":"world"}]}]}"#,
        )
        .unwrap();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages[0].content, "hello\nworld");
    }

    #[tokio::test]
    async fn uses_session_id_from_json() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("random-filename.json"),
            r#"{"id":"my-session-id","messages":[{"role":"user","content":"hi"}]}"#,
        )
        .unwrap();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "my-session-id");
    }

    #[tokio::test]
    async fn falls_back_to_filename_when_no_id() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("fallback-name.json"),
            r#"{"messages":[{"role":"user","content":"hi"}]}"#,
        )
        .unwrap();

        let reader = CodexReader::new();
        let mut stream = reader.read_sessions(tmp.path(), None);
        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "fallback-name");
    }
}
