pub mod json_file;
pub mod jsonl;
pub mod sqlite;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio_stream::Stream;

use crate::error::ReaderError;
use crate::playbook::{
    ContentConfig, Playbook, PlaybookDetect, PlaybookSource, RecordFilter, RoleConfig,
    TimestampFormat, TokenConfig,
};
use crate::reader::FormatReader;
use crate::session::estimate_tokens;
use crate::types::{AiTool, Cursor, HistoricalSession};

// ---------------------------------------------------------------------------
// Field extraction utilities
// ---------------------------------------------------------------------------

/// Resolve a dot-separated path (e.g. "message.content") against a JSON value.
pub fn resolve_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Resolve a dot-path and return the value as a string.
/// Handles both string values and numbers (converts to string).
pub fn resolve_string(value: &serde_json::Value, path: &str) -> Option<String> {
    let v = resolve_path(value, path)?;
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Check whether a record passes all the given filters.
pub fn passes_filters(record: &serde_json::Value, filters: &[RecordFilter]) -> bool {
    for filter in filters {
        let field_val = match resolve_string(record, &filter.field) {
            Some(v) => v,
            None => return false,
        };
        if !filter.include.contains(&field_val) {
            return false;
        }
    }
    true
}

/// Extract the message role from a record, applying the value_map.
pub fn extract_role(record: &serde_json::Value, config: &RoleConfig) -> Option<String> {
    let raw = resolve_string(record, &config.field)?;
    let mapped = config.value_map.get(&raw).cloned().unwrap_or(raw);
    if mapped.is_empty() {
        None
    } else {
        Some(mapped)
    }
}

/// Extract content text from a record using the configured strategy.
pub fn extract_content(record: &serde_json::Value, config: &ContentConfig) -> Option<String> {
    match config {
        ContentConfig::Plain { field } => {
            let v = resolve_path(record, field)?;
            let text = value_to_string(v);
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        ContentConfig::TextBlocks {
            field,
            type_field,
            text_field,
            include_types,
        } => {
            let v = resolve_path(record, field)?;
            let text = extract_text_blocks(v, type_field, text_field, include_types);
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        ContentConfig::PreferDisplay {
            display_field,
            fallback_field,
        } => {
            // Try display field first.
            if let Some(v) = resolve_path(record, display_field) {
                let text = value_to_string(v);
                if !text.is_empty() {
                    return Some(text);
                }
            }
            // Fallback to content field.
            let v = resolve_path(record, fallback_field)?;
            let text = extract_generic_text(v);
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
    }
}

/// Extract text from a JSON value that's either a string or an array of typed blocks.
fn extract_text_blocks(
    value: &serde_json::Value,
    type_field: &str,
    text_field: &str,
    include_types: &[String],
) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                let obj = item.as_object()?;
                let block_type = obj.get(type_field).and_then(|t| t.as_str()).unwrap_or("");
                if include_types.iter().any(|t| t == block_type) {
                    obj.get(text_field)
                        .and_then(|t| t.as_str())
                        .map(String::from)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Generic text extraction for fallback content: handles string, array of {text}, or {text}.
fn extract_generic_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                if let Some(s) = item.as_str() {
                    Some(s.to_string())
                } else if let Some(obj) = item.as_object() {
                    obj.get("text").and_then(|v| v.as_str()).map(String::from)
                } else {
                    None
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

/// Convert a JSON value to a string (handles string, number, bool).
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Parse a timestamp from a JSON value given a format config.
pub fn parse_timestamp(
    value: &serde_json::Value,
    path: &str,
    format: &TimestampFormat,
) -> Option<i64> {
    let v = resolve_path(value, path)?;
    match format {
        TimestampFormat::Iso8601 => {
            let s = v.as_str()?;
            parse_iso_timestamp(s)
        }
        TimestampFormat::EpochMs => v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)),
        TimestampFormat::EpochS => {
            let secs = v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))?;
            Some(secs * 1000)
        }
    }
}

/// Extract token count from a record if token config is set.
pub fn extract_tokens(
    record: &serde_json::Value,
    config: &Option<TokenConfig>,
    content: &str,
) -> u32 {
    if let Some(tc) = config {
        if let Some(v) = resolve_path(record, &tc.field) {
            if let Some(n) = v.as_u64() {
                return n as u32;
            }
        }
    }
    estimate_tokens(content)
}

/// Parse ISO 8601 / RFC 3339 timestamps to epoch milliseconds.
pub fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.fZ")
                .ok()
                .map(|dt| dt.and_utc().timestamp_millis())
        })
}

/// Expand `${HOME}` in a path string.
pub fn expand_home(path: &str) -> PathBuf {
    if path.contains("${HOME}") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        PathBuf::from(path.replace("${HOME}", &home.to_string_lossy()))
    } else {
        PathBuf::from(path)
    }
}

/// Return the mtime of a file in epoch milliseconds.
pub fn file_mtime_millis(path: &Path) -> Option<i64> {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

// ---------------------------------------------------------------------------
// PlaybookReader — the universal FormatReader driven by a Playbook config
// ---------------------------------------------------------------------------

/// A `FormatReader` implementation driven entirely by a `Playbook` config.
///
/// One PlaybookReader per tool. The playbook determines how to detect, collect,
/// parse, and extract session data. No tool-specific Rust code needed.
pub struct PlaybookReader {
    playbook: Playbook,
    cursor: Mutex<Option<Cursor>>,
}

impl PlaybookReader {
    pub fn new(playbook: Playbook) -> Self {
        Self {
            playbook,
            cursor: Mutex::new(None),
        }
    }

    pub fn playbook(&self) -> &Playbook {
        &self.playbook
    }
}

#[async_trait]
impl FormatReader for PlaybookReader {
    fn tool_type(&self) -> AiTool {
        AiTool::from_key(&self.playbook.tool)
    }

    fn detect(&self, root: &Path) -> bool {
        match &self.playbook.discovery.detect {
            PlaybookDetect::GlobExists { pattern } => {
                detect_glob_exists(root, pattern, &self.playbook.discovery.exclude_dirs)
            }
            PlaybookDetect::SqliteFile { filename } => {
                let db_path = root.join(filename);
                db_path.exists()
            }
        }
    }

    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>> {
        match &self.playbook.source {
            PlaybookSource::JsonlFiles { .. } => {
                jsonl::read_sessions_jsonl(&self.playbook, root, since, &self.cursor)
            }
            PlaybookSource::JsonFiles { .. } => {
                json_file::read_sessions_json(&self.playbook, root, since, &self.cursor)
            }
            PlaybookSource::SqliteKv { .. } => {
                sqlite::read_sessions_sqlite(&self.playbook, root, since, &self.cursor)
            }
        }
    }

    fn last_cursor(&self) -> Option<Cursor> {
        match self.cursor.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => {
                tracing::warn!("PlaybookReader cursor mutex poisoned, recovering");
                poisoned.into_inner().clone()
            }
        }
    }
}

/// Detection helper: check if any files matching the glob exist under root.
fn detect_glob_exists(root: &Path, pattern: &str, exclude_dirs: &[String]) -> bool {
    if !root.is_dir() {
        return false;
    }
    // Simple recursive check using the glob's file extension.
    let ext = pattern.rsplit('.').next().unwrap_or("");
    has_files_with_ext(root, ext, exclude_dirs, 0)
}

fn has_files_with_ext(dir: &Path, ext: &str, exclude_dirs: &[String], depth: usize) -> bool {
    if depth > 10 {
        return false;
    }
    let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if depth > 0 && exclude_dirs.iter().any(|e| e == dir_name) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_files_with_ext(&path, ext, exclude_dirs, depth + 1) {
                return true;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_simple() {
        let v: serde_json::Value = serde_json::json!({"a": {"b": "hello"}});
        assert_eq!(resolve_string(&v, "a.b"), Some("hello".into()));
    }

    #[test]
    fn resolve_path_missing() {
        let v: serde_json::Value = serde_json::json!({"a": 1});
        assert_eq!(resolve_path(&v, "a.b.c"), None);
    }

    #[test]
    fn resolve_path_number() {
        let v: serde_json::Value = serde_json::json!({"count": 42});
        assert_eq!(resolve_string(&v, "count"), Some("42".into()));
    }

    #[test]
    fn passes_filters_all_match() {
        let v: serde_json::Value =
            serde_json::json!({"type": "response_item", "payload": {"type": "message"}});
        let filters = vec![
            RecordFilter {
                field: "type".into(),
                include: vec!["response_item".into()],
            },
            RecordFilter {
                field: "payload.type".into(),
                include: vec!["message".into()],
            },
        ];
        assert!(passes_filters(&v, &filters));
    }

    #[test]
    fn passes_filters_one_fails() {
        let v: serde_json::Value =
            serde_json::json!({"type": "response_item", "payload": {"type": "reasoning"}});
        let filters = vec![
            RecordFilter {
                field: "type".into(),
                include: vec!["response_item".into()],
            },
            RecordFilter {
                field: "payload.type".into(),
                include: vec!["message".into()],
            },
        ];
        assert!(!passes_filters(&v, &filters));
    }

    #[test]
    fn extract_content_plain() {
        let v: serde_json::Value = serde_json::json!({"text": "hello world"});
        let config = ContentConfig::Plain {
            field: "text".into(),
        };
        assert_eq!(extract_content(&v, &config), Some("hello world".into()));
    }

    #[test]
    fn extract_content_text_blocks_string() {
        let v: serde_json::Value = serde_json::json!({"message": {"content": "plain string"}});
        let config = ContentConfig::TextBlocks {
            field: "message.content".into(),
            type_field: "type".into(),
            text_field: "text".into(),
            include_types: vec!["text".into()],
        };
        assert_eq!(extract_content(&v, &config), Some("plain string".into()));
    }

    #[test]
    fn extract_content_text_blocks_array() {
        let v: serde_json::Value = serde_json::json!({
            "message": {
                "content": [
                    {"type": "thinking", "text": "hmm"},
                    {"type": "text", "text": "hello"},
                    {"type": "text", "text": "world"},
                    {"type": "tool_use", "name": "read"}
                ]
            }
        });
        let config = ContentConfig::TextBlocks {
            field: "message.content".into(),
            type_field: "type".into(),
            text_field: "text".into(),
            include_types: vec!["text".into()],
        };
        assert_eq!(extract_content(&v, &config), Some("hello\nworld".into()));
    }

    #[test]
    fn extract_content_prefer_display() {
        let v: serde_json::Value = serde_json::json!({
            "displayContent": "rendered text",
            "content": "raw text"
        });
        let config = ContentConfig::PreferDisplay {
            display_field: "displayContent".into(),
            fallback_field: "content".into(),
        };
        assert_eq!(extract_content(&v, &config), Some("rendered text".into()));
    }

    #[test]
    fn extract_content_prefer_display_fallback() {
        let v: serde_json::Value = serde_json::json!({
            "content": "fallback text"
        });
        let config = ContentConfig::PreferDisplay {
            display_field: "displayContent".into(),
            fallback_field: "content".into(),
        };
        assert_eq!(extract_content(&v, &config), Some("fallback text".into()));
    }

    #[test]
    fn extract_role_with_value_map() {
        let v: serde_json::Value = serde_json::json!({"type": "gemini"});
        let config = RoleConfig {
            field: "type".into(),
            value_map: [("gemini".to_string(), "assistant".to_string())].into(),
        };
        assert_eq!(extract_role(&v, &config), Some("assistant".into()));
    }

    #[test]
    fn extract_role_no_map() {
        let v: serde_json::Value = serde_json::json!({"role": "user"});
        let config = RoleConfig {
            field: "role".into(),
            value_map: Default::default(),
        };
        assert_eq!(extract_role(&v, &config), Some("user".into()));
    }

    #[test]
    fn parse_iso_timestamp_rfc3339() {
        let ts = parse_iso_timestamp("2026-01-15T10:30:00.000Z");
        assert!(ts.is_some());
        assert!(ts.unwrap() > 0);
    }

    #[test]
    fn expand_home_replaces_var() {
        let expanded = expand_home("${HOME}/.test");
        assert!(!expanded.to_string_lossy().contains("${HOME}"));
    }
}
