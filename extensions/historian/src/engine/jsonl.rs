use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use tokio_stream::Stream;
use tracing::{trace, warn};

use crate::error::ReaderError;
use crate::playbook::{Playbook, PlaybookSource, SessionIdConfig};
use crate::types::{AiTool, Cursor, HistoricalMessage, HistoricalSession};

use super::{
    extract_content, extract_role, extract_tokens, file_mtime_millis, parse_timestamp,
    passes_filters, resolve_string,
};

/// Stream sessions from JSONL files using a playbook configuration.
pub fn read_sessions_jsonl<'a>(
    playbook: &'a Playbook,
    root: &Path,
    since: Option<i64>,
    cursor: &'a Mutex<Option<Cursor>>,
) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + 'a>> {
    let root = root.to_path_buf();

    let glob_pattern = match &playbook.source {
        PlaybookSource::JsonlFiles { glob, .. } => glob.clone(),
        _ => return Box::pin(tokio_stream::empty()),
    };

    Box::pin(async_stream::try_stream! {
        let files = collect_files(
            &root,
            &glob_pattern,
            &playbook.discovery.exclude_dirs,
            &playbook.discovery.exclude_file_patterns,
        );

        let mut latest_mtime: Option<i64> = None;

        for path in files {
            let file_mtime = file_mtime_millis(&path);

            match parse_jsonl_file(&path, playbook, since) {
                Ok(Some(session)) => {
                    let first_prompt = session.messages.iter()
                        .find(|m| m.role == "user")
                        .map(|m| truncate_for_log(&m.content, 80))
                        .unwrap_or_default();
                    trace!(
                        tool = %playbook.tool,
                        session_id = %session.session_id,
                        messages = session.messages.len(),
                        prompt = %first_prompt,
                        "parsed session"
                    );
                    if let Some(mt) = file_mtime {
                        latest_mtime = Some(latest_mtime.map_or(mt, |prev: i64| prev.max(mt)));
                    }
                    yield session;
                }
                Ok(None) => {
                    trace!(path = %path.display(), "no text messages found, skipping");
                }
                Err(e) => {
                    warn!(path = %path.display(), err = %e, "reader error, skipping file");
                }
            }
        }

        if let Some(mtime) = latest_mtime {
            let mut guard = match cursor.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!("jsonl cursor mutex poisoned, recovering");
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

/// Parse a single JSONL file into a HistoricalSession using the playbook config.
fn parse_jsonl_file(
    path: &Path,
    playbook: &Playbook,
    since: Option<i64>,
) -> Result<Option<HistoricalSession>, ReaderError> {
    let content = std::fs::read_to_string(path).map_err(|e| ReaderError::Reader {
        tool: playbook.tool.clone(),
        message: format!("read {}: {e}", path.display()),
    })?;

    let tool = AiTool::from_key(&playbook.tool);
    let extraction = &playbook.extraction;

    let filename_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // For MetaLine session_id, we scan for the meta line first.
    let mut session_id: Option<String> = match &extraction.session_id {
        SessionIdConfig::FileStem => Some(filename_stem.clone()),
        SessionIdConfig::Field { .. } => None, // Not applicable for JSONL
        SessionIdConfig::MetaLine { .. } => None, // Will be populated during line scan
    };

    let mut messages = Vec::new();
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    let total_lines = content.lines().count();
    let mut json_ok: u32 = 0;
    let mut filter_pass: u32 = 0;
    let mut role_pass: u32 = 0;
    let mut content_pass: u32 = 0;

    for (line_num, raw) in content.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(raw) {
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
        json_ok += 1;

        // Check for metadata line (session_id extraction).
        if let SessionIdConfig::MetaLine {
            line_type_field,
            line_type_value,
            id_path,
        } = &extraction.session_id
        {
            if let Some(lt) = resolve_string(&parsed, line_type_field) {
                if lt == *line_type_value {
                    if let Some(id) = resolve_string(&parsed, id_path) {
                        session_id = Some(id);
                    }
                    continue; // Meta lines are not message records.
                }
            }
        }

        // Apply record filters.
        if !passes_filters(&parsed, &extraction.records.filters) {
            continue;
        }
        filter_pass += 1;

        // Extract role.
        let role = match extract_role(&parsed, &extraction.role) {
            Some(r) => r,
            None => continue,
        };
        role_pass += 1;

        // Extract content.
        let text = match extract_content(&parsed, &extraction.content) {
            Some(t) => t,
            None => continue,
        };
        content_pass += 1;

        // Extract timestamp.
        let ts = parse_timestamp(
            &parsed,
            &extraction.timestamp.field,
            &extraction.timestamp.format,
        );

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

        let token_estimate = extract_tokens(&parsed, &extraction.tokens, &text);

        messages.push(HistoricalMessage {
            role,
            content: text,
            timestamp: ts,
            token_estimate,
        });
    }

    if messages.is_empty() {
        let reason = if content_pass > 0 && since.is_some() {
            "all messages older than since threshold"
        } else if content_pass == 0 && role_pass > 0 {
            "no text content in message bodies (tool calls only)"
        } else {
            "no matching messages in file"
        };
        trace!(
            path = %path.display(),
            total_lines,
            json_ok,
            filter_pass,
            role_pass,
            content_pass,
            reason,
            "skipping file"
        );
        return Ok(None);
    }

    Ok(Some(HistoricalSession {
        tool,
        session_id: session_id.unwrap_or(filename_stem),
        messages,
        started_at: min_ts,
        ended_at: max_ts,
    }))
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Recursively collect files matching the glob's extension under root,
/// respecting exclude_dirs and exclude_file_patterns.
fn collect_files(
    root: &Path,
    glob_pattern: &str,
    exclude_dirs: &[String],
    exclude_file_patterns: &[String],
) -> Vec<PathBuf> {
    let ext = glob_pattern.rsplit('.').next().unwrap_or("jsonl");

    let mut files = Vec::new();
    collect_recursive(
        root,
        ext,
        exclude_dirs,
        exclude_file_patterns,
        &mut files,
        true,
    );

    // Sort by mtime ascending (oldest first).
    files.sort_by(|a, b| {
        let ma = a.metadata().and_then(|m| m.modified()).ok();
        let mb = b.metadata().and_then(|m| m.modified()).ok();
        ma.cmp(&mb)
    });

    files
}

fn collect_recursive(
    dir: &Path,
    ext: &str,
    exclude_dirs: &[String],
    exclude_file_patterns: &[String],
    out: &mut Vec<PathBuf>,
    is_root: bool,
) {
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
            collect_recursive(&path, ext, exclude_dirs, exclude_file_patterns, out, false);
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            // Check exclude file patterns.
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if exclude_file_patterns
                .iter()
                .any(|p| filename.contains(p.as_str()))
            {
                continue;
            }
            out.push(path);
        }
    }
}

fn truncate_for_log(s: &str, max: usize) -> String {
    let clean = s.replace('\n', " ");
    if clean.len() <= max {
        clean
    } else {
        let end = clean
            .char_indices()
            .nth(max)
            .map(|(i, _)| i)
            .unwrap_or(clean.len());
        format!("{}...", &clean[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::*;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }

    fn claude_code_playbook() -> Playbook {
        Playbook {
            tool: "claude_code".into(),
            version: 1,
            provider: "anthropic".into(),
            discovery: PlaybookDiscovery {
                roots: vec!["${HOME}/.claude/projects".into()],
                detect: PlaybookDetect::GlobExists {
                    pattern: "**/*.jsonl".into(),
                },
                exclude_dirs: vec!["memory".into()],
                exclude_file_patterns: vec![],
            },
            source: PlaybookSource::JsonlFiles {
                glob: "**/*.jsonl".into(),
                session_per_file: true,
            },
            extraction: PlaybookExtraction {
                session_id: SessionIdConfig::FileStem,
                records: RecordsConfig {
                    iterate: RecordIterMethod::Lines,
                    filters: vec![RecordFilter {
                        field: "type".into(),
                        include: vec!["user".into(), "assistant".into()],
                    }],
                },
                role: RoleConfig {
                    field: "message.role".into(),
                    value_map: HashMap::new(),
                },
                content: ContentConfig::TextBlocks {
                    field: "message.content".into(),
                    type_field: "type".into(),
                    text_field: "text".into(),
                    include_types: vec!["text".into()],
                },
                timestamp: TimestampConfig {
                    field: "timestamp".into(),
                    format: TimestampFormat::Iso8601,
                    session_start_field: None,
                    session_end_field: None,
                },
                tokens: None,
            },
        }
    }

    fn codex_playbook() -> Playbook {
        Playbook {
            tool: "openai_codex".into(),
            version: 1,
            provider: "openai".into(),
            discovery: PlaybookDiscovery {
                roots: vec!["${HOME}/.codex".into()],
                detect: PlaybookDetect::GlobExists {
                    pattern: "**/*.jsonl".into(),
                },
                exclude_dirs: vec![],
                exclude_file_patterns: vec![],
            },
            source: PlaybookSource::JsonlFiles {
                glob: "sessions/**/*.jsonl".into(),
                session_per_file: true,
            },
            extraction: PlaybookExtraction {
                session_id: SessionIdConfig::MetaLine {
                    line_type_field: "type".into(),
                    line_type_value: "session_meta".into(),
                    id_path: "payload.id".into(),
                },
                records: RecordsConfig {
                    iterate: RecordIterMethod::Lines,
                    filters: vec![
                        RecordFilter {
                            field: "type".into(),
                            include: vec!["response_item".into()],
                        },
                        RecordFilter {
                            field: "payload.type".into(),
                            include: vec!["message".into()],
                        },
                    ],
                },
                role: RoleConfig {
                    field: "payload.role".into(),
                    value_map: HashMap::new(),
                },
                content: ContentConfig::TextBlocks {
                    field: "payload.content".into(),
                    type_field: "type".into(),
                    text_field: "text".into(),
                    include_types: vec!["input_text".into(), "output_text".into()],
                },
                timestamp: TimestampConfig {
                    field: "timestamp".into(),
                    format: TimestampFormat::Iso8601,
                    session_start_field: None,
                    session_end_field: None,
                },
                tokens: None,
            },
        }
    }

    #[tokio::test]
    async fn claude_code_playbook_reads_session() {
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"type":"system","content":"ignored","timestamp":"2026-01-01T00:00:00.000Z"}
{"type":"user","message":{"role":"user","content":"write hello world"},"timestamp":"2026-01-01T00:00:01.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","text":"let me think"},{"type":"text","text":"fn hello() {}"}]},"timestamp":"2026-01-01T00:00:02.000Z"}"#;
        write_file(tmp.path(), "abc-123.jsonl", jsonl);

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "abc-123");
        assert_eq!(session.tool, AiTool::ClaudeCode);
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[0].content, "write hello world");
        assert_eq!(session.messages[1].role, "assistant");
        assert_eq!(session.messages[1].content, "fn hello() {}");
        assert!(!session.messages[1].content.contains("let me think"));
        assert!(session.started_at.is_some());
    }

    #[tokio::test]
    async fn claude_code_realistic_session_with_extra_types() {
        // Realistic session with file-history-snapshot, progress, queue-operation
        // lines mixed in — must still extract user/assistant text messages.
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"type":"file-history-snapshot","messageId":"m1","snapshot":{}}
{"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/tmp","sessionId":"sess-1","version":"2.1.56","type":"user","message":{"role":"user","content":"fix the auth bug"},"uuid":"u1","timestamp":"2026-01-01T00:00:01.000Z"}
{"parentUuid":"u1","isSidechain":false,"userType":"external","cwd":"/tmp","sessionId":"sess-1","version":"2.1.56","type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I'll fix the auth bug now."}]},"uuid":"u2","timestamp":"2026-01-01T00:00:02.000Z"}
{"type":"progress","data":{"status":"running"},"timestamp":"2026-01-01T00:00:03.000Z"}
{"parentUuid":"u2","isSidechain":false,"userType":"external","cwd":"/tmp","sessionId":"sess-1","version":"2.1.56","type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"tid-1","name":"Read","input":{"file":"auth.rs"}}]},"uuid":"u3","timestamp":"2026-01-01T00:00:04.000Z"}
{"parentUuid":"u3","isSidechain":false,"userType":"external","cwd":"/tmp","sessionId":"sess-1","version":"2.1.56","type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tid-1","content":"fn auth() {}"}]},"uuid":"u4","timestamp":"2026-01-01T00:00:05.000Z"}
{"type":"queue-operation","data":{"op":"flush"},"timestamp":"2026-01-01T00:00:06.000Z"}
{"parentUuid":"u4","isSidechain":false,"userType":"external","cwd":"/tmp","sessionId":"sess-1","version":"2.1.56","type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Fixed. The auth now validates tokens."}]},"uuid":"u5","timestamp":"2026-01-01T00:00:07.000Z"}"#;
        write_file(tmp.path(), "sess-1.jsonl", jsonl);

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "sess-1");
        // 3 messages: user prompt + 2 assistant text blocks
        // Skipped: file-history-snapshot, progress, queue-operation, tool_use, tool_result
        assert_eq!(session.messages.len(), 3);
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[0].content, "fix the auth bug");
        assert_eq!(session.messages[1].role, "assistant");
        assert!(session.messages[1].content.contains("auth bug"));
        assert_eq!(session.messages[2].role, "assistant");
        assert!(session.messages[2].content.contains("validates tokens"));
    }

    #[tokio::test]
    async fn codex_playbook_reads_session() {
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"timestamp":"2025-11-30T07:23:26.312Z","type":"session_meta","payload":{"id":"codex-session-1"}}
{"timestamp":"2025-11-30T07:23:27.000Z","type":"event_msg","payload":{"event":"thinking"}}
{"timestamp":"2025-11-30T07:23:28.000Z","type":"response_item","payload":{"type":"reasoning","content":null}}
{"timestamp":"2025-11-30T07:23:29.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"refactor auth"}]}}
{"timestamp":"2025-11-30T07:23:30.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Done."}]}}"#;
        write_file(tmp.path(), "sessions/2025/11/30/rollout.jsonl", jsonl);

        let pb = codex_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "codex-session-1");
        assert_eq!(session.tool, AiTool::OpenAiCodex);
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(session.messages[0].content, "refactor auth");
        assert_eq!(session.messages[1].role, "assistant");
        assert_eq!(session.messages[1].content, "Done.");
    }

    #[tokio::test]
    async fn excludes_memory_dir() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "memory/notes.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"should not appear"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"hello"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "hello");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn since_filter_works() {
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"type":"user","message":{"role":"user","content":"old"},"timestamp":"2025-01-01T00:00:00.000Z"}
{"type":"user","message":{"role":"user","content":"new"},"timestamp":"2026-06-01T00:00:00.000Z"}"#;
        write_file(tmp.path(), "session.jsonl", jsonl);

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .timestamp_millis();

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), Some(since), &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].content, "new");
    }

    #[tokio::test]
    async fn cursor_updated_after_read() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "s.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"hi"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);
        while stream.next().await.is_some() {}

        let c = cursor.lock().unwrap();
        assert!(c.is_some());
        assert!(matches!(c.as_ref().unwrap(), Cursor::FileMtime { .. }));
    }

    #[tokio::test]
    async fn mixed_tool_calls_extracts_text_only() {
        // Sessions with tool_use/tool_result exchanges interleaved with text
        // should extract only the natural language messages.
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tid-1","content":"file contents here"}]},"timestamp":"2026-01-01T00:00:01.000Z"}
{"type":"user","message":{"role":"user","content":"Your task is to refactor the auth module"},"timestamp":"2026-01-01T00:00:02.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","text":"let me analyze"}]},"timestamp":"2026-01-01T00:00:03.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I'll refactor the auth module to use middleware."}]},"timestamp":"2026-01-01T00:00:04.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"tid-2","name":"Edit","input":{"file":"auth.rs"}}]},"timestamp":"2026-01-01T00:00:05.000Z"}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tid-2","content":"edit applied"}]},"timestamp":"2026-01-01T00:00:06.000Z"}
{"type":"progress","data":{"status":"running"},"timestamp":"2026-01-01T00:00:07.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Done. The auth module now uses middleware."}]},"timestamp":"2026-01-01T00:00:08.000Z"}"#;
        write_file(tmp.path(), "session-abc/agent-a1234.jsonl", jsonl);

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.session_id, "agent-a1234");
        // Should extract: user prompt (string), 2 assistant text blocks
        // Should skip: tool_result (user), thinking (assistant), tool_use (assistant), progress
        assert_eq!(session.messages.len(), 3);
        assert_eq!(session.messages[0].role, "user");
        assert_eq!(
            session.messages[0].content,
            "Your task is to refactor the auth module"
        );
        assert_eq!(session.messages[1].role, "assistant");
        assert!(session.messages[1].content.contains("middleware"));
        assert_eq!(session.messages[2].role, "assistant");
        assert!(session.messages[2].content.contains("Done"));
    }

    #[tokio::test]
    async fn includes_subagents_dir() {
        // Subagent files are distinct conversations spawned by the Task tool —
        // the parent session only records the tool_use call, not the full
        // sub-conversation, so these must be ingested to capture the work.
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "subagents/agent-a1234.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"delegated task"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );
        write_file(
            tmp.path(),
            "session.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"real user msg"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let mut contents: Vec<String> = Vec::new();
        while let Some(res) = stream.next().await {
            let session = res.unwrap();
            for m in session.messages {
                contents.push(m.content);
            }
        }
        contents.sort();
        assert_eq!(
            contents,
            vec!["delegated task".to_string(), "real user msg".to_string()]
        );
    }

    #[tokio::test]
    async fn all_tool_calls_file_skipped() {
        // A file with ONLY tool_use/tool_result exchanges and no text
        // should produce Ok(None) — legitimately no usable messages.
        let tmp = TempDir::new().unwrap();
        let jsonl = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tid-1","content":"file contents"}]},"timestamp":"2026-01-01T00:00:01.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"tid-2","name":"Read","input":{"file":"main.rs"}}]},"timestamp":"2026-01-01T00:00:02.000Z"}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tid-2","content":"fn main() {}"}]},"timestamp":"2026-01-01T00:00:03.000Z"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"tid-3","name":"Edit","input":{"file":"main.rs"}}]},"timestamp":"2026-01-01T00:00:04.000Z"}"#;
        write_file(tmp.path(), "session-abc.jsonl", jsonl);

        let pb = claude_code_playbook();
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        // No text content at all — file is legitimately skipped.
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn exclude_file_patterns_work() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "session.deleted.20251130.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"deleted"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );
        write_file(
            tmp.path(),
            "live.jsonl",
            r#"{"type":"user","message":{"role":"user","content":"alive"},"timestamp":"2026-01-01T00:00:00.000Z"}"#,
        );

        let mut pb = claude_code_playbook();
        pb.discovery.exclude_file_patterns = vec![".deleted.".into()];
        let cursor = Mutex::new(None);
        let mut stream = read_sessions_jsonl(&pb, tmp.path(), None, &cursor);

        let session = stream.next().await.unwrap().unwrap();
        assert_eq!(session.messages[0].content, "alive");
        assert!(stream.next().await.is_none());
    }
}
