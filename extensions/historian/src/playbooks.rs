use std::collections::HashMap;
use std::path::Path;

use tracing::{trace, warn};

use crate::playbook::*;

/// Return the built-in default playbooks for all known AI tools.
///
/// These are the baseline configs that ship with the historian. They can be
/// overridden by playbook files on disk (`~/.soth/historian/playbooks/`) or
/// by server-pushed configuration.
pub fn default_playbooks() -> Vec<Playbook> {
    vec![
        claude_code(),
        gemini_cli(),
        openai_codex(),
        cursor(),
        openclaw(),
    ]
}

/// Load all playbooks: built-in defaults merged with any on-disk overrides.
///
/// Playbook files on disk (`~/.soth/historian/playbooks/*.json`) override
/// built-in defaults for the same tool key. Additional playbook files for
/// unknown tools are appended (enabling server-pushed new tool support).
pub fn load_playbooks() -> Vec<Playbook> {
    let mut playbooks = default_playbooks();
    let override_dir =
        dirs::home_dir().map(|h| h.join(".soth").join("historian").join("playbooks"));

    if let Some(dir) = override_dir {
        if dir.is_dir() {
            let overrides = load_playbooks_from_dir(&dir);
            for ovr in overrides {
                // Replace existing playbook with same tool key, or append.
                if let Some(pos) = playbooks.iter().position(|p| p.tool == ovr.tool) {
                    trace!(tool = %ovr.tool, "overriding built-in playbook from disk");
                    playbooks[pos] = ovr;
                } else {
                    trace!(tool = %ovr.tool, "loading new playbook from disk");
                    playbooks.push(ovr);
                }
            }
        }
    }

    playbooks
}

/// Load all `.json` playbook files from a directory.
pub fn load_playbooks_from_dir(dir: &Path) -> Vec<Playbook> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return result;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<Playbook>(&content) {
                    Ok(pb) => {
                        trace!(tool = %pb.tool, path = %path.display(), "loaded playbook");
                        result.push(pb);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), err = %e, "failed to parse playbook");
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), err = %e, "failed to read playbook file");
                }
            }
        }
    }
    result
}

/// Claude Code: JSONL at `~/.claude/projects/**/*.jsonl`
fn claude_code() -> Playbook {
    Playbook {
        tool: "claude_code".into(),
        version: 1,
        provider: "anthropic".into(),
        discovery: PlaybookDiscovery {
            roots: vec!["${HOME}/.claude/projects".into()],
            detect: PlaybookDetect::GlobExists {
                pattern: "**/*.jsonl".into(),
            },
            // `subagents/agent-*.jsonl` are distinct conversations spawned by
            // the Task tool — include them. Only `memory/` (MEMORY.md etc.)
            // stays excluded as it holds notes, not transcripts.
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
            // Claude Code's session log carries the full
            // Anthropic-style usage block per assistant turn at
            // `message.usage.{input,output,cache_creation_input,
            // cache_read_input}_tokens`.  Extract all four for
            // billing-grade reconstruction in §10.11 bypass mode.
            // Verified 2026-05-08 against real session logs at
            // ~/.claude/projects/.../*.jsonl.
            tokens: Some(TokenConfig {
                field: None,
                input_tokens_field: Some("message.usage.input_tokens".into()),
                output_tokens_field: Some("message.usage.output_tokens".into()),
                cache_creation_input_tokens_field: Some(
                    "message.usage.cache_creation_input_tokens".into(),
                ),
                cache_read_input_tokens_field: Some(
                    "message.usage.cache_read_input_tokens".into(),
                ),
                total_tokens_field: None,
            }),
        },
    }
}

/// Gemini CLI: JSON at `~/.gemini/tmp/*/chats/session-*.json`
fn gemini_cli() -> Playbook {
    Playbook {
        tool: "gemini_cli".into(),
        version: 1,
        provider: "gemini".into(),
        discovery: PlaybookDiscovery {
            roots: vec!["${HOME}/.gemini".into()],
            detect: PlaybookDetect::GlobExists {
                pattern: "tmp/*/chats/*.json".into(),
            },
            exclude_dirs: vec!["antigravity".into()],
            exclude_file_patterns: vec![],
        },
        source: PlaybookSource::JsonFiles {
            glob: "tmp/*/chats/*.json".into(),
        },
        extraction: PlaybookExtraction {
            session_id: SessionIdConfig::Field {
                path: "sessionId".into(),
            },
            records: RecordsConfig {
                iterate: RecordIterMethod::Field {
                    path: "messages".into(),
                },
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
            // Gemini's session log carries a single scalar
            // total — not billing-grade per Anthropic-style
            // input/output/cache breakdown.  The playbook
            // surfaces it through `total_tokens_field` so
            // downstream code can still use it as a coarse
            // signal, but `is_billing_grade()` returns false
            // and the §10.11 audit gate stays closed for
            // gemini_cli until upstream starts emitting per-
            // direction counts.
            tokens: Some(TokenConfig::from_total_field("tokens.total")),
        },
    }
}

/// OpenAI Codex CLI: JSONL at `~/.codex/sessions/**/*.jsonl`
fn openai_codex() -> Playbook {
    Playbook {
        tool: "openai_codex".into(),
        version: 1,
        provider: "openai".into(),
        discovery: PlaybookDiscovery {
            roots: vec!["${HOME}/.codex".into()],
            detect: PlaybookDetect::GlobExists {
                pattern: "sessions/**/*.jsonl".into(),
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

/// Cursor IDE: SQLite at `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`
fn cursor() -> Playbook {
    // v2 playbook: reads both legacy inline-conversation rows and v14+ split-
    // record rows. For v14, each `composerData:<id>` row carries only a
    // `fullConversationHeadersOnly` header list; the actual bubbles live in
    // separate `bubbleId:<session>:<bubble>` rows in the same table. The
    // engine consults `split_record_source` when the inline array is empty,
    // so one playbook covers both formats without branching in code.
    Playbook {
        tool: "cursor".into(),
        version: 2,
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
            split_record_source: Some(SplitRecordSource {
                headers_field: "fullConversationHeadersOnly".into(),
                header_id_field: "bubbleId".into(),
                record_key_template: "bubbleId:{session_id}:{record_id}".into(),
            }),
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
            // Legacy composer rows use epoch-ms `createdAt`; v14 bubble rows
            // use ISO-8601 `createdAt`. The engine falls back to ISO-8601
            // parsing on the bubble path when this format fails to parse.
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

/// OpenClaw: JSONL at `~/.openclaw/agents/main/sessions/*.jsonl`
fn openclaw() -> Playbook {
    Playbook {
        tool: "openclaw".into(),
        version: 1,
        provider: "unknown".into(),
        discovery: PlaybookDiscovery {
            roots: vec!["${HOME}/.openclaw/agents/main/sessions".into()],
            detect: PlaybookDetect::GlobExists {
                pattern: "**/*.jsonl".into(),
            },
            exclude_dirs: vec![],
            exclude_file_patterns: vec![".deleted.".into()],
        },
        source: PlaybookSource::JsonlFiles {
            glob: "**/*.jsonl".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_playbooks_returns_five() {
        let pbs = default_playbooks();
        assert_eq!(pbs.len(), 5);
        let tools: Vec<&str> = pbs.iter().map(|p| p.tool.as_str()).collect();
        assert!(tools.contains(&"claude_code"));
        assert!(tools.contains(&"gemini_cli"));
        assert!(tools.contains(&"openai_codex"));
        assert!(tools.contains(&"cursor"));
        assert!(tools.contains(&"openclaw"));
    }

    #[test]
    fn all_playbooks_serialize_to_json() {
        for pb in default_playbooks() {
            let json = serde_json::to_string(&pb);
            assert!(json.is_ok(), "playbook {} failed to serialize", pb.tool);
        }
    }

    #[test]
    fn all_playbooks_roundtrip_through_json() {
        for pb in default_playbooks() {
            let json = serde_json::to_string(&pb).unwrap();
            let parsed: Playbook = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.tool, pb.tool);
            assert_eq!(parsed.version, pb.version);
        }
    }
}
