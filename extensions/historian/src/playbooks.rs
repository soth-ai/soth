use std::collections::HashMap;
use std::path::Path;

use tracing::{debug, warn};

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
    let override_dir = dirs::home_dir()
        .map(|h| h.join(".soth").join("historian").join("playbooks"));

    if let Some(dir) = override_dir {
        if dir.is_dir() {
            let overrides = load_playbooks_from_dir(&dir);
            for ovr in overrides {
                // Replace existing playbook with same tool key, or append.
                if let Some(pos) = playbooks.iter().position(|p| p.tool == ovr.tool) {
                    debug!(tool = %ovr.tool, "overriding built-in playbook from disk");
                    playbooks[pos] = ovr;
                } else {
                    debug!(tool = %ovr.tool, "loading new playbook from disk");
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
                        debug!(tool = %pb.tool, path = %path.display(), "loaded playbook");
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
            tokens: Some(TokenConfig {
                field: "tokens.total".into(),
            }),
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
    Playbook {
        tool: "cursor".into(),
        version: 1,
        provider: "openai".into(),
        discovery: PlaybookDiscovery {
            roots: vec![
                "${HOME}/Library/Application Support/Cursor/User/globalStorage".into(),
            ],
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
