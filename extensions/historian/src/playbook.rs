use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A declarative configuration that tells the historian how to discover,
/// detect, and read conversation history for a single AI tool.
///
/// Playbooks are the unit of server-pushable configuration: the cloud can
/// send a new playbook JSON/YAML and the historian can ingest a new tool's
/// history without any code changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// Tool identifier key (e.g. "claude_code", "gemini_cli").
    /// Maps to `AiTool` via `AiTool::from_key`.
    pub tool: String,
    /// Playbook schema version (currently 1).
    #[serde(default = "default_version")]
    pub version: u32,
    /// Provider name for telemetry (e.g. "anthropic", "openai", "gemini").
    #[serde(default)]
    pub provider: String,

    pub discovery: PlaybookDiscovery,
    pub source: PlaybookSource,
    pub extraction: PlaybookExtraction,
}

fn default_version() -> u32 {
    1
}

/// How to find and detect the tool on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDiscovery {
    /// Root directories to scan. Supports `${HOME}` variable expansion.
    pub roots: Vec<String>,
    /// Strategy for detecting whether the tool is present at a root.
    pub detect: PlaybookDetect,
    /// Directory names to skip during recursive file collection.
    #[serde(default)]
    pub exclude_dirs: Vec<String>,
    /// Filename substrings that cause a file to be skipped.
    #[serde(default)]
    pub exclude_file_patterns: Vec<String>,
}

/// Detection strategy — how to check if a tool is installed at a given root.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy")]
pub enum PlaybookDetect {
    /// Check that at least one file matching the glob pattern exists.
    #[serde(rename = "glob_exists")]
    GlobExists { pattern: String },
    /// Check that a specific SQLite file exists.
    #[serde(rename = "sqlite_file")]
    SqliteFile { filename: String },
}

/// Where and how files are stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PlaybookSource {
    /// Newline-delimited JSON files (`.jsonl`).
    #[serde(rename = "jsonl_files")]
    JsonlFiles {
        /// Glob pattern relative to the discovery root.
        glob: String,
        /// If true, each file is one session. If false, sessions are grouped
        /// by a session_id field across files.
        #[serde(default = "default_true")]
        session_per_file: bool,
    },
    /// Complete JSON files, each containing one conversation.
    #[serde(rename = "json_files")]
    JsonFiles {
        /// Glob pattern relative to the discovery root.
        glob: String,
    },
    /// SQLite key-value store (like Cursor's `state.vscdb`).
    #[serde(rename = "sqlite_kv")]
    SqliteKv {
        /// Database filename (resolved relative to discovery root).
        db_file: String,
        /// Table name.
        table: String,
        /// Key prefix for the LIKE filter (e.g. "composerData:").
        key_prefix: String,
        /// Column containing the JSON value.
        value_column: String,
    },
}

fn default_true() -> bool {
    true
}

/// How to extract structured data from each source item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExtraction {
    /// How to determine the session ID.
    pub session_id: SessionIdConfig,
    /// How to iterate over message records within a source item.
    pub records: RecordsConfig,
    /// How to extract the role from each record.
    pub role: RoleConfig,
    /// How to extract content text from each record.
    pub content: ContentConfig,
    /// How to extract timestamps.
    pub timestamp: TimestampConfig,
    /// Optional: how to extract token counts from data (vs heuristic).
    #[serde(default)]
    pub tokens: Option<TokenConfig>,
}

/// How to determine the session ID for each conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "from")]
pub enum SessionIdConfig {
    /// Use the filename without extension as session ID.
    #[serde(rename = "file_stem")]
    FileStem,
    /// Extract session ID from a JSON field path in the source data.
    #[serde(rename = "field")]
    Field { path: String },
    /// For JSONL: scan for a metadata line that contains the session ID.
    /// Falls back to file stem if not found.
    #[serde(rename = "meta_line")]
    MetaLine {
        /// Dot-path to the field that identifies the line type.
        line_type_field: String,
        /// Value that marks a metadata line.
        line_type_value: String,
        /// Dot-path to the session ID within the metadata line.
        id_path: String,
    },
}

/// How to iterate over message records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordsConfig {
    /// The iteration method.
    pub iterate: RecordIterMethod,
    /// Filters applied to each record. ALL must match for a record to be included.
    #[serde(default)]
    pub filters: Vec<RecordFilter>,
}

/// Method for iterating over records within a source item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum RecordIterMethod {
    /// Each JSONL line is a potential record.
    #[serde(rename = "lines")]
    Lines,
    /// Records are in a JSON array at the given dot-path.
    #[serde(rename = "field")]
    Field { path: String },
}

/// A filter that includes records where a field's value is in the allowed set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordFilter {
    /// Dot-path to the field to check.
    pub field: String,
    /// Allowed values. Record passes if the field value is in this set.
    pub include: Vec<String>,
}

/// How to extract the message role from each record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Dot-path to the role field.
    pub field: String,
    /// Map raw values to standard roles (e.g. `{"gemini": "assistant", "1": "user"}`).
    #[serde(default)]
    pub value_map: HashMap<String, String>,
}

/// How to extract content text from each record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy")]
pub enum ContentConfig {
    /// Content is a plain string at the given field path.
    #[serde(rename = "plain")]
    Plain { field: String },

    /// Content is a string OR an array of typed blocks.
    /// For strings, returns the string directly.
    /// For arrays, extracts text from blocks whose type matches `include_types`.
    #[serde(rename = "text_blocks")]
    TextBlocks {
        /// Dot-path to the content value.
        field: String,
        /// Field name within each block that indicates its type (e.g. "type").
        type_field: String,
        /// Field name within each block that holds the text (e.g. "text").
        text_field: String,
        /// Block types to include (e.g. ["text"] or ["input_text", "output_text"]).
        include_types: Vec<String>,
    },

    /// Prefer a display/rendered content field; fall back to raw content.
    /// Used by Gemini CLI which has both `displayContent` and `content`.
    #[serde(rename = "prefer_display")]
    PreferDisplay {
        /// Dot-path to the preferred display content (string).
        display_field: String,
        /// Dot-path to the fallback content (string or array of parts).
        fallback_field: String,
    },
}

/// How to extract and parse timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampConfig {
    /// Dot-path to the timestamp field in each record.
    pub field: String,
    /// The timestamp format.
    pub format: TimestampFormat,
    /// Session-level fallback for start time (e.g. for Gemini's `startTime`).
    #[serde(default)]
    pub session_start_field: Option<String>,
    /// Session-level fallback for end time (e.g. for Gemini's `lastUpdated`).
    #[serde(default)]
    pub session_end_field: Option<String>,
}

/// Supported timestamp formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampFormat {
    /// ISO 8601 / RFC 3339 string (e.g. "2026-01-15T10:30:00.000Z").
    Iso8601,
    /// Unix epoch milliseconds (integer).
    EpochMs,
    /// Unix epoch seconds (integer).
    EpochS,
}

/// How to extract token counts from the data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Dot-path to the token count field (e.g. "tokens.total").
    pub field: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playbook_roundtrips_through_json() {
        let pb = Playbook {
            tool: "test_tool".into(),
            version: 1,
            provider: "test".into(),
            discovery: PlaybookDiscovery {
                roots: vec!["${HOME}/.test".into()],
                detect: PlaybookDetect::GlobExists {
                    pattern: "**/*.jsonl".into(),
                },
                exclude_dirs: vec!["cache".into()],
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
                    field: "role".into(),
                    value_map: HashMap::new(),
                },
                content: ContentConfig::Plain {
                    field: "content".into(),
                },
                timestamp: TimestampConfig {
                    field: "timestamp".into(),
                    format: TimestampFormat::Iso8601,
                    session_start_field: None,
                    session_end_field: None,
                },
                tokens: None,
            },
        };

        let json = serde_json::to_string_pretty(&pb).unwrap();
        let parsed: Playbook = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool, "test_tool");
        assert_eq!(parsed.version, 1);
    }
}
