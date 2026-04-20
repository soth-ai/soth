use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use soth_core::DataSource;

/// AI tool whose local history the historian can read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTool {
    ClaudeCode,
    GeminiCli,
    OpenAiCodex,
    GithubCopilot,
    Cursor,
    Continue,
    OpenClaw,
    Unknown(String),
}

impl AiTool {
    /// Construct an `AiTool` from its canonical key string.
    /// Unknown keys produce `AiTool::Unknown(key)`.
    pub fn from_key(key: &str) -> Self {
        match key {
            "claude_code" => Self::ClaudeCode,
            "gemini_cli" => Self::GeminiCli,
            "openai_codex" => Self::OpenAiCodex,
            "github_copilot" => Self::GithubCopilot,
            "cursor" => Self::Cursor,
            "continue" => Self::Continue,
            "openclaw" => Self::OpenClaw,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Canonical string key used in DB rows and metadata maps.
    pub fn key(&self) -> &str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::GeminiCli => "gemini_cli",
            Self::OpenAiCodex => "openai_codex",
            Self::GithubCopilot => "github_copilot",
            Self::Cursor => "cursor",
            Self::Continue => "continue",
            Self::OpenClaw => "openclaw",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Identity metadata used by the cloud to group events by tool.
    /// Values align with bundle detection conventions (kebab-case identity keys,
    /// unified registry tool_kind/tool_category).
    pub fn identity(&self) -> ToolIdentity {
        match self {
            Self::ClaudeCode => ToolIdentity {
                identity_key: "claude-code",
                tool_name: "Claude Code",
                tool_kind: "cli",
                tool_category: "CLI Tool",
                provider_id: "anthropic",
            },
            Self::GeminiCli => ToolIdentity {
                identity_key: "gemini-cli",
                tool_name: "Gemini CLI",
                tool_kind: "cli",
                tool_category: "CLI Tool",
                provider_id: "google",
            },
            Self::OpenAiCodex => ToolIdentity {
                identity_key: "openai-codex",
                tool_name: "OpenAI Codex",
                tool_kind: "cli",
                tool_category: "CLI Tool",
                provider_id: "openai",
            },
            Self::Cursor => ToolIdentity {
                identity_key: "cursor",
                tool_name: "Cursor",
                tool_kind: "ide",
                tool_category: "Code Editor",
                provider_id: "anthropic",
            },
            Self::GithubCopilot => ToolIdentity {
                identity_key: "github-copilot",
                tool_name: "GitHub Copilot",
                tool_kind: "ide_plugin",
                tool_category: "IDE Plugin",
                provider_id: "github",
            },
            Self::Continue => ToolIdentity {
                identity_key: "continue",
                tool_name: "Continue",
                tool_kind: "ide_plugin",
                tool_category: "IDE Plugin",
                provider_id: "unknown",
            },
            Self::OpenClaw => ToolIdentity {
                identity_key: "openclaw",
                tool_name: "OpenClaw",
                tool_kind: "cli",
                tool_category: "CLI Tool",
                provider_id: "unknown",
            },
            Self::Unknown(_) => ToolIdentity {
                identity_key: "unknown",
                tool_name: "Unknown",
                tool_kind: "unknown",
                tool_category: "Unknown",
                provider_id: "unknown",
            },
        }
    }

    /// Map to the corresponding `DataSource` variant for telemetry.
    pub fn data_source(&self) -> DataSource {
        match self {
            Self::ClaudeCode => DataSource::HistorianClaudeCode,
            Self::GeminiCli => DataSource::HistorianGemini,
            Self::OpenAiCodex => DataSource::HistorianCodex,
            Self::Cursor => DataSource::HistorianCursor,
            Self::GithubCopilot => DataSource::HistorianGithubCopilot,
            Self::Continue => DataSource::HistorianContinue,
            Self::OpenClaw => DataSource::HistorianOpenClaw,
            Self::Unknown(_) => DataSource::HistorianUnknown,
        }
    }
}

/// Resolved tool identity fields written to event metadata so cloud
/// analytics can group historian events by tool without a catalog lookup.
#[derive(Debug, Clone, Copy)]
pub struct ToolIdentity {
    pub identity_key: &'static str,
    pub tool_name: &'static str,
    pub tool_kind: &'static str,
    pub tool_category: &'static str,
    pub provider_id: &'static str,
}

impl std::fmt::Display for AiTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key())
    }
}

/// How a tool stores its conversation history on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFormat {
    JsonLines,
    JsonFiles,
    SqliteDb {
        db_path: PathBuf,
        schema_hint: Option<String>,
    },
    Mixed,
}

/// A tool installation found during discovery.
#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    pub tool: AiTool,
    pub root_path: PathBuf,
    pub format: StorageFormat,
    pub session_count_estimate: Option<u64>,
}

/// Result of a full discovery scan.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryReport {
    pub tools: Vec<DiscoveredTool>,
    pub scan_duration_ms: u64,
    pub errors: Vec<String>,
}

/// A single reconstructed conversation session from local history.
#[derive(Debug, Clone)]
pub struct HistoricalSession {
    pub tool: AiTool,
    pub session_id: String,
    pub messages: Vec<HistoricalMessage>,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
}

/// A single message within a historical session.
#[derive(Debug, Clone)]
pub struct HistoricalMessage {
    pub role: String,
    pub content: String,
    pub timestamp: Option<i64>,
    pub token_estimate: u32,
}

/// Cursor for incremental reads — persisted in historian.db.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Cursor {
    FileOffset {
        path: PathBuf,
        byte_offset: u64,
        line_count: u64,
    },
    SqliteRowId {
        db_path: PathBuf,
        last_rowid: i64,
    },
    FileMtime {
        path: PathBuf,
        mtime: i64,
    },
}

/// Summary returned after a backfill run.
#[derive(Debug, Clone, Default)]
pub struct BackfillSummary {
    pub sessions_processed: u64,
    pub events_emitted: u64,
    pub duplicates_skipped: u64,
    pub errors: u64,
    pub duration_ms: u64,
}

/// Progress snapshot for an in-flight backfill.
#[derive(Debug, Clone, Default)]
pub struct BackfillProgress {
    pub tool: Option<AiTool>,
    pub sessions_total: u64,
    pub sessions_done: u64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
}
