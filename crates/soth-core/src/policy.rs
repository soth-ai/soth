use serde::{Deserialize, Serialize};

use crate::artifacts::CaptureMode;
use crate::classify::{AnomalyFlag, ProcessResolution, SessionSnapshot, TrafficClassification};
use crate::telemetry::{UseCaseLabel, VolatilityClass};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub kind: PolicyDecisionKind,
    pub matched_rule: Option<MatchedRule>,
    pub warnings: Vec<PolicyWarning>,
    pub eval_latency_us: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Block { status: u16, message: String },
    Redact { targets: Vec<RedactTarget> },
    Reroute { target: RerouteTarget },
    Flag { reason: String },
}

impl PolicyDecisionKind {
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    System,
    Org,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_kind: RuleKind,
    pub cel_expr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactTarget {
    pub field_path: String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerouteTarget {
    pub provider: String,
    pub model: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyWarning {
    RuleError { rule_id: String, error: String },
    BundleWarning(String),
    BudgetNearLimit { pct_used: f32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub process_resolution: ProcessResolution,
    pub capture_mode: CaptureMode,
    pub traffic_classification: TrafficClassification,
    pub deployment: DeploymentModel,
    pub skip_org_rules: bool,
    pub semantic: Option<SemanticPolicyContext>,
    pub session: SessionSnapshot,
    /// Action-layer fields populated by the `soth-code` hook
    /// handler from the agent's `CodeEvent`. `None` for
    /// network-layer (proxy) and session-layer (historian)
    /// evaluations — those layers don't observe individual
    /// agent actions, so the `action.*` namespace stays
    /// unbound (rules referencing it evaluate to Null).
    ///
    /// Exposed in CEL scope as `action.agent`, `action.type`,
    /// `action.tool_name`, `action.command`, `action.file_path`.
    /// Lets operators author rules like:
    ///   `action.type == "command_exec" && action.command.contains("rm -rf")`
    /// or:
    ///   `action.type == "file_write" && action.file_path.contains(".ssh/")`
    /// at the action layer where enforcement actually halts the
    /// agent before the call lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionPolicyContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPolicyContext {
    /// Adapter name — `claude_code`, `cursor`, `codex`,
    /// `gemini_cli`, `pi_agent`, `windsurf`, `opencode`.
    pub agent: String,
    /// `ActionType` serialized as snake_case (`file_read`,
    /// `command_exec`, `tool_use`, …). Mirrors
    /// `extensions/code/src/event.rs::ActionType::as_str` so
    /// CEL rules and adapter code agree on the spelling.
    pub action_type: String,
    /// Tool name from `tool_use` payloads — `"Bash"`, `"Edit"`,
    /// `"Read"` for Claude Code, agent-specific for the others.
    /// `None` for non-tool-use actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Full command string for `command_exec` actions (e.g. the
    /// argument to Bash). `None` when not a command-exec event
    /// or when the adapter couldn't extract it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Target file path for `file_read` / `file_write` /
    /// `file_delete` actions. `None` for non-file actions or
    /// when the adapter couldn't extract it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticPolicyContext {
    pub use_case_label: UseCaseLabel,
    pub use_case_confidence: f32,
    pub anomaly_score: f32,
    pub anomaly_flags: Vec<AnomalyFlag>,
    pub complexity_score: u8,
    pub volatility_class: VolatilityClass,
    pub topic_cluster_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentModel {
    Proxy,
    Sidecar {
        service_name: String,
        environment: String,
    },
    Sdk {
        service_name: String,
        environment: String,
    },
}
