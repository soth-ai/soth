use serde::{Deserialize, Serialize};

use crate::artifacts::CaptureMode;
use crate::classify::{ProcessResolution, SessionSnapshot, TrafficClassification};

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
    pub session: Option<SessionSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticPolicyContext {
    pub semantic_hash: Option<String>,
    pub previous_semantic_hash: Option<String>,
    pub semantic_drift_score: Option<f32>,
    pub use_case_label: Option<String>,
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
