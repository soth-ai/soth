use crate::artifacts::CaptureMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyContext {
    pub org_id: String,
    pub user_id_hmac: String,
    pub team_id: String,
    pub device_id_hash: String,
    pub endpoint_hash: String,
    pub process_resolution: ProcessResolution,
    pub capture_mode: CaptureMode,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
    pub traffic_classification: TrafficClassification,
    pub classification_source: ClassificationSource,
    pub session_snapshot: Option<SessionSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    Proxy,
    Sidecar,
    Sdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClassification {
    ToolUsage,
    ApplicationUsage,
    UnknownAgent,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    Host,
    NonHost,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMatchKind {
    Exact,
    Pattern,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResolution {
    pub match_kind: ProcessMatchKind,
    pub app_type: AppType,
    pub capture_mode: Option<CaptureMode>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub request_count: u32,
    pub total_tokens: u64,
    pub total_cost_usd: f32,
    pub credential_alerts: u32,
    pub embedding_centroid: Option<Vec<f32>>,
    pub prior_semantic_hashes: Vec<String>,
    pub last_model: Option<String>,
    pub current_request_timestamp: i64,
    pub last_request_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyFlag {
    TopicDrift,
    CredentialBurst,
    TokenBurst,
    ModelSwitch,
    AgentLoopPattern,
    RapidFireRequests,
    UnusualSystemPromptChange,
    ToolCallDepthSpike,
}
