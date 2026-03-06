use crate::artifacts::CaptureMode;
use crate::telemetry::RequestMethod;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<RequestMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_context: Option<DeploymentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precomputed_commitment_nonce: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precomputed_commitment_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentContext {
    pub service_name: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_model: Option<String>,
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
    // New Stage-5 deterministic anomaly inputs.
    pub session_token_total: u32,
    pub session_token_p14d_avg: f32,
    pub request_count_this_hour: u32,
    pub credential_alerts_24h: u8,
    pub topic_cluster_ids_seen: Vec<u32>,
    pub models_used_this_session: Vec<String>,
    pub last_system_prompt_hash: Option<String>,
    pub max_tool_depth_seen: u8,

    // Backward-compatible fields used by policy/runtime paths.
    pub request_count: u32,
    pub total_tokens: u64,
    pub total_cost_usd: f32,
    pub credential_alerts: u32,
    pub embedding_centroid: Option<Vec<f32>>,
    pub prior_semantic_hashes: Vec<String>,
    pub last_model: Option<String>,
    pub current_request_timestamp: i64,
    pub last_request_timestamp: Option<i64>,

    // Dedup-aware fields (Phase 1). All default to empty/zero so existing
    // consumers that construct `SessionSnapshot::default()` are unaffected.
    #[serde(default)]
    pub seen_prefix_hashes: Vec<String>,
    #[serde(default)]
    pub seen_code_hashes: Vec<String>,
    #[serde(default)]
    pub session_key_hash: String,
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
