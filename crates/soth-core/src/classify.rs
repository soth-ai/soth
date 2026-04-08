use crate::artifacts::CaptureMode;
use crate::telemetry::RequestMethod;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_trust_level: Option<crate::telemetry::BundleTrustLevel>,

    // ── Connection intelligence ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_stream_id: Option<u32>,

    // ── Product taxonomy & session (v7+) ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    #[serde(default)]
    pub surface_type: SurfaceType,
    #[serde(default)]
    pub is_shadow_it: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    Host,
    NonHost,
    #[default]
    Unknown,
}

impl AppType {
    /// Convert to the finer-grained `AppKind`. Lossy: `NonHost` maps to
    /// `AgentApp` since the original granularity (Ide/Cli/AgentApp) was lost.
    pub fn to_app_kind(self) -> crate::AppKind {
        match self {
            Self::Host => crate::AppKind::Browser,
            Self::NonHost => crate::AppKind::AgentApp,
            Self::Unknown => crate::AppKind::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMatchKind {
    Exact,
    Pattern,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessResolution {
    pub match_kind: ProcessMatchKind,
    pub app_type: AppType,
    pub capture_mode: Option<CaptureMode>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    /// Resolved app_id from the detect bundle (e.g. "claude-code", "cursor").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_app_id: Option<String>,

    // ── Unified registry resolved fields (v6+) ──
    // Pre-resolved at the edge so the cloud can use them directly
    // without catalog lookup or COALESCE fallback chains.
    /// Human-readable display name (e.g. "Cursor", "Claude Code").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Fine-grained entity kind: "ide", "cli", "browser", "platform", etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_kind: Option<String>,
    /// Dashboard category: "Code Editor", "CLI Tool", "AI Platform", etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_category: Option<String>,
    /// Linked provider entity slug (e.g. "anthropic" for Cursor→Anthropic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
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

/// Product delivery mechanism — how an AI tool reaches the user.
///
/// Aligned with `EntityKind` in the bundle: each entity kind maps 1:1 to a
/// surface type so cloud analytics can break down by delivery mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceType {
    /// IDE / code editor (e.g. VS Code, JetBrains, Neovim)
    Ide,
    /// IDE plugin / extension that runs inside an IDE host
    #[serde(rename = "ide_plugin")]
    IdePlugin,
    /// CLI tool (e.g. `gh copilot`, `aider`)
    #[serde(rename = "cli")]
    Cli,
    /// Autonomous agent application (e.g. Devin, SWE-Agent)
    Agent,
    /// Desktop application (e.g. ChatGPT.app)
    Desktop,
    /// Web application accessed via browser (e.g. chat.openai.com)
    WebApp,
    /// Browser extension (e.g. Monica, Merlin)
    BrowserExtension,
    /// Platform / SDK integration (e.g. LangChain, direct API)
    #[serde(rename = "sdk")]
    Sdk,
    #[default]
    Unknown,
}

impl SurfaceType {
    /// Derive the coarse `AppType` from the delivery surface.
    ///
    /// Web-delivered surfaces (`WebApp`, `BrowserExtension`) are `Host`; everything
    /// that runs as a standalone process or embedded tool is `NonHost`.
    pub fn app_type(&self) -> AppType {
        match self {
            Self::WebApp | Self::BrowserExtension => AppType::Host,
            Self::Ide | Self::IdePlugin | Self::Cli | Self::Agent | Self::Desktop | Self::Sdk => {
                AppType::NonHost
            }
            Self::Unknown => AppType::Unknown,
        }
    }
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
