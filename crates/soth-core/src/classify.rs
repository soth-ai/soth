use crate::artifacts::CaptureMode;
use crate::telemetry::RequestMethod;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `ProxyContext` is the per-call envelope passed into `soth-classify`.
///
/// As of PR 2 it is a thin composition of three concern-shaped sub-contexts.
/// Wire format is preserved via `#[serde(flatten)]` — cloud-side consumers
/// see the same flat JSON shape as before the split.
///
/// Audience map:
/// - [`IdentityContext`]: domain identity. Both proxy and SDK populate.
/// - [`TransportContext`]: HTTP/TLS/H2 plumbing. **Proxy-only.** SDK leaves
///   every field at `Default::default()` (all `None`). Stages 6/7 read these
///   through `Option` and gracefully omit when absent.
/// - [`AttributionContext`]: proxy-derived gating outcomes (process info,
///   shadow-IT classification, surface taxonomy). **Proxy-only.** SDK leaves
///   at `Default::default()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyContext {
    #[serde(flatten)]
    pub identity: IdentityContext,
    #[serde(flatten)]
    pub transport: TransportContext,
    #[serde(flatten)]
    pub attribution: AttributionContext,
}

impl ProxyContext {
    /// Construct a `ProxyContext` for SDK callers that only have identity
    /// information. `transport` and `attribution` are filled with all-`None`
    /// defaults; stage 6/7 reads degrade gracefully.
    pub fn sdk_only(identity: IdentityContext) -> Self {
        Self {
            identity,
            transport: TransportContext::default(),
            attribution: AttributionContext::default(),
        }
    }

    /// Construct from explicit parts (proxy/sidecar use). All three contexts
    /// are required; pass `Default::default()` for any that aren't applicable.
    pub fn from_parts(
        identity: IdentityContext,
        transport: TransportContext,
        attribution: AttributionContext,
    ) -> Self {
        Self {
            identity,
            transport,
            attribution,
        }
    }
}

/// Domain identity carried by every classify call. Both the proxy and SDK
/// populate this fully — every field here is something an SDK caller can
/// supply from app context (org_id from config, user_id_hmac from app
/// session, etc.).
///
/// Field renames preserved on the wire:
/// - `declared_provider` ⇄ `"matched_provider"` JSON key
/// - `declared_application` ⇄ `"matched_application"` JSON key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    pub org_id: String,
    pub user_id_hmac: String,
    pub team_id: String,
    pub device_id_hash: String,
    pub endpoint_hash: String,
    pub capture_mode: CaptureMode,
    pub traffic_classification: TrafficClassification,
    pub classification_source: ClassificationSource,
    pub session_snapshot: Option<SessionSnapshot>,
    /// Provider entity slug for the call. In the proxy this is filled by
    /// the gating pipeline (`matched_provider` historically); in the SDK
    /// it's declared directly by the caller (e.g. `Some("openai".into())`).
    #[serde(
        default,
        rename = "matched_provider",
        skip_serializing_if = "Option::is_none"
    )]
    pub declared_provider: Option<String>,
    /// Application entity slug for the call. Same dual-source semantics as
    /// `declared_provider`.
    #[serde(
        default,
        rename = "matched_application",
        skip_serializing_if = "Option::is_none"
    )]
    pub declared_application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_context: Option<DeploymentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_trust_level: Option<crate::telemetry::BundleTrustLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precomputed_commitment_nonce: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precomputed_commitment_hash: Option<String>,
}

/// HTTP/TLS/H2 plumbing visible only to the proxy. SDK callers leave this
/// at `Default::default()` (all fields `None`); stages 6/7 read them through
/// `Option` and gracefully omit from telemetry/policy when absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<RequestMethod>,
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
}

/// Proxy-derived attribution: process resolution, surface taxonomy,
/// shadow-IT classification. SDK callers leave this at `Default::default()`
/// — they integrated the SDK on purpose, so concepts like `is_shadow_it`
/// don't apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributionContext {
    #[serde(default)]
    pub process_resolution: ProcessResolution,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClassification {
    ToolUsage,
    ApplicationUsage,
    #[default]
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
