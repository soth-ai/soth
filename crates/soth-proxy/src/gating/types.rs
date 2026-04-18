use serde::{Deserialize, Serialize};

use soth_core::bundle::gating::{EntityId, GateStage};
use soth_core::{AppType, CaptureMode, TrafficClassification};

/// The final decision produced by the gating evaluator for a single HTTP
/// request.  All fields are proxy-internal; nothing in soth-core or any
/// downstream crate depends on this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateOutcome {
    pub decision: GateDecision,
    pub reason: DecisionReason,
    pub app_type: AppType,
    pub capture_mode: CaptureMode,
    pub matched_provider: Option<EntityId>,
    pub matched_application: Option<EntityId>,
    pub traffic_classification: TrafficClassification,
    pub discovery_capture: bool,
    pub terminal_stage: GateStage,
}

impl Default for GateOutcome {
    fn default() -> Self {
        Self {
            decision: GateDecision::Skip,
            reason: DecisionReason::NotInCatalog,
            app_type: AppType::Unknown,
            capture_mode: CaptureMode::MetadataOnly,
            matched_provider: None,
            matched_application: None,
            traffic_classification: TrafficClassification::Other,
            discovery_capture: false,
            terminal_stage: GateStage::Stage2Whitelist,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Intercept,
    Skip,
    Block { status: u16, message: String },
    Passthrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    TlsPassthroughDomain,
    TlsInterceptCatalog,
    TlsDiscovery,
    TlsDefaultPassthrough,
    ProcessAction,
    UnknownAppPolicy,
    NotInCatalog,
    PathDeniedExact,
    PathDeniedGlob,
    MethodNotAllowed,
    CaptureDisabled,
    BlacklistedKeyword,
    BlacklistedGraphQLOperation,
    HostOriginNotAllowed,
    Intercept,
}
