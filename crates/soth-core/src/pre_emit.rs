use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::CaptureMode;
use crate::classify::AnomalyFlag;
use crate::normalized::EndpointType;
use crate::policy::PolicyDecisionKind;
use crate::telemetry::{TelemetryPolicyKind, UseCaseLabel};

// ---------------------------------------------------------------------------
// PreEmitEvent — the observer-facing snapshot produced after classify
// ---------------------------------------------------------------------------
//
// This is the single type that connects soth-proxy to passive observer
// extensions via the `observer_broadcast` closure injected into ProxyConfig.
//
// It carries everything a passive observer (e.g. subscription detector) needs
// to extract signals from live proxy traffic without accessing raw content.
//
// Privacy invariant: no raw prompt, response, or URL content. Only hashes,
// counters, labels, and response metadata headers.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreEmitEvent {
    // ── Identity ──────────────────────────────────────────────────────────
    pub event_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub timestamp_epoch_ms: i64,

    // ── Provider / model ──────────────────────────────────────────────────
    pub provider: String,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,
    pub capture_mode: CaptureMode,

    // ── Hashed endpoint (never raw URL) ──────────────────────────────────
    pub endpoint_hash: String,

    // ── Token / cost estimates ────────────────────────────────────────────
    pub estimated_input_tokens: u32,
    pub estimated_output_tokens: Option<u32>,
    pub estimated_cost_usd: f32,

    // ── Classify outputs ─────────────────────────────────────────────────
    pub use_case_label: UseCaseLabel,
    pub anomaly_score: f32,
    pub anomaly_flags: Vec<AnomalyFlag>,
    pub policy_kind: Option<TelemetryPolicyKind>,
    pub policy_decision_kind: Option<PolicyDecisionKind>,

    // ── Content shape flags (no raw content) ─────────────────────────────
    pub code_present: bool,
    pub credential_detected: bool,
    pub cache_hit: bool,

    // ── Response metadata — needed for subscription/rate-limit detection ──
    pub response_status: Option<u16>,
    /// Selected response headers relevant to subscription detection.
    /// Only rate-limit and plan-tier headers; never content headers.
    #[serde(default)]
    pub response_headers: Vec<(String, String)>,
}

/// Type alias for the observer broadcast closure injected into the proxy.
pub type ObserverBroadcast = Arc<dyn Fn(&PreEmitEvent) + Send + Sync>;

impl PreEmitEvent {
    /// Construct from a TelemetryEvent and ClassifiedResult fields available
    /// in the classify_task after classification completes.
    pub fn from_telemetry_event(
        te: &crate::telemetry::TelemetryEvent,
        anomaly_score: f32,
        anomaly_flags: &[crate::classify::AnomalyFlag],
        policy_decision_kind: Option<PolicyDecisionKind>,
        capture_mode: CaptureMode,
    ) -> Self {
        let flags = &te.classification_flags;
        Self {
            event_id: te.event_id,
            connection_id: te.connection_id,
            timestamp_epoch_ms: te.timestamp_epoch_ms,
            provider: te.provider.clone(),
            model: te.model.clone(),
            endpoint_type: te.endpoint_type,
            capture_mode,
            endpoint_hash: te.endpoint_hash.clone(),
            estimated_input_tokens: te.estimated_input_tokens.unwrap_or(0),
            estimated_output_tokens: te.estimated_output_tokens,
            estimated_cost_usd: te.estimated_cost_usd.unwrap_or(0.0),
            use_case_label: te.use_case,
            anomaly_score,
            anomaly_flags: anomaly_flags.to_vec(),
            policy_kind: te.policy_kind,
            policy_decision_kind,
            code_present: flags.contains(&crate::telemetry::ClassificationFlag::CodeDetected),
            credential_detected: flags
                .contains(&crate::telemetry::ClassificationFlag::CredentialDetected),
            cache_hit: te.cache_level.is_some(),
            response_status: None,
            response_headers: Vec::new(),
        }
    }
}

impl Default for PreEmitEvent {
    fn default() -> Self {
        Self {
            event_id: Uuid::nil(),
            connection_id: None,
            timestamp_epoch_ms: 0,
            provider: "unknown".to_string(),
            model: None,
            endpoint_type: EndpointType::Unknown,
            capture_mode: CaptureMode::MetadataOnly,
            endpoint_hash: String::new(),
            estimated_input_tokens: 0,
            estimated_output_tokens: None,
            estimated_cost_usd: 0.0,
            use_case_label: UseCaseLabel::Unknown,
            anomaly_score: 0.0,
            anomaly_flags: Vec::new(),
            policy_kind: None,
            policy_decision_kind: None,
            code_present: false,
            credential_detected: false,
            cache_hit: false,
            response_status: None,
            response_headers: Vec::new(),
        }
    }
}
