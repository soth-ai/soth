use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::extensions::ExtensionSource;

// ---------------------------------------------------------------------------
// ObservationEvent — accumulated state signal from passive observer extensions
// ---------------------------------------------------------------------------
//
// Unlike GovernableEvent (discrete per-action, carries PolicyDecision),
// ObservationEvent is an aggregated signal produced periodically by passive
// observers. It has no PolicyDecision — observers cannot block.
//
// Privacy invariant: never contains raw prompts, raw response content, or raw
// URLs. `derived_state` is extension-controlled but subject to a field
// allowlist before inclusion in telemetry batches.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationEvent {
    // ── Identity ──────────────────────────────────────────────────────────
    pub event_id: Uuid,
    pub org_id: String,
    pub user_id_hmac: String,
    pub device_id_hash: String,
    pub extension_source: ExtensionSource,
    pub bundle_version: String,
    pub timestamp_utc: i64,

    // ── Observation payload ───────────────────────────────────────────────
    pub observation_kind: ObservationKind,
    pub subject: ObservationSubject,
    /// Confidence in the observation, 0.0 to 1.0.
    pub confidence: f32,
    pub evidence_signals: Vec<EvidenceSignal>,
    /// Extension-defined structured data. Reviewed against an allowlist
    /// before being included in telemetry batches.
    pub derived_state: serde_json::Value,
    pub observation_window_start: i64,
    pub observation_window_end: i64,
}

// ---------------------------------------------------------------------------
// ObservationKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Which tier/plan a tool subscription appears to be.
    SubscriptionTier,
    /// Evidence a specific AI tool is in active use.
    ToolPresence,
    /// Behavioral pattern across sessions.
    UsagePattern,
    /// Detected gap in expected governance coverage.
    ComplianceGap,
    /// Extension-defined, forward-compatible.
    Custom(String),
}

// ---------------------------------------------------------------------------
// ObservationSubject
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationSubject {
    /// Tool identifier: "claude", "chatgpt", "gemini", "copilot", etc.
    pub tool: String,
    /// Hashed endpoint — never raw URL.
    pub endpoint: Option<String>,
    pub model: Option<String>,
}

// ---------------------------------------------------------------------------
// EvidenceSignal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSignal {
    pub signal_type: EvidenceSignalType,
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSignalType {
    /// Subscription detector: a model at a specific tier was used.
    ModelAccessObserved { model_tier: String },
    /// Subscription detector: rate-limit headers indicate a tier class.
    RateLimitHeaderSeen { tier_class: String },
    /// Subscription detector: 429 response observed.
    RateLimitExceeded,
    /// Desktop app bundle detected on the system.
    DesktopAppPresent { bundle_id: String },
    /// A paid-only endpoint was successfully accessed.
    PaidEndpointHit,
    /// Traffic volume within a window.
    TrafficVolume {
        request_count: u32,
        window_seconds: u32,
    },
    /// Extension-defined, forward-compatible.
    Custom(String),
}
