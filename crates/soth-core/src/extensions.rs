use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::{CaptureMode, SensitiveArtifact};
use crate::normalized::{EndpointType, NormalizedRequest};

// ---------------------------------------------------------------------------
// Metadata key constants
// ---------------------------------------------------------------------------
//
// Standardized keys for `ExtensionContext::metadata`. Constants — not inline
// string literals — so producers and consumers across crates agree on the
// canonical name. New keys land here when more than one crate reads them.
// (→ `docs/gryph/plan.md` §10.6 for the boundary spec.)

/// Agent's own session identifier as carried in the hook payload
/// (Claude Code's project-hash-derived ID, Cursor's chat thread ID, etc.).
/// Populated by `soth-code` adapters; consumed when computing
/// [`META_CORRELATION_KEY`].
pub const META_AGENT_NATIVE_SESSION_ID: &str = "agent_native_session_id";

/// Per-action type tag (e.g. `"file_read"`, `"command_exec"`, `"tool_use"`).
/// Populated by `soth-code` adapters.
pub const META_ACTION_TYPE: &str = "action_type";

/// Per-action sequence number within an agent session, when the hook
/// payload supplies one (e.g. Claude Code's PreToolUse step counter).
pub const META_ACTION_SEQ: &str = "action_seq";

/// Cross-layer correlation key — `sha256(agent_name || ":" || agent_native_session_id)`.
/// Joins network/action/session events for the same agent session in the
/// dashboard. See [`crate::correlation::correlation_key`].
pub const META_CORRELATION_KEY: &str = "correlation_key";

/// Explicit event-layer tag mirrored into `metadata` for consumers that
/// read `GovernableEvent` rather than `TelemetryEvent` (which has the
/// first-class `event_layer` field). Values match `EventLayer` snake_case.
pub const META_EVENT_LAYER: &str = "event_layer";

// ---------------------------------------------------------------------------
// GovernableEvent — normalized event shape governance extensions produce
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernableEvent {
    pub event_id: Uuid,
    pub timestamp_epoch_ms: i64,
    pub source: EventSource,
    pub provider: String,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,
    pub normalized: Option<NormalizedRequest>,
    pub artifacts: Vec<SensitiveArtifact>,
    pub capture_mode: CaptureMode,
    /// LOCAL ONLY — used for on-device embedding; never serialized to cloud.
    #[serde(skip)]
    pub embed_content: Option<String>,
    pub context: ExtensionContext,
}

// ---------------------------------------------------------------------------
// EventSource — where the event originated
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventSource {
    Http,
    Sidecar,
    Extension { source: ExtensionSource },
}

// ---------------------------------------------------------------------------
// ExtensionSource — known extension variants
// ---------------------------------------------------------------------------
//
// Supersedes the former `ExtensionType` enum. Broader scope: includes all
// known first-party extensions plus a custom escape hatch.

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSource {
    Gryph,
    McpReticle,
    Historian,
    SubscriptionDetector,
    Custom(String),
}

impl ExtensionSource {
    /// Stable machine name used in file paths, queue files, migration tags.
    pub fn name(&self) -> &str {
        match self {
            Self::Gryph => "gryph",
            Self::McpReticle => "mcp_reticle",
            Self::Historian => "historian",
            Self::SubscriptionDetector => "subscription_detector",
            Self::Custom(name) => name.as_str(),
        }
    }
}

/// Backward-compatible alias during migration.
pub type ExtensionType = ExtensionSource;

// ---------------------------------------------------------------------------
// ExtensionContext — metadata an extension attaches to each event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionContext {
    pub extension_name: String,
    pub extension_version: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}
