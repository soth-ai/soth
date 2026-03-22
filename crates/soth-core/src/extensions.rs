use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::{CaptureMode, SensitiveArtifact};
use crate::normalized::{EndpointType, NormalizedRequest};

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
