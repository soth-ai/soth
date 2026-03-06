use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::{CaptureMode, SensitiveArtifact};
use crate::normalized::{EndpointType, NormalizedRequest};
use crate::providers::DetectedProvider;

// ---------------------------------------------------------------------------
// GovernableEvent — normalized event shape all extensions produce
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernableEvent {
    pub event_id: Uuid,
    pub timestamp_epoch_ms: i64,
    pub source: EventSource,
    pub provider: DetectedProvider,
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
    Extension { ext_type: ExtensionType },
}

// ---------------------------------------------------------------------------
// ExtensionType — known extension variants + custom escape hatch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionType {
    McpReticle,
    Gryph,
    Historian,
    Custom(String),
}

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
