use serde::{Deserialize, Serialize};

use crate::{
    CaptureMode, NormalizedRequest, ParseConfidence, ParseSource, ParseWarning, SensitiveArtifact,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub normalized: NormalizedRequest,
    pub artifacts: Vec<SensitiveArtifact>,
    pub capture_mode: CaptureMode,
    pub parse_source: ParseSource,
    pub confidence: ParseConfidence,
    pub detect_latency_us: u64,
    pub warnings: Vec<ParseWarning>,
}
