use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CaptureMode, NormalizedRequest, ParseConfidence, ParseSource, ParseWarning, SensitiveArtifact,
    SessionMutations,
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
    #[serde(default)]
    pub session_mutations: SessionMutations,
    #[serde(default)]
    pub is_prefix_repeat: bool,
    #[serde(default)]
    pub novel_token_count: u32,
    #[serde(default)]
    pub repeated_token_count: u32,
    #[serde(default)]
    pub novel_tail_start_idx: Option<usize>,
    #[serde(default)]
    pub prefix_hash: Option<String>,
    #[serde(default)]
    pub is_repeated_code_context: bool,
    #[serde(default)]
    pub ast_normalized_hash: Option<String>,
    #[serde(default)]
    pub first_blob_event_id: Option<Uuid>,
}

impl Default for DetectResult {
    fn default() -> Self {
        Self {
            normalized: NormalizedRequest::default(),
            artifacts: Vec::new(),
            capture_mode: CaptureMode::MetadataOnly,
            parse_source: ParseSource::Heuristic,
            confidence: ParseConfidence::Heuristic,
            detect_latency_us: 0,
            warnings: Vec::new(),
            session_mutations: SessionMutations::default(),
            is_prefix_repeat: false,
            novel_token_count: 0,
            repeated_token_count: 0,
            novel_tail_start_idx: None,
            prefix_hash: None,
            is_repeated_code_context: false,
            ast_normalized_hash: None,
            first_blob_event_id: None,
        }
    }
}
