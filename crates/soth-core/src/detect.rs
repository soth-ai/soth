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

    // ── Internal: session prefix-repeat dedup. SDK callers can leave at
    //    default — the proxy's session manager populates these from the
    //    SessionSnapshot, and stage 5 anomaly scoring reads them. They do
    //    not affect classification when zero/None. ───────────────────────────
    /// Internal — proxy dedup signal. SDK can default to `false`.
    #[serde(default)]
    pub is_prefix_repeat: bool,
    /// Internal — proxy dedup signal. SDK can default to `0`.
    #[serde(default)]
    pub novel_token_count: u32,
    /// Internal — proxy dedup signal. SDK can default to `0`.
    #[serde(default)]
    pub repeated_token_count: u32,
    /// Internal — proxy dedup signal. SDK can default to `None`.
    #[serde(default)]
    pub novel_tail_start_idx: Option<usize>,
    /// Internal — proxy dedup signal. SDK can default to `None`.
    #[serde(default)]
    pub prefix_hash: Option<String>,
    /// Internal — proxy dedup signal. SDK can default to `false`.
    #[serde(default)]
    pub is_repeated_code_context: bool,
    /// Internal — proxy dedup signal. SDK can default to `None`.
    #[serde(default)]
    pub ast_normalized_hash: Option<String>,
    /// Internal — proxy intelligence signal. SDK can default to `None`.
    #[serde(default)]
    pub first_blob_event_id: Option<Uuid>,

    #[serde(default)]
    pub import_categories: Vec<crate::ImportCategory>,
    /// The user's actual prompt text extracted from the parsed request body.
    /// NOT the raw HTTP body or system prompt — just what the user typed.
    /// Populated by the detect layer for embedding/classify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_prompt: Option<String>,
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
            import_categories: Vec::new(),
            user_prompt: None,
        }
    }
}

impl DetectResult {
    /// Construct a `DetectResult` for an SDK-supplied pre-parsed call.
    ///
    /// Sets `parse_source = ParseSource::Sdk` and `confidence = ParseConfidence::Full`,
    /// since the SDK has typed access to the call data and there's no parsing
    /// to be uncertain about. Dedup fields default to their zero values; if
    /// the SDK has session state it can populate them after construction or
    /// route through `soth_detect::process_normalized`, which runs the same
    /// session prefix-repeat phase as the proxy hot path.
    pub fn from_typed_call(
        normalized: NormalizedRequest,
        artifacts: Vec<SensitiveArtifact>,
        capture_mode: CaptureMode,
    ) -> Self {
        Self {
            normalized,
            artifacts,
            capture_mode,
            parse_source: ParseSource::Sdk,
            confidence: ParseConfidence::Full,
            ..Default::default()
        }
    }
}
