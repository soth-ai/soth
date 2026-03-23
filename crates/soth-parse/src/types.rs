use bytes::Bytes;
pub use soth_core::{
    AppIdentity, AppKind, CaptureMode, ConnectionMeta, FrameKind, ParseConfidence, ProcessInfo,
    RawRequest, RequestHeaders, SocketFamily, StreamChunk, TlsInfo,
};
use std::time::Instant;
use uuid::Uuid;

// Re-export bundle schema types from soth-core (moved in B5 type unification).
pub use soth_core::{
    AppPolicy, ApplicationEntry, BrowserPolicies, CaptureOverrides, CaptureRules,
    DetectBundleSlice, Filters, GraphQLHeuristicPattern, GraphQLOperationRegistry,
    GraphQLOperationSpec, GrpcFieldSpec, GrpcServiceRegistry, GrpcServiceSpec, OwnedDetectBundle,
    PreprocessOp, ProductEntry, ProviderEntry, RequestEncoding, RestFormatDescriptor,
    RestRequestPaths, RestResponsePaths, StreamFormat, StreamOptions,
};

pub type HeaderMap = RequestHeaders;

pub use soth_core::EndpointType;

pub use soth_core::GraphQlOperationType;
/// Compat alias — will be removed in B6 when NormalizedRequest unifies.
pub type GqlOpType = GraphQlOperationType;

pub use soth_core::ParseWarning;

pub use soth_core::{FormatMetadata, NormalizedRequest};
/// Compat alias kept for brevity in parsers.
pub type FormatMeta = FormatMetadata;

/// Convenience constructor for the heuristic fallback path.
pub fn empty_heuristic_request(method: &str, path: &str) -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Heuristic,
        parser_id: "heuristic-v1".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "unknown".to_string(),
        model: None,
        endpoint_type: EndpointType::Unknown,
        api_version: None,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: String::new(),
        user_content_token_estimate: 0,
        conversation_hash: String::new(),
        conversation_turn: None,
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: 0,
        estimated_cost_usd: 0.0,
        parse_source: ParseSource::Heuristic,
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        canonical_cache_key: String::new(),
        format_metadata: FormatMetadata::Unknown {
            method: method.to_string(),
            path: path.to_string(),
        },
        user_prompt: None,
    }
}

/// The parse-layer detect result produced by `soth-detect`'s internal pipeline.
///
/// This is distinct from [`soth_core::DetectResult`], which is the
/// serialisable, public-API type that crosses crate boundaries.  The internal
/// type carries extra fields (e.g. `raw_body_bytes`, `DetectWarning` list)
/// that are stripped or mapped when converting via
/// `soth_detect::engine::to_core_detect_result`.
#[derive(Clone, Debug)]
pub struct ParseDetectResult {
    pub normalized: NormalizedRequest,
    pub artifacts: Vec<SensitiveArtifact>,
    pub capture_mode: CaptureMode,
    pub parse_source: ParseSource,
    pub confidence: ParseConfidence,
    pub detect_latency_us: u64,
    pub warnings: Vec<DetectWarning>,
    /// Raw request body bytes. Used for proxy telemetry (body size logging)
    /// and intelligence replay, NOT for the scanning pipeline.
    pub raw_body_bytes: Option<Bytes>,
    pub session_mutations: soth_core::SessionMutations,
    pub is_prefix_repeat: bool,
    pub novel_token_count: u32,
    pub repeated_token_count: u32,
    pub novel_tail_start_idx: Option<usize>,
    pub prefix_hash: Option<String>,
    pub is_repeated_code_context: bool,
    pub ast_normalized_hash: Option<String>,
    pub first_blob_event_id: Option<uuid::Uuid>,
    pub import_categories: Vec<DetectedImportCategory>,
}

/// Backwards-compatibility alias.  New code should use [`ParseDetectResult`]
/// to avoid confusion with [`soth_core::DetectResult`].
#[deprecated(
    since = "0.1.0",
    note = "use `ParseDetectResult` to avoid confusion with `soth_core::DetectResult`"
)]
pub type DetectResult = ParseDetectResult;

impl ParseDetectResult {
    pub fn filtered() -> Self {
        let normalized = NormalizedRequest {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: "filtered-v1".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: vec![ParseWarning::FilteredByKeyword],
            is_ai_call: false,
            provider: "unknown".to_string(),
            model: None,
            endpoint_type: EndpointType::Unknown,
            api_version: None,
            system_prompt_hash: None,
            system_prompt_token_estimate: None,
            user_content_hash: String::new(),
            user_content_token_estimate: 0,
            conversation_hash: String::new(),
            conversation_turn: None,
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 0,
            estimated_cost_usd: 0.0,
            parse_source: ParseSource::Filtered,
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            canonical_cache_key: String::new(),
            format_metadata: FormatMetadata::Unknown {
                method: String::new(),
                path: String::new(),
            },
            user_prompt: None,
        };

        Self {
            confidence: normalized.parse_confidence,
            normalized,
            artifacts: Vec::new(),
            capture_mode: CaptureMode::MetadataOnly,
            parse_source: ParseSource::Filtered,
            detect_latency_us: 0,
            warnings: Vec::new(),
            raw_body_bytes: None,
            session_mutations: soth_core::SessionMutations::default(),
            is_prefix_repeat: false,
            novel_token_count: 0,
            repeated_token_count: 0,
            novel_tail_start_idx: None,
            prefix_hash: None,
            is_repeated_code_context: false,
            ast_normalized_hash: None,
            first_blob_event_id: None,
            import_categories: Vec::new(),
        }
    }

    pub fn not_ai_call() -> Self {
        let mut out = Self::filtered();
        out.parse_source = ParseSource::Heuristic;
        out
    }
}

pub use soth_core::ParseSource;

// Artifact types unified with soth-core. The parse-local definitions have been
// deleted; soth-core is now the single source of truth.
pub use soth_core::{
    ArtifactKind, ArtifactLocation, ArtifactSeverity, ImportCategory, SensitiveArtifact,
};

/// Alias used by engine.rs imports that reference CoreArtifactLocation.
pub use soth_core::ArtifactLocation as CoreArtifactLocation;

/// Backwards-compat alias — callers that import ArtifactType still compile.
pub type ArtifactType = ArtifactKind;
/// Backwards-compat alias — callers that import Severity still compile.
pub type Severity = ArtifactSeverity;
/// Backwards-compat alias — callers that import DetectedImportCategory still compile.
pub type DetectedImportCategory = ImportCategory;

#[derive(Clone, Debug)]
pub struct DetectWarning {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct StreamSession {
    pub connection_id: Uuid,
    pub capture_mode: CaptureMode,
    pub delta_buffer: Vec<String>,
    pub chunk_count: u64,
    pub start_time: Instant,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub request_format: Option<FormatMeta>,
    pub estimated_input_tokens: u32,
    /// The rest format descriptor name (e.g. "chatgpt_web", "gemini_web") for
    /// bundle-driven streaming response extraction.
    pub format_name: Option<String>,
    /// Whether this is a WebSocket stream (multi-turn capable).
    pub is_websocket: bool,
    /// Number of turns completed so far (WebSocket only).
    pub turns_emitted: u64,
    /// Model for the current in-flight turn, captured from the client's
    /// `response.create` request frame.  Preferred over extracting from
    /// the server's `response.completed`.
    pub current_turn_model: Option<String>,
    /// Last usage extracted from any frame in the current turn.
    pub last_usage: Option<StreamUsage>,
    /// Finish reason extracted independently of usage (providers often send
    /// finish_reason in a different chunk than the usage summary).
    pub last_finish_reason: Option<String>,
}

/// Usage data extracted from a streaming frame.
#[derive(Clone, Debug, Default)]
pub struct StreamUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: Option<String>,
}

/// A completed AI turn within a WebSocket stream.
///
/// Emitted by `process_chunk_with_bundle()` when a `response.completed`
/// event is detected.  Model comes from the client's `response.create`
/// request frame; usage comes from the server's `response.completed`.
#[derive(Clone, Debug)]
pub struct StreamTurn {
    pub connection_id: Uuid,
    pub model: Option<String>,
    pub usage: StreamUsage,
    pub turn_number: u64,
}

impl StreamSession {
    pub fn new(connection_id: Uuid, capture_mode: CaptureMode) -> Self {
        Self {
            connection_id,
            capture_mode,
            delta_buffer: Vec::new(),
            chunk_count: 0,
            start_time: Instant::now(),
            grpc_service: None,
            grpc_method: None,
            provider: None,
            model: None,
            request_format: None,
            estimated_input_tokens: 0,
            format_name: None,
            is_websocket: false,
            turns_emitted: 0,
            current_turn_model: None,
            last_usage: None,
            last_finish_reason: None,
        }
    }

    pub fn accumulate(&mut self, value: impl Into<String>) {
        self.delta_buffer.push(value.into());
    }

    /// Called by soth-proxy after parsing the request to populate context.
    pub fn set_request_context(
        &mut self,
        provider: String,
        model: Option<String>,
        format: FormatMeta,
        estimated_input_tokens: u32,
    ) {
        self.provider = Some(provider);
        self.model = model;
        self.request_format = Some(format);
        self.estimated_input_tokens = estimated_input_tokens;
    }

    /// Set the rest format descriptor name for bundle-driven streaming extraction.
    pub fn set_format_name(&mut self, name: impl Into<String>) {
        self.format_name = Some(name.into());
    }

    pub fn set_grpc_context(&mut self, service: impl Into<String>, method: impl Into<String>) {
        self.grpc_service = Some(service.into());
        self.grpc_method = Some(method.into());
    }

    pub fn finalize_response_content(&self) -> String {
        self.delta_buffer.join("")
    }
}

#[derive(Clone, Debug)]
pub struct StreamSummary {
    pub response_hash: String,
    pub chunk_count: u64,
    pub elapsed_ms: u128,
}

#[derive(Clone, Debug)]
pub struct ChunkArtifact {
    pub sequence: u64,
    pub artifacts: Vec<SensitiveArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectedFormat {
    OpenAIRest,
    AnthropicRest,
    CohereRest,
    GeminiRest,
    BedrockRest,
    CustomRest(String),
    GraphQL,
    GrpcProtobuf,
    JsonRpc,
    Unknown,
}

#[derive(Debug)]
pub enum ParseError {
    MalformedBody(String),
    MissingRequiredField(String),
    GraphQLSyntax(String),
    GraphQLUnknownOperation(String),
    GrpcDescriptorMissing(String),
    NotAnAICall,
    PartialParse(Box<NormalizedRequest>, Vec<ParseWarning>),
}

pub type ParseResult<T> = Result<T, ParseError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn filters_match_domain_path_and_keywords() {
        let filters = Filters {
            path_keywords: vec!["blocked".to_string()],
            header_keywords: vec!["x-secret".to_string()],
            domain_patterns: vec!["*.example.com".to_string()],
            path_patterns: vec!["/v1/**".to_string()],
            keywords: vec!["token".to_string()],
        };

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "api.example.com:443".to_string());
        assert!(filters.matches("/anything", &headers));

        assert!(filters.matches("/v1/chat/completions", &BTreeMap::new()));

        let mut headers = BTreeMap::new();
        headers.insert("x-secret-key".to_string(), "present".to_string());
        assert!(filters.matches("/clean", &headers));

        assert!(filters.matches("/contains-token", &BTreeMap::new()));
    }

    #[test]
    fn capture_rules_support_provider_capture_override() {
        let rules = CaptureRules::default();
        let provider_entry = ProviderEntry {
            capture: Some(serde_json::json!({"mode":"full"})),
            ..ProviderEntry::default()
        };

        assert_eq!(rules.mode_for("openai"), CaptureMode::MetadataOnly);
        assert_eq!(
            rules.mode_for_with_entry("openai", Some(&provider_entry)),
            CaptureMode::Full
        );
    }
}
