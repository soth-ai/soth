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
    DetectBundleSlice, Filters, GrpcFieldSpec, GrpcServiceRegistry, GrpcServiceSpec,
    GraphQLHeuristicPattern, GraphQLOperationRegistry, GraphQLOperationSpec, OwnedDetectBundle,
    PreprocessOp, ProviderEntry, RequestEncoding, RestFormatDescriptor, RestRequestPaths,
    RestResponsePaths, StreamFormat, StreamOptions,
};

pub type HeaderMap = RequestHeaders;

#[derive(Clone, Debug)]
pub struct Provider {
    canonical_name: String,
}

impl Provider {
    pub fn new(canonical_name: impl Into<String>) -> Self {
        Self {
            canonical_name: canonical_name.into(),
        }
    }

    pub fn canonical_name(&self) -> &str {
        self.canonical_name.as_str()
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new("unknown")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointType {
    Chat,
    Completion,
    Embedding,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GqlOpType {
    Query,
    Mutation,
    Subscription,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseWarning {
    InvalidJson,
    MissingField(String),
    NonJsonBody,
    LongestStringHeuristic,
    ContentNotExtracted,
    GraphQLSyntaxError,
    GraphQLUnknownOperation(String),
    GrpcDescriptorMissing(String),
    WebSocketBinaryUnparseable,
    TreeSitterPanic,
    TreeSitterTimeout,
    ParserError(String),
    NoParserForFormat(String),
    FilteredByKeyword,
}

#[derive(Clone, Debug)]
pub struct NormalizedRequest {
    pub parse_confidence: ParseConfidence,
    pub parser_id: String,
    pub schema_version: &'static str,
    pub parse_warnings: Vec<ParseWarning>,
    pub is_ai_call: bool,

    pub provider: Provider,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,

    pub system_prompt_hash: Option<String>,
    pub system_prompt_token_estimate: Option<u32>,
    pub user_content_hash: String,
    pub user_content_token_estimate: u32,
    pub conversation_hash: String,
    pub conversation_turn: Option<u32>,
    pub has_tool_definitions: bool,
    pub tool_definition_hash: Option<String>,

    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
    pub top_p: Option<f32>,
    pub stop_sequences: Vec<String>,

    pub estimated_input_tokens: u32,
    pub estimated_cost_usd: f32,

    pub canonical_hash: String,

    pub format_meta: FormatMeta,

    pub api_version: Option<String>,

    // Internal helper field for optional post-parse scans without raw content retention.
    pub content_sample: Option<String>,
}

impl NormalizedRequest {
    pub fn empty_heuristic(method: &str, path: &str) -> Self {
        Self {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: "heuristic-v1".to_string(),
            schema_version: "1",
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: Provider::default(),
            model: None,
            endpoint_type: EndpointType::Unknown,
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
            canonical_hash: String::new(),
            format_meta: FormatMeta::Unknown {
                method: method.to_string(),
                path: path.to_string(),
            },
            api_version: None,
            content_sample: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum FormatMeta {
    Rest {
        path: String,
    },
    GraphQL {
        operation_name: Option<String>,
        operation_type: GqlOpType,
        mutation_field: Option<String>,
    },
    Grpc {
        service: String,
        method: String,
        proto_package: Option<String>,
    },
    JsonRpc {
        method: Option<String>,
        is_batch: bool,
    },
    WebSocket {
        frame_kind_hint: String,
    },
    Unknown {
        method: String,
        path: String,
    },
}

#[derive(Clone, Debug)]
pub struct DetectResult {
    pub normalized: NormalizedRequest,
    pub artifacts: Vec<SensitiveArtifact>,
    pub capture_mode: CaptureMode,
    pub parse_source: ParseSource,
    pub confidence: ParseConfidence,
    pub detect_latency_us: u64,
    pub warnings: Vec<DetectWarning>,
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

impl DetectResult {
    pub fn filtered() -> Self {
        let normalized = NormalizedRequest {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: "filtered-v1".to_string(),
            schema_version: "1",
            parse_warnings: vec![ParseWarning::FilteredByKeyword],
            is_ai_call: false,
            provider: Provider::default(),
            model: None,
            endpoint_type: EndpointType::Unknown,
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
            canonical_hash: String::new(),
            format_meta: FormatMeta::Unknown {
                method: String::new(),
                path: String::new(),
            },
            api_version: None,
            content_sample: None,
        };

        Self {
            confidence: normalized.parse_confidence.clone(),
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

#[derive(Clone, Debug)]
pub enum ParseSource {
    OpenAI,
    Anthropic,
    Cohere,
    Google,
    Bedrock,
    GraphQL { operation_name: Option<String> },
    Grpc { service: String, method: String },
    JsonRpc { method: Option<String> },
    AgentApp { app_id: String },
    Heuristic,
    Filtered,
}

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

#[derive(Clone, Debug)]
pub struct SensitiveArtifact {
    pub artifact_type: ArtifactType,
    pub commitment: String,
    pub severity: Severity,
    pub location: ArtifactLocation,
    pub redacted_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ArtifactType {
    OpenAIKey,
    AnthropicKey,
    AwsAccessKey,
    GitHubPat,
    GitLabToken,
    SlackToken,
    StripeSecretKey,
    JwtToken,
    PrivateKey,
    ConnectionString,
    CodeBlock { language: String },
    UnknownCredential,
    AuthLogicFlag,
    CryptoFlag,
    OrgPatternMatch { pattern_id: u32 },
}

#[derive(Clone, Debug)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug)]
pub enum ArtifactLocation {
    SystemPrompt,
    UserMessage { turn_index: u32 },
    AssistantMessage { turn_index: u32 },
    ToolDefinition { tool_name: String },
    Header { header_name: String },
    StreamChunk { sequence: u64 },
    Unknown,
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
    PartialParse(NormalizedRequest, Vec<ParseWarning>),
}

pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectedImportCategory {
    Crypto,
    Auth,
    Network,
    Database,
    FileSystem,
    Serialization,
}

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
