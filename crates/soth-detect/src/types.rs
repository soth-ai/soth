use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
pub use soth_core::{
    AppIdentity, AppKind, CaptureMode, ConnectionMeta, FrameKind, ParseConfidence, ProcessInfo,
    RawRequest, RequestHeaders, SocketFamily, StreamChunk, TlsInfo,
};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

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
    pub import_categories: Vec<crate::code::DetectedImportCategory>,
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

pub trait AIRequestParser: Send + Sync {
    fn format(&self) -> DetectedFormat;
    fn parser_id(&self) -> &'static str;
    fn schema_version(&self) -> &'static str;
    fn parse(&self, req: &RawRequest) -> ParseResult<NormalizedRequest>;
    fn can_handle(&self, _req: &RawRequest) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct OwnedDetectBundle {
    pub rest_formats: HashMap<String, RestFormatDescriptor>,
    pub graphql_operations: GraphQLOperationRegistry,
    pub grpc_services: GrpcServiceRegistry,
    pub capture_rules: CaptureRules,
    pub domain_index: HashMap<String, String>,
    pub detection_index: HashMap<String, String>,
    pub llm_providers: HashMap<String, ProviderEntry>,
    pub applications: HashMap<String, ApplicationEntry>,
    pub filters: Filters,
    pub app_policies: HashMap<String, AppPolicy>,
    pub browser_policies: BrowserPolicies,
    #[serde(default)]
    pub passthrough_domains: Vec<String>,
    #[serde(default)]
    pub collectors: HashMap<String, JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_metadata: Option<JsonValue>,
    #[serde(default)]
    pub org_patterns: Vec<String>,
    /// Process names that are script runtimes / interpreters (e.g. "node", "python3").
    /// When a connection originates from a script runtime, identity resolution
    /// falls back to the parent process. Server-pushable; when empty the edge
    /// uses a built-in default list.
    #[serde(default)]
    pub script_runtimes: Vec<String>,
}

impl OwnedDetectBundle {
    pub fn as_slice(&self) -> DetectBundleSlice<'_> {
        DetectBundleSlice {
            rest_formats: &self.rest_formats,
            graphql_operations: &self.graphql_operations,
            grpc_services: &self.grpc_services,
            capture_rules: &self.capture_rules,
            domain_index: &self.domain_index,
            detection_index: &self.detection_index,
            llm_providers: &self.llm_providers,
            applications: &self.applications,
            filters: &self.filters,
            app_policies: &self.app_policies,
            browser_policies: &self.browser_policies,
            passthrough_domains: self.passthrough_domains.as_slice(),
            collectors: &self.collectors,
            source_metadata: self.source_metadata.as_ref(),
            org_patterns: &self.org_patterns,
            script_runtimes: &self.script_runtimes,
        }
    }
}

#[derive(Clone, Copy)]
pub struct DetectBundleSlice<'a> {
    pub rest_formats: &'a HashMap<String, RestFormatDescriptor>,
    pub graphql_operations: &'a GraphQLOperationRegistry,
    pub grpc_services: &'a GrpcServiceRegistry,
    pub capture_rules: &'a CaptureRules,
    pub domain_index: &'a HashMap<String, String>,
    pub detection_index: &'a HashMap<String, String>,
    pub llm_providers: &'a HashMap<String, ProviderEntry>,
    pub applications: &'a HashMap<String, ApplicationEntry>,
    pub filters: &'a Filters,
    pub app_policies: &'a HashMap<String, AppPolicy>,
    pub browser_policies: &'a BrowserPolicies,
    pub passthrough_domains: &'a [String],
    pub collectors: &'a HashMap<String, JsonValue>,
    pub source_metadata: Option<&'a JsonValue>,
    pub org_patterns: &'a [String],
    pub script_runtimes: &'a [String],
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestEncoding {
    #[default]
    Json,
    Form,
    QueryParams,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreprocessOp {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamFormat {
    #[default]
    Sse,
    Ndjson,
    LengthPrefixed,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct StreamOptions {
    /// SSE data line prefixes (default: ["data: "])
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// SSE values to skip (e.g. ["[DONE]"])
    #[serde(default)]
    pub skip_values: Vec<String>,
    /// NDJSON chunk delimiter (e.g. "}{", "-----CHUNK_BOUNDARY-----")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    /// Length-prefixed header to strip (e.g. ")]}'\\n")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_strip: Option<String>,
    /// Length-prefixed encoding (e.g. "protobuf", "json")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RestFormatDescriptor {
    pub tier: Option<u8>,
    #[serde(default)]
    pub request: RestRequestPaths,
    #[serde(default)]
    pub response: RestResponsePaths,
    #[serde(default)]
    pub system_in_messages: bool,
    #[serde(default)]
    pub content_blocks: bool,
    #[serde(default)]
    pub chat_history_mode: bool,
    pub model_from_url_segment: Option<String>,
    #[serde(default)]
    pub role_map: HashMap<String, String>,
    #[serde(default)]
    pub model_id_parse: bool,
    #[serde(default)]
    pub ephemeral_request_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_default: Option<String>,
    /// Request body encoding: json (default), form, query_params
    #[serde(default)]
    pub encoding: RequestEncoding,
    /// Form field name for form-encoded requests (e.g. "f.req", "variables")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_field: Option<String>,
    /// Request body preprocessing pipeline (json_parse, index, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preprocess: Vec<PreprocessOp>,
    /// Response streaming format (sse, ndjson, length_prefixed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_format: Option<StreamFormat>,
    /// Stream format-specific options
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RestRequestPaths {
    pub model: Option<String>,
    pub messages: Option<String>,
    pub message: Option<String>,
    pub chat_history: Option<String>,
    pub contents: Option<String>,
    pub system: Option<String>,
    pub system_instruction: Option<String>,
    pub tools: Option<String>,
    pub tool_choice: Option<String>,
    pub max_tokens: Option<String>,
    pub temperature: Option<String>,
    pub top_p: Option<String>,
    pub stream: Option<String>,
    pub stop: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RestResponsePaths {
    pub content: Option<String>,
    pub model: Option<String>,
    pub finish_reason: Option<String>,
    pub input_tokens: Option<String>,
    pub output_tokens: Option<String>,
    pub stop_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GraphQLOperationRegistry {
    pub version: Option<String>,
    #[serde(default)]
    pub operations: Vec<GraphQLOperationSpec>,
    #[serde(default)]
    pub heuristic_patterns: Vec<GraphQLHeuristicPattern>,
}

impl GraphQLOperationRegistry {
    pub fn get(&self, operation_name: &str) -> Option<&GraphQLOperationSpec> {
        self.operations
            .iter()
            .find(|op| op.operation_name.eq_ignore_ascii_case(operation_name))
    }

    pub fn with_default_operations() -> Self {
        Self {
            version: Some("1.0".to_string()),
            operations: vec![
                GraphQLOperationSpec {
                    operation_name: "SendAIMessage".to_string(),
                    provider_hint: Some("warp".to_string()),
                    is_ai_call: true,
                    content_path: Some(vec!["input".to_string(), "content".to_string()]),
                    model_path: Some(vec!["input".to_string(), "model".to_string()]),
                    system_prompt_path: None,
                    stream_path: Some(vec!["input".to_string(), "stream".to_string()]),
                    ephemeral_paths: vec![
                        vec!["input".to_string(), "sessionId".to_string()],
                        vec!["input".to_string(), "requestId".to_string()],
                        vec![
                            "input".to_string(),
                            "context".to_string(),
                            "workingDirectory".to_string(),
                        ],
                    ],
                },
                GraphQLOperationSpec {
                    operation_name: "ContinueAISession".to_string(),
                    provider_hint: Some("warp".to_string()),
                    is_ai_call: true,
                    content_path: Some(vec!["input".to_string(), "userMessage".to_string()]),
                    model_path: Some(vec!["input".to_string(), "model".to_string()]),
                    system_prompt_path: None,
                    stream_path: Some(vec!["input".to_string(), "streaming".to_string()]),
                    ephemeral_paths: vec![vec!["input".to_string(), "sessionId".to_string()]],
                },
            ],
            heuristic_patterns: vec![
                GraphQLHeuristicPattern {
                    mutation_field_contains: Some("AI".to_string()),
                    operation_name_contains: None,
                    likely_ai_call: Some(true),
                    confidence: Some("HEURISTIC".to_string()),
                },
                GraphQLHeuristicPattern {
                    mutation_field_contains: Some("Completion".to_string()),
                    operation_name_contains: None,
                    likely_ai_call: Some(true),
                    confidence: Some("HEURISTIC".to_string()),
                },
            ],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GraphQLOperationSpec {
    pub operation_name: String,
    pub provider_hint: Option<String>,
    pub is_ai_call: bool,
    pub content_path: Option<Vec<String>>,
    pub model_path: Option<Vec<String>>,
    pub system_prompt_path: Option<Vec<String>>,
    pub stream_path: Option<Vec<String>>,
    #[serde(default)]
    pub ephemeral_paths: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GraphQLHeuristicPattern {
    pub mutation_field_contains: Option<String>,
    pub operation_name_contains: Option<String>,
    pub likely_ai_call: Option<bool>,
    pub confidence: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GrpcServiceRegistry {
    pub version: Option<String>,
    #[serde(default)]
    pub services: Vec<GrpcServiceSpec>,
}

impl GrpcServiceRegistry {
    pub fn get(&self, service: &str, method: &str) -> Option<&GrpcServiceSpec> {
        self.services.iter().find(|spec| {
            spec.service.eq_ignore_ascii_case(service) && spec.method.eq_ignore_ascii_case(method)
        })
    }

    pub fn with_default_services() -> Self {
        let mut field_map = HashMap::new();
        field_map.insert(
            "model".to_string(),
            GrpcFieldSpec {
                field_number: 1,
                r#type: "string".to_string(),
            },
        );
        field_map.insert(
            "content".to_string(),
            GrpcFieldSpec {
                field_number: 2,
                r#type: "string".to_string(),
            },
        );

        Self {
            version: Some("1.0".to_string()),
            services: vec![GrpcServiceSpec {
                service: "google.cloud.aiplatform.v1.PredictionService".to_string(),
                method: "Predict".to_string(),
                provider_hint: Some("google_vertex".to_string()),
                is_ai_call: true,
                proto_package: Some("google.cloud.aiplatform.v1".to_string()),
                field_map,
            }],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GrpcServiceSpec {
    pub service: String,
    pub method: String,
    pub provider_hint: Option<String>,
    pub is_ai_call: bool,
    pub proto_package: Option<String>,
    #[serde(default)]
    pub field_map: HashMap<String, GrpcFieldSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GrpcFieldSpec {
    pub field_number: u32,
    pub r#type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaptureRules {
    pub default_mode: CaptureMode,
    #[serde(default)]
    pub full_capture_providers: Vec<String>,
    #[serde(default)]
    pub org_overrides: CaptureOverrides,
}

impl Default for CaptureRules {
    fn default() -> Self {
        Self {
            default_mode: CaptureMode::MetadataOnly,
            full_capture_providers: Vec::new(),
            org_overrides: CaptureOverrides::default(),
        }
    }
}

impl CaptureRules {
    pub fn mode_for(&self, provider: &Provider) -> CaptureMode {
        self.mode_for_with_entry(provider, None)
    }

    pub fn mode_for_with_entry(
        &self,
        provider: &Provider,
        provider_entry: Option<&ProviderEntry>,
    ) -> CaptureMode {
        if let Some(mode) = provider_entry.and_then(provider_capture_mode) {
            return mode;
        }

        let name = provider.canonical_name();

        if self
            .org_overrides
            .metadata_only_providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(name))
        {
            return CaptureMode::MetadataOnly;
        }

        if self
            .org_overrides
            .full_capture_providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(name))
            || self
                .full_capture_providers
                .iter()
                .any(|p| p.eq_ignore_ascii_case(name))
        {
            return CaptureMode::Full;
        }

        self.default_mode.clone()
    }
}

fn provider_capture_mode(entry: &ProviderEntry) -> Option<CaptureMode> {
    entry
        .capture
        .as_ref()
        .and_then(parse_capture_mode_from_value)
}

fn parse_capture_mode_from_value(value: &JsonValue) -> Option<CaptureMode> {
    if let Some(raw) = value.as_str() {
        return parse_capture_mode(raw);
    }

    value
        .get("mode")
        .and_then(JsonValue::as_str)
        .and_then(parse_capture_mode)
}

fn parse_capture_mode(raw: &str) -> Option<CaptureMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "full" => Some(CaptureMode::Full),
        "sensitive_artifacts" => Some(CaptureMode::SensitiveArtifacts),
        "full_content" => Some(CaptureMode::FullContent),
        "metadata_only" => Some(CaptureMode::MetadataOnly),
        _ => None,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct CaptureOverrides {
    #[serde(default)]
    pub full_capture_providers: Vec<String>,
    #[serde(default)]
    pub metadata_only_providers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ProviderEntry {
    pub provider_id: Option<String>,
    pub name: Option<String>,
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<JsonValue>,
    /// Signal-based matching rules from NativeBundle v3.
    /// Backward-compatible: absent/empty in v2 bundles.
    #[serde(default)]
    pub matching_rules: Vec<soth_core::MatchingRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ApplicationEntry {
    pub app_id: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    /// Signal-based matching rules from NativeBundle v3.
    /// Backward-compatible: absent/empty in v2 bundles.
    #[serde(default)]
    pub matching_rules: Vec<soth_core::MatchingRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Filters {
    #[serde(default)]
    pub path_keywords: Vec<String>,
    #[serde(default)]
    pub header_keywords: Vec<String>,
    #[serde(default)]
    pub domain_patterns: Vec<String>,
    #[serde(default)]
    pub path_patterns: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

impl Filters {
    pub fn matches(&self, path: &str, headers: &HeaderMap) -> bool {
        let path_lc = path.to_ascii_lowercase();
        if self
            .path_keywords
            .iter()
            .any(|k| !k.is_empty() && path_lc.contains(&k.to_ascii_lowercase()))
        {
            return true;
        }

        if self
            .keywords
            .iter()
            .any(|k| !k.is_empty() && path_lc.contains(&k.to_ascii_lowercase()))
        {
            return true;
        }

        if self.path_patterns.iter().any(|pattern| {
            !pattern.is_empty() && glob_match(&pattern.to_ascii_lowercase(), &path_lc)
        }) {
            return true;
        }

        if let Some(host) = host_header(headers) {
            let host_lc = host_without_port(host)
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if self.domain_patterns.iter().any(|pattern| {
                !pattern.is_empty() && glob_match(&pattern.to_ascii_lowercase(), &host_lc)
            }) {
                return true;
            }
        }

        // Only use dedicated header_keywords for header matching.
        // The shared `keywords` list is path-oriented (contains "sentry", "telemetry", etc.)
        // and would false-positive on standard request headers like `sentry-trace`.
        if self.header_keywords.is_empty() {
            return false;
        }

        headers.iter().any(|(key, value)| {
            let key_lc = key.to_ascii_lowercase();
            let val_lc = value.to_ascii_lowercase();
            self.header_keywords.iter().any(|needle| {
                let needle_lc = needle.to_ascii_lowercase();
                !needle_lc.is_empty()
                    && (key_lc.contains(&needle_lc) || val_lc.contains(&needle_lc))
            })
        })
    }
}

fn host_header<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case(":authority"))
        .map(|(_, value)| value.as_str())
}

fn host_without_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_anchored = !pattern.starts_with('*');
    let ends_anchored = !pattern.ends_with('*');

    let mut index = 0usize;
    let mut first_non_empty = true;
    for part in parts.iter().copied().filter(|part| !part.is_empty()) {
        if first_non_empty && starts_anchored {
            if !text[index..].starts_with(part) {
                return false;
            }
            index += part.len();
            first_non_empty = false;
            continue;
        }

        match text[index..].find(part) {
            Some(pos) => index += pos + part.len(),
            None => return false,
        }
        first_non_empty = false;
    }

    if ends_anchored {
        let last_non_empty = pattern
            .split('*')
            .filter(|part| !part.is_empty())
            .next_back()
            .unwrap_or("");
        text.ends_with(last_non_empty)
    } else {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppPolicy {
    pub app_id: String,
    pub display_name: Option<String>,
    pub app_kind: AppKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_list_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct BrowserPolicies {
    #[serde(default)]
    pub allowed_apps: Vec<String>,
    #[serde(default)]
    pub allowed_browsers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>,
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
        let provider = Provider::new("openai");
        let provider_entry = ProviderEntry {
            capture: Some(serde_json::json!({"mode":"full"})),
            ..ProviderEntry::default()
        };

        assert_eq!(rules.mode_for(&provider), CaptureMode::MetadataOnly);
        assert_eq!(
            rules.mode_for_with_entry(&provider, Some(&provider_entry)),
            CaptureMode::Full
        );
    }
}
