use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

pub type HeaderMap = BTreeMap<String, String>;

#[derive(Clone, Debug)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub connection_meta: ConnectionMeta,
}

#[derive(Clone, Debug)]
pub struct ConnectionMeta {
    pub connection_id: Uuid,
    pub socket_family: SocketFamily,
    pub process_info: Option<ProcessInfo>,
    pub tls_info: Option<TlsInfo>,
    pub app_identity: Option<AppIdentity>,
}

#[derive(Clone, Debug)]
pub enum SocketFamily {
    TcpV4 {
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
    TcpV6 {
        local: SocketAddrV6,
        remote: SocketAddrV6,
    },
    UnixDomain {
        path: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_process_name: Option<String>,
    pub parent_bundle_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StreamChunk {
    pub connection_id: Uuid,
    pub sequence: u64,
    pub payload: Bytes,
    pub frame_kind: FrameKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameKind {
    SseData,
    NdjsonLine,
    GrpcMessage,
    WebSocketText,
    WebSocketBinary,
    WebSocketClose,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ParseConfidence {
    Full,
    Partial,
    #[default]
    Heuristic,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum CaptureMode {
    MetadataOnly,
    Full,
}

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
    pub parser_id: &'static str,
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

    // Internal helper field for optional post-parse scans without raw content retention.
    pub content_sample: Option<String>,
}

impl NormalizedRequest {
    pub fn empty_heuristic(method: &str, path: &str) -> Self {
        Self {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: "heuristic-v1",
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
}

impl DetectResult {
    pub fn filtered() -> Self {
        let normalized = NormalizedRequest {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: "filtered-v1",
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
        }
    }

    pub fn accumulate(&mut self, value: impl Into<String>) {
        self.delta_buffer.push(value.into());
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum AppKind {
    Browser,
    AgentApp,
    Ide,
    Cli,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct AppIdentity {
    pub app_id: String,
    pub display_name: String,
    pub app_kind: AppKind,
    pub is_known: bool,
    pub confidence: f32,
}

impl Default for AppIdentity {
    fn default() -> Self {
        Self {
            app_id: "unknown".to_string(),
            display_name: "unknown".to_string(),
            app_kind: AppKind::Unknown,
            is_known: false,
            confidence: 0.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectedFormat {
    OpenAIRest,
    AnthropicRest,
    CohereRest,
    GeminiRest,
    BedrockRest,
    GraphQL,
    GrpcProtobuf,
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

#[derive(Clone, Debug, Default)]
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
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ApplicationEntry {
    pub app_id: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Filters {
    #[serde(default)]
    pub path_keywords: Vec<String>,
    #[serde(default)]
    pub header_keywords: Vec<String>,
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

        if self.header_keywords.is_empty() {
            return false;
        }

        headers.iter().any(|(key, value)| {
            let key_lc = key.to_ascii_lowercase();
            let val_lc = value.to_ascii_lowercase();
            self.header_keywords.iter().any(|needle| {
                let needle_lc = needle.to_ascii_lowercase();
                key_lc.contains(&needle_lc) || val_lc.contains(&needle_lc)
            })
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppPolicy {
    pub app_id: String,
    pub display_name: Option<String>,
    pub app_kind: AppKind,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct BrowserPolicies {
    #[serde(default)]
    pub allowed_apps: Vec<String>,
}
