use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{AppKind, BundleEnvironment, CaptureMode, MatchingRule, RequestHeaders};

// ── Utility functions ────────────────────────────────────────────────

pub fn glob_match(pattern: &str, text: &str) -> bool {
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

pub fn host_without_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

/// Canonical specificity score for a glob pattern.
/// Returns the count of non-wildcard characters (higher = more specific).
pub fn pattern_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

// ── OwnedDetectBundle ────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct OwnedDetectBundle {
    pub rest_formats: HashMap<String, RestFormatDescriptor>,
    pub graphql_operations: GraphQLOperationRegistry,
    pub grpc_services: GrpcServiceRegistry,
    pub capture_rules: CaptureRules,
    pub domain_index: HashMap<String, String>,
    pub llm_providers: HashMap<String, ProviderEntry>,
    #[serde(alias = "applications")]
    pub products: HashMap<String, ProductEntry>,
    pub filters: Filters,
    #[serde(default)]
    pub passthrough_domains: Vec<String>,
    #[serde(default)]
    pub org_patterns: Vec<String>,
    /// Known environments (IDEs, terminals, browsers) used to classify the
    /// parent process of an AI tool. Drives `EnvIndex` at bundle load time.
    #[serde(default)]
    pub environments: Vec<BundleEnvironment>,
}

impl OwnedDetectBundle {
    pub fn as_slice(&self) -> DetectBundleSlice<'_> {
        DetectBundleSlice {
            rest_formats: &self.rest_formats,
            graphql_operations: &self.graphql_operations,
            grpc_services: &self.grpc_services,
            capture_rules: &self.capture_rules,
            domain_index: &self.domain_index,
            llm_providers: &self.llm_providers,
            products: &self.products,
            filters: &self.filters,
            passthrough_domains: self.passthrough_domains.as_slice(),
            org_patterns: &self.org_patterns,
            environments: &self.environments,
        }
    }
}

// ── DetectBundleSlice ────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct DetectBundleSlice<'a> {
    pub rest_formats: &'a HashMap<String, RestFormatDescriptor>,
    pub graphql_operations: &'a GraphQLOperationRegistry,
    pub grpc_services: &'a GrpcServiceRegistry,
    pub capture_rules: &'a CaptureRules,
    pub domain_index: &'a HashMap<String, String>,
    pub llm_providers: &'a HashMap<String, ProviderEntry>,
    pub products: &'a HashMap<String, ProductEntry>,
    pub filters: &'a Filters,
    pub passthrough_domains: &'a [String],
    pub org_patterns: &'a [String],
    pub environments: &'a [BundleEnvironment],
}

// ── REST format descriptors ──────────────────────────────────────────

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
    /// WebSocket-native streaming (e.g. OpenAI Responses API, Socket.IO).
    /// Chunks arrive as WebSocketText/WebSocketBinary frames rather than
    /// HTTP streaming bytes.
    WebSocket,
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
    /// Rich feature descriptors from the parser DSL. When non-empty, the proxy
    /// uses the first matching chat feature's rules instead of the flat
    /// request/response paths above. The flat fields are kept for backward
    /// compatibility with bundles that don't carry features.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<FeatureDescriptor>,
}

// ── Parser DSL feature types ─────────────────────────────────────────

/// A parseable feature on an entity (chat, embed, translate, etc.).
///
/// Each feature describes one logical API surface: how to match requests
/// to it, how to parse the request body, and how to extract content from
/// the response (streaming or direct).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeatureDescriptor {
    /// Feature identifier (e.g. "chat", "embed", "translate").
    pub id: String,
    /// "chat" or "metadata". Proxy v1 only processes "chat".
    #[serde(default = "default_feature_type")]
    pub feature_type: String,
    /// Wire protocol: "rest", "graphql", "grpc", "websocket".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// URL glob patterns this feature matches.
    #[serde(default)]
    pub patterns: Vec<FeaturePattern>,
    /// Request body extraction spec.
    #[serde(default)]
    pub request: FeatureRequestSpec,
    /// Response extraction — streaming rules or flat field paths.
    #[serde(default)]
    pub response: FeatureResponseSpec,
}

fn default_feature_type() -> String {
    "chat".to_string()
}

fn default_protocol() -> String {
    "rest".to_string()
}

/// A URL pattern + HTTP method for matching requests to a feature.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeaturePattern {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Request-side extraction spec from the parser DSL.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FeatureRequestSpec {
    /// Semantic field name → extraction path.
    /// Paths can be JSON dot-notation, `$_query_param('name')`, or `$_url_segment(-2)`.
    #[serde(default)]
    pub fields: HashMap<String, String>,
    /// Request body encoding.
    #[serde(default)]
    pub encoding: RequestEncoding,
    /// Form field name for form-encoded requests (e.g. "f.req").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_field: Option<String>,
    /// Request body preprocessing pipeline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preprocess: Vec<PreprocessOp>,
}

/// Response extraction — either streaming with a rules engine, or direct
/// (non-streaming) with flat field-to-path mappings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FeatureResponseSpec {
    /// Streaming response with conditional rules, accumulation, and finalization.
    Stream { stream: StreamRulesSpec },
    /// Non-streaming response: field name → JSON path.
    Direct(HashMap<String, String>),
}

impl Default for FeatureResponseSpec {
    fn default() -> Self {
        Self::Direct(HashMap::new())
    }
}

/// Complete streaming rules specification from the parser DSL.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamRulesSpec {
    /// Stream wire format.
    pub format: StreamFormat,
    /// Format-specific options (prefixes, delimiters, skip values).
    #[serde(default)]
    pub format_options: StreamFormatOptions,
    /// Ordered list of conditional extraction rules.
    #[serde(default)]
    pub rules: Vec<StreamRule>,
    /// Per-field accumulation operators across chunks.
    #[serde(default)]
    pub accumulate: HashMap<String, AccumulateOp>,
    /// Final field mapping from accumulated state. Supports ternary:
    /// `"accumulated.a ? accumulated.a : accumulated.b"`.
    #[serde(default)]
    pub finalize: HashMap<String, String>,
}

/// Format-specific options for stream chunk parsing.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct StreamFormatOptions {
    /// Line prefixes to strip (e.g. `["data: ", "delta ", "message "]`).
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Values to skip entirely (e.g. `["[DONE]"]`).
    #[serde(default)]
    pub skip_values: Vec<String>,
    /// Custom chunk delimiter for NDJSON (e.g. `"}{"`). Newline if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    /// Header to strip from length-prefixed payloads (e.g. `")]}'\\n"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_strip: Option<String>,
    /// Encoding hint for length-prefixed (e.g. "protobuf").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// A single conditional extraction rule evaluated against each parsed chunk.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamRule {
    /// Condition expression. See `rules::evaluate_condition()` for syntax.
    pub when: String,
    /// Fields to extract when the condition matches: field_name → json_path.
    #[serde(default)]
    pub extract: HashMap<String, String>,
    /// Per-rule preprocessing applied before extraction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preprocess: Vec<PreprocessOp>,
}

/// Accumulation operator for merging extracted values across stream chunks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccumulateOp {
    /// Source field name to accumulate from.
    pub from: String,
    /// Accumulation strategy: "concat", "first", or "last".
    pub op: String,
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

// ── GraphQL registry ─────────────────────────────────────────────────

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

// ── gRPC registry ────────────────────────────────────────────────────

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

// ── Capture rules ────────────────────────────────────────────────────

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
    pub fn mode_for(&self, provider_name: &str) -> CaptureMode {
        self.mode_for_with_entry(provider_name, None)
    }

    pub fn mode_for_with_entry(
        &self,
        provider_name: &str,
        provider_entry: Option<&ProviderEntry>,
    ) -> CaptureMode {
        if let Some(mode) = provider_entry.and_then(provider_capture_mode) {
            return mode;
        }

        if self
            .org_overrides
            .metadata_only_providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(provider_name))
        {
            return CaptureMode::MetadataOnly;
        }

        if self
            .org_overrides
            .full_capture_providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(provider_name))
            || self
                .full_capture_providers
                .iter()
                .any(|p| p.eq_ignore_ascii_case(provider_name))
        {
            return CaptureMode::Full;
        }

        self.default_mode
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

// ── Provider / Application entries ───────────────────────────────────

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
    /// Deprecated: legacy detection hints (path_patterns, header_hints, hosts).
    /// Superseded by `matching_rules` (signal-based). Kept for cache/serde compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<JsonValue>,
    /// Signal-based matching rules from NativeBundle v3.
    /// Backward-compatible: absent/empty in v2 bundles.
    #[serde(default)]
    pub matching_rules: Vec<MatchingRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ProductEntry {
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
    /// Deprecated: legacy detection hints. Superseded by `matching_rules`.
    /// Kept for cache/serde compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    /// Signal-based matching rules from NativeBundle v3.
    /// Backward-compatible: absent/empty in v2 bundles.
    #[serde(default)]
    pub matching_rules: Vec<MatchingRule>,
}

/// Deprecated alias — use [`ProductEntry`] instead.
pub type ApplicationEntry = ProductEntry;

// ── Filters ──────────────────────────────────────────────────────────

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
    pub fn matches(&self, path: &str, headers: &RequestHeaders) -> bool {
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

fn host_header(headers: &RequestHeaders) -> Option<&str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case(":authority"))
        .map(|(_, value)| value.as_str())
}

// ── App policies ─────────────────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(!glob_match("*.example.com", "example.org"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

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
