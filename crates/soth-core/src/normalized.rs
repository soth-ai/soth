use serde::{Deserialize, Serialize};

use crate::artifacts::{ParseConfidence, ParseSource, ParseWarning};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub parse_confidence: ParseConfidence,
    pub parser_id: String,
    pub schema_version: String,
    pub parse_warnings: Vec<ParseWarning>,
    pub is_ai_call: bool,

    pub provider: String,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,
    pub api_version: Option<String>,

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
    pub estimated_cost_usd: f64,
    pub parse_source: ParseSource,

    #[serde(default)]
    pub has_structured_output: bool,
    #[serde(default)]
    pub has_tool_results: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_output_tokens: Option<u32>,

    pub canonical_cache_key: String,
    pub format_metadata: FormatMetadata,

    /// Extracted user content for embedding/classify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_prompt: Option<String>,
}

impl Default for NormalizedRequest {
    fn default() -> Self {
        Self {
            parse_confidence: ParseConfidence::Heuristic,
            parser_id: String::new(),
            schema_version: String::new(),
            parse_warnings: Vec::new(),
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
            parse_source: ParseSource::Heuristic,
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            canonical_cache_key: String::new(),
            format_metadata: FormatMetadata::Unknown {
                method: String::new(),
                path: String::new(),
            },
            user_prompt: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormatMetadata {
    Rest {
        content_type: String,
    },
    GraphQl {
        operation_name: Option<String>,
        operation_type: GraphQlOperationType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mutation_field: Option<String>,
    },
    Grpc {
        service: String,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proto_package: Option<String>,
    },
    JsonRpc {
        method: String,
        #[serde(default)]
        is_batch: bool,
    },
    WebSocket {
        #[serde(default)]
        frame_kind_hint: String,
    },
    Unknown {
        #[serde(default)]
        method: String,
        #[serde(default)]
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointType {
    ChatCompletion,
    TextCompletion,
    Embedding,
    ImageGeneration,
    AudioTranscription,
    FunctionCall,
    Streaming,
    Unknown,
}

impl Default for EndpointType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphQlOperationType {
    Query,
    Mutation,
    Subscription,
    Unknown,
}

impl Default for GraphQlOperationType {
    fn default() -> Self {
        Self::Unknown
    }
}
