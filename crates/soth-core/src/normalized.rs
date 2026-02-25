use serde::{Deserialize, Serialize};

use crate::artifacts::{ParseConfidence, ParseSource, ParseWarning};
use crate::providers::DetectedProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub parse_confidence: ParseConfidence,
    pub parser_id: String,
    pub schema_version: String,
    pub parse_warnings: Vec<ParseWarning>,
    pub is_ai_call: bool,

    pub provider: DetectedProvider,
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

    pub canonical_cache_key: String,
    pub format_metadata: FormatMetadata,
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
    },
    Grpc {
        service: String,
        method: String,
    },
    JsonRpc {
        method: String,
    },
    Unknown,
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
