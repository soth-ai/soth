use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EntryType {
    AiInference,
    AgentApp,
    Mcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainType {
    Api,
    App,
    Mcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderDefinition {
    pub id: String,
    pub name: String,
    pub vendor: String,
    #[serde(default)]
    pub vendor_url: Option<String>,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    #[serde(default)]
    pub api_format: Option<String>,
    #[serde(default)]
    pub domains: Vec<DomainEntry>,
    #[serde(default)]
    pub features: BTreeMap<String, Feature>,
    #[serde(default)]
    pub body_transform: Option<BodyTransform>,
    #[serde(default)]
    pub pricing: Option<PricingInfo>,
    #[serde(default)]
    pub user_agent_patterns: Vec<String>,
    #[serde(default)]
    pub inference_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainEntry {
    pub host: String,
    #[serde(rename = "type")]
    pub domain_type: DomainType,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Feature {
    #[serde(rename = "type")]
    pub feature_type: String,
    pub name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub parser: Option<ParserSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParserSpec {
    #[serde(default)]
    pub request: Option<RequestParser>,
    #[serde(default)]
    pub response: Option<ResponseParser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestParser {
    #[serde(default)]
    pub extract: BTreeMap<String, FieldPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseParser {
    #[serde(default)]
    pub non_streaming: Option<NonStreamingParser>,
    #[serde(default)]
    pub streaming: Option<StreamingParser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NonStreamingParser {
    #[serde(default)]
    pub extract: BTreeMap<String, FieldPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamingParser {
    pub format: StreamFormat,
    #[serde(default)]
    pub rules: Vec<StreamRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamFormat {
    Sse,
    Ndjson,
    LengthPrefixed,
    Websocket,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamRule {
    pub when: String,
    #[serde(default)]
    pub extract: BTreeMap<String, FieldPath>,
    #[serde(default)]
    pub extract_usage: BTreeMap<String, FieldPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FieldPath {
    Single(String),
    Fallback(Vec<String>),
    FromUrl { from: String, regex: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyTransform {
    None,
    StripXssi,
    GrpcFrames,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PricingInfo {
    #[serde(default)]
    pub models: BTreeMap<String, ModelPricing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelPricing {
    #[serde(default)]
    pub input_per_million_usd: Option<f64>,
    #[serde(default)]
    pub output_per_million_usd: Option<f64>,
    #[serde(default)]
    pub cache_read_per_million_usd: Option<f64>,
    #[serde(default)]
    pub cache_write_per_million_usd: Option<f64>,
}
