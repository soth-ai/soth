use serde_json::Value;
use std::sync::{Arc, Mutex};

mod cache;
mod detection;
mod engine;
mod engine_detection;
mod matchers;
mod parse_helpers;
mod pricing;
mod registry_cache;
#[cfg(test)]
mod tests;
pub mod types;

use cache::BoundedCache;
#[cfg(test)]
use matchers::{contains_noise_keyword_for_host, host_matches_pattern, select_best_domain_match};
use types::bundle::CompiledBundle;
#[cfg(test)]
use types::bundle::{parse_compiled_bundle, DomainIndexEntry};
use types::provider::{EntryType, StreamFormat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub provider_id: String,
    pub entry_type: EntryType,
    pub api_format: Option<String>,
}

impl Classification {
    pub fn entry_type_label(&self) -> &'static str {
        match self.entry_type {
            EntryType::AiInference => "ai_inference",
            EntryType::AgentApp => "agent_app",
            EntryType::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptDecision {
    Intercept {
        provider_id: String,
        entry_type: EntryType,
    },
    Passthrough,
    Noise,
    Tunnel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectDecisionAction {
    Intercept,
    Passthrough,
    Tunnel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectDecision {
    pub action: ConnectDecisionAction,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestDecisionOutcome {
    Full,
    MetadataOnly,
    Passthrough,
    Noise,
    Tunnel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDecision {
    pub outcome: RequestDecisionOutcome,
    pub provider_id: Option<String>,
    pub entry_type: Option<EntryType>,
    pub detection_id: Option<String>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub model: Option<String>,
}

impl ProviderUsage {
    pub fn has_signal(&self) -> bool {
        self.input_tokens > 0
            || self.output_tokens > 0
            || self.cache_read_tokens.unwrap_or(0) > 0
            || self.cache_write_tokens.unwrap_or(0) > 0
            || self.reasoning_tokens.unwrap_or(0) > 0
            || self
                .model
                .as_deref()
                .map(str::trim)
                .map(|s| !s.is_empty())
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionContext {
    pub host: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub model: Option<String>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetectionOutcome {
    pub agent: Option<String>,
    pub detection_reason: String,
    pub parse_confidence: f64,
    pub detection_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopedDetectionOutcome {
    pub provider_id: String,
    pub entry_type: EntryType,
    pub outcome: DetectionOutcome,
}

#[derive(Debug, Clone)]
struct StreamRuleConfig {
    when: Option<String>,
    extract: Vec<(String, Value)>,
    extract_usage: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
struct StreamParserConfig {
    format: StreamFormat,
    prefixes: Vec<String>,
    skip_values: Vec<String>,
    header_strip: Option<String>,
    rules: Vec<StreamRuleConfig>,
}

#[derive(Debug, Clone)]
pub struct OispStreamParser {
    config: StreamParserConfig,
    buffer: Vec<u8>,
}

#[derive(Clone)]
pub struct OispEngine {
    bundle: Arc<CompiledBundle>,
    classification_cache: Arc<Mutex<BoundedCache<String, Option<Classification>>>>,
    detection_cache: Arc<Mutex<BoundedCache<u64, Option<DetectionOutcome>>>>,
}
