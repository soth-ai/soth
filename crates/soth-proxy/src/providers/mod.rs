//! AI Provider support for parsing API requests and responses
//!
//! This module provides parsers for extracting model, token usage, and other
//! metadata from AI provider APIs (OpenAI, Anthropic, Google).

pub mod openai;
pub mod anthropic;
pub mod google;
pub mod sse;

use std::sync::Arc;

/// Token usage information extracted from API responses
#[derive(Debug, Clone, Default)]
pub struct ProviderUsage {
    /// Input/prompt tokens
    pub input_tokens: u64,
    /// Output/completion tokens
    pub output_tokens: u64,
    /// Cached tokens (Anthropic)
    pub cached_tokens: Option<u64>,
    /// Model used
    pub model: Option<String>,
}

impl ProviderUsage {
    /// Create new usage with just tokens
    pub fn new(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cached_tokens: None,
            model: None,
        }
    }

    /// Add cached tokens
    pub fn with_cached(mut self, cached: u64) -> Self {
        self.cached_tokens = Some(cached);
        self
    }

    /// Add model info
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Get total tokens
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// SSE event types
#[derive(Debug, Clone)]
pub enum SseEvent {
    /// Content chunk (streaming text)
    Content(String),
    /// Usage information (usually at end of stream)
    Usage(ProviderUsage),
    /// Stream is done
    Done,
    /// Other event (not content or usage)
    Other(String),
}

/// HTTP request information for provider parsing
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers (lowercase keys)
    pub headers: std::collections::HashMap<String, String>,
    /// Request body (if available)
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Create from parts
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: std::collections::HashMap::new(),
            body: None,
        }
    }

    /// Add header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into().to_lowercase(), value.into());
        self
    }

    /// Add body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get header value
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(&key.to_lowercase()).map(|s| s.as_str())
    }

    /// Parse JSON body
    pub fn json_body(&self) -> Option<serde_json::Value> {
        self.body
            .as_ref()
            .and_then(|b| serde_json::from_slice(b).ok())
    }
}

/// Trait for AI provider support
pub trait AiProvider: Send + Sync {
    /// Check if this provider handles the given host
    fn matches(&self, host: &str) -> bool;

    /// Extract model name from request
    fn extract_model(&self, request: &HttpRequest) -> Option<String>;

    /// Extract usage from response body
    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage>;

    /// Parse an SSE chunk (for streaming responses)
    fn parse_sse_chunk(&self, chunk: &str) -> Option<SseEvent>;

    /// Extract API key/identifier from request
    fn extract_api_key(&self, request: &HttpRequest) -> Option<String>;

    /// Provider name
    fn name(&self) -> &'static str;
}

/// Registry of AI providers
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn AiProvider>>,
}

impl ProviderRegistry {
    /// Create a new registry with default providers
    pub fn new() -> Self {
        Self {
            providers: vec![
                Arc::new(openai::OpenAiProvider::new()),
                Arc::new(anthropic::AnthropicProvider::new()),
                Arc::new(google::GoogleProvider::new()),
            ],
        }
    }

    /// Create an empty registry
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider
    pub fn add_provider(&mut self, provider: Arc<dyn AiProvider>) {
        self.providers.push(provider);
    }

    /// Find provider for a host
    pub fn find_provider(&self, host: &str) -> Option<Arc<dyn AiProvider>> {
        for provider in &self.providers {
            if provider.matches(host) {
                return Some(Arc::clone(provider));
            }
        }
        None
    }

    /// Check if a host has a matching provider
    pub fn has_provider(&self, host: &str) -> bool {
        self.providers.iter().any(|p| p.matches(host))
    }

    /// Get all provider names
    pub fn provider_names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_usage() {
        let usage = ProviderUsage::new(100, 50)
            .with_model("gpt-4o")
            .with_cached(25);

        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.total_tokens(), 150);
        assert_eq!(usage.cached_tokens, Some(25));
        assert_eq!(usage.model, Some("gpt-4o".to_string()));
    }

    #[test]
    fn test_http_request() {
        let req = HttpRequest::new("POST", "/v1/chat/completions")
            .with_header("Authorization", "Bearer sk-xxx")
            .with_header("Content-Type", "application/json");

        assert_eq!(req.header("authorization"), Some("Bearer sk-xxx"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Bearer sk-xxx"));
    }

    #[test]
    fn test_registry_find_provider() {
        let registry = ProviderRegistry::new();

        assert!(registry.find_provider("api.openai.com").is_some());
        assert!(registry.find_provider("api.anthropic.com").is_some());
        assert!(registry.find_provider("generativelanguage.googleapis.com").is_some());
        assert!(registry.find_provider("unknown.example.com").is_none());
    }

    #[test]
    fn test_registry_provider_names() {
        let registry = ProviderRegistry::new();
        let names = registry.provider_names();

        assert!(names.contains(&"openai"));
        assert!(names.contains(&"anthropic"));
        assert!(names.contains(&"google"));
    }
}
