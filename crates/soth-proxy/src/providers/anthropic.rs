//! Anthropic provider support
//!
//! Handles parsing for Anthropic API (api.anthropic.com)
//!
//! ## Authentication
//! - `x-api-key: <api-key>`
//!
//! ## Token usage
//! - `response.usage.input_tokens`
//! - `response.usage.output_tokens`
//! - `response.usage.cache_read_input_tokens` (cached)
//!
//! ## SSE format
//! - `event: <type>\ndata: {...}`
//! - Events: `message_start`, `content_block_start`, `content_block_delta`,
//!           `content_block_stop`, `message_delta`, `message_stop`

use super::{AiProvider, HttpRequest, ProviderUsage, SseEvent};

/// Anthropic provider
pub struct AnthropicProvider {
    hosts: Vec<&'static str>,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    pub fn new() -> Self {
        Self {
            hosts: vec!["api.anthropic.com"],
        }
    }
}

impl Default for AnthropicProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AiProvider for AnthropicProvider {
    fn matches(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| *h == host)
    }

    fn extract_model(&self, request: &HttpRequest) -> Option<String> {
        // Model is in the request body
        request
            .json_body()
            .and_then(|body| body.get("model")?.as_str().map(|s| s.to_string()))
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;

        let usage = json.get("usage")?;
        let input_tokens = usage
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let output_tokens = usage
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let cache_read_tokens = usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64());
        let cache_write_tokens = usage
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64());

        let model = json
            .get("model")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());

        Some(ProviderUsage {
            input_tokens,
            output_tokens,
            cached_tokens: cache_read_tokens,
            cache_read_tokens,
            cache_write_tokens,
            reasoning_tokens: None,
            model,
        })
    }

    fn parse_sse_chunk(&self, chunk: &str) -> Option<SseEvent> {
        // Anthropic SSE format: "event: <type>\ndata: {...}"
        let chunk = chunk.trim();

        // Parse event type and data
        let mut event_type = None;
        let mut data = None;

        for line in chunk.lines() {
            let line = line.trim();
            if let Some(evt) = line.strip_prefix("event: ") {
                event_type = Some(evt.to_string());
            } else if let Some(d) = line.strip_prefix("data: ") {
                data = Some(d.to_string());
            }
        }

        let event_type = event_type?;
        let data = data?;

        // Handle different event types
        match event_type.as_str() {
            "message_start" => {
                // Contains model and initial usage
                let json: serde_json::Value = serde_json::from_str(&data).ok()?;
                if let Some(message) = json.get("message") {
                    if let Some(usage) = message.get("usage") {
                        let input = usage
                            .get("input_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let cache_read_tokens = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64());
                        let cache_write_tokens = usage
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64());
                        let model = message
                            .get("model")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string());
                        return Some(SseEvent::Usage(ProviderUsage {
                            input_tokens: input,
                            output_tokens: 0,
                            cached_tokens: cache_read_tokens,
                            cache_read_tokens,
                            cache_write_tokens,
                            reasoning_tokens: None,
                            model,
                        }));
                    }
                }
                Some(SseEvent::Other(data))
            }
            "content_block_delta" => {
                // Contains text content
                let json: serde_json::Value = serde_json::from_str(&data).ok()?;
                if let Some(delta) = json.get("delta") {
                    if delta.get("type").and_then(|t| t.as_str()) == Some("text_delta") {
                        if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                            return Some(SseEvent::Content(text.to_string()));
                        }
                    }
                }
                Some(SseEvent::Other(data))
            }
            "message_delta" => {
                // Contains output usage
                let json: serde_json::Value = serde_json::from_str(&data).ok()?;
                if let Some(usage) = json.get("usage") {
                    let output = usage
                        .get("output_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    return Some(SseEvent::Usage(ProviderUsage {
                        input_tokens: 0, // Input was in message_start
                        output_tokens: output,
                        cached_tokens: None,
                        cache_read_tokens: None,
                        cache_write_tokens: None,
                        reasoning_tokens: None,
                        model: None,
                    }));
                }
                Some(SseEvent::Other(data))
            }
            "message_stop" => Some(SseEvent::Done),
            _ => Some(SseEvent::Other(data)),
        }
    }

    fn extract_api_key(&self, request: &HttpRequest) -> Option<String> {
        // x-api-key header
        request.header("x-api-key").map(|s| {
            // Mask the key for logging
            if s.len() > 8 {
                format!("{}...{}", &s[..4], &s[s.len() - 4..])
            } else {
                "***".to_string()
            }
        })
    }

    fn name(&self) -> &'static str {
        "anthropic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches() {
        let provider = AnthropicProvider::new();
        assert!(provider.matches("api.anthropic.com"));
        assert!(!provider.matches("api.openai.com"));
    }

    #[test]
    fn test_extract_model() {
        let provider = AnthropicProvider::new();
        let body = r#"{"model": "claude-3-5-sonnet-20241022", "messages": []}"#;
        let request = HttpRequest::new("POST", "/v1/messages").with_body(body.as_bytes().to_vec());

        assert_eq!(
            provider.extract_model(&request),
            Some("claude-3-5-sonnet-20241022".to_string())
        );
    }

    #[test]
    fn test_extract_usage() {
        let provider = AnthropicProvider::new();
        let body = r#"{
            "id": "msg_xxx",
            "model": "claude-3-5-sonnet-20241022",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 25,
                "cache_creation_input_tokens": 10
            }
        }"#;

        let usage = provider.extract_usage(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.cached_tokens, Some(25));
        assert_eq!(usage.cache_read_tokens, Some(25));
        assert_eq!(usage.cache_write_tokens, Some(10));
        assert_eq!(usage.model, Some("claude-3-5-sonnet-20241022".to_string()));
    }

    #[test]
    fn test_parse_sse_message_start() {
        let provider = AnthropicProvider::new();
        let chunk = r#"event: message_start
data: {"type":"message_start","message":{"model":"claude-3-5-sonnet","usage":{"input_tokens":100}}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.input_tokens, 100);
                assert!(usage.model.unwrap().contains("claude"));
            }
            _ => panic!("Expected Usage event"),
        }
    }

    #[test]
    fn test_parse_sse_content_block_delta() {
        let provider = AnthropicProvider::new();
        let chunk = r#"event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello!"}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Content(text)) => assert_eq!(text, "Hello!"),
            _ => panic!("Expected Content event"),
        }
    }

    #[test]
    fn test_parse_sse_message_delta() {
        let provider = AnthropicProvider::new();
        let chunk = r#"event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":50}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.output_tokens, 50);
            }
            _ => panic!("Expected Usage event"),
        }
    }

    #[test]
    fn test_parse_sse_message_stop() {
        let provider = AnthropicProvider::new();
        let chunk = r#"event: message_stop
data: {"type":"message_stop"}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Done) => {}
            _ => panic!("Expected Done event"),
        }
    }

    #[test]
    fn test_extract_api_key() {
        let provider = AnthropicProvider::new();
        let request = HttpRequest::new("POST", "/v1/messages")
            .with_header("x-api-key", "sk-ant-1234567890abcdef");

        let key = provider.extract_api_key(&request).unwrap();
        assert!(key.contains("..."));
    }
}
