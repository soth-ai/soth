//! OpenAI provider support
//!
//! Handles parsing for OpenAI API (api.openai.com)
//!
//! ## Authentication
//! - `Authorization: Bearer <api-key>`
//!
//! ## Token usage
//! - `response.usage.prompt_tokens` (input)
//! - `response.usage.completion_tokens` (output)
//!
//! ## SSE format
//! - `data: {...}\n\ndata: [DONE]`
//! - Usage in last data chunk before `[DONE]`

use super::{AiProvider, HttpRequest, ProviderUsage, SseEvent};

/// OpenAI provider
pub struct OpenAiProvider {
    hosts: Vec<&'static str>,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider
    pub fn new() -> Self {
        Self {
            hosts: vec!["api.openai.com"],
        }
    }
}

impl Default for OpenAiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AiProvider for OpenAiProvider {
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

        // OpenAI supports multiple response schemas:
        // 1) Chat Completions: usage.prompt_tokens / usage.completion_tokens
        // 2) Responses API: usage.input_tokens / usage.output_tokens
        // 3) Nested response wrappers: response.usage / response.model
        let usage = json
            .get("usage")
            .or_else(|| json.get("response").and_then(|r| r.get("usage")))?;

        let input_tokens = usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| usage.get("input_tokens").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let output_tokens = usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| usage.get("output_tokens").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let cache_read_tokens = usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                usage
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|v| v.as_u64())
            });
        let cache_write_tokens = usage
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                usage
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cache_creation_tokens"))
                    .and_then(|v| v.as_u64())
            });
        let reasoning_tokens = usage
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|v| v.as_u64())
            .or_else(|| {
                usage
                    .get("output_tokens_details")
                    .and_then(|d| d.get("reasoning_tokens"))
                    .and_then(|v| v.as_u64())
            });

        let model = json
            .get("model")
            .or_else(|| json.get("response").and_then(|r| r.get("model")))
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());

        Some(ProviderUsage {
            input_tokens,
            output_tokens,
            cached_tokens: cache_read_tokens,
            cache_read_tokens,
            cache_write_tokens,
            reasoning_tokens,
            model,
        })
    }

    fn parse_sse_chunk(&self, chunk: &str) -> Option<SseEvent> {
        // OpenAI SSE formats:
        // - Chat Completions: data: {...} / data: [DONE]
        // - Responses API: event: response.* + data: {...}
        let chunk = chunk.trim();
        let mut event_type: Option<&str> = None;
        let mut data_line: Option<&str> = None;
        for line in chunk.lines() {
            let line = line.trim();
            if let Some(evt) = line.strip_prefix("event: ") {
                event_type = Some(evt.trim());
            } else if let Some(data) = line.strip_prefix("data: ") {
                data_line = Some(data.trim());
            }
        }
        let data = data_line?;

        if data == "[DONE]" || event_type == Some("done") {
            return Some(SseEvent::Done);
        }

        // Try to parse as JSON
        let json: serde_json::Value = serde_json::from_str(data).ok()?;

        // Usage chunks appear in final chunk with stream_options/include_usage
        if let Some(usage) = self.extract_usage(data.as_bytes()) {
            if usage.input_tokens > 0 || usage.output_tokens > 0 {
                return Some(SseEvent::Usage(usage));
            }
        }

        if event_type == Some("response.completed") {
            return Some(SseEvent::Done);
        }

        // Check for content in choices
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            if let Some(choice) = choices.first() {
                if let Some(delta) = choice.get("delta") {
                    if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                        if !content.is_empty() {
                            return Some(SseEvent::Content(content.to_string()));
                        }
                    }
                }
            }
        }

        // OpenAI Responses API content delta
        if let Some(delta) = json.get("delta").and_then(|d| d.as_str()) {
            if !delta.is_empty() {
                return Some(SseEvent::Content(delta.to_string()));
            }
        }
        if let Some(text) = json
            .get("output_text")
            .and_then(|d| d.as_str())
            .or_else(|| {
                json.get("response")
                    .and_then(|r| r.get("output_text"))
                    .and_then(|d| d.as_str())
            })
        {
            if !text.is_empty() {
                return Some(SseEvent::Content(text.to_string()));
            }
        }

        Some(SseEvent::Other(data.to_string()))
    }

    fn extract_api_key(&self, request: &HttpRequest) -> Option<String> {
        // Authorization: Bearer <key>
        request
            .header("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|s| {
                // Mask the key for logging (keep first and last 4 chars)
                if s.len() > 8 {
                    format!("{}...{}", &s[..4], &s[s.len() - 4..])
                } else {
                    "***".to_string()
                }
            })
    }

    fn name(&self) -> &'static str {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches() {
        let provider = OpenAiProvider::new();
        assert!(provider.matches("api.openai.com"));
        assert!(!provider.matches("api.anthropic.com"));
    }

    #[test]
    fn test_extract_model() {
        let provider = OpenAiProvider::new();
        let body = r#"{"model": "gpt-4o", "messages": []}"#;
        let request =
            HttpRequest::new("POST", "/v1/chat/completions").with_body(body.as_bytes().to_vec());

        assert_eq!(provider.extract_model(&request), Some("gpt-4o".to_string()));
    }

    #[test]
    fn test_extract_usage() {
        let provider = OpenAiProvider::new();
        let body = r#"{
            "id": "chatcmpl-xxx",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }"#;

        let usage = provider.extract_usage(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.model, Some("gpt-4o".to_string()));
    }

    #[test]
    fn test_extract_usage_responses_api() {
        let provider = OpenAiProvider::new();
        let body = r#"{
            "id": "resp_123",
            "model": "gpt-5",
            "usage": {
                "input_tokens": 120,
                "output_tokens": 45,
                "prompt_tokens_details": {
                    "cached_tokens": 30
                },
                "output_tokens_details": {
                    "reasoning_tokens": 12
                }
            }
        }"#;

        let usage = provider.extract_usage(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 120);
        assert_eq!(usage.output_tokens, 45);
        assert_eq!(usage.cache_read_tokens, Some(30));
        assert_eq!(usage.reasoning_tokens, Some(12));
        assert_eq!(usage.model, Some("gpt-5".to_string()));
    }

    #[test]
    fn test_parse_sse_content() {
        let provider = OpenAiProvider::new();
        let chunk = r#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Content(text)) => assert_eq!(text, "Hello"),
            _ => panic!("Expected Content event"),
        }
    }

    #[test]
    fn test_parse_sse_done() {
        let provider = OpenAiProvider::new();
        let chunk = "data: [DONE]";

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Done) => {}
            _ => panic!("Expected Done event"),
        }
    }

    #[test]
    fn test_parse_sse_usage() {
        let provider = OpenAiProvider::new();
        let chunk =
            r#"data: {"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => panic!("Expected Usage event"),
        }
    }

    #[test]
    fn test_parse_sse_usage_responses_event() {
        let provider = OpenAiProvider::new();
        let chunk = r#"event: response.completed
data: {"response":{"model":"gpt-5","usage":{"input_tokens":11,"output_tokens":7}}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.input_tokens, 11);
                assert_eq!(usage.output_tokens, 7);
            }
            _ => panic!("Expected Usage event"),
        }
    }

    #[test]
    fn test_parse_sse_responses_delta() {
        let provider = OpenAiProvider::new();
        let chunk = r#"event: response.output_text.delta
data: {"delta":"Hello"}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Content(text)) => assert_eq!(text, "Hello"),
            _ => panic!("Expected Content event"),
        }
    }

    #[test]
    fn test_extract_api_key() {
        let provider = OpenAiProvider::new();
        let request = HttpRequest::new("POST", "/v1/chat/completions")
            .with_header("Authorization", "Bearer sk-1234567890abcdef");

        let key = provider.extract_api_key(&request).unwrap();
        assert!(key.contains("..."));
    }
}
