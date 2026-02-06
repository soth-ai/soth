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

        let usage = json.get("usage")?;
        let input_tokens = usage.get("prompt_tokens")?.as_u64()?;
        let output_tokens = usage.get("completion_tokens")?.as_u64()?;

        let model = json.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());

        Some(ProviderUsage {
            input_tokens,
            output_tokens,
            cached_tokens: None,
            model,
        })
    }

    fn parse_sse_chunk(&self, chunk: &str) -> Option<SseEvent> {
        // OpenAI SSE format: "data: {...}\n\n" or "data: [DONE]\n\n"
        let chunk = chunk.trim();

        if !chunk.starts_with("data: ") {
            return None;
        }

        let data = &chunk[6..]; // Skip "data: "

        if data == "[DONE]" {
            return Some(SseEvent::Done);
        }

        // Try to parse as JSON
        let json: serde_json::Value = serde_json::from_str(data).ok()?;

        // Check for usage (appears in final chunk with stream_options)
        if let Some(usage) = json.get("usage") {
            if let (Some(input), Some(output)) = (
                usage.get("prompt_tokens").and_then(|v| v.as_u64()),
                usage.get("completion_tokens").and_then(|v| v.as_u64()),
            ) {
                let model = json.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());
                return Some(SseEvent::Usage(ProviderUsage {
                    input_tokens: input,
                    output_tokens: output,
                    cached_tokens: None,
                    model,
                }));
            }
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
        let request = HttpRequest::new("POST", "/v1/chat/completions")
            .with_body(body.as_bytes().to_vec());

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
        let chunk = r#"data: {"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => panic!("Expected Usage event"),
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
