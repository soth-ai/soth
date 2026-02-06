//! Google Gemini provider support
//!
//! Handles parsing for Google Generative AI API (generativelanguage.googleapis.com)
//!
//! ## Authentication
//! - URL parameter: `?key=<api-key>`
//! - Or header: `Authorization: Bearer <token>` (OAuth)
//!
//! ## Token usage
//! - `response.usageMetadata.promptTokenCount`
//! - `response.usageMetadata.candidatesTokenCount`
//! - `response.usageMetadata.cachedContentTokenCount` (optional)
//!
//! ## Model extraction
//! - From URL path: `/models/{model}:generateContent`

use super::{AiProvider, HttpRequest, ProviderUsage, SseEvent};

/// Google Gemini provider
pub struct GoogleProvider {
    hosts: Vec<&'static str>,
}

impl GoogleProvider {
    /// Create a new Google provider
    pub fn new() -> Self {
        Self {
            hosts: vec!["generativelanguage.googleapis.com"],
        }
    }
}

impl Default for GoogleProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AiProvider for GoogleProvider {
    fn matches(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| *h == host)
    }

    fn extract_model(&self, request: &HttpRequest) -> Option<String> {
        // Model is in the URL path: /v1beta/models/gemini-pro:generateContent
        // or /v1/models/gemini-1.5-flash:streamGenerateContent
        let path = &request.path;

        // Find the model name between "/models/" and ":"
        if let Some(start) = path.find("/models/") {
            let start = start + 8; // Skip "/models/"
            if let Some(end) = path[start..].find(':') {
                return Some(path[start..start + end].to_string());
            }
        }

        None
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;

        let usage = json.get("usageMetadata")?;
        let input_tokens = usage.get("promptTokenCount")?.as_u64()?;
        let output_tokens = usage.get("candidatesTokenCount")?.as_u64()?;
        let cached_tokens = usage
            .get("cachedContentTokenCount")
            .and_then(|v| v.as_u64());

        Some(ProviderUsage {
            input_tokens,
            output_tokens,
            cached_tokens,
            model: None, // Model not usually in response
        })
    }

    fn parse_sse_chunk(&self, chunk: &str) -> Option<SseEvent> {
        // Google SSE format: "data: {...}"
        let chunk = chunk.trim();

        if !chunk.starts_with("data: ") {
            return None;
        }

        let data = &chunk[6..]; // Skip "data: "

        // Try to parse as JSON
        let json: serde_json::Value = serde_json::from_str(data).ok()?;

        // Check for usage metadata (usually in last chunk)
        if let Some(usage) = json.get("usageMetadata") {
            if let (Some(input), Some(output)) = (
                usage.get("promptTokenCount").and_then(|v| v.as_u64()),
                usage.get("candidatesTokenCount").and_then(|v| v.as_u64()),
            ) {
                let cached = usage
                    .get("cachedContentTokenCount")
                    .and_then(|v| v.as_u64());
                return Some(SseEvent::Usage(ProviderUsage {
                    input_tokens: input,
                    output_tokens: output,
                    cached_tokens: cached,
                    model: None,
                }));
            }
        }

        // Check for content in candidates
        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            if let Some(candidate) = candidates.first() {
                if let Some(content) = candidate.get("content") {
                    if let Some(parts) = content.get("parts").and_then(|p| p.as_array()) {
                        if let Some(part) = parts.first() {
                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                if !text.is_empty() {
                                    return Some(SseEvent::Content(text.to_string()));
                                }
                            }
                        }
                    }
                }

                // Check for finish reason indicating done
                if candidate.get("finishReason").is_some() {
                    return Some(SseEvent::Done);
                }
            }
        }

        Some(SseEvent::Other(data.to_string()))
    }

    fn extract_api_key(&self, request: &HttpRequest) -> Option<String> {
        // Try URL parameter first
        if let Some(pos) = request.path.find("key=") {
            let start = pos + 4;
            let end = request.path[start..]
                .find('&')
                .map(|p| start + p)
                .unwrap_or(request.path.len());
            let key = &request.path[start..end];
            if key.len() > 8 {
                return Some(format!("{}...{}", &key[..4], &key[key.len() - 4..]));
            }
            return Some("***".to_string());
        }

        // Try Authorization header (OAuth)
        request
            .header("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|s| {
                if s.len() > 8 {
                    format!("{}...{}", &s[..4], &s[s.len() - 4..])
                } else {
                    "***".to_string()
                }
            })
    }

    fn name(&self) -> &'static str {
        "google"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches() {
        let provider = GoogleProvider::new();
        assert!(provider.matches("generativelanguage.googleapis.com"));
        assert!(!provider.matches("api.openai.com"));
    }

    #[test]
    fn test_extract_model_from_path() {
        let provider = GoogleProvider::new();

        let request = HttpRequest::new(
            "POST",
            "/v1beta/models/gemini-1.5-flash:generateContent?key=xxx",
        );
        assert_eq!(
            provider.extract_model(&request),
            Some("gemini-1.5-flash".to_string())
        );

        let request = HttpRequest::new("POST", "/v1/models/gemini-pro:streamGenerateContent");
        assert_eq!(
            provider.extract_model(&request),
            Some("gemini-pro".to_string())
        );
    }

    #[test]
    fn test_extract_usage() {
        let provider = GoogleProvider::new();
        let body = r#"{
            "candidates": [{"content": {"parts": [{"text": "Hello"}]}}],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 50,
                "totalTokenCount": 150
            }
        }"#;

        let usage = provider.extract_usage(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn test_parse_sse_content() {
        let provider = GoogleProvider::new();
        let chunk = r#"data: {"candidates":[{"content":{"parts":[{"text":"Hello!"}]}}]}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Content(text)) => assert_eq!(text, "Hello!"),
            _ => panic!("Expected Content event"),
        }
    }

    #[test]
    fn test_parse_sse_usage() {
        let provider = GoogleProvider::new();
        let chunk = r#"data: {"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Usage(usage)) => {
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => panic!("Expected Usage event"),
        }
    }

    #[test]
    fn test_parse_sse_done() {
        let provider = GoogleProvider::new();
        let chunk = r#"data: {"candidates":[{"finishReason":"STOP"}]}"#;

        match provider.parse_sse_chunk(chunk) {
            Some(SseEvent::Done) => {}
            _ => panic!("Expected Done event"),
        }
    }

    #[test]
    fn test_extract_api_key_from_url() {
        let provider = GoogleProvider::new();
        let request = HttpRequest::new(
            "POST",
            "/v1beta/models/gemini-pro:generateContent?key=AIzaSyABC123456789",
        );

        let key = provider.extract_api_key(&request).unwrap();
        assert!(key.contains("..."));
    }

    #[test]
    fn test_extract_api_key_from_header() {
        let provider = GoogleProvider::new();
        let request = HttpRequest::new("POST", "/v1beta/models/gemini-pro:generateContent")
            .with_header("Authorization", "Bearer ya29.c.ElpSB3nzX123456789");

        let key = provider.extract_api_key(&request).unwrap();
        assert!(key.contains("..."));
    }
}
