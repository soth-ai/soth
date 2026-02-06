//! Token counting module
//!
//! Provides token estimation based on cl100k_base tokenizer patterns.

/// Token counter for estimating LLM token usage
pub struct TokenCounter;

impl TokenCounter {
    /// Estimate token count for text
    ///
    /// Uses heuristics based on cl100k_base tokenizer:
    /// - ~4 characters per token for regular text
    /// - JSON punctuation often becomes separate tokens
    /// - Numbers are ~1 token per 3 digits
    pub fn estimate_tokens(text: &str) -> u64 {
        if text.is_empty() {
            return 0;
        }

        let mut tokens = 0u64;
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];

            if c.is_whitespace() {
                // Whitespace often merged with adjacent tokens
                i += 1;
                continue;
            }

            // JSON punctuation - often separate tokens
            if matches!(c, '"' | '{' | '}' | '[' | ']' | ':' | ',') {
                tokens += 1;
                i += 1;
                continue;
            }

            // Numbers
            if c.is_ascii_digit() || c == '-' || c == '.' {
                let mut num_len = 0;
                while i + num_len < chars.len() {
                    let nc = chars[i + num_len];
                    if nc.is_ascii_digit() || matches!(nc, '.' | '-' | 'e' | 'E') {
                        num_len += 1;
                    } else {
                        break;
                    }
                }
                if num_len > 0 {
                    tokens += (num_len as u64).div_ceil(3); // ~3 chars per token for numbers
                    i += num_len;
                    continue;
                }
            }

            // Regular text - word-like sequences
            let mut word_len = 0;
            while i + word_len < chars.len() {
                let wc = chars[i + word_len];
                if wc.is_alphanumeric() || matches!(wc, '_' | '-') {
                    word_len += 1;
                } else {
                    break;
                }
            }

            if word_len > 0 {
                // ~4 characters per token, but common short words are often 1 token
                tokens += if word_len <= 4 {
                    1
                } else {
                    (word_len as u64).div_ceil(4)
                };
                i += word_len;
            } else {
                // Single special character
                tokens += 1;
                i += 1;
            }
        }

        tokens.max(1)
    }

    /// Count tokens in a JSON value
    pub fn count_json_tokens(value: &serde_json::Value) -> u64 {
        let json_str = serde_json::to_string(value).unwrap_or_default();
        Self::estimate_tokens(&json_str)
    }

    /// Count LLM-relevant tokens from an MCP message
    ///
    /// Extracts only payload content that goes to LLM context,
    /// not the JSON-RPC protocol overhead.
    pub fn count_mcp_context_tokens(content: &serde_json::Value) -> u64 {
        let method = content.get("method").and_then(|m| m.as_str());
        let is_response = content.get("result").is_some() || content.get("error").is_some();

        if let Some(method) = method {
            return Self::count_request_tokens(method, content);
        }

        if is_response {
            return Self::count_response_tokens(content);
        }

        Self::count_json_tokens(content)
    }

    fn count_request_tokens(method: &str, content: &serde_json::Value) -> u64 {
        match method {
            // sampling/createMessage - messages and system prompt go to LLM
            "sampling/createMessage" => {
                let mut tokens = 0u64;
                if let Some(params) = content.get("params") {
                    if let Some(system) = params.get("systemPrompt").and_then(|s| s.as_str()) {
                        tokens += Self::estimate_tokens(system);
                    }
                    if let Some(messages) = params.get("messages").and_then(|m| m.as_array()) {
                        for msg in messages {
                            tokens += Self::count_message_content(msg);
                        }
                    }
                }
                tokens.max(1)
            }

            // tools/call - arguments shown in tool use context
            "tools/call" => {
                let mut tokens = 0u64;
                if let Some(params) = content.get("params") {
                    if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
                        tokens += Self::estimate_tokens(name);
                    }
                    if let Some(args) = params.get("arguments") {
                        tokens += Self::count_json_tokens(args);
                    }
                }
                tokens.max(1)
            }

            // Protocol messages - minimal context impact
            "initialize" | "initialized" | "ping" | "cancelled" => 1,

            // List operations - no content sent to LLM
            "tools/list" | "resources/list" | "prompts/list" | "resources/templates/list" => 1,

            // Other methods - count params if present
            _ => {
                if let Some(params) = content.get("params") {
                    Self::count_json_tokens(params).max(1)
                } else {
                    1
                }
            }
        }
    }

    fn count_response_tokens(content: &serde_json::Value) -> u64 {
        // Handle errors
        if let Some(error) = content.get("error") {
            if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                return Self::estimate_tokens(msg).max(1);
            }
            return 1;
        }

        let result = match content.get("result") {
            Some(r) => r,
            None => return 1,
        };

        // tools/list response - tool definitions go into system prompt
        if let Some(tools) = result.get("tools").and_then(|t| t.as_array()) {
            let mut tokens = 0u64;
            for tool in tools {
                if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                    tokens += Self::estimate_tokens(name);
                }
                if let Some(desc) = tool.get("description").and_then(|d| d.as_str()) {
                    tokens += Self::estimate_tokens(desc);
                }
                if let Some(schema) = tool.get("inputSchema") {
                    tokens += Self::count_json_tokens(schema);
                }
            }
            return tokens.max(1);
        }

        // tools/call response - content array
        if let Some(content_arr) = result.get("content").and_then(|c| c.as_array()) {
            let mut tokens = 0u64;
            for item in content_arr {
                tokens += Self::count_content_item(item);
            }
            return tokens.max(1);
        }

        // resources/read response - text content
        if let Some(contents) = result.get("contents").and_then(|c| c.as_array()) {
            let mut tokens = 0u64;
            for content_item in contents {
                if let Some(text) = content_item.get("text").and_then(|t| t.as_str()) {
                    tokens += Self::estimate_tokens(text);
                }
                if let Some(blob) = content_item.get("blob").and_then(|b| b.as_str()) {
                    tokens += blob.len() as u64 / 4;
                }
            }
            return tokens.max(1);
        }

        // Default
        1
    }

    fn count_message_content(msg: &serde_json::Value) -> u64 {
        let mut tokens = 0u64;

        if let Some(content) = msg.get("content") {
            if let Some(text) = content.get("text").and_then(|t| t.as_str()) {
                tokens += Self::estimate_tokens(text);
            }
            if content.get("type").is_some() {
                tokens += 1;
            }
            if content.get("data").is_some() {
                // Images typically use ~85-765 tokens
                tokens += 200;
            }
        }

        tokens
    }

    fn count_content_item(item: &serde_json::Value) -> u64 {
        let mut tokens = 0u64;

        if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
            tokens += Self::estimate_tokens(text);
        }
        if item.get("data").is_some() {
            tokens += 200;
        }
        if let Some(resource) = item.get("resource") {
            if let Some(text) = resource.get("text").and_then(|t| t.as_str()) {
                tokens += Self::estimate_tokens(text);
            }
        }

        tokens.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_tokens_empty() {
        assert_eq!(TokenCounter::estimate_tokens(""), 0);
    }

    #[test]
    fn test_estimate_tokens_simple() {
        let tokens = TokenCounter::estimate_tokens("hello");
        assert!((1..=2).contains(&tokens));

        let tokens = TokenCounter::estimate_tokens("Hello world");
        assert!((2..=4).contains(&tokens));
    }

    #[test]
    fn test_estimate_tokens_json() {
        let json = r#"{"method":"tools/call","params":{"name":"test"}}"#;
        let tokens = TokenCounter::estimate_tokens(json);
        assert!((10..=30).contains(&tokens));
    }

    #[test]
    fn test_count_json_tokens() {
        let value = serde_json::json!({"method": "tools/list", "params": {}});
        let tokens = TokenCounter::count_json_tokens(&value);
        assert!(tokens > 0);
    }

    #[test]
    fn test_count_mcp_context_tokens_protocol() {
        let init = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {},
            "id": 1
        });
        let tokens = TokenCounter::count_mcp_context_tokens(&init);
        assert_eq!(tokens, 1); // Minimal for protocol messages
    }

    #[test]
    fn test_count_mcp_context_tokens_tools_call() {
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/passwd"}
            },
            "id": 1
        });
        let tokens = TokenCounter::count_mcp_context_tokens(&call);
        assert!(tokens > 1);
    }
}
