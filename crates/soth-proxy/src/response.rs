use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct UsageSummary {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_output_cost_usd: f64,
    pub finish_reason: Option<String>,
}

pub fn extract_usage(body: &[u8]) -> Option<UsageSummary> {
    if body.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return usage_from_value(&value);
    }

    if let Some(usage) = extract_usage_from_sse_bytes(body) {
        return Some(usage);
    }

    // Gemini web: length-prefixed format starting with ")]}'\\n"
    extract_usage_from_length_prefixed(body)
}

pub fn try_extract_usage(payload: &[u8]) -> Option<UsageSummary> {
    if payload.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_slice::<Value>(payload) {
        return usage_from_value(&value);
    }

    if let Some(usage) = extract_usage_from_sse_bytes(payload) {
        return Some(usage);
    }

    extract_usage_from_length_prefixed(payload)
}

fn extract_usage_from_sse_bytes(bytes: &[u8]) -> Option<UsageSummary> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut latest = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("data:") {
            continue;
        }

        let json = trimmed.trim_start_matches("data:").trim();
        if json.is_empty() || json == "[DONE]" {
            continue;
        }

        if let Ok(value) = serde_json::from_str::<Value>(json) {
            if let Some(usage) = usage_from_value(&value) {
                latest = Some(usage);
            }
        }
    }

    latest
}

fn usage_from_value(value: &Value) -> Option<UsageSummary> {
    let usage = value.get("usage");
    let usage = usage
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("usage"))
        })
        // Gemini API: usageMetadata
        .or_else(|| value.get("usageMetadata"));

    let usage = usage?;

    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("prompt_tokens").and_then(Value::as_u64))
        .or_else(|| usage.get("request_tokens").and_then(Value::as_u64))
        // Gemini: promptTokenCount
        .or_else(|| usage.get("promptTokenCount").and_then(Value::as_u64))
        .unwrap_or(0);

    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("completion_tokens").and_then(Value::as_u64))
        .or_else(|| usage.get("response_tokens").and_then(Value::as_u64))
        // Gemini: candidatesTokenCount
        .or_else(|| usage.get("candidatesTokenCount").and_then(Value::as_u64))
        .unwrap_or(0);

    let finish_reason = value
        .get("finish_reason")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|choices| choices.first())
                .and_then(|choice| choice.get("finish_reason"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        // Anthropic: stop_reason
        .or_else(|| {
            value
                .get("stop_reason")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        // Gemini: candidates[0].finishReason
        .or_else(|| {
            value
                .get("candidates")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|c| c.get("finishReason"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        // ChatGPT web: message.metadata.finish_details.type
        .or_else(|| {
            value
                .get("message")
                .and_then(|m| m.get("metadata"))
                .and_then(|m| m.get("finish_details"))
                .and_then(|f| f.get("type"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        });

    Some(UsageSummary {
        input_tokens,
        output_tokens,
        estimated_output_cost_usd: 0.0,
        finish_reason,
    })
}

/// Extract usage from Gemini web's length-prefixed response format.
///
/// Gemini web responses start with `)]}'` + newline, followed by JSON.
fn extract_usage_from_length_prefixed(body: &[u8]) -> Option<UsageSummary> {
    let text = std::str::from_utf8(body).ok()?;
    let json_text = text.strip_prefix(")]}'")?.trim_start();

    if let Ok(value) = serde_json::from_str::<Value>(json_text) {
        return usage_from_value(&value);
    }

    // Try line-by-line (Gemini sometimes returns multiple JSON lines)
    let mut latest = None;
    for line in json_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if let Some(usage) = usage_from_value(&value) {
                latest = Some(usage);
            }
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_openai_standard() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":20},"choices":[{"finish_reason":"stop"}]}"#;
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(usage.finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn usage_anthropic_standard() {
        let body = br#"{"usage":{"input_tokens":15,"output_tokens":25},"stop_reason":"end_turn"}"#;
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 15);
        assert_eq!(usage.output_tokens, 25);
        assert_eq!(usage.finish_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn usage_gemini_api() {
        let body = br#"{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":200},"candidates":[{"finishReason":"STOP"}]}"#;
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 200);
        assert_eq!(usage.finish_reason.as_deref(), Some("STOP"));
    }

    #[test]
    fn usage_gemini_length_prefixed() {
        let body = b")]}'\n{\"usageMetadata\":{\"promptTokenCount\":50,\"candidatesTokenCount\":75},\"candidates\":[{\"finishReason\":\"STOP\"}]}";
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 75);
        assert_eq!(usage.finish_reason.as_deref(), Some("STOP"));
    }

    #[test]
    fn usage_chatgpt_web_finish_details() {
        let body = br#"{"message":{"metadata":{"finish_details":{"type":"max_tokens"}}},"usage":{"prompt_tokens":30,"completion_tokens":40}}"#;
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 30);
        assert_eq!(usage.output_tokens, 40);
        assert_eq!(usage.finish_reason.as_deref(), Some("max_tokens"));
    }

    #[test]
    fn usage_sse_streaming_final_chunk() {
        let body = b"data: {\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":10},\"choices\":[{\"finish_reason\":\"stop\"}]}\n";
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn usage_empty_body_returns_none() {
        let result = extract_usage(b"");
        assert!(result.is_none());
    }

    #[test]
    fn try_extract_usage_gemini_length_prefixed() {
        let body =
            b")]}'\n{\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":20}}";
        let usage = try_extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 20);
    }

    #[test]
    fn usage_responses_api_completed() {
        // OpenAI Responses API: response.completed event (bare JSON, as in WebSocket frame)
        let body = br#"{"type":"response.completed","response":{"id":"resp_123","usage":{"input_tokens":1234,"output_tokens":321,"total_tokens":1555}}}"#;
        let usage = try_extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 1234);
        assert_eq!(usage.output_tokens, 321);
    }

    #[test]
    fn usage_responses_api_sse() {
        // OpenAI Responses API: response.completed via SSE
        let body = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_123\",\"usage\":{\"input_tokens\":500,\"output_tokens\":100}}}\n";
        let usage = extract_usage(body).unwrap();
        assert_eq!(usage.input_tokens, 500);
        assert_eq!(usage.output_tokens, 100);
    }
}
