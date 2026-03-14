use crate::types::StreamUsage;

pub(super) fn usage_from_json_value(value: &serde_json::Value) -> Option<StreamUsage> {
    let usage = value
        .get("usage")
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("usage"))
        })
        .or_else(|| value.get("usageMetadata"))?;

    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| usage.get("prompt_tokens").and_then(serde_json::Value::as_u64))
        .or_else(|| usage.get("promptTokenCount").and_then(serde_json::Value::as_u64))
        .unwrap_or(0);

    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            usage
                .get("completion_tokens")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            usage
                .get("candidatesTokenCount")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0);

    let finish_reason = value
        .get("finish_reason")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("choices")
                .and_then(serde_json::Value::as_array)
                .and_then(|c| c.first())
                .and_then(|c| c.get("finish_reason"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| value.get("stop_reason").and_then(serde_json::Value::as_str))
        .map(ToString::to_string);

    Some(StreamUsage {
        input_tokens,
        output_tokens,
        finish_reason,
    })
}

/// Extract finish_reason from a JSON value, independent of usage.
/// Covers OpenAI, Anthropic, and Gemini patterns.
pub(super) fn finish_reason_from_json_value(value: &serde_json::Value) -> Option<String> {
    // OpenAI: top-level finish_reason
    if let Some(fr) = value
        .get("finish_reason")
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    // OpenAI: choices[0].finish_reason
    if let Some(fr) = value
        .get("choices")
        .and_then(serde_json::Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("finish_reason"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    // Anthropic: stop_reason
    if let Some(fr) = value
        .get("stop_reason")
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    // Anthropic message_delta: delta.stop_reason
    if let Some(fr) = value
        .get("delta")
        .and_then(|d| d.get("stop_reason"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    // Gemini: candidates[0].finishReason
    if let Some(fr) = value
        .get("candidates")
        .and_then(serde_json::Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("finishReason"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    // ChatGPT web: message.metadata.finish_details.type
    if let Some(fr) = value
        .get("message")
        .and_then(|m| m.get("metadata"))
        .and_then(|m| m.get("finish_details"))
        .and_then(|f| f.get("type"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(fr.to_string());
    }
    None
}
