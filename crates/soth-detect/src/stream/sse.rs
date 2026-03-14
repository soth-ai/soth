use crate::types::RestFormatDescriptor;
use crate::util::{extract_string, json_path};

/// Extract text content from REST SSE streaming payloads.
///
/// Handles `data: {...}` lines from OpenAI and Anthropic streaming responses:
/// - OpenAI API: `data: {"choices":[{"delta":{"content":"..."}}]}`
/// - Anthropic API: `data: {"type":"content_block_delta","delta":{"text":"..."}}`
/// - ChatGPT web: `data: {"message":{"content":{"parts":["..."]}}}`
/// - Grok web (NDJSON): `{"result":{"response":{"text":"..."}}}`
/// - DeepSeek web: `data: {"choices":[{"delta":{"content":"..."}}]}`
pub(super) fn extract_sse_rest_delta(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut collected = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        let json_str = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') {
            trimmed
        } else {
            continue;
        };

        if json_str.is_empty() || json_str == "[DONE]" {
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        // OpenAI Responses API: response.output_text.delta → top-level "delta" string
        if value.get("type").and_then(|v| v.as_str()) == Some("response.output_text.delta") {
            if let Some(delta) = value.get("delta").and_then(|v| v.as_str()) {
                collected.push_str(delta);
                continue;
            }
        }

        // OpenAI API / DeepSeek: choices[0].delta.content
        if let Some(delta) = value
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("delta"))
            .and_then(|d| d.get("content"))
            .and_then(|v| v.as_str())
        {
            collected.push_str(delta);
            continue;
        }

        // Anthropic API: delta.text (content_block_delta)
        if let Some(delta) = value
            .get("delta")
            .and_then(|d| d.get("text"))
            .and_then(|v| v.as_str())
        {
            collected.push_str(delta);
            continue;
        }

        // Anthropic API: content_block_start with text block
        if let Some(text_val) = value
            .get("content_block")
            .and_then(|b| b.get("text"))
            .and_then(|v| v.as_str())
        {
            if !text_val.is_empty() {
                collected.push_str(text_val);
            }
            continue;
        }

        // ChatGPT web: message.content.parts[0] (full replacement, not delta)
        if let Some(content) = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
        {
            if !content.is_empty() {
                // ChatGPT web sends full accumulated content in each SSE event,
                // so we replace rather than append.
                collected = content.to_string();
            }
            continue;
        }

        // Grok web (NDJSON): result.response.text (full replacement)
        if let Some(content) = value
            .get("result")
            .and_then(|r| r.get("response"))
            .and_then(|r| r.get("text"))
            .and_then(|v| v.as_str())
        {
            if !content.is_empty() {
                collected = content.to_string();
            }
            continue;
        }

        // Claude web: completion (SSE delta)
        if let Some(content) = value.get("completion").and_then(|v| v.as_str()) {
            collected.push_str(content);
            continue;
        }

        // Perplexity web: text field
        if let Some(content) = value.get("text").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                collected.push_str(content);
            }
            continue;
        }
    }

    if collected.is_empty() {
        None
    } else {
        Some(collected)
    }
}

/// Extract the model name from SSE/NDJSON response events.
///
/// NOTE: On the hot path, prefer `model_from_value()` via `extract_all_from_sse_lines`
/// which avoids redundant JSON parsing. This function is retained for tests and
/// backward-compatible callers.
#[cfg(test)]
pub(super) fn extract_sse_model(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;

    for line in text.lines() {
        let trimmed = line.trim();
        let json_str = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') {
            trimmed
        } else {
            continue;
        };

        if json_str.is_empty() || json_str == "[DONE]" {
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        // OpenAI Responses API: response.created → response.model
        if let Some(model) = value
            .get("response")
            .and_then(|r| r.get("model"))
            .and_then(|v| v.as_str())
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // Anthropic / Claude web: message_start → message.model
        if let Some(model) = value
            .get("message")
            .and_then(|m| m.get("model"))
            .and_then(|v| v.as_str())
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // OpenAI / ChatGPT API / Copilot: top-level model
        if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // ChatGPT web: metadata.model_slug
        if let Some(model) = value
            .get("metadata")
            .and_then(|m| m.get("model_slug"))
            .and_then(|v| v.as_str())
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // ChatGPT web: message.metadata.model_slug (nested in message envelope)
        if let Some(model) = value
            .get("message")
            .and_then(|m| m.get("metadata"))
            .and_then(|m| m.get("model_slug"))
            .and_then(|v| v.as_str())
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // Grok web: result.modelResponse.model
        if let Some(model) = value
            .get("result")
            .and_then(|r| r.get("modelResponse"))
            .and_then(|mr| mr.get("model"))
            .and_then(|v| v.as_str())
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }

        // Perplexity: display_model
        if let Some(model) = value.get("display_model").and_then(|v| v.as_str()) {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }
    }

    None
}

/// Extract response content delta using the bundle's RestFormatDescriptor response paths.
///
/// NOTE: On the hot path, prefer `accumulate_delta_from_value_with_descriptor()` via
/// `extract_all_from_sse_lines`. This function is retained for tests.
#[cfg(test)]
pub(super) fn extract_delta_with_descriptor(
    payload: &[u8],
    descriptor: Option<&RestFormatDescriptor>,
) -> Option<String> {
    let desc = descriptor?;
    let content_path = desc.response.content.as_deref()?;

    let text = std::str::from_utf8(payload).ok()?;
    let mut collected = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        let json_str = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') {
            trimmed
        } else {
            continue;
        };

        if json_str.is_empty() || json_str == "[DONE]" {
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        if let Some(content) = json_path(&value, content_path).and_then(extract_string) {
            if !content.is_empty() {
                collected.push_str(&content);
            }
        }
    }

    if collected.is_empty() {
        None
    } else {
        Some(collected)
    }
}

/// Extract model from streaming response using the bundle's RestFormatDescriptor response paths.
///
/// NOTE: On the hot path, prefer `model_from_value_with_descriptor()` via
/// `extract_all_from_sse_lines`. This function is retained for tests.
#[cfg(test)]
pub(super) fn extract_model_with_descriptor(
    payload: &[u8],
    descriptor: Option<&RestFormatDescriptor>,
) -> Option<String> {
    let desc = descriptor?;
    let model_path = desc.response.model.as_deref()?;

    let text = std::str::from_utf8(payload).ok()?;

    for line in text.lines() {
        let trimmed = line.trim();
        let json_str = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') {
            trimmed
        } else {
            continue;
        };

        if json_str.is_empty() || json_str == "[DONE]" {
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        if let Some(model) = json_path(&value, model_path).and_then(extract_string) {
            if !model.is_empty() {
                return Some(model);
            }
        }
    }

    None
}

// ─── Per-value extractors (for single-pass usage in process_chunk_with_bundle) ───

/// Extract model from a single pre-parsed JSON value.
pub(super) fn model_from_value(value: &serde_json::Value) -> Option<String> {
    // OpenAI Responses API: response.created → response.model
    if let Some(model) = value
        .get("response")
        .and_then(|r| r.get("model"))
        .and_then(|v| v.as_str())
    {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // Anthropic / Claude web: message_start → message.model
    if let Some(model) = value
        .get("message")
        .and_then(|m| m.get("model"))
        .and_then(|v| v.as_str())
    {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // OpenAI / ChatGPT API / Copilot: top-level model
    if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // ChatGPT web: metadata.model_slug
    if let Some(model) = value
        .get("metadata")
        .and_then(|m| m.get("model_slug"))
        .and_then(|v| v.as_str())
    {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // ChatGPT web: message.metadata.model_slug
    if let Some(model) = value
        .get("message")
        .and_then(|m| m.get("metadata"))
        .and_then(|m| m.get("model_slug"))
        .and_then(|v| v.as_str())
    {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // Grok web: result.modelResponse.model
    if let Some(model) = value
        .get("result")
        .and_then(|r| r.get("modelResponse"))
        .and_then(|mr| mr.get("model"))
        .and_then(|v| v.as_str())
    {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    // Perplexity: display_model
    if let Some(model) = value.get("display_model").and_then(|v| v.as_str()) {
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    None
}

/// Extract model from a single value using a descriptor's model path.
pub(super) fn model_from_value_with_descriptor(
    value: &serde_json::Value,
    descriptor: Option<&RestFormatDescriptor>,
) -> Option<String> {
    let desc = descriptor?;
    let model_path = desc.response.model.as_deref()?;
    json_path(value, model_path)
        .and_then(extract_string)
        .filter(|s| !s.is_empty())
}

/// Accumulate delta content from a single pre-parsed JSON value into `collected`.
/// Returns `true` if content was found (for early-exit in callers).
pub(super) fn accumulate_delta_from_value(
    value: &serde_json::Value,
    collected: &mut String,
) -> bool {
    // OpenAI Responses API: response.output_text.delta
    if value.get("type").and_then(|v| v.as_str()) == Some("response.output_text.delta") {
        if let Some(delta) = value.get("delta").and_then(|v| v.as_str()) {
            collected.push_str(delta);
            return true;
        }
    }
    // OpenAI API / DeepSeek: choices[0].delta.content
    if let Some(delta) = value
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|v| v.as_str())
    {
        collected.push_str(delta);
        return true;
    }
    // Anthropic API: delta.text (content_block_delta)
    if let Some(delta) = value
        .get("delta")
        .and_then(|d| d.get("text"))
        .and_then(|v| v.as_str())
    {
        collected.push_str(delta);
        return true;
    }
    // Anthropic API: content_block_start with text block
    if let Some(text_val) = value
        .get("content_block")
        .and_then(|b| b.get("text"))
        .and_then(|v| v.as_str())
    {
        if !text_val.is_empty() {
            collected.push_str(text_val);
        }
        return true;
    }
    // ChatGPT web: message.content.parts[0] (full replacement)
    if let Some(content) = value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.get(0))
        .and_then(|v| v.as_str())
    {
        if !content.is_empty() {
            collected.clear();
            collected.push_str(content);
        }
        return true;
    }
    // Grok web (NDJSON): result.response.text (full replacement)
    if let Some(content) = value
        .get("result")
        .and_then(|r| r.get("response"))
        .and_then(|r| r.get("text"))
        .and_then(|v| v.as_str())
    {
        if !content.is_empty() {
            collected.clear();
            collected.push_str(content);
        }
        return true;
    }
    // Claude web: completion (SSE delta)
    if let Some(content) = value.get("completion").and_then(|v| v.as_str()) {
        collected.push_str(content);
        return true;
    }
    // Perplexity web: text field
    if let Some(content) = value.get("text").and_then(|v| v.as_str()) {
        if !content.is_empty() {
            collected.push_str(content);
        }
        return true;
    }
    false
}

/// Accumulate delta content from a single value using a descriptor's content path.
pub(super) fn accumulate_delta_from_value_with_descriptor(
    value: &serde_json::Value,
    descriptor: Option<&RestFormatDescriptor>,
    collected: &mut String,
) -> bool {
    let Some(desc) = descriptor else {
        return false;
    };
    let Some(content_path) = desc.response.content.as_deref() else {
        return false;
    };
    if let Some(content) = json_path(value, content_path).and_then(extract_string) {
        if !content.is_empty() {
            collected.push_str(&content);
            return true;
        }
    }
    false
}
