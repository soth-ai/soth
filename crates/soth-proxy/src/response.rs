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

    extract_usage_from_sse_bytes(body)
}

pub fn try_extract_usage(payload: &[u8]) -> Option<UsageSummary> {
    if payload.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_slice::<Value>(payload) {
        return usage_from_value(&value);
    }

    extract_usage_from_sse_bytes(payload)
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
    let usage = usage.or_else(|| {
        value
            .get("response")
            .and_then(|response| response.get("usage"))
    })?;

    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("prompt_tokens").and_then(Value::as_u64))
        .or_else(|| usage.get("request_tokens").and_then(Value::as_u64))
        .unwrap_or(0);

    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("completion_tokens").and_then(Value::as_u64))
        .or_else(|| usage.get("response_tokens").and_then(Value::as_u64))
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
        });

    Some(UsageSummary {
        input_tokens,
        output_tokens,
        estimated_output_cost_usd: 0.0,
        finish_reason,
    })
}
