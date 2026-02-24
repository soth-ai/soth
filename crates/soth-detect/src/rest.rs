use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::types::{
    DetectedFormat, EndpointType, FormatMeta, NormalizedRequest, ParseConfidence, ParseError,
    ParseResult, ParseWarning, Provider, RawRequest, RestFormatDescriptor,
};
use crate::util::{extract_string, json_path, normalize_unicodeish};
use serde_json::Value;

pub fn parse_rest(
    req: &RawRequest,
    provider_id: &str,
    format: DetectedFormat,
    descriptor: Option<&RestFormatDescriptor>,
) -> ParseResult<NormalizedRequest> {
    let desc =
        descriptor.ok_or_else(|| ParseError::MissingRequiredField("rest_format".to_string()))?;

    let json: Value = serde_json::from_slice(&req.body)
        .map_err(|error| ParseError::MalformedBody(error.to_string()))?;

    let mut warnings = Vec::new();

    let model = extract_model(&json, desc, &req.path);
    if model.is_none() {
        warnings.push(ParseWarning::MissingField("model".to_string()));
    }

    let mut messages = extract_messages(&json, desc);
    if messages.is_empty() {
        if let Some(message_path) = &desc.request.message {
            if let Some(value) = json_path(&json, message_path) {
                if let Some(single) = extract_string(value) {
                    messages.push(("user".to_string(), normalize_unicodeish(&single)));
                }
            }
        }
    }

    let system_prompt = extract_system_prompt(&json, desc);
    let user_content = first_user_content(&messages).unwrap_or_default();

    let conversation = messages
        .iter()
        .map(|(role, content)| format!("{role}:{content}"))
        .collect::<Vec<_>>()
        .join("\n");

    let tool_hash = desc
        .request
        .tools
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .filter(|value| !value.is_null())
        .map(|value| hash_content(&value.to_string()));

    let has_tool_definitions = tool_hash.is_some();

    let temperature = desc
        .request
        .temperature
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_f64())
        .map(|value| value as f32);

    let max_tokens = desc
        .request
        .max_tokens
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_u64())
        .map(|value| value as u32);

    let top_p = desc
        .request
        .top_p
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_f64())
        .map(|value| value as f32);

    let stream = desc
        .request
        .stream
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let stop_sequences = desc
        .request
        .stop
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(extract_string)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let system_prompt_hash = system_prompt.as_ref().map(|text| hash_content(text));
    let system_prompt_token_estimate = system_prompt.as_ref().map(|text| estimate_tokens(text));

    let user_content_hash = if user_content.is_empty() {
        hash_content("[CONTENT_NOT_EXTRACTED]")
    } else {
        hash_content(&user_content)
    };

    let user_content_token_estimate = estimate_tokens(&user_content);
    let conversation_hash = hash_content(&conversation);

    let estimated_input_tokens = estimate_tokens(
        &[
            system_prompt.clone().unwrap_or_default(),
            user_content.clone(),
        ]
        .join("\n"),
    );

    let mut normalized = NormalizedRequest {
        parse_confidence: if warnings.is_empty() {
            ParseConfidence::Full
        } else {
            ParseConfidence::Partial
        },
        parser_id: parser_id_for_format(&format),
        schema_version: "1",
        parse_warnings: warnings,
        is_ai_call: true,
        provider: Provider::new(provider_id),
        model,
        endpoint_type: infer_endpoint_type(&req.path),
        system_prompt_hash,
        system_prompt_token_estimate,
        user_content_hash,
        user_content_token_estimate,
        conversation_hash,
        conversation_turn: Some(messages.len() as u32),
        has_tool_definitions,
        tool_definition_hash: tool_hash,
        temperature,
        max_tokens,
        stream,
        top_p,
        stop_sequences,
        estimated_input_tokens,
        estimated_cost_usd: 0.0,
        canonical_hash: String::new(),
        format_meta: FormatMeta::Rest {
            path: req.path.clone(),
        },
        content_sample: if user_content.is_empty() {
            None
        } else {
            Some(user_content)
        },
    };

    normalized.canonical_hash = canonical_hash(&normalized);
    Ok(normalized)
}

fn extract_model(json: &Value, desc: &RestFormatDescriptor, path: &str) -> Option<String> {
    if desc.request.model.as_deref() == Some("{url_path}") {
        return extract_model_from_url(path, desc.model_from_url_segment.as_deref());
    }

    desc.request
        .model
        .as_ref()
        .and_then(|json_path_expr| json_path(json, json_path_expr))
        .and_then(extract_string)
}

fn extract_model_from_url(path: &str, marker: Option<&str>) -> Option<String> {
    let marker = marker.unwrap_or("/models/");
    let idx = path.find(marker)? + marker.len();
    let suffix = &path[idx..];
    let model = suffix
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(':');
    if model.is_empty() {
        None
    } else {
        Some(model.to_string())
    }
}

fn extract_system_prompt(json: &Value, desc: &RestFormatDescriptor) -> Option<String> {
    if desc.system_in_messages {
        let message_path = desc.request.messages.as_deref()?;
        let messages = json_path(json, message_path)?.as_array()?;
        for msg in messages {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role.eq_ignore_ascii_case("system") {
                if let Some(content) = msg.get("content").and_then(extract_string) {
                    return Some(normalize_unicodeish(&content));
                }
            }
        }
        return None;
    }

    desc.request
        .system
        .as_ref()
        .or(desc.request.system_instruction.as_ref())
        .and_then(|path| json_path(json, path))
        .and_then(extract_string)
        .map(|value| normalize_unicodeish(&value))
}

fn extract_messages(json: &Value, desc: &RestFormatDescriptor) -> Vec<(String, String)> {
    let path = desc
        .request
        .messages
        .as_ref()
        .or(desc.request.contents.as_ref());

    let Some(path) = path else {
        return Vec::new();
    };

    let Some(values) = json_path(json, path).and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for message in values {
        if let Some(object) = message.as_object() {
            let mut role = object
                .get("role")
                .and_then(|value| value.as_str())
                .unwrap_or("user")
                .to_string();

            if let Some(mapped) = desc.role_map.get(&role) {
                role = mapped.to_string();
            }

            let content_value = object.get("content").or_else(|| object.get("parts"));
            let content = content_value
                .and_then(extract_string)
                .map(|value| normalize_unicodeish(&value))
                .unwrap_or_default();

            if !content.is_empty() {
                out.push((role, content));
            }
        }
    }

    if desc.chat_history_mode {
        let history_path = desc
            .request
            .chat_history
            .as_deref()
            .unwrap_or("$.chat_history");
        if let Some(history) = json_path(json, history_path).and_then(|value| value.as_array()) {
            let mut rebuilt = Vec::new();
            for item in history {
                let role = item
                    .get("role")
                    .and_then(|value| value.as_str())
                    .unwrap_or("user")
                    .to_string();
                let content = item
                    .get("message")
                    .or_else(|| item.get("content"))
                    .and_then(extract_string)
                    .map(|value| normalize_unicodeish(&value))
                    .unwrap_or_default();
                if !content.is_empty() {
                    rebuilt.push((role, content));
                }
            }
            let current = desc
                .request
                .message
                .as_ref()
                .and_then(|message_path| json_path(json, message_path))
                .and_then(extract_string)
                .map(|text| ("user".to_string(), normalize_unicodeish(&text)));
            if let Some(current) = current {
                rebuilt.push(current);
            }
            return rebuilt;
        }
    }

    out
}

fn first_user_content(messages: &[(String, String)]) -> Option<String> {
    messages
        .iter()
        .find(|(role, _)| role.eq_ignore_ascii_case("user"))
        .map(|(_, content)| content.clone())
        .or_else(|| messages.first().map(|(_, content)| content.clone()))
}

fn infer_endpoint_type(path: &str) -> EndpointType {
    let lower = path.to_ascii_lowercase();
    if lower.contains("embeddings") {
        return EndpointType::Embedding;
    }
    if lower.contains("completion") {
        return EndpointType::Completion;
    }
    if lower.contains("chat") || lower.contains("message") {
        return EndpointType::Chat;
    }
    EndpointType::Unknown
}

fn parser_id_for_format(format: &DetectedFormat) -> &'static str {
    match format {
        DetectedFormat::OpenAIRest => "openai-v1",
        DetectedFormat::AnthropicRest => "anthropic-v1",
        DetectedFormat::CohereRest => "cohere-v1",
        DetectedFormat::GeminiRest => "gemini-v1",
        DetectedFormat::BedrockRest => "bedrock-v1",
        _ => "rest-v1",
    }
}
