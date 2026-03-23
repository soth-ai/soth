//! JSON-RPC 2.0 request parser.
//!
//! **Deprecated**: This parser was originally built for MCP (Model Context
//! Protocol) traffic which used JSON-RPC 2.0 as its wire format.  MCP
//! interception has been removed from SOTH.  No AI provider in the parser
//! registry uses JSON-RPC for chat/inference endpoints.
//!
//! The module is kept for backward compatibility with bundles that reference
//! `DetectedFormat::JsonRpc` and for the `ParseSource::JsonRpc` enum
//! variant, but it is no longer called in the streaming hot path.

use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::types::{
    EndpointType, FormatMeta, NormalizedRequest, ParseConfidence, ParseError, ParseResult,
    ParseWarning, RawRequest,
};
use crate::util::{extract_string, json_path, normalize_unicodeish};
use serde_json::Value;

const JSONRPC_CONTENT_PATHS: [&str; 12] = [
    "$.delta.content",
    "$.content",
    "$.text",
    "$.message",
    "$.prompt",
    "$.query",
    "$.input.content",
    "$.input.text",
    "$.input",
    "$.arguments.content",
    "$.arguments.prompt",
    "$.choices[0].delta.content",
];

pub fn parse_jsonrpc(
    req: &RawRequest,
    provider_id: &str,
    pre_parsed: Option<&Value>,
) -> ParseResult<NormalizedRequest> {
    // Reuse the caller's pre-parsed value when available to avoid a second
    // serde_json::from_slice call on the hot path.
    let owned;
    let json: &Value = match pre_parsed {
        Some(v) => v,
        None => {
            owned = serde_json::from_slice(&req.body)
                .map_err(|error| ParseError::MalformedBody(error.to_string()))?;
            &owned
        }
    };

    let calls = jsonrpc_calls(json);
    if calls.is_empty() {
        return Err(ParseError::MalformedBody(
            "json-rpc payload is not an object or batch array".to_string(),
        ));
    }

    let selected = select_best_call(&calls);
    let params = selected.get("params").unwrap_or(selected);

    let method = selected
        .get("method")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let content = extract_jsonrpc_content(params).or_else(|| {
        selected
            .get("result")
            .and_then(extract_jsonrpc_content)
            .or_else(|| selected.get("error").and_then(extract_jsonrpc_content))
    });

    let model = extract_model(params).or_else(|| extract_model(selected));
    let system_prompt = extract_system_prompt(params);

    let mut parse_warnings = Vec::new();
    if method.is_none() {
        parse_warnings.push(ParseWarning::MissingField {
            field: "method".to_string(),
        });
    }
    if content.is_none() {
        parse_warnings.push(ParseWarning::ContentNotExtracted);
    }

    let parse_confidence = match (method.as_ref(), content.as_ref()) {
        (Some(_), Some(_)) => ParseConfidence::Full,
        _ => ParseConfidence::Partial,
    };

    let stream = bool_at_paths(params, &["$.stream", "$.streaming"]).unwrap_or(false);
    let temperature = f32_at_paths(
        params,
        &[
            "$.temperature",
            "$.options.temperature",
            "$.generationConfig.temperature",
        ],
    );
    let max_tokens = u32_at_paths(
        params,
        &[
            "$.max_tokens",
            "$.maxTokens",
            "$.max_output_tokens",
            "$.generationConfig.maxOutputTokens",
        ],
    );
    let top_p = f32_at_paths(params, &["$.top_p", "$.topP", "$.generationConfig.topP"]);
    let stop_sequences = extract_stop_sequences(params);

    let tool_hash = [
        "$.tools",
        "$.tool_defs",
        "$.toolDefinitions",
        "$.input.tools",
    ]
    .iter()
    .find_map(|path| json_path(params, path).filter(|value| !value.is_null()))
    .map(|value| hash_content(&value.to_string()));

    let has_tool_definitions = tool_hash.is_some();

    let content_value = content.unwrap_or_else(|| "[CONTENT_NOT_EXTRACTED]".to_string());
    let user_content_hash = hash_content(&content_value);
    let user_content_token_estimate = estimate_tokens(&content_value);

    let system_prompt_hash = system_prompt.as_ref().map(|value| hash_content(value));
    let system_prompt_token_estimate = system_prompt.as_ref().map(|value| estimate_tokens(value));
    let estimated_input_tokens = estimate_tokens(
        &[
            system_prompt.clone().unwrap_or_default(),
            content_value.clone(),
        ]
        .join("\n"),
    );

    let conversation_turn = json_path(params, "$.messages")
        .and_then(|value| value.as_array())
        .map(|messages| messages.len() as u32)
        .filter(|count| *count > 0)
        .or_else(|| {
            if content_value == "[CONTENT_NOT_EXTRACTED]" {
                None
            } else {
                Some(1)
            }
        });

    let conversation_hash = hash_content(&content_value);
    let is_ai_call = method.as_deref().map(is_ai_method).unwrap_or(false)
        || content_value != "[CONTENT_NOT_EXTRACTED]";

    let mut normalized = NormalizedRequest {
        parse_confidence,
        parser_id: "jsonrpc-v1".to_string(),
        schema_version: "1".to_string(),
        parse_warnings,
        is_ai_call,
        provider: provider_id.to_string(),
        model,
        endpoint_type: infer_endpoint_type(method.as_deref(), &req.path),
        system_prompt_hash,
        system_prompt_token_estimate,
        user_content_hash: user_content_hash.clone(),
        user_content_token_estimate,
        conversation_hash,
        conversation_turn,
        has_tool_definitions,
        tool_definition_hash: tool_hash,
        temperature,
        max_tokens,
        stream,
        top_p,
        stop_sequences,
        estimated_input_tokens,
        estimated_cost_usd: 0.0,
        parse_source: crate::types::ParseSource::Heuristic,
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        canonical_cache_key: String::new(),
        format_metadata: FormatMeta::JsonRpc {
            method: method.clone().unwrap_or_default(),
            is_batch: matches!(json, Value::Array(_)),
        },
        api_version: None,
        user_prompt: if content_value.is_empty() || content_value == "[CONTENT_NOT_EXTRACTED]" {
            None
        } else {
            Some(content_value.clone())
        },
    };

    normalized.canonical_cache_key = canonical_hash(&normalized);
    Ok(normalized)
}

pub fn parse_jsonrpc_payload_text(payload: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(payload).ok()?;
    extract_payload_content(&value)
}

fn jsonrpc_calls(json: &Value) -> Vec<&Value> {
    match json {
        Value::Object(_) => vec![json],
        Value::Array(items) => items.iter().filter(|value| value.is_object()).collect(),
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) => Vec::new(),
    }
}

fn select_best_call<'a>(calls: &'a [&Value]) -> &'a Value {
    let mut selected = calls[0];
    let mut best_score = i32::MIN;

    for call in calls {
        let method = call
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let params = call.get("params").unwrap_or(call);
        let has_content = extract_jsonrpc_content(params).is_some();

        let mut score = 0;
        if has_content {
            score += 4;
        }
        if !method.is_empty() {
            score += 1;
        }
        if is_ai_method(method) {
            score += 2;
        }

        if score > best_score {
            best_score = score;
            selected = call;
        }
    }

    selected
}

fn extract_payload_content(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => items.iter().find_map(extract_payload_content),
        Value::Object(_) => {
            if let Some(params) = value.get("params") {
                if let Some(content) = extract_jsonrpc_content(params) {
                    return Some(content);
                }
            }

            if let Some(result) = value.get("result") {
                if let Some(content) = extract_jsonrpc_content(result) {
                    return Some(content);
                }
            }

            extract_jsonrpc_content(value)
        }
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) => None,
    }
}

fn extract_jsonrpc_content(value: &Value) -> Option<String> {
    for path in JSONRPC_CONTENT_PATHS {
        if let Some(content) = json_path(value, path)
            .and_then(extract_string)
            .map(|value| normalize_unicodeish(&value))
            .filter(|value| !value.is_empty())
        {
            return Some(content);
        }
    }

    if let Some(messages) = json_path(value, "$.messages").and_then(|value| value.as_array()) {
        for message in messages {
            let role = message
                .get("role")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let content = message
                .get("content")
                .and_then(extract_string)
                .map(|value| normalize_unicodeish(&value))
                .filter(|value| !value.is_empty());
            if role.eq_ignore_ascii_case("user") {
                if let Some(content) = content {
                    return Some(content);
                }
            }
        }

        if let Some(first) = messages
            .iter()
            .find_map(|message| message.get("content").and_then(extract_string))
            .map(|value| normalize_unicodeish(&value))
            .filter(|value| !value.is_empty())
        {
            return Some(first);
        }
    }

    if !contains_content_hints(value) {
        return None;
    }

    find_longest_string(value, 20).map(|value| normalize_unicodeish(&value))
}

fn extract_model(value: &Value) -> Option<String> {
    ["$.model", "$.model_id", "$.modelId", "$.modelName"]
        .iter()
        .find_map(|path| json_path(value, path))
        .and_then(extract_string)
}

fn extract_system_prompt(value: &Value) -> Option<String> {
    json_path(value, "$.system")
        .or_else(|| json_path(value, "$.system_prompt"))
        .or_else(|| json_path(value, "$.systemPrompt"))
        .and_then(extract_string)
        .map(|value| normalize_unicodeish(&value))
        .filter(|value| !value.is_empty())
}

fn extract_stop_sequences(value: &Value) -> Vec<String> {
    if let Some(stops) = json_path(value, "$.stop").and_then(|value| value.as_array()) {
        return stops
            .iter()
            .filter_map(extract_string)
            .map(|value| normalize_unicodeish(&value))
            .filter(|value| !value.is_empty())
            .collect();
    }

    json_path(value, "$.stop")
        .and_then(extract_string)
        .map(|value| vec![normalize_unicodeish(&value)])
        .unwrap_or_default()
}

fn bool_at_paths(value: &Value, paths: &[&str]) -> Option<bool> {
    paths
        .iter()
        .find_map(|path| json_path(value, path))
        .and_then(|value| value.as_bool())
}

fn f32_at_paths(value: &Value, paths: &[&str]) -> Option<f32> {
    paths
        .iter()
        .find_map(|path| json_path(value, path))
        .and_then(|value| value.as_f64())
        .map(|value| value as f32)
}

fn u32_at_paths(value: &Value, paths: &[&str]) -> Option<u32> {
    paths
        .iter()
        .find_map(|path| json_path(value, path))
        .and_then(|value| value.as_u64())
        .map(|value| value as u32)
}

fn infer_endpoint_type(method: Option<&str>, path: &str) -> EndpointType {
    let lower = method.unwrap_or_default().to_ascii_lowercase();
    if lower.contains("embed") {
        return EndpointType::Embedding;
    }
    if lower.contains("chat")
        || lower.contains("message")
        || lower.contains("response")
        || lower.contains("conversation")
        || lower.contains("generate")
        || lower.contains("prompt")
    {
        return EndpointType::ChatCompletion;
    }
    if lower.contains("completion") {
        return EndpointType::TextCompletion;
    }

    let path_lc = path.to_ascii_lowercase();
    if path_lc.contains("embed") {
        return EndpointType::Embedding;
    }
    if path_lc.contains("chat")
        || path_lc.contains("message")
        || path_lc.contains("response")
        || path_lc.contains("conversation")
    {
        return EndpointType::ChatCompletion;
    }
    if path_lc.contains("completion") {
        return EndpointType::TextCompletion;
    }
    EndpointType::Unknown
}

fn is_ai_method(method: &str) -> bool {
    let lower = method.to_ascii_lowercase();
    lower.contains("chat")
        || lower.contains("completion")
        || lower.contains("generate")
        || lower.contains("prompt")
        || lower.contains("message")
        || lower.contains("response")
        || lower.contains("inference")
}

fn contains_content_hints(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.keys().any(|key| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "content"
                        | "text"
                        | "message"
                        | "prompt"
                        | "query"
                        | "input"
                        | "messages"
                        | "delta"
                        | "arguments"
                        | "params"
                        | "result"
                )
            }) || map.values().any(contains_content_hints)
        }
        Value::Array(items) => items.iter().any(contains_content_hints),
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) => false,
    }
}

fn find_longest_string(value: &Value, min_len: usize) -> Option<String> {
    let mut best: Option<String> = None;
    visit_json(value, &mut |candidate| {
        if candidate.len() < min_len {
            return;
        }
        let should_replace = match best.as_ref() {
            Some(existing) => candidate.len() > existing.len(),
            None => true,
        };
        if should_replace {
            best = Some(candidate.to_string());
        }
    });
    best
}

fn visit_json(value: &Value, visit: &mut dyn FnMut(&str)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => {
            for item in items {
                visit_json(item, visit);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                visit_json(value, visit);
            }
        }
        Value::Bool(_) | Value::Null | Value::Number(_) => {}
    }
}
