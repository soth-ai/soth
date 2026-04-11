use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::types::{
    DetectedFormat, EndpointType, FormatMeta, NormalizedRequest, ParseConfidence, ParseError,
    ParseResult, ParseWarning, PreprocessOp, RawRequest, RequestEncoding, RestFormatDescriptor,
};
use crate::util::{extract_string, json_path, normalize_unicodeish};
use serde_json::Value;

pub fn parse_rest(
    req: &RawRequest,
    provider_id: &str,
    format: DetectedFormat,
    descriptor: Option<&RestFormatDescriptor>,
    pre_parsed: Option<&Value>,
) -> ParseResult<(NormalizedRequest, Value)> {
    let desc =
        descriptor.ok_or_else(|| ParseError::MissingRequiredField("rest_format".to_string()))?;

    // WebSocket features use GET with no body — the chat data flows over
    // WebSocket frames after the HTTP upgrade, so there is nothing to parse
    // from the request. Return a minimal NormalizedRequest and let the
    // streaming session handle content extraction via the feature's stream
    // rules.
    if is_websocket_feature(desc) && req.body.is_empty() {
        let parser_id = parser_id_for_format(&format, Some(desc));
        let api_version = extract_api_version(&req.headers, &req.path, &format);
        let mut normalized = NormalizedRequest {
            parse_confidence: ParseConfidence::Partial,
            parser_id,
            schema_version: "1".to_string(),
            parse_warnings: vec![],
            is_ai_call: true,
            provider: provider_id.to_string(),
            model: None,
            endpoint_type: EndpointType::ChatCompletion,
            system_prompt_hash: None,
            system_prompt_token_estimate: None,
            user_content_hash: hash_content("[WEBSOCKET_UPGRADE]"),
            user_content_token_estimate: 0,
            conversation_hash: hash_content("[WEBSOCKET_UPGRADE]"),
            conversation_turn: None,
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: None,
            stream: true,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 0,
            estimated_cost_usd: 0.0,
            parse_source: crate::types::ParseSource::Heuristic,
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            canonical_cache_key: String::new(),
            format_metadata: FormatMeta::Rest {
                content_type: req.path.clone(),
            },
            api_version,
            user_prompt: None,
        };
        normalized.canonical_cache_key = canonical_hash(&normalized);
        return Ok((normalized, Value::Null));
    }

    let json: Value = decode_request_body(req, desc, pre_parsed)?;

    let mut warnings = Vec::new();

    let model = extract_model(&json, desc, &req.path);
    if model.is_none() {
        warnings.push(ParseWarning::MissingField {
            field: "model".to_string(),
        });
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
    if messages.is_empty() {
        messages = extract_messages_fallback(&json);
    }

    // Feature-based field extraction: when flat request paths yield nothing,
    // match the request path against feature URL patterns and use the
    // feature's request.fields to extract the prompt.
    if messages.is_empty() {
        if let Some(prompt) = extract_prompt_from_feature(desc, &req.path, &req.method, &json) {
            messages.push(("user".to_string(), normalize_unicodeish(&prompt)));
        }
    }

    let system_prompt = extract_system_prompt(&json, desc);
    let user_content = last_user_content(&messages).unwrap_or_default();

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
        .map(|value| value as f32)
        .or_else(|| {
            json_path(&json, "$.generationConfig.temperature")
                .and_then(|value| value.as_f64())
                .map(|value| value as f32)
        });

    let max_tokens = desc
        .request
        .max_tokens
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_u64())
        .map(|value| value as u32)
        .or_else(|| {
            json_path(&json, "$.max_output_tokens")
                .or_else(|| json_path(&json, "$.max_completion_tokens"))
                .or_else(|| json_path(&json, "$.generationConfig.maxOutputTokens"))
                .and_then(|value| value.as_u64())
                .map(|value| value as u32)
        });

    let top_p = desc
        .request
        .top_p
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_f64())
        .map(|value| value as f32)
        .or_else(|| {
            json_path(&json, "$.generationConfig.topP")
                .and_then(|value| value.as_f64())
                .map(|value| value as f32)
        });

    let stream = desc
        .request
        .stream
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .and_then(|value| value.as_bool())
        .or_else(|| json_path(&json, "$.streaming").and_then(|value| value.as_bool()))
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
        .unwrap_or_else(|| {
            json_path(&json, "$.stop_sequences")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(extract_string)
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default()
        });

    let system_prompt_hash = system_prompt.as_ref().map(|text| hash_content(text));
    let system_prompt_token_estimate = system_prompt.as_ref().map(|text| estimate_tokens(text));

    let user_content_hash = if user_content.is_empty() {
        hash_content("[CONTENT_NOT_EXTRACTED]")
    } else {
        hash_content(&user_content)
    };

    let user_content_token_estimate = estimate_tokens(&user_content);
    let conversation_hash = hash_content(&conversation);

    // Estimate from the full conversation context (all turns, not just the first
    // user message). For multi-turn conversations this can be 5-20x larger than
    // system_prompt + first_user_content alone.
    let mut input_parts = Vec::new();
    if let Some(ref sp) = system_prompt {
        if !sp.is_empty() {
            input_parts.push(sp.as_str());
        }
    }
    if !conversation.is_empty() {
        input_parts.push(conversation.as_str());
    }
    // Tool definitions contribute tokens but were previously uncounted.
    let tool_token_estimate = desc
        .request
        .tools
        .as_ref()
        .and_then(|path| json_path(&json, path))
        .filter(|value| !value.is_null())
        .map(|value| estimate_tokens(&value.to_string()))
        .unwrap_or(0);
    let estimated_input_tokens = estimate_tokens(&input_parts.join("\n")) + tool_token_estimate;

    let api_version = extract_api_version(&req.headers, &req.path, &format);
    let parser_id = parser_id_for_format(&format, Some(desc));

    let mut normalized = NormalizedRequest {
        parse_confidence: if warnings.is_empty() {
            ParseConfidence::Full
        } else {
            ParseConfidence::Partial
        },
        parser_id,
        schema_version: "1".to_string(),
        parse_warnings: warnings,
        is_ai_call: true,
        provider: provider_id.to_string(),
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
        parse_source: crate::types::ParseSource::Heuristic,
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        canonical_cache_key: String::new(),
        format_metadata: FormatMeta::Rest {
            content_type: req.path.clone(),
        },
        api_version,
        user_prompt: if user_content.is_empty() {
            None
        } else {
            Some(user_content.clone())
        },
    };

    normalized.canonical_cache_key = canonical_hash(&normalized);
    Ok((normalized, json))
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
        .or_else(|| desc.model_default.clone())
}

fn extract_model_from_url(path: &str, marker: Option<&str>) -> Option<String> {
    let marker = marker.unwrap_or("/models/");
    let idx = path.find(marker)? + marker.len();
    let suffix = &path[idx..];
    let segment = suffix.split('/').next().unwrap_or("").trim();
    // Strip Gemini-style action suffix like ":generateContent" or ":streamGenerateContent"
    let model = segment.split(':').next().unwrap_or(segment);
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
        .or_else(|| {
            json_path(json, "$.instructions")
                .or_else(|| json_path(json, "$.system_prompt"))
                .or_else(|| json_path(json, "$.systemPrompt"))
                .and_then(extract_string)
                .map(|value| normalize_unicodeish(&value))
        })
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

    let resolved = json_path(json, path);

    // If the path resolves to a plain string (not an array of message
    // objects), treat it as a single user message.  This handles formats
    // like Gemini web where the prompt is extracted via preprocess into
    // a scalar value.
    if let Some(scalar) = resolved.as_ref().and_then(|v| extract_string(v)) {
        if !scalar.is_empty() {
            return vec![("user".to_string(), normalize_unicodeish(&scalar))];
        }
    }

    let Some(values) = resolved.and_then(|value| value.as_array()) else {
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

/// Return the content of the last user-role message in a conversation.
///
/// For multi-turn agentic conversations (e.g. Claude Code requests that carry
/// hundreds of tokens of prior history) the last user message is the actual
/// current task instruction.  The first user message is often context setup or
/// a short greeting and would produce a misleading embedding.
///
/// Falls back to the last message of any role when no explicit "user" turn is
/// found (single-message formats with no role tag).
fn last_user_content(messages: &[(String, String)]) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|(role, _)| role.eq_ignore_ascii_case("user"))
        .map(|(_, content)| content.clone())
        .or_else(|| messages.last().map(|(_, content)| content.clone()))
}

fn extract_messages_fallback(json: &Value) -> Vec<(String, String)> {
    if let Some(messages) = json_path(json, "$.messages").and_then(|value| value.as_array()) {
        let extracted = messages
            .iter()
            .filter_map(|message| extract_message_entry(message, "content"))
            .collect::<Vec<_>>();
        if !extracted.is_empty() {
            return extracted;
        }
    }

    if let Some(input) = json_path(json, "$.input") {
        let extracted = extract_input_messages(input);
        if !extracted.is_empty() {
            return extracted;
        }
    }

    if let Some(contents) = json_path(json, "$.contents").and_then(|value| value.as_array()) {
        let extracted = contents
            .iter()
            .filter_map(|entry| {
                let role = entry
                    .get("role")
                    .and_then(|value| value.as_str())
                    .unwrap_or("user")
                    .to_string();
                let value = entry
                    .get("content")
                    .or_else(|| entry.get("parts"))
                    .or_else(|| entry.get("text"))
                    .or_else(|| entry.get("input"))?;
                extract_content_string(value).map(|content| (role, content))
            })
            .collect::<Vec<_>>();
        if !extracted.is_empty() {
            return extracted;
        }
    }

    for path in [
        "$.prompt",
        "$.query",
        "$.question",
        "$.text",
        "$.message",
        "$.user_input",
    ] {
        if let Some(value) = json_path(json, path).and_then(extract_content_string) {
            return vec![("user".to_string(), value)];
        }
    }

    Vec::new()
}

fn extract_input_messages(input: &Value) -> Vec<(String, String)> {
    match input {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                if let Some((role, content)) = extract_message_entry(item, "content") {
                    return Some((role, content));
                }
                extract_content_string(item).map(|content| ("user".to_string(), content))
            })
            .collect(),
        Value::Object(_) => {
            if let Some((role, content)) = extract_message_entry(input, "content") {
                return vec![(role, content)];
            }
            extract_content_string(input)
                .map(|content| vec![("user".to_string(), content)])
                .unwrap_or_default()
        }
        _ => extract_content_string(input)
            .map(|content| vec![("user".to_string(), content)])
            .unwrap_or_default(),
    }
}

fn extract_message_entry(value: &Value, default_content_field: &str) -> Option<(String, String)> {
    let role = value
        .get("role")
        .and_then(|raw| raw.as_str())
        .unwrap_or("user")
        .to_string();

    let content_value = value
        .get(default_content_field)
        .or_else(|| value.get("input"))
        .or_else(|| value.get("text"))
        .or_else(|| value.get("message"))?;
    let content = extract_content_string(content_value)?;

    Some((role, content))
}

fn extract_content_string(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => Some(normalize_unicodeish(raw)),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(|item| {
                    item.get("text")
                        .or_else(|| item.get("input_text"))
                        .or_else(|| item.get("content"))
                        .and_then(extract_content_string)
                        .or_else(|| extract_string(item).map(|raw| normalize_unicodeish(&raw)))
                })
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            if joined.is_empty() {
                None
            } else {
                Some(joined)
            }
        }
        Value::Object(map) => map
            .get("text")
            .or_else(|| map.get("input_text"))
            .or_else(|| map.get("content"))
            .or_else(|| map.get("message"))
            .or_else(|| map.get("input"))
            .and_then(extract_content_string),
        Value::Bool(_) | Value::Number(_) => {
            extract_string(value).map(|raw| normalize_unicodeish(&raw))
        }
        Value::Null => None,
    }
}

fn infer_endpoint_type(path: &str) -> EndpointType {
    let lower = path.to_ascii_lowercase();
    if lower.contains("embeddings") || lower.contains("embed") {
        return EndpointType::Embedding;
    }
    if lower.contains("chat")
        || lower.contains("message")
        || lower.contains("conversation")
        || lower.contains("response")
        || lower.contains("generatecontent")
        || lower.contains("streamgeneratecontent")
    {
        return EndpointType::ChatCompletion;
    }
    if lower.contains("completion") {
        return EndpointType::TextCompletion;
    }
    EndpointType::Unknown
}

fn extract_api_version(
    headers: &crate::types::HeaderMap,
    path: &str,
    format: &DetectedFormat,
) -> Option<String> {
    match format {
        DetectedFormat::AnthropicRest => {
            crate::util::header_value(headers, "anthropic-version").map(str::to_string)
        }
        DetectedFormat::GeminiRest => extract_path_version(path),
        DetectedFormat::BedrockRest => crate::util::header_value(headers, "x-amz-api-version")
            .map(str::to_string)
            .or_else(|| extract_path_version(path)),
        _ => extract_path_version(path),
    }
}

fn extract_path_version(path: &str) -> Option<String> {
    let path_lc = path.to_ascii_lowercase();
    for segment in path_lc.split('/') {
        if segment.starts_with('v') && segment.len() > 1 {
            let rest = &segment[1..];
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                return Some(segment.to_string());
            }
        }
    }
    None
}

/// Try to extract the user prompt by matching the request path against
/// feature URL patterns and using the matching feature's `request.fields.prompt`.
fn extract_prompt_from_feature(
    desc: &RestFormatDescriptor,
    path: &str,
    method: &str,
    json: &Value,
) -> Option<String> {
    let path_only = path.split('?').next().unwrap_or(path);
    for feature in &desc.features {
        if feature.feature_type != "chat" {
            continue;
        }
        let pattern_matches = feature.patterns.iter().any(|p| {
            let method_ok = p
                .method
                .as_deref()
                .map_or(true, |m| m.eq_ignore_ascii_case(method));
            method_ok && crate::glob_match(&p.url, path_only)
        });
        if !pattern_matches {
            continue;
        }
        if let Some(prompt_path) = feature.request.fields.get("prompt") {
            if let Some(value) = json_path(json, prompt_path) {
                if let Some(text) = extract_string(value) {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Returns `true` when the descriptor's primary chat feature uses the
/// WebSocket protocol, meaning the initial HTTP request is a GET upgrade
/// with no body.
fn is_websocket_feature(desc: &RestFormatDescriptor) -> bool {
    desc.features
        .iter()
        .any(|f| f.feature_type == "chat" && f.protocol == "websocket")
}

fn parser_id_for_format(format: &DetectedFormat, descriptor: Option<&RestFormatDescriptor>) -> String {
    match format {
        DetectedFormat::OpenAIRest => "openai-v1".to_string(),
        DetectedFormat::AnthropicRest => "anthropic-v1".to_string(),
        DetectedFormat::CohereRest => "cohere-v1".to_string(),
        DetectedFormat::GeminiRest => "gemini-v1".to_string(),
        DetectedFormat::BedrockRest => "bedrock-v1".to_string(),
        DetectedFormat::CustomRest(_) => {
            // Use the bundle's provider_hint as parser_id — the cloud import
            // pipeline sets provider_hint = parser_id (e.g. "bing-copilot").
            descriptor
                .and_then(|d| d.provider_hint.as_deref())
                .map(str::to_string)
                .unwrap_or_else(|| "custom-rest-v1".to_string())
        }
        _ => "rest-v1".to_string(),
    }
}

/// Decode the request body according to the descriptor's encoding type.
///
/// `pre_parsed` is an optional pre-parsed JSON value.  When the encoding is
/// `Json` and there are no preprocess operations the caller's already-parsed
/// value is cloned (shallow, O(1) for references) instead of re-parsing from
/// bytes.  For all other encodings, or when a preprocess pipeline must
/// transform the raw value, the full decode path is taken.
fn decode_request_body(
    req: &RawRequest,
    desc: &RestFormatDescriptor,
    pre_parsed: Option<&Value>,
) -> Result<Value, ParseError> {
    if let (RequestEncoding::Json, Some(v), true) =
        (&desc.encoding, pre_parsed, desc.preprocess.is_empty())
    {
        return Ok(v.clone());
    }

    let raw_json = match desc.encoding {
        RequestEncoding::Json => serde_json::from_slice(&req.body)
            .map_err(|e| ParseError::MalformedBody(e.to_string()))?,
        RequestEncoding::Form => {
            let body_str = std::str::from_utf8(&req.body)
                .map_err(|e| ParseError::MalformedBody(e.to_string()))?;
            decode_form_body(body_str, desc.form_field.as_deref())?
        }
        RequestEncoding::QueryParams => decode_query_params(&req.path),
    };

    apply_preprocess(raw_json, &desc.preprocess)
}

/// Extract and parse a form-encoded body field.
fn decode_form_body(body: &str, form_field: Option<&str>) -> Result<Value, ParseError> {
    let field = form_field.unwrap_or("data");
    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if key == field {
            let decoded = percent_decode(value);
            // Try parsing as JSON; if it fails, wrap as string for preprocess pipeline
            return match serde_json::from_str::<Value>(&decoded) {
                Ok(json) => Ok(json),
                Err(_) => Ok(Value::String(decoded)),
            };
        }
    }
    // Field not found — try parsing entire body as JSON fallback
    serde_json::from_str(body).map_err(|e| ParseError::MalformedBody(e.to_string()))
}

/// Build a JSON object from URL query parameters.
fn decode_query_params(path: &str) -> Value {
    let query = path.split('?').nth(1).unwrap_or("");
    let mut map = serde_json::Map::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if !key.is_empty() {
            map.insert(key.to_string(), Value::String(percent_decode(value)));
        }
    }
    Value::Object(map)
}

/// Simple percent-decoding (no external dependency).
fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Apply a preprocessing pipeline to a JSON value.
fn apply_preprocess(mut value: Value, ops: &[PreprocessOp]) -> Result<Value, ParseError> {
    for op in ops {
        match op.op.as_str() {
            "json_parse" => {
                if let Some(s) = value.as_str() {
                    value = serde_json::from_str(s).map_err(|e| {
                        ParseError::MalformedBody(format!("preprocess json_parse: {e}"))
                    })?;
                }
            }
            "index" => {
                let idx = op.value.as_ref().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                value = value
                    .as_array()
                    .and_then(|arr| arr.get(idx).cloned())
                    .unwrap_or(Value::Null);
            }
            _ => {} // Unknown op — skip
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PreprocessOp, RequestEncoding};
    use bytes::Bytes;
    use soth_core::{ConnectionMeta, SocketFamily};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use uuid::Uuid;

    fn test_meta() -> ConnectionMeta {
        ConnectionMeta {
            connection_id: Uuid::new_v4(),
            socket_family: SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            process_info: None,
            tls_info: None,
            app_identity: None,
            capture_mode: None,
            matched_provider: None,
            matched_application: None,
            h2_connection_id: None,
            h2_stream_id: None,
        }
    }

    fn raw(method: &str, path: &str, body: &[u8]) -> RawRequest {
        RawRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: Default::default(),
            body: Bytes::copy_from_slice(body),
            connection_meta: test_meta(),
        }
    }

    #[test]
    fn decode_json_body_default() {
        let desc = RestFormatDescriptor::default();
        let req = raw("POST", "/v1/chat", br#"{"model":"gpt-4o","messages":[]}"#);
        let json = decode_request_body(&req, &desc, None).unwrap();
        assert_eq!(json.get("model").unwrap().as_str().unwrap(), "gpt-4o");
    }

    #[test]
    fn decode_json_body_uses_pre_parsed() {
        let desc = RestFormatDescriptor::default();
        let req = raw("POST", "/v1/chat", b"THIS IS NOT VALID JSON");
        // pre_parsed takes precedence over the raw bytes when encoding=Json and
        // preprocess is empty.
        let pre = serde_json::json!({"model": "gpt-4o-pre"});
        let json = decode_request_body(&req, &desc, Some(&pre)).unwrap();
        assert_eq!(json.get("model").unwrap().as_str().unwrap(), "gpt-4o-pre");
    }

    #[test]
    fn decode_form_body_extracts_field() {
        let desc = RestFormatDescriptor {
            encoding: RequestEncoding::Form,
            form_field: Some("variables".to_string()),
            ..Default::default()
        };
        let req = raw(
            "POST",
            "/api/graphql",
            b"variables=%7B%22message%22%3A%22hello%22%7D&other=1",
        );
        let json = decode_request_body(&req, &desc, None).unwrap();
        assert_eq!(json.get("message").unwrap().as_str().unwrap(), "hello");
    }

    #[test]
    fn decode_form_with_preprocess_pipeline() {
        // Simulates Gemini-style: form field → json_parse → index(1) → json_parse
        let inner = serde_json::json!(["prompt text", "conv-id"]);
        let outer = serde_json::json!(["unused", inner.to_string()]);
        let encoded = format!("f.req={}", percent_encode(&outer.to_string()));

        let desc = RestFormatDescriptor {
            encoding: RequestEncoding::Form,
            form_field: Some("f.req".to_string()),
            preprocess: vec![
                PreprocessOp {
                    op: "json_parse".to_string(),
                    value: None,
                },
                PreprocessOp {
                    op: "index".to_string(),
                    value: Some(serde_json::json!(1)),
                },
                PreprocessOp {
                    op: "json_parse".to_string(),
                    value: None,
                },
            ],
            ..Default::default()
        };
        let req = raw("POST", "/generate", encoded.as_bytes());
        let json = decode_request_body(&req, &desc, None).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr[0].as_str().unwrap(), "prompt text");
        assert_eq!(arr[1].as_str().unwrap(), "conv-id");
    }

    #[test]
    fn decode_query_params_extracts_fields() {
        let desc = RestFormatDescriptor {
            encoding: RequestEncoding::QueryParams,
            ..Default::default()
        };
        let req = raw("GET", "/search?q=hello+world&selectedChatModel=gpt-4o", b"");
        let json = decode_request_body(&req, &desc, None).unwrap();
        assert_eq!(json.get("q").unwrap().as_str().unwrap(), "hello world");
        assert_eq!(
            json.get("selectedChatModel").unwrap().as_str().unwrap(),
            "gpt-4o"
        );
    }

    #[test]
    fn percent_decode_handles_special_chars() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%7B%22k%22%3A1%7D"), r#"{"k":1}"#);
    }

    #[test]
    fn preprocess_json_parse_and_index() {
        let ops = vec![
            PreprocessOp {
                op: "json_parse".to_string(),
                value: None,
            },
            PreprocessOp {
                op: "index".to_string(),
                value: Some(serde_json::json!(0)),
            },
        ];
        let input = Value::String(r#"["first","second"]"#.to_string());
        let result = apply_preprocess(input, &ops).unwrap();
        assert_eq!(result.as_str().unwrap(), "first");
    }

    /// Simple percent-encoding for test data.
    fn percent_encode(input: &str) -> String {
        let mut out = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                _ => {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
        }
        out
    }
}
