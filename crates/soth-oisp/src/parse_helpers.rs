use crate::types::provider::StreamFormat;
use crate::{ProviderUsage, StreamParserConfig, StreamRuleConfig};
use serde_json::Value;

pub(crate) fn format_uses_strip_xssi(format_value: &Value) -> bool {
    let Some(body_transform) = format_value.get("body_transform") else {
        return false;
    };

    match body_transform {
        Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            normalized == "strip_xssi" || normalized == "strip-xssi"
        }
        Value::Array(entries) => entries.iter().any(|entry| {
            entry
                .as_str()
                .map(|raw| {
                    let normalized = raw.trim().to_ascii_lowercase();
                    normalized == "strip_xssi" || normalized == "strip-xssi"
                })
                .unwrap_or(false)
        }),
        Value::Object(map) => {
            map.contains_key("strip_prefix")
                || map
                    .get("strip_xssi")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

pub(crate) fn format_uses_grpc_frames(format_value: &Value) -> bool {
    let Some(body_transform) = format_value.get("body_transform") else {
        return false;
    };

    match body_transform {
        Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            normalized == "grpc_frames" || normalized == "grpc-frames"
        }
        Value::Array(entries) => entries.iter().any(|entry| {
            entry
                .as_str()
                .map(|raw| {
                    let normalized = raw.trim().to_ascii_lowercase();
                    normalized == "grpc_frames" || normalized == "grpc-frames"
                })
                .unwrap_or(false)
        }),
        Value::Object(map) => map
            .get("grpc_frames")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

pub(crate) fn strip_json_security_prefix_bytes(payload: &[u8]) -> &[u8] {
    let Ok(text) = std::str::from_utf8(payload) else {
        return payload;
    };
    let stripped = strip_json_security_prefix_text(text);
    if stripped.len() == text.len() {
        payload
    } else {
        stripped.as_bytes()
    }
}

pub(crate) fn strip_json_security_prefix_text(text: &str) -> &str {
    let trimmed = text.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    for prefix in [")]}'", ")]}',", "for(;;);", "while(1);"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest
                .trim_start_matches(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';');
        }
    }
    text
}

pub(crate) fn parse_json_with_xssi_fallback(payload: &[u8]) -> Option<Value> {
    if let Ok(root) = serde_json::from_slice::<Value>(payload) {
        return Some(root);
    }

    let stripped = strip_json_security_prefix_bytes(payload);
    if stripped.len() != payload.len() {
        return serde_json::from_slice::<Value>(stripped).ok();
    }

    None
}

pub(crate) fn extract_usage_from_response_value(
    payload: &[u8],
    response: &Value,
) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw_signal = false;

    if let Some(root) = parse_json_with_xssi_fallback(payload) {
        if let Some(parsed) = extract_usage_from_json_value(&root, response) {
            merge_provider_usage(&mut aggregate, parsed);
            saw_signal = saw_signal || aggregate.has_signal();
        }
    }

    let text = std::str::from_utf8(payload).ok()?;

    if let Some(parsed) = extract_from_batchexecute_wrapped_payloads(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if let Some(parsed) = extract_from_json_lines(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if let Some(parsed) = extract_from_sse_lines(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if saw_signal || aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_usage_from_json_value(root: &Value, response: &Value) -> Option<ProviderUsage> {
    let mut out = ProviderUsage::default();

    if let Some(json) = response.get("json") {
        apply_json_extract(out_ref(&mut out), root, json.get("extract"));
        apply_usage_extract(out_ref(&mut out), root, json.get("extract_usage"));
    }

    if let Some(non_streaming) = response.get("non_streaming") {
        apply_json_extract(out_ref(&mut out), root, non_streaming.get("extract"));
        apply_usage_extract(out_ref(&mut out), root, non_streaming.get("extract_usage"));
    }

    if let Some(streaming) = response.get("streaming") {
        if let Some(rules) = streaming.get("rules").and_then(Value::as_array) {
            for rule in rules {
                if !rule_matches(rule.get("when").and_then(Value::as_str), root) {
                    continue;
                }
                apply_json_extract(out_ref(&mut out), root, rule.get("extract"));
                apply_usage_extract(out_ref(&mut out), root, rule.get("extract_usage"));
            }
        }
    }

    if out.has_signal() {
        Some(out)
    } else {
        None
    }
}

fn out_ref(out: &mut ProviderUsage) -> &mut ProviderUsage {
    out
}

fn apply_json_extract(out: &mut ProviderUsage, root: &Value, extract_map: Option<&Value>) {
    let Some(map) = extract_map.and_then(Value::as_object) else {
        return;
    };

    if out.model.is_none() {
        if let Some(path) = map.get("model") {
            out.model = extract_string_from_field_path_value(root, path);
        }
    }
}

fn apply_usage_extract(out: &mut ProviderUsage, root: &Value, usage_map: Option<&Value>) {
    let Some(map) = usage_map.and_then(Value::as_object) else {
        return;
    };

    for (field, path_spec) in map {
        let value = extract_u64_from_field_path_value(root, path_spec);
        match field.as_str() {
            "input_tokens" | "prompt_tokens" => {
                out.input_tokens = merge_token(out.input_tokens, value);
            }
            "output_tokens" | "completion_tokens" => {
                out.output_tokens = merge_token(out.output_tokens, value);
            }
            "cache_read_tokens" | "cache_read_input_tokens" => {
                out.cache_read_tokens = Some(merge_option_token(out.cache_read_tokens, value));
            }
            "cache_write_tokens" | "cache_creation_input_tokens" => {
                out.cache_write_tokens = Some(merge_option_token(out.cache_write_tokens, value));
            }
            "reasoning_tokens" => {
                out.reasoning_tokens = Some(merge_option_token(out.reasoning_tokens, value));
            }
            _ => {}
        }
    }
}

fn merge_token(current: u64, next: Option<u64>) -> u64 {
    let Some(next) = next else {
        return current;
    };
    if current == 0 {
        return next;
    }
    if next >= current {
        next
    } else {
        current.saturating_add(next)
    }
}

fn merge_option_token(current: Option<u64>, next: Option<u64>) -> u64 {
    merge_token(current.unwrap_or(0), next)
}

fn merge_provider_usage(current: &mut ProviderUsage, next: ProviderUsage) {
    current.input_tokens = merge_token(current.input_tokens, Some(next.input_tokens));
    current.output_tokens = merge_token(current.output_tokens, Some(next.output_tokens));
    current.cache_read_tokens = Some(merge_option_token(
        current.cache_read_tokens,
        next.cache_read_tokens,
    ));
    current.cache_write_tokens = Some(merge_option_token(
        current.cache_write_tokens,
        next.cache_write_tokens,
    ));
    current.reasoning_tokens = Some(merge_option_token(
        current.reasoning_tokens,
        next.reasoning_tokens,
    ));
    if current.model.is_none() {
        current.model = normalize_string(next.model);
    }
}

fn extract_from_json_lines(text: &str, response: &Value) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(parsed) = extract_usage_from_json_value(&value, response) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_from_batchexecute_wrapped_payloads(
    text: &str,
    response: &Value,
) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = strip_json_security_prefix_text(line.trim()).trim();
        if trimmed.is_empty() || !trimmed.starts_with('[') {
            continue;
        }
        let Ok(wrapper) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(records) = wrapper.as_array() else {
            continue;
        };
        for record in records {
            let Some(entry) = record.as_array() else {
                continue;
            };
            if entry.first().and_then(Value::as_str) != Some("wrb.fr") {
                continue;
            }
            let Some(inner_json) = entry.get(2).and_then(Value::as_str) else {
                continue;
            };
            let Ok(inner) = serde_json::from_str::<Value>(inner_json) else {
                continue;
            };

            if let Some(parsed) = extract_usage_from_json_value(&inner, response) {
                saw = true;
                merge_provider_usage(&mut aggregate, parsed);
            }
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_from_sse_lines(text: &str, response: &Value) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r').trim_start();
        if let Some(payload) = trimmed.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(payload) else {
                continue;
            };
            if let Some(parsed) = extract_usage_from_json_value(&value, response) {
                saw = true;
                merge_provider_usage(&mut aggregate, parsed);
            }
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

pub(crate) fn parse_stream_parser_config(stream: &Value) -> Option<StreamParserConfig> {
    let format = stream
        .get("format")
        .cloned()
        .and_then(|v| serde_json::from_value::<StreamFormat>(v).ok())?;

    let prefixes = stream
        .get("format_options")
        .and_then(|v| v.get("prefixes"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["data: ".to_string()]);

    let skip_values = stream
        .get("format_options")
        .and_then(|v| v.get("skip_values"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["[DONE]".to_string()]);

    let header_strip = stream
        .get("format_options")
        .and_then(|v| v.get("header_strip"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let rules = stream
        .get("rules")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(parse_stream_rule_config)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(StreamParserConfig {
        format,
        prefixes,
        skip_values,
        header_strip,
        rules,
    })
}

fn parse_stream_rule_config(value: &Value) -> Option<StreamRuleConfig> {
    let obj = value.as_object()?;
    let when = obj
        .get("when")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let extract = obj
        .get("extract")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let extract_usage = obj
        .get("extract_usage")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(StreamRuleConfig {
        when,
        extract,
        extract_usage,
    })
}

pub(crate) fn parse_stream_payload_with_config(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    match config.format {
        StreamFormat::Sse => parse_sse_stream_payload(payload, config),
        StreamFormat::Ndjson => parse_ndjson_stream_payload(payload, config),
        StreamFormat::LengthPrefixed => parse_length_prefixed_stream_payload(payload, config),
        StreamFormat::Websocket => parse_ndjson_stream_payload(payload, config),
    }
}

fn parse_sse_stream_payload(payload: &[u8], config: &StreamParserConfig) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r').trim_start();
        let content = if let Some(prefix) = config
            .prefixes
            .iter()
            .find(|prefix| trimmed.starts_with(prefix.as_str()))
        {
            trimmed[prefix.len()..].trim()
        } else {
            continue;
        };

        if content.is_empty()
            || config
                .skip_values
                .iter()
                .any(|skip| skip.eq_ignore_ascii_case(content))
        {
            continue;
        }

        let Ok(value) = serde_json::from_str::<Value>(content) else {
            continue;
        };
        if let Some(parsed) = apply_stream_rules(&value, config) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn parse_ndjson_stream_payload(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(parsed) = apply_stream_rules(&value, config) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn parse_length_prefixed_stream_payload(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let stripped = if let Some(prefix) = config.header_strip.as_deref() {
        text.strip_prefix(prefix).unwrap_or(text)
    } else {
        text
    };
    parse_ndjson_stream_payload(stripped.as_bytes(), config)
        .or_else(|| parse_sse_stream_payload(stripped.as_bytes(), config))
}

fn apply_stream_rules(root: &Value, config: &StreamParserConfig) -> Option<ProviderUsage> {
    let mut out = ProviderUsage::default();
    let mut matched = false;

    for rule in &config.rules {
        if !rule_matches(rule.when.as_deref(), root) {
            continue;
        }
        matched = true;
        for (field, path_spec) in &rule.extract {
            if field == "model" && out.model.is_none() {
                out.model = extract_string_from_field_path_value(root, path_spec);
            }
        }
        for (field, path_spec) in &rule.extract_usage {
            let value = extract_u64_from_field_path_value(root, path_spec);
            match field.as_str() {
                "input_tokens" | "prompt_tokens" => {
                    out.input_tokens = merge_token(out.input_tokens, value)
                }
                "output_tokens" | "completion_tokens" => {
                    out.output_tokens = merge_token(out.output_tokens, value)
                }
                "cache_read_tokens" | "cache_read_input_tokens" => {
                    out.cache_read_tokens = Some(merge_option_token(out.cache_read_tokens, value))
                }
                "cache_write_tokens" | "cache_creation_input_tokens" => {
                    out.cache_write_tokens = Some(merge_option_token(out.cache_write_tokens, value))
                }
                "reasoning_tokens" => {
                    out.reasoning_tokens = Some(merge_option_token(out.reasoning_tokens, value))
                }
                _ => {}
            }
        }
    }

    if matched && out.has_signal() {
        Some(out)
    } else {
        None
    }
}

fn rule_matches(when: Option<&str>, root: &Value) -> bool {
    let Some(raw) = when.map(str::trim).filter(|w| !w.is_empty()) else {
        return true;
    };

    // Simple conjunction support: `a and b and c`.
    for clause in raw.split(" and ").map(str::trim).filter(|c| !c.is_empty()) {
        if let Some(inner) = clause
            .strip_prefix("$not(")
            .and_then(|value| value.strip_suffix(')'))
        {
            if rule_matches(Some(inner.trim()), root) {
                return false;
            }
            continue;
        }

        if let Some(path) = clause
            .strip_prefix("$exists(")
            .and_then(|value| value.strip_suffix(')'))
            .map(str::trim)
        {
            if extract_field_path_value(root, path).is_none() {
                return false;
            }
            continue;
        }

        if let Some((left, right)) = clause.split_once(" = ") {
            let left = left.trim();
            let right = right.trim().trim_matches('\'').trim_matches('"');
            if left.starts_with("$type(") && left.ends_with(')') {
                let path = left.trim_start_matches("$type(").trim_end_matches(')');
                let Some(value) = extract_field_path_value(root, path.trim()) else {
                    return false;
                };
                let actual = match value {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                };
                if !actual.eq_ignore_ascii_case(right) {
                    return false;
                }
                continue;
            }

            let Some(value) = extract_field_path_value(root, left) else {
                return false;
            };
            let actual = match value {
                Value::String(raw) => raw.as_str(),
                Value::Bool(true) => "true",
                Value::Bool(false) => "false",
                _ => return false,
            };
            if !actual.eq_ignore_ascii_case(right) {
                return false;
            }
            continue;
        }

        // Unknown clause syntax: fail open for compatibility.
    }

    true
}

fn extract_u64_from_field_path_value(root: &Value, field_path: &Value) -> Option<u64> {
    field_path_candidates(field_path)
        .into_iter()
        .find_map(|path| extract_u64_from_path(root, path.as_str()))
}

fn extract_u64_from_path(root: &Value, path: &str) -> Option<u64> {
    let value = extract_field_path_value(root, path)?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().and_then(|raw| u64::try_from(raw).ok()))
            .or_else(|| number.as_f64().map(|raw| raw.max(0.0).round() as u64)),
        Value::String(raw) => raw.trim().parse::<u64>().ok().or_else(|| {
            raw.trim()
                .parse::<f64>()
                .ok()
                .map(|parsed| parsed.max(0.0).round() as u64)
        }),
        _ => None,
    }
}

pub(crate) fn extract_string_from_field_path_value(
    root: &Value,
    field_path: &Value,
) -> Option<String> {
    field_path_candidates(field_path)
        .into_iter()
        .find_map(|path| extract_string_from_path(root, path.as_str()))
}

fn field_path_candidates(field_path: &Value) -> Vec<String> {
    match field_path {
        Value::String(path) => vec![path.clone()],
        Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| entry.as_str().map(|value| value.to_string()))
            .collect(),
        Value::Object(map) => map
            .get("path")
            .and_then(Value::as_str)
            .map(|value| vec![value.to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn extract_string_from_path(root: &Value, path: &str) -> Option<String> {
    let value = extract_field_path_value(root, path)?;
    match value {
        Value::String(raw) => normalize_string(Some(raw.clone())),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(crate) fn normalize_string(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub(crate) fn decode_grpc_frame_payloads(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 5 {
        return None;
    }
    let mut cursor = 0usize;
    let mut out = Vec::with_capacity(payload.len());
    let mut frames = 0usize;

    while cursor + 5 <= payload.len() {
        let flag = payload[cursor];
        if flag > 1 {
            return None;
        }
        let len = u32::from_be_bytes([
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
            payload[cursor + 4],
        ]) as usize;
        let start = cursor + 5;
        let end = start.checked_add(len)?;
        if end > payload.len() {
            return None;
        }
        out.extend_from_slice(&payload[start..end]);
        cursor = end;
        frames += 1;
        if frames > 64 {
            break;
        }
    }

    if frames == 0 {
        None
    } else {
        Some(out)
    }
}

fn extract_field_path_value<'a>(root: &'a Value, raw_path: &str) -> Option<&'a Value> {
    let normalized = normalize_path(raw_path)?;
    if normalized.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in split_path_segments(normalized.as_str()) {
        current = apply_segment(current, segment.as_str())?;
    }

    Some(current)
}

fn normalize_path(raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_dollar = trimmed
        .strip_prefix("$.")
        .or_else(|| trimmed.strip_prefix('$'))
        .unwrap_or(trimmed);

    let normalized = without_dollar.trim_start_matches('.');
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn split_path_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut bracket_depth: i32 = 0;

    for ch in path.chars() {
        match ch {
            '.' if bracket_depth == 0 => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = (bracket_depth - 1).max(0);
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

fn apply_segment<'a>(value: &'a Value, segment: &str) -> Option<&'a Value> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Some(value);
    }

    let (field, indexes) = parse_segment(segment);

    let mut current = if let Some(field) = field {
        value.get(field)?
    } else {
        value
    };

    for index in indexes {
        let array = current.as_array()?;
        let resolved_index = if index < 0 {
            let from_end = usize::try_from(index.unsigned_abs()).ok()?;
            if from_end == 0 || from_end > array.len() {
                return None;
            }
            array.len() - from_end
        } else {
            usize::try_from(index).ok()?
        };
        current = array.get(resolved_index)?;
    }

    Some(current)
}

fn parse_segment(segment: &str) -> (Option<&str>, Vec<i32>) {
    let first_bracket = segment.find('[');
    let field = first_bracket
        .map(|idx| &segment[..idx])
        .or(Some(segment))
        .map(str::trim)
        .and_then(|value| if value.is_empty() { None } else { Some(value) });

    let mut indexes = Vec::new();
    let mut remaining = first_bracket.map(|idx| &segment[idx..]).unwrap_or("");

    while let Some(open_idx) = remaining.find('[') {
        let tail = &remaining[(open_idx + 1)..];
        let Some(close_idx) = tail.find(']') else {
            break;
        };
        let raw_index = tail[..close_idx].trim();
        if let Ok(parsed) = raw_index.parse::<i32>() {
            indexes.push(parsed);
        }
        remaining = &tail[(close_idx + 1)..];
    }

    (field, indexes)
}
