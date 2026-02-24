use crate::types::HeaderMap;
use serde_json::Value;

pub fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn host_without_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

pub fn json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path == "$" {
        return Some(value);
    }
    let path = path.strip_prefix("$.").unwrap_or(path);
    let mut current = value;

    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }

        if let Some((name, idx)) = parse_indexed_segment(segment) {
            current = current.get(name)?;
            current = current.get(idx)?;
            continue;
        }

        if let Ok(index) = segment.parse::<usize>() {
            current = current.get(index)?;
            continue;
        }

        current = current.get(segment)?;
    }

    Some(current)
}

pub fn extract_string(value: &Value) -> Option<String> {
    match value {
        Value::String(v) => Some(v.to_string()),
        Value::Number(v) => Some(v.to_string()),
        Value::Bool(v) => Some(v.to_string()),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(extract_string)
                .collect::<Vec<_>>()
                .join(" ");
            if joined.is_empty() {
                None
            } else {
                Some(joined)
            }
        }
        Value::Object(map) => {
            if let Some(text) = map.get("text") {
                return extract_string(text);
            }
            if let Some(content) = map.get("content") {
                return extract_string(content);
            }
            None
        }
        Value::Null => None,
    }
}

pub fn normalize_unicodeish(input: &str) -> String {
    input.trim().to_string()
}

pub fn extract_grpc_service_method(path: &str) -> Option<(String, String)> {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.rsplitn(2, '/');
    let method = parts.next()?;
    let service = parts.next()?;
    if service.is_empty() || method.is_empty() {
        return None;
    }
    Some((service.to_string(), method.to_string()))
}

pub fn grpc_request_path<'a>(headers: &'a HeaderMap, fallback_path: &'a str) -> &'a str {
    if let Some(path) = header_value(headers, ":path") {
        return path;
    }
    if let Some(path) = header_value(headers, "x-grpc-path") {
        return path;
    }
    fallback_path
}

fn parse_indexed_segment(segment: &str) -> Option<(&str, usize)> {
    let start = segment.find('[')?;
    let end = segment.find(']')?;
    if start == 0 || end <= start + 1 {
        return None;
    }

    let field = &segment[..start];
    let index = segment[start + 1..end].parse::<usize>().ok()?;
    Some((field, index))
}
