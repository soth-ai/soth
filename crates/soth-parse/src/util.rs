use crate::types::HeaderMap;
use serde_json::Value;
use std::collections::HashMap;

// Re-export from soth-core (canonical location after B5 type unification).
pub use soth_core::bundle::detect::{glob_match, host_without_port};

pub fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn lookup_domain_provider<'a>(
    domain_index: &'a HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let normalized_host = host_without_port(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if let Some(provider) = domain_index.get(&normalized_host) {
        return Some(provider.as_str());
    }

    let mut best: Option<(&str, usize)> = None;
    for (pattern, provider) in domain_index {
        if !pattern.contains('*') {
            continue;
        }

        let pattern_lc = pattern.to_ascii_lowercase();
        if !glob_match(&pattern_lc, &normalized_host) {
            continue;
        }

        let specificity = pattern_lc.chars().filter(|c| *c != '*').count();
        match best {
            Some((_, best_specificity)) if best_specificity >= specificity => {}
            _ => best = Some((provider.as_str(), specificity)),
        }
    }

    best.map(|(provider, _)| provider)
}

pub fn json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path == "$" {
        return Some(value);
    }

    // Root-array indexing: $[0][0], $[4][0][1][0]
    if path.starts_with("$[") {
        return json_path_root_array(value, path);
    }

    let path = path.strip_prefix("$.").unwrap_or(path);
    let mut current = value;

    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }

        if let Some((name, idx)) = parse_indexed_segment(segment) {
            current = current.get(name)?;
            current = current.get(idx as usize)?;
            continue;
        }

        if let Ok(index) = segment.parse::<usize>() {
            current = current.get(index)?;
            continue;
        }

        // Negative index on bare segment: e.g. from split on "messages[-1]"
        if let Some((name, neg_idx)) = parse_negative_indexed_segment(segment) {
            current = current.get(name)?;
            let arr = current.as_array()?;
            let resolved = arr.len().checked_sub(neg_idx)?;
            current = arr.get(resolved)?;
            continue;
        }

        current = current.get(segment)?;
    }

    Some(current)
}

/// Resolve an index that may be negative (from the end of an array).
fn resolve_index(value: &Value, idx: i64) -> Option<&Value> {
    if idx >= 0 {
        value.get(idx as usize)
    } else {
        let arr = value.as_array()?;
        let resolved = arr.len().checked_sub(idx.unsigned_abs() as usize)?;
        arr.get(resolved)
    }
}

/// Handle root-array paths like `$[0][0]`, `$[4][0][1][0]`.
fn json_path_root_array<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    let mut rest = path.strip_prefix('$')?;

    // Consume consecutive [N] segments
    while let Some(bracket_start) = rest.strip_prefix('[') {
        let end = bracket_start.find(']')?;
        let idx_str = &bracket_start[..end];
        let idx: i64 = idx_str.parse().ok()?;
        current = resolve_index(current, idx)?;
        rest = &bracket_start[end + 1..];
    }

    // If there's a remaining dot-path after the brackets, recurse
    if let Some(dot_rest) = rest.strip_prefix('.') {
        if !dot_rest.is_empty() {
            return json_path(current, dot_rest);
        }
    }

    Some(current)
}

/// Parse `field[-1]` → ("field", 1) for negative indexing.
fn parse_negative_indexed_segment(segment: &str) -> Option<(&str, usize)> {
    let start = segment.find('[')?;
    let end = segment.find(']')?;
    if start == 0 || end <= start + 1 {
        return None;
    }
    let field = &segment[..start];
    let idx_str = &segment[start + 1..end];
    if !idx_str.starts_with('-') {
        return None;
    }
    let neg: usize = idx_str[1..].parse().ok()?;
    Some((field, neg))
}

/// Extract a query parameter value from a URL string.
pub fn extract_query_param(url: &str, param_name: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next()?;
        let val = kv.next().unwrap_or("");
        if key == param_name {
            return Some(simple_url_decode(val));
        }
    }
    None
}

/// Simple percent-decode without pulling in the `percent_encoding` crate.
fn simple_url_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().copied().unwrap_or(b'0');
            let lo = chars.next().copied().unwrap_or(b'0');
            let byte = (hex_digit(hi) << 4) | hex_digit(lo);
            out.push(byte as char);
        } else if b == b'+' {
            out.push(' ');
        } else {
            out.push(b as char);
        }
    }
    out
}

fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Extract a URL path segment by index. Negative indices count from the end.
pub fn extract_url_segment(url: &str, index: i32) -> Option<String> {
    let path = url.split('?').next().unwrap_or(url);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let resolved = if index >= 0 {
        index as usize
    } else {
        segments.len().checked_sub(index.unsigned_abs() as usize)?
    };
    segments.get(resolved).map(|s| s.to_string())
}

/// Resolve a DSL extraction path, which may be a json_path, `$_query_param('name')`,
/// or `$_url_segment(-2)`.
pub fn resolve_path<'a>(
    path: &str,
    body: &'a Value,
    url: Option<&str>,
) -> Option<Value> {
    // $_query_param('name')
    if let Some(inner) = path
        .strip_prefix("$_query_param('")
        .and_then(|s| s.strip_suffix("')"))
    {
        return extract_query_param(url?, inner).map(Value::String);
    }

    // $_url_segment(-2)
    if let Some(inner) = path
        .strip_prefix("$_url_segment(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let idx: i32 = inner.parse().ok()?;
        return extract_url_segment(url?, idx).map(Value::String);
    }

    // Standard json_path
    json_path(body, path).cloned()
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

fn parse_indexed_segment(segment: &str) -> Option<(&str, i64)> {
    let start = segment.find('[')?;
    let end = segment.find(']')?;
    if start == 0 || end <= start + 1 {
        return None;
    }

    let field = &segment[..start];
    let idx_str = &segment[start + 1..end];
    // Skip negative indices — handled by parse_negative_indexed_segment
    if idx_str.starts_with('-') {
        return None;
    }
    let index = idx_str.parse::<i64>().ok()?;
    Some((field, index))
}

