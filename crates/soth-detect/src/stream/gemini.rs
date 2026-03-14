use crate::util::extract_string;

/// Extract content from Gemini web's length-prefixed streaming format.
///
/// Gemini web responses start with `)]}'` followed by a newline, then JSON array lines.
/// Content is extracted heuristically from nested arrays by finding the longest string.
pub fn extract_gemini_length_prefixed(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;

    // Must start with )]}'  to be identified as Gemini length-prefixed format.
    let json_text = text.strip_prefix(")]}'")?.trim_start();

    // Try parsing the JSON content
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) {
        // Try known paths using direct array indexing
        // $[0][2] - common streaming delta
        if let Some(content) = value.get(0).and_then(|v| v.get(2)).and_then(extract_string) {
            if !content.is_empty() {
                return Some(content);
            }
        }
        // $[4][0][1][0] - from response descriptor
        if let Some(content) = value
            .get(4)
            .and_then(|v| v.get(0))
            .and_then(|v| v.get(1))
            .and_then(|v| v.get(0))
            .and_then(extract_string)
        {
            if !content.is_empty() {
                return Some(content);
            }
        }
        // Fallback: find the longest string in the structure
        if let Some(content) = find_longest_string_in_value(&value, 20) {
            return Some(content);
        }
    }

    // Try line-by-line (Gemini sometimes returns multiple JSON lines)
    for line in json_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(content) = find_longest_string_in_value(&value, 20) {
                return Some(content);
            }
        }
    }

    None
}

/// Find the longest string value in a JSON tree (for heuristic content extraction).
fn find_longest_string_in_value(value: &serde_json::Value, min_len: usize) -> Option<String> {
    let mut best: Option<String> = None;
    visit_json_strings(value, &mut |s| {
        if s.len() >= min_len {
            let should_replace = best.as_ref().map_or(true, |b| s.len() > b.len());
            if should_replace {
                best = Some(s.to_string());
            }
        }
    });
    best
}

fn visit_json_strings(value: &serde_json::Value, visit: &mut dyn FnMut(&str)) {
    match value {
        serde_json::Value::String(s) => visit(s),
        serde_json::Value::Array(items) => {
            for item in items {
                visit_json_strings(item, visit);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                visit_json_strings(v, visit);
            }
        }
        _ => {}
    }
}
