//! Data-driven streaming extraction engine.
//!
//! Evaluates [`StreamRulesSpec`] against streaming response chunks,
//! replacing hardcoded per-provider extraction logic with configurable
//! rules from the parser DSL.
//!
//! # Condition Language
//!
//! The `when` field on each [`StreamRule`] supports a small expression language:
//!
//! | Syntax | Meaning |
//! |--------|---------|
//! | `$exists(path)` | Field exists and is not null |
//! | `$not($exists(path))` | Field does not exist |
//! | `$type(path) = 'string'` | Type check (string, number, array, object, boolean) |
//! | `field = 'value'` | String equality |
//! | `field = true` / `field = false` | Boolean equality |
//! | `cond1 and cond2` | Logical AND |
//!
//! # Example
//!
//! ```text
//! when: "type = 'content_block_delta' and delta.type = 'text_delta'"
//! extract: { "content": "delta.text" }
//! ```

use std::collections::HashMap;

use serde_json::Value;
use soth_core::bundle::detect::{
    AccumulateOp, PreprocessOp, StreamFormat, StreamFormatOptions, StreamRulesSpec,
};
use soth_parse::grpc::best_grpc_content;
use soth_parse::proto::scan_proto_strings;
use soth_parse::util::{extract_string, json_path};

// ── Accumulator ──────────────────────────────────────────────────────────

/// Accumulator state for a streaming session using rule-based extraction.
#[derive(Debug, Clone, Default)]
pub struct RulesAccumulator {
    /// Per-field accumulated values.
    state: HashMap<String, AccumulatedField>,
}

#[derive(Debug, Clone)]
struct AccumulatedField {
    op: AccumulateKind,
    value: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum AccumulateKind {
    Concat,
    First,
    Last,
}

impl RulesAccumulator {
    /// Create a new accumulator from the accumulate spec.
    pub fn new(spec: &HashMap<String, AccumulateOp>) -> Self {
        let state = spec
            .iter()
            .map(|(field, op)| {
                let kind = match op.op.as_str() {
                    "first" => AccumulateKind::First,
                    "last" => AccumulateKind::Last,
                    _ => AccumulateKind::Concat,
                };
                (
                    field.clone(),
                    AccumulatedField {
                        op: kind,
                        value: None,
                    },
                )
            })
            .collect();
        Self { state }
    }

    /// Push an extracted value for a field.
    pub fn push(&mut self, field: &str, value: &str) {
        let entry = self
            .state
            .entry(field.to_string())
            .or_insert(AccumulatedField {
                op: AccumulateKind::Concat,
                value: None,
            });

        match entry.op {
            AccumulateKind::Concat => {
                const MAX_CONCAT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB cap
                let buf = entry.value.get_or_insert_with(String::new);
                if buf.len() + value.len() <= MAX_CONCAT_BYTES {
                    buf.push_str(value);
                }
            }
            AccumulateKind::First => {
                if entry.value.is_none() {
                    entry.value = Some(value.to_string());
                }
            }
            AccumulateKind::Last => {
                entry.value = Some(value.to_string());
            }
        }
    }

    /// Get a single accumulated field value.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.state.get(field).and_then(|f| f.value.as_deref())
    }
}

// ── Condition evaluator ──────────────────────────────────────────────────

/// Evaluate a condition expression against a JSON value.
///
/// Returns `true` if the condition matches.
pub fn evaluate_condition(condition: &str, value: &Value) -> bool {
    let trimmed = condition.trim();
    if trimmed.is_empty() || trimmed == "true" {
        return true;
    }

    // Logical AND: split on " and " and require all parts to match
    if trimmed.contains(" and ") {
        return trimmed
            .split(" and ")
            .all(|part| evaluate_single_condition(part.trim(), value));
    }

    evaluate_single_condition(trimmed, value)
}

fn evaluate_single_condition(cond: &str, value: &Value) -> bool {
    // $not($exists(path))
    if let Some(inner) = cond.strip_prefix("$not(").and_then(|s| s.strip_suffix(')')) {
        return !evaluate_single_condition(inner.trim(), value);
    }

    // $exists(path)
    if let Some(path) = cond
        .strip_prefix("$exists(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return json_path(value, path.trim()).is_some_and(|v| !v.is_null());
    }

    // $type(path) = 'type_name'
    if cond.starts_with("$type(") {
        if let Some((type_expr, expected)) = cond.split_once(" = ") {
            let path = type_expr
                .strip_prefix("$type(")
                .and_then(|s| s.strip_suffix(')'));
            let expected = expected.trim().trim_matches('\'').trim_matches('"');
            if let Some(path) = path {
                return json_path(value, path.trim()).is_some_and(|v| match expected {
                    "string" => v.is_string(),
                    "number" => v.is_number(),
                    "array" => v.is_array(),
                    "object" => v.is_object(),
                    "boolean" | "bool" => v.is_boolean(),
                    "null" => v.is_null(),
                    _ => false,
                });
            }
        }
        return false;
    }

    // field = 'value' or field = true/false
    if let Some((lhs, rhs)) = cond.split_once(" = ") {
        let lhs = lhs.trim();
        let rhs = rhs.trim();

        let actual = json_path(value, lhs);

        // Boolean comparison: field = true / field = false
        if rhs == "true" {
            return actual.is_some_and(|v| v.as_bool() == Some(true));
        }
        if rhs == "false" {
            return actual.is_some_and(|v| v.as_bool() == Some(false));
        }

        // String comparison: field = 'value' or field = "value"
        let expected = rhs.trim_matches('\'').trim_matches('"');
        return actual.is_some_and(|v| v.as_str() == Some(expected));
    }

    false
}

// ── Chunk splitting ──────────────────────────────────────────────────────

/// Split a raw payload into parseable chunks based on the stream format.
fn split_chunks<'a>(
    text: &'a str,
    format: &StreamFormat,
    options: &StreamFormatOptions,
) -> Vec<&'a str> {
    match format {
        StreamFormat::Sse => split_sse_chunks(text, options),
        StreamFormat::Ndjson => split_ndjson_chunks(text, options),
        StreamFormat::LengthPrefixed => split_length_prefixed_chunks(text, options),
        // WebSocket frames are already individual messages — treat the
        // entire payload as a single chunk (like NDJSON without delimiter).
        StreamFormat::WebSocket => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed]
            }
        }
    }
}

fn split_sse_chunks<'a>(text: &'a str, options: &StreamFormatOptions) -> Vec<&'a str> {
    let prefixes = if options.prefixes.is_empty() {
        vec!["data: ".to_string()]
    } else {
        options.prefixes.clone()
    };
    let skip = &options.skip_values;

    let mut chunks = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Try each prefix
        let json_str = prefixes
            .iter()
            .find_map(|prefix| trimmed.strip_prefix(prefix.as_str()).map(str::trim))
            .unwrap_or_else(|| {
                // Bare JSON (no prefix)
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    trimmed
                } else {
                    ""
                }
            });

        if json_str.is_empty() {
            continue;
        }
        if skip.iter().any(|s| json_str == s.as_str()) {
            continue;
        }
        chunks.push(json_str);
    }
    chunks
}

fn split_ndjson_chunks<'a>(text: &'a str, options: &StreamFormatOptions) -> Vec<&'a str> {
    if let Some(delimiter) = options.delimiter.as_deref() {
        // Custom delimiter (e.g. "}{" for Grok).
        // Split at delimiter boundaries, keeping overlapping braces so
        // each chunk is valid JSON: {"a":1}{"b":2} → ["{"a":1}", "{"b":2}"]
        let mut chunks = Vec::new();
        let mut start = 0;
        while let Some(pos) = text[start..].find(delimiter) {
            let abs_pos = start + pos;
            let end = abs_pos + 1; // include the closing brace
            let chunk = text[start..end].trim();
            if !chunk.is_empty() {
                chunks.push(chunk);
            }
            start = end; // next chunk starts at the opening brace
        }
        let remainder = text[start..].trim();
        if !remainder.is_empty() {
            chunks.push(remainder);
        }
        chunks
    } else {
        text.lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }
}

fn split_length_prefixed_chunks<'a>(text: &'a str, options: &StreamFormatOptions) -> Vec<&'a str> {
    let stripped = if let Some(header) = options.header_strip.as_deref() {
        // Unescape the header_strip pattern (handle \\n → \n)
        let header_unescaped = header.replace("\\n", "\n");
        text.strip_prefix(header_unescaped.as_str())
            .or_else(|| {
                // Try stripping just the literal prefix chars before newline
                text.lines().nth(1).map(|_rest| {
                    let first_newline = text.find('\n').unwrap_or(0);
                    &text[first_newline + 1..]
                })
            })
            .unwrap_or(text)
    } else {
        text
    };

    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        Vec::new()
    } else {
        vec![trimmed]
    }
}

// ── Preprocessing ────────────────────────────────────────────────────────

/// Apply a preprocessing pipeline to a JSON value.
fn apply_preprocess(value: &Value, ops: &[PreprocessOp]) -> Value {
    let mut current = value.clone();
    for op in ops {
        current = apply_single_preprocess(&current, op);
    }
    current
}

fn apply_single_preprocess(value: &Value, op: &PreprocessOp) -> Value {
    match op.op.as_str() {
        "json_parse" => {
            if let Some(s) = value.as_str() {
                serde_json::from_str(s).unwrap_or_else(|_| value.clone())
            } else {
                value.clone()
            }
        }
        "index" => {
            if let Some(idx) = op.value.as_ref().and_then(|v| v.as_u64()) {
                value.get(idx as usize).cloned().unwrap_or(Value::Null)
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

// ── Main extraction entry point ──────────────────────────────────────────

/// Result of rule-based extraction from a single chunk processing pass.
pub struct RulesExtracted {
    pub model: Option<String>,
    pub content: Option<String>,
    pub finish_reason: Option<String>,
}

/// Process a streaming payload using the rules engine.
///
/// This is the data-driven replacement for `extract_sse_rest_delta()`.
/// It splits the payload by format, evaluates rules against each chunk,
/// and accumulates results.
pub fn extract_with_stream_rules(
    payload: &[u8],
    rules_spec: &StreamRulesSpec,
    accumulator: &mut RulesAccumulator,
) -> RulesExtracted {
    // Protobuf-encoded payloads (e.g. ConnectRPC/Cursor): extract the
    // longest readable string from the binary frame instead of trying
    // JSON parsing.  The rules/conditions DSL doesn't apply to binary.
    let is_protobuf = rules_spec
        .format_options
        .encoding
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case("protobuf"));

    if is_protobuf {
        if let Some(content) = best_grpc_content(&scan_proto_strings(payload), 6) {
            accumulator.push("content", &content);
        }
        return RulesExtracted {
            model: accumulator.get("model").map(str::to_string),
            content: accumulator.get("content").map(str::to_string),
            finish_reason: accumulator
                .get("finish_reason")
                .or_else(|| accumulator.get("stop_reason"))
                .map(str::to_string),
        };
    }

    let Ok(text) = std::str::from_utf8(payload) else {
        return RulesExtracted {
            model: None,
            content: None,
            finish_reason: None,
        };
    };

    let chunks = split_chunks(text, &rules_spec.format, &rules_spec.format_options);

    for chunk_str in chunks {
        let Ok(value) = serde_json::from_str::<Value>(chunk_str) else {
            continue;
        };

        for rule in &rules_spec.rules {
            if !evaluate_condition(&rule.when, &value) {
                continue;
            }

            let processed = if rule.preprocess.is_empty() {
                value.clone()
            } else {
                apply_preprocess(&value, &rule.preprocess)
            };

            for (field, path) in &rule.extract {
                if let Some(extracted) = json_path(&processed, path).and_then(extract_string) {
                    accumulator.push(field, &extracted);
                }
            }
        }
    }

    RulesExtracted {
        model: accumulator.get("model").map(str::to_string),
        content: accumulator.get("content").map(str::to_string),
        finish_reason: accumulator
            .get("finish_reason")
            .or_else(|| accumulator.get("stop_reason"))
            .map(str::to_string),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use soth_core::bundle::detect::StreamRule;

    // ── Condition evaluator tests ────────────────────────────────────

    #[test]
    fn condition_exists() {
        let v = json!({"type": "message_start", "message": {"model": "claude-3"}});
        assert!(evaluate_condition("$exists(type)", &v));
        assert!(evaluate_condition("$exists(message.model)", &v));
        assert!(!evaluate_condition("$exists(missing)", &v));
    }

    #[test]
    fn condition_not_exists() {
        let v = json!({"type": "delta"});
        assert!(evaluate_condition("$not($exists(missing))", &v));
        assert!(!evaluate_condition("$not($exists(type))", &v));
    }

    #[test]
    fn condition_string_equality() {
        let v = json!({"type": "content_block_delta", "delta": {"type": "text_delta"}});
        assert!(evaluate_condition("type = 'content_block_delta'", &v));
        assert!(!evaluate_condition("type = 'message_start'", &v));
    }

    #[test]
    fn condition_boolean_equality() {
        let v = json!({"done": true, "active": false});
        assert!(evaluate_condition("done = true", &v));
        assert!(evaluate_condition("active = false", &v));
        assert!(!evaluate_condition("done = false", &v));
    }

    #[test]
    fn condition_type_check() {
        let v = json!({"v": "hello", "n": 42, "a": [1,2]});
        assert!(evaluate_condition("$type(v) = 'string'", &v));
        assert!(evaluate_condition("$type(n) = 'number'", &v));
        assert!(evaluate_condition("$type(a) = 'array'", &v));
        assert!(!evaluate_condition("$type(v) = 'number'", &v));
    }

    #[test]
    fn condition_and() {
        let v =
            json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}});
        assert!(evaluate_condition(
            "type = 'content_block_delta' and delta.type = 'text_delta'",
            &v
        ));
        assert!(!evaluate_condition(
            "type = 'content_block_delta' and delta.type = 'wrong'",
            &v
        ));
    }

    #[test]
    fn condition_empty_is_true() {
        assert!(evaluate_condition("", &json!({})));
        assert!(evaluate_condition("true", &json!({})));
    }

    // ── Accumulator tests ────────────────────────────────────────────

    #[test]
    fn accumulator_concat() {
        let spec: HashMap<String, AccumulateOp> = [(
            "content".to_string(),
            AccumulateOp {
                from: "content".to_string(),
                op: "concat".to_string(),
            },
        )]
        .into_iter()
        .collect();

        let mut acc = RulesAccumulator::new(&spec);
        acc.push("content", "Hello");
        acc.push("content", " world");
        assert_eq!(acc.get("content"), Some("Hello world"));
    }

    #[test]
    fn accumulator_first() {
        let spec: HashMap<String, AccumulateOp> = [(
            "model".to_string(),
            AccumulateOp {
                from: "model".to_string(),
                op: "first".to_string(),
            },
        )]
        .into_iter()
        .collect();

        let mut acc = RulesAccumulator::new(&spec);
        acc.push("model", "gpt-4o");
        acc.push("model", "gpt-4o-mini");
        assert_eq!(acc.get("model"), Some("gpt-4o"));
    }

    #[test]
    fn accumulator_last() {
        let spec: HashMap<String, AccumulateOp> = [(
            "status".to_string(),
            AccumulateOp {
                from: "status".to_string(),
                op: "last".to_string(),
            },
        )]
        .into_iter()
        .collect();

        let mut acc = RulesAccumulator::new(&spec);
        acc.push("status", "running");
        acc.push("status", "done");
        assert_eq!(acc.get("status"), Some("done"));
    }

    // finalize_ternary and finalize_literal tests removed along with
    // the finalize/resolve_finalize_expr/resolve_accumulated_ref methods
    // (dead code — never called from the streaming pipeline).

    // ── SSE splitting tests ──────────────────────────────────────────

    #[test]
    fn split_sse_standard_data_prefix() {
        let payload = "data: {\"content\":\"hi\"}\ndata: [DONE]\n";
        let opts = StreamFormatOptions {
            prefixes: vec!["data: ".to_string()],
            skip_values: vec!["[DONE]".to_string()],
            ..Default::default()
        };
        let chunks = split_sse_chunks(payload, &opts);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "{\"content\":\"hi\"}");
    }

    #[test]
    fn split_sse_multiple_prefixes() {
        let payload = "data: {\"a\":1}\ndelta {\"b\":2}\nmessage {\"c\":3}\n";
        let opts = StreamFormatOptions {
            prefixes: vec![
                "data: ".to_string(),
                "delta ".to_string(),
                "message ".to_string(),
            ],
            skip_values: vec![],
            ..Default::default()
        };
        let chunks = split_sse_chunks(payload, &opts);
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn split_ndjson_newline() {
        let payload = "{\"a\":1}\n{\"b\":2}\n";
        let opts = StreamFormatOptions::default();
        let chunks = split_ndjson_chunks(payload, &opts);
        assert_eq!(chunks.len(), 2);
    }

    // ── End-to-end rules extraction tests ────────────────────────────

    #[test]
    fn e2e_openai_sse_rules() {
        let spec = StreamRulesSpec {
            format: StreamFormat::Sse,
            format_options: StreamFormatOptions {
                prefixes: vec!["data: ".to_string()],
                skip_values: vec!["[DONE]".to_string()],
                ..Default::default()
            },
            rules: vec![
                StreamRule {
                    when: "$exists(choices[0].delta.content)".to_string(),
                    extract: [(
                        "content".to_string(),
                        "choices[0].delta.content".to_string(),
                    )]
                    .into_iter()
                    .collect(),
                    preprocess: vec![],
                },
                StreamRule {
                    when: "$exists(model)".to_string(),
                    extract: [("model".to_string(), "model".to_string())]
                        .into_iter()
                        .collect(),
                    preprocess: vec![],
                },
            ],
            accumulate: [
                (
                    "content".to_string(),
                    AccumulateOp {
                        from: "content".to_string(),
                        op: "concat".to_string(),
                    },
                ),
                (
                    "model".to_string(),
                    AccumulateOp {
                        from: "model".to_string(),
                        op: "first".to_string(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            finalize: HashMap::new(),
        };

        let payload = b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\ndata: [DONE]\n";
        let mut acc = RulesAccumulator::new(&spec.accumulate);
        let result = extract_with_stream_rules(payload, &spec, &mut acc);

        assert_eq!(result.model.as_deref(), Some("gpt-4o"));
        assert_eq!(result.content.as_deref(), Some("Hello world"));
    }

    #[test]
    fn e2e_anthropic_sse_rules() {
        let spec = StreamRulesSpec {
            format: StreamFormat::Sse,
            format_options: StreamFormatOptions {
                prefixes: vec!["data: ".to_string()],
                skip_values: vec![],
                ..Default::default()
            },
            rules: vec![
                StreamRule {
                    when: "type = 'message_start'".to_string(),
                    extract: [("model".to_string(), "message.model".to_string())]
                        .into_iter()
                        .collect(),
                    preprocess: vec![],
                },
                StreamRule {
                    when: "type = 'content_block_delta' and delta.type = 'text_delta'".to_string(),
                    extract: [("content".to_string(), "delta.text".to_string())]
                        .into_iter()
                        .collect(),
                    preprocess: vec![],
                },
                StreamRule {
                    when: "type = 'message_delta'".to_string(),
                    extract: [("stop_reason".to_string(), "delta.stop_reason".to_string())]
                        .into_iter()
                        .collect(),
                    preprocess: vec![],
                },
            ],
            accumulate: [
                (
                    "content".to_string(),
                    AccumulateOp {
                        from: "content".to_string(),
                        op: "concat".to_string(),
                    },
                ),
                (
                    "model".to_string(),
                    AccumulateOp {
                        from: "model".to_string(),
                        op: "first".to_string(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            finalize: HashMap::new(),
        };

        let payload = b"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\"}}\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" Claude\"}}\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n";
        let mut acc = RulesAccumulator::new(&spec.accumulate);
        let result = extract_with_stream_rules(payload, &spec, &mut acc);

        assert_eq!(result.model.as_deref(), Some("claude-sonnet-4-6"));
        assert_eq!(result.content.as_deref(), Some("Hello Claude"));
        assert_eq!(result.finish_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn e2e_ndjson_ollama_rules() {
        let spec = StreamRulesSpec {
            format: StreamFormat::Ndjson,
            format_options: StreamFormatOptions::default(),
            rules: vec![
                StreamRule {
                    when: "$exists(message.content)".to_string(),
                    extract: [
                        ("content".to_string(), "message.content".to_string()),
                        ("model".to_string(), "model".to_string()),
                    ]
                    .into_iter()
                    .collect(),
                    preprocess: vec![],
                },
                StreamRule {
                    when: "done = true".to_string(),
                    extract: HashMap::new(),
                    preprocess: vec![],
                },
            ],
            accumulate: [
                (
                    "content".to_string(),
                    AccumulateOp {
                        from: "content".to_string(),
                        op: "concat".to_string(),
                    },
                ),
                (
                    "model".to_string(),
                    AccumulateOp {
                        from: "model".to_string(),
                        op: "first".to_string(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            finalize: HashMap::new(),
        };

        let payload = b"{\"model\":\"llama3\",\"message\":{\"content\":\"Hi\"}}\n{\"model\":\"llama3\",\"message\":{\"content\":\" there\"}}\n{\"done\":true}\n";
        let mut acc = RulesAccumulator::new(&spec.accumulate);
        let result = extract_with_stream_rules(payload, &spec, &mut acc);

        assert_eq!(result.model.as_deref(), Some("llama3"));
        assert_eq!(result.content.as_deref(), Some("Hi there"));
    }
}
