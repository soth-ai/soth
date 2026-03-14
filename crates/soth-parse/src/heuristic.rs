use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::types::{
    EndpointType, NormalizedRequest, ParseConfidence, ParseWarning, Provider, RawRequest,
};
use crate::util::{extract_string, json_path};
use serde_json::Value;

pub fn parse(req: &RawRequest) -> NormalizedRequest {
    let mut nr = NormalizedRequest::empty_heuristic(&req.method, &req.path);
    nr.provider = Provider::new("unknown");
    nr.endpoint_type = EndpointType::Unknown;

    match serde_json::from_slice::<Value>(&req.body) {
        Ok(json) => {
            nr.model = try_extract_model(&json);

            let content = try_paths(
                &json,
                &[
                    "$.messages[0].content",
                    "$.prompt",
                    "$.content",
                    "$.message",
                    "$.text",
                    "$.input",
                    "$.input.content",
                    "$.request.prompt",
                    "$.query",
                ],
            );

            let content = match content {
                Some(value) if !value.is_empty() => value,
                _ => {
                    nr.parse_warnings.push(ParseWarning::ContentNotExtracted);
                    find_longest_string(&json, 20)
                        .map(|value| {
                            nr.parse_warnings.push(ParseWarning::LongestStringHeuristic);
                            value
                        })
                        .unwrap_or_else(|| "[CONTENT_NOT_EXTRACTED]".to_string())
                }
            };

            nr.user_content_hash = hash_content(&content);
            nr.user_content_token_estimate = estimate_tokens(&content);
            nr.estimated_input_tokens = nr.user_content_token_estimate;
            nr.conversation_hash = hash_content(&content);
            nr.content_sample = if content == "[CONTENT_NOT_EXTRACTED]" {
                None
            } else {
                Some(content)
            };
        }
        Err(_) => {
            nr.parse_warnings.push(ParseWarning::NonJsonBody);
            nr.user_content_hash = hash_content("[NON_JSON_BODY]");
            nr.conversation_hash = nr.user_content_hash.clone();
        }
    }

    nr.parse_confidence = ParseConfidence::Heuristic;
    nr.canonical_hash = canonical_hash(&nr);
    nr
}

fn try_extract_model(json: &Value) -> Option<String> {
    ["$.model", "$.model_id", "$.modelId", "$.modelName"]
        .iter()
        .find_map(|path| json_path(json, path))
        .and_then(extract_string)
}

fn try_paths(json: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| json_path(json, path))
        .and_then(extract_string)
}

fn find_longest_string(value: &Value, min_len: usize) -> Option<String> {
    let mut best: Option<String> = None;
    visit_json(value, &mut |candidate| {
        if candidate.len() < min_len {
            return;
        }
        let update = match best.as_ref() {
            Some(existing) => candidate.len() > existing.len(),
            None => true,
        };
        if update {
            best = Some(candidate.to_string());
        }
    });
    best
}

fn visit_json(value: &Value, f: &mut dyn FnMut(&str)) {
    match value {
        Value::String(v) => f(v),
        Value::Array(items) => {
            for item in items {
                visit_json(item, f);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                visit_json(value, f);
            }
        }
        Value::Bool(_) | Value::Number(_) | Value::Null => {}
    }
}
