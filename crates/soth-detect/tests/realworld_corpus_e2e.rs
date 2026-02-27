use bytes::Bytes;
use serde_json::{json, Value};
use soth_core::{ConnectionMeta, DetectedProvider, ParseSource, SocketFamily};
use soth_detect::{build_registry, process_with_registry, OwnedDetectBundle, RawRequest};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ExpectedFormat {
    OpenAi,
    Anthropic,
    Cohere,
    Google,
    Bedrock,
}

#[derive(Clone, Debug)]
struct GeneratedCase {
    id: String,
    host: String,
    path: String,
    body: Vec<u8>,
    expected: ExpectedFormat,
}

#[test]
fn realworld_provider_matrix_bundle_corpus() {
    let Some(bundle) = load_home_detect_bundle() else {
        return;
    };

    let registry = build_registry(&bundle.as_slice()).expect("build parser registry");
    let cases = generate_provider_matrix_cases(&bundle);

    assert!(
        cases.len() >= 40,
        "expected at least 40 provider-matrix cases from home bundle, got {}",
        cases.len()
    );

    for case in cases {
        let request = build_request(&case.host, &case.path, &case.body);
        let out = process_with_registry(&registry, &request, &bundle.as_slice());
        assert_parse_source_matches(&case, &out.parse_source);
        assert!(
            !out.normalized.canonical_cache_key.is_empty(),
            "case {}: canonical cache key should not be empty",
            case.id
        );
        assert!(
            !out.normalized.user_content_hash.is_empty(),
            "case {}: user content hash should not be empty",
            case.id
        );
    }
}

#[test]
fn realworld_gating_allow_path_bundle_corpus() {
    let Some(bundle) = load_home_detect_bundle() else {
        return;
    };
    let Some(gating) = load_home_gating_bundle() else {
        return;
    };

    let registry = build_registry(&bundle.as_slice()).expect("build parser registry");
    let cases = generate_gating_allow_path_cases(&gating);
    assert!(
        cases.len() >= 12,
        "expected at least 12 gating allow-path cases from home bundle, got {}",
        cases.len()
    );

    for case in cases {
        let request = build_request(&case.host, &case.path, &case.body);
        let out = process_with_registry(&registry, &request, &bundle.as_slice());
        assert_parse_source_matches(&case, &out.parse_source);
    }
}

fn load_home_detect_bundle() -> Option<OwnedDetectBundle> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let path = PathBuf::from(home)
        .join(".soth")
        .join("registry_bundle_cache.detect_bundle.json");
    if !path.exists() {
        eprintln!(
            "Skipping realworld detect corpus tests: detect bundle not found at {}",
            path.display()
        );
        return None;
    }

    let bytes = std::fs::read(&path).expect("read ~/.soth detect bundle");
    Some(serde_json::from_slice(&bytes).expect("deserialize detect bundle"))
}

fn load_home_gating_bundle() -> Option<Value> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let path = PathBuf::from(home)
        .join(".soth")
        .join("registry_bundle_cache.gating_bundle.json");
    if !path.exists() {
        eprintln!(
            "Skipping realworld gating corpus tests: gating bundle not found at {}",
            path.display()
        );
        return None;
    }
    let bytes = std::fs::read(&path).expect("read ~/.soth gating bundle");
    Some(serde_json::from_slice(&bytes).expect("deserialize gating bundle"))
}

fn generate_provider_matrix_cases(bundle: &OwnedDetectBundle) -> Vec<GeneratedCase> {
    let mut hosts_by_provider: HashMap<&str, Vec<&str>> = HashMap::new();
    for (host_pattern, provider_id) in &bundle.domain_index {
        hosts_by_provider
            .entry(provider_id.as_str())
            .or_default()
            .push(host_pattern.as_str());
    }

    let mut out = Vec::new();
    for (provider_id, entry) in &bundle.llm_providers {
        let Some(expected) = expected_for_api_format(entry.api_format.as_deref()) else {
            continue;
        };
        let Some(host_patterns) = hosts_by_provider.get(provider_id.as_str()) else {
            continue;
        };
        let Some(host_pattern) = host_patterns.first() else {
            continue;
        };

        let host = materialize_host_pattern(host_pattern);
        let path = default_path_for_expected(expected).to_string();
        let body = request_body_for_expected(expected, &path);
        out.push(GeneratedCase {
            id: format!("provider-matrix:{provider_id}:{host}:{path}"),
            host,
            path,
            body,
            expected,
        });
    }

    out
}

fn generate_gating_allow_path_cases(gating: &Value) -> Vec<GeneratedCase> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let sections = [
        gating.pointer("/entities/providers"),
        gating.pointer("/entities/web_apps"),
        gating.pointer("/entities/native_apps"),
    ];

    for section in sections.into_iter().flatten() {
        let Some(entities) = section.as_array() else {
            continue;
        };
        for entity in entities {
            let entity_id = entity
                .get("entity_id")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let Some(hosts) = entity.get("hosts").and_then(|value| value.as_array()) else {
                continue;
            };
            for host_entry in hosts {
                let Some(host_pattern) = host_entry.get("pattern").and_then(|value| value.as_str())
                else {
                    continue;
                };
                let host = materialize_host_pattern(host_pattern);
                let allow_paths = host_entry
                    .pointer("/paths/allow")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .unwrap_or_default();
                for allow_path in allow_paths {
                    let Some(raw_path) = allow_path.as_str() else {
                        continue;
                    };
                    let Some(expected) = expected_for_path_pattern(raw_path) else {
                        continue;
                    };
                    let path = materialize_path_pattern(raw_path);
                    let dedupe = format!("{host}|{path}|{:?}", expected);
                    if !seen.insert(dedupe) {
                        continue;
                    }
                    let body = request_body_for_expected(expected, &path);
                    out.push(GeneratedCase {
                        id: format!("gating-path:{entity_id}:{host}:{path}"),
                        host: host.clone(),
                        path,
                        body,
                        expected,
                    });
                }
            }
        }
    }

    out
}

fn expected_for_api_format(api_format: Option<&str>) -> Option<ExpectedFormat> {
    let format = api_format?.to_ascii_lowercase();
    if format.contains("openai") {
        return Some(ExpectedFormat::OpenAi);
    }
    if format.contains("anthropic") {
        return Some(ExpectedFormat::Anthropic);
    }
    if format.contains("cohere") {
        return Some(ExpectedFormat::Cohere);
    }
    if format.contains("google") || format.contains("gemini") {
        return Some(ExpectedFormat::Google);
    }
    if format.contains("bedrock") {
        return Some(ExpectedFormat::Bedrock);
    }
    None
}

fn expected_for_path_pattern(path: &str) -> Option<ExpectedFormat> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("streamgenerate") || lower.contains("generatecontent") {
        return Some(ExpectedFormat::Google);
    }
    if lower.contains("/v1/messages")
        || (lower.contains("/api/organizations/") && lower.contains("/completion"))
    {
        return Some(ExpectedFormat::Anthropic);
    }
    if lower.contains("/v2/chat") || lower.contains("/v2/generate") {
        return Some(ExpectedFormat::Cohere);
    }
    if lower.contains("/model/") && lower.contains("/invoke") {
        return Some(ExpectedFormat::Bedrock);
    }
    if lower.contains("/v1/chat/completions")
        || lower.contains("/v1/responses")
        || lower.contains("/api/v1/responses")
        || lower.contains("/api/v0/chat/completion")
        || lower.contains("/chat/api/v2/conversations")
        || lower.contains("/chat/conversation")
        || lower.contains("/backend-api/") && lower.contains("/conversation")
        || lower.contains("/backend-anon/") && lower.contains("/conversation")
        || lower.contains("/conversation")
        || lower.contains("/chat/completion")
        || lower.contains("/v1/chat-with-documents")
        || lower.contains("/v1/llm-proxy")
    {
        return Some(ExpectedFormat::OpenAi);
    }
    None
}

fn default_path_for_expected(expected: ExpectedFormat) -> &'static str {
    match expected {
        ExpectedFormat::OpenAi => "/v1/chat/completions",
        ExpectedFormat::Anthropic => "/v1/messages",
        ExpectedFormat::Cohere => "/v2/chat",
        ExpectedFormat::Google => "/v1/models/gemini-1.5-pro:generateContent",
        ExpectedFormat::Bedrock => "/model/anthropic.claude-3-sonnet/invoke",
    }
}

fn request_body_for_expected(expected: ExpectedFormat, path: &str) -> Vec<u8> {
    match expected {
        ExpectedFormat::OpenAi => {
            if path.to_ascii_lowercase().contains("/responses") {
                serde_json::to_vec(&json!({
                    "model": "gpt-4.1-mini",
                    "input": [
                        {"role": "user", "content": [{"type": "input_text", "text": "realworld corpus openai responses input"}]}
                    ]
                }))
                .expect("serialize openai responses body")
            } else {
                serde_json::to_vec(&json!({
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "realworld corpus openai chat input"}],
                    "stream": false
                }))
                .expect("serialize openai body")
            }
        }
        ExpectedFormat::Anthropic => serde_json::to_vec(&json!({
            "model": "claude-3-5-sonnet",
            "system": "You are helpful",
            "messages": [{"role": "user", "content": "realworld corpus anthropic input"}]
        }))
        .expect("serialize anthropic body"),
        ExpectedFormat::Cohere => serde_json::to_vec(&json!({
            "model": "command-r-plus",
            "message": "realworld corpus cohere input",
            "chat_history": [{"role": "SYSTEM", "message": "You are helpful"}],
            "stream": false
        }))
        .expect("serialize cohere body"),
        ExpectedFormat::Google => serde_json::to_vec(&json!({
            "contents": [{"parts": [{"text": "realworld corpus gemini input"}]}],
            "generationConfig": {"temperature": 0.2, "topP": 0.95, "maxOutputTokens": 128}
        }))
        .expect("serialize google body"),
        ExpectedFormat::Bedrock => serde_json::to_vec(&json!({
            "modelId": "anthropic.claude-3-sonnet",
            "messages": [{"role": "user", "content": "realworld corpus bedrock input"}],
            "max_tokens": 128,
            "temperature": 0.2
        }))
        .expect("serialize bedrock body"),
    }
}

fn materialize_host_pattern(pattern: &str) -> String {
    let mut host = pattern
        .trim()
        .trim_start_matches('^')
        .trim_end_matches('$')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host = host.replace("*.", "edge.");
    host = host.replace('*', "edge");
    while host.contains("..") {
        host = host.replace("..", ".");
    }
    if host.is_empty() {
        "localhost".to_string()
    } else {
        host
    }
}

fn materialize_path_pattern(pattern: &str) -> String {
    let mut path = pattern.trim().to_string();
    path = path.replace("**", "sample");
    path = path.replace('*', "sample");
    if !path.starts_with('/') {
        path = format!("/{path}");
    }
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    path
}

fn build_request(host: &str, path: &str, body: &[u8]) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), host.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: path.to_string(),
        headers,
        body: Bytes::copy_from_slice(body),
        connection_meta: ConnectionMeta::from_transport(
            Uuid::new_v4(),
            SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            None,
            None,
        ),
    }
}

fn assert_parse_source_matches(case: &GeneratedCase, source: &ParseSource) {
    match (case.expected, source) {
        (ExpectedFormat::OpenAi, ParseSource::Rest { provider })
            if *provider == DetectedProvider::OpenAi => {}
        (ExpectedFormat::Anthropic, ParseSource::Rest { provider })
            if *provider == DetectedProvider::Anthropic => {}
        (ExpectedFormat::Cohere, ParseSource::Rest { provider })
            if *provider == DetectedProvider::Cohere => {}
        (ExpectedFormat::Google, ParseSource::Rest { provider })
            if *provider == DetectedProvider::Gemini => {}
        (ExpectedFormat::Bedrock, ParseSource::Rest { provider })
            if *provider == DetectedProvider::Bedrock => {}
        _ => panic!(
            "case {}: parse source mismatch for expected {:?}, got {:?}",
            case.id, case.expected, source
        ),
    }
}
