use bytes::Bytes;
use soth_core::OwnedDetectBundle;
use soth_core::{CaptureMode, ConnectionMeta, ParseConfidence, ParseSource, SocketFamily};
use soth_detect::{build_registry, process_with_registry, RawRequest};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use uuid::Uuid;

#[test]
fn converted_registry_bundle_copy_loads_and_processes_request() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("registry_bundle_cache.detect_bundle.json");
    if !fixture.exists() {
        eprintln!(
            "Skipping converted_registry_bundle_copy_loads_and_processes_request: fixture not found at {}",
            fixture.display()
        );
        return;
    }

    let bytes = std::fs::read(&fixture).expect("read converted bundle fixture");
    let bundle: OwnedDetectBundle =
        serde_json::from_slice(bytes.as_slice()).expect("deserialize OwnedDetectBundle");

    assert!(bundle.rest_formats.contains_key("openai"));
    assert!(!bundle.domain_index.is_empty());
    assert!(!bundle.llm_providers.is_empty());
    assert!(!bundle.passthrough_domains.is_empty());

    let registry = build_registry(&bundle.as_slice()).expect("build parser registry");

    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "api.openai.com".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let request = RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers,
        body: Bytes::from_static(
            br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"bundle load smoke"}],"stream":false}"#,
        ),
        connection_meta: ConnectionMeta::from_transport(
            Uuid::new_v4(),
            SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            None,
            None,
        ),
    };

    let out = process_with_registry(
        &registry,
        &request,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert!(matches!(
        out.parse_source,
        ParseSource::Rest {
            provider: soth_core::DetectedProvider::OpenAi
        }
    ));
    assert!(matches!(
        out.confidence,
        ParseConfidence::Full | ParseConfidence::Partial
    ));
    assert_eq!(out.capture_mode, CaptureMode::MetadataOnly);
    assert_eq!(out.normalized.model.as_deref(), Some("gpt-4o-mini"));
}

#[test]
fn home_bundle_e2e_contract_cases() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let bundle_path = PathBuf::from(home)
        .join(".soth")
        .join("registry_bundle_cache.detect_bundle.json");
    if !bundle_path.exists() {
        eprintln!(
            "Skipping home_bundle_e2e_contract_cases: bundle file not found at {}",
            bundle_path.display()
        );
        return;
    }

    let bytes = std::fs::read(&bundle_path).expect("read ~/.soth converted bundle");
    let bundle: OwnedDetectBundle =
        serde_json::from_slice(bytes.as_slice()).expect("deserialize OwnedDetectBundle");
    let registry = build_registry(&bundle.as_slice()).expect("build parser registry");

    let openai = build_request(
        "POST",
        "/v1/chat/completions",
        vec![
            ("host", "api.openai.com"),
            ("content-type", "application/json"),
        ],
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"home bundle openai"}]}"#,
    );
    let out_openai = process_with_registry(
        &registry,
        &openai,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(parse_source_name(&out_openai.parse_source), "rest:openai");
    assert_eq!(out_openai.capture_mode, CaptureMode::MetadataOnly);
    assert_eq!(out_openai.normalized.model.as_deref(), Some("gpt-4o-mini"));
    assert!(matches!(out_openai.confidence, ParseConfidence::Full));

    let anthropic = build_request(
        "POST",
        "/v1/messages",
        vec![
            ("host", "api.anthropic.com"),
            ("content-type", "application/json"),
        ],
        br#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"home bundle anthropic"}]}"#,
    );
    let out_anthropic = process_with_registry(
        &registry,
        &anthropic,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(
        parse_source_name(&out_anthropic.parse_source),
        "rest:anthropic"
    );
    assert_eq!(out_anthropic.capture_mode, CaptureMode::Full);
    assert_eq!(
        out_anthropic.normalized.model.as_deref(),
        Some("claude-3-5-sonnet")
    );
    assert!(matches!(out_anthropic.confidence, ParseConfidence::Full));

    let google = build_request(
        "POST",
        "/v1/models/gemini-1.5-pro:generateContent",
        vec![
            ("host", "generativelanguage.googleapis.com"),
            ("content-type", "application/json"),
        ],
        br#"{"contents":[{"parts":[{"text":"leak sk-abcdefghijklmnopqrstuvwxyz1234"}]}]}"#,
    );
    let out_google = process_with_registry(
        &registry,
        &google,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(parse_source_name(&out_google.parse_source), "rest:gemini");
    assert_eq!(out_google.capture_mode, CaptureMode::Full);
    assert!(
        !out_google.artifacts.is_empty(),
        "google full-capture path should scan and emit artifacts"
    );

    let openrouter_responses = build_request(
        "POST",
        "/api/v1/responses",
        vec![
            ("host", "openrouter.ai"),
            ("content-type", "application/json"),
        ],
        br#"{"model":"openai/gpt-4o-mini","input":[{"role":"user","content":[{"type":"input_text","text":"home bundle openrouter"}]}]}"#,
    );
    let out_openrouter = process_with_registry(
        &registry,
        &openrouter_responses,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(
        parse_source_name(&out_openrouter.parse_source),
        "rest:openai"
    );
    assert_eq!(out_openrouter.capture_mode, CaptureMode::Full);
    assert_eq!(
        out_openrouter.normalized.model.as_deref(),
        Some("openai/gpt-4o-mini")
    );
    assert!(matches!(out_openrouter.confidence, ParseConfidence::Full));

    let chatgpt_web = build_request(
        "POST",
        "/backend-api/conversation",
        vec![
            ("host", "chatgpt.com"),
            ("content-type", "application/json"),
        ],
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"home bundle chatgpt web"}]}"#,
    );
    let out_chatgpt_web = process_with_registry(
        &registry,
        &chatgpt_web,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(
        parse_source_name(&out_chatgpt_web.parse_source),
        "rest:openai"
    );
    assert_eq!(out_chatgpt_web.capture_mode, CaptureMode::MetadataOnly);
    assert_eq!(out_chatgpt_web.normalized.model.as_deref(), Some("gpt-4o"));
    assert!(matches!(out_chatgpt_web.confidence, ParseConfidence::Full));

    let filtered = build_request("GET", "/health", vec![("host", "api.openai.com")], b"");
    let out_filtered = process_with_registry(
        &registry,
        &filtered,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    );
    assert_eq!(parse_source_name(&out_filtered.parse_source), "filtered");
}

fn build_request(method: &str, path: &str, headers: Vec<(&str, &str)>, body: &[u8]) -> RawRequest {
    let mut map = BTreeMap::new();
    for (k, v) in headers {
        map.insert(k.to_string(), v.to_string());
    }
    RawRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers: map,
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

fn parse_source_name(source: &ParseSource) -> String {
    match source {
        ParseSource::Rest { provider } => format!("rest:{}", provider.canonical_name()),
        ParseSource::GraphQl => "graphql".to_string(),
        ParseSource::Grpc => "grpc".to_string(),
        ParseSource::JsonRpc => "jsonrpc".to_string(),
        ParseSource::AgentApp => "agent_app".to_string(),
        ParseSource::Heuristic => "heuristic".to_string(),
        ParseSource::Filtered => "filtered".to_string(),
        ParseSource::Sdk => "sdk".to_string(),
    }
}
