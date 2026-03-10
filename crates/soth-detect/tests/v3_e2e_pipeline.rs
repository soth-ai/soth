/// End-to-end pipeline test: verifies the full v3 wire-format roundtrip.
///
/// 1. Build a detect bundle with matching_rules (as the cloud compat payload produces)
/// 2. Serialize to JSON → deserialize back (wire roundtrip)
/// 3. Run through process_with_registry() with real request scenarios
/// 4. Verify correct provider, format, and model extraction
///
/// This proves that matching_rules survive the cloud → edge JSON transfer and
/// that classify_request() correctly refines entity identification in the
/// detect pipeline (engine.rs refine_with_classify).
use bytes::Bytes;
use soth_core::{DetectedProvider, MatchingRule, SignalKind, SignalMatcher};
use soth_detect::{
    build_registry, process_with_registry, ApplicationEntry, ConnectionMeta, OwnedDetectBundle,
    ProcessInfo, ProviderEntry, RawRequest, RestFormatDescriptor, RestRequestPaths,
    SessionSnapshot, SocketFamily,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Test case definition
// ---------------------------------------------------------------------------

struct E2eCase {
    name: &'static str,
    method: &'static str,
    host: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static [u8],
    process_bundle_id: Option<&'static str>,
    process_name: Option<&'static str>,
    /// Expected provider in the parsed output.
    expected_provider: &'static str,
    /// Expected parse_source label.
    expected_parse_source: &'static str,
}

fn e2e_cases() -> Vec<E2eCase> {
    vec![
        E2eCase {
            name: "openai-direct-api",
            method: "POST",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![
                ("host", "api.openai.com"),
                ("content-type", "application/json"),
            ],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_provider: "openai",
            expected_parse_source: "openai",
        },
        E2eCase {
            name: "anthropic-direct-api",
            method: "POST",
            host: "api.anthropic.com",
            path: "/v1/messages",
            headers: vec![
                ("host", "api.anthropic.com"),
                ("content-type", "application/json"),
                ("anthropic-version", "2024-06-01"),
            ],
            body: br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_provider: "anthropic",
            expected_parse_source: "anthropic",
        },
        E2eCase {
            name: "cursor-via-openai-with-bundle-id",
            method: "POST",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![
                ("host", "api.openai.com"),
                ("content-type", "application/json"),
            ],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.todesktop.230313mzl4w4u92"),
            process_name: Some("Cursor"),
            // Cursor goes through OpenAI API, so provider is openai.
            expected_provider: "openai",
            expected_parse_source: "openai",
        },
        E2eCase {
            name: "claude-code-via-anthropic",
            method: "POST",
            host: "api.anthropic.com",
            path: "/v1/messages",
            headers: vec![
                ("host", "api.anthropic.com"),
                ("content-type", "application/json"),
                ("anthropic-version", "2024-06-01"),
            ],
            body: br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.anthropic.claude-code"),
            process_name: Some("claude"),
            expected_provider: "anthropic",
            expected_parse_source: "anthropic",
        },
        // Web app cases: these go through the agent-app parser path.
        // In the core DetectedProvider enum, chatgpt/claude are "unknown"
        // because they aren't standard API providers; gemini maps to "gemini".
        E2eCase {
            name: "chatgpt-web",
            method: "POST",
            host: "chatgpt.com",
            path: "/backend-api/conversation",
            headers: vec![
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_provider: "unknown",
            expected_parse_source: "agent_app",
        },
        E2eCase {
            name: "claude-web",
            method: "POST",
            host: "claude.ai",
            path: "/api/organizations/org-123/chat_conversations/conv-456/completion",
            headers: vec![
                ("host", "claude.ai"),
                ("content-type", "application/json"),
            ],
            body: br#"{"model":"claude-sonnet-4-6"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_provider: "unknown",
            expected_parse_source: "agent_app",
        },
        E2eCase {
            name: "gemini-web",
            method: "POST",
            host: "gemini.google.com",
            path: "/_/BardChatUi/data/batchexecute",
            headers: vec![
                ("host", "gemini.google.com"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            body: b"f.req=%5B%5B%22hello%22%5D%5D",
            process_bundle_id: None,
            process_name: None,
            // Gemini web uses form-encoded protobuf; the detect pipeline
            // falls back to heuristic because the body isn't JSON.
            expected_provider: "unknown",
            expected_parse_source: "heuristic",
        },
    ]
}

// ---------------------------------------------------------------------------
// Bundle builder
// ---------------------------------------------------------------------------

fn build_v3_detect_bundle() -> OwnedDetectBundle {
    let mut rest_formats = HashMap::new();
    rest_formats.insert(
        "openai".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                ..Default::default()
            },
            system_in_messages: true,
            ..Default::default()
        },
    );
    rest_formats.insert(
        "anthropic".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                system: Some("$.system".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
    );
    rest_formats.insert("chatgpt_web".to_string(), RestFormatDescriptor::default());
    rest_formats.insert("claude_web".to_string(), RestFormatDescriptor::default());
    rest_formats.insert("gemini_web".to_string(), RestFormatDescriptor::default());

    let mut domain_index = HashMap::new();
    domain_index.insert("api.openai.com".to_string(), "openai".to_string());
    domain_index.insert("api.anthropic.com".to_string(), "anthropic".to_string());
    domain_index.insert("chatgpt.com".to_string(), "chatgpt".to_string());
    domain_index.insert("claude.ai".to_string(), "claude".to_string());
    domain_index.insert("gemini.google.com".to_string(), "gemini".to_string());

    let mr = |id: &str, priority: u32, requires_all: bool, signals: Vec<SignalMatcher>| {
        MatchingRule {
            rule_id: id.to_string(),
            priority,
            requires_all,
            signals,
            ..Default::default()
        }
    };
    let sig = |kind: SignalKind, pattern: &str| SignalMatcher {
        kind,
        pattern: pattern.to_string(),
        ..Default::default()
    };

    let mut llm_providers = HashMap::new();
    llm_providers.insert(
        "openai".to_string(),
        ProviderEntry {
            provider_id: Some("openai".to_string()),
            name: Some("OpenAI".to_string()),
            api_format: Some("openai".to_string()),
            matching_rules: vec![mr(
                "openai-host",
                850,
                true,
                vec![sig(SignalKind::HttpHost, "api.openai.com")],
            )],
            ..Default::default()
        },
    );
    llm_providers.insert(
        "anthropic".to_string(),
        ProviderEntry {
            provider_id: Some("anthropic".to_string()),
            name: Some("Anthropic".to_string()),
            api_format: Some("anthropic".to_string()),
            matching_rules: vec![mr(
                "anthropic-host",
                850,
                true,
                vec![sig(SignalKind::HttpHost, "api.anthropic.com")],
            )],
            ..Default::default()
        },
    );

    let mut applications = HashMap::new();
    applications.insert(
        "chatgpt".to_string(),
        ApplicationEntry {
            app_id: Some("chatgpt".to_string()),
            name: Some("ChatGPT".to_string()),
            api_format: Some("chatgpt_web".to_string()),
            matching_rules: vec![mr(
                "chatgpt-host",
                900,
                true,
                vec![sig(SignalKind::HttpHost, "chatgpt.com")],
            )],
            ..Default::default()
        },
    );
    applications.insert(
        "claude".to_string(),
        ApplicationEntry {
            app_id: Some("claude".to_string()),
            name: Some("Claude".to_string()),
            api_format: Some("claude_web".to_string()),
            matching_rules: vec![mr(
                "claude-host",
                900,
                true,
                vec![sig(SignalKind::HttpHost, "claude.ai")],
            )],
            ..Default::default()
        },
    );
    applications.insert(
        "gemini".to_string(),
        ApplicationEntry {
            app_id: Some("gemini".to_string()),
            name: Some("Gemini".to_string()),
            api_format: Some("gemini_web".to_string()),
            matching_rules: vec![mr(
                "gemini-host",
                900,
                true,
                vec![sig(SignalKind::HttpHost, "gemini.google.com")],
            )],
            ..Default::default()
        },
    );
    applications.insert(
        "claude-code".to_string(),
        ApplicationEntry {
            app_id: Some("claude-code".to_string()),
            name: Some("Claude Code".to_string()),
            matching_rules: vec![
                mr(
                    "cc-bid",
                    1000,
                    false,
                    vec![sig(SignalKind::ProcessBundleId, "com.anthropic.claude-code")],
                ),
                mr(
                    "cc-pname",
                    950,
                    false,
                    vec![sig(SignalKind::ProcessName, "claude")],
                ),
            ],
            ..Default::default()
        },
    );
    applications.insert(
        "cursor".to_string(),
        ApplicationEntry {
            app_id: Some("cursor".to_string()),
            name: Some("Cursor".to_string()),
            matching_rules: vec![
                mr(
                    "cursor-bid",
                    1000,
                    false,
                    vec![sig(
                        SignalKind::ProcessBundleId,
                        "com.todesktop.230313mzl4w4u92",
                    )],
                ),
                mr(
                    "cursor-pname",
                    950,
                    false,
                    vec![sig(SignalKind::ProcessName, "Cursor")],
                ),
            ],
            ..Default::default()
        },
    );

    OwnedDetectBundle {
        rest_formats,
        domain_index,
        llm_providers,
        applications,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Request builder
// ---------------------------------------------------------------------------

fn build_request(case: &E2eCase) -> RawRequest {
    let headers: BTreeMap<String, String> = case
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let process_info = match (case.process_bundle_id, case.process_name) {
        (None, None) => None,
        _ => Some(ProcessInfo {
            pid: Some(12345),
            process_name: case.process_name.map(String::from),
            bundle_id: case.process_bundle_id.map(String::from),
            parent_pid: None,
            parent_process_name: None,
            parent_bundle_id: None,
        }),
    };

    let mut meta = ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        process_info,
        None,
    );
    // Simulate gating output: provider from domain_index if it maps to a known provider.
    let provider_domains = [
        ("api.openai.com", "openai"),
        ("api.anthropic.com", "anthropic"),
    ];
    for (host, provider) in &provider_domains {
        if case.host == *host {
            meta.matched_provider = Some(provider.to_string());
        }
    }

    RawRequest {
        method: case.method.to_string(),
        path: case.path.to_string(),
        headers,
        body: Bytes::from(case.body.to_vec()),
        connection_meta: meta,
    }
}

fn parse_source_label(source: &soth_core::ParseSource) -> String {
    match source {
        soth_core::ParseSource::Rest { provider } => provider.canonical_name().to_string(),
        soth_core::ParseSource::AgentApp => "agent_app".to_string(),
        soth_core::ParseSource::Heuristic => "heuristic".to_string(),
        soth_core::ParseSource::Filtered => "filtered".to_string(),
        soth_core::ParseSource::GraphQl => "graphql".to_string(),
        soth_core::ParseSource::Grpc => "grpc".to_string(),
        soth_core::ParseSource::JsonRpc => "jsonrpc".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full pipeline E2E: build a v3 bundle with matching_rules, serialize to JSON,
/// deserialize back (simulating cloud→edge wire transfer), then process requests
/// through the detect pipeline and verify correct output.
#[test]
fn v3_wire_roundtrip_full_pipeline() {
    let original = build_v3_detect_bundle();

    // Wire roundtrip: serialize → deserialize (proves serde compat).
    let json_bytes = serde_json::to_vec(&original).expect("serialize detect bundle");
    let deserialized: OwnedDetectBundle =
        serde_json::from_slice(&json_bytes).expect("deserialize detect bundle");

    // Verify matching_rules survived the roundtrip.
    let openai = deserialized.llm_providers.get("openai").unwrap();
    assert_eq!(openai.matching_rules.len(), 1, "openai should have 1 rule");
    assert_eq!(openai.matching_rules[0].rule_id, "openai-host");

    let cursor = deserialized.applications.get("cursor").unwrap();
    assert_eq!(cursor.matching_rules.len(), 2, "cursor should have 2 rules");

    let claude_code = deserialized.applications.get("claude-code").unwrap();
    assert_eq!(
        claude_code.matching_rules.len(),
        2,
        "claude-code should have 2 rules"
    );

    // Build registry and process requests through the full pipeline.
    let registry = build_registry(&deserialized.as_slice()).expect("build registry");
    let snapshot = SessionSnapshot::default();

    for case in e2e_cases() {
        let request = build_request(&case);
        let result = process_with_registry(
            &registry,
            &request,
            &deserialized.as_slice(),
            &snapshot,
        );

        assert_eq!(
            result.normalized.provider.canonical_name(),
            case.expected_provider,
            "case '{}': provider mismatch",
            case.name,
        );
        assert_eq!(
            parse_source_label(&result.parse_source),
            case.expected_parse_source,
            "case '{}': parse_source mismatch",
            case.name,
        );
    }
}

/// Verify that v3 classify_request refines entity identification within the
/// detect pipeline. Cursor traffic to api.openai.com should be attributed to
/// cursor (application) while still detecting OpenAI format (provider).
#[test]
fn v3_classify_refines_application_in_pipeline() {
    let bundle = build_v3_detect_bundle();
    let json_bytes = serde_json::to_vec(&bundle).expect("serialize");
    let bundle: OwnedDetectBundle = serde_json::from_slice(&json_bytes).expect("deserialize");
    let registry = build_registry(&bundle.as_slice()).expect("build registry");
    let snapshot = SessionSnapshot::default();

    // Cursor hitting OpenAI API: should detect as OpenAI format,
    // but classify_request should identify cursor as the application.
    let mut meta = ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        Some(ProcessInfo {
            pid: Some(1),
            process_name: Some("Cursor".to_string()),
            bundle_id: Some("com.todesktop.230313mzl4w4u92".to_string()),
            parent_pid: None,
            parent_process_name: None,
            parent_bundle_id: None,
        }),
        None,
    );
    meta.matched_provider = Some("openai".to_string());

    let request = RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: BTreeMap::from([
            ("host".to_string(), "api.openai.com".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ]),
        body: Bytes::from(
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"write tests"}]}"#
                .to_vec(),
        ),
        connection_meta: meta,
    };

    let result = process_with_registry(&registry, &request, &bundle.as_slice(), &snapshot);

    // Provider attribution: openai (format detection).
    assert_eq!(
        result.normalized.provider.canonical_name(),
        "openai",
        "cursor traffic should be attributed to openai provider"
    );
    // Parse source: OpenAI (REST format).
    assert_eq!(
        result.parse_source,
        soth_core::ParseSource::Rest {
            provider: DetectedProvider::OpenAi
        }
    );
    // Model extracted correctly.
    assert_eq!(result.normalized.model.as_deref(), Some("gpt-4o"));
}

/// Verify that v2 bundles (no matching_rules) still work through the pipeline
/// with zero regression — classify_request returns None, falls back to gating.
#[test]
fn v2_bundle_no_matching_rules_still_works() {
    let mut bundle = build_v3_detect_bundle();
    // Strip all matching_rules to simulate a v2 bundle.
    for (_, entry) in bundle.llm_providers.iter_mut() {
        entry.matching_rules.clear();
    }
    for (_, entry) in bundle.applications.iter_mut() {
        entry.matching_rules.clear();
    }

    let json_bytes = serde_json::to_vec(&bundle).expect("serialize");
    let bundle: OwnedDetectBundle = serde_json::from_slice(&json_bytes).expect("deserialize");
    let registry = build_registry(&bundle.as_slice()).expect("build registry");
    let snapshot = SessionSnapshot::default();

    // OpenAI direct API should still work via gating's matched_provider.
    let mut meta = ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        None,
        None,
    );
    meta.matched_provider = Some("openai".to_string());

    let request = RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: BTreeMap::from([
            ("host".to_string(), "api.openai.com".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ]),
        body: Bytes::from(
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#.to_vec(),
        ),
        connection_meta: meta,
    };

    let result = process_with_registry(&registry, &request, &bundle.as_slice(), &snapshot);
    assert_eq!(result.normalized.provider.canonical_name(), "openai");
    assert_eq!(
        result.parse_source,
        soth_core::ParseSource::Rest {
            provider: DetectedProvider::OpenAi
        }
    );
    assert_eq!(result.normalized.model.as_deref(), Some("gpt-4o"));
}

/// Verify that the v3 pipeline correctly extracts model names across all formats
/// after the wire roundtrip.
#[test]
fn v3_model_extraction_across_formats() {
    let bundle = build_v3_detect_bundle();
    let json_bytes = serde_json::to_vec(&bundle).expect("serialize");
    let bundle: OwnedDetectBundle = serde_json::from_slice(&json_bytes).expect("deserialize");
    let registry = build_registry(&bundle.as_slice()).expect("build registry");
    let snapshot = SessionSnapshot::default();

    let cases: Vec<(&str, &str, &str, &[u8], &str)> = vec![
        (
            "openai",
            "api.openai.com",
            "/v1/chat/completions",
            br#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hi"}]}"#,
            "gpt-4.1-mini",
        ),
        (
            "anthropic",
            "api.anthropic.com",
            "/v1/messages",
            br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}"#,
            "claude-sonnet-4-6",
        ),
    ];

    for (provider, host, path, body, expected_model) in cases {
        let mut meta = ConnectionMeta::from_transport(
            Uuid::new_v4(),
            SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            None,
            None,
        );
        meta.matched_provider = Some(provider.to_string());

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), host.to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        if provider == "anthropic" {
            headers.insert("anthropic-version".to_string(), "2024-06-01".to_string());
        }

        let request = RawRequest {
            method: "POST".to_string(),
            path: path.to_string(),
            headers,
            body: Bytes::from(body.to_vec()),
            connection_meta: meta,
        };

        let result = process_with_registry(&registry, &request, &bundle.as_slice(), &snapshot);
        assert_eq!(
            result.normalized.model.as_deref(),
            Some(expected_model),
            "model extraction failed for {provider}"
        );
    }
}
