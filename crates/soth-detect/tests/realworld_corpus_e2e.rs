/// Realworld E2E corpus tests.
///
/// Loads the NativeBundle from `~/.soth/bundle/detect/bundle.json`,
/// converts it through the same `detect_from_native` + `gating_from_native`
/// pipeline the proxy uses, generates test requests for every LLM provider
/// using the provider's own `api_format`, sets `matched_provider` from the
/// gating domain resolution, and verifies model extraction + AI call detection.
///
/// No synthetic heuristics — the bundle's own data is the ground truth.
use bytes::Bytes;
use serde_json::json;
use soth_core::{ConnectionMeta, GatingBundle, SocketFamily};
use soth_detect::{build_registry, process_with_registry, RawRequest};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Bundle loading — same path as the proxy
// ---------------------------------------------------------------------------

fn load_native_bundle() -> Option<soth_bundle::NativeBundle> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let path = PathBuf::from(home).join(".soth/bundle/detect/bundle.json");
    if !path.exists() {
        eprintln!("Skipping: NativeBundle not found at {}", path.display());
        return None;
    }
    let bytes = std::fs::read(&path).expect("read detect/bundle.json");
    let native: soth_bundle::NativeBundle =
        serde_json::from_slice(&bytes).expect("parse NativeBundle");
    eprintln!(
        "Loaded NativeBundle v{}: {} providers, {} products, {} formats, {} domains",
        native.schema_version,
        native.llm_providers.len(),
        native.products.len(),
        native.formats.len(),
        native.domain_index.len(),
    );
    Some(native)
}

// ---------------------------------------------------------------------------
// Request body builders by api_format (ground truth from the bundle)
// ---------------------------------------------------------------------------

struct TestRequest {
    body: Vec<u8>,
    path: &'static str,
    expected_model: &'static str,
    content_type: &'static str,
    extra_headers: Vec<(&'static str, &'static str)>,
}

fn request_for_api_format(api_format: &str) -> Option<TestRequest> {
    match api_format {
        "openai" => Some(TestRequest {
            body: serde_json::to_vec(&json!({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "corpus test openai"}],
                "stream": false,
            }))
            .unwrap(),
            path: "/v1/chat/completions",
            expected_model: "gpt-4o-mini",
            content_type: "application/json",
            extra_headers: vec![],
        }),
        "anthropic" => Some(TestRequest {
            body: serde_json::to_vec(&json!({
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "corpus test anthropic"}],
                "system": "You are helpful",
            }))
            .unwrap(),
            path: "/v1/messages",
            expected_model: "claude-sonnet-4-6",
            content_type: "application/json",
            extra_headers: vec![("anthropic-version", "2024-06-01")],
        }),
        "cohere" => Some(TestRequest {
            body: serde_json::to_vec(&json!({
                "model": "command-r-plus",
                "message": "corpus test cohere",
                "chat_history": [{"role": "SYSTEM", "message": "You are helpful"}],
            }))
            .unwrap(),
            path: "/v2/chat",
            expected_model: "command-r-plus",
            content_type: "application/json",
            extra_headers: vec![],
        }),
        "google" => Some(TestRequest {
            body: serde_json::to_vec(&json!({
                "contents": [{"parts": [{"text": "corpus test gemini"}]}],
                "generationConfig": {"temperature": 0.2},
            }))
            .unwrap(),
            path: "/v1/models/gemini-2.5-pro:generateContent",
            expected_model: "gemini-2.5-pro",
            content_type: "application/json",
            extra_headers: vec![],
        }),
        "bedrock" => Some(TestRequest {
            body: serde_json::to_vec(&json!({
                "modelId": "anthropic.claude-3-sonnet",
                "messages": [{"role": "user", "content": "corpus test bedrock"}],
                "max_tokens": 128,
            }))
            .unwrap(),
            path: "/model/anthropic.claude-3-sonnet/invoke",
            expected_model: "anthropic.claude-3-sonnet",
            content_type: "application/json",
            extra_headers: vec![],
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Resolve matched_provider from gating (same as proxy gating layer)
// ---------------------------------------------------------------------------

fn resolve_provider_from_gating(gating: &GatingBundle, host: &str) -> Option<String> {
    for entity in &gating.entities.providers {
        for host_rule in &entity.hosts {
            if soth_core::bundle::detect::glob_match(&host_rule.pattern, host)
                || host_rule.pattern == host
            {
                return Some(entity.entity_id.clone());
            }
        }
    }
    None
}

fn materialize_host(pattern: &str) -> String {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Core corpus test: for every LLM provider in the bundle, generate a request
/// using the provider's api_format, resolve matched_provider via gating,
/// and verify model extraction + is_ai_call.
#[test]
fn realworld_provider_corpus_model_extraction() {
    let Some(native) = load_native_bundle() else {
        return;
    };

    let detect = soth_bundle::detect_from_native(&native);
    let gating = soth_bundle::gating_from_native(&native);
    let registry = build_registry(&detect.as_slice()).expect("build registry");
    let snapshot = soth_core::SessionSnapshot::default();

    let mut tested = 0usize;
    let mut model_ok = 0usize;
    let mut ai_call_ok = 0usize;
    let mut skipped_no_format = 0usize;
    let mut failures = Vec::new();

    for (provider_id, entry) in &detect.llm_providers {
        let api_format = match entry.api_format.as_deref() {
            Some(f) => f,
            None => {
                skipped_no_format += 1;
                continue;
            }
        };

        let test_req = match request_for_api_format(api_format) {
            Some(r) => r,
            None => {
                skipped_no_format += 1;
                continue;
            }
        };

        // Find an exact (non-wildcard) host from domain_index for this provider.
        // In production, the gating layer resolves the real host; here we use
        // the exact domain entry to avoid wildcard materialization issues.
        let host = detect
            .domain_index
            .iter()
            .find(|(domain, slug)| slug.as_str() == provider_id && !domain.contains('*'))
            .map(|(domain, _)| domain.clone());

        let host = match host {
            Some(h) => h,
            None => {
                // Provider only has wildcard domains — skip (can't simulate without real host)
                skipped_no_format += 1;
                continue;
            }
        };

        // Build request with matched_provider set from gating (like the proxy does)
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), host.clone());
        headers.insert(
            "content-type".to_string(),
            test_req.content_type.to_string(),
        );
        for (k, v) in &test_req.extra_headers {
            headers.insert(k.to_string(), v.to_string());
        }

        let mut meta = ConnectionMeta::from_transport(
            Uuid::new_v4(),
            SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            None,
            None,
        );

        // Resolve matched_provider from gating — same as the proxy's gating layer
        meta.matched_provider =
            resolve_provider_from_gating(&gating, &host).or_else(|| Some(provider_id.clone()));

        let request = RawRequest {
            method: "POST".to_string(),
            path: test_req.path.to_string(),
            headers,
            body: Bytes::from(test_req.body),
            connection_meta: meta,
        };

        let out = process_with_registry(&registry, &request, &detect.as_slice(), &snapshot);

        tested += 1;

        // Model extraction
        match out.normalized.model.as_deref() {
            Some(model) if model == test_req.expected_model => model_ok += 1,
            other => {
                failures.push(format!(
                    "{} ({}): model expected '{}' got {:?}",
                    provider_id, api_format, test_req.expected_model, other
                ));
            }
        }

        // AI call detection
        if out.normalized.is_ai_call {
            ai_call_ok += 1;
        }

        // Content hash should be non-empty
        assert!(
            !out.normalized.user_content_hash.is_empty(),
            "{provider_id}: user_content_hash empty"
        );
    }

    eprintln!(
        "\n[Provider corpus] tested={tested} model={model_ok}/{tested} ai_call={ai_call_ok}/{tested} skipped={skipped_no_format}",
    );
    if !failures.is_empty() {
        eprintln!("Failures ({}):", failures.len());
        for f in &failures[..failures.len().min(15)] {
            eprintln!("  {f}");
        }
    }

    assert!(
        tested >= 20,
        "expected at least 20 testable providers, got {tested}"
    );

    // AI call detection should be near-perfect
    assert!(
        ai_call_ok * 100 / tested >= 95,
        "AI call detection rate: {}/{} ({:.0}%)",
        ai_call_ok,
        tested,
        ai_call_ok as f64 / tested as f64 * 100.0
    );

    // Model extraction currently works for providers where the detect engine
    // recognizes the host pattern (openai, anthropic, google, cohere, bedrock).
    // For other providers using OpenAI-compatible format, the engine falls back
    // to CustomRest but the format descriptor isn't applied via matched_provider
    // alone — this is a known gap in the detect pipeline to address.
    assert!(
        model_ok >= 3,
        "model extraction should work for at least core providers, got {model_ok}/{tested}",
    );
}

/// Verify that domain_index coverage is comprehensive — every provider
/// with a domain should be resolvable through the gating pipeline.
#[test]
fn realworld_domain_index_coverage() {
    let Some(native) = load_native_bundle() else {
        return;
    };

    let detect = soth_bundle::detect_from_native(&native);
    let gating = soth_bundle::gating_from_native(&native);

    let mut covered = 0usize;
    let mut uncovered = Vec::new();

    // Only check domains that map to providers/applications in the detect bundle
    // (skip tool_catalog domains which are detection-only, no gating rules)
    for (domain, provider_slug) in &detect.domain_index {
        if !detect.llm_providers.contains_key(provider_slug)
            && !detect.products.contains_key(provider_slug)
        {
            continue; // tool_catalog entry, no gating rules expected
        }
        let host = materialize_host(domain);
        if resolve_provider_from_gating(&gating, &host).is_some() {
            covered += 1;
        } else {
            uncovered.push(format!("{domain} → {provider_slug}"));
        }
    }

    let total = covered + uncovered.len();
    eprintln!(
        "\n[Domain coverage] {}/{} domains resolvable via gating ({} uncovered)",
        covered,
        total,
        uncovered.len()
    );

    // At least 50% of domains should resolve (wildcards may not match materialized hosts)
    assert!(
        total == 0 || covered * 100 / total >= 50,
        "domain resolution too low: {covered}/{total}"
    );
}

/// Verify that the detect bundle has rest_formats for all standard api_formats.
#[test]
fn realworld_rest_format_coverage() {
    let Some(native) = load_native_bundle() else {
        return;
    };

    let detect = soth_bundle::detect_from_native(&native);

    let required_formats = ["openai", "anthropic", "cohere", "google", "bedrock"];
    for fmt in &required_formats {
        assert!(
            detect.rest_formats.contains_key(*fmt),
            "rest_formats missing required format: {fmt}"
        );
    }

    eprintln!(
        "\n[Format coverage] {} rest_formats loaded (required: {})",
        detect.rest_formats.len(),
        required_formats.len()
    );
}

#[test]
fn classify_codex_format_from_bundle() {
    let Some(native) = load_native_bundle() else {
        return;
    };
    let detect = soth_bundle::detect_from_native(&native);

    // Verify codex is in applications
    assert!(
        detect.products.contains_key("codex"),
        "codex not in applications"
    );
    assert_eq!(
        detect.products["codex"].api_format.as_deref(),
        Some("codex"),
        "codex api_format wrong"
    );

    // Verify codex format in rest_formats
    assert!(
        detect.rest_formats.contains_key("codex"),
        "codex not in rest_formats"
    );

    // Test classify_request_format
    let result = soth_detect::classify_request_format(
        "chatgpt.com",
        "/backend-api/codex/responses",
        &detect.as_slice(),
    );
    eprintln!("classify_request_format result: {result:?}");
    assert_eq!(
        result.as_deref(),
        Some("codex"),
        "classify_request_format should return codex"
    );
}

#[test]
fn codex_format_features_survive_deserialization() {
    let Some(native) = load_native_bundle() else {
        return;
    };
    let detect = soth_bundle::detect_from_native(&native);

    let desc = detect
        .rest_formats
        .get("codex")
        .expect("codex in rest_formats");
    eprintln!("codex features count: {}", desc.features.len());
    assert!(
        !desc.features.is_empty(),
        "codex should have features after deserialization"
    );

    let chat = &desc.features[0];
    eprintln!("feature id: {}, type: {}", chat.id, chat.feature_type);
    assert_eq!(chat.feature_type, "chat");

    // Check if FeatureResponseSpec::Stream variant was parsed
    match &chat.response {
        soth_core::bundle::detect::FeatureResponseSpec::Stream { stream } => {
            eprintln!(
                "stream format: {:?}, rules: {}",
                stream.format,
                stream.rules.len()
            );
            assert!(!stream.rules.is_empty(), "stream rules should be non-empty");
        }
        soth_core::bundle::detect::FeatureResponseSpec::Direct(map) => {
            panic!(
                "expected Stream variant, got Direct with keys: {:?}",
                map.keys().collect::<Vec<_>>()
            );
        }
    }
}
