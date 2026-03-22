use crate::types::{DetectBundleSlice, DetectedFormat, HeaderMap, ProviderEntry};
use crate::util::{header_value, lookup_domain_provider};
// Re-export classify types from soth-core (canonical location after SOLID refactor).
pub use soth_core::bundle::classify::{ClassifyPairResult, ClassifyResult};

pub fn fingerprint(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body_prefix: &[u8],
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> DetectedFormat {
    let _ = method;

    if let Some(content_type) = header_value(headers, "content-type") {
        let ct = content_type.to_ascii_lowercase();
        if ct.contains("application/grpc") {
            return DetectedFormat::GrpcProtobuf;
        }
        if ct.contains("application/graphql") {
            return DetectedFormat::GraphQL;
        }
        if ct.contains("application/json-rpc") || ct.contains("application/jsonrpc") {
            return DetectedFormat::JsonRpc;
        }
    }

    // Application entity with an explicit api_format takes priority — web apps
    // like gemini.google.com use a different format (form-encoded) than the
    // provider API (JSON), so the app-specific descriptor must win.
    if let Some(app_id) = matched_application {
        if let Some(app_entry) = bundle.products.get(app_id) {
            if let Some(api_format) = app_entry.api_format.as_deref() {
                if bundle.rest_formats.contains_key(api_format) {
                    return DetectedFormat::CustomRest(api_format.to_string());
                }
                let synthetic = provider_entry_to_format(
                    api_format,
                    bundle.llm_providers.get(api_format),
                );
                if synthetic != DetectedFormat::Unknown {
                    return synthetic;
                }
            }
        }
    }

    if let Some(provider_id) = matched_provider {
        let hinted = provider_entry_to_format(provider_id, bundle.llm_providers.get(provider_id));
        if hinted != DetectedFormat::Unknown {
            return hinted;
        }
        if bundle.rest_formats.contains_key(provider_id) {
            return DetectedFormat::CustomRest(provider_id.to_string());
        }
    }

    if header_value(headers, "anthropic-version").is_some() {
        return DetectedFormat::AnthropicRest;
    }

    if header_value(headers, "x-goog-api-key").is_some() {
        return DetectedFormat::GeminiRest;
    }

    let path_lc = path.to_ascii_lowercase();
    let body = String::from_utf8_lossy(body_prefix).to_ascii_lowercase();

    if is_openai_like_path(&path_lc) {
        return DetectedFormat::OpenAIRest;
    }

    if is_anthropic_like_path(&path_lc) {
        return DetectedFormat::AnthropicRest;
    }

    if is_cohere_like_path(&path_lc) {
        return DetectedFormat::CohereRest;
    }

    if path_lc.contains(":generatecontent") || path_lc.contains(":streamgeneratecontent") {
        return DetectedFormat::GeminiRest;
    }

    if path_lc.contains("/model/")
        && (path_lc.contains("/invoke") || path_lc.contains("bedrock-runtime"))
    {
        return DetectedFormat::BedrockRest;
    }

    // JSON-RPC heuristic detection removed — no AI provider uses JSON-RPC
    // for inference. Explicit Content-Type and bundle api_format hints are
    // still honoured via provider_entry_to_format().

    if let Some(host) =
        header_value(headers, "host").or_else(|| header_value(headers, ":authority"))
    {
        if let Some(provider_id) = lookup_domain_provider(bundle.domain_index, host) {
            let format =
                provider_entry_to_format(provider_id, bundle.llm_providers.get(provider_id));
            if format != DetectedFormat::Unknown {
                return format;
            }
            // Apps with custom REST formats are in rest_formats, not llm_providers
            if bundle.rest_formats.contains_key(provider_id) {
                return DetectedFormat::CustomRest(provider_id.to_string());
            }
            // Domain maps to an application with api_format (e.g. chatgpt.com → chatgpt → chatgpt_web).
            // Skip if a more specific matched_application was already resolved by gating.
            if matched_application.is_none() {
                if let Some(app_entry) = bundle.products.get(provider_id) {
                    if let Some(api_format) = app_entry.api_format.as_deref() {
                        if bundle.rest_formats.contains_key(api_format) {
                            return DetectedFormat::CustomRest(api_format.to_string());
                        }
                    }
                }
            }
        }

        if host.eq_ignore_ascii_case("127.0.0.1") {
            return DetectedFormat::OpenAIRest;
        }
    }

    let looks_graphql = (body.contains("query")
        && (body.contains("mutation ")
            || body.contains("query ")
            || body.contains("subscription ")))
        || (body.contains("operationname") && body.contains("variables"))
        || (body.contains("extensions") && body.contains("persistedquery"));

    if looks_graphql {
        return DetectedFormat::GraphQL;
    }

    DetectedFormat::Unknown
}


fn is_openai_like_path(path: &str) -> bool {
    if path.contains("/v1/chat/completions")
        || path.contains("/v1/completions")
        || path.contains("/v1/embeddings")
        || path.contains("/v1/responses")
        || path.contains("/api/v1/responses")
        || path.contains("/api/v0/chat/completion")
        || path.contains("/chat/api/v2/conversations")
        || path.contains("/chat/conversation")
        || path.contains("/chat/completion")
        || path.contains("/v1/chat-with-documents")
        || path.contains("/v1/llm-proxy")
        || path.contains("/v1/llm-proxy-stream")
    {
        return true;
    }

    if (path.contains("/backend-api/") || path.contains("/backend-anon/"))
        && path.contains("conversation")
    {
        return true;
    }

    path.contains("/openai/deployments/")
        && (path.contains("/chat/completions")
            || path.contains("/completions")
            || path.contains("/embeddings")
            || path.contains("/responses"))
}

fn is_anthropic_like_path(path: &str) -> bool {
    path.contains("/v1/messages")
        || path.contains("/v1/complete")
        || (path.contains("/api/organizations/") && path.contains("/completion"))
}

fn is_cohere_like_path(path: &str) -> bool {
    path.contains("/v2/generate")
        || path.contains("/v2/chat")
        || path.contains("/v1/chat")
        || path.contains("/v1/generate")
        || path.contains("/v1/embed")
}

/// Classify a request using signal-based matching rules on providers and applications.
///
/// Thin wrapper over `soth_core::classify_request_pair` that adapts
/// `DetectBundleSlice` provider/application iterators.
pub fn classify_request(
    host: Option<&str>,
    path: &str,
    headers: &HeaderMap,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> Option<ClassifyResult> {
    let pair = classify_request_pair(
        host,
        path,
        headers,
        process_bundle_id,
        process_name,
        parent_process_name,
        bundle,
    );
    match (&pair.provider, &pair.application) {
        (Some(p), Some(a)) => {
            if p.priority >= a.priority {
                Some(p.clone())
            } else {
                Some(a.clone())
            }
        }
        (Some(p), None) => Some(p.clone()),
        (None, Some(a)) => Some(a.clone()),
        (None, None) => None,
    }
}

/// Classify a request returning the best provider AND best application match
/// independently. Delegates to `soth_core::classify_request_pair`.
pub fn classify_request_pair(
    host: Option<&str>,
    path: &str,
    headers: &HeaderMap,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> ClassifyPairResult {
    let providers = bundle.llm_providers.iter().map(|(key, entry)| {
        let entity_id = entry.provider_id.as_deref().unwrap_or(key.as_str());
        (key.as_str(), entity_id, entry.matching_rules.as_slice())
    });
    let applications = bundle.products.iter().map(|(key, entry)| {
        let entity_id = entry.app_id.as_deref().unwrap_or(key.as_str());
        (key.as_str(), entity_id, entry.matching_rules.as_slice())
    });

    soth_core::classify_request_pair(
        host,
        path,
        headers,
        process_bundle_id,
        process_name,
        parent_process_name,
        providers,
        applications,
    )
}

fn provider_entry_to_format(provider_id: &str, entry: Option<&ProviderEntry>) -> DetectedFormat {
    if let Some(entry) = entry {
        if let Some(api_format) = entry.api_format.as_deref() {
            let lower = api_format.to_ascii_lowercase();
            if lower.contains("openai") {
                return DetectedFormat::OpenAIRest;
            }
            if lower.contains("anthropic") {
                return DetectedFormat::AnthropicRest;
            }
            if lower.contains("cohere") {
                return DetectedFormat::CohereRest;
            }
            if lower.contains("google") || lower.contains("gemini") {
                return DetectedFormat::GeminiRest;
            }
            if lower.contains("bedrock") {
                return DetectedFormat::BedrockRest;
            }
            if lower.contains("graphql") {
                return DetectedFormat::GraphQL;
            }
            if lower.contains("grpc") {
                return DetectedFormat::GrpcProtobuf;
            }
            if lower.contains("jsonrpc") || lower.contains("json-rpc") {
                return DetectedFormat::JsonRpc;
            }
            return DetectedFormat::CustomRest(api_format.to_string());
        }
    }

    let fallback = provider_id.to_ascii_lowercase();
    if fallback.contains("openai") || fallback.contains("lmstudio") {
        return DetectedFormat::OpenAIRest;
    }
    if fallback.contains("anthropic") {
        return DetectedFormat::AnthropicRest;
    }
    if fallback.contains("cohere") {
        return DetectedFormat::CohereRest;
    }
    if fallback.contains("google") || fallback.contains("gemini") || fallback.contains("vertex") {
        return DetectedFormat::GeminiRest;
    }
    if fallback.contains("bedrock") {
        return DetectedFormat::BedrockRest;
    }
    if fallback.contains("jsonrpc") || fallback.contains("json-rpc") {
        return DetectedFormat::JsonRpc;
    }

    DetectedFormat::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OwnedDetectBundle;
    use soth_core::SignalKind;
    use std::collections::BTreeMap;

    fn bundle_fixture() -> OwnedDetectBundle {
        let mut bundle = OwnedDetectBundle::default();
        bundle.llm_providers.insert(
            "hint-jsonrpc".to_string(),
            ProviderEntry {
                provider_id: Some("hint-jsonrpc".to_string()),
                name: Some("hint-jsonrpc".to_string()),
                api_format: Some("jsonrpc".to_string()),
                ..ProviderEntry::default()
            },
        );
        bundle.llm_providers.insert(
            "openai".to_string(),
            ProviderEntry {
                provider_id: Some("openai".to_string()),
                name: Some("openai".to_string()),
                api_format: Some("openai".to_string()),
                ..ProviderEntry::default()
            },
        );
        bundle
            .domain_index
            .insert("api.openai.com".to_string(), "openai".to_string());
        bundle
    }

    fn headers(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (k, v) in items {
            out.insert((*k).to_string(), (*v).to_string());
        }
        out
    }

    #[test]
    fn matched_provider_hint_overrides_ambiguous_request() {
        let bundle = bundle_fixture();
        let detected = fingerprint(
            "POST",
            "/internal/proxy",
            &headers(&[("content-type", "text/plain")]),
            br#"{"hello":"world"}"#,
            Some("hint-jsonrpc"),
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::JsonRpc);
    }

    #[test]
    fn grpc_content_type_takes_priority_over_hint() {
        let bundle = bundle_fixture();
        let detected = fingerprint(
            "POST",
            "/v1/chat/completions",
            &headers(&[("content-type", "application/grpc+proto")]),
            b"\x0a\x01a",
            Some("openai"),
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::GrpcProtobuf);
    }

    #[test]
    fn host_domain_index_maps_to_provider_format() {
        let bundle = bundle_fixture();
        let detected = fingerprint(
            "POST",
            "/anything",
            &headers(&[
                ("host", "api.openai.com"),
                ("content-type", "application/octet-stream"),
            ]),
            br#"{}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn wildcard_domain_index_maps_to_provider_format() {
        let mut bundle = bundle_fixture();
        bundle
            .domain_index
            .insert("*.openai.azure.com".to_string(), "openai".to_string());

        let detected = fingerprint(
            "POST",
            "/openai/deployments/test/chat/completions",
            &headers(&[
                ("host", "my-resource.openai.azure.com"),
                ("content-type", "application/json"),
            ]),
            br#"{}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn backend_api_conversation_is_treated_as_openai_rest() {
        let bundle = bundle_fixture();
        let detected = fingerprint(
            "POST",
            "/backend-api/conversation",
            &headers(&[
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn responses_endpoint_is_treated_as_openai_rest() {
        let bundle = bundle_fixture();
        let detected = fingerprint(
            "POST",
            "/api/v1/responses",
            &headers(&[
                ("host", "openrouter.ai"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"gpt-4.1-mini","input":"hello"}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn detection_hints_match_provider_before_hardcoded_paths() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.insert(
            "anthropic".to_string(),
            ProviderEntry {
                provider_id: Some("anthropic".to_string()),
                name: Some("Anthropic".to_string()),
                api_format: Some("anthropic".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        {
                            "pattern": "api.anthropic.com",
                            "paths": {
                                "allow": ["/v1/messages"],
                                "deny_exact": [],
                                "deny_glob": []
                            }
                        }
                    ],
                    "path_patterns": ["**/v1/messages**"]
                })),
                ..ProviderEntry::default()
            },
        );

        let detected = fingerprint(
            "POST",
            "/v1/messages",
            &headers(&[
                ("host", "api.anthropic.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"claude-sonnet"}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::AnthropicRest);
    }

    #[test]
    fn app_entity_matched_provider_does_not_trigger_bedrock_catchall() {
        let mut bundle = bundle_fixture();
        // Simulate bedrock provider with catch-all path pattern (like real bundle)
        bundle.llm_providers.insert(
            "aws_bedrock".to_string(),
            ProviderEntry {
                provider_id: Some("aws_bedrock".to_string()),
                name: Some("AWS Bedrock".to_string()),
                api_format: Some("bedrock".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [{"pattern": "bedrock-runtime.*.amazonaws.com", "paths": {}}],
                    "path_patterns": ["**"]
                })),
                ..ProviderEntry::default()
            },
        );

        // chatgpt is an app entity (matched_provider from gating), not in llm_providers.
        // Should fall through to path heuristics, NOT match bedrock's ** catch-all.
        let detected = fingerprint(
            "POST",
            "/backend-api/conversation",
            &headers(&[
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            Some("chatgpt"),
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn app_entity_claude_uses_header_heuristic() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.insert(
            "aws_bedrock".to_string(),
            ProviderEntry {
                provider_id: Some("aws_bedrock".to_string()),
                name: Some("AWS Bedrock".to_string()),
                api_format: Some("bedrock".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [{"pattern": "bedrock-runtime.*.amazonaws.com", "paths": {}}],
                    "path_patterns": ["**"]
                })),
                ..ProviderEntry::default()
            },
        );

        let detected = fingerprint(
            "POST",
            "/v1/messages",
            &headers(&[
                ("host", "api.anthropic.com"),
                ("content-type", "application/json"),
                ("anthropic-version", "2024-01-01"),
            ]),
            br#"{"model":"claude-sonnet"}"#,
            Some("claude"),
            None,
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::AnthropicRest);
    }

    #[test]
    fn bedrock_path_requires_model_segment() {
        let bundle = bundle_fixture();
        // bedrock-runtime in path but without /model/ should NOT match bedrock
        let detected = fingerprint(
            "POST",
            "/some/bedrock-runtime/path",
            &headers(&[("content-type", "application/json")]),
            br#"{"hello":"world"}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_ne!(detected, DetectedFormat::BedrockRest);
    }

    #[test]
    fn app_entity_uses_api_format_for_detection() {
        let mut bundle = bundle_fixture();
        bundle.rest_formats.insert(
            "claude_web".to_string(),
            crate::types::RestFormatDescriptor {
                provider_hint: Some("anthropic".to_string()),
                ..Default::default()
            },
        );
        bundle.products.insert(
            "claude".to_string(),
            crate::types::ProductEntry {
                app_id: Some("claude".to_string()),
                name: Some("Claude Web".to_string()),
                api_format: Some("claude_web".to_string()),
                ..Default::default()
            },
        );

        let detected = fingerprint(
            "POST",
            "/api/organizations/org123/chat_conversations/conv456/completion",
            &headers(&[
                ("host", "claude.ai"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"claude-sonnet-4-6"}"#,
            None,
            Some("claude"),
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::CustomRest("claude_web".to_string()));
    }

    #[test]
    fn app_entity_without_api_format_falls_to_heuristic() {
        let mut bundle = bundle_fixture();
        bundle.products.insert(
            "chatgpt".to_string(),
            crate::types::ProductEntry {
                app_id: Some("chatgpt".to_string()),
                name: Some("ChatGPT".to_string()),
                api_format: None,
                ..Default::default()
            },
        );

        let detected = fingerprint(
            "POST",
            "/backend-api/conversation",
            &headers(&[
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"gpt-4o","messages":[]}"#,
            None,
            Some("chatgpt"),
            &bundle.as_slice(),
        );
        // Should still work via path heuristic
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }

    #[test]
    fn codex_responses_via_bundle_app_entry() {
        let mut bundle = bundle_fixture();
        // Codex is a separate app entry with its own api_format
        bundle.rest_formats.insert(
            "codex_web".to_string(),
            crate::types::RestFormatDescriptor {
                provider_hint: Some("open_ai".to_string()),
                ..Default::default()
            },
        );
        bundle.products.insert(
            "codex".to_string(),
            crate::types::ProductEntry {
                app_id: Some("codex".to_string()),
                name: Some("OpenAI Codex".to_string()),
                api_format: Some("codex_web".to_string()),
                ..Default::default()
            },
        );

        // When gating identifies as codex app, api_format drives detection
        let detected = fingerprint(
            "POST",
            "/backend-api/codex/responses",
            &headers(&[
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"model":"gpt-5-3"}"#,
            None,
            Some("codex"),
            &bundle.as_slice(),
        );
        assert_eq!(
            detected,
            DetectedFormat::CustomRest("codex_web".to_string())
        );
    }

    #[test]
    fn classify_request_matches_provider_by_http_host() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.insert(
            "anthropic".to_string(),
            ProviderEntry {
                provider_id: Some("anthropic".to_string()),
                name: Some("Anthropic".to_string()),
                api_format: Some("anthropic".to_string()),
                matching_rules: vec![soth_core::MatchingRule {
                    rule_id: "anthropic-host".to_string(),
                    priority: 850,
                    requires_all: true,
                    notes: None,
                    metadata: serde_json::json!({}),
                    signals: vec![soth_core::SignalMatcher {
                        kind: SignalKind::HttpHost,
                        pattern: "api.anthropic.com".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    }],
                }],
                ..ProviderEntry::default()
            },
        );

        let result = classify_request(
            Some("api.anthropic.com"),
            "/v1/messages",
            &headers(&[("content-type", "application/json")]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );

        let result = result.expect("should match");
        assert_eq!(result.entity_id, "anthropic");
        assert_eq!(result.entity_kind, "provider");
        assert_eq!(result.priority, 850);
    }

    #[test]
    fn classify_request_matches_app_by_process_bundle_id() {
        let mut bundle = bundle_fixture();
        bundle.products.insert(
            "cursor".to_string(),
            crate::types::ProductEntry {
                app_id: Some("cursor".to_string()),
                name: Some("Cursor IDE".to_string()),
                matching_rules: vec![soth_core::MatchingRule {
                    rule_id: "cursor-bundle-id".to_string(),
                    priority: 1000,
                    requires_all: false,
                    notes: None,
                    metadata: serde_json::json!({}),
                    signals: vec![soth_core::SignalMatcher {
                        kind: SignalKind::ProcessBundleId,
                        pattern: "com.todesktop.230313mzl4w4u92".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    }],
                }],
                ..Default::default()
            },
        );

        let result = classify_request(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers(&[("content-type", "application/json")]),
            Some("com.todesktop.230313mzl4w4u92"),
            None,
            None,
            &bundle.as_slice(),
        );

        let result = result.expect("should match");
        assert_eq!(result.entity_id, "cursor");
        assert_eq!(result.entity_kind, "application");
        assert_eq!(result.priority, 1000);
    }

    #[test]
    fn classify_request_highest_priority_wins() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.get_mut("openai").unwrap().matching_rules = vec![
            soth_core::MatchingRule {
                rule_id: "openai-host-path".to_string(),
                priority: 900,
                requires_all: true,
                notes: None,
                metadata: serde_json::json!({}),
                signals: vec![
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpHost,
                        pattern: "api.openai.com".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    },
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpPath,
                        pattern: "/v1/chat/completions".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    },
                ],
            },
        ];
        bundle.llm_providers.insert(
            "anthropic".to_string(),
            ProviderEntry {
                provider_id: Some("anthropic".to_string()),
                name: Some("Anthropic".to_string()),
                api_format: Some("anthropic".to_string()),
                matching_rules: vec![soth_core::MatchingRule {
                    rule_id: "anthropic-host".to_string(),
                    priority: 850,
                    requires_all: true,
                    notes: None,
                    metadata: serde_json::json!({}),
                    signals: vec![soth_core::SignalMatcher {
                        kind: SignalKind::HttpHost,
                        pattern: "api.anthropic.com".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    }],
                }],
                ..ProviderEntry::default()
            },
        );

        // Request matches both openai (host+path, priority 900) and wouldn't match anthropic
        let result = classify_request(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers(&[("content-type", "application/json")]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );

        let result = result.expect("should match");
        assert_eq!(result.entity_id, "openai");
        assert_eq!(result.priority, 900);
    }

    #[test]
    fn classify_request_requires_all_signals() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.get_mut("openai").unwrap().matching_rules = vec![
            soth_core::MatchingRule {
                rule_id: "openai-host-path".to_string(),
                priority: 900,
                requires_all: true,
                notes: None,
                metadata: serde_json::json!({}),
                signals: vec![
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpHost,
                        pattern: "api.openai.com".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    },
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpPath,
                        pattern: "/v1/chat/completions".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    },
                ],
            },
        ];

        // Wrong path → requires_all fails
        let result = classify_request(
            Some("api.openai.com"),
            "/v1/embeddings",
            &headers(&[("content-type", "application/json")]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn classify_request_negated_signal() {
        let mut bundle = bundle_fixture();
        bundle.llm_providers.get_mut("openai").unwrap().matching_rules = vec![
            soth_core::MatchingRule {
                rule_id: "openai-not-internal".to_string(),
                priority: 800,
                requires_all: true,
                notes: None,
                metadata: serde_json::json!({}),
                signals: vec![
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpHost,
                        pattern: "api.openai.com".to_string(),
                        name: None,
                        is_negated: false,
                        metadata: serde_json::json!({}),
                    },
                    soth_core::SignalMatcher {
                        kind: SignalKind::HttpPath,
                        pattern: "/internal/*".to_string(),
                        name: None,
                        is_negated: true,
                        metadata: serde_json::json!({}),
                    },
                ],
            },
        ];

        // /internal path → negated signal matches → overall rule fails
        let result = classify_request(
            Some("api.openai.com"),
            "/internal/health",
            &headers(&[]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );
        assert!(result.is_none());

        // Normal path → negated signal does NOT match → rule succeeds
        let result = classify_request(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers(&[]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );
        assert!(result.is_some());
    }

    #[test]
    fn classify_request_returns_none_for_empty_rules() {
        let bundle = bundle_fixture();
        let result = classify_request(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers(&[("content-type", "application/json")]),
            None,
            None,
            None,
            &bundle.as_slice(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn domain_index_resolves_app_api_format() {
        let mut bundle = bundle_fixture();
        bundle
            .domain_index
            .insert("chatgpt.com".to_string(), "chatgpt".to_string());
        bundle.rest_formats.insert(
            "chatgpt_web".to_string(),
            crate::types::RestFormatDescriptor {
                provider_hint: Some("open_ai".to_string()),
                ..Default::default()
            },
        );
        bundle.products.insert(
            "chatgpt".to_string(),
            crate::types::ProductEntry {
                app_id: Some("chatgpt".to_string()),
                name: Some("ChatGPT".to_string()),
                api_format: Some("chatgpt_web".to_string()),
                ..Default::default()
            },
        );

        // Non-codex, non-conversation path — resolved via domain_index → app → api_format
        let detected = fingerprint(
            "POST",
            "/backend-api/ces/v1/t",
            &headers(&[
                ("host", "chatgpt.com"),
                ("content-type", "application/json"),
            ]),
            br#"{"events":[]}"#,
            None,
            None,
            &bundle.as_slice(),
        );
        assert_eq!(
            detected,
            DetectedFormat::CustomRest("chatgpt_web".to_string())
        );
    }
}
