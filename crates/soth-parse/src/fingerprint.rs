use crate::types::{DetectBundleSlice, DetectedFormat, HeaderMap, ProviderEntry};
use crate::util::{header_value, host_without_port, lookup_domain_provider};
use serde_json::Value as JsonValue;
use soth_core::{MatchingRule, SignalKind};

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
        if let Some(app_entry) = bundle.applications.get(app_id) {
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
    } else if let Some(provider_id) = match_provider_by_detection_hints(path, headers, bundle) {
        let hinted = provider_entry_to_format(provider_id, bundle.llm_providers.get(provider_id));
        if hinted != DetectedFormat::Unknown {
            return hinted;
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
    let looks_jsonrpc = body.contains("\"jsonrpc\"") && body.contains("\"method\"");

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

    if path_lc.contains("jsonrpc")
        || ((path_lc.ends_with("/rpc") || path_lc.contains("/rpc/")) && looks_jsonrpc)
    {
        return DetectedFormat::JsonRpc;
    }

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
                if let Some(app_entry) = bundle.applications.get(provider_id) {
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

    if looks_jsonrpc {
        return DetectedFormat::JsonRpc;
    }

    DetectedFormat::Unknown
}

fn match_provider_by_detection_hints<'a>(
    path: &str,
    headers: &HeaderMap,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<&'a str> {
    let path_lc = path.to_ascii_lowercase();
    let host_lc = header_value(headers, "host")
        .or_else(|| header_value(headers, ":authority"))
        .map(|host| {
            host_without_port(host)
                .trim_end_matches('.')
                .to_ascii_lowercase()
        });
    let mut best: Option<(&str, usize)> = None;

    for (provider_id, entry) in bundle.llm_providers.iter() {
        let Some(score) = detection_match_score(
            entry.detection.as_ref(),
            &path_lc,
            host_lc.as_deref(),
            headers,
        ) else {
            continue;
        };

        match best {
            Some((best_provider, best_score))
                if best_score > score
                    || (best_score == score && best_provider <= provider_id.as_str()) => {}
            _ => best = Some((provider_id.as_str(), score)),
        }
    }

    best.map(|(provider_id, _)| provider_id)
}

fn detection_match_score(
    detection: Option<&JsonValue>,
    path_lc: &str,
    host_lc: Option<&str>,
    headers: &HeaderMap,
) -> Option<usize> {
    let detection = detection?;
    let mut matched = false;
    let mut score = 0usize;

    if let Some(patterns) = detection.get("path_patterns").and_then(JsonValue::as_array) {
        let mut best_path_score = 0usize;
        for pattern in patterns.iter().filter_map(JsonValue::as_str) {
            if pattern.is_empty() {
                continue;
            }
            let pattern_lc = pattern.to_ascii_lowercase();
            if glob_match(&pattern_lc, path_lc) {
                matched = true;
                best_path_score = best_path_score.max(non_wildcard_len(&pattern_lc) + 20);
            }
        }
        score += best_path_score;
    }

    if let Some(header_hints) = detection.get("header_hints") {
        let mut header_hits = 0usize;
        match header_hints {
            JsonValue::Object(map) => {
                for (name, hint_value) in map {
                    if let Some(header_val) = header_value(headers, name) {
                        if header_hint_matches(hint_value, header_val) {
                            header_hits += 1;
                        }
                    }
                }
            }
            JsonValue::Array(items) => {
                for item in items.iter().filter_map(JsonValue::as_str) {
                    if header_value(headers, item).is_some() {
                        header_hits += 1;
                    }
                }
            }
            _ => {}
        }
        if header_hits > 0 {
            matched = true;
            score += header_hits * 10;
        }
    }

    if let (Some(host), Some(hosts)) = (
        host_lc,
        detection.get("hosts").and_then(JsonValue::as_array),
    ) {
        let mut best_host_score = 0usize;
        for host_rule in hosts {
            let Some(pattern) = host_rule.get("pattern").and_then(JsonValue::as_str) else {
                continue;
            };
            let pattern_lc = pattern.to_ascii_lowercase();
            if !glob_match(&pattern_lc, host) {
                continue;
            }
            if !host_rule_allows_path(host_rule, path_lc) {
                continue;
            }
            let host_score = non_wildcard_len(&pattern_lc) + 100;
            best_host_score = best_host_score.max(host_score);
        }
        if best_host_score > 0 {
            matched = true;
            score += best_host_score;
        }
    }

    if matched {
        Some(score)
    } else {
        None
    }
}

fn host_rule_allows_path(host_rule: &JsonValue, path_lc: &str) -> bool {
    let Some(paths) = host_rule.get("paths") else {
        return true;
    };
    let deny_exact = paths
        .get("deny_exact")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(|value| value.to_ascii_lowercase());
    if deny_exact.into_iter().any(|deny| deny == path_lc) {
        return false;
    }

    let deny_glob = paths
        .get("deny_glob")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(|value| value.to_ascii_lowercase());
    if deny_glob.into_iter().any(|deny| glob_match(&deny, path_lc)) {
        return false;
    }

    let allow = paths
        .get("allow")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if allow.is_empty() {
        return true;
    }
    allow.iter().any(|allowed| glob_match(allowed, path_lc))
}

fn header_hint_matches(hint: &JsonValue, header_value_raw: &str) -> bool {
    let header_lc = header_value_raw.to_ascii_lowercase();
    match hint {
        JsonValue::String(expected) => {
            let expected_lc = expected.to_ascii_lowercase();
            expected_lc.is_empty() || expected_lc == "*" || header_lc.contains(&expected_lc)
        }
        JsonValue::Bool(flag) => *flag,
        JsonValue::Array(values) => values
            .iter()
            .any(|value| header_hint_matches(value, header_value_raw)),
        JsonValue::Object(map) => {
            if let Some(expected) = map.get("contains").and_then(JsonValue::as_str) {
                return header_lc.contains(&expected.to_ascii_lowercase());
            }
            if let Some(expected) = map.get("equals").and_then(JsonValue::as_str) {
                return header_lc == expected.to_ascii_lowercase();
            }
            true
        }
        _ => false,
    }
}

fn non_wildcard_len(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

use crate::util::glob_match;

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

/// Result of signal-based entity classification.
#[derive(Debug, Clone)]
pub struct ClassifyResult {
    /// Matched entity identifier (provider_id or app_id).
    pub entity_id: String,
    /// Whether the match is a provider ("provider") or application ("application").
    pub entity_kind: &'static str,
    /// The matching rule that fired.
    pub rule_id: String,
    /// Priority of the matching rule (higher = more specific).
    pub priority: u32,
}

/// Paired result returning the best provider AND best application match independently.
#[derive(Debug, Clone, Default)]
pub struct ClassifyPairResult {
    pub provider: Option<ClassifyResult>,
    pub application: Option<ClassifyResult>,
}

/// Classify a request using signal-based matching rules on providers and applications.
///
/// Evaluates all matching rules across all entities, picking the highest-priority
/// match. Falls back to `None` when no rules match (caller should use legacy detection).
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
    // Return the single highest-priority match for backward compat.
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
/// independently. This allows both to be resolved from matching_rules in a single pass.
pub fn classify_request_pair(
    host: Option<&str>,
    path: &str,
    headers: &HeaderMap,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> ClassifyPairResult {
    let host_lc = host.map(|h| {
        host_without_port(h)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    });
    let path_lc = path.to_ascii_lowercase();
    let content_type = header_value(headers, "content-type").map(|v| v.to_ascii_lowercase());

    let mut best_provider: Option<ClassifyResult> = None;
    let mut best_application: Option<ClassifyResult> = None;

    // Evaluate provider matching rules.
    for (provider_key, entry) in bundle.llm_providers.iter() {
        let entity_id = entry
            .provider_id
            .as_deref()
            .unwrap_or(provider_key.as_str());

        for rule in &entry.matching_rules {
            if rule_matches(
                rule,
                host_lc.as_deref(),
                &path_lc,
                headers,
                content_type.as_deref(),
                process_bundle_id,
                process_name,
                parent_process_name,
            ) {
                if best_provider
                    .as_ref()
                    .map_or(true, |b| rule.priority > b.priority)
                {
                    best_provider = Some(ClassifyResult {
                        entity_id: entity_id.to_string(),
                        entity_kind: "provider",
                        rule_id: rule.rule_id.clone(),
                        priority: rule.priority,
                    });
                }
            }
        }
    }

    // Evaluate application matching rules.
    for (app_key, entry) in bundle.applications.iter() {
        let entity_id = entry.app_id.as_deref().unwrap_or(app_key.as_str());

        for rule in &entry.matching_rules {
            if rule_matches(
                rule,
                host_lc.as_deref(),
                &path_lc,
                headers,
                content_type.as_deref(),
                process_bundle_id,
                process_name,
                parent_process_name,
            ) {
                if best_application
                    .as_ref()
                    .map_or(true, |b| rule.priority > b.priority)
                {
                    best_application = Some(ClassifyResult {
                        entity_id: entity_id.to_string(),
                        entity_kind: "application",
                        rule_id: rule.rule_id.clone(),
                        priority: rule.priority,
                    });
                }
            }
        }
    }

    ClassifyPairResult {
        provider: best_provider,
        application: best_application,
    }
}

/// Evaluate whether a single matching rule fires against the given request context.
fn rule_matches(
    rule: &MatchingRule,
    host_lc: Option<&str>,
    path_lc: &str,
    headers: &HeaderMap,
    content_type: Option<&str>,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
) -> bool {
    if rule.signals.is_empty() {
        return false;
    }

    if rule.requires_all {
        // AND: every signal must match (respecting negation).
        rule.signals.iter().all(|signal| {
            let raw_match = signal_matches(
                &signal.kind,
                &signal.pattern,
                host_lc,
                path_lc,
                headers,
                content_type,
                process_bundle_id,
                process_name,
                parent_process_name,
            );
            if signal.is_negated {
                !raw_match
            } else {
                raw_match
            }
        })
    } else {
        // OR: any signal match suffices.
        rule.signals.iter().any(|signal| {
            let raw_match = signal_matches(
                &signal.kind,
                &signal.pattern,
                host_lc,
                path_lc,
                headers,
                content_type,
                process_bundle_id,
                process_name,
                parent_process_name,
            );
            if signal.is_negated {
                !raw_match
            } else {
                raw_match
            }
        })
    }
}

/// Check if a single signal matches the request context.
fn signal_matches(
    kind: &SignalKind,
    pattern: &str,
    host_lc: Option<&str>,
    path_lc: &str,
    headers: &HeaderMap,
    content_type: Option<&str>,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
) -> bool {
    let pattern_lc = pattern.to_ascii_lowercase();
    match kind {
        SignalKind::HttpHost => {
            host_lc.map_or(false, |host| glob_match(&pattern_lc, host))
        }
        SignalKind::HttpPath => glob_match(&pattern_lc, path_lc),
        SignalKind::HttpMethod => {
            // Method comes from headers in our model (or could be passed separately).
            // Check :method pseudo-header or fall back to common method header.
            header_value(headers, ":method")
                .map_or(false, |m| m.eq_ignore_ascii_case(pattern))
        }
        SignalKind::HttpHeader => {
            // Pattern format: "header-name" (presence check) or "header-name:value" (value match).
            if let Some((name, expected)) = pattern.split_once(':') {
                header_value(headers, name.trim())
                    .map_or(false, |v| v.to_ascii_lowercase().contains(&expected.trim().to_ascii_lowercase()))
            } else {
                header_value(headers, pattern.trim()).is_some()
            }
        }
        SignalKind::ContentType => {
            content_type.map_or(false, |ct| ct.contains(&pattern_lc))
        }
        SignalKind::TlsSni => {
            // SNI is typically the same as the host for HTTPS connections.
            host_lc.map_or(false, |host| glob_match(&pattern_lc, host))
        }
        SignalKind::ProcessBundleId => {
            process_bundle_id.map_or(false, |bid| bid.eq_ignore_ascii_case(pattern))
        }
        SignalKind::ProcessName => {
            process_name.map_or(false, |pn| pn.eq_ignore_ascii_case(pattern))
        }
        SignalKind::ParentProcessName => {
            parent_process_name.map_or(false, |ppn| ppn.eq_ignore_ascii_case(pattern))
        }
        SignalKind::BodyStructure => {
            // Body structure matching requires deeper inspection; skip at fingerprint stage.
            false
        }
    }
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
        bundle.applications.insert(
            "claude".to_string(),
            crate::types::ApplicationEntry {
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
        bundle.applications.insert(
            "chatgpt".to_string(),
            crate::types::ApplicationEntry {
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
        bundle.applications.insert(
            "codex".to_string(),
            crate::types::ApplicationEntry {
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
        bundle.applications.insert(
            "cursor".to_string(),
            crate::types::ApplicationEntry {
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
        bundle.applications.insert(
            "chatgpt".to_string(),
            crate::types::ApplicationEntry {
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
