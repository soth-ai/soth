use crate::types::{DetectBundleSlice, DetectedFormat, HeaderMap, ProviderEntry};
use crate::util::{header_value, lookup_domain_provider};

pub fn fingerprint(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body_prefix: &[u8],
    matched_provider: Option<&str>,
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

    if let Some(provider_id) = matched_provider {
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

    if path_lc.contains("/model/") && path_lc.contains("/invoke")
        || path_lc.contains("bedrock-runtime")
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
            return provider_entry_to_format(provider_id, bundle.llm_providers.get(provider_id));
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
            },
        );
        bundle.llm_providers.insert(
            "openai".to_string(),
            ProviderEntry {
                provider_id: Some("openai".to_string()),
                name: Some("openai".to_string()),
                api_format: Some("openai".to_string()),
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
            &bundle.as_slice(),
        );
        assert_eq!(detected, DetectedFormat::OpenAIRest);
    }
}
