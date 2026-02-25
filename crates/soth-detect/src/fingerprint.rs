use crate::types::{DetectBundleSlice, DetectedFormat, HeaderMap, ProviderEntry};
use crate::util::{header_value, host_without_port};

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

    if path_lc.contains("/v1/chat/completions")
        || path_lc.contains("/v1/completions")
        || path_lc.contains("/v1/embeddings")
    {
        return DetectedFormat::OpenAIRest;
    }

    if path_lc.contains("/v1/messages") {
        return DetectedFormat::AnthropicRest;
    }

    if path_lc.contains("/v2/generate") || path_lc.contains("/v2/chat") {
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
        let host = host_without_port(host).to_ascii_lowercase();
        if let Some(provider_id) = bundle.domain_index.get(&host) {
            return provider_entry_to_format(provider_id, bundle.llm_providers.get(provider_id));
        }

        if host == "127.0.0.1" {
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
