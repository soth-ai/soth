//! Provider parser fallback and usage/cost enrichment helpers.

use std::sync::Arc;

use hudsucker::hyper;
use soth_budget::{PricingCatalog, TokenUsage};

use crate::providers::{
    sse::parse_sse_body, AiProvider, HttpRequest, ProviderRegistry, ProviderUsage,
};

/// Extracted usage/cost metadata from provider response payloads.
#[derive(Debug, Clone, Default)]
pub struct ResponseUsageMeta {
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

fn parser_fallback_host(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" | "chatgpt" | "codex" | "github-copilot" => Some("api.openai.com"),
        "anthropic" | "claude" | "claude-code" => Some("api.anthropic.com"),
        "google" | "gemini" => Some("generativelanguage.googleapis.com"),
        _ => None,
    }
}

pub fn resolve_provider_parser(
    registry: &ProviderRegistry,
    host: &str,
    provider: &str,
) -> Option<Arc<dyn AiProvider>> {
    registry
        .find_provider(host)
        .or_else(|| parser_fallback_host(provider).and_then(|h| registry.find_provider(h)))
}

pub fn build_http_request_for_provider(
    method: &str,
    path: &str,
    headers: &hyper::HeaderMap,
    body: Option<Vec<u8>>,
) -> HttpRequest {
    let mut req = HttpRequest::new(method, path);
    for (key, value) in headers {
        if let Ok(value_str) = value.to_str() {
            req = req.with_header(key.as_str(), value_str);
        }
    }
    if let Some(body) = body {
        req = req.with_body(body);
    }
    req
}

pub fn extract_usage_meta_from_decoded_payload(
    registry: &ProviderRegistry,
    pricing_catalog: &PricingCatalog,
    provider: &str,
    host: &str,
    decoded_body: &[u8],
    is_sse: bool,
    fallback_model: Option<&str>,
) -> ResponseUsageMeta {
    let Some(parser) = resolve_provider_parser(registry, host, provider) else {
        return ResponseUsageMeta::default();
    };

    let usage = if is_sse {
        let parsed = parse_sse_body(parser, decoded_body);
        if parsed.input_tokens == 0 && parsed.output_tokens == 0 {
            None
        } else {
            Some(parsed)
        }
    } else {
        parser.extract_usage(decoded_body)
    };

    build_response_usage_meta(usage, fallback_model, pricing_catalog)
}

fn build_response_usage_meta(
    provider_usage: Option<ProviderUsage>,
    fallback_model: Option<&str>,
    pricing_catalog: &PricingCatalog,
) -> ResponseUsageMeta {
    let mut meta = ResponseUsageMeta::default();
    let Some(provider_usage) = provider_usage else {
        return meta;
    };

    if provider_usage.input_tokens > 0 || provider_usage.output_tokens > 0 {
        meta.input_tokens = Some(provider_usage.input_tokens);
        meta.output_tokens = Some(provider_usage.output_tokens);
    }
    meta.cache_read_tokens = provider_usage
        .cache_read_tokens
        .or(provider_usage.cached_tokens);
    meta.cache_write_tokens = provider_usage.cache_write_tokens;
    meta.reasoning_tokens = provider_usage.reasoning_tokens;

    let model = provider_usage
        .model
        .or_else(|| fallback_model.map(ToString::to_string));
    meta.model = model.clone();

    if let (Some(input_tokens), Some(output_tokens)) = (meta.input_tokens, meta.output_tokens) {
        let token_usage = TokenUsage::new(input_tokens, output_tokens);
        let model_for_pricing = model.as_deref().unwrap_or("unknown");
        let cost = pricing_catalog.calculate_cost_with_cache(
            model_for_pricing,
            &token_usage,
            provider_usage.cache_read_tokens,
            provider_usage.cache_write_tokens,
        );
        meta.cost_usd = Some(cost);
    }

    meta
}
