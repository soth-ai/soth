//! Provider parser fallback and usage/cost enrichment helpers.

use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use brotli::Decompressor as BrotliDecoder;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use hudsucker::hyper;
use soth_budget::{PricingCatalog, TokenUsage};
use tokio::task::spawn_blocking;

use crate::json_security::strip_json_security_prefix;
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

const GRPC_MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const GRPC_MAX_TOTAL_DECODE_BYTES: usize = 8 * 1024 * 1024;
const GRPC_MAX_FRAMES: usize = 16;
const GRPC_DECODE_TIMEOUT: Duration = Duration::from_millis(40);

fn parser_fallback_host(provider: &str) -> Option<&'static str> {
    soth_registry::canonical_inference_host(provider)
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

pub async fn extract_usage_meta_from_decoded_payload(
    registry: &ProviderRegistry,
    pricing_catalog: &PricingCatalog,
    provider: &str,
    host: &str,
    decoded_body: &[u8],
    is_sse: bool,
    content_type: Option<&str>,
    grpc_message_encoding: Option<&str>,
    fallback_model: Option<&str>,
) -> ResponseUsageMeta {
    let Some(parser) = resolve_provider_parser(registry, host, provider) else {
        return ResponseUsageMeta::default();
    };

    if !is_sse {
        if let Some(meta) = extract_usage_from_grpc_frames(
            parser.as_ref(),
            pricing_catalog,
            host,
            decoded_body,
            content_type,
            grpc_message_encoding,
            fallback_model,
        )
        .await
        {
            return meta;
        }
    }

    let sanitized = strip_json_security_prefix(decoded_body);
    let usage = if is_sse {
        let parsed = parse_sse_body(parser, sanitized);
        if parsed.input_tokens == 0 && parsed.output_tokens == 0 {
            None
        } else {
            Some(parsed)
        }
    } else {
        parser.extract_usage(sanitized)
    };

    build_response_usage_meta(usage, fallback_model, pricing_catalog)
}

async fn extract_usage_from_grpc_frames(
    parser: &dyn AiProvider,
    pricing_catalog: &PricingCatalog,
    host: &str,
    body: &[u8],
    content_type: Option<&str>,
    grpc_message_encoding: Option<&str>,
    fallback_model: Option<&str>,
) -> Option<ResponseUsageMeta> {
    if !is_grpc_signaled(content_type, host, body) {
        return None;
    }

    let frames = parse_grpc_frames(body)?;
    let mut decoded_total = 0usize;

    for (compressed, payload) in frames.into_iter().take(GRPC_MAX_FRAMES) {
        let decoded = decode_grpc_payload(payload, compressed, grpc_message_encoding).await?;
        decoded_total = decoded_total.saturating_add(decoded.len());
        if decoded_total > GRPC_MAX_TOTAL_DECODE_BYTES {
            return None;
        }

        let sanitized = strip_json_security_prefix(&decoded);
        if let Some(usage) = parser.extract_usage(sanitized) {
            if usage.input_tokens > 0 || usage.output_tokens > 0 || usage.model.is_some() {
                return Some(build_response_usage_meta(
                    Some(usage),
                    fallback_model,
                    pricing_catalog,
                ));
            }
        }
    }

    None
}

fn is_grpc_signaled(content_type: Option<&str>, host: &str, body: &[u8]) -> bool {
    let content_type = content_type.unwrap_or_default().to_ascii_lowercase();
    if content_type.contains("application/grpc") || content_type.contains("grpc-web") {
        return true;
    }

    let host = host.to_ascii_lowercase();
    let host_hint = host.contains("googleapis.com")
        || host.contains(".grpc.")
        || host.starts_with("grpc.")
        || host.ends_with(".grpc");
    host_hint && looks_like_grpc_frame(body)
}

fn looks_like_grpc_frame(body: &[u8]) -> bool {
    if body.len() < 5 || body[0] > 1 {
        return false;
    }
    let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    length <= body.len().saturating_sub(5) && length <= GRPC_MAX_FRAME_BYTES
}

fn parse_grpc_frames(body: &[u8]) -> Option<Vec<(bool, &[u8])>> {
    if !looks_like_grpc_frame(body) {
        return None;
    }

    let mut frames = Vec::new();
    let mut cursor = 0usize;

    while cursor + 5 <= body.len() && frames.len() < GRPC_MAX_FRAMES {
        let flag = body[cursor];
        if flag > 1 {
            return None;
        }

        let len = u32::from_be_bytes([
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
            body[cursor + 4],
        ]) as usize;
        if len > GRPC_MAX_FRAME_BYTES {
            return None;
        }
        let start = cursor + 5;
        let end = start.saturating_add(len);
        if end > body.len() {
            break;
        }

        frames.push((flag == 1, &body[start..end]));
        cursor = end;
    }

    if frames.is_empty() {
        None
    } else {
        Some(frames)
    }
}

async fn decode_grpc_payload(
    payload: &[u8],
    compressed: bool,
    grpc_message_encoding: Option<&str>,
) -> Option<Vec<u8>> {
    if !compressed {
        return Some(payload.to_vec());
    }

    let encoding = grpc_message_encoding
        .unwrap_or("gzip")
        .trim()
        .to_ascii_lowercase();

    if encoding.is_empty() || encoding == "identity" {
        return Some(payload.to_vec());
    }

    let owned = payload.to_vec();
    let decode = spawn_blocking(move || decompress_grpc_payload_sync(&owned, &encoding));
    match tokio::time::timeout(GRPC_DECODE_TIMEOUT, decode).await {
        Ok(Ok(result)) => result,
        _ => None,
    }
}

fn decompress_grpc_payload_sync(payload: &[u8], encoding: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    match encoding {
        "gzip" | "x-gzip" => {
            let decoder = GzDecoder::new(payload);
            decoder
                .take((GRPC_MAX_FRAME_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .ok()?;
        }
        "deflate" | "zlib" => {
            let decoder = ZlibDecoder::new(payload);
            decoder
                .take((GRPC_MAX_FRAME_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .ok()?;
            if output.is_empty() {
                let mut alt = Vec::new();
                let decoder = DeflateDecoder::new(payload);
                decoder
                    .take((GRPC_MAX_FRAME_BYTES + 1) as u64)
                    .read_to_end(&mut alt)
                    .ok()?;
                output = alt;
            }
        }
        "br" | "brotli" => {
            let decoder = BrotliDecoder::new(payload, 4096);
            decoder
                .take((GRPC_MAX_FRAME_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .ok()?;
        }
        "zstd" => {
            let decoder = zstd::stream::Decoder::new(Cursor::new(payload)).ok()?;
            decoder
                .take((GRPC_MAX_FRAME_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .ok()?;
        }
        _ => return None,
    }

    if output.len() > GRPC_MAX_FRAME_BYTES {
        return None;
    }
    Some(output)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn grpc_frame(payload: &[u8], compressed: bool) -> Vec<u8> {
        let mut framed = Vec::with_capacity(payload.len() + 5);
        framed.push(if compressed { 1 } else { 0 });
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }

    #[tokio::test]
    async fn extracts_usage_from_uncompressed_grpc_json_frame() {
        let registry = ProviderRegistry::new();
        let pricing = PricingCatalog::with_defaults();
        let payload = br#"{"model":"gpt-4o","usage":{"prompt_tokens":120,"completion_tokens":30}}"#;
        let framed = grpc_frame(payload, false);

        let meta = extract_usage_meta_from_decoded_payload(
            &registry,
            &pricing,
            "openai",
            "api.openai.com",
            &framed,
            false,
            Some("application/grpc+proto"),
            None,
            None,
        )
        .await;

        assert_eq!(meta.input_tokens, Some(120));
        assert_eq!(meta.output_tokens, Some(30));
        assert_eq!(meta.model.as_deref(), Some("gpt-4o"));
    }

    #[tokio::test]
    async fn grpc_frame_parsing_is_guarded_for_invalid_prefix() {
        let registry = ProviderRegistry::new();
        let pricing = PricingCatalog::with_defaults();
        let invalid = b"\x00\x00\x00\x10\x00{}";

        let meta = extract_usage_meta_from_decoded_payload(
            &registry,
            &pricing,
            "openai",
            "api.openai.com",
            invalid,
            false,
            Some("application/grpc+proto"),
            None,
            Some("gpt-4o"),
        )
        .await;

        assert_eq!(meta.input_tokens, None);
        assert_eq!(meta.output_tokens, None);
    }
}
