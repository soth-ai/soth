//! Bundle-driven usage/model extraction helpers.

use soth_oisp::{OispEngine, OispStreamParser, ProviderUsage as OispProviderUsage};

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

impl ResponseUsageMeta {
    pub fn has_signal(&self) -> bool {
        self.model
            .as_deref()
            .map(str::trim)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
            || self.input_tokens.unwrap_or(0) > 0
            || self.output_tokens.unwrap_or(0) > 0
            || self.cache_read_tokens.unwrap_or(0) > 0
            || self.cache_write_tokens.unwrap_or(0) > 0
            || self.reasoning_tokens.unwrap_or(0) > 0
            || self.cost_usd.unwrap_or(0.0) > 0.0
    }
}

/// Primary + shadow extraction outcome.
#[derive(Debug, Clone, Default)]
pub struct UsageExtractionOutcome {
    pub primary: ResponseUsageMeta,
    pub shadow: Option<ResponseUsageMeta>,
    pub mismatch: bool,
}

pub fn create_stream_usage_parser(
    oisp_engine: Option<&OispEngine>,
    provider: &str,
    host: &str,
) -> Option<OispStreamParser> {
    let engine = oisp_engine?;
    let provider_id = resolve_provider_id(engine, provider, host)?;
    engine.create_stream_parser(provider_id.as_str())
}

pub fn extract_model_from_request_for_mode(
    oisp_engine: Option<&OispEngine>,
    provider: &str,
    host: &str,
    decoded_body: &[u8],
) -> Option<String> {
    let engine = oisp_engine?;
    let provider_id = resolve_provider_id(engine, provider, host)?;
    engine.extract_model_from_request(provider_id.as_str(), decoded_body)
}

pub fn extract_request_pii_probe_for_mode(
    oisp_engine: Option<&OispEngine>,
    provider: &str,
    host: &str,
    decoded_body: &[u8],
) -> Option<String> {
    let engine = oisp_engine?;
    let provider_id = resolve_provider_id(engine, provider, host)?;
    engine.extract_pii_probe_from_request(provider_id.as_str(), decoded_body)
}

pub fn extract_usage_meta_from_stream_usage(
    oisp_engine: Option<&OispEngine>,
    provider: &str,
    host: &str,
    usage: Option<OispProviderUsage>,
) -> ResponseUsageMeta {
    let Some(engine) = oisp_engine else {
        return ResponseUsageMeta::default();
    };
    let Some(provider_id) = resolve_provider_id(engine, provider, host) else {
        return ResponseUsageMeta::default();
    };
    build_response_usage_meta_with_cost(usage, engine, provider_id.as_str(), provider)
}

pub async fn extract_usage_meta_for_mode(
    oisp_engine: Option<&OispEngine>,
    provider: &str,
    host: &str,
    decoded_body: &[u8],
    _is_sse: bool,
    _content_type: Option<&str>,
    _grpc_message_encoding: Option<&str>,
) -> UsageExtractionOutcome {
    let Some(engine) = oisp_engine else {
        return UsageExtractionOutcome::default();
    };
    let Some(provider_id) = resolve_provider_id(engine, provider, host) else {
        return UsageExtractionOutcome::default();
    };

    let usage = engine.extract_usage_from_response(provider_id.as_str(), decoded_body);
    let primary =
        build_response_usage_meta_with_cost(usage, engine, provider_id.as_str(), provider);

    UsageExtractionOutcome {
        primary,
        shadow: None,
        mismatch: false,
    }
}

fn resolve_provider_id(engine: &OispEngine, provider: &str, _host: &str) -> Option<String> {
    let provider = provider.trim();
    if !provider.is_empty()
        && !provider.eq_ignore_ascii_case("unknown")
        && !provider.eq_ignore_ascii_case("-")
    {
        if let Some(canonical) = engine.canonical_provider_id(provider) {
            return Some(canonical);
        }
    }
    None
}

fn build_response_usage_meta_with_cost(
    provider_usage: Option<OispProviderUsage>,
    engine: &OispEngine,
    provider_id: &str,
    provider_hint: &str,
) -> ResponseUsageMeta {
    let mut meta = build_response_usage_meta_without_cost(provider_usage);

    if let (Some(model), Some(input_tokens), Some(output_tokens)) =
        (meta.model.as_deref(), meta.input_tokens, meta.output_tokens)
    {
        let provider_hints = if provider_hint.is_empty() {
            vec![provider_id]
        } else {
            vec![provider_id, provider_hint]
        };
        meta.cost_usd = engine.calculate_cost(
            provider_hints.as_slice(),
            model,
            input_tokens,
            output_tokens,
            meta.cache_read_tokens,
            meta.cache_write_tokens,
        );
    }

    meta
}

fn build_response_usage_meta_without_cost(
    provider_usage: Option<OispProviderUsage>,
) -> ResponseUsageMeta {
    let mut meta = ResponseUsageMeta::default();
    let Some(provider_usage) = provider_usage else {
        return meta;
    };

    if provider_usage.input_tokens > 0 || provider_usage.output_tokens > 0 {
        meta.input_tokens = Some(provider_usage.input_tokens);
        meta.output_tokens = Some(provider_usage.output_tokens);
    }
    meta.cache_read_tokens = provider_usage.cache_read_tokens;
    meta.cache_write_tokens = provider_usage.cache_write_tokens;
    meta.reasoning_tokens = provider_usage.reasoning_tokens;
    meta.model = provider_usage.model;
    meta
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn test_oisp_engine() -> OispEngine {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = json!({
            "schema_version": 1,
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "test",
            "metadata": {
                "bundle_type": "local",
                "version": "v1",
                "sha256": "abc",
                "compiled_at": "2026-02-13T00:00:00Z",
                "provider_count": 1,
                "domain_count": 1,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": {
                "schema_version": 2,
                "version": "v1",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "local",
                "domain_index": [
                    { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" }
                ],
                "providers": {
                    "openai": {
                        "id": "openai",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai"
                    }
                },
                "filters": {
                    "whitelist": ["api.openai.com"],
                    "blacklist": [],
                    "passthrough": [],
                    "noise_keywords": []
                },
                "pricing": {
                    "openai": {
                        "gpt-4o": {
                            "input_per_million_usd": 10.0,
                            "output_per_million_usd": 20.0
                        }
                    }
                },
                "formats": {
                    "openai": {
                        "name": "openai",
                        "request": {
                            "model": "$.model",
                            "prompt": [
                                "$.messages[-1].content",
                                "$.input"
                            ]
                        },
                        "response": {
                            "json": {
                                "extract": { "model": "$.model" },
                                "extract_usage": {
                                    "prompt_tokens": "$.usage.prompt_tokens",
                                    "completion_tokens": "$.usage.completion_tokens"
                                }
                            },
                            "stream": {
                                "format": "sse",
                                "rules": [
                                    {
                                        "extract_usage": {
                                            "prompt_tokens": "$.usage.prompt_tokens",
                                            "completion_tokens": "$.usage.completion_tokens"
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        });
        std::fs::write(path.clone(), serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn registry_mode_uses_bundle_pricing_for_cost() {
        let engine = test_oisp_engine();
        let body = br#"{"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":50}}"#;

        let outcome = extract_usage_meta_for_mode(
            Some(&engine),
            "openai",
            "api.openai.com",
            body,
            false,
            Some("application/json"),
            None,
        )
        .await;

        assert_eq!(outcome.primary.input_tokens, Some(100));
        assert_eq!(outcome.primary.output_tokens, Some(50));
        assert_eq!(outcome.primary.model.as_deref(), Some("gpt-4o"));
        assert!((outcome.primary.cost_usd.unwrap_or_default() - 0.002).abs() < 1e-9);
        assert!(outcome.shadow.is_none());
        assert!(!outcome.mismatch);
    }

    #[test]
    fn request_model_is_extracted_via_bundle_format() {
        let engine = test_oisp_engine();
        let body = br#"{"model":"gpt-4o"}"#;
        let model =
            extract_model_from_request_for_mode(Some(&engine), "openai", "api.openai.com", body);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn request_pii_probe_is_extracted_via_bundle_format_prompt() {
        let engine = test_oisp_engine();
        let body = br#"{"messages":[{"role":"user","content":"email me at pii@example.com"}],"model":"gpt-4o"}"#;
        let probe =
            extract_request_pii_probe_for_mode(Some(&engine), "openai", "api.openai.com", body);
        assert_eq!(probe.as_deref(), Some("email me at pii@example.com"));
    }

    #[test]
    fn request_model_requires_provider_context() {
        let engine = test_oisp_engine();
        let body = br#"{"model":"gpt-4o"}"#;
        let model =
            extract_model_from_request_for_mode(Some(&engine), "unknown", "api.openai.com", body);
        assert!(model.is_none());
    }

    #[tokio::test]
    async fn response_usage_requires_provider_context() {
        let engine = test_oisp_engine();
        let body = br#"{"model":"gpt-4o","usage":{"prompt_tokens":8,"completion_tokens":4}}"#;
        let outcome = extract_usage_meta_for_mode(
            Some(&engine),
            "unknown",
            "api.openai.com",
            body,
            false,
            Some("application/json"),
            None,
        )
        .await;
        assert!(!outcome.primary.has_signal());
    }

    #[test]
    fn stream_parser_requires_provider_context() {
        let engine = test_oisp_engine();
        let parser = create_stream_usage_parser(Some(&engine), "unknown", "api.openai.com");
        assert!(parser.is_none());
    }
}
