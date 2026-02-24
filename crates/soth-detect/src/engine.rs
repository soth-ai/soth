use crate::code::detect_code_artifacts;
use crate::fingerprint::fingerprint;
use crate::graphql::{parse_graphql, ApqStore, NoopApqStore};
use crate::grpc::parse_grpc;
use crate::hash::canonical_hash;
use crate::heuristic;
use crate::intelligence::{
    build_parse_quality_record, extract_unknown_graphql_operation_record, IntelligenceSink,
};
use crate::rest::parse_rest;
use crate::sensitive::credential_scan;
use crate::types::{
    ArtifactLocation, CaptureMode, DetectBundleSlice, DetectResult, DetectWarning, DetectedFormat,
    FormatMeta, ParseSource, ParseWarning, Provider, RawRequest,
};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

pub struct ParserRegistry {
    apq_cache: Mutex<LruCache<String, String>>,
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new(512)
    }
}

impl ParserRegistry {
    pub fn new(apq_cache_capacity: usize) -> Self {
        let capacity = if apq_cache_capacity == 0 {
            1
        } else {
            apq_cache_capacity
        };
        let non_zero = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);

        Self {
            apq_cache: Mutex::new(LruCache::new(non_zero)),
        }
    }

    pub fn process(&self, req: &RawRequest, bundle: &DetectBundleSlice<'_>) -> DetectResult {
        process_inner(req, bundle, self)
    }
}

impl ApqStore for ParserRegistry {
    fn get_query(&self, hash: &str) -> Option<String> {
        let guard = match self.apq_cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut cache = guard;
        cache.get(hash).cloned()
    }

    fn put_query(&self, hash: String, query: String) {
        let guard = match self.apq_cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut cache = guard;
        cache.put(hash, query);
    }
}

pub fn process(req: &RawRequest, bundle: &DetectBundleSlice<'_>) -> DetectResult {
    let apq = NoopApqStore;
    process_inner(req, bundle, &apq)
}

pub fn process_with_intelligence(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    sink: &dyn IntelligenceSink,
) -> DetectResult {
    let apq = NoopApqStore;
    let result = process_inner(req, bundle, &apq);
    emit_intelligence(req, &result, sink);
    result
}

pub fn process_with_registry(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
) -> DetectResult {
    registry.process(req, bundle)
}

pub fn process_with_registry_and_intelligence(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    sink: &dyn IntelligenceSink,
) -> DetectResult {
    let result = registry.process(req, bundle);
    emit_intelligence(req, &result, sink);
    result
}

fn process_inner(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    apq_store: &dyn ApqStore,
) -> DetectResult {
    let started = Instant::now();

    if bundle.filters.matches(&req.path, &req.headers) {
        let mut out = DetectResult::filtered();
        out.detect_latency_us = started.elapsed().as_micros() as u64;
        return out;
    }

    let format = fingerprint(
        &req.method,
        &req.path,
        &req.headers,
        &req.body[..req.body.len().min(512)],
        bundle,
    );

    let (mut normalized, parse_source, mut warnings) =
        parse_by_format(req, bundle, format.clone(), apq_store);

    if normalized.canonical_hash.is_empty() {
        normalized.canonical_hash = canonical_hash(&normalized);
    }

    let capture_mode = bundle.capture_rules.mode_for(&normalized.provider);
    let mut artifacts = match capture_mode {
        CaptureMode::Full => credential_scan(&req.body, ArtifactLocation::Unknown),
        CaptureMode::MetadataOnly => Vec::new(),
    };

    if capture_mode == CaptureMode::Full {
        if let Some(content_sample) = normalized.content_sample.as_deref() {
            let (code_artifacts, code_warnings) = detect_code_artifacts(
                content_sample,
                ArtifactLocation::UserMessage { turn_index: 0 },
            );
            artifacts.extend(code_artifacts);
            warnings.extend(code_warnings);
        }
    }

    let confidence = normalized.parse_confidence.clone();
    warnings.extend(
        normalized
            .parse_warnings
            .iter()
            .map(parse_warning_to_detect_warning),
    );

    DetectResult {
        normalized,
        artifacts,
        capture_mode,
        parse_source,
        confidence,
        detect_latency_us: started.elapsed().as_micros() as u64,
        warnings,
    }
}

fn parse_by_format(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    format: DetectedFormat,
    apq_store: &dyn ApqStore,
) -> (
    crate::types::NormalizedRequest,
    ParseSource,
    Vec<DetectWarning>,
) {
    let mut warnings = Vec::new();

    let provider_name = provider_for_format(&format, &req.headers, bundle);

    let result = match format {
        DetectedFormat::OpenAIRest
        | DetectedFormat::AnthropicRest
        | DetectedFormat::CohereRest
        | DetectedFormat::GeminiRest
        | DetectedFormat::BedrockRest => {
            let key = rest_key_for_format(&format);
            let descriptor = bundle.rest_formats.get(key);
            parse_rest(req, &provider_name, format.clone(), descriptor).map(|mut nr| {
                nr.provider = Provider::new(provider_name.clone());
                nr
            })
        }
        DetectedFormat::GraphQL => parse_graphql(req, bundle, apq_store).map(|outcome| {
            warnings.extend(outcome.warnings);
            outcome.normalized
        }),
        DetectedFormat::GrpcProtobuf => parse_grpc(req, bundle).map(|outcome| {
            warnings.extend(outcome.warnings);
            outcome.normalized
        }),
        DetectedFormat::Unknown => Ok(heuristic::parse(req)),
    };

    match result {
        Ok(normalized) => {
            let source = parse_source_for_format(&format, &normalized.format_meta);
            (normalized, source, warnings)
        }
        Err(error) => {
            warnings.push(DetectWarning {
                code: "parser_error",
                detail: format!("{error:?}"),
            });
            let mut normalized = heuristic::parse(req);
            normalized.provider = Provider::new(provider_name);
            normalized
                .parse_warnings
                .push(ParseWarning::ParserError(format!("{error:?}")));
            normalized.canonical_hash = canonical_hash(&normalized);
            (normalized, ParseSource::Heuristic, warnings)
        }
    }
}

fn provider_for_format(
    format: &DetectedFormat,
    headers: &crate::types::HeaderMap,
    bundle: &DetectBundleSlice<'_>,
) -> String {
    if let Some(host_provider) = host_provider_from_headers(headers, bundle) {
        return host_provider;
    }

    match format {
        DetectedFormat::OpenAIRest => "openai".to_string(),
        DetectedFormat::AnthropicRest => "anthropic".to_string(),
        DetectedFormat::CohereRest => "cohere".to_string(),
        DetectedFormat::GeminiRest => "google".to_string(),
        DetectedFormat::BedrockRest => "aws_bedrock".to_string(),
        DetectedFormat::GraphQL => "graphql".to_string(),
        DetectedFormat::GrpcProtobuf => "grpc".to_string(),
        DetectedFormat::Unknown => "unknown".to_string(),
    }
}

fn host_provider_from_headers(
    headers: &crate::types::HeaderMap,
    bundle: &DetectBundleSlice<'_>,
) -> Option<String> {
    let host = crate::util::header_value(headers, "host")
        .or_else(|| crate::util::header_value(headers, ":authority"))?;
    let normalized = crate::util::host_without_port(host).to_ascii_lowercase();
    bundle.domain_index.get(&normalized).cloned()
}

fn rest_key_for_format(format: &DetectedFormat) -> &'static str {
    match format {
        DetectedFormat::OpenAIRest => "openai",
        DetectedFormat::AnthropicRest => "anthropic",
        DetectedFormat::CohereRest => "cohere",
        DetectedFormat::GeminiRest => "google",
        DetectedFormat::BedrockRest => "bedrock",
        _ => "openai",
    }
}

fn parse_source_for_format(format: &DetectedFormat, meta: &FormatMeta) -> ParseSource {
    match format {
        DetectedFormat::OpenAIRest => ParseSource::OpenAI,
        DetectedFormat::AnthropicRest => ParseSource::Anthropic,
        DetectedFormat::CohereRest => ParseSource::Cohere,
        DetectedFormat::GeminiRest => ParseSource::Google,
        DetectedFormat::BedrockRest => ParseSource::Bedrock,
        DetectedFormat::GraphQL => {
            if let FormatMeta::GraphQL { operation_name, .. } = meta {
                ParseSource::GraphQL {
                    operation_name: operation_name.clone(),
                }
            } else {
                ParseSource::GraphQL {
                    operation_name: None,
                }
            }
        }
        DetectedFormat::GrpcProtobuf => {
            if let FormatMeta::Grpc {
                service, method, ..
            } = meta
            {
                ParseSource::Grpc {
                    service: service.clone(),
                    method: method.clone(),
                }
            } else {
                ParseSource::Grpc {
                    service: "unknown".to_string(),
                    method: "unknown".to_string(),
                }
            }
        }
        DetectedFormat::Unknown => ParseSource::Heuristic,
    }
}

fn parse_warning_to_detect_warning(warning: &ParseWarning) -> DetectWarning {
    DetectWarning {
        code: "parse_warning",
        detail: format!("{warning:?}"),
    }
}

fn emit_intelligence(req: &RawRequest, result: &DetectResult, sink: &dyn IntelligenceSink) {
    let parse_event = build_parse_quality_record(req, result);
    let parse_event_id = sink.record_parse_event(&parse_event).ok();

    if let Some(record) = extract_unknown_graphql_operation_record(req, result, parse_event_id) {
        let _ = sink.record_unknown_graphql_operation(&record);
    }
}
