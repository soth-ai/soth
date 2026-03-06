use crate::code::{self, detect_code_artifacts};
use crate::fingerprint::fingerprint;
use crate::graphql::{parse_graphql, ApqStore, NoopApqStore};
use crate::grpc::parse_grpc;
use crate::hash::canonical_hash;
use crate::heuristic;
use crate::intelligence::{
    build_parse_quality_record, extract_unknown_graphql_operation_record, IntelligenceSink,
};
use crate::jsonrpc::parse_jsonrpc;
use crate::rest::parse_rest;
use crate::sensitive::{credential_scan, org_pattern_scan, structural_scan};
use crate::types::{
    ArtifactLocation, CaptureMode, DetectBundleSlice, DetectResult, DetectWarning, DetectedFormat,
    FormatMeta, NormalizedRequest, ParseSource, ParseWarning, Provider, ProviderEntry, RawRequest,
};
use lru::LruCache;
use serde_json::Value as JsonValue;
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

    pub fn process(
        &self,
        req: &RawRequest,
        bundle: &DetectBundleSlice<'_>,
        snapshot: &soth_core::SessionSnapshot,
    ) -> DetectResult {
        process_inner(req, bundle, self, snapshot)
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

pub fn process(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
) -> DetectResult {
    let apq = NoopApqStore;
    process_inner(req, bundle, &apq, snapshot)
}

pub fn process_with_intelligence(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    sink: &dyn IntelligenceSink,
) -> DetectResult {
    let apq = NoopApqStore;
    let result = process_inner(req, bundle, &apq, snapshot);
    emit_intelligence(req, &result, sink);
    result
}

pub fn process_with_registry(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
) -> DetectResult {
    registry.process(req, bundle, snapshot)
}

pub fn process_with_registry_and_intelligence(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    sink: &dyn IntelligenceSink,
) -> DetectResult {
    let result = registry.process(req, bundle, snapshot);
    emit_intelligence(req, &result, sink);
    result
}

fn process_inner(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    apq_store: &dyn ApqStore,
    snapshot: &soth_core::SessionSnapshot,
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
        req.connection_meta.matched_provider.as_deref(),
        bundle,
    );

    let (mut normalized, parse_source, mut warnings) =
        parse_by_format(req, bundle, format.clone(), apq_store);

    if normalized.canonical_hash.is_empty() {
        normalized.canonical_hash = canonical_hash(&normalized);
    }

    let provider_entry = provider_entry_for(bundle, &normalized.provider);

    let capture_mode = req.connection_meta.capture_mode.clone().unwrap_or_else(|| {
        bundle
            .capture_rules
            .mode_for_with_entry(&normalized.provider, provider_entry)
    });

    if normalized.estimated_cost_usd <= 0.0 {
        if let Some(estimated_cost) = provider_entry.and_then(|entry| {
            estimate_input_cost_usd(
                entry,
                normalized.model.as_deref(),
                normalized.estimated_input_tokens,
            )
        }) {
            normalized.estimated_cost_usd = estimated_cost;
        }
    }

    let full_like = matches!(
        capture_mode,
        CaptureMode::Full | CaptureMode::SensitiveArtifacts | CaptureMode::FullContent
    );
    let mut artifacts = Vec::new();
    let mut ast_normalized_hash: Option<String> = None;
    let mut import_categories: Vec<code::DetectedImportCategory> = Vec::new();

    if full_like {
        // Body-level scans
        artifacts.extend(credential_scan(&req.body, ArtifactLocation::Unknown));
        artifacts.extend(structural_scan(&req.body, ArtifactLocation::Unknown));
        artifacts.extend(org_pattern_scan(
            &req.body,
            bundle.org_patterns,
            ArtifactLocation::Unknown,
        ));

        // Per-location scans (multi-turn aware)
        let scannable = extract_scannable_locations(&req.body, &normalized);

        if scannable.is_empty() {
            // Fallback: use content_sample
            if let Some(content_sample) = normalized.content_sample.as_deref() {
                let code_result = detect_code_artifacts(
                    content_sample,
                    ArtifactLocation::UserMessage { turn_index: 0 },
                );
                artifacts.extend(code_result.artifacts);
                warnings.extend(code_result.warnings);
                if let Some(ts) = &code_result.tree_sitter {
                    import_categories.extend(ts.import_categories.iter().cloned());
                }
                if ast_normalized_hash.is_none() {
                    let lang = code_result
                        .detected_language
                        .as_deref()
                        .or_else(|| {
                            code_result
                                .tree_sitter
                                .as_ref()
                                .and_then(|ts| ts.confirmed_language.as_deref())
                        });
                    if let Some(lang) = lang {
                        ast_normalized_hash = code::ast_normalized_hash(content_sample, lang);
                    }
                }
            }
        } else {
            for (location, text) in &scannable {
                artifacts.extend(credential_scan(text.as_bytes(), location.clone()));

                if matches!(location, ArtifactLocation::UserMessage { .. }) {
                    let code_result = detect_code_artifacts(text, location.clone());
                    artifacts.extend(code_result.artifacts);
                    warnings.extend(code_result.warnings);
                    if let Some(ts) = &code_result.tree_sitter {
                        import_categories.extend(ts.import_categories.iter().cloned());
                    }

                    if ast_normalized_hash.is_none() {
                        let lang = code_result
                            .detected_language
                            .as_deref()
                            .or_else(|| {
                                code_result
                                    .tree_sitter
                                    .as_ref()
                                    .and_then(|ts| ts.confirmed_language.as_deref())
                            });
                        if let Some(lang) = lang {
                            ast_normalized_hash = code::ast_normalized_hash(text, lang);
                        }
                    }
                }
            }
        }
    }
    // Deduplicate import categories
    import_categories.sort();
    import_categories.dedup();

    // Prefix repeat detection
    let (is_prefix_repeat, novel_token_count, repeated_token_count, novel_tail_start_idx, prefix_hash) =
        compute_prefix_repeat(&normalized, snapshot);

    // Code context repeat detection
    let is_repeated_code_context = ast_normalized_hash
        .as_deref()
        .map(|hash| snapshot.seen_code_hashes.iter().any(|h| h == hash))
        .unwrap_or(false);

    // Session mutations
    let session_mutations = soth_core::SessionMutations {
        new_prefix_hash: Some(normalized.conversation_hash.clone()),
        new_code_hashes: ast_normalized_hash
            .as_ref()
            .map(|hash| {
                vec![soth_core::CodeBlob {
                    ast_normalized_hash: hash.clone(),
                    language: String::new(),
                    first_event_id: uuid::Uuid::nil(),
                }]
            })
            .unwrap_or_default(),
        ..soth_core::SessionMutations::default()
    };

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
        raw_body_bytes: Some(req.body.clone()),
        session_mutations,
        is_prefix_repeat,
        novel_token_count,
        repeated_token_count,
        novel_tail_start_idx,
        prefix_hash,
        is_repeated_code_context,
        ast_normalized_hash,
        first_blob_event_id: None,
        import_categories,
    }
}

fn compute_prefix_repeat(
    normalized: &NormalizedRequest,
    snapshot: &soth_core::SessionSnapshot,
) -> (bool, u32, u32, Option<usize>, Option<String>) {
    let current_hash = &normalized.conversation_hash;

    // Exact repeat
    if snapshot
        .seen_prefix_hashes
        .iter()
        .any(|h| h == current_hash)
    {
        let repeated = normalized.estimated_input_tokens;
        return (true, 0, repeated, Some(0), Some(current_hash.clone()));
    }

    (false, normalized.estimated_input_tokens, 0, None, None)
}

fn extract_scannable_locations(
    body: &[u8],
    normalized: &NormalizedRequest,
) -> Vec<(ArtifactLocation, String)> {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };

    let mut locations = Vec::new();

    // System prompt
    if let Some(system) = json
        .get("system")
        .or_else(|| json.get("systemPrompt"))
        .or_else(|| json.get("system_prompt"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        locations.push((ArtifactLocation::SystemPrompt, system.to_string()));
    }

    // Messages array
    if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
        for (idx, msg) in messages.iter().enumerate() {
            let role = msg
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("user");
            let content = msg
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    msg.get("content")
                        .and_then(|v| v.as_array())
                        .map(|parts| {
                            parts
                                .iter()
                                .filter_map(|part| part.get("text").and_then(|t| t.as_str()))
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                });

            if let Some(text) = content.filter(|s| !s.is_empty()) {
                let location = match role {
                    "assistant" => ArtifactLocation::AssistantMessage {
                        turn_index: idx as u32,
                    },
                    _ => ArtifactLocation::UserMessage {
                        turn_index: idx as u32,
                    },
                };
                locations.push((location, text));
            }
        }
    }

    // Tool definitions
    if normalized.has_tool_definitions {
        if let Some(tools) = json.get("tools").and_then(|v| v.as_array()) {
            for tool in tools {
                let tool_name = tool
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown_tool")
                    .to_string();
                let tool_text = tool.to_string();
                locations.push((
                    ArtifactLocation::ToolDefinition { tool_name },
                    tool_text,
                ));
            }
        }
    }

    locations
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

    let provider_name = provider_for_format(&format, req, bundle);

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
        DetectedFormat::CustomRest(ref key) => {
            let descriptor = bundle.rest_formats.get(key.as_str());
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
        DetectedFormat::JsonRpc => parse_jsonrpc(req, &provider_name).map(|mut nr| {
            nr.provider = Provider::new(provider_name.clone());
            nr
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
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
) -> String {
    if let Some(provider) = req.connection_meta.matched_provider.as_deref() {
        return canonical_provider_candidate(provider, format, bundle);
    }

    let headers = &req.headers;
    if let Some(host_provider) = host_provider_from_headers(headers, bundle) {
        return canonical_provider_candidate(&host_provider, format, bundle);
    }

    default_provider_for_format(format).to_string()
}

fn host_provider_from_headers(
    headers: &crate::types::HeaderMap,
    bundle: &DetectBundleSlice<'_>,
) -> Option<String> {
    let host = crate::util::header_value(headers, "host")
        .or_else(|| crate::util::header_value(headers, ":authority"))?;
    crate::util::lookup_domain_provider(bundle.domain_index, host).map(str::to_string)
}

fn canonical_provider_candidate(
    candidate: &str,
    format: &DetectedFormat,
    bundle: &DetectBundleSlice<'_>,
) -> String {
    let normalized = candidate.to_ascii_lowercase();

    if bundle.llm_providers.contains_key(&normalized) {
        return normalized;
    }

    if let Some((provider_id, _)) = bundle.llm_providers.iter().find(|(provider_id, entry)| {
        provider_id.eq_ignore_ascii_case(&normalized)
            || entry
                .provider_id
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(&normalized))
                .unwrap_or(false)
            || entry
                .name
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(&normalized))
                .unwrap_or(false)
    }) {
        return provider_id.to_string();
    }

    default_provider_for_format(format).to_string()
}

fn provider_entry_for<'a>(
    bundle: &'a DetectBundleSlice<'_>,
    provider: &Provider,
) -> Option<&'a ProviderEntry> {
    let canonical = provider.canonical_name();
    bundle.llm_providers.get(canonical).or_else(|| {
        bundle.llm_providers.values().find(|entry| {
            entry
                .provider_id
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(canonical))
                .unwrap_or(false)
                || entry
                    .name
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(canonical))
                    .unwrap_or(false)
        })
    })
}

fn estimate_input_cost_usd(
    provider_entry: &ProviderEntry,
    model: Option<&str>,
    estimated_input_tokens: u32,
) -> Option<f32> {
    if estimated_input_tokens == 0 {
        return Some(0.0);
    }

    let pricing = provider_entry.pricing.as_ref()?;
    let usd_per_input_token = model
        .and_then(|model_id| extract_model_rate(pricing, model_id))
        .or_else(|| extract_model_rate(pricing, "default"))
        .or_else(|| extract_input_rate(pricing))?;

    Some((estimated_input_tokens as f64 * usd_per_input_token) as f32)
}

fn extract_model_rate(pricing: &JsonValue, model_id: &str) -> Option<f64> {
    let model_value = lookup_case_insensitive(pricing, model_id).or_else(|| {
        pricing
            .get("models")
            .and_then(|models| lookup_case_insensitive(models, model_id))
    })?;
    extract_input_rate(model_value)
}

fn lookup_case_insensitive<'a>(node: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    let object = node.as_object()?;
    let key_lc = key.to_ascii_lowercase();
    object.iter().find_map(|(candidate, value)| {
        if candidate.eq_ignore_ascii_case(&key_lc) || candidate.eq_ignore_ascii_case(key) {
            Some(value)
        } else {
            None
        }
    })
}

fn extract_input_rate(node: &JsonValue) -> Option<f64> {
    const PER_MILLION_KEYS: [&str; 4] = [
        "input_per_million_usd",
        "prompt_per_million_usd",
        "input_usd_per_million",
        "prompt_usd_per_million",
    ];
    const PER_K_KEYS: [&str; 4] = [
        "input_per_1k_usd",
        "prompt_per_1k_usd",
        "input_usd_per_1k",
        "prompt_usd_per_1k",
    ];
    const PER_TOKEN_KEYS: [&str; 2] = ["input_per_token_usd", "prompt_per_token_usd"];

    for key in PER_MILLION_KEYS {
        if let Some(value) = node.get(key).and_then(JsonValue::as_f64) {
            return Some(value / 1_000_000.0);
        }
    }
    for key in PER_K_KEYS {
        if let Some(value) = node.get(key).and_then(JsonValue::as_f64) {
            return Some(value / 1_000.0);
        }
    }
    for key in PER_TOKEN_KEYS {
        if let Some(value) = node.get(key).and_then(JsonValue::as_f64) {
            return Some(value);
        }
    }

    if let Some(input) = node.get("input") {
        if let Some(value) = input.get("per_million_usd").and_then(JsonValue::as_f64) {
            return Some(value / 1_000_000.0);
        }
        if let Some(value) = input.get("per_1k_usd").and_then(JsonValue::as_f64) {
            return Some(value / 1_000.0);
        }
        if let Some(value) = input.get("per_token_usd").and_then(JsonValue::as_f64) {
            return Some(value);
        }
    }

    None
}

fn default_provider_for_format(format: &DetectedFormat) -> &'static str {
    match format {
        DetectedFormat::OpenAIRest => "openai",
        DetectedFormat::AnthropicRest => "anthropic",
        DetectedFormat::CohereRest => "cohere",
        DetectedFormat::GeminiRest => "google",
        DetectedFormat::BedrockRest => "aws_bedrock",
        DetectedFormat::CustomRest(_) => "custom",
        DetectedFormat::GraphQL => "graphql",
        DetectedFormat::GrpcProtobuf => "grpc",
        DetectedFormat::JsonRpc => "jsonrpc",
        DetectedFormat::Unknown => "unknown",
    }
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
        DetectedFormat::CustomRest(ref key) => ParseSource::AgentApp {
            app_id: key.clone(),
        },
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
        DetectedFormat::JsonRpc => {
            if let FormatMeta::JsonRpc { method, .. } = meta {
                ParseSource::JsonRpc {
                    method: method.clone(),
                }
            } else {
                ParseSource::JsonRpc { method: None }
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
