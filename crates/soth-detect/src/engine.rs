use crate::code::{self, detect_code_artifacts};
use crate::fingerprint::{classify_request_pair, fingerprint};
use crate::graphql::{parse_graphql, ApqStore, NoopApqStore};
use crate::grpc::parse_grpc;
use crate::hash::canonical_hash;
use crate::heuristic;
#[cfg(feature = "intelligence")]
use crate::intelligence::{
    build_parse_quality_record, extract_unknown_graphql_operation_record, IntelligenceSink,
};
use crate::jsonrpc::parse_jsonrpc;
use crate::rest::parse_rest;
use crate::sensitive::{credential_scan, org_pattern_scan, structural_scan};
use crate::types::{
    ArtifactLocation, ArtifactType, DetectBundleSlice, DetectResult, DetectWarning, DetectedFormat,
    DetectedImportCategory, FormatMeta, GqlOpType, NormalizedRequest, ParseSource, ParseWarning,
    Provider, ProviderEntry, RawRequest,
};
use lru::LruCache;
use serde_json::Value as JsonValue;
use soth_core::{
    ArtifactKind, ArtifactLocation as CoreArtifactLocation, ArtifactSeverity, DetectedProvider,
    EndpointType as CoreEndpointType, FormatMetadata, GraphQlOperationType,
    NormalizedRequest as CoreNormalizedRequest, ParseSource as CoreParseSource,
    ParseWarning as CoreParseWarning, SensitiveArtifact,
};
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
    ) -> soth_core::DetectResult {
        to_core_detect_result(&process_inner(req, bundle, self, snapshot))
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
) -> soth_core::DetectResult {
    let apq = NoopApqStore;
    to_core_detect_result(&process_inner(req, bundle, &apq, snapshot))
}

#[cfg(feature = "intelligence")]
pub fn process_with_intelligence(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    sink: &dyn IntelligenceSink,
) -> soth_core::DetectResult {
    let apq = NoopApqStore;
    let result = process_inner(req, bundle, &apq, snapshot);
    emit_intelligence(req, &result, sink);
    to_core_detect_result(&result)
}

pub fn process_with_registry(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
) -> soth_core::DetectResult {
    registry.process(req, bundle, snapshot)
}

#[cfg(feature = "intelligence")]
pub fn process_with_registry_and_intelligence(
    registry: &ParserRegistry,
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    sink: &dyn IntelligenceSink,
) -> soth_core::DetectResult {
    let result = process_inner(req, bundle, registry, snapshot);
    emit_intelligence(req, &result, sink);
    to_core_detect_result(&result)
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

    // v3 signal-based classification: refine matched_provider/matched_application
    // using matching_rules when available, falling back to gating output otherwise.
    let (effective_provider, effective_application) =
        refine_with_classify(req, bundle);

    let format = fingerprint(
        &req.method,
        &req.path,
        &req.headers,
        &req.body[..req.body.len().min(512)],
        effective_provider.as_deref(),
        effective_application.as_deref(),
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
            .mode_for_with_entry(normalized.provider.canonical_name(), provider_entry)
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

    // Artifact extraction runs for all capture modes. The `full` mode is reserved
    // for a future extraction API that surfaces secrets externally; for now both
    // `metadata_only` and `full` run the same pipeline.
    let _ = capture_mode; // will gate the extraction API in a future release
    let mut artifacts = Vec::new();
    let mut ast_normalized_hash: Option<String> = None;
    let mut import_categories: Vec<DetectedImportCategory> = Vec::new();

    {
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

/// Refine gating's matched_provider/matched_application using v3 signal-based
/// classify_request_pair(). Resolves provider and application independently so
/// both can be identified from matching_rules in a single pass. Falls back to
/// gating output for whichever entity kind has no matching rule hit.
fn refine_with_classify(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
) -> (Option<String>, Option<String>) {
    let host = crate::util::header_value(&req.headers, "host")
        .or_else(|| crate::util::header_value(&req.headers, ":authority"));
    let (process_bundle_id, process_name, parent_process_name) =
        match req.connection_meta.process_info.as_ref() {
            Some(info) => (
                info.bundle_id.as_deref(),
                info.process_name.as_deref(),
                info.parent_process_name.as_deref(),
            ),
            None => (None, None, None),
        };

    let pair = classify_request_pair(
        host,
        &req.path,
        &req.headers,
        process_bundle_id,
        process_name,
        parent_process_name,
        bundle,
    );

    let provider = pair
        .provider
        .map(|r| r.entity_id)
        .or_else(|| req.connection_meta.matched_provider.clone());
    let application = pair
        .application
        .map(|r| r.entity_id)
        .or_else(|| req.connection_meta.matched_application.clone());

    (provider, application)
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
                // Apply model_default when model wasn't extracted from request
                if nr.model.is_none() {
                    if let Some(desc) = descriptor {
                        if let Some(default_model) = desc.model_default.as_deref() {
                            nr.model = Some(default_model.to_string());
                        }
                    }
                }
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
        let resolved = canonical_provider_candidate(provider, format, bundle);
        let default = default_provider_for_format(format);
        // If provider resolved to a known entry, use it. Otherwise fall through
        // to check the application entity's provider_hint for correct attribution.
        if resolved != default {
            return resolved;
        }
    }

    // Application entity: check api_format → provider_hint for correct attribution
    if let Some(app_id) = req.connection_meta.matched_application.as_deref() {
        if let Some(app_entry) = bundle.applications.get(app_id) {
            if let Some(api_format) = app_entry.api_format.as_deref() {
                if let Some(descriptor) = bundle.rest_formats.get(api_format) {
                    if let Some(hint) = descriptor.provider_hint.as_deref() {
                        return hint.to_string();
                    }
                }
            }
        }
        return canonical_provider_candidate(app_id, format, bundle);
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

// ---------------------------------------------------------------------------
// Conversion from internal DetectResult to soth_core::DetectResult
// ---------------------------------------------------------------------------

pub fn to_core_detect_result(value: &DetectResult) -> soth_core::DetectResult {
    soth_core::DetectResult {
        normalized: to_core_normalized(value),
        artifacts: value.artifacts.iter().map(map_artifact).collect(),
        capture_mode: value.capture_mode,
        parse_source: map_parse_source(&value.parse_source),
        confidence: value.confidence,
        detect_latency_us: value.detect_latency_us,
        warnings: value.warnings.iter().map(map_detect_warning).collect(),
        session_mutations: value.session_mutations.clone(),
        is_prefix_repeat: value.is_prefix_repeat,
        novel_token_count: value.novel_token_count,
        repeated_token_count: value.repeated_token_count,
        novel_tail_start_idx: value.novel_tail_start_idx,
        prefix_hash: value.prefix_hash.clone(),
        is_repeated_code_context: value.is_repeated_code_context,
        ast_normalized_hash: value.ast_normalized_hash.clone(),
        first_blob_event_id: value.first_blob_event_id,
        import_categories: value
            .import_categories
            .iter()
            .map(map_import_category)
            .collect(),
    }
}

fn to_core_normalized(value: &DetectResult) -> CoreNormalizedRequest {
    let normalized = &value.normalized;
    CoreNormalizedRequest {
        parse_confidence: normalized.parse_confidence,
        parser_id: normalized.parser_id.to_string(),
        schema_version: normalized.schema_version.to_string(),
        parse_warnings: normalized
            .parse_warnings
            .iter()
            .map(map_parse_warning)
            .collect(),
        is_ai_call: normalized.is_ai_call,
        provider: map_provider(normalized.provider.canonical_name()),
        model: normalized.model.clone(),
        endpoint_type: map_endpoint_type(&normalized.endpoint_type),
        api_version: normalized.api_version.clone(),
        system_prompt_hash: normalized.system_prompt_hash.clone(),
        system_prompt_token_estimate: normalized.system_prompt_token_estimate,
        user_content_hash: normalized.user_content_hash.clone(),
        user_content_token_estimate: normalized.user_content_token_estimate,
        conversation_hash: normalized.conversation_hash.clone(),
        conversation_turn: normalized.conversation_turn,
        has_tool_definitions: normalized.has_tool_definitions,
        tool_definition_hash: normalized.tool_definition_hash.clone(),
        temperature: normalized.temperature,
        max_tokens: normalized.max_tokens,
        stream: normalized.stream,
        top_p: normalized.top_p,
        stop_sequences: normalized.stop_sequences.clone(),
        estimated_input_tokens: normalized.estimated_input_tokens,
        estimated_cost_usd: normalized.estimated_cost_usd as f64,
        parse_source: map_parse_source(&value.parse_source),
        canonical_cache_key: normalized.canonical_hash.clone(),
        format_metadata: map_format_metadata(&normalized.format_meta),
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
    }
}

fn map_provider(value: &str) -> DetectedProvider {
    match value.to_ascii_lowercase().as_str() {
        "anthropic" => DetectedProvider::Anthropic,
        "openai" => DetectedProvider::OpenAi,
        "azure_openai" => DetectedProvider::AzureOpenAi,
        "gemini" | "google" | "google_vertex" => DetectedProvider::Gemini,
        "cohere" => DetectedProvider::Cohere,
        "bedrock" => DetectedProvider::Bedrock,
        "mistral" => DetectedProvider::Mistral,
        "groq" => DetectedProvider::Groq,
        "together" => DetectedProvider::Together,
        "fireworks" => DetectedProvider::Fireworks,
        "ollama" => DetectedProvider::Ollama,
        "vllm" => DetectedProvider::VLlm,
        "lmstudio" => DetectedProvider::LmStudio,
        "vertex_ai" => DetectedProvider::VertexAi,
        _ => DetectedProvider::Unknown,
    }
}

fn map_endpoint_type(value: &crate::types::EndpointType) -> CoreEndpointType {
    match value {
        crate::types::EndpointType::Chat => CoreEndpointType::ChatCompletion,
        crate::types::EndpointType::Completion => CoreEndpointType::TextCompletion,
        crate::types::EndpointType::Embedding => CoreEndpointType::Embedding,
        crate::types::EndpointType::Unknown => CoreEndpointType::Unknown,
    }
}

fn map_parse_source(value: &ParseSource) -> CoreParseSource {
    match value {
        ParseSource::OpenAI => CoreParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        ParseSource::Anthropic => CoreParseSource::Rest {
            provider: DetectedProvider::Anthropic,
        },
        ParseSource::Cohere => CoreParseSource::Rest {
            provider: DetectedProvider::Cohere,
        },
        ParseSource::Google => CoreParseSource::Rest {
            provider: DetectedProvider::Gemini,
        },
        ParseSource::Bedrock => CoreParseSource::Rest {
            provider: DetectedProvider::Bedrock,
        },
        ParseSource::GraphQL { .. } => CoreParseSource::GraphQl,
        ParseSource::Grpc { .. } => CoreParseSource::Grpc,
        ParseSource::JsonRpc { .. } => CoreParseSource::JsonRpc,
        ParseSource::AgentApp { .. } => CoreParseSource::AgentApp,
        ParseSource::Heuristic => CoreParseSource::Heuristic,
        ParseSource::Filtered => CoreParseSource::Filtered,
    }
}

fn map_format_metadata(value: &FormatMeta) -> FormatMetadata {
    match value {
        FormatMeta::Rest { path } => FormatMetadata::Rest {
            content_type: path.clone(),
        },
        FormatMeta::GraphQL {
            operation_name,
            operation_type,
            mutation_field,
        } => FormatMetadata::GraphQl {
            operation_name: operation_name.clone(),
            operation_type: match operation_type {
                GqlOpType::Query => GraphQlOperationType::Query,
                GqlOpType::Mutation => GraphQlOperationType::Mutation,
                GqlOpType::Subscription => GraphQlOperationType::Subscription,
                GqlOpType::Unknown => GraphQlOperationType::Unknown,
            },
            mutation_field: mutation_field.clone(),
        },
        FormatMeta::Grpc {
            service,
            method,
            proto_package,
        } => FormatMetadata::Grpc {
            service: service.clone(),
            method: method.clone(),
            proto_package: proto_package.clone(),
        },
        FormatMeta::JsonRpc { method, is_batch } => FormatMetadata::JsonRpc {
            method: method.clone().unwrap_or_default(),
            is_batch: *is_batch,
        },
        FormatMeta::WebSocket { frame_kind_hint } => FormatMetadata::WebSocket {
            frame_kind_hint: frame_kind_hint.clone(),
        },
        FormatMeta::Unknown { method, path } => FormatMetadata::Unknown {
            method: method.clone(),
            path: path.clone(),
        },
    }
}

fn map_parse_warning(value: &ParseWarning) -> CoreParseWarning {
    match value {
        ParseWarning::GraphQLUnknownOperation(operation_name) => {
            CoreParseWarning::GraphQlUnknownOperation {
                operation_name: operation_name.clone(),
            }
        }
        ParseWarning::GrpcDescriptorMissing(svc) => CoreParseWarning::GrpcDescriptorMissing {
            service: svc.clone(),
        },
        ParseWarning::ParserError(reason) => CoreParseWarning::ParserError {
            reason: reason.clone(),
        },
        ParseWarning::MissingField(f) => CoreParseWarning::MissingField { field: f.clone() },
        ParseWarning::NoParserForFormat(f) => {
            CoreParseWarning::NoParserForFormat { format: f.clone() }
        }
        ParseWarning::InvalidJson => CoreParseWarning::InvalidJson,
        ParseWarning::NonJsonBody => CoreParseWarning::NonJsonBody,
        ParseWarning::LongestStringHeuristic => CoreParseWarning::LongestStringHeuristic,
        ParseWarning::ContentNotExtracted => CoreParseWarning::ContentNotExtracted,
        ParseWarning::GraphQLSyntaxError => CoreParseWarning::GraphQlSyntaxError,
        ParseWarning::WebSocketBinaryUnparseable => CoreParseWarning::WebSocketBinaryUnparseable,
        ParseWarning::TreeSitterPanic => CoreParseWarning::TreeSitterPanic,
        ParseWarning::TreeSitterTimeout => CoreParseWarning::TreeSitterTimeout,
        ParseWarning::FilteredByKeyword => CoreParseWarning::FilteredByKeyword,
    }
}

fn map_detect_warning(value: &DetectWarning) -> CoreParseWarning {
    CoreParseWarning::PartialBodyParse {
        reason: format!("{}: {}", value.code, value.detail),
    }
}

pub fn map_artifact(value: &crate::types::SensitiveArtifact) -> SensitiveArtifact {
    SensitiveArtifact {
        kind: map_artifact_kind(&value.artifact_type),
        severity: map_artifact_severity(&value.severity),
        location: map_artifact_location(&value.location),
        commitment: Some(value.commitment.clone()),
        redacted_hint: value.redacted_hint.clone(),
    }
}

pub fn map_artifact_kind(value: &ArtifactType) -> ArtifactKind {
    match value {
        ArtifactType::PrivateKey => ArtifactKind::PrivateKey,
        ArtifactType::JwtToken => ArtifactKind::Jwt,
        ArtifactType::ConnectionString => ArtifactKind::ConnectionString,
        ArtifactType::CodeBlock { language } => ArtifactKind::CodeBlock {
            language: language.clone(),
        },
        ArtifactType::OpenAIKey => ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::OpenAi),
        },
        ArtifactType::AnthropicKey => ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::Anthropic),
        },
        ArtifactType::AwsAccessKey => ArtifactKind::AwsAccessKey,
        ArtifactType::GitHubPat => ArtifactKind::GitHubPat,
        ArtifactType::GitLabToken => ArtifactKind::GitLabToken,
        ArtifactType::SlackToken => ArtifactKind::SlackToken,
        ArtifactType::StripeSecretKey => ArtifactKind::StripeSecretKey,
        ArtifactType::UnknownCredential => ArtifactKind::UnknownCredential,
        ArtifactType::AuthLogicFlag => ArtifactKind::AuthLogic,
        ArtifactType::CryptoFlag => ArtifactKind::CryptoOperation,
        ArtifactType::OrgPatternMatch { pattern_id } => ArtifactKind::OrgPattern {
            pattern_id: *pattern_id,
        },
    }
}

pub fn map_artifact_severity(value: &crate::types::Severity) -> ArtifactSeverity {
    match value {
        crate::types::Severity::Critical => ArtifactSeverity::Critical,
        crate::types::Severity::High => ArtifactSeverity::High,
        crate::types::Severity::Medium => ArtifactSeverity::Medium,
        crate::types::Severity::Low => ArtifactSeverity::Low,
    }
}

pub fn map_artifact_location(value: &ArtifactLocation) -> CoreArtifactLocation {
    match value {
        ArtifactLocation::SystemPrompt => CoreArtifactLocation::SystemPrompt { char_offset: 0 },
        ArtifactLocation::UserMessage { turn_index } => CoreArtifactLocation::UserContent {
            turn: *turn_index,
            char_offset: 0,
        },
        ArtifactLocation::AssistantMessage { turn_index } => {
            CoreArtifactLocation::AssistantContent {
                turn: *turn_index,
                char_offset: 0,
            }
        }
        ArtifactLocation::ToolDefinition { tool_name } => CoreArtifactLocation::ToolResult {
            tool_name: Some(tool_name.clone()),
        },
        ArtifactLocation::Header { header_name } => CoreArtifactLocation::Header {
            name: header_name.clone(),
        },
        ArtifactLocation::StreamChunk { sequence } => {
            CoreArtifactLocation::StreamChunk { sequence: *sequence }
        }
        ArtifactLocation::Unknown => CoreArtifactLocation::Unknown,
    }
}

pub fn map_import_category(
    value: &DetectedImportCategory,
) -> soth_core::ImportCategory {
    match value {
        DetectedImportCategory::Crypto => soth_core::ImportCategory::Crypto,
        DetectedImportCategory::Auth => soth_core::ImportCategory::Auth,
        DetectedImportCategory::Network => soth_core::ImportCategory::Network,
        DetectedImportCategory::Database => soth_core::ImportCategory::Database,
        DetectedImportCategory::FileSystem => soth_core::ImportCategory::Filesystem,
        DetectedImportCategory::Serialization => soth_core::ImportCategory::Serialization,
    }
}

#[cfg(feature = "intelligence")]
fn emit_intelligence(req: &RawRequest, result: &DetectResult, sink: &dyn IntelligenceSink) {
    let parse_event = build_parse_quality_record(req, result);
    let parse_event_id = sink.record_parse_event(&parse_event).ok();

    if let Some(record) = extract_unknown_graphql_operation_record(req, result, parse_event_id) {
        let _ = sink.record_unknown_graphql_operation(&record);
    }
}
