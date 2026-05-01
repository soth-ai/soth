use crate::code::{self, detect_code_artifacts};
use crate::fingerprint_mod::fingerprint;
use crate::graphql::{parse_graphql, ApqStore};
use crate::grpc::parse_grpc;
use crate::hash::canonical_hash;
use crate::heuristic;
#[cfg(feature = "intelligence")]
use crate::intelligence::{
    build_parse_quality_record, extract_unknown_graphql_operation_record, IntelligenceSink,
};
use crate::jsonrpc::parse_jsonrpc;
use crate::rest::parse_rest;
use crate::sensitive::{
    credential_scan_str, org_pattern_scan_compiled_str, structural_scan_str, CompiledOrgPatterns,
};
use crate::types::{
    ArtifactLocation, CaptureMode, DetectBundleSlice, DetectWarning, DetectedFormat,
    DetectedImportCategory, FormatMeta, NormalizedRequest, ParseDetectResult, ParseSource,
    ParseWarning, ProviderEntry, RawRequest,
};
use lru::LruCache;
use serde_json::Value as JsonValue;
use soth_core::DetectedProvider;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

pub struct ParserRegistry {
    apq_cache: Mutex<LruCache<String, String>>,
    compiled_org: CompiledOrgPatterns,
}

// Compile-time check: SDK bindings stash an `Arc<ParserRegistry>` for the
// lifetime of the host process and call `process_normalized` /
// `process_with_registry` from arbitrary worker threads. Both ends require
// `Send + Sync`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ParserRegistry>();
};

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::with_org_patterns(512, &[])
    }
}

impl ParserRegistry {
    pub fn new(apq_cache_capacity: usize) -> Self {
        Self::with_org_patterns(apq_cache_capacity, &[])
    }

    pub fn with_org_patterns(apq_cache_capacity: usize, org_patterns: &[String]) -> Self {
        let capacity = if apq_cache_capacity == 0 {
            1
        } else {
            apq_cache_capacity
        };
        let non_zero = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);

        Self {
            apq_cache: Mutex::new(LruCache::new(non_zero)),
            compiled_org: CompiledOrgPatterns::compile(org_patterns),
        }
    }

    pub fn process(
        &self,
        req: &RawRequest,
        bundle: &DetectBundleSlice<'_>,
        snapshot: &soth_core::SessionSnapshot,
    ) -> soth_core::DetectResult {
        to_core_detect_result(&process_inner(
            req,
            bundle,
            self,
            &self.compiled_org,
            snapshot,
        ))
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

/// Convenience entry point without a `ParserRegistry`. Constructs a
/// temporary registry on every call — use `process_with_registry` for the
/// hot path. Only intended for tests and one-shot sidecar use where
/// `org_patterns` is empty. In debug builds, asserts that org_patterns is
/// empty to catch accidental misuse.
pub fn process(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
) -> soth_core::DetectResult {
    debug_assert!(
        bundle.org_patterns.is_empty(),
        "process() compiles org patterns per call — use process_with_registry() for non-empty org_patterns"
    );
    let registry = ParserRegistry::with_org_patterns(1, bundle.org_patterns);
    registry.process(req, bundle, snapshot)
}

/// Convenience entry point with intelligence logging but without a
/// `ParserRegistry`. Same caveats as `process()`.
#[cfg(feature = "intelligence")]
pub fn process_with_intelligence(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    sink: &dyn IntelligenceSink,
) -> soth_core::DetectResult {
    debug_assert!(
        bundle.org_patterns.is_empty(),
        "process_with_intelligence() compiles org patterns per call — use process_with_registry_and_intelligence()"
    );
    let registry = ParserRegistry::with_org_patterns(1, bundle.org_patterns);
    let result = process_inner(req, bundle, &registry, &registry.compiled_org, snapshot);
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
    let result = process_inner(req, bundle, registry, &registry.compiled_org, snapshot);
    emit_intelligence(req, &result, sink);
    to_core_detect_result(&result)
}

/// Pre-parsed entry point for SDK consumers that already have a typed LLM
/// call — provider, model, messages, system, tools, stream — and don't need
/// the proxy's HTTP fingerprint/parse phase.
///
/// Mirrors `process_with_registry`'s downstream behavior:
/// 1. Builds a `NormalizedRequest` from the typed call (hashes, token estimates,
///    canonical cache key) using the same primitives the REST parser uses.
/// 2. Runs the **scan phase** (credentials, structural artifacts, code,
///    org patterns) over the message content.
/// 3. Runs the **session prefix-repeat** phase using the supplied snapshot.
///
/// Output uses `parse_source = ParseSource::Sdk` and
/// `confidence = ParseConfidence::Full`. Org patterns are honored when the
/// caller supplies a `ParserRegistry` with compiled patterns; pass
/// `&ParserRegistry::default()` when none are needed.
pub fn process_normalized(
    registry: &ParserRegistry,
    call: &soth_core::TypedLlmCall,
    _bundle: &DetectBundleSlice<'_>,
    snapshot: &soth_core::SessionSnapshot,
    capture_mode: soth_core::CaptureMode,
) -> soth_core::DetectResult {
    let started = Instant::now();

    // Phase 1 (parse) is supplied by the caller — build NormalizedRequest
    // from typed fields directly.
    let normalized = build_normalized_from_typed_call(call, capture_mode);

    // Phase 2: scan. Build `segments` from the typed messages so credential
    // detection sees per-turn locations.
    let scan_input = build_scan_input_from_typed_call(call);
    let synthetic_body = call.conversation_text();
    let scan = scan_content(
        synthetic_body.as_bytes(),
        &scan_input,
        &registry.compiled_org,
    );

    // Phase 3: session prefix-repeat dedup (same primitive as proxy hot path).
    let (
        is_prefix_repeat,
        novel_token_count,
        repeated_token_count,
        novel_tail_start_idx,
        prefix_hash,
    ) = compute_prefix_repeat(&normalized, snapshot);

    let is_repeated_code_context = scan
        .ast_normalized_hash
        .as_deref()
        .map(|hash| snapshot.seen_code_hashes.iter().any(|h| h == hash))
        .unwrap_or(false);

    let session_mutations = soth_core::SessionMutations {
        new_prefix_hash: Some(normalized.conversation_hash.clone()),
        new_code_hashes: scan
            .ast_normalized_hash
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

    let user_prompt = normalized.user_prompt.clone();

    soth_core::DetectResult {
        normalized,
        artifacts: scan.artifacts,
        capture_mode,
        parse_source: ParseSource::Sdk,
        confidence: soth_core::ParseConfidence::Full,
        detect_latency_us: started.elapsed().as_micros() as u64,
        warnings: scan.warnings.iter().map(map_detect_warning).collect(),
        session_mutations,
        is_prefix_repeat,
        novel_token_count,
        repeated_token_count,
        novel_tail_start_idx,
        prefix_hash,
        is_repeated_code_context,
        ast_normalized_hash: scan.ast_normalized_hash,
        first_blob_event_id: None,
        import_categories: scan.import_categories,
        user_prompt,
    }
}

fn build_normalized_from_typed_call(
    call: &soth_core::TypedLlmCall,
    _capture_mode: soth_core::CaptureMode,
) -> NormalizedRequest {
    use crate::hash::{canonical_hash, estimate_tokens, hash_content};

    let user_content = call.user_content();
    let conversation = call.conversation_text();
    let tool_definitions = call.tool_definitions_text();

    // Mirror the REST parser: empty content hashes the sentinel placeholder
    // so the cloud sees a stable hash for content-not-extracted cases. This
    // matches `parse_rest::user_content_hash` for parity.
    let user_content_hash = if user_content.is_empty() {
        hash_content("[CONTENT_NOT_EXTRACTED]")
    } else {
        hash_content(&user_content)
    };
    let conversation_hash = hash_content(&conversation);
    let system_prompt_hash = call.system.as_deref().map(hash_content);
    let system_prompt_token_estimate = call.system.as_deref().map(estimate_tokens);
    let tool_definition_hash = tool_definitions.as_deref().map(hash_content);
    let user_content_token_estimate = estimate_tokens(&user_content);
    let estimated_input_tokens = system_prompt_token_estimate
        .unwrap_or(0)
        .saturating_add(estimate_tokens(&conversation));

    let conversation_turn = if call.messages.is_empty() {
        None
    } else {
        Some(call.messages.len() as u32)
    };

    let mut normalized = NormalizedRequest {
        parse_confidence: soth_core::ParseConfidence::Full,
        parser_id: format!("sdk:{}", call.provider),
        schema_version: "sdk-1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: call.provider.clone(),
        model: if call.model.is_empty() {
            None
        } else {
            Some(call.model.clone())
        },
        endpoint_type: call.endpoint_type,
        api_version: None,
        system_prompt_hash,
        system_prompt_token_estimate,
        user_content_hash,
        user_content_token_estimate,
        conversation_hash,
        conversation_turn,
        has_tool_definitions: !call.tools.is_empty(),
        tool_definition_hash,
        temperature: call.temperature,
        max_tokens: call.max_tokens,
        stream: call.stream,
        top_p: call.top_p,
        stop_sequences: call.stop_sequences.clone(),
        estimated_input_tokens,
        estimated_cost_usd: 0.0,
        parse_source: ParseSource::Sdk,
        has_structured_output: false,
        has_tool_results: call.messages.iter().any(|m| m.role == "tool"),
        estimated_output_tokens: None,
        canonical_cache_key: String::new(),
        format_metadata: soth_core::FormatMetadata::Rest {
            content_type: "application/json".to_string(),
        },
        user_prompt: if user_content.is_empty() {
            None
        } else {
            Some(user_content)
        },
    };

    normalized.canonical_cache_key = canonical_hash(&normalized);
    normalized
}

fn build_scan_input_from_typed_call(call: &soth_core::TypedLlmCall) -> ScanInput {
    let mut segments = Vec::new();

    if let Some(system) = &call.system {
        if !system.is_empty() {
            segments.push((
                ArtifactLocation::SystemPrompt { char_offset: 0 },
                system.clone(),
            ));
        }
    }

    for (idx, msg) in call.messages.iter().enumerate() {
        if msg.content.is_empty() {
            continue;
        }
        let location = match msg.role.as_str() {
            "assistant" => ArtifactLocation::AssistantContent {
                turn: idx as u32,
                char_offset: 0,
            },
            _ => ArtifactLocation::UserContent {
                turn: idx as u32,
                char_offset: 0,
            },
        };
        segments.push((location, msg.content.clone()));
    }

    ScanInput {
        segments,
        fallback_content: None,
    }
}

// ---------------------------------------------------------------------------
// Internal types for the parse/scan split
// ---------------------------------------------------------------------------

struct ParsePhaseResult {
    normalized: NormalizedRequest,
    parse_source: ParseSource,
    warnings: Vec<DetectWarning>,
    capture_mode: CaptureMode,
    /// JSON body already parsed during the parse phase (REST formats only).
    /// Carried forward so process_inner can hand it to the scan phase
    /// without a second serde_json::from_slice call.
    parsed_body: Option<JsonValue>,
}

struct ScanInput {
    segments: Vec<(ArtifactLocation, String)>,
    fallback_content: Option<String>,
}

struct ScanResult {
    artifacts: Vec<crate::types::SensitiveArtifact>,
    warnings: Vec<DetectWarning>,
    ast_normalized_hash: Option<String>,
    import_categories: Vec<DetectedImportCategory>,
}

// ---------------------------------------------------------------------------
// Phase 1: parse_request — fingerprint, dispatch, cost estimation
// ---------------------------------------------------------------------------

fn parse_request(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    apq_store: &dyn ApqStore,
) -> ParsePhaseResult {
    // Parse the JSON body once here, at the earliest point, so that all
    // downstream format parsers (REST, GraphQL, JSON-RPC, heuristic) can reuse
    // the already-allocated Value instead of each calling from_slice again.
    // gRPC bodies are binary protobuf and will not parse as JSON; that is
    // expected and the None is handled gracefully by every format parser.
    let pre_parsed_json: Option<JsonValue> = serde_json::from_slice(&req.body).ok();

    // Use gating's answers directly — classify_request_pair is now called
    // in the evaluator with full signal-based matching, so no re-derivation needed.
    let format = fingerprint(
        &req.method,
        &req.path,
        &req.headers,
        &req.body[..req.body.len().min(512)],
        req.connection_meta.matched_provider.as_deref(),
        req.connection_meta.matched_application.as_deref(),
        bundle,
    );

    let (mut normalized, parse_source, mut warnings, parsed_body) = parse_by_format(
        req,
        bundle,
        format.clone(),
        apq_store,
        pre_parsed_json.as_ref(),
    );

    if normalized.canonical_cache_key.is_empty() {
        normalized.canonical_cache_key = canonical_hash(&normalized);
    }

    let provider_entry = provider_entry_for(bundle, &normalized.provider);

    let capture_mode = req.connection_meta.capture_mode.unwrap_or_else(|| {
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
            normalized.estimated_cost_usd = estimated_cost as f64;
        }
    }

    warnings.extend(
        normalized
            .parse_warnings
            .iter()
            .map(parse_warning_to_detect_warning),
    );

    ParsePhaseResult {
        normalized,
        parse_source,
        warnings,
        capture_mode,
        parsed_body,
    }
}

// ---------------------------------------------------------------------------
// Phase 2a: build_scan_input — extract scannable locations with fallback
// ---------------------------------------------------------------------------

fn build_scan_input(
    body: &[u8],
    normalized: &NormalizedRequest,
    parsed_body: Option<&JsonValue>,
) -> ScanInput {
    let segments = extract_scannable_locations(body, normalized, parsed_body);
    let fallback_content = if segments.is_empty() {
        extract_content_sample(body, parsed_body)
    } else {
        None
    };
    ScanInput {
        segments,
        fallback_content,
    }
}

// ---------------------------------------------------------------------------
// Phase 2b: scan_content — credential, structural, code, org-pattern scans
// ---------------------------------------------------------------------------

fn scan_content(
    body: &[u8],
    scan_input: &ScanInput,
    compiled_org: &CompiledOrgPatterns,
) -> ScanResult {
    let mut artifacts = Vec::new();
    let mut warnings = Vec::new();
    let mut ast_normalized_hash: Option<String> = None;
    let mut import_categories: Vec<DetectedImportCategory> = Vec::new();

    // Decode body once; all three body-level scanners reuse this view.
    let body_text = String::from_utf8_lossy(body);
    artifacts.extend(credential_scan_str(&body_text, ArtifactLocation::Unknown));
    artifacts.extend(structural_scan_str(&body_text, ArtifactLocation::Unknown));
    artifacts.extend(org_pattern_scan_compiled_str(
        &body_text,
        compiled_org,
        ArtifactLocation::Unknown,
    ));
    // body_text is no longer needed after this point.
    drop(body_text);

    // Per-location scans (multi-turn aware)
    if scan_input.segments.is_empty() {
        if scan_input.fallback_content.is_none() && !body.is_empty() {
            // No structured messages found and body is not JSON-parseable
            // (e.g. protobuf/gRPC). Code detection cannot run.
            warnings.push(DetectWarning {
                code: "code_detection_skipped",
                detail: "no scannable text extracted from body".to_string(),
            });
        }

        // Fallback: use content_sample
        if let Some(content_sample) = scan_input.fallback_content.as_deref() {
            let code_result = detect_code_artifacts(
                content_sample,
                ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 0,
                },
            );
            artifacts.extend(code_result.artifacts);
            warnings.extend(code_result.warnings);
            if let Some(ts) = &code_result.tree_sitter {
                import_categories.extend(ts.import_categories.iter().cloned());
            }
            if ast_normalized_hash.is_none() {
                let lang = code_result.detected_language.as_deref().or_else(|| {
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
        for (location, text) in &scan_input.segments {
            // `text` is already a `String`; pass it as `&str` directly.
            artifacts.extend(credential_scan_str(text, location.clone()));

            if matches!(location, ArtifactLocation::UserContent { .. }) {
                let code_result = detect_code_artifacts(text, location.clone());
                artifacts.extend(code_result.artifacts);
                warnings.extend(code_result.warnings);
                if let Some(ts) = &code_result.tree_sitter {
                    import_categories.extend(ts.import_categories.iter().cloned());
                }

                if ast_normalized_hash.is_none() {
                    let lang = code_result.detected_language.as_deref().or_else(|| {
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

    // Deduplicate import categories (ImportCategory has no Ord or Hash, use O(n²) dedup).
    // The set is always small (at most 6 variants), so this is fast.
    let mut deduped: Vec<DetectedImportCategory> = Vec::new();
    for cat in import_categories {
        if !deduped.contains(&cat) {
            deduped.push(cat);
        }
    }
    let import_categories = deduped;

    ScanResult {
        artifacts,
        warnings,
        ast_normalized_hash,
        import_categories,
    }
}

// ---------------------------------------------------------------------------
// process_inner — composes parse + scan
// ---------------------------------------------------------------------------

fn process_inner(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    apq_store: &dyn ApqStore,
    compiled_org: &CompiledOrgPatterns,
    snapshot: &soth_core::SessionSnapshot,
) -> ParseDetectResult {
    let started = Instant::now();

    if bundle.filters.matches(&req.path, &req.headers) {
        let mut out = ParseDetectResult::filtered();
        out.detect_latency_us = started.elapsed().as_micros() as u64;
        return out;
    }

    // Phase 1: Parse — the parsed JSON body is threaded out of parse_request
    // for REST formats so the scan phase can reuse it without a second
    // serde_json::from_slice call.  Non-JSON formats (gRPC, GraphQL, etc.)
    // leave parsed_body as None and the scan helpers fall back to their
    // existing raw-byte paths.
    let ParsePhaseResult {
        normalized,
        parse_source,
        mut warnings,
        capture_mode,
        parsed_body,
    } = parse_request(req, bundle, apq_store);

    // Phase 2: Scan
    let scan_input = build_scan_input(&req.body, &normalized, parsed_body.as_ref());
    let scan = scan_content(&req.body, &scan_input, compiled_org);

    let artifacts = scan.artifacts;
    warnings.extend(scan.warnings);
    let ast_normalized_hash = scan.ast_normalized_hash;
    let import_categories = scan.import_categories;

    // Artifact extraction runs for all capture modes. The `full` mode is reserved
    // for a future extraction API that surfaces secrets externally; for now both
    // `metadata_only` and `full` run the same pipeline.
    let _ = capture_mode; // will gate the extraction API in a future release

    // Phase 3: Prefix repeat + session mutations
    let (
        is_prefix_repeat,
        novel_token_count,
        repeated_token_count,
        novel_tail_start_idx,
        prefix_hash,
    ) = compute_prefix_repeat(&normalized, snapshot);

    let is_repeated_code_context = ast_normalized_hash
        .as_deref()
        .map(|hash| snapshot.seen_code_hashes.iter().any(|h| h == hash))
        .unwrap_or(false);

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

    let confidence = normalized.parse_confidence;

    // Phase 4: Assemble ParseDetectResult
    ParseDetectResult {
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
    parsed_body: Option<&JsonValue>,
) -> Vec<(ArtifactLocation, String)> {
    // Use the pre-parsed value when available; otherwise parse now (handles
    // callers that don't go through process_inner, e.g. tests).
    let owned;
    let json: &JsonValue = match parsed_body {
        Some(v) => v,
        None => {
            let Ok(v) = serde_json::from_slice::<JsonValue>(body) else {
                return Vec::new();
            };
            owned = v;
            &owned
        }
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
        locations.push((
            ArtifactLocation::SystemPrompt { char_offset: 0 },
            system.to_string(),
        ));
    }

    // Messages array
    if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
        for (idx, msg) in messages.iter().enumerate() {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
            let content = msg
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    msg.get("content").and_then(|v| v.as_array()).map(|parts| {
                        parts
                            .iter()
                            .filter_map(|part| part.get("text").and_then(|t| t.as_str()))
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                });

            if let Some(text) = content.filter(|s| !s.is_empty()) {
                let location = match role {
                    "assistant" => ArtifactLocation::AssistantContent {
                        turn: idx as u32,
                        char_offset: 0,
                    },
                    _ => ArtifactLocation::UserContent {
                        turn: idx as u32,
                        char_offset: 0,
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
                    ArtifactLocation::ToolResult {
                        tool_name: Some(tool_name),
                    },
                    tool_text,
                ));
            }
        }
    }

    locations
}

/// Extract a content sample from the raw body for fallback scanning.
/// Used when `extract_scannable_locations()` finds no structured messages.
/// Mirrors the extraction logic the parsers previously wrote to
/// `NormalizedRequest.content_sample`: tries standard JSON content paths,
/// handles GraphQL variables and JSON-RPC params, then falls back to the
/// longest-string heuristic (min 20 chars). Returns `None` for non-JSON
/// bodies and for GraphQL bodies where only the query DSL is available.
///
/// `parsed_body` is an optional pre-parsed value to avoid a redundant
/// `serde_json::from_slice` call on the hot path.
fn extract_content_sample(body: &[u8], parsed_body: Option<&JsonValue>) -> Option<String> {
    let owned;
    let json: &JsonValue = match parsed_body {
        Some(v) => v,
        None => {
            owned = serde_json::from_slice(body).ok()?;
            &owned
        }
    };

    // Try first message content (most common for chat APIs)
    if let Some(content) = json
        .get("messages")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(content.to_string());
    }

    // Simple top-level content paths
    for key in &["prompt", "content", "message", "text", "input", "query"] {
        if let Some(s) = json
            .get(*key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            // Skip GraphQL query DSL — it looks like code but isn't user content
            if *key == "query"
                && (json.get("operationName").is_some() || json.get("variables").is_some())
            {
                continue;
            }
            if s != "[CONTENT_NOT_EXTRACTED]" {
                return Some(s.to_string());
            }
        }
    }

    // Nested content paths
    if let Some(s) = json
        .get("input")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(s.to_string());
    }
    if let Some(s) = json
        .get("request")
        .and_then(|v| v.get("prompt"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(s.to_string());
    }

    // GraphQL: try variables.{input,prompt,message,content}[.content]
    if json.get("operationName").is_some()
        || (json.get("query").is_some() && json.get("variables").is_some())
    {
        if let Some(vars) = json.get("variables") {
            for key in &["input", "prompt", "message", "content"] {
                if let Some(inner) = vars.get(*key) {
                    if let Some(s) = inner.as_str().filter(|s| !s.is_empty()) {
                        return Some(s.to_string());
                    }
                    if let Some(s) = inner
                        .get("content")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        return Some(s.to_string());
                    }
                }
            }
        }
        // Don't fall through to longest-string for GraphQL — the query DSL
        // would be selected and misidentified as code.
        return None;
    }

    // JSON-RPC: try params as string or params.content
    if json.get("jsonrpc").is_some() {
        if let Some(params) = json.get("params") {
            if let Some(s) = params.as_str().filter(|s| !s.is_empty()) {
                return Some(s.to_string());
            }
            if let Some(s) = params
                .get("content")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                return Some(s.to_string());
            }
        }
    }

    // Longest string fallback (min 20 chars) — mirrors heuristic parser
    let mut best: Option<String> = None;
    visit_json_strings(json, &mut |s| {
        if s.len() >= 20 {
            let better = best.as_ref().map_or(true, |b| s.len() > b.len());
            if better {
                best = Some(s.to_string());
            }
        }
    });
    best
}

fn visit_json_strings(value: &serde_json::Value, f: &mut dyn FnMut(&str)) {
    match value {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(items) => {
            for item in items {
                visit_json_strings(item, f);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                visit_json_strings(v, f);
            }
        }
        _ => {}
    }
}

fn parse_by_format(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    format: DetectedFormat,
    apq_store: &dyn ApqStore,
    pre_parsed: Option<&JsonValue>,
) -> (
    crate::types::NormalizedRequest,
    ParseSource,
    Vec<DetectWarning>,
    Option<JsonValue>,
) {
    let mut warnings = Vec::new();

    let provider_name = provider_for_format(&format, req, bundle);

    // parsed_json carries the Value for this request so process_inner can
    // reuse it in the scan phase.  For REST formats this is the post-parse
    // value returned by parse_rest (which may have gone through preprocess
    // transforms); for all other formats it is the same pre-parsed value
    // threaded from parse_request.
    let mut parsed_json: Option<JsonValue> = None;

    let result: Result<crate::types::NormalizedRequest, _> = match format {
        DetectedFormat::OpenAIRest
        | DetectedFormat::AnthropicRest
        | DetectedFormat::CohereRest
        | DetectedFormat::GeminiRest
        | DetectedFormat::BedrockRest => {
            let key = rest_key_for_format(&format);
            let descriptor = bundle.rest_formats.get(key);
            parse_rest(req, &provider_name, format.clone(), descriptor, pre_parsed).map(
                |(mut nr, json)| {
                    parsed_json = Some(json);
                    nr.provider = provider_name.clone();
                    nr
                },
            )
        }
        DetectedFormat::CustomRest(ref key) => {
            let descriptor = bundle.rest_formats.get(key.as_str());
            parse_rest(req, &provider_name, format.clone(), descriptor, pre_parsed).map(
                |(mut nr, json)| {
                    parsed_json = Some(json);
                    nr.provider = provider_name.clone();
                    // Apply model_default when model wasn't extracted from request
                    if nr.model.is_none() {
                        if let Some(desc) = descriptor {
                            if let Some(default_model) = desc.model_default.as_deref() {
                                nr.model = Some(default_model.to_string());
                            }
                        }
                    }
                    nr
                },
            )
        }
        DetectedFormat::GraphQL => {
            parse_graphql(req, bundle, apq_store, pre_parsed).map(|outcome| {
                parsed_json = pre_parsed.cloned();
                warnings.extend(outcome.warnings);
                outcome.normalized
            })
        }
        DetectedFormat::GrpcProtobuf => parse_grpc(req, bundle).map(|outcome| {
            warnings.extend(outcome.warnings);
            outcome.normalized
        }),
        DetectedFormat::JsonRpc => parse_jsonrpc(req, &provider_name, pre_parsed).map(|mut nr| {
            parsed_json = pre_parsed.cloned();
            nr.provider = provider_name.clone();
            nr
        }),
        DetectedFormat::Unknown => {
            let nr = heuristic::parse(req, pre_parsed);
            parsed_json = pre_parsed.cloned();
            Ok(nr)
        }
    };

    match result {
        Ok(normalized) => {
            let source = parse_source_for_format(&format, &normalized.format_metadata);
            (normalized, source, warnings, parsed_json)
        }
        Err(error) => {
            warnings.push(DetectWarning {
                code: "parser_error",
                detail: format!("{error:?}"),
            });
            let mut normalized = heuristic::parse(req, pre_parsed);
            normalized.provider = provider_name;
            normalized.parse_warnings.push(ParseWarning::ParserError {
                reason: format!("{error:?}"),
            });
            normalized.canonical_cache_key = canonical_hash(&normalized);
            (
                normalized,
                ParseSource::Heuristic,
                warnings,
                pre_parsed.cloned(),
            )
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
        if let Some(app_entry) = bundle.products.get(app_id) {
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

    // Last resort: domain_index lookup for host → provider mapping.
    // Handles web apps (claude.ai, chatgpt.com) whose format definitions
    // lack provider_hint but whose hosts are in the domain_index.
    let headers = &req.headers;
    if let Some(host) = crate::util::header_value(headers, "host")
        .or_else(|| crate::util::header_value(headers, ":authority"))
    {
        if let Some(provider) = crate::util::lookup_domain_provider(bundle.domain_index, host) {
            return canonical_provider_candidate(provider, format, bundle);
        }
    }

    default_provider_for_format(format).to_string()
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
    provider: &str,
) -> Option<&'a ProviderEntry> {
    let canonical = provider;
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

fn parse_source_for_format(format: &DetectedFormat, _meta: &FormatMeta) -> ParseSource {
    match format {
        DetectedFormat::OpenAIRest => ParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        DetectedFormat::AnthropicRest => ParseSource::Rest {
            provider: DetectedProvider::Anthropic,
        },
        DetectedFormat::CohereRest => ParseSource::Rest {
            provider: DetectedProvider::Cohere,
        },
        DetectedFormat::GeminiRest => ParseSource::Rest {
            provider: DetectedProvider::Gemini,
        },
        DetectedFormat::BedrockRest => ParseSource::Rest {
            provider: DetectedProvider::Bedrock,
        },
        DetectedFormat::CustomRest(_) => ParseSource::AgentApp,
        DetectedFormat::GraphQL => ParseSource::GraphQl,
        DetectedFormat::GrpcProtobuf => ParseSource::Grpc,
        DetectedFormat::JsonRpc => ParseSource::JsonRpc,
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
// Conversion from internal ParseDetectResult to soth_core::DetectResult
// ---------------------------------------------------------------------------

pub fn to_core_detect_result(value: &ParseDetectResult) -> soth_core::DetectResult {
    soth_core::DetectResult {
        normalized: value.normalized.clone(),
        artifacts: value.artifacts.clone(),
        capture_mode: value.capture_mode,
        parse_source: value.parse_source,
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
        import_categories: value.import_categories.clone(),
        user_prompt: value.normalized.user_prompt.clone(),
    }
}

fn map_detect_warning(value: &DetectWarning) -> ParseWarning {
    ParseWarning::PartialBodyParse {
        reason: format!("{}: {}", value.code, value.detail),
    }
}

#[cfg(feature = "intelligence")]
fn emit_intelligence(req: &RawRequest, result: &ParseDetectResult, sink: &dyn IntelligenceSink) {
    let parse_event = build_parse_quality_record(req, result);
    let parse_event_id = sink.record_parse_event(&parse_event).ok();

    if let Some(record) = extract_unknown_graphql_operation_record(req, result, parse_event_id) {
        let _ = sink.record_unknown_graphql_operation(&record);
    }
}
