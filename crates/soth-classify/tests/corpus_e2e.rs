#![allow(clippy::all)]
#![cfg(feature = "policy")]
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use soth_core::{
    AnomalyFlag, AppType, ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode,
    ClassificationFlag, ClassificationSource, DetectResult, DetectedProvider, EndpointType,
    FormatMetadata, NormalizedRequest, ParseConfidence, ParseSource, PolicyDecisionKind,
    ProcessMatchKind, ProcessResolution, ProgrammingLanguage, ProxyContext, RedactTarget,
    RerouteTarget, SensitiveArtifact, SessionSnapshot, SurfaceType, TelemetryPolicyKind,
    TrafficClassification, UseCaseLabel, VolatilityClass,
};
use soth_policy::sync_policy::{
    BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
    RuleDefinition, SignedPolicyBundle,
};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    input: CorpusInput,
    expect: CorpusExpect,
}

#[derive(Debug, Deserialize)]
struct CorpusInput {
    bundle_profile: String,
    content: Option<String>,
    request: RequestInput,
    #[serde(default)]
    artifacts: Vec<ArtifactInput>,
    #[serde(default)]
    context: ContextInput,
}

#[derive(Debug, Deserialize, Default)]
struct RequestInput {
    provider: Option<String>,
    model: Option<String>,
    clear_model: Option<bool>,
    parse_confidence: Option<String>,
    parse_source: Option<String>,
    is_ai_call: Option<bool>,
    stream: Option<bool>,
    has_tool_definitions: Option<bool>,
    conversation_turn: Option<u32>,
    system_prompt_hash: Option<String>,
    max_tokens: Option<u32>,
    user_content_token_estimate: Option<u32>,
    estimated_input_tokens: Option<u32>,
    estimated_cost_usd: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
struct ArtifactInput {
    kind: String,
    severity: String,
    repeat: Option<usize>,
    language: Option<String>,
    provider: Option<String>,
    pattern_id: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct ContextInput {
    capture_mode: Option<String>,
    traffic_classification: Option<String>,
    classification_source: Option<String>,
    seed_prior_semantic_hash_from_content: Option<bool>,
    inject_negative_centroid_384: Option<bool>,
    session: Option<SessionInput>,
}

#[derive(Debug, Deserialize, Default)]
struct SessionInput {
    session_token_total: Option<u32>,
    session_token_p14d_avg: Option<f32>,
    request_count_this_hour: Option<u32>,
    credential_alerts_24h: Option<u8>,
    topic_cluster_ids_seen: Option<Vec<u32>>,
    models_used_this_session: Option<Vec<String>>,
    last_system_prompt_hash: Option<String>,
    max_tool_depth_seen: Option<u8>,
    request_count: Option<u32>,
    total_tokens: Option<u64>,
    total_cost_usd: Option<f32>,
    credential_alerts: Option<u32>,
    prior_semantic_hashes: Option<Vec<String>>,
    last_model: Option<String>,
    current_request_timestamp: Option<i64>,
    last_request_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CorpusExpect {
    policy_kind: String,
    policy_status: Option<u16>,
    policy_message_contains: Option<String>,
    policy_rule_id: Option<String>,
    reroute_provider: Option<String>,
    reroute_model: Option<String>,
    redact_target_count: Option<usize>,
    flag_reason: Option<String>,
    embedding_skipped: bool,
    semantic_collision: bool,
    use_case: String,
    volatility_class: Option<String>,
    timestamp_epoch_ms: Option<i64>,
    min_anomaly_score: f32,
    max_anomaly_score: f32,
    #[serde(default)]
    required_anomaly_flags: Vec<String>,
    #[serde(default)]
    required_classification_flags: Vec<String>,
    #[serde(default)]
    forbidden_classification_flags: Vec<String>,
    #[serde(default)]
    required_languages: Vec<String>,
}

#[test]
fn classify_output_corpus_matches_expected_contract() {
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("classify_output_corpus.json");
    if !corpus_path.exists() {
        eprintln!(
            "Skipping classify_output_corpus_matches_expected_contract: corpus fixture not found at {}",
            corpus_path.display()
        );
        return;
    }

    let corpus_bytes =
        std::fs::read_to_string(&corpus_path).expect("read classify output corpus fixture");
    let corpus: Vec<CorpusCase> =
        serde_json::from_str(&corpus_bytes).expect("parse classify output corpus fixture");
    let config = soth_classify::ClassifyConfig::default();

    for case in &corpus {
        let bundle = bundle_for_profile(case.input.bundle_profile.as_str());
        let detect = build_detect_result(&case.input.request, &case.input.context);
        let content = case.input.content.as_deref();
        let proxy = build_proxy_context(&case.input.context);
        let artifacts = build_artifacts(&case.input.artifacts);

        let prepared_proxy = apply_seeded_collision_if_requested(
            proxy,
            &case.input.context,
            &detect,
            content,
            &bundle,
            &config,
        );
        let mut detect_with_artifacts = detect;
        detect_with_artifacts.artifacts = artifacts;

        let first = soth_classify::classify(
            &detect_with_artifacts,
            content,
            &prepared_proxy,
            bundle.as_ref(),
            &config,
        );
        assert_case(case.id.as_str(), &case.expect, &first);

        let second = soth_classify::classify(
            &detect_with_artifacts,
            content,
            &prepared_proxy,
            bundle.as_ref(),
            &config,
        );
        assert_stable_subset(case.id.as_str(), &first, &second);
    }
}

#[test]
fn bundle_loader_contract_supports_bytes_and_directory() {
    let policy_payload = PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: "loader-policy-v1".to_string(),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_200_100,
        },
        system_rules: Vec::new(),
        org_rules: vec![RuleDefinition {
            rule_id: "org_reroute_cost".to_string(),
            rule_name: "org_reroute_cost".to_string(),
            cel_expr: "request.estimated_cost_usd > 0.2".to_string(),
            action: RuleAction::Reroute {
                target: RerouteTarget {
                    provider: "anthropic".to_string(),
                    model: "claude-3-haiku-20240307".to_string(),
                    reason: "cost-control".to_string(),
                },
            },
        }],
        org_patterns: OrgPatterns::default(),
        budget_limits: BudgetLimits::default(),
    };

    let assets = HashMap::from([
        ("classify/embedding.onnx".to_string(), b"onnx".to_vec()),
        ("classify/centroids.bin".to_string(), centroid_asset_bytes()),
        (
            "classify/lsh_projection.bin".to_string(),
            lsh_projection_asset_bytes(),
        ),
        ("classify/use_case_mlp.bin".to_string(), b"mlp".to_vec()),
        (
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(policy_payload),
        ),
    ]);
    let manifest = manifest_bytes("classify-loader-v1", &assets);

    let from_bytes = soth_classify::load_bundle_from_bytes(manifest.as_slice(), assets.clone())
        .expect("load bundle from bytes");
    assert_eq!(from_bytes.bundle_version, "classify-loader-v1");
    assert!(from_bytes.has_real_models);
    assert_loader_policy_works(from_bytes.as_ref());

    let dir = tempfile::tempdir().expect("create tempdir");
    for (path, bytes) in &assets {
        let disk_path = dir.path().join(path);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(disk_path, bytes).expect("write asset");
    }
    std::fs::write(dir.path().join("manifest.json"), &manifest).expect("write manifest");

    let from_dir = soth_classify::load_bundle(dir.path()).expect("load bundle from directory");
    assert_eq!(from_dir.bundle_version, "classify-loader-v1");
    assert!(from_dir.has_real_models);
    assert_loader_policy_works(from_dir.as_ref());

    let mut tampered_assets = assets;
    tampered_assets.insert(
        "classify/embedding.onnx".to_string(),
        b"tampered-asset".to_vec(),
    );
    let err = match soth_classify::load_bundle_from_bytes(manifest.as_slice(), tampered_assets) {
        Ok(_) => panic!("tampered bundle should fail verification"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        soth_classify::BundleLoadError::AssetHashMismatch { .. }
    ));
}

fn centroid_asset_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    for row in 0..2usize {
        for col in 0..384usize {
            let value = if row == 0 && col == 0 {
                1.0f32
            } else if row == 1 && col == 1 {
                1.0f32
            } else {
                0.0f32
            };
            out.extend_from_slice(value.to_le_bytes().as_slice());
        }
    }
    out
}

fn lsh_projection_asset_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    for row in 0..128usize {
        for col in 0..384usize {
            let value = ((row + col) as f32 / 10_000.0) - 0.5;
            out.extend_from_slice(value.to_le_bytes().as_slice());
        }
    }
    out
}

fn assert_loader_policy_works(bundle: &soth_classify::ClassifyBundle) {
    let config = soth_classify::ClassifyConfig::default();
    let detect = build_detect_result(
        &RequestInput {
            provider: Some("openai".to_string()),
            model: Some("gpt-4o-mini".to_string()),
            clear_model: Some(false),
            parse_confidence: Some("full".to_string()),
            parse_source: None,
            is_ai_call: Some(true),
            stream: Some(false),
            has_tool_definitions: Some(false),
            conversation_turn: Some(1),
            system_prompt_hash: None,
            max_tokens: None,
            user_content_token_estimate: Some(100),
            estimated_input_tokens: Some(100),
            estimated_cost_usd: Some(0.31),
        },
        &ContextInput::default(),
    );
    let proxy = build_proxy_context(&ContextInput::default());
    let out = soth_classify::classify(&detect, Some("check routing"), &proxy, bundle, &config);
    match &out.policy_decision.kind {
        PolicyDecisionKind::Reroute { target } => {
            assert_eq!(target.provider, "anthropic");
            assert_eq!(target.model, "claude-3-haiku-20240307");
        }
        other => panic!("expected reroute from loaded policy bundle, got {other:?}"),
    }
}

fn bundle_for_profile(profile: &str) -> std::sync::Arc<soth_classify::ClassifyBundle> {
    if profile == "baseline" {
        return soth_classify::ClassifyBundle::fallback();
    }

    let rules = match profile {
        "org_reroute" => vec![RuleDefinition {
            rule_id: "org_reroute_cost".to_string(),
            rule_name: "org_reroute_cost".to_string(),
            cel_expr: "request.estimated_cost_usd > 0.2".to_string(),
            action: RuleAction::Reroute {
                target: RerouteTarget {
                    provider: "anthropic".to_string(),
                    model: "claude-3-haiku-20240307".to_string(),
                    reason: "cost-control".to_string(),
                },
            },
        }],
        "org_redact" => vec![RuleDefinition {
            rule_id: "org_redact_sensitive".to_string(),
            rule_name: "org_redact_sensitive".to_string(),
            cel_expr: "request.provider == \"anthropic\"".to_string(),
            action: RuleAction::Redact {
                targets: vec![RedactTarget {
                    field_path: "messages[*].content".to_string(),
                    artifact_type: "credential".to_string(),
                }],
            },
        }],
        "org_flag" => vec![RuleDefinition {
            rule_id: "org_flag_tools".to_string(),
            rule_name: "org_flag_tools".to_string(),
            cel_expr: "request.has_tool_definitions == true".to_string(),
            action: RuleAction::Flag {
                reason: "tool-traffic".to_string(),
            },
        }],
        other => panic!("unsupported bundle_profile in fixture: {other}"),
    };

    let payload = PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: format!("classify-test-{profile}"),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_200_000,
        },
        system_rules: Vec::new(),
        org_rules: rules,
        org_patterns: OrgPatterns::default(),
        budget_limits: BudgetLimits::default(),
    };
    let policy_bundle = signed_policy_bundle(payload);
    soth_classify::ClassifyBundle::fallback_with_policy_bundle(
        std::sync::Arc::new(policy_bundle),
        format!("classify-test-{profile}"),
    )
}

fn signed_policy_bundle(payload: PolicyBundlePayload) -> soth_policy::PolicyBundle {
    let bytes = signed_policy_bundle_bytes(payload);
    soth_policy::load_bundle_from_bytes(&bytes).expect("load signed policy bundle")
}

fn signed_policy_bundle_bytes(payload: PolicyBundlePayload) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[13u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize policy payload");
    let signature = key.sign(&payload_bytes);

    let envelope = SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    serde_json::to_vec(&envelope).expect("serialize signed policy envelope")
}

fn manifest_bytes(version: &str, assets: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Manifest<'a> {
        version: &'a str,
        assets: Vec<Entry<'a>>,
    }

    #[derive(serde::Serialize)]
    struct Entry<'a> {
        path: &'a str,
        sha256: String,
        size_bytes: u64,
    }

    let mut entries = assets
        .iter()
        .map(|(path, bytes)| Entry {
            path: path.as_str(),
            sha256: sha256_hex(bytes.as_slice()),
            size_bytes: bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(right.path));

    serde_json::to_vec(&Manifest {
        version,
        assets: entries,
    })
    .expect("serialize manifest")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn build_detect_result(request: &RequestInput, context: &ContextInput) -> DetectResult {
    let mut normalized = NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "classify-corpus".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "openai".to_string(),
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        api_version: None,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: "user-hash".to_string(),
        user_content_token_estimate: 120,
        conversation_hash: "conversation-hash".to_string(),
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: 120,
        estimated_cost_usd: 0.02,
        parse_source: ParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        canonical_cache_key: "cache-key".to_string(),
        format_metadata: FormatMetadata::Unknown {
            method: String::new(),
            path: String::new(),
        },
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        user_prompt: None,
    };

    if let Some(provider) = request.provider.as_deref() {
        normalized.provider = provider.to_string();
    }
    if request.clear_model.unwrap_or(false) {
        normalized.model = None;
    }
    if let Some(model) = request.model.as_ref() {
        normalized.model = Some(model.clone());
    }
    if let Some(parse_confidence) = request.parse_confidence.as_deref() {
        normalized.parse_confidence = parse_parse_confidence(parse_confidence);
    }
    if let Some(parse_source) = request.parse_source.as_deref() {
        normalized.parse_source = parse_parse_source(parse_source);
    } else if let ParseSource::Rest { .. } = normalized.parse_source {
        normalized.parse_source = ParseSource::Rest {
            provider: request
                .provider
                .as_deref()
                .map(parse_provider)
                .unwrap_or(DetectedProvider::OpenAi),
        };
    }
    if let Some(is_ai_call) = request.is_ai_call {
        normalized.is_ai_call = is_ai_call;
    }
    if let Some(stream) = request.stream {
        normalized.stream = stream;
    }
    if let Some(has_tool_definitions) = request.has_tool_definitions {
        normalized.has_tool_definitions = has_tool_definitions;
    }
    if let Some(conversation_turn) = request.conversation_turn {
        normalized.conversation_turn = Some(conversation_turn);
    }
    if let Some(system_prompt_hash) = request.system_prompt_hash.as_ref() {
        normalized.system_prompt_hash = Some(system_prompt_hash.clone());
    }
    if let Some(max_tokens) = request.max_tokens {
        normalized.max_tokens = Some(max_tokens);
        normalized.estimated_output_tokens = Some(max_tokens);
    }
    if let Some(user_content_token_estimate) = request.user_content_token_estimate {
        normalized.user_content_token_estimate = user_content_token_estimate;
    }
    if let Some(estimated_input_tokens) = request.estimated_input_tokens {
        normalized.estimated_input_tokens = estimated_input_tokens;
    }
    if let Some(estimated_cost_usd) = request.estimated_cost_usd {
        normalized.estimated_cost_usd = estimated_cost_usd;
    }

    let detect_confidence = request
        .parse_confidence
        .as_deref()
        .map(parse_parse_confidence)
        .unwrap_or(ParseConfidence::Full);
    let capture_mode = context
        .capture_mode
        .as_deref()
        .map(parse_capture_mode)
        .unwrap_or(CaptureMode::MetadataOnly);

    DetectResult {
        normalized,
        artifacts: Vec::new(),
        capture_mode,
        parse_source: ParseSource::Rest {
            provider: request
                .provider
                .as_deref()
                .map(parse_provider)
                .unwrap_or(DetectedProvider::OpenAi),
        },
        confidence: detect_confidence,
        detect_latency_us: 0,
        warnings: Vec::new(),
        session_mutations: soth_core::SessionMutations::default(),
        is_prefix_repeat: false,
        novel_token_count: 0,
        repeated_token_count: 0,
        novel_tail_start_idx: None,
        prefix_hash: None,
        is_repeated_code_context: false,
        ast_normalized_hash: None,
        first_blob_event_id: None,
        import_categories: Vec::new(),
        user_prompt: None,
    }
}

fn build_proxy_context(context: &ContextInput) -> ProxyContext {
    let capture_mode = context
        .capture_mode
        .as_deref()
        .map(parse_capture_mode)
        .unwrap_or(CaptureMode::MetadataOnly);
    let traffic = context
        .traffic_classification
        .as_deref()
        .map(parse_traffic_classification)
        .unwrap_or(TrafficClassification::Other);
    let source = context
        .classification_source
        .as_deref()
        .map(parse_classification_source)
        .unwrap_or(ClassificationSource::Proxy);

    let mut session = context.session.as_ref().map(build_session_snapshot);
    if context.inject_negative_centroid_384.unwrap_or(false) {
        let entry = session.get_or_insert_with(SessionSnapshot::default);
        entry.embedding_centroid = Some(vec![-1.0; 384]);
    }

    ProxyContext {
        org_id: "org-test".to_string(),
        user_id_hmac: "user-hmac".to_string(),
        team_id: "team-test".to_string(),
        device_id_hash: "device-hash".to_string(),
        endpoint_hash: "endpoint-hash".to_string(),
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: AppType::Unknown,
            capture_mode: Some(capture_mode),
            process_name: None,
            bundle_id: None,
            matched_app_id: None,
            ..Default::default()
        },
        capture_mode,
        matched_provider: Some("openai".to_string()),
        matched_application: None,
        traffic_classification: traffic,
        classification_source: source,
        session_snapshot: session,
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
        connection_id: None,
        bundle_trust_level: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
    }
}

fn apply_seeded_collision_if_requested(
    mut proxy: ProxyContext,
    context: &ContextInput,
    detect: &DetectResult,
    content: Option<&str>,
    bundle: &std::sync::Arc<soth_classify::ClassifyBundle>,
    config: &soth_classify::ClassifyConfig,
) -> ProxyContext {
    if !context
        .seed_prior_semantic_hash_from_content
        .unwrap_or(false)
    {
        return proxy;
    }

    let baseline = soth_classify::classify(detect, content, &proxy, bundle.as_ref(), config);
    let session = proxy
        .session_snapshot
        .get_or_insert_with(SessionSnapshot::default);
    session.prior_semantic_hashes.push(baseline.semantic_hash);
    proxy
}

fn build_session_snapshot(input: &SessionInput) -> SessionSnapshot {
    let mut snapshot = SessionSnapshot::default();
    if let Some(session_token_total) = input.session_token_total {
        snapshot.session_token_total = session_token_total;
    }
    if let Some(session_token_p14d_avg) = input.session_token_p14d_avg {
        snapshot.session_token_p14d_avg = session_token_p14d_avg;
    }
    if let Some(request_count_this_hour) = input.request_count_this_hour {
        snapshot.request_count_this_hour = request_count_this_hour;
    }
    if let Some(credential_alerts_24h) = input.credential_alerts_24h {
        snapshot.credential_alerts_24h = credential_alerts_24h;
    }
    if let Some(topic_cluster_ids_seen) = input.topic_cluster_ids_seen.as_ref() {
        snapshot.topic_cluster_ids_seen = topic_cluster_ids_seen.clone();
    }
    if let Some(models_used_this_session) = input.models_used_this_session.as_ref() {
        snapshot.models_used_this_session = models_used_this_session.clone();
    }
    if let Some(last_system_prompt_hash) = input.last_system_prompt_hash.as_ref() {
        snapshot.last_system_prompt_hash = Some(last_system_prompt_hash.clone());
    }
    if let Some(max_tool_depth_seen) = input.max_tool_depth_seen {
        snapshot.max_tool_depth_seen = max_tool_depth_seen;
    }
    if let Some(request_count) = input.request_count {
        snapshot.request_count = request_count;
    }
    if let Some(total_tokens) = input.total_tokens {
        snapshot.total_tokens = total_tokens;
    }
    if let Some(total_cost_usd) = input.total_cost_usd {
        snapshot.total_cost_usd = total_cost_usd;
    }
    if let Some(credential_alerts) = input.credential_alerts {
        snapshot.credential_alerts = credential_alerts;
    }
    if let Some(prior_semantic_hashes) = input.prior_semantic_hashes.as_ref() {
        snapshot.prior_semantic_hashes = prior_semantic_hashes.clone();
    }
    if let Some(last_model) = input.last_model.as_ref() {
        snapshot.last_model = Some(last_model.clone());
    }
    if let Some(current_request_timestamp) = input.current_request_timestamp {
        snapshot.current_request_timestamp = current_request_timestamp;
    }
    if let Some(last_request_timestamp) = input.last_request_timestamp {
        snapshot.last_request_timestamp = Some(last_request_timestamp);
    }
    snapshot
}

fn build_artifacts(input: &[ArtifactInput]) -> Vec<SensitiveArtifact> {
    let mut out = Vec::new();
    for artifact in input {
        let repeat = artifact.repeat.unwrap_or(1);
        let kind = parse_artifact_kind(artifact);
        let severity = parse_artifact_severity(artifact.severity.as_str());
        for _ in 0..repeat {
            out.push(SensitiveArtifact {
                kind: kind.clone(),
                severity,
                location: ArtifactLocation::Unknown,
                commitment: None,
                redacted_hint: None,
            });
        }
    }
    out
}

fn assert_case(case_id: &str, expect: &CorpusExpect, out: &soth_classify::ClassifiedResult) {
    assert_eq!(
        out.use_case_label,
        parse_use_case(expect.use_case.as_str()),
        "case {case_id}: use_case mismatch"
    );
    assert_eq!(
        out.embedding_skipped, expect.embedding_skipped,
        "case {case_id}: embedding_skipped mismatch"
    );
    assert_eq!(
        out.is_semantic_collision, expect.semantic_collision,
        "case {case_id}: semantic_collision mismatch"
    );
    if let Some(volatility_class) = expect.volatility_class.as_deref() {
        assert_eq!(
            out.volatility_class,
            parse_volatility_class(volatility_class),
            "case {case_id}: volatility class mismatch"
        );
    }
    if expect.timestamp_epoch_ms.is_some() {
        // timestamp_epoch_ms is now wall-clock time, just verify it's recent
        assert!(
            out.telemetry_event.timestamp_epoch_ms > 1_700_000_000_000,
            "case {case_id}: telemetry timestamp should be recent wall-clock time, got {}",
            out.telemetry_event.timestamp_epoch_ms
        );
    }
    assert!(
        out.anomaly_score >= expect.min_anomaly_score,
        "case {case_id}: anomaly score below min (got {}, min {})",
        out.anomaly_score,
        expect.min_anomaly_score
    );
    assert!(
        out.anomaly_score <= expect.max_anomaly_score,
        "case {case_id}: anomaly score above max (got {}, max {})",
        out.anomaly_score,
        expect.max_anomaly_score
    );

    assert_policy(case_id, expect, out);
    assert_anomaly_flags(case_id, expect, out);
    assert_classification_flags(case_id, expect, out);
    assert_languages(case_id, expect, out);
}

fn assert_policy(case_id: &str, expect: &CorpusExpect, out: &soth_classify::ClassifiedResult) {
    let expected_kind = parse_policy_kind(expect.policy_kind.as_str());
    assert_eq!(
        out.telemetry_event.policy_kind,
        Some(expected_kind),
        "case {case_id}: telemetry policy kind mismatch"
    );

    match (&out.policy_decision.kind, expected_kind) {
        (PolicyDecisionKind::Allow, TelemetryPolicyKind::Allow) => {}
        (PolicyDecisionKind::Block { status, message }, TelemetryPolicyKind::Block) => {
            if let Some(expected_status) = expect.policy_status {
                assert_eq!(
                    *status, expected_status,
                    "case {case_id}: block status mismatch"
                );
            }
            if let Some(expected_message) = expect.policy_message_contains.as_ref() {
                assert!(
                    message.contains(expected_message),
                    "case {case_id}: block message mismatch. got '{message}', expected to contain '{expected_message}'"
                );
            }
        }
        (PolicyDecisionKind::Redact { targets }, TelemetryPolicyKind::Redact) => {
            if let Some(expected_targets) = expect.redact_target_count {
                assert_eq!(
                    targets.len(),
                    expected_targets,
                    "case {case_id}: redact target count mismatch"
                );
            }
        }
        (PolicyDecisionKind::Reroute { target }, TelemetryPolicyKind::Reroute) => {
            if let Some(expected_provider) = expect.reroute_provider.as_ref() {
                assert_eq!(
                    target.provider, *expected_provider,
                    "case {case_id}: reroute provider mismatch"
                );
            }
            if let Some(expected_model) = expect.reroute_model.as_ref() {
                assert_eq!(
                    target.model, *expected_model,
                    "case {case_id}: reroute model mismatch"
                );
            }
        }
        (PolicyDecisionKind::Flag { reason }, TelemetryPolicyKind::Flag) => {
            if let Some(expected_reason) = expect.flag_reason.as_ref() {
                assert_eq!(
                    reason, expected_reason,
                    "case {case_id}: flag reason mismatch"
                );
            }
        }
        (actual, expected) => {
            panic!("case {case_id}: policy kind mismatch, actual={actual:?}, expected={expected:?}")
        }
    }

    match expect.policy_rule_id.as_ref() {
        Some(expected_rule) => {
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .unwrap_or_else(|| panic!("case {case_id}: expected matched rule"));
            assert_eq!(
                matched.rule_id, *expected_rule,
                "case {case_id}: matched rule mismatch"
            );
        }
        None => {
            assert!(
                out.policy_decision.matched_rule.is_none(),
                "case {case_id}: expected no matched rule, got {:?}",
                out.policy_decision.matched_rule
            );
        }
    }
}

fn assert_anomaly_flags(
    case_id: &str,
    expect: &CorpusExpect,
    out: &soth_classify::ClassifiedResult,
) {
    for required in &expect.required_anomaly_flags {
        let parsed = parse_anomaly_flag(required.as_str());
        assert!(
            out.anomaly_flags.contains(&parsed),
            "case {case_id}: missing anomaly flag {parsed:?}, got {:?}",
            out.anomaly_flags
        );
    }
}

fn assert_classification_flags(
    case_id: &str,
    expect: &CorpusExpect,
    out: &soth_classify::ClassifiedResult,
) {
    for required in &expect.required_classification_flags {
        let parsed = parse_classification_flag(required.as_str());
        assert!(
            out.telemetry_event.classification_flags.contains(&parsed),
            "case {case_id}: missing classification flag {parsed:?}, got {:?}",
            out.telemetry_event.classification_flags
        );
    }
    for forbidden in &expect.forbidden_classification_flags {
        let parsed = parse_classification_flag(forbidden.as_str());
        assert!(
            !out.telemetry_event.classification_flags.contains(&parsed),
            "case {case_id}: found forbidden classification flag {parsed:?}, got {:?}",
            out.telemetry_event.classification_flags
        );
    }
}

fn assert_languages(case_id: &str, expect: &CorpusExpect, out: &soth_classify::ClassifiedResult) {
    for required in &expect.required_languages {
        let parsed = parse_language(required.as_str());
        assert!(
            out.telemetry_event.languages.contains(&parsed),
            "case {case_id}: missing language {parsed:?}, got {:?}",
            out.telemetry_event.languages
        );
    }
}

fn assert_stable_subset(
    case_id: &str,
    first: &soth_classify::ClassifiedResult,
    second: &soth_classify::ClassifiedResult,
) {
    assert_eq!(
        first.use_case_label, second.use_case_label,
        "case {case_id}: use_case_label changed across identical runs"
    );
    assert_eq!(
        first.use_case_confidence, second.use_case_confidence,
        "case {case_id}: use_case_confidence changed across identical runs"
    );
    assert_eq!(
        first.secondary_label, second.secondary_label,
        "case {case_id}: secondary_label changed across identical runs"
    );
    assert_eq!(
        first.topic_cluster_id, second.topic_cluster_id,
        "case {case_id}: topic_cluster_id changed across identical runs"
    );
    assert_eq!(
        first.semantic_hash, second.semantic_hash,
        "case {case_id}: semantic_hash changed across identical runs"
    );
    assert!(
        (first.embedding_norm - second.embedding_norm).abs() <= 1e-6,
        "case {case_id}: embedding_norm changed across identical runs"
    );
    assert_eq!(
        first.complexity_score, second.complexity_score,
        "case {case_id}: complexity_score changed across identical runs"
    );
    assert_eq!(
        first.embedding_skipped, second.embedding_skipped,
        "case {case_id}: embedding_skipped changed across identical runs"
    );
    assert_eq!(
        first.volatility_class, second.volatility_class,
        "case {case_id}: volatility_class changed across identical runs"
    );
    assert!(
        (first.dynamic_fraction - second.dynamic_fraction).abs() <= 1e-6,
        "case {case_id}: dynamic_fraction changed across identical runs"
    );
    assert_eq!(
        first.is_semantic_collision, second.is_semantic_collision,
        "case {case_id}: semantic_collision changed across identical runs"
    );
    assert_eq!(
        first.prefix_repeat_signature, second.prefix_repeat_signature,
        "case {case_id}: prefix_repeat_signature changed across identical runs"
    );
    assert!(
        (first.anomaly_score - second.anomaly_score).abs() <= 1e-6,
        "case {case_id}: anomaly_score changed across identical runs"
    );
    assert_eq!(
        first.anomaly_flags, second.anomaly_flags,
        "case {case_id}: anomaly_flags changed across identical runs"
    );
    assert_eq!(
        first.policy_decision.kind, second.policy_decision.kind,
        "case {case_id}: policy kind changed across identical runs"
    );
    assert_eq!(
        first.policy_decision.matched_rule, second.policy_decision.matched_rule,
        "case {case_id}: policy matched_rule changed across identical runs"
    );
    assert_eq!(
        first.policy_decision.warnings, second.policy_decision.warnings,
        "case {case_id}: policy warnings changed across identical runs"
    );

    // timestamp_epoch_ms is wall-clock; allow small divergence between runs
    assert!(
        (first.telemetry_event.timestamp_epoch_ms - second.telemetry_event.timestamp_epoch_ms)
            .unsigned_abs()
            < 1000,
        "case {case_id}: telemetry timestamps diverged by more than 1s across identical runs"
    );
    assert_eq!(
        first.telemetry_event.provider, second.telemetry_event.provider,
        "case {case_id}: telemetry provider changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.model, second.telemetry_event.model,
        "case {case_id}: telemetry model changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.endpoint_type, second.telemetry_event.endpoint_type,
        "case {case_id}: telemetry endpoint_type changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.parse_confidence, second.telemetry_event.parse_confidence,
        "case {case_id}: telemetry parse_confidence changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.parse_source, second.telemetry_event.parse_source,
        "case {case_id}: telemetry parse_source changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.capture_mode, second.telemetry_event.capture_mode,
        "case {case_id}: telemetry capture_mode changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.use_case, second.telemetry_event.use_case,
        "case {case_id}: telemetry use_case changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.volatility_class, second.telemetry_event.volatility_class,
        "case {case_id}: telemetry volatility_class changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.request_method, second.telemetry_event.request_method,
        "case {case_id}: telemetry request_method changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.estimated_input_tokens, second.telemetry_event.estimated_input_tokens,
        "case {case_id}: telemetry estimated_input_tokens changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.estimated_output_tokens,
        second.telemetry_event.estimated_output_tokens,
        "case {case_id}: telemetry estimated_output_tokens changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.estimated_cost_usd, second.telemetry_event.estimated_cost_usd,
        "case {case_id}: telemetry estimated_cost_usd changed across identical runs"
    );
    let first_process =
        serde_json::to_value(&first.telemetry_event.process_resolution).expect("serialize process");
    let second_process = serde_json::to_value(&second.telemetry_event.process_resolution)
        .expect("serialize process");
    assert_eq!(
        first_process, second_process,
        "case {case_id}: telemetry process_resolution changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.traffic_classification, second.telemetry_event.traffic_classification,
        "case {case_id}: telemetry traffic_classification changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.languages, second.telemetry_event.languages,
        "case {case_id}: telemetry languages changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.import_categories, second.telemetry_event.import_categories,
        "case {case_id}: telemetry import_categories changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.classification_flags, second.telemetry_event.classification_flags,
        "case {case_id}: telemetry classification_flags changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.anomaly_flags, second.telemetry_event.anomaly_flags,
        "case {case_id}: telemetry anomaly_flags changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.anomaly_score, second.telemetry_event.anomaly_score,
        "case {case_id}: telemetry anomaly_score changed across identical runs"
    );
    assert_eq!(
        first.telemetry_event.policy_kind, second.telemetry_event.policy_kind,
        "case {case_id}: telemetry policy_kind changed across identical runs"
    );
    let first_sensitive = serde_json::to_value(&first.telemetry_event.sensitive_code_flags)
        .expect("serialize sensitive flags");
    let second_sensitive = serde_json::to_value(&second.telemetry_event.sensitive_code_flags)
        .expect("serialize sensitive flags");
    assert_eq!(
        first_sensitive, second_sensitive,
        "case {case_id}: telemetry sensitive_code_flags changed across identical runs"
    );

    assert_ne!(
        first.telemetry_event.event_id, second.telemetry_event.event_id,
        "case {case_id}: event_id unexpectedly identical across runs"
    );
    assert_ne!(
        first.commitment_nonce, second.commitment_nonce,
        "case {case_id}: commitment_nonce unexpectedly identical across runs"
    );
}

fn parse_provider(value: &str) -> DetectedProvider {
    match value {
        "anthropic" => DetectedProvider::Anthropic,
        "openai" => DetectedProvider::OpenAi,
        "azure_openai" => DetectedProvider::AzureOpenAi,
        "gemini" => DetectedProvider::Gemini,
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
        "unknown" => DetectedProvider::Unknown,
        other => panic!("unsupported provider in fixture: {other}"),
    }
}

fn parse_parse_source(value: &str) -> ParseSource {
    match value {
        "graphql" => ParseSource::GraphQl,
        "grpc" => ParseSource::Grpc,
        "jsonrpc" => ParseSource::JsonRpc,
        "agent_app" => ParseSource::AgentApp,
        "heuristic" => ParseSource::Heuristic,
        "filtered" => ParseSource::Filtered,
        other if other.starts_with("rest:") => ParseSource::Rest {
            provider: parse_provider(&other["rest:".len()..]),
        },
        other => panic!("unsupported parse_source in fixture: {other}"),
    }
}

fn parse_parse_confidence(value: &str) -> ParseConfidence {
    match value {
        "full" => ParseConfidence::Full,
        "partial" => ParseConfidence::Partial,
        "heuristic" => ParseConfidence::Heuristic,
        other => panic!("unsupported parse_confidence in fixture: {other}"),
    }
}

fn parse_capture_mode(value: &str) -> CaptureMode {
    match value {
        "metadata_only" => CaptureMode::MetadataOnly,
        "full" => CaptureMode::Full,
        "sensitive_artifacts" => CaptureMode::SensitiveArtifacts,
        "full_content" => CaptureMode::FullContent,
        other => panic!("unsupported capture_mode in fixture: {other}"),
    }
}

fn parse_traffic_classification(value: &str) -> TrafficClassification {
    match value {
        "tool_usage" => TrafficClassification::ToolUsage,
        "application_usage" => TrafficClassification::ApplicationUsage,
        "unknown_agent" => TrafficClassification::UnknownAgent,
        "other" => TrafficClassification::Other,
        other => panic!("unsupported traffic_classification in fixture: {other}"),
    }
}

fn parse_classification_source(value: &str) -> ClassificationSource {
    match value {
        "proxy" => ClassificationSource::Proxy,
        "sidecar" => ClassificationSource::Sidecar,
        "sdk" => ClassificationSource::Sdk,
        other => panic!("unsupported classification_source in fixture: {other}"),
    }
}

fn parse_policy_kind(value: &str) -> TelemetryPolicyKind {
    match value {
        "allow" => TelemetryPolicyKind::Allow,
        "block" => TelemetryPolicyKind::Block,
        "redact" => TelemetryPolicyKind::Redact,
        "reroute" => TelemetryPolicyKind::Reroute,
        "flag" => TelemetryPolicyKind::Flag,
        other => panic!("unsupported policy_kind in fixture: {other}"),
    }
}

fn parse_use_case(value: &str) -> UseCaseLabel {
    match value {
        "code_generation" => UseCaseLabel::CodeGeneration,
        "code_review" => UseCaseLabel::CodeReview,
        "code_debugging" => UseCaseLabel::CodeDebugging,
        "code_refactor" => UseCaseLabel::CodeRefactor,
        "text_summarization" => UseCaseLabel::TextSummarization,
        "text_generation" => UseCaseLabel::TextGeneration,
        "translation" => UseCaseLabel::Translation,
        "data_analysis" => UseCaseLabel::DataAnalysis,
        "data_extraction" => UseCaseLabel::DataExtraction,
        "question_answering" => UseCaseLabel::QuestionAnswering,
        "document_search" => UseCaseLabel::DocumentSearch,
        "agent_task" => UseCaseLabel::AgentTask,
        "tool_orchestration" => UseCaseLabel::ToolOrchestration,
        "image_analysis" => UseCaseLabel::ImageAnalysis,
        "audio_transcription" => UseCaseLabel::AudioTranscription,
        "system_prompt_only" => UseCaseLabel::SystemPromptOnly,
        "unknown" => UseCaseLabel::Unknown,
        other => panic!("unsupported use_case in fixture: {other}"),
    }
}

fn parse_volatility_class(value: &str) -> VolatilityClass {
    match value {
        "static" => VolatilityClass::Static,
        "low_volatile" => VolatilityClass::LowVolatile,
        "dynamic" => VolatilityClass::Dynamic,
        "highly_dynamic" => VolatilityClass::HighlyDynamic,
        other => panic!("unsupported volatility_class in fixture: {other}"),
    }
}

fn parse_classification_flag(value: &str) -> ClassificationFlag {
    match value {
        "code_detected" => ClassificationFlag::CodeDetected,
        "credential_detected" => ClassificationFlag::CredentialDetected,
        "high_anomaly" => ClassificationFlag::HighAnomaly,
        "policy_triggered" => ClassificationFlag::PolicyTriggered,
        other => panic!("unsupported classification_flag in fixture: {other}"),
    }
}

fn parse_anomaly_flag(value: &str) -> AnomalyFlag {
    match value {
        "topic_drift" => AnomalyFlag::TopicDrift,
        "credential_burst" => AnomalyFlag::CredentialBurst,
        "token_burst" => AnomalyFlag::TokenBurst,
        "model_switch" => AnomalyFlag::ModelSwitch,
        "agent_loop_pattern" => AnomalyFlag::AgentLoopPattern,
        "rapid_fire_requests" => AnomalyFlag::RapidFireRequests,
        "unusual_system_prompt_change" => AnomalyFlag::UnusualSystemPromptChange,
        "tool_call_depth_spike" => AnomalyFlag::ToolCallDepthSpike,
        other => panic!("unsupported anomaly_flag in fixture: {other}"),
    }
}

fn parse_language(value: &str) -> ProgrammingLanguage {
    match value {
        "python" => ProgrammingLanguage::Python,
        "javascript" => ProgrammingLanguage::JavaScript,
        "typescript" => ProgrammingLanguage::TypeScript,
        "rust" => ProgrammingLanguage::Rust,
        "go" => ProgrammingLanguage::Go,
        "java" => ProgrammingLanguage::Java,
        "cpp" => ProgrammingLanguage::Cpp,
        "c" => ProgrammingLanguage::C,
        "csharp" => ProgrammingLanguage::CSharp,
        "ruby" => ProgrammingLanguage::Ruby,
        "php" => ProgrammingLanguage::Php,
        "swift" => ProgrammingLanguage::Swift,
        "kotlin" => ProgrammingLanguage::Kotlin,
        "sql" => ProgrammingLanguage::Sql,
        "shell" => ProgrammingLanguage::Shell,
        "terraform" => ProgrammingLanguage::Terraform,
        "solidity" => ProgrammingLanguage::Solidity,
        "yaml" => ProgrammingLanguage::Yaml,
        "json" => ProgrammingLanguage::Json,
        "unknown" => ProgrammingLanguage::Unknown,
        other => panic!("unsupported language in fixture: {other}"),
    }
}

fn parse_artifact_kind(input: &ArtifactInput) -> ArtifactKind {
    match input.kind.as_str() {
        "private_key" => ArtifactKind::PrivateKey,
        "api_key" => ArtifactKind::ApiKey {
            provider: input.provider.as_deref().map(parse_provider),
        },
        "jwt" => ArtifactKind::Jwt,
        "hex_key" => ArtifactKind::HexKey,
        "connection_string" => ArtifactKind::ConnectionString,
        "code_block" => ArtifactKind::CodeBlock {
            language: input
                .language
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        },
        "unknown_credential" => ArtifactKind::UnknownCredential,
        "org_pattern" => ArtifactKind::OrgPattern {
            pattern_id: input.pattern_id.unwrap_or(0),
        },
        "auth_logic" => ArtifactKind::AuthLogic,
        "crypto_operation" => ArtifactKind::CryptoOperation,
        "aws_access_key" => ArtifactKind::AwsAccessKey,
        "github_pat" => ArtifactKind::GitHubPat,
        "gitlab_token" => ArtifactKind::GitLabToken,
        "slack_token" => ArtifactKind::SlackToken,
        "stripe_secret_key" => ArtifactKind::StripeSecretKey,
        other => panic!("unsupported artifact kind in fixture: {other}"),
    }
}

fn parse_artifact_severity(value: &str) -> ArtifactSeverity {
    match value {
        "low" => ArtifactSeverity::Low,
        "medium" => ArtifactSeverity::Medium,
        "high" => ArtifactSeverity::High,
        "critical" => ArtifactSeverity::Critical,
        other => panic!("unsupported artifact severity in fixture: {other}"),
    }
}
