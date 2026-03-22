use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use soth_core::{
    AnomalyFlag, AppType, ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode,
    DeploymentModel, DetectedProvider, EndpointType, FormatMetadata, NormalizedRequest,
    ParseConfidence, ParseSource, PolicyContext, PolicyDecision, PolicyDecisionKind, PolicyWarning,
    ProcessMatchKind, ProcessResolution, SemanticPolicyContext, SensitiveArtifact, SessionSnapshot,
    TrafficClassification, UseCaseLabel, VolatilityClass,
};
use soth_policy::sync_policy::{
    BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
    RuleDefinition, SignedPolicyBundle,
};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    input: CorpusInput,
    expect: CorpusExpect,
}

#[derive(Debug, Deserialize, Default)]
struct CorpusInput {
    #[serde(default)]
    bundle: BundleInput,
    #[serde(default)]
    request: RequestInput,
    #[serde(default)]
    artifacts: Vec<ArtifactInput>,
    #[serde(default)]
    context: ContextInput,
}

#[derive(Debug, Deserialize, Default)]
struct BundleInput {
    #[serde(default)]
    org_rules: Vec<RuleInput>,
    #[serde(default)]
    budget_limits: BudgetLimitsInput,
}

#[derive(Debug, Deserialize)]
struct RuleInput {
    rule_id: String,
    rule_name: String,
    cel_expr: String,
    action: RuleAction,
}

#[derive(Debug, Deserialize, Default)]
struct BudgetLimitsInput {
    max_tokens_per_session: Option<u64>,
    max_cost_usd_per_session: Option<f64>,
    max_requests_per_session: Option<u32>,
    max_tokens_per_day: Option<u64>,
    max_cost_usd_per_day: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
struct RequestInput {
    provider: Option<String>,
    model: Option<String>,
    endpoint_type: Option<String>,
    is_ai_call: Option<bool>,
    stream: Option<bool>,
    has_tool_definitions: Option<bool>,
    estimated_input_tokens: Option<u32>,
    estimated_cost_usd: Option<f64>,
    parse_confidence: Option<String>,
    parse_source: Option<String>,
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
    skip_org_rules: Option<bool>,
    app_type: Option<String>,
    traffic_classification: Option<String>,
    capture_mode: Option<String>,
    session: Option<SessionInput>,
    semantic: Option<SemanticInput>,
}

#[derive(Debug, Deserialize, Default)]
struct SessionInput {
    request_count: Option<u32>,
    total_tokens: Option<u64>,
    total_cost_usd: Option<f32>,
    credential_alerts: Option<u32>,
    prior_semantic_hashes: Option<Vec<String>>,
    last_model: Option<String>,
    current_request_timestamp: Option<i64>,
    last_request_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct SemanticInput {
    use_case_label: Option<String>,
    use_case_confidence: Option<f32>,
    anomaly_score: Option<f32>,
    anomaly_flags: Option<Vec<String>>,
    complexity_score: Option<u8>,
    volatility_class: Option<String>,
    topic_cluster_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CorpusExpect {
    kind: String,
    matched_rule_id: Option<String>,
    block_status: Option<u16>,
    block_message_contains: Option<String>,
    flag_reason: Option<String>,
    reroute_provider: Option<String>,
    reroute_model: Option<String>,
    redact_target_count: Option<usize>,
    #[serde(default)]
    warnings_min: usize,
    #[serde(default)]
    warnings_rule_ids_contains: Vec<String>,
}

#[test]
fn policy_output_corpus_matches_expected_contract() {
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("policy_output_corpus.json");
    if !corpus_path.exists() {
        eprintln!(
            "Skipping policy_output_corpus_matches_expected_contract: corpus fixture not found at {}",
            corpus_path.display()
        );
        return;
    }

    let corpus_bytes =
        std::fs::read_to_string(&corpus_path).expect("read policy output corpus fixture");
    let corpus: Vec<CorpusCase> =
        serde_json::from_str(&corpus_bytes).expect("parse policy output corpus fixture");

    for case in &corpus {
        let bundle = load_bundle_for_case(&case.input.bundle);
        let request = build_request(&case.input.request);
        let artifacts = build_artifacts(&case.input.artifacts);
        let context = build_context(&case.input.context);

        let out = soth_policy::evaluate(&request, &artifacts, &context, &bundle);
        assert_case(&case.id, &case.expect, &out);
    }
}

#[test]
fn signed_bundle_file_roundtrip_load_and_eval() {
    let input = BundleInput {
        org_rules: vec![RuleInput {
            rule_id: "org_flag_roundtrip".to_string(),
            rule_name: "org_flag_roundtrip".to_string(),
            cel_expr: "request.provider == \"anthropic\"".to_string(),
            action: RuleAction::Flag {
                reason: "roundtrip".to_string(),
            },
        }],
        budget_limits: BudgetLimitsInput::default(),
    };
    let bytes = signed_bundle_bytes(build_payload(&input));

    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("policy_bundle.signed.json");
    std::fs::write(&path, bytes).expect("write signed bundle file");

    let bundle = soth_policy::load_bundle(&path).expect("load bundle from path");
    soth_policy::warm(&bundle);

    let out = soth_policy::evaluate(&default_request(), &[], &default_context(), &bundle);
    match out.kind {
        PolicyDecisionKind::Flag { reason } => assert_eq!(reason, "roundtrip"),
        other => panic!("expected flag decision, got {other:?}"),
    }
    let matched = out
        .matched_rule
        .as_ref()
        .expect("matched rule should be present");
    assert_eq!(matched.rule_id, "org_flag_roundtrip");
}

#[test]
fn home_policy_bundle_contract_smoke_if_present() {
    let bundle_path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".soth")
        .join("policy_bundle.signed.json");
    if !bundle_path.exists() {
        eprintln!(
            "Skipping home_policy_bundle_contract_smoke_if_present: bundle file not found at {}",
            bundle_path.display()
        );
        return;
    }

    let bundle = soth_policy::load_bundle(&bundle_path).expect("load ~/.soth policy bundle");
    let out = soth_policy::evaluate(&default_request(), &[], &default_context(), &bundle);
    assert!(
        matches!(
            out.kind,
            PolicyDecisionKind::Allow
                | PolicyDecisionKind::Block { .. }
                | PolicyDecisionKind::Redact { .. }
                | PolicyDecisionKind::Reroute { .. }
                | PolicyDecisionKind::Flag { .. }
        ),
        "decision kind should be valid"
    );
}

fn load_bundle_for_case(input: &BundleInput) -> soth_policy::PolicyBundle {
    let payload = build_payload(input);
    let bytes = signed_bundle_bytes(payload);
    soth_policy::load_bundle_from_bytes(&bytes).expect("load signed bundle bytes")
}

fn build_payload(input: &BundleInput) -> PolicyBundlePayload {
    PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: "2026.02.26-policy-corpus".to_string(),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_100_000,
        },
        system_rules: Vec::new(),
        org_rules: input
            .org_rules
            .iter()
            .map(|rule| RuleDefinition {
                rule_id: rule.rule_id.clone(),
                rule_name: rule.rule_name.clone(),
                cel_expr: rule.cel_expr.clone(),
                action: rule.action.clone(),
            })
            .collect(),
        org_patterns: OrgPatterns::default(),
        budget_limits: BudgetLimits {
            max_tokens_per_session: input.budget_limits.max_tokens_per_session,
            max_cost_usd_per_session: input.budget_limits.max_cost_usd_per_session,
            max_requests_per_session: input.budget_limits.max_requests_per_session,
            max_tokens_per_day: input.budget_limits.max_tokens_per_day,
            max_cost_usd_per_day: input.budget_limits.max_cost_usd_per_day,
        },
    }
}

fn signed_bundle_bytes(payload: PolicyBundlePayload) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize policy payload");
    let signature = key.sign(&payload_bytes);
    let envelope = SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    serde_json::to_vec(&envelope).expect("serialize signed policy bundle")
}

fn build_request(input: &RequestInput) -> NormalizedRequest {
    let mut request = default_request();

    if let Some(provider) = input.provider.as_deref() {
        request.provider = provider.to_string();
    }
    if let Some(model) = input.model.as_ref() {
        request.model = Some(model.clone());
    }
    if let Some(endpoint_type) = input.endpoint_type.as_deref() {
        request.endpoint_type = parse_endpoint_type(endpoint_type);
    }
    if let Some(is_ai_call) = input.is_ai_call {
        request.is_ai_call = is_ai_call;
    }
    if let Some(stream) = input.stream {
        request.stream = stream;
    }
    if let Some(has_tool_definitions) = input.has_tool_definitions {
        request.has_tool_definitions = has_tool_definitions;
    }
    if let Some(estimated_input_tokens) = input.estimated_input_tokens {
        request.estimated_input_tokens = estimated_input_tokens;
    }
    if let Some(estimated_cost_usd) = input.estimated_cost_usd {
        request.estimated_cost_usd = estimated_cost_usd;
    }
    if let Some(parse_confidence) = input.parse_confidence.as_deref() {
        request.parse_confidence = parse_parse_confidence(parse_confidence);
    }
    if let Some(parse_source) = input.parse_source.as_deref() {
        request.parse_source = parse_parse_source(parse_source);
    }

    request
}

fn default_request() -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "policy-corpus-test".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "anthropic".to_string(),
        model: Some("claude-3-5-sonnet-20241022".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        api_version: None,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: "user-hash".to_string(),
        user_content_token_estimate: 128,
        conversation_hash: "conversation-hash".to_string(),
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: 512,
        estimated_cost_usd: 0.05,
        parse_source: ParseSource::GraphQl,
        canonical_cache_key: "cache-key".to_string(),
        format_metadata: FormatMetadata::Unknown {
            method: String::new(),
            path: String::new(),
        },
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        user_prompt: None,
    }
}

fn build_artifacts(input: &[ArtifactInput]) -> Vec<SensitiveArtifact> {
    let mut artifacts = Vec::new();
    for entry in input {
        let repeat = entry.repeat.unwrap_or(1);
        let kind = parse_artifact_kind(entry);
        let severity = parse_artifact_severity(entry.severity.as_str());
        for _ in 0..repeat {
            artifacts.push(SensitiveArtifact {
                kind: kind.clone(),
                severity,
                location: ArtifactLocation::Unknown,
                commitment: None,
                redacted_hint: None,
            });
        }
    }
    artifacts
}

fn build_context(input: &ContextInput) -> PolicyContext {
    let mut ctx = default_context();

    if let Some(skip_org_rules) = input.skip_org_rules {
        ctx.skip_org_rules = skip_org_rules;
    }
    if let Some(app_type) = input.app_type.as_deref() {
        ctx.process_resolution.app_type = parse_app_type(app_type);
    }
    if let Some(traffic) = input.traffic_classification.as_deref() {
        ctx.traffic_classification = parse_traffic_classification(traffic);
    }
    if let Some(capture_mode) = input.capture_mode.as_deref() {
        ctx.capture_mode = parse_capture_mode(capture_mode);
    }
    if let Some(session) = input.session.as_ref() {
        if let Some(request_count) = session.request_count {
            ctx.session.request_count = request_count;
        }
        if let Some(total_tokens) = session.total_tokens {
            ctx.session.total_tokens = total_tokens;
        }
        if let Some(total_cost_usd) = session.total_cost_usd {
            ctx.session.total_cost_usd = total_cost_usd;
        }
        if let Some(credential_alerts) = session.credential_alerts {
            ctx.session.credential_alerts = credential_alerts;
        }
        if let Some(prior_semantic_hashes) = session.prior_semantic_hashes.as_ref() {
            ctx.session.prior_semantic_hashes = prior_semantic_hashes.clone();
        }
        if let Some(last_model) = session.last_model.as_ref() {
            ctx.session.last_model = Some(last_model.clone());
        }
        if let Some(current_request_timestamp) = session.current_request_timestamp {
            ctx.session.current_request_timestamp = current_request_timestamp;
        }
        if let Some(last_request_timestamp) = session.last_request_timestamp {
            ctx.session.last_request_timestamp = Some(last_request_timestamp);
        }
    }

    if let Some(semantic) = input.semantic.as_ref() {
        let semantic_ctx = SemanticPolicyContext {
            use_case_label: semantic
                .use_case_label
                .as_deref()
                .map(parse_use_case_label)
                .unwrap_or(UseCaseLabel::Unknown),
            use_case_confidence: semantic.use_case_confidence.unwrap_or(0.0),
            anomaly_score: semantic.anomaly_score.unwrap_or(0.0),
            anomaly_flags: semantic
                .anomaly_flags
                .as_ref()
                .map(|flags| {
                    flags
                        .iter()
                        .map(|value| parse_anomaly_flag(value.as_str()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            complexity_score: semantic.complexity_score.unwrap_or(0),
            volatility_class: semantic
                .volatility_class
                .as_deref()
                .map(parse_volatility_class)
                .unwrap_or(VolatilityClass::Static),
            topic_cluster_id: semantic.topic_cluster_id.unwrap_or(0),
        };
        ctx.semantic = Some(semantic_ctx);
    }

    ctx
}

fn default_context() -> PolicyContext {
    PolicyContext {
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: AppType::Unknown,
            capture_mode: None,
            process_name: None,
            bundle_id: None,
            matched_app_id: None,
            ..Default::default()
        },
        capture_mode: CaptureMode::MetadataOnly,
        traffic_classification: TrafficClassification::ToolUsage,
        deployment: DeploymentModel::Proxy,
        skip_org_rules: false,
        semantic: None,
        session: SessionSnapshot::default(),
    }
}

fn assert_case(case_id: &str, expect: &CorpusExpect, out: &PolicyDecision) {
    match expect.kind.as_str() {
        "allow" => {
            assert!(
                matches!(out.kind, PolicyDecisionKind::Allow),
                "case {case_id}: expected allow, got {:?}",
                out.kind
            );
        }
        "block" => match &out.kind {
            PolicyDecisionKind::Block { status, message } => {
                if let Some(expected_status) = expect.block_status {
                    assert_eq!(
                        *status, expected_status,
                        "case {case_id}: block status mismatch"
                    );
                }
                if let Some(expected_msg) = expect.block_message_contains.as_ref() {
                    assert!(
                        message.contains(expected_msg),
                        "case {case_id}: block message mismatch: got '{message}', expected to contain '{expected_msg}'"
                    );
                }
            }
            other => panic!("case {case_id}: expected block, got {other:?}"),
        },
        "redact" => match &out.kind {
            PolicyDecisionKind::Redact { targets } => {
                if let Some(expected) = expect.redact_target_count {
                    assert_eq!(
                        targets.len(),
                        expected,
                        "case {case_id}: redact target count mismatch"
                    );
                }
            }
            other => panic!("case {case_id}: expected redact, got {other:?}"),
        },
        "reroute" => match &out.kind {
            PolicyDecisionKind::Reroute { target } => {
                if let Some(provider) = expect.reroute_provider.as_ref() {
                    assert_eq!(
                        target.provider, *provider,
                        "case {case_id}: reroute provider mismatch"
                    );
                }
                if let Some(model) = expect.reroute_model.as_ref() {
                    assert_eq!(
                        target.model, *model,
                        "case {case_id}: reroute model mismatch"
                    );
                }
            }
            other => panic!("case {case_id}: expected reroute, got {other:?}"),
        },
        "flag" => match &out.kind {
            PolicyDecisionKind::Flag { reason } => {
                if let Some(expected) = expect.flag_reason.as_ref() {
                    assert_eq!(reason, expected, "case {case_id}: flag reason mismatch");
                }
            }
            other => panic!("case {case_id}: expected flag, got {other:?}"),
        },
        other => panic!("case {case_id}: unsupported expected kind '{other}'"),
    }

    match expect.matched_rule_id.as_ref() {
        Some(expected_rule_id) => {
            let matched = out
                .matched_rule
                .as_ref()
                .unwrap_or_else(|| panic!("case {case_id}: expected matched rule"));
            assert_eq!(
                matched.rule_id, *expected_rule_id,
                "case {case_id}: matched rule mismatch"
            );
        }
        None => {
            assert!(
                out.matched_rule.is_none(),
                "case {case_id}: expected no matched rule, got {:?}",
                out.matched_rule
            );
        }
    }

    assert!(
        out.warnings.len() >= expect.warnings_min,
        "case {case_id}: warnings count below expected minimum (got {}, min {})",
        out.warnings.len(),
        expect.warnings_min
    );

    for expected_rule_id in &expect.warnings_rule_ids_contains {
        let found = out.warnings.iter().any(|warning| {
            matches!(
                warning,
                PolicyWarning::RuleError { rule_id, .. } if rule_id == expected_rule_id
            )
        });
        assert!(
            found,
            "case {case_id}: missing expected rule warning '{expected_rule_id}', got {:?}",
            out.warnings
        );
    }
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

fn parse_endpoint_type(value: &str) -> EndpointType {
    match value {
        "chat_completion" => EndpointType::ChatCompletion,
        "text_completion" => EndpointType::TextCompletion,
        "embedding" => EndpointType::Embedding,
        "image_generation" => EndpointType::ImageGeneration,
        "audio_transcription" => EndpointType::AudioTranscription,
        "function_call" => EndpointType::FunctionCall,
        "streaming" => EndpointType::Streaming,
        "unknown" => EndpointType::Unknown,
        other => panic!("unsupported endpoint_type in fixture: {other}"),
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
        other => panic!("unsupported traffic classification in fixture: {other}"),
    }
}

fn parse_app_type(value: &str) -> AppType {
    match value {
        "host" => AppType::Host,
        "non_host" => AppType::NonHost,
        "unknown" => AppType::Unknown,
        other => panic!("unsupported app_type in fixture: {other}"),
    }
}

fn parse_use_case_label(value: &str) -> UseCaseLabel {
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
        other => panic!("unsupported use_case_label in fixture: {other}"),
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

fn parse_volatility_class(value: &str) -> VolatilityClass {
    match value {
        "static" => VolatilityClass::Static,
        "low_volatile" => VolatilityClass::LowVolatile,
        "dynamic" => VolatilityClass::Dynamic,
        "highly_dynamic" => VolatilityClass::HighlyDynamic,
        other => panic!("unsupported volatility_class in fixture: {other}"),
    }
}

fn parse_artifact_kind(value: &ArtifactInput) -> ArtifactKind {
    match value.kind.as_str() {
        "private_key" => ArtifactKind::PrivateKey,
        "api_key" => ArtifactKind::ApiKey {
            provider: value.provider.as_deref().map(parse_provider),
        },
        "jwt" => ArtifactKind::Jwt,
        "hex_key" => ArtifactKind::HexKey,
        "connection_string" => ArtifactKind::ConnectionString,
        "code_block" => ArtifactKind::CodeBlock {
            language: value
                .language
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        },
        "unknown_credential" => ArtifactKind::UnknownCredential,
        "org_pattern" => ArtifactKind::OrgPattern {
            pattern_id: value.pattern_id.unwrap_or(0),
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
