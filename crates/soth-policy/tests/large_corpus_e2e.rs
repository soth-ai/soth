use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use soth_core::{
    AppType, ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode, DeploymentModel,
    DetectedProvider, EndpointType, FormatMetadata, NormalizedRequest, ParseConfidence,
    ParseSource, PolicyContext, PolicyDecision, PolicyDecisionKind, ProcessMatchKind,
    ProcessResolution, RedactTarget, RerouteTarget, RuleKind, SemanticPolicyContext,
    SensitiveArtifact, SessionSnapshot, TrafficClassification, UseCaseLabel, VolatilityClass,
};
use soth_policy::sync_policy::{
    BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
    RuleDefinition, SignedPolicyBundle,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedDecision {
    Allow,
    Block429,
    Block403PrivateKey,
    Block403InputTokens,
    Block451UnknownAgentCredential,
    FlagOpenAi,
    RerouteHighCost,
    RedactEmbedding,
}

#[test]
fn policy_large_corpus_rule_matrix_e2e() {
    let bundle = load_policy_bundle();

    let mut allow = 0usize;
    let mut b429 = 0usize;
    let mut b403_private = 0usize;
    let mut b403_tokens = 0usize;
    let mut b451 = 0usize;
    let mut flag = 0usize;
    let mut reroute = 0usize;
    let mut redact = 0usize;

    for idx in 0..360usize {
        let (request, artifacts, context) = case_inputs(idx);
        let expected = expected_decision(&request, &artifacts, &context);
        let out = soth_policy::evaluate(&request, &artifacts, &context, &bundle);

        assert_decision(idx, expected, &out);

        match expected {
            ExpectedDecision::Allow => allow += 1,
            ExpectedDecision::Block429 => b429 += 1,
            ExpectedDecision::Block403PrivateKey => b403_private += 1,
            ExpectedDecision::Block403InputTokens => b403_tokens += 1,
            ExpectedDecision::Block451UnknownAgentCredential => b451 += 1,
            ExpectedDecision::FlagOpenAi => flag += 1,
            ExpectedDecision::RerouteHighCost => reroute += 1,
            ExpectedDecision::RedactEmbedding => redact += 1,
        }
    }

    assert!(allow >= 40, "expected allow coverage, got {allow}");
    assert!(b429 >= 20, "expected budget block coverage, got {b429}");
    assert!(
        b403_private >= 10,
        "expected private-key system block coverage, got {b403_private}"
    );
    assert!(
        b403_tokens >= 10,
        "expected input-token system block coverage, got {b403_tokens}"
    );
    assert!(b451 >= 10, "expected org block coverage, got {b451}");
    assert!(flag >= 20, "expected org flag coverage, got {flag}");
    assert!(
        reroute >= 12,
        "expected org reroute coverage, got {reroute}"
    );
    assert!(redact >= 10, "expected org redact coverage, got {redact}");
}

fn assert_decision(idx: usize, expected: ExpectedDecision, out: &PolicyDecision) {
    match expected {
        ExpectedDecision::Allow => {
            assert!(
                matches!(out.kind, PolicyDecisionKind::Allow),
                "case {idx}: expected allow"
            );
            assert!(
                out.matched_rule.is_none(),
                "case {idx}: allow should not include matched_rule"
            );
        }
        ExpectedDecision::Block429 => {
            match &out.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 429, "case {idx}: expected 429 budget block");
                    assert!(message.to_ascii_lowercase().contains("limit"));
                }
                other => panic!("case {idx}: expected block429, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::System);
            assert_eq!(rule.rule_id, "budget_session_requests_exceeded");
        }
        ExpectedDecision::Block403PrivateKey => {
            match &out.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 403);
                    assert!(message.to_ascii_lowercase().contains("private key"));
                }
                other => panic!("case {idx}: expected private-key block403, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::System);
            assert_eq!(rule.rule_id, "sys_private_key_detected");
        }
        ExpectedDecision::Block403InputTokens => {
            match &out.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 403);
                    assert!(message.to_ascii_lowercase().contains("token"));
                }
                other => panic!("case {idx}: expected input-token block403, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::System);
            assert_eq!(rule.rule_id, "sys_input_tokens_exceeded");
        }
        ExpectedDecision::Block451UnknownAgentCredential => {
            match &out.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 451);
                    assert!(message.to_ascii_lowercase().contains("unknown"));
                }
                other => panic!("case {idx}: expected org block451, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::Org);
            assert_eq!(rule.rule_id, "org_block_unknown_agent_with_credential");
        }
        ExpectedDecision::FlagOpenAi => {
            match &out.kind {
                PolicyDecisionKind::Flag { reason } => assert_eq!(reason, "org-openai-observed"),
                other => panic!("case {idx}: expected flag, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::Org);
            assert_eq!(rule.rule_id, "org_flag_openai");
        }
        ExpectedDecision::RerouteHighCost => {
            match &out.kind {
                PolicyDecisionKind::Reroute { target } => {
                    assert_eq!(target.provider, "anthropic");
                    assert_eq!(target.model, "claude-3-haiku-20240307");
                }
                other => panic!("case {idx}: expected reroute, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::Org);
            assert_eq!(rule.rule_id, "org_reroute_high_cost");
        }
        ExpectedDecision::RedactEmbedding => {
            match &out.kind {
                PolicyDecisionKind::Redact { targets } => {
                    assert_eq!(targets.len(), 1);
                    assert_eq!(
                        targets[0],
                        RedactTarget {
                            field_path: "request.user_content".to_string(),
                            artifact_type: "embedding".to_string(),
                        }
                    );
                }
                other => panic!("case {idx}: expected redact, got {other:?}"),
            }
            let rule = out.matched_rule.as_ref().expect("matched rule");
            assert_eq!(rule.rule_kind, RuleKind::Org);
            assert_eq!(rule.rule_id, "org_redact_embedding_calls");
        }
    }
}

fn expected_decision(
    request: &NormalizedRequest,
    artifacts: &[SensitiveArtifact],
    context: &PolicyContext,
) -> ExpectedDecision {
    if context.session.request_count > 100 {
        return ExpectedDecision::Block429;
    }

    let has_private_key = artifacts
        .iter()
        .any(|artifact| matches!(artifact.kind, ArtifactKind::PrivateKey));
    if has_private_key {
        return ExpectedDecision::Block403PrivateKey;
    }
    if request.estimated_input_tokens > 2_000_000 {
        return ExpectedDecision::Block403InputTokens;
    }
    if context.skip_org_rules {
        return ExpectedDecision::Allow;
    }

    let has_credential = artifacts.iter().any(SensitiveArtifact::is_credential);
    if request.provider == "openai" {
        return ExpectedDecision::FlagOpenAi;
    }
    if request.estimated_cost_usd > 0.25 {
        return ExpectedDecision::RerouteHighCost;
    }
    if context.traffic_classification == TrafficClassification::UnknownAgent && has_credential {
        return ExpectedDecision::Block451UnknownAgentCredential;
    }
    if request.endpoint_type == EndpointType::Embedding {
        return ExpectedDecision::RedactEmbedding;
    }
    ExpectedDecision::Allow
}

fn case_inputs(idx: usize) -> (NormalizedRequest, Vec<SensitiveArtifact>, PolicyContext) {
    let mut request = default_request();
    request.provider = match idx % 4 {
        0 => "openai".to_string(),
        1 => "anthropic".to_string(),
        2 => "gemini".to_string(),
        _ => "cohere".to_string(),
    };
    request.endpoint_type = if idx % 8 == 3 {
        EndpointType::Embedding
    } else {
        EndpointType::ChatCompletion
    };
    request.estimated_cost_usd = if idx % 6 == 0 { 0.31 } else { 0.03 };
    request.estimated_input_tokens = if idx % 23 == 0 { 2_000_100 } else { 220 };

    let mut artifacts = Vec::new();
    if idx % 19 == 0 {
        artifacts.push(SensitiveArtifact {
            kind: ArtifactKind::PrivateKey,
            credential_kind: None,
            severity: ArtifactSeverity::Critical,
            location: ArtifactLocation::SystemPrompt { char_offset: 0 },
            commitment: None,
            redacted_hint: None,
        });
    } else if idx % 5 == 0 {
        artifacts.push(SensitiveArtifact {
            kind: ArtifactKind::ApiKey {
                provider: Some(DetectedProvider::OpenAi),
            },
            credential_kind: None,
            severity: ArtifactSeverity::High,
            location: ArtifactLocation::UserContent {
                turn: 0,
                char_offset: 0,
            },
            commitment: None,
            redacted_hint: None,
        });
    }

    let mut context = default_context();
    context.skip_org_rules = idx % 7 == 0;
    context.traffic_classification = if idx % 11 == 0 {
        TrafficClassification::UnknownAgent
    } else {
        TrafficClassification::ToolUsage
    };
    context.session = SessionSnapshot {
        request_count: if idx % 17 == 0 { 160 } else { 4 },
        total_tokens: 300,
        total_cost_usd: 0.04,
        credential_alerts: 0,
        embedding_centroid: None,
        prior_semantic_hashes: vec!["s1".to_string(), "s2".to_string()],
        last_model: Some("gpt-4o-mini".to_string()),
        current_request_timestamp: 1_700_000_000_000 + idx as i64,
        last_request_timestamp: Some(1_699_999_999_000 + idx as i64),
        ..Default::default()
    };
    context.semantic = Some(SemanticPolicyContext {
        use_case_label: UseCaseLabel::Unknown,
        use_case_confidence: 0.4,
        anomaly_score: 0.2,
        anomaly_flags: Vec::new(),
        complexity_score: 28,
        volatility_class: VolatilityClass::Static,
        topic_cluster_id: (idx % 32) as u32,
    });

    // Bias credential cases toward org unknown-agent block coverage.
    if !artifacts.is_empty() && !matches!(artifacts[0].kind, ArtifactKind::PrivateKey) {
        context.traffic_classification = TrafficClassification::UnknownAgent;
        context.skip_org_rules = false;
        request.provider = "anthropic".to_string();
        request.estimated_cost_usd = 0.03;
        request.endpoint_type = EndpointType::ChatCompletion;
    }

    (request, artifacts, context)
}

fn load_policy_bundle() -> soth_policy::PolicyBundle {
    let payload = PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: "policy-large-corpus-v1".to_string(),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_220_000,
        },
        system_rules: Vec::new(),
        org_rules: vec![
            RuleDefinition {
                rule_id: "org_flag_openai".to_string(),
                rule_name: "org_flag_openai".to_string(),
                cel_expr: "request.provider == \"openai\"".to_string(),
                action: RuleAction::Flag {
                    reason: "org-openai-observed".to_string(),
                },
            },
            RuleDefinition {
                rule_id: "org_reroute_high_cost".to_string(),
                rule_name: "org_reroute_high_cost".to_string(),
                cel_expr: "request.estimated_cost_usd > 0.25".to_string(),
                action: RuleAction::Reroute {
                    target: RerouteTarget {
                        provider: "anthropic".to_string(),
                        model: "claude-3-haiku-20240307".to_string(),
                        reason: "cost-control".to_string(),
                    },
                },
            },
            RuleDefinition {
                rule_id: "org_block_unknown_agent_with_credential".to_string(),
                rule_name: "org_block_unknown_agent_with_credential".to_string(),
                cel_expr:
                    "process.traffic_classification == \"unknown_agent\" && detect.credential_detected == true"
                        .to_string(),
                action: RuleAction::Block {
                    status: 451,
                    message: "Unknown agent credential flow blocked".to_string(),
                },
            },
            RuleDefinition {
                rule_id: "org_redact_embedding_calls".to_string(),
                rule_name: "org_redact_embedding_calls".to_string(),
                cel_expr: "request.endpoint_type == \"embedding\"".to_string(),
                action: RuleAction::Redact {
                    targets: vec![RedactTarget {
                        field_path: "request.user_content".to_string(),
                        artifact_type: "embedding".to_string(),
                    }],
                },
            },
        ],
        org_patterns: OrgPatterns::default(),
        budget_limits: BudgetLimits {
            max_tokens_per_session: None,
            max_cost_usd_per_session: None,
            max_requests_per_session: Some(100),
            max_tokens_per_day: None,
            max_cost_usd_per_day: None,
        },
    };

    let key = SigningKey::from_bytes(&[62u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let signature = key.sign(payload_bytes.as_slice());
    let envelope = SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    let bytes = serde_json::to_vec(&envelope).expect("serialize signed bundle");
    soth_policy::load_bundle_from_bytes(bytes.as_slice()).expect("load signed bundle")
}

fn default_request() -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "policy-large-corpus".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "openai".to_string(),
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        api_version: None,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: "u-hash".to_string(),
        user_content_token_estimate: 64,
        conversation_hash: "conv-hash".to_string(),
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: Some(0.2),
        max_tokens: Some(256),
        stream: false,
        top_p: Some(0.9),
        stop_sequences: Vec::new(),
        estimated_input_tokens: 220,
        estimated_cost_usd: 0.03,
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
    }
}

fn default_context() -> PolicyContext {
    PolicyContext {
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Pattern,
            app_type: AppType::NonHost,
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: Some("cursor".to_string()),
            bundle_id: Some("com.todesktop.230313mzl4w4u92".to_string()),
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
