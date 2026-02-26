mod common;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use soth_core::{
    ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode, ClassificationFlag,
    DetectResult, DetectedProvider, EndpointType, ParseConfidence, PolicyDecisionKind,
    ProxyContext, RedactTarget, RerouteTarget, SensitiveArtifact, SessionSnapshot,
    TelemetryPolicyKind, TrafficClassification,
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
    Block451,
    FlagOpenAi,
    RerouteHighCost,
    RedactEmbedding,
}

#[test]
fn classify_large_corpus_policy_matrix_e2e() {
    let policy_bundle = load_policy_bundle();
    let bundle = soth_classify::ClassifyBundle::fallback_with_policy_bundle(
        Arc::new(policy_bundle),
        "classify-large-corpus".to_string(),
    );
    let config = soth_classify::ClassifyConfig::default();

    let mut allow = 0usize;
    let mut block_429 = 0usize;
    let mut block_403_private = 0usize;
    let mut block_403_tokens = 0usize;
    let mut block_451 = 0usize;
    let mut flag = 0usize;
    let mut reroute = 0usize;
    let mut redact = 0usize;

    for idx in 0..320usize {
        let mut detect = common::make_detect_result();
        let mut proxy = common::make_proxy_ctx(Some(session_for_case(idx)));
        apply_case_inputs(idx, &mut detect, &mut proxy);

        let content = format!("classification corpus case {idx} content");
        let expected = expected_decision(&detect, &proxy);
        let first =
            soth_classify::classify(&detect, Some(content.as_str()), &proxy, &bundle, &config);
        let second =
            soth_classify::classify(&detect, Some(content.as_str()), &proxy, &bundle, &config);

        assert_eq!(
            first.policy_decision.kind, second.policy_decision.kind,
            "case {idx}: policy decision should be deterministic"
        );
        assert_eq!(
            first.telemetry_event.policy_kind, second.telemetry_event.policy_kind,
            "case {idx}: telemetry policy kind should be deterministic"
        );
        assert_eq!(
            first.semantic_hash, second.semantic_hash,
            "case {idx}: semantic hash should be deterministic for same input"
        );
        assert!(
            first.policy_enforced,
            "case {idx}: classify should mark policy_enforced=true"
        );

        assert_expected(idx, expected, &first);
        match expected {
            ExpectedDecision::Allow => allow += 1,
            ExpectedDecision::Block429 => block_429 += 1,
            ExpectedDecision::Block403PrivateKey => block_403_private += 1,
            ExpectedDecision::Block403InputTokens => block_403_tokens += 1,
            ExpectedDecision::Block451 => block_451 += 1,
            ExpectedDecision::FlagOpenAi => flag += 1,
            ExpectedDecision::RerouteHighCost => reroute += 1,
            ExpectedDecision::RedactEmbedding => redact += 1,
        }
    }

    assert!(allow >= 20, "expected healthy allow coverage, got {allow}");
    assert!(
        block_429 >= 10,
        "expected budget-block coverage, got {block_429}"
    );
    assert!(
        block_403_private >= 10,
        "expected private-key system-block coverage, got {block_403_private}"
    );
    assert!(
        block_403_tokens >= 5,
        "expected input-token system-block coverage, got {block_403_tokens}"
    );
    assert!(
        block_451 >= 10,
        "expected org-block coverage, got {block_451}"
    );
    assert!(flag >= 20, "expected org-flag coverage, got {flag}");
    assert!(
        reroute >= 10,
        "expected org-reroute coverage, got {reroute}"
    );
    assert!(redact >= 8, "expected org-redact coverage, got {redact}");
}

fn assert_expected(idx: usize, expected: ExpectedDecision, out: &soth_classify::ClassifiedResult) {
    match expected {
        ExpectedDecision::Allow => {
            assert!(
                matches!(out.policy_decision.kind, PolicyDecisionKind::Allow),
                "case {idx}: expected allow"
            );
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Allow)
            );
            assert!(
                !out.telemetry_event
                    .classification_flags
                    .contains(&ClassificationFlag::PolicyTriggered),
                "case {idx}: allow should not set PolicyTriggered"
            );
            assert!(
                out.policy_decision.matched_rule.is_none(),
                "case {idx}: allow should not have matched rule"
            );
        }
        ExpectedDecision::Block429 => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 429, "case {idx}: expected 429 block");
                    assert!(
                        message.to_ascii_lowercase().contains("limit"),
                        "case {idx}: expected budget message"
                    );
                }
                other => panic!("case {idx}: expected block 429, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Block)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "budget_session_requests_exceeded");
        }
        ExpectedDecision::Block403PrivateKey => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 403, "case {idx}: expected 403 block");
                    assert!(
                        message.to_ascii_lowercase().contains("private key"),
                        "case {idx}: expected private-key message"
                    );
                }
                other => panic!("case {idx}: expected private-key block 403, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Block)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "sys_private_key_detected");
        }
        ExpectedDecision::Block403InputTokens => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 403, "case {idx}: expected 403 block");
                    assert!(
                        message.to_ascii_lowercase().contains("token"),
                        "case {idx}: expected input-token message"
                    );
                }
                other => panic!("case {idx}: expected input-token block 403, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Block)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "sys_input_tokens_exceeded");
        }
        ExpectedDecision::Block451 => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Block { status, message } => {
                    assert_eq!(*status, 451, "case {idx}: expected 451 org block");
                    assert!(
                        message.to_ascii_lowercase().contains("unknown"),
                        "case {idx}: expected org block message"
                    );
                }
                other => panic!("case {idx}: expected block 451, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Block)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "org_block_unknown_agent_with_credential");
        }
        ExpectedDecision::FlagOpenAi => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Flag { reason } => assert_eq!(reason, "org-openai-observed"),
                other => panic!("case {idx}: expected flag, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Flag)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "org_flag_openai");
        }
        ExpectedDecision::RerouteHighCost => {
            match &out.policy_decision.kind {
                PolicyDecisionKind::Reroute { target } => {
                    assert_eq!(target.provider, "anthropic");
                    assert_eq!(target.model, "claude-3-haiku-20240307");
                }
                other => panic!("case {idx}: expected reroute, got {other:?}"),
            }
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Reroute)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "org_reroute_high_cost");
        }
        ExpectedDecision::RedactEmbedding => {
            match &out.policy_decision.kind {
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
            assert_eq!(
                out.telemetry_event.policy_kind,
                Some(TelemetryPolicyKind::Redact)
            );
            assert!(out
                .telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::PolicyTriggered));
            let matched = out
                .policy_decision
                .matched_rule
                .as_ref()
                .expect("matched rule");
            assert_eq!(matched.rule_id, "org_redact_embedding_calls");
        }
    }

    let has_credential = out
        .telemetry_event
        .sensitive_code_flags
        .credential_pattern_detected;
    if has_credential {
        assert!(
            out.telemetry_event
                .classification_flags
                .contains(&ClassificationFlag::CredentialDetected),
            "case {idx}: credential flags should include CredentialDetected"
        );
    }
}

fn expected_decision(detect: &DetectResult, proxy: &ProxyContext) -> ExpectedDecision {
    let has_private_key = detect
        .artifacts
        .iter()
        .any(|artifact| matches!(artifact.kind, ArtifactKind::PrivateKey));
    let has_credential = detect
        .artifacts
        .iter()
        .any(SensitiveArtifact::is_credential);
    let request_count = proxy
        .session_snapshot
        .as_ref()
        .map(|session| session.request_count)
        .unwrap_or_default();
    let cost = detect.normalized.estimated_cost_usd;

    if request_count > 100 {
        return ExpectedDecision::Block429;
    }
    if has_private_key {
        return ExpectedDecision::Block403PrivateKey;
    }
    if detect.normalized.estimated_input_tokens > 2_000_000 {
        return ExpectedDecision::Block403InputTokens;
    }
    if matches!(detect.confidence, ParseConfidence::Heuristic) {
        return ExpectedDecision::Allow;
    }
    if detect.normalized.provider == DetectedProvider::OpenAi {
        return ExpectedDecision::FlagOpenAi;
    }
    if cost > 0.25 {
        return ExpectedDecision::RerouteHighCost;
    }
    if proxy.traffic_classification == TrafficClassification::UnknownAgent && has_credential {
        return ExpectedDecision::Block451;
    }
    if detect.normalized.endpoint_type == EndpointType::Embedding {
        return ExpectedDecision::RedactEmbedding;
    }
    ExpectedDecision::Allow
}

fn apply_case_inputs(idx: usize, detect: &mut DetectResult, proxy: &mut ProxyContext) {
    detect.normalized.provider = match idx % 4 {
        0 => DetectedProvider::OpenAi,
        1 => DetectedProvider::Anthropic,
        2 => DetectedProvider::Gemini,
        _ => DetectedProvider::Cohere,
    };
    detect.normalized.endpoint_type = if idx % 9 == 0 {
        EndpointType::Embedding
    } else {
        EndpointType::ChatCompletion
    };
    detect.normalized.estimated_cost_usd = if idx % 6 == 0 { 0.31 } else { 0.03 };
    detect.normalized.estimated_input_tokens = if idx % 31 == 0 { 2_000_100 } else { 220 };

    detect.confidence = if idx % 7 == 0 {
        ParseConfidence::Heuristic
    } else {
        ParseConfidence::Full
    };

    proxy.traffic_classification = if idx % 11 == 0 {
        TrafficClassification::UnknownAgent
    } else {
        TrafficClassification::ToolUsage
    };
    proxy.capture_mode = if idx % 8 == 0 {
        CaptureMode::SensitiveArtifacts
    } else {
        CaptureMode::MetadataOnly
    };

    detect.artifacts = if idx % 17 == 0 {
        vec![SensitiveArtifact {
            kind: ArtifactKind::PrivateKey,
            severity: ArtifactSeverity::Critical,
            location: ArtifactLocation::SystemPrompt { char_offset: 0 },
        }]
    } else if idx % 5 == 0 {
        vec![SensitiveArtifact {
            kind: ArtifactKind::ApiKey {
                provider: Some(DetectedProvider::OpenAi),
            },
            severity: ArtifactSeverity::High,
            location: ArtifactLocation::UserContent {
                turn: 0,
                char_offset: 0,
            },
        }]
    } else {
        Vec::new()
    };

    // Bias credential cases toward the org block rule branch so we keep
    // meaningful coverage for unknown-agent credential controls.
    if !detect.artifacts.is_empty() && !matches!(detect.artifacts[0].kind, ArtifactKind::PrivateKey)
    {
        proxy.traffic_classification = TrafficClassification::UnknownAgent;
        detect.normalized.provider = DetectedProvider::Anthropic;
        detect.normalized.estimated_cost_usd = 0.03;
        detect.confidence = ParseConfidence::Full;
        detect.normalized.endpoint_type = EndpointType::ChatCompletion;
    }
}

fn session_for_case(idx: usize) -> SessionSnapshot {
    SessionSnapshot {
        request_count: if idx % 13 == 0 { 160 } else { 4 },
        total_tokens: 300,
        total_cost_usd: 0.12,
        credential_alerts: 0,
        embedding_centroid: None,
        prior_semantic_hashes: vec!["hash-a".to_string(), "hash-b".to_string()],
        last_model: Some("gpt-4o-mini".to_string()),
        current_request_timestamp: 1_700_000_000_000 + idx as i64,
        last_request_timestamp: Some(1_699_999_999_000 + idx as i64),
    }
}

fn load_policy_bundle() -> soth_policy::PolicyBundle {
    let payload = PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: "classify-large-corpus-policy-v1".to_string(),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_210_000,
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

    let key = SigningKey::from_bytes(&[54u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize policy payload");
    let signature = key.sign(payload_bytes.as_slice());
    let envelope = SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    let signed = serde_json::to_vec(&envelope).expect("serialize signed policy bundle");
    soth_policy::load_bundle_from_bytes(signed.as_slice()).expect("load signed policy bundle")
}
