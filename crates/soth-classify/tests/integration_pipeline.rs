#![allow(clippy::all)]
mod common;

fn private_key_artifact() -> soth_core::SensitiveArtifact {
    soth_core::SensitiveArtifact {
        kind: soth_core::ArtifactKind::PrivateKey,
        severity: soth_core::ArtifactSeverity::Critical,
        location: soth_core::ArtifactLocation::SystemPrompt { char_offset: 0 },
        commitment: None,
        redacted_hint: None,
    }
}

fn credential_artifact() -> soth_core::SensitiveArtifact {
    soth_core::SensitiveArtifact {
        kind: soth_core::ArtifactKind::ApiKey {
            provider: Some(soth_core::DetectedProvider::OpenAi),
        },
        severity: soth_core::ArtifactSeverity::High,
        location: soth_core::ArtifactLocation::UserContent {
            turn: 0,
            char_offset: 0,
        },
        commitment: None,
        redacted_hint: None,
    }
}

#[test]
fn classify_end_to_end_system_block_sets_policy_triggered() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();

    let mut detect = common::make_detect_result();
    detect.artifacts = vec![private_key_artifact()];

    let mut session = soth_core::SessionSnapshot::default();
    session.current_request_timestamp = 1_700_000_000_500;
    let proxy = common::make_proxy_ctx(Some(session));

    let out = soth_classify::classify(
        &detect,
        Some("handle a private key safely"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert!(matches!(
        out.policy_decision.kind,
        soth_core::PolicyDecisionKind::Block { status: 403, .. }
    ));
    assert!(out
        .telemetry_event
        .classification_flags
        .contains(&soth_core::ClassificationFlag::PolicyTriggered));
    assert!(out
        .telemetry_event
        .classification_flags
        .contains(&soth_core::ClassificationFlag::CredentialDetected));
    assert!(
        out.telemetry_event
            .sensitive_code_flags
            .private_key_detected
    );
    // timestamp_epoch_ms is now wall-clock time
    assert!(out.telemetry_event.timestamp_epoch_ms > 1_700_000_000_000);
}

#[test]
fn classify_end_to_end_high_anomaly_sets_high_anomaly_flag() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();

    let mut detect = common::make_detect_result();
    detect.normalized.estimated_input_tokens = 700;
    detect.normalized.user_content_token_estimate = 100;
    detect.normalized.conversation_turn = Some(7);
    detect.artifacts = vec![credential_artifact()];

    let mut session = soth_core::SessionSnapshot::default();
    session.session_token_p14d_avg = 100.0;
    session.total_tokens = 100;
    session.request_count = 10;
    session.request_count_this_hour = 30;
    session.credential_alerts = 2;
    session.credential_alerts_24h = 2;
    session.embedding_centroid = Some(vec![-1.0; 384]);
    session.last_model = Some("gpt-4o-mini".to_string());
    session.max_tool_depth_seen = 2;
    session.current_request_timestamp = 1_700_000_000_600;
    session.last_request_timestamp = Some(1_700_000_000_300);

    let proxy = common::make_proxy_ctx(Some(session));
    let out = soth_classify::classify(
        &detect,
        Some("today generate operational runbook and include summary"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert!(out.anomaly_score > 0.7);
    assert!(out
        .telemetry_event
        .classification_flags
        .contains(&soth_core::ClassificationFlag::HighAnomaly));
    assert!(!out
        .telemetry_event
        .classification_flags
        .contains(&soth_core::ClassificationFlag::PolicyTriggered));
}

#[test]
fn classify_nonce_changes_across_calls_while_semantic_hash_stays_stable() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);
    let content = Some("explain this code path with examples");

    let first = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);
    let second = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);

    assert_eq!(first.semantic_hash, second.semantic_hash);
    if first.commitment_nonce == second.commitment_nonce {
        let third = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);
        assert_ne!(third.commitment_nonce, first.commitment_nonce);
        assert_eq!(third.semantic_hash, first.semantic_hash);
    }
}
