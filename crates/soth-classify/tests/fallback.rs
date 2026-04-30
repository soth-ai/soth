mod common;

#[test]
fn fallback_bundle_returns_valid_classification_output() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);

    let out = soth_classify::classify(
        &detect,
        Some("Refactor this function to remove duplicated logic."),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert_eq!(out.use_case_label, soth_core::UseCaseLabel::Unknown);
    assert_eq!(out.use_case_confidence, 0.0);
    assert_eq!(
        out.use_case_label_reason,
        soth_core::UseCaseLabelReason::FallbackBundle,
        "fallback bundle should mark use_case_label_reason=FallbackBundle so the \
         dashboard can distinguish 'no real model' from a legitimate Unknown"
    );
    assert_eq!(
        out.telemetry_event.use_case_label_reason,
        soth_core::UseCaseLabelReason::FallbackBundle,
        "TelemetryEvent must carry the same reason as ClassifiedResult"
    );
    assert!(matches!(
        out.policy_decision.kind,
        soth_core::PolicyDecisionKind::Allow
    ));
    assert!(out.stage_latencies.total_us >= out.stage_latencies.stage7_us);
    assert!(!out.semantic_hash.is_empty());
}

/// Embedding-disabled config should yield UseCaseLabel::Unknown with
/// `EmbeddingDisabled` reason — distinct from a fallback-bundle Unknown.
#[test]
fn embedding_disabled_emits_embedding_disabled_reason() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let mut config = soth_classify::ClassifyConfig::default();
    config.embedding_enabled = false;
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);

    let out = soth_classify::classify(
        &detect,
        Some("Hello world"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert_eq!(out.use_case_label, soth_core::UseCaseLabel::Unknown);
    assert_eq!(
        out.use_case_label_reason,
        soth_core::UseCaseLabelReason::EmbeddingDisabled
    );
    assert_eq!(
        out.telemetry_event.use_case_label_reason,
        soth_core::UseCaseLabelReason::EmbeddingDisabled
    );
}
