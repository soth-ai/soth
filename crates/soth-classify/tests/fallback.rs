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
    assert!(matches!(
        out.policy_decision.kind,
        soth_core::PolicyDecisionKind::Allow
    ));
    assert!(out.stage_latencies.total_us >= out.stage_latencies.stage7_us);
    assert!(!out.semantic_hash.is_empty());
}
