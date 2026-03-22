mod common;

#[test]
fn same_input_produces_stable_semantic_outputs() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);
    let content = Some("Generate rust code for parsing json safely.");

    let first = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);
    assert!(!first.embedding_skipped);

    for _ in 0..200 {
        let next = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);
        assert_eq!(next.semantic_hash, first.semantic_hash);
        assert_eq!(next.topic_cluster_id, first.topic_cluster_id);
        assert!((next.embedding_norm - first.embedding_norm).abs() < 1e-6);
    }
}

#[test]
fn prior_semantic_hash_marks_collision() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let content = Some("Summarize this architecture into 3 bullets.");

    let base_proxy = common::make_proxy_ctx(None);
    let first = soth_classify::classify(&detect, content, &base_proxy, bundle.as_ref(), &config);

    let mut snapshot = soth_core::SessionSnapshot::default();
    snapshot.prior_semantic_hashes.push(first.semantic_hash);
    snapshot.current_request_timestamp = 1_700_000_000_000;
    let collision_proxy = common::make_proxy_ctx(Some(snapshot));

    let collided =
        soth_classify::classify(&detect, content, &collision_proxy, bundle.as_ref(), &config);

    assert!(collided.is_semantic_collision);
}

#[test]
fn heuristic_without_model_skips_embedding() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let mut detect = common::make_detect_result();
    detect.normalized.parse_confidence = soth_core::ParseConfidence::Heuristic;
    detect.confidence = soth_core::ParseConfidence::Heuristic;
    detect.normalized.model = None;

    let proxy = common::make_proxy_ctx(None);
    let out = soth_classify::classify(
        &detect,
        Some("user asked for latest build status"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert!(out.embedding_skipped);
    assert_eq!(out.topic_cluster_id, 0);
}
