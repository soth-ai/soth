use criterion::{criterion_group, criterion_main, Criterion};

fn bench_classify_fallback(c: &mut Criterion) {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect_result = soth_detect::DetectResult::filtered();

    let proxy_ctx = soth_core::ProxyContext {
        org_id: "org".to_string(),
        user_id_hmac: "user".to_string(),
        team_id: "team".to_string(),
        device_id_hash: "device".to_string(),
        endpoint_hash: "endpoint".to_string(),
        process_resolution: soth_core::ProcessResolution {
            match_kind: soth_core::ProcessMatchKind::Unknown,
            app_type: soth_core::AppType::Unknown,
            capture_mode: None,
            process_name: None,
            bundle_id: None,
            matched_app_id: None,
            ..Default::default()
        },
        capture_mode: soth_core::CaptureMode::MetadataOnly,
        matched_provider: None,
        matched_application: None,
        traffic_classification: soth_core::TrafficClassification::Other,
        classification_source: soth_core::ClassificationSource::Proxy,
        session_snapshot: None,
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
        connection_id: None,
        bundle_trust_level: None,
        session_id: None,
        product_id: None,
        surface_type: soth_core::SurfaceType::Unknown,
        is_shadow_it: false,
    };

    c.bench_function("classify/fallback", |b| {
        b.iter(|| {
            let _ =
                soth_classify::classify(&detect_result, None, &proxy_ctx, bundle.as_ref(), &config);
        });
    });
}

criterion_group!(benches, bench_classify_fallback);
criterion_main!(benches);
