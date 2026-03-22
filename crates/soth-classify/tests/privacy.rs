mod common;

#[test]
fn telemetry_event_has_no_raw_content_fields() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);

    let result = soth_classify::classify(
        &detect,
        Some("Build a SQL query to count failed runs in the last 24 hours."),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    let event_value = match serde_json::to_value(&result.telemetry_event) {
        Ok(value) => value,
        Err(error) => panic!("failed to serialize telemetry event: {error}"),
    };

    let banned = [
        "prompt", "content", "message", "response", "body", "text", "query",
    ];

    match event_value {
        serde_json::Value::Object(map) => {
            for key in banned {
                assert!(!map.contains_key(key), "found banned field key: {key}");
            }
        }
        _ => panic!("telemetry event should serialize as an object"),
    }
}

#[test]
fn classified_result_exposes_scalar_norm_and_nonce_only() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let detect = common::make_detect_result();
    let proxy = common::make_proxy_ctx(None);

    let result = soth_classify::classify(
        &detect,
        Some("Write a safe rust parser for ini files."),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    let norm: f32 = result.embedding_norm;
    let nonce: [u8; 32] = result.commitment_nonce;
    assert!(norm >= 0.0);
    assert!(nonce.len() == 32);
}
