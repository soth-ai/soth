mod common;

#[test]
fn complexity_score_boundary_minimum() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let mut detect = common::make_detect_result();
    detect.normalized.user_content_token_estimate = 0;
    detect.normalized.has_tool_definitions = false;
    detect.normalized.conversation_turn = None;
    let proxy = common::make_proxy_ctx(None);

    let out = soth_classify::classify(
        &detect,
        Some("short prompt"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert_eq!(out.complexity_score, 1);
}

#[test]
fn complexity_score_boundary_maximum() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let mut detect = common::make_detect_result();
    detect.normalized.user_content_token_estimate = 100_000;
    detect.normalized.has_tool_definitions = true;
    detect.normalized.conversation_turn = Some(20);
    let proxy = common::make_proxy_ctx(None);

    let out = soth_classify::classify(
        &detect,
        Some("long prompt with tools"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert_eq!(out.complexity_score, 5);
}

#[test]
fn volatility_class_thresholds_map_correctly() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let proxy = common::make_proxy_ctx(None);

    let mut detect_static = common::make_detect_result();
    detect_static.normalized.conversation_turn = Some(0);
    detect_static.normalized.has_tool_definitions = false;
    let out_static =
        soth_classify::classify(&detect_static, None, &proxy, bundle.as_ref(), &config);
    assert_eq!(
        out_static.volatility_class,
        soth_core::VolatilityClass::Static
    );

    let mut detect_low = common::make_detect_result();
    detect_low.normalized.conversation_turn = Some(1);
    detect_low.normalized.has_tool_definitions = false;
    let out_low = soth_classify::classify(
        &detect_low,
        Some("plain content"),
        &proxy,
        bundle.as_ref(),
        &config,
    );
    assert_eq!(
        out_low.volatility_class,
        soth_core::VolatilityClass::LowVolatile
    );

    let mut detect_dynamic = common::make_detect_result();
    detect_dynamic.normalized.conversation_turn = Some(2);
    detect_dynamic.normalized.has_tool_definitions = true;
    let out_dynamic = soth_classify::classify(
        &detect_dynamic,
        Some("plain content"),
        &proxy,
        bundle.as_ref(),
        &config,
    );
    assert_eq!(
        out_dynamic.volatility_class,
        soth_core::VolatilityClass::Dynamic
    );

    let mut detect_high = common::make_detect_result();
    detect_high.normalized.conversation_turn = Some(10);
    detect_high.normalized.has_tool_definitions = true;
    let out_high = soth_classify::classify(
        &detect_high,
        Some("today latest current recently this week right now as of my i me our we you"),
        &proxy,
        bundle.as_ref(),
        &config,
    );
    assert_eq!(
        out_high.volatility_class,
        soth_core::VolatilityClass::HighlyDynamic
    );
}

#[test]
fn volatility_uses_custom_thresholds_from_config() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let mut config = soth_classify::ClassifyConfig::default();
    config.volatility.static_threshold = 0.20;
    config.volatility.low_volatile_threshold = 0.50;
    config.volatility.dynamic_threshold = 0.90;

    let mut detect = common::make_detect_result();
    detect.normalized.conversation_turn = Some(2);
    detect.normalized.has_tool_definitions = true;
    let proxy = common::make_proxy_ctx(None);

    let out = soth_classify::classify(
        &detect,
        Some("plain content"),
        &proxy,
        bundle.as_ref(),
        &config,
    );

    assert_eq!(
        out.volatility_class,
        soth_core::VolatilityClass::LowVolatile
    );
}

#[test]
fn volatility_dynamic_fraction_is_deterministic() {
    let bundle = soth_classify::ClassifyBundle::fallback();
    let config = soth_classify::ClassifyConfig::default();
    let mut detect = common::make_detect_result();
    detect.normalized.conversation_turn = Some(4);
    detect.normalized.has_tool_definitions = true;
    let proxy = common::make_proxy_ctx(None);
    let content = Some("today now latest current with my workflow and our stack");

    let first = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);
    let second = soth_classify::classify(&detect, content, &proxy, bundle.as_ref(), &config);

    assert!((first.dynamic_fraction - second.dynamic_fraction).abs() < 1e-6);
    assert_eq!(first.volatility_class, second.volatility_class);
}
