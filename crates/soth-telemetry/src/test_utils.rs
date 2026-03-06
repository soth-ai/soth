#![cfg(test)]

use soth_core::{
    AnomalyFlag, AppType, CaptureMode, DataSource, EndpointType, ParseConfidence, ParseSource,
    ProcessMatchKind, ProcessResolution, RequestMethod, SensitiveCodeFlags, TelemetryEvent,
    TelemetryPolicyKind, TrafficClassification, UseCaseLabel, VolatilityClass,
};
use uuid::Uuid;

pub(crate) fn sample_event(event_id: Uuid) -> TelemetryEvent {
    TelemetryEvent {
        event_id,
        timestamp_epoch_ms: 1_700_000_000_000,
        connection_id: None,
        provider: soth_core::DetectedProvider::OpenAi,
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        parse_confidence: ParseConfidence::Full,
        parse_source: ParseSource::Rest {
            provider: soth_core::DetectedProvider::OpenAi,
        },
        capture_mode: CaptureMode::MetadataOnly,
        use_case: UseCaseLabel::Unknown,
        volatility_class: VolatilityClass::Static,
        cache_level: None,
        routing_reason: None,
        request_method: RequestMethod::Post,
        estimated_input_tokens: Some(100),
        estimated_output_tokens: None,
        estimated_cost_usd: Some(0.01),
        process_resolution: Some(ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: AppType::Unknown,
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: None,
            bundle_id: None,
        }),
        traffic_classification: Some(TrafficClassification::Other),
        languages: Vec::new(),
        import_categories: Vec::new(),
        classification_flags: Vec::new(),
        anomaly_flags: vec![AnomalyFlag::TopicDrift],
        anomaly_score: Some(0.2),
        policy_kind: Some(TelemetryPolicyKind::Allow),
        bundle_trust_level: Some(soth_core::BundleTrustLevel::Verified),
        sensitive_code_flags: SensitiveCodeFlags::default(),
        session_key_hash: String::new(),
        is_prefix_repeat: false,
        is_code_context_repeat: false,
        novel_token_count: 100,
        repeated_token_count: 0,
        first_step_event_id: None,
        original_event_id: None,
        prefix_hash: None,
        agent_step_number: None,
        is_historical: false,
        data_source: DataSource::LiveProxy,
        original_timestamp: None,
        topic_cluster_id: 0,
        semantic_hash: String::new(),
        is_semantic_collision: false,
        endpoint_hash: String::new(),
        policy_rule_id: None,
    }
}

pub(crate) fn sample_events(count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|_| sample_event(Uuid::new_v4()))
        .collect::<Vec<_>>()
}
