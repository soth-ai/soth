use std::collections::BTreeMap;
use std::net::SocketAddrV4;

use bytes::Bytes;
use serde_json::Value;
use uuid::Uuid;

use soth_core::{
    AppType, CaptureMode, ClassificationSource, ConnectionMeta, EndpointType, FrameKind,
    NormalizedRequest, ParseConfidence, ParseSource, PolicyContext, PolicyDecisionKind,
    ProcessMatchKind, ProcessResolution, ProxyContext, RequestMethod, SessionSnapshot,
    SocketFamily, TelemetryEvent, TelemetryPolicyKind, TrafficClassification, UseCaseLabel,
    VolatilityClass,
};

fn sample_connection_meta() -> ConnectionMeta {
    ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 10_000),
            remote: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 443),
        },
        None,
        None,
    )
}

fn sample_process_resolution() -> ProcessResolution {
    ProcessResolution {
        match_kind: ProcessMatchKind::Exact,
        app_type: AppType::NonHost,
        capture_mode: Some(CaptureMode::SensitiveArtifacts),
        process_name: Some("cursor".to_string()),
        bundle_id: Some("com.cursor.app".to_string()),
    }
}

fn sample_normalized_request() -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "parser-core-test".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: soth_core::DetectedProvider::OpenAi,
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        api_version: Some("v1".to_string()),
        system_prompt_hash: Some("sys-hash".to_string()),
        system_prompt_token_estimate: Some(10),
        user_content_hash: "user-hash".to_string(),
        user_content_token_estimate: 42,
        conversation_hash: "conv-hash".to_string(),
        conversation_turn: Some(2),
        has_tool_definitions: true,
        tool_definition_hash: Some("tool-hash".to_string()),
        temperature: Some(0.2),
        max_tokens: Some(512),
        stream: false,
        top_p: Some(0.9),
        stop_sequences: vec!["DONE".to_string()],
        estimated_input_tokens: 42,
        estimated_cost_usd: 0.01,
        parse_source: ParseSource::JsonRpc,
        canonical_cache_key: "cache-key".to_string(),
        format_metadata: soth_core::FormatMetadata::JsonRpc {
            method: "tools/call".to_string(),
        },
    }
}

#[test]
fn connection_meta_transport_and_enrichment_contract() {
    let meta = sample_connection_meta();
    assert!(meta.app_identity.is_none());
    assert!(meta.capture_mode.is_none());
    assert!(meta.matched_provider.is_none());
    assert!(meta.matched_application.is_none());
    assert!(!meta.is_proxy_enriched());

    let mut enriched = meta.clone();
    enriched.capture_mode = Some(CaptureMode::MetadataOnly);
    enriched.matched_provider = Some("openai".to_string());
    assert!(enriched.is_proxy_enriched());
}

#[test]
fn session_snapshot_defaults_include_required_fields() {
    let snapshot = SessionSnapshot::default();
    assert_eq!(snapshot.request_count, 0);
    assert_eq!(snapshot.total_tokens, 0);
    assert_eq!(snapshot.total_cost_usd, 0.0);
    assert_eq!(snapshot.credential_alerts, 0);
    assert!(snapshot.prior_semantic_hashes.is_empty());
    assert!(snapshot.last_model.is_none());
    assert_eq!(snapshot.current_request_timestamp, 0);
    assert!(snapshot.last_request_timestamp.is_none());
    assert!(snapshot.embedding_centroid.is_none());
}

#[test]
fn proxy_context_and_policy_context_semantic_extension_contract() {
    let proxy_ctx = ProxyContext {
        org_id: "org-test".to_string(),
        user_id_hmac: "user-hmac".to_string(),
        team_id: "team-test".to_string(),
        device_id_hash: "device-hash".to_string(),
        endpoint_hash: "endpoint-hash".to_string(),
        process_resolution: sample_process_resolution(),
        capture_mode: CaptureMode::SensitiveArtifacts,
        matched_provider: Some("openai".to_string()),
        matched_application: Some("cursor".to_string()),
        traffic_classification: TrafficClassification::ApplicationUsage,
        classification_source: ClassificationSource::Proxy,
        session_snapshot: Some(SessionSnapshot::default()),
    };
    assert_eq!(proxy_ctx.org_id, "org-test");
    assert_eq!(proxy_ctx.capture_mode, CaptureMode::SensitiveArtifacts);

    let policy_ctx = PolicyContext {
        process_resolution: sample_process_resolution(),
        capture_mode: CaptureMode::MetadataOnly,
        traffic_classification: TrafficClassification::ToolUsage,
        deployment: soth_core::DeploymentModel::Proxy,
        skip_org_rules: true,
        semantic: Some(soth_core::SemanticPolicyContext {
            use_case_label: UseCaseLabel::CodeGeneration,
            use_case_confidence: 0.82,
            anomaly_score: 0.11,
            anomaly_flags: vec![soth_core::AnomalyFlag::TopicDrift],
            complexity_score: 4,
            volatility_class: VolatilityClass::LowVolatile,
            topic_cluster_id: 9,
        }),
        session: SessionSnapshot::default(),
    };

    let encoded = serde_json::to_value(policy_ctx).expect("serialize policy context");
    assert_eq!(encoded.get("skip_org_rules"), Some(&Value::Bool(true)));
    assert!(encoded.get("semantic").is_some());
}

#[test]
fn telemetry_event_surface_excludes_raw_content_fields() {
    let event = TelemetryEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        connection_id: Some(Uuid::new_v4()),
        provider: soth_core::DetectedProvider::OpenAi,
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        parse_confidence: ParseConfidence::Full,
        parse_source: ParseSource::JsonRpc,
        capture_mode: CaptureMode::MetadataOnly,
        use_case: UseCaseLabel::CodeGeneration,
        volatility_class: VolatilityClass::Static,
        cache_level: Some(soth_core::CacheLevel::Exact),
        routing_reason: None,
        request_method: RequestMethod::Post,
        estimated_input_tokens: Some(10),
        estimated_output_tokens: Some(20),
        estimated_cost_usd: Some(0.01),
        process_resolution: Some(sample_process_resolution()),
        traffic_classification: Some(TrafficClassification::ToolUsage),
        languages: vec![soth_core::ProgrammingLanguage::Rust],
        import_categories: vec![soth_core::ImportCategory::Serialization],
        classification_flags: vec![soth_core::ClassificationFlag::CodeDetected],
        anomaly_flags: Vec::new(),
        anomaly_score: Some(0.1),
        policy_kind: Some(TelemetryPolicyKind::Allow),
        sensitive_code_flags: soth_core::SensitiveCodeFlags::default(),
    };

    let value = serde_json::to_value(event).expect("serialize telemetry event");
    let object = value
        .as_object()
        .expect("telemetry event must serialize to object");

    for forbidden in ["prompt", "content", "message", "response", "body", "text"] {
        assert!(
            !object.contains_key(forbidden),
            "telemetry event must not expose `{forbidden}`"
        );
    }
}

#[test]
fn jsonrpc_and_framekind_serialization_contract() {
    let source = ParseSource::JsonRpc;
    let source_json = serde_json::to_value(source).expect("serialize parse source");
    assert_eq!(
        source_json.get("kind"),
        Some(&Value::String("json_rpc".to_string()))
    );

    let normalized = sample_normalized_request();
    let normalized_json = serde_json::to_value(normalized).expect("serialize normalized request");
    assert_eq!(
        normalized_json.pointer("/format_metadata/kind"),
        Some(&Value::String("json_rpc".to_string()))
    );

    let frame_json = serde_json::to_value(FrameKind::SseData).expect("serialize frame kind");
    assert_eq!(frame_json, Value::String("sse_data".to_string()));
}

#[test]
fn request_and_policy_helpers_contract() {
    let req = soth_core::RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: BTreeMap::from([("host".to_string(), "api.openai.com".to_string())]),
        body: Bytes::from_static(br#"{"model":"gpt-4o-mini"}"#),
        connection_meta: sample_connection_meta(),
    };
    assert_eq!(req.method, "POST");

    assert!(PolicyDecisionKind::Allow.is_allow());
    assert!(!PolicyDecisionKind::Allow.is_block());
    assert!(PolicyDecisionKind::Block {
        status: 403,
        message: "blocked".to_string()
    }
    .is_block());
}
