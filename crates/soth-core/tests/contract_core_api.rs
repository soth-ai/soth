use std::collections::BTreeMap;
use std::net::SocketAddrV4;

use bytes::Bytes;
use serde_json::Value;
use uuid::Uuid;

use soth_core::{
    AppType, CaptureMode, ClassificationSource, ConnectionMeta, EndpointType, EventSource,
    ExtensionContext, ExtensionSource, FrameKind, GovernableEvent, NormalizedRequest,
    ParseConfidence, ParseSource, PolicyContext, PolicyDecisionKind, ProcessMatchKind,
    ProcessResolution, ProxyContext, RequestMethod, Session, SessionAppIdentity, SessionKey,
    SessionMutations, SessionSnapshot, SocketFamily, SurfaceType, TelemetryEvent,
    TelemetryPolicyKind, TrafficClassification, UseCaseLabel, VolatilityClass,
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
        matched_app_id: None,
        ..Default::default()
    }
}

fn sample_normalized_request() -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "parser-core-test".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "openai".to_string(),
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
            is_batch: false,
        },
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        user_prompt: None,
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
    assert_eq!(snapshot.session_token_total, 0);
    assert_eq!(snapshot.session_token_p14d_avg, 0.0);
    assert_eq!(snapshot.request_count_this_hour, 0);
    assert_eq!(snapshot.credential_alerts_24h, 0);
    assert!(snapshot.topic_cluster_ids_seen.is_empty());
    assert!(snapshot.models_used_this_session.is_empty());
    assert!(snapshot.last_system_prompt_hash.is_none());
    assert_eq!(snapshot.max_tool_depth_seen, 0);
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
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
        connection_id: None,
        bundle_trust_level: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
        ja4_hash: None,
        tls_version: None,
        alpn_protocol: None,
        h2_connection_id: None,
        h2_stream_id: None,
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
        provider: "openai".to_string(),
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
        bundle_trust_level: Some(soth_core::BundleTrustLevel::Verified),
        sensitive_code_flags: soth_core::SensitiveCodeFlags::default(),
        session_key_hash: String::new(),
        is_prefix_repeat: false,
        is_code_context_repeat: false,
        novel_token_count: 0,
        repeated_token_count: 0,
        first_step_event_id: None,
        original_event_id: None,
        prefix_hash: None,
        agent_step_number: None,
        is_historical: false,
        data_source: soth_core::DataSource::LiveProxy,
        original_timestamp: None,
        topic_cluster_id: 0,
        semantic_hash: String::new(),
        is_semantic_collision: false,
        endpoint_hash: String::new(),
        policy_rule_id: None,
        use_case_confidence: 0.0,
        secondary_label: None,
        complexity_score: 0,
        embedding_norm: 0.0,
        system_prompt_hash: None,
        system_prompt_token_length: None,
        dynamic_fraction: 0.0,
        prefix_repeat_signature: None,
        tool_definition_hash: None,
        collision_response_stability: None,
        commitment_hash: String::new(),
        code_fraction: 0.0,
        actual_output_tokens: None,
        finish_reason: None,
        response_latency_ms: None,
        ttfb_ms: None,
        session_request_count: None,
        session_total_tokens: None,
        session_credential_alerts: None,
        conversation_turn: None,
        ws_turn_number: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
        ja4_hash: None,
        tls_version: None,
        alpn_protocol: None,
        h2_connection_id: None,
        h2_stream_id: None,
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

// ---------------------------------------------------------------------------
// Phase 1: Session types contract
// ---------------------------------------------------------------------------

#[test]
fn session_key_hash_and_equality_contract() {
    let key_a = SessionKey {
        app_identity: SessionAppIdentity::NativeApp {
            identity: "cursor".to_string(),
        },
        window_start: 1700000,
    };
    let key_b = key_a.clone();
    assert_eq!(key_a, key_b);

    let key_c = SessionKey {
        app_identity: SessionAppIdentity::BrowserSession {
            browser: "chrome".to_string(),
            ai_origin: "claude.ai".to_string(),
        },
        window_start: 1700000,
    };
    assert_ne!(key_a, key_c);

    // SessionKey must be usable as HashMap key (Hash + Eq).
    let mut map = std::collections::HashMap::new();
    map.insert(key_a.clone(), 1u32);
    assert_eq!(map.get(&key_a), Some(&1));
}

#[test]
fn session_mutations_is_plain_data_carrier() {
    // SessionMutations::default() must compile — no required fields.
    let mutations = SessionMutations::default();
    assert!(mutations.new_prefix_hash.is_none());
    assert!(mutations.new_code_hashes.is_empty());
    assert_eq!(mutations.token_delta, 0);
    assert_eq!(mutations.cost_delta, 0.0);
    assert!(mutations.anomaly_update.is_none());
    assert!(!mutations.credential_alert);
}

#[test]
fn session_snapshot_dedup_fields_default_empty() {
    let snapshot = SessionSnapshot::default();
    // New dedup fields must default to empty/zero.
    assert!(snapshot.seen_prefix_hashes.is_empty());
    assert!(snapshot.seen_code_hashes.is_empty());
    assert!(snapshot.session_key_hash.is_empty());
}

#[test]
fn session_snapshot_serde_backward_compat() {
    // An old serialized snapshot (without dedup fields) must deserialize
    // into the new struct without error.
    let old_json = serde_json::json!({
        "session_token_total": 100,
        "session_token_p14d_avg": 50.0,
        "request_count_this_hour": 5,
        "credential_alerts_24h": 0,
        "topic_cluster_ids_seen": [],
        "models_used_this_session": ["gpt-4o"],
        "last_system_prompt_hash": null,
        "max_tool_depth_seen": 2,
        "request_count": 10,
        "total_tokens": 5000,
        "total_cost_usd": 0.5,
        "credential_alerts": 0,
        "embedding_centroid": null,
        "prior_semantic_hashes": [],
        "last_model": "gpt-4o",
        "current_request_timestamp": 1700000000000_i64,
        "last_request_timestamp": null
    });
    let snapshot: SessionSnapshot =
        serde_json::from_value(old_json).expect("old format must deserialize");
    assert_eq!(snapshot.session_token_total, 100);
    // Dedup fields fall back to defaults.
    assert!(snapshot.seen_prefix_hashes.is_empty());
    assert!(snapshot.seen_code_hashes.is_empty());
    assert!(snapshot.session_key_hash.is_empty());
}

#[test]
fn session_snapshot_is_clone_no_arc() {
    let snapshot = SessionSnapshot {
        session_key_hash: "abc123".to_string(),
        seen_prefix_hashes: vec!["h1".to_string(), "h2".to_string()],
        seen_code_hashes: vec!["c1".to_string()],
        ..SessionSnapshot::default()
    };
    let cloned = snapshot.clone();
    assert_eq!(cloned.session_key_hash, "abc123");
    assert_eq!(cloned.seen_prefix_hashes.len(), 2);
}

#[test]
fn session_struct_constructs_with_defaults() {
    use std::collections::VecDeque;
    let session = Session {
        key: SessionKey {
            app_identity: SessionAppIdentity::NativeApp {
                identity: "vscode".to_string(),
            },
            window_start: 1700000,
        },
        code_hash_ring: VecDeque::new(),
        prefix_hash_ring: VecDeque::new(),
        stats: soth_core::SessionStats::default(),
        anomaly_baseline: soth_core::AnomalyBaseline::default(),
        created_at: 1700000000000,
        last_activity: 1700000000000,
    };
    assert_eq!(session.stats.request_count, 0);
    assert_eq!(session.anomaly_baseline.avg_tokens_per_request, 0.0);
}

// ---------------------------------------------------------------------------
// Phase 1: Extension types contract
// ---------------------------------------------------------------------------

#[test]
fn governable_event_embed_content_is_serde_skip() {
    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Http,
        provider: "anthropic".to_string(),
        model: Some("claude-sonnet-4-6".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        normalized: None,
        artifacts: vec![],
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: Some("secret local content".to_string()),
        context: ExtensionContext::default(),
    };

    let value = serde_json::to_value(&event).expect("serialize governable event");
    let obj = value.as_object().expect("must be object");
    // embed_content must NOT appear in serialized output.
    assert!(
        !obj.contains_key("embed_content"),
        "embed_content must be skipped during serialization"
    );

    // Deserializing without embed_content yields None.
    let deserialized: GovernableEvent =
        serde_json::from_value(value).expect("deserialize governable event");
    assert!(deserialized.embed_content.is_none());
}

#[test]
fn event_source_variants_serialize_correctly() {
    let http = serde_json::to_value(EventSource::Http).unwrap();
    assert_eq!(http["kind"], "http");

    let ext = serde_json::to_value(EventSource::Extension {
        source: ExtensionSource::Historian,
    })
    .unwrap();
    assert_eq!(ext["kind"], "extension");
    assert_eq!(ext["source"], "historian");

    let custom = serde_json::to_value(EventSource::Extension {
        source: ExtensionSource::Custom("my-ext".to_string()),
    })
    .unwrap();
    assert_eq!(custom["source"]["custom"], "my-ext");
}

#[test]
fn session_mutations_serde_roundtrip() {
    let mutations = SessionMutations {
        new_prefix_hash: Some("prefix-abc".to_string()),
        new_code_hashes: vec![soth_core::CodeBlob {
            ast_normalized_hash: "hash123".to_string(),
            language: "rust".to_string(),
            first_event_id: Uuid::new_v4(),
        }],
        token_delta: 150,
        cost_delta: 0.003,
        anomaly_update: Some(soth_core::AnomalyDelta {
            token_burst: true,
            topic_drift: false,
            model_switch: false,
        }),
        credential_alert: false,
    };
    let json = serde_json::to_string(&mutations).expect("serialize");
    let back: SessionMutations = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.new_prefix_hash, Some("prefix-abc".to_string()));
    assert_eq!(back.token_delta, 150);
    assert!(back.anomaly_update.unwrap().token_burst);
}

// ---------------------------------------------------------------------------
// Phase 4: TelemetryEvent session/dedup fields backward-compat
// ---------------------------------------------------------------------------

#[test]
fn telemetry_event_new_fields_deserialize_from_old_format() {
    // Old format without the new session/dedup fields
    let old_json = serde_json::json!({
        "event_id": "00000000-0000-0000-0000-000000000001",
        "timestamp_epoch_ms": 1700000000000_i64,
        "provider": "open_ai",
        "model": "gpt-4o",
        "endpoint_type": "chat_completion",
        "parse_confidence": "full",
        "parse_source": {"kind": "heuristic"},
        "capture_mode": "metadata_only",
        "use_case": "unknown",
        "volatility_class": "static",
        "request_method": "post",
        "languages": [],
        "import_categories": [],
        "classification_flags": [],
        "anomaly_flags": [],
        "sensitive_code_flags": {
            "credential_pattern_detected": false,
            "auth_logic_detected": false,
            "crypto_operations_detected": false,
            "network_calls_detected": false,
            "file_io_detected": false,
            "org_pattern_matches": [],
            "private_key_detected": false,
            "hardcoded_secret_detected": false
        }
    });

    let event: soth_core::TelemetryEvent = serde_json::from_value(old_json)
        .expect("old format should deserialize with new fields defaulting");

    assert_eq!(event.session_key_hash, "");
    assert!(!event.is_prefix_repeat);
    assert!(!event.is_code_context_repeat);
    assert_eq!(event.novel_token_count, 0);
    assert_eq!(event.repeated_token_count, 0);
    assert_eq!(event.data_source, soth_core::DataSource::LiveProxy);
    assert!(!event.is_historical);
}

#[test]
fn telemetry_event_new_fields_serde_roundtrip() {
    let event = soth_core::TelemetryEvent {
        session_key_hash: "abc123".to_string(),
        is_prefix_repeat: true,
        is_code_context_repeat: false,
        novel_token_count: 50,
        repeated_token_count: 150,
        first_step_event_id: Some("step-1".to_string()),
        original_event_id: None,
        prefix_hash: Some("pfx-hash".to_string()),
        agent_step_number: Some(3),
        is_historical: false,
        data_source: soth_core::DataSource::LiveProxy,
        original_timestamp: None,
        event_id: uuid::Uuid::nil(),
        timestamp_epoch_ms: 0,
        connection_id: None,
        provider: "unknown".to_string(),
        model: None,
        endpoint_type: EndpointType::Unknown,
        parse_confidence: ParseConfidence::Heuristic,
        parse_source: ParseSource::Heuristic,
        capture_mode: CaptureMode::MetadataOnly,
        use_case: UseCaseLabel::Unknown,
        volatility_class: VolatilityClass::Static,
        cache_level: None,
        routing_reason: None,
        request_method: RequestMethod::Post,
        estimated_input_tokens: None,
        estimated_output_tokens: None,
        estimated_cost_usd: None,
        process_resolution: None,
        traffic_classification: None,
        languages: Vec::new(),
        import_categories: Vec::new(),
        classification_flags: Vec::new(),
        anomaly_flags: Vec::new(),
        anomaly_score: None,
        policy_kind: None,
        bundle_trust_level: None,
        sensitive_code_flags: soth_core::SensitiveCodeFlags::default(),
        topic_cluster_id: 0,
        semantic_hash: String::new(),
        is_semantic_collision: false,
        endpoint_hash: String::new(),
        policy_rule_id: None,
        use_case_confidence: 0.0,
        secondary_label: None,
        complexity_score: 0,
        embedding_norm: 0.0,
        system_prompt_hash: None,
        system_prompt_token_length: None,
        dynamic_fraction: 0.0,
        prefix_repeat_signature: None,
        tool_definition_hash: None,
        collision_response_stability: None,
        commitment_hash: String::new(),
        code_fraction: 0.0,
        actual_output_tokens: None,
        finish_reason: None,
        response_latency_ms: None,
        ttfb_ms: None,
        session_request_count: None,
        session_total_tokens: None,
        session_credential_alerts: None,
        conversation_turn: None,
        ws_turn_number: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
        ja4_hash: None,
        tls_version: None,
        alpn_protocol: None,
        h2_connection_id: None,
        h2_stream_id: None,
    };

    let json = serde_json::to_string(&event).expect("serialize");
    let roundtrip: soth_core::TelemetryEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(roundtrip.session_key_hash, "abc123");
    assert!(roundtrip.is_prefix_repeat);
    assert_eq!(roundtrip.novel_token_count, 50);
    assert_eq!(roundtrip.repeated_token_count, 150);
    assert_eq!(roundtrip.first_step_event_id.as_deref(), Some("step-1"));
    assert_eq!(roundtrip.agent_step_number, Some(3));
}

// ---------------------------------------------------------------------------
// from_governable artifact-based enrichment
// ---------------------------------------------------------------------------

#[test]
fn from_governable_enriches_languages_and_classification_flags() {
    use soth_core::{
        ArtifactKind, ArtifactLocation, ArtifactSeverity, ClassificationFlag, ProgrammingLanguage,
        SensitiveArtifact,
    };

    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Extension {
            source: ExtensionSource::Historian,
        },
        provider: "openai".to_string(),
        model: Some("gpt-4o".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        normalized: Some(sample_normalized_request()),
        artifacts: vec![
            SensitiveArtifact {
                kind: ArtifactKind::CodeBlock {
                    language: "rust".to_string(),
                },
                severity: ArtifactSeverity::Low,
                location: ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 0,
                },
                commitment: None,
                redacted_hint: None,
            },
            SensitiveArtifact {
                kind: ArtifactKind::CodeBlock {
                    language: "python".to_string(),
                },
                severity: ArtifactSeverity::Low,
                location: ArtifactLocation::UserContent {
                    turn: 1,
                    char_offset: 0,
                },
                commitment: None,
                redacted_hint: None,
            },
            SensitiveArtifact {
                kind: ArtifactKind::ApiKey { provider: None },
                severity: ArtifactSeverity::High,
                location: ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 50,
                },
                commitment: None,
                redacted_hint: None,
            },
        ],
        capture_mode: CaptureMode::SensitiveArtifacts,
        embed_content: None,
        context: ExtensionContext {
            extension_name: "historian".to_string(),
            extension_version: "0.1.0".to_string(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("is_historical".to_string(), "true".to_string());
                m.insert(
                    "data_source".to_string(),
                    "historian_claude_code".to_string(),
                );
                m
            },
        },
    };

    let telemetry = TelemetryEvent::from_governable(&event, Some(TelemetryPolicyKind::Allow));

    // Languages extracted from code block artifacts
    assert!(telemetry.languages.contains(&ProgrammingLanguage::Rust));
    assert!(telemetry.languages.contains(&ProgrammingLanguage::Python));
    assert_eq!(telemetry.languages.len(), 2);

    // Classification flags from artifacts
    assert!(telemetry
        .classification_flags
        .contains(&ClassificationFlag::CodeDetected));
    assert!(telemetry
        .classification_flags
        .contains(&ClassificationFlag::CredentialDetected));

    // Sensitive code flags from artifacts
    assert!(telemetry.sensitive_code_flags.credential_pattern_detected);
    assert!(telemetry.sensitive_code_flags.hardcoded_secret_detected);

    // Code fraction is non-zero (2 code blocks / 42 tokens)
    assert!(telemetry.code_fraction > 0.0);

    // Historical metadata still mapped
    assert!(telemetry.is_historical);

    // Token estimates from normalized
    assert_eq!(telemetry.estimated_input_tokens, Some(42));
    assert_eq!(telemetry.estimated_cost_usd, Some(0.01));
    assert_eq!(
        telemetry.tool_definition_hash,
        Some("tool-hash".to_string())
    );
}

#[test]
fn from_governable_with_private_key_sets_sensitive_flags() {
    use soth_core::{ArtifactKind, ArtifactLocation, ArtifactSeverity, SensitiveArtifact};

    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Http,
        provider: "anthropic".to_string(),
        model: Some("claude-sonnet-4-6".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        normalized: None,
        artifacts: vec![SensitiveArtifact {
            kind: ArtifactKind::PrivateKey,
            severity: ArtifactSeverity::Critical,
            location: ArtifactLocation::SystemPrompt { char_offset: 0 },
            commitment: None,
            redacted_hint: None,
        }],
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: None,
        context: ExtensionContext::default(),
    };

    let telemetry = TelemetryEvent::from_governable(&event, Some(TelemetryPolicyKind::Block));

    assert!(telemetry.sensitive_code_flags.private_key_detected);
    assert!(telemetry.sensitive_code_flags.hardcoded_secret_detected);
    assert!(telemetry.sensitive_code_flags.credential_pattern_detected);

    // Block policy sets PolicyTriggered flag
    assert!(telemetry
        .classification_flags
        .contains(&soth_core::ClassificationFlag::PolicyTriggered));
    // Also CredentialDetected from the private key
    assert!(telemetry
        .classification_flags
        .contains(&soth_core::ClassificationFlag::CredentialDetected));
}

#[test]
fn from_governable_without_artifacts_has_empty_enrichment() {
    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Http,
        provider: "unknown".to_string(),
        model: None,
        endpoint_type: EndpointType::Unknown,
        normalized: None,
        artifacts: vec![],
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: None,
        context: ExtensionContext::default(),
    };

    let telemetry = TelemetryEvent::from_governable(&event, Some(TelemetryPolicyKind::Allow));

    assert!(telemetry.languages.is_empty());
    assert!(telemetry.classification_flags.is_empty());
    assert!(!telemetry.sensitive_code_flags.credential_pattern_detected);
    assert_eq!(telemetry.code_fraction, 0.0);
}

#[test]
fn from_governable_reads_classify_metadata() {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert(
        "classify.use_case".to_string(),
        "\"code_generation\"".to_string(),
    );
    metadata.insert(
        "classify.use_case_confidence".to_string(),
        "0.85".to_string(),
    );
    metadata.insert(
        "classify.volatility_class".to_string(),
        "\"dynamic\"".to_string(),
    );
    metadata.insert("classify.dynamic_fraction".to_string(), "0.42".to_string());
    metadata.insert("classify.anomaly_score".to_string(), "0.15".to_string());
    metadata.insert("classify.complexity_score".to_string(), "3".to_string());
    metadata.insert("classify.topic_cluster_id".to_string(), "17".to_string());

    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Http,
        provider: "openai".to_string(),
        model: Some("gpt-4o".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        normalized: None,
        artifacts: vec![],
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: None,
        context: ExtensionContext {
            extension_name: "historian".to_string(),
            extension_version: "0.1.0".to_string(),
            metadata,
        },
    };

    let telemetry = TelemetryEvent::from_governable(&event, None);

    assert_eq!(telemetry.use_case, UseCaseLabel::CodeGeneration);
    assert!((telemetry.use_case_confidence - 0.85).abs() < 0.001);
    assert_eq!(telemetry.volatility_class, VolatilityClass::Dynamic);
    assert!((telemetry.dynamic_fraction - 0.42).abs() < 0.001);
    assert_eq!(telemetry.anomaly_score, Some(0.15));
    assert_eq!(telemetry.complexity_score, 3);
    assert_eq!(telemetry.topic_cluster_id, 17);
}

#[test]
fn from_governable_without_classify_metadata_uses_defaults() {
    let event = GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1_700_000_000_000,
        source: EventSource::Http,
        provider: "unknown".to_string(),
        model: None,
        endpoint_type: EndpointType::Unknown,
        normalized: None,
        artifacts: vec![],
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: None,
        context: ExtensionContext::default(),
    };

    let telemetry = TelemetryEvent::from_governable(&event, None);

    assert_eq!(telemetry.use_case, UseCaseLabel::Unknown);
    assert_eq!(telemetry.use_case_confidence, 0.0);
    assert_eq!(telemetry.volatility_class, VolatilityClass::Static);
    assert_eq!(telemetry.dynamic_fraction, 0.0);
    assert_eq!(telemetry.anomaly_score, None);
    assert_eq!(telemetry.complexity_score, 0);
    assert_eq!(telemetry.topic_cluster_id, 0);
}
