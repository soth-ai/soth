use soth_core::{
    AppType, CaptureMode, ClassificationSource, DetectResult, DetectedProvider, EndpointType,
    FormatMetadata, NormalizedRequest, ParseConfidence, ParseSource, ProcessMatchKind,
    ProcessResolution, ProxyContext, SessionSnapshot, TrafficClassification,
};

fn main() {
    let bundle_dir = std::env::var("SOTH_CLASSIFY_BUNDLE_DIR").unwrap_or_else(|_| {
        format!(
            "{}/.soth-local/bundle",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )
    });
    let bundle_path = std::path::Path::new(bundle_dir.as_str());
    let bundle = soth_classify::load_bundle(bundle_path).expect("load sample bundle");
    let model_status = bundle.model_asset_status();

    let detect = DetectResult {
        normalized: NormalizedRequest {
            parse_confidence: ParseConfidence::Full,
            parser_id: "sample-parser".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: DetectedProvider::OpenAi,
            model: Some("gpt-4o-mini".to_string()),
            endpoint_type: EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: None,
            system_prompt_token_estimate: None,
            user_content_hash: "u-hash".to_string(),
            user_content_token_estimate: 120,
            conversation_hash: "c-hash".to_string(),
            conversation_turn: Some(2),
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: Some(256),
            stream: false,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 120,
            estimated_cost_usd: 0.01,
            parse_source: ParseSource::Rest {
                provider: DetectedProvider::OpenAi,
            },
            canonical_cache_key: "cache-key".to_string(),
            format_metadata: FormatMetadata::Unknown,
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
        },
        artifacts: Vec::new(),
        capture_mode: CaptureMode::MetadataOnly,
        parse_source: ParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        confidence: ParseConfidence::Full,
        detect_latency_us: 0,
        warnings: Vec::new(),
        session_mutations: soth_core::SessionMutations::default(),
        is_prefix_repeat: false,
        novel_token_count: 0,
        repeated_token_count: 0,
        novel_tail_start_idx: None,
        prefix_hash: None,
        is_repeated_code_context: false,
        ast_normalized_hash: None,
        first_blob_event_id: None,
        import_categories: Vec::new(),
    };

    let mut session = SessionSnapshot::default();
    session.current_request_timestamp = 1_777_000_000_000;

    let proxy = ProxyContext {
        org_id: "org".to_string(),
        user_id_hmac: "user".to_string(),
        team_id: "team".to_string(),
        device_id_hash: "device".to_string(),
        endpoint_hash: "endpoint".to_string(),
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::NonHost,
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: Some("cursor".to_string()),
            bundle_id: Some("com.todesktop.230313mzl4w4u92".to_string()),
        },
        capture_mode: CaptureMode::MetadataOnly,
        matched_provider: Some("openai".to_string()),
        matched_application: None,
        traffic_classification: TrafficClassification::ToolUsage,
        classification_source: ClassificationSource::Proxy,
        session_snapshot: Some(session),
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
    };

    let out = soth_classify::classify(
        &detect,
        Some("Build a rust parser for websocket events"),
        &proxy,
        bundle.as_ref(),
        &soth_classify::ClassifyConfig::default(),
    );

    println!(
        "bundle_version={} has_real_models={} onnx_runtime={}",
        bundle.bundle_version, bundle.has_real_models, model_status.has_onnx_runtime
    );
    println!(
        "use_case={:?} cluster={} semantic_hash={} anomaly_score={:.3}",
        out.use_case_label, out.topic_cluster_id, out.semantic_hash, out.anomaly_score
    );
    println!("policy={:?}", out.policy_decision.kind);
    println!("timing_us_total={}", out.stage_latencies.total_us);
}
