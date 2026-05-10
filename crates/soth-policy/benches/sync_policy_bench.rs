use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use soth_core::{
    AppType, CaptureMode, DeploymentModel, EndpointType, FormatMetadata, NormalizedRequest,
    ParseConfidence, ParseSource, PolicyContext, ProcessMatchKind, ProcessResolution,
    SessionSnapshot, TrafficClassification,
};
use soth_policy::sync_policy::{
    evaluate, load_bundle_from_bytes, BudgetLimits, OrgPatterns, PolicyBundleMetadata,
    PolicyBundlePayload, RuleAction, RuleDefinition, SignedPolicyBundle,
};

fn signed_bundle_bytes(payload: PolicyBundlePayload) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let signature = key.sign(&payload_bytes);
    let envelope = SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    serde_json::to_vec(&envelope).expect("serialize signed envelope")
}

fn benchmark_bundle(rule_count: usize, matching_rule_index: usize) -> PolicyBundlePayload {
    let mut org_rules = Vec::with_capacity(rule_count);
    for idx in 0..rule_count {
        let expr = if idx == matching_rule_index {
            "request.provider == \"anthropic\"".to_string()
        } else {
            format!("request.provider == \"provider_{idx}\"")
        };
        org_rules.push(RuleDefinition {
            rule_id: format!("org_rule_{idx}"),
            rule_name: format!("OrgRule{idx}"),
            cel_expr: expr,
            action: RuleAction::Flag {
                reason: "bench".to_string(),
            },
        });
    }

    PolicyBundlePayload {
        metadata: PolicyBundleMetadata {
            bundle_version: "2026.02.25-bench".to_string(),
            schema_version: "1".to_string(),
            org_id: "bench-org".to_string(),
            signed_at: 1_772_000_000,
        },
        system_rules: vec![RuleDefinition {
            rule_id: "sys_private_key".to_string(),
            rule_name: "PrivateKey".to_string(),
            cel_expr: "detect.private_key_detected == true".to_string(),
            action: RuleAction::Block {
                status: 403,
                message: "blocked".to_string(),
            },
        }],
        org_rules,
        org_patterns: OrgPatterns::default(),
        budget_limits: BudgetLimits::default(),
    }
}

fn fixture_request() -> NormalizedRequest {
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "sync-policy-bench".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: "anthropic".to_string(),
        model: Some("claude-3-5-sonnet-20241022".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        api_version: None,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: "bench-user-hash".to_string(),
        user_content_token_estimate: 512,
        conversation_hash: "bench-conv-hash".to_string(),
        conversation_turn: Some(6),
        stream: false,
        has_tool_definitions: true,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: 2048,
        estimated_cost_usd: 0.21,
        parse_source: ParseSource::GraphQl,
        canonical_cache_key: String::new(),
        format_metadata: FormatMetadata::Unknown {
            method: String::new(),
            path: String::new(),
        },
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
        user_prompt: None,
    }
}

fn fixture_context() -> PolicyContext {
    PolicyContext {
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            bundle_id: Some("com.example.agent".to_string()),
            app_type: AppType::Host,
            capture_mode: None,
            process_name: Some("agentd".to_string()),
            matched_app_id: None,
            ..Default::default()
        },
        capture_mode: CaptureMode::MetadataOnly,
        traffic_classification: TrafficClassification::ToolUsage,
        deployment: DeploymentModel::Proxy,
        skip_org_rules: false,
        semantic: None,
        session: SessionSnapshot {
            total_tokens: 100_000,
            total_cost_usd: 3.15,
            request_count: 42,
            credential_alerts: 0,
            ..Default::default()
        },
        action: None,
    }
}

fn bench_sync_policy(c: &mut Criterion) {
    let request = fixture_request();
    let context = fixture_context();
    let artifacts = Vec::new();

    let mut group = c.benchmark_group("sync_policy_evaluate");
    for rule_count in [20usize, 100usize] {
        let payload = benchmark_bundle(rule_count, rule_count.saturating_sub(1));
        let bundle = load_bundle_from_bytes(&signed_bundle_bytes(payload)).expect("valid bundle");

        group.bench_with_input(
            BenchmarkId::new("rules", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| {
                    let decision = evaluate(
                        black_box(&request),
                        black_box(&artifacts),
                        black_box(&context),
                        black_box(&bundle),
                    );
                    black_box(decision);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_sync_policy);
criterion_main!(benches);
