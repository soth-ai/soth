use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use soth_policy::sync_policy::{
    evaluate, load_bundle_from_bytes, AppType, BudgetLimits, CaptureMode, DeploymentModel,
    NormalizedRequest, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, PolicyContext,
    ProcessResolution, RuleAction, RuleDefinition, SessionBudget, SignedPolicyBundle,
    TrafficClassification,
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
        provider: "anthropic".to_string(),
        model: Some("claude-3-5-sonnet-20241022".to_string()),
        endpoint_type: "chat".to_string(),
        is_ai_call: true,
        stream: false,
        has_tool_definitions: true,
        estimated_input_tokens: 2048,
        estimated_cost_usd: 0.21,
        conversation_turn: Some(6),
        parse_confidence: "full".to_string(),
        parse_source: "graphql".to_string(),
    }
}

fn fixture_context() -> PolicyContext {
    PolicyContext {
        process_resolution: ProcessResolution {
            bundle_id: Some("com.example.agent".to_string()),
            app_type: AppType::Host,
            process_name: Some("agentd".to_string()),
        },
        capture_mode: CaptureMode::MetadataOnly,
        traffic_classification: TrafficClassification::ToolUsage,
        deployment: DeploymentModel::Proxy,
        session: Some(SessionBudget {
            session_id: "bench-session".to_string(),
            total_tokens_this_session: 100_000,
            total_cost_usd_this_session: 3.14,
            request_count_this_session: 42,
            credential_alerts_this_session: 0,
        }),
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
