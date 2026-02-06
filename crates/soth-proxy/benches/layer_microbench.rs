//! Layer microbenchmarks
//!
//! Isolates each layer to measure individual performance contributions.
//! Also provides a breakdown comparison showing overhead per layer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use soth_observe::PiiDetector;
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::middleware::RequestContext;
use soth_proxy::pipeline::observe::{ObserveConfig, ObserveLayer};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::PipelineBuilder;
use soth_proxy::protocol::{JsonRpcMessage, JsonRpcRequest, RequestId};
use std::time::Duration;

// -----------------------------------------------------------------------------
// Test Data
// -----------------------------------------------------------------------------

fn simple_tools_call(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "read_file",
            "arguments": {"path": "/etc/hosts"}
        })),
        RequestId::Number(id),
    ))
}

fn pii_tools_call(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "process_user",
            "arguments": {
                "email": "user@example.com",
                "ssn": "123-45-6789",
                "phone": "(212) 555-1234"
            }
        })),
        RequestId::Number(id),
    ))
}

// -----------------------------------------------------------------------------
// Individual Layer Benchmarks
// -----------------------------------------------------------------------------

fn bench_identity_layer_isolated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("layer_isolated/identity");

    // Disabled (fastest)
    let layer_disabled = IdentityLayer::new(IdentityConfig {
        mode: IdentityMode::Disabled,
        ..Default::default()
    });

    let pipeline_disabled = PipelineBuilder::new().layer(layer_disabled).build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Optional (typical case)
    let layer_optional = IdentityLayer::new(IdentityConfig {
        mode: IdentityMode::Optional,
        ..Default::default()
    });

    let pipeline_optional = PipelineBuilder::new().layer(layer_optional).build();

    group.bench_function("optional", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_optional.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_policy_layer_isolated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("layer_isolated/policy");

    // Disabled
    let pipeline_disabled = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Disabled,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Enforce (default allow)
    let pipeline_enforce = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("enforce", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_enforce.process(&mut ctx, msg).await);
        })
    });

    // Audit mode
    let pipeline_audit = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Audit,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("audit", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_audit.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_observe_layer_isolated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("layer_isolated/observe");

    // Minimal observation
    let pipeline_minimal = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: false,
            pii_detection: false,
            count_tokens: false,
            log_to_file: false,
        }))
        .build();

    group.bench_function("minimal", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_minimal.process(&mut ctx, msg).await);
        })
    });

    // With PII detection
    let pipeline_pii = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: false,
            log_to_file: false,
        }))
        .build();

    group.bench_function("with_pii_detection", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_pii.process(&mut ctx, msg).await);
        })
    });

    // Full observation with PII content
    group.bench_function("pii_content", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = pii_tools_call(1);
            let _ = black_box(pipeline_pii.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_budget_layer_isolated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("layer_isolated/budget");

    // Disabled
    let pipeline_disabled = PipelineBuilder::new()
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Enabled (tracking only)
    let pipeline_enabled = PipelineBuilder::new()
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("enabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(pipeline_enabled.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// PII Detection Microbenchmarks
// -----------------------------------------------------------------------------

fn bench_pii_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_patterns");
    let detector = PiiDetector::new();

    // Individual pattern tests
    let test_cases = [
        ("email_only", "Contact: user@example.com"),
        ("phone_only", "Phone: (212) 555-1234"),
        ("ssn_only", "SSN: 123-45-6789"),
        ("credit_card", "Card: 4111-1111-1111-1111 expires 12/25"),
        (
            "no_pii",
            "Hello world, this is a test message with no sensitive data",
        ),
        (
            "mixed_pii",
            "User john.doe@example.com called from (212) 555-1234",
        ),
    ];

    for (name, content) in test_cases {
        group.bench_with_input(BenchmarkId::new("detect", name), &content, |b, content| {
            b.iter(|| {
                let _ = black_box(detector.detect(content));
            })
        });

        group.bench_with_input(
            BenchmarkId::new("contains_pii", name),
            &content,
            |b, content| {
                b.iter(|| {
                    let _ = black_box(detector.contains_pii(content));
                })
            },
        );
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Layer Timing Breakdown
// -----------------------------------------------------------------------------

fn bench_layer_breakdown(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("layer_breakdown");
    group.measurement_time(Duration::from_secs(10));

    // Baseline: empty pipeline
    let baseline = PipelineBuilder::new().build();

    group.bench_function("0_baseline", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(baseline.process(&mut ctx, msg).await);
        })
    });

    // +Identity
    let with_identity = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .build();

    group.bench_function("1_+identity", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(with_identity.process(&mut ctx, msg).await);
        })
    });

    // +Identity +Policy
    let with_policy = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("2_+policy", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(with_policy.process(&mut ctx, msg).await);
        })
    });

    // +Identity +Policy +Observe
    let with_observe = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false,
        }))
        .build();

    group.bench_function("3_+observe", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(with_observe.process(&mut ctx, msg).await);
        })
    });

    // Full pipeline
    let full = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false,
        }))
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("4_+budget_full", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = black_box(full.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Timing Recording Overhead
// -----------------------------------------------------------------------------

fn bench_timing_overhead(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("timing_overhead");

    // Full pipeline that records timings
    let pipeline = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false,
        }))
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("process_with_timing", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let result = pipeline.process(&mut ctx, msg).await;
            // Access timings to ensure they're recorded
            let _ = black_box(ctx.timings.total_ns());
            black_box(result)
        })
    });

    // Verify timing breakdown is populated
    group.bench_function("timing_breakdown", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench");
            let msg = simple_tools_call(1);
            let _ = pipeline.process(&mut ctx, msg).await;
            black_box(ctx.timings.format_breakdown())
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Criterion Groups
// -----------------------------------------------------------------------------

criterion_group!(
    layer_isolated,
    bench_identity_layer_isolated,
    bench_policy_layer_isolated,
    bench_observe_layer_isolated,
    bench_budget_layer_isolated,
);

criterion_group!(pii_patterns, bench_pii_patterns,);

criterion_group!(breakdown, bench_layer_breakdown, bench_timing_overhead,);

criterion_main!(layer_isolated, pii_patterns, breakdown);
