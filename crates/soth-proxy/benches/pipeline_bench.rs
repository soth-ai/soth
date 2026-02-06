//! Performance benchmarks for the SOTH proxy pipeline
//!
//! Benchmarks cover:
//! - Pipeline processing with no layers (baseline)
//! - Pipeline with individual layers (identity, policy, observe, budget)
//! - Policy evaluation with cache hit vs miss scenarios
//! - PII detection on various content sizes
//! - Full pipeline with all layers enabled

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use soth_observe::PiiDetector;
use soth_policy::{PolicyEngine, PolicyEngineConfig};
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::middleware::RequestContext;
use soth_proxy::pipeline::observe::{ObserveConfig, ObserveLayer};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::PipelineBuilder;
use soth_proxy::protocol::{JsonRpcMessage, JsonRpcRequest, RequestId};
use std::time::Duration;

// -----------------------------------------------------------------------------
// Test Data Generators
// -----------------------------------------------------------------------------

/// Create a simple JSON-RPC request for tools/call
fn create_tools_call_request(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "read_file",
            "arguments": {
                "path": "/etc/hosts"
            }
        })),
        RequestId::Number(id),
    ))
}

/// Create a request with large parameters
fn create_large_request(id: i64, size: usize) -> JsonRpcMessage {
    let data = "x".repeat(size);
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "process_data",
            "arguments": {
                "data": data,
                "options": {
                    "format": "json",
                    "compress": true
                }
            }
        })),
        RequestId::Number(id),
    ))
}

/// Create a request containing PII data
fn create_pii_request(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "process_user",
            "arguments": {
                "user": {
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                    "ssn": "123-45-6789",
                    "phone": "(212) 555-1234",
                    "card": "4111-1111-1111-1111"
                }
            }
        })),
        RequestId::Number(id),
    ))
}

/// Generate text content of specified size with embedded PII
fn generate_pii_content(size: usize) -> String {
    let pii_samples = [
        "Contact: john.doe@example.com",
        "SSN: 123-45-6789",
        "Phone: (212) 555-1234",
        "Card: 4111-1111-1111-1111",
    ];

    let mut content = String::with_capacity(size);
    let mut i = 0;

    while content.len() < size {
        if i % 100 == 0 && content.len() + 50 < size {
            // Insert PII sample every ~100 characters
            content.push_str(pii_samples[i % pii_samples.len()]);
            content.push(' ');
        } else {
            content.push_str("Lorem ipsum dolor sit amet. ");
        }
        i += 1;
    }

    content.truncate(size);
    content
}

/// Generate clean text content without PII
fn generate_clean_content(size: usize) -> String {
    let words = [
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "consectetur",
        "adipiscing",
        "elit",
        "sed",
        "do",
        "eiusmod",
        "tempor",
        "incididunt",
        "labore",
        "dolore",
        "magna",
        "aliqua",
    ];

    let mut content = String::with_capacity(size);
    let mut i = 0;

    while content.len() < size {
        content.push_str(words[i % words.len()]);
        content.push(' ');
        i += 1;
    }

    content.truncate(size);
    content
}

// -----------------------------------------------------------------------------
// Benchmark: Empty Pipeline (Baseline)
// -----------------------------------------------------------------------------

fn bench_empty_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let pipeline = PipelineBuilder::new().build();

    c.bench_function("pipeline/empty", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline.process(&mut ctx, msg).await);
        })
    });
}

// -----------------------------------------------------------------------------
// Benchmark: Individual Layers
// -----------------------------------------------------------------------------

fn bench_identity_layer(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/identity");

    // Disabled mode (fastest path)
    let pipeline_disabled = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Disabled,
            ..Default::default()
        }))
        .build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Optional mode (no identity provided)
    let pipeline_optional = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .build();

    group.bench_function("optional_no_identity", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_optional.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_policy_layer(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/policy");

    // Disabled mode
    let pipeline_disabled = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Disabled,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Enforce mode with default engine (allow all)
    let pipeline_enforce = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("enforce_allow", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
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
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_audit.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_observe_layer(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/observe");

    // Minimal observation (no PII, no tokens)
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
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_minimal.process(&mut ctx, msg).await);
        })
    });

    // Full observation (PII + tokens)
    let pipeline_full = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false,
        }))
        .build();

    group.bench_function("full", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_full.process(&mut ctx, msg).await);
        })
    });

    // Observation with PII content
    group.bench_function("with_pii_content", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_pii_request(1);
            let _ = black_box(pipeline_full.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

fn bench_budget_layer(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/budget");

    // Disabled
    let pipeline_disabled = PipelineBuilder::new()
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("disabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_disabled.process(&mut ctx, msg).await);
        })
    });

    // Enabled with tracking
    let pipeline_enabled = PipelineBuilder::new()
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false,
            ..Default::default()
        }))
        .build();

    group.bench_function("enabled", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline_enabled.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark: Policy Engine Cache Performance
// -----------------------------------------------------------------------------

fn bench_policy_engine_cache(c: &mut Criterion) {
    use soth_core::types::identity::{AgentContext, IdentityContext};
    use soth_core::types::policy::{
        EnvironmentContext, PolicyInput, RequestContext as PolicyRequestContext, SessionContext,
    };

    let mut group = c.benchmark_group("policy/cache");

    let engine = PolicyEngine::with_config(PolicyEngineConfig::default());

    // Prepare test input
    let input = PolicyInput {
        agent: AgentContext {
            id: "test-agent".to_string(),
            capabilities: vec!["read".to_string()],
            ..Default::default()
        },
        request: PolicyRequestContext {
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            ..Default::default()
        },
        session: SessionContext::default(),
        identity: IdentityContext::default(),
        context: EnvironmentContext::default(),
    };

    // Cold evaluation (cache miss)
    group.bench_function("cold_evaluation", |b| {
        b.iter(|| {
            // Invalidate cache before each iteration for true cold eval
            let engine = PolicyEngine::with_config(PolicyEngineConfig::default());
            let _ = black_box(engine.evaluate(&input));
        })
    });

    // Warm the cache first
    let _ = engine.evaluate(&input);

    // Hot evaluation (cache hit)
    group.bench_function("hot_evaluation", |b| {
        b.iter(|| {
            let _ = black_box(engine.evaluate(&input));
        })
    });

    // Multiple different inputs (simulating realistic workload)
    group.bench_function("varied_inputs", |b| {
        let mut counter = 0i64;
        b.iter(|| {
            counter += 1;
            let input = PolicyInput {
                agent: AgentContext {
                    id: format!("agent-{}", counter % 10),
                    ..Default::default()
                },
                request: PolicyRequestContext {
                    method: "tools/call".to_string(),
                    tool: Some(format!("tool-{}", counter % 5)),
                    ..Default::default()
                },
                session: SessionContext::default(),
                identity: IdentityContext::default(),
                context: EnvironmentContext::default(),
            };
            let _ = black_box(engine.evaluate(&input));
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark: PII Detection Performance
// -----------------------------------------------------------------------------

fn bench_pii_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii/detection");

    let detector = PiiDetector::new();

    // Test various content sizes
    let sizes = [100, 1_000, 10_000, 100_000];

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));

        // Clean content (no PII)
        let clean_content = generate_clean_content(size);
        group.bench_with_input(
            BenchmarkId::new("clean", size),
            &clean_content,
            |b, content| {
                b.iter(|| {
                    let _ = black_box(detector.detect(content));
                })
            },
        );

        // Content with PII
        let pii_content = generate_pii_content(size);
        group.bench_with_input(
            BenchmarkId::new("with_pii", size),
            &pii_content,
            |b, content| {
                b.iter(|| {
                    let _ = black_box(detector.detect(content));
                })
            },
        );
    }

    group.finish();
}

fn bench_pii_contains_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii/contains");

    let detector = PiiDetector::new();

    // Fast check vs full detection
    let content = generate_pii_content(1000);

    group.bench_function("contains_pii", |b| {
        b.iter(|| {
            let _ = black_box(detector.contains_pii(&content));
        })
    });

    group.bench_function("detect_types", |b| {
        b.iter(|| {
            let _ = black_box(detector.detect_types(&content));
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark: Full Pipeline (All Layers)
// -----------------------------------------------------------------------------

fn bench_full_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/full");
    group.measurement_time(Duration::from_secs(10));

    // Build full pipeline with all layers
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

    // Simple request
    group.bench_function("simple_request", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(pipeline.process(&mut ctx, msg).await);
        })
    });

    // Request with PII
    group.bench_function("pii_request", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_pii_request(1);
            let _ = black_box(pipeline.process(&mut ctx, msg).await);
        })
    });

    // Large request
    group.bench_function("large_request_1kb", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_large_request(1, 1024);
            let _ = black_box(pipeline.process(&mut ctx, msg).await);
        })
    });

    group.bench_function("large_request_10kb", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_large_request(1, 10 * 1024);
            let _ = black_box(pipeline.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark: Pipeline Throughput
// -----------------------------------------------------------------------------

fn bench_pipeline_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pipeline/throughput");
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(10));

    // Minimal pipeline for maximum throughput
    let minimal_pipeline = PipelineBuilder::new()
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Disabled,
            log_evaluations: false,
        }))
        .build();

    group.bench_function("minimal", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(minimal_pipeline.process(&mut ctx, msg).await);
        })
    });

    // Production-like pipeline
    let production_pipeline = PipelineBuilder::new()
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
            log_responses: false,
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

    group.bench_function("production", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = RequestContext::new("bench-session");
            let msg = create_tools_call_request(1);
            let _ = black_box(production_pipeline.process(&mut ctx, msg).await);
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Criterion Groups
// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_empty_pipeline,
    bench_identity_layer,
    bench_policy_layer,
    bench_observe_layer,
    bench_budget_layer,
    bench_policy_engine_cache,
    bench_pii_detection,
    bench_pii_contains_check,
    bench_full_pipeline,
    bench_pipeline_throughput,
);

criterion_main!(benches);
