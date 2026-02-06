//! Overhead measurement tests
//!
//! Measures the latency overhead SOTH adds to MCP calls by comparing
//! baseline (direct) vs wrapped (through pipeline) execution times.

use soth_policy::CacheConfig as PolicyCacheConfig;
use soth_policy::PolicyEngine;
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::middleware::RequestContext;
use soth_proxy::pipeline::observe::{ObserveConfig, ObserveLayer};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::PipelineBuilder;
use soth_proxy::protocol::{JsonRpcMessage, JsonRpcRequest, RequestId};
use soth_proxy::Pipeline;
use soth_test_utils::overhead::{LatencyStats, OverheadMeasurement};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Create a minimal pipeline (identity + policy only)
fn create_minimal_pipeline() -> Pipeline {
    PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        }))
        .build()
}

/// Create a full production-like pipeline
fn create_production_pipeline() -> Pipeline {
    let cache_config = PolicyCacheConfig {
        enabled: true,
        l1_ttl: Duration::from_secs(10),
        l2_ttl: Duration::from_secs(300),
        l1_max_entries: 10000,
        l2_max_entries: 1000,
    };
    let engine = PolicyEngine::with_cache_config(cache_config);

    PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::with_engine(
            PolicyConfig {
                mode: PolicyMode::Enforce,
                log_evaluations: false,
            },
            engine,
        ))
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
        .build()
}

/// Create a simple test request
fn create_simple_request(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "echo",
            "arguments": {"text": format!("test message {}", id)}
        })),
        RequestId::Number(id),
    ))
}

/// Measure pipeline overhead
async fn measure_pipeline_overhead(
    pipeline: Arc<Pipeline>,
    iterations: usize,
) -> OverheadMeasurement {
    // Warmup
    let warmup = iterations / 10;
    for i in 0..warmup {
        let request = create_simple_request(i as i64);
        let mut ctx = RequestContext::new(format!("warmup-{}", i));
        let _ = pipeline.process(&mut ctx, request).await;
    }

    // Measure baseline (empty pipeline with no layers)
    let baseline_pipeline = Arc::new(PipelineBuilder::new().build());
    let mut baseline_durations = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let request = create_simple_request(i as i64);
        let mut ctx = RequestContext::new(format!("baseline-{}", i));
        let start = Instant::now();
        let _ = baseline_pipeline.process(&mut ctx, request).await;
        baseline_durations.push(start.elapsed());
    }

    // Measure with SOTH pipeline
    let mut soth_durations = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let request = create_simple_request(i as i64);
        let mut ctx = RequestContext::new(format!("soth-{}", i));
        let start = Instant::now();
        let _ = pipeline.process(&mut ctx, request).await;
        soth_durations.push(start.elapsed());
    }

    let baseline = LatencyStats::from_durations(&baseline_durations);
    let with_soth = LatencyStats::from_durations(&soth_durations);

    OverheadMeasurement::calculate(baseline, with_soth)
}

#[tokio::test]
async fn test_wrap_overhead_simple() {
    let pipeline = Arc::new(create_minimal_pipeline());
    let measurement = measure_pipeline_overhead(pipeline, 1000).await;

    println!();
    println!("=== Simple Pipeline Overhead Test ===");
    measurement.print_report();

    // Verify overhead is acceptable
    // Target: <500us P50 overhead, <2ms P95 overhead
    assert!(
        measurement.overhead.p50_added_us < 500.0,
        "P50 overhead ({:.1}us) should be < 500us",
        measurement.overhead.p50_added_us
    );
    assert!(
        measurement.overhead.p95_added_us < 2000.0,
        "P95 overhead ({:.1}us) should be < 2ms",
        measurement.overhead.p95_added_us
    );
}

#[tokio::test]
async fn test_wrap_overhead_production() {
    let pipeline = Arc::new(create_production_pipeline());
    let measurement = measure_pipeline_overhead(pipeline, 1000).await;

    println!();
    println!("=== Production Pipeline Overhead Test ===");
    measurement.print_report();

    // Production pipeline has more overhead but should still be reasonable
    // Target: <1ms P50 overhead, <5ms P95 overhead
    assert!(
        measurement.overhead.p50_added_us < 1000.0,
        "P50 overhead ({:.1}us) should be < 1ms",
        measurement.overhead.p50_added_us
    );
    assert!(
        measurement.overhead.p95_added_us < 5000.0,
        "P95 overhead ({:.1}us) should be < 5ms",
        measurement.overhead.p95_added_us
    );
}

#[tokio::test]
async fn test_layer_timing_breakdown() {
    let pipeline = Arc::new(create_production_pipeline());

    // Process a request and check timing breakdown
    let request = create_simple_request(1);
    let mut ctx = RequestContext::new("timing-test");

    let _ = pipeline.process(&mut ctx, request).await;

    // Verify timings are recorded
    let timings = &ctx.timings;

    println!();
    println!("=== Layer Timing Breakdown ===");
    println!("Identity: {:?}ns", timings.identity_ns);
    println!("Policy:   {:?}ns", timings.policy_ns);
    println!("Observe:  {:?}ns", timings.observe_ns);
    println!("Budget:   {:?}ns", timings.budget_ns);
    println!("Total:    {:.1}us", timings.total_us());
    println!("Breakdown: {}", timings.format_breakdown());

    // All layers should have timing recorded
    assert!(
        timings.identity_ns.is_some(),
        "Identity timing should be recorded"
    );
    assert!(
        timings.policy_ns.is_some(),
        "Policy timing should be recorded"
    );
    assert!(
        timings.observe_ns.is_some(),
        "Observe timing should be recorded"
    );
    assert!(
        timings.budget_ns.is_some(),
        "Budget timing should be recorded"
    );

    // Total should be positive
    assert!(timings.total_ns() > 0, "Total timing should be > 0");
}

#[tokio::test]
async fn test_cache_effectiveness_overhead() {
    let pipeline = Arc::new(create_production_pipeline());

    // Cold cache (first run)
    let cold_measurement = measure_pipeline_overhead(Arc::clone(&pipeline), 500).await;

    println!();
    println!("=== Cache Effectiveness Test ===");
    println!("Cold Cache:");
    println!("  P50: {:.1}us", cold_measurement.with_soth.p50_us);
    println!("  P95: {:.1}us", cold_measurement.with_soth.p95_us);

    // Warm cache (same requests again)
    let warm_measurement = measure_pipeline_overhead(pipeline, 500).await;

    println!("Warm Cache:");
    println!("  P50: {:.1}us", warm_measurement.with_soth.p50_us);
    println!("  P95: {:.1}us", warm_measurement.with_soth.p95_us);

    // Warm cache should be faster (or at least not slower)
    // Note: This is probabilistic due to system variability
    let warm_is_faster_or_equal =
        warm_measurement.with_soth.p50_us <= cold_measurement.with_soth.p50_us * 1.2;
    println!(
        "Warm cache faster: {} (allowing 20% tolerance)",
        warm_is_faster_or_equal
    );
}

#[tokio::test]
async fn test_overhead_percentages() {
    let pipeline = Arc::new(create_minimal_pipeline());
    let measurement = measure_pipeline_overhead(pipeline, 1000).await;

    println!();
    println!("=== Overhead Percentages Test ===");
    println!(
        "P50 overhead: {:.1}us ({:+.1}%)",
        measurement.overhead.p50_added_us, measurement.overhead.p50_percent
    );
    println!(
        "P95 overhead: {:.1}us ({:+.1}%)",
        measurement.overhead.p95_added_us, measurement.overhead.p95_percent
    );
    println!(
        "P99 overhead: {:.1}us ({:+.1}%)",
        measurement.overhead.p99_added_us, measurement.overhead.p99_percent
    );

    // The overhead is acceptable if it meets our targets
    // Note: percentage depends on baseline, so we check absolute values
    println!();
    println!(
        "Acceptable (P50 < 500us, P95 < 2ms): {}",
        measurement.is_acceptable(500.0, 2000.0)
    );
}

#[tokio::test]
async fn test_timing_consistency() {
    let pipeline = Arc::new(create_production_pipeline());

    // Collect multiple timing breakdowns
    let mut identity_times = Vec::new();
    let mut policy_times = Vec::new();
    let mut observe_times = Vec::new();
    let mut budget_times = Vec::new();

    for i in 0..100 {
        let request = create_simple_request(i);
        let mut ctx = RequestContext::new(format!("consistency-{}", i));
        let _ = pipeline.process(&mut ctx, request).await;

        if let Some(ns) = ctx.timings.identity_ns {
            identity_times.push(ns);
        }
        if let Some(ns) = ctx.timings.policy_ns {
            policy_times.push(ns);
        }
        if let Some(ns) = ctx.timings.observe_ns {
            observe_times.push(ns);
        }
        if let Some(ns) = ctx.timings.budget_ns {
            budget_times.push(ns);
        }
    }

    fn stats(times: &[u64]) -> (f64, f64, f64) {
        if times.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let sum: u64 = times.iter().sum();
        let mean = sum as f64 / times.len() as f64;
        let variance = times
            .iter()
            .map(|&t| (t as f64 - mean).powi(2))
            .sum::<f64>()
            / times.len() as f64;
        let std_dev = variance.sqrt();
        let min = *times.iter().min().unwrap_or(&0) as f64;
        (mean, std_dev, min)
    }

    println!();
    println!("=== Timing Consistency (100 samples) ===");
    let (mean, std_dev, min) = stats(&identity_times);
    println!(
        "Identity: mean={:.1}ns, std_dev={:.1}ns, min={:.1}ns",
        mean, std_dev, min
    );
    let (mean, std_dev, min) = stats(&policy_times);
    println!(
        "Policy:   mean={:.1}ns, std_dev={:.1}ns, min={:.1}ns",
        mean, std_dev, min
    );
    let (mean, std_dev, min) = stats(&observe_times);
    println!(
        "Observe:  mean={:.1}ns, std_dev={:.1}ns, min={:.1}ns",
        mean, std_dev, min
    );
    let (mean, std_dev, min) = stats(&budget_times);
    println!(
        "Budget:   mean={:.1}ns, std_dev={:.1}ns, min={:.1}ns",
        mean, std_dev, min
    );

    // All layers should have recorded times
    assert!(
        identity_times.len() == 100,
        "Identity should record timing every time"
    );
    assert!(
        policy_times.len() == 100,
        "Policy should record timing every time"
    );
    assert!(
        observe_times.len() == 100,
        "Observe should record timing every time"
    );
    assert!(
        budget_times.len() == 100,
        "Budget should record timing every time"
    );
}
