//! Load testing for SOTH pipeline
//!
//! Tests throughput and latency under concurrent load.

use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine};
use soth_proxy::pipeline::middleware::RequestContext;
use soth_proxy::pipeline::observe::{ObserveConfig, ObserveLayer};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyMode, PolicyLayer};
use soth_proxy::protocol::{JsonRpcMessage, JsonRpcRequest, RequestId};
use soth_proxy::{Pipeline, PipelineBuilder};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Create a test pipeline with all layers
fn create_test_pipeline() -> Pipeline {
    let mut builder = PipelineBuilder::new();

    // Observe layer
    builder = builder.layer(ObserveLayer::new(ObserveConfig {
        log_requests: true,
        log_responses: true,
        pii_detection: true,
        count_tokens: true,
        log_to_file: false,
    }));

    // Policy layer with cache
    let cache_config = PolicyCacheConfig {
        enabled: true,
        l1_ttl: Duration::from_secs(10),
        l2_ttl: Duration::from_secs(300),
        l1_max_entries: 10000,
        l2_max_entries: 1000,
    };
    let engine = PolicyEngine::with_cache_config(cache_config);
    builder = builder.layer(PolicyLayer::with_engine(
        PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: false,
        },
        engine,
    ));

    builder.build()
}

/// Create a test request
fn create_request(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "echo",
            "arguments": {"text": format!("test message {}", id)}
        })),
        RequestId::Number(id),
    ))
}

/// Create a request with PII
fn create_pii_request(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "echo",
            "arguments": {"text": format!("SSN: 123-45-6789, email: test{}@example.com", id)}
        })),
        RequestId::Number(id),
    ))
}

/// Run a load test
async fn run_load_test(
    pipeline: Arc<Pipeline>,
    num_requests: usize,
    use_pii: bool,
) -> LoadTestResults {
    let mut latencies = Vec::with_capacity(num_requests);
    let start = Instant::now();

    for i in 0..num_requests {
        let request = if use_pii {
            create_pii_request(i as i64)
        } else {
            create_request(i as i64)
        };

        let mut ctx = RequestContext::new(format!("session-{}", i % 100));
        let req_start = Instant::now();
        let _ = pipeline.process(&mut ctx, request).await;
        latencies.push(req_start.elapsed());
    }

    let total_duration = start.elapsed();

    LoadTestResults::calculate(latencies, total_duration)
}

/// Load test results
#[derive(Debug)]
struct LoadTestResults {
    total_requests: usize,
    total_duration: Duration,
    throughput: f64,
    min_latency: Duration,
    max_latency: Duration,
    avg_latency: Duration,
    p50_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
}

impl LoadTestResults {
    fn calculate(mut latencies: Vec<Duration>, total_duration: Duration) -> Self {
        latencies.sort();
        let total_requests = latencies.len();
        let throughput = total_requests as f64 / total_duration.as_secs_f64();

        let min_latency = *latencies.first().unwrap_or(&Duration::ZERO);
        let max_latency = *latencies.last().unwrap_or(&Duration::ZERO);
        let avg_latency = latencies.iter().sum::<Duration>() / total_requests as u32;

        let p50_latency = latencies[total_requests * 50 / 100];
        let p95_latency = latencies[total_requests * 95 / 100];
        let p99_latency = latencies[total_requests * 99 / 100];

        Self {
            total_requests,
            total_duration,
            throughput,
            min_latency,
            max_latency,
            avg_latency,
            p50_latency,
            p95_latency,
            p99_latency,
        }
    }

    fn print(&self, label: &str) {
        println!("\n{}", label);
        println!("  Requests:   {}", self.total_requests);
        println!("  Duration:   {:?}", self.total_duration);
        println!("  Throughput: {:.2} req/s", self.throughput);
        println!("  Latency:");
        println!("    Min:  {:?}", self.min_latency);
        println!("    Avg:  {:?}", self.avg_latency);
        println!("    P50:  {:?}", self.p50_latency);
        println!("    P95:  {:?}", self.p95_latency);
        println!("    P99:  {:?}", self.p99_latency);
        println!("    Max:  {:?}", self.max_latency);
    }
}

#[tokio::test]
async fn load_test_simple_requests() {
    let pipeline = Arc::new(create_test_pipeline());

    // Warmup
    let _ = run_load_test(Arc::clone(&pipeline), 100, false).await;

    // Actual test
    let results = run_load_test(pipeline, 1000, false).await;
    results.print("Simple Requests (1000)");

    // Assertions
    assert!(results.throughput > 1000.0, "Throughput should be > 1000 req/s");
    assert!(results.p95_latency < Duration::from_millis(10), "P95 should be < 10ms");
}

#[tokio::test]
async fn load_test_pii_requests() {
    let pipeline = Arc::new(create_test_pipeline());

    // Warmup
    let _ = run_load_test(Arc::clone(&pipeline), 100, true).await;

    // Actual test
    let results = run_load_test(pipeline, 1000, true).await;
    results.print("PII Requests (1000)");

    // PII detection adds overhead, so more lenient threshold
    assert!(results.throughput > 500.0, "Throughput should be > 500 req/s");
    assert!(results.p95_latency < Duration::from_millis(20), "P95 should be < 20ms");
}

#[tokio::test]
async fn load_test_cache_effectiveness() {
    let pipeline = Arc::new(create_test_pipeline());

    // First run - cache cold
    let cold_results = run_load_test(Arc::clone(&pipeline), 500, false).await;
    cold_results.print("Cold Cache (500)");

    // Second run - cache warm (same requests)
    let warm_results = run_load_test(pipeline, 500, false).await;
    warm_results.print("Warm Cache (500)");

    // Warm cache should be faster
    assert!(
        warm_results.avg_latency < cold_results.avg_latency,
        "Warm cache should be faster than cold cache"
    );
}

#[tokio::test]
async fn load_test_concurrent_sessions() {
    use tokio::task::JoinSet;

    let pipeline = Arc::new(create_test_pipeline());
    let num_sessions = 10;
    let requests_per_session = 100;

    let start = Instant::now();
    let mut tasks = JoinSet::new();

    for session_id in 0..num_sessions {
        let pipeline = Arc::clone(&pipeline);
        tasks.spawn(async move {
            for i in 0..requests_per_session {
                let request = create_request((session_id * 1000 + i) as i64);
                let mut ctx = RequestContext::new(format!("session-{}", session_id));
                let _ = pipeline.process(&mut ctx, request).await;
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("Task panicked");
    }

    let duration = start.elapsed();
    let total_requests = num_sessions * requests_per_session;
    let throughput = total_requests as f64 / duration.as_secs_f64();

    println!("\nConcurrent Sessions Test");
    println!("  Sessions:    {}", num_sessions);
    println!("  Req/Session: {}", requests_per_session);
    println!("  Total:       {}", total_requests);
    println!("  Duration:    {:?}", duration);
    println!("  Throughput:  {:.2} req/s", throughput);

    assert!(throughput > 5000.0, "Concurrent throughput should be > 5000 req/s");
}
