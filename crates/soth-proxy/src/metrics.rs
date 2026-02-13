//! Prometheus metrics for SOTH proxy
//!
//! Provides counters, gauges, and histograms for monitoring proxy health and performance.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;
use std::time::Duration;

/// Global Prometheus handle for rendering metrics
static PROMETHEUS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Initialize the Prometheus metrics exporter
///
/// Call this once at startup. Returns the handle for rendering metrics.
pub fn init_metrics() -> PrometheusHandle {
    PROMETHEUS_HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .install_recorder()
                .expect("Failed to install Prometheus recorder");

            // Describe all metrics
            describe_counters();
            describe_gauges();
            describe_histograms();

            handle
        })
        .clone()
}

/// Get the Prometheus handle (must call init_metrics first)
pub fn get_prometheus_handle() -> Option<PrometheusHandle> {
    PROMETHEUS_HANDLE.get().cloned()
}

/// Render current metrics as Prometheus text format
pub fn render_metrics() -> String {
    PROMETHEUS_HANDLE
        .get()
        .map(|h| h.render())
        .unwrap_or_default()
}

// === Metric Names ===

// Counters
pub const REQUESTS_TOTAL: &str = "soth_proxy_requests_total";
pub const RESPONSES_TOTAL: &str = "soth_proxy_responses_total";
pub const ERRORS_TOTAL: &str = "soth_proxy_errors_total";
pub const TOKENS_TOTAL: &str = "soth_proxy_tokens_total";
pub const RATE_LIMITED_TOTAL: &str = "soth_proxy_rate_limited_total";
pub const CIRCUIT_BREAKER_TRIPS: &str = "soth_proxy_circuit_breaker_trips_total";
pub const POLICY_RELOAD_TOTAL: &str = "soth_policy_reload_total";
pub const POLICY_EVAL_TOTAL: &str = "soth_policy_evaluations_total";
pub const BUDGET_CHECKS_TOTAL: &str = "soth_budget_checks_total";
pub const BUDGET_BLOCKS_TOTAL: &str = "soth_budget_blocks_total";
pub const ENFORCEMENT_FAILOPEN_TOTAL: &str = "soth_enforcement_failopen_total";
pub const STREAM_CAPTURE_LIMIT_REACHED_TOTAL: &str = "soth_stream_capture_limit_reached_total";
pub const TLS_LEARNED_PASSTHROUGH_TOTAL: &str = "soth_tls_learned_passthrough_total";
pub const DETECTION_MISMATCH_COUNT: &str = "soth_detection_mismatch_count";
pub const PROVIDER_MISMATCH_COUNT: &str = "soth_provider_mismatch_count";
pub const USAGE_MISMATCH_COUNT: &str = "soth_usage_mismatch_count";

// Gauges
pub const ACTIVE_CONNECTIONS: &str = "soth_proxy_active_connections";
pub const CIRCUIT_BREAKER_STATE: &str = "soth_proxy_circuit_breaker_state";
pub const POLICY_ACTIVE_VERSION: &str = "soth_policy_active_version";
pub const TLS_LEARNED_PASSTHROUGH_ACTIVE: &str = "soth_tls_learned_passthrough_active";

// Histograms
pub const REQUEST_DURATION: &str = "soth_proxy_request_duration_seconds";
pub const UPSTREAM_LATENCY: &str = "soth_proxy_upstream_latency_seconds";
pub const POLICY_EVAL_DURATION: &str = "soth_policy_eval_duration_seconds";

fn describe_counters() {
    describe_counter!(
        REQUESTS_TOTAL,
        "Total number of requests processed by the proxy"
    );
    describe_counter!(
        RESPONSES_TOTAL,
        "Total number of responses returned by the proxy"
    );
    describe_counter!(ERRORS_TOTAL, "Total number of errors encountered");
    describe_counter!(TOKENS_TOTAL, "Total number of tokens processed");
    describe_counter!(
        RATE_LIMITED_TOTAL,
        "Total number of requests rejected due to rate limiting"
    );
    describe_counter!(
        CIRCUIT_BREAKER_TRIPS,
        "Total number of circuit breaker trips"
    );
    describe_counter!(
        POLICY_RELOAD_TOTAL,
        "Total number of policy reload attempts"
    );
    describe_counter!(
        POLICY_EVAL_TOTAL,
        "Total number of policy evaluations by outcome"
    );
    describe_counter!(BUDGET_CHECKS_TOTAL, "Total number of budget checks");
    describe_counter!(
        BUDGET_BLOCKS_TOTAL,
        "Total number of budget blocks by scope"
    );
    describe_counter!(
        ENFORCEMENT_FAILOPEN_TOTAL,
        "Total number of fail-open enforcement events by reason"
    );
    describe_counter!(
        STREAM_CAPTURE_LIMIT_REACHED_TOTAL,
        "Total number of response streams where capture limit was reached"
    );
    describe_counter!(
        TLS_LEARNED_PASSTHROUGH_TOTAL,
        "Total learned TLS passthrough events by action"
    );
    describe_counter!(
        DETECTION_MISMATCH_COUNT,
        "Total number of shadow detection mismatches between legacy and registry paths"
    );
    describe_counter!(
        PROVIDER_MISMATCH_COUNT,
        "Total number of shadow provider mismatches between legacy and registry paths"
    );
    describe_counter!(
        USAGE_MISMATCH_COUNT,
        "Total number of shadow usage extraction mismatches between parser paths"
    );
}

fn describe_gauges() {
    describe_gauge!(ACTIVE_CONNECTIONS, "Current number of active connections");
    describe_gauge!(
        CIRCUIT_BREAKER_STATE,
        "Circuit breaker state (0=closed, 1=half-open, 2=open)"
    );
    describe_gauge!(
        POLICY_ACTIVE_VERSION,
        "Marker gauge for active policy version (1 for current labels)"
    );
    describe_gauge!(
        TLS_LEARNED_PASSTHROUGH_ACTIVE,
        "Current number of learned passthrough hosts"
    );
}

fn describe_histograms() {
    describe_histogram!(REQUEST_DURATION, "Request duration in seconds");
    describe_histogram!(UPSTREAM_LATENCY, "Upstream server latency in seconds");
    describe_histogram!(POLICY_EVAL_DURATION, "Policy evaluation latency in seconds");
}

// === Recording Functions ===

/// Record a request
pub fn record_request(provider: &str, method: &str) {
    counter!(REQUESTS_TOTAL, "provider" => provider.to_string(), "method" => method.to_string())
        .increment(1);
}

/// Record a response
pub fn record_response(provider: &str, status: &str) {
    counter!(RESPONSES_TOTAL, "provider" => provider.to_string(), "status" => status.to_string())
        .increment(1);
}

/// Record an error
pub fn record_error(provider: &str, error_type: &str) {
    counter!(ERRORS_TOTAL, "provider" => provider.to_string(), "type" => error_type.to_string())
        .increment(1);
}

/// Record tokens processed
pub fn record_tokens(provider: &str, model: &str, token_type: &str, count: u64) {
    counter!(
        TOKENS_TOTAL,
        "provider" => provider.to_string(),
        "model" => model.to_string(),
        "type" => token_type.to_string()
    )
    .increment(count);
}

/// Record a rate-limited request
pub fn record_rate_limited(provider: &str, key: &str) {
    counter!(
        RATE_LIMITED_TOTAL,
        "provider" => provider.to_string(),
        "key" => key.to_string()
    )
    .increment(1);
}

/// Record a circuit breaker trip
pub fn record_circuit_breaker_trip(provider: &str) {
    counter!(CIRCUIT_BREAKER_TRIPS, "provider" => provider.to_string()).increment(1);
}

/// Record a policy reload result
pub fn record_policy_reload(success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!(POLICY_RELOAD_TOTAL, "result" => result.to_string()).increment(1);
}

/// Record policy evaluation latency and outcome
pub fn record_policy_evaluation(outcome: &str, duration: Duration) {
    counter!(POLICY_EVAL_TOTAL, "outcome" => outcome.to_string()).increment(1);
    histogram!(POLICY_EVAL_DURATION, "outcome" => outcome.to_string())
        .record(duration.as_secs_f64());
}

/// Expose active policy version as a labeled gauge marker
pub fn set_policy_active_version(version: &str) {
    gauge!(POLICY_ACTIVE_VERSION, "version" => version.to_string()).set(1.0);
}

/// Record budget checks
pub fn record_budget_check(scope: &str) {
    counter!(BUDGET_CHECKS_TOTAL, "scope" => scope.to_string()).increment(1);
}

/// Record budget blocks
pub fn record_budget_block(scope: &str) {
    counter!(BUDGET_BLOCKS_TOTAL, "scope" => scope.to_string()).increment(1);
}

/// Record an enforcement fail-open event.
pub fn record_enforcement_failopen(reason: &str) {
    counter!(
        ENFORCEMENT_FAILOPEN_TOTAL,
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record a stream response capture limit hit.
pub fn record_stream_capture_limit_reached(provider: &str, stream_kind: &str) {
    counter!(
        STREAM_CAPTURE_LIMIT_REACHED_TOTAL,
        "provider" => provider.to_string(),
        "stream_kind" => stream_kind.to_string()
    )
    .increment(1);
}

/// Record learned TLS passthrough action.
pub fn record_tls_learned_passthrough(action: &str) {
    counter!(
        TLS_LEARNED_PASSTHROUGH_TOTAL,
        "action" => action.to_string()
    )
    .increment(1);
}

/// Record a legacy-vs-registry detection-class mismatch.
pub fn record_detection_mismatch(source: &str) {
    counter!(
        DETECTION_MISMATCH_COUNT,
        "source" => source.to_string()
    )
    .increment(1);
}

/// Record a legacy-vs-registry provider mismatch.
pub fn record_provider_mismatch(source: &str) {
    counter!(
        PROVIDER_MISMATCH_COUNT,
        "source" => source.to_string()
    )
    .increment(1);
}

/// Record a usage extraction mismatch between primary and shadow parser paths.
pub fn record_usage_mismatch(provider: &str, stream_kind: &str) {
    counter!(
        USAGE_MISMATCH_COUNT,
        "provider" => provider.to_string(),
        "stream_kind" => stream_kind.to_string()
    )
    .increment(1);
}

/// Set current learned passthrough active host count.
pub fn set_tls_learned_passthrough_active(count: f64) {
    gauge!(TLS_LEARNED_PASSTHROUGH_ACTIVE).set(count);
}

/// Set active connections gauge
pub fn set_active_connections(provider: &str, count: f64) {
    gauge!(ACTIVE_CONNECTIONS, "provider" => provider.to_string()).set(count);
}

/// Increment active connections
pub fn increment_connections(provider: &str) {
    gauge!(ACTIVE_CONNECTIONS, "provider" => provider.to_string()).increment(1.0);
}

/// Decrement active connections
pub fn decrement_connections(provider: &str) {
    gauge!(ACTIVE_CONNECTIONS, "provider" => provider.to_string()).decrement(1.0);
}

/// Set circuit breaker state
/// 0 = closed (normal), 1 = half-open (probing), 2 = open (blocking)
pub fn set_circuit_breaker_state(provider: &str, state: CircuitState) {
    gauge!(CIRCUIT_BREAKER_STATE, "provider" => provider.to_string()).set(state as u8 as f64);
}

/// Record request duration
pub fn record_request_duration(provider: &str, duration: Duration) {
    histogram!(REQUEST_DURATION, "provider" => provider.to_string()).record(duration.as_secs_f64());
}

/// Record upstream latency
pub fn record_upstream_latency(provider: &str, duration: Duration) {
    histogram!(UPSTREAM_LATENCY, "provider" => provider.to_string()).record(duration.as_secs_f64());
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    Closed = 0,
    HalfOpen = 1,
    Open = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_metrics() {
        // This test just verifies the metrics can be initialized
        // In a real test environment, we'd need to handle the global state
        let _ = init_metrics();
    }

    #[test]
    fn test_circuit_state_values() {
        assert_eq!(CircuitState::Closed as u8, 0);
        assert_eq!(CircuitState::HalfOpen as u8, 1);
        assert_eq!(CircuitState::Open as u8, 2);
    }
}
