//! Prometheus metrics for SOTH proxy
//!
//! Provides counters, gauges, and histograms for monitoring proxy health and performance.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
#[cfg(feature = "monitoring")]
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
#[cfg(feature = "monitoring")]
use once_cell::sync::OnceCell;
use soth_core::api::HeartbeatTelemetry;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(feature = "monitoring"))]
#[derive(Clone, Debug)]
pub struct PrometheusHandle;

/// Global Prometheus handle for rendering metrics
#[cfg(feature = "monitoring")]
static PROMETHEUS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();
static BLACKLIST_KEYWORD_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLACKLIST_GRAPHQL_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_CATALOG_INTERCEPT_TOTAL: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_CATALOG_SEEN_SKIP_TOTAL: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_CATALOG_CAP_SKIP_TOTAL: AtomicU64 = AtomicU64::new(0);
static REGISTRY_SOURCE_STATE: AtomicU64 = AtomicU64::new(0);
static REGISTRY_REFRESH_CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);
static REGISTRY_REFRESH_LAST_SUCCESS_UNIX_SECS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_OPEN_FDS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_FD_SOFT_LIMIT: AtomicU64 = AtomicU64::new(0);
static RUNTIME_FD_HARD_LIMIT: AtomicU64 = AtomicU64::new(0);
static EMFILE_FORWARD_ERROR_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Initialize the Prometheus metrics exporter
///
/// Call this once at startup. Returns the handle for rendering metrics.
#[cfg(feature = "monitoring")]
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

#[cfg(not(feature = "monitoring"))]
pub fn init_metrics() -> PrometheusHandle {
    // Keep shape compatibility when monitoring is disabled.
    describe_counters();
    describe_gauges();
    describe_histograms();
    PrometheusHandle
}

/// Get the Prometheus handle (must call init_metrics first)
#[cfg(feature = "monitoring")]
pub fn get_prometheus_handle() -> Option<PrometheusHandle> {
    PROMETHEUS_HANDLE.get().cloned()
}

#[cfg(not(feature = "monitoring"))]
pub fn get_prometheus_handle() -> Option<PrometheusHandle> {
    None
}

/// Render current metrics as Prometheus text format
#[cfg(feature = "monitoring")]
pub fn render_metrics() -> String {
    PROMETHEUS_HANDLE
        .get()
        .map(|h| h.render())
        .unwrap_or_default()
}

#[cfg(not(feature = "monitoring"))]
pub fn render_metrics() -> String {
    String::new()
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
pub const FILTER_DECISIONS_TOTAL: &str = "soth_filter_decisions_total";

// Gauges
pub const ACTIVE_CONNECTIONS: &str = "soth_proxy_active_connections";
pub const CIRCUIT_BREAKER_STATE: &str = "soth_proxy_circuit_breaker_state";
pub const POLICY_ACTIVE_VERSION: &str = "soth_policy_active_version";
pub const TLS_LEARNED_PASSTHROUGH_ACTIVE: &str = "soth_tls_learned_passthrough_active";
pub const RUNTIME_OPEN_FDS_GAUGE: &str = "soth_runtime_open_fds";
pub const RUNTIME_FD_SOFT_LIMIT_GAUGE: &str = "soth_runtime_fd_soft_limit";
pub const RUNTIME_FD_HARD_LIMIT_GAUGE: &str = "soth_runtime_fd_hard_limit";
pub const RUNTIME_FD_UTILIZATION_GAUGE: &str = "soth_runtime_fd_utilization_ratio";

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
        FILTER_DECISIONS_TOTAL,
        "Total host filter decisions by phase and decision"
    );
    describe_counter!(
        "soth_runtime_emfile_forward_errors_total",
        "Total forwarded request failures attributed to EMFILE-like conditions"
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
    describe_gauge!(RUNTIME_OPEN_FDS_GAUGE, "Current open file descriptor count");
    describe_gauge!(
        RUNTIME_FD_SOFT_LIMIT_GAUGE,
        "Current RLIMIT_NOFILE soft limit"
    );
    describe_gauge!(
        RUNTIME_FD_HARD_LIMIT_GAUGE,
        "Current RLIMIT_NOFILE hard limit"
    );
    describe_gauge!(
        RUNTIME_FD_UTILIZATION_GAUGE,
        "Open/soft-limit file descriptor utilization ratio"
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

/// Set current learned passthrough active host count.
pub fn set_tls_learned_passthrough_active(count: f64) {
    gauge!(TLS_LEARNED_PASSTHROUGH_ACTIVE).set(count);
}

/// Record host-filter decision at HTTP/CONNECT phase.
pub fn record_filter_decision(phase: &str, decision: &str) {
    counter!(
        FILTER_DECISIONS_TOTAL,
        "phase" => phase.to_string(),
        "decision" => decision.to_string()
    )
    .increment(1);

    if phase.eq_ignore_ascii_case("http") && decision.eq_ignore_ascii_case("noise") {
        BLACKLIST_KEYWORD_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if phase.eq_ignore_ascii_case("http") && decision.eq_ignore_ascii_case("blacklist_graphql") {
        BLACKLIST_GRAPHQL_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if decision.eq_ignore_ascii_case("catalog_discovery_intercept") {
        DISCOVERY_CATALOG_INTERCEPT_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if decision.eq_ignore_ascii_case("catalog_discovery_seen_skip") {
        DISCOVERY_CATALOG_SEEN_SKIP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if decision.eq_ignore_ascii_case("catalog_discovery_cap_skip") {
        DISCOVERY_CATALOG_CAP_SKIP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot heartbeat telemetry counters useful for cloud-side aggregate analytics.
pub fn heartbeat_telemetry_snapshot() -> HeartbeatTelemetry {
    let mut counters = BTreeMap::new();
    counters.insert(
        "edge.blacklist.keyword_dropped_total".to_string(),
        BLACKLIST_KEYWORD_DROPPED_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.blacklist.graphql_dropped_total".to_string(),
        BLACKLIST_GRAPHQL_DROPPED_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.discovery.catalog.intercept_total".to_string(),
        DISCOVERY_CATALOG_INTERCEPT_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.discovery.catalog.already_seen_skip_total".to_string(),
        DISCOVERY_CATALOG_SEEN_SKIP_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.discovery.catalog.daily_cap_skip_total".to_string(),
        DISCOVERY_CATALOG_CAP_SKIP_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.registry.source_state".to_string(),
        REGISTRY_SOURCE_STATE.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.registry.refresh.consecutive_failures".to_string(),
        REGISTRY_REFRESH_CONSECUTIVE_FAILURES.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.registry.refresh.last_success_unix_secs".to_string(),
        REGISTRY_REFRESH_LAST_SUCCESS_UNIX_SECS.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.open_fds".to_string(),
        RUNTIME_OPEN_FDS.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.fd_soft_limit".to_string(),
        RUNTIME_FD_SOFT_LIMIT.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.fd_hard_limit".to_string(),
        RUNTIME_FD_HARD_LIMIT.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.emfile_forward_errors_total".to_string(),
        EMFILE_FORWARD_ERROR_TOTAL.load(Ordering::Relaxed),
    );
    HeartbeatTelemetry { counters }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RegistryBundleSourceState {
    DegradedEmbedded = 0,
    DegradedCached = 1,
    HealthyCloud = 2,
}

pub fn set_registry_source_state(state: RegistryBundleSourceState) {
    REGISTRY_SOURCE_STATE.store(state as u64, Ordering::Relaxed);
}

pub fn set_registry_refresh_consecutive_failures(count: u64) {
    REGISTRY_REFRESH_CONSECUTIVE_FAILURES.store(count, Ordering::Relaxed);
}

pub fn set_registry_refresh_last_success_unix_secs(unix_secs: u64) {
    REGISTRY_REFRESH_LAST_SUCCESS_UNIX_SECS.store(unix_secs, Ordering::Relaxed);
}

pub fn set_runtime_fd_snapshot(open_fds: u64, soft_limit: u64, hard_limit: u64) {
    RUNTIME_OPEN_FDS.store(open_fds, Ordering::Relaxed);
    RUNTIME_FD_SOFT_LIMIT.store(soft_limit, Ordering::Relaxed);
    RUNTIME_FD_HARD_LIMIT.store(hard_limit, Ordering::Relaxed);
    gauge!(RUNTIME_OPEN_FDS_GAUGE).set(open_fds as f64);
    gauge!(RUNTIME_FD_SOFT_LIMIT_GAUGE).set(soft_limit as f64);
    gauge!(RUNTIME_FD_HARD_LIMIT_GAUGE).set(hard_limit as f64);
    let utilization = if soft_limit == 0 {
        0.0
    } else {
        (open_fds as f64) / (soft_limit as f64)
    };
    gauge!(RUNTIME_FD_UTILIZATION_GAUGE).set(utilization);
}

/// Return the latest runtime FD snapshot captured by the monitor loop.
pub fn runtime_fd_snapshot() -> (u64, u64, u64) {
    (
        RUNTIME_OPEN_FDS.load(Ordering::Relaxed),
        RUNTIME_FD_SOFT_LIMIT.load(Ordering::Relaxed),
        RUNTIME_FD_HARD_LIMIT.load(Ordering::Relaxed),
    )
}

pub fn record_emfile_forward_error() {
    EMFILE_FORWARD_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
    counter!("soth_runtime_emfile_forward_errors_total").increment(1);
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
