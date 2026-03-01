use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use soth_sync::api_types::HeartbeatTelemetry;

const REGISTRY_SOURCE_DEGRADED_EMBEDDED: u64 = 0;
const REGISTRY_SOURCE_DEGRADED_CACHED: u64 = 1;
const REGISTRY_SOURCE_HEALTHY_CLOUD: u64 = 2;
const REGISTRY_STALE_AFTER_SECS: u64 = 24 * 60 * 60;

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
static RUNTIME_EMFILE_FORWARD_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static RUNTIME_POLICY_ENFORCED_FALSE_TOTAL: AtomicU64 = AtomicU64::new(0);
static RUNTIME_CLASSIFY_OVERLOAD_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static RUNTIME_CLASSIFY_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
static RUNTIME_DB_WRITE_QUEUE_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn record_blacklist_keyword_dropped() {
    BLACKLIST_KEYWORD_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_blacklist_graphql_dropped() {
    BLACKLIST_GRAPHQL_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_discovery_catalog_intercept() {
    DISCOVERY_CATALOG_INTERCEPT_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_discovery_catalog_seen_skip() {
    DISCOVERY_CATALOG_SEEN_SKIP_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_discovery_catalog_cap_skip() {
    DISCOVERY_CATALOG_CAP_SKIP_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_runtime_emfile_forward_error() {
    RUNTIME_EMFILE_FORWARD_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_runtime_error_if_emfile(message: &str) {
    let text = message.to_ascii_lowercase();
    if text.contains("too many open files") || text.contains("emfile") {
        record_runtime_emfile_forward_error();
    }
}

pub fn record_policy_enforced_false() {
    RUNTIME_POLICY_ENFORCED_FALSE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_classify_overload_drop() {
    RUNTIME_CLASSIFY_OVERLOAD_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_classify_in_flight_started() {
    RUNTIME_CLASSIFY_IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
}

pub fn record_classify_in_flight_finished() {
    let _ =
        RUNTIME_CLASSIFY_IN_FLIGHT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_sub(1))
        });
}

pub fn record_db_write_queue_fallback() {
    RUNTIME_DB_WRITE_QUEUE_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn refresh_registry_runtime_metrics(registry_cache_path: &Path) {
    let status = soth_sync::cache::registry_bundle_runtime_status(
        registry_cache_path,
        std::time::Duration::from_secs(REGISTRY_STALE_AFTER_SECS),
    );
    let source_state = map_registry_source_state(&status);
    REGISTRY_SOURCE_STATE.store(source_state, Ordering::Relaxed);
    let refresh_failures = if status.cache_error.is_some()
        || status.validation_status.as_deref() == Some("failed")
        || status.validation_failed_reason.is_some()
    {
        1
    } else {
        0
    };
    REGISTRY_REFRESH_CONSECUTIVE_FAILURES.store(refresh_failures, Ordering::Relaxed);
    let last_success_unix = status
        .fetched_at
        .as_deref()
        .and_then(parse_rfc3339_unix_secs)
        .unwrap_or(0);
    REGISTRY_REFRESH_LAST_SUCCESS_UNIX_SECS.store(last_success_unix, Ordering::Relaxed);
}

pub fn heartbeat_telemetry_snapshot() -> HeartbeatTelemetry {
    refresh_runtime_fd_metrics();
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
        RUNTIME_EMFILE_FORWARD_ERRORS_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.policy_enforced_false_total".to_string(),
        RUNTIME_POLICY_ENFORCED_FALSE_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.classify_overload_dropped_total".to_string(),
        RUNTIME_CLASSIFY_OVERLOAD_DROPPED_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.classify_in_flight".to_string(),
        RUNTIME_CLASSIFY_IN_FLIGHT.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.db_write_queue_fallback_total".to_string(),
        RUNTIME_DB_WRITE_QUEUE_FALLBACK_TOTAL.load(Ordering::Relaxed),
    );
    HeartbeatTelemetry { counters }
}

fn map_registry_source_state(status: &soth_sync::cache::RegistryBundleRuntimeStatus) -> u64 {
    let validation_failed = status.validation_status.as_deref() == Some("failed")
        || status.validation_failed_reason.is_some();
    if !status.cache_present {
        return REGISTRY_SOURCE_DEGRADED_EMBEDDED;
    }
    if status.stale || validation_failed || status.cache_error.is_some() {
        return REGISTRY_SOURCE_DEGRADED_CACHED;
    }
    REGISTRY_SOURCE_HEALTHY_CLOUD
}

fn parse_rfc3339_unix_secs(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|dt| u64::try_from(dt.with_timezone(&Utc).timestamp()).ok())
}

fn refresh_runtime_fd_metrics() {
    let (open_fds, soft_limit, hard_limit) = runtime_fd_snapshot();
    RUNTIME_OPEN_FDS.store(open_fds, Ordering::Relaxed);
    RUNTIME_FD_SOFT_LIMIT.store(soft_limit, Ordering::Relaxed);
    RUNTIME_FD_HARD_LIMIT.store(hard_limit, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn runtime_fd_snapshot() -> (u64, u64, u64) {
    let open_fds = std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count() as u64)
        .unwrap_or(0);
    let (soft_limit, hard_limit) = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|contents| parse_linux_fd_limits(&contents))
        .unwrap_or((0, 0));
    (open_fds, soft_limit, hard_limit)
}

#[cfg(target_os = "macos")]
fn runtime_fd_snapshot() -> (u64, u64, u64) {
    let open_fds = std::fs::read_dir("/dev/fd")
        .ok()
        .map(|entries| entries.count() as u64)
        .unwrap_or(0);
    (open_fds, 0, 0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn runtime_fd_snapshot() -> (u64, u64, u64) {
    (0, 0, 0)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_fd_limits(contents: &str) -> Option<(u64, u64)> {
    let line = contents
        .lines()
        .find(|line| line.trim_start().starts_with("Max open files"))?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let soft = parse_limit_value(parts[3])?;
    let hard = parse_limit_value(parts[4])?;
    Some((soft, hard))
}

#[cfg(any(target_os = "linux", test))]
fn parse_limit_value(value: &str) -> Option<u64> {
    if value.eq_ignore_ascii_case("unlimited") {
        return Some(0);
    }
    value.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{
        heartbeat_telemetry_snapshot, parse_linux_fd_limits, record_blacklist_keyword_dropped,
        record_classify_in_flight_finished, record_classify_in_flight_started,
        record_classify_overload_drop, record_db_write_queue_fallback,
        record_discovery_catalog_intercept, record_policy_enforced_false,
    };

    #[test]
    fn snapshot_contains_expected_namespaces() {
        let telemetry = heartbeat_telemetry_snapshot();
        assert!(telemetry
            .counters
            .contains_key("edge.blacklist.keyword_dropped_total"));
        assert!(telemetry
            .counters
            .contains_key("edge.registry.source_state"));
        assert!(telemetry
            .counters
            .contains_key("edge.runtime.policy_enforced_false_total"));
    }

    #[test]
    fn policy_enforced_false_counter_increments() {
        let before = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.policy_enforced_false_total")
            .copied()
            .unwrap_or(0);
        record_policy_enforced_false();
        let after = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.policy_enforced_false_total")
            .copied()
            .unwrap_or(0);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn classify_runtime_counters_increment() {
        let before = heartbeat_telemetry_snapshot();
        let before_overload = before
            .counters
            .get("edge.runtime.classify_overload_dropped_total")
            .copied()
            .unwrap_or(0);
        let before_in_flight = before
            .counters
            .get("edge.runtime.classify_in_flight")
            .copied()
            .unwrap_or(0);
        let before_db_fallback = before
            .counters
            .get("edge.runtime.db_write_queue_fallback_total")
            .copied()
            .unwrap_or(0);

        record_classify_overload_drop();
        record_db_write_queue_fallback();
        record_classify_in_flight_started();
        record_classify_in_flight_finished();

        let after = heartbeat_telemetry_snapshot();
        assert_eq!(
            after
                .counters
                .get("edge.runtime.classify_overload_dropped_total")
                .copied()
                .unwrap_or(0),
            before_overload + 1
        );
        assert_eq!(
            after
                .counters
                .get("edge.runtime.db_write_queue_fallback_total")
                .copied()
                .unwrap_or(0),
            before_db_fallback + 1
        );
        assert_eq!(
            after
                .counters
                .get("edge.runtime.classify_in_flight")
                .copied()
                .unwrap_or(0),
            before_in_flight
        );
    }

    #[test]
    fn producer_counters_increment() {
        let before_blacklist = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.blacklist.keyword_dropped_total")
            .copied()
            .unwrap_or(0);
        let before_discovery = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.discovery.catalog.intercept_total")
            .copied()
            .unwrap_or(0);
        record_blacklist_keyword_dropped();
        record_discovery_catalog_intercept();
        let after = heartbeat_telemetry_snapshot();
        assert_eq!(
            after
                .counters
                .get("edge.blacklist.keyword_dropped_total")
                .copied()
                .unwrap_or(0),
            before_blacklist + 1
        );
        assert_eq!(
            after
                .counters
                .get("edge.discovery.catalog.intercept_total")
                .copied()
                .unwrap_or(0),
            before_discovery + 1
        );
    }

    #[test]
    fn runtime_error_emfile_detection_increments_counter() {
        let before = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.emfile_forward_errors_total")
            .copied()
            .unwrap_or(0);
        super::record_runtime_error_if_emfile("upstream failed: EMFILE");
        let after = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.emfile_forward_errors_total")
            .copied()
            .unwrap_or(0);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn parse_linux_fd_limits_extracts_soft_and_hard() {
        let limits =
            "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 4096                 files\n";
        assert_eq!(parse_linux_fd_limits(limits), Some((1024, 4096)));
    }
}
