use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use soth_sync::api_types::HeartbeatTelemetry;

const REGISTRY_SOURCE_DEGRADED_EMBEDDED: u64 = 0;
const REGISTRY_SOURCE_DEGRADED_CACHED: u64 = 1;
const REGISTRY_SOURCE_HEALTHY_CLOUD: u64 = 2;
const REGISTRY_STALE_AFTER_SECS: u64 = 24 * 60 * 60;

// ── Latency histogram ─────────────────────────────────────────────────────────

/// Bucket boundaries in microseconds: 0.1ms … 5 s.
pub static LATENCY_BOUNDARIES_US: &[u64] = &[
    100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000,
];

/// A lock-free latency histogram built from `AtomicU64` counters.
///
/// Observations are bucketed in **O(log n)** time via binary search, then
/// recorded with a single relaxed atomic add. The overflow bucket captures
/// anything above the highest boundary.
pub struct AtomicHistogram {
    boundaries: &'static [u64],
    /// `boundaries.len() + 1` buckets — the last element is the overflow bucket.
    buckets: Vec<AtomicU64>,
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl AtomicHistogram {
    /// Create a new histogram with the given microsecond boundaries.
    pub fn new(boundaries: &'static [u64]) -> Self {
        let n = boundaries.len() + 1; // +1 for overflow
        let buckets = (0..n).map(|_| AtomicU64::new(0)).collect();
        Self {
            boundaries,
            buckets,
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record a single observation of `value_us` microseconds.
    pub fn record_us(&self, value_us: u64) {
        // Binary search for the first boundary that value_us fits under.
        let bucket = self.boundaries.partition_point(|&b| value_us > b);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(value_us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the histogram for exposition.  Returns per-bucket (not
    /// cumulative) counts so that the caller can decide the exposition format.
    pub fn snapshot(&self) -> HistogramSnapshot {
        let bucket_counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let sum_us = self.sum_us.load(Ordering::Relaxed);
        let count = self.count.load(Ordering::Relaxed);
        HistogramSnapshot {
            boundaries: self.boundaries,
            bucket_counts,
            sum_seconds: sum_us as f64 / 1_000_000.0,
            count,
        }
    }
}

/// A point-in-time snapshot of an [`AtomicHistogram`].
pub struct HistogramSnapshot {
    /// Bucket boundaries in microseconds (same slice as the source histogram).
    pub boundaries: &'static [u64],
    /// Per-bucket counts in the same order as `boundaries` plus one overflow
    /// bucket at the end.  These are **not** cumulative.
    pub bucket_counts: Vec<u64>,
    /// Sum of all observed values, converted to seconds.
    pub sum_seconds: f64,
    /// Total number of observations.
    pub count: u64,
}

static DETECT_LATENCY: Lazy<AtomicHistogram> =
    Lazy::new(|| AtomicHistogram::new(LATENCY_BOUNDARIES_US));
static CLASSIFY_LATENCY: Lazy<AtomicHistogram> =
    Lazy::new(|| AtomicHistogram::new(LATENCY_BOUNDARIES_US));

/// Record a single detect-stage latency observation (in microseconds).
pub fn record_detect_latency_us(us: u64) {
    DETECT_LATENCY.record_us(us);
}

/// Record a single classify-stage latency observation (in microseconds).
pub fn record_classify_latency_us(us: u64) {
    CLASSIFY_LATENCY.record_us(us);
}

/// Return a point-in-time snapshot of the detect latency histogram.
pub fn detect_latency_snapshot() -> HistogramSnapshot {
    DETECT_LATENCY.snapshot()
}

/// Return a point-in-time snapshot of the classify latency histogram.
pub fn classify_latency_snapshot() -> HistogramSnapshot {
    CLASSIFY_LATENCY.snapshot()
}

// ── Heartbeat counters ────────────────────────────────────────────────────────

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
static RUNTIME_CLASSIFY_PANIC_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static RUNTIME_CLASSIFY_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
static RUNTIME_DB_WRITE_QUEUE_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static RUNTIME_BUNDLE_TRUST_LEVEL: AtomicU64 = AtomicU64::new(0);

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

/// Counter for events dropped because the classify worker panicked or
/// returned a JoinError. Distinct from `record_classify_overload_drop`
/// (saturation): this surfaces actual classify-pipeline crashes which
/// should be near zero in a healthy fleet. Each increment corresponds
/// to a `tracing::warn!` from `spawn_classify_task`.
pub fn record_classify_panic_drop() {
    RUNTIME_CLASSIFY_PANIC_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
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

pub fn record_bundle_trust_level(level: soth_bundle::BundleTrustLevel) {
    RUNTIME_BUNDLE_TRUST_LEVEL.store(bundle_trust_level_code(level), Ordering::Relaxed);
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
        "edge.runtime.classify_panic_dropped_total".to_string(),
        RUNTIME_CLASSIFY_PANIC_DROPPED_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.classify_in_flight".to_string(),
        RUNTIME_CLASSIFY_IN_FLIGHT.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.db_write_queue_fallback_total".to_string(),
        RUNTIME_DB_WRITE_QUEUE_FALLBACK_TOTAL.load(Ordering::Relaxed),
    );
    counters.insert(
        "edge.runtime.bundle_trust_level".to_string(),
        RUNTIME_BUNDLE_TRUST_LEVEL.load(Ordering::Relaxed),
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

fn bundle_trust_level_code(level: soth_bundle::BundleTrustLevel) -> u64 {
    match level {
        soth_bundle::BundleTrustLevel::Verified => 2,
        soth_bundle::BundleTrustLevel::Unverified => 1,
        soth_bundle::BundleTrustLevel::SignatureDisabled => 0,
    }
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
        record_bundle_trust_level, record_classify_in_flight_finished,
        record_classify_in_flight_started, record_classify_overload_drop,
        record_db_write_queue_fallback, record_discovery_catalog_intercept,
        record_policy_enforced_false, AtomicHistogram, LATENCY_BOUNDARIES_US,
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
        assert!(telemetry
            .counters
            .contains_key("edge.runtime.bundle_trust_level"));
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

    #[test]
    fn bundle_trust_level_counter_updates() {
        record_bundle_trust_level(soth_bundle::BundleTrustLevel::Verified);
        let verified = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.bundle_trust_level")
            .copied()
            .unwrap_or(0);
        assert_eq!(verified, 2);

        record_bundle_trust_level(soth_bundle::BundleTrustLevel::Unverified);
        let unverified = heartbeat_telemetry_snapshot()
            .counters
            .get("edge.runtime.bundle_trust_level")
            .copied()
            .unwrap_or(0);
        assert_eq!(unverified, 1);
    }

    // ── AtomicHistogram tests ─────────────────────────────────────────────────

    #[test]
    fn histogram_empty_snapshot_is_all_zeros() {
        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        let snap = h.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.sum_seconds, 0.0);
        assert!(snap.bucket_counts.iter().all(|&c| c == 0));
        // Number of buckets = boundaries + 1 overflow
        assert_eq!(snap.bucket_counts.len(), LATENCY_BOUNDARIES_US.len() + 1);
    }

    #[test]
    fn histogram_records_below_first_boundary() {
        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        // 50 µs < 100 µs (first boundary) → bucket 0
        h.record_us(50);
        let snap = h.snapshot();
        assert_eq!(snap.count, 1);
        assert_eq!(snap.bucket_counts[0], 1);
        // All other buckets should be zero.
        for &c in &snap.bucket_counts[1..] {
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn histogram_records_above_last_boundary() {
        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        // 10_000_000 µs > 5_000_000 µs (last boundary) → overflow bucket
        h.record_us(10_000_000);
        let snap = h.snapshot();
        assert_eq!(snap.count, 1);
        let overflow_idx = LATENCY_BOUNDARIES_US.len();
        assert_eq!(snap.bucket_counts[overflow_idx], 1);
    }

    #[test]
    fn histogram_records_at_exact_boundary() {
        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        // 1_000 µs == boundary[2] (1ms); partition_point finds first b where value > b,
        // so exactly equal goes into bucket at that index (value is NOT > boundary).
        h.record_us(1_000);
        let snap = h.snapshot();
        assert_eq!(snap.count, 1);
        // 1_000 is not > 1_000, so partition_point returns index 2 (the 1_000 boundary).
        assert_eq!(snap.bucket_counts[2], 1);
    }

    #[test]
    fn histogram_sum_and_count_accumulate() {
        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        h.record_us(200); // 0.0002 s
        h.record_us(800); // 0.0008 s
        h.record_us(2_000); // 0.002 s
        let snap = h.snapshot();
        assert_eq!(snap.count, 3);
        let expected_sum = (200 + 800 + 2_000) as f64 / 1_000_000.0;
        // Allow small floating-point rounding.
        assert!((snap.sum_seconds - expected_sum).abs() < 1e-9);
    }

    #[test]
    fn histogram_public_fns_record_and_snapshot() {
        // Exercise the module-level helpers against the shared statics.
        // We can't assert exact values because other tests may have already
        // incremented the counters, but we can confirm count increases.
        let before = super::detect_latency_snapshot().count;
        super::record_detect_latency_us(500);
        let after = super::detect_latency_snapshot().count;
        assert_eq!(after, before + 1);

        let before = super::classify_latency_snapshot().count;
        super::record_classify_latency_us(1_500);
        let after = super::classify_latency_snapshot().count;
        assert_eq!(after, before + 1);
    }
}
