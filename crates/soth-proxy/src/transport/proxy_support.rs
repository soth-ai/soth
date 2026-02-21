//! Support helpers for proxy transport.
//!
//! This module intentionally contains pure support/runtime helpers so
//! `proxy.rs` can stay focused on orchestration logic.

use chrono::{NaiveDate, Utc};
use hudsucker::hyper_util::client::legacy::Error as LegacyClientError;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rustls::{AlertDescription, Error as RustlsError};
use serde::{Deserialize, Serialize};
use soth_core::types::TrafficEnvelope;
use soth_core::EventLogger;
use soth_oisp::InterceptDecision;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub(crate) struct TunnelDebugRuntime {
    pub(crate) enabled: bool,
    pub(crate) include_noise: bool,
    min_log_interval: Duration,
    last_log_by_key: Arc<Mutex<HashMap<String, Instant>>>,
}

impl TunnelDebugRuntime {
    pub(crate) fn new(enabled: bool, include_noise: bool, min_log_interval: Duration) -> Self {
        Self {
            enabled,
            include_noise,
            min_log_interval,
            last_log_by_key: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn should_log(
        &self,
        decision_label: &str,
        host: &str,
        process_pid: Option<u32>,
        process_name: Option<&str>,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        if decision_label == "noise" && !self.include_noise {
            return false;
        }
        let key = format!(
            "{}|{}|{}|{}",
            decision_label,
            host.to_ascii_lowercase(),
            process_pid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            process_name.unwrap_or("unknown").to_ascii_lowercase()
        );
        let now = Instant::now();
        let mut map = self.last_log_by_key.lock();
        if map.len() > 4096 {
            map.retain(|_, logged_at| {
                now.saturating_duration_since(*logged_at) < self.min_log_interval
            });
            if map.len() > 8192 {
                map.clear();
            }
        }
        if let Some(previous) = map.get(&key) {
            if now.saturating_duration_since(*previous) < self.min_log_interval {
                return false;
            }
        }
        map.insert(key, now);
        true
    }
}

const FD_PRESSURE_SHED_ENTER_RATIO: f64 = 0.95;
const FD_PRESSURE_SHED_EXIT_RATIO: f64 = 0.85;
const FD_PRESSURE_LOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub(crate) struct FdPressureSnapshot {
    pub(crate) open_fds: u64,
    pub(crate) soft_limit: u64,
    pub(crate) hard_limit: u64,
    pub(crate) utilization: f64,
}

#[derive(Debug)]
struct FdPressureState {
    active: bool,
    last_log_at: Option<Instant>,
}

static FD_PRESSURE_STATE: Lazy<Mutex<FdPressureState>> = Lazy::new(|| {
    Mutex::new(FdPressureState {
        active: false,
        last_log_at: None,
    })
});

pub(crate) fn should_shed_intercept_due_to_fd_pressure() -> Option<FdPressureSnapshot> {
    let (open_fds, soft_limit, hard_limit) = crate::metrics::runtime_fd_snapshot();
    if soft_limit == 0 {
        return None;
    }
    let utilization = (open_fds as f64) / (soft_limit as f64);
    let snapshot = FdPressureSnapshot {
        open_fds,
        soft_limit,
        hard_limit,
        utilization,
    };

    let now = Instant::now();
    let mut state = FD_PRESSURE_STATE.lock();
    if state.active {
        if utilization <= FD_PRESSURE_SHED_EXIT_RATIO {
            state.active = false;
            state.last_log_at = None;
            info!(
                open_fds = open_fds,
                soft_limit = soft_limit,
                hard_limit = hard_limit,
                utilization_pct = format!("{:.1}", utilization * 100.0),
                "FD pressure recovered; resuming MITM interception decisions"
            );
            return None;
        }
    } else if utilization >= FD_PRESSURE_SHED_ENTER_RATIO {
        state.active = true;
        state.last_log_at = None;
    }

    if !state.active {
        return None;
    }

    let should_log = state
        .last_log_at
        .map(|last| now.saturating_duration_since(last) >= FD_PRESSURE_LOG_INTERVAL)
        .unwrap_or(true);
    if should_log {
        state.last_log_at = Some(now);
        warn!(
            open_fds = open_fds,
            soft_limit = soft_limit,
            hard_limit = hard_limit,
            utilization_pct = format!("{:.1}", utilization * 100.0),
            "FD pressure fail-open active: tunneling CONNECT instead of MITM to prevent EMFILE"
        );
    }

    Some(snapshot)
}

pub(crate) fn is_benign_proxy_forward_error(err: &LegacyClientError) -> bool {
    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(hyper_error) = cause.downcast_ref::<hyper::Error>() {
            if hyper_error.is_canceled()
                || hyper_error.is_closed()
                || hyper_error.is_incomplete_message()
                || hyper_error.is_body_write_aborted()
            {
                return true;
            }
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

pub(crate) fn classify_tls_intercept_forward_error(
    err: &LegacyClientError,
) -> Option<&'static str> {
    let mut saw_tls_error = false;
    let mut saw_timeout = false;
    let mut saw_certificate_error = false;

    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(tls_error) = cause.downcast_ref::<RustlsError>() {
            saw_tls_error = true;
            match tls_error {
                RustlsError::InvalidCertificate(_)
                | RustlsError::NoCertificatesPresented
                | RustlsError::UnsupportedNameType => {
                    saw_certificate_error = true;
                }
                RustlsError::AlertReceived(alert) => {
                    if matches!(
                        alert,
                        AlertDescription::BadCertificate
                            | AlertDescription::UnsupportedCertificate
                            | AlertDescription::CertificateRevoked
                            | AlertDescription::CertificateExpired
                            | AlertDescription::CertificateUnknown
                            | AlertDescription::UnknownCA
                            | AlertDescription::AccessDenied
                    ) {
                        saw_certificate_error = true;
                    }
                }
                _ => {}
            }
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            if io_error.kind() == std::io::ErrorKind::TimedOut {
                saw_timeout = true;
            }
        }
        source = cause.source();
    }

    if saw_certificate_error {
        return Some("tls_certificate_validation_failed");
    }
    if saw_tls_error {
        return Some("tls_handshake_failed");
    }
    if saw_timeout {
        return Some("tls_handshake_timeout");
    }

    let error = err.to_string().to_ascii_lowercase();
    if error.contains("certificate")
        || error.contains("unknown ca")
        || error.contains("bad certificate")
        || error.contains("certificate verify")
        || error.contains("authority invalid")
    {
        return Some("tls_certificate_validation_failed");
    }
    if error.contains("tls")
        || error.contains("ssl")
        || error.contains("handshake")
        || error.contains("alert")
    {
        return Some("tls_handshake_failed");
    }

    None
}

pub(crate) fn is_emfile_proxy_forward_error(err: &LegacyClientError) -> bool {
    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            if io_error
                .raw_os_error()
                .is_some_and(|code| code == 24 || code == 10024)
            {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

pub(crate) const STREAM_CAPTURE_MAX_BYTES: usize = 100 * 1024 * 1024;
const STREAM_CAPTURE_INITIAL_CAPACITY: usize = 64 * 1024;
const STREAM_BUFFER_POOL_MAX_BUFFERS: usize = 32;
const STREAM_BUFFER_POOL_MAX_RETAINED_CAPACITY: usize = 4 * 1024 * 1024;

static STREAM_BUFFER_POOL: Lazy<Mutex<Vec<Vec<u8>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub(crate) fn acquire_stream_buffer() -> Vec<u8> {
    let mut pool = STREAM_BUFFER_POOL.lock();
    if let Some(mut buffer) = pool.pop() {
        buffer.clear();
        return buffer;
    }
    Vec::with_capacity(STREAM_CAPTURE_INITIAL_CAPACITY)
}

pub(crate) fn release_stream_buffer(mut buffer: Vec<u8>) {
    if buffer.capacity() > STREAM_BUFFER_POOL_MAX_RETAINED_CAPACITY {
        return;
    }
    buffer.clear();
    let mut pool = STREAM_BUFFER_POOL.lock();
    if pool.len() < STREAM_BUFFER_POOL_MAX_BUFFERS {
        pool.push(buffer);
    }
}

/// Append a stream chunk into capture buffer with a hard memory cap.
/// Returns true when the cap is reached (or already reached).
pub(crate) fn append_stream_capture(buffer: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if buffer.len() >= STREAM_CAPTURE_MAX_BYTES {
        return true;
    }
    let remaining = STREAM_CAPTURE_MAX_BYTES - buffer.len();
    let write_len = remaining.min(chunk.len());
    buffer.extend_from_slice(&chunk[..write_len]);
    write_len < chunk.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DiscoveryKind {
    Catalog,
    App,
    Domain,
}

impl DiscoveryKind {
    fn as_key_segment(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::App => "app",
            Self::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryReserveResult {
    Reserved,
    AlreadySeen,
    DailyCapReached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDiscoveryState {
    day: String,
    seen: Vec<String>,
    count: u32,
}

#[derive(Debug, Clone)]
struct DiscoveryState {
    day: NaiveDate,
    seen: HashSet<String>,
    count: u32,
}

impl DiscoveryState {
    fn empty(day: NaiveDate) -> Self {
        Self {
            day,
            seen: HashSet::new(),
            count: 0,
        }
    }
}

pub(crate) struct CatalogDiscoveryLimiter {
    state_by_kind: Mutex<HashMap<DiscoveryKind, DiscoveryState>>,
    event_logger: Mutex<Option<Arc<EventLogger>>>,
    catalog_daily_cap: u32,
    app_daily_cap: u32,
    domain_daily_cap: u32,
}

impl Default for CatalogDiscoveryLimiter {
    fn default() -> Self {
        Self {
            state_by_kind: Mutex::new(HashMap::new()),
            event_logger: Mutex::new(None),
            catalog_daily_cap: 250,
            app_daily_cap: 250,
            domain_daily_cap: 250,
        }
    }
}

impl CatalogDiscoveryLimiter {
    #[cfg(test)]
    pub(crate) fn with_catalog_daily_cap(catalog_daily_cap: u32) -> Self {
        Self {
            state_by_kind: Mutex::new(HashMap::new()),
            event_logger: Mutex::new(None),
            catalog_daily_cap,
            app_daily_cap: 250,
            domain_daily_cap: 250,
        }
    }

    fn normalized_key(value: &str) -> String {
        value.trim().to_ascii_lowercase()
    }

    fn sync_state_key(kind: DiscoveryKind) -> String {
        format!("discovery.{}.state", kind.as_key_segment())
    }

    pub(crate) fn set_event_logger(&self, logger: Arc<EventLogger>) {
        *self.event_logger.lock() = Some(logger);
    }

    fn current_day() -> NaiveDate {
        Utc::now().date_naive()
    }

    fn cap_for_kind(&self, kind: DiscoveryKind) -> u32 {
        match kind {
            DiscoveryKind::Catalog => self.catalog_daily_cap,
            DiscoveryKind::App => self.app_daily_cap,
            DiscoveryKind::Domain => self.domain_daily_cap,
        }
    }

    pub(crate) fn reserve_once_per_day(
        &self,
        kind: DiscoveryKind,
        value: &str,
    ) -> DiscoveryReserveResult {
        let normalized = Self::normalized_key(value);
        if normalized.is_empty() {
            return DiscoveryReserveResult::AlreadySeen;
        }

        let today = Self::current_day();
        let logger = self.event_logger.lock().clone();

        let mut states = self.state_by_kind.lock();
        let state = states
            .entry(kind)
            .or_insert_with(|| Self::load_state(kind, today, logger.as_ref()))
            .clone();

        let mut state = if state.day == today {
            state
        } else {
            Self::load_state(kind, today, logger.as_ref())
        };

        if state.seen.contains(normalized.as_str()) {
            states.insert(kind, state);
            return DiscoveryReserveResult::AlreadySeen;
        }

        if state.count >= self.cap_for_kind(kind) {
            states.insert(kind, state);
            return DiscoveryReserveResult::DailyCapReached;
        }

        state.seen.insert(normalized);
        state.count = state.count.saturating_add(1);
        let persisted = Self::encode_state(&state);
        states.insert(kind, state);
        drop(states);

        if let (Some(logger), Some(payload)) = (logger, persisted) {
            if let Err(error) = logger.set_sync_state(&Self::sync_state_key(kind), payload.as_str())
            {
                debug!(
                    kind = %kind.as_key_segment(),
                    ?error,
                    "Failed persisting discovery limiter state; continuing with in-memory state"
                );
            }
        }

        DiscoveryReserveResult::Reserved
    }

    pub(crate) fn was_reserved_today(&self, kind: DiscoveryKind, value: &str) -> bool {
        let normalized = Self::normalized_key(value);
        if normalized.is_empty() {
            return false;
        }

        let today = Self::current_day();
        let logger = self.event_logger.lock().clone();
        let mut states = self.state_by_kind.lock();
        let state = states
            .entry(kind)
            .or_insert_with(|| Self::load_state(kind, today, logger.as_ref()))
            .clone();
        let state = if state.day == today {
            state
        } else {
            Self::load_state(kind, today, logger.as_ref())
        };
        let reserved = state.seen.contains(normalized.as_str());
        states.insert(kind, state);
        reserved
    }

    fn load_state(
        kind: DiscoveryKind,
        today: NaiveDate,
        logger: Option<&Arc<EventLogger>>,
    ) -> DiscoveryState {
        let Some(logger) = logger else {
            return DiscoveryState::empty(today);
        };

        let raw = match logger.get_sync_state(&Self::sync_state_key(kind)) {
            Ok(value) => value,
            Err(error) => {
                debug!(
                    kind = %kind.as_key_segment(),
                    ?error,
                    "Failed reading persisted discovery limiter state"
                );
                None
            }
        };

        let Some(raw) = raw else {
            return DiscoveryState::empty(today);
        };

        let parsed: PersistedDiscoveryState = match serde_json::from_str(raw.as_str()) {
            Ok(parsed) => parsed,
            Err(error) => {
                debug!(
                    kind = %kind.as_key_segment(),
                    ?error,
                    "Failed parsing persisted discovery limiter state"
                );
                return DiscoveryState::empty(today);
            }
        };

        let parsed_day = match NaiveDate::parse_from_str(parsed.day.as_str(), "%Y-%m-%d") {
            Ok(day) => day,
            Err(error) => {
                debug!(
                    kind = %kind.as_key_segment(),
                    ?error,
                    "Invalid persisted discovery limiter day format"
                );
                return DiscoveryState::empty(today);
            }
        };

        if parsed_day != today {
            return DiscoveryState::empty(today);
        }

        let mut seen = HashSet::with_capacity(parsed.seen.len());
        for item in parsed.seen {
            let normalized = Self::normalized_key(item.as_str());
            if !normalized.is_empty() {
                seen.insert(normalized);
            }
        }
        let count = parsed.count.max(seen.len() as u32);
        DiscoveryState {
            day: today,
            seen,
            count,
        }
    }

    fn encode_state(state: &DiscoveryState) -> Option<String> {
        let mut seen: Vec<String> = state.seen.iter().cloned().collect();
        seen.sort();
        serde_json::to_string(&PersistedDiscoveryState {
            day: state.day.format("%Y-%m-%d").to_string(),
            seen,
            count: state.count,
        })
        .ok()
    }
}

pub(crate) fn append_catalog_discovery_tags(tags: &mut BTreeMap<String, String>, host: &str) {
    tags.insert("discovery_mode".to_string(), "catalog".to_string());
    tags.insert("discovery_capture".to_string(), "daily_first".to_string());
    tags.insert("discovery_payload".to_string(), "metadata_only".to_string());
    tags.insert("discovery_host".to_string(), host.to_string());
}

pub(crate) fn is_blacklist_detection_reason(reason: Option<&str>) -> bool {
    matches!(
        reason,
        Some("bundle.blacklist.keyword" | "bundle.blacklist.graphql")
    )
}

pub(crate) fn decision_label_from_intercept_decision(decision: InterceptDecision) -> &'static str {
    match decision {
        InterceptDecision::Intercept { .. } => "intercept",
        InterceptDecision::Passthrough => "passthrough",
        InterceptDecision::Noise => "noise",
        InterceptDecision::Tunnel => "tunnel",
    }
}

pub(crate) fn process_bundle_id_from_executable(path: Option<&str>) -> Option<String> {
    let path = path?;
    node_package_id_from_executable_path(path)
        .or_else(|| macos_bundle_id_from_executable_path(path))
}

fn node_package_id_from_executable_path(path: &str) -> Option<String> {
    let normalized_path = path.replace('\\', "/");
    let lower = normalized_path.to_ascii_lowercase();
    let marker = "/node_modules/";
    let mut offset = 0usize;

    while let Some(found) = lower[offset..].find(marker) {
        let marker_start = offset + found;
        if let Some(parent_package) =
            scoped_parent_package_before_node_modules(&normalized_path, marker_start)
        {
            return Some(parent_package);
        }
        let start = marker_start + marker.len();
        let remainder = &normalized_path[start..];
        let mut segments = remainder.split('/');
        let first = segments.next().map(str::trim).unwrap_or_default();
        if first.is_empty() || first.starts_with('.') {
            offset = start;
            continue;
        }
        if first.starts_with('@') {
            let second = segments
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(second) = second {
                return Some(format!(
                    "{}/{}",
                    first.to_ascii_lowercase(),
                    second.to_ascii_lowercase()
                ));
            }
            offset = start;
            continue;
        }
        return Some(first.to_ascii_lowercase());
    }

    None
}

fn scoped_parent_package_before_node_modules(path: &str, marker_start: usize) -> Option<String> {
    let prefix = path.get(..marker_start)?;
    let mut segments = prefix.rsplit('/');
    let package = segments.next().map(str::trim).unwrap_or_default();
    let scope = segments.next().map(str::trim).unwrap_or_default();
    if package.is_empty() || !scope.starts_with('@') {
        return None;
    }
    Some(format!(
        "{}/{}",
        scope.to_ascii_lowercase(),
        package.to_ascii_lowercase()
    ))
}

fn macos_bundle_id_from_executable_path(path: &str) -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        return None;
    }

    #[cfg(target_os = "macos")]
    {
        static MACOS_BUNDLE_ID_CACHE: Lazy<Mutex<HashMap<String, Option<String>>>> =
            Lazy::new(|| Mutex::new(HashMap::new()));

        let normalized_path = path.replace('\\', "/");

        if let Some(bundle_id) = macos_bundle_id_from_bundle_marker(
            normalized_path.as_str(),
            ".app",
            &MACOS_BUNDLE_ID_CACHE,
        ) {
            return Some(bundle_id);
        }
        if let Some(bundle_id) = macos_bundle_id_from_bundle_marker(
            normalized_path.as_str(),
            ".xpc",
            &MACOS_BUNDLE_ID_CACHE,
        ) {
            return Some(bundle_id);
        }

        let leaf = normalized_path
            .rsplit('/')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default();
        if looks_like_bundle_id(leaf) {
            return Some(leaf.to_string());
        }

        None
    }
}

#[cfg(target_os = "macos")]
fn macos_bundle_id_from_bundle_marker(
    path: &str,
    marker: &str,
    cache: &Mutex<HashMap<String, Option<String>>>,
) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let idx = lower.find(marker)?;
    let bundle_root = format!("{}{}", &path[..idx], marker);

    if let Some(cached) = cache.lock().get(&bundle_root).cloned() {
        return cached;
    }

    let plist_path = format!("{bundle_root}/Contents/Info.plist");
    let detected = std::process::Command::new("defaults")
        .args(["read", plist_path.as_str(), "CFBundleIdentifier"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    cache.lock().insert(bundle_root, detected.clone());
    detected
}

fn looks_like_bundle_id(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.matches('.').count() < 2 {
        return false;
    }
    let parts = trimmed.split('.').collect::<Vec<_>>();
    if !matches!(
        parts.first().copied(),
        Some("com" | "org" | "net" | "io" | "app" | "me" | "co" | "dev")
    ) {
        return false;
    }
    parts.iter().all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    })
}

pub(crate) fn append_capture_tags(
    tags: &mut BTreeMap<String, String>,
    request_body_truncated: bool,
    response_body_truncated: bool,
    response_reason: Option<&str>,
    capture_limit_bytes: Option<u64>,
) {
    if request_body_truncated {
        tags.insert("capture.request_body".to_string(), "truncated".to_string());
    }
    if response_body_truncated {
        tags.insert("capture.response_body".to_string(), "truncated".to_string());
        if let Some(reason) = response_reason {
            tags.insert("capture.response_reason".to_string(), reason.to_string());
        }
    }
    if let Some(limit) = capture_limit_bytes {
        tags.insert("capture.body_limit_bytes".to_string(), limit.to_string());
    }
}

pub(crate) fn append_process_attribution_tags(
    tags: &mut BTreeMap<String, String>,
    envelope: Option<&TrafficEnvelope>,
) {
    let Some(envelope) = envelope else {
        return;
    };
    if let Some(source) = envelope.process_attribution_source.as_ref() {
        tags.insert("metadata.attribution_source".to_string(), source.clone());
    }
    if let Some(confidence) = envelope.process_attribution_confidence {
        tags.insert(
            "metadata.attribution_confidence".to_string(),
            format!("{confidence:.3}"),
        );
    }
    if let Some(app_type) = envelope.process_app_type.as_ref() {
        tags.insert("metadata.process_app_type".to_string(), app_type.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::process_bundle_id_from_executable;

    #[test]
    fn process_bundle_id_extracts_scoped_node_package() {
        let path = "/Users/example/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/codex/codex";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("@openai/codex".to_string())
        );
    }

    #[test]
    fn process_bundle_id_extracts_scoped_node_package_from_pnpm_layout() {
        let path = "/Users/example/project/node_modules/.pnpm/@openai+codex@0.25.0/node_modules/@openai/codex/bin/codex";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("@openai/codex".to_string())
        );
    }

    #[test]
    fn process_bundle_id_accepts_reverse_domain_executable_name() {
        let path = "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("com.apple.WebKit.Networking".to_string())
        );
    }
}
