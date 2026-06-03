//! Lightweight ops HTTP server exposing `/healthz`, `/readyz`, `/metrics`, and
//! `/reload`.
//!
//! Bound on a separate port from the MITM proxy so that monitoring systems can
//! reach it independently. If the bind address is empty or the port is already
//! in use, the server logs a warning and the proxy continues without it.
//!
//! ## Auth
//!
//! `/metrics` and `/reload` require `Authorization: Bearer <token>`. The token
//! is generated on first startup, persisted to `<state_dir>/ops.token` with
//! `0600` permissions, and re-read on subsequent starts. `/healthz` and
//! `/readyz` remain unauthenticated so process supervisors and k8s probes can
//! reach them without credentials — they reveal nothing sensitive.
//!
//! All routes also reject requests whose `Host` header is not a loopback name
//! (`127.0.0.1`, `localhost`, `[::1]`) when the server is bound to a loopback
//! address. This defeats DNS-rebinding attacks where a malicious page convinces
//! the browser to resolve an attacker-controlled hostname to `127.0.0.1` and
//! then send authenticated requests. Operators who explicitly bind to a
//! non-loopback address (for remote Prometheus scraping) opt out of this check.

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

/// State shared across all ops handler functions.
pub struct OpsState {
    /// Timestamp recorded when the proxy process started.
    pub startup_time: Instant,
    /// Path to the SQLite database — used for disk-space checks in `/readyz`.
    pub db_path: PathBuf,
    /// Bearer token required for `/metrics` and `/reload`. Empty string
    /// disables auth (test-only — production code must pass a token).
    pub auth_token: String,
    /// Whether to enforce loopback `Host` headers. Set to `true` when the
    /// server is bound to a loopback address.
    pub enforce_loopback_host: bool,
}

/// Generate a fresh ops bearer token or load the existing one from disk.
///
/// On first start, generates 32 bytes of CSPRNG output, hex-encodes them, and
/// writes them to `path` with `0600` permissions (Unix). Subsequent starts read
/// the persisted value so existing scrapers keep working across restarts. If
/// the file exists but has loose permissions, this returns an error rather
/// than silently using a key any other local user could have read.
pub fn generate_or_load_token(path: &Path) -> std::io::Result<String> {
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(path)?;
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "ops token file {} has overly permissive mode {:o}; \
                         expected 0600. Delete it and let the proxy regenerate, \
                         or fix with: chmod 600 {}",
                        path.display(),
                        mode,
                        path.display(),
                    ),
                ));
            }
        }
        let raw = std::fs::read_to_string(path)?;
        return Ok(raw.trim().to_string());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    std::fs::write(path, format!("{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token)
}

/// Returns true when the given bind string resolves to a loopback address.
/// Used to decide whether to enforce the loopback-Host check.
pub fn bind_is_loopback(bind: &str) -> bool {
    use std::net::ToSocketAddrs;
    bind.to_socket_addrs()
        .map(|mut iter| iter.all(|addr| addr.ip().is_loopback()))
        .unwrap_or(false)
}

/// Build the [`Router`] for the ops server.
///
/// The returned router is ready to be served with [`axum::serve`]. Auth and
/// Host-header checks are layered as middleware so they apply uniformly.
pub fn build_router(state: Arc<OpsState>) -> Router {
    let protected = Router::new()
        .route("/metrics", get(metrics))
        .route("/reload", post(reload))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(protected)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_loopback_host,
        ))
        .with_state(state)
}

// ── Middleware ───────────────────────────────────────────────────────────────

/// Reject requests with a non-loopback `Host` header when the server is bound
/// to a loopback address. Defeats DNS-rebinding attacks.
async fn require_loopback_host(
    State(state): State<Arc<OpsState>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.enforce_loopback_host {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let host_name = host_name.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = matches!(host_name, "127.0.0.1" | "localhost" | "::1");
    if !is_loopback {
        tracing::warn!(
            host = host,
            "rejected ops request with non-loopback Host header"
        );
        return (StatusCode::FORBIDDEN, "forbidden_host\n").into_response();
    }
    next.run(req).await
}

/// Require `Authorization: Bearer <token>` matching the persisted ops token.
async fn require_bearer_token(
    State(state): State<Arc<OpsState>>,
    req: Request,
    next: Next,
) -> Response {
    if state.auth_token.is_empty() {
        return next.run(req).await;
    }
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(presented.as_bytes(), state.auth_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
    }
    next.run(req).await
}

/// Constant-time byte comparison to avoid token-length timing leaks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Always returns `200 ok`. A non-200 here means the process is dead.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Returns `200 ready` when the process is healthy enough to handle traffic.
/// Returns `503 disk_critically_low` when fewer than 100 MiB remain on the
/// filesystem that holds the database.
async fn readyz(State(state): State<Arc<OpsState>>) -> impl IntoResponse {
    #[cfg(unix)]
    {
        if let Some(avail) = check_disk_bytes(&state.db_path) {
            if avail < 100 * 1024 * 1024 {
                return (StatusCode::SERVICE_UNAVAILABLE, "disk_critically_low\n");
            }
        }
    }
    let _ = &state; // suppress unused warning on non-unix targets
    (StatusCode::OK, "ready\n")
}

/// Returns a Prometheus text exposition of all heartbeat counters plus uptime.
async fn metrics(State(state): State<Arc<OpsState>>) -> impl IntoResponse {
    let snap = crate::heartbeat_telemetry::heartbeat_telemetry_snapshot();
    let mut out = String::with_capacity(4096);

    // Uptime gauge
    let uptime = state.startup_time.elapsed().as_secs();
    writeln!(
        out,
        "# HELP soth_uptime_seconds Time since proxy process started."
    )
    .ok();
    writeln!(out, "# TYPE soth_uptime_seconds gauge").ok();
    writeln!(out, "soth_uptime_seconds {uptime}").ok();

    // Emit all heartbeat counters.  Keys that end in `_total` or contain
    // known monotonic suffixes are typed as `counter`; everything else
    // (state fields, gauges) is typed as `gauge`.
    for (key, value) in &snap.counters {
        let prom_name = prometheus_name(key);
        let metric_type = if is_counter_key(key) {
            "counter"
        } else {
            "gauge"
        };
        writeln!(out, "# TYPE {prom_name} {metric_type}").ok();
        writeln!(out, "{prom_name} {value}").ok();
    }

    // Latency histograms
    write_histogram(
        &mut out,
        "soth_detect_latency_seconds",
        &crate::heartbeat_telemetry::detect_latency_snapshot(),
    );
    write_histogram(
        &mut out,
        "soth_classify_latency_seconds",
        &crate::heartbeat_telemetry::classify_latency_snapshot(),
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
}

/// Triggers a live reload of the global DNS resolver.
///
/// Re-reads the system nameserver configuration and replaces the running
/// resolver atomically. In-flight DNS queries on the old resolver complete
/// safely via Arc refcounting; new queries use the replacement immediately.
///
/// Returns `200 reloaded\n` on success. The endpoint is idempotent and safe
/// to call at any time without disrupting proxy traffic.
async fn reload() -> impl IntoResponse {
    soth_mitm::reload_dns_resolver(None);
    (StatusCode::OK, "reloaded\n")
}

/// Write a single Prometheus histogram in text exposition format.
///
/// Bucket counts in the snapshot are per-bucket (not cumulative); this
/// function accumulates them before writing so the output is spec-compliant.
fn write_histogram(
    out: &mut String,
    name: &str,
    snap: &crate::heartbeat_telemetry::HistogramSnapshot,
) {
    writeln!(out, "# HELP {name} Latency histogram").ok();
    writeln!(out, "# TYPE {name} histogram").ok();
    let mut cumulative: u64 = 0;
    for (i, boundary) in snap.boundaries.iter().enumerate() {
        cumulative += snap.bucket_counts[i];
        // Convert microsecond boundary to seconds for Prometheus.
        let le = *boundary as f64 / 1_000_000.0;
        writeln!(out, "{name}_bucket{{le=\"{le}\"}} {cumulative}").ok();
    }
    // Overflow bucket (+Inf) includes every observation.
    cumulative += snap.bucket_counts[snap.boundaries.len()];
    writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {cumulative}").ok();
    writeln!(out, "{name}_sum {}", snap.sum_seconds).ok();
    writeln!(out, "{name}_count {}", snap.count).ok();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert a dot-separated metric key to a valid Prometheus metric name.
fn prometheus_name(key: &str) -> String {
    key.replace('.', "_")
}

/// Heuristic: a key is a monotonic counter when its last segment ends with
/// `_total` or `_errors` — everything else is treated as a gauge.
fn is_counter_key(key: &str) -> bool {
    let last = key.rsplit('.').next().unwrap_or(key);
    last.ends_with("_total") || last.ends_with("_errors")
}

/// Return the number of available bytes on the filesystem that contains `path`.
/// Returns `None` if the path cannot be stat'd or the syscall fails.
#[cfg(unix)]
#[allow(unsafe_code)]
fn check_disk_bytes(path: &std::path::Path) -> Option<u64> {
    // Walk up to the nearest existing ancestor so we can stat even when the
    // database file does not yet exist (first-run scenario).
    let mut probe = path;
    loop {
        if probe.exists() {
            break;
        }
        match probe.parent() {
            Some(parent) => probe = parent,
            None => return None,
        }
    }

    let c_path = std::ffi::CString::new(probe.to_str()?).ok()?;
    // SAFETY: `statvfs` is called with a valid C string and a zeroed-out
    // `statvfs` struct that we own.  The only memory written is `stat` on
    // the stack, which is valid for the duration of the call.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if ret == 0 {
        Some(stat.f_bavail as u64 * stat.f_frsize)
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{is_counter_key, prometheus_name, OpsState};
    use std::sync::Arc;
    use std::time::Instant;

    /// Test helper: build an OpsState that disables auth and Host checks so
    /// existing route tests stay focused on handler behavior. Auth-specific
    /// tests construct OpsState directly with the relevant flags.
    fn unauth_state() -> Arc<OpsState> {
        Arc::new(OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
            auth_token: String::new(),
            enforce_loopback_host: false,
        })
    }

    #[test]
    fn prometheus_name_replaces_dots_with_underscores() {
        assert_eq!(
            prometheus_name("edge.runtime.classify_in_flight"),
            "edge_runtime_classify_in_flight"
        );
        assert_eq!(
            prometheus_name("edge.blacklist.keyword_dropped_total"),
            "edge_blacklist_keyword_dropped_total"
        );
    }

    #[test]
    fn is_counter_key_identifies_totals() {
        assert!(is_counter_key("edge.blacklist.keyword_dropped_total"));
        assert!(is_counter_key("edge.runtime.emfile_forward_errors_total"));
        assert!(!is_counter_key("edge.runtime.classify_in_flight"));
        assert!(!is_counter_key("edge.registry.source_state"));
        assert!(!is_counter_key("edge.runtime.bundle_trust_level"));
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        use axum::body::to_bytes;
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let app = super::build_router(unauth_state());
        let req = Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"ok\n");
    }

    #[tokio::test]
    async fn readyz_returns_200_when_disk_ok() {
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let app = super::build_router(unauth_state());
        let req = Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // On any reasonable machine /tmp has more than 100 MiB free.
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_contains_uptime_and_heartbeat_keys() {
        use axum::body::to_bytes;
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let app = super::build_router(unauth_state());
        let req = Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("soth_uptime_seconds"),
            "missing uptime metric"
        );
        assert!(
            text.contains("edge_blacklist_keyword_dropped_total"),
            "missing heartbeat counter"
        );
        assert!(
            text.contains("soth_detect_latency_seconds_bucket"),
            "missing detect latency histogram"
        );
        assert!(
            text.contains("soth_classify_latency_seconds_bucket"),
            "missing classify latency histogram"
        );
        assert!(
            text.contains("le=\"+Inf\""),
            "histogram missing +Inf bucket"
        );
    }

    #[tokio::test]
    async fn metrics_requires_bearer_token() {
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let state = Arc::new(OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
            auth_token: "secret-token".to_string(),
            enforce_loopback_host: false,
        });
        let app = super::build_router(state);

        // No header → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);

        // Wrong token → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", "Bearer wrong")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);

        // Correct token → 200
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", "Bearer secret-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_does_not_require_token() {
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let state = Arc::new(OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
            auth_token: "secret-token".to_string(),
            enforce_loopback_host: false,
        });
        let app = super::build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_non_loopback_host_when_enforced() {
        use axum::http::Request;
        use tower::util::ServiceExt as _;

        let state = Arc::new(OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
            auth_token: String::new(),
            enforce_loopback_host: true,
        });
        let app = super::build_router(state);

        // attacker.example → 403 even on /healthz
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header("host", "attacker.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        // 127.0.0.1:9090 → 200
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header("host", "127.0.0.1:9090")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // localhost → 200
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header("host", "localhost")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn generate_or_load_token_persists_across_reads() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Drop the empty tempfile so the generator can create it fresh with
        // the right permissions.
        drop(tmp);
        std::fs::remove_file(&path).ok();

        let first = super::generate_or_load_token(&path).unwrap();
        assert_eq!(first.len(), 64, "token should be 32 bytes hex-encoded");
        let second = super::generate_or_load_token(&path).unwrap();
        assert_eq!(
            first, second,
            "second load should reuse the persisted token"
        );

        // Permissions must be 0600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600, "token file must be 0600");
        }
    }

    #[test]
    fn bind_is_loopback_detects_loopback_addresses() {
        assert!(super::bind_is_loopback("127.0.0.1:9090"));
        assert!(super::bind_is_loopback("localhost:9090"));
        assert!(super::bind_is_loopback("[::1]:9090"));
        assert!(!super::bind_is_loopback("0.0.0.0:9090"));
    }

    #[test]
    fn write_histogram_produces_cumulative_buckets() {
        use crate::heartbeat_telemetry::{AtomicHistogram, LATENCY_BOUNDARIES_US};

        let h = AtomicHistogram::new(LATENCY_BOUNDARIES_US);
        // Record one observation in each of the first two buckets.
        h.record_us(50); // bucket 0 (<100 µs)
        h.record_us(200); // bucket 1 (<500 µs)
        h.record_us(20_000_000); // overflow
        let snap = h.snapshot();

        let mut out = String::new();
        super::write_histogram(&mut out, "test_hist", &snap);

        // The +Inf bucket must equal total count (3).
        assert!(
            out.contains("test_hist_bucket{le=\"+Inf\"} 3"),
            "unexpected +Inf count in:\n{out}"
        );
        // _count must equal 3.
        assert!(
            out.contains("test_hist_count 3"),
            "unexpected count in:\n{out}"
        );
        // _sum should be positive.
        assert!(
            out.contains("test_hist_sum "),
            "missing sum line in:\n{out}"
        );
    }
}
