//! Lightweight ops HTTP server exposing `/healthz`, `/readyz`, and `/metrics`.
//!
//! Bound on a separate port from the MITM proxy so that monitoring systems can
//! reach it independently. If the bind address is empty or the port is already
//! in use, the server logs a warning and the proxy continues without it.

use std::fmt::Write as FmtWrite;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};

/// State shared across all ops handler functions.
pub struct OpsState {
    /// Timestamp recorded when the proxy process started.
    pub startup_time: Instant,
    /// Path to the SQLite database — used for disk-space checks in `/readyz`.
    pub db_path: PathBuf,
}

/// Build the [`Router`] for the ops server.
///
/// The returned router is ready to be served with [`axum::serve`].
pub fn build_router(state: Arc<OpsState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
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

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
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
    use super::{is_counter_key, prometheus_name};

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
        use std::time::Instant;
        use tower::util::ServiceExt as _;

        let state = std::sync::Arc::new(super::OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
        });
        let app = super::build_router(state);
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
        use std::time::Instant;
        use tower::util::ServiceExt as _;

        let state = std::sync::Arc::new(super::OpsState {
            startup_time: Instant::now(),
            // /tmp always exists and has space on CI
            db_path: std::path::PathBuf::from("/tmp/test.db"),
        });
        let app = super::build_router(state);
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
        use std::time::Instant;
        use tower::util::ServiceExt as _;

        let state = std::sync::Arc::new(super::OpsState {
            startup_time: Instant::now(),
            db_path: std::path::PathBuf::from("/tmp/test.db"),
        });
        let app = super::build_router(state);
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
    }
}
