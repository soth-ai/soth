//! API routes for the dashboard

use crate::event_store::{
    AgentsSummary, ClustersSummary, CryptoMerkleSummary, CryptoStatusSummary, EventStore,
    EventsSummary, RollupsSummary, StreamStats,
};
use crate::state::{
    AdvancedBudgetMetrics, BudgetMetrics, BudgetPrimitives, DashboardState, FilterDecisionMetrics,
    IdentityMetrics, ObserveMetrics, PolicyMetrics, ProxyMetrics,
};
use crate::websocket::event_stream_handler;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Wrapper response for API endpoints
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub timestamp: String,
    pub uptime_secs: u64,
    pub data: T,
}

/// Combined dashboard snapshot payload.
#[derive(Serialize)]
pub struct DashboardSnapshot {
    pub identity: IdentityMetrics,
    pub policy: PolicyMetrics,
    pub observe: ObserveMetrics,
    pub budget: BudgetMetrics,
    pub proxy: ProxyMetrics,
}

impl<T> ApiResponse<T> {
    fn new(state: &DashboardState, data: T) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            uptime_secs: state.uptime_secs(),
            data,
        }
    }
}

fn observe_metrics_for_state(state: &AppState) -> ObserveMetrics {
    if let Some(ref events) = state.events {
        let from_events = events.observe_metrics();
        if from_events.requests > 0 || from_events.responses > 0 || from_events.pii_detections > 0 {
            return from_events;
        }
    }
    state.dashboard.observe()
}

fn proxy_metrics_for_state(state: &AppState) -> ProxyMetrics {
    let mut proxy = state.dashboard.proxy();
    if let Some(renderer) = state.metrics_renderer {
        let metrics_text = renderer();
        proxy.filter_decisions = parse_filter_decisions_metric(metrics_text.as_str());
    }
    proxy
}

/// Combined application state
#[derive(Clone)]
pub struct AppState {
    pub dashboard: DashboardState,
    pub events: Option<Arc<EventStore>>,
    /// Readiness flag (can be set to false during graceful shutdown)
    pub ready: Arc<AtomicBool>,
    /// Optional Prometheus metrics renderer
    pub metrics_renderer: Option<fn() -> String>,
}

impl AppState {
    pub fn new(dashboard: DashboardState) -> Self {
        Self {
            dashboard,
            events: None,
            ready: Arc::new(AtomicBool::new(true)),
            metrics_renderer: None,
        }
    }

    pub fn with_event_store(mut self, store: Arc<EventStore>) -> Self {
        self.events = Some(store);
        self
    }

    pub fn with_metrics_renderer(mut self, renderer: fn() -> String) -> Self {
        self.metrics_renderer = Some(renderer);
        self
    }

    /// Set readiness state
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    /// Check if ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
}

/// Create the API router
pub fn api_router(state: DashboardState) -> Router {
    api_router_with_events(AppState::new(state))
}

/// Create the API router with event store
pub fn api_router_with_events(state: AppState) -> Router {
    let mut router = Router::new()
        // API endpoints
        .route("/api/snapshot", get(get_snapshot))
        .route("/api/identity", get(get_identity))
        .route("/api/policy", get(get_policy))
        .route("/api/observe", get(get_observe))
        .route("/api/budget", get(get_budget))
        .route("/api/budget/primitives", get(get_budget_primitives))
        .route("/api/proxy", get(get_proxy))
        .route("/api/health", get(get_health))
        .route("/api/events", get(get_events))
        .route("/api/clusters", get(get_clusters))
        .route("/api/rollups", get(get_rollups))
        .route("/api/events/:event_id/payload", get(get_event_payload))
        .route("/api/events/stream/stats", get(get_event_stream_stats))
        .route("/api/agents", get(get_agents))
        .route("/api/crypto/status", get(get_crypto_status))
        .route("/api/crypto/merkle/recent", get(get_crypto_merkle_recent))
        // Advanced budget endpoints
        .route("/api/budget/advanced", get(get_advanced_budget))
        .route("/api/metrics/identity", get(get_identity))
        .route("/api/metrics/policy", get(get_policy))
        .route("/api/metrics/observe", get(get_observe))
        .route("/api/metrics/budget", get(get_advanced_budget))
        .route("/api/metrics/budget/primitives", get(get_budget_primitives))
        .route("/api/metrics/proxy", get(get_proxy))
        // Production health check endpoints
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics));

    // Add WebSocket route if event store is available
    if let Some(ref events) = state.events {
        router = router.route(
            "/api/events/stream",
            get({
                let events = events.clone();
                move |ws, query| event_stream_handler(ws, State(events.clone()), query)
            }),
        );
    }

    router.with_state(state)
}

/// Get combined dashboard snapshot in one request.
async fn get_snapshot(State(state): State<AppState>) -> Json<ApiResponse<DashboardSnapshot>> {
    Json(ApiResponse::new(
        &state.dashboard,
        DashboardSnapshot {
            identity: state.dashboard.identity(),
            policy: state.dashboard.policy(),
            observe: observe_metrics_for_state(&state),
            budget: state.dashboard.budget(),
            proxy: proxy_metrics_for_state(&state),
        },
    ))
}

/// Query parameters for events endpoint
#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub since_seq: Option<i64>,
}

#[derive(Deserialize)]
pub struct ClustersQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub since_seq: Option<i64>,
}

#[derive(Deserialize)]
pub struct RollupsQuery {
    #[serde(default = "default_rollup_limit")]
    pub limit: usize,
}

#[derive(Deserialize)]
pub struct CryptoMerkleQuery {
    #[serde(default = "default_crypto_merkle_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

fn default_rollup_limit() -> usize {
    240
}

fn default_crypto_merkle_limit() -> usize {
    20
}

#[derive(Deserialize)]
pub struct EventPayloadQuery {
    pub part: String,
}

#[derive(Serialize)]
pub struct EventPayloadData {
    pub event_id: String,
    pub part: String,
    pub content: String,
}

/// Get identity metrics
async fn get_identity(State(state): State<AppState>) -> Json<ApiResponse<IdentityMetrics>> {
    Json(ApiResponse::new(
        &state.dashboard,
        state.dashboard.identity(),
    ))
}

/// Get policy metrics
async fn get_policy(State(state): State<AppState>) -> Json<ApiResponse<PolicyMetrics>> {
    Json(ApiResponse::new(&state.dashboard, state.dashboard.policy()))
}

/// Get observe metrics
async fn get_observe(State(state): State<AppState>) -> Json<ApiResponse<ObserveMetrics>> {
    Json(ApiResponse::new(
        &state.dashboard,
        observe_metrics_for_state(&state),
    ))
}

/// Get budget metrics
async fn get_budget(State(state): State<AppState>) -> Json<ApiResponse<BudgetMetrics>> {
    Json(ApiResponse::new(&state.dashboard, state.dashboard.budget()))
}

/// Get canonical budget primitives for unified dashboard + observability exports.
async fn get_budget_primitives(
    State(state): State<AppState>,
) -> Json<ApiResponse<BudgetPrimitives>> {
    Json(ApiResponse::new(
        &state.dashboard,
        state.dashboard.budget_primitives(),
    ))
}

/// Get proxy metrics
async fn get_proxy(State(state): State<AppState>) -> Json<ApiResponse<ProxyMetrics>> {
    Json(ApiResponse::new(&state.dashboard, proxy_metrics_for_state(&state)))
}

/// Get advanced budget metrics (for Developer and CFO views)
async fn get_advanced_budget(
    State(state): State<AppState>,
) -> Json<ApiResponse<AdvancedBudgetMetrics>> {
    Json(ApiResponse::new(
        &state.dashboard,
        state.dashboard.advanced_budget(),
    ))
}

/// Get recent events
async fn get_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Json<ApiResponse<EventsSummary>> {
    let summary = if let Some(ref events) = state.events {
        if let Some(since_seq) = query.since_seq {
            events.get_events_since_seq(since_seq, query.limit)
        } else {
            events.get_events(query.limit)
        }
    } else {
        EventsSummary {
            total_events: 0,
            events: Vec::new(),
        }
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Get materialized request/response clusters.
async fn get_clusters(
    State(state): State<AppState>,
    Query(query): Query<ClustersQuery>,
) -> Json<ApiResponse<ClustersSummary>> {
    let summary = if let Some(ref events) = state.events {
        if let Some(since_seq) = query.since_seq {
            events.get_clusters_since_seq(since_seq, query.limit)
        } else {
            events.get_clusters(query.limit)
        }
    } else {
        ClustersSummary {
            total_clusters: 0,
            clusters: Vec::new(),
        }
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Get materialized minute rollups.
async fn get_rollups(
    State(state): State<AppState>,
    Query(query): Query<RollupsQuery>,
) -> Json<ApiResponse<RollupsSummary>> {
    let summary = if let Some(ref events) = state.events {
        events.get_rollups_1m(query.limit)
    } else {
        RollupsSummary {
            total_rows: 0,
            rows: Vec::new(),
        }
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Get full payload body for an event part (request|response|content).
async fn get_event_payload(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
    Query(query): Query<EventPayloadQuery>,
) -> Json<ApiResponse<EventPayloadData>> {
    let requested_part = query.part.to_ascii_lowercase();
    let part = match requested_part.as_str() {
        "request" | "response" | "content" => requested_part,
        _ => "content".to_string(),
    };

    let content = if let Some(ref events) = state.events {
        events
            .get_event_payload(&event_id, &part)
            .unwrap_or_default()
    } else {
        String::new()
    };

    Json(ApiResponse::new(
        &state.dashboard,
        EventPayloadData {
            event_id,
            part,
            content,
        },
    ))
}

/// Get agent statistics
async fn get_agents(State(state): State<AppState>) -> Json<ApiResponse<AgentsSummary>> {
    let summary = if let Some(ref events) = state.events {
        events.get_agents()
    } else {
        AgentsSummary {
            total_agents: 0,
            agents: Vec::new(),
        }
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Get websocket stream reliability/backpressure telemetry.
async fn get_event_stream_stats(State(state): State<AppState>) -> Json<ApiResponse<StreamStats>> {
    let stats = if let Some(ref events) = state.events {
        events.stream_stats()
    } else {
        StreamStats {
            lagged_receivers: 0,
            lagged_events: 0,
            backfill_batches: 0,
            backfilled_events: 0,
            broadcast_send_failures: 0,
            latest_seq: 0,
        }
    };

    Json(ApiResponse::new(&state.dashboard, stats))
}

/// Get crypto pipeline status summary.
async fn get_crypto_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<CryptoStatusSummary>> {
    let summary = if let Some(ref events) = state.events {
        events.get_crypto_status()
    } else {
        CryptoStatusSummary::default()
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Get recent Merkle seals with lightweight verification indicators.
async fn get_crypto_merkle_recent(
    State(state): State<AppState>,
    Query(query): Query<CryptoMerkleQuery>,
) -> Json<ApiResponse<CryptoMerkleSummary>> {
    let summary = if let Some(ref events) = state.events {
        events.get_crypto_merkle_recent(query.limit)
    } else {
        CryptoMerkleSummary {
            total_batches: 0,
            seals: Vec::new(),
        }
    };

    Json(ApiResponse::new(&state.dashboard, summary))
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_secs: u64,
    pub event_store_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_decisions: Option<FilterDecisionMetrics>,
}

/// Health check endpoint
async fn get_health(State(state): State<AppState>) -> Json<HealthResponse> {
    let filter_decisions = state.metrics_renderer.map(|renderer| {
        let metrics_text = renderer();
        parse_filter_decisions_metric(metrics_text.as_str())
    });

    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_secs: state.dashboard.uptime_secs(),
        event_store_enabled: state.events.is_some(),
        filter_decisions,
    })
}

fn parse_filter_decisions_metric(metrics_text: &str) -> FilterDecisionMetrics {
    let mut out = FilterDecisionMetrics::default();

    for line in metrics_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || !trimmed.starts_with("soth_filter_decisions_total")
        {
            continue;
        }

        let (head, value_raw) = match trimmed.rsplit_once(' ') {
            Some(parts) => parts,
            None => continue,
        };
        let value = match value_raw.trim().parse::<f64>() {
            Ok(v) if v.is_finite() && v >= 0.0 => v as u64,
            _ => continue,
        };

        out.total = out.total.saturating_add(value);

        let labels = match parse_prometheus_labels(head) {
            Some(v) => v,
            None => continue,
        };
        if let Some(phase) = labels.get("phase") {
            *out.by_phase.entry(phase.clone()).or_insert(0) += value;
        }
        if let Some(decision) = labels.get("decision") {
            *out.by_decision.entry(decision.clone()).or_insert(0) += value;
        }
    }

    out
}

fn parse_prometheus_labels(metric_head: &str) -> Option<std::collections::HashMap<String, String>> {
    let start = metric_head.find('{')?;
    let end = metric_head.rfind('}')?;
    if end <= start + 1 {
        return Some(std::collections::HashMap::new());
    }

    let mut out = std::collections::HashMap::new();
    let body = &metric_head[start + 1..end];
    for pair in body.split(',') {
        let (key_raw, value_raw) = match pair.split_once('=') {
            Some(v) => v,
            None => continue,
        };
        let key = key_raw.trim();
        if key.is_empty() {
            continue;
        }
        let value = value_raw.trim().trim_matches('"').to_string();
        out.insert(key.to_string(), value);
    }
    Some(out)
}

// === Production Health Check Endpoints ===

/// Liveness probe - returns 200 if the service is running
/// Used by Kubernetes to determine if the container should be restarted
async fn healthz() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::OK, "OK")
}

/// Readiness probe - returns 200 if the service is ready to accept traffic
/// Used by Kubernetes to determine if traffic should be sent to this pod
async fn readyz(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    if state.is_ready() {
        (axum::http::StatusCode::OK, "READY")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "NOT READY")
    }
}

/// Prometheus metrics endpoint
async fn metrics(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    if let Some(renderer) = state.metrics_renderer {
        let metrics_output = renderer();
        (
            axum::http::StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            metrics_output,
        )
    } else {
        (
            axum::http::StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            "# No metrics configured\n".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn make_request(app: Router, uri: &str) -> (StatusCode, String) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        (status, body_str)
    }

    #[tokio::test]
    async fn test_identity_endpoint() {
        let state = DashboardState::new();
        state.record_identity_verification("did:key:z123", true);

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/identity").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"successful\":1"));
    }

    #[tokio::test]
    async fn test_policy_endpoint() {
        let state = DashboardState::new();
        state.record_policy_evaluation(true, None);

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/policy").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"allowed\":1"));
    }

    #[tokio::test]
    async fn test_observe_endpoint() {
        let state = DashboardState::new();
        state.record_request();

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/observe").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"requests\":1"));
    }

    #[tokio::test]
    async fn test_budget_endpoint() {
        let state = DashboardState::new();
        state.record_token_usage("gpt-4o", 100, 0.01);

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/budget").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_tokens\":100"));
    }

    #[tokio::test]
    async fn test_budget_primitives_endpoint() {
        let state = DashboardState::new();
        state.record_proxy_request(
            Some("req-budget-routes"),
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
        );
        state.record_proxy_response(
            Some("req-budget-routes"),
            "openai",
            200,
            90,
            Some("gpt-4o"),
            Some(50),
            Some(75),
            Some(0.0125),
        );

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/budget/primitives").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_input_tokens\":50"));
        assert!(body.contains("\"total_output_tokens\":75"));
        assert!(body.contains("\"provider_breakdown\""));
    }

    #[tokio::test]
    async fn test_proxy_endpoint() {
        let state = DashboardState::new();
        state.record_proxy_request(
            Some("req-openai-route-test"),
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
        );

        let app = api_router(state);
        let (status, body) = make_request(app, "/api/proxy").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_requests\":1"));
        assert!(body.contains("\"openai\""));
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/health").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"status\":\"ok\""));
    }

    #[tokio::test]
    async fn test_events_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/events").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_events\":0"));
    }

    #[tokio::test]
    async fn test_agents_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/agents").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_agents\":0"));
    }

    #[tokio::test]
    async fn test_crypto_status_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/crypto/status").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_events\":0"));
        assert!(body.contains("\"merkle_batches\":0"));
    }

    #[tokio::test]
    async fn test_crypto_merkle_recent_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/crypto/merkle/recent").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_batches\":0"));
        assert!(body.contains("\"seals\":[]"));
    }

    #[tokio::test]
    async fn test_clusters_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/clusters").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_clusters\":0"));
        assert!(body.contains("\"clusters\":[]"));
    }

    #[tokio::test]
    async fn test_rollups_endpoint_no_store() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/api/rollups").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"total_rows\":0"));
        assert!(body.contains("\"rows\":[]"));
    }

    #[tokio::test]
    async fn test_healthz_endpoint() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/healthz").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "OK");
    }

    #[tokio::test]
    async fn test_readyz_endpoint_ready() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/readyz").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "READY");
    }

    #[tokio::test]
    async fn test_readyz_endpoint_not_ready() {
        let state = DashboardState::new();
        let app_state = AppState::new(state);
        app_state.set_ready(false);
        let app = api_router_with_events(app_state);
        let (status, body) = make_request(app, "/readyz").await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "NOT READY");
    }

    #[test]
    fn test_parse_filter_decisions_metric_aggregates_labels() {
        let metrics = r#"
# HELP soth_filter_decisions_total Total host filter decisions by phase and decision
# TYPE soth_filter_decisions_total counter
soth_filter_decisions_total{phase="http",decision="intercept"} 11
soth_filter_decisions_total{phase="http",decision="tunnel"} 3
soth_filter_decisions_total{phase="connect",decision="block"} 1
"#;

        let parsed = parse_filter_decisions_metric(metrics);
        assert_eq!(parsed.total, 15);
        assert_eq!(parsed.by_decision.get("intercept").copied(), Some(11));
        assert_eq!(parsed.by_decision.get("tunnel").copied(), Some(3));
        assert_eq!(parsed.by_decision.get("block").copied(), Some(1));
        assert_eq!(parsed.by_phase.get("http").copied(), Some(14));
        assert_eq!(parsed.by_phase.get("connect").copied(), Some(1));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_no_renderer() {
        let state = DashboardState::new();
        let app = api_router(state);
        let (status, body) = make_request(app, "/metrics").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("No metrics configured"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_with_renderer() {
        fn test_renderer() -> String {
            "# HELP test_metric A test metric\ntest_metric 42\n".to_string()
        }

        let state = DashboardState::new();
        let app_state = AppState::new(state).with_metrics_renderer(test_renderer);
        let app = api_router_with_events(app_state);
        let (status, body) = make_request(app, "/metrics").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("test_metric 42"));
    }
}
