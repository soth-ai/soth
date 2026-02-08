//! API routes for the dashboard

use crate::event_store::{
    AgentsSummary, ClustersSummary, EventStore, EventsSummary, RollupsSummary, StreamStats,
};
use crate::state::{
    AdvancedBudgetMetrics, BudgetMetrics, BudgetPrimitives, DashboardState, IdentityMetrics,
    ObserveMetrics, PolicyMetrics, ProxyMetrics,
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
            observe: state.dashboard.observe(),
            budget: state.dashboard.budget(),
            proxy: state.dashboard.proxy(),
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

fn default_limit() -> usize {
    100
}

fn default_rollup_limit() -> usize {
    240
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
        state.dashboard.observe(),
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
    Json(ApiResponse::new(&state.dashboard, state.dashboard.proxy()))
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

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_secs: u64,
    pub event_store_enabled: bool,
}

/// Health check endpoint
async fn get_health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_secs: state.dashboard.uptime_secs(),
        event_store_enabled: state.events.is_some(),
    })
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
