//! SOTH Dashboard - Real-time metrics dashboard server
//!
//! Provides a lightweight web dashboard with 5 panels (Identity, Policy, Observability, Budget, Proxy)
//! that displays real-time metrics via JSON API and a minimal HTML/JS frontend.
//!
//! Additionally provides:
//! - Live event feed from wrap sessions via WebSocket
//! - Agent tracking and statistics

pub mod event_store;
pub mod routes;
pub mod server;
pub mod state;
pub mod websocket;

pub use event_store::{
    AgentStats, AgentsSummary, ClustersSummary, EventStore, EventsSummary, RollupsSummary,
};
pub use routes::{api_router, api_router_with_events, AppState};
pub use server::DashboardServer;
pub use state::{
    BudgetAlert, BudgetMetrics, BudgetPrimitives, BudgetRequestPrimitive, DashboardState,
    DenialEntry, DidEntry, IdentityMetrics, ObserveMetrics, PolicyMetrics, ProviderBudgetPrimitive,
    ProviderTokens, ProxyMetrics, ProxyRequestEntry, ProxyStatus,
};
