//! Dashboard HTTP server

use crate::event_store::EventStore;
use crate::routes::{api_router_with_events, AppState};
use crate::state::DashboardState;
use axum::{response::Html, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

/// Dashboard server
pub struct DashboardServer {
    state: DashboardState,
    port: u16,
    event_store: Option<Arc<EventStore>>,
}

impl DashboardServer {
    /// Create a new dashboard server
    pub fn new(state: DashboardState, port: u16) -> Self {
        Self {
            state,
            port,
            event_store: None,
        }
    }

    /// Enable event store for live feed
    pub fn with_event_store(mut self) -> Self {
        if let Some(store) = EventStore::with_default_path() {
            self.event_store = Some(Arc::new(store));
        }
        self
    }

    /// Enable event store with custom path
    pub fn with_event_store_path(mut self, path: std::path::PathBuf) -> Self {
        self.event_store = Some(Arc::new(EventStore::new(path)));
        self
    }

    /// Run the dashboard server
    pub async fn run(self) -> std::io::Result<()> {
        self.run_with_shutdown(std::future::pending::<()>()).await
    }

    /// Run the dashboard server with graceful shutdown.
    pub async fn run_with_shutdown<F>(self, shutdown: F) -> std::io::Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        // Build app state
        let app_state = AppState::new(self.state);

        let app_state = if let Some(ref store) = self.event_store {
            app_state.with_event_store(store.clone())
        } else {
            app_state
        };

        // Load initial events and start watcher
        let mut watcher_task = None;
        if let Some(ref store) = self.event_store {
            let store_clone = store.clone();
            let store_path = store.path().display().to_string();

            // Load initial events
            if let Err(e) = store.load_initial().await {
                tracing::warn!("Failed to load initial events: {}", e);
            }

            // Start file watcher in background
            watcher_task = Some(tokio::spawn(async move {
                store_clone.watch().await;
            }));

            info!("Event store enabled, watching {}", store_path);
        }

        let app = Router::new()
            .route("/", get(serve_dashboard))
            .merge(api_router_with_events(app_state))
            .layer(CorsLayer::permissive());

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        info!("Dashboard API available at http://{}", addr);

        if self.event_store.is_some() {
            info!(
                "WebSocket streaming available at ws://{}/api/events/stream",
                addr
            );
        }

        info!("For the full React dashboard, run: cd dashboard && npm run dev");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        let serve_result = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await;

        if let Some(task) = watcher_task {
            task.abort();
        }

        serve_result
    }
}

/// Serve the embedded dashboard HTML (lightweight fallback)
async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}
