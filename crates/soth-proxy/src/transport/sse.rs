//! SSE (Server-Sent Events) transport implementation
//!
//! Provides HTTP server with SSE for real-time messaging and POST for requests.

use super::{AsyncMessageHandler, Transport, TransportConfig};
use crate::error::ProxyError;
use crate::protocol::{JsonRpcMessage, JsonRpcResponse, JsonRpcError, RequestId};
use async_trait::async_trait;
use axum::{
    extract::{State, Path},
    response::{sse::{Event, Sse}, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Session state for SSE connections
struct Session {
    /// Session ID
    #[allow(dead_code)]
    id: String,
    /// Channel to send events to this session
    tx: broadcast::Sender<JsonRpcMessage>,
}

/// Shared state for the SSE transport
struct SseState {
    /// Active sessions
    sessions: RwLock<HashMap<String, Session>>,
    /// Message handler
    handler: AsyncMessageHandler,
    /// Configuration
    config: TransportConfig,
}

/// SSE transport for web clients
pub struct SseTransport {
    /// Listen port
    port: u16,
    /// Configuration
    config: TransportConfig,
    /// Message handler
    handler: Option<AsyncMessageHandler>,
    /// Cancellation token for shutdown
    cancel: Option<CancellationToken>,
    /// Server handle
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SseTransport {
    /// Create a new SSE transport
    pub fn new(port: u16, config: TransportConfig) -> Self {
        Self {
            port,
            config,
            handler: None,
            cancel: None,
            server_handle: None,
        }
    }

    /// Create the router
    fn create_router(state: Arc<SseState>) -> Router {
        Router::new()
            .route("/sse", get(handle_sse))
            .route("/sse/:session_id", get(handle_sse_with_session))
            .route("/message", post(handle_message))
            .route("/message/:session_id", post(handle_message_with_session))
            .route("/health", get(handle_health))
            .with_state(state)
    }
}

/// Health check handler
async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "transport": "sse"
    }))
}

/// SSE endpoint - creates a new session
async fn handle_sse(
    State(state): State<Arc<SseState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session_id = uuid::Uuid::new_v4().to_string();
    create_sse_stream(state, session_id).await
}

/// SSE endpoint with explicit session ID
async fn handle_sse_with_session(
    State(state): State<Arc<SseState>>,
    Path(session_id): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    create_sse_stream(state, session_id).await
}

/// Create an SSE stream for a session
async fn create_sse_stream(
    state: Arc<SseState>,
    session_id: String,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, _rx) = broadcast::channel::<JsonRpcMessage>(state.config.buffer_size);

    // Store session
    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(
            session_id.clone(),
            Session {
                id: session_id.clone(),
                tx: tx.clone(),
            },
        );
    }

    info!("SSE session created: {}", session_id);

    // Create the stream
    let session_id_clone = session_id.clone();
    let state_clone = state.clone();

    let stream = async_stream::stream! {
        // Send session ID as first event
        yield Ok(Event::default()
            .event("session")
            .data(serde_json::json!({"session_id": session_id_clone}).to_string()));

        // Subscribe to receive messages
        let mut rx = tx.subscribe();

        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if let Ok(json) = msg.to_string() {
                        yield Ok(Event::default()
                            .event("message")
                            .data(json));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    debug!("SSE stream lagged by {} messages", n);
                    continue;
                }
            }
        }

        // Cleanup session on disconnect
        let mut sessions = state_clone.sessions.write().await;
        sessions.remove(&session_id_clone);
        info!("SSE session closed: {}", session_id_clone);
    };

    Sse::new(stream)
}

/// Handle incoming message (POST)
async fn handle_message(
    State(state): State<Arc<SseState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    process_message(state, None, body).await
}

/// Handle incoming message with session ID
async fn handle_message_with_session(
    State(state): State<Arc<SseState>>,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    process_message(state, Some(session_id), body).await
}

/// Process an incoming message
async fn process_message(
    state: Arc<SseState>,
    session_id: Option<String>,
    body: serde_json::Value,
) -> Response {
    // Parse the message
    let msg = match JsonRpcMessage::parse(body) {
        Ok(m) => m,
        Err(e) => {
            return Json(JsonRpcResponse::error(
                RequestId::Null,
                e,
            )).into_response();
        }
    };

    // Process through handler
    let result = (state.handler)(msg).await;

    match result {
        Ok(Some(response)) => {
            // If we have a session, also send via SSE
            if let Some(sid) = session_id {
                let sessions = state.sessions.read().await;
                if let Some(session) = sessions.get(&sid) {
                    let _ = session.tx.send(response.clone());
                }
            }

            // Return as HTTP response
            match response {
                JsonRpcMessage::Response(resp) => Json(resp).into_response(),
                JsonRpcMessage::Request(req) => Json(req).into_response(),
            }
        }
        Ok(None) => {
            // No response (notification was handled)
            Json(serde_json::json!({"status": "accepted"})).into_response()
        }
        Err(_) => {
            Json(JsonRpcResponse::error(
                RequestId::Null,
                JsonRpcError::internal_error(),
            )).into_response()
        }
    }
}

#[async_trait]
impl Transport for SseTransport {
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let handler = self.handler.take()
            .ok_or_else(|| ProxyError::Transport("No handler set".to_string()))?;

        let state = Arc::new(SseState {
            sessions: RwLock::new(HashMap::new()),
            handler,
            config: self.config.clone(),
        });

        let router = Self::create_router(state);
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], self.port));

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ProxyError::Transport(format!("Failed to bind: {e}")))?;

        info!("SSE transport listening on {}", addr);

        self.cancel = Some(cancel.clone());

        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    cancel.cancelled().await;
                })
                .await
                .ok();
        });

        self.server_handle = Some(handle);

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ProxyError> {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }

        if let Some(handle) = self.server_handle.take() {
            handle.await.ok();
        }

        info!("SSE transport stopped");
        Ok(())
    }

    async fn send(&self, _message: JsonRpcMessage) -> Result<(), ProxyError> {
        // SSE is server-push only; messages are sent via session channels
        Ok(())
    }

    fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    fn name(&self) -> &'static str {
        "sse"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_transport_creation() {
        let transport = SseTransport::new(3000, TransportConfig::default());
        assert_eq!(transport.port, 3000);
        assert_eq!(transport.name(), "sse");
    }
}
