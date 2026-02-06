//! HTTP transport implementation
//!
//! Provides simple HTTP POST interface for request/response communication.

use super::{AsyncMessageHandler, Transport, TransportConfig};
use crate::error::ProxyError;
use crate::protocol::{JsonRpcMessage, JsonRpcResponse, JsonRpcError, RequestId};
use async_trait::async_trait;
use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Shared state for HTTP transport
struct HttpState {
    /// Message handler
    handler: AsyncMessageHandler,
    /// Configuration
    #[allow(dead_code)]
    config: TransportConfig,
}

/// HTTP transport for simple request/response communication
pub struct HttpTransport {
    /// Listen port
    port: u16,
    /// Configuration
    config: TransportConfig,
    /// Message handler
    handler: Option<AsyncMessageHandler>,
    /// Cancellation token
    cancel: Option<CancellationToken>,
    /// Server handle
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HttpTransport {
    /// Create a new HTTP transport
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
    fn create_router(state: Arc<HttpState>) -> Router {
        Router::new()
            .route("/", post(handle_request))
            .route("/mcp", post(handle_request))
            .route("/jsonrpc", post(handle_request))
            .route("/health", get(handle_health))
            .with_state(state)
    }
}

/// Health check handler
async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "transport": "http"
    }))
}

/// Handle incoming JSON-RPC request
async fn handle_request(
    State(state): State<Arc<HttpState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Parse the message
    let msg = match JsonRpcMessage::parse(body.clone()) {
        Ok(m) => m,
        Err(e) => {
            // Try to extract ID from the request
            let id = body
                .get("id")
                .and_then(|v| {
                    if v.is_string() {
                        Some(RequestId::String(v.as_str().unwrap().to_string()))
                    } else if v.is_i64() {
                        Some(RequestId::Number(v.as_i64().unwrap()))
                    } else {
                        None
                    }
                })
                .unwrap_or(RequestId::Null);

            return Json(JsonRpcResponse::error(id, e));
        }
    };

    // Get the request ID for the response
    let request_id = match &msg {
        JsonRpcMessage::Request(req) => req.id.clone().unwrap_or(RequestId::Null),
        JsonRpcMessage::Response(resp) => resp.id.clone(),
    };

    // Process through handler
    match (state.handler)(msg).await {
        Ok(Some(response)) => match response {
            JsonRpcMessage::Response(resp) => Json(resp),
            JsonRpcMessage::Request(req) => {
                // Convert request to response (shouldn't happen normally)
                Json(JsonRpcResponse::success(
                    request_id,
                    serde_json::to_value(&req).unwrap_or_default(),
                ))
            }
        },
        Ok(None) => {
            // No response needed (notification)
            Json(JsonRpcResponse::success(
                request_id,
                serde_json::json!({"status": "accepted"}),
            ))
        }
        Err(e) => {
            error!("Handler error: {}", e);
            Json(JsonRpcResponse::error(
                request_id,
                JsonRpcError::internal_error(),
            ))
        }
    }
}

/// Handle batch requests
#[allow(dead_code)]
async fn handle_batch(
    state: Arc<HttpState>,
    requests: Vec<serde_json::Value>,
) -> Vec<JsonRpcResponse> {
    let mut responses = Vec::with_capacity(requests.len());

    for body in requests {
        let msg = match JsonRpcMessage::parse(body.clone()) {
            Ok(m) => m,
            Err(e) => {
                let id = body
                    .get("id")
                    .and_then(|v| v.as_i64())
                    .map(RequestId::Number)
                    .unwrap_or(RequestId::Null);
                responses.push(JsonRpcResponse::error(id, e));
                continue;
            }
        };

        let request_id = match &msg {
            JsonRpcMessage::Request(req) => req.id.clone().unwrap_or(RequestId::Null),
            JsonRpcMessage::Response(resp) => resp.id.clone(),
        };

        match (state.handler)(msg).await {
            Ok(Some(JsonRpcMessage::Response(resp))) => {
                responses.push(resp);
            }
            Ok(Some(JsonRpcMessage::Request(_))) => {
                responses.push(JsonRpcResponse::success(
                    request_id,
                    serde_json::json!({"status": "accepted"}),
                ));
            }
            Ok(None) => {
                // Notification - no response added to batch
            }
            Err(_) => {
                responses.push(JsonRpcResponse::error(
                    request_id,
                    JsonRpcError::internal_error(),
                ));
            }
        }
    }

    responses
}

#[async_trait]
impl Transport for HttpTransport {
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let handler = self.handler.take()
            .ok_or_else(|| ProxyError::Transport("No handler set".to_string()))?;

        let state = Arc::new(HttpState {
            handler,
            config: self.config.clone(),
        });

        let router = Self::create_router(state);
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], self.port));

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ProxyError::Transport(format!("Failed to bind: {e}")))?;

        info!("HTTP transport listening on {}", addr);

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

        info!("HTTP transport stopped");
        Ok(())
    }

    async fn send(&self, _message: JsonRpcMessage) -> Result<(), ProxyError> {
        // HTTP is request/response only; can't push messages
        Err(ProxyError::Transport("HTTP transport doesn't support push".to_string()))
    }

    fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    fn name(&self) -> &'static str {
        "http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_creation() {
        let transport = HttpTransport::new(8080, TransportConfig::default());
        assert_eq!(transport.port, 8080);
        assert_eq!(transport.name(), "http");
    }
}
