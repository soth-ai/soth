//! Request forwarding layer

use super::middleware::{error_response, Layer, LayerResult, RequestContext};
use crate::error::ProxyError;
use crate::protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, warn};

/// Forward layer configuration
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum pending requests
    pub max_pending: usize,
    /// Whether to forward notifications
    pub forward_notifications: bool,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_pending: 1000,
            forward_notifications: true,
        }
    }
}

/// Pending request tracking
struct PendingRequest {
    /// Response sender
    response_tx: oneshot::Sender<JsonRpcResponse>,
    /// Request timestamp
    timestamp: chrono::DateTime<chrono::Utc>,
}

/// Forward layer for sending requests to upstream
pub struct ForwardLayer {
    /// Configuration
    config: ForwardConfig,
    /// Outgoing message sender
    outgoing_tx: mpsc::Sender<JsonRpcMessage>,
    /// Pending requests awaiting response
    pending: Arc<RwLock<HashMap<String, PendingRequest>>>,
}

impl ForwardLayer {
    /// Create a new forward layer
    pub fn new(
        config: ForwardConfig,
        outgoing_tx: mpsc::Sender<JsonRpcMessage>,
    ) -> Self {
        Self {
            config,
            outgoing_tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Handle an incoming response from upstream
    pub async fn handle_response(&self, response: JsonRpcResponse) -> bool {
        let id_str = response.id.to_string();

        let mut pending = self.pending.write().await;
        if let Some(req) = pending.remove(&id_str) {
            let _ = req.response_tx.send(response);
            true
        } else {
            warn!("Received response for unknown request: {}", id_str);
            false
        }
    }

    /// Forward a request and wait for response
    async fn forward_request(
        &self,
        request: JsonRpcRequest,
    ) -> Result<JsonRpcResponse, ProxyError> {
        let id = request.id.clone().unwrap_or(RequestId::Null);
        let id_str = id.to_string();

        // Check pending limit
        {
            let pending = self.pending.read().await;
            if pending.len() >= self.config.max_pending {
                return Err(ProxyError::Transport("Too many pending requests".into()));
            }
        }

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending request
        {
            let mut pending = self.pending.write().await;
            pending.insert(
                id_str.clone(),
                PendingRequest {
                    response_tx: tx,
                    timestamp: chrono::Utc::now(),
                },
            );
        }

        // Send request
        self.outgoing_tx
            .send(JsonRpcMessage::Request(request))
            .await
            .map_err(|e| ProxyError::Transport(format!("Send failed: {e}")))?;

        debug!("Forwarded request: {}", id_str);

        // Wait for response with timeout
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        match timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => {
                debug!("Received response for: {}", id_str);
                Ok(response)
            }
            Ok(Err(_)) => {
                // Channel closed
                let mut pending = self.pending.write().await;
                pending.remove(&id_str);
                Err(ProxyError::Transport("Response channel closed".into()))
            }
            Err(_) => {
                // Timeout
                let mut pending = self.pending.write().await;
                pending.remove(&id_str);
                Err(ProxyError::Timeout(self.config.timeout_ms))
            }
        }
    }

    /// Forward a notification (fire and forget)
    async fn forward_notification(&self, request: JsonRpcRequest) -> Result<(), ProxyError> {
        let method = request.method.clone();
        self.outgoing_tx
            .send(JsonRpcMessage::Request(request))
            .await
            .map_err(|e| ProxyError::Transport(format!("Send failed: {e}")))?;
        debug!("Forwarded notification: {}", method);
        Ok(())
    }

    /// Clean up stale pending requests
    pub async fn cleanup_stale(&self, max_age_ms: u64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::milliseconds(max_age_ms as i64);
        let mut pending = self.pending.write().await;

        pending.retain(|id, req| {
            if req.timestamp < cutoff {
                warn!("Cleaning up stale pending request: {}", id);
                false
            } else {
                true
            }
        });
    }
}

impl Layer for ForwardLayer {
    fn process<'a>(
        &'a self,
        _ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
        Box::pin(async move {
            match message {
                JsonRpcMessage::Request(req) => {
                    if req.is_notification() {
                        // Handle notification
                        if self.config.forward_notifications {
                            match self.forward_notification(req).await {
                                Ok(_) => LayerResult::Drop, // No response for notifications
                                Err(e) => {
                                    error!("Failed to forward notification: {}", e);
                                    LayerResult::Drop
                                }
                            }
                        } else {
                            LayerResult::Drop
                        }
                    } else {
                        // Handle request
                        let id = req.id.clone().unwrap_or(RequestId::Null);

                        match self.forward_request(req).await {
                            Ok(response) => {
                                LayerResult::Response(response)
                            }
                            Err(ProxyError::Timeout(_)) => {
                                error_response(id, JsonRpcError::request_timeout())
                            }
                            Err(e) => {
                                error!("Forward error: {}", e);
                                error_response(id, JsonRpcError::internal_error())
                            }
                        }
                    }
                }
                JsonRpcMessage::Response(resp) => {
                    // Responses should be handled via handle_response(), not through the pipeline
                    // But if they come through here, just pass them along
                    LayerResult::Response(resp)
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "forward"
    }
}

/// Simple pass-through layer that just returns the message
/// Useful for testing or when no upstream is configured
pub struct PassthroughLayer;

impl Layer for PassthroughLayer {
    fn process(
        &self,
        _ctx: &mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + '_>> {
        Box::pin(async move {
            LayerResult::Continue(message)
        })
    }

    fn name(&self) -> &'static str {
        "passthrough"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_passthrough_layer() {
        let layer = PassthroughLayer;
        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "test",
            None,
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[test]
    fn test_forward_config_default() {
        let config = ForwardConfig::default();
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.max_pending, 1000);
        assert!(config.forward_notifications);
    }
}
