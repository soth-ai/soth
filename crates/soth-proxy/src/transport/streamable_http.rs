//! Streamable HTTP transport implementation (MCP 2025-03-26)
//!
//! Implements the Streamable HTTP transport per the MCP specification:
//! - Single MCP endpoint supporting POST and GET methods
//! - Session management via `Mcp-Session-Id` header
//! - SSE streaming for server responses
//! - Batch request/response support
//! - Origin validation for DNS rebinding protection
//!
//! Reference: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports

use super::{AsyncMessageHandler, Transport, TransportConfig};
use crate::error::ProxyError;
use crate::protocol::{JsonRpcError, JsonRpcMessage, JsonRpcResponse, RequestId};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum::body::Bytes;
use dashmap::DashMap;
use futures::stream::Stream;
use std::collections::HashSet;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use uuid::Uuid;

/// Session state
#[derive(Debug)]
struct Session {
    /// Session ID
    id: String,
    /// Creation timestamp
    created_at: std::time::Instant,
    /// Last activity timestamp
    last_activity: std::sync::atomic::AtomicU64,
    /// Event counter for SSE IDs
    event_counter: AtomicU64,
    /// Pending server-initiated messages
    pending_messages: RwLock<Vec<JsonRpcMessage>>,
    /// Server-to-client message sender
    server_tx: broadcast::Sender<SseEvent>,
}

impl Session {
    fn new() -> Self {
        let (server_tx, _) = broadcast::channel(100);
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: std::time::Instant::now(),
            last_activity: AtomicU64::new(0),
            event_counter: AtomicU64::new(0),
            pending_messages: RwLock::new(Vec::new()),
            server_tx,
        }
    }

    fn touch(&self) {
        self.last_activity.store(
            self.created_at.elapsed().as_secs(),
            Ordering::Relaxed,
        );
    }

    fn next_event_id(&self) -> u64 {
        self.event_counter.fetch_add(1, Ordering::SeqCst)
    }

    fn subscribe(&self) -> broadcast::Receiver<SseEvent> {
        self.server_tx.subscribe()
    }
}

/// SSE event types
#[derive(Debug, Clone)]
enum SseEvent {
    Message(JsonRpcMessage),
    Ping,
}

/// Shared state for Streamable HTTP transport
struct StreamableHttpState {
    /// Message handler
    handler: AsyncMessageHandler,
    /// Configuration
    config: StreamableHttpConfig,
    /// Active sessions
    sessions: DashMap<String, Arc<Session>>,
    /// Allowed origins (empty = allow all)
    allowed_origins: HashSet<String>,
}

impl StreamableHttpState {
    fn validate_origin(&self, origin: Option<&HeaderValue>) -> bool {
        if self.allowed_origins.is_empty() {
            // If no origins configured, allow localhost only for security
            if let Some(origin) = origin {
                if let Ok(origin_str) = origin.to_str() {
                    return origin_str.starts_with("http://localhost")
                        || origin_str.starts_with("http://127.0.0.1")
                        || origin_str.starts_with("https://localhost")
                        || origin_str.starts_with("https://127.0.0.1");
                }
            }
            // Allow requests without Origin header (non-browser clients)
            return origin.is_none();
        }

        match origin {
            Some(origin) => {
                if let Ok(origin_str) = origin.to_str() {
                    self.allowed_origins.contains(origin_str)
                } else {
                    false
                }
            }
            // Allow requests without Origin (non-browser clients)
            None => true,
        }
    }

    fn get_session(&self, session_id: &str) -> Option<Arc<Session>> {
        self.sessions.get(session_id).map(|s| s.value().clone())
    }

    fn create_session(&self) -> Arc<Session> {
        let session = Arc::new(Session::new());
        self.sessions.insert(session.id.clone(), session.clone());
        session
    }

    fn remove_session(&self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }
}

/// Configuration for Streamable HTTP transport
#[derive(Debug, Clone)]
pub struct StreamableHttpConfig {
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
    /// Whether to require session IDs after initialization
    pub require_session: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// SSE keep-alive interval in seconds
    pub sse_keepalive_secs: u64,
}

impl Default for StreamableHttpConfig {
    fn default() -> Self {
        Self {
            session_timeout_secs: 3600,     // 1 hour
            require_session: true,
            max_batch_size: 100,
            sse_keepalive_secs: 30,
        }
    }
}

/// Streamable HTTP transport (MCP 2025-03-26)
pub struct StreamableHttpTransport {
    /// Listen port
    port: u16,
    /// Base configuration
    base_config: TransportConfig,
    /// Streamable HTTP specific config
    config: StreamableHttpConfig,
    /// Allowed origins for CORS
    allowed_origins: HashSet<String>,
    /// Message handler
    handler: Option<AsyncMessageHandler>,
    /// Cancellation token
    cancel: Option<CancellationToken>,
    /// Server handle
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl StreamableHttpTransport {
    /// Create a new Streamable HTTP transport
    pub fn new(port: u16, base_config: TransportConfig) -> Self {
        Self {
            port,
            base_config,
            config: StreamableHttpConfig::default(),
            allowed_origins: HashSet::new(),
            handler: None,
            cancel: None,
            server_handle: None,
        }
    }

    /// Set streamable HTTP specific configuration
    pub fn with_config(mut self, config: StreamableHttpConfig) -> Self {
        self.config = config;
        self
    }

    /// Add allowed origin for CORS
    pub fn with_allowed_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.insert(origin.into());
        self
    }

    /// Create the router
    fn create_router(state: Arc<StreamableHttpState>) -> Router {
        Router::new()
            .route("/mcp", post(handle_post).get(handle_get).delete(handle_delete))
            .route("/health", get(handle_health))
            .with_state(state)
    }
}

/// Health check handler
async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "transport": "streamable-http",
        "protocol_version": "2025-03-26"
    }))
}

/// Handle POST requests (client-to-server messages)
async fn handle_post(
    State(state): State<Arc<StreamableHttpState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    // Validate origin
    if !state.validate_origin(headers.get(header::ORIGIN)) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Invalid origin"}
            })),
        ).into_response();
    }

    // Check session ID for non-initialize requests
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Parse the message(s)
    let messages = if body.is_array() {
        // Batch request
        match serde_json::from_value::<Vec<serde_json::Value>>(body) {
            Ok(msgs) if msgs.len() > state.config.max_batch_size => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Batch too large"}
                    })),
                ).into_response();
            }
            Ok(msgs) => msgs,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {"code": -32700, "message": "Parse error"}
                    })),
                ).into_response();
            }
        }
    } else {
        vec![body]
    };

    // Check if this is an initialization request
    let is_initialize = messages.iter().any(|m| {
        m.get("method").and_then(|v| v.as_str()) == Some("initialize")
    });

    // Require session ID for non-initialize requests if configured
    if !is_initialize && state.config.require_session && session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Missing Mcp-Session-Id header"}
            })),
        ).into_response();
    }

    // Validate session if provided
    let session = if let Some(ref sid) = session_id {
        match state.get_session(sid) {
            Some(s) => {
                s.touch();
                Some(s)
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Session not found"}
                    })),
                ).into_response();
            }
        }
    } else {
        None
    };

    // Categorize messages
    let mut requests = Vec::new();
    let mut notifications_and_responses = Vec::new();

    for msg_value in messages {
        match JsonRpcMessage::parse(msg_value.clone()) {
            Ok(JsonRpcMessage::Request(req)) => {
                if req.id.is_some() {
                    requests.push((msg_value, req));
                } else {
                    notifications_and_responses.push(msg_value);
                }
            }
            Ok(JsonRpcMessage::Response(_)) => {
                notifications_and_responses.push(msg_value);
            }
            Err(_) => {
                // Invalid message - skip or error depending on batch
                continue;
            }
        }
    }

    // Handle notifications and responses (202 Accepted, no body)
    if requests.is_empty() {
        // Process notifications/responses
        for msg_value in notifications_and_responses {
            if let Ok(msg) = JsonRpcMessage::parse(msg_value) {
                let _ = (state.handler)(msg).await;
            }
        }
        return StatusCode::ACCEPTED.into_response();
    }

    // Handle requests - need to return responses
    let new_session = if is_initialize {
        Some(state.create_session())
    } else {
        None
    };

    let _active_session = new_session.as_ref().or(session.as_ref());

    // Process requests and collect responses
    let mut responses = Vec::new();

    for (_, req) in &requests {
        let msg = JsonRpcMessage::Request(req.clone());
        match (state.handler)(msg).await {
            Ok(Some(JsonRpcMessage::Response(resp))) => {
                responses.push(resp);
            }
            Ok(Some(JsonRpcMessage::Request(_))) => {
                // Server-initiated request - queue it
                // For now, just return an error
            }
            Ok(None) => {
                // No response (shouldn't happen for requests with ID)
            }
            Err(e) => {
                let id = req.id.clone().unwrap_or(RequestId::Null);
                responses.push(JsonRpcResponse::error(id, JsonRpcError::internal_error()));
                error!("Handler error: {}", e);
            }
        }
    }

    // Build response
    let mut response_builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");

    // Add session ID header if this was initialization
    if let Some(ref session) = new_session {
        response_builder = response_builder.header("mcp-session-id", &session.id);
    }

    // Return single response or batch
    let body = if responses.len() == 1 {
        serde_json::to_string(&responses[0]).unwrap()
    } else {
        serde_json::to_string(&responses).unwrap()
    };

    response_builder
        .body(Body::from(body))
        .unwrap()
}

/// Handle GET requests (SSE stream for server-to-client messages)
async fn handle_get(
    State(state): State<Arc<StreamableHttpState>>,
    headers: HeaderMap,
) -> Response {
    // Validate origin
    if !state.validate_origin(headers.get(header::ORIGIN)) {
        return (StatusCode::FORBIDDEN, "Invalid origin").into_response();
    }

    // Check Accept header
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !accept.contains("text/event-stream") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            "Must accept text/event-stream",
        ).into_response();
    }

    // Get session
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok());

    let session = match session_id {
        Some(sid) => match state.get_session(sid) {
            Some(s) => {
                s.touch();
                s
            }
            None => {
                return (StatusCode::NOT_FOUND, "Session not found").into_response();
            }
        },
        None if state.config.require_session => {
            return (StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id").into_response();
        }
        None => {
            // Create a temporary session for the stream
            state.create_session()
        }
    };

    // Check for Last-Event-ID (for resumption)
    let _last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Create SSE stream
    let stream = SseStream::new(session, state.config.sse_keepalive_secs);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Handle DELETE requests (terminate session)
async fn handle_delete(
    State(state): State<Arc<StreamableHttpState>>,
    headers: HeaderMap,
) -> Response {
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok());

    match session_id {
        Some(sid) => {
            if state.remove_session(sid) {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        None => (StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id").into_response(),
    }
}

/// SSE stream implementation
struct SseStream {
    rx: broadcast::Receiver<SseEvent>,
    session: Arc<Session>,
    keepalive_interval: tokio::time::Interval,
}

impl SseStream {
    fn new(session: Arc<Session>, keepalive_secs: u64) -> Self {
        Self {
            rx: session.subscribe(),
            session,
            keepalive_interval: tokio::time::interval(Duration::from_secs(keepalive_secs)),
        }
    }

    /// Format an SSE event as a string
    fn format_sse_event(event_type: &str, data: &str, id: Option<&str>) -> String {
        let mut output = String::new();
        if let Some(id) = id {
            output.push_str(&format!("id: {}\n", id));
        }
        output.push_str(&format!("event: {}\n", event_type));
        for line in data.lines() {
            output.push_str(&format!("data: {}\n", line));
        }
        if data.is_empty() {
            output.push_str("data: \n");
        }
        output.push('\n');
        output
    }
}

impl Stream for SseStream {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check for keepalive
        if self.keepalive_interval.poll_tick(cx).is_ready() {
            let event = Self::format_sse_event("ping", "", None);
            return Poll::Ready(Some(Ok(Bytes::from(event))));
        }

        // Try to receive a message
        match self.rx.try_recv() {
            Ok(SseEvent::Message(msg)) => {
                let event_id = self.session.next_event_id().to_string();
                // Convert JsonRpcMessage to JSON value, then to string
                let data = match &msg {
                    JsonRpcMessage::Request(req) => serde_json::to_string(req).unwrap_or_default(),
                    JsonRpcMessage::Response(resp) => serde_json::to_string(resp).unwrap_or_default(),
                };
                let event = Self::format_sse_event("message", &data, Some(&event_id));
                Poll::Ready(Some(Ok(Bytes::from(event))))
            }
            Ok(SseEvent::Ping) => {
                let event = Self::format_sse_event("ping", "", None);
                Poll::Ready(Some(Ok(Bytes::from(event))))
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                // Missed some messages, continue
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                Poll::Ready(None)
            }
        }
    }
}

#[async_trait]
impl Transport for StreamableHttpTransport {
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let handler = self
            .handler
            .take()
            .ok_or_else(|| ProxyError::Transport("No handler set".to_string()))?;

        let state = Arc::new(StreamableHttpState {
            handler,
            config: self.config.clone(),
            sessions: DashMap::new(),
            allowed_origins: self.allowed_origins.clone(),
        });

        let router = Self::create_router(state.clone());

        // Bind to localhost only by default (security)
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ProxyError::Transport(format!("Failed to bind: {e}")))?;

        info!(
            "Streamable HTTP transport listening on {} (MCP 2025-03-26)",
            addr
        );

        self.cancel = Some(cancel.clone());

        // Spawn session cleanup task
        let cleanup_state = state.clone();
        let timeout = self.config.session_timeout_secs;
        let cleanup_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = cleanup_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        cleanup_state.sessions.retain(|_, session| {
                            let age = session.created_at.elapsed().as_secs();
                            let last = session.last_activity.load(Ordering::Relaxed);
                            let inactive = age - last;
                            inactive < timeout
                        });
                    }
                }
            }
        });

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

        info!("Streamable HTTP transport stopped");
        Ok(())
    }

    async fn send(&self, _message: JsonRpcMessage) -> Result<(), ProxyError> {
        // Server-initiated messages would be sent via SSE
        // This requires access to the session, which isn't available here
        Err(ProxyError::Transport(
            "Use SSE stream for server-initiated messages".to_string(),
        ))
    }

    fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    fn name(&self) -> &'static str {
        "streamable-http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new();
        assert!(!session.id.is_empty());
        assert_eq!(session.event_counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_session_event_counter() {
        let session = Session::new();
        assert_eq!(session.next_event_id(), 0);
        assert_eq!(session.next_event_id(), 1);
        assert_eq!(session.next_event_id(), 2);
    }

    #[test]
    fn test_config_default() {
        let config = StreamableHttpConfig::default();
        assert_eq!(config.session_timeout_secs, 3600);
        assert!(config.require_session);
        assert_eq!(config.max_batch_size, 100);
    }

    #[test]
    fn test_transport_creation() {
        let transport = StreamableHttpTransport::new(8080, TransportConfig::default());
        assert_eq!(transport.port, 8080);
        assert_eq!(transport.name(), "streamable-http");
    }

    #[test]
    fn test_origin_validation_localhost() {
        let state = StreamableHttpState {
            handler: Arc::new(|_| Box::pin(async { Ok(None) })),
            config: StreamableHttpConfig::default(),
            sessions: DashMap::new(),
            allowed_origins: HashSet::new(),
        };

        // Localhost should be allowed by default
        assert!(state.validate_origin(Some(&HeaderValue::from_static("http://localhost:3000"))));
        assert!(state.validate_origin(Some(&HeaderValue::from_static("http://127.0.0.1:8080"))));

        // Remote origins should be blocked
        assert!(!state.validate_origin(Some(&HeaderValue::from_static("http://evil.com"))));

        // No origin (non-browser) should be allowed
        assert!(state.validate_origin(None));
    }

    #[test]
    fn test_origin_validation_allowed_list() {
        let mut allowed = HashSet::new();
        allowed.insert("https://myapp.com".to_string());

        let state = StreamableHttpState {
            handler: Arc::new(|_| Box::pin(async { Ok(None) })),
            config: StreamableHttpConfig::default(),
            sessions: DashMap::new(),
            allowed_origins: allowed,
        };

        assert!(state.validate_origin(Some(&HeaderValue::from_static("https://myapp.com"))));
        assert!(!state.validate_origin(Some(&HeaderValue::from_static("http://localhost:3000"))));
        assert!(state.validate_origin(None)); // Non-browser allowed
    }
}
