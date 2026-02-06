//! Transport layer for MCP communication
//!
//! Provides multiple transport implementations:
//! - stdio: Standard input/output for CLI tools
//! - SSE: Server-Sent Events for web clients
//! - HTTP: HTTP POST for simple integrations
//! - Streamable HTTP: MCP 2025-03-26 spec compliant HTTP with SSE streaming

pub mod stdio;
pub mod sse;
pub mod http;
pub mod streamable_http;
pub mod forward_proxy;
pub mod hudsucker_proxy;

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::error::ProxyError;
use crate::protocol::JsonRpcMessage;

/// Message handler callback type
pub type MessageHandler = Arc<dyn Fn(JsonRpcMessage) -> Result<Option<JsonRpcMessage>, ProxyError> + Send + Sync>;

/// Async message handler for pipeline processing
pub type AsyncMessageHandler = Arc<dyn Fn(JsonRpcMessage) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<JsonRpcMessage>, ProxyError>> + Send>> + Send + Sync>;

/// Transport trait for MCP communication
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start the transport
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError>;

    /// Stop the transport
    async fn stop(&mut self) -> Result<(), ProxyError>;

    /// Send a message
    async fn send(&self, message: JsonRpcMessage) -> Result<(), ProxyError>;

    /// Set the message handler for incoming messages
    fn set_handler(&mut self, handler: AsyncMessageHandler);

    /// Get transport name
    fn name(&self) -> &'static str;
}

/// Transport direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Message from client to server
    ClientToServer,
    /// Message from server to client
    ServerToClient,
}

/// Transport event for logging
#[derive(Debug, Clone)]
pub struct TransportEvent {
    /// Direction of message
    pub direction: Direction,
    /// The message
    pub message: Value,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl TransportEvent {
    /// Create a new transport event
    pub fn new(direction: Direction, message: Value) -> Self {
        Self {
            direction,
            message,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Transport builder for creating configured transports
pub struct TransportBuilder {
    transport_type: TransportType,
    config: TransportConfig,
}

/// Transport type selection
#[derive(Debug, Clone)]
pub enum TransportType {
    Stdio,
    Sse { port: u16 },
    Http { port: u16 },
    /// Streamable HTTP (MCP 2025-03-26 spec)
    StreamableHttp { port: u16 },
}

/// Transport configuration
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    /// Buffer size for message channels
    pub buffer_size: usize,
    /// Timeout for operations in milliseconds
    pub timeout_ms: u64,
    /// Whether to enable message logging
    pub log_messages: bool,
}

impl TransportBuilder {
    /// Create a new transport builder
    pub fn new(transport_type: TransportType) -> Self {
        Self {
            transport_type,
            config: TransportConfig {
                buffer_size: 1000,
                timeout_ms: 30000,
                log_messages: false,
            },
        }
    }

    /// Set buffer size
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.config.buffer_size = size;
        self
    }

    /// Set timeout in milliseconds
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.config.timeout_ms = ms;
        self
    }

    /// Enable message logging
    pub fn log_messages(mut self, enabled: bool) -> Self {
        self.config.log_messages = enabled;
        self
    }

    /// Build the transport
    pub fn build(self) -> Box<dyn Transport> {
        match self.transport_type {
            TransportType::Stdio => Box::new(stdio::StdioTransport::new(self.config)),
            TransportType::Sse { port } => Box::new(sse::SseTransport::new(port, self.config)),
            TransportType::Http { port } => Box::new(http::HttpTransport::new(port, self.config)),
            TransportType::StreamableHttp { port } => {
                Box::new(streamable_http::StreamableHttpTransport::new(port, self.config))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_builder() {
        let builder = TransportBuilder::new(TransportType::Stdio)
            .buffer_size(500)
            .timeout_ms(5000)
            .log_messages(true);

        assert_eq!(builder.config.buffer_size, 500);
        assert_eq!(builder.config.timeout_ms, 5000);
        assert!(builder.config.log_messages);
    }

    #[test]
    fn test_transport_event() {
        let event = TransportEvent::new(
            Direction::ClientToServer,
            serde_json::json!({"method": "test"}),
        );
        assert_eq!(event.direction, Direction::ClientToServer);
    }
}
