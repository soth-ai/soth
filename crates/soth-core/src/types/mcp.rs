//! MCP (Model Context Protocol) JSON-RPC types
//!
//! Defines the JSON-RPC 2.0 message types used by MCP.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 version string
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version (always "2.0")
    pub jsonrpc: String,

    /// Request ID (null for notifications)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,

    /// Method name
    pub method: String,

    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Create a new request
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(Value::Number(1.into())),
            method: method.into(),
            params,
        }
    }

    /// Create a new notification (no ID)
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: None,
            method: method.into(),
            params,
        }
    }

    /// Set the request ID
    pub fn with_id(mut self, id: impl Into<Value>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Check if this is a notification (no ID)
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// JSON-RPC Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version (always "2.0")
    pub jsonrpc: String,

    /// Request ID
    pub id: Value,

    /// Result (mutually exclusive with error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Error (mutually exclusive with result)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// JSON-RPC Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i64,

    /// Human-readable error message
    pub message: String,

    /// Optional additional data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Add error data
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    // Standard JSON-RPC error codes

    /// Parse error (-32700)
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }

    /// Invalid request (-32600)
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(-32600, msg)
    }

    /// Method not found (-32601)
    pub fn method_not_found(method: &str) -> Self {
        Self::new(-32601, format!("Method not found: {method}"))
    }

    /// Invalid params (-32602)
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, msg)
    }

    /// Internal error (-32603)
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(-32603, msg)
    }

    // MCP-specific error codes

    /// Request cancelled (-32800)
    pub fn request_cancelled() -> Self {
        Self::new(-32800, "Request cancelled")
    }

    /// Content too large (-32801)
    pub fn content_too_large() -> Self {
        Self::new(-32801, "Content too large")
    }
}

/// JSON-RPC Notification (request without ID)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// Protocol version
    pub jsonrpc: String,

    /// Method name
    pub method: String,

    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Create a new notification
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC message (request, response, or notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

impl JsonRpcMessage {
    /// Parse a JSON-RPC message from a JSON value
    pub fn from_value(value: Value) -> Result<Self, String> {
        // Check if it has a method (request/notification) or result/error (response)
        if value.get("method").is_some() {
            if value.get("id").is_some() {
                serde_json::from_value(value)
                    .map(JsonRpcMessage::Request)
                    .map_err(|e| e.to_string())
            } else {
                serde_json::from_value(value)
                    .map(JsonRpcMessage::Notification)
                    .map_err(|e| e.to_string())
            }
        } else if value.get("result").is_some() || value.get("error").is_some() {
            serde_json::from_value(value)
                .map(JsonRpcMessage::Response)
                .map_err(|e| e.to_string())
        } else {
            Err("Invalid JSON-RPC message".to_string())
        }
    }

    /// Get the method name if this is a request/notification
    pub fn method(&self) -> Option<&str> {
        match self {
            JsonRpcMessage::Request(r) => Some(&r.method),
            JsonRpcMessage::Notification(n) => Some(&n.method),
            JsonRpcMessage::Response(_) => None,
        }
    }

    /// Get the ID if present
    pub fn id(&self) -> Option<&Value> {
        match self {
            JsonRpcMessage::Request(r) => r.id.as_ref(),
            JsonRpcMessage::Response(r) => Some(&r.id),
            JsonRpcMessage::Notification(_) => None,
        }
    }
}

/// Common MCP method names
pub mod methods {
    /// Initialize the connection
    pub const INITIALIZE: &str = "initialize";
    /// Notification that initialization is complete
    pub const INITIALIZED: &str = "initialized";
    /// Ping
    pub const PING: &str = "ping";

    /// List available tools
    pub const TOOLS_LIST: &str = "tools/list";
    /// Call a tool
    pub const TOOLS_CALL: &str = "tools/call";

    /// List available resources
    pub const RESOURCES_LIST: &str = "resources/list";
    /// Read a resource
    pub const RESOURCES_READ: &str = "resources/read";

    /// List available prompts
    pub const PROMPTS_LIST: &str = "prompts/list";
    /// Get a prompt
    pub const PROMPTS_GET: &str = "prompts/get";

    /// Request sampling from LLM
    pub const SAMPLING_CREATE_MESSAGE: &str = "sampling/createMessage";

    /// Complete operation
    pub const COMPLETION_COMPLETE: &str = "completion/complete";

    /// Request cancellation
    pub const CANCELLED: &str = "cancelled";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let req = JsonRpcRequest::new("tools/call", Some(serde_json::json!({"name": "test"})));
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "tools/call");
        assert!(!req.is_notification());
    }

    #[test]
    fn test_notification() {
        let notif = JsonRpcRequest::notification("initialized", None);
        assert!(notif.is_notification());
        assert!(notif.id.is_none());
    }

    #[test]
    fn test_response_success() {
        let resp = JsonRpcResponse::success(
            Value::Number(1.into()),
            serde_json::json!({"result": "ok"}),
        );
        assert!(!resp.is_error());
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_response_error() {
        let resp = JsonRpcResponse::error(
            Value::Number(1.into()),
            JsonRpcError::method_not_found("test"),
        );
        assert!(resp.is_error());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_message_parsing() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "test"},
            "id": 1
        });

        let msg = JsonRpcMessage::from_value(json).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
        assert_eq!(msg.method(), Some("tools/call"));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(JsonRpcError::parse_error().code, -32700);
        assert_eq!(JsonRpcError::invalid_request("").code, -32600);
        assert_eq!(JsonRpcError::method_not_found("").code, -32601);
        assert_eq!(JsonRpcError::invalid_params("").code, -32602);
        assert_eq!(JsonRpcError::internal_error("").code, -32603);
    }
}
