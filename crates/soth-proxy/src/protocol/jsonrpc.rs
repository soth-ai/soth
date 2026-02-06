//! JSON-RPC 2.0 protocol implementation

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC version string
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC request ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum RequestId {
    /// String ID
    String(String),
    /// Numeric ID
    Number(i64),
    /// Null ID (for notifications)
    Null,
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        RequestId::Number(n)
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        RequestId::String(s)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        RequestId::String(s.to_string())
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::String(s) => write!(f, "{s}"),
            RequestId::Number(n) => write!(f, "{n}"),
            RequestId::Null => write!(f, "null"),
        }
    }
}

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request method
    pub method: String,
    /// Request parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request ID (None for notifications)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
}

impl JsonRpcRequest {
    /// Create a new request
    pub fn new(method: impl Into<String>, params: Option<Value>, id: RequestId) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
            id: Some(id),
        }
    }

    /// Create a notification (no response expected)
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
            id: None,
        }
    }

    /// Check if this is a notification
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Result (mutually exclusive with error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (mutually exclusive with result)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Response ID (matches request ID)
    pub id: RequestId,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response
    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create an error with additional data
    pub fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    // Standard JSON-RPC error codes

    /// Parse error (-32700)
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }

    /// Invalid request (-32600)
    pub fn invalid_request() -> Self {
        Self::new(-32600, "Invalid Request")
    }

    /// Method not found (-32601)
    pub fn method_not_found() -> Self {
        Self::new(-32601, "Method not found")
    }

    /// Invalid params (-32602)
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }

    /// Internal error (-32603)
    pub fn internal_error() -> Self {
        Self::new(-32603, "Internal error")
    }

    /// Server error (reserved range: -32000 to -32099)
    pub fn server_error(code: i32, message: impl Into<String>) -> Self {
        let code = code.clamp(-32099, -32000);
        Self::new(code, message)
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// JSON-RPC message (request, response, or notification)
#[derive(Debug, Clone)]
pub enum JsonRpcMessage {
    /// Request message
    Request(JsonRpcRequest),
    /// Response message
    Response(JsonRpcResponse),
}

impl JsonRpcMessage {
    /// Parse a JSON-RPC message from a JSON value
    pub fn parse(value: Value) -> Result<Self, JsonRpcError> {
        // Check if it's a response (has result or error field)
        if value.get("result").is_some() || value.get("error").is_some() {
            let response: JsonRpcResponse =
                serde_json::from_value(value).map_err(|_| JsonRpcError::parse_error())?;
            return Ok(JsonRpcMessage::Response(response));
        }

        // Otherwise it's a request
        let request: JsonRpcRequest =
            serde_json::from_value(value).map_err(|_| JsonRpcError::parse_error())?;
        Ok(JsonRpcMessage::Request(request))
    }

    /// Parse from a JSON string
    pub fn from_json_str(s: &str) -> Result<Self, JsonRpcError> {
        let value: Value = serde_json::from_str(s).map_err(|_| JsonRpcError::parse_error())?;
        Self::parse(value)
    }

    /// Serialize to JSON string
    pub fn to_string(&self) -> Result<String, JsonRpcError> {
        match self {
            JsonRpcMessage::Request(req) => {
                serde_json::to_string(req).map_err(|_| JsonRpcError::internal_error())
            }
            JsonRpcMessage::Response(resp) => {
                serde_json::to_string(resp).map_err(|_| JsonRpcError::internal_error())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = JsonRpcRequest::new(
            "test_method",
            Some(serde_json::json!({"key": "value"})),
            RequestId::Number(1),
        );

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"test_method\""));
    }

    #[test]
    fn test_notification() {
        let notif = JsonRpcRequest::notification("progress", Some(serde_json::json!({"percent": 50})));
        assert!(notif.is_notification());
        assert!(notif.id.is_none());
    }

    #[test]
    fn test_response_success() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"result": "ok"}));
        assert!(!resp.is_error());
    }

    #[test]
    fn test_response_error() {
        let resp = JsonRpcResponse::error(RequestId::Number(1), JsonRpcError::method_not_found());
        assert!(resp.is_error());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let msg = JsonRpcMessage::from_json_str(json).unwrap();
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test");
            }
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn test_parse_response() {
        let json = r#"{"jsonrpc":"2.0","result":{"status":"ok"},"id":1}"#;
        let msg = JsonRpcMessage::from_json_str(json).unwrap();
        match msg {
            JsonRpcMessage::Response(resp) => {
                assert!(resp.result.is_some());
            }
            _ => panic!("Expected response"),
        }
    }
}
