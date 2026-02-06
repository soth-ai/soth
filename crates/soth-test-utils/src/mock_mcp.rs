//! Mock MCP Server for in-process testing
//!
//! Provides a fast, configurable mock MCP server that can be used for
//! deterministic testing without external processes or network calls.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Configuration for simulated latency
#[derive(Debug, Clone)]
pub struct LatencyConfig {
    /// Base latency in milliseconds
    pub base_ms: u64,
    /// Random jitter to add (0 to jitter_ms)
    pub jitter_ms: u64,
}

impl Default for LatencyConfig {
    fn default() -> Self {
        Self {
            base_ms: 0,
            jitter_ms: 0,
        }
    }
}

impl LatencyConfig {
    /// Create instant response config (no latency)
    pub fn instant() -> Self {
        Self::default()
    }

    /// Create config with fixed latency
    pub fn fixed(ms: u64) -> Self {
        Self {
            base_ms: ms,
            jitter_ms: 0,
        }
    }

    /// Create config with base + jitter
    pub fn with_jitter(base_ms: u64, jitter_ms: u64) -> Self {
        Self { base_ms, jitter_ms }
    }

    /// Get the actual delay duration
    pub fn delay(&self) -> Duration {
        let jitter = if self.jitter_ms > 0 {
            rand::random::<u64>() % self.jitter_ms
        } else {
            0
        };
        Duration::from_millis(self.base_ms + jitter)
    }
}

/// A mock tool handler
pub type ToolHandler = Arc<dyn Fn(Value) -> Value + Send + Sync>;

/// Mock tool definition
#[derive(Clone)]
pub struct MockTool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    pub input_schema: Value,
    /// Handler function
    handler: ToolHandler,
    /// Per-tool latency config
    pub latency: Option<LatencyConfig>,
}

impl MockTool {
    /// Create a new mock tool
    pub fn new<F>(name: impl Into<String>, description: impl Into<String>, handler: F) -> Self
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            handler: Arc::new(handler),
            latency: None,
        }
    }

    /// Set the input schema
    pub fn with_schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }

    /// Set per-tool latency
    pub fn with_latency(mut self, latency: LatencyConfig) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Call the tool handler
    pub fn call(&self, args: Value) -> Value {
        (self.handler)(args)
    }
}

/// Mock MCP Server for in-process testing
///
/// This provides a fast, configurable MCP server that runs in-process,
/// eliminating the need for external processes or network calls in tests.
///
/// # Example
/// ```
/// use soth_test_utils::MockMcpServer;
/// use serde_json::json;
///
/// let server = MockMcpServer::new()
///     .with_tool("echo", |args| {
///         json!({
///             "content": [{
///                 "type": "text",
///                 "text": args.get("text").and_then(|v| v.as_str()).unwrap_or("")
///             }]
///         })
///     })
///     .with_latency(soth_test_utils::LatencyConfig::fixed(10));
///
/// // Process requests through the server
/// ```
pub struct MockMcpServer {
    tools: HashMap<String, MockTool>,
    resources: HashMap<String, Value>,
    latency_config: LatencyConfig,
    call_history: Arc<RwLock<Vec<CallRecord>>>,
    initialized: Arc<RwLock<bool>>,
}

/// Record of a call made to the mock server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub method: String,
    pub params: Option<Value>,
    pub latency_ms: u64,
}

impl Default for MockMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMcpServer {
    /// Create a new empty mock MCP server
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            resources: HashMap::new(),
            latency_config: LatencyConfig::instant(),
            call_history: Arc::new(RwLock::new(Vec::new())),
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Add a simple tool with a handler function
    pub fn with_tool<F>(mut self, name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        let name = name.into();
        let tool = MockTool::new(name.clone(), format!("Mock tool: {}", name), handler);
        self.tools.insert(name, tool);
        self
    }

    /// Add a full MockTool
    pub fn with_mock_tool(mut self, tool: MockTool) -> Self {
        self.tools.insert(tool.name.clone(), tool);
        self
    }

    /// Set global latency config
    pub fn with_latency(mut self, config: LatencyConfig) -> Self {
        self.latency_config = config;
        self
    }

    /// Add a mock resource
    pub fn with_resource(mut self, uri: impl Into<String>, content: Value) -> Self {
        self.resources.insert(uri.into(), content);
        self
    }

    /// Process a JSON-RPC request and return a response
    ///
    /// Returns `None` for notifications (no id).
    pub async fn process(&self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        // Notifications don't get responses
        if request.id.is_none() {
            return None;
        }

        let start = std::time::Instant::now();

        // Apply global latency
        let delay = self.latency_config.delay();
        if delay > Duration::ZERO {
            tokio::time::sleep(delay).await;
        }

        let params = request.params.clone().unwrap_or(json!({}));
        let id = request.id.clone();

        let response = match request.method.as_str() {
            "initialize" => {
                *self.initialized.write().await = true;
                JsonRpcResponse::success(
                    id.clone(),
                    json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {}
                        },
                        "serverInfo": {
                            "name": "mock-mcp-server",
                            "version": "0.1.0"
                        }
                    }),
                )
            }
            "ping" => JsonRpcResponse::success(id.clone(), json!({})),
            "tools/list" => {
                let tools: Vec<Value> = self
                    .tools
                    .values()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema
                        })
                    })
                    .collect();
                JsonRpcResponse::success(id.clone(), json!({ "tools": tools }))
            }
            "tools/call" => {
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

                if let Some(tool) = self.tools.get(tool_name) {
                    // Apply tool-specific latency if set
                    if let Some(ref latency) = tool.latency {
                        let delay = latency.delay();
                        if delay > Duration::ZERO {
                            tokio::time::sleep(delay).await;
                        }
                    }

                    let args = params.get("arguments").cloned().unwrap_or(json!({}));
                    let result = tool.call(args);
                    JsonRpcResponse::success(id.clone(), result)
                } else {
                    JsonRpcResponse::error(
                        id.clone(),
                        -32601,
                        &format!("Unknown tool: {}", tool_name),
                    )
                }
            }
            "resources/list" => {
                let resources: Vec<Value> = self
                    .resources
                    .keys()
                    .map(|uri| {
                        json!({
                            "uri": uri,
                            "name": uri,
                            "mimeType": "application/json"
                        })
                    })
                    .collect();
                JsonRpcResponse::success(id.clone(), json!({ "resources": resources }))
            }
            "resources/read" => {
                let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(content) = self.resources.get(uri) {
                    JsonRpcResponse::success(
                        id.clone(),
                        json!({
                            "contents": [{
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": content.to_string()
                            }]
                        }),
                    )
                } else {
                    JsonRpcResponse::error(
                        id.clone(),
                        -32002,
                        &format!("Resource not found: {}", uri),
                    )
                }
            }
            "prompts/list" => JsonRpcResponse::success(id.clone(), json!({ "prompts": [] })),
            _ => JsonRpcResponse::error(
                id.clone(),
                -32601,
                &format!("Method not found: {}", request.method),
            ),
        };

        // Record the call
        let latency_ms = start.elapsed().as_millis() as u64;
        self.call_history.write().await.push(CallRecord {
            timestamp: chrono::Utc::now(),
            method: request.method.clone(),
            params: request.params.clone(),
            latency_ms,
        });

        Some(response)
    }

    /// Get the call history
    pub async fn get_call_history(&self) -> Vec<CallRecord> {
        self.call_history.read().await.clone()
    }

    /// Clear the call history
    pub async fn clear_history(&self) {
        self.call_history.write().await.clear();
    }

    /// Check if the server has been initialized
    pub async fn is_initialized(&self) -> bool {
        *self.initialized.read().await
    }
}

/// JSON-RPC request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl JsonRpcRequest {
    /// Create a new JSON-RPC request
    pub fn new(method: impl Into<String>, params: Option<Value>, id: impl Into<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: Some(id.into()),
        }
    }

    /// Create a notification (no id)
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: None,
        }
    }
}

/// JSON-RPC response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response
    pub fn error(id: Option<Value>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
            id,
        }
    }

    /// Check if the response is an error
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// JSON-RPC error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_initialize() {
        let server = MockMcpServer::new();

        let request = JsonRpcRequest::new("initialize", None, 1);
        let response = server.process(&request).await.unwrap();

        assert!(response.result.is_some());
        assert!(!response.is_error());
        assert!(server.is_initialized().await);
    }

    #[tokio::test]
    async fn test_mock_server_tool_call() {
        let server = MockMcpServer::new().with_tool("echo", |args| {
            json!({
                "content": [{
                    "type": "text",
                    "text": args.get("text").and_then(|v| v.as_str()).unwrap_or("")
                }]
            })
        });

        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {"text": "hello world"}
            })),
            1,
        );

        let response = server.process(&request).await.unwrap();
        assert!(!response.is_error());

        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "hello world");
    }

    #[tokio::test]
    async fn test_mock_server_latency() {
        let server = MockMcpServer::new()
            .with_latency(LatencyConfig::fixed(50))
            .with_tool("fast", |_| json!({"ok": true}));

        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "fast", "arguments": {}})),
            1,
        );

        let start = std::time::Instant::now();
        let _ = server.process(&request).await;
        let elapsed = start.elapsed();

        // Should have at least 50ms latency
        assert!(elapsed.as_millis() >= 50);
    }

    #[tokio::test]
    async fn test_mock_server_call_history() {
        let server = MockMcpServer::new().with_tool("test", |_| json!({}));

        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "test", "arguments": {}})),
            1,
        );

        server.process(&request).await;
        server.process(&request).await;

        let history = server.get_call_history().await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].method, "tools/call");
    }

    #[tokio::test]
    async fn test_mock_server_notification() {
        let server = MockMcpServer::new();

        // Notifications have no id and no response
        let notification = JsonRpcRequest::notification("notifications/initialized", None);
        let response = server.process(&notification).await;

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn test_mock_server_unknown_tool() {
        let server = MockMcpServer::new();

        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "nonexistent", "arguments": {}})),
            1,
        );

        let response = server.process(&request).await.unwrap();
        assert!(response.is_error());
        assert_eq!(response.error.unwrap().code, -32601);
    }
}
