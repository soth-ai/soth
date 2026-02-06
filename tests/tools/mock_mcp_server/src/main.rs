//! Mock MCP Server for testing SOTH
//!
//! A simple stdio-based MCP server that responds to standard protocol messages.
//! Useful for isolated testing without external dependencies.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl JsonRpcResponse {
    fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn error(id: Option<Value>, code: i32, message: &str) -> Self {
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
}

/// Available mock tools
fn get_tools() -> Value {
    json!({
        "tools": [
            {
                "name": "echo",
                "description": "Echoes back the input text",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to echo back"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "add",
                "description": "Adds two numbers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": { "type": "number" },
                        "b": { "type": "number" }
                    },
                    "required": ["a", "b"]
                }
            },
            {
                "name": "get_time",
                "description": "Returns the current server time",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "slow_operation",
                "description": "Simulates a slow operation (for timeout testing)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "delay_ms": {
                            "type": "integer",
                            "description": "Delay in milliseconds"
                        }
                    }
                }
            },
            {
                "name": "fail",
                "description": "Always returns an error (for error handling testing)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Error message to return"
                        }
                    }
                }
            },
            {
                "name": "blocked_tool",
                "description": "A tool that should be blocked by policy",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    })
}

/// Available mock resources
fn get_resources() -> Value {
    json!({
        "resources": [
            {
                "uri": "file:///test/readme.txt",
                "name": "Test README",
                "mimeType": "text/plain"
            },
            {
                "uri": "file:///test/config.json",
                "name": "Test Config",
                "mimeType": "application/json"
            }
        ]
    })
}

/// Handle a tools/call request
fn handle_tool_call(params: &Value) -> Result<Value, (i32, String)> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "Missing tool name".to_string()))?;

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "echo" => {
            let text = args
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("(no text)");
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": text
                    }
                ]
            }))
        }
        "add" => {
            let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("{} + {} = {}", a, b, a + b)
                    }
                ]
            }))
        }
        "get_time" => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("Current timestamp: {}", timestamp)
                    }
                ]
            }))
        }
        "slow_operation" => {
            let delay_ms = args.get("delay_ms").and_then(|v| v.as_u64()).unwrap_or(1000);
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("Completed after {}ms delay", delay_ms)
                    }
                ]
            }))
        }
        "fail" => {
            let message = args
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Intentional failure");
            Err((-32000, message.to_string()))
        }
        "blocked_tool" => {
            // This should be blocked by policy before reaching here
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": "WARNING: blocked_tool was executed (should have been blocked by policy)"
                    }
                ]
            }))
        }
        _ => Err((-32601, format!("Unknown tool: {}", name))),
    }
}

/// Handle a resources/read request
fn handle_resource_read(params: &Value) -> Result<Value, (i32, String)> {
    let uri = params
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "Missing uri".to_string()))?;

    match uri {
        "file:///test/readme.txt" => Ok(json!({
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": "This is a test README file.\n\nIt contains some sample content for testing."
                }
            ]
        })),
        "file:///test/config.json" => Ok(json!({
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": "{\"name\": \"test\", \"version\": \"1.0.0\"}"
                }
            ]
        })),
        _ => Err((-32002, format!("Resource not found: {}", uri))),
    }
}

/// Handle an incoming request
fn handle_request(request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    // Notifications don't get responses
    if request.id.is_none() {
        eprintln!("[mock-mcp] Received notification: {}", request.method);
        return None;
    }

    let id = request.id.clone();
    let params = request.params.clone().unwrap_or(json!({}));

    eprintln!("[mock-mcp] Handling: {}", request.method);

    let response = match request.method.as_str() {
        "initialize" => JsonRpcResponse::success(
            id,
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
        ),
        "ping" => JsonRpcResponse::success(id, json!({})),
        "tools/list" => JsonRpcResponse::success(id, get_tools()),
        "tools/call" => match handle_tool_call(&params) {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err((code, msg)) => JsonRpcResponse::error(id, code, &msg),
        },
        "resources/list" => JsonRpcResponse::success(id, get_resources()),
        "resources/read" => match handle_resource_read(&params) {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err((code, msg)) => JsonRpcResponse::error(id, code, &msg),
        },
        "prompts/list" => JsonRpcResponse::success(id, json!({"prompts": []})),
        _ => JsonRpcResponse::error(id, -32601, &format!("Method not found: {}", request.method)),
    };

    Some(response)
}

fn main() {
    eprintln!("[mock-mcp] Mock MCP Server starting...");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[mock-mcp] Read error: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        eprintln!("[mock-mcp] Received: {}", line);

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[mock-mcp] Parse error: {}", e);
                let error_response = JsonRpcResponse::error(None, -32700, "Parse error");
                let _ = writeln!(stdout_lock, "{}", serde_json::to_string(&error_response).unwrap());
                let _ = stdout_lock.flush();
                continue;
            }
        };

        if let Some(response) = handle_request(&request) {
            let response_str = serde_json::to_string(&response).unwrap();
            eprintln!("[mock-mcp] Responding: {}", response_str);
            let _ = writeln!(stdout_lock, "{}", response_str);
            let _ = stdout_lock.flush();
        }
    }

    eprintln!("[mock-mcp] Mock MCP Server shutting down");
}
