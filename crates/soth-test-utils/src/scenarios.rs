//! Pre-built test scenarios for common testing patterns
//!
//! These scenarios provide ready-to-use MockMcpServer configurations
//! for testing specific features and edge cases.

use crate::mock_mcp::{LatencyConfig, MockMcpServer, MockTool};
use serde_json::{json, Value};

/// Create a scenario where a specific tool should be blocked by policy
///
/// Returns a server with a "blocked_tool" that the policy layer should deny.
pub fn policy_blocked_tool() -> MockMcpServer {
    MockMcpServer::new()
        .with_mock_tool(MockTool::new(
            "blocked_tool",
            "A tool that should be blocked by policy",
            |_| {
                json!({
                    "content": [{
                        "type": "text",
                        "text": "ERROR: This should have been blocked by policy"
                    }]
                })
            },
        ))
        .with_mock_tool(MockTool::new(
            "allowed_tool",
            "A tool that should be allowed",
            |args| {
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Allowed: {:?}", args)
                    }]
                })
            },
        ))
}

/// Create a scenario with requests containing PII data
///
/// Returns a server with tools that handle various PII types.
pub fn pii_in_request() -> MockMcpServer {
    MockMcpServer::new()
        .with_tool("process_user", |args| {
            // Echo back the user data (for testing PII detection)
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("Processed user: {}", args)
                }]
            })
        })
        .with_tool("send_email", |args| {
            // Simulates sending an email
            let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("Email sent to: {}", to)
                }]
            })
        })
}

/// Create a test request with various PII types
pub fn request_with_pii() -> Value {
    json!({
        "name": "process_user",
        "arguments": {
            "user": {
                "name": "John Doe",
                "email": "john.doe@example.com",
                "ssn": "123-45-6789",
                "phone": "(212) 555-1234",
                "credit_card": "4111-1111-1111-1111"
            }
        }
    })
}

/// Create a request with an email address
pub fn request_with_email() -> Value {
    json!({
        "name": "send_email",
        "arguments": {
            "to": "user@example.com",
            "subject": "Test",
            "body": "Hello world"
        }
    })
}

/// Create a slow server scenario for testing timeouts
pub fn slow_server(latency_ms: u64) -> MockMcpServer {
    MockMcpServer::new()
        .with_latency(LatencyConfig::fixed(latency_ms))
        .with_tool("slow_operation", |_| {
            json!({
                "content": [{
                    "type": "text",
                    "text": "Operation completed"
                }]
            })
        })
}

/// Create a server that simulates variable latency (for realistic load testing)
pub fn variable_latency_server(base_ms: u64, jitter_ms: u64) -> MockMcpServer {
    MockMcpServer::new()
        .with_latency(LatencyConfig::with_jitter(base_ms, jitter_ms))
        .with_tool("echo", |args| {
            json!({
                "content": [{
                    "type": "text",
                    "text": args.get("text").and_then(|v| v.as_str()).unwrap_or("")
                }]
            })
        })
}

/// Create a server that always returns errors
pub fn error_server() -> MockMcpServer {
    MockMcpServer::new().with_tool("fail", |args| {
        // Note: The tool returns an error structure, but the response is still "success"
        // from JSON-RPC perspective. For actual errors, see the tools/call handler.
        json!({
            "content": [{
                "type": "text",
                "text": format!("Error: {}", args.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error"))
            }],
            "isError": true
        })
    })
}

/// Create a server with various test tools for comprehensive testing
pub fn full_test_server() -> MockMcpServer {
    MockMcpServer::new()
        // Basic tools
        .with_tool("echo", |args| {
            json!({
                "content": [{
                    "type": "text",
                    "text": args.get("text").and_then(|v| v.as_str()).unwrap_or("")
                }]
            })
        })
        .with_tool("add", |args| {
            let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("{} + {} = {}", a, b, a + b)
                }]
            })
        })
        .with_tool("get_time", |_| {
            let now = chrono::Utc::now();
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("Current time: {}", now.to_rfc3339())
                }]
            })
        })
        // Tool that should be blocked by policy
        .with_mock_tool(MockTool::new("blocked_tool", "Should be blocked", |_| {
            json!({
                "content": [{
                    "type": "text",
                    "text": "ERROR: blocked_tool was executed"
                }]
            })
        }))
        // Resource for testing resource reads
        .with_resource(
            "file:///test/config.json",
            json!({"name": "test", "version": "1.0.0"}),
        )
        .with_resource(
            "file:///test/readme.txt",
            json!("This is a test file for testing resource reads."),
        )
}

/// Create a simple request for the echo tool
pub fn echo_request(text: &str, id: i64) -> crate::mock_mcp::JsonRpcRequest {
    crate::mock_mcp::JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {"text": text}
        })),
        id,
    )
}

/// Create a simple request for the add tool
pub fn add_request(a: f64, b: f64, id: i64) -> crate::mock_mcp::JsonRpcRequest {
    crate::mock_mcp::JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": "add",
            "arguments": {"a": a, "b": b}
        })),
        id,
    )
}

/// Create an initialize request
pub fn initialize_request(id: i64) -> crate::mock_mcp::JsonRpcRequest {
    crate::mock_mcp::JsonRpcRequest::new(
        "initialize",
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "0.1.0"
            }
        })),
        id,
    )
}

/// Create a tools/list request
pub fn tools_list_request(id: i64) -> crate::mock_mcp::JsonRpcRequest {
    crate::mock_mcp::JsonRpcRequest::new("tools/list", None, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_blocked_scenario() {
        let server = policy_blocked_tool();

        // Blocked tool exists
        let request = crate::mock_mcp::JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "blocked_tool", "arguments": {}})),
            1,
        );
        let response = server.process(&request).await.unwrap();
        assert!(!response.is_error());

        // Allowed tool exists
        let request = crate::mock_mcp::JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "allowed_tool", "arguments": {}})),
            2,
        );
        let response = server.process(&request).await.unwrap();
        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_slow_server_scenario() {
        let server = slow_server(100);

        let request = crate::mock_mcp::JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "slow_operation", "arguments": {}})),
            1,
        );

        let start = std::time::Instant::now();
        let response = server.process(&request).await.unwrap();
        let elapsed = start.elapsed();

        assert!(!response.is_error());
        assert!(elapsed.as_millis() >= 100);
    }

    #[tokio::test]
    async fn test_full_test_server() {
        let server = full_test_server();

        // Test echo
        let response = server.process(&echo_request("hello", 1)).await.unwrap();
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "hello");

        // Test add
        let response = server.process(&add_request(2.0, 3.0, 2)).await.unwrap();
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("5"));

        // Test resource read
        let request = crate::mock_mcp::JsonRpcRequest::new(
            "resources/read",
            Some(json!({"uri": "file:///test/config.json"})),
            3,
        );
        let response = server.process(&request).await.unwrap();
        assert!(!response.is_error());
    }
}
