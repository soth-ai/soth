//! MCP (Model Context Protocol) specific message handling

use super::jsonrpc::{JsonRpcError, JsonRpcRequest, RequestId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP protocol version
pub const MCP_VERSION: &str = "2024-11-05";

/// MCP capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCapabilities {
    /// Tool capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolCapabilities>,
    /// Resource capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceCapabilities>,
    /// Prompt capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptCapabilities>,
    /// Logging capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingCapabilities>,
    /// Sampling capabilities (for servers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingCapabilities>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolCapabilities {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    #[serde(default)]
    pub subscribe: bool,
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptCapabilities {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingCapabilities {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamplingCapabilities {}

/// MCP server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    /// Server name
    pub name: String,
    /// Server version
    pub version: String,
}

/// MCP client info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClientInfo {
    /// Client name
    pub name: String,
    /// Client version
    pub version: String,
}

/// Initialize request params
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// Protocol version
    pub protocol_version: String,
    /// Client capabilities
    pub capabilities: McpCapabilities,
    /// Client info
    pub client_info: McpClientInfo,
}

/// Initialize response result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// Protocol version
    pub protocol_version: String,
    /// Server capabilities
    pub capabilities: McpCapabilities,
    /// Server info
    pub server_info: McpServerInfo,
}

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// Tool name
    pub name: String,
    /// Tool description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for input parameters
    pub input_schema: Value,
}

/// Tools list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
}

/// Tool call params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    /// Tool name
    pub name: String,
    /// Tool arguments
    #[serde(default)]
    pub arguments: Value,
}

/// Content types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    /// Text content
    Text { text: String },
    /// Image content
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    /// Resource content
    Resource { resource: ResourceContent },
}

/// Resource content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContent {
    /// Resource URI
    pub uri: String,
    /// Resource text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Resource blob
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Tool call result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    /// Result content
    pub content: Vec<Content>,
    /// Whether the result is an error
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

/// Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    /// Resource URI
    pub uri: String,
    /// Resource name
    pub name: String,
    /// Resource description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Resources list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListResult {
    pub resources: Vec<Resource>,
}

/// Resource read params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReadParams {
    pub uri: String,
}

/// Resource read result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReadResult {
    pub contents: Vec<ResourceContent>,
}

/// Prompt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    /// Prompt name
    pub name: String,
    /// Prompt description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

/// Prompt argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name
    pub name: String,
    /// Argument description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether required
    #[serde(default)]
    pub required: bool,
}

/// Prompts list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsListResult {
    pub prompts: Vec<Prompt>,
}

/// MCP method constants
pub mod methods {
    pub const INITIALIZE: &str = "initialize";
    pub const INITIALIZED: &str = "notifications/initialized";
    pub const PING: &str = "ping";
    pub const CANCELLED: &str = "notifications/cancelled";
    pub const PROGRESS: &str = "notifications/progress";

    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";

    pub const RESOURCES_LIST: &str = "resources/list";
    pub const RESOURCES_READ: &str = "resources/read";
    pub const RESOURCES_SUBSCRIBE: &str = "resources/subscribe";
    pub const RESOURCES_UNSUBSCRIBE: &str = "resources/unsubscribe";
    pub const RESOURCES_UPDATED: &str = "notifications/resources/updated";
    pub const RESOURCES_LIST_CHANGED: &str = "notifications/resources/list_changed";

    pub const PROMPTS_LIST: &str = "prompts/list";
    pub const PROMPTS_GET: &str = "prompts/get";
    pub const PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";

    pub const LOGGING_SET_LEVEL: &str = "logging/setLevel";
    pub const LOGGING_MESSAGE: &str = "notifications/message";

    pub const SAMPLING_CREATE_MESSAGE: &str = "sampling/createMessage";
}

/// MCP error codes (in addition to standard JSON-RPC codes)
pub mod error_codes {
    /// Request was cancelled
    pub const REQUEST_CANCELLED: i32 = -32800;
    /// Request timeout
    pub const REQUEST_TIMEOUT: i32 = -32801;
    /// Tool not found
    pub const TOOL_NOT_FOUND: i32 = -32802;
    /// Resource not found
    pub const RESOURCE_NOT_FOUND: i32 = -32803;
    /// Prompt not found
    pub const PROMPT_NOT_FOUND: i32 = -32804;
    /// Policy denied
    pub const POLICY_DENIED: i32 = -32850;
    /// Budget exceeded
    pub const BUDGET_EXCEEDED: i32 = -32851;
    /// Identity required
    pub const IDENTITY_REQUIRED: i32 = -32852;
}

/// Helper to create MCP-specific errors
impl JsonRpcError {
    /// Request was cancelled
    pub fn request_cancelled() -> Self {
        Self::new(error_codes::REQUEST_CANCELLED, "Request cancelled")
    }

    /// Request timeout
    pub fn request_timeout() -> Self {
        Self::new(error_codes::REQUEST_TIMEOUT, "Request timeout")
    }

    /// Tool not found
    pub fn tool_not_found(name: &str) -> Self {
        Self::new(error_codes::TOOL_NOT_FOUND, format!("Tool not found: {name}"))
    }

    /// Resource not found
    pub fn resource_not_found(uri: &str) -> Self {
        Self::new(error_codes::RESOURCE_NOT_FOUND, format!("Resource not found: {uri}"))
    }

    /// Prompt not found
    pub fn prompt_not_found(name: &str) -> Self {
        Self::new(error_codes::PROMPT_NOT_FOUND, format!("Prompt not found: {name}"))
    }

    /// Policy denied
    pub fn policy_denied(reason: &str) -> Self {
        Self::new(error_codes::POLICY_DENIED, format!("Policy denied: {reason}"))
    }

    /// Budget exceeded
    pub fn budget_exceeded(reason: &str) -> Self {
        Self::new(error_codes::BUDGET_EXCEEDED, format!("Budget exceeded: {reason}"))
    }

    /// Identity required
    pub fn identity_required() -> Self {
        Self::new(error_codes::IDENTITY_REQUIRED, "Identity verification required")
    }
}

/// Extract tool name from a tools/call request
pub fn extract_tool_name(params: &Value) -> Option<&str> {
    params.get("name").and_then(|v| v.as_str())
}

/// Extract tool arguments from a tools/call request
pub fn extract_tool_arguments(params: &Value) -> Option<&Value> {
    params.get("arguments")
}

/// Extract resource URI from a resources/read request
pub fn extract_resource_uri(params: &Value) -> Option<&str> {
    params.get("uri").and_then(|v| v.as_str())
}

/// Create an initialize request
pub fn create_initialize_request(client_info: McpClientInfo, capabilities: McpCapabilities, id: RequestId) -> JsonRpcRequest {
    let params = InitializeParams {
        protocol_version: MCP_VERSION.to_string(),
        capabilities,
        client_info,
    };
    JsonRpcRequest::new(
        methods::INITIALIZE,
        Some(serde_json::to_value(params).unwrap()),
        id,
    )
}

/// Create an initialized notification
pub fn create_initialized_notification() -> JsonRpcRequest {
    JsonRpcRequest::notification(methods::INITIALIZED, None)
}

/// Create a tools/list request
pub fn create_tools_list_request(id: RequestId) -> JsonRpcRequest {
    JsonRpcRequest::new(methods::TOOLS_LIST, None, id)
}

/// Create a tools/call request
pub fn create_tools_call_request(name: &str, arguments: Value, id: RequestId) -> JsonRpcRequest {
    let params = ToolCallParams {
        name: name.to_string(),
        arguments,
    };
    JsonRpcRequest::new(
        methods::TOOLS_CALL,
        Some(serde_json::to_value(params).unwrap()),
        id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_params() {
        let params = InitializeParams {
            protocol_version: MCP_VERSION.to_string(),
            capabilities: McpCapabilities::default(),
            client_info: McpClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
        };

        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], MCP_VERSION);
        assert_eq!(json["clientInfo"]["name"], "test-client");
    }

    #[test]
    fn test_tool_serialization() {
        let tool = Tool {
            name: "read_file".to_string(),
            description: Some("Read a file".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
        };

        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "read_file");
        assert!(json["inputSchema"].is_object());
    }

    #[test]
    fn test_content_types() {
        let text = Content::Text {
            text: "Hello".to_string(),
        };
        let json = serde_json::to_value(&text).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "Hello");

        let image = Content::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_value(&image).unwrap();
        assert_eq!(json["type"], "image");
    }

    #[test]
    fn test_extract_tool_name() {
        let params = serde_json::json!({
            "name": "read_file",
            "arguments": { "path": "/etc/hosts" }
        });
        assert_eq!(extract_tool_name(&params), Some("read_file"));
    }

    #[test]
    fn test_mcp_errors() {
        let err = JsonRpcError::policy_denied("blocked by policy");
        assert_eq!(err.code, error_codes::POLICY_DENIED);
        assert!(err.message.contains("blocked by policy"));
    }
}
