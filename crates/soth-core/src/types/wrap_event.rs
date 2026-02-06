//! Wrap event types for SOTH
//!
//! Defines types for the `soth wrap` command event logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Source of the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// MCP traffic from soth wrap (stdio interception)
    #[default]
    Mcp,
    /// Direct AI API inference traffic (api.openai.com, api.anthropic.com, etc.)
    AiProxy,
    /// AI agent app traffic (chatgpt.com, claude.ai - end-user applications)
    AgentApp,
}

/// An event captured during a wrap session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapEvent {
    /// Unique event ID
    pub id: String,

    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,

    /// Session ID for this wrap instance
    pub session_id: String,

    /// Human-readable server name
    pub server_name: String,

    /// Direction of message flow
    pub direction: WrapDirection,

    /// Source of this event (MCP or AI Proxy)
    #[serde(default)]
    pub source: EventSource,

    /// AI provider name (for proxy traffic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// AI model name (for proxy traffic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// JSON-RPC method (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Tool name (for tools/call)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Full message content (JSON-RPC message)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Truncated content preview for large payloads
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_preview: Option<String>,

    /// Request content (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_content: Option<String>,

    /// Request preview (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_preview: Option<String>,

    /// Response content (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_content: Option<String>,

    /// Response preview (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<String>,

    /// HTTP status code (for AI proxy responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    /// Detected agent information
    pub agent: AgentInfo,

    /// Policy evaluation result (if policy layer enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_allowed: Option<bool>,

    /// Policy denial reason
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason: Option<String>,

    /// Whether PII was detected
    #[serde(default)]
    pub pii_detected: bool,

    /// Types of PII detected
    #[serde(default)]
    pub pii_types: Vec<String>,

    /// Token count estimate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_count: Option<u64>,

    /// Estimated cost in USD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,

    /// Latency in milliseconds (for responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

impl WrapEvent {
    /// Create a new wrap event
    pub fn new(
        session_id: impl Into<String>,
        server_name: impl Into<String>,
        direction: WrapDirection,
        agent: AgentInfo,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            session_id: session_id.into(),
            server_name: server_name.into(),
            direction,
            source: EventSource::Mcp,
            provider: None,
            model: None,
            method: None,
            tool_name: None,
            content: None,
            content_preview: None,
            request_content: None,
            request_preview: None,
            response_content: None,
            response_preview: None,
            status_code: None,
            agent,
            policy_allowed: None,
            policy_reason: None,
            pii_detected: false,
            pii_types: Vec::new(),
            token_count: None,
            cost_usd: None,
            latency_ms: None,
        }
    }

    /// Set the event source
    pub fn with_source(mut self, source: EventSource) -> Self {
        self.source = source;
        self
    }

    /// Set the AI provider
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set the AI model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set the method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set the tool name
    pub fn with_tool_name(mut self, name: impl Into<String>) -> Self {
        self.tool_name = Some(name.into());
        self
    }

    /// Set the full content (JSON-RPC message)
    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Set the content preview
    pub fn with_content_preview(mut self, preview: impl Into<String>) -> Self {
        self.content_preview = Some(preview.into());
        self
    }

    /// Set request content (for paired events)
    pub fn with_request(mut self, content: impl Into<String>, preview: impl Into<String>) -> Self {
        self.request_content = Some(content.into());
        self.request_preview = Some(preview.into());
        self
    }

    /// Set response content (for paired events)
    pub fn with_response(mut self, content: impl Into<String>, preview: impl Into<String>) -> Self {
        self.response_content = Some(content.into());
        self.response_preview = Some(preview.into());
        self
    }

    /// Set HTTP status code
    pub fn with_status_code(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }

    /// Set policy result
    pub fn with_policy(mut self, allowed: bool, reason: Option<String>) -> Self {
        self.policy_allowed = Some(allowed);
        self.policy_reason = reason;
        self
    }

    /// Set PII detection results
    pub fn with_pii(mut self, detected: bool, types: Vec<String>) -> Self {
        self.pii_detected = detected;
        self.pii_types = types;
        self
    }

    /// Set token count
    pub fn with_tokens(mut self, count: u64) -> Self {
        self.token_count = Some(count);
        self
    }

    /// Set cost
    pub fn with_cost(mut self, cost: f64) -> Self {
        self.cost_usd = Some(cost);
        self
    }

    /// Set latency
    pub fn with_latency(mut self, ms: u64) -> Self {
        self.latency_ms = Some(ms);
        self
    }
}

/// Direction of message flow in wrap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WrapDirection {
    /// Agent → Server (incoming to server)
    #[serde(rename = "in")]
    In,
    /// Server → Agent (outgoing to agent)
    #[serde(rename = "out")]
    Out,
}

impl std::fmt::Display for WrapDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapDirection::In => write!(f, "→"),
            WrapDirection::Out => write!(f, "←"),
        }
    }
}

/// Information about the detected agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Agent name (e.g., "Claude Desktop", "Claude Code", "Cursor")
    pub name: String,

    /// Agent version if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// How the agent was detected
    pub detected_from: DetectionSource,
}

impl AgentInfo {
    /// Create agent info with a name and detection source
    pub fn new(name: impl Into<String>, detected_from: DetectionSource) -> Self {
        Self {
            name: name.into(),
            version: None,
            detected_from,
        }
    }

    /// Add version information
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Create an unknown agent
    pub fn unknown() -> Self {
        Self {
            name: "Unknown".to_string(),
            version: None,
            detected_from: DetectionSource::Unknown,
        }
    }
}

impl Default for AgentInfo {
    fn default() -> Self {
        Self::unknown()
    }
}

/// How the agent was detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// From MCP initialize message clientInfo
    McpInitialize,
    /// From environment variables
    Environment,
    /// From parent process inspection
    ProcessTree,
    /// From --agent CLI flag
    CommandLine,
    /// Detection source unknown
    Unknown,
}

impl std::fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionSource::McpInitialize => write!(f, "MCP Initialize"),
            DetectionSource::Environment => write!(f, "Environment"),
            DetectionSource::ProcessTree => write!(f, "Process Tree"),
            DetectionSource::CommandLine => write!(f, "CLI Flag"),
            DetectionSource::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_event_creation() {
        let agent =
            AgentInfo::new("Claude Code", DetectionSource::McpInitialize).with_version("1.0.0");
        let event = WrapEvent::new("session-1", "postgres", WrapDirection::In, agent)
            .with_method("tools/call")
            .with_tool_name("query")
            .with_policy(true, None);

        assert_eq!(event.session_id, "session-1");
        assert_eq!(event.server_name, "postgres");
        assert_eq!(event.direction, WrapDirection::In);
        assert_eq!(event.method, Some("tools/call".to_string()));
        assert_eq!(event.tool_name, Some("query".to_string()));
        assert_eq!(event.policy_allowed, Some(true));
    }

    #[test]
    fn test_agent_info() {
        let agent = AgentInfo::new("Cursor", DetectionSource::Environment).with_version("0.42.0");

        assert_eq!(agent.name, "Cursor");
        assert_eq!(agent.version, Some("0.42.0".to_string()));
        assert_eq!(agent.detected_from, DetectionSource::Environment);
    }

    #[test]
    fn test_wrap_direction_display() {
        assert_eq!(WrapDirection::In.to_string(), "→");
        assert_eq!(WrapDirection::Out.to_string(), "←");
    }

    #[test]
    fn test_serialization() {
        let agent = AgentInfo::new("Claude Desktop", DetectionSource::McpInitialize);
        let event = WrapEvent::new("sess-123", "filesystem", WrapDirection::Out, agent)
            .with_method("tools/list");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"direction\":\"out\""));
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"detected_from\":\"mcp_initialize\""));

        // Verify deserialization
        let parsed: WrapEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "sess-123");
        assert_eq!(parsed.direction, WrapDirection::Out);
    }
}
