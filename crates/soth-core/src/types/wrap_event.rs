//! Wrap event types for SOTH
//!
//! Defines types for the `soth wrap` command event logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::traffic_envelope::TrafficEnvelope;

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
    /// Monotonic SQLite sequence cursor when sourced from DB-backed event logs.
    /// Absent for JSONL/newly-created in-memory events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,

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

    /// Canonical normalized ingress envelope for this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_envelope: Option<TrafficEnvelope>,

    /// Event hash used as Merkle leaf input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,

    /// Merkle batch identifier when event is sealed into an audit batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_batch_id: Option<String>,

    /// Leaf index within the Merkle batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_leaf_index: Option<u32>,

    /// Merkle root for the sealed batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,

    /// Signature over Merkle root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_signature: Option<String>,

    /// DID used for signing Merkle roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_signer_did: Option<String>,

    /// AI provider name (for proxy traffic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// AI model name (for proxy traffic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// JSON-RPC method (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// GraphQL operation label when request is GraphQL-based.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graphql_operation: Option<String>,

    /// Tool name (for tools/call)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Full message content (JSON-RPC message)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Local collector source name for file-derived events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_source: Option<String>,

    /// Local collector byte offset for file-derived events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_offset: Option<u64>,

    /// External payload reference for full content when moved out of event_json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,

    /// Truncated content preview for large payloads
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_preview: Option<String>,

    /// Request content (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_content: Option<String>,

    /// External payload reference for full request content when moved out of event_json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_content_ref: Option<String>,

    /// Request preview (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_preview: Option<String>,

    /// Response content (for paired request/response events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_content: Option<String>,

    /// External payload reference for full response content when moved out of event_json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_content_ref: Option<String>,

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

    /// Active policy artifact version used for this decision path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,

    /// Whether PII was detected
    #[serde(default)]
    pub pii_detected: bool,

    /// Types of PII detected
    #[serde(default)]
    pub pii_types: Vec<String>,

    /// Token count estimate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_count: Option<u64>,

    /// Input/prompt tokens for AI responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,

    /// Output/completion tokens for AI responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,

    /// Prompt cache read tokens (cache hits)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,

    /// Prompt cache write tokens (cache creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_tokens: Option<u64>,

    /// Reasoning token usage (where provider reports it)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,

    /// Request payload size in bytes (wire payload)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_size_bytes: Option<u64>,

    /// Response payload size in bytes (wire payload)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_size_bytes: Option<u64>,

    /// Sanitized HTTP headers captured for observability (sensitive values redacted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,

    /// User-configured event tags for cost allocation/routing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,

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
            seq: None,
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            session_id: session_id.into(),
            server_name: server_name.into(),
            direction,
            source: EventSource::Mcp,
            traffic_envelope: None,
            event_hash: None,
            merkle_batch_id: None,
            merkle_leaf_index: None,
            merkle_root: None,
            merkle_signature: None,
            audit_signer_did: None,
            provider: None,
            model: None,
            method: None,
            graphql_operation: None,
            tool_name: None,
            content: None,
            collector_source: None,
            collector_offset: None,
            content_ref: None,
            content_preview: None,
            request_content: None,
            request_content_ref: None,
            request_preview: None,
            response_content: None,
            response_content_ref: None,
            response_preview: None,
            status_code: None,
            agent,
            policy_allowed: None,
            policy_reason: None,
            policy_version: None,
            pii_detected: false,
            pii_types: Vec::new(),
            token_count: None,
            input_tokens: None,
            output_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            reasoning_tokens: None,
            request_size_bytes: None,
            response_size_bytes: None,
            headers: None,
            tags: None,
            cost_usd: None,
            latency_ms: None,
        }
    }

    /// Set the event source
    pub fn with_source(mut self, source: EventSource) -> Self {
        self.source = source;
        self
    }

    /// Attach canonical ingress envelope metadata.
    pub fn with_traffic_envelope(mut self, envelope: TrafficEnvelope) -> Self {
        self.traffic_envelope = Some(envelope);
        self
    }

    /// Attach hash used as Merkle leaf input.
    pub fn with_event_hash(mut self, event_hash: impl Into<String>) -> Self {
        self.event_hash = Some(event_hash.into());
        self
    }

    /// Attach Merkle seal metadata for this event.
    pub fn with_merkle_seal(
        mut self,
        batch_id: impl Into<String>,
        leaf_index: u32,
        root: impl Into<String>,
        signature: impl Into<String>,
        signer_did: impl Into<String>,
    ) -> Self {
        self.merkle_batch_id = Some(batch_id.into());
        self.merkle_leaf_index = Some(leaf_index);
        self.merkle_root = Some(root.into());
        self.merkle_signature = Some(signature.into());
        self.audit_signer_did = Some(signer_did.into());
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

    /// Set GraphQL operation label.
    pub fn with_graphql_operation(mut self, operation: impl Into<String>) -> Self {
        self.graphql_operation = Some(operation.into());
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

    /// Set local collector metadata for file-derived events.
    pub fn with_collector_metadata(mut self, source: impl Into<String>, offset: u64) -> Self {
        self.collector_source = Some(source.into());
        self.collector_offset = Some(offset);
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
        let preview = preview.into();
        if !preview.is_empty() {
            self.request_preview = Some(preview);
        }
        self
    }

    /// Set response content (for paired events)
    pub fn with_response(mut self, content: impl Into<String>, preview: impl Into<String>) -> Self {
        self.response_content = Some(content.into());
        let preview = preview.into();
        if !preview.is_empty() {
            self.response_preview = Some(preview);
        }
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

    /// Set policy version
    pub fn with_policy_version(mut self, version: impl Into<String>) -> Self {
        self.policy_version = Some(version.into());
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

    /// Set input/output usage and derived total token count
    pub fn with_usage_tokens(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.input_tokens = Some(input_tokens);
        self.output_tokens = Some(output_tokens);
        self.token_count = Some(input_tokens + output_tokens);
        self
    }

    /// Set cache token details
    pub fn with_cache_tokens(
        mut self,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> Self {
        self.cache_read_tokens = cache_read_tokens;
        self.cache_write_tokens = cache_write_tokens;
        self
    }

    /// Set reasoning token detail
    pub fn with_reasoning_tokens(mut self, reasoning_tokens: u64) -> Self {
        self.reasoning_tokens = Some(reasoning_tokens);
        self
    }

    /// Set request/response payload sizes
    pub fn with_payload_sizes(
        mut self,
        request_size_bytes: Option<u64>,
        response_size_bytes: Option<u64>,
    ) -> Self {
        self.request_size_bytes = request_size_bytes;
        self.response_size_bytes = response_size_bytes;
        self
    }

    /// Set sanitized headers map
    pub fn with_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        if headers.is_empty() {
            self.headers = None;
        } else {
            self.headers = Some(headers);
        }
        self
    }

    /// Set event tags map
    pub fn with_tags(mut self, tags: BTreeMap<String, String>) -> Self {
        if tags.is_empty() {
            self.tags = None;
        } else {
            self.tags = Some(tags);
        }
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

    #[test]
    fn test_usage_tokens_sets_total() {
        let agent = AgentInfo::new("Claude Desktop", DetectionSource::McpInitialize);
        let event = WrapEvent::new("sess-usage", "api.anthropic.com", WrapDirection::Out, agent)
            .with_usage_tokens(120, 45)
            .with_cache_tokens(Some(33), Some(12))
            .with_reasoning_tokens(9)
            .with_payload_sizes(Some(1_024), Some(2_048));

        assert_eq!(event.input_tokens, Some(120));
        assert_eq!(event.output_tokens, Some(45));
        assert_eq!(event.token_count, Some(165));
        assert_eq!(event.cache_read_tokens, Some(33));
        assert_eq!(event.cache_write_tokens, Some(12));
        assert_eq!(event.reasoning_tokens, Some(9));
        assert_eq!(event.request_size_bytes, Some(1_024));
        assert_eq!(event.response_size_bytes, Some(2_048));
    }

    #[test]
    fn test_merkle_fields() {
        let agent = AgentInfo::new("Codex", DetectionSource::Environment);
        let event = WrapEvent::new("sess-merkle", "api.openai.com", WrapDirection::Out, agent)
            .with_event_hash("event-hash-1")
            .with_merkle_seal("batch-1", 7, "root-abc", "sig-xyz", "did:key:z6MkSigner");

        assert_eq!(event.event_hash.as_deref(), Some("event-hash-1"));
        assert_eq!(event.merkle_batch_id.as_deref(), Some("batch-1"));
        assert_eq!(event.merkle_leaf_index, Some(7));
        assert_eq!(event.merkle_root.as_deref(), Some("root-abc"));
        assert_eq!(event.merkle_signature.as_deref(), Some("sig-xyz"));
        assert_eq!(
            event.audit_signer_did.as_deref(),
            Some("did:key:z6MkSigner")
        );
    }
}
