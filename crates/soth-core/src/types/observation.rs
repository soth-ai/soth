//! Observation types for SOTH
//!
//! Defines types for logging, auditing, and observability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Direction of message flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// From client to server (incoming)
    #[serde(rename = "in")]
    In,
    /// From server to client (outgoing)
    #[serde(rename = "out")]
    Out,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::In => write!(f, "in"),
            Direction::Out => write!(f, "out"),
        }
    }
}

/// Type of message content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    /// Valid JSON-RPC message
    #[default]
    JsonRpc,
    /// Raw text output
    Raw,
    /// Error output from stderr
    Stderr,
}

/// An observation event for logging/audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationEvent {
    /// Unique event ID
    pub id: String,

    /// Session ID
    pub session_id: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Direction of the message
    pub direction: Direction,

    /// Event type
    pub event_type: EventType,

    /// The message content (may be redacted)
    pub content: String,

    /// Original content hash (for integrity verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// Extracted method name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Message type
    #[serde(default)]
    pub message_type: MessageType,

    /// Estimated token count
    #[serde(default)]
    pub token_count: u64,

    /// Whether PII was detected
    #[serde(default)]
    pub pii_detected: bool,

    /// Types of PII detected
    #[serde(default)]
    pub pii_types: Vec<PiiType>,

    /// Processing duration in microseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_micros: Option<u64>,

    /// Agent ID if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Policy decision for this event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<PolicyDecisionSummary>,
}

impl ObservationEvent {
    /// Create a new observation event
    pub fn new(
        session_id: impl Into<String>,
        direction: Direction,
        event_type: EventType,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            timestamp: Utc::now(),
            direction,
            event_type,
            content: content.into(),
            content_hash: None,
            method: None,
            message_type: MessageType::default(),
            token_count: 0,
            pii_detected: false,
            pii_types: Vec::new(),
            duration_micros: None,
            agent_id: None,
            policy_decision: None,
        }
    }

    /// Set the method name
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set the token count
    pub fn with_token_count(mut self, count: u64) -> Self {
        self.token_count = count;
        self
    }

    /// Set PII detection results
    pub fn with_pii(mut self, detected: bool, types: Vec<PiiType>) -> Self {
        self.pii_detected = detected;
        self.pii_types = types;
        self
    }
}

/// Event type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Request from client
    Request,
    /// Response from server
    Response,
    /// Notification
    Notification,
    /// Session started
    SessionStart,
    /// Session ended
    SessionEnd,
    /// Policy evaluation
    PolicyEval,
    /// Error occurred
    Error,
}

/// Types of PII that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    /// Social Security Number
    Ssn,
    /// Email address
    Email,
    /// Credit card number
    CreditCard,
    /// Phone number
    Phone,
    /// IP address
    IpAddress,
    /// API key or secret
    ApiKey,
    /// Other sensitive data
    Other,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiType::Ssn => write!(f, "SSN"),
            PiiType::Email => write!(f, "Email"),
            PiiType::CreditCard => write!(f, "Credit Card"),
            PiiType::Phone => write!(f, "Phone"),
            PiiType::IpAddress => write!(f, "IP Address"),
            PiiType::ApiKey => write!(f, "API Key"),
            PiiType::Other => write!(f, "Other"),
        }
    }
}

/// Summary of a policy decision for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionSummary {
    /// Whether allowed
    pub allowed: bool,
    /// Matched rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// Violations if denied
    #[serde(default)]
    pub violations: Vec<String>,
}

/// Log entry for JSON-RPC messages (compatible with mcp-reticle)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique ID for this log entry
    pub id: String,

    /// Session ID this log belongs to
    pub session_id: String,

    /// When the message was intercepted (microseconds since UNIX_EPOCH)
    pub timestamp: u64,

    /// Direction of the message
    pub direction: Direction,

    /// The JSON-RPC message content as string
    pub content: String,

    /// Optional: extracted method from JSON-RPC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Optional: processing duration in microseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_micros: Option<u64>,

    /// Type of message content
    #[serde(default)]
    pub message_type: MessageType,

    /// Estimated token count
    #[serde(default)]
    pub token_count: u64,

    /// Server name for multi-server filtering
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

impl LogEntry {
    /// Create a new log entry from JSON content
    pub fn new(
        id: impl Into<String>,
        session_id: impl Into<String>,
        direction: Direction,
        content: serde_json::Value,
    ) -> Self {
        let content_str = serde_json::to_string(&content).unwrap_or_default();
        let method = content
            .get("method")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());

        Self {
            id: id.into(),
            session_id: session_id.into(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            direction,
            content: content_str,
            method,
            duration_micros: None,
            message_type: MessageType::JsonRpc,
            token_count: 0,
            server_name: None,
        }
    }

    /// Create a raw log entry
    pub fn new_raw(
        id: impl Into<String>,
        session_id: impl Into<String>,
        direction: Direction,
        content: impl Into<String>,
        message_type: MessageType,
    ) -> Self {
        Self {
            id: id.into(),
            session_id: session_id.into(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            direction,
            content: content.into(),
            method: None,
            duration_micros: None,
            message_type,
            token_count: 0,
            server_name: None,
        }
    }

    /// Set the server name
    pub fn with_server(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }

    /// Set the token count
    pub fn with_token_count(mut self, count: u64) -> Self {
        self.token_count = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::In.to_string(), "in");
        assert_eq!(Direction::Out.to_string(), "out");
    }

    #[test]
    fn test_observation_event() {
        let event = ObservationEvent::new("session-1", Direction::In, EventType::Request, "{}")
            .with_method("tools/call")
            .with_token_count(100);

        assert_eq!(event.session_id, "session-1");
        assert_eq!(event.direction, Direction::In);
        assert_eq!(event.method, Some("tools/call".to_string()));
        assert_eq!(event.token_count, 100);
    }

    #[test]
    fn test_log_entry_new() {
        let content = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1
        });

        let entry = LogEntry::new("log-1", "session-1", Direction::In, content);
        assert_eq!(entry.method, Some("tools/call".to_string()));
        assert_eq!(entry.message_type, MessageType::JsonRpc);
    }

    #[test]
    fn test_pii_type_display() {
        assert_eq!(PiiType::Ssn.to_string(), "SSN");
        assert_eq!(PiiType::CreditCard.to_string(), "Credit Card");
    }
}
