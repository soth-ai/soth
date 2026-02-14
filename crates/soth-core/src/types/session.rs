//! Session recording for MCP message capture and replay
//!
//! Provides functionality to record complete MCP sessions with full message
//! payloads and timing information for accurate replay.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A complete recorded session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedSession {
    /// Unique session ID
    pub id: String,

    /// Human-readable session name
    pub name: String,

    /// Session start timestamp
    pub started_at: DateTime<Utc>,

    /// Session end timestamp (None if still active)
    pub ended_at: Option<DateTime<Utc>>,

    /// All recorded messages in order
    pub messages: Vec<RecordedMessage>,

    /// Session metadata
    pub metadata: SessionMetadata,
}

impl RecordedSession {
    /// Get session duration in milliseconds
    pub fn duration_ms(&self) -> Option<u64> {
        self.ended_at
            .map(|end| (end - self.started_at).num_milliseconds().max(0) as u64)
    }

    /// Get message count
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get messages by direction
    pub fn messages_by_direction(&self, direction: MessageDirection) -> Vec<&RecordedMessage> {
        self.messages
            .iter()
            .filter(|m| m.direction == direction)
            .collect()
    }

    /// Get messages by method
    pub fn messages_by_method(&self, method: &str) -> Vec<&RecordedMessage> {
        self.messages
            .iter()
            .filter(|m| m.method() == Some(method))
            .collect()
    }
}

/// Individual recorded message with full content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedMessage {
    /// Unique message ID
    pub id: String,

    /// Absolute timestamp
    pub timestamp: DateTime<Utc>,

    /// Time since session start in milliseconds
    pub relative_time_ms: u64,

    /// Message direction
    pub direction: MessageDirection,

    /// Full JSON-RPC message content
    pub content: serde_json::Value,

    /// Message metadata
    pub metadata: MessageMetadata,
}

impl RecordedMessage {
    /// Extract method from content
    pub fn method(&self) -> Option<&str> {
        self.content.get("method").and_then(|v| v.as_str())
    }

    /// Extract JSON-RPC ID from content
    pub fn jsonrpc_id(&self) -> Option<&serde_json::Value> {
        self.content.get("id")
    }

    /// Check if this is a request (has method)
    pub fn is_request(&self) -> bool {
        self.content.get("method").is_some()
    }

    /// Check if this is a response (has result or error)
    pub fn is_response(&self) -> bool {
        self.content.get("result").is_some() || self.content.get("error").is_some()
    }

    /// Check if this is a notification (request without id)
    pub fn is_notification(&self) -> bool {
        self.is_request() && self.content.get("id").is_none()
    }
}

/// Message direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// Message from agent/client to server
    ToServer,
    /// Message from server to agent/client
    ToClient,
}

impl std::fmt::Display for MessageDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageDirection::ToServer => write!(f, "→"),
            MessageDirection::ToClient => write!(f, "←"),
        }
    }
}

/// Metadata about a recorded message
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageMetadata {
    /// MCP method name (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// JSON-RPC message ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonrpc_id: Option<serde_json::Value>,

    /// Size in bytes
    pub size_bytes: usize,

    /// Whether this message was modified during recording
    #[serde(default)]
    pub modified: bool,

    /// Policy evaluation result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_allowed: Option<bool>,

    /// PII detection result
    #[serde(default)]
    pub pii_detected: bool,

    /// Token count estimate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_count: Option<u64>,
}

/// Session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Server name
    pub server_name: String,

    /// Transport type (stdio, sse, http)
    pub transport: String,

    /// Agent information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,

    /// Agent version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,

    /// Server version (from MCP initialize)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,

    /// Protocol version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,

    /// Custom tags for filtering
    #[serde(default)]
    pub tags: Vec<String>,

    /// Total token count
    #[serde(default)]
    pub total_tokens: u64,

    /// Messages with PII
    #[serde(default)]
    pub pii_message_count: usize,
}

impl Default for SessionMetadata {
    fn default() -> Self {
        Self {
            server_name: "unknown".to_string(),
            transport: "stdio".to_string(),
            agent_name: None,
            agent_version: None,
            server_version: None,
            protocol_version: None,
            tags: Vec::new(),
            total_tokens: 0,
            pii_message_count: 0,
        }
    }
}

/// Active session recorder
///
/// Thread-safe recorder for capturing MCP messages during a session.
#[derive(Clone)]
pub struct SessionRecorder {
    /// Session ID
    session_id: String,
    /// Session name
    session_name: String,
    /// Session start time
    started_at: DateTime<Utc>,
    /// Recorded messages
    messages: Arc<Mutex<Vec<RecordedMessage>>>,
    /// Session metadata
    metadata: Arc<Mutex<SessionMetadata>>,
    /// Message counter for IDs
    message_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl SessionRecorder {
    /// Create a new session recorder
    pub fn new(session_id: String, session_name: String, server_name: String) -> Self {
        Self {
            session_id,
            session_name,
            started_at: Utc::now(),
            messages: Arc::new(Mutex::new(Vec::new())),
            metadata: Arc::new(Mutex::new(SessionMetadata {
                server_name,
                ..Default::default()
            })),
            message_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get session name
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Record a message
    pub async fn record_message(
        &self,
        content: serde_json::Value,
        direction: MessageDirection,
    ) -> Result<String, SessionRecordError> {
        let now = Utc::now();
        let relative_time_ms = (now - self.started_at).num_milliseconds().max(0) as u64;

        // Extract metadata from content
        let method = content
            .get("method")
            .and_then(|v| v.as_str())
            .map(String::from);
        let jsonrpc_id = content.get("id").cloned();

        let content_str = serde_json::to_string(&content)
            .map_err(|e| SessionRecordError::Serialization(e.to_string()))?;
        let size_bytes = content_str.len();

        // Generate message ID
        let counter = self
            .message_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let message_id = format!("{}-msg-{}", self.session_id, counter);

        let message = RecordedMessage {
            id: message_id.clone(),
            timestamp: now,
            relative_time_ms,
            direction,
            content,
            metadata: MessageMetadata {
                method,
                jsonrpc_id,
                size_bytes,
                ..Default::default()
            },
        };

        // Store message
        let mut messages = self.messages.lock().await;
        messages.push(message);

        Ok(message_id)
    }

    /// Record a message with additional metadata
    pub async fn record_message_with_metadata(
        &self,
        content: serde_json::Value,
        direction: MessageDirection,
        policy_allowed: Option<bool>,
        pii_detected: bool,
        token_count: Option<u64>,
    ) -> Result<String, SessionRecordError> {
        let now = Utc::now();
        let relative_time_ms = (now - self.started_at).num_milliseconds().max(0) as u64;

        let method = content
            .get("method")
            .and_then(|v| v.as_str())
            .map(String::from);
        let jsonrpc_id = content.get("id").cloned();

        let content_str = serde_json::to_string(&content)
            .map_err(|e| SessionRecordError::Serialization(e.to_string()))?;
        let size_bytes = content_str.len();

        let counter = self
            .message_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let message_id = format!("{}-msg-{}", self.session_id, counter);

        let message = RecordedMessage {
            id: message_id.clone(),
            timestamp: now,
            relative_time_ms,
            direction,
            content,
            metadata: MessageMetadata {
                method,
                jsonrpc_id,
                size_bytes,
                modified: false,
                policy_allowed,
                pii_detected,
                token_count,
            },
        };

        // Update session metadata
        {
            let mut meta = self.metadata.lock().await;
            if let Some(tokens) = token_count {
                meta.total_tokens += tokens;
            }
            if pii_detected {
                meta.pii_message_count += 1;
            }
        }

        let mut messages = self.messages.lock().await;
        messages.push(message);

        Ok(message_id)
    }

    /// Update agent information (typically from initialize message)
    pub async fn set_agent_info(&self, name: String, version: Option<String>) {
        let mut meta = self.metadata.lock().await;
        meta.agent_name = Some(name);
        meta.agent_version = version;
    }

    /// Update server information (typically from initialize response)
    pub async fn set_server_info(&self, version: Option<String>, protocol_version: Option<String>) {
        let mut meta = self.metadata.lock().await;
        meta.server_version = version;
        meta.protocol_version = protocol_version;
    }

    /// Add a tag
    pub async fn add_tag(&self, tag: String) {
        let mut meta = self.metadata.lock().await;
        if !meta.tags.contains(&tag) {
            meta.tags.push(tag);
        }
    }

    /// Get current message count
    pub async fn message_count(&self) -> usize {
        self.messages.lock().await.len()
    }

    /// Finalize the recording and return the complete session
    pub async fn finalize(self) -> Result<RecordedSession, SessionRecordError> {
        let ended_at = Utc::now();
        let messages = self.messages.lock().await.clone();
        let metadata = self.metadata.lock().await.clone();

        Ok(RecordedSession {
            id: self.session_id,
            name: self.session_name,
            started_at: self.started_at,
            ended_at: Some(ended_at),
            messages,
            metadata,
        })
    }
}

/// Session storage for saving and loading recordings
pub struct SessionStorage {
    /// Base directory for session files
    base_dir: PathBuf,
}

impl SessionStorage {
    /// Create storage with the default directory (~/.soth/recordings)
    pub fn new() -> Result<Self, SessionRecordError> {
        let base_dir = dirs::home_dir()
            .ok_or_else(|| SessionRecordError::Storage("Could not find home directory".into()))?
            .join(".soth")
            .join("recordings");

        std::fs::create_dir_all(&base_dir)
            .map_err(|e| SessionRecordError::Storage(format!("Failed to create directory: {e}")))?;

        Ok(Self { base_dir })
    }

    /// Create storage with a custom directory
    pub fn with_dir(base_dir: PathBuf) -> Result<Self, SessionRecordError> {
        std::fs::create_dir_all(&base_dir)
            .map_err(|e| SessionRecordError::Storage(format!("Failed to create directory: {e}")))?;

        Ok(Self { base_dir })
    }

    /// Get the path for a session file
    fn session_path(&self, session_id: &str) -> PathBuf {
        self.base_dir.join(format!("{session_id}.json"))
    }

    /// Save a session to disk
    pub fn save(&self, session: &RecordedSession) -> Result<PathBuf, SessionRecordError> {
        let path = self.session_path(&session.id);
        let content = serde_json::to_string_pretty(session)
            .map_err(|e| SessionRecordError::Serialization(e.to_string()))?;

        std::fs::write(&path, content)
            .map_err(|e| SessionRecordError::Storage(format!("Failed to write session: {e}")))?;

        Ok(path)
    }

    /// Load a session from disk
    pub fn load(&self, session_id: &str) -> Result<RecordedSession, SessionRecordError> {
        let path = self.session_path(session_id);
        self.load_from_path(&path)
    }

    /// Load a session from a specific path
    pub fn load_from_path(&self, path: &Path) -> Result<RecordedSession, SessionRecordError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SessionRecordError::Storage(format!("Failed to read session: {e}")))?;

        serde_json::from_str(&content).map_err(|e| SessionRecordError::Serialization(e.to_string()))
    }

    /// List all available sessions
    pub fn list(&self) -> Result<Vec<SessionSummary>, SessionRecordError> {
        let mut summaries = Vec::new();

        let entries = std::fs::read_dir(&self.base_dir)
            .map_err(|e| SessionRecordError::Storage(format!("Failed to read directory: {e}")))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(session) = self.load_from_path(&path) {
                    let duration_ms = session.duration_ms();
                    let message_count = session.messages.len();
                    summaries.push(SessionSummary {
                        id: session.id,
                        name: session.name,
                        server_name: session.metadata.server_name,
                        started_at: session.started_at,
                        ended_at: session.ended_at,
                        message_count,
                        duration_ms,
                    });
                }
            }
        }

        // Sort by start time, newest first
        summaries.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        Ok(summaries)
    }

    /// Delete a session
    pub fn delete(&self, session_id: &str) -> Result<(), SessionRecordError> {
        let path = self.session_path(session_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| SessionRecordError::Storage(format!("Failed to delete: {e}")))?;
        }
        Ok(())
    }
}

impl Default for SessionStorage {
    fn default() -> Self {
        Self::new().expect("Failed to create default session storage")
    }
}

/// Summary of a recorded session (for listing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session ID
    pub id: String,
    /// Session name
    pub name: String,
    /// Server name
    pub server_name: String,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time
    pub ended_at: Option<DateTime<Utc>>,
    /// Number of messages
    pub message_count: usize,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
}

/// Session recording errors
#[derive(Debug, thiserror::Error)]
pub enum SessionRecordError {
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Session not found: {0}")]
    NotFound(String),

    #[error("Replay error: {0}")]
    Replay(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_direction_display() {
        assert_eq!(MessageDirection::ToServer.to_string(), "→");
        assert_eq!(MessageDirection::ToClient.to_string(), "←");
    }

    #[tokio::test]
    async fn test_session_recorder() {
        let recorder = SessionRecorder::new(
            "test-session".to_string(),
            "Test Session".to_string(),
            "test-server".to_string(),
        );

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });

        let id = recorder
            .record_message(msg, MessageDirection::ToServer)
            .await
            .unwrap();

        assert!(id.starts_with("test-session-msg-"));
        assert_eq!(recorder.message_count().await, 1);
    }

    #[tokio::test]
    async fn test_session_finalize() {
        let recorder = SessionRecorder::new(
            "session-1".to_string(),
            "Session One".to_string(),
            "postgres".to_string(),
        );

        recorder
            .record_message(
                serde_json::json!({"method": "initialize"}),
                MessageDirection::ToServer,
            )
            .await
            .unwrap();

        recorder
            .record_message(
                serde_json::json!({"result": {}}),
                MessageDirection::ToClient,
            )
            .await
            .unwrap();

        recorder
            .set_agent_info("Claude".to_string(), Some("1.0".to_string()))
            .await;
        recorder.add_tag("test".to_string()).await;

        let session = recorder.finalize().await.unwrap();

        assert_eq!(session.id, "session-1");
        assert_eq!(session.name, "Session One");
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.metadata.agent_name, Some("Claude".to_string()));
        assert!(session.metadata.tags.contains(&"test".to_string()));
        assert!(session.ended_at.is_some());
    }

    #[test]
    fn test_recorded_message_helpers() {
        let request = RecordedMessage {
            id: "msg-1".to_string(),
            timestamp: Utc::now(),
            relative_time_ms: 0,
            direction: MessageDirection::ToServer,
            content: serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 1
            }),
            metadata: MessageMetadata::default(),
        };

        assert!(request.is_request());
        assert!(!request.is_response());
        assert!(!request.is_notification());
        assert_eq!(request.method(), Some("tools/call"));

        let notification = RecordedMessage {
            id: "msg-2".to_string(),
            timestamp: Utc::now(),
            relative_time_ms: 10,
            direction: MessageDirection::ToServer,
            content: serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled"
            }),
            metadata: MessageMetadata::default(),
        };

        assert!(notification.is_notification());

        let response = RecordedMessage {
            id: "msg-3".to_string(),
            timestamp: Utc::now(),
            relative_time_ms: 20,
            direction: MessageDirection::ToClient,
            content: serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"tools": []},
                "id": 1
            }),
            metadata: MessageMetadata::default(),
        };

        assert!(response.is_response());
        assert!(!response.is_request());
    }

    #[test]
    fn test_session_serialization() {
        let session = RecordedSession {
            id: "test-id".to_string(),
            name: "Test Session".to_string(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            messages: vec![],
            metadata: SessionMetadata::default(),
        };

        let json = serde_json::to_string(&session).unwrap();
        let parsed: RecordedSession = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, session.id);
        assert_eq!(parsed.name, session.name);
    }
}
