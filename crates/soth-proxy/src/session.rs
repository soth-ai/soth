//! Session management

use crate::pipeline::middleware::RequestContext;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Session state
#[derive(Debug, Clone)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// Agent ID (if identified)
    pub agent_id: Option<String>,
    /// Session start time
    pub started_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Request count
    pub request_count: u64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
    /// Total cost
    pub total_cost: f64,
    /// Session metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Whether the session is initialized (MCP handshake complete)
    pub initialized: bool,
    /// Server capabilities (after initialize)
    pub server_capabilities: Option<serde_json::Value>,
}

impl Session {
    /// Create a new session
    pub fn new(id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            agent_id: None,
            started_at: now,
            last_activity: now,
            request_count: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost: 0.0,
            metadata: HashMap::new(),
            initialized: false,
            server_capabilities: None,
        }
    }

    /// Update last activity time
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Increment request count
    pub fn increment_requests(&mut self) {
        self.request_count += 1;
        self.touch();
    }

    /// Add token usage
    pub fn add_tokens(&mut self, input: u64, output: u64) {
        self.total_input_tokens += input;
        self.total_output_tokens += output;
        self.touch();
    }

    /// Add cost
    pub fn add_cost(&mut self, cost: f64) {
        self.total_cost += cost;
    }

    /// Set agent ID
    pub fn set_agent_id(&mut self, agent_id: impl Into<String>) {
        self.agent_id = Some(agent_id.into());
    }

    /// Mark session as initialized
    pub fn mark_initialized(&mut self, capabilities: serde_json::Value) {
        self.initialized = true;
        self.server_capabilities = Some(capabilities);
        self.touch();
    }

    /// Get session duration in seconds
    pub fn duration_secs(&self) -> i64 {
        (self.last_activity - self.started_at).num_seconds()
    }

    /// Create a request context for this session
    pub fn create_context(&self) -> RequestContext {
        let mut ctx = RequestContext::new(&self.id);
        ctx.agent_id = self.agent_id.clone();
        ctx
    }
}

/// Session manager
pub struct SessionManager {
    /// Active sessions
    sessions: RwLock<HashMap<String, Session>>,
    /// Maximum sessions
    max_sessions: usize,
    /// Session timeout in seconds
    session_timeout_secs: i64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions: 1000,
            session_timeout_secs: 3600, // 1 hour
        }
    }

    /// Create with configuration
    pub fn with_config(max_sessions: usize, session_timeout_secs: i64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            session_timeout_secs,
        }
    }

    /// Get or create a session
    pub async fn get_or_create(&self, session_id: &str) -> Session {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.touch();
            return session.clone();
        }

        // Check max sessions
        if sessions.len() >= self.max_sessions {
            // Remove oldest session
            let oldest = sessions
                .iter()
                .min_by_key(|(_, s)| s.last_activity)
                .map(|(id, _)| id.clone());

            if let Some(id) = oldest {
                sessions.remove(&id);
            }
        }

        let session = Session::new(session_id);
        sessions.insert(session_id.to_string(), session.clone());
        session
    }

    /// Get a session
    pub async fn get(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update a session
    pub async fn update(&self, session: Session) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session);
    }

    /// Remove a session
    pub async fn remove(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id)
    }

    /// Get all session IDs
    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    /// Get session count
    pub async fn count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.session_timeout_secs);
        let mut sessions = self.sessions.write().await;

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.last_activity < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            sessions.remove(&id);
        }

        count
    }

    /// Get session statistics
    pub async fn stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;

        let mut stats = SessionStats {
            total_sessions: sessions.len(),
            ..Default::default()
        };

        for session in sessions.values() {
            stats.total_requests += session.request_count;
            stats.total_input_tokens += session.total_input_tokens;
            stats.total_output_tokens += session.total_output_tokens;
            stats.total_cost += session.total_cost;

            if session.initialized {
                stats.initialized_sessions += 1;
            }
        }

        stats
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Session statistics
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Total active sessions
    pub total_sessions: usize,
    /// Initialized sessions
    pub initialized_sessions: usize,
    /// Total requests across all sessions
    pub total_requests: u64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
    /// Total cost
    pub total_cost: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("test-session");
        assert_eq!(session.id, "test-session");
        assert_eq!(session.request_count, 0);
        assert!(!session.initialized);
    }

    #[test]
    fn test_session_updates() {
        let mut session = Session::new("test-session");

        session.increment_requests();
        assert_eq!(session.request_count, 1);

        session.add_tokens(100, 50);
        assert_eq!(session.total_input_tokens, 100);
        assert_eq!(session.total_output_tokens, 50);

        session.add_cost(0.05);
        assert!((session.total_cost - 0.05).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::new();

        let session = manager.get_or_create("session-1").await;
        assert_eq!(session.id, "session-1");

        assert_eq!(manager.count().await, 1);

        let removed = manager.remove("session-1").await;
        assert!(removed.is_some());
        assert_eq!(manager.count().await, 0);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let manager = SessionManager::new();

        let mut session = manager.get_or_create("session-1").await;
        session.increment_requests();
        session.add_tokens(100, 50);
        session.add_cost(0.05);
        manager.update(session).await;

        let stats = manager.stats().await;
        assert_eq!(stats.total_sessions, 1);
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.total_input_tokens, 100);
    }
}
