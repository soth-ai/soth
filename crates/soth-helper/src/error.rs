//! Proxy error types

use thiserror::Error;

/// Proxy error type
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(String),

    /// Identity error
    #[error("Identity error: {0}")]
    Identity(String),

    /// Budget error
    #[error("Budget error: {0}")]
    Budget(String),

    /// Timeout error
    #[error("Timeout after {0}ms")]
    Timeout(u64),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ProxyError {
    /// Create a transport error
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Transport(msg.into())
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a policy error
    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    /// Create an identity error
    pub fn identity(msg: impl Into<String>) -> Self {
        Self::Identity(msg.into())
    }

    /// Create a budget error
    pub fn budget(msg: impl Into<String>) -> Self {
        Self::Budget(msg.into())
    }

    /// Create a timeout error
    pub fn timeout(ms: u64) -> Self {
        Self::Timeout(ms)
    }

    /// Create a config error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Check if this is a transport error
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, ProxyError>;
