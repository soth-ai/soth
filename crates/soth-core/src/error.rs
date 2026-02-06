//! Error types for SOTH
//!
//! Provides a unified error type with thiserror for all SOTH components.

use thiserror::Error;

/// Result type alias using SothError
pub type Result<T> = std::result::Result<T, SothError>;

/// Unified error type for SOTH
#[derive(Error, Debug)]
pub enum SothError {
    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Configuration file not found: {0}")]
    ConfigNotFound(String),

    #[error("Invalid configuration: {0}")]
    ConfigInvalid(String),

    // Identity errors
    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    // Policy errors
    #[error("Policy error: {0}")]
    Policy(String),

    #[error("Policy compilation failed: {0}")]
    PolicyCompilation(String),

    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    #[error("Policy denied: {violations:?}")]
    PolicyDenied { violations: Vec<String> },

    // Observation errors
    #[error("Observation error: {0}")]
    Observation(String),

    #[error("PII detection error: {0}")]
    PiiDetection(String),

    #[error("Merkle tree error: {0}")]
    MerkleTree(String),

    #[error("Audit log error: {0}")]
    AuditLog(String),

    // Budget errors
    #[error("Budget error: {0}")]
    Budget(String),

    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("Cost calculation error: {0}")]
    CostCalculation(String),

    // Proxy/Transport errors
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Upstream connection failed: {0}")]
    UpstreamConnection(String),

    #[error("Request forwarding failed: {0}")]
    Forwarding(String),

    #[error("Session error: {0}")]
    Session(String),

    // Protocol errors
    #[error("JSON-RPC error: code={code}, message={message}")]
    JsonRpc { code: i64, message: String },

    #[error("Invalid JSON-RPC message: {0}")]
    InvalidJsonRpc(String),

    #[error("MCP protocol error: {0}")]
    McpProtocol(String),

    // Storage errors
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Database error: {0}")]
    Database(String),

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // Serialization errors
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    #[error("YAML parsing error: {0}")]
    YamlParsing(#[from] serde_yaml::Error),

    // Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl SothError {
    /// Create a JSON-RPC error with standard error codes
    pub fn jsonrpc_parse_error() -> Self {
        Self::JsonRpc {
            code: -32700,
            message: "Parse error".to_string(),
        }
    }

    pub fn jsonrpc_invalid_request(msg: impl Into<String>) -> Self {
        Self::JsonRpc {
            code: -32600,
            message: msg.into(),
        }
    }

    pub fn jsonrpc_method_not_found(method: &str) -> Self {
        Self::JsonRpc {
            code: -32601,
            message: format!("Method not found: {method}"),
        }
    }

    pub fn jsonrpc_invalid_params(msg: impl Into<String>) -> Self {
        Self::JsonRpc {
            code: -32602,
            message: msg.into(),
        }
    }

    pub fn jsonrpc_internal_error(msg: impl Into<String>) -> Self {
        Self::JsonRpc {
            code: -32603,
            message: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SothError::Config("test error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test error");
    }

    #[test]
    fn test_jsonrpc_errors() {
        let err = SothError::jsonrpc_parse_error();
        assert!(matches!(err, SothError::JsonRpc { code: -32700, .. }));

        let err = SothError::jsonrpc_method_not_found("test/method");
        assert!(matches!(err, SothError::JsonRpc { code: -32601, .. }));
    }

    #[test]
    fn test_policy_denied() {
        let err = SothError::PolicyDenied {
            violations: vec!["rule1".to_string(), "rule2".to_string()],
        };
        assert!(err.to_string().contains("rule1"));
    }
}
