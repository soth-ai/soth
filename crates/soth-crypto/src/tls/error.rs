//! TLS error types

use thiserror::Error;

/// Result type alias for TLS operations
pub type Result<T> = std::result::Result<T, TlsError>;

/// TLS error type
#[derive(Debug, Error)]
pub enum TlsError {
    /// Certificate generation error
    #[error("Certificate generation failed: {0}")]
    CertGeneration(String),

    /// CA error
    #[error("CA error: {0}")]
    CaError(String),

    /// Key generation error
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Certificate loading error
    #[error("Failed to load certificate: {0}")]
    CertLoad(String),

    /// Key loading error
    #[error("Failed to load private key: {0}")]
    KeyLoad(String),

    /// SNI extraction error
    #[error("SNI extraction failed: {0}")]
    SniExtraction(String),

    /// Certificate cache error
    #[error("Certificate cache error: {0}")]
    CacheError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid PEM format
    #[error("Invalid PEM format: {0}")]
    InvalidPem(String),

    /// Certificate expired
    #[error("Certificate expired: {0}")]
    Expired(String),

    /// TLS handshake error
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
}

impl TlsError {
    /// Create a certificate generation error
    pub fn cert_generation(msg: impl Into<String>) -> Self {
        Self::CertGeneration(msg.into())
    }

    /// Create a CA error
    pub fn ca_error(msg: impl Into<String>) -> Self {
        Self::CaError(msg.into())
    }

    /// Create a key generation error
    pub fn key_generation(msg: impl Into<String>) -> Self {
        Self::KeyGeneration(msg.into())
    }

    /// Create a certificate load error
    pub fn cert_load(msg: impl Into<String>) -> Self {
        Self::CertLoad(msg.into())
    }

    /// Create a key load error
    pub fn key_load(msg: impl Into<String>) -> Self {
        Self::KeyLoad(msg.into())
    }

    /// Create an SNI extraction error
    pub fn sni_extraction(msg: impl Into<String>) -> Self {
        Self::SniExtraction(msg.into())
    }
}
