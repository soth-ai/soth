use thiserror::Error;

use crate::BundleTrustLevel;

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("invalid vendor public key")]
    InvalidVendorPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    #[error("missing asset: {0}")]
    MissingAsset(String),
    #[error("asset size mismatch for {path}: expected {expected}, got {actual}")]
    AssetSizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("asset hash mismatch for {path}: expected {expected}, got {actual}")]
    AssetHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("bundle expired at {expires_at} (current epoch: {now})")]
    BundleExpired { expires_at: u64, now: u64 },
    #[error("bundle verification required but trust level is {trust_level:?}")]
    VerificationRequired { trust_level: BundleTrustLevel },
    #[error("bundle scope expansion refused: {reason}")]
    ScopeExpansionRefused { reason: String },
    #[error("classify bundle load failed: {0}")]
    ClassifyLoadFailed(String),
    #[error("policy bundle load failed: {0}")]
    PolicyLoadFailed(String),
    #[error("detect bundle load failed: {0}")]
    DetectLoadFailed(String),
    #[error("SQLite error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("watcher channel closed")]
    WatcherChannelClosed,
    #[error("I/O error reading bundle: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    ManifestParse(#[from] serde_json::Error),
    #[error("canonical manifest serialization failed: {0}")]
    CanonicalManifest(String),
    #[error("sqlite connection mutex poisoned")]
    DbMutexPoisoned,
}
