use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SdkError {
    #[error("SDK config invalid: {0}")]
    InvalidConfig(String),

    #[error("HMAC key resolution failed: {0}")]
    HmacKey(String),

    #[error("bundle pull failed: {0}")]
    BundlePull(String),

    #[error("bundle verification failed: {0}")]
    BundleVerification(String),

    /// `ClassificationMode::Full` was requested on a target where local ONNX
    /// is unavailable. Customer must pick `Reduced` or `CloudOptIn`.
    #[error("local ONNX classification unavailable on this target — pick ClassificationMode::Reduced or CloudOptIn")]
    OnnxUnavailable,

    /// `ClassificationMode::CloudOptIn` was requested but no
    /// `cloud_classify_endpoint` was configured.
    #[error("cloud-classify endpoint not configured for ClassificationMode::CloudOptIn")]
    CloudClassifyEndpointMissing,

    /// Customer's HmacKey resolved successfully but is empty / shorter than
    /// the documented minimum (32 bytes).
    #[error("HMAC key too short: expected ≥32 bytes, got {got}")]
    HmacKeyTooShort { got: usize },
}
