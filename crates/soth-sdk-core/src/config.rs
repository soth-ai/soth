//! `SdkConfig` and friends.
//!
//! Locked by `SDK_DECISION_API_SPEC.md` §4 and
//! `SDK_WASM_TRUST_BOUNDARY_SPEC.md` §3. The HMAC key lifecycle in
//! particular is part of the trust model: the SDK never sees the
//! plaintext key over the wire and there is no key-fetching endpoint.

use std::path::PathBuf;
use std::sync::Arc;

use soth_core::CaptureMode;
use zeroize::Zeroizing;

use crate::error::SdkError;

/// Customer-controlled HMAC key reference.
///
/// The key is generated once in the SOTH dashboard, downloaded by the
/// org admin, and stored in the customer's secret manager. The SDK
/// references it via this enum; the cloud never has the plaintext.
///
/// `Static` is provided for tests and rapid prototyping; production
/// integrations use `FromEnv` / `FromFile` / `FromCallback`.
#[non_exhaustive]
pub enum HmacKey {
    /// Read the key from an environment variable (e.g.
    /// `HmacKey::from_env("SOTH_HMAC_KEY")`).
    FromEnv(String),
    /// Read the key from a mounted secret file. The file's full
    /// contents are treated as the key after trimming trailing
    /// whitespace.
    FromFile(PathBuf),
    /// Vault / secret-manager integration. The callback is invoked
    /// at SDK init; failures bubble up as `SdkError::HmacKey`.
    FromCallback(Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>),
    /// Inline bytes — discouraged in production. The wrapper zeroes
    /// the buffer on drop.
    Static(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print actual key material.
        match self {
            Self::FromEnv(name) => f
                .debug_tuple("HmacKey::FromEnv")
                .field(&format!("${name}"))
                .finish(),
            Self::FromFile(path) => f.debug_tuple("HmacKey::FromFile").field(path).finish(),
            Self::FromCallback(_) => f.write_str("HmacKey::FromCallback(<fn>)"),
            Self::Static(bytes) => f
                .debug_tuple("HmacKey::Static")
                .field(&format!("<{} bytes redacted>", bytes.len()))
                .finish(),
        }
    }
}

impl HmacKey {
    pub fn from_env(name: impl Into<String>) -> Self {
        HmacKey::FromEnv(name.into())
    }

    pub fn from_file(path: impl Into<PathBuf>) -> Self {
        HmacKey::FromFile(path.into())
    }

    /// Resolve the key material at SDK init time. Returns the raw bytes
    /// or `SdkError::HmacKey` / `HmacKeyTooShort` on failure. Resolved
    /// material is held in a `Zeroizing<Vec<u8>>` so it scrubs on drop.
    pub fn resolve(&self) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let raw: Zeroizing<Vec<u8>> = match self {
            HmacKey::FromEnv(name) => match std::env::var(name) {
                Ok(value) => Zeroizing::new(value.trim().as_bytes().to_vec()),
                Err(error) => return Err(SdkError::HmacKey(format!("env {name}: {error}"))),
            },
            HmacKey::FromFile(path) => match std::fs::read(path) {
                Ok(bytes) => {
                    let trimmed = std::str::from_utf8(&bytes)
                        .map(|s| s.trim().as_bytes().to_vec())
                        .unwrap_or(bytes);
                    Zeroizing::new(trimmed)
                }
                Err(error) => {
                    return Err(SdkError::HmacKey(format!("file {path:?}: {error}")));
                }
            },
            HmacKey::FromCallback(cb) => match cb() {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(error) => return Err(SdkError::HmacKey(format!("callback: {error}"))),
            },
            HmacKey::Static(bytes) => bytes.clone(),
        };
        if raw.len() < 32 {
            return Err(SdkError::HmacKeyTooShort { got: raw.len() });
        }
        Ok(raw)
    }
}

/// Local-classification mode. Locked by
/// `SDK_WASM_TRUST_BOUNDARY_SPEC.md` §3.2.
///
/// Default selection is **per-target** rather than universal:
/// - Native (Python / Node) and WASM-where-it-fits → `Full`.
/// - Size-constrained edge runtimes (CF Workers, Vercel Edge) → `Reduced`.
/// - `CloudOptIn` is never the default. Customer must set it explicitly
///   after their legal team signs the cloud-classify DPA addendum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ClassificationMode {
    /// Local embedding via ONNX (native or ONNX Web). Content never
    /// leaves the customer's environment.
    #[default]
    Full,
    /// No local embedding. Heuristic detect, counter-based anomaly,
    /// and artifact-based policy. Telemetry events emit with sentinel
    /// values for the semantic fields and a canonical `missing_fields`
    /// list so cloud analytics can filter precisely.
    Reduced,
    /// Customer has explicitly opted in to send normalized request
    /// data to soth-cloud for classification. Requires a DPA covering
    /// content egress.
    CloudOptIn,
}

/// Where the SDK persists its outbox between process restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StorageMode {
    /// In-memory queue only. Telemetry events are lost on process
    /// restart — fine for serverless / short-lived workers.
    #[default]
    InMemory,
    /// File-backed outbox at the configured `bundle_cache_dir`. Long-
    /// lived servers wanting durable delivery should use this.
    /// (Stub for v0; transport implementation lands in Phase 1.)
    FileBacked,
}

/// Where bundles come from at SDK init.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[derive(Default)]
pub enum BundleSource {
    /// Pull from the configured CDN URL with Ed25519 signature
    /// verification. Default for production deployments.
    Cdn { url: String },
    /// Use whatever bundle is bundled into the binding (lite-only).
    /// `ClassificationMode::Reduced` only — the lite bundle does not
    /// contain ONNX models.
    Embedded,
    /// Tests / dev: use the deterministic fallback bundle from
    /// `soth_classify::fallback_bundle()`.
    #[default]
    Fallback,
}


/// Top-level SDK configuration. Construct via [`SdkConfigBuilder`].
pub struct SdkConfig {
    pub api_key: String,
    pub org_id: String,
    /// Optional in v1. When set, the SDK validates the key resolves at
    /// init time and reserves the field for the future
    /// `soth.hash_user_id()` helper. When absent, customers either
    /// pre-compute `user_id_hmac` themselves with their own HMAC
    /// scheme and pass it via `CallContext`, or omit user attribution
    /// entirely.
    ///
    /// **Privacy tradeoff:** without an HMAC key, anything passed
    /// through `user_id_hmac` reaches soth-cloud as-is. Regulated
    /// workloads (HIPAA / heavy-PII) SHOULD still configure a key.
    /// See `SDK_WASM_TRUST_BOUNDARY_SPEC.md` §6.6 for the Phase-2
    /// implementation that closes this loop end-to-end.
    pub hmac_key: Option<HmacKey>,
    pub default_team_id: Option<String>,
    pub default_device_id_hash: Option<String>,
    pub capture_mode: CaptureMode,
    pub storage_mode: StorageMode,
    pub bundle_source: BundleSource,
    pub bundle_cache_dir: Option<PathBuf>,
    pub local_classification: ClassificationMode,
    pub telemetry_endpoint: Option<String>,
    pub cloud_classify_endpoint: Option<String>,
    pub sample_rate: f64,
}

impl std::fmt::Debug for SdkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdkConfig")
            .field("org_id", &self.org_id)
            .field("api_key", &"<redacted>")
            .field("hmac_key", &self.hmac_key)
            .field("default_team_id", &self.default_team_id)
            .field("capture_mode", &self.capture_mode)
            .field("storage_mode", &self.storage_mode)
            .field("bundle_source", &self.bundle_source)
            .field("bundle_cache_dir", &self.bundle_cache_dir)
            .field("local_classification", &self.local_classification)
            .field("telemetry_endpoint", &self.telemetry_endpoint)
            .field("cloud_classify_endpoint", &self.cloud_classify_endpoint)
            .field("sample_rate", &self.sample_rate)
            .finish()
    }
}

/// Fluent builder for [`SdkConfig`]. Required fields (`api_key`,
/// `org_id`, `hmac_key`) must be set before [`build`] is called.
#[derive(Default)]
pub struct SdkConfigBuilder {
    api_key: Option<String>,
    org_id: Option<String>,
    hmac_key: Option<HmacKey>,
    default_team_id: Option<String>,
    default_device_id_hash: Option<String>,
    capture_mode: Option<CaptureMode>,
    storage_mode: Option<StorageMode>,
    bundle_source: Option<BundleSource>,
    bundle_cache_dir: Option<PathBuf>,
    local_classification: Option<ClassificationMode>,
    telemetry_endpoint: Option<String>,
    cloud_classify_endpoint: Option<String>,
    sample_rate: Option<f64>,
}

impl SdkConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }
    pub fn org_id(mut self, org: impl Into<String>) -> Self {
        self.org_id = Some(org.into());
        self
    }
    pub fn hmac_key(mut self, key: HmacKey) -> Self {
        self.hmac_key = Some(key);
        self
    }
    pub fn team_id(mut self, team: impl Into<String>) -> Self {
        self.default_team_id = Some(team.into());
        self
    }
    pub fn device_id_hash(mut self, device: impl Into<String>) -> Self {
        self.default_device_id_hash = Some(device.into());
        self
    }
    pub fn capture_mode(mut self, mode: CaptureMode) -> Self {
        self.capture_mode = Some(mode);
        self
    }
    pub fn storage_mode(mut self, mode: StorageMode) -> Self {
        self.storage_mode = Some(mode);
        self
    }
    pub fn bundle_source(mut self, source: BundleSource) -> Self {
        self.bundle_source = Some(source);
        self
    }
    pub fn bundle_cache_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.bundle_cache_dir = Some(path.into());
        self
    }
    pub fn local_classification(mut self, mode: ClassificationMode) -> Self {
        self.local_classification = Some(mode);
        self
    }
    pub fn telemetry_endpoint(mut self, url: impl Into<String>) -> Self {
        self.telemetry_endpoint = Some(url.into());
        self
    }
    pub fn cloud_classify_endpoint(mut self, url: impl Into<String>) -> Self {
        self.cloud_classify_endpoint = Some(url.into());
        self
    }
    pub fn sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = Some(rate);
        self
    }

    pub fn build(self) -> Result<SdkConfig, SdkError> {
        let api_key = self
            .api_key
            .ok_or_else(|| SdkError::InvalidConfig("api_key required".into()))?;
        let org_id = self
            .org_id
            .ok_or_else(|| SdkError::InvalidConfig("org_id required".into()))?;
        // hmac_key is optional in v1. Customers who skip it pass
        // user_id_hmac through plaintext (or omit it). Phase-2.5 SDK
        // ships a hashing helper that activates per-customer privacy.
        let hmac_key = self.hmac_key;
        let local_classification = self.local_classification.unwrap_or_default();

        // CloudOptIn requires a configured endpoint. Validation here
        // matches the spec's no-auto-fallback rule.
        if matches!(local_classification, ClassificationMode::CloudOptIn)
            && self.cloud_classify_endpoint.is_none()
        {
            return Err(SdkError::CloudClassifyEndpointMissing);
        }

        Ok(SdkConfig {
            api_key,
            org_id,
            hmac_key,
            default_team_id: self.default_team_id,
            default_device_id_hash: self.default_device_id_hash,
            capture_mode: self.capture_mode.unwrap_or(CaptureMode::MetadataOnly),
            storage_mode: self.storage_mode.unwrap_or_default(),
            bundle_source: self.bundle_source.unwrap_or_default(),
            bundle_cache_dir: self.bundle_cache_dir,
            local_classification,
            telemetry_endpoint: self.telemetry_endpoint,
            cloud_classify_endpoint: self.cloud_classify_endpoint,
            sample_rate: self.sample_rate.unwrap_or(1.0).clamp(0.0, 1.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_required_fields() {
        let err = SdkConfigBuilder::new().build().unwrap_err();
        assert!(matches!(err, SdkError::InvalidConfig(_)));
    }

    #[test]
    fn builder_round_trips_minimal_config() {
        let cfg = SdkConfigBuilder::new()
            .api_key("sk-test")
            .org_id("org-test")
            .hmac_key(HmacKey::Static(Zeroizing::new(vec![0u8; 32])))
            .build()
            .expect("build");
        assert_eq!(cfg.org_id, "org-test");
        assert_eq!(cfg.local_classification, ClassificationMode::Full);
        assert!(cfg.hmac_key.is_some());
    }

    #[test]
    fn builder_succeeds_without_hmac_key() {
        // HMAC is opt-in for v1 — see crate docs. Builder must accept
        // the no-key configuration without error.
        let cfg = SdkConfigBuilder::new()
            .api_key("sk-test")
            .org_id("org-test")
            .build()
            .expect("build");
        assert!(cfg.hmac_key.is_none());
    }

    #[test]
    fn cloud_optin_without_endpoint_fails() {
        let err = SdkConfigBuilder::new()
            .api_key("k")
            .org_id("o")
            .local_classification(ClassificationMode::CloudOptIn)
            .build()
            .unwrap_err();
        assert!(matches!(err, SdkError::CloudClassifyEndpointMissing));
    }

    #[test]
    fn hmac_resolve_short_key_rejects() {
        let key = HmacKey::Static(Zeroizing::new(vec![0u8; 8]));
        let err = key.resolve().unwrap_err();
        assert!(matches!(err, SdkError::HmacKeyTooShort { got: 8 }));
    }

    #[test]
    fn hmac_resolve_long_key_works() {
        let key = HmacKey::Static(Zeroizing::new(vec![0u8; 32]));
        let resolved = key.resolve().expect("resolve");
        assert_eq!(resolved.len(), 32);
    }

    #[test]
    fn debug_redacts_static_bytes() {
        let key = HmacKey::Static(Zeroizing::new(vec![1u8; 32]));
        let formatted = format!("{key:?}");
        assert!(formatted.contains("redacted"));
        assert!(!formatted.contains("0x01"));
    }
}
