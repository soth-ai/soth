//! SOTH Policy - policy bundle evaluation.
//!
//! The default path is `sync_policy`, built on shared `soth-core` types.
//! Legacy policy engine modules are behind the `legacy-engine` feature.

#[cfg(feature = "legacy-engine")]
pub mod cache;
#[cfg(feature = "legacy-engine")]
pub mod compiler;
#[cfg(feature = "legacy-engine")]
pub mod engine;
#[cfg(feature = "legacy-engine")]
pub mod loader;
pub mod sync_policy;
#[cfg(feature = "opa-wasm")]
pub mod wasm;

#[cfg(feature = "legacy-engine")]
pub use cache::{CacheConfig, CacheMetrics, DecisionCache};
#[cfg(feature = "legacy-engine")]
pub use compiler::{PolicyCompiler, PolicyDefinition};
#[cfg(feature = "legacy-engine")]
pub use engine::{PolicyEngine, PolicyEngineConfig};
#[cfg(feature = "legacy-engine")]
pub use loader::PolicyLoader;

pub use soth_core::error::{Result, SothError};
pub use soth_core::policy::*;
pub use sync_policy::{PolicyBundle, PolicyBundleError as PolicyError};

/// Evaluate a normalized request and detected artifacts against the active policy bundle.
///
/// This is the canonical synchronous policy entrypoint used by classify/proxy wiring.
pub fn evaluate(
    normalized: &soth_core::NormalizedRequest,
    artifacts: &[soth_core::SensitiveArtifact],
    ctx: &soth_core::PolicyContext,
    bundle: &PolicyBundle,
) -> soth_core::PolicyDecision {
    sync_policy::evaluate(normalized, artifacts, ctx, bundle)
}

/// Load a signed policy bundle from disk.
pub fn load_bundle(path: &std::path::Path) -> std::result::Result<PolicyBundle, PolicyError> {
    sync_policy::load_bundle(path)
}

/// Load a signed policy bundle from bytes.
pub fn load_bundle_from_bytes(bytes: &[u8]) -> std::result::Result<PolicyBundle, PolicyError> {
    sync_policy::load_bundle_from_bytes(bytes)
}

/// Warm policy state after load.
///
/// Current implementation is a no-op warmup hook that preserves the stable contract.
pub fn warm(bundle: &PolicyBundle) {
    sync_policy::warm(bundle);
}
