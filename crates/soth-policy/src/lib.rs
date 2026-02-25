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
