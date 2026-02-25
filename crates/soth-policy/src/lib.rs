//! SOTH Policy - OPA Wasm policy evaluation
//!
//! This crate provides:
//! - OPA Wasm runtime using wasmtime
//! - Two-tier decision caching
//! - YAML policy definition compiler
//! - Policy file loading and hot-reload support
//! - `sync_policy` (Phase-1) standalone synchronous policy API scaffold

pub mod cache;
pub mod compiler;
pub mod engine;
pub mod loader;
pub mod sync_policy;
#[cfg(feature = "opa-wasm")]
pub mod wasm;

pub use cache::{CacheConfig, CacheMetrics, DecisionCache};
pub use compiler::{PolicyCompiler, PolicyDefinition};
pub use engine::{PolicyEngine, PolicyEngineConfig};
pub use loader::PolicyLoader;

pub use soth_core::error::{Result, SothError};
pub use soth_core::types::policy::*;
