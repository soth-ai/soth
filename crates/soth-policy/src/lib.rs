//! SOTH Policy - OPA Wasm policy evaluation
//!
//! This crate provides:
//! - OPA Wasm runtime using wasmtime
//! - Two-tier decision caching
//! - YAML policy definition compiler
//! - Policy file loading and hot-reload support

pub mod cache;
pub mod compiler;
pub mod engine;
pub mod loader;
#[cfg(feature = "opa-wasm")]
pub mod wasm;

pub use cache::{CacheConfig, CacheMetrics, DecisionCache};
pub use compiler::{PolicyCompiler, PolicyDefinition};
pub use engine::{PolicyEngine, PolicyEngineConfig};
pub use loader::PolicyLoader;

pub use soth_core::error::{Result, SothError};
pub use soth_core::types::policy::*;
