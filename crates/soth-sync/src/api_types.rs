//! Cloud API wire types — moved into the standalone `soth-api-types`
//! crate so the SDK (`soth-sdk-core`) and the proxy (`soth-sync`)
//! share one source of truth and cannot drift on the contract.
//!
//! This module re-exports the types under their original paths so
//! existing call sites elsewhere in `soth-sync` keep compiling.

pub use soth_api_types::api_types::*;

/// Compatibility submodule preserved for call sites that imported
/// `crate::api_types::version::*`.
pub mod version {
    pub use soth_api_types::api_types::{API_VERSION, API_VERSION_HEADER};
}
