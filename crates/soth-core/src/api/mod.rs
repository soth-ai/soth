//! Shared edge-cloud wire API contract types.
//!
//! This module intentionally contains only serializable data structures and
//! version helpers used by both edge and cloud implementations.

pub mod types;
pub mod version;

pub use types::*;
pub use version::*;
