#![forbid(unsafe_code)]
//! Bootstrap stage for rebuilding `soth-core`.

pub mod error;

pub use error::{Result, SothError};

pub const REBUILD_STAGE: &str = "bootstrap";
