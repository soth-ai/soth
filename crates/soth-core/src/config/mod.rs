//! Configuration module for SOTH

pub mod loader;
pub mod runtime_paths;
pub mod types;

pub use loader::load_config;
pub use runtime_paths::*;
pub use types::*;
