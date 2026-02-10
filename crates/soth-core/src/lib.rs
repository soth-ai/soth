//! SOTH Core - Shared types, config, and error handling
//!
//! This crate provides the foundation types used across all SOTH components:
//! - Error types with thiserror
//! - Configuration parsing (YAML with env var overrides)
//! - Identity context and trust levels
//! - Policy input/decision types
//! - Observation event types
//! - Budget tracking types
//! - MCP JSON-RPC protocol types
//! - File watching utilities
//! - Event logging utilities

pub mod api;
pub mod config;
pub mod error;
pub mod event_logger;
pub mod types;
pub mod watch;

pub use api::*;
pub use config::{loader::load_config, types::HostAction, types::SothConfig};
pub use error::{Result, SothError};
pub use event_logger::EventLogger;
pub use types::{
    budget::*, identity::*, mcp::*, name_generator::*, observation::*, policy::*, replay::*,
    session::*,
};
