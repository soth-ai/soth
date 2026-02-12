//! SOTH sync scaffolding for local edge -> cloud coordination.
//!
//! This crate intentionally starts as lightweight plumbing. It provides:
//! - shared API request clients for metadata/body/config
//! - local config cache helpers
//! - retry queue primitives
//! - a small `SyncAgent` orchestrator scaffold

pub mod agent;
pub mod body_uploader;
pub mod cache;
pub mod config_puller;
pub mod heartbeat;
pub mod metadata_pusher;
pub mod registry_puller;
pub mod retry_queue;

pub use agent::*;
pub use body_uploader::*;
pub use cache::*;
pub use config_puller::*;
pub use heartbeat::*;
pub use metadata_pusher::*;
pub use registry_puller::*;
pub use retry_queue::*;
