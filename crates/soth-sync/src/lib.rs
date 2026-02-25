//! SOTH sync runtime.
//!
//! Public contract surface is intentionally small:
//! - `SyncAgent`
//! - `SyncAgentConfig`
//! - `SyncTickSummary`
//! - `SyncTelemetrySink`
//! - `TelemetrySyncConfig`
//! - `BundleInstallHook`

pub mod agent;
pub mod api_types;
pub mod body_uploader;
pub mod cache;
pub mod config;
pub mod config_puller;
pub mod db;
pub mod exchange;
pub mod heartbeat;
pub mod http_client;
pub mod metadata_pusher;
pub mod registry_puller;
pub mod retry_queue;
pub mod telemetry;

pub use agent::{HeartbeatTelemetryProvider, SyncAgent, SyncAgentConfig, SyncTickSummary};
pub use config::TelemetrySyncConfig;
pub use registry_puller::BundleInstallHook;
pub use telemetry::SyncTelemetrySink;
