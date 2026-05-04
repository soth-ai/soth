//! SOTH cloud API wire contract.
//!
//! This crate is the single source of truth for the request/response
//! shapes the proxy (`soth-sync`) and the SDK (`soth-sdk-core`) speak
//! to the SOTH cloud. Keeping the types in one crate prevents the
//! kind of silent schema drift that would otherwise let one side
//! ship events the cloud rejects.
//!
//! - `api_types` — serde structs for telemetry, exchange, heartbeat,
//!   config, registry, and blob upload endpoints.
//! - `convert` — `map_event` plus helpers that turn an in-process
//!   `soth_core::TelemetryEvent` into the cloud-bound
//!   `api_types::TelemetryEvent`. The proxy and the SDK both call
//!   this so a wire-format change here propagates to both at once.
//!
//! No I/O, no tokio, no reqwest. WASM-compatible.

pub mod api_types;
pub mod convert;

pub use api_types::*;
pub use convert::map_event;
