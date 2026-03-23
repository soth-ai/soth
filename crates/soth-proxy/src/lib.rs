// unsafe_code is denied crate-wide; the single exception is sqlite_vec, which
// must call sqlite3_auto_extension via FFI. deny (not forbid) is used so that
// the per-module allow override on sqlite_vec is permitted.
#![deny(unsafe_code)]

pub mod classify_task;
pub mod config;
pub mod db;
pub mod error;
pub mod gating;
pub mod handler;
mod heartbeat_telemetry;
pub mod pending;
pub mod pending_emit;
pub mod response;
pub mod search;
pub mod session;
#[allow(unsafe_code)]
pub mod sqlite_vec;
pub mod streaming;
mod trace;

pub use config::ProxyConfig;
pub use error::ProxyError;
pub use handler::ProxyHandler;
