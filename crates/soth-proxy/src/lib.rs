// unsafe_code is denied crate-wide; the single exception is sqlite_vec, which
// must call sqlite3_auto_extension via FFI. deny (not forbid) is used so that
// the per-module allow override on sqlite_vec is permitted.
#![deny(unsafe_code)]
#![allow(clippy::too_many_arguments)]

// ── Public API ───────────────────────────────────────────────────────────────
//
// External consumers go through ProxyHandler / ProxyConfig / ProxyError and
// the items re-exported from `config`, `error`, and `runtime`. Module-level
// submodules below are exposed only where the workspace's own CLI or
// integration tests need them; everything else is crate-internal.

pub mod classify_task;
pub mod config;
pub mod db;
pub mod drain_signal;
pub mod error;
pub mod gating;
pub mod runtime;

pub use config::ProxyConfig;
pub use error::ProxyError;
pub use handler::ProxyHandler;

// ── Crate-internal modules ───────────────────────────────────────────────────
//
// These were previously `pub mod`, but their contents are implementation
// details — any change to them would otherwise be a SemVer-breaking change
// for downstream consumers. Lock them down so we have room to refactor.

pub(crate) mod bundle_runtime;
pub(crate) mod handler;
pub(crate) mod heartbeat_telemetry;
pub(crate) mod observability;
pub(crate) mod ops_server;
pub(crate) mod pending;
pub(crate) mod pending_emit;
pub(crate) mod response;
pub(crate) mod search;
pub(crate) mod session;
#[allow(unsafe_code)]
pub(crate) mod sqlite_vec;
pub(crate) mod streaming;
mod trace;
