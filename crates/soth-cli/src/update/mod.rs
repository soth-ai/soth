//! Hot-update client (Phase 1 / 0.1.1).
//!
//! Public surface used by `commands::update` and `commands::proxy::status`:
//! - [`Channel`] — stable / canary / staging
//! - [`UpdateManifest`] / [`PlatformEntry`] — verified server-supplied data
//! - [`fetch_and_verify_manifest`] — main "is there a new version?" entry
//! - [`download_binary`] — sha256-checked staged download
//! - [`Swapper`] / [`make_swapper`] — atomic per-OS swap dispatch
//! - [`UpdateCache`] — `~/.soth/run/update_cache.json` reader/writer
//!
//! Plan reference: docs/common/2026-05-11/hot-update-0.1.1-impl-plan.md §3.3-3.4
//! Schema reference: docs/common/2026-05-09/hot-update-plan.md §2.1

pub mod cache;
pub mod download;
pub mod manifest;
pub mod swap;

#[cfg(target_os = "linux")]
mod swap_linux;
#[cfg(target_os = "macos")]
mod swap_macos;
#[cfg(target_os = "windows")]
mod swap_windows;

pub use cache::{CachedUpdate, UpdateCache};
pub use download::{download_binary, sha256_of_file, BinarySink};
// Phase 1 callers only use a subset of these; the rest are kept on the
// public surface for Phase 2 (heartbeat-delivered offers) and Phase 4
// (auto-applier). `allow(unused_imports)` to silence dead-re-export
// warnings until those callers land.
#[allow(unused_imports)]
pub use manifest::{
    fetch_and_verify_manifest, platform_key, Channel, PlatformEntry, UpdateManifest, VerifyOptions,
    MANIFEST_SCHEMA_VERSION,
};
#[allow(unused_imports)]
pub use swap::{make_swapper, Swapper};
