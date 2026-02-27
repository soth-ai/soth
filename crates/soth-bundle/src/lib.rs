#![forbid(unsafe_code)]

mod db;
mod error;
mod loader;
mod manifest;
mod scope_check;
mod verify;
mod watcher;

use std::sync::Arc;
use std::sync::Mutex;

pub use crate::db::{mark_superseded, record_bundle_installed, record_policy_config};
pub use crate::error::BundleError;
pub use crate::loader::{
    load_from_bytes, load_from_bytes_with_options, load_from_dir, load_from_dir_with_options,
};
pub use crate::manifest::{AssetEntry, BundleManifest, BundleScope, OrgSignedConfig};
pub use crate::scope_check::check_scope;
pub use crate::watcher::{BundleHandle, BundleWatcher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOptions {
    pub verify_vendor_signature: bool,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            verify_vendor_signature: true,
        }
    }
}

#[derive(Clone)]
pub struct LoadedBundle {
    pub version: String,
    pub installed_at: i64,
    pub classify: Arc<soth_classify::ClassifyBundle>,
    pub policy: Arc<soth_policy::sync_policy::PolicyBundle>,
    pub detect: Arc<soth_detect::OwnedDetectBundle>,
    pub gating: Arc<soth_core::GatingBundle>,
    pub manifest: BundleManifest,
}

impl LoadedBundle {
    pub fn detect_slice(&self) -> soth_detect::DetectBundleSlice<'_> {
        self.detect.as_slice()
    }
}

pub fn init(
    bundle_dir: &std::path::Path,
    vendor_pubkey: &[u8; 32],
    org_config: Arc<OrgSignedConfig>,
    db: Arc<Mutex<rusqlite::Connection>>,
) -> Result<(BundleWatcher, BundleHandle), BundleError> {
    init_with_options(
        bundle_dir,
        vendor_pubkey,
        org_config,
        db,
        VerificationOptions::default(),
    )
}

pub fn init_with_options(
    bundle_dir: &std::path::Path,
    vendor_pubkey: &[u8; 32],
    org_config: Arc<OrgSignedConfig>,
    db: Arc<Mutex<rusqlite::Connection>>,
    verification: VerificationOptions,
) -> Result<(BundleWatcher, BundleHandle), BundleError> {
    let initial = load_from_dir_with_options(bundle_dir, vendor_pubkey, &org_config, verification)?;
    BundleWatcher::new(initial, *vendor_pubkey, org_config, db, verification)
}
