#![forbid(unsafe_code)]

mod db;
mod error;
mod loader;
mod manifest;
mod scope_check;
mod verify;
mod watcher;
#[cfg(feature = "native-bundle")]
pub mod entity_helpers;
#[cfg(feature = "native-bundle")]
pub mod entity_index;
#[cfg(feature = "native-bundle")]
mod gating_from_native;
#[cfg(feature = "native-bundle")]
mod detect_from_native;

use std::sync::Arc;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

pub use crate::db::{mark_superseded, record_bundle_installed, record_policy_config};
pub use crate::error::BundleError;
pub use crate::loader::{
    load_from_bytes, load_from_bytes_with_options, load_from_dir, load_from_dir_with_options,
};
pub use crate::manifest::{AssetEntry, BundleManifest, BundleScope, OrgSignedConfig};
pub use crate::scope_check::check_scope;
pub use crate::watcher::{BundleHandle, BundleWatcher};
#[cfg(feature = "native-bundle")]
pub use crate::entity_index::entity_index_from_native;
#[cfg(feature = "native-bundle")]
pub use crate::gating_from_native::gating_from_native;
#[cfg(feature = "native-bundle")]
pub use crate::detect_from_native::detect_from_native;
#[cfg(feature = "native-bundle")]
pub use soth_interface::NativeBundle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOptions {
    pub verify_vendor_signature: bool,
    pub require_verified_bundle: bool,
    pub org_approval_pubkey: Option<[u8; 32]>,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            verify_vendor_signature: true,
            require_verified_bundle: false,
            org_approval_pubkey: None,
        }
    }
}

pub use soth_core::BundleTrustLevel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMeta {
    pub bundle_id: String,
    pub model_version: String,
    pub policy_version: String,
    pub org_id: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub vendor_sig: Option<String>,
    pub org_approval_sig: Option<String>,
}

#[derive(Clone)]
pub struct LoadedBundle {
    pub version: String,
    pub installed_at: i64,
    pub meta: BundleMeta,
    pub trust_level: BundleTrustLevel,
    pub classify: Arc<soth_classify::ClassifyBundle>,
    pub policy: Arc<soth_policy::sync_policy::PolicyBundle>,
    pub detect: Arc<soth_core::OwnedDetectBundle>,
    pub gating: Arc<soth_core::GatingBundle>,
    pub env_index: Arc<soth_core::EnvIndex>,
    /// Pre-built entity index for O(1) product/provider identity resolution.
    /// Built from NativeBundle.entities at bundle load time.
    pub entity_index: Arc<soth_core::EntityIndex>,
    pub manifest: BundleManifest,
}

impl LoadedBundle {
    pub fn detect_slice(&self) -> soth_core::DetectBundleSlice<'_> {
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
