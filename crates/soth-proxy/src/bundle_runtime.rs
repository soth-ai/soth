use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::warn;

#[path = "bundle_runtime_state.rs"]
mod state;

use state::{
    record_bundle_reload_failure, record_bundle_reload_success, write_runtime_status,
    RuntimeBundleState, StartupBundleSource,
};

const LAST_KNOWN_GOOD_DIR_NAME: &str = "bundle.last_known_good";

#[derive(Clone)]
pub(crate) struct BundleWatcherInstallHook {
    watcher: Arc<soth_bundle::BundleWatcher>,
    allow_registry_projection_install: bool,
    bundle_dir: PathBuf,
    startup_bundle_source: StartupBundleSource,
}

impl BundleWatcherInstallHook {
    pub(crate) fn new(
        watcher: Arc<soth_bundle::BundleWatcher>,
        allow_registry_projection_install: bool,
        bundle_dir: PathBuf,
        startup_bundle_source: StartupBundleSource,
    ) -> Self {
        Self {
            watcher,
            allow_registry_projection_install,
            bundle_dir,
            startup_bundle_source,
        }
    }
}

impl soth_sync::BundleWatcher for BundleWatcherInstallHook {
    fn install_bundle(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String> {
        let snapshot_assets = assets.clone();
        match self.watcher.install(manifest_bytes, assets) {
            Ok(version) => {
                // Persist to the primary bundle_dir so the next startup
                // loads this version immediately (without waiting for sync).
                if let Err(error) = persist_primary_bundle(
                    self.bundle_dir.as_path(),
                    manifest_bytes,
                    &snapshot_assets,
                ) {
                    warn!(
                        error = %error,
                        "bundle installed in memory but primary dir update failed"
                    );
                }
                if let Err(error) = persist_last_known_good_from_payload(
                    self.bundle_dir.as_path(),
                    manifest_bytes,
                    &snapshot_assets,
                ) {
                    let message = format!(
                        "bundle installed in memory but failed updating last-known-good snapshot: {error:#}"
                    );
                    warn!(
                        bundle_version = %version,
                        error = %error,
                        "bundle snapshot persistence failed"
                    );
                    if let Err(status_error) = record_bundle_reload_failure(
                        self.startup_bundle_source,
                        message.as_str(),
                        Some(version.as_str()),
                    ) {
                        warn!(
                            error = %status_error,
                            "failed writing bundle runtime status after snapshot failure"
                        );
                    }
                } else if let Err(status_error) =
                    record_bundle_reload_success(self.startup_bundle_source, version.as_str())
                {
                    warn!(
                        error = %status_error,
                        "failed writing bundle runtime status after successful reload"
                    );
                }

                Ok(version)
            }
            Err(error) => {
                let message = format!("bundle reload rejected; keeping current bundle: {error:#}");
                warn!(error = %error, "bundle reload rejected; current bundle retained");
                if let Err(status_error) =
                    record_bundle_reload_failure(self.startup_bundle_source, message.as_str(), None)
                {
                    warn!(
                        error = %status_error,
                        "failed writing bundle runtime status after rejected reload"
                    );
                }
                Err(anyhow::Error::from(error))
            }
        }
    }

    fn allow_registry_projection_install(&self) -> bool {
        self.allow_registry_projection_install
    }
}

pub(crate) fn init_bundle_watcher_with_fallback(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: Arc<soth_bundle::OrgSignedConfig>,
    db: Arc<Mutex<rusqlite::Connection>>,
    verification: soth_bundle::VerificationOptions,
) -> Result<(
    soth_bundle::BundleWatcher,
    soth_bundle::BundleHandle,
    StartupBundleSource,
)> {
    match soth_bundle::init_with_options(
        bundle_dir,
        vendor_pubkey,
        org_config.clone(),
        db.clone(),
        verification,
    ) {
        Ok((watcher, handle)) => {
            let active_version = handle.current().version.clone();
            let mut state =
                RuntimeBundleState::new(StartupBundleSource::Primary, None, Some(active_version));
            if let Err(error) = persist_last_known_good_from_dir(bundle_dir) {
                warn!(
                    error = %error,
                    snapshot_dir = %last_known_good_bundle_dir(bundle_dir).display(),
                    "failed to persist last-known-good bundle snapshot from primary bundle"
                );
                state.last_reload_error = Some(format!(
                    "failed to update last-known-good snapshot from primary bundle: {error:#}"
                ));
            }
            if let Err(error) = write_runtime_status(&state) {
                warn!(
                    error = %error,
                    "failed writing bundle runtime status after primary startup"
                );
            }
            Ok((watcher, handle, StartupBundleSource::Primary))
        }
        Err(primary_error) => {
            let fallback_dir = last_known_good_bundle_dir(bundle_dir);
            let primary_message = format!("{primary_error:#}");
            match soth_bundle::init_with_options(
                fallback_dir.as_path(),
                vendor_pubkey,
                org_config,
                db,
                verification,
            ) {
                Ok((watcher, handle)) => {
                    warn!(
                        error = %primary_message,
                        fallback_dir = %fallback_dir.display(),
                        "primary bundle load failed; running from last-known-good bundle snapshot"
                    );
                    let state = RuntimeBundleState::new(
                        StartupBundleSource::FallbackLastKnownGood,
                        Some(primary_message),
                        Some(handle.current().version.clone()),
                    );
                    if let Err(error) = write_runtime_status(&state) {
                        warn!(
                            error = %error,
                            "failed writing bundle runtime status for fallback startup"
                        );
                    }
                    Ok((watcher, handle, StartupBundleSource::FallbackLastKnownGood))
                }
                Err(fallback_error) => {
                    let combined = format!(
                        "primary bundle load failed: {primary_error:#}; fallback load failed from {}: {fallback_error:#}",
                        fallback_dir.display()
                    );
                    let state = RuntimeBundleState::new(
                        StartupBundleSource::StartupFailed,
                        Some(combined.clone()),
                        None,
                    );
                    if let Err(error) = write_runtime_status(&state) {
                        warn!(
                            error = %error,
                            "failed writing bundle runtime status for startup failure"
                        );
                    }
                    Err(anyhow::anyhow!(combined))
                }
            }
        }
    }
}

fn persist_last_known_good_from_dir(bundle_dir: &Path) -> Result<()> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
        format!(
            "read manifest for last-known-good snapshot at {}",
            manifest_path.display()
        )
    })?;
    let manifest: soth_bundle::BundleManifest =
        serde_json::from_slice(manifest_bytes.as_slice())
            .context("parse manifest for last-known-good snapshot")?;
    let mut assets = HashMap::with_capacity(manifest.assets.len());
    for entry in manifest.assets {
        ensure_safe_relative_asset_path(entry.path.as_str())?;
        let asset_path = bundle_dir.join(entry.path.as_str());
        let bytes = std::fs::read(&asset_path).with_context(|| {
            format!(
                "read asset for last-known-good snapshot {}",
                asset_path.display()
            )
        })?;
        assets.insert(entry.path, bytes);
    }
    persist_last_known_good_from_payload(bundle_dir, manifest_bytes.as_slice(), &assets)
}

/// Write the installed bundle assets directly into the primary bundle_dir
/// so the next proxy startup loads this version without waiting for sync.
fn persist_primary_bundle(
    bundle_dir: &Path,
    manifest_bytes: &[u8],
    assets: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    // Write manifest
    let manifest_path = bundle_dir.join("manifest.json");
    std::fs::write(&manifest_path, manifest_bytes)
        .with_context(|| format!("write primary manifest {}", manifest_path.display()))?;

    // Write each asset
    for (relative_path, bytes) in assets {
        ensure_safe_relative_asset_path(relative_path.as_str())?;
        let target = bundle_dir.join(relative_path.as_str());
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create asset parent {}", parent.display()))?;
        }
        std::fs::write(&target, bytes)
            .with_context(|| format!("write primary asset {}", target.display()))?;
    }
    Ok(())
}

pub(crate) fn persist_last_known_good_from_payload(
    bundle_dir: &Path,
    manifest_bytes: &[u8],
    assets: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    let snapshot_dir = last_known_good_bundle_dir(bundle_dir);
    write_snapshot(snapshot_dir.as_path(), manifest_bytes, assets)
}

fn write_snapshot(
    snapshot_dir: &Path,
    manifest_bytes: &[u8],
    assets: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    let snapshot_parent = snapshot_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(snapshot_parent.as_path())
        .with_context(|| format!("create snapshot parent {}", snapshot_parent.display()))?;
    let temp_dir = snapshot_parent.join(format!(
        ".{LAST_KNOWN_GOOD_DIR_NAME}.tmp.{}.{}",
        process::id(),
        now_epoch_ms()
    ));
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(temp_dir.as_path())
        .with_context(|| format!("create temp snapshot dir {}", temp_dir.display()))?;

    let mut entries = assets.iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    for (relative_path, bytes) in entries {
        ensure_safe_relative_asset_path(relative_path.as_str())?;
        let target = temp_dir.join(relative_path.as_str());
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create snapshot asset parent {}", parent.display()))?;
        }
        std::fs::write(target.as_path(), bytes)
            .with_context(|| format!("write snapshot asset {}", target.display()))?;
    }

    let manifest_target = temp_dir.join("manifest.json");
    std::fs::write(manifest_target.as_path(), manifest_bytes)
        .with_context(|| format!("write snapshot manifest {}", manifest_target.display()))?;

    if snapshot_dir.exists() {
        std::fs::remove_dir_all(snapshot_dir)
            .with_context(|| format!("remove stale snapshot dir {}", snapshot_dir.display()))?;
    }
    if let Err(error) = std::fs::rename(temp_dir.as_path(), snapshot_dir) {
        let _ = std::fs::remove_dir_all(temp_dir.as_path());
        return Err(error).with_context(|| {
            format!(
                "promote snapshot from {} to {}",
                temp_dir.display(),
                snapshot_dir.display()
            )
        });
    }
    Ok(())
}

fn ensure_safe_relative_asset_path(relative_path: &str) -> Result<()> {
    let candidate = Path::new(relative_path);
    if relative_path.trim().is_empty() {
        anyhow::bail!("bundle asset path is empty");
    }
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        anyhow::bail!("bundle asset path is not safe: {relative_path}");
    }
    Ok(())
}

fn last_known_good_bundle_dir(bundle_dir: &Path) -> PathBuf {
    bundle_dir
        .parent()
        .map(|parent| parent.join(LAST_KNOWN_GOOD_DIR_NAME))
        .unwrap_or_else(|| PathBuf::from(LAST_KNOWN_GOOD_DIR_NAME))
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{ensure_safe_relative_asset_path, last_known_good_bundle_dir};
    use std::path::PathBuf;

    #[test]
    fn rejects_parent_directory_asset_path() {
        let result = ensure_safe_relative_asset_path("../manifest.json");
        assert!(result.is_err());
    }

    #[test]
    fn resolves_last_known_good_as_bundle_sibling() {
        let bundle = PathBuf::from("/tmp/soth/.soth/bundle");
        let resolved = last_known_good_bundle_dir(bundle.as_path());
        assert_eq!(
            resolved,
            PathBuf::from("/tmp/soth/.soth/bundle.last_known_good")
        );
    }
}
