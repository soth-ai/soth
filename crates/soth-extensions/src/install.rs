use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::ExtensionError;

// ---------------------------------------------------------------------------
// InstallTarget trait — generic install/uninstall with backup scaffolding
// ---------------------------------------------------------------------------

pub trait InstallTarget {
    type Config: Serialize + DeserializeOwned;

    fn target_path(&self) -> &Path;
    fn load_existing(&self) -> Result<Option<Self::Config>, ExtensionError>;
    fn merge(
        &self,
        existing: Option<Self::Config>,
        additions: Self::Config,
    ) -> Result<Self::Config, ExtensionError>;
    fn validate(&self, config: &Self::Config) -> Result<(), ExtensionError>;
    fn write(&self, config: &Self::Config) -> Result<(), ExtensionError>;
}

#[derive(Debug)]
pub struct InstallSummary {
    pub target_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub was_fresh: bool,
    pub dry_run: bool,
}

pub fn install_with_backup<T: InstallTarget>(
    target: &T,
    additions: T::Config,
    backup_dir: &Path,
    dry_run: bool,
) -> Result<InstallSummary, ExtensionError> {
    let existing = target.load_existing()?;
    let was_fresh = existing.is_none();
    let backup_path = if !was_fresh && !dry_run {
        Some(backup_file(target.target_path(), backup_dir)?)
    } else {
        None
    };
    let merged = target.merge(existing, additions)?;
    target.validate(&merged)?;
    if !dry_run {
        target.write(&merged)?;
    }
    Ok(InstallSummary {
        target_path: target.target_path().to_owned(),
        backup_path,
        was_fresh,
        dry_run,
    })
}

fn backup_file(source: &Path, backup_dir: &Path) -> Result<PathBuf, ExtensionError> {
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| ExtensionError::Install(format!("create backup dir: {e}")))?;
    let filename = source
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let backup_name = format!("{filename}.{ts}.bak");
    let dest = backup_dir.join(backup_name);
    std::fs::copy(source, &dest)
        .map_err(|e| ExtensionError::Install(format!("backup copy: {e}")))?;
    Ok(dest)
}
