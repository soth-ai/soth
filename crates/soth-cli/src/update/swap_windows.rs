//! Windows swap stub.
//!
//! Windows holds an exclusive lock on the running `.exe`, so the
//! standard rename trick doesn't work — you need either a sidecar
//! updater or the `MOVEFILE_DELAY_UNTIL_REBOOT` flag. The full
//! sidecar implementation ships in 0.2.0 (Phase 4b). Until then
//! we surface a clean error with the manual download URL so users
//! aren't left guessing.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

use super::swap::{resolve_install_path, Swapper};

pub struct WindowsSwapper {
    install_path: PathBuf,
    stage_path: PathBuf,
}

impl WindowsSwapper {
    pub fn new(stage_path: PathBuf) -> Result<Self> {
        let install_path = resolve_install_path()?;
        Ok(Self {
            install_path,
            stage_path,
        })
    }
}

#[async_trait]
impl Swapper for WindowsSwapper {
    fn install_path(&self) -> &Path {
        &self.install_path
    }

    fn previous_path(&self) -> PathBuf {
        let mut p = self.install_path.clone();
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("soth.exe")
            .to_string();
        p.set_file_name(format!(
            "{}.previous.exe",
            name.strip_suffix(".exe").unwrap_or(&name)
        ));
        p
    }

    fn stage_path(&self) -> &Path {
        &self.stage_path
    }

    async fn pre_swap(&self) -> Result<()> {
        Ok(())
    }

    async fn swap(&self) -> Result<()> {
        bail!(
            "Windows in-place self-update is not supported in 0.1.x — \
             ships in 0.2.0 (sidecar updater). Download manually from \
             the manifest's download_url and replace {}",
            self.install_path.display()
        )
    }

    async fn post_swap(&self) -> Result<()> {
        Ok(())
    }

    async fn rollback(&self) -> Result<()> {
        bail!(
            "Windows in-place self-update is not supported in 0.1.x — \
             ships in 0.2.0; manual rollback required"
        )
    }
}
