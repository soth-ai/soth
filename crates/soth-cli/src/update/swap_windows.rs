//! Windows atomic swap (Phase 4b, ships with 0.2.0).
//!
//! Windows holds an exclusive lock on the running `.exe`, so the
//! rename-while-running trick used on macOS / Linux fails. We delegate
//! the actual swap to a tiny sidecar binary `soth-update.exe` that
//! ships alongside the main binary in the install directory:
//!
//!   %LOCALAPPDATA%\soth\soth.exe         <- main binary (will be replaced)
//!   %LOCALAPPDATA%\soth\soth-update.exe  <- sidecar (stable; rarely updated)
//!
//! Flow:
//!   1. `swap()` writes the new binary to the standard staging path,
//!      finds the sidecar, and spawns it with --parent-pid + paths,
//!      then exits the main soth.exe so the lock releases.
//!   2. The sidecar (see `crates/soth-cli-update-sidecar`) waits for
//!      the parent PID to exit, MoveFileExW(MOVEFILE_REPLACE_EXISTING)
//!      to swap install→.previous and stage→install, then `sc start
//!      soth` to restart the service. On healthcheck failure it rolls
//!      back to .previous automatically.
//!
//! Pre-0.2.0 installs lack the sidecar. We surface a clear error in
//! that case so users can manually drop in soth-update.exe rather than
//! ending up in a half-updated state.

#![cfg(target_os = "windows")]

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

use super::swap::{resolve_install_path, Swapper};

const SIDECAR_FILENAME: &str = "soth-update.exe";

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

    fn previous(&self) -> PathBuf {
        let mut p = self.install_path.clone();
        let stem = p
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("soth")
            .to_string();
        p.set_file_name(format!("{}.previous.exe", stem));
        p
    }

    fn sidecar_path(&self) -> Result<PathBuf> {
        let parent = self
            .install_path
            .parent()
            .ok_or_else(|| anyhow!("install_path has no parent"))?;
        let sidecar = parent.join(SIDECAR_FILENAME);
        if !sidecar.exists() {
            bail!(
                "{} not found alongside soth.exe; download it from the same release URL \
                 (soth-update-windows-amd64.exe) and place it next to soth.exe before \
                 re-running update --apply",
                sidecar.display()
            );
        }
        Ok(sidecar)
    }
}

#[async_trait]
impl Swapper for WindowsSwapper {
    fn install_path(&self) -> &Path {
        &self.install_path
    }

    fn previous_path(&self) -> PathBuf {
        self.previous()
    }

    fn stage_path(&self) -> &Path {
        &self.stage_path
    }

    async fn pre_swap(&self) -> Result<()> {
        // Sidecar handles service stop. Nothing for the parent to do.
        Ok(())
    }

    async fn swap(&self) -> Result<()> {
        // Spawn the sidecar with our PID + paths and exit; the sidecar
        // waits for our process to release the install_path lock.
        let sidecar = self.sidecar_path()?;
        let parent_pid = std::process::id();
        let previous = self.previous();

        // Detach the sidecar so it survives our exit. We don't await
        // it — once it's launched, our job is to drop the lock.
        std::process::Command::new(&sidecar)
            .arg("--parent-pid")
            .arg(parent_pid.to_string())
            .arg("--new-binary")
            .arg(&self.stage_path)
            .arg("--install-path")
            .arg(&self.install_path)
            .arg("--previous-path")
            .arg(&previous)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", sidecar.display()))?;

        eprintln!(
            "Windows update: handoff to {} as PID-watcher; \
             this process will exit so the binary lock releases.",
            sidecar.display()
        );
        // Give the sidecar a moment to set up its parent-PID watch
        // before we exit. The sidecar polls every 250ms with a 15s
        // timeout, so 200ms is plenty without slowing the apply down.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // Hard-exit instead of returning Ok(()) — the caller's
        // post_swap healthcheck would fail because there'd be no
        // soth.exe running yet (the sidecar is mid-swap). The sidecar
        // owns the rest of the lifecycle.
        std::process::exit(0);
    }

    async fn post_swap(&self) -> Result<()> {
        // Unreachable on Windows — `swap()` exits the process. Defined
        // for trait completeness only.
        Ok(())
    }

    async fn rollback(&self) -> Result<()> {
        // Manual rollback path: invoke the sidecar with new_binary set
        // to the .previous file. The sidecar treats this exactly like
        // a fresh install — moves install_path → install_path.previous2
        // (preserving forensics), moves new_binary (which IS .previous)
        // → install_path, restarts the service.
        let sidecar = self.sidecar_path()?;
        let previous = self.previous();
        if !previous.exists() {
            bail!("no previous binary at {}", previous.display());
        }
        let parent_pid = std::process::id();

        // For rollback the "previous of previous" path is just a temp
        // park location.
        let mut park = self.install_path.clone();
        let stem = park
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("soth")
            .to_string();
        park.set_file_name(format!("{}.failed.exe", stem));

        std::process::Command::new(&sidecar)
            .arg("--parent-pid")
            .arg(parent_pid.to_string())
            .arg("--new-binary")
            .arg(&previous)
            .arg("--install-path")
            .arg(&self.install_path)
            .arg("--previous-path")
            .arg(&park)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {} for rollback", sidecar.display()))?;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        std::process::exit(0);
    }
}
