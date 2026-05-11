//! Atomic-swap dispatcher.
//!
//! Each platform owns the gnarly subset of "stop the daemon, replace the
//! file, restart, healthcheck" — see `swap_macos.rs`, `swap_linux.rs`,
//! `swap_windows.rs`. This module exposes a uniform [`Swapper`] trait so
//! the `update --apply` command stays platform-agnostic.

use anyhow::Result;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

#[async_trait]
#[allow(dead_code)] // install_path/previous_path/stage_path used by tests + Phase 4
pub trait Swapper: Send + Sync {
    /// Path of the currently-installed `soth` binary that will be replaced.
    fn install_path(&self) -> &Path;

    /// Where the previous binary is moved to before swap (the rollback target).
    fn previous_path(&self) -> PathBuf;

    /// Where a freshly-downloaded binary is staged before swap.
    fn stage_path(&self) -> &Path;

    /// Stop the running daemon (or detach the launchd / systemd unit).
    /// Idempotent: repeated calls during retry must not error if the
    /// daemon is already down.
    async fn pre_swap(&self) -> Result<()>;

    /// Move install→previous, stage→install. Per-platform pre-rename
    /// fixups (codesign on macOS, chmod on Linux) live here too.
    async fn swap(&self) -> Result<()>;

    /// Restart the daemon and confirm it bound its listener.
    async fn post_swap(&self) -> Result<()>;

    /// Best-effort restore: stop, mv previous→install, restart.
    /// Used both on failure during apply and via `soth update --rollback`.
    async fn rollback(&self) -> Result<()>;
}

/// Build the platform-appropriate swapper. The `staged_binary` argument
/// is the freshly-downloaded artifact that will become the new `soth`.
pub fn make_swapper(staged_binary: PathBuf) -> Result<Box<dyn Swapper>> {
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(super::swap_macos::MacosSwapper::new(
            staged_binary,
        )?));
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(super::swap_linux::LinuxSwapper::new(
            staged_binary,
        )?));
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(super::swap_windows::WindowsSwapper::new(
            staged_binary,
        )?));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = staged_binary;
        anyhow::bail!("self-update is not supported on this platform");
    }
}

/// Resolve the canonical install path. Used by all three swap impls.
///
/// Order (matches docs/INSTALL.md):
/// 1. `which soth` — if it points to one of the canonical paths, use it.
/// 2. `~/.local/bin/soth` (Unix) or `%LOCALAPPDATA%\soth\soth.exe`.
/// 3. `/usr/local/bin/soth` (Unix) or `%PROGRAMFILES%\soth\soth.exe`.
/// 4. Refuse with a clear error if nothing matches.
pub(super) fn resolve_install_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::current_exe() {
        if is_canonical_install_path(&path) {
            return Ok(path);
        }
    }

    #[cfg(unix)]
    {
        if let Some(home) = dirs::home_dir() {
            let user = home.join(".local").join("bin").join("soth");
            if user.exists() {
                return Ok(user);
            }
        }
        let root = PathBuf::from("/usr/local/bin/soth");
        if root.exists() {
            return Ok(root);
        }
    }
    #[cfg(windows)]
    {
        if let Some(local) = dirs::data_local_dir() {
            let user = local.join("soth").join("soth.exe");
            if user.exists() {
                return Ok(user);
            }
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            let root = PathBuf::from(pf).join("soth").join("soth.exe");
            if root.exists() {
                return Ok(root);
            }
        }
    }

    anyhow::bail!(
        "soth not installed at a canonical path; manual update required (see docs/INSTALL.md)"
    )
}

fn is_canonical_install_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    // Reject Homebrew-managed paths — Homebrew owns its bottles, we don't.
    if s.contains("/Cellar/") || s.contains("/opt/homebrew/") || s.contains("/linuxbrew/") {
        return false;
    }
    s.ends_with("/.local/bin/soth")
        || s.ends_with("/usr/local/bin/soth")
        || s.ends_with("\\soth\\soth.exe")
}
