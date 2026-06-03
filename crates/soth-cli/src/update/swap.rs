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
        Ok(Box::new(super::swap_macos::MacosSwapper::new(
            staged_binary,
        )?))
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
/// Order (matches docs/INSTALL.md + soth-app's hosted install script):
/// 1. `current_exe()` — if it points to one of the canonical paths, use it.
/// 2. `~/.local/bin/soth[.exe]` — the install script's default on every
///    OS (it standardizes on a Unix-style layout that works under MINGW
///    / Git Bash on Windows, where `$HOME` resolves to the user profile
///    and the binary lands at `C:\Users\<name>\.local\bin\soth.exe`).
/// 3. Windows-only fallbacks for sysadmin-style installs:
///    `%LOCALAPPDATA%\soth\soth.exe` and `%PROGRAMFILES%\soth\soth.exe`.
/// 4. Unix-only fallback: `/usr/local/bin/soth`.
/// 5. Refuse with a clear error if nothing matches.
pub(super) fn resolve_install_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::current_exe() {
        if is_canonical_install_path(&path) {
            return Ok(path);
        }
    }

    // The hosted install script always installs to `$HOME/.local/bin/`
    // — Unix-shaped layout that works the same way under MINGW on
    // Windows (Git Bash's `$HOME` is `C:\Users\<name>`). Checked first
    // on every OS so the swap path lines up with the install path.
    if let Some(home) = dirs::home_dir() {
        let user = home.join(".local").join("bin").join(soth_filename());
        if user.exists() {
            return Ok(user);
        }
    }

    #[cfg(unix)]
    {
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

#[cfg(windows)]
fn soth_filename() -> &'static str {
    "soth.exe"
}
#[cfg(not(windows))]
fn soth_filename() -> &'static str {
    "soth"
}

fn is_canonical_install_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    // Reject Homebrew-managed paths — Homebrew owns its bottles, we don't.
    if s.contains("/Cellar/") || s.contains("/opt/homebrew/") || s.contains("/linuxbrew/") {
        return false;
    }
    // Unix install locations.
    if s.ends_with("/.local/bin/soth") || s.ends_with("/usr/local/bin/soth") {
        return true;
    }
    // Windows install locations. The hosted install script places the
    // binary at `%USERPROFILE%\.local\bin\soth.exe` (MINGW-style
    // layout that mirrors the Unix install for consistency). The
    // sysadmin path is `%LOCALAPPDATA%\soth\soth.exe` or
    // `%PROGRAMFILES%\soth\soth.exe`. Accept both shapes.
    s.ends_with("\\.local\\bin\\soth.exe") || s.ends_with("\\soth\\soth.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_install_paths_accepted() {
        assert!(is_canonical_install_path(Path::new(
            "/home/user/.local/bin/soth"
        )));
        assert!(is_canonical_install_path(Path::new("/usr/local/bin/soth")));
    }

    #[test]
    fn windows_install_script_path_accepted() {
        // The hosted install script writes to
        // `$HOME/.local/bin/soth.exe` on every OS — including Windows
        // under MINGW where `$HOME` is `C:\Users\<name>`. Regression
        // guard for the 0.1.1 Windows smoke test that surfaced this
        // bug ("soth not installed at a canonical path" on a binary
        // installed by the standard install script).
        assert!(is_canonical_install_path(Path::new(
            r"C:\Users\Prabhat\.local\bin\soth.exe"
        )));
        assert!(is_canonical_install_path(Path::new(
            r"C:\Users\someone with spaces\.local\bin\soth.exe"
        )));
    }

    #[test]
    fn windows_sysadmin_paths_accepted() {
        assert!(is_canonical_install_path(Path::new(
            r"C:\Users\u\AppData\Local\soth\soth.exe"
        )));
        assert!(is_canonical_install_path(Path::new(
            r"C:\Program Files\soth\soth.exe"
        )));
    }

    #[test]
    fn homebrew_paths_rejected() {
        // Homebrew owns its bottles; we can't replace files under
        // /opt/homebrew/ without breaking brew's manifest tracking.
        assert!(!is_canonical_install_path(Path::new(
            "/opt/homebrew/bin/soth"
        )));
        assert!(!is_canonical_install_path(Path::new(
            "/opt/homebrew/Cellar/soth/0.1.0/bin/soth"
        )));
        assert!(!is_canonical_install_path(Path::new(
            "/home/linuxbrew/.linuxbrew/bin/soth"
        )));
    }

    #[test]
    fn dev_checkout_and_random_paths_rejected() {
        // A dev checkout build (cargo build) shouldn't self-swap —
        // it's not the user's installed binary.
        assert!(!is_canonical_install_path(Path::new(
            "/Users/me/code/soth/target/debug/soth"
        )));
        assert!(!is_canonical_install_path(Path::new(
            r"D:\work\SothRepo\soth\target\release\soth.exe"
        )));
        assert!(!is_canonical_install_path(Path::new("/tmp/soth")));
        // A file named "soth.exe" that isn't in either canonical
        // Windows layout should be rejected too.
        assert!(!is_canonical_install_path(Path::new(r"C:\tools\soth.exe")));
    }
}
