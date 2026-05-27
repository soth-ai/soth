//! macOS atomic swap.
//!
//! The gnarly bits we hit on PR #76 (May 6) and documented in the
//! parent plan §5.2:
//!
//! - macOS caches code-signing metadata against an inode/path; replacing
//!   the binary while the launchd-managed daemon is still attached can
//!   trigger `Taskgated Invalid Signature` SIGKILL on the next start.
//!   Workaround: `launchctl bootout` first to fully detach, then
//!   bootstrap the unit again after the new binary has been adhoc-resigned.
//!
//! - We re-sign with `codesign --force --sign -` (adhoc) so the new
//!   binary inherits a fresh signature blob; without this the kernel may
//!   reject the new file even after bootout.
//!
//! - Quarantine xattr (`com.apple.quarantine`) is cleared best-effort —
//!   most curl-installed binaries don't have it, but downloads through
//!   Safari/Finder will.
//!
//! Gated at the `mod swap_macos;` declaration in update/mod.rs by
//! `#[cfg(target_os = "macos")]`; no inner cfg needed here.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

use super::swap::{resolve_install_path, Swapper};

const LAUNCHD_LABEL: &str = "ai.soth.proxy";
const LISTENER_HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

pub struct MacosSwapper {
    install_path: PathBuf,
    stage_path: PathBuf,
    plist_path: PathBuf,
}

impl MacosSwapper {
    pub fn new(stage_path: PathBuf) -> Result<Self> {
        let install_path = resolve_install_path()?;
        let plist_path = launch_agent_plist_path()?;
        Ok(Self {
            install_path,
            stage_path,
            plist_path,
        })
    }

    fn previous(&self) -> PathBuf {
        let mut p = self.install_path.clone();
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("soth")
            .to_string();
        p.set_file_name(format!("{name}.previous"));
        p
    }
}

#[async_trait]
impl Swapper for MacosSwapper {
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
        // Bootout the user-domain LaunchAgent. Idempotent: if it isn't
        // bootstrapped, this returns non-zero with a benign "service not
        // found" message — we tolerate that.
        let uid = unsafe { libc::getuid() };
        let target = format!("gui/{uid}/{LAUNCHD_LABEL}");
        let out = Command::new("launchctl")
            .arg("bootout")
            .arg(&target)
            .output()
            .await
            .context("launchctl bootout")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // launchctl returns 113 ("Could not find service") when the
            // unit isn't loaded — fine, we wanted that state anyway.
            if !stderr.contains("Could not find service")
                && !stderr.contains("not currently loaded")
            {
                tracing::warn!(stderr = %stderr, "launchctl bootout returned non-zero (continuing)");
            }
        }

        // `launchctl bootout` is async — it sends SIGTERM and returns
        // before the daemon has finished tearing down its listener.
        // Without an explicit wait here, post_swap's bootstrap races
        // the old daemon's port-release path and the new daemon-child
        // can't bind 8080 → KeepAlive retries for ~90s before the port
        // finally frees (observed in edge-autostart.log:
        //   "Error: port 8080 is already bound by pid(s) X (not a soth
        //    process). Stop that process or pass `--port <PORT>` to
        //    use a different port."
        // repeated every ~10s for ~1m40s until success).
        //
        // Poll the proxy port until we can bind it ourselves — that's
        // the only signal the old listener is truly gone. Time out
        // after 15s and let post_swap try anyway; if it fails the
        // helper's rollback path takes over. Mirrors the Windows
        // sidecar's `wait_for_pid_exit` pattern.
        if let Some(port) = read_configured_port() {
            wait_for_port_release(port, Duration::from_secs(15)).await;
        }
        Ok(())
    }

    async fn swap(&self) -> Result<()> {
        // Re-sign the staged binary with adhoc signature so the kernel
        // accepts it after the path-replace.
        let out = Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&self.stage_path)
            .output()
            .await
            .context("codesign --force --sign -")?;
        if !out.status.success() {
            bail!("codesign failed: {}", String::from_utf8_lossy(&out.stderr));
        }

        // Best-effort: clear quarantine xattr if present.
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&self.stage_path)
            .status()
            .await;

        let prev = self.previous();
        if prev.exists() {
            tokio::fs::remove_file(&prev)
                .await
                .with_context(|| format!("removing stale {}", prev.display()))?;
        }

        // install_path → previous (rename, atomic on same fs)
        tokio::fs::rename(&self.install_path, &prev)
            .await
            .with_context(|| {
                format!(
                    "renaming {} → {}",
                    self.install_path.display(),
                    prev.display()
                )
            })?;
        // stage → install
        tokio::fs::rename(&self.stage_path, &self.install_path)
            .await
            .with_context(|| {
                format!(
                    "renaming {} → {}",
                    self.stage_path.display(),
                    self.install_path.display()
                )
            })?;
        Ok(())
    }

    async fn post_swap(&self) -> Result<()> {
        let uid = unsafe { libc::getuid() };
        if !self.plist_path.exists() {
            // No LaunchAgent — caller likely runs the daemon manually.
            // Healthcheck still runs against the listener port if config
            // exists, but skipping is OK here for foreground users.
            tracing::info!(
                plist = %self.plist_path.display(),
                "no LaunchAgent installed; skipping bootstrap"
            );
            return Ok(());
        }
        let target_domain = format!("gui/{uid}");
        let out = Command::new("launchctl")
            .arg("bootstrap")
            .arg(&target_domain)
            .arg(&self.plist_path)
            .output()
            .await
            .context("launchctl bootstrap")?;
        if !out.status.success() {
            bail!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        wait_for_listener_or_log(LISTENER_HEALTHCHECK_TIMEOUT).await
    }

    async fn rollback(&self) -> Result<()> {
        let prev = self.previous();
        if !prev.exists() {
            bail!(
                "no previous binary at {} — cannot roll back",
                prev.display()
            );
        }
        // Stop, swap previous→install, restart.
        self.pre_swap().await?;
        if self.install_path.exists() {
            // Park the (likely-bad) current install at .failed so we
            // don't lose the artifact entirely; useful for forensics.
            let mut failed = self.install_path.clone();
            let name = failed
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("soth")
                .to_string();
            failed.set_file_name(format!("{name}.failed"));
            let _ = tokio::fs::remove_file(&failed).await;
            tokio::fs::rename(&self.install_path, &failed)
                .await
                .with_context(|| format!("parking failed binary at {}", failed.display()))?;
        }
        tokio::fs::rename(&prev, &self.install_path)
            .await
            .with_context(|| {
                format!(
                    "restoring {} → {}",
                    prev.display(),
                    self.install_path.display()
                )
            })?;
        self.post_swap().await
    }
}

fn launch_agent_plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

/// Wait for the proxy port to be unbound — i.e. for the previous
/// daemon's listener to fully release after `launchctl bootout`.
///
/// `launchctl bootout` is asynchronous: it returns immediately after
/// signalling the daemon, before the listener fd has been closed.
/// If the helper races into `launchctl bootstrap` while the kernel is
/// still tearing down the listener, the new daemon-child fails to
/// bind 8080 and launchd's KeepAlive falls into a 1s/attempt retry
/// loop that can stretch to ~90s before the port finally frees.
///
/// We poll by trying to bind the port ourselves; the moment that
/// succeeds (we drop immediately), the new daemon will too. Best-
/// effort: on timeout we just continue and let post_swap's bootstrap
/// race the old listener — the helper's rollback path covers the
/// failure case if bootstrap actually fails.
async fn wait_for_port_release(port: u16, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    while std::time::Instant::now() < deadline {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                // Drop the listener immediately so the new daemon-
                // child can claim it. If bind succeeds the kernel
                // has fully released the previous owner's fd.
                drop(listener);
                return;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    tracing::warn!(
        port = port,
        timeout_secs = timeout.as_secs(),
        "port still bound after bootout — proceeding anyway; bootstrap may need to retry"
    );
}

/// Best-effort: wait for the daemon to bind its TCP listener.
/// We can't always know the port (pre-config or different config
/// schemas across versions), so we attempt to read `~/.soth/soth.yaml`
/// and parse the proxy port; if that fails, we just sleep briefly
/// and return Ok — Phase 4 introduces real failure detection.
async fn wait_for_listener_or_log(timeout: Duration) -> Result<()> {
    let port = match read_configured_port() {
        Some(p) => p,
        None => {
            tracing::info!("could not read configured proxy port; skipping post-swap healthcheck");
            return Ok(());
        }
    };
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    bail!(
        "daemon did not bind 127.0.0.1:{port} within {timeout:?} after swap"
    );
}

fn read_configured_port() -> Option<u16> {
    let home = dirs::home_dir()?;
    let cfg = home.join(".soth").join("soth.yaml");
    let body = std::fs::read_to_string(&cfg).ok()?;
    // Cheap port extraction without pulling the full SothConfig schema in
    // here. Looks for `port: <num>` at any indentation.
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("port:") {
            if let Ok(n) = rest.trim().parse::<u16>() {
                return Some(n);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Returns immediately when the port is already free.
    #[tokio::test]
    async fn wait_for_port_release_returns_immediately_when_port_is_free() {
        // Bind ephemeral port to get a guaranteed-free one, then release.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let start = Instant::now();
        wait_for_port_release(port, Duration::from_secs(15)).await;
        let elapsed = start.elapsed();
        // Should complete on the first poll, well under the 250ms
        // backoff. Allow generous slack for CI scheduling.
        assert!(
            elapsed < Duration::from_millis(200),
            "expected immediate return on free port; took {elapsed:?}",
        );
    }

    /// Waits + then succeeds when the port is held but released
    /// before the deadline.
    #[tokio::test]
    async fn wait_for_port_release_unblocks_when_other_listener_drops() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Drop the listener after a short delay; the wait helper
        // should observe the port free and return.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            drop(listener);
        });

        let start = Instant::now();
        wait_for_port_release(port, Duration::from_secs(5)).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(300),
            "expected to wait for the spawned drop; took {elapsed:?}",
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "expected to return shortly after drop; took {elapsed:?}",
        );
    }

    /// Times out gracefully when the port is held past the deadline.
    /// Best-effort means we log + continue; the function never errors.
    #[tokio::test]
    async fn wait_for_port_release_times_out_gracefully() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let start = Instant::now();
        wait_for_port_release(port, Duration::from_millis(500)).await;
        let elapsed = start.elapsed();
        // Should have waited approximately the full timeout (port
        // never freed) and returned without panicking.
        assert!(
            elapsed >= Duration::from_millis(400),
            "expected to wait near the timeout; took {elapsed:?}",
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "expected to give up after the timeout; took {elapsed:?}",
        );
        drop(listener);
    }
}
