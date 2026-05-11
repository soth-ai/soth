//! Linux atomic swap.
//!
//! Two flavours auto-detected:
//!
//! 1. **systemd-managed** — root install at `/usr/local/bin/soth`, unit
//!    name `soth-proxy.service`. We `systemctl stop` (root or --user),
//!    rename, `systemctl start`, then healthcheck.
//!
//! 2. **user install, no systemd** — typical `~/.local/bin/soth` run
//!    with `nohup soth proxy start`. We SIGTERM the pid recorded at
//!    `~/.soth/run/proxy.pid`, rename, respawn, healthcheck.
//!
//! Detection order: prefer `systemctl --user is-active` (matches user
//! installs that use systemd-user), fall back to system-wide `systemctl`,
//! fall back to pid-file.

#![cfg(target_os = "linux")]

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

use super::swap::{resolve_install_path, Swapper};

const SYSTEMD_UNIT: &str = "soth-proxy.service";
const LISTENER_HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
enum SupervisorKind {
    SystemdUser,
    SystemdSystem,
    PidFile,
}

pub struct LinuxSwapper {
    install_path: PathBuf,
    stage_path: PathBuf,
    supervisor: SupervisorKind,
}

impl LinuxSwapper {
    pub fn new(stage_path: PathBuf) -> Result<Self> {
        let install_path = resolve_install_path()?;
        let supervisor = detect_supervisor();
        Ok(Self {
            install_path,
            stage_path,
            supervisor,
        })
    }

    fn previous(&self) -> PathBuf {
        let mut p = self.install_path.clone();
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("soth")
            .to_string();
        p.set_file_name(format!("{}.previous", name));
        p
    }
}

#[async_trait]
impl Swapper for LinuxSwapper {
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
        match self.supervisor {
            SupervisorKind::SystemdUser => systemctl(&["--user", "stop", SYSTEMD_UNIT]).await,
            SupervisorKind::SystemdSystem => systemctl(&["stop", SYSTEMD_UNIT]).await,
            SupervisorKind::PidFile => stop_via_pid_file().await,
        }
    }

    async fn swap(&self) -> Result<()> {
        // Linux doesn't need codesign; just chmod +x and swap. Download
        // already chmodded the staging file, but make sure.
        let prev = self.previous();
        if prev.exists() {
            tokio::fs::remove_file(&prev)
                .await
                .with_context(|| format!("removing stale {}", prev.display()))?;
        }
        tokio::fs::rename(&self.install_path, &prev)
            .await
            .with_context(|| {
                format!(
                    "renaming {} → {}",
                    self.install_path.display(),
                    prev.display()
                )
            })?;
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
        match self.supervisor {
            SupervisorKind::SystemdUser => systemctl(&["--user", "start", SYSTEMD_UNIT]).await?,
            SupervisorKind::SystemdSystem => systemctl(&["start", SYSTEMD_UNIT]).await?,
            SupervisorKind::PidFile => {
                start_via_nohup(&self.install_path).await?;
            }
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
        self.pre_swap().await?;
        if self.install_path.exists() {
            let mut failed = self.install_path.clone();
            let name = failed
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("soth")
                .to_string();
            failed.set_file_name(format!("{}.failed", name));
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

fn detect_supervisor() -> SupervisorKind {
    if std::process::Command::new("systemctl")
        .args(["--user", "is-active", SYSTEMD_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return SupervisorKind::SystemdUser;
    }
    if std::process::Command::new("systemctl")
        .args(["is-active", SYSTEMD_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return SupervisorKind::SystemdSystem;
    }
    SupervisorKind::PidFile
}

async fn systemctl(args: &[&str]) -> Result<()> {
    let out = Command::new("systemctl")
        .args(args)
        .output()
        .await
        .with_context(|| format!("systemctl {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

async fn stop_via_pid_file() -> Result<()> {
    let pid_path = pid_file_path()?;
    let pid_str = match tokio::fs::read_to_string(&pid_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("reading {}", pid_path.display())),
    };
    let pid: i32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("parsing pid from {}", pid_path.display()))?;
    // SIGTERM and wait briefly. If it survives, escalate to SIGKILL.
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if !process_alive(pid) {
            return Ok(());
        }
    }
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    Ok(())
}

async fn start_via_nohup(install_path: &Path) -> Result<()> {
    Command::new("nohup")
        .arg(install_path)
        .args(["proxy", "start"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("nohup {} proxy start", install_path.display()))?;
    Ok(())
}

fn pid_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    Ok(home.join(".soth").join("run").join("proxy.pid"))
}

fn process_alive(pid: i32) -> bool {
    // signal(0) returns 0 if the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

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
        "daemon did not bind 127.0.0.1:{} within {:?} after swap",
        port,
        timeout
    );
}

fn read_configured_port() -> Option<u16> {
    let home = dirs::home_dir()?;
    let cfg = home.join(".soth").join("soth.yaml");
    let body = std::fs::read_to_string(&cfg).ok()?;
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
