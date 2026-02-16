//! Daemon lifecycle utilities for `soth start`.

use crate::style;
use anyhow::{anyhow, Context};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const PID_FILE: &str = "proxy.pid";
const LOG_FILE: &str = "proxy.log";

fn soth_home_dir() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn run_dir() -> PathBuf {
    soth_home_dir().join("run")
}

fn logs_dir() -> PathBuf {
    soth_home_dir().join("logs")
}

pub fn pid_path() -> PathBuf {
    run_dir().join(PID_FILE)
}

pub fn log_path() -> PathBuf {
    logs_dir().join(LOG_FILE)
}

fn ensure_runtime_dirs() -> anyhow::Result<()> {
    std::fs::create_dir_all(run_dir()).context("failed creating ~/.soth/run")?;
    std::fs::create_dir_all(logs_dir()).context("failed creating ~/.soth/logs")?;
    Ok(())
}

fn read_pid() -> anyhow::Result<Option<u32>> {
    let path = pid_path();
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading pid file {}", path.display()))?;
    let pid = content
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid file contents in {}", path.display()))?;
    Ok(Some(pid))
}

fn write_pid(pid: u32) -> anyhow::Result<()> {
    let path = pid_path();
    std::fs::write(&path, format!("{pid}\n"))
        .with_context(|| format!("failed writing pid file {}", path.display()))?;
    Ok(())
}

fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_path());
}

fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn send_term(pid: u32) {
    #[cfg(unix)]
    {
        let group = format!("-{pid}");
        let group_status = Command::new("kill")
            .arg("-TERM")
            .arg(&group)
            .stderr(Stdio::null())
            .status();
        if !group_status.map(|status| status.success()).unwrap_or(false) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn send_kill(pid: u32) {
    #[cfg(unix)]
    {
        let group = format!("-{pid}");
        let group_status = Command::new("kill")
            .arg("-KILL")
            .arg(&group)
            .stderr(Stdio::null())
            .status();
        if !group_status.map(|status| status.success()).unwrap_or(false) {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(pid.to_string())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn compact_path(path: &Path) -> String {
    let full = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home = home.display().to_string();
        if full.starts_with(&home) {
            return format!("~{}", &full[home.len()..]);
        }
    }
    full
}

pub async fn run_start_daemon(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> anyhow::Result<()> {
    ensure_runtime_dirs()?;

    if let Some(pid) = read_pid()? {
        if is_process_running(pid) {
            if !quiet {
                style::success(&format!("Proxy daemon already running (pid {pid})."));
                style::info(&format!(
                    "Logs: {} (use `soth logs -f`)",
                    compact_path(&log_path())
                ));
            }
            return Ok(());
        }
        remove_pid_file();
    }

    let log_file_path = log_path();
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
        .with_context(|| format!("failed opening {}", log_file_path.display()))?;
    let stderr_file = stdout_file
        .try_clone()
        .context("failed cloning daemon log file handle")?;

    let current_exe = std::env::current_exe().context("failed resolving current executable")?;
    let mut cmd = Command::new(current_exe);
    cmd.arg("start")
        .arg("--daemon-child")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    if quiet {
        cmd.arg("--quiet");
    }

    if let Some(port) = port {
        cmd.arg("--port").arg(port.to_string());
    }
    if let Some(ref config_path) = config_path {
        cmd.arg("--config").arg(config_path);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn().context("failed spawning proxy daemon")?;
    std::thread::sleep(Duration::from_millis(300));

    if let Some(status) = child
        .try_wait()
        .context("failed checking proxy daemon startup status")?
    {
        return Err(anyhow!(
            "proxy daemon exited early with status {status}; check {}",
            compact_path(&log_file_path)
        ));
    }

    let pid = child.id();
    write_pid(pid)?;

    if !quiet {
        style::success(&format!("Proxy daemon started (pid {pid})."));
        style::kv("Logs", &compact_path(&log_file_path));
        style::kv("Control", "soth stop");
        style::kv("Tail", "soth logs -f");
    }
    Ok(())
}

pub async fn run_stop() -> anyhow::Result<()> {
    let Some(pid) = read_pid()? else {
        style::warning("Proxy daemon is not running (no pid file).");
        return Ok(());
    };

    if !is_process_running(pid) {
        remove_pid_file();
        style::warning("Proxy daemon pid file was stale; cleaned up.");
        let _ = super::system::disable_quiet().await;
        return Ok(());
    }

    send_term(pid);
    for _ in 0..40 {
        if !is_process_running(pid) {
            remove_pid_file();
            let _ = super::system::disable_quiet().await;
            style::success("Proxy daemon stopped.");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    send_kill(pid);
    for _ in 0..20 {
        if !is_process_running(pid) {
            remove_pid_file();
            let _ = super::system::disable_quiet().await;
            style::success("Proxy daemon stopped (forced).");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(anyhow!(
        "failed to stop proxy daemon pid {}; stop manually then remove {}",
        pid,
        compact_path(&pid_path())
    ))
}

pub async fn run_logs(follow: bool, lines: usize) -> anyhow::Result<()> {
    let path = log_path();
    if !path.exists() {
        style::warning(&format!("Log file not found: {}", compact_path(&path)));
        return Ok(());
    }

    let lines = lines.max(1);
    let mut tail = Command::new("tail");
    tail.arg("-n").arg(lines.to_string());
    if follow {
        tail.arg("-f");
    }
    tail.arg(&path);

    match tail.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(anyhow!("tail exited with status {}", status)),
        Err(_) => {
            print_last_lines(&path, lines)?;
            if follow {
                style::warning(
                    "follow mode requires `tail`; install it or use another terminal tool.",
                );
            }
            Ok(())
        }
    }
}

fn print_last_lines(path: &Path, lines: usize) -> anyhow::Result<()> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut all = Vec::new();
    for line in reader.lines() {
        all.push(line?);
    }
    let start = all.len().saturating_sub(lines);
    for line in all.into_iter().skip(start) {
        println!("{line}");
    }
    Ok(())
}
