//! Daemon lifecycle utilities for `soth start`.

use crate::style;
use anyhow::{anyhow, Context};
use std::env;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const PID_FILE: &str = "proxy.pid";
const LOG_FILE: &str = "proxy.log";
const DEFAULT_PROXY_PORT: u16 = 8080;
const DEFAULT_DAEMON_STARTUP_TIMEOUT_SECS: u64 = 12;
const MIN_DAEMON_STARTUP_TIMEOUT_SECS: u64 = 3;
const MAX_DAEMON_STARTUP_TIMEOUT_SECS: u64 = 60;
const DEFAULT_PROXY_LOG_MAX_BYTES: u64 = 20 * 1024 * 1024;
const MIN_PROXY_LOG_MAX_BYTES: u64 = 1 * 1024 * 1024;
const MAX_PROXY_LOG_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_PROXY_LOG_MAX_BACKUPS: usize = 5;
const MAX_PROXY_LOG_MAX_BACKUPS: usize = 20;
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "AWS_CA_BUNDLE",
];

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

fn parse_env_u64(key: &str) -> Option<u64> {
    env::var(key).ok()?.trim().parse::<u64>().ok()
}

fn parse_env_usize(key: &str) -> Option<usize> {
    env::var(key).ok()?.trim().parse::<usize>().ok()
}

fn daemon_startup_timeout() -> Duration {
    let secs = parse_env_u64("SOTH_DAEMON_STARTUP_TIMEOUT_SECS")
        .unwrap_or(DEFAULT_DAEMON_STARTUP_TIMEOUT_SECS)
        .clamp(
            MIN_DAEMON_STARTUP_TIMEOUT_SECS,
            MAX_DAEMON_STARTUP_TIMEOUT_SECS,
        );
    Duration::from_secs(secs)
}

fn proxy_log_rotation_limits() -> (u64, usize) {
    let max_bytes = parse_env_u64("SOTH_PROXY_LOG_MAX_BYTES")
        .unwrap_or(DEFAULT_PROXY_LOG_MAX_BYTES)
        .clamp(MIN_PROXY_LOG_MAX_BYTES, MAX_PROXY_LOG_MAX_BYTES);
    let max_backups = parse_env_usize("SOTH_PROXY_LOG_MAX_BACKUPS")
        .unwrap_or(DEFAULT_PROXY_LOG_MAX_BACKUPS)
        .clamp(1, MAX_PROXY_LOG_MAX_BACKUPS);
    (max_bytes, max_backups)
}

fn rotated_log_path(base: &Path, generation: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", base.display(), generation))
}

fn rotate_proxy_log_if_needed(
    log_path: &Path,
    max_bytes: u64,
    max_backups: usize,
) -> anyhow::Result<bool> {
    let metadata = match std::fs::metadata(log_path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.len() < max_bytes {
        return Ok(false);
    }

    let last_backup = rotated_log_path(log_path, max_backups);
    if last_backup.exists() {
        let _ = std::fs::remove_file(&last_backup);
    }
    for generation in (1..=max_backups).rev() {
        let src = if generation == 1 {
            log_path.to_path_buf()
        } else {
            rotated_log_path(log_path, generation - 1)
        };
        if !src.exists() {
            continue;
        }
        let dst = rotated_log_path(log_path, generation);
        std::fs::rename(&src, &dst).with_context(|| {
            format!(
                "failed rotating log from {} to {}",
                src.display(),
                dst.display()
            )
        })?;
    }

    Ok(true)
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

#[cfg(unix)]
fn running_daemon_pids() -> Vec<u32> {
    let output = Command::new("pgrep")
        .args(["-f", "soth start --daemon-child"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| is_process_running(*pid))
        .collect()
}

#[cfg(not(unix))]
fn running_daemon_pids() -> Vec<u32> {
    Vec::new()
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

fn stop_pid_and_wait(pid: u32, timeout: Duration) -> bool {
    if !is_process_running(pid) {
        return true;
    }

    send_term(pid);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !is_process_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    send_kill(pid);
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if !is_process_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    !is_process_running(pid)
}

fn is_local_listener_ready(port: u16) -> bool {
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(120)).is_ok()
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

fn shell_unset_hint_command() -> &'static str {
    let shell = env::var("SHELL")
        .ok()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if shell.contains("fish") {
        "eval (soth runtime env --shell fish --unset)"
    } else {
        "eval \"$(soth runtime env --unset)\""
    }
}

fn shell_set_hint_command() -> &'static str {
    let shell = env::var("SHELL")
        .ok()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if shell.contains("fish") {
        "eval (soth runtime env --shell fish)"
    } else {
        "eval \"$(soth runtime env)\""
    }
}

fn has_local_proxy_env() -> bool {
    PROXY_ENV_KEYS.iter().any(|key| {
        let Ok(value) = env::var(key) else {
            return false;
        };
        let normalized = value.to_ascii_lowercase();
        match *key {
            "HTTP_PROXY" | "HTTPS_PROXY" | "http_proxy" | "https_proxy" => {
                normalized.contains("127.0.0.1") || normalized.contains("localhost")
            }
            "NO_PROXY" | "no_proxy" => {
                normalized.contains("127.0.0.1") || normalized.contains("localhost")
            }
            "SSL_CERT_FILE"
            | "REQUESTS_CA_BUNDLE"
            | "NODE_EXTRA_CA_CERTS"
            | "CURL_CA_BUNDLE"
            | "GIT_SSL_CAINFO"
            | "AWS_CA_BUNDLE" => normalized.contains(".soth"),
            _ => false,
        }
    })
}

fn print_env_setup_hint_if_needed() {
    if !has_local_proxy_env() {
        style::info(&format!(
            "Set shell proxy env in this terminal: {}",
            shell_set_hint_command()
        ));
    }
}

fn should_hint_env_cleanup() -> bool {
    has_local_proxy_env()
}

fn print_env_cleanup_hint_if_needed() {
    if should_hint_env_cleanup() {
        style::info(&format!(
            "Clear shell proxy env in this terminal: {}",
            shell_unset_hint_command()
        ));
    }
}

pub async fn run_start_daemon(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    intercept_all: bool,
    intercept_all_for: Option<u64>,
) -> anyhow::Result<()> {
    ensure_runtime_dirs()?;

    let expected_port = port.unwrap_or(DEFAULT_PROXY_PORT);

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

    // Handle orphaned daemon-child processes from prior runs where pid tracking drifted.
    let orphaned = running_daemon_pids();
    if !orphaned.is_empty() {
        if !quiet {
            style::warning(&format!(
                "Found {} orphan daemon process(es); cleaning up before start.",
                orphaned.len()
            ));
        }
        for pid in orphaned {
            let stopped = stop_pid_and_wait(pid, Duration::from_secs(4));
            if !quiet {
                if stopped {
                    style::info(&format!("Stopped orphan daemon pid {pid}."));
                } else {
                    style::warning(&format!(
                        "Could not stop orphan daemon pid {pid}; startup may fail."
                    ));
                }
            }
        }
    }

    let log_file_path = log_path();
    let (log_max_bytes, log_max_backups) = proxy_log_rotation_limits();
    if let Err(error) = rotate_proxy_log_if_needed(&log_file_path, log_max_bytes, log_max_backups) {
        if !quiet {
            style::warning(&format!(
                "Failed to rotate proxy log (continuing): {}",
                error
            ));
        }
    }

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
    if intercept_all {
        cmd.arg("--intercept-all");
    }
    if let Some(seconds) = intercept_all_for {
        cmd.arg("--intercept-all-for").arg(seconds.to_string());
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
    let startup_timeout = daemon_startup_timeout();
    let startup_deadline = std::time::Instant::now() + startup_timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed checking proxy daemon startup status")?
        {
            return Err(anyhow!(
                "proxy daemon exited early with status {status}; check {}",
                compact_path(&log_file_path)
            ));
        }

        if is_local_listener_ready(expected_port) {
            break;
        }

        if std::time::Instant::now() >= startup_deadline {
            let pid = child.id();
            let _ = stop_pid_and_wait(pid, Duration::from_secs(2));
            return Err(anyhow!(
                "proxy daemon did not open 127.0.0.1:{} within {}s startup timeout; check {}",
                expected_port,
                startup_timeout.as_secs(),
                compact_path(&log_file_path)
            ));
        }

        std::thread::sleep(Duration::from_millis(120));
    }

    let pid = child.id();
    write_pid(pid)?;

    if !quiet {
        style::success(&format!("Proxy daemon started (pid {pid})."));
        style::kv("Logs", &compact_path(&log_file_path));
        style::kv("Control", "soth stop");
        style::kv("Tail", "soth logs -f");
        print_env_setup_hint_if_needed();
    }
    Ok(())
}

pub async fn run_stop() -> anyhow::Result<()> {
    let Some(pid) = read_pid()? else {
        let orphaned = running_daemon_pids();
        if orphaned.is_empty() {
            style::warning("Proxy daemon is not running (no pid file).");
            print_env_cleanup_hint_if_needed();
            return Ok(());
        }
        for orphan_pid in orphaned {
            let _ = stop_pid_and_wait(orphan_pid, Duration::from_secs(4));
        }
        let _ = super::system::disable_quiet().await;
        style::success("Stopped orphaned proxy daemon process(es).");
        print_env_cleanup_hint_if_needed();
        return Ok(());
    };

    if !is_process_running(pid) {
        remove_pid_file();
        let orphaned = running_daemon_pids();
        if orphaned.is_empty() {
            style::warning("Proxy daemon pid file was stale; cleaned up.");
            let _ = super::system::disable_quiet().await;
            print_env_cleanup_hint_if_needed();
            return Ok(());
        }
        for orphan_pid in orphaned {
            let _ = stop_pid_and_wait(orphan_pid, Duration::from_secs(4));
        }
        let _ = super::system::disable_quiet().await;
        style::success("Stopped proxy daemon process(es) after stale pid cleanup.");
        print_env_cleanup_hint_if_needed();
        return Ok(());
    }

    send_term(pid);
    for _ in 0..40 {
        if !is_process_running(pid) {
            remove_pid_file();
            let _ = super::system::disable_quiet().await;
            style::success("Proxy daemon stopped.");
            print_env_cleanup_hint_if_needed();
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
            print_env_cleanup_hint_if_needed();
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
