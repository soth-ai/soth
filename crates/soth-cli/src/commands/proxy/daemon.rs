//! Daemon lifecycle utilities for `soth start`.

use crate::cli_config;
use crate::style;
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PID_FILE: &str = "proxy.pid";
const PID_META_FILE: &str = "proxy.pid.meta.json";
const PID_OWNER_TOKEN_FILE: &str = "proxy.pid.token";
const LOCK_FILE: &str = "proxy.lifecycle.lock";
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
const DEFAULT_STOP_TIMEOUT_SECS: u64 = 4;
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

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
const WINDOWS_LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

#[cfg(target_os = "windows")]
#[repr(C)]
struct WindowsOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: *mut std::ffi::c_void,
}

#[cfg(target_os = "windows")]
fn windows_lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            h_file: *mut std::ffi::c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut WindowsOverlapped,
        ) -> i32;
    }

    let mut overlapped = WindowsOverlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event: std::ptr::null_mut(),
    };
    let rc = unsafe {
        LockFileEx(
            file.as_raw_handle().cast(),
            WINDOWS_LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if rc == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_unlock_file(file: &File) {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn UnlockFileEx(
            h_file: *mut std::ffi::c_void,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut WindowsOverlapped,
        ) -> i32;
    }

    let mut overlapped = WindowsOverlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event: std::ptr::null_mut(),
    };
    let _ = unsafe { UnlockFileEx(file.as_raw_handle().cast(), 0, 1, 0, &mut overlapped) };
}

#[cfg(target_os = "windows")]
fn apply_windows_hidden_process_flags(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPidMetadata {
    schema_version: u32,
    pid: u32,
    port: u16,
    executable: String,
    #[serde(default)]
    owner_token: String,
    started_at_unix_secs: u64,
}

struct DaemonLifecycleLock {
    #[allow(dead_code)]
    file: File,
}

impl Drop for DaemonLifecycleLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(target_os = "windows")]
        {
            windows_unlock_file(&self.file);
        }
    }
}

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

fn pid_meta_path() -> PathBuf {
    run_dir().join(PID_META_FILE)
}

fn lock_path() -> PathBuf {
    run_dir().join(LOCK_FILE)
}

fn owner_token_path() -> PathBuf {
    run_dir().join(PID_OWNER_TOKEN_FILE)
}

pub fn log_path() -> PathBuf {
    logs_dir().join(LOG_FILE)
}

fn ensure_runtime_dirs() -> anyhow::Result<()> {
    std::fs::create_dir_all(run_dir()).context("failed creating ~/.soth/run")?;
    std::fs::create_dir_all(logs_dir()).context("failed creating ~/.soth/logs")?;
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn acquire_lifecycle_lock() -> anyhow::Result<DaemonLifecycleLock> {
    let path = lock_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating lifecycle lock directory {}",
                parent.display()
            )
        })?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed opening lifecycle lock {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            return Err(anyhow!(
                "failed acquiring daemon lifecycle lock {}: {}",
                path.display(),
                error
            ));
        }
    }
    #[cfg(target_os = "windows")]
    {
        windows_lock_file_exclusive(&file).with_context(|| {
            format!("failed acquiring daemon lifecycle lock {}", path.display())
        })?;
    }
    Ok(DaemonLifecycleLock { file })
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

fn resolve_expected_port(port: Option<u16>, config_path: Option<&PathBuf>) -> u16 {
    if let Some(value) = port {
        return value;
    }
    cli_config::load_effective_config(config_path, None)
        .map(|cfg| cfg.forward_proxy.port)
        .unwrap_or(DEFAULT_PROXY_PORT)
}

fn resolve_autostart_enabled(no_autostart: bool, config_path: Option<&PathBuf>) -> bool {
    if no_autostart {
        return false;
    }
    cli_config::load_effective_config(config_path, None)
        .map(|cfg| cfg.forward_proxy.autostart_on_boot)
        .unwrap_or(true)
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

fn read_pid_metadata() -> anyhow::Result<Option<DaemonPidMetadata>> {
    let path = pid_meta_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading pid metadata {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonPidMetadata>(&raw)
        .with_context(|| format!("failed parsing pid metadata {}", path.display()))?;
    Ok(Some(parsed))
}

fn write_pid_metadata(pid: u32, port: u16, owner_token: &str) -> anyhow::Result<()> {
    let path = pid_meta_path();
    let executable = std::env::current_exe()
        .ok()
        .map(|value| value.display().to_string())
        .unwrap_or_else(|| "soth".to_string());
    let metadata = DaemonPidMetadata {
        schema_version: 2,
        pid,
        port,
        executable,
        owner_token: owner_token.to_string(),
        started_at_unix_secs: now_unix_secs(),
    };
    let body = serde_json::to_vec_pretty(&metadata)?;
    std::fs::write(&path, body)
        .with_context(|| format!("failed writing pid metadata {}", path.display()))?;
    Ok(())
}

fn remove_pid_artifacts() {
    let _ = std::fs::remove_file(pid_path());
    let _ = std::fs::remove_file(pid_meta_path());
    let _ = std::fs::remove_file(owner_token_path());
}

fn read_pid_owner_token() -> anyhow::Result<Option<String>> {
    let path = owner_token_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading pid owner token {}", path.display()))?;
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value.to_string()))
}

fn write_pid_owner_token(value: &str) -> anyhow::Result<()> {
    let path = owner_token_path();
    std::fs::write(&path, format!("{value}\n"))
        .with_context(|| format!("failed writing pid owner token {}", path.display()))?;
    Ok(())
}

fn trusted_pid_from_metadata() -> Option<u32> {
    let metadata = read_pid_metadata().ok().flatten()?;
    let token = read_pid_owner_token().ok().flatten()?;
    if metadata.owner_token.is_empty() || metadata.owner_token != token {
        return None;
    }
    if let Ok(Some(pid)) = read_pid() {
        if pid != metadata.pid {
            return None;
        }
    }
    Some(metadata.pid)
}

fn pid_matches_owned_artifacts(pid: u32) -> bool {
    let Some(meta_pid) = trusted_pid_from_metadata() else {
        return false;
    };
    meta_pid == pid
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
    #[cfg(target_os = "windows")]
    {
        let filter = format!("PID eq {}", pid);
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", &filter, "/FO", "CSV", "/NH"]);
        apply_windows_hidden_process_flags(&mut cmd);
        let output = cmd.output().ok();
        let Some(output) = output else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.to_ascii_lowercase().starts_with("info:") {
                return false;
            }
            let cols = parse_csv_columns(trimmed);
            if cols
                .get(1)
                .and_then(|value| value.trim().parse::<u32>().ok())
                == Some(pid)
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = pid;
        false
    }
}

#[cfg(target_os = "windows")]
fn parse_csv_columns(line: &str) -> Vec<String> {
    line.split(',')
        .map(|value| value.trim().trim_matches('"').to_string())
        .collect()
}

#[cfg(target_os = "windows")]
fn process_commandline_via_powershell(pid: u32) -> Option<String> {
    let script = format!(
        "(Get-CimInstance Win32_Process -Filter \"ProcessId = {}\" | Select-Object -ExpandProperty CommandLine)",
        pid
    );
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &script,
    ]);
    apply_windows_hidden_process_flags(&mut cmd);
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "windows")]
fn process_commandline_via_wmic(pid: u32) -> Option<String> {
    let mut cmd = Command::new("wmic");
    cmd.args([
        "process",
        "where",
        &format!("processid={}", pid),
        "get",
        "CommandLine",
        "/value",
    ]);
    apply_windows_hidden_process_flags(&mut cmd);
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("CommandLine="))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn process_commandline(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd)
    }
}

#[cfg(target_os = "windows")]
fn process_commandline(pid: u32) -> Option<String> {
    process_commandline_via_powershell(pid).or_else(|| process_commandline_via_wmic(pid))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn process_commandline(_pid: u32) -> Option<String> {
    None
}

fn is_expected_daemon_process(pid: u32) -> bool {
    if !is_process_running(pid) {
        return false;
    }
    let Some(command) = process_commandline(pid) else {
        return false;
    };
    let normalized = command.to_ascii_lowercase();
    let looks_like_soth_binary = normalized.contains("soth.exe")
        || normalized.contains("/soth")
        || normalized.contains("\\soth")
        || normalized.starts_with("soth ")
        || normalized == "soth";
    normalized.contains(" start ")
        && normalized.contains("--daemon-child")
        && looks_like_soth_binary
}

#[cfg(unix)]
fn listener_owner_pids(port: u16) -> Option<Vec<u32>> {
    let output = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fp"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut owners = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(pid) = line
            .strip_prefix('p')
            .and_then(|value| value.parse::<u32>().ok())
        {
            owners.push(pid);
        }
    }
    owners.sort_unstable();
    owners.dedup();
    Some(owners)
}

#[cfg(target_os = "windows")]
fn parse_endpoint_port(endpoint: &str) -> Option<u16> {
    let trimmed = endpoint.trim();
    let (_, port_part) = trimmed.rsplit_once(':')?;
    port_part.trim().parse::<u16>().ok()
}

#[cfg(target_os = "windows")]
fn listener_owner_pids(port: u16) -> Option<Vec<u32>> {
    let mut cmd = Command::new("netstat");
    cmd.args(["-ano", "-p", "tcp"]);
    apply_windows_hidden_process_flags(&mut cmd);
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let mut owners = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("TCP") {
            continue;
        }
        let columns: Vec<&str> = trimmed.split_whitespace().collect();
        if columns.len() < 5 {
            continue;
        }
        let local_addr = columns[1];
        let state = columns[3];
        let pid = columns[4];
        if !state.eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        if parse_endpoint_port(local_addr) != Some(port) {
            continue;
        }
        if let Ok(parsed_pid) = pid.parse::<u32>() {
            owners.push(parsed_pid);
        }
    }

    owners.sort_unstable();
    owners.dedup();
    Some(owners)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn listener_owner_pids(_port: u16) -> Option<Vec<u32>> {
    None
}

#[cfg(any(unix, target_os = "windows"))]
fn is_listener_owned_by_pid(port: u16, pid: u32) -> Option<bool> {
    let owners = listener_owner_pids(port)?;
    Some(owners.into_iter().any(|owner_pid| owner_pid == pid))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn is_listener_owned_by_pid(_port: u16, _pid: u32) -> Option<bool> {
    None
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
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string(), "/T"]);
        apply_windows_hidden_process_flags(&mut cmd);
        let _ = cmd.status();
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
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string(), "/T", "/F"]);
        apply_windows_hidden_process_flags(&mut cmd);
        let _ = cmd.status();
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
        "eval (soth env --shell fish --unset)"
    } else {
        "eval \"$(soth env --unset)\""
    }
}

fn shell_set_hint_command() -> &'static str {
    let shell = env::var("SHELL")
        .ok()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if shell.contains("fish") {
        "eval (soth env --shell fish)"
    } else {
        "eval \"$(soth env)\""
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

fn adopt_running_daemon_state(expected_port: u16, quiet: bool) -> anyhow::Result<Option<u32>> {
    let owners = listener_owner_pids(expected_port).unwrap_or_default();
    if owners.len() != 1 {
        return Ok(None);
    }
    let pid = owners[0];
    if !is_expected_daemon_process(pid) {
        return Ok(None);
    }
    let owner_token = uuid::Uuid::new_v4().to_string();
    write_pid(pid)?;
    write_pid_owner_token(&owner_token)?;
    let _ = write_pid_metadata(pid, expected_port, &owner_token);
    if !quiet {
        style::warning(&format!(
            "Recovered missing daemon pid state from running listener (pid {}, port {}).",
            pid, expected_port
        ));
    }
    Ok(Some(pid))
}

pub async fn run_start_daemon(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    no_autostart: bool,
) -> anyhow::Result<()> {
    ensure_runtime_dirs()?;
    let _lifecycle_lock = acquire_lifecycle_lock()?;

    let expected_port = resolve_expected_port(port, config_path.as_ref());
    let autostart_enabled = resolve_autostart_enabled(no_autostart, config_path.as_ref());
    if read_pid()?.is_none() && trusted_pid_from_metadata().is_none() {
        let _ = adopt_running_daemon_state(expected_port, quiet);
    }

    if let Some(pid) = read_pid()? {
        if is_expected_daemon_process(pid) {
            if !quiet {
                style::success(&format!("Proxy daemon already running (pid {pid})."));
                style::info(&format!(
                    "Logs: {} (use `soth logs -f`)",
                    compact_path(&log_path())
                ));
                if autostart_enabled {
                    match super::autostart::ensure_enabled(expected_port, config_path.as_ref()) {
                        Ok(details) => {
                            style::info(&format!("Startup autostart ensured: {details}"))
                        }
                        Err(error) => style::warning(&format!(
                            "Could not register startup autostart (continuing): {}",
                            error
                        )),
                    }
                } else {
                    style::info("Startup autostart skipped (disabled via flag/config).");
                }
            }
            return Ok(());
        }
        if !quiet {
            style::warning(&format!(
                "Ignoring stale or untrusted pid file entry for pid {}.",
                pid
            ));
        }
        remove_pid_artifacts();
    }

    // Handle orphaned daemon-child process only when owned metadata remains.
    let orphaned = trusted_pid_from_metadata()
        .filter(|pid| is_expected_daemon_process(*pid))
        .into_iter()
        .collect::<Vec<u32>>();
    if read_pid()?.is_none() && !orphaned.is_empty() {
        if !quiet {
            style::warning(&format!(
                "Found owned orphan daemon pid {}; cleaning up before start.",
                orphaned[0]
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

    if autostart_enabled && super::autostart::supports_managed_mode() {
        match super::autostart::start_managed(expected_port, config_path.as_ref()) {
            Ok(details) => {
                let startup_timeout = daemon_startup_timeout();
                let startup_deadline = std::time::Instant::now() + startup_timeout;
                while !is_local_listener_ready(expected_port) {
                    if std::time::Instant::now() >= startup_deadline {
                        return Err(anyhow!(
                            "managed proxy startup did not open 127.0.0.1:{} within {}s timeout; check {}",
                            expected_port,
                            startup_timeout.as_secs(),
                            compact_path(&log_path())
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(120));
                }

                let _ = adopt_running_daemon_state(expected_port, true);
                if !quiet {
                    let pid_text = read_pid()?
                        .map(|pid| format!(" (pid {pid})"))
                        .unwrap_or_default();
                    style::success(&format!("Proxy managed service started{pid_text}."));
                    style::kv("Logs", &compact_path(&log_path()));
                    style::kv("Control", "soth stop");
                    style::kv("Tail", "soth logs -f");
                    style::info(&format!("Startup autostart ensured: {details}"));
                    print_env_setup_hint_if_needed();
                }
                return Ok(());
            }
            Err(error) => {
                if !quiet {
                    style::warning(&format!(
                        "Managed startup unavailable (falling back to daemon-child): {}",
                        error
                    ));
                }
            }
        }
    }

    let log_file_path = log_path();
    if let Some(parent) = log_file_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed creating daemon log directory {}", parent.display())
        })?;
    }
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
            match is_listener_owned_by_pid(expected_port, child.id()) {
                Some(true) => break,
                Some(false) => {
                    if std::time::Instant::now() >= startup_deadline {
                        let pid = child.id();
                        let _ = stop_pid_and_wait(pid, Duration::from_secs(2));
                        return Err(anyhow!(
                            "proxy daemon startup failed: 127.0.0.1:{} is listening but not owned by child pid {}; check {}",
                            expected_port,
                            pid,
                            compact_path(&log_file_path)
                        ));
                    }
                }
                None => break,
            }
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
    let owner_token = uuid::Uuid::new_v4().to_string();
    write_pid(pid)?;
    write_pid_owner_token(&owner_token)?;
    let _ = write_pid_metadata(pid, expected_port, &owner_token);

    if !quiet {
        style::success(&format!("Proxy daemon started (pid {pid})."));
        style::kv("Logs", &compact_path(&log_file_path));
        style::kv("Control", "soth stop");
        style::kv("Tail", "soth logs -f");
        print_env_setup_hint_if_needed();
    }

    if autostart_enabled {
        match super::autostart::ensure_enabled(expected_port, config_path.as_ref()) {
            Ok(details) => {
                if !quiet {
                    style::info(&format!("Startup autostart ensured: {details}"));
                }
            }
            Err(error) => {
                if !quiet {
                    style::warning(&format!(
                        "Could not register startup autostart (continuing): {}",
                        error
                    ));
                }
            }
        }
    } else if !quiet {
        style::info("Startup autostart skipped (disabled via flag/config).");
    }

    Ok(())
}

pub async fn run_stop() -> anyhow::Result<()> {
    ensure_runtime_dirs()?;
    let _lifecycle_lock = acquire_lifecycle_lock()?;
    let mut stopped_any = false;

    match super::autostart::stop_managed_runtime_only() {
        Ok(Some(details)) => style::info(&format!("Managed runtime stop: {details}")),
        Ok(None) => {}
        Err(error) => style::warning(&format!(
            "Could not stop managed runtime cleanly (continuing): {}",
            error
        )),
    }

    if read_pid()?.is_none() && trusted_pid_from_metadata().is_none() {
        let expected_port = resolve_expected_port(None, None);
        let _ = adopt_running_daemon_state(expected_port, true);
    }

    let Some(pid) = read_pid()? else {
        let owned_orphan = trusted_pid_from_metadata();
        if owned_orphan.is_none() {
            remove_pid_artifacts();
            style::warning("Proxy daemon is not running (no pid file).");
            let _ = super::system::disable_quiet().await;
            print_env_cleanup_hint_if_needed();
            return Ok(());
        }
        if let Some(orphan_pid) = owned_orphan {
            let stopped =
                stop_pid_and_wait(orphan_pid, Duration::from_secs(DEFAULT_STOP_TIMEOUT_SECS));
            stopped_any |= stopped;
        }
        remove_pid_artifacts();
        let _ = super::system::disable_quiet().await;
        if stopped_any {
            style::success("Stopped owned orphan proxy daemon process.");
        } else {
            style::warning("Found owned orphan daemon process, but stop confirmation failed.");
        }
        print_env_cleanup_hint_if_needed();
        return Ok(());
    };

    if let Some(meta) = read_pid_metadata().ok().flatten() {
        if meta.pid != pid {
            style::warning(&format!(
                "Pid metadata mismatch (pid file {}, metadata {}); treating as stale.",
                pid, meta.pid
            ));
            remove_pid_artifacts();
        }
    }

    if !is_expected_daemon_process(pid) {
        style::warning(&format!(
            "Pid file points to non-daemon process (pid {}); refusing to signal it.",
            pid
        ));
        remove_pid_artifacts();
        style::warning("Proxy daemon pid file was stale; cleaned up.");
        let _ = super::system::disable_quiet().await;
        print_env_cleanup_hint_if_needed();
        return Ok(());
    }
    if !pid_matches_owned_artifacts(pid) {
        style::warning(&format!(
            "Refusing to signal pid {} because daemon ownership token/metadata does not match.",
            pid
        ));
        remove_pid_artifacts();
        let _ = super::system::disable_quiet().await;
        print_env_cleanup_hint_if_needed();
        return Ok(());
    }

    send_term(pid);
    for _ in 0..40 {
        if !is_process_running(pid) {
            remove_pid_artifacts();
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
            remove_pid_artifacts();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_env_mutex() -> std::sync::MutexGuard<'static, ()> {
        match ENV_MUTEX.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn with_temp_home<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
        let guard = lock_env_mutex();
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = env::var_os("HOME");
        unsafe {
            env::set_var("HOME", temp.path());
        }
        let result = std::panic::catch_unwind(f);
        match old_home {
            Some(value) => unsafe {
                env::set_var("HOME", value);
            },
            None => unsafe {
                env::remove_var("HOME");
            },
        }
        drop(guard);
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn trusted_pid_rejects_owner_token_mismatch() {
        with_temp_home(|| {
            ensure_runtime_dirs().expect("runtime dirs");
            write_pid(4242).expect("pid file");
            write_pid_owner_token("token-a").expect("owner token");

            let meta = DaemonPidMetadata {
                schema_version: 2,
                pid: 4242,
                port: 8080,
                executable: "soth".to_string(),
                owner_token: "token-b".to_string(),
                started_at_unix_secs: now_unix_secs(),
            };
            std::fs::write(
                pid_meta_path(),
                serde_json::to_vec_pretty(&meta).expect("serialize"),
            )
            .expect("meta file");

            assert!(trusted_pid_from_metadata().is_none());
        });
    }

    #[test]
    fn trusted_pid_accepts_matching_owner_token() {
        with_temp_home(|| {
            ensure_runtime_dirs().expect("runtime dirs");
            write_pid(5050).expect("pid file");
            write_pid_owner_token("token-ok").expect("owner token");

            let meta = DaemonPidMetadata {
                schema_version: 2,
                pid: 5050,
                port: 8080,
                executable: "soth".to_string(),
                owner_token: "token-ok".to_string(),
                started_at_unix_secs: now_unix_secs(),
            };
            std::fs::write(
                pid_meta_path(),
                serde_json::to_vec_pretty(&meta).expect("serialize"),
            )
            .expect("meta file");

            assert_eq!(trusted_pid_from_metadata(), Some(5050));
        });
    }

    #[test]
    fn daemon_timeout_env_is_clamped() {
        let _guard = lock_env_mutex();
        unsafe {
            env::set_var("SOTH_DAEMON_STARTUP_TIMEOUT_SECS", "999");
        }
        assert_eq!(
            daemon_startup_timeout().as_secs(),
            MAX_DAEMON_STARTUP_TIMEOUT_SECS
        );
        unsafe {
            env::remove_var("SOTH_DAEMON_STARTUP_TIMEOUT_SECS");
        }
    }

    #[test]
    fn daemon_start_reports_child_early_exit() {
        with_temp_home(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            let err = runtime
                .block_on(run_start_daemon(Some(18888), None, true, false))
                .expect_err("daemon start should fail in unit test binary");
            let text = format!("{err:#}");
            assert!(
                text.contains("proxy daemon exited early")
                    || text.contains("managed proxy startup did not open"),
                "unexpected error: {text}"
            );
        });
    }
}
