//! `soth-update.exe` — Windows sidecar updater for the SOTH proxy.
//!
//! Why a sidecar:
//!   Windows holds an exclusive lock on the running `.exe`, so the
//!   in-place rename trick that works on macOS / Linux fails. The main
//!   `soth.exe` stages a new binary, spawns this sidecar with the
//!   parent PID + paths, then exits — and only after the lock is
//!   released can the sidecar atomically replace the file.
//!
//! Usage (always invoked by the soth daemon, never directly):
//!   soth-update.exe \
//!     --parent-pid <PID> \
//!     --new-binary <abs path to staged .exe> \
//!     --install-path <abs path to current soth.exe> \
//!     --previous-path <abs path to .previous.exe>
//!
//! Behavior:
//!   1. Wait up to PARENT_EXIT_TIMEOUT for parent PID to exit.
//!      (Polls every 250ms — Windows OpenProcess fails when the process
//!      is gone.)
//!   2. Move install_path → previous_path  (MoveFileExW MOVEFILE_REPLACE_EXISTING)
//!   3. Move new_binary → install_path     (same flags)
//!   4. Spawn `sc start soth` to restart the registered service.
//!   5. If service start fails OR the new soth.exe doesn't bind a
//!      listener within HEALTHCHECK_TIMEOUT, swap previous_path back
//!      into install_path and start that.
//!
//! The sidecar is intentionally tiny + self-contained. A bug in the
//! main soth.exe must not be able to brick the rollback path, so this
//! crate has zero deps on workspace-internal crates.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
struct Args {
    parent_pid: u32,
    new_binary: PathBuf,
    install_path: PathBuf,
    previous_path: PathBuf,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    let mut parent_pid: Option<u32> = None;
    let mut new_binary: Option<PathBuf> = None;
    let mut install_path: Option<PathBuf> = None;
    let mut previous_path: Option<PathBuf> = None;

    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| anyhow!("flag {} requires a value", flag))?;
        match flag.as_str() {
            "--parent-pid" => {
                parent_pid = Some(value.parse().context("--parent-pid not a u32")?);
            }
            "--new-binary" => new_binary = Some(PathBuf::from(value)),
            "--install-path" => install_path = Some(PathBuf::from(value)),
            "--previous-path" => previous_path = Some(PathBuf::from(value)),
            other => bail!("unknown flag {}", other),
        }
    }

    Ok(Args {
        parent_pid: parent_pid.ok_or_else(|| anyhow!("--parent-pid required"))?,
        new_binary: new_binary.ok_or_else(|| anyhow!("--new-binary required"))?,
        install_path: install_path.ok_or_else(|| anyhow!("--install-path required"))?,
        previous_path: previous_path.ok_or_else(|| anyhow!("--previous-path required"))?,
    })
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // Print to stderr; on Windows GUI apps this lands in the
            // attached console if any, otherwise it's lost. The main
            // soth.exe should redirect stderr to a log file when
            // spawning to keep diagnostics.
            eprintln!("soth-update: {:#}", err);
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(not(windows))]
fn run() -> Result<()> {
    bail!("soth-update is a Windows-only sidecar; not supported on this platform")
}

#[cfg(windows)]
fn run() -> Result<()> {
    use std::time::{Duration, Instant};

    const PARENT_EXIT_TIMEOUT: Duration = Duration::from_secs(15);
    const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(250);

    let args = parse_args()?;

    eprintln!(
        "soth-update: waiting up to {:?} for parent PID {} to exit",
        PARENT_EXIT_TIMEOUT, args.parent_pid
    );
    let deadline = Instant::now() + PARENT_EXIT_TIMEOUT;
    while Instant::now() < deadline {
        if !windows::process_alive(args.parent_pid) {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    if windows::process_alive(args.parent_pid) {
        bail!(
            "parent process {} still alive after {:?}; refusing to replace running binary",
            args.parent_pid,
            PARENT_EXIT_TIMEOUT
        );
    }

    eprintln!(
        "soth-update: parent gone; replacing {} → {}",
        args.install_path.display(),
        args.previous_path.display()
    );
    windows::move_file_replace(&args.install_path, &args.previous_path)
        .with_context(|| {
            format!(
                "MoveFileExW {} → {}",
                args.install_path.display(),
                args.previous_path.display()
            )
        })?;

    eprintln!(
        "soth-update: installing {} → {}",
        args.new_binary.display(),
        args.install_path.display()
    );
    if let Err(error) = windows::move_file_replace(&args.new_binary, &args.install_path) {
        // Lost mid-rename: try to restore previous so the user isn't
        // left without any soth.exe at all.
        eprintln!(
            "soth-update: install rename failed ({:#}); restoring previous",
            error
        );
        let _ = windows::move_file_replace(&args.previous_path, &args.install_path);
        return Err(error.context("install rename"));
    }

    eprintln!("soth-update: starting service");
    let start_status = std::process::Command::new("sc")
        .args(["start", "soth"])
        .status();
    let start_ok = matches!(start_status, Ok(s) if s.success());
    if !start_ok {
        // sc start failure isn't necessarily fatal — service may auto-
        // start on next login, or this user installed without the
        // service. Try a direct spawn so the daemon comes up either way.
        eprintln!(
            "soth-update: sc start returned non-zero; spawning {} directly",
            args.install_path.display()
        );
        if let Err(error) = std::process::Command::new(&args.install_path)
            .args(["proxy", "start"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            eprintln!(
                "soth-update: direct spawn failed ({:#}); rolling back to previous",
                error
            );
            return rollback(&args, HEALTHCHECK_TIMEOUT);
        }
    }

    if !wait_for_listener(HEALTHCHECK_TIMEOUT) {
        eprintln!(
            "soth-update: new soth did not bind a listener within {:?}; rolling back",
            HEALTHCHECK_TIMEOUT
        );
        return rollback(&args, HEALTHCHECK_TIMEOUT);
    }

    eprintln!("soth-update: install verified; new binary is live");
    Ok(())
}

#[cfg(windows)]
fn rollback(args: &Args, healthcheck_timeout: std::time::Duration) -> Result<()> {
    // Best-effort: try to stop the (presumably bad) service first so
    // we don't double-bind the port.
    let _ = std::process::Command::new("sc").args(["stop", "soth"]).status();
    // Park the failed install at .failed so it's preserved for forensics.
    let mut failed = args.install_path.clone();
    let stem = failed
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("soth")
        .to_string();
    failed.set_file_name(format!("{}.failed.exe", stem));
    let _ = windows::move_file_replace(&args.install_path, &failed);
    windows::move_file_replace(&args.previous_path, &args.install_path)
        .context("rollback move")?;
    let _ = std::process::Command::new("sc").args(["start", "soth"]).status();
    if !wait_for_listener(healthcheck_timeout) {
        bail!(
            "rollback: previous binary failed to bind listener within {:?}",
            healthcheck_timeout
        );
    }
    eprintln!("soth-update: rolled back to previous binary");
    Ok(())
}

#[cfg(windows)]
fn wait_for_listener(timeout: std::time::Duration) -> bool {
    use std::net::TcpStream;
    use std::time::Instant;

    // Cheap port discovery: the user's ~/.soth/soth.yaml carries
    // forward_proxy.port. If we can't read it, skip the healthcheck
    // (the service start succeeded, which is the primary signal).
    let port = match read_configured_port() {
        Some(p) => p,
        None => return true,
    };
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(250),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

#[cfg(windows)]
fn read_configured_port() -> Option<u16> {
    let appdata = std::env::var("USERPROFILE").ok()?;
    let cfg = PathBuf::from(appdata).join(".soth").join("soth.yaml");
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

#[cfg(windows)]
mod windows {
    use std::path::Path;

    use anyhow::{anyhow, Result};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Returns true if the process is still running. False on either
    /// "not found" or "access denied" (we never run elevated, so a
    /// PROCESS_QUERY_LIMITED_INFORMATION handle should always succeed
    /// for our own parent).
    pub fn process_alive(pid: u32) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    pub fn move_file_replace(src: &Path, dst: &Path) -> Result<()> {
        let src_w = wide(src);
        let dst_w = wide(dst);
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow!("MoveFileExW failed: {}", err));
        }
        Ok(())
    }

    fn wide(p: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}
