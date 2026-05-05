//! Start proxy runtime command.

use super::daemon;
use crate::cli_config::{self, SothConfig};
use crate::style;
use anyhow::{Context, Result};
use serde::Serialize;
use std::env;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tracing::{info, warn};
use uuid::Uuid;

// Default budget for the supervisor to wait for the worker proxy to bind
// 127.0.0.1:<port>. The bind happens late in `proxy.start()` — after
// `verify_bundle_source_ready()` synchronously fetches AND installs the
// cloud bundle, which on cold-install Windows boxes with Defender
// real-time scanning can take 15-20s on its own. 60s gives that path
// headroom without making real failures (port in use, panic at startup)
// linger forever. Operators can override via
// `SOTH_PROXY_LISTENER_STARTUP_TIMEOUT_SECS` if their environment is even
// slower (corporate AV, encrypted volumes, etc.).
const LISTENER_STARTUP_TIMEOUT_SECS: u64 = 60;
const MIN_LISTENER_STARTUP_TIMEOUT_SECS: u64 = 5;
const MAX_LISTENER_STARTUP_TIMEOUT_SECS: u64 = 300;
const LISTENER_HEALTH_CHECK_INTERVAL_MS: u64 = 1_000;
/// How long the listener can be unresponsive before the supervisor kills and
/// restarts the proxy.  Kept short (5s) so laptop sleep/wake recovery is fast.
const LISTENER_HEALTH_FAILURE_WINDOW_MS: u64 = 5_000;
const MAX_RESTART_ATTEMPTS: u32 = 10;
const RESTART_BACKOFF_BASE_MS: u64 = 1_000;
const RESTART_BACKOFF_MAX_MS: u64 = 30_000;

/// If the supervisor loop sees a wall-clock gap larger than this between two
/// iterations, we assume the OS was suspended (sleep / hibernate / Modern
/// Standby) for that duration. Sleep > 60s is the threshold because tokio's
/// `interval` ticks at 1s and any sub-minute gap is plausibly just a slow
/// upstream call or GC pause; everything beyond that is overwhelmingly
/// likely to be a real suspend.
const WAKE_DETECTION_GAP_SECS: u64 = 60;
/// How long to wait for the listener to come up on the first restart after a
/// detected wake event. Windows in particular can take many seconds to bring
/// the network stack back up, during which the worker fails to bind. The
/// regular 20s timeout is too aggressive here.
const WAKE_LISTENER_STARTUP_TIMEOUT_SECS: u64 = 60;
const DEFAULT_NOFILE_MIN_SOFT_LIMIT: u64 = 8_192;
const DEFAULT_NOFILE_WARN_SOFT_LIMIT: u64 = 2_048;
const AGENT_INSTANCE_ID_TAG: &str = "agent_instance_id";
const AGENT_INSTANCE_ID_FILE: &str = "agent_instance_id";
const AGENT_INSTANCE_ID_PREFIX: &str = "edge-";

/// Run the start command.
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    daemon_child: bool,
    no_autostart: bool,
    allow_daemon_child_fallback: bool,
) -> Result<()> {
    // Worker mode: re-execed by the supervisor to run the in-process MITM
    // runtime. Bypasses supervisor/CA bootstrap logic — those are the
    // supervisor's job; this process only runs the proxy loop.
    if std::env::var(PROXY_WORKER_ENV).is_ok() {
        return run_proxy_worker().await;
    }

    // Windows autostart self-detach: when `soth start --daemon-child` is
    // invoked from HKCU\...\Run at user login, explorer.exe spawns it with
    // default creation flags — the binary gets a visible console and is
    // tied to explorer. Closing that console kills the supervisor, and with
    // it the proxy. Spawners that already applied detached flags set
    // DAEMON_DETACHED_ENV to skip this re-exec; anyone else (Run key, user
    // shell) triggers the self-detach below.
    #[cfg(target_os = "windows")]
    if daemon_child && std::env::var(DAEMON_DETACHED_ENV).is_err() {
        return self_detach_daemon(port, config_path.as_ref(), quiet);
    }

    if !foreground && !daemon_child {
        return daemon::run_start_daemon(
            port,
            config_path,
            quiet,
            no_autostart,
            allow_daemon_child_fallback,
        )
        .await;
    }

    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let ca_paths = super::ca_health::resolve_ca_paths(&config);
    ensure_fd_budget();
    let cert_path = ca_paths.runtime_cert_path.clone();
    let key_path = ca_paths.runtime_key_path.clone();
    if !cert_path.exists() || !key_path.exists() {
        anyhow::bail!("CA certificate not found. Run `soth setup-ca` first.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let key_meta = std::fs::metadata(&key_path)?;
        let mode = key_meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %key_path.display(),
                mode = format!("{:o}", mode),
                "CA private key has overly permissive file permissions. \
                 Expected 0600, got {:o}. Run: chmod 600 {}",
                mode,
                key_path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        // Idempotently re-apply the restrictive ACL on the CA private key at startup.
        // This repairs drift if something loosened it post-install and is a no-op when
        // the ACL is already correct.
        if let Err(error) = reapply_windows_key_acl(&key_path) {
            tracing::warn!(
                path = %key_path.display(),
                error = %error,
                "failed to re-apply restrictive ACL on CA private key; key may be readable by other local users"
            );
        }
    }
    ensure_ca_runtime_health(&ca_paths, quiet)?;

    let generated_path = write_proxy_config(&config, port)?;
    let expected_port = port.unwrap_or(config.forward_proxy.port);

    #[cfg(unix)]
    let _supervisor_listener =
        bind_supervisor_listener(&config.forward_proxy.address, expected_port)
            .map_err(|error| friendly_bind_error(error, expected_port))?;
    #[cfg(unix)]
    let listener_fd = Some({
        use std::os::unix::io::AsRawFd;
        _supervisor_listener.as_raw_fd()
    });
    #[cfg(not(unix))]
    let listener_fd: Option<i32> = None;

    let mut child = spawn_proxy_process(generated_path.as_path(), listener_fd)
        .await
        .context("spawn soth-proxy process")?;
    wait_for_listener_start(&mut child, expected_port).await?;

    // Engage the OS-level system proxy so traffic actually flows through us.
    // Reached by both foreground (`soth up --foreground`) and daemon-child
    // paths; the standalone-daemon path (line ~67) re-execs back into this
    // function with daemon_child=true, so it lands here too.
    //
    // Failure here is non-fatal — the proxy is healthy, we just didn't
    // capture system traffic. Surface it as a warning and let the user
    // recover with `soth on` after fixing whatever blocked the toggle
    // (e.g. missing pf admin grant on macOS, registry ACL on Windows).
    if let Err(error) = super::system::enable(Some(expected_port)).await {
        tracing::warn!(
            error = %error,
            port = expected_port,
            "system proxy engage failed at startup; proxy is running but traffic is not captured. \
             Re-run `soth on` once the underlying cause is fixed."
        );
        if !quiet {
            style::warning(&format!(
                "Proxy is running on port {expected_port} but the system proxy did not engage: {error}. \
                 Run `soth on` to retry, or `soth doctor` to diagnose."
            ));
        }
    }

    if !quiet && foreground {
        style::success("Proxy started in foreground mode.");
        style::info("Press Ctrl+C to stop.");
    }

    supervise_proxy(
        &mut child,
        generated_path.as_path(),
        expected_port,
        foreground,
        listener_fd,
    )
    .await
}

fn ensure_ca_runtime_health(paths: &super::ca_health::ResolvedCaPaths, quiet: bool) -> Result<()> {
    if !paths.trust_cert_path.exists() {
        anyhow::bail!(
            "Configured trust cert path does not exist: {} (source={}).",
            paths.trust_cert_path.display(),
            paths.trust_source
        );
    }

    let runtime_fp = super::ca_health::cert_fingerprint_sha256(paths.runtime_cert_path.as_path())
        .context("compute runtime CA fingerprint")?;
    let trust_fp = super::ca_health::cert_fingerprint_sha256(paths.trust_cert_path.as_path())
        .context("compute trust CA fingerprint")?;
    if runtime_fp != trust_fp {
        anyhow::bail!(
            "CA fingerprint mismatch between runtime cert and trust cert.\nruntime={} ({})\ntrust={} ({})",
            runtime_fp,
            paths.runtime_cert_path.display(),
            trust_fp,
            paths.trust_cert_path.display()
        );
    }

    let key_matches = super::ca_health::cert_matches_key(
        paths.runtime_cert_path.as_path(),
        paths.runtime_key_path.as_path(),
    )
    .context("validate runtime CA cert/key pair")?;
    if !key_matches {
        anyhow::bail!(
            "CA private key does not match runtime CA certificate.\ncert={}\nkey={}",
            paths.runtime_cert_path.display(),
            paths.runtime_key_path.display()
        );
    }

    match super::ca_health::check_os_trust(paths.trust_cert_path.as_path()) {
        Ok(check) => match check.status {
            super::ca_health::OsTrustStatus::Trusted => {}
            super::ca_health::OsTrustStatus::Untrusted => {
                if paths.external_trust_path {
                    anyhow::bail!(
                        "External trust cert is not trusted by OS (source={}): {}.\nInstall trust via MDM/profile and retry.",
                        paths.trust_source,
                        check.detail
                    );
                }
                anyhow::bail!(
                    "Runtime CA is not trusted by OS: {}. Run `soth setup-ca` and retry.",
                    check.detail
                );
            }
            super::ca_health::OsTrustStatus::Unknown => {
                if !quiet {
                    warn!("Skipping strict OS CA trust gate: {}", check.detail);
                }
            }
        },
        Err(error) => {
            if !quiet {
                warn!("Failed to check OS CA trust state (continuing): {}", error);
            }
        }
    }

    Ok(())
}

async fn spawn_proxy_process(config_path: &Path, listener_fd: Option<i32>) -> Result<Child> {
    let current_exe =
        std::env::current_exe().context("resolve current executable for proxy worker")?;
    let mut cmd = Command::new(current_exe);
    // `start --daemon-child` + SOTH_PROXY_WORKER=1 selects the in-process MITM
    // runtime path in `run()` below, replacing the historical `soth-proxy`
    // sibling binary.
    cmd.arg("start").arg("--daemon-child");
    cmd.env(PROXY_WORKER_ENV, "1");
    cmd.env("SOTH_PROXY_CONFIG", config_path);
    if let Some(fd) = listener_fd {
        cmd.env("SOTH_LISTENER_FD", fd.to_string());
    }
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        cmd.env("RUST_LOG", rust_log);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    // On Windows a console-subsystem binary creates its own console window
    // unless CREATE_NO_WINDOW is set. Without this the worker pops a blank
    // "soth.exe" window and closing it kills the daemon via CTRL_CLOSE_EVENT.
    // CREATE_NEW_PROCESS_GROUP so supervisor SIGBREAK/termination of the
    // shell that launched `soth up` does not cascade to the worker.
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .map_err(|error| anyhow::anyhow!("failed launching proxy worker: {error}"))
}

/// Env var toggle that re-executed child processes use to enter in-process
/// MITM runtime mode. Set by [`spawn_proxy_process`].
pub(crate) const PROXY_WORKER_ENV: &str = "SOTH_PROXY_WORKER";

/// Windows-only marker env var. Set by spawners that have already applied
/// `DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` flags so
/// the child doesn't re-detach in a loop. When a daemon-child process starts
/// without this var set (e.g. triggered from HKCU\Run at login), it re-execs
/// itself detached via [`self_detach_daemon`] and exits.
#[cfg(target_os = "windows")]
pub(crate) const DAEMON_DETACHED_ENV: &str = "SOTH_DAEMON_DETACHED";

/// Re-spawn ourselves as a fully detached daemon child and return `Ok(())` so
/// the caller (Run key / shell) exits cleanly. stdout/stderr go to
/// `~/.soth/logs/proxy.log` so the detached child has persistent logging.
#[cfg(target_os = "windows")]
fn self_detach_daemon(port: Option<u16>, config_path: Option<&PathBuf>, quiet: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    let exe = std::env::current_exe().context("resolve current executable for self-detach")?;
    let log_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("home directory not found for self-detach log"))?
        .join(".soth")
        .join("logs")
        .join("proxy.log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating proxy log directory {}", parent.display()))?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed opening proxy log {}", log_path.display()))?;
    let log_clone = log
        .try_clone()
        .context("failed cloning proxy log file handle for self-detach stderr")?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("start").arg("--daemon-child");
    if quiet {
        cmd.arg("--quiet");
    }
    if let Some(p) = port {
        cmd.arg("--port").arg(p.to_string());
    }
    if let Some(cfg) = config_path {
        cmd.arg("--config").arg(cfg);
    }
    cmd.env(DAEMON_DETACHED_ENV, "1");
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        cmd.env("RUST_LOG", rust_log);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_clone))
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    cmd.spawn()
        .context("failed spawning detached SOTH proxy daemon on Windows")?;

    Ok(())
}

/// Supervise the proxy child process with auto-restart on failure.
///
/// The proxy is a system-level component — if it dies, all network traffic
/// routed through it stops working.  Instead of bailing on failure, we
/// kill the unhealthy child and respawn it, with exponential backoff up to
/// [`MAX_RESTART_ATTEMPTS`] consecutive failures.  The restart counter
/// resets every time the proxy runs healthily for at least 60 seconds.
async fn supervise_proxy(
    child: &mut Child,
    config_path: &Path,
    expected_port: u16,
    foreground: bool,
    listener_fd: Option<i32>,
) -> Result<()> {
    let mut consecutive_failures: u32 = 0;
    let mut last_healthy = Instant::now();
    let mut last_iteration = Instant::now();
    // First restart after a detected wake gets a longer startup grace
    // window — see WAKE_LISTENER_STARTUP_TIMEOUT_SECS for the rationale.
    let mut next_startup_timeout = listener_startup_timeout();
    // Watches for primary-network changes (wifi switch, captive-portal
    // address reassignment) and triggers a graceful child rotation so the
    // upstream connection pool isn't left bound to the old gateway.
    let mut network_change_rx = super::network_watcher::spawn();

    loop {
        let exit_reason =
            wait_until_exit_or_unhealthy(child, expected_port, foreground, &mut network_change_rx)
                .await;

        // Detect wake-from-sleep before applying restart-budget logic. A long
        // wall-clock gap between supervisor iterations almost always means
        // the OS was suspended (sleep / hibernate / Modern Standby). Tokio's
        // monotonic timers don't distinguish "we awaited a 1s tick" from
        // "the OS suspended us for 8 hours mid-tick" — only Instant deltas
        // do. On detection, treat the upcoming restart as a fresh start
        // rather than letting transient post-wake bind failures drain the
        // failure budget and kill the supervisor entirely (which would
        // leave the user with no proxy until next login or `soth up`).
        let now = Instant::now();
        let iteration_gap = now.duration_since(last_iteration);
        last_iteration = now;
        if iteration_gap > Duration::from_secs(WAKE_DETECTION_GAP_SECS) {
            warn!(
                gap_secs = iteration_gap.as_secs(),
                "supervisor saw a {}s wall-clock gap between iterations — assuming system resume from sleep/hibernate; resetting failure counter and granting longer listener-start grace",
                iteration_gap.as_secs()
            );
            consecutive_failures = 0;
            last_healthy = now;
            next_startup_timeout = Duration::from_secs(WAKE_LISTENER_STARTUP_TIMEOUT_SECS);
        }

        match exit_reason {
            ProxyExit::Signal => {
                terminate_child(child).await?;
                return Ok(());
            }
            ProxyExit::ChildExited(status) if status.success() => {
                return Ok(());
            }
            ProxyExit::ChildExited(status) => {
                warn!("soth-proxy exited with status {status}");
            }
            ProxyExit::Reload => {
                info!("reload requested (SIGHUP or network change) — performing graceful child rotation");
                let mut new_child = spawn_proxy_process(config_path, listener_fd)
                    .await
                    .context("spawn new soth-proxy for graceful rotation")?;
                if let Err(error) = wait_for_listener_start(&mut new_child, expected_port).await {
                    warn!(error = %error, "new proxy child failed to start; keeping old child");
                    let _ = terminate_child(&mut new_child).await;
                    continue;
                }
                info!("new proxy child healthy — draining old child");
                graceful_stop_child(child).await?;
                *child = new_child;
                last_healthy = Instant::now();
                consecutive_failures = 0;
                info!("graceful child rotation complete");
                continue;
            }
            ProxyExit::Unhealthy => {
                warn!(
                    port = expected_port,
                    "proxy listener unresponsive for {}s — restarting child process",
                    LISTENER_HEALTH_FAILURE_WINDOW_MS / 1000
                );
                terminate_child(child).await?;
            }
        }

        // If the proxy was healthy for a sustained period, reset the failure counter.
        if last_healthy.elapsed() < Duration::from_secs(60) {
            consecutive_failures += 1;
        } else {
            consecutive_failures = 1;
        }

        if consecutive_failures > MAX_RESTART_ATTEMPTS {
            anyhow::bail!(
                "soth-proxy failed {MAX_RESTART_ATTEMPTS} consecutive times — giving up. Check logs for root cause."
            );
        }

        let backoff_ms = (RESTART_BACKOFF_BASE_MS * 2u64.saturating_pow(consecutive_failures - 1))
            .min(RESTART_BACKOFF_MAX_MS);
        warn!(
            attempt = consecutive_failures,
            max_attempts = MAX_RESTART_ATTEMPTS,
            backoff_ms,
            "restarting soth-proxy in {}ms",
            backoff_ms
        );
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

        *child = spawn_proxy_process(config_path, listener_fd)
            .await
            .context("respawn soth-proxy process")?;
        if let Err(error) =
            wait_for_listener_start_with_timeout(child, expected_port, next_startup_timeout).await
        {
            warn!(
                timeout_secs = next_startup_timeout.as_secs(),
                "proxy failed to start after respawn: {error}"
            );
            continue;
        }
        info!(
            port = expected_port,
            attempt = consecutive_failures,
            "soth-proxy restarted successfully"
        );
        last_healthy = Instant::now();
        // After a successful restart, drop back to the normal startup
        // budget — the wake-up grace window is one-shot.
        next_startup_timeout = listener_startup_timeout();
    }
}

enum ProxyExit {
    Signal,
    ChildExited(std::process::ExitStatus),
    Unhealthy,
    Reload,
}

async fn wait_until_exit_or_unhealthy(
    child: &mut Child,
    expected_port: u16,
    foreground: bool,
    network_change_rx: &mut tokio::sync::watch::Receiver<u64>,
) -> ProxyExit {
    let health_monitor = monitor_listener_health(expected_port);
    tokio::pin!(health_monitor);

    if foreground {
        tokio::select! {
            status = child.wait() => {
                ProxyExit::ChildExited(status.unwrap_or_else(|_| {
                    std::process::ExitStatus::default()
                }))
            }
            _ = tokio::signal::ctrl_c() => ProxyExit::Signal,
            _ = &mut health_monitor => ProxyExit::Unhealthy,
            _ = network_change_rx.changed() => ProxyExit::Reload,
        }
    } else {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("listen for SIGTERM");
            let mut interrupt = signal(SignalKind::interrupt()).expect("listen for SIGINT");
            let mut hangup = signal(SignalKind::hangup()).expect("listen for SIGHUP");
            tokio::select! {
                status = child.wait() => {
                    ProxyExit::ChildExited(status.unwrap_or_else(|_| {
                        std::process::ExitStatus::default()
                    }))
                }
                _ = term.recv() => ProxyExit::Signal,
                _ = interrupt.recv() => ProxyExit::Signal,
                _ = hangup.recv() => ProxyExit::Reload,
                _ = &mut health_monitor => ProxyExit::Unhealthy,
                _ = network_change_rx.changed() => ProxyExit::Reload,
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                status = child.wait() => {
                    ProxyExit::ChildExited(status.unwrap_or_else(|_| {
                        std::process::ExitStatus::default()
                    }))
                }
                _ = &mut health_monitor => ProxyExit::Unhealthy,
                _ = network_change_rx.changed() => ProxyExit::Reload,
            }
        }
    }
}

async fn terminate_child(child: &mut Child) -> Result<()> {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
    Ok(())
}

/// Sends SIGUSR1 to the child to trigger graceful shutdown (stop accepting,
/// drain in-flight connections), then waits up to 30 seconds for exit.
/// Falls back to SIGKILL if the child doesn't exit in time.
#[cfg(unix)]
async fn graceful_stop_child(child: &mut Child) -> Result<()> {
    if let Some(pid) = child.id() {
        // SIGUSR1 tells soth-proxy to stop accepting and drain in-flight connections.
        unsafe { libc::kill(pid as i32, libc::SIGUSR1) };
    }
    match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(status)) => {
            info!(status = %status, "old proxy child exited after drain");
        }
        Ok(Err(error)) => {
            warn!(error = %error, "error waiting for old proxy child");
        }
        Err(_) => {
            warn!("old proxy child did not exit within 30s drain window; killing");
            let _ = terminate_child(child).await;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn graceful_stop_child(child: &mut Child) -> Result<()> {
    terminate_child(child).await
}

async fn wait_for_listener_start(child: &mut Child, port: u16) -> Result<()> {
    wait_for_listener_start_with_timeout(child, port, listener_startup_timeout()).await
}

async fn wait_for_listener_start_with_timeout(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if is_local_listener_ready(port) {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .context("failed checking soth-proxy startup status")?
        {
            anyhow::bail!("soth-proxy exited early with status {status}");
        }
        if Instant::now() >= deadline {
            let _ = terminate_child(child).await;
            anyhow::bail!(
                "soth-proxy did not open 127.0.0.1:{} within {}s startup timeout",
                port,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

async fn monitor_listener_health(port: u16) -> Result<()> {
    let mut interval =
        tokio::time::interval(Duration::from_millis(LISTENER_HEALTH_CHECK_INTERVAL_MS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut unhealthy_since: Option<Instant> = None;
    let failure_window = Duration::from_millis(LISTENER_HEALTH_FAILURE_WINDOW_MS);
    let mut warned = false;

    loop {
        interval.tick().await;
        if is_local_listener_ready(port) {
            if warned {
                info!(
                    port,
                    "proxy listener recovered — accepting connections again"
                );
            }
            unhealthy_since = None;
            warned = false;
            continue;
        }

        let now = Instant::now();
        let started_at = unhealthy_since.get_or_insert(now);
        let elapsed = now.duration_since(*started_at);

        if !warned && elapsed >= Duration::from_secs(2) {
            warn!(
                port,
                elapsed_ms = elapsed.as_millis() as u64,
                "proxy listener not accepting connections — monitoring (will bail after {}s)",
                LISTENER_HEALTH_FAILURE_WINDOW_MS / 1000
            );
            warned = true;
        }

        if elapsed >= failure_window {
            anyhow::bail!(
                "proxy listener on 127.0.0.1:{port} stopped accepting connections for >= {LISTENER_HEALTH_FAILURE_WINDOW_MS}ms"
            );
        }
    }
}

fn is_local_listener_ready(port: u16) -> bool {
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

fn write_proxy_config(config: &SothConfig, port_override: Option<u16>) -> Result<PathBuf> {
    let soth_home = soth_home_dir();
    let root = soth_home.join("run");
    std::fs::create_dir_all(&root)
        .with_context(|| format!("failed creating {}", root.display()))?;

    let path = root.join("proxy.generated.toml");
    let sync_agent_instance_id = resolve_sync_agent_instance_id(config, soth_home.as_path())?;
    let sync_enabled = config.cloud.enabled
        && config
            .cloud
            .api_key
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
    let ca_cert_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()));
    let ca_key_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.key_path.as_str()));
    let forward_proxy = &config.forward_proxy;
    let lookup_timeout_ms = forward_proxy
        .process_attribution
        .lookup_timeout
        .to_millis_or(5_000)
        .max(1);
    let process_cache_ttl_ms = forward_proxy
        .process_attribution
        .cache_ttl
        .as_ref()
        .map(|duration| duration.to_millis_or(0))
        .filter(|ttl| *ttl > 0);
    let upstream_timeout_ms = forward_proxy.upstream_timeout.to_millis_or(30_000).max(1);
    let upstream_connect_timeout_ms = forward_proxy
        .pool
        .connect_timeout
        .to_millis_or(10_000)
        .max(1);
    let upstream_retry_delay_ms = forward_proxy.upstream_retry_delay.to_millis_or(200).max(1);
    let idle_timeout_ms = forward_proxy.pool.idle_timeout.to_millis_or(60_000).max(1);
    let request_timeout_ms = forward_proxy
        .handler_request_timeout
        .to_millis_or(5_000)
        .max(1);
    let response_timeout_ms = forward_proxy
        .handler_response_timeout
        .to_millis_or(5_000)
        .max(1);
    let accept_retry_backoff_ms = forward_proxy.accept_retry_backoff.to_millis_or(100).max(1);
    let stale_flow_ttl_ms = forward_proxy
        .flow_runtime
        .stale_flow_ttl
        .as_ref()
        .map(|duration| duration.to_millis_or(0))
        .filter(|ttl| *ttl > 0);
    let dispatch_queue_send_timeout_ms = forward_proxy
        .flow_runtime
        .dispatch_queue_send_timeout
        .as_ref()
        .map(|duration| duration.to_millis_or(0))
        .filter(|ttl| *ttl > 0);
    let dispatch_close_join_timeout_ms = forward_proxy
        .flow_runtime
        .dispatch_close_join_timeout
        .as_ref()
        .map(|duration| duration.to_millis_or(0))
        .filter(|ttl| *ttl > 0);

    let generated = GeneratedProxyConfig {
        db_path: cli_config::resolved_db_path(config).display().to_string(),
        org_id: config
            .cloud
            .tags
            .get("org_id")
            .or_else(|| config.cloud.tags.get("workspace_id"))
            .cloned()
            .unwrap_or_else(|| "local-org".to_string()),
        team_id: config
            .cloud
            .tags
            .get("team_id")
            .or_else(|| config.cloud.tags.get("workspace_id"))
            .cloned()
            .unwrap_or_else(|| "local-team".to_string()),
        device_id_hash: config
            .cloud
            .tags
            .get("device_id")
            .cloned()
            .unwrap_or_else(|| sync_agent_instance_id.clone()),
        mitm: GeneratedMitmConfig {
            bind: format!(
                "{}:{}",
                config.forward_proxy.address,
                port_override.unwrap_or(config.forward_proxy.port)
            ),
            unix_socket_path: forward_proxy.unix_socket_path.clone(),
            destinations: if forward_proxy.destinations.is_empty() {
                vec!["*".to_string()]
            } else {
                forward_proxy.destinations.clone()
            },
            passthrough_unlisted: forward_proxy.passthrough_unlisted,
            process_attribution_enabled: forward_proxy.process_attribution.enabled,
            process_lookup_timeout_ms: lookup_timeout_ms,
            process_cache_capacity: forward_proxy.process_attribution.cache_capacity.max(1),
            process_cache_ttl_ms,
            ca_cert_path: ca_cert_path.display().to_string(),
            ca_key_path: ca_key_path.display().to_string(),
            capture_fingerprint: forward_proxy.tls.capture_fingerprint,
            http2_enabled: forward_proxy.tls.http2_enabled,
            http2_max_header_list_size: forward_proxy.tls.http2_max_header_list_size.max(1),
            http3_passthrough: forward_proxy.tls.http3_passthrough,
            max_http_head_bytes: forward_proxy.max_http_head_bytes.max(1),
            accept_retry_backoff_ms,
            max_flow_event_backlog: forward_proxy.max_flow_event_backlog.max(1),
            max_in_flight_bytes: forward_proxy.max_in_flight_bytes.max(1),
            max_concurrent_flows: forward_proxy.max_concurrent_flows.max(1),
            upstream_timeout_ms,
            upstream_connect_timeout_ms,
            upstream_retry_on_failure: forward_proxy.upstream_retry_on_failure,
            upstream_retry_delay_ms,
            verify_upstream_tls: forward_proxy.tls.verify_upstream_tls,
            max_connections_per_host: forward_proxy.pool.max_connections_per_host.max(1),
            idle_timeout_ms,
            max_idle_per_host: forward_proxy.pool.max_idle_per_host.max(1),
            max_body_bytes: forward_proxy.capture_max_body_bytes.max(1),
            buffer_request_bodies: forward_proxy.buffer_request_bodies,
            request_timeout_ms,
            response_timeout_ms,
            handler_recover_from_panics: forward_proxy.handler_recover_from_panics,
            flow_dispatch_queue_capacity: forward_proxy.flow_runtime.dispatch_queue_capacity,
            closed_flow_lru_capacity: forward_proxy.flow_runtime.closed_flow_lru_capacity,
            stale_flow_ttl_ms,
            stale_reap_max_batch: forward_proxy.flow_runtime.stale_reap_max_batch,
            dispatch_queue_send_timeout_ms,
            dispatch_close_join_timeout_ms,
        },
        bundle: GeneratedBundleConfig {
            bundle_dir: cli_config::expand_tilde(Path::new(config.bundle.bundle_dir.as_str()))
                .display()
                .to_string(),
            vendor_pubkey_hex: config.bundle.vendor_pubkey_hex.clone(),
            verify_vendor_signature: config.bundle.verify_vendor_signature,
            require_verified_bundle: config.bundle.require_verified_bundle,
            org_approval_pubkey_hex: config.bundle.org_approval_pubkey_hex.clone(),
        },
        sync: GeneratedSyncConfig {
            enabled: sync_enabled,
            // Runtime sync (heartbeat, telemetry, registry puller) is
            // edge plane — must target soth-ingestion, not the management API.
            endpoint: config.cloud.resolved_ingest_endpoint(),
            api_key: config.cloud.api_key.clone().unwrap_or_default(),
            agent_instance_id: sync_agent_instance_id,
            sync_interval_secs: config.cloud.sync_interval_secs.max(5),
            legacy_exchange_upload_enabled: config.exchange.legacy_upload_enabled,
        },
        classify: GeneratedClassifyConfig {
            max_in_flight: config.proxy.classify_max_in_flight,
            slot_acquire_timeout_ms: config.proxy.classify_slot_acquire_timeout_ms,
            db_write_queue_capacity: config.proxy.db_write_queue_capacity,
        },
        pipeline: GeneratedPipelineConfig {
            unknown_app_action: config.pipeline.unknown_app_action.clone(),
            non_cataloged_host_action: config.pipeline.non_cataloged_host_action.clone(),
        },
        telemetry: GeneratedTelemetryConfig {
            enabled: sync_enabled && config.exchange.enabled,
        },
    };

    let body = toml::to_string_pretty(&generated).context("serialize proxy TOML")?;
    std::fs::write(&path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(path)
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn resolve_sync_agent_instance_id(config: &SothConfig, soth_home: &Path) -> Result<String> {
    if let Some(value) = config.cloud.tags.get(AGENT_INSTANCE_ID_TAG) {
        if let Some(normalized) = normalize_agent_instance_id(value) {
            return Ok(normalized);
        }
    }

    let runtime_dir = soth_home.join("runtime");
    std::fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("failed creating {}", runtime_dir.display()))?;
    let id_path = runtime_dir.join(AGENT_INSTANCE_ID_FILE);

    // Prefer the yaml's `device_id` (written at enrollment) so heartbeat and
    // telemetry agree on a single identifier — without this they diverge:
    // heartbeat writes a fresh "edge-<uuid>" to postgres while telemetry
    // sends "device-<uuid>" from the yaml, and the cloud's hostname-resolution
    // join can never line them up.
    if let Some(value) = config.cloud.tags.get("device_id") {
        if let Some(normalized) = normalize_agent_instance_id(value) {
            let _ = std::fs::write(&id_path, format!("{normalized}\n"));
            return Ok(normalized);
        }
    }

    if let Ok(raw) = std::fs::read_to_string(&id_path) {
        if let Some(normalized) = normalize_agent_instance_id(raw.as_str()) {
            return Ok(normalized);
        }
    }

    let generated = format!("{AGENT_INSTANCE_ID_PREFIX}{}", Uuid::new_v4());
    std::fs::write(&id_path, format!("{generated}\n"))
        .with_context(|| format!("failed writing {}", id_path.display()))?;
    Ok(generated)
}

fn normalize_agent_instance_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(trimmed.len());
    let mut previous_dash = false;
    for ch in trimmed.chars() {
        let next = if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':') {
            ch
        } else {
            '-'
        };
        if next == '-' {
            if previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        normalized.push(next);
    }

    let normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Translate `bind_supervisor_listener` failures into something a user can act
/// on. The raw OS error is "Address already in use (os error 48)" which gives
/// no hint about which process is holding the port. We probe the listener's
/// owners via `lsof`/`netstat` and, if any of them look like a soth daemon,
/// say so explicitly.
#[cfg(unix)]
fn friendly_bind_error(error: anyhow::Error, port: u16) -> anyhow::Error {
    let root = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>());
    let is_addr_in_use = root
        .map(|err| err.kind() == std::io::ErrorKind::AddrInUse)
        .unwrap_or(false);
    if !is_addr_in_use {
        return error;
    }

    let owners = daemon::listener_owner_pids(port).unwrap_or_default();
    let soth_owner = owners
        .iter()
        .copied()
        .find(|pid| daemon::is_expected_daemon_process(*pid));

    if let Some(pid) = soth_owner {
        return anyhow::anyhow!(
            "another soth proxy is already running on :{port} (pid {pid}). \
             Run `soth down` to stop it before starting a new instance, \
             or pass `--port <PORT>` to use a different port."
        );
    }

    if !owners.is_empty() {
        let pid_list = owners
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return anyhow::anyhow!(
            "port {port} is already bound by pid(s) {pid_list} (not a soth process). \
             Stop that process or pass `--port <PORT>` to use a different port."
        );
    }

    error
}

#[cfg(unix)]
fn bind_supervisor_listener(address: &str, port: u16) -> Result<std::net::TcpListener> {
    let addr = format!("{address}:{port}");
    let listener = std::net::TcpListener::bind(&addr)
        .with_context(|| format!("supervisor: failed to bind listener on {addr}"))?;
    // Clear FD_CLOEXEC so the child process inherits this socket.
    use std::os::unix::io::AsRawFd;
    let fd = listener.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
    }
    info!(bind = %addr, fd, "supervisor bound listener");
    Ok(listener)
}

fn parse_env_u64(key: &str) -> Option<u64> {
    env::var(key).ok()?.trim().parse::<u64>().ok()
}

/// Resolve the listener-bind startup deadline. Defaults to
/// `LISTENER_STARTUP_TIMEOUT_SECS`; operators can override via
/// `SOTH_PROXY_LISTENER_STARTUP_TIMEOUT_SECS`. Clamped to
/// `[MIN_LISTENER_STARTUP_TIMEOUT_SECS, MAX_LISTENER_STARTUP_TIMEOUT_SECS]`
/// so a misconfiguration can't make the supervisor wait forever or give
/// up before the worker has a chance to bind.
fn listener_startup_timeout() -> Duration {
    let secs = parse_env_u64("SOTH_PROXY_LISTENER_STARTUP_TIMEOUT_SECS")
        .unwrap_or(LISTENER_STARTUP_TIMEOUT_SECS)
        .clamp(
            MIN_LISTENER_STARTUP_TIMEOUT_SECS,
            MAX_LISTENER_STARTUP_TIMEOUT_SECS,
        );
    Duration::from_secs(secs)
}

#[cfg(unix)]
fn ensure_fd_budget() {
    let requested_min_soft = parse_env_u64("SOTH_PROXY_NOFILE_MIN_SOFT_LIMIT")
        .unwrap_or(DEFAULT_NOFILE_MIN_SOFT_LIMIT)
        .max(1);
    let warn_soft = parse_env_u64("SOTH_PROXY_NOFILE_WARN_SOFT_LIMIT")
        .unwrap_or(DEFAULT_NOFILE_WARN_SOFT_LIMIT)
        .max(1);

    // SAFETY: getrlimit/setrlimit operate on process-level rlimit values.
    unsafe {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) != 0 {
            warn!("Failed to read RLIMIT_NOFILE");
            return;
        }

        let initial_soft = limits.rlim_cur;
        let hard = limits.rlim_max;

        if initial_soft < requested_min_soft {
            let target = std::cmp::min(hard, requested_min_soft) as libc::rlim_t;
            if target > limits.rlim_cur {
                limits.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limits) == 0 {
                    info!(
                        previous_soft = initial_soft,
                        new_soft = target as u64,
                        hard_limit = hard,
                        "Raised RLIMIT_NOFILE soft limit"
                    );
                } else {
                    warn!(
                        soft_limit = initial_soft,
                        hard_limit = hard,
                        requested_min_soft = requested_min_soft,
                        "Failed to raise RLIMIT_NOFILE soft limit"
                    );
                }
            }
        }

        let mut verify = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut verify) == 0 {
            let effective_soft = verify.rlim_cur;
            let effective_hard = verify.rlim_max;
            if effective_soft < warn_soft {
                warn!(
                    soft_limit = effective_soft,
                    hard_limit = effective_hard,
                    warn_soft = warn_soft,
                    "Low RLIMIT_NOFILE soft limit may cause EMFILE under bursty traffic"
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn ensure_fd_budget() {}

#[cfg(windows)]
fn reapply_windows_key_acl(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let username = std::env::var("USERNAME").context("USERNAME env var not set")?;
    if username.is_empty() {
        anyhow::bail!("USERNAME env var is empty");
    }
    let grant = format!("{username}:F");

    let output = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", grant.as_str()])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("failed to spawn icacls")?;
    if !output.status.success() {
        anyhow::bail!(
            "icacls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct GeneratedProxyConfig {
    db_path: String,
    org_id: String,
    team_id: String,
    device_id_hash: String,
    mitm: GeneratedMitmConfig,
    bundle: GeneratedBundleConfig,
    sync: GeneratedSyncConfig,
    classify: GeneratedClassifyConfig,
    pipeline: GeneratedPipelineConfig,
    telemetry: GeneratedTelemetryConfig,
}

#[derive(Debug, Serialize)]
struct GeneratedMitmConfig {
    bind: String,
    unix_socket_path: Option<String>,
    destinations: Vec<String>,
    passthrough_unlisted: bool,
    process_attribution_enabled: bool,
    process_lookup_timeout_ms: u64,
    process_cache_capacity: usize,
    process_cache_ttl_ms: Option<u64>,
    ca_cert_path: String,
    ca_key_path: String,
    capture_fingerprint: bool,
    http2_enabled: bool,
    http2_max_header_list_size: u32,
    http3_passthrough: bool,
    max_http_head_bytes: usize,
    accept_retry_backoff_ms: u64,
    max_flow_event_backlog: usize,
    max_in_flight_bytes: usize,
    max_concurrent_flows: usize,
    upstream_timeout_ms: u64,
    upstream_connect_timeout_ms: u64,
    upstream_retry_on_failure: bool,
    upstream_retry_delay_ms: u64,
    verify_upstream_tls: bool,
    max_connections_per_host: u32,
    idle_timeout_ms: u64,
    max_idle_per_host: u32,
    max_body_bytes: usize,
    buffer_request_bodies: bool,
    request_timeout_ms: u64,
    response_timeout_ms: u64,
    handler_recover_from_panics: bool,
    flow_dispatch_queue_capacity: Option<usize>,
    closed_flow_lru_capacity: Option<usize>,
    stale_flow_ttl_ms: Option<u64>,
    stale_reap_max_batch: Option<usize>,
    dispatch_queue_send_timeout_ms: Option<u64>,
    dispatch_close_join_timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GeneratedBundleConfig {
    bundle_dir: String,
    vendor_pubkey_hex: String,
    verify_vendor_signature: bool,
    require_verified_bundle: bool,
    org_approval_pubkey_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct GeneratedSyncConfig {
    enabled: bool,
    endpoint: String,
    api_key: String,
    agent_instance_id: String,
    sync_interval_secs: u64,
    legacy_exchange_upload_enabled: bool,
}

#[derive(Debug, Serialize)]
struct GeneratedClassifyConfig {
    max_in_flight: usize,
    slot_acquire_timeout_ms: u64,
    db_write_queue_capacity: usize,
}

#[derive(Debug, Serialize)]
struct GeneratedPipelineConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    unknown_app_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_cataloged_host_action: Option<String>,
}

#[derive(Debug, Serialize)]
struct GeneratedTelemetryConfig {
    enabled: bool,
}

/// In-process MITM runtime, invoked by re-execed supervisor children (see
/// [`spawn_proxy_process`]). Registers the historian extension and delegates
/// to `soth_proxy::runtime::run`.
async fn run_proxy_worker() -> Result<()> {
    use std::sync::Arc;

    soth_proxy::runtime::init_rustls_provider();

    let mut registry = soth_extensions::ExtensionRegistry::empty();
    registry.register(Arc::new(soth_historian::HistorianExtension::with_defaults()));

    let tracing_targets = registry.tracing_targets();
    // Hold the observability guard until proxy.run() returns so that the
    // OTel batch exporter + Sentry transport flush in-flight events on
    // graceful shutdown. If the worker is killed (signal, panic), Sentry's
    // own panic handler still ships the event before the process exits.
    let _observability_guard = soth_proxy::runtime::init_tracing(&tracing_targets);

    soth_proxy::runtime::run(registry).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_home<T>(f: impl FnOnce(std::path::PathBuf) -> T + std::panic::UnwindSafe) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_soth_home = std::env::var_os("SOTH_HOME_DIR");
        let soth_home = temp.path().join(".soth");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("SOTH_HOME_DIR", &soth_home);
        }

        let result = std::panic::catch_unwind(|| f(temp.path().to_path_buf()));

        match old_home {
            Some(value) => unsafe {
                std::env::set_var("HOME", value);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        match old_soth_home {
            Some(value) => unsafe {
                std::env::set_var("SOTH_HOME_DIR", value);
            },
            None => unsafe {
                std::env::remove_var("SOTH_HOME_DIR");
            },
        }
        drop(guard);

        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn generated_proxy_config_includes_ca_paths_and_port_override() {
        with_temp_home(|home| {
            let mut config = SothConfig::default();
            config.forward_proxy.address = "127.0.0.1".to_string();
            config.forward_proxy.port = 8080;
            config.forward_proxy.ca.cert_path = home
                .join("certs")
                .join("custom-ca.pem")
                .display()
                .to_string();
            config.forward_proxy.ca.key_path = home
                .join("certs")
                .join("custom-ca-key.pem")
                .display()
                .to_string();
            config.bundle.bundle_dir = home.join("bundle").display().to_string();
            config.bundle.vendor_pubkey_hex = "11".repeat(32);
            config.proxy.classify_max_in_flight = 12;
            config.proxy.classify_slot_acquire_timeout_ms = 750;
            config.proxy.db_write_queue_capacity = 8_192;

            let generated = write_proxy_config(&config, Some(9999)).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");

            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("bind"))
                    .and_then(toml::Value::as_str),
                Some("127.0.0.1:9999")
            );
            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("ca_cert_path"))
                    .and_then(toml::Value::as_str),
                Some(config.forward_proxy.ca.cert_path.as_str())
            );
            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("ca_key_path"))
                    .and_then(toml::Value::as_str),
                Some(config.forward_proxy.ca.key_path.as_str())
            );
            assert_eq!(
                value
                    .get("classify")
                    .and_then(|v| v.get("max_in_flight"))
                    .and_then(toml::Value::as_integer),
                Some(12)
            );
            assert_eq!(
                value
                    .get("classify")
                    .and_then(|v| v.get("slot_acquire_timeout_ms"))
                    .and_then(toml::Value::as_integer),
                Some(750)
            );
            assert_eq!(
                value
                    .get("classify")
                    .and_then(|v| v.get("db_write_queue_capacity"))
                    .and_then(toml::Value::as_integer),
                Some(8_192)
            );
        });
    }

    #[test]
    fn generated_proxy_config_wires_mitm_perf_and_backpressure_fields() {
        with_temp_home(|_home| {
            let mut config = SothConfig::default();
            config.forward_proxy.pool.max_connections_per_host = 24;
            config.forward_proxy.pool.max_idle_per_host = 6;
            config.forward_proxy.pool.idle_timeout =
                crate::cli_config::DurationSetting::Text("1m 30s".to_string());
            config.forward_proxy.pool.connect_timeout =
                crate::cli_config::DurationSetting::Text("12s".to_string());
            config.forward_proxy.process_attribution.lookup_timeout =
                crate::cli_config::DurationSetting::Text("250ms".to_string());
            config.forward_proxy.process_attribution.cache_capacity = 8_192;
            config.forward_proxy.process_attribution.cache_ttl =
                Some(crate::cli_config::DurationSetting::Text("30s".to_string()));
            config.forward_proxy.upstream_timeout =
                crate::cli_config::DurationSetting::Text("45s".to_string());
            config.forward_proxy.upstream_retry_on_failure = true;
            config.forward_proxy.upstream_retry_delay =
                crate::cli_config::DurationSetting::Text("350ms".to_string());
            config.forward_proxy.capture_max_body_bytes = 2 * 1024 * 1024;
            config.forward_proxy.buffer_request_bodies = false;
            config.forward_proxy.handler_request_timeout =
                crate::cli_config::DurationSetting::Text("1500ms".to_string());
            config.forward_proxy.handler_response_timeout =
                crate::cli_config::DurationSetting::Text("1750ms".to_string());
            config.forward_proxy.handler_recover_from_panics = false;
            config.forward_proxy.max_http_head_bytes = 96 * 1024;
            config.forward_proxy.accept_retry_backoff =
                crate::cli_config::DurationSetting::Text("150ms".to_string());
            config.forward_proxy.max_flow_event_backlog = 9_999;
            config.forward_proxy.max_in_flight_bytes = 32 * 1024 * 1024;
            config.forward_proxy.max_concurrent_flows = 1_024;
            config.forward_proxy.tls.http2_enabled = false;
            config.forward_proxy.tls.http2_max_header_list_size = 96 * 1024;
            config.forward_proxy.tls.http3_passthrough = false;
            config.forward_proxy.tls.verify_upstream_tls = false;
            config.forward_proxy.tls.capture_fingerprint = false;
            config.forward_proxy.destinations = vec![
                "api.openai.com:443".to_string(),
                "*.google.com:443".to_string(),
            ];
            config.forward_proxy.passthrough_unlisted = false;
            config.forward_proxy.flow_runtime.dispatch_queue_capacity = Some(777);
            config.forward_proxy.flow_runtime.closed_flow_lru_capacity = Some(8_888);
            config.forward_proxy.flow_runtime.stale_flow_ttl =
                Some(crate::cli_config::DurationSetting::Text("40s".to_string()));
            config.forward_proxy.flow_runtime.stale_reap_max_batch = Some(44);
            config
                .forward_proxy
                .flow_runtime
                .dispatch_queue_send_timeout = Some(crate::cli_config::DurationSetting::Text(
                "900ms".to_string(),
            ));
            config
                .forward_proxy
                .flow_runtime
                .dispatch_close_join_timeout = Some(crate::cli_config::DurationSetting::Text(
                "1500ms".to_string(),
            ));

            let generated = write_proxy_config(&config, None).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");
            let mitm = value.get("mitm").expect("mitm table must exist");

            assert_eq!(
                mitm.get("max_connections_per_host")
                    .and_then(toml::Value::as_integer),
                Some(24)
            );
            assert_eq!(
                mitm.get("max_idle_per_host")
                    .and_then(toml::Value::as_integer),
                Some(6)
            );
            assert_eq!(
                mitm.get("idle_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(90_000)
            );
            assert_eq!(
                mitm.get("upstream_connect_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(12_000)
            );
            assert_eq!(
                mitm.get("process_lookup_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(250)
            );
            assert_eq!(
                mitm.get("process_cache_capacity")
                    .and_then(toml::Value::as_integer),
                Some(8_192)
            );
            assert_eq!(
                mitm.get("process_cache_ttl_ms")
                    .and_then(toml::Value::as_integer),
                Some(30_000)
            );
            assert_eq!(
                mitm.get("upstream_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(45_000)
            );
            assert_eq!(
                mitm.get("upstream_retry_on_failure")
                    .and_then(toml::Value::as_bool),
                Some(true)
            );
            assert_eq!(
                mitm.get("upstream_retry_delay_ms")
                    .and_then(toml::Value::as_integer),
                Some(350)
            );
            assert_eq!(
                mitm.get("max_body_bytes").and_then(toml::Value::as_integer),
                Some((2 * 1024 * 1024) as i64)
            );
            assert_eq!(
                mitm.get("buffer_request_bodies")
                    .and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("request_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(1_500)
            );
            assert_eq!(
                mitm.get("response_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(1_750)
            );
            assert_eq!(
                mitm.get("handler_recover_from_panics")
                    .and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("max_http_head_bytes")
                    .and_then(toml::Value::as_integer),
                Some((96 * 1024) as i64)
            );
            assert_eq!(
                mitm.get("accept_retry_backoff_ms")
                    .and_then(toml::Value::as_integer),
                Some(150)
            );
            assert_eq!(
                mitm.get("max_flow_event_backlog")
                    .and_then(toml::Value::as_integer),
                Some(9_999)
            );
            assert_eq!(
                mitm.get("max_in_flight_bytes")
                    .and_then(toml::Value::as_integer),
                Some((32 * 1024 * 1024) as i64)
            );
            assert_eq!(
                mitm.get("max_concurrent_flows")
                    .and_then(toml::Value::as_integer),
                Some(1_024)
            );
            assert_eq!(
                mitm.get("http2_enabled").and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("http2_max_header_list_size")
                    .and_then(toml::Value::as_integer),
                Some((96 * 1024) as i64)
            );
            assert_eq!(
                mitm.get("http3_passthrough").and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("verify_upstream_tls")
                    .and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("capture_fingerprint")
                    .and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("passthrough_unlisted")
                    .and_then(toml::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                mitm.get("flow_dispatch_queue_capacity")
                    .and_then(toml::Value::as_integer),
                Some(777)
            );
            assert_eq!(
                mitm.get("closed_flow_lru_capacity")
                    .and_then(toml::Value::as_integer),
                Some(8_888)
            );
            assert_eq!(
                mitm.get("stale_flow_ttl_ms")
                    .and_then(toml::Value::as_integer),
                Some(40_000)
            );
            assert_eq!(
                mitm.get("stale_reap_max_batch")
                    .and_then(toml::Value::as_integer),
                Some(44)
            );
            assert_eq!(
                mitm.get("dispatch_queue_send_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(900)
            );
            assert_eq!(
                mitm.get("dispatch_close_join_timeout_ms")
                    .and_then(toml::Value::as_integer),
                Some(1_500)
            );
            assert_eq!(
                mitm.get("destinations")
                    .and_then(toml::Value::as_array)
                    .map(|items| items.len()),
                Some(2)
            );
        });
    }

    #[test]
    fn generated_proxy_config_prefers_org_and_team_tags() {
        with_temp_home(|home| {
            let mut config = SothConfig::default();
            config
                .cloud
                .tags
                .insert("workspace_id".to_string(), "ws_fallback".to_string());
            config
                .cloud
                .tags
                .insert("org_id".to_string(), "org_primary".to_string());
            config
                .cloud
                .tags
                .insert("team_id".to_string(), "team_primary".to_string());
            config
                .cloud
                .tags
                .insert("device_id".to_string(), "device_primary".to_string());

            let generated = write_proxy_config(&config, None).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");

            assert_eq!(
                value.get("org_id").and_then(toml::Value::as_str),
                Some("org_primary")
            );
            assert_eq!(
                value.get("team_id").and_then(toml::Value::as_str),
                Some("team_primary")
            );
            assert_eq!(
                value.get("device_id_hash").and_then(toml::Value::as_str),
                Some("device_primary")
            );

            // agent_instance_id now mirrors the yaml's device_id so heartbeat
            // and telemetry write the same identifier.
            let agent_instance_id = value
                .get("sync")
                .and_then(|v| v.get("agent_instance_id"))
                .and_then(toml::Value::as_str)
                .expect("agent_instance_id should be set");
            assert_eq!(agent_instance_id, "device_primary");

            let persisted = std::fs::read_to_string(
                home.join(".soth").join("runtime").join("agent_instance_id"),
            )
            .expect("agent_instance_id should be persisted");
            assert_eq!(persisted.trim(), agent_instance_id);
        });
    }

    #[test]
    fn generated_proxy_config_wires_legacy_exchange_upload_flag() {
        with_temp_home(|_home| {
            let mut config = SothConfig::default();
            config.exchange.legacy_upload_enabled = true;

            let generated = write_proxy_config(&config, None).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");

            assert_eq!(
                value
                    .get("sync")
                    .and_then(|v| v.get("legacy_exchange_upload_enabled"))
                    .and_then(toml::Value::as_bool),
                Some(true)
            );
        });
    }

    #[test]
    fn generated_proxy_config_prefers_tagged_agent_instance_id() {
        with_temp_home(|_home| {
            let mut config = SothConfig::default();
            config.cloud.tags.insert(
                AGENT_INSTANCE_ID_TAG.to_string(),
                " custom  edge::agent-01 ".to_string(),
            );

            let generated = write_proxy_config(&config, None).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");

            assert_eq!(
                value
                    .get("sync")
                    .and_then(|v| v.get("agent_instance_id"))
                    .and_then(toml::Value::as_str),
                Some("custom-edge::agent-01")
            );
        });
    }
}
