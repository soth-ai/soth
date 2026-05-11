//! Runtime command handlers used by the CLI command graph.

mod autostart;
pub(crate) mod ca_health;
mod daemon;
mod doctor;
mod env;
mod network_watcher;
mod setup_ca;
pub(crate) mod shell_env;
mod start;
mod status;
mod system;
mod update_applier;

/// Apply `CREATE_NO_WINDOW` to a `std::process::Command` on Windows so that
/// spawned helper processes (tasklist, reg, certutil, etc.) don't briefly
/// flash a console window during proxy lifecycle operations.
#[cfg(target_os = "windows")]
#[inline]
pub(crate) fn hide_console_window(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

use std::path::PathBuf;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
pub(crate) fn lock_test_env() -> std::sync::MutexGuard<'static, ()> {
    static TEST_ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    match TEST_ENV_MUTEX.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub async fn run_on(port: Option<u16>, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let selected_port = if port.is_some() {
        port
    } else {
        let config = crate::cli_config::load_effective_config(None, global_config.as_ref())?;
        Some(daemon::active_daemon_port_hint().unwrap_or(config.forward_proxy.port))
    };
    system::enable(selected_port).await
}

pub async fn run_off() -> anyhow::Result<()> {
    system::disable().await
}

pub async fn run_start_internal(
    port: Option<u16>,
    config: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    daemon_child: bool,
    no_autostart: bool,
    allow_daemon_child_fallback: bool,
) -> anyhow::Result<()> {
    start::run(
        port,
        config,
        quiet,
        foreground,
        daemon_child,
        no_autostart,
        allow_daemon_child_fallback,
    )
    .await
}

pub async fn run_stop() -> anyhow::Result<()> {
    daemon::run_stop().await
}

pub async fn run_logs(follow: bool, lines: usize) -> anyhow::Result<()> {
    daemon::run_logs(follow, lines).await
}

pub async fn run_setup_ca(
    no_trust: bool,
    output: Option<String>,
    global_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    setup_ca::run(output, no_trust, global_config).await
}

pub async fn run_env(
    shell: &str,
    ca_only: bool,
    unset: bool,
    hook: bool,
    config: Option<PathBuf>,
) -> anyhow::Result<()> {
    env::run(shell, ca_only, unset, hook, config).await
}

pub(crate) fn emit_shell_env_activate(config_path: Option<&PathBuf>) -> anyhow::Result<()> {
    shell_env::emit_activate_patch(config_path)
}

pub(crate) fn emit_shell_env_deactivate() -> anyhow::Result<()> {
    shell_env::emit_deactivate_patch()
}

pub async fn run_status(config: Option<PathBuf>, json: bool) -> anyhow::Result<bool> {
    status::run(config, json).await
}

pub async fn run_doctor(config: Option<PathBuf>, json: bool) -> anyhow::Result<()> {
    doctor::run(config, json).await
}

/// One-shot recovery for "I can't browse even with proxy off" — usually
/// means stale system-proxy state, lingering shell env vars, and a stale
/// mDNSResponder cache from a prior network. Idempotent.
pub async fn run_doctor_reset_network() -> anyhow::Result<()> {
    use crate::style;

    println!("{} Running soth network reset...", style::ARROW_RIGHT);

    // 1. Disable system proxy. With the signature-based path in
    //    `system::disable`, this works even if the state-file is missing.
    if let Err(error) = system::disable().await {
        eprintln!(
            "   {} system proxy disable returned: {error}",
            style::WARNING
        );
    }

    // 2. Emit the shell env deactivate patch so a sibling shell that
    //    sources it (`eval "$(soth env --unset)"`) drops HTTP_PROXY etc.
    if let Err(error) = emit_shell_env_deactivate() {
        eprintln!(
            "   {} shell env deactivate emit failed: {error}",
            style::WARNING
        );
    }

    // 3. Flush DNS caches. User-level dscacheutil never needs sudo;
    //    mDNSResponder kill does. We attempt user-level unconditionally
    //    and prompt on the system-level — non-fatal either way.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("dscacheutil")
            .arg("-flushcache")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        println!("   {} Flushed dscacheutil cache", style::CHECK);

        // Best-effort sudo invocation. If the user can't sudo without a
        // password, we just print the manual command and continue.
        let mdns_status = std::process::Command::new("sudo")
            .args(["-n", "killall", "-HUP", "mDNSResponder"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match mdns_status {
            Ok(s) if s.success() => {
                println!(
                    "   {} HUP'd mDNSResponder (system DNS cache cleared)",
                    style::CHECK
                );
            }
            _ => {
                println!(
                    "   {} Could not HUP mDNSResponder without prompt; run manually:\n      sudo killall -HUP mDNSResponder",
                    style::INFO
                );
            }
        }
    }

    println!(
        "\n{} Network reset complete. If problems persist, restart your browser to clear its proxy/DNS caches.",
        style::success_prefix()
    );
    Ok(())
}
