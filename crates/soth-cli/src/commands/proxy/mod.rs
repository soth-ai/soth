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
