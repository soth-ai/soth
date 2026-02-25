//! Runtime command handlers used by the CLI command graph.

mod autostart;
mod daemon;
mod env;
mod setup_ca;
mod start;
mod status;
mod system;

use std::path::PathBuf;

pub async fn run_on(port: Option<u16>, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let selected_port = if port.is_some() {
        port
    } else {
        let config = crate::cli_config::load_effective_config(None, global_config.as_ref())?;
        Some(config.forward_proxy.port)
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
) -> anyhow::Result<()> {
    start::run(port, config, quiet, foreground, daemon_child, no_autostart).await
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
    config: Option<PathBuf>,
) -> anyhow::Result<()> {
    env::run(shell, ca_only, unset, config).await
}

pub async fn run_status(config: Option<PathBuf>, json: bool) -> anyhow::Result<bool> {
    status::run(config, json).await
}
