//! Shared runtime/dev command handlers used by the SOTH CLI command tree.

use crate::cli_config;
mod api;
mod ca_info;
mod circuit;
mod connections;
mod daemon;
mod env;
mod metrics;
mod profile;
mod ratelimit;
mod retention;
mod setup_ca;
mod start;
mod status;
mod system;
mod ui;

use clap::Subcommand;
use std::path::PathBuf;

/// Proxy subcommands
#[derive(Subcommand)]
pub enum ProxyCommands {
    /// Generate and optionally install CA certificate
    SetupCa {
        /// Don't add CA to system trust store
        #[arg(long)]
        no_trust: bool,

        /// Output directory for CA files (defaults to config CA directory)
        #[arg(long)]
        output: Option<String>,
    },

    /// Advanced diagnostics and controls
    Advanced {
        #[command(subcommand)]
        action: AdvancedAction,
    },

    /// API service management (HTTP + WebSocket)
    Api {
        #[command(subcommand)]
        action: ApiAction,
    },

    /// UI service management
    Ui {
        #[command(subcommand)]
        action: UiAction,
    },

    /// Runtime profile management (sensor/api/ui/dev stack)
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Output shell environment variables for proxy configuration
    Env {
        /// Shell type (bash, zsh, fish, powershell)
        #[arg(long, default_value = "bash")]
        shell: String,

        /// Only show CA cert path (for --cacert)
        #[arg(long)]
        ca_only: bool,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Show proxy status
    Status {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Show CA certificate information
    CaInfo {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

pub async fn run_on(port: Option<u16>, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let selected_port = if port.is_some() {
        port
    } else {
        let config = cli_config::load_effective_config(None, global_config.as_ref())?;
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
    intercept_all: bool,
    intercept_all_for: Option<u64>,
    daemon_child: bool,
) -> anyhow::Result<()> {
    start::run(
        port,
        config,
        quiet,
        foreground,
        intercept_all,
        intercept_all_for,
        daemon_child,
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

pub async fn run_env(shell: &str, ca_only: bool, config: Option<PathBuf>) -> anyhow::Result<()> {
    env::run(shell, ca_only, config).await
}

pub async fn run_status(config: Option<PathBuf>) -> anyhow::Result<()> {
    status::run(config).await
}

pub async fn run_ca_info(config: Option<PathBuf>) -> anyhow::Result<()> {
    ca_info::run(config).await
}

/// API service actions
#[derive(Subcommand)]
pub enum ApiAction {
    /// Start API service
    Start {
        /// API port override (uses configured port when omitted)
        #[arg(short, long)]
        port: Option<u16>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Suppress startup helper lines
        #[arg(short, long)]
        quiet: bool,
    },
}

/// UI service actions
#[derive(Subcommand)]
pub enum UiAction {
    /// Start UI dev service
    Start {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// API port override used for NEXT_PUBLIC_SOTH_API_BASE/WS
        #[arg(long)]
        api_port: Option<u16>,

        /// UI working directory (defaults to ./dashboard)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Suppress startup helper lines
        #[arg(short, long)]
        quiet: bool,
    },
}

/// Runtime profile actions
#[derive(Subcommand)]
pub enum ProfileAction {
    /// Start one of the runtime profiles
    Start {
        /// Runtime profile to launch
        #[arg(long, default_value = "sensor-only")]
        profile: profile::RuntimeProfile,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Sensor port override
        #[arg(long)]
        sensor_port: Option<u16>,

        /// API port override
        #[arg(long)]
        api_port: Option<u16>,

        /// UI working directory (defaults to ./dashboard)
        #[arg(long)]
        ui_dir: Option<PathBuf>,

        /// For dev-stack profile, skip launching UI
        #[arg(long)]
        no_ui: bool,

        /// Suppress startup helper lines
        #[arg(short, long)]
        quiet: bool,
    },
}

/// Advanced diagnostics actions
#[derive(Subcommand)]
pub enum AdvancedAction {
    /// Show Prometheus metrics from running proxy
    Metrics {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output raw Prometheus format
        #[arg(long)]
        raw: bool,
    },

    /// Show active connections and recent requests
    Connections {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Circuit breaker management
    Circuit {
        #[command(subcommand)]
        action: CircuitAction,
    },

    /// Show rate limit status
    RateLimit {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// Circuit breaker actions
#[derive(Subcommand)]
pub enum CircuitAction {
    /// Show circuit breaker status
    Status {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Reset circuit breaker for a host
    Reset {
        /// Host to reset (all hosts if not specified)
        #[arg(short = 'H', long)]
        host: Option<String>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// Run proxy command
pub async fn run(cmd: ProxyCommands, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    match cmd {
        ProxyCommands::SetupCa { no_trust, output } => {
            setup_ca::run(output, no_trust, global_config.clone()).await
        }
        ProxyCommands::Advanced { action } => match action {
            AdvancedAction::Metrics { config, raw } => {
                metrics::run(config.or(global_config.clone()), raw).await
            }
            AdvancedAction::Connections { config } => {
                connections::run(config.or(global_config.clone())).await
            }
            AdvancedAction::Circuit { action } => match action {
                CircuitAction::Status { config } => {
                    circuit::run_status(config.or(global_config.clone())).await
                }
                CircuitAction::Reset { host, config } => {
                    circuit::run_reset(host, config.or(global_config.clone())).await
                }
            },
            AdvancedAction::RateLimit { config } => {
                ratelimit::run(config.or(global_config.clone())).await
            }
        },
        ProxyCommands::Api { action } => match action {
            ApiAction::Start {
                port,
                config,
                quiet,
            } => api::run_start(port, config.or(global_config.clone()), quiet).await,
        },
        ProxyCommands::Ui { action } => match action {
            UiAction::Start {
                config,
                api_port,
                dir,
                quiet,
            } => ui::run_start(config.or(global_config.clone()), api_port, dir, quiet).await,
        },
        ProxyCommands::Profile { action } => match action {
            ProfileAction::Start {
                profile,
                config,
                sensor_port,
                api_port,
                ui_dir,
                no_ui,
                quiet,
            } => {
                profile::run_start(
                    profile,
                    sensor_port,
                    api_port,
                    config.or(global_config.clone()),
                    ui_dir,
                    no_ui,
                    quiet,
                )
                .await
            }
        },
        ProxyCommands::Env {
            shell,
            ca_only,
            config,
        } => env::run(&shell, ca_only, config.or(global_config.clone())).await,
        ProxyCommands::Status { config } => status::run(config.or(global_config.clone())).await,
        ProxyCommands::CaInfo { config } => ca_info::run(config.or(global_config.clone())).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        proxy: ProxyCommands,
    }

    #[test]
    fn parses_profile_dev_stack_with_overrides() {
        let cli = TestCli::try_parse_from([
            "soth",
            "profile",
            "start",
            "--profile",
            "dev-stack",
            "--sensor-port",
            "8088",
            "--api-port",
            "3010",
            "--no-ui",
            "--quiet",
        ])
        .expect("profile command should parse");

        match cli.proxy {
            ProxyCommands::Profile { action } => match action {
                ProfileAction::Start {
                    profile,
                    sensor_port,
                    api_port,
                    no_ui,
                    quiet,
                    ..
                } => {
                    assert!(matches!(profile, profile::RuntimeProfile::DevStack));
                    assert_eq!(sensor_port, Some(8088));
                    assert_eq!(api_port, Some(3010));
                    assert!(no_ui);
                    assert!(quiet);
                }
            },
            _ => panic!("expected profile subcommand"),
        }
    }

    #[test]
    fn profile_defaults_to_sensor_only() {
        let cli = TestCli::try_parse_from(["soth", "profile", "start"])
            .expect("profile start should parse");

        match cli.proxy {
            ProxyCommands::Profile { action } => match action {
                ProfileAction::Start { profile, .. } => {
                    assert!(matches!(profile, profile::RuntimeProfile::SensorOnly));
                }
            },
            _ => panic!("expected profile subcommand"),
        }
    }
}
