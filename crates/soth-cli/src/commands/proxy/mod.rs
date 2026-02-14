//! Soth proxy CLI commands
//!
//! Commands for managing the HTTP/HTTPS soth proxy:
//! - `soth proxy on` - Enable system proxy (route traffic through SOTH)
//! - `soth proxy off` - Disable system proxy (direct connections)
//! - `soth proxy setup-ca` - Generate CA certificate
//! - `soth proxy start` - Start sensor-only proxy runtime
//! - `soth proxy api start` - Start API/WebSocket service
//! - `soth proxy ui start` - Start UI dev service
//! - `soth proxy profile start` - Start runtime profile (sensor/api/ui/dev stack)
//! - `soth proxy env` - Output environment variables
//! - `soth proxy status` - Show proxy status
//! - `soth proxy ca-info` - Show CA certificate info
//! - `soth proxy metrics` - Show proxy metrics
//! - `soth proxy connections` - Show active connections
//! - `soth proxy circuit` - Circuit breaker status
//! - `soth proxy rate-limit` - Rate limit status

use crate::cli_config;
mod api;
mod ca_info;
mod circuit;
mod connections;
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
    /// Enable system proxy (route traffic through SOTH)
    ///
    /// Configures the system to route HTTPS traffic through SOTH proxy.
    /// AI traffic (OpenAI, Anthropic, Google) will be intercepted for
    /// inspection. All other traffic tunnels through without inspection.
    On {
        /// Proxy port override (uses configured port when omitted)
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Disable system proxy (restore direct connections)
    Off,

    /// Generate and optionally install CA certificate
    SetupCa {
        /// Don't add CA to system trust store
        #[arg(long)]
        no_trust: bool,

        /// Output directory for CA files (defaults to config CA directory)
        #[arg(long)]
        output: Option<String>,
    },

    /// Start the sensor-only soth proxy
    Start {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Suppress startup banner and helper lines
        #[arg(short, long)]
        quiet: bool,
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
        #[arg(short, long)]
        host: Option<String>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// Run proxy command
pub async fn run(cmd: ProxyCommands, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    match cmd {
        ProxyCommands::On { port } => {
            let selected_port = if port.is_some() {
                port
            } else {
                let config = cli_config::load_effective_config(None, global_config.as_ref())?;
                Some(config.forward_proxy.port)
            };
            system::enable(selected_port).await
        }
        ProxyCommands::Off => system::disable().await,
        ProxyCommands::SetupCa { no_trust, output } => {
            setup_ca::run(output, no_trust, global_config.clone()).await
        }
        ProxyCommands::Start {
            port,
            config,
            quiet,
        } => start::run(port, config.or(global_config.clone()), quiet).await,
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
        ProxyCommands::Metrics { config, raw } => {
            metrics::run(config.or(global_config.clone()), raw).await
        }
        ProxyCommands::Connections { config } => {
            connections::run(config.or(global_config.clone())).await
        }
        ProxyCommands::Circuit { action } => match action {
            CircuitAction::Status { config } => {
                circuit::run_status(config.or(global_config.clone())).await
            }
            CircuitAction::Reset { host, config } => {
                circuit::run_reset(host, config.or(global_config.clone())).await
            }
        },
        ProxyCommands::RateLimit { config } => ratelimit::run(config.or(global_config)).await,
    }
}
