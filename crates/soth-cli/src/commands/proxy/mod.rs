//! Forward proxy CLI commands
//!
//! Commands for managing the HTTP/HTTPS forward proxy:
//! - `soth proxy on` - Enable system proxy (route traffic through SOTH)
//! - `soth proxy off` - Disable system proxy (direct connections)
//! - `soth proxy setup-ca` - Generate CA certificate
//! - `soth proxy start` - Start the forward proxy
//! - `soth proxy env` - Output environment variables
//! - `soth proxy status` - Show proxy status
//! - `soth proxy ca-info` - Show CA certificate info
//! - `soth proxy metrics` - Show proxy metrics
//! - `soth proxy connections` - Show active connections
//! - `soth proxy circuit` - Circuit breaker status
//! - `soth proxy rate-limit` - Rate limit status

mod ca_info;
mod circuit;
mod connections;
mod env;
mod metrics;
mod ratelimit;
mod setup_ca;
mod start;
mod status;
mod system;

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
        /// Proxy port (default: 8080)
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

        /// Output directory for CA files
        #[arg(long, default_value = "~/.soth/ca")]
        output: String,
    },

    /// Start the forward proxy
    Start {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use legacy ForwardProxyTransport instead of hudsucker
        #[arg(long)]
        legacy: bool,
    },

    /// Output shell environment variables for proxy configuration
    Env {
        /// Shell type (bash, zsh, fish, powershell)
        #[arg(long, default_value = "bash")]
        shell: String,

        /// Only show CA cert path (for --cacert)
        #[arg(long)]
        ca_only: bool,
    },

    /// Show proxy status
    Status,

    /// Show CA certificate information
    CaInfo,

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
        #[arg(short, long)]
        host: Option<String>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// Run proxy command
pub async fn run(cmd: ProxyCommands) -> anyhow::Result<()> {
    match cmd {
        ProxyCommands::On { port } => {
            system::enable(port).await
        }
        ProxyCommands::Off => {
            system::disable().await
        }
        ProxyCommands::SetupCa { no_trust, output } => {
            setup_ca::run(output, no_trust).await
        }
        ProxyCommands::Start { port, config, legacy } => {
            start::run_with_mode(port, config, legacy).await
        }
        ProxyCommands::Env { shell, ca_only } => {
            env::run(&shell, ca_only).await
        }
        ProxyCommands::Status => {
            status::run().await
        }
        ProxyCommands::CaInfo => {
            ca_info::run().await
        }
        ProxyCommands::Metrics { config, raw } => {
            metrics::run(config, raw).await
        }
        ProxyCommands::Connections { config } => {
            connections::run(config).await
        }
        ProxyCommands::Circuit { action } => {
            match action {
                CircuitAction::Status { config } => {
                    circuit::run_status(config).await
                }
                CircuitAction::Reset { host, config } => {
                    circuit::run_reset(host, config).await
                }
            }
        }
        ProxyCommands::RateLimit { config } => {
            ratelimit::run(config).await
        }
    }
}
