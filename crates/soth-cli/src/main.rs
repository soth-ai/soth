//! SOTH CLI - Command-line interface for the SOTH edge proxy
//!
//! Usage:
//!   soth wrap -- <cmd>           - Wrap an MCP server for interception
//!   soth install                 - Auto-configure MCP clients to use wrap
//!   soth uninstall               - Remove wrap configuration
//!   soth setup wizard            - Guided setup for proxy/wrap/shell
//!   soth init                    - Initialize config and keys
//!   soth login                   - Store cloud API credentials locally
//!   soth enroll <token>          - Exchange enrollment token for machine credentials
//!   soth up                      - One-command bootstrap + start lifecycle
//!   soth down                    - One-command stop lifecycle
//!   soth start                   - Start sensor proxy daemon
//!   soth stop                    - Stop sensor proxy daemon
//!   soth logs -f                 - Follow sensor proxy logs
//!   soth tui                     - Interactive API-backed TUI
//!   soth attach                  - Attach TUI to a running sensor API
//!   soth runtime setup-ca        - Generate/install local CA certificate
//!   soth runtime env             - Print proxy env exports
//!   soth dev api start           - Start local API/WebSocket service
//!   soth dev ui start            - Start local UI dev service
//!   soth dev profile start       - Start runtime profile (sensor/api/ui/dev)
//!   soth identity generate       - Generate a new keypair
//!   soth identity list           - List trusted agents
//!   soth identity trust <did>    - Add DID to trust store
//!   soth policy compile          - Compile YAML policies to Rego
//!   soth policy test             - Run policy tests
//!   soth budget status           - Show current budget status
//!   soth budget report           - Generate spend report
//!   soth audit verify            - Verify Merkle audit trail

mod cli_config;
mod commands;
mod logging;
pub mod style;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*};

/// SOTH - Edge proxy for AI agent traffic
#[derive(Parser)]
#[command(name = "soth")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Global config file path (applies to all commands)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wrap an MCP server to intercept all traffic
    Wrap(commands::wrap::WrapArgs),

    /// Auto-configure MCP clients to route through soth wrap
    Install {
        /// Install for specific client (claude-desktop, cursor, windsurf)
        #[arg(long)]
        target: Option<String>,

        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Remove soth wrap configuration from MCP clients
    Uninstall {
        /// Uninstall for specific client
        #[arg(long)]
        target: Option<String>,
    },

    /// Show installation status
    Status,

    /// Guided setup and health checks
    Setup {
        #[command(subcommand)]
        action: commands::setup::SetupCommands,
    },

    /// Store cloud API credentials locally
    Login(commands::login::LoginArgs),

    /// Enroll this machine with a centralized SOTH workspace
    Enroll(commands::enroll::EnrollArgs),

    /// Initialize configuration and keys
    Init {
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Sensor/system runtime operations
    Runtime {
        #[command(subcommand)]
        action: RuntimeCommands,
    },

    /// Development/runtime surfaces (API/UI/profiles/diagnostics)
    Dev {
        #[command(subcommand)]
        action: DevCommands,
    },

    /// Start the sensor proxy daemon
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

        /// Run in the foreground (do not daemonize)
        #[arg(long)]
        foreground: bool,

        /// Internal daemon child execution mode (hidden)
        #[arg(long, hide = true)]
        daemon_child: bool,
    },

    /// Bootstrap prerequisites and start the sensor lifecycle
    Up {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Suppress startup helper lines
        #[arg(short, long)]
        quiet: bool,

        /// Run in the foreground (do not daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the sensor lifecycle and restore direct network path
    Down,

    /// Stop the sensor proxy daemon
    Stop,

    /// Show/tail sensor proxy daemon logs
    Logs {
        /// Follow logs continuously
        #[arg(short, long)]
        follow: bool,

        /// Number of recent lines to print
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
    },

    /// Enable system proxy (route traffic through SOTH)
    On {
        /// Sensor port override (uses configured port when omitted)
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Disable system proxy (restore direct connections)
    Off,

    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityCommands,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Budget management
    Budget {
        #[command(subcommand)]
        action: BudgetCommands,
    },

    /// Interactive API-backed TUI
    Tui(commands::tui::TuiArgs),

    /// Attach TUI to a running soth sensor API
    Attach(commands::tui::TuiArgs),

    /// Audit trail management
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Run tests with CI-friendly output
    Test(commands::test::TestArgs),

    /// Session recording and replay
    Session {
        #[command(subcommand)]
        action: commands::session::SessionCommands,
    },
}

#[derive(Subcommand)]
enum RuntimeCommands {
    /// Generate and optionally install CA certificate
    SetupCa {
        /// Don't add CA to system trust store
        #[arg(long)]
        no_trust: bool,

        /// Output directory for CA files (defaults to config CA directory)
        #[arg(long)]
        output: Option<String>,
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

    /// Show sensor/runtime status
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

#[derive(Subcommand)]
enum DevCommands {
    /// API service management (HTTP + WebSocket)
    Api {
        #[command(subcommand)]
        action: commands::proxy::ApiAction,
    },

    /// UI service management
    Ui {
        #[command(subcommand)]
        action: commands::proxy::UiAction,
    },

    /// Runtime profile management (sensor/api/ui/dev stack)
    Profile {
        #[command(subcommand)]
        action: commands::proxy::ProfileAction,
    },

    /// Advanced diagnostics and controls
    Advanced {
        #[command(subcommand)]
        action: commands::proxy::AdvancedAction,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Generate a new keypair
    Generate {
        /// Output path for the private key
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List trusted DIDs
    List,

    /// Add a DID to the trust store
    Trust {
        /// The DID to trust
        did: String,

        /// Optional alias for the DID
        #[arg(short, long)]
        alias: Option<String>,
    },

    /// Remove a DID from the trust store
    Untrust {
        /// The DID to remove
        did: String,
    },

    /// Verify a DID signature
    Verify {
        /// The DID to verify
        did: String,

        /// Path to the signed document
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Show the public DID for a key file
    Show {
        /// Path to the key file
        #[arg(short, long)]
        key: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Compile YAML policies to Rego
    Compile {
        /// Input directory
        #[arg(short, long, default_value = "policies")]
        input: PathBuf,

        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Test policies
    Test {
        /// Policy directory
        #[arg(short, long, default_value = "policies")]
        dir: PathBuf,
    },

    /// Evaluate a policy
    Evaluate {
        /// Input JSON file
        #[arg(short, long)]
        input: PathBuf,

        /// Policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },

    /// List loaded policies
    List,
}

#[derive(Subcommand)]
enum BudgetCommands {
    /// Show current budget status
    Status {
        /// Show detailed breakdown
        #[arg(short, long)]
        detailed: bool,
    },

    /// Generate spend report
    Report {
        /// Report period (daily, weekly, monthly)
        #[arg(short, long, default_value = "daily")]
        period: String,

        /// Output format (json, csv, text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Reset budget counters
    Reset {
        /// Budget ID to reset (or "all")
        #[arg(default_value = "all")]
        budget_id: String,
    },

    /// Set budget limits
    Set {
        /// Scope (global, agent:<id>)
        scope: String,

        /// Daily limit
        #[arg(long)]
        daily: Option<f64>,

        /// Weekly limit
        #[arg(long)]
        weekly: Option<f64>,

        /// Monthly limit
        #[arg(long)]
        monthly: Option<f64>,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Verify Merkle audit trail integrity
    Verify {
        /// Audit log path
        #[arg(short, long)]
        log: Option<PathBuf>,

        /// Lower bound for batch seal timestamp (RFC3339).
        #[arg(long)]
        from: Option<String>,

        /// Upper bound for batch seal timestamp (RFC3339).
        #[arg(long)]
        to: Option<String>,
    },

    /// Export audit proof
    Proof {
        /// Event ID
        event_id: String,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show audit statistics
    Stats {
        /// Audit log path
        #[arg(short, long)]
        log: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Validate configuration file
    Validate {
        /// Config file to validate (uses -c/--config if not specified)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Show detailed validation output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show effective configuration (with defaults)
    Show {
        /// Output format (yaml, json)
        #[arg(short, long, default_value = "yaml")]
        format: String,
    },

    /// Generate example configuration
    Example {
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Registry cache and bundle diagnostics
    Registry {
        #[command(subcommand)]
        action: ConfigRegistryCommands,
    },
}

#[derive(Subcommand)]
enum ConfigRegistryCommands {
    /// Show local cloud registry cache status
    Status,
}

async fn ensure_config_for_up(
    command_config: Option<PathBuf>,
    global_config: Option<PathBuf>,
    quiet: bool,
) -> anyhow::Result<Option<PathBuf>> {
    if let Some(resolved) =
        cli_config::resolve_config_path(command_config.as_ref(), global_config.as_ref())
    {
        if resolved.exists() {
            return Ok(Some(resolved));
        }
        anyhow::bail!(
            "config file not found: {} (run `soth init --output {}` first)",
            resolved.display(),
            resolved
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".to_string())
        );
    }

    let init_output = dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"));
    if !quiet {
        style::info(&format!(
            "No config found. Bootstrapping runtime in {}",
            init_output.display()
        ));
    }
    commands::init::run(init_output.clone()).await?;
    Ok(Some(init_output.join("soth.yaml")))
}

async fn ensure_ca_for_up(config_path: Option<PathBuf>, quiet: bool) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let cert_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path);
    let key_path = cli_config::expand_tilde(&config.forward_proxy.ca.key_path);
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    if !quiet {
        style::info("CA certificate not found. Generating now.");
    }
    commands::proxy::run_setup_ca(false, None, config_path).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = logging::default_log_filter(cli.verbose);
    let use_ansi = logging::use_ansi_colors();

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .event_format(logging::SothLogFormatter::new(use_ansi))
                .with_ansi(use_ansi),
        )
        .with(filter)
        .init();

    // Execute command
    match cli.command {
        Commands::Wrap(mut args) => {
            if args.config.is_none() {
                args.config = cli.config.clone();
            }
            commands::wrap::run(args).await?;
        }
        Commands::Install { target, dry_run } => {
            commands::install::run_install(target, dry_run).await?;
        }
        Commands::Uninstall { target } => {
            commands::install::run_uninstall(target).await?;
        }
        Commands::Status => {
            commands::install::run_status().await?;
        }
        Commands::Setup { action } => {
            commands::setup::run(action, cli.config.clone()).await?;
        }
        Commands::Login(args) => {
            commands::login::run(args, cli.config.clone()).await?;
        }
        Commands::Enroll(args) => {
            commands::enroll::run(args, cli.config.clone()).await?;
        }
        Commands::Init { output } => {
            commands::init::run(output).await?;
        }
        Commands::Runtime { action } => match action {
            RuntimeCommands::SetupCa { no_trust, output } => {
                commands::proxy::run_setup_ca(no_trust, output, cli.config.clone()).await?;
            }
            RuntimeCommands::Env {
                shell,
                ca_only,
                config,
            } => {
                commands::proxy::run_env(&shell, ca_only, config.or(cli.config.clone())).await?;
            }
            RuntimeCommands::Status { config } => {
                commands::proxy::run_status(config.or(cli.config.clone())).await?;
            }
            RuntimeCommands::CaInfo { config } => {
                commands::proxy::run_ca_info(config.or(cli.config.clone())).await?;
            }
        },
        Commands::Dev { action } => match action {
            DevCommands::Api { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Api { action },
                    cli.config.clone(),
                )
                .await?;
            }
            DevCommands::Ui { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Ui { action },
                    cli.config.clone(),
                )
                .await?;
            }
            DevCommands::Profile { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Profile { action },
                    cli.config.clone(),
                )
                .await?;
            }
            DevCommands::Advanced { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Advanced { action },
                    cli.config.clone(),
                )
                .await?;
            }
        },
        Commands::Start {
            port,
            config,
            quiet,
            foreground,
            daemon_child,
        } => {
            commands::proxy::run_start_internal(
                port,
                config.or(cli.config.clone()),
                quiet,
                foreground,
                daemon_child,
            )
            .await?;
        }
        Commands::Up {
            port,
            config,
            quiet,
            foreground,
        } => {
            let effective_config = ensure_config_for_up(config, cli.config.clone(), quiet).await?;
            ensure_ca_for_up(effective_config.clone(), quiet).await?;

            if foreground {
                commands::proxy::run_on(port, effective_config.clone()).await?;
                commands::proxy::run_start_internal(port, effective_config, quiet, true, false)
                    .await?;
            } else {
                commands::proxy::run_start_internal(
                    port,
                    effective_config.clone(),
                    quiet,
                    false,
                    false,
                )
                .await?;
                commands::proxy::run_on(port, effective_config).await?;
            }
        }
        Commands::Down => {
            commands::proxy::run_off().await?;
            commands::proxy::run_stop().await?;
        }
        Commands::Stop => {
            commands::proxy::run_stop().await?;
        }
        Commands::Logs { follow, lines } => {
            commands::proxy::run_logs(follow, lines).await?;
        }
        Commands::On { port } => {
            commands::proxy::run_on(port, cli.config.clone()).await?;
        }
        Commands::Off => {
            commands::proxy::run_off().await?;
        }
        Commands::Identity { action } => {
            commands::identity::run(action).await?;
        }
        Commands::Policy { action } => {
            commands::policy::run(action).await?;
        }
        Commands::Budget { action } => {
            commands::budget::run(action).await?;
        }
        Commands::Tui(args) => {
            commands::tui::run(args).await?;
        }
        Commands::Attach(args) => {
            commands::tui::run(args).await?;
        }
        Commands::Audit { action } => {
            commands::audit::run(action).await?;
        }
        Commands::Config { action } => {
            commands::config::run(cli.config.clone(), action).await?;
        }
        Commands::Test(args) => {
            commands::test::run(args).await?;
        }
        Commands::Session { action } => {
            commands::session::run(action).await?;
        }
    }

    Ok(())
}
