//! SOTH CLI - Command-line interface for the SOTH edge proxy
//!
//! Usage:
//!   soth wrap -- <cmd>           - Wrap an MCP server for interception
//!   soth install                 - Auto-configure MCP clients to use wrap
//!   soth uninstall               - Remove wrap configuration
//!   soth init                    - Initialize config and keys
//!   soth start                   - Start the proxy
//!   soth tui                     - Interactive TUI dashboard
//!   soth identity generate       - Generate a new keypair
//!   soth identity list           - List trusted agents
//!   soth identity trust <did>    - Add DID to trust store
//!   soth policy compile          - Compile YAML policies to Rego
//!   soth policy test             - Run policy tests
//!   soth budget status           - Show current budget status
//!   soth budget report           - Generate spend report
//!   soth tail                    - Stream live events
//!   soth audit verify            - Verify Merkle audit trail

mod commands;
pub mod style;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// SOTH - Edge proxy for AI agent traffic
#[derive(Parser)]
#[command(name = "soth")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "soth.yaml")]
    config: PathBuf,

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

    /// Initialize configuration and keys
    Init {
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Start the proxy
    Start {
        /// Transport type (stdio, sse, http, streamable-http)
        #[arg(short, long)]
        transport: Option<String>,

        /// Listen port (for SSE/HTTP/Streamable HTTP)
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// HTTP/HTTPS forward proxy management
    Proxy {
        #[command(subcommand)]
        action: commands::proxy::ProxyCommands,
    },

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

    /// Stream live events
    Tail(commands::tail::TailArgs),

    /// Interactive TUI dashboard
    Tui(commands::tui::TuiArgs),

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
        log: PathBuf,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    // Execute command
    match cli.command {
        Commands::Wrap(args) => {
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
        Commands::Init { output } => {
            commands::init::run(output).await?;
        }
        Commands::Start { transport, port } => {
            commands::start::run(cli.config, transport, port).await?;
        }
        Commands::Proxy { action } => {
            commands::proxy::run(action).await?;
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
        Commands::Tail(args) => {
            commands::tail::run(args).await?;
        }
        Commands::Tui(args) => {
            commands::tui::run(args).await?;
        }
        Commands::Audit { action } => {
            commands::audit::run(action).await?;
        }
        Commands::Config { action } => {
            commands::config::run(cli.config, action).await?;
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
