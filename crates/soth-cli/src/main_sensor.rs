//! SOTH sensor CLI entry point.
//!
//! Focused runtime surface:
//! - wrap/init/bootstrap/start/stop lifecycle
//! - login/enroll onboarding
//! - runtime CA/env/status helpers
//! - system proxy on/off controls

mod cli_config;
mod commands;
mod logging;
pub mod style;

use clap::{Parser, Subcommand};
use std::env;
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*};

/// SOTH sensor runtime
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
    Wrap(soth_wrap::WrapArgs),

    /// Store cloud API credentials locally (interactive prompt or flag/stdin)
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

        /// Debug: intercept all non-local hosts (full MITM) while this process runs.
        #[arg(long)]
        intercept_all: bool,

        /// Debug: limit intercept-all window to N seconds (implies --intercept-all).
        #[arg(long, value_name = "SECONDS")]
        intercept_all_for: Option<u64>,

        /// Internal daemon child execution mode (hidden)
        #[arg(long, hide = true)]
        daemon_child: bool,

        /// Do not register startup autostart (launchd/systemd/Run key)
        #[arg(long)]
        no_autostart: bool,
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

        /// Debug: intercept all non-local hosts (full MITM) while this process runs.
        #[arg(long)]
        intercept_all: bool,

        /// Debug: limit intercept-all window to N seconds (implies --intercept-all).
        #[arg(long, value_name = "SECONDS")]
        intercept_all_for: Option<u64>,

        /// Enrollment invite token to exchange before startup
        #[arg(long, conflicts_with = "enroll_token_stdin")]
        enroll_token: Option<String>,

        /// Read enrollment token from stdin before startup
        #[arg(long, conflicts_with = "enroll_token")]
        enroll_token_stdin: bool,

        /// Enrollment endpoint override
        #[arg(long)]
        enroll_endpoint: Option<String>,

        /// Optional machine name override sent during enrollment
        #[arg(long)]
        machine_name: Option<String>,

        /// Do not register startup autostart (launchd/systemd/Run key)
        #[arg(long)]
        no_autostart: bool,
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

        /// Print unset/remove commands instead of set/export commands
        #[arg(long)]
        unset: bool,

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

    /// Manage startup autostart registration
    Autostart {
        #[command(subcommand)]
        action: commands::proxy::AutostartAction,
    },
}

// These command enums are defined in the sensor binary root behind `ops` so
// shared command modules compile cleanly when `--features ops` is enabled
// alongside default features.
#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum IdentityCommands {
    Generate {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    List,
    Trust {
        did: String,
        #[arg(short, long)]
        alias: Option<String>,
    },
    Untrust {
        did: String,
    },
    Verify {
        did: String,
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    Show {
        #[arg(short, long)]
        key: PathBuf,
    },
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum PolicyCommands {
    Compile {
        #[arg(short, long, default_value = "policies")]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Test {
        #[arg(short, long, default_value = "policies")]
        dir: PathBuf,
    },
    Evaluate {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    List,
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum BudgetCommands {
    Status {
        #[arg(short, long)]
        detailed: bool,
    },
    Report {
        #[arg(short, long, default_value = "daily")]
        period: String,
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    Reset {
        #[arg(default_value = "all")]
        budget_id: String,
    },
    Set {
        scope: String,
        #[arg(long)]
        daily: Option<f64>,
        #[arg(long)]
        weekly: Option<f64>,
        #[arg(long)]
        monthly: Option<f64>,
    },
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum AuditCommands {
    Verify {
        #[arg(short, long)]
        log: Option<PathBuf>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    Proof {
        event_id: String,
        #[arg(short, long)]
        log: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Stats {
        #[arg(short, long)]
        log: Option<PathBuf>,
    },
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum ConfigCommands {
    Validate {
        #[arg(short, long)]
        file: Option<PathBuf>,
        #[arg(short, long)]
        verbose: bool,
    },
    Show {
        #[arg(short, long, default_value = "yaml")]
        format: String,
    },
    Example {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Registry {
        #[command(subcommand)]
        action: ConfigRegistryCommands,
    },
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
enum ConfigRegistryCommands {
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

fn parse_env_usize(key: &str) -> Option<usize> {
    env::var(key).ok()?.parse::<usize>().ok()
}

fn parse_env_u32(key: &str) -> Option<u32> {
    env::var(key).ok()?.parse::<u32>().ok()
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 32)
}

fn build_tokio_runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    let worker_threads = parse_env_usize("SOTH_TOKIO_WORKER_THREADS")
        .filter(|v| *v > 0)
        .unwrap_or_else(default_worker_threads);
    let max_blocking_threads = parse_env_usize("SOTH_TOKIO_MAX_BLOCKING_THREADS")
        .filter(|v| *v > 0)
        .unwrap_or(512);
    let thread_stack_size = parse_env_usize("SOTH_TOKIO_THREAD_STACK_SIZE")
        .filter(|v| *v >= 256 * 1024)
        .unwrap_or(3 * 1024 * 1024);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .thread_stack_size(thread_stack_size)
        .thread_name("soth-rt");

    if let Some(value) = parse_env_u32("SOTH_TOKIO_EVENT_INTERVAL").filter(|v| *v > 0) {
        builder.event_interval(value);
    }
    if let Some(value) = parse_env_u32("SOTH_TOKIO_GLOBAL_QUEUE_INTERVAL").filter(|v| *v > 0) {
        builder.global_queue_interval(value);
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to initialize Tokio runtime: {e}"))
}

fn main() -> anyhow::Result<()> {
    build_tokio_runtime()?.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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

    match cli.command {
        Commands::Wrap(mut args) => {
            if args.config.is_none() {
                args.config = cli.config.clone();
            }
            soth_wrap::run(args).await?;
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
                unset,
                ca_only,
                config,
            } => {
                commands::proxy::run_env(&shell, ca_only, unset, config.or(cli.config.clone()))
                    .await?;
            }
            RuntimeCommands::Status { config } => {
                commands::proxy::run_status(config.or(cli.config.clone())).await?;
            }
            RuntimeCommands::CaInfo { config } => {
                commands::proxy::run_ca_info(config.or(cli.config.clone())).await?;
            }
            RuntimeCommands::Autostart { action } => {
                commands::proxy::run_autostart(action, cli.config.clone()).await?;
            }
        },
        Commands::Start {
            port,
            config,
            quiet,
            foreground,
            intercept_all,
            intercept_all_for,
            daemon_child,
            no_autostart,
        } => {
            commands::proxy::run_start_internal(
                port,
                config.or(cli.config.clone()),
                quiet,
                foreground,
                intercept_all,
                intercept_all_for,
                daemon_child,
                no_autostart,
            )
            .await?;
        }
        Commands::Up {
            port,
            config,
            quiet,
            foreground,
            intercept_all,
            intercept_all_for,
            enroll_token,
            enroll_token_stdin,
            enroll_endpoint,
            machine_name,
            no_autostart,
        } => {
            let effective_config = ensure_config_for_up(config, cli.config.clone(), quiet).await?;

            if enroll_token.is_some() || enroll_token_stdin {
                if !quiet {
                    style::info("Enrollment requested via `up`; exchanging token before startup.");
                }
                if let Err(error) = commands::enroll::run(
                    commands::enroll::EnrollArgs {
                        token: enroll_token,
                        endpoint: enroll_endpoint,
                        config: effective_config.clone(),
                        from_stdin: enroll_token_stdin,
                        non_interactive: true,
                        machine_name,
                    },
                    effective_config.clone(),
                )
                .await
                {
                    tracing::warn!(
                        error = %error,
                        "Enrollment exchange failed during `up`; continuing fail-open with local runtime"
                    );
                    if !quiet {
                        style::warning(&format!(
                            "Enrollment failed during `up` (continuing fail-open): {error}"
                        ));
                    }
                }
            }

            ensure_ca_for_up(effective_config.clone(), quiet).await?;

            if foreground {
                commands::proxy::run_on(port, effective_config.clone()).await?;
                commands::proxy::run_start_internal(
                    port,
                    effective_config,
                    quiet,
                    true,
                    intercept_all,
                    intercept_all_for,
                    false,
                    no_autostart,
                )
                .await?;
            } else {
                commands::proxy::run_start_internal(
                    port,
                    effective_config.clone(),
                    quiet,
                    false,
                    intercept_all,
                    intercept_all_for,
                    false,
                    no_autostart,
                )
                .await?;
                commands::proxy::run_on(port, effective_config).await?;
            }
        }
        Commands::Down => {
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
    }

    Ok(())
}
