use crate::{cli_config, commands, logging, style};
use clap::{Args, Parser, Subcommand};
use std::env;
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*};

#[derive(Args, Clone)]
pub struct GlobalOptions {
    /// Global config file path (applies to all commands)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// SOTH sensor runtime
#[derive(Parser)]
#[command(name = "soth")]
#[command(author, version, about, long_about = None)]
pub struct SensorCli {
    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: SensorCommands,
}

/// SOTH - Edge proxy for AI agent traffic
#[cfg(feature = "ops")]
#[derive(Parser)]
#[command(name = "soth")]
#[command(author, version, about, long_about = None)]
pub struct OpsCli {
    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: OpsCommands,
}

#[derive(Args, Clone)]
pub struct StartArgs {
    /// Port to listen on
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Suppress startup banner and helper lines
    #[arg(short, long)]
    pub quiet: bool,

    /// Run in the foreground (do not daemonize)
    #[arg(long)]
    pub foreground: bool,

    /// Debug: intercept all non-local hosts (full MITM) while this process runs.
    #[arg(long)]
    pub intercept_all: bool,

    /// Debug: limit intercept-all window to N seconds (implies --intercept-all).
    #[arg(long, value_name = "SECONDS")]
    pub intercept_all_for: Option<u64>,

    /// Internal daemon child execution mode (hidden)
    #[arg(long, hide = true)]
    pub daemon_child: bool,

    /// Do not register startup autostart (launchd/systemd/Run key)
    #[arg(long)]
    pub no_autostart: bool,
}

#[derive(Args, Clone)]
pub struct UpArgs {
    /// Port to listen on
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Suppress startup helper lines
    #[arg(short, long)]
    pub quiet: bool,

    /// Run in the foreground (do not daemonize)
    #[arg(long)]
    pub foreground: bool,

    /// Debug: intercept all non-local hosts (full MITM) while this process runs.
    #[arg(long)]
    pub intercept_all: bool,

    /// Debug: limit intercept-all window to N seconds (implies --intercept-all).
    #[arg(long, value_name = "SECONDS")]
    pub intercept_all_for: Option<u64>,

    /// Do not register startup autostart (launchd/systemd/Run key)
    #[arg(long)]
    pub no_autostart: bool,
}

#[derive(Args, Clone)]
pub struct SensorUpArgs {
    #[command(flatten)]
    pub common: UpArgs,

    /// Enrollment invite token to exchange before startup
    #[arg(long, conflicts_with = "enroll_token_stdin")]
    pub enroll_token: Option<String>,

    /// Read enrollment token from stdin before startup
    #[arg(long, conflicts_with = "enroll_token")]
    pub enroll_token_stdin: bool,

    /// Enrollment endpoint override
    #[arg(long)]
    pub enroll_endpoint: Option<String>,

    /// Optional machine name override sent during enrollment
    #[arg(long)]
    pub machine_name: Option<String>,
}

#[derive(Args, Clone)]
pub struct LogsArgs {
    /// Follow logs continuously
    #[arg(short, long)]
    pub follow: bool,

    /// Number of recent lines to print
    #[arg(short = 'n', long, default_value_t = 100)]
    pub lines: usize,
}

#[derive(Args, Clone)]
pub struct OnArgs {
    /// Sensor port override (uses configured port when omitted)
    #[arg(short, long)]
    pub port: Option<u16>,
}

#[derive(Subcommand)]
pub enum SensorCommands {
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
    Start(StartArgs),

    /// Bootstrap prerequisites and start the sensor lifecycle
    Up(SensorUpArgs),

    /// Stop the sensor lifecycle and restore direct network path
    Down,

    /// Stop the sensor proxy daemon
    Stop,

    /// Show/tail sensor proxy daemon logs
    Logs(LogsArgs),

    /// Enable system proxy (route traffic through SOTH)
    On(OnArgs),

    /// Disable system proxy (restore direct connections)
    Off,
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum OpsCommands {
    /// Wrap an MCP server to intercept all traffic
    Wrap(soth_wrap::WrapArgs),

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

    #[cfg(feature = "local-debug")]
    /// Development/runtime surfaces (API/UI/profiles/diagnostics)
    Dev {
        #[command(subcommand)]
        action: DevCommands,
    },

    /// Start the sensor proxy daemon
    Start(StartArgs),

    /// Bootstrap prerequisites and start the sensor lifecycle
    Up(UpArgs),

    /// Stop the sensor lifecycle and restore direct network path
    Down,

    /// Stop the sensor proxy daemon
    Stop,

    /// Show/tail sensor proxy daemon logs
    Logs(LogsArgs),

    /// Enable system proxy (route traffic through SOTH)
    On(OnArgs),

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

    #[cfg(feature = "local-debug")]
    /// Interactive API-backed TUI
    Tui(commands::tui::TuiArgs),

    #[cfg(feature = "local-debug")]
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

    #[cfg(feature = "local-debug")]
    /// Run tests with CI-friendly output
    Test(commands::test::TestArgs),

    /// Session recording and replay
    Session {
        #[command(subcommand)]
        action: commands::session::SessionCommands,
    },
}

#[derive(Subcommand)]
pub enum RuntimeCommands {
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

#[cfg(feature = "local-debug")]
#[derive(Subcommand)]
pub enum DevCommands {
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

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum IdentityCommands {
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

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum PolicyCommands {
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

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum BudgetCommands {
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

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum AuditCommands {
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

        /// Audit log path
        #[arg(short, long)]
        log: Option<PathBuf>,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show audit statistics
    Stats {
        /// Audit log path
        #[arg(short, long)]
        log: Option<PathBuf>,
    },
}

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum ConfigCommands {
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

#[cfg(feature = "ops")]
#[derive(Subcommand)]
pub enum ConfigRegistryCommands {
    /// Show local cloud registry cache status
    Status,
}

#[derive(Clone)]
struct UpEnrollmentOptions {
    enroll_token: Option<String>,
    enroll_token_stdin: bool,
    enroll_endpoint: Option<String>,
    machine_name: Option<String>,
}

#[cfg_attr(feature = "ops", allow(dead_code))]
pub fn run_sensor() -> anyhow::Result<()> {
    build_tokio_runtime()?.block_on(async_main_sensor())
}

#[cfg(feature = "ops")]
pub fn run_ops() -> anyhow::Result<()> {
    build_tokio_runtime()?.block_on(async_main_ops())
}

#[cfg_attr(feature = "ops", allow(dead_code))]
async fn async_main_sensor() -> anyhow::Result<()> {
    let cli = SensorCli::parse();
    init_logging(cli.global.verbose);
    run_sensor_command(cli.command, cli.global.config).await
}

#[cfg(feature = "ops")]
async fn async_main_ops() -> anyhow::Result<()> {
    let cli = OpsCli::parse();
    init_logging(cli.global.verbose);
    run_ops_command(cli.command, cli.global.config).await
}

fn init_logging(verbose: bool) {
    let filter = logging::default_log_filter(verbose);
    let use_ansi = logging::use_ansi_colors();

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .event_format(logging::SothLogFormatter::new(use_ansi))
                .with_ansi(use_ansi),
        )
        .with(filter)
        .init();
}

#[cfg_attr(feature = "ops", allow(dead_code))]
async fn run_sensor_command(
    command: SensorCommands,
    global_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    match command {
        SensorCommands::Wrap(mut args) => {
            if args.config.is_none() {
                args.config = global_config.clone();
            }
            soth_wrap::run(args).await?;
        }
        SensorCommands::Login(args) => {
            commands::login::run(args, global_config.clone()).await?;
        }
        SensorCommands::Enroll(args) => {
            commands::enroll::run(args, global_config.clone()).await?;
        }
        SensorCommands::Init { output } => {
            commands::init::run(output).await?;
        }
        SensorCommands::Runtime { action } => {
            run_runtime_command(action, global_config.clone()).await?;
        }
        SensorCommands::Start(args) => {
            run_start_command(args, global_config.clone()).await?;
        }
        SensorCommands::Up(args) => {
            run_up_command(
                args.common,
                global_config.clone(),
                Some(UpEnrollmentOptions {
                    enroll_token: args.enroll_token,
                    enroll_token_stdin: args.enroll_token_stdin,
                    enroll_endpoint: args.enroll_endpoint,
                    machine_name: args.machine_name,
                }),
            )
            .await?;
        }
        SensorCommands::Down | SensorCommands::Stop => {
            commands::proxy::run_stop().await?;
        }
        SensorCommands::Logs(args) => {
            commands::proxy::run_logs(args.follow, args.lines).await?;
        }
        SensorCommands::On(args) => {
            commands::proxy::run_on(args.port, global_config.clone()).await?;
        }
        SensorCommands::Off => {
            commands::proxy::run_off().await?;
        }
    }

    Ok(())
}

#[cfg(feature = "ops")]
async fn run_ops_command(
    command: OpsCommands,
    global_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    match command {
        OpsCommands::Wrap(mut args) => {
            if args.config.is_none() {
                args.config = global_config.clone();
            }
            soth_wrap::run(args).await?;
        }
        OpsCommands::Install { target, dry_run } => {
            commands::install::run_install(target, dry_run).await?;
        }
        OpsCommands::Uninstall { target } => {
            commands::install::run_uninstall(target).await?;
        }
        OpsCommands::Status => {
            commands::install::run_status().await?;
        }
        OpsCommands::Setup { action } => {
            commands::setup::run(action, global_config.clone()).await?;
        }
        OpsCommands::Login(args) => {
            commands::login::run(args, global_config.clone()).await?;
        }
        OpsCommands::Enroll(args) => {
            commands::enroll::run(args, global_config.clone()).await?;
        }
        OpsCommands::Init { output } => {
            commands::init::run(output).await?;
        }
        OpsCommands::Runtime { action } => {
            run_runtime_command(action, global_config.clone()).await?;
        }
        #[cfg(feature = "local-debug")]
        OpsCommands::Dev { action } => match action {
            DevCommands::Api { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Api { action },
                    global_config.clone(),
                )
                .await?;
            }
            DevCommands::Ui { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Ui { action },
                    global_config.clone(),
                )
                .await?;
            }
            DevCommands::Profile { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Profile { action },
                    global_config.clone(),
                )
                .await?;
            }
            DevCommands::Advanced { action } => {
                commands::proxy::run(
                    commands::proxy::ProxyCommands::Advanced { action },
                    global_config.clone(),
                )
                .await?;
            }
        },
        OpsCommands::Start(args) => {
            run_start_command(args, global_config.clone()).await?;
        }
        OpsCommands::Up(args) => {
            run_up_command(args, global_config.clone(), None).await?;
        }
        OpsCommands::Down | OpsCommands::Stop => {
            commands::proxy::run_stop().await?;
        }
        OpsCommands::Logs(args) => {
            commands::proxy::run_logs(args.follow, args.lines).await?;
        }
        OpsCommands::On(args) => {
            commands::proxy::run_on(args.port, global_config.clone()).await?;
        }
        OpsCommands::Off => {
            commands::proxy::run_off().await?;
        }
        OpsCommands::Identity { action } => {
            commands::identity::run(action).await?;
        }
        OpsCommands::Policy { action } => {
            commands::policy::run(action).await?;
        }
        OpsCommands::Budget { action } => {
            commands::budget::run(action).await?;
        }
        #[cfg(feature = "local-debug")]
        OpsCommands::Tui(args) => {
            commands::tui::run(args).await?;
        }
        #[cfg(feature = "local-debug")]
        OpsCommands::Attach(args) => {
            commands::tui::run(args).await?;
        }
        OpsCommands::Audit { action } => {
            commands::audit::run(action).await?;
        }
        OpsCommands::Config { action } => {
            commands::config::run(global_config.clone(), action).await?;
        }
        #[cfg(feature = "local-debug")]
        OpsCommands::Test(args) => {
            commands::test::run(args).await?;
        }
        OpsCommands::Session { action } => {
            commands::session::run(action).await?;
        }
    }

    Ok(())
}

async fn run_runtime_command(
    action: RuntimeCommands,
    global_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    match action {
        RuntimeCommands::SetupCa { no_trust, output } => {
            commands::proxy::run_setup_ca(no_trust, output, global_config).await?;
        }
        RuntimeCommands::Env {
            shell,
            unset,
            ca_only,
            config,
        } => {
            commands::proxy::run_env(&shell, ca_only, unset, config.or(global_config)).await?;
        }
        RuntimeCommands::Status { config } => {
            commands::proxy::run_status(config.or(global_config)).await?;
        }
        RuntimeCommands::CaInfo { config } => {
            commands::proxy::run_ca_info(config.or(global_config)).await?;
        }
        RuntimeCommands::Autostart { action } => {
            commands::proxy::run_autostart(action, global_config).await?;
        }
    }

    Ok(())
}

async fn run_start_command(args: StartArgs, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    commands::proxy::run_start_internal(
        args.port,
        args.config.or(global_config),
        args.quiet,
        args.foreground,
        args.intercept_all,
        args.intercept_all_for,
        args.daemon_child,
        args.no_autostart,
    )
    .await
}

async fn run_up_command(
    args: UpArgs,
    global_config: Option<PathBuf>,
    enrollment: Option<UpEnrollmentOptions>,
) -> anyhow::Result<()> {
    let UpArgs {
        port,
        config,
        quiet,
        foreground,
        intercept_all,
        intercept_all_for,
        no_autostart,
    } = args;

    let effective_config = ensure_config_for_up(config, global_config, quiet).await?;

    if let Some(enrollment) = enrollment {
        if enrollment.enroll_token.is_some() || enrollment.enroll_token_stdin {
            if !quiet {
                style::info("Enrollment requested via `up`; exchanging token before startup.");
            }
            if let Err(error) = commands::enroll::run(
                commands::enroll::EnrollArgs {
                    token: enrollment.enroll_token,
                    endpoint: enrollment.enroll_endpoint,
                    config: effective_config.clone(),
                    from_stdin: enrollment.enroll_token_stdin,
                    non_interactive: true,
                    machine_name: enrollment.machine_name,
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
    }

    ensure_ca_for_up(effective_config.clone(), quiet).await?;

    if foreground {
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

        if let Err(error) = commands::proxy::run_on(port, effective_config).await {
            tracing::warn!(
                error = %error,
                "Post-start proxy enable failed during `up`; daemon remains running"
            );
            if !quiet {
                style::warning(&format!(
                    "Could not enable system proxy after daemon start (continuing): {error}"
                ));
                style::info(
                    "Sensor daemon is running. Use `soth on` after resolving network/permission issues.",
                );
            }
        }
    }

    Ok(())
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
