use crate::{cli_config, commands, logging, style};
use clap::{Args, Parser, Subcommand, ValueEnum};
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

#[derive(Parser)]
#[command(name = "soth")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy daemon
    Start(StartArgs),

    /// Stop the proxy daemon
    Stop,

    /// One-shot bootstrap: init -> CA -> start -> on
    Up(UpArgs),

    /// stop + off
    Down,

    /// Enable system proxy
    On(OnArgs),

    /// Disable system proxy
    Off,

    /// Show daemon logs
    Logs(LogsArgs),

    /// Proxy health, bundle, sync state, and 24h summary
    Status(StatusArgs),

    /// Generate config + keys
    Init(InitArgs),

    /// Exchange enrollment token and persist credentials
    Enroll(commands::enroll::EnrollArgs),

    /// Generate and trust CA certificate
    SetupCa(SetupCaArgs),

    /// Print shell proxy env
    Env(EnvArgs),

    /// Query and stream local events
    Events {
        #[command(subcommand)]
        action: commands::events::EventsCommands,
    },
}

#[derive(Args, Clone)]
pub struct StartArgs {
    /// Port to listen on
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Suppress startup helper output
    #[arg(short, long)]
    pub quiet: bool,

    /// Run in the foreground (no daemonization)
    #[arg(long)]
    pub foreground: bool,

    /// Internal daemon child execution mode
    #[arg(long, hide = true)]
    pub daemon_child: bool,

    /// Do not register startup autostart
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

    /// Enrollment invite token to exchange before startup
    #[arg(long)]
    pub token: Option<String>,

    /// Enrollment endpoint override
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Optional machine name override sent during enrollment
    #[arg(long)]
    pub machine_name: Option<String>,

    /// Suppress startup helper output
    #[arg(short, long)]
    pub quiet: bool,

    /// Run in the foreground (no daemonization)
    #[arg(long)]
    pub foreground: bool,

    /// Do not register startup autostart
    #[arg(long)]
    pub no_autostart: bool,
}

#[derive(Args, Clone)]
pub struct OnArgs {
    /// Proxy port override
    #[arg(short, long)]
    pub port: Option<u16>,
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
pub struct StatusArgs {
    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Clone)]
pub struct InitArgs {
    /// Output directory
    #[arg(short, long, default_value = "~/.soth")]
    pub output: PathBuf,
}

#[derive(Args, Clone)]
pub struct SetupCaArgs {
    /// Don't add CA to system trust store
    #[arg(long)]
    pub no_trust: bool,

    /// Output directory for CA files
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Args, Clone)]
pub struct EnvArgs {
    /// Shell type
    #[arg(long, value_enum, default_value_t = Shell::Bash)]
    pub shell: Shell,

    /// Print unset/remove commands
    #[arg(long)]
    pub unset: bool,

    /// Only show CA cert path
    #[arg(long)]
    pub ca_only: bool,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl Shell {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Powershell => "powershell",
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    build_tokio_runtime()?.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.global.verbose);
    run_command(cli.command, cli.global.config).await
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

async fn run_command(command: Commands, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    match command {
        Commands::Start(args) => {
            run_start_command(args, global_config).await?;
        }
        Commands::Stop => {
            commands::proxy::run_stop().await?;
        }
        Commands::Up(args) => {
            run_up_command(args, global_config).await?;
        }
        Commands::Down => {
            commands::proxy::run_stop().await?;
            commands::proxy::run_off().await?;
        }
        Commands::On(args) => {
            commands::proxy::run_on(args.port, global_config).await?;
        }
        Commands::Off => {
            commands::proxy::run_off().await?;
        }
        Commands::Logs(args) => {
            commands::proxy::run_logs(args.follow, args.lines).await?;
        }
        Commands::Status(args) => {
            let healthy =
                commands::proxy::run_status(args.config.or(global_config), args.json).await?;
            if args.json && !healthy {
                std::process::exit(1);
            }
        }
        Commands::Init(args) => {
            let output = cli_config::expand_tilde(args.output.as_path());
            commands::init::run(output).await?;
        }
        Commands::Enroll(args) => {
            commands::enroll::run(args, global_config).await?;
        }
        Commands::SetupCa(args) => {
            commands::proxy::run_setup_ca(args.no_trust, args.output, global_config).await?;
        }
        Commands::Env(args) => {
            commands::proxy::run_env(
                args.shell.as_str(),
                args.ca_only,
                args.unset,
                args.config.or(global_config),
            )
            .await?;
        }
        Commands::Events { action } => {
            commands::events::run(action, global_config).await?;
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
        args.daemon_child,
        args.no_autostart,
    )
    .await
}

async fn run_up_command(args: UpArgs, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let effective_config = ensure_config_for_up(args.config, global_config, args.quiet).await?;

    if args.token.is_some() {
        if !args.quiet {
            style::info("Enrollment token provided via `up`; exchanging before startup.");
        }
        if let Err(error) = commands::enroll::run(
            commands::enroll::EnrollArgs {
                token: args.token,
                endpoint: args.endpoint,
                config: effective_config.clone(),
                from_stdin: false,
                non_interactive: true,
                machine_name: args.machine_name,
            },
            effective_config.clone(),
        )
        .await
        {
            tracing::warn!(
                error = %error,
                "Enrollment failed during `up`; continuing fail-open with local runtime"
            );
        }
    }

    ensure_ca_for_up(effective_config.clone(), args.quiet).await?;

    if args.foreground {
        commands::proxy::run_start_internal(
            args.port,
            effective_config,
            args.quiet,
            true,
            false,
            args.no_autostart,
        )
        .await?;
        return Ok(());
    }

    commands::proxy::run_start_internal(
        args.port,
        effective_config.clone(),
        args.quiet,
        false,
        false,
        args.no_autostart,
    )
    .await?;

    if let Err(error) = commands::proxy::run_on(args.port, effective_config).await {
        tracing::warn!(
            error = %error,
            "Post-start proxy enable failed during `up`; daemon remains running"
        );
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
    let cert_path = cli_config::expand_tilde(config.forward_proxy.ca.cert_path.as_ref());
    let key_path = cli_config::expand_tilde(config.forward_proxy.ca.key_path.as_ref());
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
