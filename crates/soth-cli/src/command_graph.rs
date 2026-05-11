use crate::{cli_config, commands, logging, style};
use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

    /// Runtime diagnostics for daemon, system proxy, and loopback state
    Doctor(DoctorArgs),

    /// Generate config + keys
    Init(InitArgs),

    /// Exchange enrollment token and persist credentials
    Enroll(commands::enroll::EnrollArgs),

    /// Persist a long-lived cloud API key to the local config
    Login(commands::login::LoginArgs),

    /// Generate and trust CA certificate
    SetupCa(SetupCaArgs),

    /// Print shell proxy env
    Env(EnvArgs),

    /// Query and stream local events
    Events {
        #[command(subcommand)]
        action: commands::events::EventsCommands,
    },

    /// Bundle diagnostics and verification
    Bundle {
        #[command(subcommand)]
        action: commands::bundle::BundleCommands,
    },

    /// Validate configuration without starting the proxy
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Synchronous policy gate at the AI coding agent's hook boundary
    /// (Claude Code, Cursor, Codex, …). See `docs/gryph/plan.md`.
    Code {
        #[command(subcommand)]
        action: commands::code::CodeCommands,
    },

    /// Check for or apply a soth release update
    /// (`docs/common/2026-05-09/hot-update-plan.md`)
    Update(UpdateArgs),
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Parse and sanity-check the config file (exits 1 on errors)
    Validate(ConfigValidateArgs),
}

#[derive(Args, Clone)]
pub struct ConfigValidateArgs {
    /// Config file path (defaults to ~/.soth/soth.yaml)
    #[arg(short, long)]
    pub config: Option<PathBuf>,
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

    /// Internal historian sibling worker mode. Set by the supervisor when
    /// re-execing this binary as the historian worker (see
    /// `spawn_historian_process`). Hidden from `--help`; user code never
    /// sets this. The `SOTH_HISTORIAN_WORKER=1` env paired with this
    /// flag is what actually dispatches into `run_historian_worker`.
    #[arg(long, hide = true)]
    pub historian_child: bool,

    /// Internal classify-daemon sibling worker mode. Same pattern as
    /// `historian_child` — set by the supervisor when re-execing this
    /// binary as the classify daemon worker (see
    /// `spawn_classify_daemon_process`). Hidden from `--help`. The
    /// `SOTH_CODE_CLASSIFY_WORKER=1` env paired with this flag is what
    /// actually dispatches into `run_classify_daemon_worker`.
    #[arg(long, hide = true)]
    pub classify_daemon_child: bool,

    /// Do not register startup autostart
    #[arg(long)]
    pub no_autostart: bool,

    /// Allow fallback to daemon-child mode when managed service startup is unavailable
    #[arg(long)]
    pub allow_daemon_child_fallback: bool,
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

    /// Cloud management endpoint override (persisted as `cloud.endpoint`)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Cloud edge/ingest endpoint override (used for the enrollment exchange
    /// and persisted as `cloud.ingest_endpoint`). Only needed when management
    /// and ingest can't be derived from each other by hostname rewrite — e.g.
    /// local Docker where they're different ports on the same host.
    #[arg(long)]
    pub ingest_endpoint: Option<String>,

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

    /// Allow fallback to daemon-child mode when managed service startup is unavailable
    #[arg(long)]
    pub allow_daemon_child_fallback: bool,

    /// Skip the soth-code hook auto-install sweep that would
    /// otherwise wire hooks for every detected AI coding agent
    /// (Claude Code, Cursor, Codex, Gemini CLI, Pi Agent,
    /// Windsurf, OpenCode) on this host.  Use when you want
    /// proxy-only governance and intend to install hooks
    /// per-agent by hand.
    #[arg(long)]
    pub skip_hooks: bool,

    /// Force re-install of every detected agent's hooks even
    /// when state says they're already wired.  Use after a
    /// soth binary upgrade that moved the executable path.
    /// Implied automatically when binary drift is detected.
    #[arg(long)]
    pub repair_hooks: bool,
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
pub struct DoctorArgs {
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,

    /// One-shot recovery for "I can't browse even with proxy off" situations.
    /// Disables system proxy (signature-aware), removes the bypass list
    /// soth installed, flushes mDNSResponder's cache (sudo required for the
    /// system-level part), and emits the shell-env deactivation patch.
    /// Idempotent — safe to run repeatedly.
    #[arg(long)]
    pub reset_network: bool,
}

#[derive(Args, Clone)]
pub struct InitArgs {
    /// Output directory
    #[arg(short, long, default_value = "~/.soth")]
    pub output: PathBuf,
}

#[derive(Args, Clone)]
pub struct UpdateArgs {
    /// Channel to query (default: stable). Operators can run --channel
    /// canary on the same machine to ride pre-stable releases.
    #[arg(long, default_value = "stable")]
    pub channel: String,

    /// Just check; don't download or swap (this is the default).
    #[arg(long, conflicts_with_all = ["apply", "rollback"])]
    pub check: bool,

    /// Download, verify, and atomically swap to the latest version.
    #[arg(long, conflicts_with = "rollback")]
    pub apply: bool,

    /// Restore the previous binary from <install>.previous and restart.
    #[arg(long)]
    pub rollback: bool,

    /// Bypass the release_seq anti-rollback gate. Operator escape hatch
    /// for emergency reverts; refuses to run without --apply.
    #[arg(long, requires = "apply")]
    pub force_downgrade: bool,

    /// Pin a specific version. Fetches the frozen per-version manifest
    /// at <base>/manifest/<channel>.v<version>.json instead of the
    /// channel-current pointer, so the binary URLs and sha256s in the
    /// manifest match a real, historical release. Implicitly disables
    /// the anti-rollback gate (the version pin is itself the explicit
    /// operator authorization).
    #[arg(long)]
    pub version: Option<String>,

    /// Override the manifest base URL. Hidden from --help; used by
    /// integration tests and ad-hoc operator overrides.
    #[arg(long, hide = true)]
    pub manifest_url: Option<String>,

    /// Internal: macOS auto-update helper mode. The daemon spawns
    /// `soth update --finish-staged` as a detached process so the
    /// `launchctl bootout` step doesn't kill the in-process auto-
    /// applier mid-swap. Hidden — operators should use --apply.
    #[arg(long, hide = true, requires = "staged_path")]
    pub finish_staged: bool,

    /// Internal: path to the binary already downloaded + sha256-checked
    /// by the daemon's auto-applier. Only meaningful with --finish-staged.
    #[arg(long, hide = true)]
    pub staged_path: Option<PathBuf>,
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

    /// Print shell wrapper hook that auto-applies env changes on `soth` commands
    #[arg(long)]
    pub hook: bool,

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
    // Skip the early CLI fmt-only subscriber when we're about to re-enter
    // the binary as the proxy MITM worker. The worker installs its own
    // *layered* tracing subscriber (fmt + tracing-opentelemetry +
    // sentry-tracing) via `soth_proxy::runtime::init_tracing`, and a
    // tracing subscriber can only be installed once per process — if we
    // call `.init()` here first, the worker's call falls through to a
    // no-op and Honeycomb / Sentry never get attached.
    //
    // `SOTH_PROXY_WORKER=1` is set by the supervisor when it spawns its
    // child process (see `commands::proxy::start::PROXY_WORKER_ENV`), so
    // the env var is the authoritative signal for "we're going to run
    // the MITM runtime in this process".
    let in_worker_mode = std::env::var("SOTH_PROXY_WORKER")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !in_worker_mode {
        init_logging(cli.global.verbose);
    }
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
            proxy_run_stop().await?;
            if let Err(error) = commands::proxy::emit_shell_env_deactivate() {
                tracing::warn!(
                    error = %error,
                    "Proxy stopped but failed to emit shell env deactivation patch"
                );
            }
        }
        Commands::Up(args) => {
            run_up_command(args, global_config).await?;
        }
        Commands::Down => {
            proxy_run_stop().await?;
            if let Err(error) = commands::proxy::emit_shell_env_deactivate() {
                tracing::warn!(
                    error = %error,
                    "Proxy down stop phase completed but failed to emit shell env deactivation patch"
                );
            }
            proxy_run_off().await?;
        }
        Commands::On(args) => {
            proxy_run_on(args.port, global_config).await?;
        }
        Commands::Off => {
            proxy_run_off().await?;
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
        Commands::Doctor(args) => {
            if args.reset_network {
                commands::proxy::run_doctor_reset_network().await?;
            } else {
                commands::proxy::run_doctor(global_config, args.json).await?;
            }
        }
        Commands::Init(args) => {
            let output = cli_config::expand_tilde(args.output.as_path());
            commands::init::run(output).await?;
        }
        Commands::Enroll(args) => {
            commands::enroll::run(args, global_config).await?;
        }
        Commands::Login(args) => {
            commands::login::run(args, global_config).await?;
        }
        Commands::SetupCa(args) => {
            commands::proxy::run_setup_ca(args.no_trust, args.output, global_config).await?;
        }
        Commands::Env(args) => {
            commands::proxy::run_env(
                args.shell.as_str(),
                args.ca_only,
                args.unset,
                args.hook,
                args.config.or(global_config),
            )
            .await?;
        }
        Commands::Events { action } => {
            commands::events::run(action, global_config).await?;
        }
        Commands::Bundle { action } => {
            commands::bundle::run(action, global_config).await?;
        }
        Commands::Config { action } => {
            run_config_command(action, global_config)?;
        }
        Commands::Code { action } => {
            // `commands::code::run` calls `std::process::exit` directly
            // when the adapter chooses a non-zero code (Block etc.) —
            // the agent expects a precise exit value the dispatcher
            // can't reshape. Returning Ok(()) here is unreachable for
            // the hook subcommand; `status` does normally return.
            commands::code::run(action, global_config).await?;
        }
        Commands::Update(args) => {
            run_update_command(args).await?;
        }
    }

    Ok(())
}

async fn run_update_command(args: UpdateArgs) -> anyhow::Result<()> {
    use crate::update::Channel;
    let channel: Channel = args.channel.parse()?;
    if args.rollback {
        commands::update::run_rollback().await?;
        return Ok(());
    }
    if args.finish_staged {
        // clap already enforced staged_path is set via `requires`, but
        // we destructure defensively rather than .unwrap().
        let staged = args
            .staged_path
            .ok_or_else(|| anyhow::anyhow!("--finish-staged requires --staged-path"))?;
        commands::update::run_finish_staged(channel, staged, args.manifest_url, args.version)
            .await?;
        return Ok(());
    }
    if args.apply {
        // Ergonomic shortcut: if the operator runs `soth update --apply`
        // with no overrides and there's a heartbeat-delivered offer
        // waiting, fill in --manifest-url + --version from it. Saves
        // them re-typing what the cloud already told the daemon. The
        // signed-manifest trust gate still runs against whatever URL we
        // end up fetching, so this only changes ergonomics, not trust.
        let mut manifest_url = args.manifest_url;
        let mut version = args.version;
        if manifest_url.is_none() && version.is_none() {
            if let Ok(Some(pending)) = soth_sync::update_pending::read() {
                if let Some(base) = commands::update::derive_base_url_from_offer(
                    &pending.offer.url,
                    &pending.offer.version,
                ) {
                    eprintln!(
                        "using pending offer: {} (release_seq={}) from {}",
                        pending.offer.version, pending.offer.release_seq, base,
                    );
                    manifest_url = Some(base);
                    version = Some(pending.offer.version);
                }
            }
        }
        commands::update::run_apply(channel, manifest_url, args.force_downgrade, version).await?;
        return Ok(());
    }
    // default: --check
    let status = commands::update::run_check(channel, args.manifest_url, args.version).await?;
    if let crate::commands::update::UpdateStatus::UpdateAvailable = status {
        std::process::exit(status.exit_code());
    }
    Ok(())
}

async fn proxy_run_start_internal(
    port: Option<u16>,
    config: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    daemon_child: bool,
    no_autostart: bool,
    allow_daemon_child_fallback: bool,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(result) = proxy_test_hooks::maybe_start(
        port,
        config.clone(),
        quiet,
        foreground,
        daemon_child,
        no_autostart,
        allow_daemon_child_fallback,
    ) {
        return result;
    }

    commands::proxy::run_start_internal(
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

async fn proxy_run_on(port: Option<u16>, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(result) = proxy_test_hooks::maybe_on(port, global_config.clone()) {
        return result;
    }
    commands::proxy::run_on(port, global_config).await
}

async fn proxy_run_off() -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(result) = proxy_test_hooks::maybe_off() {
        return result;
    }
    commands::proxy::run_off().await
}

async fn proxy_run_stop() -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(result) = proxy_test_hooks::maybe_stop() {
        return result;
    }
    commands::proxy::run_stop().await
}

#[cfg(test)]
mod proxy_test_hooks {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum ProxyCall {
        Start {
            port: Option<u16>,
            config: Option<PathBuf>,
            quiet: bool,
            foreground: bool,
            daemon_child: bool,
            no_autostart: bool,
            allow_daemon_child_fallback: bool,
        },
        On {
            port: Option<u16>,
            global_config: Option<PathBuf>,
        },
        Off,
        Stop,
    }

    #[derive(Default)]
    pub(super) struct ProxyBehavior {
        pub start_results: VecDeque<Result<(), String>>,
        pub on_results: VecDeque<Result<(), String>>,
        pub off_results: VecDeque<Result<(), String>>,
        pub stop_results: VecDeque<Result<(), String>>,
    }

    #[derive(Default)]
    struct ProxyState {
        active: bool,
        calls: Vec<ProxyCall>,
        behavior: ProxyBehavior,
    }

    static STATE: OnceLock<Mutex<ProxyState>> = OnceLock::new();

    fn state() -> &'static Mutex<ProxyState> {
        STATE.get_or_init(|| Mutex::new(ProxyState::default()))
    }

    fn next_result(queue: &mut VecDeque<Result<(), String>>) -> anyhow::Result<()> {
        match queue.pop_front().unwrap_or(Ok(())) {
            Ok(()) => Ok(()),
            Err(error) => Err(anyhow::anyhow!(error)),
        }
    }

    pub(super) fn install(behavior: ProxyBehavior) {
        let mut guard = state().lock().expect("proxy test hook lock");
        guard.active = true;
        guard.calls.clear();
        guard.behavior = behavior;
    }

    pub(super) fn reset() {
        let mut guard = state().lock().expect("proxy test hook lock");
        guard.active = false;
        guard.calls.clear();
        guard.behavior = ProxyBehavior::default();
    }

    pub(super) fn calls() -> Vec<ProxyCall> {
        state().lock().expect("proxy test hook lock").calls.clone()
    }

    pub(super) fn is_active() -> bool {
        state().lock().expect("proxy test hook lock").active
    }

    pub(super) fn maybe_start(
        port: Option<u16>,
        config: Option<PathBuf>,
        quiet: bool,
        foreground: bool,
        daemon_child: bool,
        no_autostart: bool,
        allow_daemon_child_fallback: bool,
    ) -> Option<anyhow::Result<()>> {
        let mut guard = state().lock().expect("proxy test hook lock");
        if !guard.active {
            return None;
        }
        guard.calls.push(ProxyCall::Start {
            port,
            config,
            quiet,
            foreground,
            daemon_child,
            no_autostart,
            allow_daemon_child_fallback,
        });
        Some(next_result(&mut guard.behavior.start_results))
    }

    pub(super) fn maybe_on(
        port: Option<u16>,
        global_config: Option<PathBuf>,
    ) -> Option<anyhow::Result<()>> {
        let mut guard = state().lock().expect("proxy test hook lock");
        if !guard.active {
            return None;
        }
        guard.calls.push(ProxyCall::On {
            port,
            global_config,
        });
        Some(next_result(&mut guard.behavior.on_results))
    }

    pub(super) fn maybe_off() -> Option<anyhow::Result<()>> {
        let mut guard = state().lock().expect("proxy test hook lock");
        if !guard.active {
            return None;
        }
        guard.calls.push(ProxyCall::Off);
        Some(next_result(&mut guard.behavior.off_results))
    }

    pub(super) fn maybe_stop() -> Option<anyhow::Result<()>> {
        let mut guard = state().lock().expect("proxy test hook lock");
        if !guard.active {
            return None;
        }
        guard.calls.push(ProxyCall::Stop);
        Some(next_result(&mut guard.behavior.stop_results))
    }
}

fn run_config_command(
    action: ConfigCommands,
    global_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    match action {
        ConfigCommands::Validate(args) => {
            let path =
                cli_config::resolve_config_path(args.config.as_ref(), global_config.as_ref())
                    .unwrap_or_else(cli_config::default_config_path);
            commands::config::validate(&path)
        }
    }
}

async fn run_start_command(args: StartArgs, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let effective_config = args.config.clone().or(global_config.clone());
    ensure_bundle_for_bootstrap(effective_config.clone(), args.quiet).await?;
    proxy_run_start_internal(
        args.port,
        effective_config.clone(),
        args.quiet,
        args.foreground,
        args.daemon_child,
        args.no_autostart,
        args.allow_daemon_child_fallback,
    )
    .await?;

    if !args.daemon_child && !args.foreground {
        if let Err(error) = commands::proxy::emit_shell_env_activate(effective_config.as_ref()) {
            tracing::warn!(
                error = %error,
                "Proxy started but failed to emit shell env activation patch"
            );
        }
    }

    Ok(())
}

async fn run_up_command(args: UpArgs, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    // `--endpoint` on `up` is the enrollment-exchange URL — only consumed
    // inside the `if args.token.is_some()` branch below. Without a token
    // it would have been silently ignored, which broke at least one pilot
    // tester who expected `--endpoint` to switch the persisted cloud
    // endpoint. Surface a clear error pointing at the command that
    // actually does that, instead of failing later in confusing ways.
    if args.endpoint.is_some() && args.token.is_none() {
        anyhow::bail!(
            "--endpoint on `soth up` is only honoured together with --token (it's the enrollment endpoint). \
             To switch the persisted cloud endpoint without re-enrolling, run \
             `soth login --endpoint <url>` first, then `soth up`."
        );
    }

    let effective_config = ensure_config_for_up(args.config, global_config, args.quiet).await?;
    let mut enrollment_error: Option<anyhow::Error> = None;

    if args.token.is_some() {
        if !args.quiet {
            style::info("Enrollment token provided via `up`; exchanging before startup.");
        }
        if let Err(error) = commands::enroll::run(
            commands::enroll::EnrollArgs {
                token: args.token,
                endpoint: args.endpoint,
                ingest_endpoint: args.ingest_endpoint,
                config: effective_config.clone(),
                from_stdin: false,
                non_interactive: true,
                machine_name: args.machine_name,
            },
            effective_config.clone(),
        )
        .await
        {
            enrollment_error = Some(error);
        }
    }

    if let Some(error) = enrollment_error {
        // Enrollment failed. Don't bail here — fall through to
        // `ensure_bundle_for_bootstrap`, which knows how to either reuse a
        // local manifest or pull one from the cloud using any API key
        // already on disk from a prior `soth enroll` / `soth login`. Hard
        // failure only happens if neither path produces a bundle.
        tracing::warn!(
            error = %format!("{error:#}"),
            "Enrollment failed during `up`; attempting bundle bootstrap with existing credentials"
        );
        if !args.quiet {
            style::warning(&format!(
                "Enrollment failed: {error:#}\nContinuing with any local bundle or existing cloud credentials."
            ));
        }
    }

    #[cfg(test)]
    let skip_infra_checks = proxy_test_hooks::is_active();
    #[cfg(not(test))]
    let skip_infra_checks = false;

    if !skip_infra_checks {
        ensure_ca_for_up(effective_config.clone(), args.quiet).await?;
        ensure_bundle_for_bootstrap(effective_config.clone(), args.quiet).await?;
    }

    if args.foreground {
        proxy_run_start_internal(
            args.port,
            effective_config.clone(),
            args.quiet,
            true,
            false,
            args.no_autostart,
            args.allow_daemon_child_fallback,
        )
        .await?;
        return Ok(());
    }

    proxy_run_start_internal(
        args.port,
        effective_config.clone(),
        args.quiet,
        false,
        false,
        args.no_autostart,
        args.allow_daemon_child_fallback,
    )
    .await?;

    if let Err(error) = proxy_run_on(args.port, effective_config.clone()).await {
        tracing::warn!(
            error = %error,
            "Post-start proxy enable failed during `up`; attempting rollback stop"
        );
        if let Err(stop_error) = proxy_run_stop().await {
            let _ = commands::proxy::emit_shell_env_deactivate();
            return Err(anyhow::anyhow!(
                "`soth up` failed enabling system proxy ({error}) and rollback stop failed ({stop_error})"
            ));
        }
        let _ = commands::proxy::emit_shell_env_deactivate();
        return Err(anyhow::anyhow!(
            "`soth up` failed enabling system proxy: {error}. Daemon was stopped as rollback."
        ));
    }

    if let Err(error) = commands::proxy::emit_shell_env_activate(effective_config.as_ref()) {
        tracing::warn!(
            error = %error,
            "Proxy up completed but failed to emit shell env activation patch"
        );
    }

    // Auto-install soth-code hooks for every AI coding agent
    // detected on this host.  Idempotent: a state file at
    // ~/.soth/installed.json records which agents the install
    // already wrote; agents already in state with a matching
    // binary path get skipped, the rest get fresh installs.
    // The state file makes a re-run of `soth up` cheap (no
    // unnecessary settings.json rewrites) and gives operators
    // a single place to see "which agents this host has
    // governed."
    if !args.skip_hooks {
        if let Err(error) = auto_install_detected_hooks(args.repair_hooks, args.quiet) {
            tracing::warn!(error = %format!("{error:#}"), "soth-code auto-install sweep failed");
            if !args.quiet {
                style::warning(&format!(
                    "soth-code hook auto-install failed: {error:#}\n\
                     Per-agent install is still available via `soth code install --target <agent>`."
                ));
            }
        }
    }
    Ok(())
}

/// Detect AI coding agents on this host and install soth-code
/// hooks for any that aren't already governed.  Idempotent —
/// the per-host state file at ~/.soth/installed.json records
/// what's been done so re-runs are cheap.  Per-agent install
/// failures don't abort the sweep; we report them in the final
/// summary so operators can see which agents need a manual
/// follow-up.
fn auto_install_detected_hooks(force_repair: bool, quiet: bool) -> anyhow::Result<()> {
    use soth_code::install;
    use soth_code::state::InstalledHostState;

    let detected = install::detect_installable_agents();
    let state_path = InstalledHostState::default_path()
        .context("could not resolve ~/.soth/installed.json — pass HOME or run with --skip-hooks")?;
    let current_binary = std::env::current_exe()
        .context("could not resolve current binary path for state recording")?;

    let result = run_sweep(
        &detected,
        &state_path,
        &current_binary,
        force_repair,
        install_one,
    );
    if !quiet {
        report_sweep(&detected, &result);
    }
    Ok(())
}

/// One row of sweep output — the `installed` / `skipped` /
/// `repaired` / `failed` partition for the agents the
/// orchestrator processed.  Returned to make `run_sweep`
/// pure-ish (no side-channel via `style::info` calls inside
/// the loop) and easy to assert on from tests.
#[derive(Debug, Default, PartialEq, Eq)]
struct SweepResult {
    installed: Vec<String>,
    skipped: Vec<String>,
    repaired: Vec<String>,
    failed: Vec<(String, String)>,
}

/// Pure orchestration: walk the detected agents, decide for
/// each whether to install / skip / repair, call the injected
/// `install_fn` for the install/repair cases, and persist the
/// updated state.  No I/O on stdout — the `report_sweep`
/// helper handles operator-facing output.  No production
/// dependency on `current_exe()` or `default_path()` — both
/// are caller-provided, so a test can drive this against a
/// tmpdir-rooted state file and a synthetic binary path.
///
/// Per-agent install failures land in `result.failed` rather
/// than aborting the sweep — the operator sees which agents
/// need a manual follow-up.
fn run_sweep<F>(
    detected: &[soth_code::install::DetectedAgent],
    state_path: &Path,
    current_binary: &Path,
    force_repair: bool,
    install_fn: F,
) -> SweepResult
where
    F: Fn(&str, &Path) -> anyhow::Result<()>,
{
    use soth_code::state::InstalledHostState;

    let mut state = InstalledHostState::load(state_path).unwrap_or_default();
    let mut result = SweepResult::default();

    for det in detected {
        let drifted = state.binary_drifted(det.agent, current_binary);
        let needs_install = force_repair || drifted || !det.already_installed;
        if !needs_install {
            // Already wired and in-state; just refresh
            // installed_at so the audit trail shows this host
            // saw the agent on this run too.
            state.record_install(
                det.agent,
                det.settings_path.clone(),
                current_binary.to_path_buf(),
            );
            result.skipped.push(det.agent.to_string());
            continue;
        }
        match install_fn(det.agent, &det.settings_path) {
            Ok(()) => {
                state.record_install(
                    det.agent,
                    det.settings_path.clone(),
                    current_binary.to_path_buf(),
                );
                if drifted {
                    result.repaired.push(det.agent.to_string());
                } else {
                    result.installed.push(det.agent.to_string());
                }
            }
            Err(e) => {
                result
                    .failed
                    .push((det.agent.to_string(), format!("{e:#}")));
            }
        }
    }

    if let Err(e) = state.save(state_path) {
        tracing::warn!(error = %format!("{e:#}"), "failed to persist install state");
    }

    result
}

/// Operator-facing summary of a sweep.  Pulled out of
/// `run_sweep` so the pure orchestration is easy to assert
/// on from tests.
fn report_sweep(detected: &[soth_code::install::DetectedAgent], result: &SweepResult) {
    if detected.is_empty() {
        style::info(
            "No AI coding agents detected on this host. Skipping soth-code hook \
             auto-install. Re-run `soth up` after installing Claude Code, Cursor, \
             Codex, Gemini CLI, Pi Agent, Windsurf, or OpenCode.",
        );
        return;
    }
    if !result.installed.is_empty() {
        style::info(&format!(
            "soth-code hooks installed: {}",
            result.installed.join(", ")
        ));
    }
    if !result.repaired.is_empty() {
        style::info(&format!(
            "soth-code hooks repaired (binary path drift): {}",
            result.repaired.join(", ")
        ));
    }
    if !result.skipped.is_empty() {
        style::info(&format!(
            "soth-code hooks already up-to-date: {}",
            result.skipped.join(", ")
        ));
    }
    for (agent, err) in &result.failed {
        style::warning(&format!("soth-code hook install failed for {agent}: {err}"));
    }
}

/// Per-agent install dispatch.  Mirrors the `soth code install`
/// match arm but is invoked from the auto-install sweep with
/// the canonical settings path (no `--settings-path` override).
fn install_one(agent: &str, settings_path: &Path) -> anyhow::Result<()> {
    use soth_code::install::{
        install_claude_code, install_codex, install_cursor, install_gemini_cli, install_opencode,
        install_pi_agent, install_windsurf,
    };
    match agent {
        "claude_code" => install_claude_code(settings_path, None)
            .map(|_| ())
            .context("install claude_code hooks"),
        "cursor" => install_cursor(settings_path, None)
            .map(|_| ())
            .context("install cursor hooks"),
        "openai_codex" => install_codex(settings_path, None)
            .map(|_| ())
            .context("install codex hooks"),
        "gemini_cli" => install_gemini_cli(settings_path, None)
            .map(|_| ())
            .context("install gemini_cli hooks"),
        "windsurf" => install_windsurf(settings_path, None)
            .map(|_| ())
            .context("install windsurf hooks"),
        "pi_agent" => install_pi_agent(settings_path, None)
            .map(|_| ())
            .context("install pi_agent plugin"),
        "opencode" => install_opencode(settings_path, None)
            .map(|_| ())
            .context("install opencode plugin"),
        // OpenClaw deliberately omitted from the auto-installer
        // — config format pending upstream (gryph PR #31).
        other => anyhow::bail!("auto-install does not support agent: {other}"),
    }
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
    let ca_paths = commands::proxy::ca_health::resolve_ca_paths(&config);
    if ca_paths.runtime_cert_path.exists() && ca_paths.runtime_key_path.exists() {
        if !ca_paths.trust_cert_path.exists() {
            anyhow::bail!(
                "Configured trust cert path is missing: {}. Fix forward_proxy.ca.trust_cert_path or run `soth setup-ca`.",
                ca_paths.trust_cert_path.display()
            );
        }

        let runtime_fp = commands::proxy::ca_health::cert_fingerprint_sha256(
            ca_paths.runtime_cert_path.as_path(),
        )
        .context("compute runtime CA fingerprint")?;
        let trust_fp =
            commands::proxy::ca_health::cert_fingerprint_sha256(ca_paths.trust_cert_path.as_path())
                .context("compute trust CA fingerprint")?;
        if runtime_fp != trust_fp {
            anyhow::bail!(
                "CA fingerprint mismatch between runtime cert and trust cert.\nruntime={} ({})\ntrust={} ({})",
                runtime_fp,
                ca_paths.runtime_cert_path.display(),
                trust_fp,
                ca_paths.trust_cert_path.display()
            );
        }

        match commands::proxy::ca_health::check_os_trust(ca_paths.trust_cert_path.as_path()) {
            Ok(check) if check.status == commands::proxy::ca_health::OsTrustStatus::Untrusted => {
                if ca_paths.external_trust_path {
                    anyhow::bail!(
                        "External trust cert is not trusted by OS (source={}): {}. Install trust via MDM/profile and retry.",
                        ca_paths.trust_source,
                        check.detail
                    );
                }
                if !quiet {
                    style::info("CA exists but OS trust is missing. Repairing trust now.");
                }
                commands::proxy::run_setup_ca(false, None, config_path).await?;
                return Ok(());
            }
            Ok(_) => return Ok(()),
            Err(error) => {
                if !quiet {
                    style::warning(&format!(
                        "Unable to verify OS trust state for CA (continuing): {error}"
                    ));
                }
                return Ok(());
            }
        }
    }

    if !quiet {
        style::info("CA certificate not found. Generating now.");
    }
    commands::proxy::run_setup_ca(false, None, config_path).await
}

#[derive(Clone)]
struct BootstrapBundleInstallHook {
    bundle_dir: PathBuf,
    vendor_pubkey: [u8; 32],
    org_config: soth_bundle::OrgSignedConfig,
    verification: soth_bundle::VerificationOptions,
}

impl soth_sync::BundleWatcher for BootstrapBundleInstallHook {
    fn install_bundle(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String> {
        let loaded = soth_bundle::load_from_bytes_with_options(
            manifest_bytes,
            assets.clone(),
            &self.vendor_pubkey,
            &self.org_config,
            self.verification,
        )
        .map_err(|error| anyhow::anyhow!("bundle payload failed validation: {error}"))?;

        install_runtime_bundle_files(self.bundle_dir.as_path(), manifest_bytes, assets)?;
        Ok(loaded.version)
    }

    fn allow_registry_projection_install(&self) -> bool {
        false
    }
}

async fn ensure_bundle_for_bootstrap(
    config_path: Option<PathBuf>,
    quiet: bool,
) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let bundle_dir = cli_config::expand_tilde(Path::new(config.bundle.bundle_dir.as_str()));
    if bundle_dir.join("manifest.json").exists() {
        return Ok(());
    }

    // Bundle bootstrap hits `/v1/edge/registry/*` (edge plane) on
    // soth-ingestion. Use the ingest endpoint, not the management one.
    let endpoint = config.cloud.resolved_ingest_endpoint();
    let api_key = config
        .cloud
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let api_key = match api_key {
        Some(value) => value,
        None => {
            anyhow::bail!(
                "Bundle directory {} is missing and cloud credentials are not configured; bootstrap cannot fetch bundle.\n\
                 Run one of:\n  soth enroll <token>       (exchange an invite token for an API key)\n  soth login --api-key <key> (persist a pre-issued API key directly)",
                bundle_dir.display()
            );
        }
    };

    if endpoint.is_empty() {
        anyhow::bail!(
            "Bundle directory {} is missing and no cloud endpoint is configured; bootstrap cannot fetch bundle.",
            bundle_dir.display()
        );
    }

    if !quiet {
        style::info(&format!(
            "Bundle not found at {}. Fetching from cloud bootstrap endpoint.",
            bundle_dir.display()
        ));
    }

    let vendor_pubkey = parse_fixed_hex_32(
        config.bundle.vendor_pubkey_hex.as_str(),
        "bundle.vendor_pubkey_hex",
    )?;
    let org_approval_pubkey = parse_optional_fixed_hex_32(
        config.bundle.org_approval_pubkey_hex.as_deref(),
        "bundle.org_approval_pubkey_hex",
    )?;

    let verification = soth_bundle::VerificationOptions {
        verify_vendor_signature: config.bundle.verify_vendor_signature,
        require_verified_bundle: config.bundle.require_verified_bundle,
        org_approval_pubkey,
    };
    let org_config = soth_bundle::OrgSignedConfig {
        allows_https_intercept: true,
        allows_http_intercept: true,
        process_filter: None,
        allowed_capture_modes: vec![
            "metadata_only".to_string(),
            "sensitive_artifacts".to_string(),
            "full".to_string(),
        ],
    };

    let install_hook = Arc::new(BootstrapBundleInstallHook {
        bundle_dir: bundle_dir.clone(),
        vendor_pubkey,
        org_config,
        verification,
    });

    let mut puller = soth_sync::registry_puller::RegistryPuller::new(
        endpoint,
        api_key,
        bundle_dir.join("registry_bundle_cache.json"),
    )
    .with_bundle_watcher(install_hook);

    if let Some(device_id_hash) = config
        .cloud
        .tags
        .get("device_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        puller = puller.with_device_id_hash(device_id_hash.to_string());
    } else if let Some(device_id_hash) = cli_config::read_client_device_id() {
        puller = puller.with_device_id_hash(device_id_hash);
    }

    let outcome = puller
        .refresh_now()
        .await
        .context("bootstrap bundle fetch failed")?;
    if !bundle_dir.join("manifest.json").exists() {
        let cache_path = bundle_dir.join("registry_bundle_cache.json");
        anyhow::bail!(
            "Cloud bootstrap check completed (checked={}, downloaded={}) but no runtime bundle was installed at {}.\n\
             The cloud endpoint likely returned a registry cache payload (cache-only) instead of an installable channel-2 bundle.\n\
             For first-time bootstrap, /v1/edge/bundle/current must return a payload with `manifest` + `assets` so edge can materialize {}/manifest.json.\n\
             Registry cache path: {}",
            outcome.checked,
            outcome.downloaded,
            bundle_dir.display(),
            bundle_dir.display(),
            cache_path.display()
        );
    }

    if !quiet {
        if let Some(version) = outcome.version.as_deref() {
            style::success(&format!("Bootstrap bundle ready: {version}"));
        } else {
            style::success("Bootstrap bundle ready.");
        }
    }

    Ok(())
}

fn parse_fixed_hex_32(value: &str, field: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = value.trim();
    let bytes = hex::decode(trimmed).map_err(|_| anyhow::anyhow!("{field} must be hex-encoded"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "{field} must decode to exactly 32 bytes, got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn parse_optional_fixed_hex_32(
    value: Option<&str>,
    field: &str,
) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(raw) = value.map(str::trim) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    parse_fixed_hex_32(raw, field).map(Some)
}

fn install_runtime_bundle_files(
    bundle_dir: &Path,
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(bundle_dir)
        .with_context(|| format!("failed creating {}", bundle_dir.display()))?;

    for (relative_path, bytes) in assets {
        let rel = Path::new(relative_path.as_str());
        if rel.is_absolute()
            || rel
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            anyhow::bail!("bundle asset path is not safe: {relative_path}");
        }

        let full_path = bundle_dir.join(rel);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::write(&full_path, bytes)
            .with_context(|| format!("failed writing {}", full_path.display()))?;
    }

    let manifest_path = bundle_dir.join("manifest.json");
    std::fs::write(&manifest_path, manifest_bytes)
        .with_context(|| format!("failed writing {}", manifest_path.display()))?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::proxy_test_hooks::{self, ProxyBehavior, ProxyCall};
    use super::*;
    use std::collections::VecDeque;
    use std::env;

    struct HookGuard;

    impl Drop for HookGuard {
        fn drop(&mut self) {
            proxy_test_hooks::reset();
        }
    }

    fn install_hooks(behavior: ProxyBehavior) -> HookGuard {
        proxy_test_hooks::install(behavior);
        HookGuard
    }

    fn with_temp_home<T>(f: impl FnOnce(&tempfile::TempDir) -> T + std::panic::UnwindSafe) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let soth_home = temp.path().join(".soth");
        let bundle_dir = soth_home.join("bundle");
        std::fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        std::fs::write(bundle_dir.join("manifest.json"), "{}").expect("write bundle marker");
        let old_home = env::var_os("HOME");
        let old_soth_home = env::var_os("SOTH_HOME_DIR");
        unsafe {
            env::set_var("HOME", temp.path());
            env::set_var("SOTH_HOME_DIR", &soth_home);
        }
        let result = std::panic::catch_unwind(|| f(&temp));
        match old_home {
            Some(value) => unsafe { env::set_var("HOME", value) },
            None => unsafe { env::remove_var("HOME") },
        }
        match old_soth_home {
            Some(value) => unsafe { env::set_var("SOTH_HOME_DIR", value) },
            None => unsafe { env::remove_var("SOTH_HOME_DIR") },
        }
        drop(guard);
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn build_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    fn write_config_with_ca(root: &tempfile::TempDir) -> PathBuf {
        let cert_dir = root.path().join("certs");
        std::fs::create_dir_all(&cert_dir).expect("cert dir");
        let cert_path = cert_dir.join("soth-mitm-ca.pem");
        let key_path = cert_dir.join("soth-mitm-ca-key.pem");

        // Generate a real self-signed CA cert so fingerprint checks work.
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=soth-test-ca",
                "-keyout",
            ])
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("openssl must be available");
        assert!(status.success(), "openssl cert generation failed");

        let mut cfg = crate::cli_config::SothConfig::default();
        cfg.forward_proxy.ca.cert_path = cert_path.display().to_string();
        cfg.forward_proxy.ca.key_path = key_path.display().to_string();
        let config_path = root.path().join("soth.yaml");
        crate::cli_config::write_config(&config_path, &cfg).expect("write config");
        config_path
    }

    #[test]
    fn start_forwards_allow_daemon_child_fallback_flag() {
        with_temp_home(|_| {
            let _hooks = install_hooks(ProxyBehavior::default());
            let rt = build_runtime();
            rt.block_on(run_start_command(
                StartArgs {
                    port: Some(18080),
                    config: None,
                    quiet: true,
                    foreground: false,
                    daemon_child: false,
                    historian_child: false,
                    classify_daemon_child: false,
                    no_autostart: true,
                    allow_daemon_child_fallback: true,
                },
                None,
            ))
            .expect("start should succeed via hook");

            let calls = proxy_test_hooks::calls();
            assert_eq!(calls.len(), 1);
            match &calls[0] {
                ProxyCall::Start {
                    no_autostart,
                    allow_daemon_child_fallback,
                    ..
                } => {
                    assert!(*no_autostart);
                    assert!(*allow_daemon_child_fallback);
                }
                other => panic!("unexpected call: {other:?}"),
            }
        });
    }

    #[test]
    fn up_rolls_back_when_on_fails() {
        with_temp_home(|temp| {
            let config_path = write_config_with_ca(temp);
            let behavior = ProxyBehavior {
                start_results: VecDeque::from([Ok(())]),
                on_results: VecDeque::from([Err("enable failed".to_string())]),
                stop_results: VecDeque::from([Ok(())]),
                ..Default::default()
            };
            let _hooks = install_hooks(behavior);

            let rt = build_runtime();
            let err = rt
                .block_on(run_up_command(
                    UpArgs {
                        port: Some(18081),
                        config: Some(config_path.clone()),
                        token: None,
                        endpoint: None,
                        ingest_endpoint: None,
                        machine_name: None,
                        quiet: true,
                        foreground: false,
                        no_autostart: false,
                        allow_daemon_child_fallback: false,
                        skip_hooks: true,
                        repair_hooks: false,
                    },
                    None,
                ))
                .expect_err("up should fail when on fails");

            let text = format!("{err:#}");
            assert!(text.contains("Daemon was stopped as rollback."));

            let calls = proxy_test_hooks::calls();
            assert_eq!(calls.len(), 3);
            assert!(matches!(calls[0], ProxyCall::Start { .. }));
            assert!(matches!(calls[1], ProxyCall::On { .. }));
            assert!(matches!(calls[2], ProxyCall::Stop));
        });
    }

    #[test]
    fn up_reports_when_on_and_rollback_stop_fail() {
        with_temp_home(|temp| {
            let config_path = write_config_with_ca(temp);
            let behavior = ProxyBehavior {
                start_results: VecDeque::from([Ok(())]),
                on_results: VecDeque::from([Err("enable failed".to_string())]),
                stop_results: VecDeque::from([Err("stop failed".to_string())]),
                ..Default::default()
            };
            let _hooks = install_hooks(behavior);

            let rt = build_runtime();
            let err = rt
                .block_on(run_up_command(
                    UpArgs {
                        port: Some(18082),
                        config: Some(config_path),
                        token: None,
                        endpoint: None,
                        ingest_endpoint: None,
                        machine_name: None,
                        quiet: true,
                        foreground: false,
                        no_autostart: false,
                        allow_daemon_child_fallback: false,
                        skip_hooks: true,
                        repair_hooks: false,
                    },
                    None,
                ))
                .expect_err("up should fail");

            let text = format!("{err:#}");
            assert!(text.contains("rollback stop failed"));

            let calls = proxy_test_hooks::calls();
            assert_eq!(calls.len(), 3);
            assert!(matches!(calls[0], ProxyCall::Start { .. }));
            assert!(matches!(calls[1], ProxyCall::On { .. }));
            assert!(matches!(calls[2], ProxyCall::Stop));
        });
    }

    #[test]
    fn up_success_does_not_stop() {
        with_temp_home(|temp| {
            let config_path = write_config_with_ca(temp);
            let behavior = ProxyBehavior {
                start_results: VecDeque::from([Ok(())]),
                on_results: VecDeque::from([Ok(())]),
                ..Default::default()
            };
            let _hooks = install_hooks(behavior);

            let rt = build_runtime();
            rt.block_on(run_up_command(
                UpArgs {
                    port: Some(18083),
                    config: Some(config_path),
                    token: None,
                    endpoint: None,
                    ingest_endpoint: None,
                    machine_name: None,
                    quiet: true,
                    foreground: false,
                    no_autostart: false,
                    allow_daemon_child_fallback: false,
                    skip_hooks: true,
                    repair_hooks: false,
                },
                None,
            ))
            .expect("up should succeed");

            let calls = proxy_test_hooks::calls();
            assert_eq!(calls.len(), 2);
            assert!(matches!(calls[0], ProxyCall::Start { .. }));
            assert!(matches!(calls[1], ProxyCall::On { .. }));
        });
    }

    #[test]
    fn down_calls_stop_then_off() {
        with_temp_home(|_| {
            let behavior = ProxyBehavior {
                stop_results: VecDeque::from([Ok(())]),
                off_results: VecDeque::from([Ok(())]),
                ..Default::default()
            };
            let _hooks = install_hooks(behavior);

            let rt = build_runtime();
            rt.block_on(run_command(Commands::Down, None))
                .expect("down should succeed");

            let calls = proxy_test_hooks::calls();
            assert_eq!(calls, vec![ProxyCall::Stop, ProxyCall::Off]);
        });
    }

    #[test]
    fn start_fails_fast_when_bundle_missing_and_cloud_not_configured() {
        with_temp_home(|temp| {
            let _hooks = install_hooks(ProxyBehavior::default());
            let soth_home = temp.path().join(".soth");
            std::fs::remove_file(soth_home.join("bundle").join("manifest.json"))
                .expect("remove test bundle marker");
            let config_path = write_config_with_ca(temp);

            let rt = build_runtime();
            let error = rt
                .block_on(run_start_command(
                    StartArgs {
                        port: Some(18084),
                        config: Some(config_path),
                        quiet: true,
                        foreground: false,
                        daemon_child: false,
                        historian_child: false,
                        classify_daemon_child: false,
                        no_autostart: true,
                        allow_daemon_child_fallback: false,
                    },
                    None,
                ))
                .expect_err("missing bundle should fail before proxy start");

            assert!(format!("{error:#}").contains("bootstrap cannot fetch bundle"));
            assert!(proxy_test_hooks::calls().is_empty());
        });
    }
}

#[cfg(test)]
mod sweep_tests {
    //! Integration tests for `run_sweep` — the soth-code hook
    //! auto-installer's pure orchestration core.  Drives the
    //! orchestrator against tmpdir-rooted state files with an
    //! injected install function so tests cover the
    //! idempotency / drift-triggers-repair / failure-tolerance
    //! contracts without actually mutating any settings.json
    //! on the test host.

    use super::{run_sweep, SweepResult};
    use soth_code::install::DetectedAgent;
    use soth_code::state::InstalledHostState;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn detected(agent: &'static str, dir: &Path, already: bool) -> DetectedAgent {
        DetectedAgent {
            agent,
            settings_path: dir.join(format!("{agent}-settings")),
            already_installed: already,
        }
    }

    /// Always-success install fn that records every call so
    /// the test can assert which agents were actually installed.
    fn recording_install(
        calls: &Mutex<Vec<(String, PathBuf)>>,
    ) -> impl Fn(&str, &Path) -> anyhow::Result<()> + '_ {
        move |agent: &str, path: &Path| {
            calls
                .lock()
                .unwrap()
                .push((agent.to_string(), path.to_path_buf()));
            Ok(())
        }
    }

    #[test]
    fn fresh_sweep_installs_every_detected_agent_and_writes_state() {
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin = PathBuf::from("/usr/local/bin/soth");
        let detected_agents = vec![
            detected("claude_code", tmp.path(), false),
            detected("cursor", tmp.path(), false),
        ];
        let calls = Mutex::new(Vec::new());
        let install_fn = recording_install(&calls);

        let result = run_sweep(&detected_agents, &state_path, &bin, false, install_fn);

        assert_eq!(result.installed, vec!["claude_code", "cursor"]);
        assert!(result.skipped.is_empty());
        assert!(result.repaired.is_empty());
        assert!(result.failed.is_empty());
        // Both agents got their install_fn invoked.
        assert_eq!(calls.lock().unwrap().len(), 2);

        // State file persisted both records.
        let state = InstalledHostState::load(&state_path).unwrap();
        assert!(state.hooks.contains_key("claude_code"));
        assert!(state.hooks.contains_key("cursor"));
        assert_eq!(state.hooks["claude_code"].binary_path, bin);
    }

    #[test]
    fn rerun_with_already_installed_skips_install_call() {
        // Pin the idempotency contract: when `already_installed
        // == true` (the agent's settings file has the soth-
        // managed marker) AND state shows the same binary path,
        // re-running shouldn't call install_fn again.
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin = PathBuf::from("/usr/local/bin/soth");
        let detected_agents = vec![detected("claude_code", tmp.path(), false)];

        // First sweep: installs.
        let calls1 = Mutex::new(Vec::new());
        let _ = run_sweep(
            &detected_agents,
            &state_path,
            &bin,
            false,
            recording_install(&calls1),
        );
        assert_eq!(calls1.lock().unwrap().len(), 1);

        // Second sweep: detection now reports already_installed
        // = true (the marker is in the settings file post-
        // install).  install_fn must NOT be called again.
        let detected2 = vec![detected("claude_code", tmp.path(), true)];
        let calls2 = Mutex::new(Vec::new());
        let result = run_sweep(
            &detected2,
            &state_path,
            &bin,
            false,
            recording_install(&calls2),
        );
        assert!(
            calls2.lock().unwrap().is_empty(),
            "install must be skipped on re-run"
        );
        assert_eq!(result.skipped, vec!["claude_code"]);
        assert!(result.installed.is_empty());
        assert!(result.repaired.is_empty());
    }

    #[test]
    fn binary_drift_triggers_repair_install_even_when_already_installed() {
        // Pin the drift contract: when state shows binary
        // path = X but current_binary = Y (operator brewed a
        // new soth that landed at a different prefix), the
        // sweep MUST re-install so the hook entries get
        // re-pointed.  Otherwise hooks keep dispatching to
        // the old (possibly missing) binary.
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin_old = PathBuf::from("/old/path/soth");
        let bin_new = PathBuf::from("/new/path/soth");
        let detected_agents = vec![detected("claude_code", tmp.path(), true)];

        // Bootstrap state with the OLD binary path.
        let calls1 = Mutex::new(Vec::new());
        let _ = run_sweep(
            &detected_agents,
            &state_path,
            &bin_old,
            false,
            recording_install(&calls1),
        );

        // Now run with NEW binary path (drift).  Even though
        // already_installed is still true, the sweep must
        // detect the drift and re-install.
        let calls2 = Mutex::new(Vec::new());
        let result = run_sweep(
            &detected_agents,
            &state_path,
            &bin_new,
            false,
            recording_install(&calls2),
        );
        assert_eq!(
            calls2.lock().unwrap().len(),
            1,
            "drift must trigger re-install"
        );
        assert_eq!(result.repaired, vec!["claude_code"]);
        assert!(result.installed.is_empty());

        // State updated to the new binary path so the next
        // sweep treats this as no-drift.
        let state = InstalledHostState::load(&state_path).unwrap();
        assert_eq!(state.hooks["claude_code"].binary_path, bin_new);
    }

    #[test]
    fn force_repair_reinstalls_even_without_drift() {
        // `--repair-hooks` forces re-install regardless of
        // state — operators use it after edge-case binary
        // moves the drift detector misses (e.g. symlink
        // changes that resolve to the same canonical path).
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin = PathBuf::from("/usr/local/bin/soth");
        let detected_agents = vec![detected("claude_code", tmp.path(), true)];

        let calls1 = Mutex::new(Vec::new());
        let _ = run_sweep(
            &detected_agents,
            &state_path,
            &bin,
            false,
            recording_install(&calls1),
        );

        // Same binary, same already_installed=true — but
        // force_repair=true forces an install_fn call.
        let calls2 = Mutex::new(Vec::new());
        let result = run_sweep(
            &detected_agents,
            &state_path,
            &bin,
            true, // force_repair
            recording_install(&calls2),
        );
        assert_eq!(calls2.lock().unwrap().len(), 1);
        assert_eq!(result.installed, vec!["claude_code"]);
        // No drift, so it shows as `installed` not `repaired`.
        // Drift specifically means "binary moved" — force_repair
        // is a separate signal.
    }

    #[test]
    fn per_agent_failure_does_not_abort_sweep() {
        // Pin the failure-tolerance contract: when one
        // agent's install_fn returns an error, the sweep
        // continues with the remaining agents.  Operators
        // need to know about the failures (result.failed) but
        // shouldn't have a single broken agent prevent the
        // others from being governed.
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin = PathBuf::from("/usr/local/bin/soth");
        let detected_agents = vec![
            detected("claude_code", tmp.path(), false),
            detected("cursor", tmp.path(), false),
            detected("openai_codex", tmp.path(), false),
        ];

        let install_fn = |agent: &str, _path: &Path| -> anyhow::Result<()> {
            if agent == "cursor" {
                anyhow::bail!("simulated cursor install failure")
            }
            Ok(())
        };

        let result = run_sweep(&detected_agents, &state_path, &bin, false, install_fn);

        assert_eq!(result.installed, vec!["claude_code", "openai_codex"]);
        assert_eq!(result.failed.len(), 1);
        assert_eq!(result.failed[0].0, "cursor");
        assert!(
            result.failed[0]
                .1
                .contains("simulated cursor install failure"),
            "failure detail must surface the underlying error"
        );

        // State persisted only the successful installs.
        let state = InstalledHostState::load(&state_path).unwrap();
        assert!(state.hooks.contains_key("claude_code"));
        assert!(state.hooks.contains_key("openai_codex"));
        assert!(!state.hooks.contains_key("cursor"));
    }

    #[test]
    fn install_one_dispatches_every_canonical_agent_name() {
        // Pin the contract: every canonical agent name that
        // `detect_installable_agents` may emit MUST have a
        // matching arm in `install_one`'s dispatch.  A mismatch
        // there silently fails real installs at runtime — the
        // sweep_tests above all use a mocked install_fn so a
        // stale `install_one` arm wasn't catchable from those.
        // This test exercises the real `install_one` against
        // throwaway paths; we don't care if the underlying
        // installer succeeds (it usually fails because the
        // tmp path doesn't have a real settings.json), only
        // that the dispatch DOESN'T return the
        // "auto-install does not support agent: X" bail.
        let tmp = TempDir::new().unwrap();
        let canonical_names = [
            "claude_code",
            "cursor",
            "openai_codex",
            "gemini_cli",
            "windsurf",
            "pi_agent",
            "opencode",
        ];
        for agent in canonical_names {
            let path = tmp.path().join(format!("{agent}-fake-settings"));
            let result = super::install_one(agent, &path);
            if let Err(e) = &result {
                let msg = format!("{e:#}");
                assert!(
                    !msg.contains("auto-install does not support agent"),
                    "install_one returned dispatch-miss bail for {agent}: {msg}\n\
                     This means detect_installable_agents emits {agent} but install_one\n\
                     has no matching arm — the sweep would silently skip this agent at\n\
                     runtime."
                );
            }
        }
    }

    #[test]
    fn empty_detection_produces_empty_result() {
        // Host with no AI coding agents — sweep is a no-op.
        // No calls to install_fn, no state file mutation,
        // empty result partitions.
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("installed.json");
        let bin = PathBuf::from("/usr/local/bin/soth");

        let calls = Mutex::new(Vec::new());
        let result = run_sweep(&[], &state_path, &bin, false, recording_install(&calls));

        assert_eq!(result, SweepResult::default());
        assert!(calls.lock().unwrap().is_empty());
    }
}
