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
