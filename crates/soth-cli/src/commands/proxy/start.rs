//! Start soth proxy command

use crate::cli_config;
use crate::commands::cloud_hooks;
use crate::commands::enforcement;
use crate::commands::proxy::retention;
use crate::commands::proxy::system;
use crate::commands::proxy::StartUiMode;
use crate::commands::tui::{self, TuiArgs};
use crate::logging;
use crate::style;
use anyhow::Context;
use console::Term;
use owo_colors::OwoColorize;
use soth_collector::CollectorRuntime;
use soth_core::config::{HostFilterMode, SothConfig};
use soth_core::event_logger::default_event_log_write_path;
use soth_core::EventLogger;
use soth_dashboard::server::DashboardServer;
use soth_dashboard::DashboardState;
use soth_proxy::metrics;
use soth_proxy::transport::hudsucker_proxy;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::task::JoinHandle;

const SOTH_PROXY_ASCII: &[&str] = &[
    "  █████████     ███████    ███████████ █████   █████",
    " ███░░░░░███  ███░░░░░███ ░█░░░███░░░█░░███   ░░███ ",
    "░███    ░░░  ███     ░░███░   ░███  ░  ░███    ░███ ",
    "░░█████████ ░███      ░███    ░███     ░███████████ ",
    " ░░░░░░░░███░███      ░███    ░███     ░███░░░░░███ ",
    " ███    ░███░░███     ███     ░███     ░███    ░███ ",
    "░░█████████  ░░░███████░      █████    █████   █████",
    " ░░░░░░░░░     ░░░░░░░       ░░░░░    ░░░░░   ░░░░░ ",
];
const SOTH_ACCENT: (u8, u8, u8) = (0xD9, 0x77, 0x57);
const SOTH_MUTED: (u8, u8, u8) = (0x9F, 0x9F, 0x9F);
const SOTH_TEXT: (u8, u8, u8) = (0xFF, 0xFF, 0xFF);
const DEFAULT_DASHBOARD_UI_DIR: &str = "dashboard";
const DEFAULT_DASHBOARD_UI_URL: &str = "http://localhost:3002";
const DEFAULT_DASHBOARD_UI_LOG_FILE: &str = "dashboard-ui-dev.log";

/// Run the start command
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    ui_mode: StartUiMode,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    cloud_hooks::apply_cached_controls(&mut config)?;
    let resolved_ui = resolve_ui_mode(ui_mode, &config, quiet);
    if matches!(ui_mode, StartUiMode::Tui) && matches!(resolved_ui, StartUiMode::Logs) && !quiet {
        style::warning("Dashboard API is disabled in config; falling back to log mode.");
    }

    // Override port if specified
    let mut proxy_config = config.forward_proxy.clone();
    if let Some(p) = port {
        proxy_config.port = p;
    }

    // Ensure proxy is enabled
    proxy_config.enabled = true;

    // Hudsucker proxy requires cert and key paths.
    let ca_cert_path = cli_config::expand_tilde(&proxy_config.ca.cert_path);
    let ca_key_path = cli_config::expand_tilde(&proxy_config.ca.key_path);

    // Show startup spinner only in non-quiet mode.
    let spinner = if quiet {
        None
    } else {
        Some(style::spinner("Loading CA certificate..."))
    };

    // Check CA exists
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        if let Some(pb) = spinner {
            pb.finish_and_clear();
        }
        style::error("CA certificate not found. Run: soth proxy setup-ca");
        return Ok(());
    }

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    // Best-effort startup refresh: try cloud registry fetch first, then fall back to cache.
    cloud_hooks::refresh_registry_bundle_on_start(&config).await;

    // Auto-enable system proxy when soth proxy starts without extra console noise.
    system::enable_quiet(Some(proxy_config.port)).await?;

    let intercept_count = proxy_config.hosts.intercept_domain_count();
    let mut intercept_hosts: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for host in proxy_config
        .hosts
        .ai_inference
        .iter()
        .chain(proxy_config.hosts.mcp.iter())
        .chain(proxy_config.hosts.agent_apps.iter())
    {
        if seen.insert(host.clone()) {
            intercept_hosts.push(host.clone());
        }
    }

    let intercept_summary = match proxy_config.hosts.mode {
        HostFilterMode::Discovery => {
            let seed_preview = summarize_hosts(&intercept_hosts, 2);
            if intercept_count > 0 {
                format!("all non-local hosts (discovery), seeds: {seed_preview}")
            } else {
                "all non-local hosts (discovery mode)".to_string()
            }
        }
        HostFilterMode::Selective => summarize_hosts(&intercept_hosts, 3),
    };

    let inline_threshold = config.observe.storage.inline_threshold_bytes;
    let (event_logger, event_logging_status) =
        match EventLogger::with_default_path_from_runtime_config(
            inline_threshold,
            &config.crypto_identity,
        ) {
            Ok(logger) => {
                let display = compact_path(logger.path());
                (Some(logger), display)
            }
            Err(_) => (None, "disabled".to_string()),
        };

    let dashboard_display = if config.dashboard.enabled {
        format!("http://localhost:{}", config.dashboard.port)
    } else {
        "disabled".to_string()
    };
    let runtime_line = format!(
        "soth proxy | {} | {} | {}",
        proxy_config.registry_mode,
        proxy_config.hosts.mode,
        proxy_config.socket_addr()
    );
    let rules_line = format!(
        "AI:{}  MCP:{}  Agent:{}  Total:{}",
        proxy_config.hosts.ai_inference.len(),
        proxy_config.hosts.mcp.len(),
        proxy_config.hosts.agent_apps.len(),
        intercept_count
    );
    let dashboard_line = format!("{dashboard_display}   Events {event_logging_status}");
    let system_proxy_line = format!("enabled @ 127.0.0.1:{}", proxy_config.port);

    // Initialize Prometheus metrics
    let _ = metrics::init_metrics();

    if !quiet {
        print_logo_banner();
        render_startup_panel(
            &runtime_line,
            &rules_line,
            &intercept_summary,
            "eval $(soth proxy env)",
            &compact_path(&ca_cert_path),
            &dashboard_line,
            &system_proxy_line,
        );

        if matches!(resolved_ui, StartUiMode::Logs) {
            // Ready message (log mode)
            println!(
                "{} {}  |  AI/MCP → {}  |  Other → {}  |  {}",
                style::CHECK.green(),
                "Ready".bold(),
                "MITM".cyan(),
                "blind tunnel".dimmed(),
                "Ctrl+C to stop".dimmed()
            );
            println!();
        } else {
            // TUI mode handoff message
            println!(
                "{} {}  |  {}",
                style::CHECK.green(),
                "Ready checks passed".bold(),
                "Launching TUI…".cyan()
            );
            println!();
        }
    }

    let dashboard_ui_process = if config.dashboard.enabled {
        let dashboard_ui_dir = PathBuf::from(DEFAULT_DASHBOARD_UI_DIR);
        match spawn_dashboard_ui_process(
            &dashboard_ui_dir,
            config.dashboard.port,
            DEFAULT_DASHBOARD_UI_URL,
            quiet,
        ) {
            Ok(child) => Some(child),
            Err(error) => {
                if !quiet {
                    style::warning(&format!(
                        "Failed to start dashboard UI dev server: {}",
                        error
                    ));
                    style::info("Continuing with proxy only.");
                }
                None
            }
        }
    } else {
        None
    };

    match resolved_ui {
        StartUiMode::Tui => {
            if !quiet && matches!(ui_mode, StartUiMode::Auto) {
                style::info("Launching interactive TUI (auto mode).");
            }
            run_forward_proxy_with_tui(
                &config,
                proxy_config,
                ca_cert_path,
                ca_key_path,
                event_logger,
                dashboard_ui_process,
                quiet,
            )
            .await
        }
        StartUiMode::Logs | StartUiMode::Auto => {
            run_forward_proxy(
                &config,
                proxy_config,
                ca_cert_path,
                ca_key_path,
                event_logger,
                dashboard_ui_process,
                quiet,
            )
            .await
        }
    }
}

fn resolve_ui_mode(requested: StartUiMode, config: &SothConfig, quiet: bool) -> StartUiMode {
    match requested {
        StartUiMode::Auto => {
            if quiet {
                StartUiMode::Logs
            } else if config.dashboard.enabled && terminal_supports_tui() {
                StartUiMode::Tui
            } else {
                StartUiMode::Logs
            }
        }
        StartUiMode::Tui => {
            if config.dashboard.enabled {
                StartUiMode::Tui
            } else {
                StartUiMode::Logs
            }
        }
        StartUiMode::Logs => StartUiMode::Logs,
    }
}

fn terminal_supports_tui() -> bool {
    if !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal() {
        return false;
    }

    if std::env::var_os("CI").is_some() {
        return false;
    }

    let term = std::env::var("TERM").unwrap_or_default();
    if term.eq_ignore_ascii_case("dumb") || term.is_empty() {
        return false;
    }

    true
}

fn render_startup_panel(
    runtime: &str,
    rules: &str,
    intercept: &str,
    env_line: &str,
    ca_path: &str,
    dashboard_line: &str,
    system_proxy_line: &str,
) {
    let term_width = Term::stdout().size().1 as usize;
    let total_width = term_width.saturating_sub(2).clamp(78, 110);
    let inner_width = total_width.saturating_sub(2);

    print_panel_top(inner_width, &format!("SOTH Proxy ─ {runtime}"));
    print_panel_kv_row(inner_width, "Rules", rules);
    print_panel_kv_row(inner_width, "Intercept", intercept);
    print_panel_kv_row(inner_width, "Env", env_line);
    print_panel_kv_row(inner_width, "CA", ca_path);
    print_panel_kv_row(inner_width, "Dashboard", dashboard_line);
    print_panel_kv_row(inner_width, "System", system_proxy_line);

    print_panel_bottom(inner_width);
    println!();
}

fn print_logo_banner() {
    println!();
    for icon in SOTH_PROXY_ASCII {
        let icon_colored = icon
            .truecolor(SOTH_ACCENT.0, SOTH_ACCENT.1, SOTH_ACCENT.2)
            .bold()
            .to_string();
        println!("  {}", icon_colored);
    }
}

fn print_panel_top(inner_width: usize, title: &str) {
    let middle_width = inner_width;
    let prefix = "─ ";
    let mut title_text = format!("{prefix}{title} ");
    if display_width(&title_text) > middle_width {
        title_text = truncate_display(&title_text, middle_width);
    }
    let fill = middle_width.saturating_sub(display_width(&title_text));
    println!("╭{}{}╮", title_text, "─".repeat(fill));
}

fn print_panel_bottom(inner_width: usize) {
    println!("╰{}╯", "─".repeat(inner_width));
}

fn print_panel_kv_row(inner_width: usize, label: &str, value: &str) {
    let label_field = format!("{label:<10}");
    let label_width = display_width(&label_field);
    let value_width = inner_width.saturating_sub(label_width);
    let value = truncate_display(value, value_width);
    let pad = inner_width
        .saturating_sub(label_width)
        .saturating_sub(display_width(&value));

    println!(
        "│{}{}{}│",
        label_field
            .truecolor(SOTH_MUTED.0, SOTH_MUTED.1, SOTH_MUTED.2)
            .bold(),
        value.truecolor(SOTH_TEXT.0, SOTH_TEXT.1, SOTH_TEXT.2),
        " ".repeat(pad)
    );
}

fn truncate_display(value: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }

    if display_width(value) <= max_width {
        return value.to_string();
    }

    if max_width == 1 {
        return "…".to_string();
    }

    let mut out = String::new();
    for ch in value.chars() {
        if out.chars().count() + 1 >= max_width {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

fn display_width(value: &str) -> usize {
    value.chars().count()
}

fn summarize_hosts(hosts: &[String], take: usize) -> String {
    if hosts.is_empty() {
        return "none".to_string();
    }

    let mut preview = hosts
        .iter()
        .take(take)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if hosts.len() > take {
        preview.push_str(&format!(", +{}", hosts.len() - take));
    }
    preview
}

fn compact_path(path: &std::path::Path) -> String {
    let full = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home = home.display().to_string();
        if full.starts_with(&home) {
            return format!("~{}", &full[home.len()..]);
        }
    }
    full
}

fn resolve_registry_bundle_cache_path(config: &SothConfig) -> PathBuf {
    if let Some(config_cache_path) = config.cloud.cache_path.as_ref() {
        let expanded = cli_config::expand_tilde(config_cache_path);
        if let Some(parent) = expanded.parent() {
            return parent.join("registry_bundle_cache.json");
        }
    }

    dirs::home_dir()
        .map(|home| home.join(".soth").join("registry_bundle_cache.json"))
        .unwrap_or_else(|| PathBuf::from(".soth/registry_bundle_cache.json"))
}

struct ProxyRuntime {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    proxy_task: JoinHandle<anyhow::Result<()>>,
    event_logger: Option<EventLogger>,
    dashboard_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    dashboard_task: Option<JoinHandle<()>>,
    retention_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    retention_task: Option<JoinHandle<()>>,
    cloud_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    cloud_task: Option<JoinHandle<()>>,
    collector_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    collector_task: Option<JoinHandle<()>>,
}

/// Run the soth proxy transport.
async fn run_forward_proxy(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    event_logger: Option<EventLogger>,
    dashboard_ui_process: Option<Child>,
    quiet: bool,
) -> anyhow::Result<()> {
    logging::set_log_output_paused(false);
    let runtime = match spawn_proxy_runtime(
        config,
        proxy_config,
        ca_cert_path,
        ca_key_path,
        event_logger,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            disable_system_proxy_after_run(quiet).await;
            return Err(error);
        }
    };
    let mut dashboard_shutdown_tx = runtime.dashboard_shutdown_tx;
    let mut dashboard_task = runtime.dashboard_task;
    let mut retention_shutdown_tx = runtime.retention_shutdown_tx;
    let mut retention_task = runtime.retention_task;
    let mut cloud_shutdown_tx = runtime.cloud_shutdown_tx;
    let mut cloud_task = runtime.cloud_task;
    let mut collector_shutdown_tx = runtime.collector_shutdown_tx;
    let mut collector_task = runtime.collector_task;
    let mut event_logger = runtime.event_logger;
    let shutdown_tx = runtime.shutdown_tx;
    let proxy_task = runtime.proxy_task;
    let shutdown_timeout = runtime_shutdown_timeout(config);

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        if !quiet {
            println!();
            style::warning("Initiating graceful shutdown...");
        }
        let _ = shutdown_tx.send(());
    });

    let result = match proxy_task.await {
        Ok(runtime_result) => runtime_result,
        Err(error) => Err(anyhow::anyhow!("proxy runtime task join failed: {}", error)),
    };

    shutdown_collector_runtime(
        &mut collector_shutdown_tx,
        &mut collector_task,
        shutdown_timeout,
    )
    .await;
    flush_local_event_buffers(&mut event_logger, shutdown_timeout, quiet).await;
    shutdown_cloud_runtime(&mut cloud_shutdown_tx, &mut cloud_task, shutdown_timeout).await;
    shutdown_retention_runtime(
        &mut retention_shutdown_tx,
        &mut retention_task,
        shutdown_timeout,
    )
    .await;
    shutdown_dashboard_runtime(
        &mut dashboard_shutdown_tx,
        &mut dashboard_task,
        quiet,
        shutdown_timeout,
    )
    .await;

    if let Some(mut child) = dashboard_ui_process {
        stop_dashboard_ui_process(&mut child);
    }
    disable_system_proxy_after_run(quiet).await;

    match result {
        Ok(()) => {
            if !quiet {
                style::success("Proxy stopped.");
            }
            Ok(())
        }
        Err(e) => {
            style::error(&format!("Proxy error: {}", e));
            Err(anyhow::anyhow!("Proxy error: {}", e))
        }
    }
}

async fn run_forward_proxy_with_tui(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    event_logger: Option<EventLogger>,
    dashboard_ui_process: Option<Child>,
    quiet: bool,
) -> anyhow::Result<()> {
    let dashboard_port = config.dashboard.port;
    let runtime = match spawn_proxy_runtime(
        config,
        proxy_config,
        ca_cert_path,
        ca_key_path,
        event_logger,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            disable_system_proxy_after_run(quiet).await;
            return Err(error);
        }
    };
    let mut shutdown_tx = Some(runtime.shutdown_tx);
    let mut proxy_task = runtime.proxy_task;
    let mut dashboard_shutdown_tx = runtime.dashboard_shutdown_tx;
    let mut dashboard_task = runtime.dashboard_task;
    let mut retention_shutdown_tx = runtime.retention_shutdown_tx;
    let mut retention_task = runtime.retention_task;
    let mut cloud_shutdown_tx = runtime.cloud_shutdown_tx;
    let mut cloud_task = runtime.cloud_task;
    let mut collector_shutdown_tx = runtime.collector_shutdown_tx;
    let mut collector_task = runtime.collector_task;
    let mut event_logger = runtime.event_logger;
    let shutdown_timeout = runtime_shutdown_timeout(config);

    // Pause stdout logs before waiting + entering alternate screen to avoid overlap.
    logging::set_log_output_paused(true);

    if !wait_for_dashboard_ready(dashboard_port, Duration::from_secs(25)).await && !quiet {
        style::warning("Dashboard API not ready yet; opening TUI and retrying in background.");
    }

    let tui_result = tui::run(TuiArgs {
        api_url: format!("http://127.0.0.1:{dashboard_port}"),
        refresh: 2,
    })
    .await;
    logging::set_log_output_paused(false);

    match tui_result {
        Ok(()) => {
            if !quiet {
                style::info("TUI closed. Proxy is still running (log mode). Press Ctrl+C to stop.");
            }
        }
        Err(error) => {
            if !quiet {
                style::warning(&format!(
                    "TUI exited with error: {}. Continuing in log mode; press Ctrl+C to stop.",
                    error
                ));
            }
        }
    }

    // Keep proxy alive after TUI exits; stop only on Ctrl+C or runtime termination.
    let result = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            if let Some(tx) = shutdown_tx.take() {
                let _ = tx.send(());
            }
            proxy_task.await.context("proxy runtime task join failed")?
        }
        join_result = &mut proxy_task => {
            join_result.context("proxy runtime task join failed")?
        }
    };

    shutdown_collector_runtime(
        &mut collector_shutdown_tx,
        &mut collector_task,
        shutdown_timeout,
    )
    .await;
    flush_local_event_buffers(&mut event_logger, shutdown_timeout, quiet).await;
    shutdown_cloud_runtime(&mut cloud_shutdown_tx, &mut cloud_task, shutdown_timeout).await;
    shutdown_retention_runtime(
        &mut retention_shutdown_tx,
        &mut retention_task,
        shutdown_timeout,
    )
    .await;
    shutdown_dashboard_runtime(
        &mut dashboard_shutdown_tx,
        &mut dashboard_task,
        quiet,
        shutdown_timeout,
    )
    .await;

    if let Some(mut child) = dashboard_ui_process {
        stop_dashboard_ui_process(&mut child);
    }
    disable_system_proxy_after_run(quiet).await;

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            style::error(&format!("Proxy error: {}", e));
            Err(anyhow::anyhow!("Proxy error: {}", e))
        }
    }
}

fn spawn_proxy_runtime(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    event_logger: Option<EventLogger>,
) -> anyhow::Result<ProxyRuntime> {
    let enforcer = enforcement::build_proxy_enforcer(config)?;
    let observe_config = config.observe.clone();
    let event_db_path = event_logger
        .as_ref()
        .map(|logger| logger.path().clone())
        .or_else(|| default_event_log_write_path().ok());
    let _policy_reload_task = enforcer
        .policy_engine()
        .and_then(|engine| enforcement::spawn_policy_hot_reload(config, engine));

    let dashboard_state = if let Some(path) = event_db_path.as_deref() {
        DashboardState::new_with_rollup_warm_start(path)
    } else {
        DashboardState::new()
    };

    let mut dashboard_shutdown_tx = None;
    let mut dashboard_task = None;
    if config.dashboard.enabled {
        let state_clone = dashboard_state.clone();
        let dashboard_port = config.dashboard.port;
        let (dashboard_tx, dashboard_rx) = tokio::sync::oneshot::channel::<()>();
        dashboard_shutdown_tx = Some(dashboard_tx);
        dashboard_task = Some(tokio::spawn(async move {
            let server = DashboardServer::new(state_clone, dashboard_port).with_event_store();
            if let Err(e) = server
                .run_with_shutdown(async move {
                    let _ = dashboard_rx.await;
                })
                .await
            {
                tracing::error!("Dashboard server error: {}", e);
            }
        }));
    }

    let mut retention_shutdown_tx = None;
    let mut retention_task = None;
    if let Some(runtime) = retention::spawn_retention_runtime(config, event_db_path.clone()) {
        retention_shutdown_tx = Some(runtime.shutdown_tx);
        retention_task = Some(runtime.task);
    }

    let mut cloud_shutdown_tx = None;
    let mut cloud_task = None;
    if let Some(runtime) = cloud_hooks::spawn_cloud_pull_runtime(config, event_db_path.clone()) {
        cloud_shutdown_tx = Some(runtime.shutdown_tx);
        cloud_task = Some(runtime.task);
    }

    let mut collector_shutdown_tx = None;
    let mut collector_task = None;
    if let Some(ref logger) = event_logger {
        if let Some(CollectorRuntime { shutdown_tx, task }) =
            soth_collector::spawn_from_env(logger.clone(), config.observe.event_tags.clone())
        {
            collector_shutdown_tx = Some(shutdown_tx);
            collector_task = Some(task);
        }
    }

    let shutdown_event_logger = event_logger.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let oisp_registry_cache_path = resolve_registry_bundle_cache_path(config);
    let handle = tokio::spawn(async move {
        hudsucker_proxy::start_proxy_with_shutdown(
            proxy_config,
            &ca_cert_path,
            &ca_key_path,
            async move {
                shutdown_rx.await.ok();
            },
            Some(dashboard_state),
            event_logger,
            Some(enforcer),
            Some(observe_config),
            Some(oisp_registry_cache_path),
        )
        .await
        .map_err(|error| anyhow::anyhow!("Proxy error: {}", error))
    });

    Ok(ProxyRuntime {
        shutdown_tx,
        proxy_task: handle,
        event_logger: shutdown_event_logger,
        dashboard_shutdown_tx,
        dashboard_task,
        retention_shutdown_tx,
        retention_task,
        cloud_shutdown_tx,
        cloud_task,
        collector_shutdown_tx,
        collector_task,
    })
}

async fn wait_for_dashboard_ready(port: u16, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .no_proxy()
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };

    let url = format!("http://127.0.0.1:{port}/readyz");
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    false
}

fn spawn_dashboard_ui_process(
    dashboard_ui_dir: &std::path::Path,
    dashboard_port: u16,
    dashboard_ui_url: &str,
    quiet: bool,
) -> anyhow::Result<Child> {
    if !dashboard_ui_dir.exists() {
        anyhow::bail!(
            "Dashboard UI directory not found: {}",
            dashboard_ui_dir.display()
        );
    }

    if !dashboard_ui_dir.join("package.json").exists() {
        anyhow::bail!(
            "No package.json found in dashboard UI directory: {}",
            dashboard_ui_dir.display()
        );
    }

    let (stdout_stdio, stderr_stdio, log_path) = match open_dashboard_ui_log_stdio() {
        Ok((stdout, stderr, path)) => (stdout, stderr, Some(path)),
        Err(error) => {
            if !quiet {
                style::warning(&format!(
                    "Could not open dashboard UI log file: {}. Suppressing UI output.",
                    error
                ));
            }
            (Stdio::null(), Stdio::null(), None)
        }
    };

    let mut cmd = Command::new(npm_executable());
    cmd.arg("run")
        .arg("dev")
        .current_dir(dashboard_ui_dir)
        .stdin(Stdio::null())
        .stdout(stdout_stdio)
        .stderr(stderr_stdio)
        .env(
            "NEXT_PUBLIC_SOTH_API_BASE",
            format!("http://localhost:{}/api", dashboard_port),
        )
        .env(
            "NEXT_PUBLIC_SOTH_WS_BASE",
            format!("ws://localhost:{}", dashboard_port),
        );
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd
        .spawn()
        .with_context(|| "failed to spawn dashboard UI dev server (`npm run dev`)")?;

    if !quiet {
        if let Some(log_path) = log_path {
            style::info(&format!(
                "Dashboard UI dev server: {} (PID {}, dir: {}, logs: {})",
                dashboard_ui_url,
                child.id(),
                dashboard_ui_dir.display(),
                log_path.display(),
            ));
        } else {
            style::info(&format!(
                "Dashboard UI dev server: {} (PID {}, dir: {})",
                dashboard_ui_url,
                child.id(),
                dashboard_ui_dir.display(),
            ));
        }
    }

    Ok(child)
}

fn open_dashboard_ui_log_stdio() -> anyhow::Result<(Stdio, Stdio, PathBuf)> {
    let log_path = dashboard_ui_log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create dashboard UI log directory: {}",
                parent.display()
            )
        })?;
    }

    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| {
            format!(
                "failed to open dashboard UI log file: {}",
                log_path.display()
            )
        })?;

    let stderr_file = stdout_file.try_clone().with_context(|| {
        format!(
            "failed to clone dashboard UI log file: {}",
            log_path.display()
        )
    })?;

    Ok((Stdio::from(stdout_file), Stdio::from(stderr_file), log_path))
}

fn dashboard_ui_log_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        return home
            .join(".soth")
            .join("logs")
            .join(DEFAULT_DASHBOARD_UI_LOG_FILE);
    }

    PathBuf::from(DEFAULT_DASHBOARD_UI_LOG_FILE)
}

fn stop_dashboard_ui_process(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(error) => {
            style::warning(&format!(
                "Failed to check dashboard UI process status: {}",
                error
            ));
            return;
        }
    }

    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.id());
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(&process_group)
            .status();
        for _ in 0..10 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(120)),
                Err(_) => break,
            }
        }
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(&process_group)
            .status();
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
    }

    if let Err(error) = child.kill() {
        style::warning(&format!("Failed to stop dashboard UI process: {}", error));
        return;
    }

    if let Err(error) = child.wait() {
        style::warning(&format!(
            "Failed waiting for dashboard UI process shutdown: {}",
            error
        ));
    }
}

async fn shutdown_dashboard_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    dashboard_task: &mut Option<JoinHandle<()>>,
    quiet: bool,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut task) = dashboard_task.take() {
        match tokio::time::timeout(timeout_budget, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if !quiet {
                    style::warning(&format!("Dashboard task join error: {}", error));
                }
            }
            Err(_) => {
                task.abort();
                if !quiet {
                    style::warning("Dashboard server shutdown timed out; aborted task.");
                }
            }
        }
    }
}

async fn shutdown_retention_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Retention task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Retention task shutdown timed out; aborted task.");
            }
        }
    }
}

async fn shutdown_cloud_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Cloud pull task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Cloud pull task shutdown timed out; aborted task.");
            }
        }
    }
}

async fn shutdown_collector_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Collector task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Collector task shutdown timed out; aborted task.");
            }
        }
    }
}

fn runtime_shutdown_timeout(config: &SothConfig) -> Duration {
    config
        .server
        .graceful_shutdown
        .max(Duration::from_secs(2))
        .min(Duration::from_secs(20))
}

async fn flush_local_event_buffers(
    event_logger: &mut Option<EventLogger>,
    timeout_budget: Duration,
    quiet: bool,
) {
    let Some(logger) = event_logger.take() else {
        return;
    };

    let flush_logger = logger.clone();
    match tokio::time::timeout(
        timeout_budget,
        tokio::task::spawn_blocking(move || flush_logger.flush()),
    )
    .await
    {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            if !quiet {
                style::warning(&format!("Failed to flush local event logger: {}", error));
            }
        }
        Ok(Err(error)) => {
            if !quiet {
                style::warning(&format!("Event logger flush task join error: {}", error));
            }
        }
        Err(_) => {
            if !quiet {
                style::warning("Timed out flushing local event logger before shutdown.");
            }
        }
    }

    let close_logger = logger.clone();
    match tokio::time::timeout(
        timeout_budget,
        tokio::task::spawn_blocking(move || close_logger.close()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if !quiet {
                style::warning(&format!("Event logger close task join error: {}", error));
            }
        }
        Err(_) => {
            if !quiet {
                style::warning("Timed out closing local event logger; continuing shutdown.");
            }
        }
    }
}

fn npm_executable() -> &'static str {
    if cfg!(target_os = "windows") {
        "npm.cmd"
    } else {
        "npm"
    }
}

async fn disable_system_proxy_after_run(quiet: bool) {
    if let Err(error) = system::disable_quiet().await {
        if !quiet {
            style::warning(&format!(
                "Failed to disable system proxy automatically: {}",
                error
            ));
        }
    }
}
