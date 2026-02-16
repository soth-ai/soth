//! Start sensor runtime command

use super::daemon;
use crate::cli_config;
use crate::commands::cloud_hooks;
use crate::commands::enforcement;
use crate::commands::proxy::retention;
use crate::commands::proxy::system;
use crate::style;
use console::Term;
use owo_colors::OwoColorize;
use soth_collector::CollectorRuntime;
use soth_core::config::{HostFilterMode, ObserveCollectorConfig, SothConfig};
use soth_core::event_logger::default_event_log_write_path;
use soth_core::EventLogger;
use soth_proxy::metrics;
use soth_proxy::transport::hudsucker_proxy;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{info, warn};

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
const MIN_NOFILE_SOFT_LIMIT: u64 = 8192;
const WARN_NOFILE_SOFT_LIMIT: u64 = 2048;
const FD_MONITOR_INTERVAL: Duration = Duration::from_secs(10);
const FD_MONITOR_WARN_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(unix)]
fn ensure_fd_budget() {
    unsafe {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) != 0 {
            warn!("Failed to read RLIMIT_NOFILE");
            return;
        }

        let initial_soft = limits.rlim_cur as u64;
        let hard = limits.rlim_max as u64;

        if initial_soft < MIN_NOFILE_SOFT_LIMIT {
            let target = std::cmp::min(hard, MIN_NOFILE_SOFT_LIMIT) as libc::rlim_t;
            if target > limits.rlim_cur {
                limits.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limits) == 0 {
                    info!(
                        previous_soft = initial_soft,
                        new_soft = target as u64,
                        hard_limit = hard,
                        "Raised RLIMIT_NOFILE soft limit"
                    );
                } else {
                    warn!(
                        soft_limit = initial_soft,
                        hard_limit = hard,
                        "Failed to raise RLIMIT_NOFILE soft limit"
                    );
                }
            }
        }

        let mut verify = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut verify) == 0 {
            let effective_soft = verify.rlim_cur as u64;
            let effective_hard = verify.rlim_max as u64;
            if effective_soft < WARN_NOFILE_SOFT_LIMIT {
                warn!(
                    soft_limit = effective_soft,
                    hard_limit = effective_hard,
                    "Low RLIMIT_NOFILE soft limit may cause EMFILE under bursty traffic"
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn ensure_fd_budget() {}

/// Run the start command
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    daemon_child: bool,
) -> anyhow::Result<()> {
    if !foreground && !daemon_child {
        return daemon::run_start_daemon(port, config_path, quiet).await;
    }

    ensure_fd_budget();

    let mut config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    cloud_hooks::apply_cached_controls(&mut config)?;

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
        style::error("CA certificate not found. Run: soth runtime setup-ca");
        return Ok(());
    }

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    // Best-effort startup refresh: try cloud registry fetch first, then fall back to cache.
    cloud_hooks::refresh_registry_bundle_on_start(&config).await;

    // Auto-enable system proxy when soth starts without extra console noise.
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

    let runtime_line = format!(
        "soth sensor | {} | {} | {}",
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
    let api_line = format!(
        "off (run `soth dev api start --port {}` to enable)",
        config.dashboard.port
    );
    let ui_line = "off (run `soth dev ui start` to enable)".to_string();
    let system_proxy_line = format!("enabled @ 127.0.0.1:{}", proxy_config.port);

    // Initialize Prometheus metrics
    let _ = metrics::init_metrics();

    if !quiet {
        print_logo_banner();
        render_startup_panel(
            &runtime_line,
            &rules_line,
            &intercept_summary,
            "eval $(soth runtime env)",
            &compact_path(&ca_cert_path),
            &api_line,
            &ui_line,
            &event_logging_status,
            &system_proxy_line,
        );
        println!(
            "{} {}  |  AI/MCP → {}  |  Other → {}  |  {}",
            style::CHECK.green(),
            "Ready".bold(),
            "MITM".cyan(),
            "blind tunnel".dimmed(),
            "Ctrl+C to stop".dimmed()
        );
        println!();
    }

    run_forward_proxy(
        &config,
        proxy_config,
        ca_cert_path,
        ca_key_path,
        event_logger,
        quiet,
    )
    .await
}

fn render_startup_panel(
    runtime: &str,
    rules: &str,
    intercept: &str,
    env_line: &str,
    ca_path: &str,
    api_line: &str,
    ui_line: &str,
    events_line: &str,
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
    print_panel_kv_row(inner_width, "API", api_line);
    print_panel_kv_row(inner_width, "UI", ui_line);
    print_panel_kv_row(inner_width, "Events", events_line);
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
    fd_monitor_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    fd_monitor_task: Option<JoinHandle<()>>,
    retention_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    retention_task: Option<JoinHandle<()>>,
    cloud_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    cloud_task: Option<JoinHandle<()>>,
    collector_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    collector_task: Option<JoinHandle<()>>,
}

/// Run the sensor transport.
async fn run_forward_proxy(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    event_logger: Option<EventLogger>,
    quiet: bool,
) -> anyhow::Result<()> {
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
    let mut retention_shutdown_tx = runtime.retention_shutdown_tx;
    let mut retention_task = runtime.retention_task;
    let mut fd_monitor_shutdown_tx = runtime.fd_monitor_shutdown_tx;
    let mut fd_monitor_task = runtime.fd_monitor_task;
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
    shutdown_fd_monitor_runtime(
        &mut fd_monitor_shutdown_tx,
        &mut fd_monitor_task,
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

    let mut retention_shutdown_tx = None;
    let mut retention_task = None;
    if let Some(runtime) = retention::spawn_retention_runtime(config, event_db_path.clone()) {
        retention_shutdown_tx = Some(runtime.shutdown_tx);
        retention_task = Some(runtime.task);
    }

    let mut fd_monitor_shutdown_tx = None;
    let mut fd_monitor_task = None;
    if let Some(runtime) = spawn_fd_monitor_runtime() {
        fd_monitor_shutdown_tx = Some(runtime.shutdown_tx);
        fd_monitor_task = Some(runtime.task);
    }

    let mut cloud_shutdown_tx = None;
    let mut cloud_task = None;
    if let Some(runtime) = cloud_hooks::spawn_cloud_pull_runtime(config, event_db_path.clone()) {
        cloud_shutdown_tx = Some(runtime.shutdown_tx);
        cloud_task = Some(runtime.task);
    }

    let mut collector_shutdown_tx = None;
    let mut collector_task = None;
    apply_collector_env_overrides(&config.observe.collector);
    if let Some(ref logger) = event_logger {
        if let Some(CollectorRuntime { shutdown_tx, task }) = soth_collector::spawn_from_env(
            logger.clone(),
            config.observe.event_tags.clone(),
            config.exchange_v2.clone(),
        ) {
            collector_shutdown_tx = Some(shutdown_tx);
            collector_task = Some(task);
        }
    }

    let shutdown_event_logger = event_logger.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let oisp_registry_cache_path = resolve_registry_bundle_cache_path(config);
    let exchange_v2_config = config.exchange_v2.clone();
    let handle = tokio::spawn(async move {
        hudsucker_proxy::start_proxy_with_shutdown(
            proxy_config,
            &ca_cert_path,
            &ca_key_path,
            async move {
                shutdown_rx.await.ok();
            },
            event_logger,
            Some(enforcer),
            Some(observe_config),
            Some(oisp_registry_cache_path),
            Some(exchange_v2_config),
        )
        .await
        .map_err(|error| anyhow::anyhow!("Proxy error: {}", error))
    });

    Ok(ProxyRuntime {
        shutdown_tx,
        proxy_task: handle,
        event_logger: shutdown_event_logger,
        fd_monitor_shutdown_tx,
        fd_monitor_task,
        retention_shutdown_tx,
        retention_task,
        cloud_shutdown_tx,
        cloud_task,
        collector_shutdown_tx,
        collector_task,
    })
}

struct FdMonitorRuntime {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

#[cfg(unix)]
fn spawn_fd_monitor_runtime() -> Option<FdMonitorRuntime> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(FD_MONITOR_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_warn_at: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    if let Some((open_fds, soft_limit, hard_limit)) = current_fd_snapshot() {
                        metrics::set_runtime_fd_snapshot(open_fds, soft_limit, hard_limit);
                        if soft_limit > 0 {
                            let utilization = (open_fds as f64) / (soft_limit as f64);
                            if utilization >= 0.9 {
                                let should_warn = last_warn_at
                                    .map(|last| last.elapsed() >= FD_MONITOR_WARN_INTERVAL)
                                    .unwrap_or(true);
                                if should_warn {
                                    last_warn_at = Some(Instant::now());
                                    warn!(
                                        open_fds = open_fds,
                                        soft_limit = soft_limit,
                                        hard_limit = hard_limit,
                                        utilization_pct = format!("{:.1}", utilization * 100.0),
                                        "High file-descriptor utilization detected"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Some(FdMonitorRuntime { shutdown_tx, task })
}

#[cfg(not(unix))]
fn spawn_fd_monitor_runtime() -> Option<FdMonitorRuntime> {
    None
}

#[cfg(unix)]
fn current_fd_snapshot() -> Option<(u64, u64, u64)> {
    let (soft_limit, hard_limit) = current_nofile_limits()?;
    let open_fds = current_open_fd_count()?;
    Some((open_fds, soft_limit, hard_limit))
}

#[cfg(unix)]
fn current_nofile_limits() -> Option<(u64, u64)> {
    unsafe {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) != 0 {
            return None;
        }
        Some((limits.rlim_cur as u64, limits.rlim_max as u64))
    }
}

#[cfg(unix)]
fn current_open_fd_count() -> Option<u64> {
    for path in ["/proc/self/fd", "/dev/fd"] {
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(Result::ok).count() as u64;
            if count > 0 {
                return Some(count);
            }
        }
    }
    None
}

fn set_env_if_present<T: ToString>(key: &str, value: Option<T>) {
    if let Some(value) = value {
        std::env::set_var(key, value.to_string());
    }
}

fn apply_collector_env_overrides(collector: &ObserveCollectorConfig) {
    if !collector.enabled {
        return;
    }

    std::env::set_var("SOTH_COLLECTOR_ENABLED", "true");

    if !collector.sources.is_empty() {
        let sources = collector
            .sources
            .iter()
            .map(|source| {
                cli_config::expand_tilde(&source.path)
                    .to_string_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(",");
        std::env::set_var("SOTH_COLLECTOR_SOURCES", sources);
    }

    set_env_if_present(
        "SOTH_COLLECTOR_POLL_INTERVAL_SECS",
        collector.poll_interval_secs,
    );
    set_env_if_present(
        "SOTH_COLLECTOR_MAX_READ_BYTES",
        collector.max_read_bytes_per_source,
    );
    set_env_if_present("SOTH_COLLECTOR_MAX_LINE_BYTES", collector.max_line_bytes);
    set_env_if_present(
        "SOTH_COLLECTOR_STATE_PATH",
        collector
            .state_path
            .as_ref()
            .map(cli_config::expand_tilde)
            .map(|path| path.to_string_lossy().to_string()),
    );
    set_env_if_present("SOTH_COLLECTOR_AGENT", collector.agent_name.clone());
    set_env_if_present(
        "SOTH_COLLECTOR_EVENT_SOURCE",
        collector.event_source.clone(),
    );
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

async fn shutdown_fd_monitor_runtime(
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
                tracing::warn!("FD monitor task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("FD monitor task shutdown timed out; aborted task.");
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
