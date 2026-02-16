//! Start sensor runtime command

use super::daemon;
use super::start_fd::{ensure_fd_budget, spawn_fd_monitor_runtime};
use super::start_shutdown::{
    disable_system_proxy_after_run, flush_local_event_buffers,
    is_expected_shutdown_transport_error, runtime_shutdown_timeout, shutdown_cloud_runtime,
    shutdown_collector_runtime, shutdown_fd_monitor_runtime, shutdown_retention_runtime,
};
use super::start_ui::{compact_path, print_logo_banner, render_startup_panel};
use crate::cli_config;
use crate::commands::cloud_hooks;
use crate::commands::enforcement;
use crate::commands::proxy::retention;
use crate::commands::proxy::system;
use crate::style;
use owo_colors::OwoColorize;
use soth_collector::CollectorRuntime;
use soth_core::config::{HostFilterMode, ObserveCollectorConfig, SothConfig};
use soth_core::event_logger::default_event_log_write_path;
use soth_core::EventLogger;
use soth_proxy::metrics;
use soth_proxy::transport::proxy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// Run the start command
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    intercept_all: bool,
    intercept_all_for: Option<u64>,
    daemon_child: bool,
) -> anyhow::Result<()> {
    if !foreground && !daemon_child {
        return daemon::run_start_daemon(
            port,
            config_path,
            quiet,
            intercept_all,
            intercept_all_for,
        )
        .await;
    }

    ensure_fd_budget();

    let mut config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    cloud_hooks::apply_cached_controls(&mut config)?;

    // Override port if specified
    let mut proxy_config = config.forward_proxy.clone();
    if let Some(p) = port {
        proxy_config.port = p;
    }
    let debug_intercept_all_for = intercept_all_for.map(Duration::from_secs);
    let debug_intercept_all_enabled = intercept_all || debug_intercept_all_for.is_some();

    // Ensure proxy is enabled
    proxy_config.enabled = true;

    // Forward proxy requires cert and key paths.
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

    let intercept_summary = match proxy_config.hosts.mode {
        HostFilterMode::Discovery => "all non-local hosts (discovery mode)".to_string(),
        HostFilterMode::Selective => "bundle-classified hosts (registry cache)".to_string(),
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
    let rules_line = "source=cloud bundle (ai/mcp/agent classification)".to_string();
    #[cfg(feature = "local-debug")]
    let api_line = format!(
        "off (run `soth dev api start --port {}` to enable)",
        config.dashboard.port
    );
    #[cfg(not(feature = "local-debug"))]
    let api_line = "unavailable in this build (enable `local-debug`)".to_string();

    #[cfg(feature = "local-debug")]
    let ui_line = "off (run `soth dev ui start` to enable)".to_string();
    #[cfg(not(feature = "local-debug"))]
    let ui_line = "unavailable in this build (enable `local-debug`)".to_string();
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
        if debug_intercept_all_enabled {
            match debug_intercept_all_for {
                Some(window) => style::warning(&format!(
                    "Debug intercept-all enabled for {}s (non-local hosts)",
                    window.as_secs()
                )),
                None => style::warning("Debug intercept-all enabled (non-local hosts)"),
            }
        }
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
        debug_intercept_all_enabled,
        debug_intercept_all_for,
    )
    .await
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
    debug_intercept_all_enabled: bool,
    debug_intercept_all_for: Option<Duration>,
) -> anyhow::Result<()> {
    let runtime = match spawn_proxy_runtime(
        config,
        proxy_config,
        ca_cert_path,
        ca_key_path,
        event_logger,
        debug_intercept_all_enabled,
        debug_intercept_all_for,
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
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let run_started_at = Instant::now();

    let shutdown_requested_signal = shutdown_requested.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        shutdown_requested_signal.store(true, Ordering::SeqCst);
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
        Err(error)
            if is_expected_shutdown_transport_error(&error)
                && (shutdown_requested.load(Ordering::SeqCst)
                    || run_started_at.elapsed() >= Duration::from_secs(2)) =>
        {
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
    debug_intercept_all_enabled: bool,
    debug_intercept_all_for: Option<Duration>,
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
        proxy::start_proxy_with_shutdown(
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
            debug_intercept_all_enabled,
            debug_intercept_all_for,
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
