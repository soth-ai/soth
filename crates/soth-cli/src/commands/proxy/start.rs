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
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::warn;

/// Run the start command
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    intercept_all: bool,
    intercept_all_for: Option<u64>,
    daemon_child: bool,
    no_autostart: bool,
) -> anyhow::Result<()> {
    if !foreground && !daemon_child {
        return daemon::run_start_daemon(
            port,
            config_path,
            quiet,
            intercept_all,
            intercept_all_for,
            no_autostart,
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
        anyhow::bail!("CA certificate not found");
    }

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    // Best-effort startup refresh: in daemon-child mode, do not block proxy bind/readiness.
    if daemon_child {
        let startup_refresh_config = config.clone();
        tokio::spawn(async move {
            cloud_hooks::refresh_registry_bundle_on_start(&startup_refresh_config).await;
        });
    } else {
        cloud_hooks::refresh_registry_bundle_on_start(&config).await;
    }

    // Fail-open: proxy runtime should still start even if system proxy toggling fails.
    if let Err(error) = system::enable_quiet(Some(proxy_config.port)).await {
        warn!(
            error = %error,
            port = proxy_config.port,
            "Failed to auto-enable system proxy; continuing with sensor runtime only"
        );
        if !quiet {
            style::warning(&format!(
                "Could not auto-enable system proxy (continuing fail-open): {error}"
            ));
            style::info("Use `soth on` after resolving network/permission issues.");
        }
    }

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
    apply_collector_env_overrides(config, &config.observe.collector);
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

#[derive(Debug, Clone)]
struct RegistryCollectorSource {
    agent: String,
    path: String,
    parser: Option<String>,
}

fn set_env_if_present<T: ToString>(key: &str, value: Option<T>) {
    if let Some(value) = value {
        std::env::set_var(key, value.to_string());
    }
}

fn parse_registry_collector_sources(bundle: &serde_json::Value) -> Vec<RegistryCollectorSource> {
    let sources = bundle
        .get("collector")
        .and_then(|value| value.get("sources"))
        .or_else(|| bundle.get("collector_sources"))
        .and_then(serde_json::Value::as_array);
    let Some(sources) = sources else {
        return Vec::new();
    };

    let mut parsed = Vec::new();
    let mut seen = BTreeSet::new();
    for source in sources {
        let Some(source_obj) = source.as_object() else {
            continue;
        };
        let Some(agent) = source_obj
            .get("agent")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(path) = source_obj
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let parser = source_obj
            .get("parser")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let key = format!("{agent}|{path}");
        if !seen.insert(key) {
            continue;
        }
        parsed.push(RegistryCollectorSource {
            agent: agent.to_string(),
            path: path.to_string(),
            parser,
        });
    }

    parsed
}

fn load_registry_collector_sources(config: &SothConfig) -> Vec<RegistryCollectorSource> {
    let cache_path = resolve_registry_bundle_cache_path(config);
    let cached = match soth_sync::cache::load_registry_bundle_cache(cache_path.as_path()) {
        Ok(Some(cached)) => cached,
        Ok(None) => return Vec::new(),
        Err(error) => {
            warn!(
                cache = %cache_path.display(),
                error = %error,
                "Failed to read registry cache for collector source hints"
            );
            return Vec::new();
        }
    };
    parse_registry_collector_sources(&cached.bundle)
}

fn apply_collector_env_overrides(config: &SothConfig, collector: &ObserveCollectorConfig) {
    let registry_sources = load_registry_collector_sources(config);
    if !collector.enabled {
        if !registry_sources.is_empty() {
            warn!(
                sources = registry_sources.len(),
                "Registry collector sources available but observe.collector.enabled=false; collector remains disabled"
            );
        }
        return;
    }

    std::env::set_var("SOTH_COLLECTOR_ENABLED", "true");
    std::env::set_var(
        "SOTH_COLLECTOR_AUTO_DISCOVER",
        collector.auto_discover_sources.to_string(),
    );
    std::env::set_var(
        "SOTH_COLLECTOR_FRONTLOAD_ON_START",
        collector.frontload_on_start.to_string(),
    );
    std::env::set_var(
        "SOTH_COLLECTOR_FRONTLOAD_FORCE_FIRST_RUN",
        collector.frontload_force_first_run.to_string(),
    );
    std::env::set_var(
        "SOTH_COLLECTOR_FRONTLOAD_RESET_OFFSETS_ON_START",
        collector.frontload_reset_offsets_on_start.to_string(),
    );

    let mut source_paths = BTreeSet::new();
    let mut structured_sources = collector
        .sources
        .iter()
        .map(|source| {
            let path = cli_config::expand_tilde(&source.path)
                .to_string_lossy()
                .to_string();
            source_paths.insert(path.clone());
            serde_json::json!({
                "name": source.name,
                "path": path,
                "parser": source.parser,
            })
        })
        .collect::<Vec<_>>();

    for source in &registry_sources {
        source_paths.insert(source.path.clone());
        structured_sources.push(serde_json::json!({
            "name": format!("registry:{}", source.agent),
            "path": source.path,
            "parser": source.parser.clone().unwrap_or_else(|| "jsonl".to_string()),
            "agent": source.agent,
            "server_name": source.agent,
            "tags": {
                "collector.discovery": "registry_bundle",
                "collector.agent": source.agent,
            },
        }));
    }

    if !structured_sources.is_empty() {
        std::env::set_var(
            "SOTH_COLLECTOR_SOURCES",
            source_paths.into_iter().collect::<Vec<_>>().join(","),
        );
        if let Ok(raw) = serde_json::to_string(&structured_sources) {
            std::env::set_var("SOTH_COLLECTOR_SOURCES_JSON", raw);
        }
    }
    if !collector.sqlite_sources.is_empty() {
        let sqlite_sources = collector
            .sqlite_sources
            .iter()
            .map(|source| {
                serde_json::json!({
                    "name": source.name,
                    "db_path": cli_config::expand_tilde(&source.db_path).to_string_lossy().to_string(),
                    "server_name": source.server_name,
                    "provider": source.provider,
                    "model": source.model,
                    "tags": source.tags,
                    "queries": source.queries.iter().map(|query| serde_json::json!({
                        "file_type": query.file_type,
                        "sql": query.sql,
                        "incremental_field": query.incremental_field,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        if let Ok(raw) = serde_json::to_string(&sqlite_sources) {
            std::env::set_var("SOTH_COLLECTOR_SQLITE_SOURCES", raw);
        }
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
        "SOTH_COLLECTOR_FRONTLOAD_MAX_CYCLES",
        collector.frontload_max_cycles,
    );
    set_env_if_present(
        "SOTH_COLLECTOR_FRONTLOAD_MAX_READ_BYTES",
        collector.frontload_max_read_bytes_per_source,
    );
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
