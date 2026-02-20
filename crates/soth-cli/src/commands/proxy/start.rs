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
use tracing::{info, warn};

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
    if config.cloud.enabled {
        let _ = cli_config::sync_client_device_id(&mut config, None)?;
    }
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

    apply_collector_env_overrides(config, &config.observe.collector);

    let mut cloud_shutdown_tx = None;
    let mut cloud_task = None;
    if let Some(runtime) = cloud_hooks::spawn_cloud_pull_runtime(config, event_db_path.clone()) {
        cloud_shutdown_tx = Some(runtime.shutdown_tx);
        cloud_task = Some(runtime.task);
    }

    let mut collector_shutdown_tx = None;
    let mut collector_task = None;
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

#[derive(Debug, Clone)]
struct RegistryCollectorSqliteQuery {
    file_type: String,
    sql: String,
    incremental_field: Option<String>,
}

#[derive(Debug, Clone)]
struct RegistryCollectorSqliteSource {
    agent: String,
    db_path: String,
    queries: Vec<RegistryCollectorSqliteQuery>,
    tags: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct RegistryCollectorHints {
    file_sources: Vec<RegistryCollectorSource>,
    sqlite_sources: Vec<RegistryCollectorSqliteSource>,
    upload_endpoint: Option<String>,
}

fn set_env_if_present<T: ToString>(key: &str, value: Option<T>) {
    if let Some(value) = value {
        std::env::set_var(key, value.to_string());
    }
}

fn parse_registry_collector_hints(bundle: &serde_json::Value) -> RegistryCollectorHints {
    let mut file_sources = Vec::new();
    let mut file_seen = BTreeSet::new();
    let mut sqlite_sources = Vec::new();
    let mut sections = vec![bundle];
    if let Some(data) = bundle.get("data") {
        sections.push(data);
    }
    let mut upload_endpoint = None;

    for section in sections {
        parse_registry_collector_sources_from_local_sources_v2(
            section.get("collector"),
            &mut file_sources,
            &mut file_seen,
            &mut sqlite_sources,
            &mut upload_endpoint,
        );
        if upload_endpoint.is_none() {
            upload_endpoint = section
                .get("localDataSources")
                .and_then(|value| value.get("upload_endpoint"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }
        parse_registry_collector_sources_from_array(
            section
                .get("collector")
                .and_then(|value| value.get("sources"))
                .and_then(serde_json::Value::as_array),
            &mut file_sources,
            &mut file_seen,
        );
        parse_registry_collector_sources_from_array(
            section
                .get("collector_sources")
                .and_then(serde_json::Value::as_array),
            &mut file_sources,
            &mut file_seen,
        );
        parse_registry_collector_sources_from_local_artifacts(
            section
                .get("local_artifacts")
                .and_then(serde_json::Value::as_array),
            &mut file_sources,
            &mut file_seen,
            &mut sqlite_sources,
        );
        parse_registry_collector_sources_from_local_data_sources(
            section
                .get("localDataSources")
                .and_then(|value| value.get("sources"))
                .and_then(serde_json::Value::as_array),
            &mut file_sources,
            &mut file_seen,
            &mut sqlite_sources,
        );
    }

    RegistryCollectorHints {
        file_sources,
        sqlite_sources,
        upload_endpoint,
    }
}

fn parse_registry_collector_sources_from_array(
    sources: Option<&Vec<serde_json::Value>>,
    parsed: &mut Vec<RegistryCollectorSource>,
    seen: &mut BTreeSet<String>,
) {
    let Some(sources) = sources else {
        return;
    };
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
        push_registry_collector_source(parsed, seen, agent, path, parser);
    }
}

fn parse_registry_collector_sources_from_local_sources_v2(
    collector: Option<&serde_json::Value>,
    file_sources: &mut Vec<RegistryCollectorSource>,
    file_seen: &mut BTreeSet<String>,
    sqlite_sources: &mut Vec<RegistryCollectorSqliteSource>,
    upload_endpoint: &mut Option<String>,
) {
    let Some(collector_obj) = collector.and_then(serde_json::Value::as_object) else {
        return;
    };
    if collector_obj
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return;
    }

    if upload_endpoint.is_none() {
        *upload_endpoint = collector_obj
            .get("local_ingestion")
            .and_then(serde_json::Value::as_object)
            .and_then(|ingestion| ingestion.get("upload_endpoint"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
    }

    let source_bindings = collector_obj
        .get("local_ingestion")
        .and_then(serde_json::Value::as_object)
        .and_then(|ingestion| ingestion.get("source_bindings"))
        .and_then(serde_json::Value::as_object);

    let Some(sources_obj) = collector_obj
        .get("artifact_catalog")
        .and_then(serde_json::Value::as_object)
        .and_then(|catalog| catalog.get("sources"))
        .and_then(serde_json::Value::as_object)
    else {
        return;
    };

    for (source_name, source_value) in sources_obj {
        let Some(source_obj) = source_value.as_object() else {
            continue;
        };
        if !local_source_binding_enabled(source_bindings, source_name.as_str()) {
            continue;
        }
        let agent = source_obj
            .get("detection_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(source_name.as_str());

        let parser = source_obj
            .get("parser")
            .and_then(serde_json::Value::as_object)
            .and_then(|parser| {
                let enabled = parser
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true);
                if enabled {
                    parser
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                } else {
                    None
                }
            });

        let Some(collectors) = source_obj
            .get("collectors")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };

        for collector_entry in collectors {
            let Some(entry_obj) = collector_entry.as_object() else {
                continue;
            };
            let kind = entry_obj
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            match kind {
                "glob" => {
                    let Some(pattern) = entry_obj
                        .get("pattern")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    let content_type = entry_obj
                        .get("content_type")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim);
                    if !is_supported_registry_collector_glob(pattern, content_type) {
                        continue;
                    }
                    let parser_name = parser.clone().or_else(|| {
                        Some(
                            default_registry_collector_parser_for_glob(pattern, content_type)
                                .to_string(),
                        )
                    });
                    push_registry_collector_source(
                        file_sources,
                        file_seen,
                        agent,
                        pattern,
                        parser_name,
                    );
                }
                "sqlite_query" => {
                    let Some(db_path) = entry_obj
                        .get("db_path")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    let Some(file_type) = entry_obj
                        .get("file_type")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    let Some(sql) = entry_obj
                        .get("sql")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    let incremental_field = entry_obj
                        .get("incremental_field")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string);
                    let mut tags = std::collections::BTreeMap::new();
                    tags.insert(
                        "collector.discovery".to_string(),
                        "registry_bundle".to_string(),
                    );
                    tags.insert("collector.agent".to_string(), agent.to_string());

                    push_registry_sqlite_source(
                        sqlite_sources,
                        RegistryCollectorSqliteSource {
                            agent: agent.to_string(),
                            db_path: db_path.to_string(),
                            queries: vec![RegistryCollectorSqliteQuery {
                                file_type: file_type.to_string(),
                                sql: sql.to_string(),
                                incremental_field,
                            }],
                            tags,
                        },
                    );
                }
                _ => {}
            }
        }
    }
}

fn local_source_binding_enabled(
    source_bindings: Option<&serde_json::Map<String, serde_json::Value>>,
    source_name: &str,
) -> bool {
    source_bindings
        .and_then(|bindings| bindings.get(source_name))
        .and_then(serde_json::Value::as_object)
        .and_then(|binding| binding.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
}

fn parse_registry_collector_sources_from_local_artifacts(
    artifacts: Option<&Vec<serde_json::Value>>,
    file_sources: &mut Vec<RegistryCollectorSource>,
    file_seen: &mut BTreeSet<String>,
    sqlite_sources: &mut Vec<RegistryCollectorSqliteSource>,
) {
    let Some(artifacts) = artifacts else {
        return;
    };
    for artifact in artifacts {
        let Some(obj) = artifact.as_object() else {
            continue;
        };
        let Some(agent) = obj
            .get("slug")
            .or_else(|| obj.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let parser = obj
            .get("parserConfig")
            .and_then(|value| value.get("parserName"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let globs = obj
            .get("collectionConfig")
            .and_then(|value| value.get("globs"))
            .and_then(serde_json::Value::as_array);
        let Some(globs) = globs else {
            continue;
        };
        for glob in globs {
            let Some(pattern) = glob
                .get("pattern")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let content_type = glob
                .get("content_type")
                .and_then(serde_json::Value::as_str)
                .map(str::trim);
            if !is_supported_registry_collector_glob(pattern, content_type) {
                continue;
            }
            let parser = parser.clone().or_else(|| {
                Some(default_registry_collector_parser_for_glob(pattern, content_type).to_string())
            });
            push_registry_collector_source(file_sources, file_seen, agent, pattern, parser);
        }
        for sqlite_source in parse_registry_sqlite_sources_from_collection(
            obj.get("collectionConfig")
                .and_then(|value| value.get("sqlite"))
                .and_then(serde_json::Value::as_array),
            agent,
        ) {
            push_registry_sqlite_source(sqlite_sources, sqlite_source);
        }
    }
}

fn parse_registry_collector_sources_from_local_data_sources(
    sources: Option<&Vec<serde_json::Value>>,
    file_sources: &mut Vec<RegistryCollectorSource>,
    file_seen: &mut BTreeSet<String>,
    sqlite_sources: &mut Vec<RegistryCollectorSqliteSource>,
) {
    let Some(sources) = sources else {
        return;
    };
    for source in sources {
        let Some(source_obj) = source.as_object() else {
            continue;
        };
        if source_obj
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|enabled| !enabled)
        {
            continue;
        }
        let Some(agent) = source_obj
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if let Some(globs) = source_obj
            .get("globs")
            .and_then(serde_json::Value::as_array)
        {
            for glob in globs {
                let Some(pattern) = glob
                    .get("pattern")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                let content_type = glob
                    .get("content_type")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim);
                if !is_supported_registry_collector_glob(pattern, content_type) {
                    continue;
                }
                push_registry_collector_source(
                    file_sources,
                    file_seen,
                    agent,
                    pattern,
                    Some(
                        default_registry_collector_parser_for_glob(pattern, content_type)
                            .to_string(),
                    ),
                );
            }
        }
        for sqlite_source in parse_registry_sqlite_sources_from_collection(
            source_obj
                .get("sqlite")
                .and_then(serde_json::Value::as_array),
            agent,
        ) {
            push_registry_sqlite_source(sqlite_sources, sqlite_source);
        }
    }
}

fn push_registry_collector_source(
    parsed: &mut Vec<RegistryCollectorSource>,
    seen: &mut BTreeSet<String>,
    agent: &str,
    path: &str,
    parser: Option<String>,
) {
    let key = format!("{agent}|{path}");
    if !seen.insert(key) {
        return;
    }
    parsed.push(RegistryCollectorSource {
        agent: agent.to_string(),
        path: path.to_string(),
        parser,
    });
}

fn is_supported_registry_collector_glob(pattern: &str, content_type: Option<&str>) -> bool {
    let normalized_content_type = content_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    if matches!(normalized_content_type.as_deref(), Some("binary")) {
        return false;
    }
    if matches!(normalized_content_type.as_deref(), Some("json" | "text")) {
        return true;
    }

    let lower = pattern.trim().to_ascii_lowercase();
    [
        ".jsonl", ".ndjson", ".json", ".toml", ".md", ".txt", ".log", ".yaml", ".yml", ".xml",
        ".csv", ".pbtxt",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn default_registry_collector_parser_for_glob(
    pattern: &str,
    content_type: Option<&str>,
) -> &'static str {
    let normalized_content_type = content_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if normalized_content_type == "binary" {
        return "text";
    }
    let lower = pattern.trim().to_ascii_lowercase();
    if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") {
        "jsonl"
    } else {
        "text"
    }
}

fn parse_registry_sqlite_sources_from_collection(
    sqlite_entries: Option<&Vec<serde_json::Value>>,
    agent: &str,
) -> Vec<RegistryCollectorSqliteSource> {
    let Some(sqlite_entries) = sqlite_entries else {
        return Vec::new();
    };
    let mut parsed = Vec::new();
    for sqlite in sqlite_entries {
        let Some(db_path) = sqlite
            .get("db_path")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let queries = sqlite
            .get("queries")
            .and_then(serde_json::Value::as_array)
            .map(parse_registry_sqlite_queries)
            .unwrap_or_default();
        if queries.is_empty() {
            continue;
        }
        let mut tags = std::collections::BTreeMap::new();
        tags.insert(
            "collector.discovery".to_string(),
            "registry_bundle".to_string(),
        );
        tags.insert("collector.agent".to_string(), agent.to_string());
        parsed.push(RegistryCollectorSqliteSource {
            agent: agent.to_string(),
            db_path: db_path.to_string(),
            queries,
            tags,
        });
    }
    parsed
}

fn parse_registry_sqlite_queries(
    queries: &Vec<serde_json::Value>,
) -> Vec<RegistryCollectorSqliteQuery> {
    let mut parsed = Vec::new();
    for query in queries {
        let Some(file_type) = query
            .get("file_type")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(sql) = query
            .get("sql")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let incremental_field = query
            .get("incremental_field")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        parsed.push(RegistryCollectorSqliteQuery {
            file_type: file_type.to_string(),
            sql: sql.to_string(),
            incremental_field,
        });
    }
    parsed
}

fn push_registry_sqlite_source(
    parsed: &mut Vec<RegistryCollectorSqliteSource>,
    source: RegistryCollectorSqliteSource,
) {
    if let Some(existing) = parsed.iter_mut().find(|entry| {
        entry.agent.eq_ignore_ascii_case(source.agent.as_str())
            && entry.db_path.eq_ignore_ascii_case(source.db_path.as_str())
    }) {
        for (key, value) in source.tags {
            existing.tags.entry(key).or_insert(value);
        }
        for query in source.queries {
            if !existing.queries.iter().any(|entry| {
                entry.file_type == query.file_type
                    && entry.sql == query.sql
                    && entry.incremental_field == query.incremental_field
            }) {
                existing.queries.push(query);
            }
        }
        return;
    }
    parsed.push(source);
}

fn load_registry_collector_hints(config: &SothConfig) -> RegistryCollectorHints {
    let cache_path = resolve_registry_bundle_cache_path(config);
    let cached = match soth_sync::cache::load_registry_bundle_cache(cache_path.as_path()) {
        Ok(Some(cached)) => cached,
        Ok(None) => return RegistryCollectorHints::default(),
        Err(error) => {
            warn!(
                cache = %cache_path.display(),
                error = %error,
                "Failed to read registry cache for collector source hints"
            );
            return RegistryCollectorHints::default();
        }
    };
    parse_registry_collector_hints(&cached.bundle)
}

fn apply_collector_env_overrides(config: &SothConfig, collector: &ObserveCollectorConfig) {
    let registry_hints = load_registry_collector_hints(config);
    let registry_sources = &registry_hints.file_sources;
    if config.cloud.enabled {
        if let Some(api_key) = config
            .cloud
            .api_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            std::env::set_var("SOTH_COLLECTOR_DIRECT_UPLOAD_ENABLED", "true");
            std::env::set_var(
                "SOTH_COLLECTOR_CLOUD_ENDPOINT",
                config.cloud.endpoint.trim_end_matches('/'),
            );
            std::env::set_var("SOTH_COLLECTOR_CLOUD_API_KEY", api_key);
            let upload_path = registry_hints
                .upload_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("/api/v1/ingest/local-sessions");
            std::env::set_var("SOTH_COLLECTOR_UPLOAD_PATH", upload_path);
            if let Some(device_id) = config
                .cloud
                .tags
                .get("device_id")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                std::env::set_var("SOTH_COLLECTOR_CLIENT_DEVICE_ID", device_id);
            } else {
                std::env::remove_var("SOTH_COLLECTOR_CLIENT_DEVICE_ID");
            }
        } else {
            std::env::set_var("SOTH_COLLECTOR_DIRECT_UPLOAD_ENABLED", "false");
            warn!("Collector direct upload disabled because cloud.api_key is missing");
        }
    } else {
        std::env::set_var("SOTH_COLLECTOR_DIRECT_UPLOAD_ENABLED", "false");
    }
    if config.cloud.frontload_exchange_upload_path.is_none() {
        if let Some(upload_endpoint) = registry_hints.upload_endpoint.as_deref() {
            let trimmed = upload_endpoint.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("/api/v1/exchanges/batch") {
                std::env::set_var("SOTH_CLOUD_FRONTLOAD_UPLOAD_PATH", trimmed);
                info!(
                    upload_endpoint = trimmed,
                    "Applied registry localDataSources upload_endpoint for collector frontload exchange uploads"
                );
            }
        }
    }
    if !collector.enabled {
        if !registry_sources.is_empty() || !registry_hints.sqlite_sources.is_empty() {
            warn!(
                file_sources = registry_sources.len(),
                sqlite_sources = registry_hints.sqlite_sources.len(),
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

    for source in registry_sources {
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
    let mut sqlite_sources = collector
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
    for source in &registry_hints.sqlite_sources {
        sqlite_sources.push(serde_json::json!({
            "name": format!("registry:{}", source.agent),
            "db_path": source.db_path,
            "server_name": source.agent,
            "provider": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "tags": source.tags,
            "queries": source.queries.iter().map(|query| serde_json::json!({
                "file_type": query.file_type,
                "sql": query.sql,
                "incremental_field": query.incremental_field,
            })).collect::<Vec<_>>(),
        }));
    }
    if !sqlite_sources.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::parse_registry_collector_hints;

    #[test]
    fn parse_registry_collector_sources_supports_sensor_local_sources() {
        let bundle = serde_json::json!({
            "data": {
                "local_artifacts": [
                    {
                        "slug": "codex",
                        "parserConfig": { "parserName": "codex" },
                        "collectionConfig": {
                            "globs": [
                                { "pattern": "~/.codex/sessions/**/*.jsonl" },
                                { "pattern": "~/.codex/config.toml" }
                            ]
                        }
                    }
                ],
                "localDataSources": {
                    "sources": [
                        {
                            "name": "codex",
                            "enabled": true,
                            "globs": [
                                { "pattern": "~/.codex/sessions/**/*.jsonl" },
                                { "pattern": "~/.codex/history.jsonl" }
                            ]
                        }
                    ]
                }
            }
        });

        let hints = parse_registry_collector_hints(&bundle);
        assert_eq!(hints.file_sources.len(), 3);
        assert!(hints.file_sources.iter().any(|source| {
            source.agent == "codex" && source.path == "~/.codex/sessions/**/*.jsonl"
        }));
        assert!(hints
            .file_sources
            .iter()
            .any(|source| { source.agent == "codex" && source.path == "~/.codex/history.jsonl" }));
        assert!(hints
            .file_sources
            .iter()
            .any(|source| { source.agent == "codex" && source.path == "~/.codex/config.toml" }));
    }

    #[test]
    fn parse_registry_collector_sources_skips_binary_globs() {
        let bundle = serde_json::json!({
            "data": {
                "localDataSources": {
                    "sources": [
                        {
                            "name": "antigravity",
                            "enabled": true,
                            "globs": [
                                { "pattern": "~/.gemini/antigravity/conversations/*.pb", "content_type": "binary" },
                                { "pattern": "~/.gemini/antigravity/annotations/*.pbtxt", "content_type": "text" }
                            ]
                        }
                    ]
                }
            }
        });

        let hints = parse_registry_collector_hints(&bundle);
        assert_eq!(hints.file_sources.len(), 1);
        assert_eq!(
            hints.file_sources[0].path,
            "~/.gemini/antigravity/annotations/*.pbtxt"
        );
    }

    #[test]
    fn parse_registry_collector_sources_supports_legacy_collector_sources() {
        let bundle = serde_json::json!({
            "collector_sources": [
                { "agent": "claude_code", "path": "~/.claude/projects/*/*.jsonl", "parser": "jsonl" }
            ]
        });

        let hints = parse_registry_collector_hints(&bundle);
        assert_eq!(hints.file_sources.len(), 1);
        assert_eq!(hints.file_sources[0].agent, "claude_code");
        assert_eq!(hints.file_sources[0].path, "~/.claude/projects/*/*.jsonl");
    }

    #[test]
    fn parse_registry_collector_hints_extracts_sqlite_sources() {
        let bundle = serde_json::json!({
            "data": {
                "localDataSources": {
                    "upload_endpoint": "/api/v1/ingest/local-sessions",
                    "sources": [
                        {
                            "name": "cursor",
                            "enabled": true,
                            "sqlite": [
                                {
                                    "db_path": "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
                                    "queries": [
                                        {
                                            "file_type": "sqlite_composer",
                                            "sql": "SELECT rowid, value FROM cursorDiskKV WHERE rowid > ?",
                                            "incremental_field": "rowid"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        });

        let hints = parse_registry_collector_hints(&bundle);
        assert_eq!(
            hints.upload_endpoint.as_deref(),
            Some("/api/v1/ingest/local-sessions")
        );
        assert_eq!(hints.sqlite_sources.len(), 1);
        let sqlite = &hints.sqlite_sources[0];
        assert_eq!(sqlite.agent, "cursor");
        assert_eq!(
            sqlite.db_path,
            "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb"
        );
        assert_eq!(sqlite.queries.len(), 1);
        assert_eq!(sqlite.queries[0].file_type, "sqlite_composer");
    }

    #[test]
    fn parse_registry_collector_hints_supports_local_sources_v2_shape() {
        let bundle = serde_json::json!({
            "collector": {
                "schema_version": 2,
                "artifact_catalog": {
                    "sources": {
                        "codex": {
                            "detection_id": "agent.codex.app",
                            "parser": { "name": "codex", "enabled": true },
                            "collectors": [
                                {
                                    "id": "glob_session_transcript_1",
                                    "kind": "glob",
                                    "pattern": "~/.codex/sessions/**/*.jsonl",
                                    "file_type": "session_transcript",
                                    "read_mode": "incremental",
                                    "content_type": "json"
                                }
                            ]
                        },
                        "cursor": {
                            "detection_id": "agent.cursor.app",
                            "collectors": [
                                {
                                    "id": "sqlite_sqlite_composer",
                                    "kind": "sqlite_query",
                                    "db_path": "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
                                    "file_type": "sqlite_composer",
                                    "sql": "SELECT rowid, value FROM cursorDiskKV WHERE rowid > ?",
                                    "incremental_field": "rowid"
                                }
                            ]
                        }
                    }
                },
                "local_ingestion": {
                    "upload_endpoint": "/api/v1/ingest/local-sessions",
                    "source_bindings": {
                        "codex": { "enabled": true },
                        "cursor": { "enabled": true }
                    }
                }
            }
        });

        let hints = parse_registry_collector_hints(&bundle);
        assert_eq!(
            hints.upload_endpoint.as_deref(),
            Some("/api/v1/ingest/local-sessions")
        );
        assert!(hints
            .file_sources
            .iter()
            .any(|source| source.agent == "agent.codex.app"
                && source.path == "~/.codex/sessions/**/*.jsonl"));
        assert_eq!(hints.sqlite_sources.len(), 1);
        assert_eq!(hints.sqlite_sources[0].agent, "agent.cursor.app");
        assert_eq!(hints.sqlite_sources[0].queries.len(), 1);
        assert_eq!(
            hints.sqlite_sources[0].queries[0].file_type,
            "sqlite_composer"
        );
    }
}
