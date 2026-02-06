//! Start command - Run the SOTH proxy

use anyhow::{Context, Result};
use soth_budget::BudgetTracker;
use soth_core::config::SothConfig;
use soth_dashboard::{DashboardServer, DashboardState};
use soth_identity::TrustStore;
use soth_observe::{LoggerConfig as ObserveLoggerConfig, ObservationLogger};
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine};
use soth_proxy::{
    pipeline::budget::BudgetConfig,
    pipeline::identity::{IdentityConfig, IdentityMode},
    pipeline::observe::ObserveConfig,
    pipeline::policy::{PolicyConfig, PolicyMode},
    transport::stdio::StdioProxy,
    BudgetLayer, IdentityLayer, ObserveLayer, Pipeline, PipelineBuilder, PolicyLayer,
    TransportBuilder, TransportConfig, TransportType,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Run the start command
pub async fn run(
    config_path: PathBuf,
    transport_override: Option<String>,
    port_override: Option<u16>,
) -> Result<()> {
    // Load configuration
    let config = if config_path.exists() {
        let content = fs::read_to_string(&config_path).await?;
        serde_yaml::from_str::<SothConfig>(&content).context("Failed to parse config file")?
    } else {
        info!("Config file not found, using defaults");
        SothConfig::default()
    };

    info!("Starting SOTH proxy...");

    // Create cancellation token for graceful shutdown
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal");
        cancel_clone.cancel();
    });

    // Create dashboard state if enabled
    let dashboard_state = if config.dashboard.enabled {
        Some(DashboardState::new())
    } else {
        None
    };

    // Start dashboard server if enabled
    if let Some(ref state) = dashboard_state {
        let dashboard_port = config.dashboard.port;
        let dashboard_state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = DashboardServer::new(dashboard_state_clone, dashboard_port)
                .run()
                .await
            {
                tracing::error!("Dashboard server error: {}", e);
            }
        });
    }

    // Determine transport type
    let transport_type = transport_override
        .as_deref()
        .unwrap_or(&config.server.transport);

    match transport_type {
        "stdio" => {
            run_stdio_proxy(config, cancel, dashboard_state).await?;
        }
        "sse" => {
            let port = port_override.unwrap_or(config.server.listen.port);
            run_server_transport(config, TransportType::Sse { port }, cancel, dashboard_state)
                .await?;
        }
        "http" => {
            let port = port_override.unwrap_or(config.server.listen.port);
            run_server_transport(
                config,
                TransportType::Http { port },
                cancel,
                dashboard_state,
            )
            .await?;
        }
        "streamable-http" => {
            let port = port_override.unwrap_or(config.server.listen.port);
            run_server_transport(
                config,
                TransportType::StreamableHttp { port },
                cancel,
                dashboard_state,
            )
            .await?;
        }
        _ => {
            anyhow::bail!("Unknown transport type: {transport_type}. Valid types: stdio, sse, http, streamable-http");
        }
    }

    Ok(())
}

/// Run the stdio proxy
async fn run_stdio_proxy(
    config: SothConfig,
    cancel: CancellationToken,
    dashboard_state: Option<DashboardState>,
) -> Result<()> {
    let command = config
        .upstream
        .command
        .clone()
        .ok_or_else(|| anyhow::anyhow!("No upstream command configured"))?;

    info!(
        "Starting stdio proxy: {} {:?}",
        command, config.upstream.args
    );

    // Build the pipeline
    let pipeline = build_pipeline(&config, dashboard_state).await;
    let pipeline = Arc::new(pipeline);

    // Create the stdio proxy
    let mut proxy = StdioProxy::new(
        command,
        config.upstream.args.clone(),
        TransportConfig {
            buffer_size: 1000,
            timeout_ms: 30000,
            log_messages: config.observe.enabled,
        },
    );

    // Create message handler
    let pipeline_clone = Arc::clone(&pipeline);
    let handler = Arc::new(move |msg| {
        let pipeline = Arc::clone(&pipeline_clone);
        Box::pin(async move {
            let mut ctx = soth_proxy::pipeline::middleware::RequestContext::new(
                uuid::Uuid::new_v4().to_string(),
            );
            pipeline.process(&mut ctx, msg).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
    });

    proxy.set_handler(handler);

    // Run the proxy
    proxy.run(cancel).await?;

    info!("Proxy stopped");
    Ok(())
}

/// Run with a server transport (SSE or HTTP)
async fn run_server_transport(
    config: SothConfig,
    transport_type: TransportType,
    cancel: CancellationToken,
    dashboard_state: Option<DashboardState>,
) -> Result<()> {
    let port = match &transport_type {
        TransportType::Sse { port } => *port,
        TransportType::Http { port } => *port,
        TransportType::StreamableHttp { port } => *port,
        TransportType::Stdio => 0,
    };

    info!("Starting server on port {}", port);

    // Build the pipeline
    let pipeline = build_pipeline(&config, dashboard_state).await;
    let pipeline = Arc::new(pipeline);

    // Create transport
    let mut transport = TransportBuilder::new(transport_type)
        .buffer_size(1000)
        .timeout_ms(30000)
        .log_messages(config.observe.enabled)
        .build();

    // Create message handler
    let pipeline_clone = Arc::clone(&pipeline);
    let handler = Arc::new(move |msg| {
        let pipeline = Arc::clone(&pipeline_clone);
        Box::pin(async move {
            let mut ctx = soth_proxy::pipeline::middleware::RequestContext::new(
                uuid::Uuid::new_v4().to_string(),
            );
            pipeline.process(&mut ctx, msg).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
    });

    transport.set_handler(handler);

    // Start transport
    transport.start(cancel.clone()).await?;

    // Wait for cancellation
    cancel.cancelled().await;

    // Stop transport
    transport.stop().await?;

    info!("Server stopped");
    Ok(())
}

/// Build the processing pipeline
async fn build_pipeline(config: &SothConfig, dashboard_state: Option<DashboardState>) -> Pipeline {
    let mut builder = PipelineBuilder::new();

    // Add observe layer (first to capture all traffic)
    if config.observe.enabled {
        let storage_backend = config.observe.storage.backend.to_lowercase();
        let supports_persistent_storage =
            matches!(storage_backend.as_str(), "local" | "jsonl" | "sqlite");

        let observe_config = ObserveConfig {
            log_requests: config.observe.log_requests,
            log_responses: config.observe.log_responses,
            pii_detection: config.observe.pii_detection,
            count_tokens: true,
            log_to_file: supports_persistent_storage,
        };

        let mut observe_layer = if observe_config.log_to_file {
            let storage_path =
                resolve_observation_storage_path(&config.observe.storage.path, &storage_backend);
            let logger_config = ObserveLoggerConfig {
                buffer_size: config.observe.buffer_size,
                flush_interval: config.observe.flush_interval,
                batch_size: std::cmp::max(1, config.observe.buffer_size / 10),
                pii_detection: config.observe.pii_detection,
                pii_redaction: false,
                tamper_proof: config.observe.tamper_proof,
                log_path: storage_path.clone(),
                storage_backend: storage_backend.clone(),
            };

            match ObservationLogger::new(logger_config).await {
                Ok(logger) => {
                    info!(
                        backend = %storage_backend,
                        path = %storage_path.display(),
                        "Observe logger initialized for pipeline"
                    );
                    ObserveLayer::with_logger(observe_config.clone(), Arc::new(logger))
                }
                Err(e) => {
                    warn!(
                        backend = %storage_backend,
                        path = %storage_path.display(),
                        error = %e,
                        "Failed to initialize observe logger; continuing without persistent storage"
                    );
                    ObserveLayer::new(observe_config.clone())
                }
            }
        } else {
            warn!(
                backend = %config.observe.storage.backend,
                "Observe storage backend is not supported; skipping persistent storage"
            );
            ObserveLayer::new(observe_config.clone())
        };

        if let Some(ref state) = dashboard_state {
            observe_layer = observe_layer.with_dashboard(state.clone());
        }
        builder = builder.layer(observe_layer);
    }

    // Add identity layer
    let identity_mode = match config.identity.mode.as_str() {
        "disabled" => IdentityMode::Disabled,
        "required" => IdentityMode::Required,
        _ => IdentityMode::Optional,
    };
    let mut trust_store = if let Some(path) = &config.identity.trust_store_path {
        let trust_store_path = resolve_trust_store_path(path);
        match TrustStore::new(&trust_store_path) {
            Ok(store) => store,
            Err(e) => {
                warn!(
                    path = %trust_store_path.display(),
                    error = %e,
                    "Failed to load trust store path; continuing with in-memory trust store"
                );
                TrustStore::in_memory()
            }
        }
    } else {
        TrustStore::in_memory()
    };

    for did in &config.identity.allowed_dids {
        if let Err(e) = trust_store.trust(did) {
            warn!(did = %did, error = %e, "Invalid allowed DID in identity config; skipping");
        }
    }

    let mut identity_layer = IdentityLayer::with_trust_store(
        IdentityConfig {
            mode: identity_mode,
            ..Default::default()
        },
        trust_store,
    );
    if let Some(ref state) = dashboard_state {
        identity_layer = identity_layer.with_dashboard(state.clone());
    }
    builder = builder.layer(identity_layer);

    // Add policy layer
    if config.policy.enabled {
        let policy_mode = match config.policy.mode.as_str() {
            "audit" => PolicyMode::Audit,
            "enforce" => PolicyMode::Enforce,
            _ => PolicyMode::Enforce,
        };
        // Convert core CacheConfig to policy CacheConfig
        let cache_config: PolicyCacheConfig = config.policy.cache.clone().into();
        let engine = PolicyEngine::with_cache_config(cache_config);

        if let Some(data_file) = &config.policy.data_file {
            let data = match data_file.extension().and_then(|ext| ext.to_str()) {
                Some("yaml") | Some("yml") => {
                    soth_policy::PolicyLoader::load_policy_data_yaml(data_file)
                }
                _ => soth_policy::PolicyLoader::load_policy_data(data_file),
            };
            match data {
                Ok(data) => {
                    if let Err(e) = engine.set_policy_data(data) {
                        warn!(
                            path = %data_file.display(),
                            error = %e,
                            "Failed to apply policy data file"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        path = %data_file.display(),
                        error = %e,
                        "Failed to load policy data file"
                    );
                }
            }
        }

        if let Some(policy_dir) = &config.policy.policy_dir {
            let mut modules = std::collections::HashMap::new();
            match soth_policy::PolicyLoader::load_rego_dir(policy_dir) {
                Ok(loaded) => modules.extend(loaded),
                Err(e) => {
                    warn!(
                        path = %policy_dir.display(),
                        error = %e,
                        "No Rego modules loaded from policy_dir"
                    );
                }
            }
            if let Ok(loaded_yaml) = soth_policy::PolicyLoader::load_yaml_dir(policy_dir) {
                modules.extend(loaded_yaml);
            }
            if !modules.is_empty() {
                if let Err(e) = engine.load_modules(modules) {
                    warn!(
                        path = %policy_dir.display(),
                        error = %e,
                        "Failed to load policy modules into engine"
                    );
                }
            }
        }

        let mut policy_layer = PolicyLayer::with_engine(
            PolicyConfig {
                mode: policy_mode,
                log_evaluations: true,
            },
            engine,
        );
        if let Some(ref state) = dashboard_state {
            policy_layer = policy_layer.with_dashboard(state.clone());
        }
        builder = builder.layer(policy_layer);
    }

    // Add budget layer
    if config.budget.enabled {
        let tracker = BudgetTracker::new();
        for limit in &config.budget.limits {
            match limit.scope.as_str() {
                "global" => {
                    tracker.set_global_budget(limit.daily, limit.weekly, limit.monthly);
                }
                "per_agent" => {
                    if let Some(agent_id) = &limit.agent_id {
                        tracker.set_agent_budget(
                            agent_id,
                            limit.daily,
                            limit.weekly,
                            limit.monthly,
                        );
                    } else {
                        warn!("Skipping per_agent budget limit with missing agent_id");
                    }
                }
                "per_session" => {
                    warn!("Budget scope 'per_session' is not yet supported by runtime tracker");
                }
                other => {
                    warn!(scope = %other, "Unknown budget scope; skipping");
                }
            }
        }

        let mut budget_layer = BudgetLayer::with_tracker(
            BudgetConfig {
                enabled: true,
                block_on_exceeded: true,
                default_model: "gpt-4o".to_string(),
            },
            tracker,
        );
        if let Some(ref state) = dashboard_state {
            budget_layer = budget_layer.with_dashboard(state.clone());
            // Set the daily limit from config if available
            if let Some(limit) = config
                .budget
                .limits
                .iter()
                .find(|l| l.scope == "global")
                .and_then(|l| l.daily)
            {
                state.set_daily_limit(Some(limit));
            }
        }
        builder = builder.layer(budget_layer);
    }

    builder.build()
}

fn resolve_observation_storage_path(base_path: &Path, backend: &str) -> PathBuf {
    if base_path.extension().is_some() {
        return base_path.to_path_buf();
    }

    match backend {
        "sqlite" => base_path.join("observations.db"),
        _ => base_path.join("observations.jsonl"),
    }
}

fn resolve_trust_store_path(base_path: &Path) -> PathBuf {
    if base_path.extension().is_some() {
        base_path.to_path_buf()
    } else {
        base_path.join("trust_store")
    }
}
