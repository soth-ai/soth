//! Start command - Run the SOTH proxy

use anyhow::{Context, Result};
use soth_core::config::SothConfig;
use soth_dashboard::{DashboardServer, DashboardState};
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine};
use soth_proxy::{
    Pipeline, PipelineBuilder, BudgetLayer, IdentityLayer, ObserveLayer, PolicyLayer,
    TransportBuilder, TransportType, TransportConfig,
    pipeline::identity::{IdentityConfig, IdentityMode},
    pipeline::policy::{PolicyConfig, PolicyMode},
    pipeline::observe::ObserveConfig,
    pipeline::budget::BudgetConfig,
    transport::stdio::StdioProxy,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Run the start command
pub async fn run(
    config_path: PathBuf,
    transport_override: Option<String>,
    port_override: Option<u16>,
) -> Result<()> {
    // Load configuration
    let config = if config_path.exists() {
        let content = fs::read_to_string(&config_path).await?;
        serde_yaml::from_str::<SothConfig>(&content)
            .context("Failed to parse config file")?
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
            run_server_transport(config, TransportType::Sse { port }, cancel, dashboard_state).await?;
        }
        "http" => {
            let port = port_override.unwrap_or(config.server.listen.port);
            run_server_transport(config, TransportType::Http { port }, cancel, dashboard_state).await?;
        }
        "streamable-http" => {
            let port = port_override.unwrap_or(config.server.listen.port);
            run_server_transport(config, TransportType::StreamableHttp { port }, cancel, dashboard_state).await?;
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
    let command = config.upstream.command.clone()
        .ok_or_else(|| anyhow::anyhow!("No upstream command configured"))?;

    info!(
        "Starting stdio proxy: {} {:?}",
        command,
        config.upstream.args
    );

    // Build the pipeline
    let pipeline = build_pipeline(&config, dashboard_state);
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
    let pipeline = build_pipeline(&config, dashboard_state);
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
fn build_pipeline(config: &SothConfig, dashboard_state: Option<DashboardState>) -> Pipeline {
    let mut builder = PipelineBuilder::new();

    // Add observe layer (first to capture all traffic)
    if config.observe.enabled {
        let mut observe_layer = ObserveLayer::new(ObserveConfig {
            log_requests: config.observe.log_requests,
            log_responses: config.observe.log_responses,
            pii_detection: config.observe.pii_detection,
            count_tokens: true,
            log_to_file: true,
        });
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
    let mut identity_layer = IdentityLayer::new(IdentityConfig {
        mode: identity_mode,
        ..Default::default()
    });
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
        let mut budget_layer = BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: true,
            default_model: "gpt-4o".to_string(),
        });
        if let Some(ref state) = dashboard_state {
            budget_layer = budget_layer.with_dashboard(state.clone());
            // Set the daily limit from config if available
            if let Some(limit) = config.budget.limits.iter()
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
