//! Start forward proxy command

use crate::style;
use owo_colors::OwoColorize;
use soth_core::config::load_config;
use soth_core::EventLogger;
use soth_dashboard::server::DashboardServer;
use soth_dashboard::DashboardState;
use soth_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soth_proxy::metrics;
use soth_proxy::rate_limit::{RateLimiter, RateLimitConfig};
use soth_proxy::transport::forward_proxy::ForwardProxyTransport;
use soth_proxy::transport::hudsucker_proxy;
use soth_proxy::Transport;
use soth_tls::CertificateAuthority;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// Expand tilde in path
fn expand_path(path: &PathBuf) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(&path_str[2..]);
            }
        }
    }
    path.clone()
}

/// Run the start command with mode selection
pub async fn run_with_mode(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    legacy: bool,
) -> anyhow::Result<()> {
    // Load config
    let config = if let Some(path) = config_path {
        load_config(path)?
    } else {
        // Try default paths
        let default_paths = [
            "soth.yaml",
            "soth.yml",
            ".soth.yaml",
            "~/.soth/soth.yaml",
        ];
        let mut loaded = None;
        for path in default_paths {
            let expanded = if path.starts_with("~/") {
                dirs::home_dir()
                    .map(|h| h.join(&path[2..]))
                    .unwrap_or_else(|| PathBuf::from(path))
            } else {
                PathBuf::from(path)
            };
            if expanded.exists() {
                loaded = Some(load_config(&expanded)?);
                break;
            }
        }
        loaded.unwrap_or_default()
    };

    // Override port if specified
    let mut proxy_config = config.forward_proxy.clone();
    if let Some(p) = port {
        proxy_config.port = p;
    }

    // Ensure proxy is enabled
    proxy_config.enabled = true;

    // Expand CA paths
    let ca_path = expand_path(&proxy_config.ca.cert_path)
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();

    // Show startup spinner
    let spinner = style::spinner("Loading CA certificate...");

    // For hudsucker, we need the paths; for legacy, we need the CertificateAuthority
    let ca_cert_path = ca_path.join("ca.crt");
    let ca_key_path = ca_path.join("ca.key");

    // Check CA exists
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        spinner.finish_and_clear();
        style::error("CA certificate not found. Run: soth proxy setup-ca");
        return Ok(());
    }

    spinner.finish_and_clear();

    // Display startup banner
    style::header("SOTH Forward Proxy");

    let mode = if legacy { "legacy" } else { "hudsucker" };
    style::kv("Mode", mode);
    style::kv("Listen address", &proxy_config.socket_addr().to_string());
    style::kv("CA certificate", &ca_cert_path.display().to_string());
    println!();

    // Show AI intercept domains
    style::subtitle("AI Traffic Interception");
    let intercept_count = proxy_config.hosts.intercept.len();
    if intercept_count > 0 {
        // Show first few domains
        for host in proxy_config.hosts.intercept.iter().take(5) {
            println!("  {} {}", style::CIRCLE_FILLED.cyan(), host);
        }
        if intercept_count > 5 {
            println!(
                "  {} ... and {} more domains",
                style::CIRCLE_FILLED.dimmed(),
                intercept_count - 5
            );
        }
    }
    println!();

    // Show blocked domains if any
    if !proxy_config.hosts.block.is_empty() {
        style::subtitle("Blocked Domains");
        for host in &proxy_config.hosts.block {
            println!("  {} {}", style::CROSS.red(), host);
        }
        println!();
    }

    style::subtitle("Environment Setup");
    println!(
        "  {} {}",
        "export".dimmed(),
        format!("HTTP_PROXY=http://{}", proxy_config.socket_addr()).green()
    );
    println!(
        "  {} {}",
        "export".dimmed(),
        format!("HTTPS_PROXY=http://{}", proxy_config.socket_addr()).green()
    );
    println!(
        "  {} {}",
        "export".dimmed(),
        format!("SSL_CERT_FILE={}", ca_cert_path.display()).green()
    );
    println!();

    // Initialize Prometheus metrics
    let _ = metrics::init_metrics();

    style::footer();

    // Ready message
    style::success(&format!(
        "Proxy ready on {}",
        proxy_config.socket_addr().to_string().bold()
    ));
    println!(
        "{} AI traffic → {} | Other traffic → {}",
        style::INFO,
        "MITM intercept".cyan(),
        "blind tunnel".dimmed()
    );
    println!(
        "{} Press {} to stop",
        style::CIRCLE_FILLED.dimmed(),
        "Ctrl+C".bold()
    );
    println!();

    if legacy {
        // Legacy mode: use ForwardProxyTransport
        run_legacy_proxy(config, proxy_config, ca_path).await
    } else {
        // Default: use hudsucker-based proxy
        run_hudsucker_proxy(config.dashboard, proxy_config, ca_cert_path, ca_key_path).await
    }
}

/// Run the hudsucker-based proxy (default, battle-tested)
async fn run_hudsucker_proxy(
    dashboard_config: soth_core::config::DashboardConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
) -> anyhow::Result<()> {
    // Create dashboard state for metrics
    let dashboard_state = DashboardState::new();

    // Start dashboard server if enabled
    if dashboard_config.enabled {
        let state_clone = dashboard_state.clone();
        let port = dashboard_config.port;

        tokio::spawn(async move {
            let server = DashboardServer::new(state_clone, port)
                .with_event_store();

            if let Err(e) = server.run().await {
                tracing::error!("Dashboard server error: {}", e);
            }
        });

        style::kv("Dashboard API", &format!("http://localhost:{}", port));
    }

    // Create event logger for observability
    let event_logger = match EventLogger::with_default_path() {
        Ok(logger) => {
            style::kv_colored("Event logging", logger.path().display().to_string().as_str(), true);
            Some(logger)
        }
        Err(e) => {
            style::warning(&format!("Event logging disabled: {}", e));
            None
        }
    };

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn signal handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!();
        style::warning("Initiating graceful shutdown...");
        let _ = shutdown_tx.send(());
    });

    // Start the hudsucker proxy with our shutdown signal
    let result = hudsucker_proxy::start_proxy_with_shutdown(
        proxy_config,
        &ca_cert_path,
        &ca_key_path,
        async move {
            shutdown_rx.await.ok();
        },
        Some(dashboard_state),
        event_logger,
    )
    .await;

    match result {
        Ok(()) => {
            style::success("Proxy stopped.");
            Ok(())
        }
        Err(e) => {
            style::error(&format!("Proxy error: {}", e));
            Err(anyhow::anyhow!("Proxy error: {}", e))
        }
    }
}

/// Run the legacy ForwardProxyTransport (for compatibility/testing)
async fn run_legacy_proxy(
    config: soth_core::config::SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_path: PathBuf,
) -> anyhow::Result<()> {
    // Load CA
    let ca = CertificateAuthority::load_or_generate(ca_path)
        .map_err(|e| anyhow::anyhow!("Failed to load CA: {}", e))?;

    // Create rate limiter from production config
    let rate_limiter = if config.production.rate_limit.enabled {
        style::kv_colored(
            "Rate limiting",
            &format!(
                "{} req/s, burst {}",
                config.production.rate_limit.requests_per_second,
                config.production.rate_limit.burst_size
            ),
            true,
        );
        Some(RateLimiter::new(RateLimitConfig {
            requests_per_second: config.production.rate_limit.requests_per_second,
            burst_size: config.production.rate_limit.burst_size,
            enabled: true,
        }))
    } else {
        None
    };

    // Create circuit breaker from production config
    let circuit_breaker = if config.production.circuit_breaker.enabled {
        style::kv_colored(
            "Circuit breaker",
            &format!(
                "threshold {}, open {:?}",
                config.production.circuit_breaker.failure_threshold,
                config.production.circuit_breaker.open_duration
            ),
            true,
        );
        Some(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: config.production.circuit_breaker.failure_threshold,
            open_duration: config.production.circuit_breaker.open_duration,
            success_threshold: config.production.circuit_breaker.success_threshold,
            failure_window: config.production.circuit_breaker.failure_window,
            enabled: true,
        }))
    } else {
        None
    };

    // Get graceful shutdown timeout from config
    let shutdown_timeout = config.server.graceful_shutdown;

    // Create and start transport
    let mut transport = ForwardProxyTransport::new(proxy_config, ca)
        .with_shutdown_timeout(shutdown_timeout);

    // Wire in production features
    if let Some(limiter) = rate_limiter {
        transport = transport.with_rate_limiter(limiter);
    }
    if let Some(breaker) = circuit_breaker {
        transport = transport.with_circuit_breaker(breaker);
    }

    // Add event logger for observability
    match EventLogger::with_default_path() {
        Ok(logger) => {
            style::kv_colored("Event logging", logger.path().display().to_string().as_str(), true);
            transport = transport.with_event_logger(logger);
        }
        Err(e) => {
            style::warning(&format!("Event logging disabled: {}", e));
        }
    }

    // Set up signal handler
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!();
        style::warning("Initiating graceful shutdown...");
        style::info("Waiting for in-flight connections to complete...");
        cancel_clone.cancel();
    });

    // Start the proxy
    transport
        .start(cancel)
        .await
        .map_err(|e| anyhow::anyhow!("Proxy error: {}", e))?;

    style::success("Proxy stopped.");
    Ok(())
}
