//! Runtime/bootstrap wiring for proxy transport.

use chrono::Utc;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper_util::{rt::TokioExecutor, server::conn::auto::Builder as AutoServerBuilder},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    Proxy,
};
use soth_crypto::tls::LearnedPassthrough;
use soth_oisp::types::bundle::{BundleStats, BundleType};
use soth_oisp::types::EntryType;
use soth_oisp::types::{CompiledBundle, DomainFilters, ResolvedProvider};
use soth_oisp::OispEngine;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

use crate::error::ProxyError;
use crate::metrics;
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::proxy::AiProxyHandler;
use crate::transport::proxy_enforcer::ProxyEnforcer;
use crate::transport::proxy_websocket::AiWebSocketHandler;
use soth_core::config::{ExchangeV2Config, ForwardProxyConfig, ObserveConfig};
use soth_core::EventLogger;

pub(crate) fn load_oisp_engine(cache_path: Option<&Path>) -> Result<Arc<OispEngine>, ProxyError> {
    fn fallback_engine(reason: &str) -> Result<Arc<OispEngine>, ProxyError> {
        // Fail-open fallback: keep proxy online and tunnel traffic when bundle/cache is unavailable.
        // This avoids startup outages while preserving operator visibility.
        let provider_id = "fallback-unknown".to_string();
        let mut providers = BTreeMap::new();
        providers.insert(
            provider_id.clone(),
            ResolvedProvider {
                id: provider_id,
                entity_id: Some("p_fallback_unknown".to_string()),
                name: "Fallback Unknown".to_string(),
                entry_type: EntryType::AgentApp,
                api_format: None,
                domains: Vec::new(),
                user_agent_patterns: Vec::new(),
                detection: None,
            },
        );

        let bundle = CompiledBundle {
            schema_version: 3,
            version: "fallback-local-1".to_string(),
            compiled_at: Utc::now().to_rfc3339(),
            bundle_type: BundleType::Local,
            domain_index: Vec::new(),
            providers,
            filters: DomainFilters::default(),
            pricing: BTreeMap::new(),
            stats: BundleStats {
                providers: 1,
                domains: 0,
                formats: 0,
            },
            formats: BTreeMap::new(),
            catalog_domains: Vec::new(),
            meta: None,
            signatures: None,
        };

        let engine = OispEngine::new(bundle).map_err(|error| {
            ProxyError::transport(format!(
                "failed to construct fallback OISP engine for fail-open mode: {error}"
            ))
        })?;
        warn!(reason = reason, "Using fail-open fallback OISP engine");
        Ok(Arc::new(engine))
    }

    let Some(path) = cache_path else {
        return fallback_engine("registry cache path not configured");
    };

    match OispEngine::load_from_registry_cache(path) {
        Ok(Some(engine)) => {
            info!(
                cache = %path.display(),
                bundle_version = %engine.bundle_version(),
                providers = engine.provider_count(),
                domains = engine.domain_count(),
                catalog_domains = engine.catalog_domain_count(),
                whitelist = engine.whitelist_count(),
                blacklist = engine.blacklist_count(),
                passthrough = engine.passthrough_count(),
                noise_keywords = engine.noise_keyword_count(),
                "Loaded OISP bundle for proxy classification"
            );
            Ok(Arc::new(engine))
        }
        Ok(None) => fallback_engine(&format!(
            "registry cache not found at {}; running in tunnel-first fail-open mode",
            path.display()
        )),
        Err(error) => {
            error!(
                cache = %path.display(),
                error = %error,
                "Failed to load OISP registry cache"
            );
            fallback_engine(&format!(
                "failed loading registry cache {}: {error}",
                path.display()
            ))
        }
    }
}

/// Start the forward proxy with graceful shutdown support.
pub async fn start_proxy(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
) -> Result<(), ProxyError> {
    // Create shutdown channel.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn signal handler.
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    start_proxy_with_shutdown(
        config,
        ca_cert_path,
        ca_key_path,
        async move {
            shutdown_rx.await.ok();
        },
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .await
}

/// Start the forward proxy with custom shutdown future.
pub async fn start_proxy_with_shutdown<F>(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    shutdown: F,
    event_logger: Option<EventLogger>,
    enforcer: Option<ProxyEnforcer>,
    observe_config: Option<ObserveConfig>,
    oisp_registry_cache_path: Option<PathBuf>,
    exchange_v2_config: Option<ExchangeV2Config>,
    force_intercept_all: bool,
    force_intercept_all_for: Option<Duration>,
) -> Result<(), ProxyError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Load CA cert and key as strings (PEM format).
    let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
        .map_err(|e| ProxyError::transport(format!("Failed to read CA cert: {}", e)))?;
    let ca_key_pem = std::fs::read_to_string(ca_key_path)
        .map_err(|e| ProxyError::transport(format!("Failed to read CA key: {}", e)))?;

    // Parse key pair.
    let key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| ProxyError::transport(format!("Failed to parse CA key: {}", e)))?;

    // Create issuer from CA cert + key.
    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)
        .map_err(|e| ProxyError::transport(format!("Failed to create issuer: {}", e)))?;

    // Create CA with cache size of 1000 certs.
    let ca = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    let listen_addr: SocketAddr = config
        .socket_addr()
        .parse()
        .map_err(|e| ProxyError::transport(format!("Invalid listen address: {}", e)))?;

    // Preflight socket bind to surface actionable OS error details (e.g. EADDRINUSE).
    {
        let preflight = std::net::TcpListener::bind(listen_addr).map_err(|error| {
            ProxyError::transport(format!(
                "Proxy preflight bind failed on {}: {}",
                listen_addr, error
            ))
        })?;
        drop(preflight);
    }

    // Create a shared session ID for both handlers.
    let session_id = uuid::Uuid::new_v4().to_string();

    // Convert event_logger to Arc for sharing.
    let event_logger_arc = event_logger.map(Arc::new);
    let ws_hosts = Arc::new(config.hosts.clone());
    let observe_config = observe_config.unwrap_or_default();
    let event_tags = Arc::new(observe_config.event_tags.clone());
    let pii_enricher = Arc::new(PiiEventEnricher::from_observe_config(&observe_config));
    let oisp_engine = load_oisp_engine(oisp_registry_cache_path.as_deref())?;
    let ai_protected_patterns = oisp_engine.ai_inference_domain_patterns();
    let learned_passthrough = if config.tls.learned_passthrough.enabled {
        let learned = Arc::new(LearnedPassthrough::new(
            config.tls.learned_passthrough.state_path.clone(),
            ai_protected_patterns,
            config.tls.learned_passthrough.max_age,
        ));
        learned.load();
        metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
        Some(learned)
    } else {
        None
    };
    let force_intercept_all_until =
        force_intercept_all_for.and_then(|window| SystemTime::now().checked_add(window));

    let handler = {
        let mut h = AiProxyHandler::new(&config, &observe_config, oisp_engine.clone());
        if let Some(ref logger) = event_logger_arc {
            h = h.with_event_logger_arc(logger.clone());
        }
        if let Some(ref proxy_enforcer) = enforcer {
            h = h.with_enforcer(proxy_enforcer.clone());
        }
        if let Some(ref exchange_cfg) = exchange_v2_config {
            h = h.with_exchange_v2(exchange_cfg.clone());
        }
        if let Some(ref learned) = learned_passthrough {
            h = h.with_learned_passthrough(
                learned.clone(),
                config.tls.learned_passthrough.failure_threshold,
                config.tls.learned_passthrough.failure_window,
            );
        }
        if force_intercept_all {
            h = h.with_force_intercept_all(force_intercept_all, force_intercept_all_until);
        }
        h
    };

    // Create WebSocket handler with event logger.
    let ws_handler = AiWebSocketHandler::new(
        session_id,
        event_logger_arc,
        ws_hosts,
        oisp_engine.clone(),
        event_tags,
        pii_enricher,
    );

    info!("Starting soth proxy on {}", listen_addr);
    info!("  Registry mode -> {}", config.registry_mode);
    info!("  AI+MCP domains -> MITM intercept");
    info!("  Other domains -> blind tunnel");
    if config.tunnel_debug.enabled {
        info!(
            include_noise = config.tunnel_debug.include_noise,
            min_log_interval_secs = config.tunnel_debug.min_log_interval.as_secs(),
            "  Tunnel debug -> metadata logging enabled for tunneled traffic"
        );
    }
    if force_intercept_all {
        match force_intercept_all_for {
            Some(window) => info!(
                window_secs = window.as_secs(),
                "  Debug catch-all -> MITM intercept all non-local hosts (temporary)"
            ),
            None => info!("  Debug catch-all -> MITM intercept all non-local hosts"),
        }
    }

    // ChatGPT web requests can carry extremely large sentinel/auth headers.
    // Raise parser budgets so requests are accepted and then sanitized in handler logic.
    let mut server = AutoServerBuilder::new(TokioExecutor::new());
    server
        .http1()
        .max_headers(512)
        .max_buf_size(1024 * 1024)
        .title_case_headers(true)
        .preserve_header_case(true);
    server.http2().max_header_list_size(262_144);

    let proxy = Proxy::builder()
        .with_addr(listen_addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_server(server)
        .with_http_handler(handler)
        .with_websocket_handler(ws_handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .map_err(|e| ProxyError::transport(format!("Failed to build proxy: {}", e)))?;

    proxy.start().await.map_err(|error| {
        ProxyError::transport(format!(
            "Proxy start failed on {}: {} (debug: {:?})",
            listen_addr, error, error
        ))
    })?;

    if let Some(ref learned) = learned_passthrough {
        learned.persist();
        metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
    }

    Ok(())
}
