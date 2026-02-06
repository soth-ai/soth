//! Start forward proxy command

use crate::style;
use owo_colors::OwoColorize;
use soth_budget::BudgetTracker;
use soth_core::config::{load_config, SothConfig};
use soth_core::EventLogger;
use soth_dashboard::server::DashboardServer;
use soth_dashboard::DashboardState;
use soth_identity::TrustStore;
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine, PolicyLoader};
use soth_proxy::metrics;
use soth_proxy::transport::hudsucker_proxy::{
    self, ProxyEnforcer, ProxyIdentityMode, ProxyPolicyMode,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

fn resolve_trust_store_file(path: &Path) -> PathBuf {
    if path.extension().is_some() {
        path.to_path_buf()
    } else {
        path.join("trust_store")
    }
}

fn build_proxy_enforcer(config: &SothConfig) -> anyhow::Result<ProxyEnforcer> {
    let identity_mode = match config.identity.mode.as_str() {
        "disabled" => ProxyIdentityMode::Disabled,
        "required" => ProxyIdentityMode::Required,
        _ => ProxyIdentityMode::Optional,
    };

    let mut trusted_dids: HashSet<String> = HashSet::new();
    for did in &config.identity.allowed_dids {
        trusted_dids.insert(did.clone());
    }

    if let Some(path) = &config.identity.trust_store_path {
        let trust_store_file = resolve_trust_store_file(path);
        if trust_store_file.exists() {
            let store = TrustStore::new(&trust_store_file)?;
            for did in store.list() {
                trusted_dids.insert(did.to_string());
            }
        }
    }

    let mut enforcer = ProxyEnforcer::new()
        .with_identity_mode(identity_mode, trusted_dids)
        .with_identity_headers("X-Agent-DID", "X-Agent-Signature");

    if config.policy.enabled {
        let policy_mode = match config.policy.mode.as_str() {
            "audit" => ProxyPolicyMode::Audit,
            "enforce" => ProxyPolicyMode::Enforce,
            _ => ProxyPolicyMode::Enforce,
        };
        let cache_config: PolicyCacheConfig = config.policy.cache.clone().into();
        let engine = PolicyEngine::with_cache_config(cache_config);

        if let Some(data_file) = &config.policy.data_file {
            let data = match data_file.extension().and_then(|e| e.to_str()) {
                Some("yaml") | Some("yml") => PolicyLoader::load_policy_data_yaml(data_file)?,
                _ => PolicyLoader::load_policy_data(data_file)?,
            };
            engine.set_policy_data(data)?;
        }

        if let Some(policy_dir) = &config.policy.policy_dir {
            let mut modules = std::collections::HashMap::new();

            if policy_dir.exists() {
                if let Ok(rego_modules) = PolicyLoader::load_rego_dir(policy_dir) {
                    modules.extend(rego_modules);
                }
                if let Ok(yaml_modules) = PolicyLoader::load_yaml_dir(policy_dir) {
                    modules.extend(yaml_modules);
                }
            }

            if !modules.is_empty() {
                engine.load_modules(modules)?;
            }
        }

        enforcer = enforcer.with_policy(policy_mode, engine);
    }

    if config.budget.enabled {
        let tracker = BudgetTracker::new();
        for limit in &config.budget.limits {
            match limit.scope.as_str() {
                "global" => tracker.set_global_budget(limit.daily, limit.weekly, limit.monthly),
                "per_agent" => {
                    if let Some(agent_id) = &limit.agent_id {
                        tracker.set_agent_budget(
                            agent_id,
                            limit.daily,
                            limit.weekly,
                            limit.monthly,
                        );
                    }
                }
                _ => {}
            }
        }

        enforcer = enforcer.with_budget(tracker, true, "gpt-4o");
    }

    Ok(enforcer)
}

/// Run the start command
pub async fn run(port: Option<u16>, config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // Load config
    let config = if let Some(path) = config_path {
        load_config(path)?
    } else {
        // Try default paths
        let default_paths = ["soth.yaml", "soth.yml", ".soth.yaml", "~/.soth/soth.yaml"];
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

    // Hudsucker proxy requires cert and key paths.
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

    style::kv("Mode", "hudsucker");
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

    run_hudsucker_proxy(&config, proxy_config, ca_cert_path, ca_key_path).await
}

/// Run the hudsucker-based proxy (default, battle-tested)
async fn run_hudsucker_proxy(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
) -> anyhow::Result<()> {
    let enforcer = build_proxy_enforcer(config)?;

    // Create dashboard state for metrics
    let dashboard_state = DashboardState::new();

    // Start dashboard server if enabled
    if config.dashboard.enabled {
        let state_clone = dashboard_state.clone();
        let port = config.dashboard.port;

        tokio::spawn(async move {
            let server = DashboardServer::new(state_clone, port).with_event_store();

            if let Err(e) = server.run().await {
                tracing::error!("Dashboard server error: {}", e);
            }
        });

        style::kv("Dashboard API", &format!("http://localhost:{}", port));
    }

    // Create event logger for observability
    let event_logger = match EventLogger::with_default_path() {
        Ok(logger) => {
            style::kv_colored(
                "Event logging",
                logger.path().display().to_string().as_str(),
                true,
            );
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
        Some(enforcer),
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
