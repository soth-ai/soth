//! Start forward proxy command

use crate::cli_config;
use crate::commands::enforcement;
use crate::style;
use console::Term;
use owo_colors::OwoColorize;
use soth_core::config::{HostFilterMode, SothConfig};
use soth_core::EventLogger;
use soth_dashboard::server::DashboardServer;
use soth_dashboard::DashboardState;
use soth_proxy::metrics;
use soth_proxy::transport::hudsucker_proxy;
use std::path::PathBuf;

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

/// Run the start command
pub async fn run(port: Option<u16>, config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;

    // Override port if specified
    let mut proxy_config = config.forward_proxy.clone();
    if let Some(p) = port {
        proxy_config.port = p;
    }

    // Ensure proxy is enabled
    proxy_config.enabled = true;

    // Show startup spinner
    let spinner = style::spinner("Loading CA certificate...");

    // Hudsucker proxy requires cert and key paths.
    let ca_cert_path = cli_config::expand_tilde(&proxy_config.ca.cert_path);
    let ca_key_path = cli_config::expand_tilde(&proxy_config.ca.key_path);

    // Check CA exists
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        spinner.finish_and_clear();
        style::error("CA certificate not found. Run: soth proxy setup-ca");
        return Ok(());
    }

    spinner.finish_and_clear();

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

    let (event_logger, event_logging_status) = match EventLogger::with_default_path() {
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
        "forward-proxy | {} | {}",
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

    print_logo_banner();
    render_startup_panel(
        &runtime_line,
        &rules_line,
        &intercept_summary,
        "eval $(soth proxy env)",
        &compact_path(&ca_cert_path),
        &dashboard_line,
    );

    // Initialize Prometheus metrics
    let _ = metrics::init_metrics();

    // Ready message
    println!(
        "{} {}  |  AI/MCP → {}  |  Other → {}  |  {}",
        style::CHECK.green(),
        "Ready".bold(),
        "MITM".cyan(),
        "blind tunnel".dimmed(),
        "Ctrl+C to stop".dimmed()
    );
    println!();

    run_forward_proxy(
        &config,
        proxy_config,
        ca_cert_path,
        ca_key_path,
        event_logger,
    )
    .await
}

fn render_startup_panel(
    runtime: &str,
    rules: &str,
    intercept: &str,
    env_line: &str,
    ca_path: &str,
    dashboard_line: &str,
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

/// Run the forward proxy transport (battle-tested).
async fn run_forward_proxy(
    config: &SothConfig,
    proxy_config: soth_core::config::ForwardProxyConfig,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    event_logger: Option<EventLogger>,
) -> anyhow::Result<()> {
    let enforcer = enforcement::build_proxy_enforcer(config)?;
    let _policy_reload_task = enforcer
        .policy_engine()
        .and_then(|engine| enforcement::spawn_policy_hot_reload(config, engine));

    // Create dashboard state for metrics
    let dashboard_state = DashboardState::new();

    // Start dashboard server if enabled
    if config.dashboard.enabled {
        let state_clone = dashboard_state.clone();
        let dashboard_port = config.dashboard.port;

        tokio::spawn(async move {
            let server = DashboardServer::new(state_clone, dashboard_port).with_event_store();

            if let Err(e) = server.run().await {
                tracing::error!("Dashboard server error: {}", e);
            }
        });
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

    // Start the forward proxy transport with our shutdown signal
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
