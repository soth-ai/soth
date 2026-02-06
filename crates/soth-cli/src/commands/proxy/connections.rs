//! Proxy connections command
//!
//! Displays active connections from the running proxy.

use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use serde::Deserialize;
use soth_core::config::load_config;
use std::path::PathBuf;

#[derive(Deserialize)]
struct ApiResponse<T> {
    data: T,
}

#[derive(Deserialize)]
struct ProxyMetrics {
    total_requests: u64,
    total_responses: u64,
    active_connections: u64,
    requests_by_provider: std::collections::HashMap<String, u64>,
    total_tokens: u64,
    total_cost_usd: f64,
    recent_requests: Vec<RecentRequest>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RecentRequest {
    provider: String,
    host: String,
    method: String,
    path: String,
    status_code: Option<u16>,
    latency_ms: Option<u64>,
    model: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

/// Run the connections command
pub async fn run(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // Load config to get dashboard port
    let config = if let Some(path) = config_path {
        load_config(path)?
    } else {
        let default_paths = ["soth.yaml", "soth.yml", ".soth.yaml"];
        let mut loaded = None;
        for path in default_paths {
            if std::path::Path::new(path).exists() {
                loaded = Some(load_config(path)?);
                break;
            }
        }
        loaded.unwrap_or_default()
    };

    let port = config.dashboard.port;
    let url = format!("http://127.0.0.1:{}/api/proxy", port);

    // Fetch proxy metrics
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let api_response: ApiResponse<ProxyMetrics> = resp.json().await?;
            display_connections(&api_response.data);
        }
        Ok(resp) => {
            anyhow::bail!(
                "Failed to fetch connections: HTTP {} from {}",
                resp.status(),
                url
            );
        }
        Err(e) => {
            style::error("Could not connect to dashboard");
            eprintln!();
            style::kv("URL", &url);
            eprintln!();
            style::info("Make sure the proxy is running with dashboard enabled:");
            println!("  soth proxy start");
            eprintln!();
            anyhow::bail!("Connection failed: {}", e);
        }
    }

    Ok(())
}

fn display_connections(metrics: &ProxyMetrics) {
    style::header("Proxy Connections");

    // Summary stats
    let mut summary_table = style::table();
    summary_table.set_header(vec!["Metric", "Value"]);

    // Color active connections based on count
    let active_display = if metrics.active_connections > 0 {
        format!("{} {}", style::CIRCLE_FILLED.cyan(), metrics.active_connections)
    } else {
        format!("{} {}", style::CIRCLE_EMPTY.dimmed(), metrics.active_connections)
    };

    summary_table.add_row(vec![
        Cell::new("Active Connections"),
        Cell::new(active_display),
    ]);
    summary_table.add_row(vec![
        Cell::new("Total Requests"),
        Cell::new(style::format_number(metrics.total_requests)),
    ]);
    summary_table.add_row(vec![
        Cell::new("Total Responses"),
        Cell::new(style::format_number(metrics.total_responses)),
    ]);
    summary_table.add_row(vec![
        Cell::new("Total Tokens"),
        Cell::new(style::format_number(metrics.total_tokens)),
    ]);
    summary_table.add_row(vec![
        Cell::new("Total Cost"),
        Cell::new(format!("${:.4}", metrics.total_cost_usd).green().to_string()),
    ]);
    println!("{summary_table}");

    // Requests by provider
    if !metrics.requests_by_provider.is_empty() {
        println!();
        style::subtitle("Requests by Provider");

        let mut provider_table = style::table();
        provider_table.set_header(vec!["Provider", "Requests"]);

        // Sort by request count descending
        let mut providers: Vec<_> = metrics.requests_by_provider.iter().collect();
        providers.sort_by(|a, b| b.1.cmp(a.1));

        for (provider, count) in providers {
            let provider_colored = color_provider(provider);
            provider_table.add_row(vec![
                Cell::new(provider_colored),
                Cell::new(style::format_number(*count)),
            ]);
        }
        println!("{provider_table}");
    }

    // Recent requests
    if !metrics.recent_requests.is_empty() {
        println!();
        style::subtitle("Recent Requests");

        let mut req_table = style::table();
        req_table.set_header(vec!["Provider", "Host", "Status", "Latency", "Tokens"]);

        for req in metrics.recent_requests.iter().take(10) {
            let status_display = match req.status_code {
                Some(code) if code >= 200 && code < 300 => {
                    format!("{} {}", style::CHECK.green(), code)
                }
                Some(code) if code >= 400 => {
                    format!("{} {}", style::CROSS.red(), code)
                }
                Some(code) => code.to_string(),
                None => "-".dimmed().to_string(),
            };

            let latency = req
                .latency_ms
                .map(|l| format!("{}ms", l))
                .unwrap_or_else(|| "-".dimmed().to_string());

            let tokens = match (req.input_tokens, req.output_tokens) {
                (Some(i), Some(o)) => format!("{}/{}", i, o),
                _ => "-".dimmed().to_string(),
            };

            req_table.add_row(vec![
                Cell::new(color_provider(&req.provider)),
                Cell::new(style::truncate(&req.host, 25)),
                Cell::new(status_display),
                Cell::new(latency),
                Cell::new(tokens),
            ]);
        }
        println!("{req_table}");
    }

    style::footer();
}

/// Color provider name based on known providers
fn color_provider(provider: &str) -> String {
    match provider.to_lowercase().as_str() {
        "openai" => provider.bright_green().to_string(),
        "anthropic" => provider.bright_magenta().to_string(),
        "google" | "gemini" => provider.bright_blue().to_string(),
        "azure" => provider.bright_cyan().to_string(),
        _ => provider.to_string(),
    }
}
