//! Proxy metrics command
//!
//! Displays Prometheus metrics from the running proxy/dashboard.

use crate::cli_config;
use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Run the metrics command
pub async fn run(config_path: Option<PathBuf>, raw: bool) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;

    let port = config.dashboard.port;
    let url = format!("http://127.0.0.1:{}/metrics", port);

    // Fetch metrics
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await?;

            if raw {
                // Output raw Prometheus format
                println!("{}", body);
            } else {
                // Parse and display in human-readable format
                display_metrics(&body);
            }
        }
        Ok(resp) => {
            anyhow::bail!(
                "Failed to fetch metrics: HTTP {} from {}",
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
            style::info("Or check your config has dashboard enabled:");
            println!("  dashboard:");
            println!("    enabled: true");
            println!("    port: {}", port);
            eprintln!();
            anyhow::bail!("Connection failed: {}", e);
        }
    }

    Ok(())
}

/// Display metrics in human-readable format
fn display_metrics(prometheus_text: &str) {
    style::header("Proxy Metrics");

    // Parse simple metrics
    let mut requests: u64 = 0;
    let mut responses: u64 = 0;
    let mut errors: u64 = 0;
    let mut tokens: u64 = 0;
    let mut rate_limited: u64 = 0;
    let mut circuit_trips: u64 = 0;

    for line in prometheus_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse metric lines like: metric_name{labels} value
        if let Some((name, value)) = parse_metric_line(line) {
            match name {
                n if n.starts_with("soth_proxy_requests_total") => {
                    requests += value as u64;
                }
                n if n.starts_with("soth_proxy_responses_total") => {
                    responses += value as u64;
                }
                n if n.starts_with("soth_proxy_errors_total") => {
                    errors += value as u64;
                }
                n if n.starts_with("soth_proxy_tokens_total") => {
                    tokens += value as u64;
                }
                n if n.starts_with("soth_proxy_rate_limited_total") => {
                    rate_limited += value as u64;
                }
                n if n.starts_with("soth_proxy_circuit_breaker_trips") => {
                    circuit_trips += value as u64;
                }
                _ => {}
            }
        }
    }

    style::subtitle("Summary");

    let mut table = style::table();
    table.set_header(vec!["Metric", "Value", "Status"]);

    // Requests
    table.add_row(vec![
        Cell::new("Total Requests"),
        Cell::new(style::format_number(requests)),
        Cell::new(style::CIRCLE_FILLED.cyan().to_string()),
    ]);

    // Responses
    table.add_row(vec![
        Cell::new("Total Responses"),
        Cell::new(style::format_number(responses)),
        Cell::new(style::CIRCLE_FILLED.cyan().to_string()),
    ]);

    // Errors - highlight if non-zero
    let error_status = if errors > 0 {
        format!("{} attention", style::WARNING.yellow())
    } else {
        format!("{} ok", style::CHECK.green())
    };
    table.add_row(vec![
        Cell::new("Total Errors"),
        Cell::new(if errors > 0 {
            style::format_number(errors).red().to_string()
        } else {
            style::format_number(errors)
        }),
        Cell::new(error_status),
    ]);

    // Tokens
    table.add_row(vec![
        Cell::new("Total Tokens"),
        Cell::new(style::format_number(tokens)),
        Cell::new(style::CIRCLE_FILLED.cyan().to_string()),
    ]);

    // Rate Limited - highlight if non-zero
    let rate_status = if rate_limited > 0 {
        format!("{} throttled", style::WARNING.yellow())
    } else {
        format!("{} ok", style::CHECK.green())
    };
    table.add_row(vec![
        Cell::new("Rate Limited"),
        Cell::new(if rate_limited > 0 {
            style::format_number(rate_limited).yellow().to_string()
        } else {
            style::format_number(rate_limited)
        }),
        Cell::new(rate_status),
    ]);

    // Circuit Breaker Trips - highlight if non-zero
    let circuit_status = if circuit_trips > 0 {
        format!("{} tripped", style::CROSS.red())
    } else {
        format!("{} ok", style::CHECK.green())
    };
    table.add_row(vec![
        Cell::new("Circuit Trips"),
        Cell::new(if circuit_trips > 0 {
            style::format_number(circuit_trips).red().to_string()
        } else {
            style::format_number(circuit_trips)
        }),
        Cell::new(circuit_status),
    ]);

    println!("{table}");
    println!();
    println!(
        "{} Use {} for full Prometheus output",
        style::CIRCLE_FILLED.dimmed(),
        "--raw".bold()
    );

    style::footer();
}

/// Parse a Prometheus metric line
fn parse_metric_line(line: &str) -> Option<(&str, f64)> {
    // Handle lines with labels: metric{label="value"} 123
    // And simple lines: metric 123
    let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let value: f64 = parts[0].parse().ok()?;
    let name = parts[1];

    // Extract metric name (before { or entire string)
    let metric_name = name.split('{').next()?;

    Some((metric_name, value))
}
