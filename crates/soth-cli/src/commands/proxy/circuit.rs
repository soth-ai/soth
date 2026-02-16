//! Circuit breaker command
//!
//! Shows circuit breaker status and allows resetting circuits.

use crate::cli_config;
use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Run the circuit command (show status)
pub async fn run_status(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;

    let port = config.dashboard.port;
    let url = format!("http://127.0.0.1:{}/metrics", port);

    // Fetch metrics to get circuit breaker state
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await?;
            display_circuit_status(&body, &config);
        }
        Ok(resp) => {
            anyhow::bail!(
                "Failed to fetch metrics: HTTP {} from {}",
                resp.status(),
                url
            );
        }
        Err(e) => {
            style::error("Could not connect to API service");
            eprintln!();
            style::kv("URL", &url);
            eprintln!();
            style::warning(&format!(
                "Start the API service first: soth dev api start --port {}",
                port
            ));
            anyhow::bail!("Connection failed: {}", e);
        }
    }

    Ok(())
}

/// Run the reset command
pub async fn run_reset(host: Option<String>, _config_path: Option<PathBuf>) -> anyhow::Result<()> {
    style::header("Circuit Breaker Reset");

    if let Some(h) = host {
        style::kv("Target host", &h);
    } else {
        style::kv("Target", "All hosts");
    }
    println!();

    style::warning("Remote circuit reset is not yet implemented.");
    println!();
    println!("To reset circuits, restart the proxy:");
    style::step(1, 2, "Stop the proxy (Ctrl+C)");
    style::step(2, 2, "Start it again: soth start");
    println!();
    println!(
        "Circuit breakers will automatically recover after the configured {}.",
        "open_duration (30s default)".dimmed()
    );

    style::footer();
    Ok(())
}

fn display_circuit_status(prometheus_text: &str, config: &soth_core::config::SothConfig) {
    style::header("Circuit Breaker Status");

    // Show config
    let cb_config = &config.production.circuit_breaker;
    style::subtitle("Configuration");

    let mut config_table = style::table();
    config_table.set_header(vec!["Setting", "Value"]);
    config_table.add_row(vec![
        Cell::new("Enabled"),
        Cell::new(style::enabled(cb_config.enabled)),
    ]);
    config_table.add_row(vec![
        Cell::new("Failure Threshold"),
        Cell::new(cb_config.failure_threshold.to_string()),
    ]);
    config_table.add_row(vec![
        Cell::new("Open Duration"),
        Cell::new(format!("{:?}", cb_config.open_duration)),
    ]);
    config_table.add_row(vec![
        Cell::new("Success Threshold"),
        Cell::new(cb_config.success_threshold.to_string()),
    ]);
    config_table.add_row(vec![
        Cell::new("Failure Window"),
        Cell::new(format!("{:?}", cb_config.failure_window)),
    ]);
    println!("{config_table}");

    // Parse circuit breaker states from metrics
    let mut circuits: Vec<(String, &str)> = Vec::new();
    let mut trips: Vec<(String, u64)> = Vec::new();

    for line in prometheus_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse circuit breaker state: soth_proxy_circuit_breaker_state{provider="..."} value
        if line.contains("circuit_breaker_state") {
            if let Some((provider, value)) = parse_labeled_metric(line, "provider") {
                let state = match value as u8 {
                    0 => "CLOSED",
                    1 => "HALF-OPEN",
                    2 => "OPEN",
                    _ => "UNKNOWN",
                };
                circuits.push((provider, state));
            }
        }

        // Parse circuit breaker trips
        if line.contains("circuit_breaker_trips") {
            if let Some((provider, value)) = parse_labeled_metric(line, "provider") {
                trips.push((provider, value as u64));
            }
        }
    }

    println!();
    style::subtitle("Circuit States");

    if circuits.is_empty() {
        style::warning("No circuit breaker data available");
        println!();
        println!("This could mean:");
        style::kv("  -", "No requests have been made yet");
        style::kv("  -", "Circuit breaker is disabled");
        style::kv("  -", "Metrics are not being collected");
    } else {
        let mut table = style::table();
        table.set_header(vec!["Provider", "State", "Trips"]);

        for (provider, state) in &circuits {
            let trip_count = trips
                .iter()
                .find(|(p, _)| p == provider)
                .map(|(_, c)| *c)
                .unwrap_or(0);

            let state_styled = match *state {
                "CLOSED" => format!("{} Closed", style::CHECK.green()),
                "HALF-OPEN" => format!("{} Half-Open", style::CIRCLE_FILLED.yellow()),
                "OPEN" => format!("{} Open", style::CROSS.red()),
                s => s.to_string(),
            };

            table.add_row(vec![
                Cell::new(provider),
                Cell::new(state_styled),
                Cell::new(style::format_number(trip_count)),
            ]);
        }
        println!("{table}");
    }

    style::footer();
}

fn parse_labeled_metric(line: &str, label_name: &str) -> Option<(String, f64)> {
    // Parse: metric_name{label="value"} number
    let label_pattern = format!("{}=\"", label_name);

    if let Some(label_start) = line.find(&label_pattern) {
        let value_start = label_start + label_pattern.len();
        if let Some(value_end) = line[value_start..].find('"') {
            let label_value = line[value_start..value_start + value_end].to_string();

            // Get the numeric value (last space-separated part)
            if let Some(num_str) = line.rsplit(' ').next() {
                if let Ok(num) = num_str.parse::<f64>() {
                    return Some((label_value, num));
                }
            }
        }
    }

    None
}
