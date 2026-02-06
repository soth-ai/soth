//! Rate limit command
//!
//! Shows rate limit status from the running proxy.

use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use soth_core::config::load_config;
use std::path::PathBuf;

/// Run the rate-limit command
pub async fn run(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // Load config to get dashboard port and rate limit config
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
            display_rate_limit_status(&body, &config);
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
            style::warning("Make sure the proxy is running with dashboard enabled.");
            anyhow::bail!("Connection failed: {}", e);
        }
    }

    Ok(())
}

fn display_rate_limit_status(prometheus_text: &str, config: &soth_core::config::SothConfig) {
    style::header("Rate Limit Status");

    // Show config
    let rl_config = &config.production.rate_limit;
    style::subtitle("Configuration");

    let mut config_table = style::table();
    config_table.set_header(vec!["Setting", "Value"]);

    config_table.add_row(vec![
        Cell::new("Enabled"),
        Cell::new(style::enabled(rl_config.enabled)),
    ]);
    config_table.add_row(vec![
        Cell::new("Requests/Second"),
        Cell::new(format!("{:.1}", rl_config.requests_per_second)),
    ]);
    config_table.add_row(vec![
        Cell::new("Burst Size"),
        Cell::new(rl_config.burst_size.to_string()),
    ]);
    config_table.add_row(vec![
        Cell::new("Global Requests/Sec"),
        Cell::new(format!("{:.1}", rl_config.global_requests_per_second)),
    ]);
    config_table.add_row(vec![
        Cell::new("Global Burst"),
        Cell::new(rl_config.global_burst_size.to_string()),
    ]);
    println!("{config_table}");

    // Parse rate limited counts from metrics
    let mut rate_limited_by_key: Vec<(String, String, u64)> = Vec::new();
    let mut total_rate_limited: u64 = 0;

    for line in prometheus_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse: soth_proxy_rate_limited_total{provider="...",key="..."} value
        if line.contains("rate_limited_total") {
            if let Some((provider, key, value)) = parse_rate_limited_metric(line) {
                total_rate_limited += value;
                rate_limited_by_key.push((provider, key, value));
            }
        }
    }

    println!();
    style::subtitle("Rate Limited Requests");

    // Summary with status indicator
    let status = if total_rate_limited > 0 {
        format!(
            "{} {} requests throttled",
            style::WARNING.yellow(),
            style::format_number(total_rate_limited)
        )
    } else {
        format!("{} No requests throttled", style::CHECK.green())
    };
    println!("{}", status);

    if !rate_limited_by_key.is_empty() {
        println!();
        style::subtitle("Breakdown by Key");

        let mut table = style::table();
        table.set_header(vec!["Provider", "Key", "Count"]);

        // Sort by count descending
        rate_limited_by_key.sort_by(|a, b| b.2.cmp(&a.2));

        for (provider, key, count) in rate_limited_by_key.iter().take(20) {
            table.add_row(vec![
                Cell::new(style::truncate(provider, 20)),
                Cell::new(style::truncate(key, 25)),
                Cell::new(style::format_number(*count).yellow().to_string()),
            ]);
        }
        println!("{table}");
    } else if rl_config.enabled {
        println!();
        style::info("No requests have been rate limited yet.");
    }

    if !rl_config.enabled {
        println!();
        style::warning("Rate limiting is currently DISABLED in config.");
        println!();
        println!("To enable, add to your soth.yaml:");
        println!("{}", "  production:".dimmed());
        println!("{}", "    rate_limit:".dimmed());
        println!("{}", "      enabled: true".dimmed());
        println!("{}", "      requests_per_second: 100".dimmed());
        println!("{}", "      burst_size: 200".dimmed());
    }

    style::footer();
}

fn parse_rate_limited_metric(line: &str) -> Option<(String, String, u64)> {
    // Parse: soth_proxy_rate_limited_total{provider="...",key="..."} value
    let provider = extract_label(line, "provider")?;
    let key = extract_label(line, "key")?;

    // Get the numeric value
    let value_str = line.rsplit(' ').next()?;
    let value: u64 = value_str.parse().ok()?;

    Some((provider, key, value))
}

fn extract_label(line: &str, label_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", label_name);
    let start = line.find(&pattern)? + pattern.len();
    let end = start + line[start..].find('"')?;
    Some(line[start..end].to_string())
}
