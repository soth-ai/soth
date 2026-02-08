//! Proxy status command

use crate::cli_config;
use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Run the status command
pub async fn run(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let cert_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path);
    let key_path = cli_config::expand_tilde(&config.forward_proxy.ca.key_path);

    style::header("SOTH Proxy Status");

    // CA Certificate status
    style::subtitle("CA Certificate");

    let ca_installed = cert_path.exists() && key_path.exists();
    if ca_installed {
        let mut ca_table = style::table();
        ca_table.set_header(vec!["Property", "Value"]);

        ca_table.add_row(vec![
            Cell::new("Status"),
            Cell::new(format!("{} Installed", style::CHECK.green())),
        ]);
        ca_table.add_row(vec![
            Cell::new("Certificate"),
            Cell::new(cert_path.display().to_string().dimmed().to_string()),
        ]);
        ca_table.add_row(vec![
            Cell::new("Private Key"),
            Cell::new(key_path.display().to_string().dimmed().to_string()),
        ]);

        // Check cert format
        if let Ok(pem) = std::fs::read_to_string(&cert_path) {
            if pem.contains("BEGIN CERTIFICATE") {
                ca_table.add_row(vec![
                    Cell::new("Format"),
                    Cell::new(format!("{} PEM (valid)", style::CHECK.green())),
                ]);
            }
        }
        println!("{ca_table}");
    } else {
        style::warning("CA certificate not installed");
        println!();
        style::info("Run the following to set up:");
        println!("  {}", "soth proxy setup-ca".bold());
    }

    // Proxy server status
    println!();
    style::subtitle("Proxy Server");

    let proxy_addr = config.forward_proxy.socket_addr();
    let mut server_table = style::table();
    server_table.set_header(vec!["Property", "Value"]);

    server_table.add_row(vec![
        Cell::new("Configured Address"),
        Cell::new(proxy_addr.to_string().cyan().to_string()),
    ]);

    let running = tokio::net::TcpStream::connect(proxy_addr.as_str()).await.is_ok();
    let status_display = if running {
        format!("{} Running", style::CIRCLE_FILLED.green())
    } else {
        format!("{} Not running", style::CIRCLE_EMPTY.dimmed())
    };
    server_table.add_row(vec![Cell::new("Status"), Cell::new(status_display)]);
    println!("{server_table}");

    if !running {
        println!();
        style::info("Start the proxy with:");
        println!("  {}", "soth proxy start".bold());
    }

    // Environment variables
    println!();
    style::subtitle("Environment");

    let mut env_table = style::table();
    env_table.set_header(vec!["Variable", "Value"]);

    let http_proxy = std::env::var("HTTP_PROXY").ok();
    let https_proxy = std::env::var("HTTPS_PROXY").ok();
    let ssl_cert_file = std::env::var("SSL_CERT_FILE").ok();

    env_table.add_row(vec![
        Cell::new("HTTP_PROXY"),
        Cell::new(
            http_proxy
                .map(|v| v.green().to_string())
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    env_table.add_row(vec![
        Cell::new("HTTPS_PROXY"),
        Cell::new(
            https_proxy
                .map(|v| v.green().to_string())
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    env_table.add_row(vec![
        Cell::new("SSL_CERT_FILE"),
        Cell::new(
            ssl_cert_file
                .map(|v| v.green().to_string())
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    println!("{env_table}");

    println!();
    style::info("To configure environment for this proxy:");
    println!("  {}", "eval $(soth proxy env)".bold());

    style::footer();
    Ok(())
}
