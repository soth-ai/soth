//! Proxy status command

use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Expand tilde in path
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Run the status command
pub async fn run() -> anyhow::Result<()> {
    let ca_path = expand_path("~/.soth/ca");
    let cert_path = ca_path.join("ca.crt");
    let key_path = ca_path.join("ca.key");

    style::header("Forward Proxy Status");

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
        style::error("CA certificate not installed");
        println!();
        style::info("Run the following to set up:");
        println!("  {}", "soth proxy setup-ca".bold());
    }

    // Proxy server status
    println!();
    style::subtitle("Proxy Server");

    let proxy_addr = "127.0.0.1:8080";
    let mut server_table = style::table();
    server_table.set_header(vec!["Property", "Value"]);

    server_table.add_row(vec![Cell::new("Default Address"), Cell::new(proxy_addr)]);

    let running = tokio::net::TcpStream::connect(proxy_addr).await.is_ok();
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
    style::info("To configure environment:");
    println!("  {}", "eval $(soth proxy env)".bold());

    style::footer();
    Ok(())
}
