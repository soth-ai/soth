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
    let expected_proxy = format!("http://{}", config.forward_proxy.socket_addr());

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
        println!("  {}", "soth runtime setup-ca".bold());
    }

    // Runtime service status
    println!();
    style::subtitle("Services");

    let proxy_addr = config.forward_proxy.socket_addr();
    let mut server_table = style::table();
    server_table.set_header(vec!["Property", "Value"]);

    server_table.add_row(vec![
        Cell::new("Sensor Address"),
        Cell::new(proxy_addr.to_string().cyan().to_string()),
    ]);

    let running = tokio::net::TcpStream::connect(proxy_addr.as_str())
        .await
        .is_ok();
    let status_display = if running {
        format!("{} Running", style::CHECK.green())
    } else {
        format!("{} Not running", style::CROSS.red())
    };
    server_table.add_row(vec![Cell::new("Sensor Status"), Cell::new(status_display)]);

    #[cfg(feature = "local-debug")]
    let api_addr = format!("127.0.0.1:{}", config.dashboard.port);
    #[cfg(feature = "local-debug")]
    let api_running = tokio::net::TcpStream::connect(api_addr.as_str())
        .await
        .is_ok();
    #[cfg(feature = "local-debug")]
    server_table.add_row(vec![
        Cell::new("API Address"),
        Cell::new(format!("http://{}", api_addr).cyan().to_string()),
    ]);
    #[cfg(feature = "local-debug")]
    server_table.add_row(vec![
        Cell::new("API Status"),
        Cell::new(if api_running {
            format!("{} Running", style::CHECK.green())
        } else {
            format!("{} Not running", style::CROSS.red())
        }),
    ]);
    #[cfg(not(feature = "local-debug"))]
    server_table.add_row(vec![
        Cell::new("Local Debug"),
        Cell::new("disabled in this build (enable `local-debug`)"),
    ]);
    println!("{server_table}");

    if !running {
        println!();
        style::info("Start sensor runtime with:");
        println!("  {}", "soth start".bold());
    }
    #[cfg(feature = "local-debug")]
    if !api_running {
        println!();
        style::info("Start API service with:");
        println!(
            "  {}",
            format!("soth dev api start --port {}", config.dashboard.port).bold()
        );
    }
    #[cfg(feature = "local-debug")]
    {
        println!();
        style::info("Optional UI/TUI surfaces:");
        println!("  {}", "soth dev ui start".bold());
        println!("  {}", "soth dev profile start --profile dev-stack".bold());
        println!(
            "  {}",
            format!(
                "soth attach --api-url http://127.0.0.1:{}",
                config.dashboard.port
            )
            .bold()
        );
    }

    // Environment variables
    println!();
    style::subtitle("Environment");

    let mut env_table = style::table();
    env_table.set_header(vec!["Variable", "Value"]);

    let http_proxy = std::env::var("HTTP_PROXY").ok();
    let https_proxy = std::env::var("HTTPS_PROXY").ok();
    let no_proxy = std::env::var("NO_PROXY").ok();
    let ssl_cert_file = std::env::var("SSL_CERT_FILE").ok();

    env_table.add_row(vec![
        Cell::new("HTTP_PROXY"),
        Cell::new(
            http_proxy
                .as_ref()
                .map(|v| {
                    if v == &expected_proxy {
                        v.as_str().green().to_string()
                    } else {
                        v.as_str().yellow().to_string()
                    }
                })
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    env_table.add_row(vec![
        Cell::new("HTTPS_PROXY"),
        Cell::new(
            https_proxy
                .as_ref()
                .map(|v| {
                    if v == &expected_proxy {
                        v.as_str().green().to_string()
                    } else {
                        v.as_str().yellow().to_string()
                    }
                })
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    env_table.add_row(vec![
        Cell::new("NO_PROXY"),
        Cell::new(
            no_proxy
                .as_ref()
                .map(|v| v.as_str().green().to_string())
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    env_table.add_row(vec![
        Cell::new("SSL_CERT_FILE"),
        Cell::new(
            ssl_cert_file
                .as_ref()
                .map(|v| v.as_str().green().to_string())
                .unwrap_or_else(|| "(not set)".dimmed().to_string()),
        ),
    ]);
    println!("{env_table}");

    if let Some(ref current_http) = http_proxy {
        if current_http != &expected_proxy {
            style::warning(&format!(
                "HTTP_PROXY points to {}, expected {}",
                current_http, expected_proxy
            ));
        }
    }
    if let Some(ref current_https) = https_proxy {
        if current_https != &expected_proxy {
            style::warning(&format!(
                "HTTPS_PROXY points to {}, expected {}",
                current_https, expected_proxy
            ));
        }
    }

    println!();
    style::info("To configure environment for this proxy:");
    println!("  {}", "eval $(soth runtime env)".bold());

    style::footer();
    Ok(())
}
