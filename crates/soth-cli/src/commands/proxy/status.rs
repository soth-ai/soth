//! Proxy status command

use crate::cli_config;
use crate::style;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use serde::Deserialize;
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

    // Cloud enrollment state
    println!();
    style::subtitle("Cloud Enrollment");

    let cloud_enabled = config.cloud.enabled;
    let api_key = config
        .cloud
        .api_key
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty());
    let exchange_v2_enabled = config.exchange_v2.enabled;

    let mut cloud_table = style::table();
    cloud_table.set_header(vec!["Property", "Value"]);
    let enrollment_display = if cloud_enabled && api_key.is_some() {
        format!("{} Enrolled", style::CHECK.green())
    } else if cloud_enabled {
        format!("{} Cloud enabled (missing API key)", style::CROSS.red())
    } else {
        format!("{} Local only", style::CIRCLE_FILLED.yellow())
    };
    cloud_table.add_row(vec![Cell::new("Enrollment"), Cell::new(enrollment_display)]);
    cloud_table.add_row(vec![
        Cell::new("Cloud Enabled"),
        Cell::new(if cloud_enabled {
            "true".green().to_string()
        } else {
            "false".yellow().to_string()
        }),
    ]);
    cloud_table.add_row(vec![
        Cell::new("Endpoint"),
        Cell::new(config.cloud.endpoint.as_str().cyan().to_string()),
    ]);
    cloud_table.add_row(vec![
        Cell::new("API Key"),
        Cell::new(
            api_key
                .map(mask_secret)
                .unwrap_or_else(|| "(not configured)".dimmed().to_string()),
        ),
    ]);
    cloud_table.add_row(vec![
        Cell::new("Exchange V2"),
        Cell::new(if exchange_v2_enabled {
            "enabled".green().to_string()
        } else {
            "disabled".yellow().to_string()
        }),
    ]);
    let workspace_id = config
        .cloud
        .tags
        .get("workspace_id")
        .or_else(|| config.cloud.tags.get("team_id"))
        .map(String::as_str)
        .unwrap_or("-");
    cloud_table.add_row(vec![
        Cell::new("Workspace"),
        Cell::new(workspace_id.to_string()),
    ]);
    let device_id = config
        .cloud
        .tags
        .get("device_id")
        .map(String::as_str)
        .unwrap_or("-");
    cloud_table.add_row(vec![
        Cell::new("Device ID"),
        Cell::new(device_id.to_string()),
    ]);
    if let Some(runtime_state) = load_registry_runtime_state() {
        cloud_table.add_row(vec![
            Cell::new("Registry Source"),
            Cell::new(runtime_state.source),
        ]);
        cloud_table.add_row(vec![
            Cell::new("Registry Failures"),
            Cell::new(runtime_state.consecutive_failures.to_string()),
        ]);
        cloud_table.add_row(vec![
            Cell::new("Registry Last Success"),
            Cell::new(runtime_state.last_success_unix_secs.to_string()),
        ]);
    }
    println!("{cloud_table}");

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

fn mask_secret(raw: &str) -> String {
    if raw.len() <= 10 {
        return "***".to_string();
    }
    let head = &raw[..6];
    let tail = &raw[raw.len() - 4..];
    format!("{head}…{tail}")
}

#[derive(Debug, Deserialize)]
struct RegistryRuntimeState {
    source: String,
    consecutive_failures: u64,
    last_success_unix_secs: u64,
}

fn load_registry_runtime_state() -> Option<RegistryRuntimeState> {
    let path = dirs::home_dir()
        .map(|home| {
            home.join(".soth")
                .join("runtime")
                .join("registry_runtime_state.json")
        })
        .unwrap_or_else(|| PathBuf::from(".soth/runtime/registry_runtime_state.json"));
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<RegistryRuntimeState>(&body).ok()
}
