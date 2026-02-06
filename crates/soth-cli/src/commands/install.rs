//! Install/Uninstall commands - Auto-configure MCP clients
//!
//! Transforms MCP client configurations to route all servers through `soth wrap`.

use crate::style;
use anyhow::{Context, Result};
use chrono::Utc;
use comfy_table::Cell;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use soth_core::event_logger::default_event_log_write_path;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::info;

/// Known MCP clients and their config locations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpClient {
    ClaudeDesktop,
    Cursor,
    Windsurf,
    ClaudeCode,
}

impl McpClient {
    fn name(&self) -> &'static str {
        match self {
            McpClient::ClaudeDesktop => "Claude Desktop",
            McpClient::Cursor => "Cursor",
            McpClient::Windsurf => "Windsurf",
            McpClient::ClaudeCode => "Claude Code",
        }
    }

    fn id(&self) -> &'static str {
        match self {
            McpClient::ClaudeDesktop => "claude-desktop",
            McpClient::Cursor => "cursor",
            McpClient::Windsurf => "windsurf",
            McpClient::ClaudeCode => "claude-code",
        }
    }

    fn config_path(&self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;

        match self {
            McpClient::ClaudeDesktop => {
                #[cfg(target_os = "macos")]
                {
                    Some(home.join("Library/Application Support/Claude/claude_desktop_config.json"))
                }
                #[cfg(target_os = "linux")]
                {
                    Some(home.join(".config/Claude/claude_desktop_config.json"))
                }
                #[cfg(target_os = "windows")]
                {
                    dirs::config_dir().map(|c| c.join("Claude/claude_desktop_config.json"))
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                {
                    None
                }
            }
            McpClient::Cursor => Some(home.join(".cursor/mcp.json")),
            McpClient::Windsurf => Some(home.join(".codeium/windsurf/mcp_config.json")),
            McpClient::ClaudeCode => {
                // Claude Code uses ~/.mcp.json for global MCP servers
                Some(home.join(".mcp.json"))
            }
        }
    }

    fn all() -> Vec<McpClient> {
        vec![
            McpClient::ClaudeDesktop,
            McpClient::Cursor,
            McpClient::Windsurf,
            McpClient::ClaudeCode,
        ]
    }

    fn from_str(s: &str) -> Option<McpClient> {
        match s.to_lowercase().as_str() {
            "claude-desktop" | "claude_desktop" | "claudedesktop" => Some(McpClient::ClaudeDesktop),
            "cursor" => Some(McpClient::Cursor),
            "windsurf" => Some(McpClient::Windsurf),
            "claude-code" | "claude_code" | "claudecode" => Some(McpClient::ClaudeCode),
            _ => None,
        }
    }
}

/// MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// MCP client configuration file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClientConfig {
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: HashMap<String, McpServerConfig>,

    // Preserve other fields
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// Run install command
pub async fn run_install(target: Option<String>, dry_run: bool) -> Result<()> {
    style::header("SOTH Installation");

    // Verify soth is in PATH
    let soth_path = find_soth_binary()?;
    style::kv("Binary", &soth_path);
    println!();

    let clients = if let Some(ref t) = target {
        let client = McpClient::from_str(t).with_context(|| {
            format!(
                "Unknown client: {}. Valid: claude-desktop, cursor, windsurf",
                t
            )
        })?;
        vec![client]
    } else {
        McpClient::all()
    };

    let mut results = Vec::new();
    for client in &clients {
        let result = install_for_client(*client, &soth_path, dry_run).await;
        results.push((*client, result));
    }

    // Show results table
    println!();
    style::subtitle("Results");

    let mut table = style::table();
    table.set_header(vec!["Client", "Status", "Details"]);

    for (client, result) in &results {
        match result {
            Ok(status) => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(format!("{} Success", style::CHECK.green())),
                    Cell::new(status),
                ]);
            }
            Err(e) => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(format!("{} Failed", style::CROSS.red())),
                    Cell::new(style::truncate(&e.to_string(), 30)),
                ]);
            }
        }
    }
    println!("{table}");

    if !dry_run {
        println!();
        style::success("Installation complete");
        style::info("Please restart your MCP clients.");
        println!();
        match get_log_path() {
            Ok(path) => style::kv("Log file", &path.display().to_string()),
            Err(_) => style::kv("Log file", "~/.soth/logs/events.db"),
        }
        println!();
        style::info("Run 'soth tail' to see live events.");
    }

    style::footer();
    Ok(())
}

/// Run uninstall command
pub async fn run_uninstall(target: Option<String>) -> Result<()> {
    style::header("SOTH Uninstallation");

    let clients = if let Some(ref t) = target {
        let client = McpClient::from_str(t).with_context(|| format!("Unknown client: {}", t))?;
        vec![client]
    } else {
        McpClient::all()
    };

    let mut results = Vec::new();
    for client in &clients {
        let result = uninstall_for_client(*client).await;
        results.push((*client, result));
    }

    // Show results table
    println!();
    style::subtitle("Results");

    let mut table = style::table();
    table.set_header(vec!["Client", "Status", "Details"]);

    for (client, result) in &results {
        match result {
            Ok(status) => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(format!("{} Success", style::CHECK.green())),
                    Cell::new(status),
                ]);
            }
            Err(e) => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(format!("{} Failed", style::CROSS.red())),
                    Cell::new(style::truncate(&e.to_string(), 30)),
                ]);
            }
        }
    }
    println!("{table}");

    println!();
    style::success("Uninstallation complete");
    style::info("Please restart your MCP clients.");

    style::footer();
    Ok(())
}

/// Run status command
pub async fn run_status() -> Result<()> {
    style::header("Installation Status");

    let mut table = style::table();
    table.set_header(vec!["Client", "Config Path", "Status"]);

    for client in McpClient::all() {
        let config_path = match client.config_path() {
            Some(p) => p,
            None => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new("-".dimmed().to_string()),
                    Cell::new("config path unknown".dimmed().to_string()),
                ]);
                continue;
            }
        };

        if !config_path.exists() {
            table.add_row(vec![
                Cell::new(client.name()),
                Cell::new(
                    style::truncate(&config_path.display().to_string(), 35)
                        .dimmed()
                        .to_string(),
                ),
                Cell::new(format!("{} not configured", style::CIRCLE_EMPTY.dimmed())),
            ]);
            continue;
        }

        match check_client_status(client, &config_path).await {
            Ok(status) => {
                let status_icon = if status.contains("fully wrapped") {
                    format!("{} {}", style::CHECK.green(), status)
                } else if status.contains("partially") {
                    format!("{} {}", style::WARNING.yellow(), status)
                } else if status.contains("not wrapped") {
                    format!("{} {}", style::CIRCLE_EMPTY.dimmed(), status)
                } else {
                    status.clone()
                };
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(
                        style::truncate(&config_path.display().to_string(), 35)
                            .dimmed()
                            .to_string(),
                    ),
                    Cell::new(status_icon),
                ]);
            }
            Err(e) => {
                table.add_row(vec![
                    Cell::new(client.name()),
                    Cell::new(
                        style::truncate(&config_path.display().to_string(), 35)
                            .dimmed()
                            .to_string(),
                    ),
                    Cell::new(format!("{} {}", style::CROSS.red(), e)),
                ]);
            }
        }
    }
    println!("{table}");

    // Check log file
    let log_path = get_log_path()?;
    println!();
    style::subtitle("Log File");
    if log_path.exists() {
        let metadata = std::fs::metadata(&log_path)?;
        style::kv("Path", &log_path.display().to_string());
        style::kv("Size", &style::format_bytes(metadata.len()));
    } else {
        style::kv("Path", &log_path.display().to_string());
        style::kv("Status", &"not yet created".dimmed().to_string());
    }

    style::footer();
    Ok(())
}

async fn install_for_client(client: McpClient, soth_path: &str, dry_run: bool) -> Result<String> {
    let config_path = client
        .config_path()
        .context("Config path not available for this platform")?;

    if !config_path.exists() {
        return Ok(format!(
            "skipped (no config at {})",
            style::truncate(&config_path.display().to_string(), 20)
        ));
    }

    // Read current config
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config: {:?}", config_path))?;

    let mut config: McpClientConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config: {:?}", config_path))?;

    if config.mcp_servers.is_empty() {
        return Ok("skipped (no MCP servers)".to_string());
    }

    // Check if already wrapped
    let already_wrapped = config.mcp_servers.values().all(is_wrapped);

    if already_wrapped {
        return Ok("already wrapped".to_string());
    }

    // Transform servers
    let mut transformed = 0;
    for (name, server) in config.mcp_servers.iter_mut() {
        if !is_wrapped(server) {
            wrap_server(name, server, soth_path);
            transformed += 1;
        }
    }

    if dry_run {
        return Ok(format!("would wrap {} server(s)", transformed));
    }

    // Backup original
    backup_config(&config_path)?;

    // Write transformed config
    let new_content = serde_json::to_string_pretty(&config)?;
    std::fs::write(&config_path, new_content)
        .with_context(|| format!("Failed to write config: {:?}", config_path))?;

    Ok(format!("wrapped {} server(s)", transformed))
}

async fn uninstall_for_client(client: McpClient) -> Result<String> {
    let config_path = client
        .config_path()
        .context("Config path not available for this platform")?;

    if !config_path.exists() {
        return Ok("skipped (no config file)".to_string());
    }

    // Try to restore from backup first
    let backup_dir = get_backup_dir()?;

    // Find most recent backup
    let mut backups: Vec<_> = std::fs::read_dir(&backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{}-", client.id()))
        })
        .collect();

    backups.sort_by_key(|e| std::cmp::Reverse(e.metadata().ok().and_then(|m| m.modified().ok())));

    if let Some(backup) = backups.first() {
        // Restore from backup
        std::fs::copy(backup.path(), &config_path)?;
        return Ok("restored from backup".to_string());
    }

    // No backup - manually unwrap
    let content = std::fs::read_to_string(&config_path)?;
    let mut config: McpClientConfig = serde_json::from_str(&content)?;

    let mut unwrapped = 0;
    for (_name, server) in config.mcp_servers.iter_mut() {
        if is_wrapped(server) {
            unwrap_server(server)?;
            unwrapped += 1;
        }
    }

    if unwrapped > 0 {
        let new_content = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_path, new_content)?;
        return Ok(format!("unwrapped {} server(s)", unwrapped));
    }

    Ok("not wrapped".to_string())
}

async fn check_client_status(_client: McpClient, config_path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(config_path)?;
    let config: McpClientConfig = serde_json::from_str(&content)?;

    if config.mcp_servers.is_empty() {
        return Ok("no MCP servers".to_string());
    }

    let wrapped_count = config
        .mcp_servers
        .values()
        .filter(|s| is_wrapped(s))
        .count();
    let total = config.mcp_servers.len();

    if wrapped_count == 0 {
        Ok(format!("not wrapped ({} servers)", total))
    } else if wrapped_count == total {
        Ok(format!("fully wrapped ({} servers)", total))
    } else {
        Ok(format!(
            "partially wrapped ({}/{} servers)",
            wrapped_count, total
        ))
    }
}

fn is_wrapped(server: &McpServerConfig) -> bool {
    // Check if command is "soth" or ends with "/soth" (full path)
    let is_soth = server.command == "soth" || server.command.ends_with("/soth");
    is_soth && server.args.first().map(|a| a == "wrap").unwrap_or(false)
}

fn wrap_server(name: &str, server: &mut McpServerConfig, soth_path: &str) {
    let original_command = server.command.clone();
    let original_args = server.args.clone();

    server.command = soth_path.to_string();
    server.args = vec![
        "wrap".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--".to_string(),
        original_command,
    ];
    server.args.extend(original_args);
}

fn unwrap_server(server: &mut McpServerConfig) -> Result<()> {
    // Find the -- separator
    let separator_pos = server
        .args
        .iter()
        .position(|a| a == "--")
        .context("Malformed wrap config: missing '--' separator")?;

    // Extract original command and args
    if separator_pos + 1 >= server.args.len() {
        anyhow::bail!("Malformed wrap config: no command after '--'");
    }

    let original_command = server.args[separator_pos + 1].clone();
    let original_args: Vec<String> = server.args[separator_pos + 2..].to_vec();

    server.command = original_command;
    server.args = original_args;

    Ok(())
}

fn find_soth_binary() -> Result<String> {
    // First try current exe
    if let Ok(exe) = std::env::current_exe() {
        return Ok(exe.to_string_lossy().to_string());
    }

    // Try PATH
    if let Ok(output) = std::process::Command::new("which").arg("soth").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    // Default to just "soth" and hope it's in PATH
    Ok("soth".to_string())
}

fn backup_config(config_path: &PathBuf) -> Result<()> {
    let backup_dir = get_backup_dir()?;
    std::fs::create_dir_all(&backup_dir)?;

    let filename = config_path
        .file_name()
        .context("No filename")?
        .to_string_lossy();

    // Include client name in backup
    let client_name = config_path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let backup_name = format!("{}-{}-{}", client_name.to_lowercase(), timestamp, filename);
    let backup_path = backup_dir.join(backup_name);

    std::fs::copy(config_path, &backup_path)?;
    info!("Backed up config to {:?}", backup_path);

    Ok(())
}

fn get_backup_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".soth").join("backups"))
}

fn get_log_path() -> Result<PathBuf> {
    default_event_log_write_path().context("Could not determine default event log path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_server() {
        let mut server = McpServerConfig {
            command: "npx".to_string(),
            args: vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ],
            env: HashMap::new(),
        };

        wrap_server("postgres", &mut server, "/usr/local/bin/soth");

        assert_eq!(server.command, "/usr/local/bin/soth");
        assert_eq!(server.args[0], "wrap");
        assert_eq!(server.args[1], "--name");
        assert_eq!(server.args[2], "postgres");
        assert_eq!(server.args[3], "--");
        assert_eq!(server.args[4], "npx");
        assert_eq!(server.args[5], "-y");
    }

    #[test]
    fn test_unwrap_server() {
        let mut server = McpServerConfig {
            command: "soth".to_string(),
            args: vec![
                "wrap".to_string(),
                "--name".to_string(),
                "postgres".to_string(),
                "--".to_string(),
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ],
            env: HashMap::new(),
        };

        unwrap_server(&mut server).unwrap();

        assert_eq!(server.command, "npx");
        assert_eq!(
            server.args,
            vec!["-y", "@modelcontextprotocol/server-postgres"]
        );
    }

    #[test]
    fn test_is_wrapped() {
        let wrapped = McpServerConfig {
            command: "soth".to_string(),
            args: vec!["wrap".to_string(), "--".to_string(), "npx".to_string()],
            env: HashMap::new(),
        };
        assert!(is_wrapped(&wrapped));

        let not_wrapped = McpServerConfig {
            command: "npx".to_string(),
            args: vec!["-y".to_string(), "server".to_string()],
            env: HashMap::new(),
        };
        assert!(!is_wrapped(&not_wrapped));
    }

    #[test]
    fn test_client_from_str() {
        assert_eq!(
            McpClient::from_str("claude-desktop"),
            Some(McpClient::ClaudeDesktop)
        );
        assert_eq!(McpClient::from_str("CURSOR"), Some(McpClient::Cursor));
        assert_eq!(McpClient::from_str("unknown"), None);
    }
}
