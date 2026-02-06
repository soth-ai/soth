//! Initialize command

use anyhow::Result;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

const DEFAULT_CONFIG: &str = r#"# SOTH Configuration
version: "1.0"

server:
  listen:
    address: "127.0.0.1"
    port: 3000
  transport: "stdio"  # stdio | sse | http

# Upstream MCP server configuration
upstream:
  command: "npx"
  args:
    - "-y"
    - "@modelcontextprotocol/server-filesystem"
    - "/tmp"

# Identity configuration
identity:
  mode: "optional"  # disabled | optional | required
  key_path: "~/.soth/identity.pem"
  trust_store_path: "~/.soth/trust_store"

# Policy configuration
policy:
  enabled: true
  mode: "enforce"  # audit | enforce
  policy_dir: "policies"
  data_file: null

# Observation configuration
observe:
  enabled: true
  pii_detection: true
  log_requests: true
  log_responses: true
  tamper_proof: true
  storage:
    backend: "sqlite"
    path: "./logs/observations.db"

# Budget configuration
budget:
  enabled: true
  storage_path: "./budget.db"
  limits:
    - scope: "global"
      daily: 50.00
      weekly: null
      monthly: 500.00
  alerts:
    - threshold_percent: 50
      action: "notify"
    - threshold_percent: 80
      action: "warn"
    - threshold_percent: 100
      action: "block"
"#;

const DEFAULT_POLICY: &str = r#"# Default SOTH Policy
# This policy provides basic safety controls

name: default
description: Default safety policy for MCP traffic

rules:
  # Block dangerous tools by default
  - name: block_dangerous_tools
    description: Block tools that could be dangerous
    conditions:
      method: "tools/call"
      tool:
        in:
          - "shell_exec"
          - "system_command"
          - "eval"
          - "delete_all"
    action: deny
    message: "This tool is blocked by policy"

  # Require identity for sensitive operations
  - name: require_identity_for_write
    description: Require verified identity for write operations
    conditions:
      method: "tools/call"
      tool:
        matches: "write.*|delete.*|update.*"
      identity_verified: false
    action: deny
    message: "Verified identity required for write operations"

  # Rate limit sampling requests
  - name: rate_limit_sampling
    description: Rate limit sampling requests
    conditions:
      method: "sampling/createMessage"
    action: rate_limit
    rate_limit:
      requests: 10
      window_seconds: 60

  # Log all tool calls
  - name: log_tool_calls
    description: Log all tool calls for audit
    conditions:
      method: "tools/call"
    action: log

  # Allow everything else
  - name: allow_default
    description: Allow all other requests
    conditions: {}
    action: allow
"#;

/// Run the init command
pub async fn run(output: PathBuf) -> Result<()> {
    info!("Initializing SOTH in {:?}", output);

    // Create output directory
    fs::create_dir_all(&output).await?;

    // Create config file
    let config_path = output.join("soth.yaml");
    if !config_path.exists() {
        fs::write(&config_path, DEFAULT_CONFIG).await?;
        info!("Created config file: {:?}", config_path);
    } else {
        info!("Config file already exists: {:?}", config_path);
    }

    // Create policies directory
    let policies_dir = output.join("policies");
    fs::create_dir_all(&policies_dir).await?;

    // Create default policy
    let policy_path = policies_dir.join("default.yaml");
    if !policy_path.exists() {
        fs::write(&policy_path, DEFAULT_POLICY).await?;
        info!("Created default policy: {:?}", policy_path);
    }

    // Create logs directory
    let logs_dir = output.join("logs");
    fs::create_dir_all(&logs_dir).await?;
    info!("Created logs directory: {:?}", logs_dir);

    // Create .soth directory in home
    if let Some(home) = dirs::home_dir() {
        let soth_dir = home.join(".soth");
        fs::create_dir_all(&soth_dir).await?;

        let trust_store = soth_dir.join("trust_store");
        fs::create_dir_all(&trust_store).await?;

        info!("Created SOTH home directory: {:?}", soth_dir);
    }

    println!("\n✓ SOTH initialized successfully!");
    println!("\nNext steps:");
    println!("  1. Edit soth.yaml to configure your upstream server");
    println!("  2. Generate an identity: soth identity generate");
    println!("  3. Start the proxy: soth start");
    println!();

    Ok(())
}
