//! Initialize command

use anyhow::Result;
use soth_core::config::HostFilterConfig;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

const DEFAULT_CONFIG: &str = r#"# SOTH Configuration
version: "1.0"

# Forward proxy configuration
forward_proxy:
  enabled: true
  address: "127.0.0.1"
  port: 8080
  capture_max_body_bytes: 15728640
  hosts:
    mode: "selective"  # selective | discovery
    # Domain classes are loaded from dedicated files (recommended).
    # If a file is configured, it replaces the corresponding inline list.
    domain_files:
      ai_inference: "./domains/ai_inference.yaml"
      mcp: "./domains/mcp.yaml"
      agent_apps: "./domains/agent_apps.yaml"
    ai_inference: []
    mcp: []
    agent_apps: []
    block: []

# Identity configuration
identity:
  mode: "optional"  # disabled | optional | required
  key_path: "~/.soth/identity.pem"
  trust_store_path: "~/.soth/trust_store"

# Unified crypto identity rollout
crypto_identity:
  enabled: false
  mode: "audit" # audit | enforce
  enforce_principals: []
  signing:
    envelope_metadata_only: true
    algorithm: "ed25519"
  hierarchy:
    derivation: "slip10_hardened"
    rotation_days: 90
  merkle:
    enabled: true
    seal_interval: "3s"
    max_events_per_batch: 500
  tls:
    bind_to_org_identity: true
    leaf_ttl: "24h"

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
  pii_scopes:
    ai_inference: true
    mcp: true
    agent_apps: true
  event_tags:
    project: "local-dev"
    environment: "development"
  log_requests: true
  log_responses: true
  tamper_proof: true
  storage:
    backend: "sqlite"
    path: "./logs/observations.db"
    retention:
      ai_proxy_days: 7
      mcp_days: 7
      agent_app_days: 1
      clusters_days: 14
      rollups_days: 90
      vacuum_after_cleanup: true
    inline_threshold_bytes: 4096

# Budget configuration
budget:
  enabled: true
  db_path: "~/.soth/budget.db"
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

# Cloud sync configuration (optional)
cloud:
  enabled: false
  api_key: null
  endpoint: "https://api.soth.ai"
  sync_interval_secs: 60
  config_pull_interval_secs: 300
  config_debounce_secs: 6
  body_upload_enabled: true
  metadata_max_events_per_batch: 200
  metadata_max_compressed_batch_bytes: 5242880
  body_upload_max_bytes: 15728640
  cache_path: "~/.soth/cloud_config_cache.json"
  tags: {}
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

fn render_domain_list(comment: &str, domains: &[String]) -> String {
    let mut out = String::new();
    out.push_str(comment);
    out.push('\n');
    out.push_str("domains:\n");
    for domain in domains {
        out.push_str(&format!("  - \"{}\"\n", domain));
    }
    out
}

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

    // Create domain-list files from canonical defaults.
    let default_hosts = HostFilterConfig::default();
    let ai_domain_content =
        render_domain_list("# AI inference/API domains", &default_hosts.ai_inference);
    let mcp_domain_content =
        render_domain_list("# MCP transport/service domains", &default_hosts.mcp);
    let agent_domain_content = render_domain_list(
        "# Agent app domains (chat/web/IDE agents)",
        &default_hosts.agent_apps,
    );

    let domains_dir = output.join("domains");
    fs::create_dir_all(&domains_dir).await?;
    let ai_domains_path = domains_dir.join("ai_inference.yaml");
    if !ai_domains_path.exists() {
        fs::write(&ai_domains_path, ai_domain_content).await?;
        info!("Created AI domain list: {:?}", ai_domains_path);
    }
    let mcp_domains_path = domains_dir.join("mcp.yaml");
    if !mcp_domains_path.exists() {
        fs::write(&mcp_domains_path, mcp_domain_content).await?;
        info!("Created MCP domain list: {:?}", mcp_domains_path);
    }
    let agent_domains_path = domains_dir.join("agent_apps.yaml");
    if !agent_domains_path.exists() {
        fs::write(&agent_domains_path, agent_domain_content).await?;
        info!("Created agent app domain list: {:?}", agent_domains_path);
    }

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
    println!("  1. Edit domains/*.yaml (ai_inference, mcp, agent_apps)");
    println!("  2. Edit soth.yaml for runtime/proxy settings");
    println!("  3. Generate an identity: soth identity generate");
    println!("  4. Start the proxy: soth proxy start");
    println!();

    Ok(())
}
