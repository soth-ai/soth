//! Initialize command

use anyhow::Result;
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
  autostart_on_boot: true
  capture_max_body_bytes: 15728640
  process_attribution:
    enabled: true
    lookup_timeout: "200ms"
    cache_ttl: "30s"
  tunnel_debug:
    enabled: false
    include_noise: false
    min_log_interval: "30s"
  hosts:
    mode: "discovery"  # discovery | selective
    # Classification/interception is bundle-driven.
    # Keep only explicit local block rules here.
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
  collector:
    enabled: true
    auto_discover_sources: true
    frontload_on_start: true
    frontload_force_first_run: true
    frontload_reset_offsets_on_start: false
    frontload_max_cycles: 24
    frontload_max_read_bytes_per_source: 8388608
    poll_interval_secs: 5
    max_read_bytes_per_source: 524288
    max_line_bytes: 65536
    sources: []
    sqlite_sources: []
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
  frontload_enabled: true
  frontload_max_events_per_batch: 1500
  frontload_max_compressed_batch_bytes: 33554432
  frontload_hard_events_cap: 5000
  frontload_hard_compressed_cap_bytes: 67108864
  frontload_exchange_upload_path: null
  body_upload_max_bytes: 15728640
  cache_path: "~/.soth/cloud_config_cache.json"
  tags: {}

# Unified exchange v2 pipeline (disabled by default)
exchange_v2:
  enabled: false
  inline_max_bytes: 262144
  max_body_bytes: 15728640
  max_stream_buffer_bytes: 15728640
  stream_idle_timeout: "30s"
  stream_max_duration: "10m"
  spool_path: "~/.soth/runtime/exchange-spool.db"
  spool_max_inflight: 10000
  upload_queue_max_items: 20000
  upload_queue_max_bytes: 536870912
  recover_inflight_on_start: true
"#;

const DEFAULT_POLICY: &str = include_str!("../../assets/policies/default.yaml");

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
    println!("  1. Edit soth.yaml for runtime/proxy settings");
    println!("  2. Generate an identity: soth identity generate");
    println!("  3. Start the sensor lifecycle: soth up");
    println!();

    Ok(())
}
