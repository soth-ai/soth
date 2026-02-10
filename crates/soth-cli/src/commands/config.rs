//! Config command - Validate and manage configuration
//!
//! Provides tools to validate YAML configs, show effective settings,
//! and generate example configurations.

use crate::cli_config;
use crate::ConfigCommands;
use anyhow::{Context, Result};
use soth_core::config::{HostFilterMode, SothConfig};
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

/// Run the config command
pub async fn run(global_config: Option<PathBuf>, action: ConfigCommands) -> Result<()> {
    match action {
        ConfigCommands::Validate { file, verbose } => {
            let config_path =
                cli_config::resolve_config_path(file.as_ref(), global_config.as_ref())
                    .unwrap_or_else(|| PathBuf::from("soth.yaml"));
            validate_config(&config_path, verbose).await?;
        }
        ConfigCommands::Show { format } => {
            let selected = cli_config::resolve_config_path(None, global_config.as_ref());
            show_config(selected.as_ref(), &format).await?;
        }
        ConfigCommands::Example { output } => {
            generate_example(output).await?;
        }
    }
    Ok(())
}

/// Validate a configuration file
async fn validate_config(config_path: &PathBuf, verbose: bool) -> Result<()> {
    println!("Validating configuration: {}", config_path.display());
    println!();

    // Check if file exists
    if !config_path.exists() {
        println!("❌ Config file not found: {}", config_path.display());
        return Err(anyhow::anyhow!("Config file not found"));
    }
    println!("✓ Config file exists");

    // Read the file
    let content = fs::read_to_string(config_path)
        .await
        .context("Failed to read config file")?;
    println!("✓ Config file readable ({} bytes)", content.len());

    // Parse as YAML
    let config: SothConfig = match serde_yaml::from_str(&content) {
        Ok(c) => {
            println!("✓ Valid YAML syntax");
            c
        }
        Err(e) => {
            println!("❌ Invalid YAML syntax:");
            println!("   {e}");
            return Err(anyhow::anyhow!("Invalid YAML syntax"));
        }
    };

    // Validate individual sections
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Validate soth proxy section
    validate_forward_proxy(&config, &mut warnings, &mut errors);

    // Validate identity section
    validate_identity(&config, &mut warnings, &mut errors);

    // Validate policy section
    validate_policy(&config, &mut warnings, &mut errors);

    // Validate observe section
    validate_observe(&config, &mut warnings, &mut errors);

    // Validate budget section
    validate_budget(&config, &mut warnings, &mut errors);

    // Print results
    println!();
    if !warnings.is_empty() {
        println!("⚠️  Warnings ({}):", warnings.len());
        for warning in &warnings {
            println!("   - {warning}");
        }
        println!();
    }

    if !errors.is_empty() {
        println!("❌ Errors ({}):", errors.len());
        for error in &errors {
            println!("   - {error}");
        }
        println!();
        return Err(anyhow::anyhow!(
            "Configuration has {} error(s)",
            errors.len()
        ));
    }

    println!("✓ Configuration is valid");

    // Show verbose details
    if verbose {
        println!();
        println!("Configuration Summary:");
        println!("  Version:     {}", config.version);
        println!(
            "  Forward:     {} ({})",
            if config.forward_proxy.enabled {
                "enabled"
            } else {
                "disabled"
            },
            config.forward_proxy.socket_addr()
        );
        println!(
            "  AI hosts:    {}",
            config.forward_proxy.hosts.ai_inference.len()
        );
        println!("  MCP hosts:   {}", config.forward_proxy.hosts.mcp.len());
        println!(
            "  Agent hosts: {}",
            config.forward_proxy.hosts.agent_apps.len()
        );
        println!("  Host mode:   {}", config.forward_proxy.hosts.mode);
        println!(
            "  Block:       {} hosts",
            config.forward_proxy.hosts.block.len()
        );
        println!("  Identity:    {}", config.identity.mode);
        println!(
            "  Policy:      {} ({})",
            if config.policy.enabled {
                "enabled"
            } else {
                "disabled"
            },
            config.policy.mode
        );
        println!(
            "  PII detect:  {}",
            if config.observe.pii_detection {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "  PII scopes:  ai={} mcp={} agent={}",
            config.observe.pii_scopes.ai_inference,
            config.observe.pii_scopes.mcp,
            config.observe.pii_scopes.agent_apps
        );
        println!("  Event tags:  {}", config.observe.event_tags.len());
        println!(
            "  Budget:      {}",
            if config.budget.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );

        // Cache config
        println!();
        println!("Cache Configuration:");
        println!("  Enabled:      {}", config.policy.cache.enabled);
        println!("  L1 TTL:       {:?}", config.policy.cache.l1_ttl);
        println!(
            "  L2 TTL:       {:?}",
            config.policy.cache.effective_l2_ttl()
        );
        println!("  L1 Max:       {}", config.policy.cache.l1_max_entries);
        println!("  L2 Max:       {}", config.policy.cache.l2_max_entries);
    }

    Ok(())
}

/// Validate soth proxy configuration
fn validate_forward_proxy(
    config: &SothConfig,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let proxy = &config.forward_proxy;

    if proxy.address.trim().is_empty() {
        errors.push("forward_proxy.address cannot be empty".to_string());
    }
    if proxy.port == 0 {
        errors.push("forward_proxy.port cannot be 0".to_string());
    }
    if proxy.port < 1024 {
        warnings.push(format!(
            "Port {} may require elevated privileges",
            proxy.port
        ));
    }
    if proxy.hosts.mode == HostFilterMode::Selective
        && proxy.hosts.ai_inference.is_empty()
        && proxy.hosts.mcp.is_empty()
        && proxy.hosts.agent_apps.is_empty()
    {
        warnings.push(
            "No AI/MCP/Agent host patterns configured; traffic will mostly tunnel".to_string(),
        );
    }
    if proxy.hosts.mode == HostFilterMode::Discovery {
        warnings.push(
            "Host mode is discovery; all non-local hosts will be MITM intercepted (higher CPU/memory usage)"
                .to_string(),
        );
    }
}

/// Validate identity configuration
fn validate_identity(config: &SothConfig, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    let mode = &config.identity.mode;
    if !["disabled", "optional", "required"].contains(&mode.as_str()) {
        errors.push(format!(
            "Invalid identity mode '{mode}' (valid: disabled, optional, required)"
        ));
    }

    if mode == "required" && config.identity.key_path.is_none() {
        warnings.push("Identity mode is 'required' but no key_path specified".to_string());
    }
    if mode == "required" {
        warnings.push(
            "Identity mode 'required' is currently downgraded to 'optional' until agentfacts rollout"
                .to_string(),
        );
    }
}

/// Validate policy configuration
fn validate_policy(config: &SothConfig, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    if !config.policy.enabled {
        return;
    }

    let mode = &config.policy.mode;
    if !["audit", "enforce"].contains(&mode.as_str()) {
        errors.push(format!(
            "Invalid policy mode '{mode}' (valid: audit, enforce)"
        ));
    }

    // Cache validation
    if config.policy.cache.l1_ttl.as_secs() == 0 {
        warnings.push("Cache L1 TTL is 0, caching will be ineffective".to_string());
    }

    if config.policy.cache.l1_max_entries == 0 {
        warnings.push("Cache L1 max_entries is 0, caching is disabled".to_string());
    }
}

/// Validate observe configuration
fn validate_observe(config: &SothConfig, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    if !config.observe.enabled {
        warnings.push("Observe is disabled, no logging/PII detection will occur".to_string());
    }

    if config.observe.enabled && !config.observe.pii_detection {
        warnings.push("PII detection is disabled, sensitive data may be logged".to_string());
    }

    if config.observe.enabled
        && config.observe.pii_detection
        && !config.observe.pii_scopes.ai_inference
        && !config.observe.pii_scopes.mcp
        && !config.observe.pii_scopes.agent_apps
    {
        warnings.push("PII detection is enabled but all PII scopes are disabled".to_string());
    }

    if config.observe.buffer_size == 0 {
        warnings.push("Observe buffer_size is 0, logging may be synchronous".to_string());
    }

    let backend = config.observe.storage.backend.to_lowercase();
    if backend != "sqlite" {
        errors.push(format!(
            "Invalid observe.storage.backend '{}' (valid: sqlite)",
            config.observe.storage.backend
        ));
    }
}

/// Validate budget configuration
fn validate_budget(config: &SothConfig, warnings: &mut Vec<String>, _errors: &mut [String]) {
    if !config.budget.enabled {
        return;
    }

    if config.budget.limits.is_empty() {
        warnings.push("Budget is enabled but no limits are configured".to_string());
    }

    for (i, limit) in config.budget.limits.iter().enumerate() {
        if limit.daily.is_none() && limit.weekly.is_none() && limit.monthly.is_none() {
            warnings.push(format!("Budget limit {i} has no actual limits set"));
        }
    }
}

/// Show the effective configuration
async fn show_config(config_path: Option<&PathBuf>, format: &str) -> Result<()> {
    let config = if let Some(path) = config_path {
        if path.exists() {
            let content = fs::read_to_string(path).await?;
            serde_yaml::from_str::<SothConfig>(&content)?
        } else {
            info!("Config file {} not found, showing defaults", path.display());
            SothConfig::default()
        }
    } else {
        info!("No config file selected, showing defaults");
        SothConfig::default()
    };

    match format {
        "json" => {
            let output = serde_json::to_string_pretty(&config)?;
            println!("{output}");
        }
        _ => {
            let output = serde_yaml::to_string(&config)?;
            println!("{output}");
        }
    }

    Ok(())
}

/// Generate an example configuration
async fn generate_example(output: Option<PathBuf>) -> Result<()> {
    let example = include_str!("../../../../soth.example.yaml");

    match output {
        Some(path) => {
            fs::write(&path, example).await?;
            println!("Example configuration written to: {}", path.display());
        }
        None => {
            println!("{example}");
        }
    }

    Ok(())
}
