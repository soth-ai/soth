//! Config command - Validate and manage configuration
//!
//! Provides tools to validate YAML configs, show effective settings,
//! and generate example configurations.

use crate::ConfigCommands;
use anyhow::{Context, Result};
use soth_core::config::SothConfig;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

/// Run the config command
pub async fn run(default_config: PathBuf, action: ConfigCommands) -> Result<()> {
    match action {
        ConfigCommands::Validate { file, verbose } => {
            let config_path = file.unwrap_or(default_config);
            validate_config(&config_path, verbose).await?;
        }
        ConfigCommands::Show { format } => {
            show_config(&default_config, &format).await?;
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

    // Validate server section
    validate_server(&config, &mut warnings, &mut errors);

    // Validate upstream section
    validate_upstream(&config, &mut warnings, &mut errors);

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
        println!("  Transport:   {}", config.server.transport);
        println!("  Listen:      {}", config.server.listen.socket_addr());
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

/// Validate server configuration
fn validate_server(config: &SothConfig, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    let transport = &config.server.transport;
    if !["stdio", "sse", "http"].contains(&transport.as_str()) {
        errors.push(format!(
            "Invalid transport '{transport}' (valid: stdio, sse, http)"
        ));
    }

    if transport != "stdio" {
        if config.server.listen.port == 0 {
            errors.push("Listen port cannot be 0 for SSE/HTTP transport".to_string());
        }
        if config.server.listen.port < 1024 && config.server.listen.port > 0 {
            warnings.push(format!(
                "Port {} requires root privileges",
                config.server.listen.port
            ));
        }
    }

    if config.server.max_connections == 0 {
        warnings.push("max_connections is 0, no connections will be accepted".to_string());
    }
}

/// Validate upstream configuration
fn validate_upstream(config: &SothConfig, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    let has_command = config.upstream.command.is_some();
    let has_url = config.upstream.url.is_some();

    if !has_command && !has_url {
        errors.push("Upstream must have either 'command' or 'url' configured".to_string());
    }

    if has_command && has_url {
        warnings.push("Both 'command' and 'url' specified for upstream; 'command' will be used for stdio transport".to_string());
    }

    if config.server.transport == "stdio" && !has_command {
        errors.push("stdio transport requires upstream 'command' to be set".to_string());
    }

    if (config.server.transport == "sse" || config.server.transport == "http") && !has_url {
        warnings.push("SSE/HTTP transport may require upstream 'url' to be set".to_string());
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

    if config.observe.buffer_size == 0 {
        warnings.push("Observe buffer_size is 0, logging may be synchronous".to_string());
    }

    let backend = config.observe.storage.backend.to_lowercase();
    if !["local", "jsonl", "sqlite"].contains(&backend.as_str()) {
        errors.push(format!(
            "Invalid observe.storage.backend '{}' (valid: local, jsonl, sqlite)",
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
async fn show_config(config_path: &PathBuf, format: &str) -> Result<()> {
    let config = if config_path.exists() {
        let content = fs::read_to_string(config_path).await?;
        serde_yaml::from_str::<SothConfig>(&content)?
    } else {
        info!("Config file not found, showing defaults");
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
