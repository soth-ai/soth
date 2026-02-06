//! Configuration loader with environment variable overrides
//!
//! Loads configuration from YAML files with support for environment variable overrides.

use crate::config::types::SothConfig;
use crate::error::{Result, SothError};
use std::path::Path;

/// Load configuration from a YAML file
pub fn load_config(path: impl AsRef<Path>) -> Result<SothConfig> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(SothError::ConfigNotFound(path.display().to_string()));
    }

    let content = std::fs::read_to_string(path)?;
    let mut config: SothConfig = serde_yaml::from_str(&content)?;

    // Apply environment variable overrides
    apply_env_overrides(&mut config);

    Ok(config)
}

/// Load configuration from a string
pub fn load_config_from_str(content: &str) -> Result<SothConfig> {
    let mut config: SothConfig = serde_yaml::from_str(content)?;
    apply_env_overrides(&mut config);
    Ok(config)
}

/// Apply environment variable overrides to the configuration
fn apply_env_overrides(config: &mut SothConfig) {
    // Server overrides
    if let Ok(addr) = std::env::var("SOTH_LISTEN_ADDRESS") {
        config.server.listen.address = addr;
    }
    if let Ok(port) = std::env::var("SOTH_LISTEN_PORT") {
        if let Ok(p) = port.parse() {
            config.server.listen.port = p;
        }
    }
    if let Ok(transport) = std::env::var("SOTH_TRANSPORT") {
        config.server.transport = transport;
    }

    // Upstream overrides
    if let Ok(url) = std::env::var("SOTH_UPSTREAM_URL") {
        config.upstream.url = Some(url);
    }
    if let Ok(cmd) = std::env::var("SOTH_UPSTREAM_COMMAND") {
        config.upstream.command = Some(cmd);
    }

    // Identity overrides
    if let Ok(mode) = std::env::var("SOTH_IDENTITY_MODE") {
        config.identity.mode = mode;
    }
    if let Ok(path) = std::env::var("SOTH_IDENTITY_KEY_PATH") {
        config.identity.key_path = Some(path.into());
    }

    // Policy overrides
    if let Ok(enabled) = std::env::var("SOTH_POLICY_ENABLED") {
        config.policy.enabled = enabled.parse().unwrap_or(false);
    }
    if let Ok(mode) = std::env::var("SOTH_POLICY_MODE") {
        config.policy.mode = mode;
    }
    if let Ok(dir) = std::env::var("SOTH_POLICY_DIR") {
        config.policy.policy_dir = Some(dir.into());
    }

    // Observe overrides
    if let Ok(enabled) = std::env::var("SOTH_OBSERVE_ENABLED") {
        config.observe.enabled = enabled.parse().unwrap_or(true);
    }
    if let Ok(pii) = std::env::var("SOTH_OBSERVE_PII_DETECTION") {
        config.observe.pii_detection = pii.parse().unwrap_or(true);
    }

    // Budget overrides
    if let Ok(enabled) = std::env::var("SOTH_BUDGET_ENABLED") {
        config.budget.enabled = enabled.parse().unwrap_or(false);
    }

    // Logging overrides
    if let Ok(level) = std::env::var("SOTH_LOG_LEVEL") {
        config.logging.level = level;
    }
    if let Ok(format) = std::env::var("SOTH_LOG_FORMAT") {
        config.logging.format = format;
    }
}

/// Expand tilde and environment variables in paths
pub fn expand_path(path: &Path) -> std::path::PathBuf {
    let path_str = path.to_string_lossy();

    // Expand ~ to home directory
    let expanded = if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(stripped)
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    // Expand environment variables
    let path_str = expanded.to_string_lossy();
    let re = regex::Regex::new(r"\$\{?([A-Z_][A-Z0-9_]*)\}?").unwrap();
    let result = re.replace_all(&path_str, |caps: &regex::Captures| {
        std::env::var(&caps[1]).unwrap_or_default()
    });

    std::path::PathBuf::from(result.to_string())
}

// Add dirs dependency for home_dir
mod dirs {
    pub fn home_dir() -> Option<std::path::PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(std::path::PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_from_str() {
        let yaml = r#"
version: "1.0"
server:
  listen:
    port: 8080
"#;
        let config = load_config_from_str(yaml).unwrap();
        assert_eq!(config.server.listen.port, 8080);
    }

    #[test]
    fn test_expand_path_tilde() {
        std::env::set_var("HOME", "/home/test");
        let path = Path::new("~/config/soth.yaml");
        let expanded = expand_path(path);
        assert!(expanded.to_string_lossy().contains("/home/test"));
    }

    #[test]
    fn test_expand_path_env_var() {
        std::env::set_var("SOTH_CONFIG_DIR", "/etc/soth");
        let path = Path::new("$SOTH_CONFIG_DIR/config.yaml");
        let expanded = expand_path(path);
        assert_eq!(expanded.to_string_lossy(), "/etc/soth/config.yaml");
    }
}
