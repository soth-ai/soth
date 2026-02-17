//! Configuration loader with environment variable overrides
//!
//! Loads configuration from YAML files with support for environment variable overrides.

use crate::config::types::SothConfig;
use crate::error::{Result, SothError};
use std::collections::BTreeMap;
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
    normalize_cloud_config(&mut config);
    normalize_budget_db_path(&mut config);

    Ok(config)
}

/// Load configuration from a string
pub fn load_config_from_str(content: &str) -> Result<SothConfig> {
    let mut config: SothConfig = serde_yaml::from_str(content)?;
    apply_env_overrides(&mut config);
    normalize_cloud_config(&mut config);
    normalize_budget_db_path(&mut config);
    Ok(config)
}

fn normalize_budget_db_path(config: &mut SothConfig) {
    if let Some(path) = config.budget.db_path.clone() {
        config.budget.db_path = Some(expand_path(&path));
    }
}

fn normalize_cloud_config(config: &mut SothConfig) {
    if let Some(path) = config.cloud.cache_path.clone() {
        config.cloud.cache_path = Some(expand_path(&path));
    }
    if config.cloud.api_key.is_none() {
        config.cloud.enabled = false;
    }
}

/// Apply environment variable overrides to the configuration
fn apply_env_overrides(config: &mut SothConfig) {
    // Forward proxy overrides
    if let Ok(addr) = std::env::var("SOTH_LISTEN_ADDRESS") {
        config.server.listen.address = addr.clone();
        config.forward_proxy.address = addr;
    }
    if let Ok(port) = std::env::var("SOTH_LISTEN_PORT") {
        if let Ok(p) = port.parse() {
            config.server.listen.port = p;
            config.forward_proxy.port = p;
        }
    }
    if let Ok(addr) = std::env::var("SOTH_FORWARD_PROXY_ADDRESS") {
        config.forward_proxy.address = addr;
    }
    if let Ok(port) =
        std::env::var("SOTH_FORWARD_PROXY_PORT").or_else(|_| std::env::var("SOTH_PROXY_PORT"))
    {
        if let Ok(p) = port.parse() {
            config.forward_proxy.port = p;
        }
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
    if let Ok(value) = std::env::var("SOTH_OBSERVE_PII_AI_INFERENCE") {
        config.observe.pii_scopes.ai_inference = value.parse().unwrap_or(true);
    }
    if let Ok(value) = std::env::var("SOTH_OBSERVE_PII_MCP") {
        config.observe.pii_scopes.mcp = value.parse().unwrap_or(true);
    }
    if let Ok(value) = std::env::var("SOTH_OBSERVE_PII_AGENT_APPS") {
        config.observe.pii_scopes.agent_apps = value.parse().unwrap_or(true);
    }
    if let Ok(value) = std::env::var("SOTH_OBSERVE_EVENT_TAGS") {
        config.observe.event_tags = parse_key_value_tags(&value);
    }

    // Cloud overrides
    if let Ok(enabled) = std::env::var("SOTH_CLOUD_ENABLED") {
        config.cloud.enabled = enabled.parse().unwrap_or(config.cloud.enabled);
    }
    if let Ok(api_key) = std::env::var("SOTH_CLOUD_API_KEY") {
        if !api_key.trim().is_empty() {
            config.cloud.api_key = Some(api_key);
        }
    }
    if let Ok(endpoint) = std::env::var("SOTH_CLOUD_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            config.cloud.endpoint = endpoint;
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_TAGS") {
        config.cloud.tags = parse_key_value_tags(&value);
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_SYNC_INTERVAL_SECS") {
        if let Ok(parsed) = value.parse() {
            config.cloud.sync_interval_secs = parsed;
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_CONFIG_PULL_INTERVAL_SECS") {
        if let Ok(parsed) = value.parse() {
            config.cloud.config_pull_interval_secs = parsed;
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_CONFIG_DEBOUNCE_SECS") {
        if let Ok(parsed) = value.parse() {
            config.cloud.config_debounce_secs = parsed;
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_BODY_UPLOAD_ENABLED") {
        config.cloud.body_upload_enabled =
            value.parse().unwrap_or(config.cloud.body_upload_enabled);
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_METADATA_MAX_EVENTS_PER_BATCH") {
        if let Ok(parsed) = value.parse::<usize>() {
            config.cloud.metadata_max_events_per_batch = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_METADATA_MAX_COMPRESSED_BATCH_BYTES") {
        if let Ok(parsed) = value.parse::<u64>() {
            config.cloud.metadata_max_compressed_batch_bytes = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_FRONTLOAD_ENABLED") {
        config.cloud.frontload_enabled = value.parse().unwrap_or(config.cloud.frontload_enabled);
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_FRONTLOAD_MAX_EVENTS_PER_BATCH") {
        if let Ok(parsed) = value.parse::<usize>() {
            config.cloud.frontload_max_events_per_batch = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_FRONTLOAD_MAX_COMPRESSED_BATCH_BYTES") {
        if let Ok(parsed) = value.parse::<u64>() {
            config.cloud.frontload_max_compressed_batch_bytes = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_FRONTLOAD_HARD_EVENTS_CAP") {
        if let Ok(parsed) = value.parse::<usize>() {
            config.cloud.frontload_hard_events_cap = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_FRONTLOAD_HARD_COMPRESSED_CAP_BYTES") {
        if let Ok(parsed) = value.parse::<u64>() {
            config.cloud.frontload_hard_compressed_cap_bytes = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_BODY_UPLOAD_MAX_BYTES") {
        if let Ok(parsed) = value.parse::<u64>() {
            config.cloud.body_upload_max_bytes = parsed.max(1);
        }
    }
    if let Ok(value) = std::env::var("SOTH_CLOUD_CACHE_PATH") {
        if !value.trim().is_empty() {
            config.cloud.cache_path = Some(value.into());
        }
    }
    if let Ok(value) = std::env::var("SOTH_FORWARD_PROXY_CAPTURE_MAX_BODY_BYTES") {
        if let Ok(parsed) = value.parse::<u64>() {
            config.forward_proxy.capture_max_body_bytes = parsed.max(1);
        }
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

fn parse_key_value_tags(input: &str) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        tags.insert(key.to_string(), value.to_string());
    }
    tags
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
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env_var(name: &str, previous: Option<OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

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
    fn test_budget_storage_path_alias_maps_to_db_path() {
        let yaml = r#"
budget:
  enabled: true
  storage_path: "/tmp/soth-budget-alias.db"
"#;
        let config = load_config_from_str(yaml).unwrap();
        assert_eq!(
            config.budget.db_path,
            Some(std::path::PathBuf::from("/tmp/soth-budget-alias.db"))
        );
    }

    #[test]
    fn test_budget_db_path_defaults_to_soth_home_db() {
        let config = load_config_from_str("version: \"1.0\"").unwrap();
        let db_path = config.budget.db_path.expect("default budget db path");
        assert!(
            db_path.to_string_lossy().contains(".soth/budget.db"),
            "unexpected default budget db path: {}",
            db_path.display()
        );
    }

    #[test]
    fn test_expand_path_tilde() {
        let _guard = env_lock().lock().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/home/test");
        let path = Path::new("~/config/soth.yaml");
        let expanded = expand_path(path);
        assert!(expanded.to_string_lossy().contains("/home/test"));
        restore_env_var("HOME", prev_home);
    }

    #[test]
    fn test_expand_path_env_var() {
        let _guard = env_lock().lock().unwrap();
        let prev = std::env::var_os("SOTH_CONFIG_DIR");
        std::env::set_var("SOTH_CONFIG_DIR", "/etc/soth");
        let path = Path::new("$SOTH_CONFIG_DIR/config.yaml");
        let expanded = expand_path(path);
        assert_eq!(expanded.to_string_lossy(), "/etc/soth/config.yaml");
        restore_env_var("SOTH_CONFIG_DIR", prev);
    }

    #[test]
    fn test_parse_key_value_tags() {
        let tags = parse_key_value_tags("project=soth, env = dev,invalid,foo=bar");
        assert_eq!(tags.get("project"), Some(&"soth".to_string()));
        assert_eq!(tags.get("env"), Some(&"dev".to_string()));
        assert_eq!(tags.get("foo"), Some(&"bar".to_string()));
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn test_observe_event_tags_env_override() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("SOTH_OBSERVE_EVENT_TAGS", "project=soth,env=staging");
        let config = load_config_from_str("version: \"1.0\"").unwrap();
        assert_eq!(
            config.observe.event_tags.get("project"),
            Some(&"soth".to_string())
        );
        assert_eq!(
            config.observe.event_tags.get("env"),
            Some(&"staging".to_string())
        );
        std::env::remove_var("SOTH_OBSERVE_EVENT_TAGS");
    }

    #[test]
    fn test_cloud_overrides_and_normalization() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("SOTH_CLOUD_ENABLED", "true");
        std::env::set_var("SOTH_CLOUD_API_KEY", "soth_live_test");
        std::env::set_var("SOTH_CLOUD_ENDPOINT", "https://staging.soth.ai");
        std::env::set_var("SOTH_CLOUD_TAGS", "project=soth,env=qa");
        std::env::set_var("SOTH_CLOUD_SYNC_INTERVAL_SECS", "45");
        std::env::set_var("SOTH_CLOUD_CONFIG_PULL_INTERVAL_SECS", "180");
        std::env::set_var("SOTH_CLOUD_CONFIG_DEBOUNCE_SECS", "9");
        std::env::set_var("SOTH_CLOUD_BODY_UPLOAD_ENABLED", "true");
        std::env::set_var("SOTH_CLOUD_METADATA_MAX_EVENTS_PER_BATCH", "150");
        std::env::set_var("SOTH_CLOUD_METADATA_MAX_COMPRESSED_BATCH_BYTES", "4194304");
        std::env::set_var("SOTH_CLOUD_FRONTLOAD_ENABLED", "true");
        std::env::set_var("SOTH_CLOUD_FRONTLOAD_MAX_EVENTS_PER_BATCH", "2400");
        std::env::set_var("SOTH_CLOUD_FRONTLOAD_MAX_COMPRESSED_BATCH_BYTES", "8388608");
        std::env::set_var("SOTH_CLOUD_FRONTLOAD_HARD_EVENTS_CAP", "5000");
        std::env::set_var("SOTH_CLOUD_FRONTLOAD_HARD_COMPRESSED_CAP_BYTES", "16777216");
        std::env::set_var("SOTH_CLOUD_BODY_UPLOAD_MAX_BYTES", "10485760");
        std::env::set_var("SOTH_FORWARD_PROXY_CAPTURE_MAX_BODY_BYTES", "7340032");

        let config = load_config_from_str("version: \"1.0\"").unwrap();
        assert!(config.cloud.enabled);
        assert_eq!(config.cloud.api_key.as_deref(), Some("soth_live_test"));
        assert_eq!(config.cloud.endpoint, "https://staging.soth.ai");
        assert_eq!(config.cloud.sync_interval_secs, 45);
        assert_eq!(config.cloud.config_pull_interval_secs, 180);
        assert_eq!(config.cloud.config_debounce_secs, 9);
        assert!(config.cloud.body_upload_enabled);
        assert_eq!(config.cloud.metadata_max_events_per_batch, 150);
        assert_eq!(config.cloud.metadata_max_compressed_batch_bytes, 4_194_304);
        assert!(config.cloud.frontload_enabled);
        assert_eq!(config.cloud.frontload_max_events_per_batch, 2400);
        assert_eq!(
            config.cloud.frontload_max_compressed_batch_bytes,
            8 * 1024 * 1024
        );
        assert_eq!(config.cloud.frontload_hard_events_cap, 5000);
        assert_eq!(
            config.cloud.frontload_hard_compressed_cap_bytes,
            16 * 1024 * 1024
        );
        assert_eq!(config.cloud.body_upload_max_bytes, 10_485_760);
        assert_eq!(config.forward_proxy.capture_max_body_bytes, 7_340_032);
        assert_eq!(config.cloud.tags.get("project"), Some(&"soth".to_string()));

        std::env::remove_var("SOTH_CLOUD_ENABLED");
        std::env::remove_var("SOTH_CLOUD_API_KEY");
        std::env::remove_var("SOTH_CLOUD_ENDPOINT");
        std::env::remove_var("SOTH_CLOUD_TAGS");
        std::env::remove_var("SOTH_CLOUD_SYNC_INTERVAL_SECS");
        std::env::remove_var("SOTH_CLOUD_CONFIG_PULL_INTERVAL_SECS");
        std::env::remove_var("SOTH_CLOUD_CONFIG_DEBOUNCE_SECS");
        std::env::remove_var("SOTH_CLOUD_BODY_UPLOAD_ENABLED");
        std::env::remove_var("SOTH_CLOUD_METADATA_MAX_EVENTS_PER_BATCH");
        std::env::remove_var("SOTH_CLOUD_METADATA_MAX_COMPRESSED_BATCH_BYTES");
        std::env::remove_var("SOTH_CLOUD_FRONTLOAD_ENABLED");
        std::env::remove_var("SOTH_CLOUD_FRONTLOAD_MAX_EVENTS_PER_BATCH");
        std::env::remove_var("SOTH_CLOUD_FRONTLOAD_MAX_COMPRESSED_BATCH_BYTES");
        std::env::remove_var("SOTH_CLOUD_FRONTLOAD_HARD_EVENTS_CAP");
        std::env::remove_var("SOTH_CLOUD_FRONTLOAD_HARD_COMPRESSED_CAP_BYTES");
        std::env::remove_var("SOTH_CLOUD_BODY_UPLOAD_MAX_BYTES");
        std::env::remove_var("SOTH_FORWARD_PROXY_CAPTURE_MAX_BODY_BYTES");
    }

    #[test]
    fn test_cloud_disabled_when_api_key_missing() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("SOTH_CLOUD_ENABLED");
        std::env::remove_var("SOTH_CLOUD_API_KEY");

        let yaml = r#"
cloud:
  enabled: true
"#;
        let config = load_config_from_str(yaml).unwrap();
        assert!(!config.cloud.enabled);

        std::env::remove_var("SOTH_CLOUD_ENABLED");
        std::env::remove_var("SOTH_CLOUD_API_KEY");
    }
}
