//! Configuration loader with environment variable overrides
//!
//! Loads configuration from YAML files with support for environment variable overrides.

use crate::config::types::SothConfig;
use crate::error::{Result, SothError};
use serde::Deserialize;
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
    config.observe.storage.apply_legacy_retention_days();
    apply_host_domain_file_overrides(&mut config, path.parent())?;

    // Apply environment variable overrides
    apply_env_overrides(&mut config);
    normalize_budget_db_path(&mut config);

    Ok(config)
}

/// Load configuration from a string
pub fn load_config_from_str(content: &str) -> Result<SothConfig> {
    let mut config: SothConfig = serde_yaml::from_str(content)?;
    config.observe.storage.apply_legacy_retention_days();
    apply_host_domain_file_overrides(&mut config, None)?;
    apply_env_overrides(&mut config);
    normalize_budget_db_path(&mut config);
    Ok(config)
}

fn normalize_budget_db_path(config: &mut SothConfig) {
    if let Some(path) = config.budget.db_path.clone() {
        config.budget.db_path = Some(expand_path(&path));
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DomainListFile {
    List(Vec<String>),
    Object { domains: Vec<String> },
}

fn normalize_domains(domains: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(domains.len());
    let mut seen = std::collections::HashSet::with_capacity(domains.len());
    for entry in domains {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn resolve_domain_file_path(raw_path: &Path, base_dir: Option<&Path>) -> std::path::PathBuf {
    let expanded = expand_path(raw_path);
    if expanded.is_absolute() {
        expanded
    } else if let Some(base) = base_dir {
        base.join(expanded)
    } else {
        expanded
    }
}

fn load_domain_list_file(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Err(SothError::ConfigInvalid(format!(
            "Domain list file not found: {}",
            path.display()
        )));
    }

    let content = std::fs::read_to_string(path)?;
    let parsed: DomainListFile = serde_yaml::from_str(&content).map_err(|e| {
        SothError::ConfigInvalid(format!(
            "Invalid domain list file {}: {}",
            path.display(),
            e
        ))
    })?;

    let domains = match parsed {
        DomainListFile::List(domains) => domains,
        DomainListFile::Object { domains } => domains,
    };
    Ok(normalize_domains(domains))
}

fn apply_host_domain_file_overrides(
    config: &mut SothConfig,
    base_dir: Option<&Path>,
) -> Result<()> {
    let domain_files = config.forward_proxy.hosts.domain_files.clone();

    if let Some(path) = domain_files.ai_inference.as_ref() {
        let resolved = resolve_domain_file_path(path, base_dir);
        config.forward_proxy.hosts.ai_inference = load_domain_list_file(&resolved)?;
    }

    if let Some(path) = domain_files.mcp.as_ref() {
        let resolved = resolve_domain_file_path(path, base_dir);
        config.forward_proxy.hosts.mcp = load_domain_list_file(&resolved)?;
    }

    if let Some(path) = domain_files.agent_apps.as_ref() {
        let resolved = resolve_domain_file_path(path, base_dir);
        config.forward_proxy.hosts.agent_apps = load_domain_list_file(&resolved)?;
    }

    Ok(())
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
    use tempfile::TempDir;

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
    fn test_legacy_retention_days_migrates_to_source_aware_retention() {
        let yaml = r#"
observe:
  storage:
    retention_days: 5
"#;
        let config = load_config_from_str(yaml).unwrap();
        assert_eq!(config.observe.storage.retention.ai_proxy_days, 5);
        assert_eq!(config.observe.storage.retention.mcp_days, 5);
        assert_eq!(config.observe.storage.retention.agent_app_days, 5);
        assert_eq!(config.observe.storage.retention.clusters_days, 5);
        assert_eq!(config.observe.storage.retention.rollups_days, 5);
    }

    #[test]
    fn test_explicit_retention_config_wins_over_legacy_retention_days() {
        let yaml = r#"
observe:
  storage:
    retention:
      ai_proxy_days: 9
      mcp_days: 8
      agent_app_days: 2
      clusters_days: 20
      rollups_days: 120
      vacuum_after_cleanup: false
    retention_days: 3
"#;
        let config = load_config_from_str(yaml).unwrap();
        assert_eq!(config.observe.storage.retention.ai_proxy_days, 9);
        assert_eq!(config.observe.storage.retention.mcp_days, 8);
        assert_eq!(config.observe.storage.retention.agent_app_days, 2);
        assert_eq!(config.observe.storage.retention.clusters_days, 20);
        assert_eq!(config.observe.storage.retention.rollups_days, 120);
        assert!(!config.observe.storage.retention.vacuum_after_cleanup);
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

    #[test]
    fn test_load_config_with_domain_files_replaces_inline_lists() {
        let temp = TempDir::new().unwrap();
        let domains_dir = temp.path().join("domains");
        std::fs::create_dir_all(&domains_dir).unwrap();

        std::fs::write(
            domains_dir.join("ai.yaml"),
            "domains:\n  - api.openai.com\n  - chatgpt.com\n",
        )
        .unwrap();
        std::fs::write(
            domains_dir.join("mcp.yaml"),
            "domains:\n  - api.github.com\n  - api.notion.com\n",
        )
        .unwrap();
        std::fs::write(
            domains_dir.join("agent.yaml"),
            "domains:\n  - chatgpt.com\n  - claude.ai\n",
        )
        .unwrap();

        let config_path = temp.path().join("soth.yaml");
        std::fs::write(
            &config_path,
            r#"
forward_proxy:
  hosts:
    ai_inference: ["legacy.ai.example"]
    mcp: ["legacy.mcp.example"]
    agent_apps: ["legacy.agent.example"]
    domain_files:
      ai_inference: "./domains/ai.yaml"
      mcp: "./domains/mcp.yaml"
      agent_apps: "./domains/agent.yaml"
"#,
        )
        .unwrap();

        let config = load_config(&config_path).unwrap();
        assert_eq!(
            config.forward_proxy.hosts.ai_inference,
            vec!["api.openai.com".to_string(), "chatgpt.com".to_string()]
        );
        assert_eq!(
            config.forward_proxy.hosts.mcp,
            vec!["api.github.com".to_string(), "api.notion.com".to_string()]
        );
        assert_eq!(
            config.forward_proxy.hosts.agent_apps,
            vec!["chatgpt.com".to_string(), "claude.ai".to_string()]
        );
    }

    #[test]
    fn test_load_config_with_missing_domain_file_fails() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("soth.yaml");
        std::fs::write(
            &config_path,
            r#"
forward_proxy:
  hosts:
    domain_files:
      ai_inference: "./domains/missing-ai.yaml"
"#,
        )
        .unwrap();

        let err = load_config(&config_path).unwrap_err();
        assert!(matches!(err, SothError::ConfigInvalid(_)));
    }

    #[test]
    fn test_domain_list_file_supports_root_sequence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("domains.yaml");
        std::fs::write(
            &path,
            "- api.openai.com\n- api.openai.com\n- \"  \"\n- chatgpt.com\n",
        )
        .unwrap();

        let domains = load_domain_list_file(&path).unwrap();
        assert_eq!(
            domains,
            vec!["api.openai.com".to_string(), "chatgpt.com".to_string()]
        );
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
}
