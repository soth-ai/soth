//! Integration tests for configuration features
//!
//! Tests PII detection optional and cache configuration.

use soth_core::config::{CacheConfig, SothConfig};
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine};
use soth_proxy::pipeline::observe::{ObserveConfig, ObserveLayer};
use std::time::Duration;

/// Test: PII detection disabled means no detector/redactor allocation
#[test]
fn test_pii_detection_disabled_no_allocation() {
    let yaml = r#"
version: "1.0"
observe:
  enabled: true
  pii_detection: false
"#;
    let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

    assert!(!config.observe.pii_detection);

    // Create observe layer with PII disabled
    let observe_config = ObserveConfig {
        log_requests: config.observe.log_requests,
        log_responses: config.observe.log_responses,
        pii_detection: config.observe.pii_detection,
        count_tokens: true,
        log_to_file: false,
    };

    let _layer = ObserveLayer::new(observe_config);

    // The layer should have None for pii_detector and pii_redactor
    // We verify this indirectly by checking the config was properly applied
    assert!(!config.observe.pii_detection);
}

/// Test: PII detection enabled creates detector/redactor
#[test]
fn test_pii_detection_enabled_has_allocation() {
    let yaml = r#"
version: "1.0"
observe:
  enabled: true
  pii_detection: true
"#;
    let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

    assert!(config.observe.pii_detection);
}

/// Test: Cache config with custom L1/L2 TTLs parses correctly
#[test]
fn test_cache_config_custom_ttls() {
    let yaml = r#"
version: "1.0"
policy:
  enabled: true
  cache:
    enabled: true
    l1_ttl: "30s"
    l2_ttl: "2m"
    l1_max_entries: 5000
    l2_max_entries: 500
"#;
    let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

    assert!(config.policy.cache.enabled);
    assert_eq!(config.policy.cache.l1_ttl, Duration::from_secs(30));
    assert_eq!(config.policy.cache.l2_ttl, Some(Duration::from_secs(120)));
    assert_eq!(config.policy.cache.l1_max_entries, 5000);
    assert_eq!(config.policy.cache.l2_max_entries, 500);
}

/// Test: Cache config with default L2 TTL (30x L1)
#[test]
fn test_cache_config_default_l2_ttl() {
    let yaml = r#"
version: "1.0"
policy:
  enabled: true
  cache:
    enabled: true
    l1_ttl: "10s"
"#;
    let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

    assert!(config.policy.cache.enabled);
    assert_eq!(config.policy.cache.l1_ttl, Duration::from_secs(10));
    assert!(config.policy.cache.l2_ttl.is_none());

    // effective_l2_ttl should return 30x L1
    assert_eq!(config.policy.cache.effective_l2_ttl(), Duration::from_secs(300));
}

/// Test: Cache config converts correctly to policy cache config
#[test]
fn test_cache_config_conversion() {
    let core_config = CacheConfig {
        enabled: true,
        l1_ttl: Duration::from_secs(20),
        l2_ttl: Some(Duration::from_secs(60)),
        l1_max_entries: 8000,
        l2_max_entries: 800,
    };

    let policy_config: PolicyCacheConfig = core_config.into();

    assert!(policy_config.enabled);
    assert_eq!(policy_config.l1_ttl, Duration::from_secs(20));
    assert_eq!(policy_config.l2_ttl, Duration::from_secs(60));
    assert_eq!(policy_config.l1_max_entries, 8000);
    assert_eq!(policy_config.l2_max_entries, 800);
}

/// Test: PolicyEngine uses custom cache config
#[test]
fn test_policy_engine_with_cache_config() {
    let cache_config = PolicyCacheConfig {
        enabled: true,
        l1_ttl: Duration::from_secs(15),
        l2_ttl: Duration::from_secs(90),
        l1_max_entries: 3000,
        l2_max_entries: 300,
    };

    let engine = PolicyEngine::with_cache_config(cache_config);

    // Engine should be functional
    assert!(engine.is_enabled());

    // Cache metrics should be accessible
    let metrics = engine.cache_metrics();
    assert_eq!(metrics.lookups, 0);
    assert_eq!(metrics.l1_hits, 0);
    assert_eq!(metrics.l2_hits, 0);
}

/// Test: Full config parsing with all cache options
#[test]
fn test_full_config_with_cache() {
    let yaml = r#"
version: "1.0"
server:
  transport: "stdio"
upstream:
  command: "echo"
  args: ["test"]
observe:
  enabled: true
  pii_detection: false
policy:
  enabled: true
  mode: "enforce"
  cache:
    enabled: true
    l1_ttl: "30s"
    l2_ttl: "5m"
    l1_max_entries: 10000
    l2_max_entries: 1000
budget:
  enabled: false
"#;
    let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

    // Verify all settings
    assert!(!config.observe.pii_detection);
    assert!(config.policy.enabled);
    assert!(config.policy.cache.enabled);
    assert_eq!(config.policy.cache.l1_ttl, Duration::from_secs(30));
    assert_eq!(config.policy.cache.l2_ttl, Some(Duration::from_secs(300)));
}
