//! Direct conversion from [`soth_core::native_bundle::NativeBundle`] to [`soth_core::GatingBundle`],
//! bypassing the intermediate `OwnedDetectBundle` representation.
//!
//! This is the 1-hop path:
//! ```text
//! NativeBundle → gating_from_native → GatingBundle
//! ```
//! compared to the 3-hop compat path:
//! ```text
//! NativeBundle → compat → OwnedDetectBundle → gating_from_detect → GatingBundle
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "native-bundle")]
//! # {
//! use soth_bundle::gating_from_native;
//! use soth_core::native_bundle::NativeBundle;
//!
//! let json = std::fs::read_to_string("bundle.json").unwrap();
//! let bundle: NativeBundle = serde_json::from_str(&json).unwrap();
//! let gating = gating_from_native(&bundle);
//! assert!(!gating.entities.providers.is_empty());
//! # }
//! ```

use std::collections::HashSet;

use soth_core::native_bundle::NativeBundle;
use soth_core::{
    normalize_bundle_host_pattern, BlacklistMatchType, EntityCatalog, GateConfig, GateDefaults,
    GatingBundle, IdentityIndex, NonCatalogedAction, Stage0Config, Stage1Config, Stage2Config,
    Stage3Config, Stage4Config, Stage5Config, UnknownAppAction,
};

use crate::entity_helpers::source_entities;

/// Convert a [`NativeBundle`] directly into a [`GatingBundle`] for use by
/// the gating pipeline at request time.
///
/// **Entity source selection** matches `entity_index_from_native`:
/// - If `bundle.entities` is non-empty (schema_version ≥ 4), it is the sole source.
/// - Otherwise `bundle.llm_providers` + `bundle.products` are chained (v3 compat).
///
/// The returned bundle has `normalize_host_patterns_in_place()` applied.
pub fn gating_from_native(bundle: &NativeBundle) -> GatingBundle {
    let entities = source_entities(bundle);

    // ── Step 1: build tls_intercept_hosts from all HttpHost/TlsSni signals ──
    let mut tls_intercept_hosts: HashSet<String> = HashSet::new();
    for entity in &entities {
        for rule in &entity.matching_rules {
            for signal in &rule.signals {
                if (signal.kind == "HttpHost" || signal.kind == "TlsSni") && !signal.is_negated {
                    if let Some(normalized) = normalize_bundle_host_pattern(&signal.pattern) {
                        tls_intercept_hosts.insert(normalized);
                    }
                }
            }
        }
    }
    // Also include entries from the domain_index.
    for host in bundle.domain_index.keys() {
        if let Some(normalized) = normalize_bundle_host_pattern(host) {
            tls_intercept_hosts.insert(normalized);
        }
    }

    // ── Step 5: passthrough_domains from bundle.settings ──────────────────
    let passthrough_domains: HashSet<String> = bundle
        .settings
        .iter()
        .filter(|s| s.setting_key == "passthrough_domains")
        .flat_map(|s| {
            // definition may be an array of strings or a single string.
            if let Some(arr) = s.definition.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(normalize_bundle_host_pattern)
                    .collect::<Vec<_>>()
            } else if let Some(single) = s.definition.as_str() {
                normalize_bundle_host_pattern(single)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        })
        .collect();

    // ── Step 6: stage3 blacklist from bundle.filters ───────────────────────
    let path_keywords: Vec<String> = bundle
        .filters
        .iter()
        .filter(|f| f.filter_type == "path_keywords")
        .flat_map(|f| {
            if let Some(arr) = f.definition.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            } else if let Some(s) = f.definition.as_str() {
                vec![s.to_string()]
            } else {
                Vec::new()
            }
        })
        .collect();

    // ── Step 7: allowed_host_origins ──────────────────────────────────────
    // Union of domain_index hosts and all HttpHost signal patterns.
    let mut allowed_host_origins: HashSet<String> = bundle
        .domain_index
        .keys()
        .filter_map(|host| normalize_bundle_host_pattern(host))
        .collect();
    allowed_host_origins.extend(tls_intercept_hosts.iter().cloned());

    // ── Step 8: assemble and normalize ────────────────────────────────────
    let mut gating = GatingBundle {
        identity_index: IdentityIndex::default(),
        gates: GateConfig {
            order: vec![
                soth_core::GateStage::Stage0Tls,
                soth_core::GateStage::Stage1AppOrigin,
                soth_core::GateStage::Stage2Whitelist,
                soth_core::GateStage::Stage3Blacklist,
                soth_core::GateStage::Stage4AppType,
                soth_core::GateStage::Stage5HostOrigin,
                soth_core::GateStage::Intercept,
            ],
            defaults: GateDefaults {
                sensor_enabled: true,
                fail_open_on_config_error: true,
                unknown_app_action: UnknownAppAction::Intercept,
                non_cataloged_host_action: NonCatalogedAction::Skip,
                discovery: soth_core::DiscoveryConfig::default(),
                source_unknown_app_action: None,
                source_whitelisted_unknown_app_action: None,
                source_non_whitelisted_host_action: None,
                source_browser_default_action: None,
            },
            stage0_tls: Stage0Config {
                tls_intercept_hosts,
                passthrough_domains,
                enable_discovery: false,
            },
            stage1_app_origin: Stage1Config {
                skip_if_unresolved_process: true,
            },
            stage2_whitelist: Stage2Config {
                allow_empty_means_allow_all_except_denied: true,
            },
            stage3_blacklist: Stage3Config {
                blacklisted_keywords: path_keywords.clone(),
                blacklisted_path_substrings: path_keywords,
                blacklisted_host_substrings: Vec::new(),
                graphql_operation_blacklist: Vec::new(),
                graphql_operation_blacklist_enabled: false,
                match_type: BlacklistMatchType::CaseInsensitiveSubstring,
            },
            stage4_app_type: Stage4Config {
                derive_from_identity_index: true,
            },
            stage5_host_origin: Stage5Config {
                allowed_host_origins,
                skip_for_discovery_capture: true,
            },
        },
        entities: EntityCatalog::default(),
    };
    gating.normalize_host_patterns_in_place();
    gating
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Entity classification, app type derivation, and capture mode parsing
// now live in crate::entity_helpers (single authority).

// Path rules are now built by EntityIndex (entity_index.rs:build_host_rules_for_entity).
// build_path_rules_by_host and the EntityCatalog/IdentityIndex builders were removed
// as part of the EntityResolver consolidation (P5 + Batch A).

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use soth_core::native_bundle::{
        NativeBundle, NativeBundleCapture, NativeBundleEntity, NativeBundleMetadata,
        NativeBundleRule, NativeBundleSignal,
    };

    use super::gating_from_native;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn metadata() -> NativeBundleMetadata {
        NativeBundleMetadata {
            version: "test-0.0.1".into(),
            compiled_at: "2026-03-14T00:00:00Z".into(),
            compiled_by: "test".into(),
            notes: None,
            vendor_count: 0,
            llm_provider_count: 0,
            product_count: 0,
            rule_count: 0,
            format_count: 0,
            filter_count: 0,
            settings_count: 0,
            entity_count: 0,
            tool_catalog_count: 0,
        }
    }

    fn capture(mode: &str) -> NativeBundleCapture {
        NativeBundleCapture {
            mode: mode.into(),
            methods: Vec::new(),
            enabled: true,
        }
    }

    fn signal(kind: &str, pattern: &str) -> NativeBundleSignal {
        NativeBundleSignal {
            kind: kind.into(),
            name: None,
            pattern: pattern.into(),
            is_negated: false,
            metadata: serde_json::Value::Null,
        }
    }

    fn rule(signals: Vec<NativeBundleSignal>) -> NativeBundleRule {
        NativeBundleRule {
            rule_id: uuid::Uuid::new_v4().to_string(),
            priority: 10,
            requires_all: false,
            notes: None,
            metadata: serde_json::Value::Null,
            signals,
        }
    }

    fn entity(
        slug: &str,
        entity_kind: Option<&str>,
        kind: Option<&str>,
        capture_mode: &str,
        rules: Vec<NativeBundleRule>,
    ) -> NativeBundleEntity {
        NativeBundleEntity {
            slug: slug.into(),
            entity_kind: entity_kind.map(str::to_string),
            kind: kind.map(str::to_string),
            vendor_slug: None,
            name: slug.into(),
            category: None,
            subtype: None,
            api_format: None,
            description: None,
            notes: None,
            primary_url: None,
            docs_url: None,
            logo_url: None,
            primary_domain: None,
            risk_level: None,
            risk_score: None,
            capture: capture(capture_mode),
            metadata: serde_json::Value::Null,
            details: serde_json::Value::Null,
            matching_rules: rules,
            provider_links: Vec::new(),
        }
    }

    fn empty_bundle() -> NativeBundle {
        NativeBundle {
            schema_version: 4,
            metadata: metadata(),
            vendors: Vec::new(),
            llm_providers: Vec::new(),
            products: Vec::new(),
            formats: Vec::new(),
            filters: Vec::new(),
            settings: Vec::new(),
            domain_index: Default::default(),
            entities: Vec::new(),
            tool_catalog: Vec::new(),
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// An empty bundle produces a valid GatingBundle without panicking.
    #[test]
    fn empty_bundle_is_valid() {
        let bundle = empty_bundle();
        let gating = gating_from_native(&bundle);
        assert!(gating.entities.providers.is_empty());
        assert!(gating.identity_index.hosts.is_empty());
        assert!(gating.identity_index.non_hosts.is_empty());
    }

    // NOTE: Tests for identity resolution (ProcessBundleId, ProcessName, browser
    // kind classification) and entity catalog (provider host rules, capture mode)
    // are now in entity_index.rs — the single authority for entity resolution.
    // gating_from_native no longer builds IdentityIndex or EntityCatalog.

    /// HttpHost signals from all entities contribute to tls_intercept_hosts.
    #[test]
    fn http_host_signals_populate_tls_intercept_hosts() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "openai",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "api.openai.com")])],
        ));

        let gating = gating_from_native(&bundle);
        assert!(gating
            .gates
            .stage0_tls
            .tls_intercept_hosts
            .contains("api.openai.com"));
    }

    /// Regex-style host patterns from matching_rules are normalized.
    #[test]
    fn host_patterns_are_normalized() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "openai",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "^.*\\.openai\\.com$")])],
        ));

        let gating = gating_from_native(&bundle);
        // Should be normalized to wildcard form, not raw regex.
        assert!(
            gating
                .gates
                .stage0_tls
                .tls_intercept_hosts
                .contains("*.openai.com"),
            "expected normalized *.openai.com, got: {:?}",
            gating.gates.stage0_tls.tls_intercept_hosts
        );
    }

    /// passthrough_domains setting is parsed from bundle.settings.
    #[test]
    fn passthrough_domains_from_settings() {
        use soth_core::native_bundle::NativeBundleSetting;

        let mut bundle = empty_bundle();
        bundle.settings.push(NativeBundleSetting {
            setting_key: "passthrough_domains".to_string(),
            definition: serde_json::json!(["icloud.com", "apple.com"]),
            notes: None,
        });

        let gating = gating_from_native(&bundle);
        let passthrough = &gating.gates.stage0_tls.passthrough_domains;
        assert!(passthrough.contains("icloud.com"));
        assert!(passthrough.contains("apple.com"));
    }

    /// path_keywords filter populates the stage3 blacklist.
    #[test]
    fn path_keywords_filter_populates_blacklist() {
        use soth_core::native_bundle::NativeBundleFilter;

        let mut bundle = empty_bundle();
        bundle.filters.push(NativeBundleFilter {
            filter_key: "default".to_string(),
            filter_type: "path_keywords".to_string(),
            definition: serde_json::json!(["sentry", "telemetry"]),
        });

        let gating = gating_from_native(&bundle);
        assert!(gating
            .gates
            .stage3_blacklist
            .blacklisted_keywords
            .contains(&"sentry".to_string()));
        assert!(gating
            .gates
            .stage3_blacklist
            .blacklisted_path_substrings
            .contains(&"telemetry".to_string()));
    }

    /// v3 bundles (empty entities, split providers/applications) are handled.
    #[test]
    fn v3_bundle_chains_providers_and_applications() {
        let mut bundle = empty_bundle();
        bundle.schema_version = 3;

        bundle.llm_providers.push(entity(
            "anthropic",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "api.anthropic.com")])],
        ));
        bundle.products.push(entity(
            "cursor",
            Some("product"),
            Some("ide"),
            "metadata_only",
            vec![rule(vec![signal(
                "ProcessBundleId",
                "com.todesktop.230313mzl4w4u92",
            )])],
        ));

        let gating = gating_from_native(&bundle);
        // v3 bundles chain llm_providers + products for tls_intercept_hosts
        assert!(gating
            .gates
            .stage0_tls
            .tls_intercept_hosts
            .contains("api.anthropic.com"));
    }

    /// TlsSni signals also populate tls_intercept_hosts.
    #[test]
    fn tls_sni_signals_populate_tls_intercept_hosts() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "openai",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![signal("TlsSni", "api.openai.com")])],
        ));

        let gating = gating_from_native(&bundle);
        assert!(gating
            .gates
            .stage0_tls
            .tls_intercept_hosts
            .contains("api.openai.com"));
    }

    /// domain_index entries also contribute to tls_intercept_hosts.
    #[test]
    fn domain_index_contributes_to_tls_intercept_hosts() {
        use soth_core::native_bundle::NativeBundleDomainIndexEntry;
        use std::collections::BTreeMap;

        let mut bundle = empty_bundle();
        let mut domain_index = BTreeMap::new();
        domain_index.insert(
            "api.cohere.com".to_string(),
            vec![NativeBundleDomainIndexEntry {
                entity_type: "provider".to_string(),
                entity_slug: "cohere".to_string(),
                rule_id: "cohere-host".to_string(),
                priority: 100,
            }],
        );
        bundle.domain_index = domain_index;

        let gating = gating_from_native(&bundle);
        assert!(gating
            .gates
            .stage0_tls
            .tls_intercept_hosts
            .contains("api.cohere.com"));
    }

    // capture_mode preservation is now tested in entity_index.rs

    /// Gate defaults are present and sensible.
    #[test]
    fn gate_defaults_are_sensible() {
        let bundle = empty_bundle();
        let gating = gating_from_native(&bundle);
        assert!(gating.gates.defaults.sensor_enabled);
        assert!(gating.gates.defaults.fail_open_on_config_error);
        assert_eq!(
            gating.gates.defaults.unknown_app_action,
            soth_core::UnknownAppAction::Intercept
        );
        assert!(gating.gates.stage1_app_origin.skip_if_unresolved_process);
        assert!(
            gating
                .gates
                .stage2_whitelist
                .allow_empty_means_allow_all_except_denied
        );
    }
}
