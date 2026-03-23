//! Adapter that converts a [`soth_core::native_bundle::NativeBundle`] (the canonical
//! cloud bundle format) into a [`soth_core::EntityIndex`] for O(1) identity
//! resolution at proxy request time.
//!
//! This module is compiled only when the `native-bundle` feature is enabled,
//! keeping the OSS proxy binary free of the proprietary `soth-interface` crate.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "native-bundle")]
//! # {
//! use soth_bundle::entity_index::entity_index_from_native;
//! use soth_core::native_bundle::NativeBundle;
//!
//! let json = std::fs::read_to_string("bundle.json").unwrap();
//! let bundle: NativeBundle = serde_json::from_str(&json).unwrap();
//! let index = entity_index_from_native(&bundle);
//!
//! if let Some(entity) = index.resolve_host("api.anthropic.com") {
//!     println!("provider: {}", entity.id);
//! }
//! # }
//! ```

use soth_core::bundle::entity_index::{EntityIndex, EntityIndexEntry};
use soth_core::native_bundle::{NativeBundle, NativeBundleEntity};

use crate::entity_helpers::{
    derive_kind, flatten_signals, primary_backend_provider, source_entities,
};

/// Convert a [`NativeBundle`] into a fully-built [`EntityIndex`].
///
/// **Entity source selection** (v4 forward-compat):
/// - If `bundle.entities` is non-empty (schema_version ≥ 4), it is used as
///   the single authoritative list.
/// - Otherwise the function chains `bundle.llm_providers` + `bundle.products`
///   for backward compatibility with schema_version 3 bundles.
///
/// **Kind derivation** (when `entity.kind` is absent):
/// - `entity_kind == "provider"` → `"platform"`
/// - anything else (incl. `"application"` or absent) → `"other"`
///
/// **Provider ID** is resolved from the first `provider_links` entry whose
/// `relation_kind` is `"primary_backend"`.  If no such link exists the field
/// is `None`.
///
/// **Signals** are the flattened union of all `matching_rules[*].signals`,
/// emitted as `(signal.kind, signal.pattern)` pairs.  Negated signals are
/// skipped because they cannot serve as positive index keys.
pub fn entity_index_from_native(bundle: &NativeBundle) -> EntityIndex {
    let entries: Vec<EntityIndexEntry> = source_entities(bundle)
        .into_iter()
        .map(entity_to_entry)
        .collect();
    EntityIndex::build(entries)
}

fn entity_to_entry(entity: &NativeBundleEntity) -> EntityIndexEntry {
    let kind = derive_kind(entity);
    let provider_id = primary_backend_provider(entity);
    let signals = flatten_signals(entity);
    let host_rules = build_host_rules_for_entity(entity);

    EntityIndexEntry {
        slug: entity.slug.clone(),
        name: entity.name.clone(),
        kind,
        category: entity.category.clone(),
        capture_mode: entity.capture.mode.clone(),
        api_format: entity.api_format.clone(),
        provider_id,
        vendor_slug: entity.vendor_slug.clone(),
        action: soth_core::ProcessAction::Intercept,
        signals,
        host_rules,
    }
}

/// Build host rules with path constraints from an entity's matching rules.
/// Collects all HttpHost patterns and their associated HttpPath allow/deny rules
/// across all matching rules on the entity.
fn build_host_rules_for_entity(
    entity: &NativeBundleEntity,
) -> Vec<(String, Vec<String>, soth_core::PathRules)> {
    let mut hosts: Vec<String> = Vec::new();
    let mut paths = soth_core::PathRules::default();

    for rule in &entity.matching_rules {
        for signal in &rule.signals {
            match signal.kind.as_str() {
                "HttpHost" | "TlsSni" if !signal.is_negated => {
                    let normalized = soth_core::normalize_bundle_host_pattern(&signal.pattern)
                        .unwrap_or_else(|| signal.pattern.to_ascii_lowercase());
                    if !hosts.contains(&normalized) {
                        hosts.push(normalized);
                    }
                }
                "HttpPath" => {
                    if signal.is_negated {
                        if signal.pattern.contains('*') {
                            paths.deny_glob.push(signal.pattern.clone());
                        } else {
                            paths.deny_exact.push(signal.pattern.clone());
                        }
                    } else {
                        paths.allow.push(signal.pattern.clone());
                    }
                }
                _ => {}
            }
        }
    }

    hosts
        .into_iter()
        .map(|host| (host, Vec::new(), paths.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use soth_core::native_bundle::{
        NativeBundle, NativeBundleCapture, NativeBundleEntity, NativeBundleMetadata,
        NativeBundleProviderLink, NativeBundleRule, NativeBundleSignal,
    };

    use super::entity_index_from_native;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn minimal_metadata() -> NativeBundleMetadata {
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

    fn negated_signal(kind: &str, pattern: &str) -> NativeBundleSignal {
        NativeBundleSignal {
            kind: kind.into(),
            name: None,
            pattern: pattern.into(),
            is_negated: true,
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

    fn provider_link(slug: &str, relation_kind: &str) -> NativeBundleProviderLink {
        NativeBundleProviderLink {
            provider_slug: slug.into(),
            relation_kind: relation_kind.into(),
            metadata: serde_json::Value::Null,
        }
    }

    fn empty_bundle() -> NativeBundle {
        NativeBundle {
            schema_version: 4,
            metadata: minimal_metadata(),
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

    #[allow(clippy::too_many_arguments)]
    fn entity(
        slug: &str,
        name: &str,
        entity_kind: Option<&str>,
        kind: Option<&str>,
        category: Option<&str>,
        api_format: Option<&str>,
        capture_mode: &str,
        rules: Vec<NativeBundleRule>,
        links: Vec<NativeBundleProviderLink>,
    ) -> NativeBundleEntity {
        NativeBundleEntity {
            slug: slug.into(),
            entity_kind: entity_kind.map(str::to_string),
            kind: kind.map(str::to_string),
            vendor_slug: None,
            name: name.into(),
            category: category.map(str::to_string),
            subtype: None,
            api_format: api_format.map(str::to_string),
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
            provider_links: links,
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// A v4 bundle with `entities` populated should use that list exclusively.
    #[test]
    fn v4_entities_preferred_over_legacy_lists() {
        let mut bundle = empty_bundle();

        // Put something in the legacy lists to confirm they are ignored.
        bundle.llm_providers.push(entity(
            "legacy-provider",
            "Legacy",
            Some("llm_provider"),
            None,
            None,
            None,
            "metadata_only",
            vec![],
            vec![],
        ));

        bundle.entities.push(entity(
            "anthropic",
            "Anthropic",
            Some("llm_provider"),
            Some("platform"),
            Some("AI Platform"),
            Some("anthropic"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "api.anthropic.com")])],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);

        assert_eq!(index.len(), 1, "legacy entity must not appear in the index");

        let resolved = index.resolve_host("api.anthropic.com").unwrap();
        assert_eq!(resolved.id, "anthropic");
        assert_eq!(resolved.name, "Anthropic");
        assert_eq!(resolved.api_format.as_deref(), Some("anthropic"));

        // The legacy slug must not be reachable.
        assert!(index.get("legacy-provider").is_none());
    }

    /// A v3 bundle (empty `entities`) should chain providers + applications.
    #[test]
    fn v3_fallback_chains_providers_and_applications() {
        let mut bundle = empty_bundle();
        bundle.schema_version = 3;
        // entities stays empty

        bundle.llm_providers.push(entity(
            "openai",
            "OpenAI",
            Some("llm_provider"),
            Some("platform"),
            Some("AI Platform"),
            Some("openai"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "api.openai.com")])],
            vec![],
        ));
        bundle.products.push(entity(
            "cursor",
            "Cursor",
            Some("product"),
            Some("ide"),
            Some("Code Editor"),
            None,
            "metadata_only",
            vec![rule(vec![
                signal("ProcessBundleId", "com.todesktop.230313mzl4w4u92"),
                signal("ProcessName", "Cursor"),
            ])],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);

        assert_eq!(index.len(), 2);

        let provider = index.resolve_host("api.openai.com").unwrap();
        assert_eq!(provider.id, "openai");

        let (app, source) = index
            .resolve_tool(
                Some("com.todesktop.230313mzl4w4u92"),
                None,
                None,
                None,
                &soth_core::EnvIndex::default(),
            )
            .unwrap();
        assert_eq!(app.id, "cursor");
        assert_eq!(source, "bundle_id");

        let (app2, source2) = index
            .resolve_tool(
                None,
                Some("Cursor"),
                None,
                None,
                &soth_core::EnvIndex::default(),
            )
            .unwrap();
        assert_eq!(app2.id, "cursor");
        assert_eq!(source2, "process_name");
    }

    /// `kind` field takes priority; falls back to entity_kind mapping.
    #[test]
    fn kind_derivation_priority() {
        let mut bundle = empty_bundle();

        // Has explicit fine-grained kind.
        bundle.entities.push(entity(
            "cursor",
            "Cursor",
            Some("product"),
            Some("ide"), // fine-grained kind present
            None,
            None,
            "metadata_only",
            vec![],
            vec![],
        ));
        // entity_kind="provider" but no fine-grained kind → "platform".
        bundle.entities.push(entity(
            "anthropic",
            "Anthropic",
            Some("llm_provider"),
            None, // no fine-grained kind
            None,
            None,
            "metadata_only",
            vec![],
            vec![],
        ));
        // Neither kind field set → "other".
        bundle.entities.push(entity(
            "mystery",
            "Mystery Tool",
            None,
            None,
            None,
            None,
            "metadata_only",
            vec![],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);

        assert_eq!(
            index.get("cursor").unwrap().kind,
            soth_core::bundle::entity_index::EntityKind::Ide
        );
        assert_eq!(
            index.get("anthropic").unwrap().kind,
            soth_core::bundle::entity_index::EntityKind::Platform
        );
        assert_eq!(
            index.get("mystery").unwrap().kind,
            soth_core::bundle::entity_index::EntityKind::Other
        );
    }

    /// provider_id is taken from the first "primary_backend" link.
    #[test]
    fn provider_id_from_primary_backend_link() {
        let mut bundle = empty_bundle();

        bundle.entities.push(entity(
            "chatgpt",
            "ChatGPT",
            Some("product"),
            Some("browser_app"),
            Some("AI Chat"),
            None,
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "chatgpt.com")])],
            vec![
                provider_link("some-other", "secondary"), // not primary_backend
                provider_link("openai", "primary_backend"), // this one is used
                provider_link("azure", "primary_backend"), // duplicate — first wins
            ],
        ));

        let index = entity_index_from_native(&bundle);
        let resolved = index.get("chatgpt").unwrap();
        assert_eq!(resolved.provider_id.as_deref(), Some("openai"));
    }

    /// No primary_backend link → provider_id is None.
    #[test]
    fn provider_id_none_when_no_primary_backend() {
        let mut bundle = empty_bundle();

        bundle.entities.push(entity(
            "standalone",
            "Standalone",
            Some("llm_provider"),
            Some("platform"),
            None,
            None,
            "metadata_only",
            vec![],
            vec![provider_link("other", "related")], // wrong relation_kind
        ));

        let index = entity_index_from_native(&bundle);
        assert!(index.get("standalone").unwrap().provider_id.is_none());
    }

    /// Negated signals must not be indexed.
    #[test]
    fn negated_signals_excluded() {
        let mut bundle = empty_bundle();

        bundle.entities.push(entity(
            "selective",
            "Selective",
            Some("llm_provider"),
            Some("platform"),
            None,
            None,
            "metadata_only",
            vec![rule(vec![
                signal("HttpHost", "real.example.com"), // should be indexed
                negated_signal("HttpHost", "excluded.example.com"), // must NOT be indexed
            ])],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);

        assert!(index.resolve_host("real.example.com").is_some());
        assert!(
            index.resolve_host("excluded.example.com").is_none(),
            "negated signal patterns must not appear as index keys"
        );
    }

    /// Multiple rules on one entity — signals from all rules are indexed.
    #[test]
    fn signals_from_multiple_rules_all_indexed() {
        let mut bundle = empty_bundle();

        bundle.entities.push(entity(
            "openai",
            "OpenAI",
            Some("llm_provider"),
            Some("platform"),
            Some("AI Platform"),
            Some("openai"),
            "metadata_only",
            vec![
                rule(vec![signal("HttpHost", "api.openai.com")]),
                rule(vec![signal("HttpHost", "oaiapi.azure.com")]),
            ],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);

        assert_eq!(index.resolve_host("api.openai.com").unwrap().id, "openai");
        assert_eq!(index.resolve_host("oaiapi.azure.com").unwrap().id, "openai");
    }

    /// capture_mode string is forwarded verbatim; EntityIndex::build parses it.
    #[test]
    fn capture_mode_forwarded() {
        let mut bundle = empty_bundle();

        bundle.entities.push(entity(
            "full-cap",
            "Full Cap",
            Some("llm_provider"),
            Some("platform"),
            None,
            None,
            "full", // should parse to CaptureMode::Full
            vec![rule(vec![signal("HttpHost", "full.example.com")])],
            vec![],
        ));

        let index = entity_index_from_native(&bundle);
        let resolved = index.resolve_host("full.example.com").unwrap();
        assert_eq!(
            resolved.capture_mode,
            soth_core::artifacts::CaptureMode::Full
        );
    }

    /// An empty bundle produces an empty EntityIndex without panicking.
    #[test]
    fn empty_bundle_produces_empty_index() {
        let bundle = empty_bundle();
        let index = entity_index_from_native(&bundle);
        assert!(index.is_empty());
    }
}
