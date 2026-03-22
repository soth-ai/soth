//! Converts a [`soth_core::native_bundle::NativeBundle`] into a [`soth_core::OwnedDetectBundle`],
//! providing the detect-layer view of the bundle for format detection, capture rules,
//! and process/host identity resolution.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "native-bundle")]
//! # {
//! use soth_bundle::detect_from_native;
//! use soth_core::native_bundle::NativeBundle;
//!
//! let json = std::fs::read_to_string("bundle.json").unwrap();
//! let bundle: NativeBundle = serde_json::from_str(&json).unwrap();
//! let detect = detect_from_native(&bundle);
//! assert!(!detect.llm_providers.is_empty());
//! # }
//! ```

use std::collections::HashMap;

use soth_core::native_bundle::NativeBundle;
use soth_core::{
    BundleEnvironment, CaptureMode, CaptureRules, Filters, OwnedDetectBundle, ProductEntry,
    ProviderEntry, RestFormatDescriptor,
};

use crate::entity_helpers::{
    convert_rules, is_product, is_provider, parse_capture_mode, source_entities,
};

/// Convert a [`NativeBundle`] into an [`OwnedDetectBundle`] suitable for the
/// detect layer (format matching, capture rules, process/host identity).
///
/// **Entity source selection** matches `entity_index_from_native` and
/// `gating_from_native`:
/// - `bundle.entities` non-empty → use that list exclusively (v4+).
/// - Otherwise chain `bundle.llm_providers` + `bundle.products` (v3 compat).
pub fn detect_from_native(bundle: &NativeBundle) -> OwnedDetectBundle {
    let entities = source_entities(bundle);

    // ── rest_formats ───────────────────────────────────────────────────────
    //
    // Formats with format_type == "runtime_format" are the REST format
    // descriptors used by the detect layer to parse AI API calls.
    let mut rest_formats: HashMap<String, RestFormatDescriptor> = bundle
        .formats
        .iter()
        .filter(|f| f.format_type == "runtime_format")
        .filter_map(|f| {
            // Try direct deserialization. If it fails, try the schema fixup
            // for bundles compiled from raw_bundle imports before the
            // normalize_format_definition fix was applied.
            let descriptor = serde_json::from_value::<RestFormatDescriptor>(f.definition.clone())
                .ok()
                .or_else(|| try_fixup_legacy_format(&f.definition))?;
            Some((f.format_key.clone(), descriptor))
        })
        .collect();

    // ── feature merge ────────────────────────────────────────────────────
    //
    // The bundle compiler may emit two formats for the same entity: one
    // keyed by the entity slug (e.g. "gemini") with rich features from
    // the parser DSL, and another keyed by the api_format name (e.g.
    // "gemini_web") with flat fields.  When the entity's api_format
    // points to the flat format, inject the features from the sibling.
    {
        // Collect entity_slug → owned features from formats that have them.
        let mut features_by_entity: HashMap<String, Vec<soth_core::FeatureDescriptor>> =
            HashMap::new();
        for f in &bundle.formats {
            if f.format_type != "runtime_format" {
                continue;
            }
            let slug = match f.entity_slug.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            if let Some(descriptor) = rest_formats.get(&f.format_key) {
                if !descriptor.features.is_empty() {
                    features_by_entity.insert(slug.to_string(), descriptor.features.clone());
                }
            }
        }

        // For each entity with an api_format, if that format has no
        // features but a sibling format (keyed by entity slug) does,
        // merge them in.
        for entity in &entities {
            let api_format = match entity.api_format.as_deref() {
                Some(af) => af,
                None => continue,
            };
            let needs_merge = rest_formats
                .get(api_format)
                .is_some_and(|d| d.features.is_empty());
            if !needs_merge {
                continue;
            }
            if let Some(features) = features_by_entity.get(entity.slug.as_str()) {
                if let Some(descriptor) = rest_formats.get_mut(api_format) {
                    descriptor.features = features.clone();
                }
            }
        }
    }

    // ── domain_index ───────────────────────────────────────────────────────
    //
    // Flatten NativeBundle's multi-entry domain_index (multiple candidates
    // per domain) to the single highest-priority entity slug per domain,
    // which is what OwnedDetectBundle.domain_index expects.
    let domain_index: HashMap<String, String> = bundle
        .domain_index
        .iter()
        .filter_map(|(host, entries)| {
            // entries is sorted by Ord on NativeBundleDomainIndexEntry, but we
            // want highest priority (largest value) → take the max.
            let best = entries.iter().max_by_key(|e| e.priority)?;
            Some((host.clone(), best.entity_slug.clone()))
        })
        .collect();

    // ── llm_providers ──────────────────────────────────────────────────────
    let mut llm_providers: HashMap<String, ProviderEntry> = HashMap::new();
    for entity in &entities {
        if !is_provider(entity) {
            continue;
        }
        let matching_rules = convert_rules(&entity.matching_rules);
        let entry = ProviderEntry {
            provider_id: Some(entity.slug.clone()),
            name: Some(entity.name.clone()),
            api_format: entity.api_format.clone(),
            provider_type: entity.kind.clone().or_else(|| entity.entity_kind.clone()),
            pricing: None,
            capture: Some(serde_json::json!({ "mode": entity.capture.mode })),
            detection: None,
            matching_rules,
        };
        llm_providers.insert(entity.slug.clone(), entry);
    }

    // ── products ───────────────────────────────────────────────────────────
    let mut products: HashMap<String, ProductEntry> = HashMap::new();
    for entity in &entities {
        if !is_product(entity) {
            continue;
        }
        let matching_rules = convert_rules(&entity.matching_rules);

        // Extract bundle_ids and process_names from ProcessBundleId /
        // ProcessName signals for backward-compat with v2 consumers.
        let mut bundle_ids: Vec<String> = Vec::new();
        let mut process_names: Vec<String> = Vec::new();
        for rule in &entity.matching_rules {
            for signal in &rule.signals {
                if signal.is_negated {
                    continue;
                }
                match signal.kind.as_str() {
                    "ProcessBundleId" => bundle_ids.push(signal.pattern.clone()),
                    "ProcessName" => process_names.push(signal.pattern.clone()),
                    _ => {}
                }
            }
        }
        bundle_ids.sort_unstable();
        bundle_ids.dedup();
        process_names.sort_unstable();
        process_names.dedup();

        let app_type = entity.kind.clone().or_else(|| entity.entity_kind.clone());

        let entry = ProductEntry {
            app_id: Some(entity.slug.clone()),
            name: Some(entity.name.clone()),
            bundle_ids,
            process_names,
            app_type,
            pricing: None,
            capture: Some(serde_json::json!({ "mode": entity.capture.mode })),
            detection: None,
            api_format: entity.api_format.clone(),
            matching_rules,
        };
        products.insert(entity.slug.clone(), entry);
    }

    // ── filters ────────────────────────────────────────────────────────────
    let mut path_keywords: Vec<String> = Vec::new();
    let mut header_keywords: Vec<String> = Vec::new();
    let mut domain_patterns: Vec<String> = Vec::new();
    let mut path_patterns: Vec<String> = Vec::new();
    let mut keywords: Vec<String> = Vec::new();

    for filter in &bundle.filters {
        let values: Vec<String> = if let Some(arr) = filter.definition.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        } else if let Some(s) = filter.definition.as_str() {
            vec![s.to_string()]
        } else {
            Vec::new()
        };

        match filter.filter_type.as_str() {
            "path_keywords" => path_keywords.extend(values),
            "header_keywords" => header_keywords.extend(values),
            "domain_patterns" => domain_patterns.extend(values),
            "path_patterns" => path_patterns.extend(values),
            "keywords" => keywords.extend(values),
            _ => {}
        }
    }

    let filters = Filters {
        path_keywords,
        header_keywords,
        domain_patterns,
        path_patterns,
        keywords,
    };

    // ── capture_rules ──────────────────────────────────────────────────────
    //
    // Build the capture rules from the entities' capture mode settings.
    // Providers that have `full` capture mode go into full_capture_providers.
    let mut full_capture_providers: Vec<String> = Vec::new();
    for entity in &entities {
        if is_provider(entity)
            && parse_capture_mode(&entity.capture.mode) == Some(CaptureMode::Full)
        {
            full_capture_providers.push(entity.slug.clone());
        }
    }

    let capture_rules = CaptureRules {
        default_mode: CaptureMode::MetadataOnly,
        full_capture_providers,
        org_overrides: soth_core::CaptureOverrides::default(),
    };

    // ── passthrough_domains ────────────────────────────────────────────────
    let passthrough_domains: Vec<String> = bundle
        .settings
        .iter()
        .filter(|s| s.setting_key == "passthrough_domains")
        .flat_map(|s| {
            if let Some(arr) = s.definition.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            } else if let Some(single) = s.definition.as_str() {
                vec![single.to_string()]
            } else {
                Vec::new()
            }
        })
        .collect();

    // ── environments ───────────────────────────────────────────────────────
    let environments: Vec<BundleEnvironment> = bundle
        .settings
        .iter()
        .filter(|s| s.setting_key == "environments")
        .flat_map(|s| {
            if let Some(arr) = s.definition.as_array() {
                arr.iter()
                    .filter_map(|v| serde_json::from_value::<BundleEnvironment>(v.clone()).ok())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        })
        .collect();

    OwnedDetectBundle {
        rest_formats,
        graphql_operations: soth_core::GraphQLOperationRegistry::default(),
        grpc_services: soth_core::GrpcServiceRegistry::default(),
        capture_rules,
        domain_index,
        llm_providers,
        products,
        filters,
        passthrough_domains,
        org_patterns: Vec::new(),
        environments,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Entity classification, signal conversion, and capture mode parsing
// now live in crate::entity_helpers (single authority).

// ── Format definition helpers ─────────────────────────────────────────────────

/// Backward-compat fixup for format definitions compiled before
/// `normalize_format_definition` was added to the raw_bundle importer.
/// Lifts encoding/form_field/preprocess from request to top level and
/// flattens response.json.extract to response.
fn try_fixup_legacy_format(defn: &serde_json::Value) -> Option<RestFormatDescriptor> {
    let mut fixed = defn.clone();
    if let Some(req) = fixed.get("request").cloned() {
        if let Some(obj) = req.as_object() {
            if obj.contains_key("encoding") || obj.contains_key("form_field") {
                if let Some(top) = fixed.as_object_mut() {
                    for key in ["encoding", "form_field", "preprocess"] {
                        if let Some(val) = obj.get(key) {
                            top.insert(key.to_string(), val.clone());
                        }
                    }
                    let clean_req: serde_json::Map<String, serde_json::Value> = obj
                        .iter()
                        .filter(|(k, _)| {
                            !matches!(k.as_str(), "encoding" | "form_field" | "preprocess")
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    top.insert("request".to_string(), serde_json::Value::Object(clean_req));
                }
            }
        }
    }

    // Also lift response paths from nested response.json.extract structure
    if let Some(extract) = fixed.pointer("/response/json/extract") {
        let extract = extract.clone();
        if let Some(top) = fixed.as_object_mut() {
            top.insert("response".to_string(), extract);
        }
    }

    serde_json::from_value::<RestFormatDescriptor>(fixed).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use soth_core::native_bundle::{
        NativeBundle, NativeBundleCapture, NativeBundleEntity, NativeBundleFilter,
        NativeBundleFormat, NativeBundleMetadata, NativeBundleRule, NativeBundleSetting,
        NativeBundleSignal,
    };

    use super::detect_from_native;

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

    #[test]
    fn empty_bundle_produces_empty_detect_bundle() {
        let bundle = empty_bundle();
        let detect = detect_from_native(&bundle);
        assert!(detect.llm_providers.is_empty());
        assert!(detect.products.is_empty());
        assert!(detect.rest_formats.is_empty());
        assert!(detect.domain_index.is_empty());
    }

    #[test]
    fn provider_entity_populates_llm_providers() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "anthropic",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![signal("HttpHost", "api.anthropic.com")])],
        ));

        let detect = detect_from_native(&bundle);
        let provider = detect
            .llm_providers
            .get("anthropic")
            .expect("anthropic should be in llm_providers");
        assert_eq!(provider.provider_id.as_deref(), Some("anthropic"));
        // matching_rules should be converted
        assert_eq!(provider.matching_rules.len(), 1);
        assert_eq!(provider.matching_rules[0].signals.len(), 1);
        assert_eq!(
            provider.matching_rules[0].signals[0].kind,
            soth_core::SignalKind::HttpHost
        );
    }

    #[test]
    fn application_entity_populates_applications() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "cursor",
            Some("product"),
            Some("ide"),
            "metadata_only",
            vec![rule(vec![
                signal("ProcessBundleId", "com.todesktop.230313mzl4w4u92"),
                signal("ProcessName", "Cursor"),
            ])],
        ));

        let detect = detect_from_native(&bundle);
        let app = detect
            .products
            .get("cursor")
            .expect("cursor should be in products");
        assert!(app
            .bundle_ids
            .contains(&"com.todesktop.230313mzl4w4u92".to_string()));
        assert!(app.process_names.contains(&"Cursor".to_string()));
    }

    #[test]
    fn runtime_format_populates_rest_formats() {
        let mut bundle = empty_bundle();
        bundle.formats.push(NativeBundleFormat {
            entity_kind: None,
            entity_slug: None,
            format_key: "openai".to_string(),
            format_type: "runtime_format".to_string(),
            definition: serde_json::json!({
                "request": { "model": "model", "messages": "messages" },
                "response": { "content": "choices[0].message.content" }
            }),
        });
        // Non-runtime formats should be ignored.
        bundle.formats.push(NativeBundleFormat {
            entity_kind: None,
            entity_slug: None,
            format_key: "other".to_string(),
            format_type: "schema".to_string(),
            definition: serde_json::json!({}),
        });

        let detect = detect_from_native(&bundle);
        assert!(detect.rest_formats.contains_key("openai"));
        assert!(!detect.rest_formats.contains_key("other"));
    }

    #[test]
    fn domain_index_flattened_to_highest_priority() {
        use soth_core::native_bundle::NativeBundleDomainIndexEntry;
        use std::collections::BTreeMap;

        let mut bundle = empty_bundle();
        let mut domain_index = BTreeMap::new();
        domain_index.insert(
            "api.openai.com".to_string(),
            vec![
                NativeBundleDomainIndexEntry {
                    entity_type: "provider".to_string(),
                    entity_slug: "openai-low".to_string(),
                    rule_id: "low".to_string(),
                    priority: 100,
                },
                NativeBundleDomainIndexEntry {
                    entity_type: "provider".to_string(),
                    entity_slug: "openai-high".to_string(),
                    rule_id: "high".to_string(),
                    priority: 900,
                },
            ],
        );
        bundle.domain_index = domain_index;

        let detect = detect_from_native(&bundle);
        assert_eq!(
            detect
                .domain_index
                .get("api.openai.com")
                .map(String::as_str),
            Some("openai-high"),
            "highest-priority entry should win"
        );
    }

    #[test]
    fn filters_grouped_by_type() {
        let mut bundle = empty_bundle();
        bundle.filters.push(NativeBundleFilter {
            filter_key: "kw".to_string(),
            filter_type: "path_keywords".to_string(),
            definition: serde_json::json!(["sentry", "telemetry"]),
        });
        bundle.filters.push(NativeBundleFilter {
            filter_key: "dom".to_string(),
            filter_type: "domain_patterns".to_string(),
            definition: serde_json::json!(["*.internal.example.com"]),
        });

        let detect = detect_from_native(&bundle);
        assert!(detect.filters.path_keywords.contains(&"sentry".to_string()));
        assert!(detect
            .filters
            .domain_patterns
            .contains(&"*.internal.example.com".to_string()));
    }

    #[test]
    fn passthrough_domains_from_settings() {
        let mut bundle = empty_bundle();
        bundle.settings.push(NativeBundleSetting {
            setting_key: "passthrough_domains".to_string(),
            definition: serde_json::json!(["icloud.com", "apple.com"]),
            notes: None,
        });

        let detect = detect_from_native(&bundle);
        assert!(detect
            .passthrough_domains
            .contains(&"icloud.com".to_string()));
        assert!(detect
            .passthrough_domains
            .contains(&"apple.com".to_string()));
    }

    #[test]
    fn full_capture_mode_populates_full_capture_providers() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "anthropic",
            Some("llm_provider"),
            Some("platform"),
            "full",
            vec![],
        ));
        bundle.entities.push(entity(
            "openai",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![],
        ));

        let detect = detect_from_native(&bundle);
        assert!(detect
            .capture_rules
            .full_capture_providers
            .contains(&"anthropic".to_string()));
        assert!(!detect
            .capture_rules
            .full_capture_providers
            .contains(&"openai".to_string()));
    }

    #[test]
    fn v3_bundle_chains_providers_and_applications() {
        let mut bundle = empty_bundle();
        bundle.schema_version = 3;

        bundle.llm_providers.push(entity(
            "anthropic",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![],
        ));
        bundle.products.push(entity(
            "cursor",
            Some("product"),
            Some("ide"),
            "metadata_only",
            vec![],
        ));

        let detect = detect_from_native(&bundle);
        assert!(detect.llm_providers.contains_key("anthropic"));
        assert!(detect.products.contains_key("cursor"));
    }

    #[test]
    fn unknown_signal_kind_is_silently_skipped() {
        let mut bundle = empty_bundle();
        bundle.entities.push(entity(
            "anthropic",
            Some("llm_provider"),
            Some("platform"),
            "metadata_only",
            vec![rule(vec![
                signal("HttpHost", "api.anthropic.com"),
                // Future unknown kind — must not panic.
                NativeBundleSignal {
                    kind: "UnknownFutureSignal".into(),
                    name: None,
                    pattern: "anything".into(),
                    is_negated: false,
                    metadata: serde_json::Value::Null,
                },
            ])],
        ));

        let detect = detect_from_native(&bundle);
        let provider = detect.llm_providers.get("anthropic").unwrap();
        // Only the HttpHost signal survived conversion; UnknownFutureSignal dropped.
        assert_eq!(provider.matching_rules[0].signals.len(), 1);
        assert_eq!(
            provider.matching_rules[0].signals[0].kind,
            soth_core::SignalKind::HttpHost
        );
    }
}
