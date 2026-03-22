//! Shared entity classification and conversion helpers.
//!
//! Single authority for entity kind classification, signal kind parsing,
//! capture mode parsing, and v3/v4 entity source selection. All three
//! bundle converters (detect_from_native, gating_from_native, entity_index)
//! import from here instead of defining their own copies.

use soth_core::{AppType, MatchingRule, SignalKind, SignalMatcher};
use soth_interface::{NativeBundleEntity, NativeBundleRule, NativeBundleSignal, NativeBundle};

// ── V3/V4 entity source selection ────────────────────────────────────────────

/// Returns the authoritative entity list from a NativeBundle.
///
/// - schema_version ≥ 4: `bundle.entities` (unified list)
/// - schema_version 3: chains `bundle.llm_providers` + `bundle.products`
pub fn source_entities(bundle: &NativeBundle) -> Vec<&NativeBundleEntity> {
    if !bundle.entities.is_empty() {
        bundle.entities.iter().collect()
    } else {
        bundle
            .llm_providers
            .iter()
            .chain(bundle.products.iter())
            .collect()
    }
}

// ── Entity kind classification ───────────────────────────────────────────────

/// Returns `true` if the entity is an LLM provider (not a product/application).
pub fn is_provider(entity: &NativeBundleEntity) -> bool {
    matches!(entity.entity_kind.as_deref(), Some("llm_provider") | Some("provider"))
        || (entity.entity_kind.is_none()
            && entity
                .kind
                .as_deref()
                .map_or(false, |k| matches!(k, "platform" | "provider" | "llm_provider")))
}

/// Returns `true` if the entity is a product/application (not a provider).
pub fn is_product(entity: &NativeBundleEntity) -> bool {
    matches!(entity.entity_kind.as_deref(), Some("product") | Some("application"))
        || (entity.entity_kind.is_none()
            && entity.kind.as_deref().map_or(false, |k| {
                !matches!(k, "platform" | "provider" | "llm_provider")
            }))
}

/// Derive the fine-grained kind string for an entity.
///
/// Priority:
/// 1. `entity.kind` if present (e.g. `"ide"`, `"cli"`, `"browser"`).
/// 2. Coarse mapping of `entity.entity_kind`:
///    - `"llm_provider"` / `"provider"` → `"platform"`
///    - anything else → `"other"`
pub fn derive_kind(entity: &NativeBundleEntity) -> String {
    if let Some(k) = entity.kind.as_deref().filter(|s| !s.is_empty()) {
        return k.to_string();
    }
    match entity.entity_kind.as_deref() {
        Some("llm_provider") | Some("provider") => "platform".to_string(),
        _ => "other".to_string(),
    }
}

/// Derive the coarse `AppType` from an entity's kind fields.
///
/// `"browser"` and `"browser_app"` → `Host`; everything else → `NonHost`.
pub fn derive_app_type(entity: &NativeBundleEntity) -> AppType {
    if let Some(k) = entity.kind.as_deref() {
        return match k.trim().to_ascii_lowercase().as_str() {
            "browser" | "browser_app" => AppType::Host,
            _ => AppType::NonHost,
        };
    }
    AppType::NonHost
}

// ── Capture mode parsing ─────────────────────────────────────────────────────

/// Parse a capture mode string. Returns `None` for unrecognised values.
pub fn parse_capture_mode(raw: &str) -> Option<soth_core::CaptureMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "full" => Some(soth_core::CaptureMode::Full),
        "sensitive_artifacts" => Some(soth_core::CaptureMode::SensitiveArtifacts),
        "full_content" => Some(soth_core::CaptureMode::FullContent),
        "metadata_only" => Some(soth_core::CaptureMode::MetadataOnly),
        _ => None,
    }
}

// ── Signal kind parsing ──────────────────────────────────────────────────────

/// Parse a signal kind string into the typed `SignalKind` enum.
///
/// Returns `None` for unrecognised kinds so future additions don't
/// cause hard failures — they are simply skipped.
pub fn parse_signal_kind(raw: &str) -> Option<SignalKind> {
    match raw {
        "TlsSni" => Some(SignalKind::TlsSni),
        "ProcessBundleId" => Some(SignalKind::ProcessBundleId),
        "ProcessName" => Some(SignalKind::ProcessName),
        "ParentProcessName" => Some(SignalKind::ParentProcessName),
        "HttpHost" => Some(SignalKind::HttpHost),
        "HttpPath" => Some(SignalKind::HttpPath),
        "HttpMethod" => Some(SignalKind::HttpMethod),
        "HttpHeader" => Some(SignalKind::HttpHeader),
        "ContentType" => Some(SignalKind::ContentType),
        "BodyStructure" => Some(SignalKind::BodyStructure),
        _ => None,
    }
}

// ── Rule/signal conversion ───────────────────────────────────────────────────

/// Convert `NativeBundleRule` (soth-interface) → `MatchingRule` (soth-core).
pub fn convert_rules(rules: &[NativeBundleRule]) -> Vec<MatchingRule> {
    rules.iter().map(convert_rule).collect()
}

fn convert_rule(rule: &NativeBundleRule) -> MatchingRule {
    MatchingRule {
        rule_id: rule.rule_id.clone(),
        priority: rule.priority,
        requires_all: rule.requires_all,
        notes: rule.notes.clone(),
        metadata: rule.metadata.clone(),
        signals: rule.signals.iter().filter_map(convert_signal).collect(),
    }
}

fn convert_signal(signal: &NativeBundleSignal) -> Option<SignalMatcher> {
    let kind = parse_signal_kind(&signal.kind)?;
    Some(SignalMatcher {
        kind,
        pattern: signal.pattern.clone(),
        name: signal.name.clone(),
        is_negated: signal.is_negated,
        metadata: signal.metadata.clone(),
    })
}

// ── Shared signal helpers ────────────────────────────────────────────────────

/// Return the `provider_slug` of the first `provider_links` entry whose
/// `relation_kind` is `"primary_backend"`, or `None` if no such link exists.
pub fn primary_backend_provider(entity: &NativeBundleEntity) -> Option<String> {
    entity
        .provider_links
        .iter()
        .find(|link| link.relation_kind == "primary_backend")
        .map(|link| link.provider_slug.clone())
}

/// Flatten all `matching_rules[*].signals` into `(kind, pattern)` pairs,
/// skipping negated signals (they cannot serve as positive lookup keys).
pub fn flatten_signals(entity: &NativeBundleEntity) -> Vec<(String, String)> {
    entity
        .matching_rules
        .iter()
        .flat_map(|rule| rule.signals.iter())
        .filter(|signal| !signal.is_negated)
        .map(|signal| (signal.kind.clone(), signal.pattern.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_interface::NativeBundleCapture;

    fn make_entity(
        slug: &str,
        entity_kind: Option<&str>,
        kind: Option<&str>,
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
            capture: NativeBundleCapture {
                mode: "metadata_only".into(),
                methods: Vec::new(),
                enabled: true,
            },
            metadata: serde_json::Value::Null,
            details: serde_json::Value::Null,
            matching_rules: Vec::new(),
            provider_links: Vec::new(),
        }
    }

    #[test]
    fn provider_classification() {
        assert!(is_provider(&make_entity("openai", Some("llm_provider"), Some("platform"))));
        assert!(is_provider(&make_entity("openai", Some("provider"), None)));
        assert!(is_provider(&make_entity("openai", None, Some("platform"))));
        assert!(!is_provider(&make_entity("cursor", Some("product"), Some("ide"))));
        assert!(!is_provider(&make_entity("cursor", None, Some("ide"))));
    }

    #[test]
    fn product_classification() {
        assert!(is_product(&make_entity("cursor", Some("product"), Some("ide"))));
        assert!(is_product(&make_entity("cursor", Some("application"), None)));
        assert!(is_product(&make_entity("cursor", None, Some("ide"))));
        assert!(!is_product(&make_entity("openai", Some("llm_provider"), Some("platform"))));
    }

    #[test]
    fn derive_kind_priority() {
        // kind field takes priority
        assert_eq!(derive_kind(&make_entity("x", Some("llm_provider"), Some("ide"))), "ide");
        // Falls back to entity_kind mapping
        assert_eq!(derive_kind(&make_entity("x", Some("llm_provider"), None)), "platform");
        assert_eq!(derive_kind(&make_entity("x", Some("product"), None)), "other");
    }

    #[test]
    fn derive_app_type_browser_vs_non_host() {
        assert_eq!(derive_app_type(&make_entity("x", None, Some("browser"))), AppType::Host);
        assert_eq!(derive_app_type(&make_entity("x", None, Some("browser_app"))), AppType::Host);
        assert_eq!(derive_app_type(&make_entity("x", None, Some("ide"))), AppType::NonHost);
        assert_eq!(derive_app_type(&make_entity("x", None, None)), AppType::NonHost);
    }

    #[test]
    fn capture_mode_parsing() {
        assert_eq!(parse_capture_mode("full"), Some(soth_core::CaptureMode::Full));
        assert_eq!(parse_capture_mode("METADATA_ONLY"), Some(soth_core::CaptureMode::MetadataOnly));
        assert_eq!(parse_capture_mode("garbage"), None);
    }

    #[test]
    fn signal_kind_round_trip() {
        assert_eq!(parse_signal_kind("HttpHost"), Some(SignalKind::HttpHost));
        assert_eq!(parse_signal_kind("ProcessBundleId"), Some(SignalKind::ProcessBundleId));
        assert_eq!(parse_signal_kind("FutureKind"), None);
    }
}
