//! Embedded default policy rule pack.
//!
//! The starter rules at `extensions/code/policies/code-default-rules.json`
//! are compiled into the binary so the hook handler has a sensible default
//! policy even when no signed bundle is on disk. The on-disk
//! `~/.soth/code-policy.bundle` (when present) always takes precedence —
//! this fallback exists so a fresh install doesn't fail-closed on every
//! prompt that happens to look code-shaped.
//!
//! Two consumers:
//!
//! - `hook.rs::policy_bundle()` — loads the embedded payload as an
//!   in-memory `PolicyBundle` (unsigned, built via `soth_policy::build_bundle`).
//! - `soth code policy install-default` — uses the same JSON source to
//!   produce a dev-signed on-disk bundle for operators who want to edit
//!   the rules locally.

use serde::Deserialize;
use soth_policy::{
    BudgetLimits, OrgPatterns, PolicyBundle, PolicyBundleMetadata, PolicyBundlePayload,
    RuleDefinition,
};

/// JSON source of the starter rule pack. Embedded at compile time so the
/// fallback works on hosts that haven't run `soth code policy install-default`.
pub const DEFAULT_RULES_JSON: &str = include_str!("../policies/code-default-rules.json");

/// Deserializable view of the rules JSON. Public so the CLI's
/// `policy install-default` flow can share the same shape.
#[derive(Deserialize)]
pub struct DefaultRulesSource {
    #[serde(default)]
    pub system_rules: Vec<RuleDefinition>,
    #[serde(default)]
    pub org_rules: Vec<RuleDefinition>,
    #[serde(default)]
    pub org_patterns: OrgPatterns,
    #[serde(default)]
    pub budget_limits: BudgetLimits,
}

impl DefaultRulesSource {
    /// Parse the embedded JSON. Panics only on developer error — the
    /// JSON file is checked in and parsed by tests, so a runtime parse
    /// failure means the file was edited into invalid shape since
    /// compile-time.
    pub fn from_embedded() -> serde_json::Result<Self> {
        serde_json::from_str(DEFAULT_RULES_JSON)
    }

    /// Wrap into a `PolicyBundlePayload` with placeholder metadata. The
    /// `org_id` is the literal string `embedded-default` so operators
    /// reading the doctor output can tell the in-process fallback apart
    /// from a real signed bundle.
    pub fn into_payload(self) -> PolicyBundlePayload {
        PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: format!("soth-code-embedded-{}", env!("CARGO_PKG_VERSION")),
                schema_version: "1".to_string(),
                org_id: "embedded-default".to_string(),
                signed_at: 0,
            },
            system_rules: self.system_rules,
            org_rules: self.org_rules,
            org_patterns: self.org_patterns,
            budget_limits: self.budget_limits,
        }
    }
}

/// Build the embedded default policy bundle in-memory.
///
/// Returns `Err` only if the embedded JSON is malformed or a rule fails
/// CEL compilation — both developer errors caught by `cargo test`. The
/// hook handler treats an `Err` here as "no policy", same shape as a
/// missing on-disk bundle.
pub fn embedded_default_bundle() -> Result<PolicyBundle, EmbeddedBundleError> {
    let source = DefaultRulesSource::from_embedded().map_err(EmbeddedBundleError::Parse)?;
    soth_policy::build_bundle(source.into_payload()).map_err(EmbeddedBundleError::Build)
}

#[derive(Debug, thiserror::Error)]
pub enum EmbeddedBundleError {
    #[error("parse embedded code-default-rules.json: {0}")]
    Parse(serde_json::Error),
    #[error("build embedded policy bundle: {0}")]
    Build(soth_policy::PolicyError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_json_parses() {
        DefaultRulesSource::from_embedded().expect("embedded rules JSON must parse");
    }

    #[test]
    fn embedded_bundle_builds() {
        let bundle = embedded_default_bundle().expect("embedded rules must compile to a bundle");
        // Sanity: the starter pack has at least one rule. If this drops
        // to zero, default-deny on missing bundle returns, which is the
        // bug we're guarding against.
        let total = bundle.system_rules.rules.len() + bundle.org_rules.rules.len();
        assert!(total > 0, "embedded default bundle must contain rules");
        assert_eq!(bundle.metadata.org_id, "embedded-default");
    }
}
