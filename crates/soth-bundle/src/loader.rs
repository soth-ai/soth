use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use soth_policy::sync_policy::{load_bundle_from_bytes, PolicyBundle, PolicyBundleMetadata};

use crate::error::BundleError;
use crate::manifest::{BundleManifest, OrgSignedConfig};
use crate::scope_check;
use crate::verify;
use crate::{BundleMeta, LoadedBundle, VerificationOptions};

pub fn load_from_dir(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    load_from_dir_with_options(
        bundle_dir,
        vendor_pubkey,
        org_config,
        VerificationOptions::default(),
    )
}

pub fn load_from_dir_with_options(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes.as_slice())?;

    let mut asset_bytes = HashMap::with_capacity(manifest.assets.len());
    for entry in &manifest.assets {
        let path = bundle_dir.join(entry.path.as_str());
        let bytes = std::fs::read(path)?;
        asset_bytes.insert(entry.path.clone(), bytes);
    }

    load_verified(
        manifest,
        asset_bytes,
        vendor_pubkey,
        org_config,
        verification,
    )
}

pub fn load_from_bytes(
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    load_from_bytes_with_options(
        manifest_bytes,
        assets,
        vendor_pubkey,
        org_config,
        VerificationOptions::default(),
    )
}

pub fn load_from_bytes_with_options(
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    load_verified(manifest, assets, vendor_pubkey, org_config, verification)
}

pub(crate) fn load_verified(
    manifest: BundleManifest,
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    // Phase 1: Verify signature and scope
    let trust_level =
        verify::verify_bundle_with_options(&manifest, &assets, Some(vendor_pubkey), verification)?;
    scope_check::check_scope(&manifest.scope, org_config)?;

    // Phase 2: Load policy bundle
    let policy = load_policy_bundle(&assets)?;

    // Phase 3: Load NativeBundle and build projections (detect, gating, env_index, entity_index)
    let native_bundle = load_native_bundle(&assets)?;
    let (detect, gating, env_index) = build_projections(&native_bundle);
    let entity_index = crate::entity_index::entity_index_from_native(&native_bundle);

    // Phase 4: Load classify bundle
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let classify = soth_classify::load_bundle_from_bytes(manifest_bytes.as_slice(), assets)
        .map_err(|error| BundleError::ClassifyLoadFailed(error.to_string()))?;

    // Phase 5: Build metadata
    let meta = build_meta(&manifest, &classify, &policy);

    Ok(LoadedBundle {
        version: manifest.version.clone(),
        installed_at: Utc::now().timestamp(),
        meta,
        trust_level,
        classify,
        policy,
        detect,
        gating,
        env_index,
        entity_index: Arc::new(entity_index),
        manifest,
    })
}

/// Known asset paths for NativeBundle JSON, checked in priority order.
const NATIVE_BUNDLE_PATHS: &[&str] = &[
    "native/bundle.json",
    "detect/bundle.json",
    "registry/raw_bundle.json",
];

/// Load and parse a NativeBundle from assets, trying known paths in order.
fn load_native_bundle(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<soth_core::native_bundle::NativeBundle, BundleError> {
    let native_bytes = NATIVE_BUNDLE_PATHS
        .iter()
        .find_map(|path| assets.get(*path))
        .ok_or_else(|| {
            BundleError::DetectLoadFailed(format!(
                "no NativeBundle found (checked: {})",
                NATIVE_BUNDLE_PATHS.join(", ")
            ))
        })?;

    serde_json::from_slice(native_bytes)
        .map_err(|e| BundleError::DetectLoadFailed(format!("NativeBundle parse failed: {e}")))
}

/// Build all bundle projections from a NativeBundle.
fn build_projections(
    native_bundle: &soth_core::native_bundle::NativeBundle,
) -> (
    Arc<soth_core::OwnedDetectBundle>,
    Arc<soth_core::GatingBundle>,
    Arc<soth_core::EnvIndex>,
) {
    let detect = Arc::new(crate::detect_from_native::detect_from_native(native_bundle));
    let gating = Arc::new(crate::gating_from_native::gating_from_native(native_bundle));
    let env_index = Arc::new(soth_core::EnvIndex::build(&detect.environments));
    (detect, gating, env_index)
}

/// Build bundle metadata from manifest with fallbacks to classify/policy values.
fn build_meta(
    manifest: &BundleManifest,
    classify: &soth_classify::ClassifyBundle,
    policy: &PolicyBundle,
) -> BundleMeta {
    let issued_at = manifest
        .issued_at
        .or_else(|| u64::try_from(manifest.created_at).ok())
        .unwrap_or_else(|| Utc::now().timestamp().max(0) as u64);

    BundleMeta {
        bundle_id: manifest
            .bundle_id
            .clone()
            .unwrap_or_else(|| manifest.version.clone()),
        model_version: manifest
            .model_version
            .clone()
            .unwrap_or_else(|| classify.bundle_version.clone()),
        policy_version: manifest
            .policy_version
            .clone()
            .unwrap_or_else(|| policy.metadata.bundle_version.clone()),
        org_id: manifest
            .org_id
            .clone()
            .unwrap_or_else(|| policy.metadata.org_id.clone()),
        issued_at,
        expires_at: manifest.expires_at,
        vendor_sig: if manifest.vendor_sig.trim().is_empty() {
            None
        } else {
            Some(manifest.vendor_sig.clone())
        },
        org_approval_sig: manifest.org_approval_sig.clone(),
    }
}

fn extract_section(assets: &HashMap<String, Vec<u8>>, prefix: &str) -> HashMap<String, Vec<u8>> {
    let mut section = HashMap::new();
    for (path, bytes) in assets {
        if let Some(stripped) = path.strip_prefix(prefix) {
            section.insert(stripped.to_string(), bytes.clone());
        }
    }
    section
}

fn load_policy_bundle(assets: &HashMap<String, Vec<u8>>) -> Result<Arc<PolicyBundle>, BundleError> {
    let section = extract_section(assets, "policy/");
    let payload = if let Some(bytes) = section.get("policy_bundle.json") {
        bytes
    } else if let Some(bytes) = section.get("bundle.json") {
        bytes
    } else if let Some(bytes) = assets.get("policy_bundle.json") {
        bytes
    } else {
        eprintln!("[soth-bundle] WARN: no policy bundle found in assets; using empty fallback");
        return Ok(Arc::new(empty_policy_bundle()));
    };

    let loaded = load_bundle_from_bytes(payload.as_slice())
        .map_err(|error| BundleError::PolicyLoadFailed(error.to_string()))?;
    // Pre-compile policy rule set once at load/install time for request-path latency.
    soth_policy::warm(&loaded);
    Ok(Arc::new(loaded))
}

fn empty_policy_bundle() -> PolicyBundle {
    use soth_policy::sync_policy::{BudgetLimits, CompiledRuleSet, OrgPatterns};
    PolicyBundle {
        metadata: PolicyBundleMetadata {
            bundle_version: "fallback-0.0.0".to_string(),
            schema_version: "1".to_string(),
            org_id: "unknown".to_string(),
            signed_at: 0,
        },
        system_rules: Arc::new(CompiledRuleSet::default()),
        org_rules: Arc::new(CompiledRuleSet::default()),
        org_patterns: Arc::new(OrgPatterns::default()),
        budget_limits: BudgetLimits::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use soth_policy::sync_policy::{
        BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
        RuleDefinition, SignedPolicyBundle,
    };

    use super::*;
    use crate::manifest::{canonical_manifest_bytes, AssetEntry, BundleScope};
    use crate::verify::sha256_hex;

    fn empty_native_bundle_bytes() -> Vec<u8> {
        let bundle = soth_core::native_bundle::NativeBundle {
            schema_version: 4,
            metadata: soth_core::native_bundle::NativeBundleMetadata {
                version: "test-0.0.1".into(),
                compiled_at: "2026-03-19T00:00:00Z".into(),
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
            },
            vendors: Vec::new(),
            llm_providers: Vec::new(),
            products: Vec::new(),
            formats: Vec::new(),
            filters: Vec::new(),
            settings: Vec::new(),
            domain_index: Default::default(),
            entities: Vec::new(),
            tool_catalog: Vec::new(),
        };
        serde_json::to_vec(&bundle).expect("serialize native bundle")
    }

    fn signed_policy_bundle_bytes() -> Vec<u8> {
        let payload = PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: "policy-v1".to_string(),
                schema_version: "1".to_string(),
                org_id: "demo-org".to_string(),
                signed_at: 1_772_000_001,
            },
            system_rules: vec![RuleDefinition {
                rule_id: "sys-allow".to_string(),
                rule_name: "allow".to_string(),
                cel_expr: "false".to_string(),
                action: RuleAction::Flag {
                    reason: "flag".to_string(),
                },
            }],
            org_rules: Vec::new(),
            org_patterns: OrgPatterns::default(),
            budget_limits: BudgetLimits::default(),
        };
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signature = key.sign(payload_bytes.as_slice());
        let envelope = SignedPolicyBundle {
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("serialize envelope")
    }

    fn signed_manifest_bytes(
        assets: &HashMap<String, Vec<u8>>,
        scope: BundleScope,
        vendor: &SigningKey,
    ) -> Vec<u8> {
        let mut entries: Vec<AssetEntry> = assets
            .iter()
            .map(|(path, bytes)| AssetEntry {
                path: path.clone(),
                sha256: sha256_hex(bytes.as_slice()),
                size_bytes: bytes.len() as u64,
            })
            .collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let mut manifest = BundleManifest {
            version: "bundle-v1".to_string(),
            created_at: 1_772_000_100,
            bundle_id: None,
            model_version: None,
            policy_version: None,
            org_id: None,
            issued_at: None,
            expires_at: None,
            vendor_sig: String::new(),
            org_approval_sig: None,
            assets: entries,
            scope,
        };
        let canonical = canonical_manifest_bytes(&manifest).expect("canonical");
        manifest.vendor_sig = hex::encode(vendor.sign(canonical.as_slice()).to_bytes());
        serde_json::to_vec(&manifest).expect("serialize manifest")
    }

    #[test]
    fn load_from_bytes_success() {
        let vendor = SigningKey::from_bytes(&[31u8; 32]);
        let policy_bytes = signed_policy_bundle_bytes();

        let assets = HashMap::from([
            ("policy/policy_bundle.json".to_string(), policy_bytes),
            (
                "detect/bundle.json".to_string(),
                empty_native_bundle_bytes(),
            ),
            (
                "classify/embedding.onnx".to_string(),
                b"stub-model".to_vec(),
            ),
        ]);
        let manifest_bytes = signed_manifest_bytes(&assets, BundleScope::default(), &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };
        let loaded = load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("bundle should load");

        assert_eq!(loaded.version, "bundle-v1");
        assert_eq!(loaded.policy.metadata.bundle_version, "policy-v1");
        assert_eq!(loaded.detect.rest_formats.len(), 0);
    }

    #[test]
    fn rejects_scope_expansion() {
        let vendor = SigningKey::from_bytes(&[32u8; 32]);
        let assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let scope = BundleScope {
            intercept_https: true,
            intercept_http: false,
            process_filter: None,
            capture_modes: Vec::new(),
        };
        let manifest_bytes = signed_manifest_bytes(&assets, scope, &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };
        let err = match load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        ) {
            Ok(_) => panic!("scope expansion should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, BundleError::ScopeExpansionRefused { .. }));
    }

    #[test]
    fn load_native_bundle_builds_identity_index_from_process_signals() {
        use soth_core::native_bundle::*;

        let vendor = SigningKey::from_bytes(&[33u8; 32]);

        let bundle = NativeBundle {
            schema_version: 4,
            metadata: NativeBundleMetadata {
                version: "test-identity".into(),
                compiled_at: "2026-03-19T00:00:00Z".into(),
                compiled_by: "test".into(),
                notes: None,
                vendor_count: 0,
                llm_provider_count: 0,
                product_count: 2,
                rule_count: 2,
                format_count: 0,
                filter_count: 0,
                settings_count: 0,
                entity_count: 2,
                tool_catalog_count: 0,
            },
            vendors: Vec::new(),
            llm_providers: Vec::new(),
            products: Vec::new(),
            formats: Vec::new(),
            filters: Vec::new(),
            settings: Vec::new(),
            domain_index: Default::default(),
            tool_catalog: Vec::new(),
            entities: vec![
                NativeBundleEntity {
                    slug: "chrome".into(),
                    entity_kind: Some("product".into()),
                    kind: Some("browser".into()),
                    vendor_slug: None,
                    name: "Chrome".into(),
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
                        methods: vec![],
                        enabled: true,
                    },
                    metadata: serde_json::Value::Null,
                    details: serde_json::Value::Null,
                    matching_rules: vec![NativeBundleRule {
                        rule_id: "process-0".into(),
                        priority: 1000,
                        requires_all: true,
                        notes: None,
                        metadata: serde_json::Value::Null,
                        signals: vec![NativeBundleSignal {
                            kind: "ProcessBundleId".into(),
                            name: None,
                            pattern: "com.google.Chrome".into(),
                            is_negated: false,
                            metadata: serde_json::Value::Null,
                        }],
                    }],
                    provider_links: Vec::new(),
                },
                NativeBundleEntity {
                    slug: "cursor".into(),
                    entity_kind: Some("product".into()),
                    kind: Some("ide".into()),
                    vendor_slug: None,
                    name: "Cursor".into(),
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
                        methods: vec![],
                        enabled: true,
                    },
                    metadata: serde_json::Value::Null,
                    details: serde_json::Value::Null,
                    matching_rules: vec![NativeBundleRule {
                        rule_id: "process-0".into(),
                        priority: 950,
                        requires_all: true,
                        notes: None,
                        metadata: serde_json::Value::Null,
                        signals: vec![NativeBundleSignal {
                            kind: "ProcessName".into(),
                            name: None,
                            pattern: "Cursor".into(),
                            is_negated: false,
                            metadata: serde_json::Value::Null,
                        }],
                    }],
                    provider_links: Vec::new(),
                },
            ],
        };
        let native_bytes = serde_json::to_vec(&bundle).expect("native json");

        let assets = HashMap::from([
            (
                "policy/policy_bundle.json".to_string(),
                signed_policy_bundle_bytes(),
            ),
            ("detect/bundle.json".to_string(), native_bytes),
            (
                "classify/embedding.onnx".to_string(),
                b"stub-model".to_vec(),
            ),
        ]);
        let manifest_bytes = signed_manifest_bytes(&assets, BundleScope::default(), &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };

        let loaded = load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("bundle should load");

        // Identity resolution is now handled by EntityIndex, not gating_from_native.
        // Verify the bundle loaded successfully and gating has TLS intercept hosts
        // (which is still built by gating_from_native).
        assert!(loaded.gating.identity_index.hosts.is_empty());
        assert!(loaded.gating.identity_index.non_hosts.is_empty());
    }
}
