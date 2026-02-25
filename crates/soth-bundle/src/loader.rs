use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use soth_policy::sync_policy::{load_bundle_from_bytes, PolicyBundle, PolicyBundleMetadata};

use crate::error::BundleError;
use crate::manifest::{BundleManifest, OrgSignedConfig};
use crate::scope_check;
use crate::verify;
use crate::LoadedBundle;

pub fn load_from_dir(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
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

    load_verified(manifest, asset_bytes, vendor_pubkey, org_config)
}

pub fn load_from_bytes(
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    load_verified(manifest, assets, vendor_pubkey, org_config)
}

pub(crate) fn load_verified(
    manifest: BundleManifest,
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    verify::verify_bundle(&manifest, &assets, vendor_pubkey)?;
    scope_check::check_scope(&manifest.scope, org_config)?;

    let policy = load_policy_bundle(&assets)?;
    let detect = load_detect_bundle(&assets)?;
    let classify = soth_classify::ClassifyBundle::fallback_with_policy_bundle(
        policy.clone(),
        manifest.version.clone(),
    );

    Ok(LoadedBundle {
        version: manifest.version.clone(),
        installed_at: Utc::now().timestamp(),
        classify,
        policy,
        detect,
        manifest,
    })
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
        return Ok(Arc::new(empty_policy_bundle()));
    };

    let loaded = load_bundle_from_bytes(payload.as_slice())
        .map_err(|error| BundleError::PolicyLoadFailed(error.to_string()))?;
    Ok(Arc::new(loaded))
}

fn load_detect_bundle(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Arc<soth_detect::OwnedDetectBundle>, BundleError> {
    let section = extract_section(assets, "detect/");
    if let Some(bytes) = section.get("bundle.json") {
        let bundle: soth_detect::OwnedDetectBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        return Ok(Arc::new(bundle));
    }
    if section.is_empty() && !assets.contains_key("detect_bundle.json") {
        return Ok(Arc::new(soth_detect::OwnedDetectBundle::default()));
    }
    if let Some(bytes) = assets.get("detect_bundle.json") {
        let bundle: soth_detect::OwnedDetectBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        return Ok(Arc::new(bundle));
    }
    Ok(Arc::new(soth_detect::OwnedDetectBundle::default()))
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
        let detect_bytes =
            serde_json::to_vec(&soth_detect::OwnedDetectBundle::default()).expect("detect json");

        let assets = HashMap::from([
            ("policy/policy_bundle.json".to_string(), policy_bytes),
            ("detect/bundle.json".to_string(), detect_bytes),
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
}
