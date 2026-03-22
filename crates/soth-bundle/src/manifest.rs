use serde::{Deserialize, Serialize};

use crate::error::BundleError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub version: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub vendor_sig: String,
    pub org_approval_sig: Option<String>,
    #[serde(default)]
    pub assets: Vec<AssetEntry>,
    pub scope: BundleScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BundleScope {
    #[serde(default)]
    pub intercept_https: bool,
    #[serde(default)]
    pub intercept_http: bool,
    pub process_filter: Option<Vec<String>>,
    #[serde(default)]
    pub capture_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OrgSignedConfig {
    #[serde(default)]
    pub allows_https_intercept: bool,
    #[serde(default)]
    pub allows_http_intercept: bool,
    pub process_filter: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_capture_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CanonicalManifest<'a> {
    version: &'a str,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    vendor_sig: &'a str,
    org_approval_sig: Option<&'a str>,
    assets: Vec<&'a AssetEntry>,
    scope: &'a BundleScope,
}

pub fn canonical_manifest_bytes(manifest: &BundleManifest) -> Result<Vec<u8>, BundleError> {
    let mut assets: Vec<&AssetEntry> = manifest.assets.iter().collect();
    assets.sort_by(|left, right| left.path.cmp(&right.path));

    let canonical = CanonicalManifest {
        version: &manifest.version,
        created_at: manifest.created_at,
        bundle_id: manifest.bundle_id.as_deref(),
        model_version: manifest.model_version.as_deref(),
        policy_version: manifest.policy_version.as_deref(),
        org_id: manifest.org_id.as_deref(),
        issued_at: manifest.issued_at,
        expires_at: manifest.expires_at,
        vendor_sig: "",
        org_approval_sig: manifest.org_approval_sig.as_deref(),
        assets,
        scope: &manifest.scope,
    };

    serde_json::to_vec(&canonical)
        .map_err(|error| BundleError::CanonicalManifest(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_stable_with_unsorted_assets() {
        let manifest = BundleManifest {
            version: "v1".to_string(),
            created_at: 1,
            bundle_id: None,
            model_version: None,
            policy_version: None,
            org_id: None,
            issued_at: None,
            expires_at: None,
            vendor_sig: "deadbeef".to_string(),
            org_approval_sig: None,
            assets: vec![
                AssetEntry {
                    path: "b".to_string(),
                    sha256: "b".repeat(64),
                    size_bytes: 2,
                },
                AssetEntry {
                    path: "a".to_string(),
                    sha256: "a".repeat(64),
                    size_bytes: 1,
                },
            ],
            scope: BundleScope::default(),
        };

        let first = canonical_manifest_bytes(&manifest).expect("canonical");
        let second = canonical_manifest_bytes(&manifest).expect("canonical");
        assert_eq!(first, second);
    }
}
