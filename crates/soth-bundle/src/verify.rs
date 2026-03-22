use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::BundleError;
use crate::manifest::{canonical_manifest_bytes, BundleManifest};
use crate::{BundleTrustLevel, VerificationOptions};

pub fn verify_bundle_with_options(
    manifest: &BundleManifest,
    asset_bytes: &HashMap<String, Vec<u8>>,
    vendor_pubkey: Option<&[u8; 32]>,
    verification: VerificationOptions,
) -> Result<BundleTrustLevel, BundleError> {
    let mut trust_level =
        if verification.verify_vendor_signature || verification.require_verified_bundle {
            verify_vendor_signature(manifest, vendor_pubkey)
        } else {
            BundleTrustLevel::SignatureDisabled
        };

    for entry in &manifest.assets {
        let bytes = asset_bytes
            .get(entry.path.as_str())
            .ok_or_else(|| BundleError::MissingAsset(entry.path.clone()))?;
        let actual_size = bytes.len() as u64;
        if actual_size != entry.size_bytes {
            return Err(BundleError::AssetSizeMismatch {
                path: entry.path.clone(),
                expected: entry.size_bytes,
                actual: actual_size,
            });
        }
        let actual_hash = sha256_hex(bytes.as_slice());
        if actual_hash != entry.sha256 {
            return Err(BundleError::AssetHashMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual_hash,
            });
        }
    }

    if let Some(expires_at) = manifest.expires_at {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if expires_at < now {
            return Err(BundleError::BundleExpired { expires_at, now });
        }
    }

    if !verify_org_approval_signature(
        manifest,
        verification.org_approval_pubkey.as_ref(),
        manifest
            .bundle_id
            .as_deref()
            .unwrap_or(manifest.version.as_str()),
    ) {
        trust_level = BundleTrustLevel::Unverified;
    }

    if verification.require_verified_bundle && trust_level != BundleTrustLevel::Verified {
        return Err(BundleError::VerificationRequired { trust_level });
    }

    Ok(trust_level)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn verify_vendor_signature(
    manifest: &BundleManifest,
    vendor_pubkey: Option<&[u8; 32]>,
) -> BundleTrustLevel {
    if manifest.vendor_sig.trim().is_empty() {
        return BundleTrustLevel::SignatureDisabled;
    }

    let Some(vendor_pubkey) = vendor_pubkey else {
        return BundleTrustLevel::Unverified;
    };
    let Ok(canonical) = canonical_manifest_bytes(manifest) else {
        return BundleTrustLevel::Unverified;
    };
    let Ok(signature_bytes) = hex::decode(manifest.vendor_sig.as_str()) else {
        return BundleTrustLevel::Unverified;
    };
    let Ok(signature_array): Result<[u8; 64], _> = signature_bytes.as_slice().try_into() else {
        return BundleTrustLevel::Unverified;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(vendor_pubkey) else {
        return BundleTrustLevel::Unverified;
    };
    let signature = Signature::from_bytes(&signature_array);
    if verifying_key
        .verify_strict(canonical.as_slice(), &signature)
        .is_ok()
    {
        BundleTrustLevel::Verified
    } else {
        BundleTrustLevel::Unverified
    }
}

fn verify_org_approval_signature(
    manifest: &BundleManifest,
    org_approval_pubkey: Option<&[u8; 32]>,
    bundle_id: &str,
) -> bool {
    let Some(sig_hex) = manifest.org_approval_sig.as_deref() else {
        return true;
    };
    let Some(pubkey) = org_approval_pubkey else {
        return false;
    };

    let Ok(signature_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(signature_array): Result<[u8; 64], _> = signature_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };

    let payload = format!("{bundle_id}:{}", manifest.vendor_sig);
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify_strict(payload.as_bytes(), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::manifest::{AssetEntry, BundleScope};

    fn sign_manifest(manifest: &BundleManifest, key: &SigningKey) -> String {
        let canonical = canonical_manifest_bytes(manifest).expect("canonical bytes");
        let sig = key.sign(canonical.as_slice());
        hex::encode(sig.to_bytes())
    }

    fn fixture_bundle() -> (BundleManifest, HashMap<String, Vec<u8>>, SigningKey) {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let bytes = b"hello-bundle".to_vec();
        let mut manifest = BundleManifest {
            version: "v1".to_string(),
            created_at: 1,
            bundle_id: None,
            model_version: None,
            policy_version: None,
            org_id: None,
            issued_at: None,
            expires_at: None,
            vendor_sig: String::new(),
            org_approval_sig: None,
            assets: vec![AssetEntry {
                path: "policy/policy_bundle.json".to_string(),
                sha256: sha256_hex(bytes.as_slice()),
                size_bytes: bytes.len() as u64,
            }],
            scope: BundleScope::default(),
        };
        manifest.vendor_sig = sign_manifest(&manifest, &key);
        let mut assets = HashMap::new();
        assets.insert("policy/policy_bundle.json".to_string(), bytes);
        (manifest, assets, key)
    }

    #[test]
    fn verify_success() {
        let (manifest, assets, key) = fixture_bundle();
        let pubkey = key.verifying_key().to_bytes();
        let trust = verify_bundle_with_options(
            &manifest,
            &assets,
            Some(&pubkey),
            VerificationOptions::default(),
        )
        .expect("valid bundle");
        assert_eq!(trust, BundleTrustLevel::Verified);
    }

    #[test]
    fn verify_fails_on_tampered_asset() {
        let (manifest, mut assets, key) = fixture_bundle();
        assets.insert(
            "policy/policy_bundle.json".to_string(),
            b"tampered".to_vec(),
        );
        let pubkey = key.verifying_key().to_bytes();
        let err = verify_bundle_with_options(
            &manifest,
            &assets,
            Some(&pubkey),
            VerificationOptions::default(),
        )
        .expect_err("tampered should fail");
        assert!(matches!(
            err,
            BundleError::AssetSizeMismatch { .. } | BundleError::AssetHashMismatch { .. }
        ));
    }

    #[test]
    fn verify_marks_unverified_with_wrong_key() {
        let (manifest, assets, _key) = fixture_bundle();
        let wrong = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let trust = verify_bundle_with_options(
            &manifest,
            &assets,
            Some(&wrong),
            VerificationOptions::default(),
        )
        .expect("bundle should still load as unverified");
        assert_eq!(trust, BundleTrustLevel::Unverified);
    }

    #[test]
    fn verify_requires_verified_when_enabled() {
        let (manifest, assets, _key) = fixture_bundle();
        let wrong = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let err = verify_bundle_with_options(
            &manifest,
            &assets,
            Some(&wrong),
            VerificationOptions {
                verify_vendor_signature: true,
                require_verified_bundle: true,
                org_approval_pubkey: None,
            },
        )
        .expect_err("bad signature should fail when verified bundles are required");
        assert!(matches!(
            err,
            BundleError::VerificationRequired {
                trust_level: BundleTrustLevel::Unverified
            }
        ));
    }

    #[test]
    fn verify_skips_signature_when_disabled() {
        let (manifest, assets, _key) = fixture_bundle();
        let trust = verify_bundle_with_options(
            &manifest,
            &assets,
            None,
            VerificationOptions {
                verify_vendor_signature: false,
                require_verified_bundle: false,
                org_approval_pubkey: None,
            },
        )
        .expect("signature skipped should still validate assets");
        assert_eq!(trust, BundleTrustLevel::SignatureDisabled);
    }

    #[test]
    fn verify_fails_for_expired_bundle() {
        let (mut manifest, assets, key) = fixture_bundle();
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        manifest.expires_at = Some(now.saturating_sub(1));
        let pubkey = key.verifying_key().to_bytes();
        let err = verify_bundle_with_options(
            &manifest,
            &assets,
            Some(&pubkey),
            VerificationOptions::default(),
        )
        .expect_err("expired bundle must fail");
        assert!(matches!(err, BundleError::BundleExpired { .. }));
    }
}
