use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::BundleError;
use crate::manifest::{canonical_manifest_bytes, BundleManifest};

pub fn verify_bundle(
    manifest: &BundleManifest,
    asset_bytes: &HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
) -> Result<(), BundleError> {
    let canonical = canonical_manifest_bytes(manifest)?;
    let signature_bytes = hex::decode(manifest.vendor_sig.as_str())
        .map_err(|_| BundleError::InvalidSignatureEncoding)?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::InvalidSignatureLength)?;
    let signature = Signature::from_bytes(&signature_array);
    let verifying_key =
        VerifyingKey::from_bytes(vendor_pubkey).map_err(|_| BundleError::InvalidVendorPublicKey)?;

    verifying_key
        .verify_strict(canonical.as_slice(), &signature)
        .map_err(|_| BundleError::SignatureVerificationFailed)?;

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

    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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
        verify_bundle(&manifest, &assets, &pubkey).expect("valid bundle");
    }

    #[test]
    fn verify_fails_on_tampered_asset() {
        let (manifest, mut assets, key) = fixture_bundle();
        assets.insert(
            "policy/policy_bundle.json".to_string(),
            b"tampered".to_vec(),
        );
        let pubkey = key.verifying_key().to_bytes();
        let err = verify_bundle(&manifest, &assets, &pubkey).expect_err("tampered should fail");
        assert!(matches!(
            err,
            BundleError::AssetSizeMismatch { .. } | BundleError::AssetHashMismatch { .. }
        ));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (manifest, assets, _key) = fixture_bundle();
        let wrong = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let err = verify_bundle(&manifest, &assets, &wrong).expect_err("wrong key should fail");
        assert!(matches!(err, BundleError::SignatureVerificationFailed));
    }
}
