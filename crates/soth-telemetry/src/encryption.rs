use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, Zeroizing};

use crate::types::{EncryptedBatch, SignedBatch};

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("hkdf expand failed")]
    HkdfExpandFailed,
    #[error("cipher initialization failed")]
    CipherInitFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
}

pub fn encrypt_batch(
    signed: &SignedBatch,
    vendor_static_pubkey: &[u8; 32],
) -> Result<EncryptedBatch, EncryptionError> {
    // Generate a fresh ephemeral Curve25519 scalar and immediately derive
    // both outputs before zeroing it so the raw secret never lingers.
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(ephemeral_secret.as_mut());
    let ephemeral_pubkey = x25519(*ephemeral_secret, X25519_BASEPOINT_BYTES);
    let mut shared_secret = Zeroizing::new(x25519(*ephemeral_secret, *vendor_static_pubkey));
    // ephemeral_secret is no longer needed; zero it before continuing.
    ephemeral_secret.zeroize();

    let aead_key = derive_aead_key(&shared_secret, &ephemeral_pubkey)?;
    // shared_secret is no longer needed once the AEAD key is derived.
    shared_secret.zeroize();

    let plaintext = rmp_serde::to_vec_named(signed)
        .map_err(|error| EncryptionError::Serialization(error.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // aead_key is Zeroizing<[u8;32]> and will be wiped when it goes out of scope.
    let cipher = ChaCha20Poly1305::new_from_slice(aead_key.as_ref())
        .map_err(|_| EncryptionError::CipherInitFailed)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| EncryptionError::EncryptFailed)?;

    let payload_hash = sha256_hex(&ciphertext);

    Ok(EncryptedBatch {
        batch_id: signed.batch.batch_id,
        org_id: signed.batch.org_id.clone(),
        ephemeral_pubkey,
        nonce: nonce_bytes,
        ciphertext,
        payload_hash,
    })
}

#[cfg(test)]
pub(crate) fn decrypt_batch_for_tests(
    encrypted: &EncryptedBatch,
    vendor_static_secret: &[u8; 32],
) -> Result<SignedBatch, EncryptionError> {
    let mut shared_secret =
        Zeroizing::new(x25519(*vendor_static_secret, encrypted.ephemeral_pubkey));
    let aead_key = derive_aead_key(&shared_secret, &encrypted.ephemeral_pubkey)?;
    shared_secret.zeroize();
    let cipher = ChaCha20Poly1305::new_from_slice(aead_key.as_ref())
        .map_err(|_| EncryptionError::CipherInitFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_slice(),
        )
        .map_err(|_| EncryptionError::DecryptFailed)?;
    rmp_serde::from_slice(&plaintext)
        .map_err(|error| EncryptionError::Deserialization(error.to_string()))
}

/// Derives the ChaCha20-Poly1305 AEAD key from a Diffie-Hellman shared secret
/// using HKDF-SHA256 with the ephemeral public key as the salt.
///
/// Using the ephemeral public key as the salt is the standard ECIES construction:
/// it provides domain separation between different ephemeral key pairs so that
/// even if two ephemeral secrets coincidentally produced the same DH output, the
/// derived AEAD keys would still differ.  Returns the key wrapped in [`Zeroizing`]
/// so it is automatically overwritten when the value is dropped.
fn derive_aead_key(
    shared_secret: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_pubkey.as_slice()), shared_secret);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"soth-telemetry-v1", out.as_mut())
        .map_err(|_| EncryptionError::HkdfExpandFailed)?;
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

    use super::*;
    use crate::signing::build_signed_batch;
    use crate::types::TelemetryBatch;

    fn signed_batch() -> SignedBatch {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let events = vec![
            crate::test_utils::sample_event(uuid::Uuid::new_v4()),
            crate::test_utils::sample_event(uuid::Uuid::new_v4()),
        ];
        let batch = TelemetryBatch {
            batch_id: uuid::Uuid::new_v4(),
            org_id: "org-test".to_string(),
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            event_count: events.len() as u32,
            events,
            timestamp_utc: 1_700_000_000,
            observation_records: None,
        };
        match build_signed_batch(batch, &key) {
            Ok(signed) => signed,
            Err(error) => panic!("expected signed batch: {error}"),
        }
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let signed = signed_batch();
        let vendor_secret = [21u8; 32];
        let vendor_pubkey = x25519(vendor_secret, X25519_BASEPOINT_BYTES);

        let encrypted = match encrypt_batch(&signed, &vendor_pubkey) {
            Ok(batch) => batch,
            Err(error) => panic!("encryption should succeed: {error}"),
        };
        let recovered = match decrypt_batch_for_tests(&encrypted, &vendor_secret) {
            Ok(batch) => batch,
            Err(error) => panic!("decryption should succeed: {error}"),
        };

        assert_eq!(recovered.batch.batch_id, signed.batch.batch_id);
        assert_eq!(recovered.batch.event_count, signed.batch.event_count);
        assert_eq!(
            recovered
                .batch
                .events
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            signed
                .batch
                .events
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn uses_fresh_ephemeral_keypair_per_batch() {
        let signed = signed_batch();
        let vendor_secret = [22u8; 32];
        let vendor_pubkey = x25519(vendor_secret, X25519_BASEPOINT_BYTES);

        let first = match encrypt_batch(&signed, &vendor_pubkey) {
            Ok(batch) => batch,
            Err(error) => panic!("first encryption should succeed: {error}"),
        };
        let second = match encrypt_batch(&signed, &vendor_pubkey) {
            Ok(batch) => batch,
            Err(error) => panic!("second encryption should succeed: {error}"),
        };

        assert_ne!(first.ephemeral_pubkey, second.ephemeral_pubkey);
        assert_ne!(first.nonce, second.nonce);
    }
}
