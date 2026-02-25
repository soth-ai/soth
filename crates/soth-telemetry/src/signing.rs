use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::types::{SignedBatch, TelemetryBatch};

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("telemetry batch cannot be empty")]
    EmptyBatch,
    #[error("signing payload serialization failed: {0}")]
    Serialization(String),
}

pub fn signing_message(batch: &TelemetryBatch) -> Vec<u8> {
    let mut msg = batch.batch_id.as_bytes().to_vec();
    let mut event_ids: Vec<Uuid> = batch.events.iter().map(|event| event.event_id).collect();
    event_ids.sort_unstable();
    for event_id in event_ids {
        msg.extend_from_slice(event_id.as_bytes());
    }
    msg
}

pub fn sign_batch(batch: &TelemetryBatch, signing_key: &SigningKey) -> [u8; 64] {
    signing_key.sign(&signing_message(batch)).to_bytes()
}

pub fn build_signed_batch(
    batch: TelemetryBatch,
    signing_key: &SigningKey,
) -> Result<SignedBatch, SigningError> {
    if batch.events.is_empty() {
        return Err(SigningError::EmptyBatch);
    }

    let proxy_signature = sign_batch(&batch, signing_key);
    let proxy_pubkey = signing_key.verifying_key().to_bytes();
    let canonical_hash = signed_payload_hash(&batch, &proxy_signature, &proxy_pubkey)?;

    Ok(SignedBatch {
        proxy_signature,
        proxy_pubkey,
        canonical_hash,
        batch,
    })
}

fn signed_payload_hash(
    batch: &TelemetryBatch,
    proxy_signature: &[u8; 64],
    proxy_pubkey: &[u8; 32],
) -> Result<String, SigningError> {
    #[derive(serde::Serialize)]
    struct CanonicalSignedBatch {
        batch: TelemetryBatch,
        proxy_signature: Vec<u8>,
        proxy_pubkey: [u8; 32],
    }

    let payload = CanonicalSignedBatch {
        batch: batch.clone(),
        proxy_signature: proxy_signature.to_vec(),
        proxy_pubkey: *proxy_pubkey,
    };

    let encoded = rmp_serde::to_vec(&payload)
        .map_err(|error| SigningError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use uuid::Uuid;

    use super::*;
    use crate::types::TelemetryBatch;

    fn batch_with_ids(ids: &[Uuid]) -> TelemetryBatch {
        TelemetryBatch {
            batch_id: Uuid::new_v4(),
            org_id: "org-test".to_string(),
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            events: ids
                .iter()
                .copied()
                .map(crate::test_utils::sample_event)
                .collect(),
            event_count: ids.len() as u32,
            timestamp_utc: 1_700_000_000,
        }
    }

    #[test]
    fn sign_batch_verifies_with_matching_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let batch = batch_with_ids(&ids);
        let sig = sign_batch(&batch, &key);
        let verify_key: VerifyingKey = key.verifying_key();

        let result = verify_key.verify(&signing_message(&batch), &Signature::from_bytes(&sig));
        assert!(result.is_ok());
    }

    #[test]
    fn sign_batch_fails_with_wrong_key() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let batch = batch_with_ids(&ids);
        let sig = sign_batch(&batch, &key);

        let result = wrong_key
            .verifying_key()
            .verify(&signing_message(&batch), &Signature::from_bytes(&sig));
        assert!(result.is_err());
    }

    #[test]
    fn signing_message_is_order_invariant_by_event_id() {
        let id_a = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap_or(Uuid::nil());
        let id_b = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap_or(Uuid::nil());
        let id_c = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap_or(Uuid::nil());

        let batch1 = batch_with_ids(&[id_b, id_a, id_c]);
        let batch2 = batch_with_ids(&[id_c, id_b, id_a]);
        let mut batch2_same_id = batch2;
        batch2_same_id.batch_id = batch1.batch_id;

        assert_eq!(
            signing_message(&batch1),
            signing_message(&batch2_same_id),
            "message must be deterministic regardless of event insertion order"
        );
    }

    #[test]
    fn build_signed_batch_rejects_empty() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let batch = TelemetryBatch {
            batch_id: Uuid::new_v4(),
            org_id: "org-test".to_string(),
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            events: Vec::new(),
            event_count: 0,
            timestamp_utc: 0,
        };
        let result = build_signed_batch(batch, &key);
        assert!(matches!(result, Err(SigningError::EmptyBatch)));
    }
}
