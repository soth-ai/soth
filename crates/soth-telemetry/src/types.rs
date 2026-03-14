use serde::{Deserialize, Serialize};
use uuid::Uuid;

use soth_core::{ObservationEvent, TelemetryEvent};

/// Wrapper for ObservationEvent in telemetry batches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationTelemetryRecord {
    pub schema_version: u8,
    pub event: ObservationEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatch {
    pub batch_id: Uuid,
    pub org_id: String,
    pub proxy_version: String,
    pub bundle_version: String,
    pub events: Vec<TelemetryEvent>,
    pub event_count: u32,
    pub timestamp_utc: i64,
    /// Observation records from passive observer extensions.
    /// Optional to maintain backward compatibility with cloud consumers
    /// that do not yet process observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_records: Option<Vec<ObservationTelemetryRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatch {
    pub batch: TelemetryBatch,
    #[serde(with = "arr64")]
    pub proxy_signature: [u8; 64],
    pub proxy_pubkey: [u8; 32],
    pub canonical_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBatch {
    pub batch_id: Uuid,
    pub org_id: String,
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransmittedBatch {
    Signed(SignedBatch),
    Encrypted(EncryptedBatch),
}

impl TransmittedBatch {
    pub fn batch_id(&self) -> Uuid {
        match self {
            Self::Signed(batch) => batch.batch.batch_id,
            Self::Encrypted(batch) => batch.batch_id,
        }
    }

    pub fn org_id(&self) -> &str {
        match self {
            Self::Signed(batch) => &batch.batch.org_id,
            Self::Encrypted(batch) => &batch.org_id,
        }
    }

    pub fn payload_hash(&self) -> &str {
        match self {
            Self::Signed(batch) => &batch.canonical_hash,
            Self::Encrypted(batch) => &batch.payload_hash,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }
}

mod arr64 {
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(D::Error::invalid_length(
                bytes.len(),
                &"64-byte Ed25519 signature",
            ));
        }

        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
