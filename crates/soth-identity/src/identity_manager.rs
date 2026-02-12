//! Unified key hierarchy manager for organization/user/agent identities.
//!
//! This provides deterministic hardened key derivation from an organization seed,
//! active key lookup, key rotation, and verification across historical key versions.

use crate::{Did, KeyPair};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use soth_core::error::{Result, SothError};
use std::collections::HashMap;

const HARDENED_OFFSET: u32 = 0x8000_0000;
const DERIVATION_PURPOSE: u32 = 44;
const DERIVATION_APP: u32 = 73_684; // "soth" namespace
const SLIP10_MASTER_KEY: &[u8] = b"ed25519 seed";
const HMAC_BLOCK_SIZE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
    Org,
    User { user_id: String },
    Agent { user_id: String, agent_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Rotated,
}

#[derive(Debug, Clone)]
pub struct IdentityKeyVersion {
    pub key_id: String,
    pub did: String,
    pub principal: Principal,
    pub version: u32,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    keypair: KeyPair,
}

impl IdentityKeyVersion {
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.keypair.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.keypair.verify(message, signature)
    }
}

#[derive(Debug, Clone)]
pub struct VerificationMatch {
    pub key_id: String,
    pub did: String,
    pub version: u32,
    pub is_active: bool,
}

/// Deterministic identity manager for org/user/agent key lifecycle.
pub struct IdentityManager {
    org_id: String,
    org_seed: Vec<u8>,
    key_versions: HashMap<Principal, Vec<IdentityKeyVersion>>,
}

impl IdentityManager {
    /// Create a manager from an organization identifier and root seed bytes.
    pub fn new(org_id: impl Into<String>, org_seed: &[u8]) -> Result<Self> {
        if org_seed.len() < 16 {
            return Err(SothError::Identity(format!(
                "Organization seed too short: expected at least 16 bytes, got {}",
                org_seed.len()
            )));
        }

        Ok(Self {
            org_id: org_id.into(),
            org_seed: org_seed.to_vec(),
            key_versions: HashMap::new(),
        })
    }

    /// Return active key for principal, deriving version `0` if it does not exist.
    pub fn active_key(&mut self, principal: Principal) -> Result<IdentityKeyVersion> {
        if let Some(existing) = self.active_key_ref(&principal) {
            return Ok(existing.clone());
        }
        let derived = self.derive_version(&principal, 0)?;
        self.key_versions
            .entry(principal)
            .or_default()
            .push(derived.clone());
        Ok(derived)
    }

    /// Rotate principal to a new active key version and retain historical versions.
    pub fn rotate_key(&mut self, principal: Principal) -> Result<IdentityKeyVersion> {
        // Ensure every principal starts at v0 so rotate semantics are always "advance".
        if self.active_key_ref(&principal).is_none() {
            let _ = self.active_key(principal.clone())?;
        }

        let now = Utc::now();
        let next_version = {
            let versions = self.key_versions.entry(principal.clone()).or_default();
            let mut candidate = 0u32;
            for existing in versions.iter_mut() {
                if existing.status == KeyStatus::Active {
                    existing.status = KeyStatus::Rotated;
                    existing.rotated_at = Some(now);
                }
                candidate = candidate.max(existing.version.saturating_add(1));
            }
            candidate
        };

        let mut derived = self.derive_version(&principal, next_version)?;
        derived.created_at = now;
        let versions = self.key_versions.entry(principal).or_default();
        versions.push(derived.clone());
        Ok(derived)
    }

    /// Verify signature across active + historical key versions for a principal.
    pub fn verify_with_historical_keys(
        &self,
        principal: &Principal,
        message: &[u8],
        signature: &[u8],
    ) -> Option<VerificationMatch> {
        let versions = self.key_versions.get(principal)?;
        versions.iter().find_map(|candidate| {
            if candidate.verify(message, signature) {
                Some(VerificationMatch {
                    key_id: candidate.key_id.clone(),
                    did: candidate.did.clone(),
                    version: candidate.version,
                    is_active: candidate.status == KeyStatus::Active,
                })
            } else {
                None
            }
        })
    }

    /// Get all known key versions for principal (active + historical).
    pub fn key_history(&self, principal: &Principal) -> Vec<IdentityKeyVersion> {
        self.key_versions
            .get(principal)
            .cloned()
            .unwrap_or_default()
    }

    fn active_key_ref(&self, principal: &Principal) -> Option<&IdentityKeyVersion> {
        self.key_versions.get(principal).and_then(|versions| {
            versions
                .iter()
                .find(|entry| entry.status == KeyStatus::Active)
        })
    }

    fn derive_version(&self, principal: &Principal, version: u32) -> Result<IdentityKeyVersion> {
        let mut path = vec![
            hardened(DERIVATION_PURPOSE),
            hardened(DERIVATION_APP),
            hardened(hash_index(self.org_id.as_bytes())),
        ];

        match principal {
            Principal::Org => {
                path.push(hardened(0));
            }
            Principal::User { user_id } => {
                path.push(hardened(1));
                path.push(hardened(hash_index(user_id.as_bytes())));
            }
            Principal::Agent { user_id, agent_id } => {
                path.push(hardened(2));
                path.push(hardened(hash_index(user_id.as_bytes())));
                path.push(hardened(hash_index(agent_id.as_bytes())));
            }
        }

        path.push(hardened(version));

        let private_key = derive_slip10_private_key(&self.org_seed, &path)?;
        let keypair = KeyPair::from_private_key_bytes(&private_key)?;
        let did = Did::from_key_pair(&keypair)?.uri();
        let key_id = key_id_for(principal, version);

        Ok(IdentityKeyVersion {
            key_id,
            did,
            principal: principal.clone(),
            version,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_at: None,
            keypair,
        })
    }
}

fn key_id_for(principal: &Principal, version: u32) -> String {
    match principal {
        Principal::Org => format!("org:root:v{version}"),
        Principal::User { user_id } => format!("user:{user_id}:v{version}"),
        Principal::Agent { user_id, agent_id } => format!("agent:{user_id}:{agent_id}:v{version}"),
    }
}

fn hash_index(value: &[u8]) -> u32 {
    let digest = Sha256::digest(value);
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest[..4]);
    u32::from_be_bytes(bytes) & 0x7fff_ffff
}

fn hardened(index: u32) -> u32 {
    index | HARDENED_OFFSET
}

fn derive_slip10_private_key(seed: &[u8], path: &[u32]) -> Result<[u8; 32]> {
    let master = hmac_sha512(SLIP10_MASTER_KEY, seed);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&master[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&master[32..]);

    for index in path {
        if (index & HARDENED_OFFSET) == 0 {
            return Err(SothError::Identity(format!(
                "Non-hardened index not supported for ed25519 derivation: {index}"
            )));
        }

        let mut data = Vec::with_capacity(1 + 32 + 4);
        data.push(0u8);
        data.extend_from_slice(&secret);
        data.extend_from_slice(&index.to_be_bytes());
        let output = hmac_sha512(&chain_code, &data);
        secret.copy_from_slice(&output[..32]);
        chain_code.copy_from_slice(&output[32..]);
    }

    Ok(secret)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut normalized_key = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        let digest = Sha512::digest(key);
        normalized_key[..64].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; HMAC_BLOCK_SIZE];
    let mut opad = [0u8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] = normalized_key[i] ^ 0x36;
        opad[i] = normalized_key[i] ^ 0x5c;
    }

    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_digest);
    let output = outer.finalize();

    let mut result = [0u8; 64];
    result.copy_from_slice(&output);
    result
}

#[cfg(test)]
mod tests {
    use super::{IdentityManager, KeyStatus, Principal};

    #[test]
    fn deterministic_derivation_for_same_seed_and_principal() {
        let seed = b"org-seed-deterministic-32-bytes----";
        let mut mgr_a = IdentityManager::new("org-acme", seed).unwrap();
        let mut mgr_b = IdentityManager::new("org-acme", seed).unwrap();

        let key_a = mgr_a
            .active_key(Principal::User {
                user_id: "alice".to_string(),
            })
            .unwrap();
        let key_b = mgr_b
            .active_key(Principal::User {
                user_id: "alice".to_string(),
            })
            .unwrap();

        assert_eq!(key_a.did, key_b.did);
        assert_eq!(key_a.key_id, key_b.key_id);
        assert_eq!(key_a.version, 0);
    }

    #[test]
    fn different_principals_derive_different_keys() {
        let seed = b"org-seed-deterministic-32-bytes----";
        let mut mgr = IdentityManager::new("org-acme", seed).unwrap();

        let user_key = mgr
            .active_key(Principal::User {
                user_id: "alice".to_string(),
            })
            .unwrap();
        let agent_key = mgr
            .active_key(Principal::Agent {
                user_id: "alice".to_string(),
                agent_id: "codex".to_string(),
            })
            .unwrap();

        assert_ne!(user_key.did, agent_key.did);
        assert_ne!(user_key.key_id, agent_key.key_id);
    }

    #[test]
    fn rotate_key_preserves_historical_verification() {
        let seed = b"org-seed-deterministic-32-bytes----";
        let principal = Principal::Agent {
            user_id: "alice".to_string(),
            agent_id: "codex".to_string(),
        };
        let mut mgr = IdentityManager::new("org-acme", seed).unwrap();
        let active_v0 = mgr.active_key(principal.clone()).unwrap();
        let message = b"event-envelope-metadata";
        let sig_v0 = active_v0.sign(message).unwrap();

        let active_v1 = mgr.rotate_key(principal.clone()).unwrap();
        assert_eq!(active_v1.version, 1);
        assert_eq!(active_v1.status, KeyStatus::Active);
        assert_ne!(active_v1.did, active_v0.did);

        let historical_match = mgr
            .verify_with_historical_keys(&principal, message, &sig_v0)
            .expect("historical v0 key should still verify");
        assert_eq!(historical_match.key_id, active_v0.key_id);
        assert!(!historical_match.is_active);

        let sig_v1 = active_v1.sign(message).unwrap();
        let active_match = mgr
            .verify_with_historical_keys(&principal, message, &sig_v1)
            .expect("active v1 key should verify");
        assert_eq!(active_match.key_id, active_v1.key_id);
        assert!(active_match.is_active);
    }

    #[test]
    fn rotate_without_existing_key_creates_v0_then_v1() {
        let seed = b"org-seed-deterministic-32-bytes----";
        let principal = Principal::User {
            user_id: "alice".to_string(),
        };
        let mut mgr = IdentityManager::new("org-acme", seed).unwrap();

        let active = mgr.rotate_key(principal.clone()).unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.status, KeyStatus::Active);

        let history = mgr.key_history(&principal);
        assert_eq!(history.len(), 2);
        assert!(history
            .iter()
            .any(|k| k.version == 0 && k.status == KeyStatus::Rotated));
        assert!(history
            .iter()
            .any(|k| k.version == 1 && k.status == KeyStatus::Active));
    }
}
