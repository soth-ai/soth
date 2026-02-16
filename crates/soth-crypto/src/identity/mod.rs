//! SOTH identity primitives.

pub mod canonicalization;
pub mod did;
pub mod identity_manager;
pub mod keypair;
pub mod signing;
pub mod trust_store;

pub use canonicalization::{canonicalize_json, compute_hash, normalize_for_signing};
pub use did::Did;
pub use identity_manager::{
    IdentityKeyVersion, IdentityManager, KeyStatus, Principal, VerificationMatch,
};
pub use keypair::KeyPair;
pub use signing::{sign_json, verify_json_signature, SignedDocument};
pub use trust_store::TrustStore;

/// Decode a DID:key string and extract the public key.
pub fn decode_did_key(did_string: &str) -> Result<[u8; 32]> {
    let did = Did::parse(did_string)?;
    did.extract_public_key()
}

/// Encode a public key as a DID:key string.
pub fn encode_did_key(public_key: &[u8]) -> Result<String> {
    let did = Did::from_public_key(public_key)?;
    Ok(did.uri())
}

pub use soth_core::error::{Result, SothError};
