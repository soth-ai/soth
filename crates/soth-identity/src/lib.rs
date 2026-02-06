//! SOTH Identity - Cryptographic identity for agents
//!
//! This crate provides Ed25519 key management, DID:key encoding/decoding,
//! RFC 8785 JSON canonicalization, and digital signatures.
//!
//! # Example
//!
//! ```rust
//! use soth_identity::{KeyPair, Did};
//!
//! // Generate a new key pair
//! let keypair = KeyPair::generate();
//!
//! // Create a DID from the public key
//! let did = Did::from_public_key(&keypair.public_key_bytes()).unwrap();
//!
//! // Sign some data
//! let signature = keypair.sign(b"hello world").unwrap();
//!
//! // Verify the signature
//! assert!(keypair.verify(b"hello world", &signature));
//! ```

pub mod canonicalization;
pub mod did;
pub mod keypair;
pub mod signing;
pub mod trust_store;

pub use canonicalization::{canonicalize_json, compute_hash, normalize_for_signing};
pub use did::Did;
pub use keypair::KeyPair;
pub use signing::{sign_json, verify_json_signature, SignedDocument};
pub use trust_store::TrustStore;

/// Decode a DID:key string and extract the public key
///
/// Returns the 32-byte Ed25519 public key if the DID is valid.
pub fn decode_did_key(did_string: &str) -> Result<[u8; 32]> {
    let did = Did::parse(did_string)?;
    did.extract_public_key()
}

/// Encode a public key as a DID:key string
///
/// Takes 32-byte Ed25519 public key and returns the DID URI.
pub fn encode_did_key(public_key: &[u8]) -> Result<String> {
    let did = Did::from_public_key(public_key)?;
    Ok(did.uri())
}

/// Re-export error types
pub use soth_core::error::{Result, SothError};
