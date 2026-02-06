//! JSON document signing and verification
//!
//! Provides functions to sign and verify JSON documents using Ed25519 signatures
//! with RFC 8785 canonicalization.

use crate::canonicalization::{canonicalize_json, normalize_for_signing};
use crate::keypair::KeyPair;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soth_core::error::{Result, SothError};

/// A signed JSON document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDocument {
    /// The original document content
    #[serde(flatten)]
    pub content: serde_json::Value,

    /// The signature block
    pub signature: SignatureBlock,
}

/// Signature metadata block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Signature algorithm (always "Ed25519")
    pub algorithm: String,

    /// Base64url-encoded signature
    pub value: String,

    /// DID of the signer
    pub signer: String,

    /// When the signature was created
    pub created: DateTime<Utc>,
}

/// Sign a JSON document
///
/// Creates a canonical representation of the document (excluding any existing
/// signature fields), signs it with the provided key pair, and returns a
/// SignedDocument with the signature attached.
pub fn sign_json(
    document: &serde_json::Value,
    keypair: &KeyPair,
    did: &str,
) -> Result<SignedDocument> {
    // Normalize the document (remove existing signature fields)
    let normalized = normalize_for_signing(document, true)?;

    // Canonicalize the normalized document
    let canonical = canonicalize_json(&normalized)?;

    // Sign the canonical bytes
    let signature = keypair.sign(&canonical)?;
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &signature,
    );

    // Create the signature block
    let signature_block = SignatureBlock {
        algorithm: "Ed25519".to_string(),
        value: signature_b64,
        signer: did.to_string(),
        created: Utc::now(),
    };

    Ok(SignedDocument {
        content: document.clone(),
        signature: signature_block,
    })
}

/// Verify a signed JSON document
///
/// Extracts the signature, recreates the canonical form of the document,
/// and verifies the signature using the provided key pair or the DID in
/// the signature block.
pub fn verify_json_signature(document: &SignedDocument, keypair: &KeyPair) -> Result<bool> {
    // Normalize the content (remove signature fields)
    let normalized = normalize_for_signing(&document.content, true)?;

    // Canonicalize
    let canonical = canonicalize_json(&normalized)?;

    // Decode the signature
    let signature = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &document.signature.value,
    )
    .map_err(|e| SothError::SignatureVerification(format!("Invalid signature encoding: {e}")))?;

    // Verify
    Ok(keypair.verify(&canonical, &signature))
}

/// Verify a signed document by extracting the key from the DID
pub fn verify_json_signature_from_did(document: &SignedDocument) -> Result<bool> {
    // Parse the DID from the signature
    let did = crate::did::Did::parse(&document.signature.signer)?;

    // Get a verification key pair from the DID
    let keypair = did.to_key_pair()?;

    // Verify
    verify_json_signature(document, &keypair)
}

/// Sign arbitrary bytes and return signature with metadata
pub fn sign_bytes(data: &[u8], keypair: &KeyPair, did: &str) -> Result<SignatureBlock> {
    let signature = keypair.sign(data)?;
    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &signature,
    );

    Ok(SignatureBlock {
        algorithm: "Ed25519".to_string(),
        value: signature_b64,
        signer: did.to_string(),
        created: Utc::now(),
    })
}

/// Verify a signature on arbitrary bytes
pub fn verify_bytes(data: &[u8], signature: &SignatureBlock, keypair: &KeyPair) -> Result<bool> {
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &signature.value,
    )
    .map_err(|e| SothError::SignatureVerification(format!("Invalid signature encoding: {e}")))?;

    Ok(keypair.verify(data, &sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::Did;
    use serde_json::json;

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap();

        let document = json!({
            "name": "Test Agent",
            "version": "1.0"
        });

        let signed = sign_json(&document, &keypair, &did.uri()).unwrap();

        assert!(verify_json_signature(&signed, &keypair).unwrap());
    }

    #[test]
    fn test_verify_from_did() {
        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap();

        let document = json!({
            "type": "AgentFacts",
            "data": "test"
        });

        let signed = sign_json(&document, &keypair, &did.uri()).unwrap();

        assert!(verify_json_signature_from_did(&signed).unwrap());
    }

    #[test]
    fn test_tampered_document() {
        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap();

        let document = json!({"value": 100});
        let mut signed = sign_json(&document, &keypair, &did.uri()).unwrap();

        // Tamper with the content
        signed.content["value"] = json!(200);

        // Verification should fail
        assert!(!verify_json_signature(&signed, &keypair).unwrap());
    }

    #[test]
    fn test_wrong_key() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let did1 = Did::from_key_pair(&keypair1).unwrap();

        let document = json!({"test": true});
        let signed = sign_json(&document, &keypair1, &did1.uri()).unwrap();

        // Verification with wrong key should fail
        assert!(!verify_json_signature(&signed, &keypair2).unwrap());
    }

    #[test]
    fn test_signature_block() {
        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap();

        let document = json!({"data": "test"});
        let signed = sign_json(&document, &keypair, &did.uri()).unwrap();

        assert_eq!(signed.signature.algorithm, "Ed25519");
        assert_eq!(signed.signature.signer, did.uri());
        assert!(!signed.signature.value.is_empty());
    }

    #[test]
    fn test_sign_bytes() {
        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap();

        let data = b"hello world";
        let signature = sign_bytes(data, &keypair, &did.uri()).unwrap();

        assert!(verify_bytes(data, &signature, &keypair).unwrap());
        assert!(!verify_bytes(b"wrong data", &signature, &keypair).unwrap());
    }
}
