//! Identity integration tests
//!
//! Tests for keygen → sign → verify round-trip

use soth_identity::{KeyPair, Did, TrustStore, sign_json, verify_json_signature};
use tempfile::tempdir;

#[test]
fn test_keypair_generation_and_signing() {
    // Generate a new keypair
    let keypair = KeyPair::generate();

    // Verify it can sign
    assert!(keypair.can_sign());

    // Sign a message
    let message = b"Hello, SOTH!";
    let signature = keypair.sign(message).expect("signing should succeed");

    // Verify the signature
    assert!(keypair.verify(message, &signature));

    // Verify fails with wrong message
    assert!(!keypair.verify(b"Wrong message", &signature));
}

#[test]
fn test_did_encoding_roundtrip() {
    // Generate keypair
    let keypair = KeyPair::generate();

    // Create DID from public key
    let did = Did::from_public_key(&keypair.public_key_bytes())
        .expect("DID creation should succeed");

    // Get the DID URI
    let uri = did.uri();
    assert!(uri.starts_with("did:key:z"));

    // Parse the DID back
    let parsed = Did::parse(&uri).expect("DID parsing should succeed");

    // Extract public key and verify it matches
    let extracted_key = parsed.extract_public_key()
        .expect("public key extraction should succeed");
    assert_eq!(extracted_key, keypair.public_key_bytes());
}

#[test]
fn test_did_from_keypair() {
    let keypair = KeyPair::generate();

    // Create DID from keypair
    let did = Did::from_key_pair(&keypair)
        .expect("DID from keypair should succeed");

    // The fingerprint should be consistent
    let fingerprint1 = did.fingerprint();
    let fingerprint2 = did.fingerprint();
    assert_eq!(fingerprint1, fingerprint2);
}

#[test]
fn test_trust_store_operations() {
    let dir = tempdir().expect("temp dir creation should succeed");
    let store_path = dir.path().join("trust_store");

    // Create trust store
    let mut store = TrustStore::new(&store_path)
        .expect("trust store creation should succeed");

    // Generate a DID
    let keypair = KeyPair::generate();
    let did = Did::from_key_pair(&keypair).expect("DID creation should succeed");
    let did_uri = did.uri();

    // Initially not trusted
    assert!(!store.is_trusted(&did_uri));

    // Trust the DID
    store.trust(&did_uri).expect("trusting should succeed");
    assert!(store.is_trusted(&did_uri));

    // List should include it
    let list = store.list();
    assert!(list.iter().any(|d| d == &did_uri));

    // Untrust
    store.untrust(&did_uri).expect("untrusting should succeed");
    assert!(!store.is_trusted(&did_uri));
}

#[test]
fn test_json_signing_and_verification() {
    let keypair = KeyPair::generate();
    let did = Did::from_key_pair(&keypair).expect("DID creation should succeed");

    // Create JSON data to sign
    let data = serde_json::json!({
        "action": "tools/call",
        "tool": "read_file",
        "arguments": {
            "path": "/tmp/test.txt"
        }
    });

    // Sign the JSON
    let signed = sign_json(&data, &keypair, &did.uri())
        .expect("JSON signing should succeed");

    // Verify the signed document
    let is_valid = verify_json_signature(&signed, &keypair)
        .expect("verification should succeed");
    assert!(is_valid);

    // The signed document should contain the original data
    assert_eq!(signed.content["action"], "tools/call");
    assert_eq!(signed.content["tool"], "read_file");
}

#[test]
fn test_keypair_serialization() {
    let keypair = KeyPair::generate();

    // Get private key bytes
    let private_bytes = keypair.private_key_bytes()
        .expect("private key bytes should be available");
    assert_eq!(private_bytes.len(), 32);

    // Recreate keypair from bytes
    let restored = KeyPair::from_private_key_bytes(&private_bytes)
        .expect("keypair restoration should succeed");

    // Both should produce same signatures
    let message = b"test message";
    let sig1 = keypair.sign(message).expect("signing should succeed");
    let sig2 = restored.sign(message).expect("signing should succeed");

    assert_eq!(sig1, sig2);
}

#[test]
fn test_public_key_only_keypair() {
    let full_keypair = KeyPair::generate();

    // Create verify-only keypair
    let verify_only = KeyPair::from_public_key_bytes(&full_keypair.public_key_bytes())
        .expect("public key only keypair should succeed");

    // Cannot sign
    assert!(!verify_only.can_sign());

    // But can verify
    let message = b"test";
    let signature = full_keypair.sign(message).expect("signing should succeed");
    assert!(verify_only.verify(message, &signature));
}

#[test]
fn test_fingerprint_consistency() {
    let keypair = KeyPair::generate();

    // Fingerprint should be consistent
    let fp1 = keypair.fingerprint();
    let fp2 = keypair.fingerprint();
    assert_eq!(fp1, fp2);

    // Short fingerprint is prefix of full fingerprint
    let short = keypair.short_fingerprint();
    assert!(fp1.starts_with(&short));
    assert_eq!(short.len(), 16);
}

#[test]
fn test_base64_signature() {
    let keypair = KeyPair::generate();
    let message = b"Hello World";

    // Sign with base64 encoding
    let sig_b64 = keypair.sign_base64(message)
        .expect("base64 signing should succeed");

    // Verify with base64
    assert!(keypair.verify_base64(message, &sig_b64));

    // Invalid base64 should fail gracefully
    assert!(!keypair.verify_base64(message, "not-valid-base64!!!"));
}
