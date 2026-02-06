//! Ed25519 key pair management
//!
//! Provides secure key generation, serialization, and storage for agent identity.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use soth_core::error::{Result, SothError};
use std::path::Path;

/// Ed25519 key pair for agent identity
#[derive(Clone)]
pub struct KeyPair {
    /// The signing key (private key)
    signing_key: Option<SigningKey>,
    /// The verifying key (public key)
    verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key: Some(signing_key),
            verifying_key,
        }
    }

    /// Create a key pair from raw private key bytes (32 bytes)
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(SothError::Identity(format!(
                "Invalid private key length: expected 32, got {}",
                bytes.len()
            )));
        }

        let signing_key = SigningKey::try_from(bytes)
            .map_err(|e| SothError::Identity(format!("Invalid private key: {e}")))?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key,
        })
    }

    /// Create a key pair from base64-encoded private key
    pub fn from_private_key_base64(encoded: &str) -> Result<Self> {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
                .map_err(|e| SothError::Identity(format!("Invalid base64: {e}")))?;

        Self::from_private_key_bytes(&bytes)
    }

    /// Create a key pair from PEM-encoded private key
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| SothError::Identity(format!("Invalid PEM encoding: {e}")))?;

        // Parse PEM format
        // Expected format: -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----
        let base64_content: String = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();

        let der_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_content)
                .map_err(|e| SothError::Identity(format!("Invalid PEM base64: {e}")))?;

        // PKCS#8 format: extract the raw 32-byte Ed25519 key from DER
        // The raw key is at the end of the DER structure
        if der_bytes.len() < 32 {
            return Err(SothError::Identity("PEM data too short".to_string()));
        }

        // For Ed25519 PKCS#8, the key is typically at offset 16 in a 48-byte structure
        // or we can try the last 32 bytes
        let key_bytes = if der_bytes.len() >= 48 {
            &der_bytes[16..48]
        } else {
            &der_bytes[der_bytes.len() - 32..]
        };

        Self::from_private_key_bytes(key_bytes)
    }

    /// Load a key pair from a PEM file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let pem_data = std::fs::read(path.as_ref())?;
        Self::from_pem(&pem_data)
    }

    /// Create a verification-only key pair from public key bytes
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(SothError::Identity(format!(
                "Invalid public key length: expected 32, got {}",
                bytes.len()
            )));
        }

        let verifying_key = VerifyingKey::try_from(bytes)
            .map_err(|e| SothError::Identity(format!("Invalid public key: {e}")))?;

        Ok(Self {
            signing_key: None,
            verifying_key,
        })
    }

    /// Create a verification-only key pair from base64-encoded public key
    pub fn from_public_key_base64(encoded: &str) -> Result<Self> {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
                .map_err(|e| SothError::Identity(format!("Invalid base64: {e}")))?;

        Self::from_public_key_bytes(&bytes)
    }

    /// Get the raw private key bytes (32 bytes)
    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        self.signing_key
            .as_ref()
            .map(|k| k.to_bytes())
            .ok_or_else(|| SothError::Identity("No private key available".to_string()))
    }

    /// Get the raw public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get base64url-encoded private key
    pub fn private_key_base64(&self) -> Result<String> {
        let bytes = self.private_key_bytes()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ))
    }

    /// Get base64url-encoded public key
    pub fn public_key_base64(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            self.public_key_bytes(),
        )
    }

    /// Export to PEM format
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        let private_bytes = self.private_key_bytes()?;

        // Create PKCS#8 DER structure for Ed25519
        // OID: 1.3.101.112
        let mut der = vec![
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING, 34 bytes
            0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
        ];
        der.extend_from_slice(&private_bytes);

        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);

        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");

        Ok(pem.into_bytes())
    }

    /// Save to a PEM file with restricted permissions
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let pem_data = self.to_pem()?;
        std::fs::write(path.as_ref(), &pem_data)?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path.as_ref(), perms)?;
        }

        Ok(())
    }

    /// Sign a message with the private key
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| SothError::Signing("No private key available".to_string()))?;

        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Sign a message and return base64-encoded signature
    pub fn sign_base64(&self, message: &[u8]) -> Result<String> {
        let signature = self.sign(message)?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature,
        ))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }

        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying_key.verify(message, &sig).is_ok()
    }

    /// Verify a base64-encoded signature
    pub fn verify_base64(&self, message: &[u8], signature_b64: &str) -> bool {
        let signature = match base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature_b64,
        ) {
            Ok(s) => s,
            Err(_) => return false,
        };

        self.verify(message, &signature)
    }

    /// Check if this key pair can sign (has private key)
    pub fn can_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Get a SHA-256 fingerprint of the public key
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get a short fingerprint (first 16 hex chars)
    pub fn short_fingerprint(&self) -> String {
        self.fingerprint()[..16].to_string()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_type = if self.can_sign() {
            "full"
        } else {
            "verify-only"
        };
        f.debug_struct("KeyPair")
            .field("type", &key_type)
            .field("fingerprint", &self.short_fingerprint())
            .finish()
    }
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.public_key_bytes() == other.public_key_bytes()
    }
}

impl Eq for KeyPair {}

impl std::hash::Hash for KeyPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_key_bytes().hash(state);
    }
}

// Hex encoding helper
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = KeyPair::generate();
        assert!(kp.can_sign());
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let kp = KeyPair::generate();
        let message = b"hello world";

        let signature = kp.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        assert!(kp.verify(message, &signature));
        assert!(!kp.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_sign_verify_base64() {
        let kp = KeyPair::generate();
        let message = b"test message";

        let sig_b64 = kp.sign_base64(message).unwrap();
        assert!(kp.verify_base64(message, &sig_b64));
    }

    #[test]
    fn test_verify_only_keypair() {
        let kp = KeyPair::generate();
        let pub_bytes = kp.public_key_bytes();

        let verify_only = KeyPair::from_public_key_bytes(&pub_bytes).unwrap();
        assert!(!verify_only.can_sign());

        // Can still verify
        let message = b"test";
        let signature = kp.sign(message).unwrap();
        assert!(verify_only.verify(message, &signature));
    }

    #[test]
    fn test_fingerprint() {
        let kp = KeyPair::generate();
        let fp = kp.fingerprint();
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_base64_roundtrip() {
        let kp = KeyPair::generate();
        let priv_b64 = kp.private_key_base64().unwrap();
        let pub_b64 = kp.public_key_base64();

        let kp2 = KeyPair::from_private_key_base64(&priv_b64).unwrap();
        assert_eq!(kp.public_key_bytes(), kp2.public_key_bytes());

        let kp3 = KeyPair::from_public_key_base64(&pub_b64).unwrap();
        assert_eq!(kp.public_key_bytes(), kp3.public_key_bytes());
    }
}
