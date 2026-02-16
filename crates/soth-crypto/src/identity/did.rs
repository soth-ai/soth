//! Decentralized Identifier (DID) implementation
//!
//! Implements the did:key method using Ed25519 public keys.
//! DID Format: did:key:z6Mk<base58-multibase-encoded-public-key>

use super::keypair::KeyPair;
use sha2::{Digest, Sha256};
use soth_core::error::{Result, SothError};

/// Multicodec prefix for Ed25519 public key (0xed01)
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xED, 0x01];

/// Base58 Bitcoin alphabet
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decentralized Identifier using the did:key method
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    /// DID method (e.g., "key")
    pub method: String,
    /// Method-specific identifier (e.g., "z6Mk...")
    pub identifier: String,
}

impl Did {
    /// Create a DID from Ed25519 public key bytes
    ///
    /// The identifier is created by:
    /// 1. Prepending the Ed25519 multicodec prefix (0xed01)
    /// 2. Base58-encoding the result
    /// 3. Prepending 'z' (multibase prefix for base58btc)
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != 32 {
            return Err(SothError::InvalidDid(format!(
                "Invalid public key length: expected 32, got {}",
                public_key.len()
            )));
        }

        // Prepend multicodec prefix
        let mut multicodec_key = Vec::with_capacity(34);
        multicodec_key.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        multicodec_key.extend_from_slice(public_key);

        // Base58 encode
        let encoded = base58_encode(&multicodec_key);

        // Add multibase prefix 'z' for base58btc
        let identifier = format!("z{encoded}");

        Ok(Self {
            method: "key".to_string(),
            identifier,
        })
    }

    /// Create a DID from a KeyPair
    pub fn from_key_pair(key_pair: &KeyPair) -> Result<Self> {
        Self::from_public_key(&key_pair.public_key_bytes())
    }

    /// Generate a new DID with a fresh key pair
    pub fn generate() -> (Self, KeyPair) {
        let key_pair = KeyPair::generate();
        let did = Self::from_key_pair(&key_pair).expect("KeyPair always has valid public key");
        (did, key_pair)
    }

    /// Parse a DID string
    pub fn parse(did_string: &str) -> Result<Self> {
        if !did_string.starts_with("did:") {
            return Err(SothError::InvalidDid(format!(
                "Invalid DID format: must start with 'did:' - got {did_string}"
            )));
        }

        let parts: Vec<&str> = did_string.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(SothError::InvalidDid(format!(
                "Invalid DID format: expected 'did:method:identifier' - got {did_string}"
            )));
        }

        let method = parts[1].to_string();
        let identifier = parts[2].to_string();

        // Validate did:key format
        if method == "key" {
            if !identifier.starts_with('z') {
                return Err(SothError::InvalidDid(format!(
                    "Invalid did:key format: identifier must start with 'z' - got {identifier}"
                )));
            }

            // Validate that we can decode the identifier
            let did = Self { method, identifier };
            did.extract_public_key()?;
            return Ok(did);
        }

        Ok(Self { method, identifier })
    }

    /// Extract the Ed25519 public key from a did:key DID
    pub fn extract_public_key(&self) -> Result<[u8; 32]> {
        if self.method != "key" {
            return Err(SothError::InvalidDid(format!(
                "Cannot extract public key from did:{} - only did:key is supported",
                self.method
            )));
        }

        if !self.identifier.starts_with('z') {
            return Err(SothError::InvalidDid(
                "Invalid multibase prefix (expected 'z' for base58btc)".to_string(),
            ));
        }

        // Decode base58 (skip the 'z' prefix)
        let decoded = base58_decode(&self.identifier[1..])?;

        // Verify and strip multicodec prefix
        if decoded.len() < 2
            || decoded[0] != ED25519_MULTICODEC_PREFIX[0]
            || decoded[1] != ED25519_MULTICODEC_PREFIX[1]
        {
            return Err(SothError::InvalidDid(
                "Invalid multicodec prefix (expected Ed25519 0xed01)".to_string(),
            ));
        }

        let public_key = &decoded[2..];
        if public_key.len() != 32 {
            return Err(SothError::InvalidDid(format!(
                "Invalid public key length: expected 32 bytes, got {}",
                public_key.len()
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(public_key);
        Ok(result)
    }

    /// Convert to a verification-only KeyPair
    pub fn to_key_pair(&self) -> Result<KeyPair> {
        let public_key = self.extract_public_key()?;
        KeyPair::from_public_key_bytes(&public_key)
    }

    /// Get the full DID URI
    pub fn uri(&self) -> String {
        format!("did:{}:{}", self.method, self.identifier)
    }

    /// Get a shortened identifier for display
    pub fn short_id(&self, length: usize) -> String {
        if self.identifier.len() > length {
            self.identifier[..length].to_string()
        } else {
            self.identifier.clone()
        }
    }

    /// Get a SHA-256 fingerprint of the DID
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.uri().as_bytes());
        let hash = hasher.finalize();
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string()
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.uri())
    }
}

impl std::str::FromStr for Did {
    type Err = SothError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl serde::Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.uri())
    }
}

impl<'de> serde::Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Encode bytes to base58 (Bitcoin alphabet)
fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Convert bytes to a big integer
    let mut num = data.iter().fold(num_bigint::BigUint::ZERO, |acc, &byte| {
        (acc << 8) + num_bigint::BigUint::from(byte)
    });

    let mut result = Vec::new();
    let fifty_eight = num_bigint::BigUint::from(58u32);

    while num > num_bigint::BigUint::ZERO {
        let (div, rem) = num.div_rem(&fifty_eight);
        let rem_u8: u8 = rem.try_into().unwrap_or(0);
        result.push(BASE58_ALPHABET[rem_u8 as usize]);
        num = div;
    }

    // Handle leading zeros
    for byte in data {
        if *byte == 0 {
            result.push(BASE58_ALPHABET[0]);
        } else {
            break;
        }
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

/// Decode base58 string to bytes
fn base58_decode(encoded: &str) -> Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    let mut num = num_bigint::BigUint::ZERO;
    let fifty_eight = num_bigint::BigUint::from(58u32);

    for c in encoded.chars() {
        let idx = BASE58_ALPHABET
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| SothError::InvalidDid(format!("Invalid base58 character: {c}")))?;
        num = num * &fifty_eight + num_bigint::BigUint::from(idx);
    }

    // Convert to bytes
    let bytes = num.to_bytes_be();

    // Handle leading '1's (zeros)
    let mut leading_zeros = 0;
    for c in encoded.chars() {
        if c == '1' {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    let mut result = vec![0u8; leading_zeros];
    result.extend_from_slice(&bytes);
    Ok(result)
}

// BigUint implementation for base58 encoding/decoding
mod num_bigint {
    use std::ops::{Add, Mul, Shl};

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct BigUint {
        digits: Vec<u32>, // Little-endian
    }

    impl BigUint {
        pub const ZERO: Self = Self { digits: Vec::new() };

        fn normalize(&mut self) {
            while let Some(&0) = self.digits.last() {
                self.digits.pop();
            }
        }

        pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
            if divisor.digits.is_empty() {
                panic!("Division by zero");
            }

            if self.digits.is_empty() {
                return (Self::ZERO, Self::ZERO);
            }

            if self < divisor {
                return (Self::ZERO, self.clone());
            }

            // Simple long division for small divisors (fits in u32)
            if divisor.digits.len() == 1 {
                let d = divisor.digits[0] as u64;
                let mut remainder = 0u64;
                let mut quotient = vec![0u32; self.digits.len()];

                for i in (0..self.digits.len()).rev() {
                    let cur = (remainder << 32) + self.digits[i] as u64;
                    quotient[i] = (cur / d) as u32;
                    remainder = cur % d;
                }

                let mut q = Self { digits: quotient };
                q.normalize();
                let r = Self::from(remainder as u32);
                return (q, r);
            }

            // For larger divisors, use a simpler but slower approach
            let mut quotient = Self::ZERO;
            let mut remainder = self.clone();

            while &remainder >= divisor {
                remainder = &remainder - divisor;
                quotient = &quotient + &Self::from(1u32);
            }

            (quotient, remainder)
        }

        pub fn to_bytes_be(&self) -> Vec<u8> {
            if self.digits.is_empty() {
                return vec![0];
            }

            let mut bytes = Vec::new();
            for &digit in self.digits.iter().rev() {
                bytes.extend_from_slice(&digit.to_be_bytes());
            }

            // Remove leading zeros
            while bytes.len() > 1 && bytes[0] == 0 {
                bytes.remove(0);
            }

            bytes
        }
    }

    impl From<u8> for BigUint {
        fn from(n: u8) -> Self {
            if n == 0 {
                Self::ZERO
            } else {
                Self {
                    digits: vec![n as u32],
                }
            }
        }
    }

    impl From<u32> for BigUint {
        fn from(n: u32) -> Self {
            if n == 0 {
                Self::ZERO
            } else {
                Self { digits: vec![n] }
            }
        }
    }

    impl From<usize> for BigUint {
        fn from(n: usize) -> Self {
            Self::from(n as u32)
        }
    }

    impl TryFrom<BigUint> for u8 {
        type Error = ();

        fn try_from(value: BigUint) -> Result<Self, Self::Error> {
            if value.digits.is_empty() {
                Ok(0)
            } else if value.digits.len() == 1 && value.digits[0] <= 255 {
                Ok(value.digits[0] as u8)
            } else {
                Err(())
            }
        }
    }

    impl Shl<usize> for BigUint {
        type Output = Self;

        fn shl(self, shift: usize) -> Self::Output {
            if self.digits.is_empty() || shift == 0 {
                return self;
            }

            let word_shift = shift / 32;
            let bit_shift = shift % 32;

            let mut result = vec![0u32; self.digits.len() + word_shift + 1];

            for (i, &digit) in self.digits.iter().enumerate() {
                let shifted = (digit as u64) << bit_shift;
                result[i + word_shift] |= shifted as u32;
                result[i + word_shift + 1] |= (shifted >> 32) as u32;
            }

            let mut r = Self { digits: result };
            r.normalize();
            r
        }
    }

    impl Add<BigUint> for BigUint {
        type Output = Self;

        fn add(self, rhs: BigUint) -> Self::Output {
            &self + &rhs
        }
    }

    impl Add<&BigUint> for &BigUint {
        type Output = BigUint;

        fn add(self, rhs: &BigUint) -> Self::Output {
            let max_len = self.digits.len().max(rhs.digits.len());
            let mut result = vec![0u32; max_len + 1];
            let mut carry = 0u64;

            for (i, item) in result.iter_mut().enumerate().take(max_len) {
                let a = self.digits.get(i).copied().unwrap_or(0) as u64;
                let b = rhs.digits.get(i).copied().unwrap_or(0) as u64;
                let sum = a + b + carry;
                *item = sum as u32;
                carry = sum >> 32;
            }

            if carry > 0 {
                result[max_len] = carry as u32;
            }

            let mut r = BigUint { digits: result };
            r.normalize();
            r
        }
    }

    impl std::ops::Sub<&BigUint> for &BigUint {
        type Output = BigUint;

        fn sub(self, rhs: &BigUint) -> Self::Output {
            let mut result = self.digits.clone();
            let mut borrow = 0i64;

            for (i, item) in result.iter_mut().enumerate() {
                let a = *item as i64;
                let b = rhs.digits.get(i).copied().unwrap_or(0) as i64;
                let diff = a - b - borrow;
                if diff < 0 {
                    *item = (diff + (1i64 << 32)) as u32;
                    borrow = 1;
                } else {
                    *item = diff as u32;
                    borrow = 0;
                }
            }

            let mut r = BigUint { digits: result };
            r.normalize();
            r
        }
    }

    impl Mul<&BigUint> for BigUint {
        type Output = Self;

        fn mul(self, rhs: &BigUint) -> Self::Output {
            if self.digits.is_empty() || rhs.digits.is_empty() {
                return Self::ZERO;
            }

            let mut result = vec![0u32; self.digits.len() + rhs.digits.len()];

            for (i, &a) in self.digits.iter().enumerate() {
                let mut carry = 0u64;
                for (j, &b) in rhs.digits.iter().enumerate() {
                    let prod = (a as u64) * (b as u64) + result[i + j] as u64 + carry;
                    result[i + j] = prod as u32;
                    carry = prod >> 32;
                }
                if carry > 0 {
                    result[i + rhs.digits.len()] += carry as u32;
                }
            }

            let mut r = Self { digits: result };
            r.normalize();
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_from_keypair() {
        let kp = KeyPair::generate();
        let did = Did::from_key_pair(&kp).unwrap();

        assert_eq!(did.method, "key");
        assert!(did.identifier.starts_with('z'));
        assert!(did.uri().starts_with("did:key:z"));
    }

    #[test]
    fn test_did_parse() {
        let kp = KeyPair::generate();
        let did1 = Did::from_key_pair(&kp).unwrap();

        let did2 = Did::parse(&did1.uri()).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_extract_public_key() {
        let kp = KeyPair::generate();
        let did = Did::from_key_pair(&kp).unwrap();

        let extracted = did.extract_public_key().unwrap();
        assert_eq!(extracted, kp.public_key_bytes());
    }

    #[test]
    fn test_did_to_keypair() {
        let kp = KeyPair::generate();
        let did = Did::from_key_pair(&kp).unwrap();

        let kp2 = did.to_key_pair().unwrap();
        assert_eq!(kp.public_key_bytes(), kp2.public_key_bytes());
        assert!(!kp2.can_sign()); // Verification only
    }

    #[test]
    fn test_did_generate() {
        let (did, kp) = Did::generate();

        assert!(did.uri().starts_with("did:key:z6Mk"));
        assert!(kp.can_sign());

        let extracted = did.extract_public_key().unwrap();
        assert_eq!(extracted, kp.public_key_bytes());
    }

    #[test]
    fn test_did_display() {
        let (did, _) = Did::generate();
        let uri = did.to_string();
        assert!(uri.starts_with("did:key:z"));
    }

    #[test]
    fn test_did_serde() {
        let (did1, _) = Did::generate();
        let json = serde_json::to_string(&did1).unwrap();
        let did2: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_invalid_did() {
        assert!(Did::parse("invalid").is_err());
        assert!(Did::parse("did:key:invalid").is_err());
        assert!(Did::parse("did:method").is_err());
    }

    #[test]
    fn test_base58_roundtrip() {
        let data = vec![0xED, 0x01, 1, 2, 3, 4, 5];
        let encoded = base58_encode(&data);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
}
