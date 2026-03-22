use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

use crate::normalized::NormalizedRequest;

/// SHA-256 hex digest of arbitrary bytes. Single authority for all
/// hashing across the proxy codebase.
pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_ref());
    hex::encode(hasher.finalize())
}

pub fn commitment_hash(body_bytes: &[u8], nonce: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(nonce);
    hasher.update(body_bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Deterministically derives a per-device Ed25519 seed from the device identity.
///
/// The output is stable for the same device id hash and safe to pass into
/// `ed25519_dalek::SigningKey::from_bytes`.
pub fn derive_proxy_signing_seed(device_id_hash: &str) -> [u8; 32] {
    let normalized = if device_id_hash.trim().is_empty() {
        "local-device"
    } else {
        device_id_hash.trim()
    };
    let mut hasher = Sha256::new();
    hasher.update(b"soth.proxy.ed25519.seed.v1|");
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn cache_key_from_normalized(nr: &NormalizedRequest) -> String {
    let mut hasher = Sha256::new();

    hasher.update(nr.provider.as_bytes());
    hasher.update(b"|");
    hasher.update(nr.model.as_deref().unwrap_or(""));
    hasher.update(b"|");
    hasher.update(format!("{:?}", nr.endpoint_type).as_bytes());
    hasher.update(b"|");
    hasher.update(nr.api_version.as_deref().unwrap_or(""));
    hasher.update(b"|");

    hasher.update(nr.system_prompt_hash.as_deref().unwrap_or(""));
    hasher.update(b"|");
    hasher.update(&nr.user_content_hash);
    hasher.update(b"|");
    hasher.update(&nr.conversation_hash);
    hasher.update(b"|");
    hasher.update(nr.tool_definition_hash.as_deref().unwrap_or(""));
    hasher.update(b"|");

    hasher.update(if nr.stream { b"1" } else { b"0" });
    hasher.update(b"|");
    hasher.update(format!("{:?}", nr.temperature).as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{:?}", nr.top_p).as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{:?}", nr.max_tokens).as_bytes());
    hasher.update(b"|");

    for stop in &nr.stop_sequences {
        hasher.update(stop.as_bytes());
        hasher.update(b",,");
    }

    let digest = hasher.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{ParseConfidence, ParseSource};
    use crate::normalized::{EndpointType, FormatMetadata, NormalizedRequest};
    use crate::providers::DetectedProvider;

    #[test]
    fn commitment_hash_is_stable() {
        let nonce = [7u8; 32];
        let left = commitment_hash(b"hello", &nonce);
        let right = commitment_hash(b"hello", &nonce);
        assert_eq!(left, right);
    }

    #[test]
    fn derive_proxy_signing_seed_is_stable() {
        let left = derive_proxy_signing_seed("device-test-123");
        let right = derive_proxy_signing_seed("device-test-123");
        assert_eq!(left, right);
        assert_ne!(left, derive_proxy_signing_seed("device-test-456"));
    }

    #[test]
    fn cache_key_changes_with_model() {
        let mut req = sample_request();
        let k1 = cache_key_from_normalized(&req);
        req.model = Some("claude-3-5-haiku".to_string());
        let k2 = cache_key_from_normalized(&req);
        assert_ne!(k1, k2);
    }

    fn sample_request() -> NormalizedRequest {
        NormalizedRequest {
            parse_confidence: ParseConfidence::Full,
            parser_id: "p1".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: "anthropic".to_string(),
            model: Some("claude-3-5-sonnet".to_string()),
            endpoint_type: EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: Some("s".to_string()),
            system_prompt_token_estimate: Some(10),
            user_content_hash: "u".to_string(),
            user_content_token_estimate: 20,
            conversation_hash: "c".to_string(),
            conversation_turn: Some(1),
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: Some(0.2),
            max_tokens: Some(2048),
            stream: false,
            top_p: Some(0.9),
            stop_sequences: vec!["stop".to_string()],
            estimated_input_tokens: 30,
            estimated_cost_usd: 0.1,
            parse_source: ParseSource::Heuristic,
            canonical_cache_key: String::new(),
            format_metadata: FormatMetadata::Unknown { method: String::new(), path: String::new() },
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            user_prompt: None,
        }
    }
}
