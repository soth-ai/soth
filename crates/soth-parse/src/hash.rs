use crate::types::NormalizedRequest;
use sha2::{Digest, Sha256};

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_ref());
    format!("{:x}", hasher.finalize())
}

pub fn hash_content(content: &str) -> String {
    sha256_hex(content.as_bytes())
}

pub fn canonical_hash(nr: &NormalizedRequest) -> String {
    let line = format!(
        "{}|{}|{}|{}|{}|{:.4}|{}|{}",
        nr.provider.canonical_name(),
        nr.model.as_deref().unwrap_or(""),
        nr.system_prompt_hash.as_deref().unwrap_or(""),
        nr.user_content_hash,
        nr.tool_definition_hash.as_deref().unwrap_or(""),
        nr.temperature.unwrap_or(0.0),
        nr.max_tokens.unwrap_or(0),
        nr.stop_sequences.join(",")
    );
    sha256_hex(line)
}

pub fn estimate_tokens(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let chars = text.chars().count();
    ((chars as f32) / 4.0).ceil() as u32
}
