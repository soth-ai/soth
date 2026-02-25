use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::config::ClassifyConfig;

#[derive(Debug, Clone)]
pub(crate) struct ClusterOutput {
    pub topic_cluster_id: u32,
    pub semantic_hash: String,
    pub is_semantic_collision: bool,
}

impl Default for ClusterOutput {
    fn default() -> Self {
        Self {
            topic_cluster_id: 0,
            semantic_hash: "00000000000000000000000000000000".to_string(),
            is_semantic_collision: false,
        }
    }
}

pub(crate) fn run(
    embedding: Option<&[f32]>,
    session: Option<&soth_core::SessionSnapshot>,
    config: &ClassifyConfig,
) -> (ClusterOutput, u64) {
    let started = Instant::now();

    let Some(embedding) = embedding else {
        return (
            ClusterOutput::default(),
            started.elapsed().as_micros() as u64,
        );
    };

    let mut hasher = Sha256::new();
    for value in embedding {
        hasher.update(value.to_le_bytes());
    }
    let digest = hasher.finalize();
    let semantic_hash = hex::encode(digest)[..32].to_string();

    let topic_cluster_id = {
        let bytes = [digest[0], digest[1], digest[2], digest[3]];
        u32::from_le_bytes(bytes) % 1024
    };

    let is_semantic_collision = session
        .map(|snapshot| {
            snapshot.prior_semantic_hashes.iter().any(|prior| {
                hamming_distance_hex(&semantic_hash, prior) <= config.lsh_near_dupe_threshold
            })
        })
        .unwrap_or(false);

    (
        ClusterOutput {
            topic_cluster_id,
            semantic_hash,
            is_semantic_collision,
        },
        started.elapsed().as_micros() as u64,
    )
}

fn hamming_distance_hex(a: &str, b: &str) -> u32 {
    let bytes_a = a.as_bytes();
    let bytes_b = b.as_bytes();
    let pairs = bytes_a.chunks(2).zip(bytes_b.chunks(2));

    pairs
        .map(|(left, right)| {
            let left_str = std::str::from_utf8(left).unwrap_or("00");
            let right_str = std::str::from_utf8(right).unwrap_or("00");
            let left_val = u8::from_str_radix(left_str, 16).unwrap_or(0);
            let right_val = u8::from_str_radix(right_str, 16).unwrap_or(0);
            (left_val ^ right_val).count_ones()
        })
        .sum()
}
