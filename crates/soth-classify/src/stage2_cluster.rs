use std::time::Instant;

use crate::config::ClassifyConfig;

const LSH_BITS: usize = 128;
const CLUSTER_SPACE: u32 = 1000;
const LSH_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

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
    centroids: &[Vec<f32>],
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

    let semantic_hash = semantic_lsh_hex(embedding);
    let topic_cluster_id = nearest_centroid_id(embedding, centroids)
        .unwrap_or_else(|| cluster_id_from_hash(&semantic_hash));

    let is_semantic_collision = session
        .map(|snapshot| {
            snapshot.prior_semantic_hashes.iter().any(|prior| {
                hamming_distance_hex(&semantic_hash, prior) <= config.lsh_near_dupe_threshold
            })
        })
        .unwrap_or(false);

    let output = ClusterOutput {
        topic_cluster_id,
        semantic_hash,
        is_semantic_collision,
    };

    (output, started.elapsed().as_micros() as u64)
}

fn semantic_lsh_hex(embedding: &[f32]) -> String {
    let mut bytes = [0u8; LSH_BITS / 8];

    for bit_idx in 0..LSH_BITS {
        let mut projection = 0.0f32;
        for (dim_idx, value) in embedding.iter().enumerate() {
            projection += *value * projection_weight(bit_idx as u64, dim_idx as u64);
        }

        if projection >= 0.0 {
            let byte_idx = bit_idx / 8;
            let bit_in_byte = 7 - (bit_idx % 8);
            bytes[byte_idx] |= 1 << bit_in_byte;
        }
    }

    hex::encode(bytes)
}

fn cluster_id_from_hash(semantic_hash: &str) -> u32 {
    let Ok(bytes) = hex::decode(semantic_hash) else {
        return 0;
    };
    if bytes.len() < 4 {
        return 0;
    }
    let prefix = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    prefix % CLUSTER_SPACE
}

fn nearest_centroid_id(embedding: &[f32], centroids: &[Vec<f32>]) -> Option<u32> {
    let mut best: Option<(usize, f32)> = None;
    for (idx, centroid) in centroids.iter().enumerate() {
        if centroid.len() != embedding.len() {
            continue;
        }
        let score = embedding
            .iter()
            .zip(centroid.iter())
            .map(|(left, right)| left * right)
            .sum::<f32>();
        match best {
            Some((_, best_score)) if score <= best_score => {}
            _ => best = Some((idx, score)),
        }
    }
    best.map(|(idx, _)| idx as u32)
}

fn projection_weight(bit_idx: u64, dim_idx: u64) -> f32 {
    sample_signed(LSH_SEED, bit_idx, dim_idx)
}

fn sample_signed(seed: u64, a: u64, b: u64) -> f32 {
    let mixed = splitmix64(seed ^ (a.wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ b);
    let fraction = ((mixed >> 11) as f64) / ((1u64 << 53) as f64);
    (fraction as f32) * 2.0 - 1.0
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = value;
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn hamming_distance_hex(a: &str, b: &str) -> u32 {
    let (Ok(bytes_a), Ok(bytes_b)) = (hex::decode(a), hex::decode(b)) else {
        return u32::MAX;
    };

    if bytes_a.len() != bytes_b.len() {
        return u32::MAX;
    }

    bytes_a
        .iter()
        .zip(bytes_b.iter())
        .map(|(left, right)| (left ^ right).count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_with_seed(seed: u64) -> Vec<f32> {
        let mut out = Vec::with_capacity(384);
        for idx in 0..384u64 {
            out.push(sample_signed(seed, idx, 0xABCD));
        }
        let norm = out.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 1e-9 {
            for value in &mut out {
                *value /= norm;
            }
        }
        out
    }

    #[test]
    fn semantic_lsh_hash_is_128_bits_hex() {
        let vector = vector_with_seed(1);
        let hash = semantic_lsh_hex(vector.as_slice());
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn run_marks_collision_when_prior_hash_matches() {
        let vector = vector_with_seed(7);
        let hash = semantic_lsh_hex(vector.as_slice());
        let mut session = soth_core::SessionSnapshot::default();
        session.prior_semantic_hashes = vec![hash];

        let config = crate::ClassifyConfig::default();
        let (out, _) = run(Some(vector.as_slice()), &[], Some(&session), &config);
        assert!(out.is_semantic_collision);
    }

    #[test]
    fn hash_changes_for_different_embeddings() {
        let left = semantic_lsh_hex(vector_with_seed(41).as_slice());
        let right = semantic_lsh_hex(vector_with_seed(42).as_slice());
        assert_ne!(left, right);
    }

    #[test]
    fn nearest_centroid_assignment_uses_max_dot_score() {
        let embedding = vec![1.0, 0.0, 0.0];
        let centroids = vec![
            vec![0.0, 1.0, 0.0],
            vec![0.8, 0.0, 0.2],
            vec![0.5, 0.0, 0.0],
        ];
        let id = nearest_centroid_id(embedding.as_slice(), &centroids);
        assert_eq!(id, Some(1));
    }
}
