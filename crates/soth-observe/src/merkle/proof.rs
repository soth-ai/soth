//! Merkle proof types

use serde::{Deserialize, Serialize};

/// A proof that a leaf exists in the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf in the tree
    pub leaf_index: usize,

    /// Hash of the leaf (hex encoded)
    pub leaf_hash: String,

    /// Sibling hashes and positions needed to reconstruct the root
    /// Each tuple is (hash, position) where position is "left" or "right"
    pub siblings: Vec<(String, String)>,

    /// Expected root hash (hex encoded)
    pub root: String,
}

impl MerkleProof {
    /// Serialize to JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "siblings": self.siblings.iter()
                .map(|(h, p)| serde_json::json!([h, p]))
                .collect::<Vec<_>>(),
            "root": self.root
        })
    }

    /// Deserialize from JSON value
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        let leaf_index = value.get("leaf_index")?.as_u64()? as usize;
        let leaf_hash = value.get("leaf_hash")?.as_str()?.to_string();
        let root = value.get("root")?.as_str()?.to_string();

        let siblings_arr = value.get("siblings")?.as_array()?;
        let siblings: Vec<(String, String)> = siblings_arr
            .iter()
            .filter_map(|v| {
                let arr = v.as_array()?;
                let hash = arr.first()?.as_str()?.to_string();
                let pos = arr.get(1)?.as_str()?.to_string();
                Some((hash, pos))
            })
            .collect();

        Some(Self {
            leaf_index,
            leaf_hash,
            siblings,
            root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        let proof = MerkleProof {
            leaf_index: 0,
            leaf_hash: "abc123".to_string(),
            siblings: vec![("def456".to_string(), "right".to_string())],
            root: "root789".to_string(),
        };

        let json = proof.to_json();
        let restored = MerkleProof::from_json(&json).unwrap();

        assert_eq!(restored.leaf_index, 0);
        assert_eq!(restored.leaf_hash, "abc123");
        assert_eq!(restored.root, "root789");
    }
}
