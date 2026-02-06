//! Merkle tree implementation for verifiable data structures

use super::proof::MerkleProof;
use sha2::{Digest, Sha256};

/// Hash a leaf node with a 0x00 prefix (domain separation)
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // Leaf prefix
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash an internal node with a 0x01 prefix (domain separation)
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // Internal node prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// A Merkle tree for verifiable data integrity
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    /// Leaf hashes
    leaves: Vec<[u8; 32]>,
    /// Tree layers (bottom to top)
    layers: Vec<Vec<[u8; 32]>>,
    /// Root hash
    root: Option<[u8; 32]>,
}

impl MerkleTree {
    /// Create an empty Merkle tree
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a tree from a list of data items
    pub fn from_data<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut tree = Self::new();
        for item in items {
            tree.append(item.as_ref());
        }
        tree
    }

    /// Create a tree from pre-computed leaf hashes
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let mut tree = Self {
            leaves: leaves.clone(),
            layers: vec![leaves],
            root: None,
        };
        tree.rebuild();
        tree
    }

    /// Append data to the tree
    pub fn append(&mut self, data: &[u8]) -> usize {
        let leaf_hash = hash_leaf(data);
        self.leaves.push(leaf_hash);
        self.rebuild();
        self.leaves.len() - 1
    }

    /// Append a pre-computed hash
    pub fn append_hash(&mut self, hash: [u8; 32]) -> usize {
        self.leaves.push(hash);
        self.rebuild();
        self.leaves.len() - 1
    }

    /// Rebuild the tree structure
    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.layers.clear();
            self.root = None;
            return;
        }

        // Start with leaf layer
        let mut current_layer = self.leaves.clone();
        self.layers = vec![current_layer.clone()];

        // Build up the tree
        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                let left = &current_layer[i];
                // If odd number of nodes, duplicate the last one
                let right = if i + 1 < current_layer.len() {
                    &current_layer[i + 1]
                } else {
                    left
                };
                next_layer.push(hash_node(left, right));
            }

            current_layer = next_layer.clone();
            self.layers.push(next_layer);
        }

        self.root = Some(current_layer[0]);
    }

    /// Get the root hash
    pub fn root(&self) -> Option<&[u8; 32]> {
        self.root.as_ref()
    }

    /// Get the root hash as a hex string
    pub fn root_hex(&self) -> Option<String> {
        self.root.map(|r| hex_encode(&r))
    }

    /// Get the number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get a proof of inclusion for a leaf
    pub fn get_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut current_index = index;

        // Traverse from leaf to root (excluding root layer)
        for layer in self.layers.iter().take(self.layers.len().saturating_sub(1)) {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let position = if current_index % 2 == 0 {
                "right".to_string()
            } else {
                "left".to_string()
            };

            // If sibling exists, use it; otherwise use current (odd layer)
            let sibling_hash = if sibling_index < layer.len() {
                hex_encode(&layer[sibling_index])
            } else {
                hex_encode(&layer[current_index])
            };

            siblings.push((sibling_hash, position));

            // Move up the tree
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: hex_encode(&self.leaves[index]),
            siblings,
            root: self.root_hex().unwrap_or_default(),
        })
    }

    /// Verify a proof
    pub fn verify_proof(proof: &MerkleProof, leaf_data: Option<&[u8]>) -> bool {
        let mut computed_hash = if let Some(data) = leaf_data {
            hash_leaf(data)
        } else {
            match hex_decode(&proof.leaf_hash) {
                Ok(h) => h,
                Err(_) => return false,
            }
        };

        for (sibling_hex, position) in &proof.siblings {
            let sibling = match hex_decode(sibling_hex) {
                Ok(s) => s,
                Err(_) => return false,
            };

            computed_hash = if position == "right" {
                hash_node(&computed_hash, &sibling)
            } else {
                hash_node(&sibling, &computed_hash)
            };
        }

        hex_encode(&computed_hash) == proof.root
    }

    /// Serialize the tree to a storable format
    pub fn to_serializable(&self) -> SerializableMerkleTree {
        SerializableMerkleTree {
            leaves: self.leaves.iter().map(|l| hex_encode(l)).collect(),
            root: self.root_hex(),
        }
    }

    /// Deserialize a tree from storage
    pub fn from_serializable(data: &SerializableMerkleTree) -> Option<Self> {
        let leaves: Vec<[u8; 32]> = data
            .leaves
            .iter()
            .filter_map(|h| hex_decode(h).ok())
            .collect();

        if leaves.len() != data.leaves.len() {
            return None;
        }

        Some(Self::from_leaves(leaves))
    }
}

/// Serializable version of the Merkle tree
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableMerkleTree {
    pub leaves: Vec<String>,
    pub root: Option<String>,
}

// Hex encoding helpers
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<[u8; 32], &'static str> {
    if hex.len() != 64 {
        return Err("Invalid hex length");
    }

    let mut result = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8")?;
        result[i] = u8::from_str_radix(s, 16).map_err(|_| "Invalid hex")?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert!(tree.root().is_none());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.append(b"hello");

        assert_eq!(tree.len(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_multiple_leaves() {
        let tree = MerkleTree::from_data(vec!["a", "b", "c", "d"]);
        assert_eq!(tree.len(), 4);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let tree = MerkleTree::from_data(vec!["a", "b", "c", "d"]);

        for i in 0..4 {
            let proof = tree.get_proof(i).unwrap();
            assert!(MerkleTree::verify_proof(&proof, None));
        }
    }

    #[test]
    fn test_proof_with_data() {
        let tree = MerkleTree::from_data(vec!["hello", "world"]);

        let proof = tree.get_proof(0).unwrap();
        assert!(MerkleTree::verify_proof(&proof, Some(b"hello")));
        assert!(!MerkleTree::verify_proof(&proof, Some(b"wrong")));
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let tree = MerkleTree::from_data(vec!["a", "b", "c"]);
        assert_eq!(tree.len(), 3);

        let proof = tree.get_proof(2).unwrap();
        assert!(MerkleTree::verify_proof(&proof, None));
    }

    #[test]
    fn test_serialization() {
        let tree = MerkleTree::from_data(vec!["a", "b", "c"]);
        let serialized = tree.to_serializable();

        let restored = MerkleTree::from_serializable(&serialized).unwrap();
        assert_eq!(tree.root_hex(), restored.root_hex());
    }

    #[test]
    fn test_deterministic_root() {
        let tree1 = MerkleTree::from_data(vec!["a", "b", "c"]);
        let tree2 = MerkleTree::from_data(vec!["a", "b", "c"]);

        assert_eq!(tree1.root_hex(), tree2.root_hex());
    }

    #[test]
    fn test_different_data_different_root() {
        let tree1 = MerkleTree::from_data(vec!["a", "b"]);
        let tree2 = MerkleTree::from_data(vec!["a", "c"]);

        assert_ne!(tree1.root_hex(), tree2.root_hex());
    }
}
