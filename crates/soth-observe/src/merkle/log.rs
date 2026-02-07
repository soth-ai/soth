//! Transparency log implementation

use super::proof::MerkleProof;
use super::tree::MerkleTree;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Entry in the transparency log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Sequence number
    pub sequence: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of the data
    pub data_hash: String,
    /// Type of entry
    pub entry_type: String,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Append-only transparency log with Merkle tree integrity
#[derive(Debug)]
pub struct TransparencyLog {
    /// The Merkle tree
    tree: MerkleTree,
    /// Log entries
    entries: Vec<LogEntry>,
    /// Path to storage file
    path: Option<std::path::PathBuf>,
}

impl TransparencyLog {
    /// Create a new in-memory transparency log
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            entries: Vec::new(),
            path: None,
        }
    }

    /// Create or load a transparency log from a file
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if path.exists() {
            // Load existing log
            let content = std::fs::read_to_string(&path)?;
            let stored: StoredLog = serde_json::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let tree = MerkleTree::from_serializable(&stored.tree).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid tree")
            })?;

            Ok(Self {
                tree,
                entries: stored.entries,
                path: Some(path),
            })
        } else {
            Ok(Self {
                tree: MerkleTree::new(),
                entries: Vec::new(),
                path: Some(path),
            })
        }
    }

    /// Append data to the log
    pub fn append(
        &mut self,
        data: &[u8],
        entry_type: impl Into<String>,
        metadata: Option<serde_json::Value>,
    ) -> LogEntry {
        let data_hash = Self::hash_data(data);
        let sequence = self.entries.len() as u64;

        let entry = LogEntry {
            sequence,
            timestamp: Utc::now(),
            data_hash: data_hash.clone(),
            entry_type: entry_type.into(),
            metadata,
        };

        // Add to tree (hash the entry JSON for the tree)
        let entry_bytes = serde_json::to_vec(&entry).unwrap_or_default();
        self.tree.append(&entry_bytes);

        self.entries.push(entry.clone());

        // Persist if we have a path
        let _ = self.save();

        entry
    }

    /// Append a JSON value to the log
    pub fn append_json(
        &mut self,
        value: &serde_json::Value,
        entry_type: impl Into<String>,
    ) -> LogEntry {
        let data = serde_json::to_vec(value).unwrap_or_default();
        self.append(&data, entry_type, None)
    }

    /// Get the current root hash
    pub fn root_hash(&self) -> Option<String> {
        self.tree.root_hex()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by sequence number
    pub fn get_entry(&self, sequence: u64) -> Option<&LogEntry> {
        self.entries.get(sequence as usize)
    }

    /// Get all entries
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Get a proof for an entry
    pub fn get_proof(&self, sequence: u64) -> Option<MerkleProof> {
        self.tree.get_proof(sequence as usize)
    }

    /// Verify a proof against this log
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        // Check that root matches
        if let Some(root) = self.root_hash() {
            if root != proof.root {
                return false;
            }
        } else {
            return false;
        }

        MerkleTree::verify_proof(proof, None)
    }

    /// Verify the integrity of the entire log
    pub fn verify_integrity(&self) -> bool {
        // Rebuild tree from entries and compare roots
        let mut check_tree = MerkleTree::new();
        for entry in &self.entries {
            let entry_bytes = serde_json::to_vec(entry).unwrap_or_default();
            check_tree.append(&entry_bytes);
        }

        check_tree.root_hex() == self.tree.root_hex()
    }

    /// Get consistency proof between two tree sizes
    pub fn get_consistency_proof(
        &self,
        old_size: usize,
        new_size: usize,
    ) -> Option<ConsistencyProof> {
        if old_size > new_size || new_size > self.entries.len() {
            return None;
        }

        // Build old tree
        let old_entries: Vec<_> = self.entries[..old_size]
            .iter()
            .map(|e| serde_json::to_vec(e).unwrap_or_default())
            .collect();
        let old_tree = MerkleTree::from_data(old_entries);

        // Build new tree
        let new_entries: Vec<_> = self.entries[..new_size]
            .iter()
            .map(|e| serde_json::to_vec(e).unwrap_or_default())
            .collect();
        let new_tree = MerkleTree::from_data(new_entries);

        Some(ConsistencyProof {
            old_size,
            new_size,
            old_root: old_tree.root_hex().unwrap_or_default(),
            new_root: new_tree.root_hex().unwrap_or_default(),
        })
    }

    /// Save the log to disk
    fn save(&self) -> std::io::Result<()> {
        if let Some(path) = &self.path {
            let stored = StoredLog {
                tree: self.tree.to_serializable(),
                entries: self.entries.clone(),
            };
            let content = serde_json::to_string_pretty(&stored)?;
            std::fs::write(path, content)?;
        }
        Ok(())
    }

    /// Hash data for the log
    fn hash_data(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Consistency proof between two tree states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: usize,
    pub new_size: usize,
    pub old_root: String,
    pub new_root: String,
}

/// Stored format for persistence
#[derive(Serialize, Deserialize)]
struct StoredLog {
    tree: super::tree::SerializableMerkleTree,
    entries: Vec<LogEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_verify() {
        let mut log = TransparencyLog::new();

        log.append(b"entry 1", "test", None);
        log.append(b"entry 2", "test", None);
        log.append(b"entry 3", "test", None);

        assert_eq!(log.len(), 3);
        assert!(log.verify_integrity());
    }

    #[test]
    fn test_proof_generation() {
        let mut log = TransparencyLog::new();

        log.append(b"entry 1", "test", None);
        log.append(b"entry 2", "test", None);

        let proof = log.get_proof(0).unwrap();
        assert!(log.verify_proof(&proof));
    }

    #[test]
    fn test_root_changes() {
        let mut log = TransparencyLog::new();

        log.append(b"entry 1", "test", None);
        let root1 = log.root_hash();

        log.append(b"entry 2", "test", None);
        let root2 = log.root_hash();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_get_entry() {
        let mut log = TransparencyLog::new();

        log.append(b"first", "test", None);
        log.append(b"second", "test", None);

        let entry = log.get_entry(1).unwrap();
        assert_eq!(entry.sequence, 1);
    }

    #[test]
    fn test_json_append() {
        let mut log = TransparencyLog::new();

        let data = serde_json::json!({"key": "value"});
        log.append_json(&data, "json_test");

        assert_eq!(log.len(), 1);
        assert!(log.verify_integrity());
    }
}
