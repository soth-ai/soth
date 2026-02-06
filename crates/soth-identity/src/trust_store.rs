//! Trust store for managing trusted DIDs
//!
//! Provides file-based storage for trusted agent DIDs.

use crate::did::Did;
use soth_core::error::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Trust store for managing trusted DIDs
#[derive(Debug)]
pub struct TrustStore {
    /// Path to the trust store file
    path: PathBuf,
    /// Cached set of trusted DIDs
    trusted: HashSet<String>,
}

impl TrustStore {
    /// Create or load a trust store from a file
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let trusted = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            HashSet::new()
        };

        Ok(Self { path, trusted })
    }

    /// Create an in-memory trust store (for testing)
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            trusted: HashSet::new(),
        }
    }

    /// Load trusted DIDs from a file (one DID per line)
    fn load_from_file(path: &Path) -> Result<HashSet<String>> {
        let content = std::fs::read_to_string(path)?;
        let mut trusted = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Validate the DID
            if let Ok(did) = Did::parse(line) {
                trusted.insert(did.uri());
            } else {
                tracing::warn!("Invalid DID in trust store: {}", line);
            }
        }

        Ok(trusted)
    }

    /// Save the trust store to file
    fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // In-memory store
        }

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content: String = self
            .trusted
            .iter()
            .map(|s| format!("{s}\n"))
            .collect();

        std::fs::write(&self.path, content)?;
        Ok(())
    }

    /// Check if a DID is trusted
    pub fn is_trusted(&self, did: &str) -> bool {
        self.trusted.contains(did)
    }

    /// Check if a DID is trusted (accepts Did object)
    pub fn is_did_trusted(&self, did: &Did) -> bool {
        self.trusted.contains(&did.uri())
    }

    /// Add a DID to the trust store
    pub fn trust(&mut self, did: &str) -> Result<()> {
        // Validate the DID
        let parsed = Did::parse(did)?;
        self.trusted.insert(parsed.uri());
        self.save()
    }

    /// Add a DID to the trust store (accepts Did object)
    pub fn trust_did(&mut self, did: &Did) -> Result<()> {
        self.trusted.insert(did.uri());
        self.save()
    }

    /// Remove a DID from the trust store
    pub fn untrust(&mut self, did: &str) -> Result<()> {
        self.trusted.remove(did);
        self.save()
    }

    /// List all trusted DIDs
    pub fn list(&self) -> Vec<&str> {
        self.trusted.iter().map(|s| s.as_str()).collect()
    }

    /// Get the number of trusted DIDs
    pub fn len(&self) -> usize {
        self.trusted.len()
    }

    /// Check if the trust store is empty
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    /// Clear all trusted DIDs
    pub fn clear(&mut self) -> Result<()> {
        self.trusted.clear();
        self.save()
    }

    /// Reload the trust store from disk
    pub fn reload(&mut self) -> Result<()> {
        if !self.path.as_os_str().is_empty() && self.path.exists() {
            self.trusted = Self::load_from_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_in_memory_store() {
        let mut store = TrustStore::in_memory();
        assert!(store.is_empty());

        let (did, _) = Did::generate();
        store.trust_did(&did).unwrap();

        assert!(store.is_did_trusted(&did));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_file_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trust_store");

        let (did1, _) = Did::generate();
        let (did2, _) = Did::generate();

        // Create and populate store
        {
            let mut store = TrustStore::new(&path).unwrap();
            store.trust_did(&did1).unwrap();
            store.trust_did(&did2).unwrap();
        }

        // Reload and verify
        {
            let store = TrustStore::new(&path).unwrap();
            assert_eq!(store.len(), 2);
            assert!(store.is_did_trusted(&did1));
            assert!(store.is_did_trusted(&did2));
        }
    }

    #[test]
    fn test_untrust() {
        let mut store = TrustStore::in_memory();

        let (did, _) = Did::generate();
        store.trust_did(&did).unwrap();
        assert!(store.is_did_trusted(&did));

        store.untrust(&did.uri()).unwrap();
        assert!(!store.is_did_trusted(&did));
    }

    #[test]
    fn test_list() {
        let mut store = TrustStore::in_memory();

        let (did1, _) = Did::generate();
        let (did2, _) = Did::generate();

        store.trust_did(&did1).unwrap();
        store.trust_did(&did2).unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&did1.uri().as_str()));
        assert!(list.contains(&did2.uri().as_str()));
    }

    #[test]
    fn test_clear() {
        let mut store = TrustStore::in_memory();

        let (did, _) = Did::generate();
        store.trust_did(&did).unwrap();

        store.clear().unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn test_trust_string_validation() {
        let mut store = TrustStore::in_memory();

        // Valid DID
        let (did, _) = Did::generate();
        assert!(store.trust(&did.uri()).is_ok());

        // Invalid DID
        assert!(store.trust("not-a-did").is_err());
    }
}
