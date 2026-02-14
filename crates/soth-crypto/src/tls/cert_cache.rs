//! Certificate cache with TTL-based expiration

use dashmap::DashMap;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Cached certificate entry
#[derive(Clone)]
pub struct CachedCert {
    /// DER-encoded certificate
    pub cert_der: Vec<u8>,
    /// DER-encoded private key
    pub key_der: Vec<u8>,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Instant,
    /// CA key id used to issue this leaf certificate (if tracked)
    pub ca_key_id: Option<String>,
    /// Leaf key id for this certificate keypair (if tracked)
    pub leaf_key_id: Option<String>,
}

impl CachedCert {
    /// Create a new cached certificate
    pub fn new(cert_der: Vec<u8>, key_der: Vec<u8>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            cert_der,
            key_der,
            created_at: now,
            expires_at: now + ttl,
            ca_key_id: None,
            leaf_key_id: None,
        }
    }

    /// Create a new cached certificate with identity metadata.
    pub fn new_with_identity(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        ttl: Duration,
        ca_key_id: impl Into<String>,
        leaf_key_id: impl Into<String>,
    ) -> Self {
        let mut entry = Self::new(cert_der, key_der, ttl);
        entry.ca_key_id = Some(ca_key_id.into());
        entry.leaf_key_id = Some(leaf_key_id.into());
        entry
    }

    /// Check if this entry is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Certificate cache with automatic TTL-based expiration
pub struct CertCache {
    /// Cache storage
    cache: DashMap<String, CachedCert>,
    /// Default TTL for new entries
    default_ttl: Duration,
    /// Maximum number of entries
    max_entries: usize,
}

impl CertCache {
    /// Create a new certificate cache
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
            max_entries,
        }
    }

    /// Get a certificate from the cache
    pub fn get(&self, domain: &str) -> Option<CachedCert> {
        if let Some(entry) = self.cache.get(domain) {
            if entry.is_expired() {
                trace!("Certificate expired for domain: {}", domain);
                drop(entry);
                self.cache.remove(domain);
                return None;
            }
            trace!("Cache hit for domain: {}", domain);
            return Some(entry.clone());
        }
        trace!("Cache miss for domain: {}", domain);
        None
    }

    /// Insert a certificate into the cache
    pub fn insert(&self, domain: String, cert_der: Vec<u8>, key_der: Vec<u8>) {
        self.insert_with_ttl(domain, cert_der, key_der, self.default_ttl)
    }

    /// Insert a certificate with custom TTL
    pub fn insert_with_ttl(
        &self,
        domain: String,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        ttl: Duration,
    ) {
        // Evict if at capacity
        if self.cache.len() >= self.max_entries {
            self.evict_expired();
            // If still at capacity, evict oldest
            if self.cache.len() >= self.max_entries {
                self.evict_oldest();
            }
        }

        let entry = CachedCert::new(cert_der, key_der, ttl);
        debug!("Caching certificate for domain: {}", domain);
        self.cache.insert(domain, entry);
    }

    /// Insert a certificate with custom TTL and identity metadata.
    pub fn insert_with_identity(
        &self,
        domain: String,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        ttl: Duration,
        ca_key_id: impl Into<String>,
        leaf_key_id: impl Into<String>,
    ) {
        // Evict if at capacity
        if self.cache.len() >= self.max_entries {
            self.evict_expired();
            if self.cache.len() >= self.max_entries {
                self.evict_oldest();
            }
        }

        let entry = CachedCert::new_with_identity(cert_der, key_der, ttl, ca_key_id, leaf_key_id);
        debug!("Caching certificate for domain: {}", domain);
        self.cache.insert(domain, entry);
    }

    /// Remove expired entries
    pub fn evict_expired(&self) {
        let expired: Vec<String> = self
            .cache
            .iter()
            .filter(|entry| entry.is_expired())
            .map(|entry| entry.key().clone())
            .collect();

        for domain in expired {
            debug!("Evicting expired certificate for: {}", domain);
            self.cache.remove(&domain);
        }
    }

    /// Evict the oldest entry
    fn evict_oldest(&self) {
        let oldest = self
            .cache
            .iter()
            .min_by_key(|entry| entry.created_at)
            .map(|entry| entry.key().clone());

        if let Some(domain) = oldest {
            debug!("Evicting oldest certificate for: {}", domain);
            self.cache.remove(&domain);
        }
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut expired = 0;
        let mut valid = 0;
        let mut total_remaining_ttl = Duration::ZERO;
        let mut identity_bound_entries = 0usize;
        let mut ca_key_ids = std::collections::BTreeSet::new();

        for entry in self.cache.iter() {
            if entry.is_expired() {
                expired += 1;
            } else {
                valid += 1;
                total_remaining_ttl += entry.remaining_ttl();
            }
            if let Some(ca_key_id) = &entry.ca_key_id {
                identity_bound_entries += 1;
                ca_key_ids.insert(ca_key_id.clone());
            }
        }

        let avg_remaining_ttl = if valid > 0 {
            total_remaining_ttl / valid as u32
        } else {
            Duration::ZERO
        };

        CacheStats {
            total: self.cache.len(),
            valid,
            expired,
            max_entries: self.max_entries,
            avg_remaining_ttl,
            identity_bound_entries,
            distinct_ca_key_ids: ca_key_ids.len(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total entries in cache
    pub total: usize,
    /// Valid (non-expired) entries
    pub valid: usize,
    /// Expired entries (pending eviction)
    pub expired: usize,
    /// Maximum allowed entries
    pub max_entries: usize,
    /// Average remaining TTL for valid entries
    pub avg_remaining_ttl: Duration,
    /// Entries carrying CA/leaf identity metadata
    pub identity_bound_entries: usize,
    /// Distinct CA key ids represented in current cache
    pub distinct_ca_key_ids: usize,
}

impl Default for CertCache {
    fn default() -> Self {
        // Default: 1 hour TTL, 10K max entries
        Self::new(Duration::from_secs(3600), 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = CertCache::new(Duration::from_secs(60), 100);
        cache.insert("example.com".to_string(), vec![1, 2, 3], vec![4, 5, 6]);

        let entry = cache.get("example.com").unwrap();
        assert_eq!(entry.cert_der, vec![1, 2, 3]);
        assert_eq!(entry.key_der, vec![4, 5, 6]);
    }

    #[test]
    fn test_cache_miss() {
        let cache = CertCache::new(Duration::from_secs(60), 100);
        assert!(cache.get("nonexistent.com").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = CertCache::new(Duration::from_millis(50), 100);
        cache.insert("example.com".to_string(), vec![1, 2, 3], vec![4, 5, 6]);

        // Should be present initially
        assert!(cache.get("example.com").is_some());

        // Wait for expiration
        sleep(Duration::from_millis(100));

        // Should be expired now
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_cache_eviction_at_capacity() {
        let cache = CertCache::new(Duration::from_secs(60), 2);
        cache.insert("domain1.com".to_string(), vec![1], vec![1]);
        cache.insert("domain2.com".to_string(), vec![2], vec![2]);
        cache.insert("domain3.com".to_string(), vec![3], vec![3]);

        // Should have evicted the oldest (domain1)
        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_cache_stats() {
        let cache = CertCache::new(Duration::from_secs(60), 100);
        cache.insert("domain1.com".to_string(), vec![1], vec![1]);
        cache.insert("domain2.com".to_string(), vec![2], vec![2]);

        let stats = cache.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.valid, 2);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.identity_bound_entries, 0);
        assert_eq!(stats.distinct_ca_key_ids, 0);
    }

    #[test]
    fn test_cache_identity_stats() {
        let cache = CertCache::new(Duration::from_secs(60), 100);
        cache.insert_with_identity(
            "domain1.com".to_string(),
            vec![1],
            vec![1],
            Duration::from_secs(60),
            "ca:key-a",
            "leaf:a",
        );
        cache.insert_with_identity(
            "domain2.com".to_string(),
            vec![2],
            vec![2],
            Duration::from_secs(60),
            "ca:key-a",
            "leaf:b",
        );

        let stats = cache.stats();
        assert_eq!(stats.identity_bound_entries, 2);
        assert_eq!(stats.distinct_ca_key_ids, 1);
    }
}
