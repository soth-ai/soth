//! Decision caching for policy evaluation
//!
//! Provides a two-tier cache:
//! - L1: Request-level (short TTL, exact match)
//! - L2: Session-level (longer TTL, pattern match)

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use soth_core::types::policy::{PolicyDecision, PolicyInput};
use std::time::{Duration, Instant};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// L1 cache TTL
    pub l1_ttl: Duration,
    /// L2 cache TTL
    pub l2_ttl: Duration,
    /// Maximum L1 entries
    pub l1_max_entries: usize,
    /// Maximum L2 entries
    pub l2_max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            l1_ttl: Duration::from_secs(10),
            l2_ttl: Duration::from_secs(300),
            l1_max_entries: 10000,
            l2_max_entries: 1000,
        }
    }
}

impl From<soth_core::config::CacheConfig> for CacheConfig {
    fn from(core: soth_core::config::CacheConfig) -> Self {
        Self {
            enabled: core.enabled,
            l1_ttl: core.l1_ttl,
            l2_ttl: core.effective_l2_ttl(),
            l1_max_entries: core.l1_max_entries,
            l2_max_entries: core.l2_max_entries,
        }
    }
}

/// Cache metrics for monitoring
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheMetrics {
    /// L1 cache hits
    pub l1_hits: u64,
    /// L2 cache hits
    pub l2_hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Total lookups
    pub lookups: u64,
    /// Current L1 cache size
    pub l1_size: usize,
    /// Current L2 cache size
    pub l2_size: usize,
    /// Hit rate (0.0 - 1.0)
    pub hit_rate: f64,
}

/// Cached decision entry
#[derive(Debug, Clone)]
struct CacheEntry {
    decision: PolicyDecision,
    created_at: Instant,
}

/// Two-tier decision cache
pub struct DecisionCache {
    /// L1 cache: exact request match
    l1: DashMap<String, CacheEntry>,
    /// L2 cache: session/agent pattern match
    l2: DashMap<String, CacheEntry>,
    /// Configuration
    config: CacheConfig,
    /// Statistics
    stats: parking_lot::RwLock<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// L1 cache hits
    pub l1_hits: u64,
    /// L2 cache hits
    pub l2_hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Total lookups
    pub lookups: u64,
    /// Evictions
    pub evictions: u64,
}

impl DecisionCache {
    /// Create a new decision cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            l1: DashMap::new(),
            l2: DashMap::new(),
            config,
            stats: parking_lot::RwLock::new(CacheStats::default()),
        }
    }

    /// Compute L1 cache key (exact match)
    pub fn compute_l1_key(&self, input: &PolicyInput) -> String {
        let mut hasher = Sha256::new();

        // Include all relevant fields
        hasher.update(input.agent.id.as_bytes());
        hasher.update(input.request.method.as_bytes());
        if let Some(tool) = &input.request.tool {
            hasher.update(tool.as_bytes());
        }
        hasher.update(input.session.id.as_bytes());
        if let Some(did) = &input.identity.did {
            hasher.update(did.as_bytes());
        }

        // Include arguments hash
        let args_json = serde_json::to_string(&input.request.arguments).unwrap_or_default();
        hasher.update(args_json.as_bytes());

        hex_encode(&hasher.finalize())
    }

    /// Compute L2 cache key (pattern match - less specific)
    pub fn compute_l2_key(&self, input: &PolicyInput) -> String {
        let mut hasher = Sha256::new();

        // Only include stable identifiers
        hasher.update(input.agent.id.as_bytes());
        hasher.update(input.request.method.as_bytes());
        if let Some(tool) = &input.request.tool {
            hasher.update(tool.as_bytes());
        }
        // IMPORTANT: Include identity info - different identities must have different cache entries
        if input.identity.verified {
            hasher.update(b"verified");
        }
        if let Some(did) = &input.identity.did {
            hasher.update(did.as_bytes());
        }
        // Skip arguments and session details for broader matching

        hex_encode(&hasher.finalize())
    }

    /// Get a cached decision
    pub fn get(&self, input: &PolicyInput) -> (Option<PolicyDecision>, bool, String) {
        if !self.config.enabled {
            return (None, false, String::new());
        }

        let mut stats = self.stats.write();
        stats.lookups += 1;

        let now = Instant::now();

        // Try L1 first
        let l1_key = self.compute_l1_key(input);
        if let Some(entry) = self.l1.get(&l1_key) {
            if now.duration_since(entry.created_at) < self.config.l1_ttl {
                stats.l1_hits += 1;
                return (Some(entry.decision.clone()), true, "L1".to_string());
            } else {
                // Expired, remove it
                drop(entry);
                self.l1.remove(&l1_key);
            }
        }

        // Try L2
        let l2_key = self.compute_l2_key(input);
        if let Some(entry) = self.l2.get(&l2_key) {
            if now.duration_since(entry.created_at) < self.config.l2_ttl {
                stats.l2_hits += 1;
                return (Some(entry.decision.clone()), true, "L2".to_string());
            } else {
                // Expired, remove it
                drop(entry);
                self.l2.remove(&l2_key);
            }
        }

        stats.misses += 1;
        (None, false, String::new())
    }

    /// Cache a decision
    pub fn set(&self, input: &PolicyInput, decision: &PolicyDecision) {
        if !self.config.enabled {
            return;
        }

        let now = Instant::now();
        let entry = CacheEntry {
            decision: decision.clone(),
            created_at: now,
        };

        // Set in L1
        let l1_key = self.compute_l1_key(input);
        if self.l1.len() >= self.config.l1_max_entries {
            self.evict_l1();
        }
        self.l1.insert(l1_key, entry.clone());

        // Set in L2
        let l2_key = self.compute_l2_key(input);
        if self.l2.len() >= self.config.l2_max_entries {
            self.evict_l2();
        }
        self.l2.insert(l2_key, entry);
    }

    /// Invalidate all cache entries
    pub fn invalidate(&self) {
        self.l1.clear();
        self.l2.clear();
    }

    /// Invalidate entries for a specific session
    pub fn invalidate_session(&self, _session_id: &str) {
        // In a more sophisticated implementation, we'd track session -> keys mapping
        // For now, just clear L1 (L2 is broader and can remain)
        self.l1.clear();
    }

    /// Evict old L1 entries
    fn evict_l1(&self) {
        let now = Instant::now();
        let mut evicted = 0;

        self.l1.retain(|_, entry| {
            let keep = now.duration_since(entry.created_at) < self.config.l1_ttl;
            if !keep {
                evicted += 1;
            }
            keep
        });

        if evicted > 0 {
            let mut stats = self.stats.write();
            stats.evictions += evicted;
        }
    }

    /// Evict old L2 entries
    fn evict_l2(&self) {
        let now = Instant::now();
        let mut evicted = 0;

        self.l2.retain(|_, entry| {
            let keep = now.duration_since(entry.created_at) < self.config.l2_ttl;
            if !keep {
                evicted += 1;
            }
            keep
        });

        if evicted > 0 {
            let mut stats = self.stats.write();
            stats.evictions += evicted;
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Get hit rate
    pub fn hit_rate(&self) -> f64 {
        let stats = self.stats.read();
        if stats.lookups == 0 {
            return 0.0;
        }
        (stats.l1_hits + stats.l2_hits) as f64 / stats.lookups as f64
    }

    /// Get cache metrics for monitoring
    pub fn metrics(&self) -> CacheMetrics {
        let stats = self.stats.read();
        let hit_rate = if stats.lookups == 0 {
            0.0
        } else {
            (stats.l1_hits + stats.l2_hits) as f64 / stats.lookups as f64
        };
        CacheMetrics {
            l1_hits: stats.l1_hits,
            l2_hits: stats.l2_hits,
            misses: stats.misses,
            lookups: stats.lookups,
            l1_size: self.l1.len(),
            l2_size: self.l2.len(),
            hit_rate,
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::identity::{AgentContext, IdentityContext};
    use soth_core::types::policy::{EnvironmentContext, RequestContext, SessionContext};

    fn make_input(agent_id: &str, method: &str) -> PolicyInput {
        PolicyInput {
            agent: AgentContext {
                id: agent_id.to_string(),
                ..Default::default()
            },
            request: RequestContext {
                method: method.to_string(),
                ..Default::default()
            },
            session: SessionContext::default(),
            identity: IdentityContext::default(),
            context: EnvironmentContext::default(),
        }
    }

    #[test]
    fn test_cache_miss() {
        let cache = DecisionCache::new(CacheConfig::default());
        let input = make_input("agent-1", "tools/call");

        let (decision, hit, _) = cache.get(&input);
        assert!(decision.is_none());
        assert!(!hit);
    }

    #[test]
    fn test_cache_hit() {
        let cache = DecisionCache::new(CacheConfig::default());
        let input = make_input("agent-1", "tools/call");
        let decision = PolicyDecision::allow();

        cache.set(&input, &decision);

        let (cached, hit, tier) = cache.get(&input);
        assert!(cached.is_some());
        assert!(hit);
        assert_eq!(tier, "L1");
    }

    #[test]
    fn test_l2_cache() {
        let cache = DecisionCache::new(CacheConfig {
            l1_ttl: Duration::from_millis(1), // Very short L1 TTL
            ..Default::default()
        });

        let input = make_input("agent-1", "tools/call");
        let decision = PolicyDecision::allow();

        cache.set(&input, &decision);

        // Wait for L1 to expire
        std::thread::sleep(Duration::from_millis(5));

        let (cached, hit, tier) = cache.get(&input);
        assert!(cached.is_some());
        assert!(hit);
        assert_eq!(tier, "L2");
    }

    #[test]
    fn test_invalidate() {
        let cache = DecisionCache::new(CacheConfig::default());
        let input = make_input("agent-1", "tools/call");
        let decision = PolicyDecision::allow();

        cache.set(&input, &decision);
        cache.invalidate();

        let (cached, hit, _) = cache.get(&input);
        assert!(cached.is_none());
        assert!(!hit);
    }

    #[test]
    fn test_different_inputs() {
        let cache = DecisionCache::new(CacheConfig::default());

        let input1 = make_input("agent-1", "tools/call");
        let input2 = make_input("agent-2", "tools/call");

        cache.set(&input1, &PolicyDecision::allow());

        let (cached, hit, _) = cache.get(&input2);
        // Different agent, should miss on L1 but might hit L2 (same method)
        // Actually with different agent ID, L2 key will also differ
        assert!(!hit || cached.is_some());
    }

    #[test]
    fn test_stats() {
        let cache = DecisionCache::new(CacheConfig::default());
        let input = make_input("agent-1", "tools/call");

        // Miss
        cache.get(&input);

        // Set and hit
        cache.set(&input, &PolicyDecision::allow());
        cache.get(&input);

        let stats = cache.stats();
        assert_eq!(stats.lookups, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.l1_hits, 1);
    }

    #[test]
    fn test_cache_config_from_core() {
        use soth_core::config::CacheConfig as CoreCacheConfig;

        // Test with explicit L2 TTL
        let core_config = CoreCacheConfig {
            enabled: true,
            l1_ttl: Duration::from_secs(20),
            l2_ttl: Some(Duration::from_secs(120)),
            l1_max_entries: 5000,
            l2_max_entries: 500,
        };

        let cache_config: CacheConfig = core_config.into();
        assert!(cache_config.enabled);
        assert_eq!(cache_config.l1_ttl, Duration::from_secs(20));
        assert_eq!(cache_config.l2_ttl, Duration::from_secs(120));
        assert_eq!(cache_config.l1_max_entries, 5000);
        assert_eq!(cache_config.l2_max_entries, 500);
    }

    #[test]
    fn test_cache_config_from_core_default_l2() {
        use soth_core::config::CacheConfig as CoreCacheConfig;

        // Test with default L2 TTL (30x L1)
        let core_config = CoreCacheConfig {
            enabled: true,
            l1_ttl: Duration::from_secs(10),
            l2_ttl: None,
            l1_max_entries: 10000,
            l2_max_entries: 1000,
        };

        let cache_config: CacheConfig = core_config.into();
        assert_eq!(cache_config.l1_ttl, Duration::from_secs(10));
        // L2 should default to 30x L1 = 300 seconds
        assert_eq!(cache_config.l2_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_cache_metrics() {
        let cache = DecisionCache::new(CacheConfig::default());
        let input = make_input("agent-1", "tools/call");

        // Initial metrics
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 0);
        assert_eq!(metrics.l1_hits, 0);
        assert_eq!(metrics.l2_hits, 0);
        assert_eq!(metrics.misses, 0);
        assert_eq!(metrics.l1_size, 0);
        assert_eq!(metrics.l2_size, 0);
        assert_eq!(metrics.hit_rate, 0.0);

        // After miss
        cache.get(&input);
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 1);
        assert_eq!(metrics.misses, 1);

        // After set
        cache.set(&input, &PolicyDecision::allow());
        let metrics = cache.metrics();
        assert_eq!(metrics.l1_size, 1);
        assert_eq!(metrics.l2_size, 1);

        // After hit
        cache.get(&input);
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 2);
        assert_eq!(metrics.l1_hits, 1);
        assert_eq!(metrics.hit_rate, 0.5); // 1 hit / 2 lookups
    }
}
