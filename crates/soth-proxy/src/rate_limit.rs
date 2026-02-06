//! Rate limiting for the proxy
//!
//! Implements token bucket rate limiting with support for:
//! - Per-key rate limits (e.g., per API key, per agent)
//! - Global rate limits
//! - Configurable burst capacity

use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second (refill rate)
    pub requests_per_second: f64,
    /// Maximum burst capacity
    pub burst_size: u32,
    /// Whether rate limiting is enabled
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100.0,
            burst_size: 200,
            enabled: true,
        }
    }
}

/// Token bucket for a single key
#[derive(Debug)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Last refill time
    last_refill: Instant,
    /// Tokens per second (refill rate)
    rate: f64,
    /// Maximum tokens (burst capacity)
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            rate,
            capacity: capacity as f64,
        }
    }

    /// Try to acquire a token. Returns true if successful, false if rate limited.
    fn try_acquire(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Get current available tokens
    fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// Rate limiter with per-key tracking
#[derive(Clone)]
pub struct RateLimiter {
    /// Per-key token buckets
    buckets: Arc<DashMap<String, Mutex<TokenBucket>>>,
    /// Global bucket (optional)
    global_bucket: Option<Arc<Mutex<TokenBucket>>>,
    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = if config.enabled {
            Some(Arc::new(Mutex::new(TokenBucket::new(
                config.requests_per_second * 10.0, // Global limit is 10x per-key
                config.burst_size * 10,
            ))))
        } else {
            None
        };

        Self {
            buckets: Arc::new(DashMap::new()),
            global_bucket,
            config,
        }
    }

    /// Create a disabled rate limiter (always allows)
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Check if a request should be allowed for the given key
    pub fn check(&self, key: &str) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        // Check global limit first
        if let Some(ref global) = self.global_bucket {
            let mut bucket = global.lock();
            if !bucket.try_acquire() {
                return RateLimitResult::Limited {
                    retry_after: Duration::from_secs_f64(1.0 / self.config.requests_per_second),
                    reason: RateLimitReason::Global,
                };
            }
        }

        // Check per-key limit
        let entry = self.buckets
            .entry(key.to_string())
            .or_insert_with(|| {
                Mutex::new(TokenBucket::new(
                    self.config.requests_per_second,
                    self.config.burst_size,
                ))
            });
        let mut bucket = entry.lock();

        if bucket.try_acquire() {
            RateLimitResult::Allowed
        } else {
            RateLimitResult::Limited {
                retry_after: Duration::from_secs_f64(1.0 / self.config.requests_per_second),
                reason: RateLimitReason::PerKey,
            }
        }
    }

    /// Get rate limit status for a key without consuming a token
    pub fn status(&self, key: &str) -> RateLimitStatus {
        if !self.config.enabled {
            return RateLimitStatus {
                available: self.config.burst_size as f64,
                limit: self.config.burst_size as f64,
                reset_in: Duration::ZERO,
            };
        }

        let available = self.buckets
            .get(key)
            .map(|b| b.lock().available())
            .unwrap_or(self.config.burst_size as f64);

        RateLimitStatus {
            available,
            limit: self.config.burst_size as f64,
            reset_in: Duration::from_secs_f64(
                (self.config.burst_size as f64 - available) / self.config.requests_per_second
            ),
        }
    }

    /// Clean up old buckets that haven't been used recently
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.buckets.retain(|_, bucket| {
            bucket.lock().last_refill > cutoff
        });
    }

    /// Get current configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Get number of tracked keys
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request is rate limited
    Limited {
        /// Suggested retry delay
        retry_after: Duration,
        /// Reason for limiting
        reason: RateLimitReason,
    },
}

impl RateLimitResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Reason for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// Global rate limit exceeded
    Global,
    /// Per-key rate limit exceeded
    PerKey,
}

/// Rate limit status for a key
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Available tokens
    pub available: f64,
    /// Maximum tokens (limit)
    pub limit: f64,
    /// Time until bucket is full
    pub reset_in: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_rate_limiter_allows_initial_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10.0,
            burst_size: 5,
            enabled: true,
        });

        // Should allow burst_size requests immediately
        for i in 0..5 {
            assert!(
                limiter.check("test-key").is_allowed(),
                "Request {} should be allowed",
                i
            );
        }

        // Next request should be limited
        assert!(!limiter.check("test-key").is_allowed());
    }

    #[test]
    fn test_rate_limiter_refills() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 100.0, // Fast refill for testing
            burst_size: 1,
            enabled: true,
        });

        // Use the one token
        assert!(limiter.check("test-key").is_allowed());

        // Should be limited
        assert!(!limiter.check("test-key").is_allowed());

        // Wait for refill (10ms for 1 token at 100/s)
        sleep(Duration::from_millis(15));

        // Should be allowed again
        assert!(limiter.check("test-key").is_allowed());
    }

    #[test]
    fn test_rate_limiter_per_key_isolation() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10.0,
            burst_size: 2,
            enabled: true,
        });

        // Exhaust key1
        assert!(limiter.check("key1").is_allowed());
        assert!(limiter.check("key1").is_allowed());
        assert!(!limiter.check("key1").is_allowed());

        // key2 should still have tokens
        assert!(limiter.check("key2").is_allowed());
        assert!(limiter.check("key2").is_allowed());
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let limiter = RateLimiter::disabled();

        // Should always allow
        for _ in 0..100 {
            assert!(limiter.check("any-key").is_allowed());
        }
    }

    #[test]
    fn test_rate_limit_status() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10.0,
            burst_size: 5,
            enabled: true,
        });

        // Initially full
        let status = limiter.status("test-key");
        assert!((status.available - 5.0).abs() < 0.1);
        assert!((status.limit - 5.0).abs() < 0.1);

        // Use some tokens
        limiter.check("test-key");
        limiter.check("test-key");

        let status = limiter.status("test-key");
        assert!(status.available < 4.0);
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimiter::new(RateLimitConfig::default());

        // Create some buckets
        limiter.check("key1");
        limiter.check("key2");
        limiter.check("key3");

        assert_eq!(limiter.tracked_keys(), 3);

        // Cleanup with zero max age should remove all
        limiter.cleanup(Duration::ZERO);
        assert_eq!(limiter.tracked_keys(), 0);
    }
}
