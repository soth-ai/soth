//! Circuit breaker for upstream connections
//!
//! Implements the circuit breaker pattern to prevent cascading failures.
//! States: Closed (normal) -> Open (failing) -> Half-Open (probing)

use crate::metrics::{self, CircuitState};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Duration to keep circuit open before half-open
    pub open_duration: Duration,
    /// Number of successful requests in half-open to close circuit
    pub success_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
    /// Whether circuit breaker is enabled
    pub enabled: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
            enabled: true,
        }
    }
}

/// Circuit state for a single upstream
#[derive(Debug)]
struct Circuit {
    state: CircuitState,
    failures: Vec<Instant>,
    successes_in_half_open: u32,
    opened_at: Option<Instant>,
    config: CircuitBreakerConfig,
}

impl Circuit {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failures: Vec::new(),
            successes_in_half_open: 0,
            opened_at: None,
            config,
        }
    }

    /// Check if a request should be allowed
    fn allow_request(&mut self) -> bool {
        self.cleanup_old_failures();

        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(opened_at) = self.opened_at {
                    if opened_at.elapsed() >= self.config.open_duration {
                        self.state = CircuitState::HalfOpen;
                        self.successes_in_half_open = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request
    fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                // Clear failures on success (optional, can be configured)
            }
            CircuitState::HalfOpen => {
                self.successes_in_half_open += 1;
                if self.successes_in_half_open >= self.config.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failures.clear();
                    self.opened_at = None;
                    self.successes_in_half_open = 0;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed request
    fn record_failure(&mut self) {
        let now = Instant::now();

        match self.state {
            CircuitState::Closed => {
                self.failures.push(now);
                self.cleanup_old_failures();

                if self.failures.len() >= self.config.failure_threshold as usize {
                    self.state = CircuitState::Open;
                    self.opened_at = Some(now);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open reopens the circuit
                self.state = CircuitState::Open;
                self.opened_at = Some(now);
                self.successes_in_half_open = 0;
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Remove failures outside the time window
    fn cleanup_old_failures(&mut self) {
        let cutoff = Instant::now() - self.config.failure_window;
        self.failures.retain(|t| *t > cutoff);
    }

    /// Get current state
    fn state(&self) -> CircuitState {
        self.state
    }
}

/// Circuit breaker manager for multiple upstreams
#[derive(Clone)]
pub struct CircuitBreaker {
    circuits: Arc<DashMap<String, RwLock<Circuit>>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Create a new circuit breaker manager
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            circuits: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Create a disabled circuit breaker
    pub fn disabled() -> Self {
        Self::new(CircuitBreakerConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Check if a request to the given upstream should be allowed
    pub fn allow_request(&self, upstream: &str) -> CircuitBreakerResult {
        if !self.config.enabled {
            return CircuitBreakerResult::Allowed;
        }

        let entry = self.circuits
            .entry(upstream.to_string())
            .or_insert_with(|| RwLock::new(Circuit::new(self.config.clone())));

        let mut circuit = entry.write();
        if circuit.allow_request() {
            CircuitBreakerResult::Allowed
        } else {
            CircuitBreakerResult::Rejected {
                retry_after: self.config.open_duration.saturating_sub(
                    circuit.opened_at.map(|t| t.elapsed()).unwrap_or_default()
                ),
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self, upstream: &str) {
        if !self.config.enabled {
            return;
        }

        if let Some(entry) = self.circuits.get(upstream) {
            let mut circuit = entry.write();
            let old_state = circuit.state();
            circuit.record_success();
            let new_state = circuit.state();

            // Update metrics if state changed
            if old_state != new_state {
                metrics::set_circuit_breaker_state(upstream, new_state);
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self, upstream: &str) {
        if !self.config.enabled {
            return;
        }

        let entry = self.circuits
            .entry(upstream.to_string())
            .or_insert_with(|| RwLock::new(Circuit::new(self.config.clone())));

        let mut circuit = entry.write();
        let old_state = circuit.state();
        circuit.record_failure();
        let new_state = circuit.state();

        // Update metrics and record trip if state changed
        if old_state != new_state {
            metrics::set_circuit_breaker_state(upstream, new_state);
            if new_state == CircuitState::Open {
                metrics::record_circuit_breaker_trip(upstream);
            }
        }
    }

    /// Get the current state of a circuit
    pub fn state(&self, upstream: &str) -> CircuitState {
        if !self.config.enabled {
            return CircuitState::Closed;
        }

        self.circuits
            .get(upstream)
            .map(|e| e.read().state())
            .unwrap_or(CircuitState::Closed)
    }

    /// Get the number of tracked upstreams
    pub fn tracked_upstreams(&self) -> usize {
        self.circuits.len()
    }

    /// Reset a circuit to closed state
    pub fn reset(&self, upstream: &str) {
        if let Some(entry) = self.circuits.get(upstream) {
            let mut circuit = entry.write();
            circuit.state = CircuitState::Closed;
            circuit.failures.clear();
            circuit.opened_at = None;
            circuit.successes_in_half_open = 0;
            metrics::set_circuit_breaker_state(upstream, CircuitState::Closed);
        }
    }

    /// Reset all circuits
    pub fn reset_all(&self) {
        for entry in self.circuits.iter() {
            let upstream = entry.key();
            let mut circuit = entry.value().write();
            circuit.state = CircuitState::Closed;
            circuit.failures.clear();
            circuit.opened_at = None;
            circuit.successes_in_half_open = 0;
            metrics::set_circuit_breaker_state(upstream, CircuitState::Closed);
        }
    }
}

/// Result of a circuit breaker check
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerResult {
    /// Request is allowed
    Allowed,
    /// Request is rejected (circuit is open)
    Rejected {
        /// Suggested retry delay
        retry_after: Duration,
    },
}

impl CircuitBreakerResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state("test"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });

        // Record failures
        for _ in 0..3 {
            cb.record_failure("test");
        }

        assert_eq!(cb.state("test"), CircuitState::Open);
        assert!(!cb.allow_request("test").is_allowed());
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_millis(50),
            ..Default::default()
        });

        // Open the circuit
        cb.record_failure("test");
        cb.record_failure("test");
        assert_eq!(cb.state("test"), CircuitState::Open);

        // Wait for open duration
        sleep(Duration::from_millis(60));

        // Should transition to half-open on next request
        assert!(cb.allow_request("test").is_allowed());
        assert_eq!(cb.state("test"), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_closes_after_successes_in_half_open() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            open_duration: Duration::from_millis(10),
            ..Default::default()
        });

        // Open the circuit
        cb.record_failure("test");
        cb.record_failure("test");

        // Wait for half-open
        sleep(Duration::from_millis(20));
        cb.allow_request("test"); // Transition to half-open

        // Record successes
        cb.record_success("test");
        cb.record_success("test");

        assert_eq!(cb.state("test"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_reopens_on_failure_in_half_open() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            open_duration: Duration::from_millis(10),
            ..Default::default()
        });

        // Open the circuit
        cb.record_failure("test");
        cb.record_failure("test");

        // Wait for half-open
        sleep(Duration::from_millis(20));
        cb.allow_request("test"); // Transition to half-open
        assert_eq!(cb.state("test"), CircuitState::HalfOpen);

        // Failure in half-open reopens
        cb.record_failure("test");
        assert_eq!(cb.state("test"), CircuitState::Open);
    }

    #[test]
    fn test_circuit_disabled() {
        let cb = CircuitBreaker::disabled();

        // Record many failures
        for _ in 0..100 {
            cb.record_failure("test");
        }

        // Should still allow requests
        assert!(cb.allow_request("test").is_allowed());
        assert_eq!(cb.state("test"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_reset() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        });

        // Open the circuit
        cb.record_failure("test");
        cb.record_failure("test");
        assert_eq!(cb.state("test"), CircuitState::Open);

        // Reset
        cb.reset("test");
        assert_eq!(cb.state("test"), CircuitState::Closed);
        assert!(cb.allow_request("test").is_allowed());
    }

    #[test]
    fn test_multiple_upstreams_isolated() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        });

        // Open circuit for upstream1
        cb.record_failure("upstream1");
        cb.record_failure("upstream1");

        // upstream1 should be open, upstream2 should be closed
        assert_eq!(cb.state("upstream1"), CircuitState::Open);
        assert_eq!(cb.state("upstream2"), CircuitState::Closed);
        assert!(cb.allow_request("upstream2").is_allowed());
    }
}
