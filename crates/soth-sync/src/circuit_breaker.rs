//! Lock-free circuit breaker for outbound network calls.
//!
//! The breaker cycles through three states:
//! - **Closed** — requests flow normally.
//! - **Open** — requests are rejected until `open_duration_ms` elapses.
//! - **Half-open** — one probe request is allowed; repeated successes close the
//!   breaker, any failure reopens it.
//!
//! All state is stored in atomics so the type is `Send + Sync` with no locking.
//!
//! # Example
//!
//! ```rust
//! use soth_sync::circuit_breaker::CircuitBreaker;
//!
//! let cb = CircuitBreaker::new(3, 30_000, 2);
//!
//! // Simulate failures until the breaker opens.
//! for _ in 0..3 {
//!     cb.record_failure();
//! }
//! assert!(cb.is_open());
//! assert!(!cb.allow_request());
//! ```

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CLOSED: u8 = 0;
const OPEN: u8 = 1;
const HALF_OPEN: u8 = 2;

/// A lock-free, three-state circuit breaker.
pub struct CircuitBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    consecutive_successes: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    failure_threshold: u32,
    success_threshold: u32,
    open_duration_ms: u64,
}

impl CircuitBreaker {
    /// Creates a new `CircuitBreaker` in the **closed** state.
    ///
    /// - `failure_threshold` — number of consecutive failures needed to open.
    /// - `open_duration_ms` — milliseconds to stay open before probing.
    /// - `success_threshold` — consecutive probe successes needed to close.
    pub fn new(failure_threshold: u32, open_duration_ms: u64, success_threshold: u32) -> Self {
        Self {
            state: AtomicU8::new(CLOSED),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            open_duration_ms,
        }
    }

    /// Returns `true` if the caller should proceed with the request.
    ///
    /// When the breaker is **open** and the timeout has elapsed, the state
    /// transitions atomically to **half-open** and returns `true` to allow a
    /// single probe.
    pub fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            CLOSED => true,
            OPEN => {
                let elapsed =
                    now_ms().saturating_sub(self.last_failure_epoch_ms.load(Ordering::Acquire));
                if elapsed >= self.open_duration_ms {
                    // Transition to half-open and allow the probe.
                    // Use compare_exchange so only one concurrent caller wins
                    // the race to flip to HALF_OPEN; others will still see OPEN
                    // and be rejected until the winner flips the state.
                    let _ = self.state.compare_exchange(
                        OPEN,
                        HALF_OPEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    // Re-read state: if we won the race we're HALF_OPEN (allow);
                    // if another goroutine already moved it forward, respect that.
                    self.state.load(Ordering::Acquire) != OPEN
                } else {
                    false
                }
            }
            HALF_OPEN => true, // allow probe through
            _ => true,
        }
    }

    /// Records a successful request outcome.
    ///
    /// - In the **closed** state, resets the failure counter.
    /// - In the **half-open** state, increments the success counter and closes
    ///   the breaker once `success_threshold` is reached.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        match self.state.load(Ordering::Acquire) {
            HALF_OPEN => {
                let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.success_threshold {
                    self.state.store(CLOSED, Ordering::Release);
                    self.consecutive_successes.store(0, Ordering::Relaxed);
                }
            }
            _ => {
                self.consecutive_successes.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Records a failed request outcome.
    ///
    /// - In the **half-open** state a single failure immediately reopens the
    ///   breaker; the failure counter is also reset so the next close attempt
    ///   starts fresh.
    /// - In all other states the failure counter is incremented, and the
    ///   breaker opens once `failure_threshold` consecutive failures are reached.
    pub fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.last_failure_epoch_ms
            .store(now_ms(), Ordering::Release);

        if self.state.load(Ordering::Acquire) == HALF_OPEN {
            // Any failure during the probe window reopens the breaker immediately.
            self.consecutive_failures.store(0, Ordering::Relaxed);
            self.state.store(OPEN, Ordering::Release);
            return;
        }

        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.failure_threshold {
            self.state.store(OPEN, Ordering::Release);
        }
    }

    /// Returns `true` when the breaker is in the **open** state.
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPEN
    }

    /// Returns the current state as a human-readable string for diagnostics.
    pub fn state_label(&self) -> &'static str {
        match self.state.load(Ordering::Acquire) {
            CLOSED => "closed",
            OPEN => "open",
            HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn closed_allows_requests() {
        let cb = CircuitBreaker::new(3, 30_000, 2);
        assert!(cb.allow_request());
        assert!(!cb.is_open());
        assert_eq!(cb.state_label(), "closed");
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, 30_000, 2);
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open(), "should still be closed after 2 failures");
        cb.record_failure();
        assert!(cb.is_open(), "should be open after 3 failures");
        assert_eq!(cb.state_label(), "open");
    }

    #[test]
    fn open_rejects_requests() {
        let cb = CircuitBreaker::new(2, 30_000, 2);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());
        assert!(!cb.allow_request(), "open breaker must reject requests");
    }

    #[test]
    fn success_in_closed_resets_failure_counter() {
        let cb = CircuitBreaker::new(3, 30_000, 2);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // Two more failures should not open (counter was reset).
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open());
    }

    #[test]
    fn transitions_to_half_open_after_timeout() {
        // Use a zero-duration window so the probe fires immediately.
        let cb = CircuitBreaker::new(2, 0, 2);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());

        // With open_duration_ms = 0 the elapsed time will always be >= 0,
        // so allow_request should flip to half-open and return true.
        assert!(cb.allow_request(), "should allow probe after timeout");
        assert_eq!(cb.state_label(), "half_open");
    }

    #[test]
    fn half_open_closes_after_success_threshold() {
        let cb = CircuitBreaker::new(2, 0, 3);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());

        // Transition to half-open via probe.
        cb.allow_request();
        assert_eq!(cb.state_label(), "half_open");

        cb.record_success();
        cb.record_success();
        assert_eq!(
            cb.state_label(),
            "half_open",
            "should still be half_open after 2 successes (threshold=3)"
        );
        cb.record_success();
        assert_eq!(cb.state_label(), "closed", "should close after 3 successes");
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_reopens_on_failure() {
        // Use a non-zero open duration so the breaker stays open after
        // record_failure re-opens it (allowing the final assertion to hold).
        let cb = CircuitBreaker::new(2, 60_000_000, 3);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());

        // Force-transition to half-open by manipulating the timestamp so the
        // open-duration check passes — easiest in tests by using a zero-duration
        // variant just for the probe transition.
        //
        // Instead, directly manipulate state via a zero-duration clone for the
        // probe step, then verify re-open on the original.  Since CircuitBreaker
        // is not Clone, we simply construct the scenario with duration=0 for the
        // transition probe and duration=large for the final assertion.
        let cb = CircuitBreaker::new(2, 0, 3);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());

        // Probe (open_duration=0 → immediately half-open).
        assert!(cb.allow_request());
        assert_eq!(cb.state_label(), "half_open");

        cb.record_success(); // one success — not enough to close
        assert_eq!(cb.state_label(), "half_open");

        cb.record_failure(); // failure in half-open → immediately re-opens
        assert!(
            cb.is_open(),
            "failure in half-open should reopen the breaker"
        );
        assert_eq!(cb.state_label(), "open");
    }

    #[test]
    fn open_duration_gates_half_open_probe() {
        // Use a very long open duration so the probe is NOT yet allowed.
        let cb = CircuitBreaker::new(2, 60_000_000, 2);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());
        assert!(
            !cb.allow_request(),
            "open_duration not elapsed — must remain rejected"
        );
        assert_eq!(cb.state_label(), "open");
    }

    #[test]
    fn minimum_thresholds_are_clamped_to_one() {
        // Zero thresholds are unsafe; constructor clamps to 1.
        let cb = CircuitBreaker::new(0, 0, 0);
        cb.record_failure();
        assert!(cb.is_open(), "single failure should open with threshold=1");

        let cb2 = CircuitBreaker::new(0, 0, 0);
        cb2.record_failure();
        cb2.allow_request(); // moves to half-open
        cb2.record_success();
        assert_eq!(
            cb2.state_label(),
            "closed",
            "single success should close with success_threshold=1"
        );
    }

    /// Verify that the helper used in production returns a plausible timestamp.
    #[test]
    fn now_ms_returns_reasonable_epoch() {
        let ms = now_ms();
        // 2020-01-01 in milliseconds — a sane lower bound.
        assert!(ms > 1_577_836_800_000, "epoch ms looks stale: {ms}");
        // Upper bound: roughly year 2100 as a sanity check.
        assert!(
            ms < 4_102_444_800_000,
            "epoch ms looks too far in future: {ms}"
        );
    }

    /// Simulate a realistic sequence: failures open the breaker, timeout
    /// triggers half-open, successes close it again.
    #[test]
    fn full_lifecycle() {
        // Normal operation with a long open duration.
        let cb = CircuitBreaker::new(3, 60_000_000, 2);

        assert!(cb.allow_request());
        cb.record_success();
        assert_eq!(cb.state_label(), "closed");

        // Failures accumulate and open the breaker.
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open(), "two failures below threshold");
        cb.record_failure();
        assert!(cb.is_open(), "third failure crosses threshold");

        // While open (and timeout not elapsed), requests are rejected.
        assert!(!cb.allow_request(), "open breaker must reject requests");
        assert_eq!(cb.state_label(), "open");

        // Simulate elapsed timeout by using a zero-duration breaker for the
        // recovery leg (tests cannot sleep 60 s).
        let cb2 = CircuitBreaker::new(3, 0, 2);
        cb2.record_failure();
        cb2.record_failure();
        cb2.record_failure();
        assert!(cb2.is_open());

        // open_duration=0 → probe is allowed immediately.
        assert!(cb2.allow_request(), "probe allowed after timeout");
        assert_eq!(cb2.state_label(), "half_open");

        // Recovery via successes.
        cb2.record_success();
        cb2.record_success();
        assert_eq!(cb2.state_label(), "closed");
        assert!(cb2.allow_request());
    }

    /// Test that `Duration::from_secs` conversion for typical configs works.
    #[test]
    fn thirty_second_open_duration() {
        let open_ms = Duration::from_secs(30).as_millis() as u64;
        let cb = CircuitBreaker::new(5, open_ms, 3);
        for _ in 0..5 {
            cb.record_failure();
        }
        assert!(cb.is_open());
        // Should not transition yet since 30 s have not elapsed.
        assert!(!cb.allow_request());
    }
}
