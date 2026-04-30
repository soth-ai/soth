//! In-memory telemetry queue (v0 stub).
//!
//! Events are enqueued by `post_call` / `stream_end`; a background
//! shipper drains them to soth-cloud. The shipper itself is Phase-1
//! work; v0 keeps the queue and exposes a `drain_for_test` helper so
//! the smoke test can assert events were emitted.
//!
//! Queue is bounded — when full, oldest events drop with a counter so
//! cluster operators know to size up. Locked by Plan 2's "Sampling &
//! cost control" cross-cutting note.

use std::collections::VecDeque;
use std::sync::Mutex;

use soth_core::TelemetryEvent;

const DEFAULT_CAPACITY: usize = 4096;

pub(crate) struct TelemetryQueue {
    inner: Mutex<VecDeque<TelemetryEvent>>,
    capacity: usize,
    dropped: std::sync::atomic::AtomicU64,
}

impl TelemetryQueue {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn push(&self, event: TelemetryEvent) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if guard.len() >= self.capacity {
            guard.pop_front();
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        guard.push_back(event);
    }

    #[allow(dead_code)] // Phase-1 hook for shipper batching diagnostics
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[allow(dead_code)] // Phase-1 hook for shipper batching diagnostics
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Test helper — drain all queued events. Production shipper will
    /// pull batches via a separate API in Phase 1.
    pub fn drain_for_test(&self) -> Vec<TelemetryEvent> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_event() -> TelemetryEvent {
        TelemetryEvent {
            provider: "openai".to_string(),
            ..TelemetryEvent::default()
        }
    }

    #[test]
    fn push_then_drain_is_fifo() {
        let q = TelemetryQueue::new();
        q.push(fake_event());
        q.push(fake_event());
        assert_eq!(q.len(), 2);
        let drained = q.drain_for_test();
        assert_eq!(drained.len(), 2);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn full_queue_drops_oldest_and_increments_counter() {
        let q = TelemetryQueue::with_capacity(2);
        q.push(fake_event());
        q.push(fake_event());
        q.push(fake_event());
        assert_eq!(q.len(), 2);
        assert_eq!(q.dropped_count(), 1);
    }
}
