//! Graceful shutdown coordination
//!
//! Tracks in-flight requests and coordinates graceful shutdown.
//! When shutdown is requested:
//! 1. Stop accepting new connections
//! 2. Wait for in-flight requests to complete
//! 3. Force close after timeout

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Shutdown coordinator for graceful termination
#[derive(Clone)]
pub struct ShutdownCoordinator {
    inner: Arc<ShutdownInner>,
}

struct ShutdownInner {
    /// Number of active connections/requests
    active_count: AtomicUsize,
    /// Whether shutdown has been requested
    shutting_down: AtomicBool,
    /// Broadcast channel for shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Timeout for graceful shutdown
    shutdown_timeout: Duration,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new(shutdown_timeout: Duration) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            inner: Arc::new(ShutdownInner {
                active_count: AtomicUsize::new(0),
                shutting_down: AtomicBool::new(false),
                shutdown_tx,
                shutdown_timeout,
            }),
        }
    }

    /// Create with default 30 second timeout
    pub fn default_timeout() -> Self {
        Self::new(Duration::from_secs(30))
    }

    /// Register a new active connection/request
    /// Returns a guard that decrements the count when dropped
    pub fn register(&self) -> Option<ConnectionGuard> {
        // Don't accept new connections if shutting down
        if self.is_shutting_down() {
            return None;
        }

        self.inner.active_count.fetch_add(1, Ordering::SeqCst);
        debug!("Connection registered, active: {}", self.active_count());

        Some(ConnectionGuard {
            coordinator: self.clone(),
        })
    }

    /// Get current active connection count
    pub fn active_count(&self) -> usize {
        self.inner.active_count.load(Ordering::SeqCst)
    }

    /// Check if shutdown has been requested
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::SeqCst)
    }

    /// Subscribe to shutdown signal
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.inner.shutdown_tx.subscribe()
    }

    /// Initiate graceful shutdown
    /// Returns when all connections are closed or timeout is reached
    pub async fn shutdown(&self) -> ShutdownResult {
        info!("Initiating graceful shutdown");

        // Set shutting down flag
        self.inner.shutting_down.store(true, Ordering::SeqCst);

        // Notify all subscribers
        let _ = self.inner.shutdown_tx.send(());

        let active = self.active_count();
        if active == 0 {
            info!("No active connections, shutdown complete");
            return ShutdownResult::Clean;
        }

        info!(
            "Waiting for {} active connections to complete (timeout: {:?})",
            active, self.inner.shutdown_timeout
        );

        // Wait for connections to drain with timeout
        let result = timeout(self.inner.shutdown_timeout, self.wait_for_zero()).await;

        match result {
            Ok(_) => {
                info!("All connections closed gracefully");
                ShutdownResult::Clean
            }
            Err(_) => {
                let remaining = self.active_count();
                warn!(
                    "Shutdown timeout reached with {} connections remaining",
                    remaining
                );
                ShutdownResult::Timeout { remaining }
            }
        }
    }

    /// Wait until active count reaches zero
    async fn wait_for_zero(&self) {
        loop {
            if self.active_count() == 0 {
                return;
            }
            // Poll every 100ms
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Decrement active count (called by ConnectionGuard)
    fn decrement(&self) {
        let prev = self.inner.active_count.fetch_sub(1, Ordering::SeqCst);
        debug!("Connection closed, active: {}", prev.saturating_sub(1));
    }
}

/// Guard that tracks a single connection's lifetime
pub struct ConnectionGuard {
    coordinator: ShutdownCoordinator,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.coordinator.decrement();
    }
}

/// Result of shutdown operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownResult {
    /// All connections closed cleanly
    Clean,
    /// Timeout reached with connections still active
    Timeout {
        /// Number of connections that were force-closed
        remaining: usize,
    },
}

impl ShutdownResult {
    /// Returns true if shutdown was clean
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_creation() {
        let coord = ShutdownCoordinator::default_timeout();
        assert_eq!(coord.active_count(), 0);
        assert!(!coord.is_shutting_down());
    }

    #[test]
    fn test_register_increments_count() {
        let coord = ShutdownCoordinator::default_timeout();

        let _guard1 = coord.register().unwrap();
        assert_eq!(coord.active_count(), 1);

        let _guard2 = coord.register().unwrap();
        assert_eq!(coord.active_count(), 2);
    }

    #[test]
    fn test_guard_decrements_on_drop() {
        let coord = ShutdownCoordinator::default_timeout();

        {
            let _guard = coord.register().unwrap();
            assert_eq!(coord.active_count(), 1);
        }

        assert_eq!(coord.active_count(), 0);
    }

    #[test]
    fn test_register_fails_during_shutdown() {
        let coord = ShutdownCoordinator::default_timeout();
        coord.inner.shutting_down.store(true, Ordering::SeqCst);

        assert!(coord.register().is_none());
    }

    #[tokio::test]
    async fn test_clean_shutdown_no_connections() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(100));
        let result = coord.shutdown().await;
        assert_eq!(result, ShutdownResult::Clean);
    }

    #[tokio::test]
    async fn test_clean_shutdown_with_connections() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(5));

        let guard = coord.register().unwrap();

        // Spawn task to drop guard after short delay
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(guard);
            assert_eq!(coord_clone.active_count(), 0);
        });

        let result = coord.shutdown().await;
        assert_eq!(result, ShutdownResult::Clean);
    }

    #[tokio::test]
    async fn test_shutdown_timeout() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(100));

        // Hold connection that won't be released
        let _guard = coord.register().unwrap();

        let result = coord.shutdown().await;
        assert!(matches!(result, ShutdownResult::Timeout { remaining: 1 }));
    }

    #[tokio::test]
    async fn test_shutdown_signal_broadcast() {
        let coord = ShutdownCoordinator::default_timeout();
        let mut rx = coord.subscribe();

        // Spawn shutdown in background
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            coord_clone.shutdown().await;
        });

        // Should receive shutdown signal
        let result = timeout(Duration::from_secs(1), rx.recv()).await;
        assert!(result.is_ok());
    }
}
