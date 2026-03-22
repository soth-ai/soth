use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use uuid::Uuid;

/// State needed to run classify_task after the first WebSocket frame enriches the detect result.
#[derive(Clone)]
pub struct DeferredClassify {
    pub content_for_embedding: Option<String>,
    pub raw_body_for_db: Option<Bytes>,
    pub classify_bundle: Arc<soth_classify::ClassifyBundle>,
    pub policy_bundle: Arc<soth_policy::PolicyBundle>,
    pub bundle_trust_level: soth_core::BundleTrustLevel,
    pub classify_config: Arc<soth_classify::ClassifyConfig>,
    pub lane: crate::session::Lane,
}

impl std::fmt::Debug for DeferredClassify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredClassify")
            .field("lane", &self.lane)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct PendingCapture {
    pub connection_id: Uuid,
    pub stored_at: Instant,
    pub request_method: String,
    pub request_host: String,
    pub request_path: String,
    pub request_body_bytes: usize,
    pub outcome: soth_core::GateOutcome,
    pub detect_result: soth_core::DetectResult,
    pub proxy_ctx: soth_core::ProxyContext,
    pub raw_body: Option<Bytes>,
    /// When set, classify_task was not spawned at request time and should be
    /// triggered after the first WebSocket frame enriches the detect result.
    pub deferred_classify: Option<DeferredClassify>,
    /// True when this capture represents a WebSocket upgrade.  WebSocket
    /// streams can carry multiple AI turns; the streaming layer uses this
    /// to emit per-turn records instead of waiting for connection close.
    pub is_websocket: bool,
}

pub struct PendingStore {
    inner: DashMap<Uuid, PendingCapture>,
    max_capacity: usize,
}

impl Default for PendingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            max_capacity: 2_048,
        }
    }

    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            inner: DashMap::new(),
            max_capacity,
        }
    }

    pub fn insert(&self, capture: PendingCapture) {
        // Enforce capacity: evict oldest entries if at limit
        if self.inner.len() >= self.max_capacity {
            self.evict_oldest(self.max_capacity / 8); // evict ~12.5% to avoid thrashing
        }
        self.inner.insert(capture.connection_id, capture);
    }

    pub fn take(&self, connection_id: &Uuid) -> Option<PendingCapture> {
        self.inner.remove(connection_id).map(|(_, value)| value)
    }

    pub fn remove(&self, connection_id: &Uuid) -> bool {
        self.inner.remove(connection_id).is_some()
    }

    pub fn evict_stale(&self, max_age: Duration, max_scan: usize) {
        let mut scanned = 0;
        let mut to_remove = Vec::new();
        for entry in self.inner.iter() {
            if scanned >= max_scan {
                break;
            }
            if entry.value().stored_at.elapsed() > max_age {
                to_remove.push(*entry.key());
            }
            scanned += 1;
        }
        for id in to_remove {
            self.inner.remove(&id);
        }
    }

    /// Force-evict the oldest N entries regardless of age.
    fn evict_oldest(&self, count: usize) {
        let mut entries: Vec<(Uuid, Instant)> = self.inner.iter()
            .map(|e| (*e.key(), e.value().stored_at))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        for (id, _) in entries.into_iter().take(count) {
            self.inner.remove(&id);
        }
    }
}
