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
        }
    }

    pub fn insert(&self, capture: PendingCapture) {
        self.inner.insert(capture.connection_id, capture);
    }

    pub fn take(&self, connection_id: &Uuid) -> Option<PendingCapture> {
        self.inner.remove(connection_id).map(|(_, value)| value)
    }

    pub fn remove(&self, connection_id: &Uuid) -> bool {
        self.inner.remove(connection_id).is_some()
    }

    pub fn evict_stale(&self, max_age: Duration) {
        self.inner
            .retain(|_, pending| pending.stored_at.elapsed() <= max_age);
    }
}
