use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use uuid::Uuid;

use crate::pipeline::gates::DetectionOutcome;

#[derive(Debug, Clone)]
pub struct PendingCapture {
    pub connection_id: Uuid,
    pub stored_at: Instant,
    pub outcome: DetectionOutcome,
    pub detect_result: soth_detect::DetectResult,
    pub proxy_ctx: soth_core::ProxyContext,
    pub raw_body: Option<Bytes>,
}

pub struct PendingStore {
    inner: DashMap<Uuid, PendingCapture>,
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

    pub fn evict_stale(&self, max_age: Duration) {
        self.inner
            .retain(|_, pending| pending.stored_at.elapsed() <= max_age);
    }
}
