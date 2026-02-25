use std::time::{Duration, Instant};

use dashmap::DashMap;
use soth_core::StreamChunk;
use uuid::Uuid;

use crate::pending::PendingCapture;
use crate::response::{try_extract_usage, UsageSummary};

#[derive(Debug, Clone)]
struct StreamAccumulator {
    pending: PendingCapture,
    chunk_count: u64,
    started_at: Instant,
    last_usage: Option<UsageSummary>,
}

#[derive(Debug, Clone)]
pub struct CompletedStream {
    pub pending: PendingCapture,
    pub chunk_count: u64,
    pub elapsed: Duration,
    pub usage: Option<UsageSummary>,
}

pub struct StreamingStore {
    inner: DashMap<Uuid, StreamAccumulator>,
}

impl StreamingStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn start_stream(&self, pending: PendingCapture) {
        self.inner.insert(
            pending.connection_id,
            StreamAccumulator {
                pending,
                chunk_count: 0,
                started_at: Instant::now(),
                last_usage: None,
            },
        );
    }

    pub fn on_chunk(&self, chunk: &StreamChunk) {
        if let Some(mut state) = self.inner.get_mut(&chunk.connection_id) {
            state.chunk_count = state.chunk_count.saturating_add(1);
            if let Some(usage) = try_extract_usage(chunk.payload.as_ref()) {
                state.last_usage = Some(usage);
            }
        }
    }

    pub fn contains(&self, connection_id: &Uuid) -> bool {
        self.inner.contains_key(connection_id)
    }

    pub fn take(&self, connection_id: &Uuid) -> Option<CompletedStream> {
        self.inner
            .remove(connection_id)
            .map(|(_, state)| CompletedStream {
                pending: state.pending,
                chunk_count: state.chunk_count,
                elapsed: state.started_at.elapsed(),
                usage: state.last_usage,
            })
    }

    pub fn evict_stale(&self, max_age: Duration) {
        self.inner
            .retain(|_, state| state.started_at.elapsed() <= max_age);
    }
}
