use std::time::{Duration, Instant};

use dashmap::DashMap;
use soth_core::StreamChunk;
use soth_core::DetectBundleSlice;
use soth_detect::{ChunkEvent, StreamTurn};
use uuid::Uuid;

use crate::pending::PendingCapture;
use crate::response::UsageSummary;

#[derive(Debug, Clone)]
struct StreamAccumulator {
    pending: PendingCapture,
    chunk_count: u64,
    started_at: Instant,
    /// Timestamp of the first chunk received (for TTFB calculation).
    first_chunk_at: Option<Instant>,
    accumulated_payload_bytes: u64,
    /// Detect-layer stream session that owns model extraction, usage
    /// extraction, turn lifecycle, and content accumulation.
    detect_session: soth_detect::StreamDetectState,
}

#[derive(Debug, Clone)]
pub struct CompletedStream {
    pub pending: PendingCapture,
    pub chunk_count: u64,
    pub elapsed: Duration,
    pub usage: Option<UsageSummary>,
    pub accumulated_payload_bytes: u64,
    pub extracted_model: Option<String>,
    /// Time to first byte: duration from request arrival to first chunk.
    pub ttfb: Option<Duration>,
}

pub struct StreamingStore {
    inner: DashMap<Uuid, StreamAccumulator>,
    max_capacity: usize,
}

impl Default for StreamingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            max_capacity: 1_024,
        }
    }

    pub fn start_stream(&self, pending: PendingCapture) {
        // Enforce capacity
        if self.inner.len() >= self.max_capacity {
            self.evict_oldest(self.max_capacity / 8);
        }
        let mut detect_session =
            soth_detect::StreamDetectState::new(pending.connection_id, pending.outcome.capture_mode);
        detect_session.is_websocket = pending.is_websocket;

        // Anchor timing to request arrival (stored_at) so that elapsed and TTFB
        // measure from request → stream end / request → first chunk, not from
        // first chunk → stream end (which would make TTFB ≈ 0).
        let request_time = pending.stored_at;
        self.inner.insert(
            pending.connection_id,
            StreamAccumulator {
                pending,
                chunk_count: 0,
                started_at: request_time,
                first_chunk_at: None,
                accumulated_payload_bytes: 0,
                detect_session,
            },
        );
    }

    /// Process a stream chunk through soth-detect's parser layer.
    /// Returns `Some(StreamTurn)` when a WebSocket turn completes.
    pub fn on_chunk(
        &self,
        chunk: &StreamChunk,
        bundle: &DetectBundleSlice<'_>,
    ) -> Option<StreamTurn> {
        if let Some(mut state) = self.inner.get_mut(&chunk.connection_id) {
            if state.first_chunk_at.is_none() {
                state.first_chunk_at = Some(Instant::now());

                // Resolve format_name from matched entity's api_format on first
                // chunk. This is critical for WebSocket streams where the initial
                // GET has no body, so the detect pipeline can't fingerprint the
                // format from the request alone.
                if state.detect_session.format_name.is_none() {
                    // Resolve api_format using the same classify path the
                    // detect engine uses: match host + path against entity
                    // matching_rules to find the most specific entity.
                    let host = state.pending.request_host.as_str();
                    let path = state.pending.request_path.as_str();
                    let format_name = soth_detect::classify_request_format(
                        host, path, bundle,
                    );
                    if let Some(name) = format_name {
                        state.detect_session.set_format_name(name);
                    }
                }
            }
            state.chunk_count = state.chunk_count.saturating_add(1);
            state.accumulated_payload_bytes = state
                .accumulated_payload_bytes
                .saturating_add(chunk.payload.len() as u64);

            // Delegate all parsing to soth-detect: model extraction, usage
            // extraction, turn lifecycle, content accumulation, artifact scan.
            if let Some(event) =
                soth_detect::process_chunk_with_bundle(chunk, &mut state.detect_session, bundle)
            {
                match event {
                    ChunkEvent::TurnCompleted(turn) => return Some(turn),
                    ChunkEvent::Artifact(_artifact) => {
                        // TODO: forward sensitive artifacts to classify/telemetry
                    }
                }
            }
        }
        None
    }

    /// Get a clone of the pending capture for this connection without removing it.
    pub fn peek_pending(&self, connection_id: &Uuid) -> Option<PendingCapture> {
        self.inner
            .get(connection_id)
            .map(|state| state.pending.clone())
    }

    pub fn contains(&self, connection_id: &Uuid) -> bool {
        self.inner.contains_key(connection_id)
    }

    pub fn remove(&self, connection_id: &Uuid) -> bool {
        self.inner.remove(connection_id).is_some()
    }

    pub fn take(&self, connection_id: &Uuid) -> Option<CompletedStream> {
        self.inner
            .remove(connection_id)
            .map(|(_, state)| {
                let session = &state.detect_session;
                // Merge finish_reason: prefer the independently-extracted one
                // (always the most recent), falling back to the one co-located
                // with usage data. Providers often send finish_reason in a
                // separate chunk from usage, so the independent value is more
                // reliable.
                let merged_finish_reason = session
                    .last_finish_reason
                    .clone()
                    .or_else(|| {
                        session
                            .last_usage
                            .as_ref()
                            .and_then(|u| u.finish_reason.clone())
                    });
                let usage = session.last_usage.as_ref().map(|u| UsageSummary {
                    input_tokens: u.input_tokens,
                    output_tokens: u.output_tokens,
                    estimated_output_cost_usd: 0.0,
                    finish_reason: merged_finish_reason,
                });
                let ttfb = state
                    .first_chunk_at
                    .and_then(|first| first.checked_duration_since(state.started_at));
                CompletedStream {
                    pending: state.pending,
                    chunk_count: state.chunk_count,
                    elapsed: state.started_at.elapsed(),
                    usage,
                    accumulated_payload_bytes: state.accumulated_payload_bytes,
                    extracted_model: session.model.clone(),
                    ttfb,
                }
            })
    }

    pub fn evict_stale(&self, max_age: Duration, max_scan: usize) {
        let mut scanned = 0;
        let mut to_remove = Vec::new();
        for entry in self.inner.iter() {
            if scanned >= max_scan {
                break;
            }
            if entry.value().started_at.elapsed() > max_age {
                to_remove.push(*entry.key());
            }
            scanned += 1;
        }
        for id in to_remove {
            self.inner.remove(&id);
        }
    }

    fn evict_oldest(&self, count: usize) {
        let mut entries: Vec<(Uuid, Instant)> = self.inner.iter()
            .map(|e| (*e.key(), e.value().started_at))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        for (id, _) in entries.into_iter().take(count) {
            self.inner.remove(&id);
        }
    }
}
