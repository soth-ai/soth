use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

use crate::response::UsageSummary;

/// Response-side data collected after the upstream response arrives.
#[derive(Debug)]
pub struct ResponseData {
    pub output_tokens: u64,
    pub finish_reason: Option<String>,
    pub response_latency_ms: u64,
    pub ttfb_ms: Option<u64>,
}

/// Classify-side data produced by the classification pipeline.
#[derive(Debug)]
pub struct ClassifyData {
    pub telemetry_event: soth_core::TelemetryEvent,
    pub anomaly_score: f32,
    pub anomaly_flags: Vec<soth_core::AnomalyFlag>,
    pub policy_decision_kind: Option<soth_core::PolicyDecisionKind>,
    pub capture_mode: soth_core::CaptureMode,
}

/// Slot that holds both halves of a telemetry event.
/// The second writer to arrive triggers merge_and_emit.
#[derive(Debug)]
struct PendingEmit {
    classify_data: Option<ClassifyData>,
    response_data: Option<ResponseData>,
    created_at: Instant,
    session_request_count: u32,
    session_total_tokens: u64,
    session_credential_alerts: u32,
    conversation_turn: Option<u32>,
}

/// Resolved result returned when both halves are available (merge) or when
/// a stale entry is evicted. Callers check `classify_data`/`response_data`
/// to determine whether the emit is complete or partial.
pub struct ResolvedEmit {
    pub classify_data: Option<ClassifyData>,
    pub response_data: Option<ResponseData>,
    pub session_request_count: u32,
    pub session_total_tokens: u64,
    pub session_credential_alerts: u32,
    pub conversation_turn: Option<u32>,
}

/// Concurrent rendezvous store for telemetry emission.
///
/// Both classify_task and response handlers deposit their halves here.
/// The second writer to arrive atomically removes the slot and returns
/// both halves so the caller can emit the complete telemetry event.
pub struct PendingEmitStore {
    inner: DashMap<Uuid, PendingEmit>,
    max_capacity: usize,
}

impl Default for PendingEmitStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingEmitStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            max_capacity: 2_048,
        }
    }

    /// Initialize a slot for a new connection with session metadata snapshot.
    pub fn init_slot(
        &self,
        connection_id: Uuid,
        session_request_count: u32,
        session_total_tokens: u64,
        session_credential_alerts: u32,
        conversation_turn: Option<u32>,
    ) {
        // Enforce capacity: evict oldest entries if at limit
        if self.inner.len() >= self.max_capacity {
            self.evict_oldest(self.max_capacity / 8); // evict ~12.5% to avoid thrashing
        }
        self.inner.insert(
            connection_id,
            PendingEmit {
                classify_data: None,
                response_data: None,
                created_at: Instant::now(),
                session_request_count,
                session_total_tokens,
                session_credential_alerts,
                conversation_turn,
            },
        );
    }

    /// Deposit classify-side data. If both halves are now present, atomically
    /// removes the slot and returns the resolved emit (moved, not cloned).
    pub fn deposit_classify(
        &self,
        connection_id: Uuid,
        data: ClassifyData,
    ) -> Option<ResolvedEmit> {
        {
            let mut entry = self.inner.get_mut(&connection_id)?;
            entry.classify_data = Some(data);
            if entry.response_data.is_none() {
                return None;
            }
        }
        // Both halves present — atomically remove and move data out.
        self.remove_resolved(&connection_id)
    }

    /// Deposit response-side data. If both halves are now present, atomically
    /// removes the slot and returns the resolved emit (moved, not cloned).
    pub fn deposit_response(
        &self,
        connection_id: Uuid,
        data: ResponseData,
    ) -> Option<ResolvedEmit> {
        {
            let mut entry = self.inner.get_mut(&connection_id)?;
            entry.response_data = Some(data);
            if entry.classify_data.is_none() {
                return None;
            }
        }
        // Both halves present — atomically remove and move data out.
        self.remove_resolved(&connection_id)
    }

    /// Remove and discard a slot (cleanup for early-exit paths).
    pub fn remove(&self, connection_id: &Uuid) {
        self.inner.remove(connection_id);
    }

    /// Evict entries older than `max_age`. Scans at most `max_scan` entries per call
    /// to avoid GC pauses. Returns stale entries that had at least classify or
    /// response data (for partial emission).
    pub fn evict_stale(&self, max_age: Duration, max_scan: usize) -> Vec<(Uuid, ResolvedEmit)> {
        let mut stale = Vec::new();
        let mut scanned = 0;
        let mut to_remove = Vec::new();
        for entry in self.inner.iter() {
            if scanned >= max_scan {
                break;
            }
            if entry.value().created_at.elapsed() > max_age {
                to_remove.push(*entry.key());
            }
            scanned += 1;
        }
        for id in to_remove {
            if let Some((_, entry)) = self.inner.remove(&id) {
                if entry.classify_data.is_some() || entry.response_data.is_some() {
                    stale.push((
                        id,
                        ResolvedEmit {
                            classify_data: entry.classify_data,
                            response_data: entry.response_data,
                            session_request_count: entry.session_request_count,
                            session_total_tokens: entry.session_total_tokens,
                            session_credential_alerts: entry.session_credential_alerts,
                            conversation_turn: entry.conversation_turn,
                        },
                    ));
                }
            }
        }
        stale
    }

    fn evict_oldest(&self, count: usize) {
        let mut entries: Vec<(Uuid, Instant)> = self.inner.iter()
            .map(|e| (*e.key(), e.value().created_at))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        for (id, _) in entries.into_iter().take(count) {
            self.inner.remove(&id);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn remove_resolved(&self, connection_id: &Uuid) -> Option<ResolvedEmit> {
        let (_, slot) = self.inner.remove(connection_id)?;
        Some(ResolvedEmit {
            classify_data: slot.classify_data,
            response_data: slot.response_data,
            session_request_count: slot.session_request_count,
            session_total_tokens: slot.session_total_tokens,
            session_credential_alerts: slot.session_credential_alerts,
            conversation_turn: slot.conversation_turn,
        })
    }
}

/// Merge response + session data into a TelemetryEvent for emission.
pub fn apply_response_to_event(
    event: &mut soth_core::TelemetryEvent,
    response: &ResponseData,
    session_request_count: u32,
    session_total_tokens: u64,
    session_credential_alerts: u32,
    conversation_turn: Option<u32>,
) {
    event.actual_output_tokens = Some(response.output_tokens);
    event.finish_reason = response.finish_reason.clone();
    event.response_latency_ms = Some(response.response_latency_ms);
    event.ttfb_ms = response.ttfb_ms;
    event.session_request_count = Some(session_request_count);
    event.session_total_tokens = Some(session_total_tokens);
    event.session_credential_alerts = Some(session_credential_alerts);
    event.conversation_turn = conversation_turn;
}

/// Build ResponseData from a UsageSummary and timing information.
pub fn response_data_from_usage(
    usage: &UsageSummary,
    latency_ms: u64,
    ttfb_ms: Option<u64>,
) -> ResponseData {
    ResponseData {
        output_tokens: usage.output_tokens,
        finish_reason: usage.finish_reason.clone(),
        response_latency_ms: latency_ms,
        ttfb_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_classify_data() -> ClassifyData {
        ClassifyData {
            telemetry_event: soth_core::TelemetryEvent::default(),
            anomaly_score: 0.0,
            anomaly_flags: vec![],
            policy_decision_kind: None,
            capture_mode: soth_core::CaptureMode::MetadataOnly,
        }
    }

    fn sample_response_data() -> ResponseData {
        ResponseData {
            output_tokens: 100,
            finish_reason: Some("stop".to_string()),
            response_latency_ms: 250,
            ttfb_ms: Some(50),
        }
    }

    #[test]
    fn classify_first_then_response_merges() {
        let store = PendingEmitStore::new();
        let id = Uuid::new_v4();
        store.init_slot(id, 5, 1000, 0, Some(3));

        let merged = store.deposit_classify(id, sample_classify_data());
        assert!(merged.is_none(), "classify alone should not merge");

        let merged = store.deposit_response(id, sample_response_data());
        assert!(merged.is_some(), "both halves present should merge");

        let m = merged.unwrap();
        assert!(m.classify_data.is_some());
        assert!(m.response_data.is_some());
        assert_eq!(m.response_data.as_ref().unwrap().output_tokens, 100);
        assert_eq!(m.session_request_count, 5);
        assert_eq!(m.conversation_turn, Some(3));
        // Slot should be removed atomically
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn response_first_then_classify_merges() {
        let store = PendingEmitStore::new();
        let id = Uuid::new_v4();
        store.init_slot(id, 2, 500, 1, None);

        let merged = store.deposit_response(id, sample_response_data());
        assert!(merged.is_none(), "response alone should not merge");

        let merged = store.deposit_classify(id, sample_classify_data());
        assert!(merged.is_some(), "both halves present should merge");
        assert_eq!(store.len(), 0, "slot should be removed atomically");
    }

    #[test]
    fn eviction_returns_stale_with_classify_only() {
        let store = PendingEmitStore::new();
        let id = Uuid::new_v4();
        store.init_slot(id, 1, 100, 0, None);
        store.deposit_classify(id, sample_classify_data());

        // Evict with zero duration to force stale
        let stale = store.evict_stale(std::time::Duration::ZERO, 256);
        assert_eq!(stale.len(), 1);
        assert!(stale[0].1.classify_data.is_some());
        assert!(stale[0].1.response_data.is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn deposit_without_init_returns_none() {
        let store = PendingEmitStore::new();
        let id = Uuid::new_v4();
        assert!(store.deposit_classify(id, sample_classify_data()).is_none());
        assert!(store.deposit_response(id, sample_response_data()).is_none());
    }

    #[test]
    fn remove_cleans_up_slot() {
        let store = PendingEmitStore::new();
        let id = Uuid::new_v4();
        store.init_slot(id, 1, 100, 0, None);
        assert_eq!(store.len(), 1);
        store.remove(&id);
        assert_eq!(store.len(), 0);
    }
}
