use std::time::{Duration, Instant};

use dashmap::DashMap;
use soth_classify::ClassifiedResult;
use soth_core::SessionSnapshot;
use uuid::Uuid;

use crate::response::UsageSummary;

#[derive(Debug, Clone)]
struct SessionEntry {
    snapshot: SessionSnapshot,
    last_active: Instant,
}

pub struct SessionStore {
    inner: DashMap<Uuid, SessionEntry>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            ttl,
        }
    }

    pub fn snapshot(&self, connection_id: Uuid) -> SessionSnapshot {
        self.inner
            .get(&connection_id)
            .map(|entry| entry.snapshot.clone())
            .unwrap_or_default()
    }

    pub fn apply_classification(&self, connection_id: Uuid, result: &ClassifiedResult) {
        let mut entry = self
            .inner
            .entry(connection_id)
            .or_insert_with(|| SessionEntry {
                snapshot: SessionSnapshot::default(),
                last_active: Instant::now(),
            });

        entry.last_active = Instant::now();
        let snapshot = &mut entry.snapshot;

        snapshot.request_count = snapshot.request_count.saturating_add(1);
        snapshot.total_tokens = snapshot.total_tokens.saturating_add(u64::from(
            result.telemetry_event.estimated_input_tokens.unwrap_or(0),
        ));
        snapshot.total_cost_usd +=
            f64::from(result.telemetry_event.estimated_cost_usd.unwrap_or(0.0));

        if result
            .telemetry_event
            .sensitive_code_flags
            .credential_pattern_detected
        {
            snapshot.credential_alerts = snapshot.credential_alerts.saturating_add(1);
        }

        if !snapshot
            .topic_cluster_ids_seen
            .iter()
            .any(|seen| *seen == result.topic_cluster_id)
        {
            snapshot
                .topic_cluster_ids_seen
                .push(result.topic_cluster_id);
            if snapshot.topic_cluster_ids_seen.len() > 128 {
                snapshot.topic_cluster_ids_seen.remove(0);
            }
        }

        snapshot
            .prior_semantic_hashes
            .push(result.semantic_hash.clone());
        if snapshot.prior_semantic_hashes.len() > 50 {
            snapshot.prior_semantic_hashes.remove(0);
        }

        snapshot.last_model = result.telemetry_event.model.clone();
        snapshot.current_request_timestamp = result.telemetry_event.timestamp_epoch_ms;
        snapshot.last_request_timestamp = Some(result.telemetry_event.timestamp_epoch_ms);
        if snapshot.session_start.is_none() {
            snapshot.session_start = Some(result.telemetry_event.timestamp_epoch_ms);
        }
    }

    pub fn apply_response_usage(&self, connection_id: Uuid, usage: &UsageSummary) {
        if let Some(mut entry) = self.inner.get_mut(&connection_id) {
            entry.last_active = Instant::now();
            entry.snapshot.total_tokens = entry
                .snapshot
                .total_tokens
                .saturating_add(usage.output_tokens);
            entry.snapshot.total_cost_usd += usage.estimated_output_cost_usd;
        }
    }

    pub fn evict_stale(&self) {
        let ttl = self.ttl;
        self.inner
            .retain(|_, value| value.last_active.elapsed() <= ttl);
    }
}
