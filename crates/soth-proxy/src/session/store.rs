use std::time::{Duration, Instant};

use dashmap::DashMap;
use soth_classify::ClassifiedResult;
use soth_core::SessionSnapshot;
use uuid::Uuid;

use crate::response::UsageSummary;

#[derive(Debug, Clone)]
struct SessionEntry {
    snapshot: SessionSnapshot,
    request_timestamps_ms: Vec<i64>,
    credential_timestamps_ms: Vec<i64>,
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

    pub fn mark_request_started(&self, connection_id: Uuid, timestamp_epoch_ms: i64) {
        let mut entry = self
            .inner
            .entry(connection_id)
            .or_insert_with(|| SessionEntry {
                snapshot: SessionSnapshot::default(),
                request_timestamps_ms: Vec::new(),
                credential_timestamps_ms: Vec::new(),
                last_active: Instant::now(),
            });
        entry.last_active = Instant::now();
        entry.snapshot.current_request_timestamp = timestamp_epoch_ms;
    }

    pub fn apply_classification(
        &self,
        connection_id: Uuid,
        result: &ClassifiedResult,
        normalized: &soth_core::NormalizedRequest,
    ) {
        let mut entry = self
            .inner
            .entry(connection_id)
            .or_insert_with(|| SessionEntry {
                snapshot: SessionSnapshot::default(),
                request_timestamps_ms: Vec::new(),
                credential_timestamps_ms: Vec::new(),
                last_active: Instant::now(),
            });

        entry.last_active = Instant::now();
        let current_ts = result.telemetry_event.timestamp_epoch_ms;
        const ONE_HOUR_MS: i64 = 3_600_000;
        const ONE_DAY_MS: i64 = 86_400_000;
        let credential_detected = result
            .telemetry_event
            .sensitive_code_flags
            .credential_pattern_detected;

        let input_tokens = result.telemetry_event.estimated_input_tokens.unwrap_or(0);

        entry.request_timestamps_ms.push(current_ts);
        entry
            .request_timestamps_ms
            .retain(|ts| *ts >= current_ts - ONE_HOUR_MS);
        if credential_detected {
            entry.credential_timestamps_ms.push(current_ts);
        }
        entry
            .credential_timestamps_ms
            .retain(|ts| *ts >= current_ts - ONE_DAY_MS);
        let request_count_this_hour =
            entry.request_timestamps_ms.len().min(u32::MAX as usize) as u32;
        let credential_alerts_24h = entry
            .credential_timestamps_ms
            .len()
            .min(usize::from(u8::MAX)) as u8;

        let snapshot = &mut entry.snapshot;
        snapshot.request_count = snapshot.request_count.saturating_add(1);
        snapshot.total_tokens = snapshot
            .total_tokens
            .saturating_add(u64::from(input_tokens));
        snapshot.session_token_total = snapshot.session_token_total.saturating_add(input_tokens);
        snapshot.total_cost_usd += result.telemetry_event.estimated_cost_usd.unwrap_or(0.0);
        snapshot.request_count_this_hour = request_count_this_hour;
        if credential_detected {
            snapshot.credential_alerts = snapshot.credential_alerts.saturating_add(1);
        }
        snapshot.credential_alerts_24h = credential_alerts_24h;

        snapshot
            .prior_semantic_hashes
            .push(result.semantic_hash.clone());
        if snapshot.prior_semantic_hashes.len() > 50 {
            snapshot.prior_semantic_hashes.remove(0);
        }

        snapshot
            .topic_cluster_ids_seen
            .push(result.topic_cluster_id);
        if snapshot.topic_cluster_ids_seen.len() > 50 {
            snapshot.topic_cluster_ids_seen.remove(0);
        }

        snapshot.last_model = result.telemetry_event.model.clone();
        if let Some(model) = result.telemetry_event.model.as_ref() {
            snapshot.models_used_this_session.push(model.clone());
            if snapshot.models_used_this_session.len() > 50 {
                snapshot.models_used_this_session.remove(0);
            }
        }

        snapshot.last_system_prompt_hash = normalized.system_prompt_hash.clone();
        let tool_depth = normalized
            .conversation_turn
            .unwrap_or(0)
            .min(u32::from(u8::MAX)) as u8;
        snapshot.max_tool_depth_seen = snapshot.max_tool_depth_seen.max(tool_depth);

        snapshot.current_request_timestamp = current_ts;
        snapshot.last_request_timestamp = Some(current_ts);
    }

    pub fn apply_response_usage(&self, connection_id: Uuid, usage: &UsageSummary) {
        if let Some(mut entry) = self.inner.get_mut(&connection_id) {
            entry.last_active = Instant::now();
            entry.snapshot.total_tokens = entry
                .snapshot
                .total_tokens
                .saturating_add(usage.output_tokens);
            entry.snapshot.total_cost_usd += usage.estimated_output_cost_usd as f32;
        }
    }

    pub fn evict_stale(&self) {
        let ttl = self.ttl;
        self.inner
            .retain(|_, value| value.last_active.elapsed() <= ttl);
    }

    pub fn remove(&self, connection_id: &Uuid) -> bool {
        self.inner.remove(connection_id).is_some()
    }
}
