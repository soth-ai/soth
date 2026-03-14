use std::collections::VecDeque;
use std::time::Instant;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use soth_classify::ClassifiedResult;
use soth_core::{
    AnomalyBaseline, AppType, SeenPrefixRecord, Session, SessionAppIdentity, SessionKey,
    SessionMutations, SessionSnapshot, SessionStats,
};
use uuid::Uuid;

use crate::config::SessionConfig;
use crate::response::UsageSummary;

/// Maps connection_id → SessionKey so we can look up sessions when only
/// the connection_id is available (e.g. on_response, on_connection_close).
struct ConnectionBinding {
    session_key: SessionKey,
    bound_at: Instant,
}

pub struct SessionManager {
    sessions: DashMap<SessionKey, SessionEntry>,
    connection_map: DashMap<Uuid, ConnectionBinding>,
    config: SessionConfig,
}

struct SessionEntry {
    session: Session,
    /// Cached SHA-256 hash of the session key, computed once at creation.
    key_hash: String,
    request_timestamps_ms: Vec<i64>,
    credential_timestamps_ms: Vec<i64>,
    last_active: Instant,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            connection_map: DashMap::new(),
            config,
        }
    }

    /// Derive a SessionKey from the gate outcome's process resolution.
    pub fn derive_key(
        &self,
        process_resolution: &soth_core::ProcessResolution,
        matched_application: Option<&str>,
    ) -> SessionKey {
        let app_identity = match process_resolution.app_type {
            AppType::Host => {
                let browser = process_resolution
                    .bundle_id
                    .as_deref()
                    .or(process_resolution.process_name.as_deref())
                    .unwrap_or("unknown-browser")
                    .to_string();
                let ai_origin = matched_application
                    .unwrap_or("unknown-origin")
                    .to_string();
                SessionAppIdentity::BrowserSession { browser, ai_origin }
            }
            _ => {
                let identity = matched_application
                    .map(String::from)
                    .or_else(|| process_resolution.bundle_id.clone())
                    .or_else(|| process_resolution.process_name.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                SessionAppIdentity::NativeApp { identity }
            }
        };

        let now_epoch_secs = chrono::Utc::now().timestamp();
        let window_secs = self.config.window_secs.max(1) as i64;
        let window_start = (now_epoch_secs / window_secs) * window_secs;

        SessionKey {
            app_identity,
            window_start,
        }
    }

    /// Bind a connection_id to a SessionKey so future lookups by connection_id work.
    pub fn bind_connection(&self, connection_id: Uuid, key: SessionKey) {
        self.connection_map.insert(
            connection_id,
            ConnectionBinding {
                session_key: key,
                bound_at: Instant::now(),
            },
        );
    }

    /// Unbind a connection and return whether it was bound.
    pub fn unbind_connection(&self, connection_id: &Uuid) -> bool {
        self.connection_map.remove(connection_id).is_some()
    }

    /// Get or create a session for the given key. Returns the session key hash.
    pub fn get_or_create(&self, key: &SessionKey) -> String {
        if let Some(entry) = self.sessions.get(key) {
            return entry.key_hash.clone();
        }

        // Enforce max_sessions: evict oldest if needed
        if self.sessions.len() >= self.config.max_sessions {
            self.evict_oldest();
        }

        let key_hash = session_key_hash(key);
        let now_ms = chrono::Utc::now().timestamp_millis();
        self.sessions.insert(
            key.clone(),
            SessionEntry {
                session: Session {
                    key: key.clone(),
                    code_hash_ring: VecDeque::new(),
                    prefix_hash_ring: VecDeque::new(),
                    stats: SessionStats::default(),
                    anomaly_baseline: AnomalyBaseline::default(),
                    created_at: now_ms,
                    last_activity: now_ms,
                },
                key_hash: key_hash.clone(),
                request_timestamps_ms: Vec::new(),
                credential_timestamps_ms: Vec::new(),
                last_active: Instant::now(),
            },
        );

        key_hash
    }

    /// Produce an immutable SessionSnapshot from the current session state.
    pub fn snapshot(&self, key: &SessionKey) -> SessionSnapshot {
        self.sessions
            .get(key)
            .map(|entry| self.entry_to_snapshot(&entry))
            .unwrap_or_default()
    }

    /// Snapshot via connection_id (for response/stream handlers that don't have the key).
    pub fn snapshot_by_connection(&self, connection_id: Uuid) -> SessionSnapshot {
        let Some(binding) = self.connection_map.get(&connection_id) else {
            return SessionSnapshot::default();
        };
        self.snapshot(&binding.session_key)
    }

    /// Mark request start (updates timestamps, request count).
    pub fn mark_request_started(&self, key: &SessionKey, timestamp_epoch_ms: i64) {
        if let Some(mut entry) = self.sessions.get_mut(key) {
            entry.last_active = Instant::now();
            entry.session.last_activity = timestamp_epoch_ms;
            entry.request_timestamps_ms.push(timestamp_epoch_ms);
        }
    }

    /// Apply mutations returned by detect (dedup hashes, token deltas, credential alerts).
    pub fn apply_detect_mutations(&self, key: &SessionKey, mutations: &SessionMutations) {
        let Some(mut entry) = self.sessions.get_mut(key) else {
            return;
        };
        entry.last_active = Instant::now();

        let session = &mut entry.session;

        // Push new prefix hash into ring
        if let Some(ref prefix_hash) = mutations.new_prefix_hash {
            let now_ms = chrono::Utc::now().timestamp_millis();
            session.prefix_hash_ring.push_back(SeenPrefixRecord {
                hash: prefix_hash.clone(),
                timestamp: now_ms,
                event_id: Uuid::new_v4(),
            });
            while session.prefix_hash_ring.len() > self.config.prefix_hash_ring_capacity {
                session.prefix_hash_ring.pop_front();
            }
        }

        // Push new code hashes into ring
        for blob in &mutations.new_code_hashes {
            session.code_hash_ring.push_back(blob.clone());
            while session.code_hash_ring.len() > self.config.code_hash_ring_capacity {
                session.code_hash_ring.pop_front();
            }
        }

        // Update stats
        session.stats.total_tokens = session
            .stats
            .total_tokens
            .saturating_add(u64::from(mutations.token_delta));
        session.stats.total_cost_usd += mutations.cost_delta;
        if mutations.credential_alert {
            session.stats.credential_alerts = session.stats.credential_alerts.saturating_add(1);
        }
    }

    /// Apply classify results (semantic hashes, model tracking, anomaly baseline).
    pub fn apply_classification(
        &self,
        key: &SessionKey,
        result: &ClassifiedResult,
        _normalized: &soth_core::NormalizedRequest,
    ) {
        let Some(mut entry) = self.sessions.get_mut(key) else {
            return;
        };
        entry.last_active = Instant::now();

        let current_ts = result.telemetry_event.timestamp_epoch_ms;
        const ONE_HOUR_MS: i64 = 3_600_000;
        const ONE_DAY_MS: i64 = 86_400_000;
        let credential_detected = result
            .telemetry_event
            .sensitive_code_flags
            .credential_pattern_detected;

        if credential_detected {
            entry.credential_timestamps_ms.push(current_ts);
        }
        entry
            .credential_timestamps_ms
            .retain(|ts| *ts >= current_ts - ONE_DAY_MS);
        entry
            .request_timestamps_ms
            .retain(|ts| *ts >= current_ts - ONE_HOUR_MS);

        let requests_per_hour = entry
            .request_timestamps_ms
            .len()
            .min(u32::MAX as usize) as f32;

        let s = &mut entry.session;
        s.stats.request_count = s.stats.request_count.saturating_add(1);

        let input_tokens = result.telemetry_event.estimated_input_tokens.unwrap_or(0);
        s.stats.total_tokens = s.stats.total_tokens.saturating_add(u64::from(input_tokens));
        s.stats.total_cost_usd += result.telemetry_event.estimated_cost_usd.unwrap_or(0.0);
        if credential_detected {
            s.stats.credential_alerts = s.stats.credential_alerts.saturating_add(1);
        }

        // Update anomaly baseline (running average)
        let count = s.stats.request_count.max(1) as f32;
        s.anomaly_baseline.avg_tokens_per_request = s.stats.total_tokens as f32 / count;
        s.anomaly_baseline.avg_requests_per_hour = requests_per_hour;
        s.last_activity = current_ts;
    }

    /// Apply response usage (output tokens + cost) via connection_id.
    pub fn apply_response_usage(&self, connection_id: Uuid, usage: &UsageSummary) {
        let Some(binding) = self.connection_map.get(&connection_id) else {
            return;
        };
        let key = binding.session_key.clone();
        drop(binding);

        if let Some(mut entry) = self.sessions.get_mut(&key) {
            entry.last_active = Instant::now();
            entry.session.stats.total_tokens = entry
                .session
                .stats
                .total_tokens
                .saturating_add(usage.output_tokens);
            entry.session.stats.total_cost_usd += usage.estimated_output_cost_usd as f32;
        }
    }

    /// Evict sessions inactive for longer than 2x window_secs.
    pub fn evict_stale(&self) {
        let max_inactive = std::time::Duration::from_secs(self.config.window_secs * 2);
        self.sessions
            .retain(|_, entry| entry.last_active.elapsed() <= max_inactive);

        // Also clean up stale connection bindings
        let max_binding_age = std::time::Duration::from_secs(self.config.window_secs * 3);
        self.connection_map
            .retain(|_, binding| binding.bound_at.elapsed() <= max_binding_age);
    }

    /// Apply classification via connection_id (backward-compat wrapper for classify_task).
    pub fn apply_classification_by_connection(
        &self,
        connection_id: Uuid,
        result: &ClassifiedResult,
        normalized: &soth_core::NormalizedRequest,
    ) {
        let Some(binding) = self.connection_map.get(&connection_id) else {
            return;
        };
        let key = binding.session_key.clone();
        drop(binding);
        self.apply_classification(&key, result, normalized);
    }

    fn entry_to_snapshot(&self, entry: &SessionEntry) -> SessionSnapshot {
        let session = &entry.session;
        let request_count_this_hour = entry
            .request_timestamps_ms
            .len()
            .min(u32::MAX as usize) as u32;
        let credential_alerts_24h = entry
            .credential_timestamps_ms
            .len()
            .min(usize::from(u8::MAX)) as u8;

        SessionSnapshot {
            session_token_total: session.stats.total_tokens.min(u64::from(u32::MAX)) as u32,
            session_token_p14d_avg: session.anomaly_baseline.avg_tokens_per_request,
            request_count_this_hour,
            credential_alerts_24h,
            topic_cluster_ids_seen: Vec::new(),
            models_used_this_session: Vec::new(),
            last_system_prompt_hash: None,
            max_tool_depth_seen: 0,
            request_count: session.stats.request_count,
            total_tokens: session.stats.total_tokens,
            total_cost_usd: session.stats.total_cost_usd,
            credential_alerts: session.stats.credential_alerts,
            embedding_centroid: None,
            prior_semantic_hashes: Vec::new(),
            last_model: None,
            current_request_timestamp: session.last_activity,
            last_request_timestamp: Some(session.last_activity),
            // Dedup fields: copy from ring buffers
            seen_prefix_hashes: session
                .prefix_hash_ring
                .iter()
                .map(|record| record.hash.clone())
                .collect(),
            seen_code_hashes: session
                .code_hash_ring
                .iter()
                .map(|blob| blob.ast_normalized_hash.clone())
                .collect(),
            session_key_hash: entry.key_hash.clone(),
        }
    }

    fn evict_oldest(&self) {
        let mut oldest_key = None;
        let mut oldest_time = Instant::now();
        for entry in self.sessions.iter() {
            if entry.value().last_active < oldest_time {
                oldest_time = entry.value().last_active;
                oldest_key = Some(entry.key().clone());
            }
        }
        if let Some(key) = oldest_key {
            self.sessions.remove(&key);
        }
    }
}

fn session_key_hash(key: &SessionKey) -> String {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = serde_json::to_vec(key) {
        hasher.update(&bytes);
    }
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::CodeBlob;

    fn test_config() -> SessionConfig {
        SessionConfig {
            window_secs: 3600,
            max_sessions: 10,
            reaper_interval_secs: 3600,
            code_hash_ring_capacity: 4,
            prefix_hash_ring_capacity: 3,
        }
    }

    fn native_key(identity: &str) -> SessionKey {
        SessionKey {
            app_identity: SessionAppIdentity::NativeApp {
                identity: identity.to_string(),
            },
            window_start: 0,
        }
    }

    #[test]
    fn get_or_create_inserts_new_session() {
        let mgr = SessionManager::new(test_config());
        let key = native_key("cursor");
        let hash = mgr.get_or_create(&key);
        assert!(!hash.is_empty());

        let snapshot = mgr.snapshot(&key);
        assert_eq!(snapshot.request_count, 0);
        assert_eq!(snapshot.session_key_hash, hash);
    }

    #[test]
    fn apply_detect_mutations_pushes_hashes_into_rings() {
        let mgr = SessionManager::new(test_config());
        let key = native_key("cursor");
        mgr.get_or_create(&key);

        let mutations = SessionMutations {
            new_prefix_hash: Some("pfx-1".to_string()),
            new_code_hashes: vec![CodeBlob {
                ast_normalized_hash: "code-1".to_string(),
                language: "rust".to_string(),
                first_event_id: Uuid::nil(),
            }],
            token_delta: 100,
            cost_delta: 0.01,
            credential_alert: false,
            anomaly_update: None,
        };
        mgr.apply_detect_mutations(&key, &mutations);

        let snapshot = mgr.snapshot(&key);
        assert_eq!(snapshot.seen_prefix_hashes, vec!["pfx-1"]);
        assert_eq!(snapshot.seen_code_hashes, vec!["code-1"]);
    }

    #[test]
    fn ring_capacity_is_enforced() {
        let mgr = SessionManager::new(test_config()); // prefix capacity = 3
        let key = native_key("cursor");
        mgr.get_or_create(&key);

        for i in 0..5 {
            mgr.apply_detect_mutations(
                &key,
                &SessionMutations {
                    new_prefix_hash: Some(format!("pfx-{i}")),
                    ..SessionMutations::default()
                },
            );
        }

        let snapshot = mgr.snapshot(&key);
        assert_eq!(snapshot.seen_prefix_hashes.len(), 3);
        assert_eq!(snapshot.seen_prefix_hashes[0], "pfx-2");
    }

    #[test]
    fn max_sessions_evicts_oldest() {
        let mgr = SessionManager::new(test_config()); // max 10
        for i in 0..12 {
            let key = native_key(&format!("app-{i}"));
            mgr.get_or_create(&key);
        }
        assert!(mgr.sessions.len() <= 10);
    }

    #[test]
    fn bind_and_lookup_by_connection() {
        let mgr = SessionManager::new(test_config());
        let key = native_key("cursor");
        mgr.get_or_create(&key);

        let conn_id = Uuid::new_v4();
        mgr.bind_connection(conn_id, key.clone());

        let snapshot = mgr.snapshot_by_connection(conn_id);
        assert_eq!(snapshot.session_key_hash, session_key_hash(&key));
    }

    #[test]
    fn evict_stale_removes_inactive_sessions() {
        let config = SessionConfig {
            window_secs: 0, // 2x window = 0, so everything is stale
            ..test_config()
        };
        let mgr = SessionManager::new(config);
        let key = native_key("cursor");
        mgr.get_or_create(&key);

        // Force last_active to be in the past
        if let Some(mut entry) = mgr.sessions.get_mut(&key) {
            entry.last_active = Instant::now() - std::time::Duration::from_secs(10);
        }

        mgr.evict_stale();
        assert_eq!(mgr.sessions.len(), 0);
    }

    #[test]
    fn derive_key_native_app() {
        let mgr = SessionManager::new(test_config());
        let process_resolution = soth_core::ProcessResolution {
            match_kind: soth_core::ProcessMatchKind::Exact,
            app_type: AppType::NonHost,
            capture_mode: None,
            process_name: Some("cursor".to_string()),
            bundle_id: Some("com.cursor".to_string()),
            matched_app_id: None,
            ..Default::default()
        };
        let key = mgr.derive_key(&process_resolution, Some("cursor-app"));
        match &key.app_identity {
            SessionAppIdentity::NativeApp { identity } => {
                assert_eq!(identity, "cursor-app");
            }
            _ => panic!("expected NativeApp"),
        }
    }

    #[test]
    fn derive_key_browser_session() {
        let mgr = SessionManager::new(test_config());
        let process_resolution = soth_core::ProcessResolution {
            match_kind: soth_core::ProcessMatchKind::Exact,
            app_type: AppType::Host,
            capture_mode: None,
            process_name: None,
            bundle_id: Some("com.google.chrome".to_string()),
            matched_app_id: None,
            ..Default::default()
        };
        let key = mgr.derive_key(&process_resolution, Some("chatgpt.com"));
        match &key.app_identity {
            SessionAppIdentity::BrowserSession {
                browser,
                ai_origin,
            } => {
                assert_eq!(browser, "com.google.chrome");
                assert_eq!(ai_origin, "chatgpt.com");
            }
            _ => panic!("expected BrowserSession"),
        }
    }
}
