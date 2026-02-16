//! Event store - watches event logs and stores recent events for dashboard.
//!
//! Uses SQLite wrap-event storage.
//! Provides real-time event streaming via broadcast channel.

use crate::state::ObserveMetrics;
use parking_lot::RwLock;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use soth_core::event_logger::default_event_log_write_path;
use soth_core::types::exchange_v2::{ExchangeEventV2, ExchangeSourceClass};
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_storage::open_sqlite_read_write_with_timeout;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Maximum number of events to keep in memory.
const MAX_EVENTS: usize = 1000;

/// Maximum number of agents to track.
const MAX_AGENTS: usize = 100;

/// Wait window for SQLite lock contention before failing a dashboard query/update.
const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Projection retries for transient lock contention.
const SQLITE_PROJECTION_MAX_RETRIES: usize = 8;
const SQLITE_PROJECTION_RETRY_BASE_MS: u64 = 100;
const SQLITE_PROJECTION_RETRY_MAX_MS: u64 = 2_000;
const SQLITE_PROJECTION_VERSION: i64 = 4;

/// Event store that watches wrap events and provides real-time streaming.
#[derive(Clone)]
pub struct EventStore {
    inner: Arc<RwLock<EventStoreInner>>,
    db_path: PathBuf,
    event_tx: broadcast::Sender<WrapEvent>,
    stream_stats: Arc<StreamStatsInner>,
}

struct EventStoreInner {
    /// Recent events (newest first).
    events: VecDeque<WrapEvent>,
    /// Agent statistics.
    agents: HashMap<String, AgentStats>,
    /// Last seen SQLite sequence number.
    sqlite_seq: i64,
}

#[derive(Default)]
struct StreamStatsInner {
    lagged_receivers: AtomicU64,
    lagged_events: AtomicU64,
    backfill_batches: AtomicU64,
    backfilled_events: AtomicU64,
    broadcast_send_failures: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamStats {
    pub lagged_receivers: u64,
    pub lagged_events: u64,
    pub backfill_batches: u64,
    pub backfilled_events: u64,
    pub broadcast_send_failures: u64,
    pub latest_seq: i64,
}

/// Statistics for a detected agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStats {
    /// Agent name
    pub name: String,
    /// Agent version (if known)
    pub version: Option<String>,
    /// Detection source
    pub detected_from: String,
    /// Number of events from this agent
    pub event_count: u64,
    /// Last seen timestamp
    pub last_seen: String,
    /// Servers this agent has used
    pub servers: Vec<String>,
}

/// Summary of all agents
#[derive(Debug, Clone, Serialize)]
pub struct AgentsSummary {
    pub total_agents: usize,
    pub agents: Vec<AgentStats>,
}

/// Summary of recent events
#[derive(Debug, Clone, Serialize)]
pub struct EventsSummary {
    pub total_events: usize,
    pub events: Vec<WrapEvent>,
}

/// Materialized request/response cluster row.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterRow {
    pub cluster_id: String,
    pub request_event_id: String,
    pub response_event_id: Option<String>,
    pub request_seq: i64,
    pub response_seq: Option<i64>,
    pub timestamp: String,
    pub source: String,
    pub provider: Option<String>,
    pub agent: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub policy_allowed: Option<bool>,
    pub pii_detected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClustersSummary {
    pub total_clusters: usize,
    pub clusters: Vec<ClusterRow>,
}

/// Materialized minute rollup row.
#[derive(Debug, Clone, Serialize)]
pub struct RollupRow {
    pub bucket_start: String,
    pub source: String,
    pub provider: Option<String>,
    pub agent: Option<String>,
    pub total_events: u64,
    pub requests: u64,
    pub responses: u64,
    pub error_events: u64,
    pub pii_events: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollupsSummary {
    pub total_rows: usize,
    pub rows: Vec<RollupRow>,
}

/// Aggregated cryptographic pipeline status for dashboard/API.
#[derive(Debug, Clone, Serialize)]
pub struct CryptoStatusSummary {
    pub total_events: u64,
    pub signed_events: u64,
    pub signature_coverage_pct: f64,
    pub verification_failures: u64,
    pub active_key_id: Option<String>,
    pub merkle_batches: u64,
    pub latest_batch_id: Option<String>,
    pub latest_root_hash: Option<String>,
    pub latest_signer_did: Option<String>,
    pub latest_sealed_at: Option<String>,
}

impl Default for CryptoStatusSummary {
    fn default() -> Self {
        Self {
            total_events: 0,
            signed_events: 0,
            signature_coverage_pct: 0.0,
            verification_failures: 0,
            active_key_id: None,
            merkle_batches: 0,
            latest_batch_id: None,
            latest_root_hash: None,
            latest_signer_did: None,
            latest_sealed_at: None,
        }
    }
}

/// One recent Merkle seal with lightweight verification indicators.
#[derive(Debug, Clone, Serialize)]
pub struct CryptoMerkleSealRow {
    pub batch_id: String,
    pub seq_start: i64,
    pub seq_end: i64,
    pub expected_events: u64,
    pub observed_events: u64,
    pub root_hash: String,
    pub signer_did: String,
    pub prev_root: Option<String>,
    pub sealed_at: String,
    pub chain_link_valid: bool,
    pub verification_status: String,
}

/// Recent Merkle seal list response.
#[derive(Debug, Clone, Serialize)]
pub struct CryptoMerkleSummary {
    pub total_batches: usize,
    pub seals: Vec<CryptoMerkleSealRow>,
}

impl EventStore {
    /// Create a new event store.
    ///
    pub fn new(log_path: PathBuf) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            inner: Arc::new(RwLock::new(EventStoreInner {
                events: VecDeque::with_capacity(MAX_EVENTS),
                agents: HashMap::new(),
                sqlite_seq: 0,
            })),
            db_path: log_path,
            event_tx,
            stream_stats: Arc::new(StreamStatsInner::default()),
        }
    }

    /// Create with default log path (`~/.soth/logs/events.db`).
    pub fn with_default_path() -> Option<Self> {
        let log_path = default_event_log_write_path().ok()?;
        Some(Self::new(log_path))
    }

    /// Path currently used by this store.
    pub fn path(&self) -> &Path {
        self.db_path.as_path()
    }

    /// Subscribe to new events.
    pub fn subscribe(&self) -> broadcast::Receiver<WrapEvent> {
        self.event_tx.subscribe()
    }

    /// Current highest committed sqlite sequence observed by the store.
    pub fn latest_seq(&self) -> i64 {
        self.inner.read().sqlite_seq
    }

    /// Stream backpressure and replay telemetry counters.
    pub fn stream_stats(&self) -> StreamStats {
        StreamStats {
            lagged_receivers: self.stream_stats.lagged_receivers.load(Ordering::Relaxed),
            lagged_events: self.stream_stats.lagged_events.load(Ordering::Relaxed),
            backfill_batches: self.stream_stats.backfill_batches.load(Ordering::Relaxed),
            backfilled_events: self.stream_stats.backfilled_events.load(Ordering::Relaxed),
            broadcast_send_failures: self
                .stream_stats
                .broadcast_send_failures
                .load(Ordering::Relaxed),
            latest_seq: self.latest_seq(),
        }
    }

    pub fn record_stream_lagged(&self, lagged_events: u64) {
        self.stream_stats
            .lagged_receivers
            .fetch_add(1, Ordering::Relaxed);
        self.stream_stats
            .lagged_events
            .fetch_add(lagged_events, Ordering::Relaxed);
    }

    pub fn record_stream_backfill_batch(&self, events: u64) {
        self.stream_stats
            .backfill_batches
            .fetch_add(1, Ordering::Relaxed);
        self.stream_stats
            .backfilled_events
            .fetch_add(events, Ordering::Relaxed);
    }

    /// Get recent events.
    pub fn get_events(&self, limit: usize) -> EventsSummary {
        let inner = self.inner.read();
        let events: Vec<WrapEvent> = inner
            .events
            .iter()
            .take(limit.min(MAX_EVENTS))
            .cloned()
            .collect();

        EventsSummary {
            total_events: inner.events.len(),
            events,
        }
    }

    /// Derive observe metrics from in-memory event stream state.
    ///
    /// This keeps Overview/Observe panels aligned with what is currently visible
    /// in observability without depending on legacy dashboard state counters.
    pub fn observe_metrics(&self) -> ObserveMetrics {
        let inner = self.inner.read();
        let mut metrics = ObserveMetrics::default();

        for event in inner.events.iter() {
            match event.direction {
                WrapDirection::In => metrics.requests += 1,
                WrapDirection::Out => metrics.responses += 1,
            }

            if event.pii_detected {
                metrics.pii_detections += 1;
                for pii_type in &event.pii_types {
                    *metrics.pii_by_type.entry(pii_type.clone()).or_insert(0) += 1;
                }
            }
        }

        metrics
    }

    /// Get events strictly newer than a sqlite sequence cursor.
    ///
    /// Queries durable storage (ordered ASC by sequence).
    pub fn get_events_since_seq(&self, since_seq: i64, limit: usize) -> EventsSummary {
        if limit == 0 {
            return EventsSummary {
                total_events: self.inner.read().events.len(),
                events: Vec::new(),
            };
        }

        let capped_limit = limit.min(5_000);
        let rows = read_sqlite_events(&self.db_path, Some(since_seq), None).unwrap_or_default();
        let total_events = self.inner.read().events.len();

        let mut events: Vec<WrapEvent> = rows.into_iter().map(|(_, event)| event).collect();
        if events.len() > capped_limit {
            let keep_from = events.len() - capped_limit;
            events = events.split_off(keep_from);
        }

        EventsSummary {
            total_events,
            events,
        }
    }

    /// Get materialized clusters (newest first).
    pub fn get_clusters(&self, limit: usize) -> ClustersSummary {
        let capped_limit = limit.clamp(1, 5_000);
        let rows = read_sqlite_clusters(&self.db_path, None, capped_limit).unwrap_or_default();
        ClustersSummary {
            total_clusters: read_sqlite_cluster_total(&self.db_path).unwrap_or(rows.len()),
            clusters: rows,
        }
    }

    /// Get clusters with request sequence strictly newer than cursor.
    pub fn get_clusters_since_seq(&self, since_seq: i64, limit: usize) -> ClustersSummary {
        let capped_limit = limit.clamp(1, 5_000);
        let rows =
            read_sqlite_clusters(&self.db_path, Some(since_seq), capped_limit).unwrap_or_default();
        ClustersSummary {
            total_clusters: read_sqlite_cluster_total(&self.db_path).unwrap_or(rows.len()),
            clusters: rows,
        }
    }

    /// Get minute rollups (newest buckets first).
    pub fn get_rollups_1m(&self, limit: usize) -> RollupsSummary {
        let capped_limit = limit.clamp(1, 10_000);
        let rows = read_sqlite_rollups_1m(&self.db_path, capped_limit).unwrap_or_default();
        RollupsSummary {
            total_rows: read_sqlite_rollup_total(&self.db_path).unwrap_or(rows.len()),
            rows,
        }
    }

    /// Get cryptographic pipeline status.
    pub fn get_crypto_status(&self) -> CryptoStatusSummary {
        read_sqlite_crypto_status(&self.db_path).unwrap_or_default()
    }

    /// Get recent Merkle seals with lightweight verification.
    pub fn get_crypto_merkle_recent(&self, limit: usize) -> CryptoMerkleSummary {
        let capped_limit = limit.clamp(1, 200);
        let seals =
            read_sqlite_crypto_merkle_recent(&self.db_path, capped_limit).unwrap_or_default();
        CryptoMerkleSummary {
            total_batches: read_sqlite_merkle_batch_total(&self.db_path).unwrap_or(seals.len()),
            seals,
        }
    }

    /// Get agent statistics.
    pub fn get_agents(&self) -> AgentsSummary {
        let inner = self.inner.read();
        let mut agents: Vec<AgentStats> = inner.agents.values().cloned().collect();

        // Sort by event count (most active first)
        agents.sort_by(|a, b| b.event_count.cmp(&a.event_count));

        AgentsSummary {
            total_agents: agents.len(),
            agents,
        }
    }

    /// Get a full payload body for a specific event and part.
    pub fn get_event_payload(&self, event_id: &str, part: &str) -> Option<String> {
        read_sqlite_event_payload(&self.db_path, event_id, part)
            .ok()
            .flatten()
    }

    /// Load initial events from storage.
    pub async fn load_initial(&self) -> std::io::Result<usize> {
        self.load_initial_sqlite(&self.db_path).await
    }

    async fn load_initial_sqlite(&self, db_path: &Path) -> std::io::Result<usize> {
        if !db_path.exists() {
            debug!("Event log database does not exist yet: {:?}", db_path);
            return Ok(0);
        }

        let db_path = db_path.to_path_buf();
        let query_path = db_path.clone();
        let rows = tokio::task::spawn_blocking(move || {
            read_sqlite_events(&query_path, None, Some(MAX_EVENTS))
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;

        let mut count = 0usize;
        let mut last_seq = 0i64;
        for (seq, event) in rows {
            self.add_event(event);
            count += 1;
            last_seq = seq;
        }

        {
            let mut inner = self.inner.write();
            inner.sqlite_seq = last_seq;
        }

        let projection_path = db_path.clone();
        if let Err(error) =
            tokio::task::spawn_blocking(move || project_sqlite_events(&projection_path))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?
        {
            warn!(
                "Failed to update event projections during bootstrap: {}",
                error
            );
        }

        info!("Loaded {} initial events from {:?}", count, db_path);
        Ok(count)
    }

    /// Watch for new events.
    pub async fn watch(&self) {
        self.watch_sqlite(self.db_path.clone()).await
    }

    async fn watch_sqlite(&self, db_path: PathBuf) {
        info!("Starting SQLite event poller for {:?}", db_path);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if let Err(e) = self.check_for_new_sqlite_events(&db_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Error checking sqlite event log: {}", e);
                }
            }
        }
    }

    async fn check_for_new_sqlite_events(&self, db_path: &Path) -> std::io::Result<()> {
        if !db_path.exists() {
            return Ok(());
        }

        let cursor = {
            let inner = self.inner.read();
            inner.sqlite_seq
        };

        let query_path = db_path.to_path_buf();
        let rows = tokio::task::spawn_blocking(move || {
            read_sqlite_events(&query_path, Some(cursor), None)
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;

        if rows.is_empty() {
            return Ok(());
        }

        let mut last_seq = cursor;
        for (seq, event) in rows {
            last_seq = seq;
            if self.event_tx.send(event.clone()).is_err() {
                self.stream_stats
                    .broadcast_send_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.add_event(event);
        }

        {
            let mut inner = self.inner.write();
            inner.sqlite_seq = last_seq;
        }

        let projection_path = db_path.to_path_buf();
        if let Err(error) =
            tokio::task::spawn_blocking(move || project_sqlite_events(&projection_path))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?
        {
            warn!("Failed to update event projections: {}", error);
        }

        Ok(())
    }

    fn add_event(&self, event: WrapEvent) {
        let mut inner = self.inner.write();

        // Update agent stats
        let agent_key = event.agent.name.clone();
        let stats = inner
            .agents
            .entry(agent_key.clone())
            .or_insert_with(|| AgentStats {
                name: event.agent.name.clone(),
                version: event.agent.version.clone(),
                detected_from: format!("{:?}", event.agent.detected_from),
                event_count: 0,
                last_seen: event.timestamp.to_rfc3339(),
                servers: Vec::new(),
            });

        stats.event_count += 1;
        stats.last_seen = event.timestamp.to_rfc3339();

        // Track servers
        if !stats.servers.contains(&event.server_name) {
            stats.servers.push(event.server_name.clone());
            // Limit servers list
            if stats.servers.len() > 10 {
                stats.servers.remove(0);
            }
        }

        // Limit agents
        if inner.agents.len() > MAX_AGENTS {
            // Remove least active agent
            if let Some(min_key) = inner
                .agents
                .iter()
                .min_by_key(|(_, s)| s.event_count)
                .map(|(k, _)| k.clone())
            {
                inner.agents.remove(&min_key);
            }
        }

        // Add event to front (newest first)
        inner.events.push_front(event);

        // Trim to max size
        while inner.events.len() > MAX_EVENTS {
            inner.events.pop_back();
        }
    }
}

fn read_sqlite_events(
    db_path: &Path,
    since_seq: Option<i64>,
    initial_limit: Option<usize>,
) -> std::io::Result<Vec<(i64, WrapEvent)>> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;

    if has_exchange_rows_conn(&conn)? {
        return read_sqlite_events_from_exchange(&conn, since_seq, initial_limit);
    }

    let mut events = Vec::new();
    if let Some(cursor) = since_seq {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM wrap_events
                WHERE seq > ?1
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([cursor], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            if let Ok(mut event) = serde_json::from_str::<WrapEvent>(&json) {
                event.seq = Some(seq);
                events.push((seq, event));
            }
        }
    } else if let Some(limit) = initial_limit {
        let bounded_limit = limit.max(1) as i64;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM (
                    SELECT seq, event_json
                    FROM wrap_events
                    ORDER BY seq DESC
                    LIMIT ?1
                )
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([bounded_limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            if let Ok(mut event) = serde_json::from_str::<WrapEvent>(&json) {
                event.seq = Some(seq);
                events.push((seq, event));
            }
        }
    } else {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM wrap_events
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            if let Ok(mut event) = serde_json::from_str::<WrapEvent>(&json) {
                event.seq = Some(seq);
                events.push((seq, event));
            }
        }
    }

    Ok(events)
}

fn read_sqlite_events_from_exchange(
    conn: &Connection,
    since_seq: Option<i64>,
    initial_limit: Option<usize>,
) -> std::io::Result<Vec<(i64, WrapEvent)>> {
    let mut events = Vec::new();

    if let Some(cursor) = since_seq {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM exchange_events
                WHERE seq > ?1
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;
        let rows = stmt
            .query_map([cursor], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;
        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            let Ok(exchange) = serde_json::from_str::<ExchangeEventV2>(&json) else {
                continue;
            };
            events.push((seq, exchange_to_wrap_event(seq, exchange)));
        }
        return Ok(events);
    }

    if let Some(limit) = initial_limit {
        let bounded_limit = limit.max(1) as i64;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT seq, event_json
                FROM (
                    SELECT seq, event_json
                    FROM exchange_events
                    ORDER BY seq DESC
                    LIMIT ?1
                )
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;
        let rows = stmt
            .query_map([bounded_limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;
        for row in rows {
            let (seq, json) = row.map_err(to_io_err)?;
            let Ok(exchange) = serde_json::from_str::<ExchangeEventV2>(&json) else {
                continue;
            };
            events.push((seq, exchange_to_wrap_event(seq, exchange)));
        }
        return Ok(events);
    }

    let mut stmt = conn
        .prepare(
            r#"
            SELECT seq, event_json
            FROM exchange_events
            ORDER BY seq ASC
            "#,
        )
        .map_err(to_io_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(to_io_err)?;
    for row in rows {
        let (seq, json) = row.map_err(to_io_err)?;
        let Ok(exchange) = serde_json::from_str::<ExchangeEventV2>(&json) else {
            continue;
        };
        events.push((seq, exchange_to_wrap_event(seq, exchange)));
    }
    Ok(events)
}

fn read_sqlite_cluster_total(db_path: &Path) -> std::io::Result<usize> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;
    let count = conn
        .query_row("SELECT COUNT(*) FROM event_clusters", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(to_io_err)?;
    Ok(count.max(0) as usize)
}

fn read_sqlite_rollup_total(db_path: &Path) -> std::io::Result<usize> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;
    let count = conn
        .query_row("SELECT COUNT(*) FROM rollups_1m", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(to_io_err)?;
    Ok(count.max(0) as usize)
}

fn read_sqlite_merkle_batch_total(db_path: &Path) -> std::io::Result<usize> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;
    let count = conn
        .query_row("SELECT COUNT(*) FROM merkle_batches", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(to_io_err)?;
    Ok(count.max(0) as usize)
}

fn read_sqlite_clusters(
    db_path: &Path,
    since_seq: Option<i64>,
    limit: usize,
) -> std::io::Result<Vec<ClusterRow>> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;
    let mut rows_out = Vec::new();

    if let Some(cursor) = since_seq {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT cluster_id, request_event_id, response_event_id, request_seq, response_seq,
                       timestamp, source, provider, agent, method, status_code, latency_ms,
                       policy_allowed, pii_detected
                FROM event_clusters
                WHERE request_seq > ?1
                ORDER BY request_seq DESC
                LIMIT ?2
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map(params![cursor, limit as i64], |row| {
                Ok(ClusterRow {
                    cluster_id: row.get(0)?,
                    request_event_id: row.get(1)?,
                    response_event_id: row.get(2)?,
                    request_seq: row.get(3)?,
                    response_seq: row.get(4)?,
                    timestamp: row.get(5)?,
                    source: row.get(6)?,
                    provider: row.get(7)?,
                    agent: row.get(8)?,
                    method: row.get(9)?,
                    status_code: row.get(10)?,
                    latency_ms: row.get(11)?,
                    policy_allowed: row.get(12)?,
                    pii_detected: row.get::<_, i64>(13)? != 0,
                })
            })
            .map_err(to_io_err)?;

        for row in rows {
            rows_out.push(row.map_err(to_io_err)?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT cluster_id, request_event_id, response_event_id, request_seq, response_seq,
                       timestamp, source, provider, agent, method, status_code, latency_ms,
                       policy_allowed, pii_detected
                FROM event_clusters
                ORDER BY request_seq DESC
                LIMIT ?1
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([limit as i64], |row| {
                Ok(ClusterRow {
                    cluster_id: row.get(0)?,
                    request_event_id: row.get(1)?,
                    response_event_id: row.get(2)?,
                    request_seq: row.get(3)?,
                    response_seq: row.get(4)?,
                    timestamp: row.get(5)?,
                    source: row.get(6)?,
                    provider: row.get(7)?,
                    agent: row.get(8)?,
                    method: row.get(9)?,
                    status_code: row.get(10)?,
                    latency_ms: row.get(11)?,
                    policy_allowed: row.get(12)?,
                    pii_detected: row.get::<_, i64>(13)? != 0,
                })
            })
            .map_err(to_io_err)?;

        for row in rows {
            rows_out.push(row.map_err(to_io_err)?);
        }
    }

    Ok(rows_out)
}

fn read_sqlite_rollups_1m(db_path: &Path, limit: usize) -> std::io::Result<Vec<RollupRow>> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT bucket_start, source, provider, agent, total_events, requests, responses,
                   error_events, pii_events, total_tokens, total_cost_usd
            FROM rollups_1m
            ORDER BY bucket_start DESC
            LIMIT ?1
            "#,
        )
        .map_err(to_io_err)?;

    let rows = stmt
        .query_map([limit as i64], |row| {
            Ok(RollupRow {
                bucket_start: row.get(0)?,
                source: row.get(1)?,
                provider: row.get(2)?,
                agent: row.get(3)?,
                total_events: row.get::<_, i64>(4)?.max(0) as u64,
                requests: row.get::<_, i64>(5)?.max(0) as u64,
                responses: row.get::<_, i64>(6)?.max(0) as u64,
                error_events: row.get::<_, i64>(7)?.max(0) as u64,
                pii_events: row.get::<_, i64>(8)?.max(0) as u64,
                total_tokens: row.get::<_, i64>(9)?.max(0) as u64,
                total_cost_usd: row.get::<_, f64>(10)?,
            })
        })
        .map_err(to_io_err)?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(to_io_err)?);
    }
    Ok(result)
}

fn read_sqlite_crypto_status(db_path: &Path) -> std::io::Result<CryptoStatusSummary> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;

    if has_exchange_rows_conn(&conn)? {
        let total_events: i64 = conn
            .query_row("SELECT COUNT(*) FROM exchange_events", [], |row| row.get(0))
            .map_err(to_io_err)?;
        let signed_events: i64 = conn
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM exchange_events
                WHERE json_extract(event_json, '$.integrity.signature') IS NOT NULL
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(to_io_err)?;
        let latest_batch: Option<(String, String, String, String)> = conn
            .query_row(
                r#"
                SELECT batch_id, root_hash, signer_did, sealed_at
                FROM merkle_batches
                ORDER BY seq_end DESC
                LIMIT 1
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(to_io_err)?;
        let merkle_batches: i64 = conn
            .query_row("SELECT COUNT(*) FROM merkle_batches", [], |row| row.get(0))
            .map_err(to_io_err)?;
        let active_key_id: Option<String> = conn
            .query_row(
                r#"
                SELECT key_id
                FROM key_versions
                WHERE status = 'active'
                ORDER BY datetime(created_at) DESC
                LIMIT 1
                "#,
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_io_err)?;

        let total_events_u = total_events.max(0) as u64;
        let signed_events_u = signed_events.max(0) as u64;
        let signature_coverage_pct = if total_events_u == 0 {
            0.0
        } else {
            (signed_events_u as f64 / total_events_u as f64) * 100.0
        };

        return Ok(CryptoStatusSummary {
            total_events: total_events_u,
            signed_events: signed_events_u,
            signature_coverage_pct,
            verification_failures: 0,
            active_key_id,
            merkle_batches: merkle_batches.max(0) as u64,
            latest_batch_id: latest_batch.as_ref().map(|v| v.0.clone()),
            latest_root_hash: latest_batch.as_ref().map(|v| v.1.clone()),
            latest_signer_did: latest_batch.as_ref().map(|v| v.2.clone()),
            latest_sealed_at: latest_batch.as_ref().map(|v| v.3.clone()),
        });
    }

    let total_events: i64 = conn
        .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
        .map_err(to_io_err)?;
    let signed_events: i64 = conn
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM wrap_events
            WHERE json_extract(event_json, '$.traffic_envelope.signature') IS NOT NULL
               OR json_extract(event_json, '$.merkle_signature') IS NOT NULL
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(to_io_err)?;
    let verification_failures: i64 = conn
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM wrap_events
            WHERE json_extract(event_json, '$.policy_allowed') = 0
              AND (
                    lower(COALESCE(json_extract(event_json, '$.policy_reason'), '')) LIKE '%signature%'
                 OR lower(COALESCE(json_extract(event_json, '$.policy_reason'), '')) LIKE '%identity%'
              )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(to_io_err)?;

    let latest_batch: Option<(String, String, String, String)> = conn
        .query_row(
            r#"
            SELECT batch_id, root_hash, signer_did, sealed_at
            FROM merkle_batches
            ORDER BY seq_end DESC
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(to_io_err)?;
    let merkle_batches: i64 = conn
        .query_row("SELECT COUNT(*) FROM merkle_batches", [], |row| row.get(0))
        .map_err(to_io_err)?;
    let active_key_id: Option<String> = conn
        .query_row(
            r#"
            SELECT key_id
            FROM key_versions
            WHERE status = 'active'
            ORDER BY datetime(created_at) DESC
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(to_io_err)?;

    let total_events_u = total_events.max(0) as u64;
    let signed_events_u = signed_events.max(0) as u64;
    let signature_coverage_pct = if total_events_u == 0 {
        0.0
    } else {
        (signed_events_u as f64 / total_events_u as f64) * 100.0
    };

    Ok(CryptoStatusSummary {
        total_events: total_events_u,
        signed_events: signed_events_u,
        signature_coverage_pct,
        verification_failures: verification_failures.max(0) as u64,
        active_key_id,
        merkle_batches: merkle_batches.max(0) as u64,
        latest_batch_id: latest_batch.as_ref().map(|v| v.0.clone()),
        latest_root_hash: latest_batch.as_ref().map(|v| v.1.clone()),
        latest_signer_did: latest_batch.as_ref().map(|v| v.2.clone()),
        latest_sealed_at: latest_batch.as_ref().map(|v| v.3.clone()),
    })
}

fn read_sqlite_crypto_merkle_recent(
    db_path: &Path,
    limit: usize,
) -> std::io::Result<Vec<CryptoMerkleSealRow>> {
    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;

    let fetch_limit = (limit + 1) as i64;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT batch_id, seq_start, seq_end, root_hash, signature, signer_did, prev_root, sealed_at
            FROM merkle_batches
            ORDER BY seq_end DESC
            LIMIT ?1
            "#,
        )
        .map_err(to_io_err)?;

    #[derive(Clone)]
    struct BatchRow {
        batch_id: String,
        seq_start: i64,
        seq_end: i64,
        root_hash: String,
        _signature: String,
        signer_did: String,
        prev_root: Option<String>,
        sealed_at: String,
    }

    let rows = stmt
        .query_map([fetch_limit], |row| {
            Ok(BatchRow {
                batch_id: row.get(0)?,
                seq_start: row.get(1)?,
                seq_end: row.get(2)?,
                root_hash: row.get(3)?,
                _signature: row.get(4)?,
                signer_did: row.get(5)?,
                prev_root: row.get(6)?,
                sealed_at: row.get(7)?,
            })
        })
        .map_err(to_io_err)?;

    let mut batches = Vec::new();
    for row in rows {
        batches.push(row.map_err(to_io_err)?);
    }

    if batches.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    for (idx, batch) in batches.iter().take(limit).enumerate() {
        let expected_events = (batch.seq_end - batch.seq_start + 1).max(0) as u64;
        let observed_events: i64 = conn
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM wrap_events
                WHERE json_extract(event_json, '$.merkle_batch_id') = ?1
                "#,
                [batch.batch_id.as_str()],
                |row| row.get(0),
            )
            .map_err(to_io_err)?;
        let observed_events = observed_events.max(0) as u64;

        let chain_link_valid = if let Some(next_batch) = batches.get(idx + 1) {
            batch.prev_root.as_deref() == Some(next_batch.root_hash.as_str())
        } else {
            batch.prev_root.is_none()
        };

        let verification_status = if !chain_link_valid {
            "chain_mismatch".to_string()
        } else if observed_events != expected_events {
            "event_count_mismatch".to_string()
        } else {
            "ok".to_string()
        };

        result.push(CryptoMerkleSealRow {
            batch_id: batch.batch_id.clone(),
            seq_start: batch.seq_start,
            seq_end: batch.seq_end,
            expected_events,
            observed_events,
            root_hash: batch.root_hash.clone(),
            signer_did: batch.signer_did.clone(),
            prev_root: batch.prev_root.clone(),
            sealed_at: batch.sealed_at.clone(),
            chain_link_valid,
            verification_status,
        });
    }

    Ok(result)
}

fn project_sqlite_events(db_path: &Path) -> std::io::Result<i64> {
    for retry in 0..=SQLITE_PROJECTION_MAX_RETRIES {
        match project_sqlite_events_once(db_path) {
            Ok(projected_seq) => return Ok(projected_seq),
            Err(error) if retry < SQLITE_PROJECTION_MAX_RETRIES && is_sqlite_lock_error(&error) => {
                let exponent = (retry as u32).min(10);
                let multiplier = 1_u64 << exponent;
                let backoff_ms = SQLITE_PROJECTION_RETRY_BASE_MS
                    .saturating_mul(multiplier)
                    .min(SQLITE_PROJECTION_RETRY_MAX_MS);
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
            Err(error) => return Err(error),
        }
    }

    Err(std::io::Error::other(
        "SQLite projection retry loop exited unexpectedly",
    ))
}

fn project_sqlite_events_once(db_path: &Path) -> std::io::Result<i64> {
    let mut conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;
    let tx = conn.transaction().map_err(to_io_err)?;
    ensure_projection_version(&tx)?;

    if has_exchange_events(&tx)? {
        let projected_exchange_seq = project_sqlite_exchange_rows(&tx)?;
        tx.commit().map_err(to_io_err)?;
        return Ok(projected_exchange_seq);
    }

    let mut projected_seq: i64 = tx
        .query_row(
            "SELECT value FROM projection_meta WHERE key = 'last_projected_seq'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_err)?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);

    let mut queued_rows: Vec<(i64, String)> = Vec::new();
    {
        let mut stmt = tx
            .prepare(
                r#"
                SELECT seq, event_json
                FROM wrap_events
                WHERE seq > ?1
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([projected_seq], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            queued_rows.push(row.map_err(to_io_err)?);
        }
    }

    for (seq, event_json) in queued_rows {
        let Ok(event) = serde_json::from_str::<WrapEvent>(&event_json) else {
            continue;
        };

        update_rollup_1m(&tx, &event)?;
        project_pair_cluster_for_event(&tx, seq, &event)?;
        projected_seq = seq.max(projected_seq);
    }

    tx.execute(
        r#"
        INSERT INTO projection_meta (key, value, updated_at)
        VALUES ('last_projected_seq', ?1, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = CURRENT_TIMESTAMP
        "#,
        [projected_seq.to_string()],
    )
    .map_err(to_io_err)?;

    tx.commit().map_err(to_io_err)?;
    Ok(projected_seq)
}

fn has_exchange_events(tx: &rusqlite::Transaction<'_>) -> std::io::Result<bool> {
    let table_exists = tx
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'exchange_events' LIMIT 1",
            [],
            |_row| Ok(true),
        )
        .optional()
        .map_err(to_io_err)?
        .unwrap_or(false);
    if !table_exists {
        return Ok(false);
    }

    let count: i64 = tx
        .query_row("SELECT COUNT(*) FROM exchange_events", [], |row| row.get(0))
        .map_err(to_io_err)?;
    Ok(count > 0)
}

fn project_sqlite_exchange_rows(tx: &rusqlite::Transaction<'_>) -> std::io::Result<i64> {
    let mut projected_seq: i64 = tx
        .query_row(
            "SELECT value FROM projection_meta WHERE key = 'last_projected_exchange_seq'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_err)?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);

    let mut queued_rows: Vec<(i64, String)> = Vec::new();
    {
        let mut stmt = tx
            .prepare(
                r#"
                SELECT seq, event_json
                FROM exchange_events
                WHERE seq > ?1
                ORDER BY seq ASC
                "#,
            )
            .map_err(to_io_err)?;

        let rows = stmt
            .query_map([projected_seq], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_io_err)?;

        for row in rows {
            queued_rows.push(row.map_err(to_io_err)?);
        }
    }

    for (seq, event_json) in queued_rows {
        let Ok(event) = serde_json::from_str::<ExchangeEventV2>(&event_json) else {
            continue;
        };
        update_rollup_1m_from_exchange(tx, &event)?;
        upsert_cluster_from_exchange(tx, seq, &event)?;
        projected_seq = seq.max(projected_seq);
    }

    tx.execute(
        r#"
        INSERT INTO projection_meta (key, value, updated_at)
        VALUES ('last_projected_exchange_seq', ?1, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = CURRENT_TIMESTAMP
        "#,
        [projected_seq.to_string()],
    )
    .map_err(to_io_err)?;

    Ok(projected_seq)
}

fn ensure_projection_version(tx: &rusqlite::Transaction<'_>) -> std::io::Result<()> {
    let current_version = tx
        .query_row(
            "SELECT value FROM projection_meta WHERE key = 'projection_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_err)?
        .and_then(|value| value.parse::<i64>().ok());

    if current_version == Some(SQLITE_PROJECTION_VERSION) {
        return Ok(());
    }

    tx.execute_batch(
        r#"
        DELETE FROM event_pairs;
        DELETE FROM event_clusters;
        DELETE FROM event_pending_requests;
        DELETE FROM rollups_1m;
        "#,
    )
    .map_err(to_io_err)?;

    tx.execute(
        r#"
        INSERT INTO projection_meta (key, value, updated_at)
        VALUES ('last_projected_seq', '0', CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = CURRENT_TIMESTAMP
        "#,
        [],
    )
    .map_err(to_io_err)?;

    tx.execute(
        r#"
        INSERT INTO projection_meta (key, value, updated_at)
        VALUES ('last_projected_exchange_seq', '0', CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = CURRENT_TIMESTAMP
        "#,
        [],
    )
    .map_err(to_io_err)?;

    tx.execute(
        r#"
        INSERT INTO projection_meta (key, value, updated_at)
        VALUES ('projection_version', ?1, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = CURRENT_TIMESTAMP
        "#,
        [SQLITE_PROJECTION_VERSION.to_string()],
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn event_source_label(source: EventSource) -> &'static str {
    match source {
        EventSource::Mcp => "mcp",
        EventSource::AiProxy => "ai_proxy",
        EventSource::AgentApp => "agent_app",
    }
}

fn has_paired_payload(event: &WrapEvent) -> bool {
    event.request_content.is_some()
        || event.request_content_ref.is_some()
        || event.request_preview.is_some()
        || event.response_content.is_some()
        || event.response_content_ref.is_some()
        || event.response_preview.is_some()
}

fn has_request_payload(event: &WrapEvent) -> bool {
    event.request_content.is_some()
        || event.request_content_ref.is_some()
        || event.request_preview.is_some()
}

fn has_response_payload(event: &WrapEvent) -> bool {
    event.response_content.is_some()
        || event.response_content_ref.is_some()
        || event.response_preview.is_some()
}

fn is_paired_proxy_response_event(event: &WrapEvent) -> bool {
    matches!(event.source, EventSource::AiProxy | EventSource::AgentApp)
        && event.direction == WrapDirection::Out
        && has_response_payload(event)
}

fn event_request_key(event: &WrapEvent) -> String {
    if let Some(request_id) = event
        .traffic_envelope
        .as_ref()
        .and_then(|envelope| envelope.request_id.as_ref())
        .filter(|value| !value.is_empty())
    {
        return format!("rid:{request_id}");
    }

    let method = event
        .method
        .as_deref()
        .unwrap_or("request")
        .to_ascii_lowercase();
    format!(
        "fb:{}|{}|{}|{}",
        event_source_label(event.source),
        event.session_id,
        event.server_name,
        method
    )
}

fn parse_rfc3339_to_ms(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

fn update_rollup_1m(tx: &rusqlite::Transaction<'_>, event: &WrapEvent) -> std::io::Result<()> {
    let bucket_start = event.timestamp.format("%Y-%m-%dT%H:%M:00Z").to_string();
    let source = event_source_label(event.source);
    let provider = event.provider.as_deref().unwrap_or("unknown");
    let agent = event.agent.name.as_str();
    // Paired proxy events may contain both request and response semantics in a single
    // finalized `Out` event. Count both sides for AI/agent traffic even when request
    // body is empty (e.g., GET /backend-api/wham/usage).
    let requests = if event.direction == WrapDirection::In
        || has_request_payload(event)
        || is_paired_proxy_response_event(event)
    {
        1_i64
    } else {
        0_i64
    };
    let responses = if event.direction == WrapDirection::Out || has_response_payload(event) {
        1_i64
    } else {
        0_i64
    };
    let error_events = if event.status_code.map(|code| code >= 400).unwrap_or(false)
        || event.policy_allowed == Some(false)
    {
        1_i64
    } else {
        0_i64
    };
    let pii_events = if event.pii_detected { 1_i64 } else { 0_i64 };
    let total_tokens = event
        .token_count
        .or_else(|| Some(event.input_tokens.unwrap_or(0) + event.output_tokens.unwrap_or(0)))
        .unwrap_or(0) as i64;
    let total_cost = event.cost_usd.unwrap_or(0.0_f64);

    tx.execute(
        r#"
        INSERT INTO rollups_1m (
            bucket_start, source, provider, agent, total_events,
            requests, responses, error_events, pii_events, total_tokens, total_cost_usd
        )
        VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(bucket_start, source, provider, agent) DO UPDATE SET
            total_events = total_events + 1,
            requests = requests + excluded.requests,
            responses = responses + excluded.responses,
            error_events = error_events + excluded.error_events,
            pii_events = pii_events + excluded.pii_events,
            total_tokens = total_tokens + excluded.total_tokens,
            total_cost_usd = total_cost_usd + excluded.total_cost_usd
        "#,
        params![
            bucket_start,
            source,
            provider,
            agent,
            requests,
            responses,
            error_events,
            pii_events,
            total_tokens,
            total_cost
        ],
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn update_rollup_1m_from_exchange(
    tx: &rusqlite::Transaction<'_>,
    event: &ExchangeEventV2,
) -> std::io::Result<()> {
    let bucket_start = event.observed_at.format("%Y-%m-%dT%H:%M:00Z").to_string();
    let source = match event.source_class {
        ExchangeSourceClass::AiInference => "ai_proxy",
        ExchangeSourceClass::AgentApp => "agent_app",
        ExchangeSourceClass::Mcp => "mcp",
        ExchangeSourceClass::Collector => "agent_app",
    };
    let provider = event.provider.as_deref().unwrap_or("unknown");
    let agent = event.agent.as_deref().unwrap_or("unknown");
    let requests = 1_i64;
    let responses = if event.status_code.is_some() {
        1_i64
    } else {
        0_i64
    };
    let error_events = if event.status_code.map(|code| code >= 400).unwrap_or(false) {
        1_i64
    } else {
        0_i64
    };
    let pii_events = if event.flags.pii_detected {
        1_i64
    } else {
        0_i64
    };
    let total_tokens =
        (event.usage.input_tokens.unwrap_or(0) + event.usage.output_tokens.unwrap_or(0)) as i64;
    let total_cost = event
        .cost
        .as_ref()
        .map(|cost| cost.estimated_usd)
        .unwrap_or(0.0_f64);

    tx.execute(
        r#"
        INSERT INTO rollups_1m (
            bucket_start, source, provider, agent, total_events,
            requests, responses, error_events, pii_events, total_tokens, total_cost_usd
        )
        VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(bucket_start, source, provider, agent) DO UPDATE SET
            total_events = total_events + 1,
            requests = requests + excluded.requests,
            responses = responses + excluded.responses,
            error_events = error_events + excluded.error_events,
            pii_events = pii_events + excluded.pii_events,
            total_tokens = total_tokens + excluded.total_tokens,
            total_cost_usd = total_cost_usd + excluded.total_cost_usd
        "#,
        params![
            bucket_start,
            source,
            provider,
            agent,
            requests,
            responses,
            error_events,
            pii_events,
            total_tokens,
            total_cost
        ],
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn upsert_cluster_from_exchange(
    tx: &rusqlite::Transaction<'_>,
    seq: i64,
    event: &ExchangeEventV2,
) -> std::io::Result<()> {
    let source = match event.source_class {
        ExchangeSourceClass::AiInference => "ai_proxy",
        ExchangeSourceClass::AgentApp => "agent_app",
        ExchangeSourceClass::Mcp => "mcp",
        ExchangeSourceClass::Collector => "agent_app",
    };
    let status_code = event.status_code.map(i64::from);
    let latency_ms = event.duration_ms.map(|value| value as i64);
    let pii_detected = if event.flags.pii_detected {
        1_i64
    } else {
        0_i64
    };

    tx.execute(
        r#"
        INSERT OR REPLACE INTO event_clusters (
            cluster_id, request_event_id, response_event_id, request_seq, response_seq,
            timestamp, source, provider, agent, method, status_code, latency_ms,
            policy_allowed, pii_detected
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
        params![
            event.exchange_id,
            event.exchange_id,
            event.exchange_id,
            seq,
            Some(seq),
            event.observed_at.to_rfc3339(),
            source,
            event.provider.as_deref(),
            event.agent.as_deref(),
            event.method.as_deref(),
            status_code,
            latency_ms,
            Option::<i64>::None,
            pii_detected
        ],
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn upsert_cluster_pair(
    tx: &rusqlite::Transaction<'_>,
    cluster_id: &str,
    request_event_id: &str,
    response_event_id: Option<&str>,
    request_seq: i64,
    response_seq: Option<i64>,
    request_event: &WrapEvent,
    response_event: &WrapEvent,
) -> std::io::Result<()> {
    let source = event_source_label(request_event.source);
    let provider = request_event
        .provider
        .as_deref()
        .or(response_event.provider.as_deref())
        .unwrap_or("unknown");
    let method = request_event
        .method
        .as_deref()
        .or(response_event.method.as_deref())
        .unwrap_or("request");
    let agent = request_event.agent.name.as_str();
    let status_code = response_event.status_code.map(i64::from);
    let latency_ms = response_seq.and_then(|_| {
        let req_ms = parse_rfc3339_to_ms(&request_event.timestamp.to_rfc3339())?;
        let rsp_ms = parse_rfc3339_to_ms(&response_event.timestamp.to_rfc3339())?;
        Some((rsp_ms - req_ms).max(0))
    });
    let policy_allowed = response_event
        .policy_allowed
        .or(request_event.policy_allowed)
        .map(|value| if value { 1_i64 } else { 0_i64 });
    let pii_detected = if request_event.pii_detected || response_event.pii_detected {
        1_i64
    } else {
        0_i64
    };
    let timestamp = request_event.timestamp.to_rfc3339();

    tx.execute(
        r#"
        INSERT OR REPLACE INTO event_pairs (
            pair_id, request_event_id, response_event_id, request_seq, response_seq,
            session_id, source, server_name, method, tool_name, provider, agent,
            status_code, latency_ms, pii_detected, policy_allowed, timestamp
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
        "#,
        params![
            cluster_id,
            request_event_id,
            response_event_id,
            request_seq,
            response_seq,
            request_event.session_id.as_str(),
            source,
            request_event.server_name.as_str(),
            method,
            request_event.tool_name.as_deref(),
            provider,
            agent,
            status_code,
            latency_ms,
            pii_detected,
            policy_allowed,
            timestamp,
        ],
    )
    .map_err(to_io_err)?;

    tx.execute(
        r#"
        INSERT OR REPLACE INTO event_clusters (
            cluster_id, request_event_id, response_event_id, request_seq, response_seq,
            timestamp, source, provider, agent, method, status_code, latency_ms,
            policy_allowed, pii_detected
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
        params![
            cluster_id,
            request_event_id,
            response_event_id,
            request_seq,
            response_seq,
            timestamp,
            source,
            provider,
            agent,
            method,
            status_code,
            latency_ms,
            policy_allowed,
            pii_detected,
        ],
    )
    .map_err(to_io_err)?;

    Ok(())
}

fn project_pair_cluster_for_event(
    tx: &rusqlite::Transaction<'_>,
    seq: i64,
    event: &WrapEvent,
) -> std::io::Result<()> {
    if has_paired_payload(event) {
        let cluster_id = format!("pair:self:{}", event.id);
        upsert_cluster_pair(
            tx,
            &cluster_id,
            &event.id,
            Some(&event.id),
            seq,
            Some(seq),
            event,
            event,
        )?;
        return Ok(());
    }

    let request_key = event_request_key(event);
    match event.direction {
        WrapDirection::In => {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO event_pending_requests (
                    request_key, request_event_id, request_seq, session_id, source, server_name,
                    method, tool_name, provider, agent, timestamp
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    request_key,
                    event.id.as_str(),
                    seq,
                    event.session_id.as_str(),
                    event_source_label(event.source),
                    event.server_name.as_str(),
                    event.method.as_deref(),
                    event.tool_name.as_deref(),
                    event.provider.as_deref(),
                    event.agent.name.as_str(),
                    event.timestamp.to_rfc3339(),
                ],
            )
            .map_err(to_io_err)?;
        }
        WrapDirection::Out => {
            let pending = tx
                .query_row(
                    r#"
                    SELECT request_event_id, request_seq
                    FROM event_pending_requests
                    WHERE request_key = ?1
                    LIMIT 1
                    "#,
                    [&request_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(to_io_err)?;

            if let Some((request_event_id, request_seq)) = pending {
                let request_event_json: Option<String> = tx
                    .query_row(
                        "SELECT event_json FROM wrap_events WHERE id = ?1 LIMIT 1",
                        [&request_event_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(to_io_err)?;

                if let Some(request_event_json) = request_event_json {
                    if let Ok(request_event) =
                        serde_json::from_str::<WrapEvent>(&request_event_json)
                    {
                        let cluster_id = format!("pair:{}", request_event_id);
                        upsert_cluster_pair(
                            tx,
                            &cluster_id,
                            &request_event_id,
                            Some(&event.id),
                            request_seq,
                            Some(seq),
                            &request_event,
                            event,
                        )?;
                    }
                }

                tx.execute(
                    "DELETE FROM event_pending_requests WHERE request_key = ?1",
                    [&request_key],
                )
                .map_err(to_io_err)?;
            }
        }
    }

    Ok(())
}

fn ensure_wrap_events_schema(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS wrap_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wrap_event_payloads (
            event_id TEXT NOT NULL,
            payload_kind TEXT NOT NULL,
            payload BLOB NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (event_id, payload_kind)
        );

        CREATE TABLE IF NOT EXISTS exchange_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            exchange_id TEXT NOT NULL UNIQUE,
            observed_at TEXT NOT NULL,
            event_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projection_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS event_pending_requests (
            request_key TEXT PRIMARY KEY,
            request_event_id TEXT NOT NULL,
            request_seq INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            source TEXT NOT NULL,
            server_name TEXT NOT NULL,
            method TEXT,
            tool_name TEXT,
            provider TEXT,
            agent TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS event_pairs (
            pair_id TEXT PRIMARY KEY,
            request_event_id TEXT NOT NULL,
            response_event_id TEXT,
            request_seq INTEGER NOT NULL,
            response_seq INTEGER,
            session_id TEXT NOT NULL,
            source TEXT NOT NULL,
            server_name TEXT NOT NULL,
            method TEXT,
            tool_name TEXT,
            provider TEXT,
            agent TEXT,
            status_code INTEGER,
            latency_ms INTEGER,
            pii_detected INTEGER NOT NULL DEFAULT 0,
            policy_allowed INTEGER,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS event_clusters (
            cluster_id TEXT PRIMARY KEY,
            request_event_id TEXT NOT NULL,
            response_event_id TEXT,
            request_seq INTEGER NOT NULL,
            response_seq INTEGER,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            provider TEXT,
            agent TEXT,
            method TEXT,
            status_code INTEGER,
            latency_ms INTEGER,
            policy_allowed INTEGER,
            pii_detected INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS rollups_1m (
            bucket_start TEXT NOT NULL,
            source TEXT NOT NULL,
            provider TEXT NOT NULL,
            agent TEXT NOT NULL,
            total_events INTEGER NOT NULL DEFAULT 0,
            requests INTEGER NOT NULL DEFAULT 0,
            responses INTEGER NOT NULL DEFAULT 0,
            error_events INTEGER NOT NULL DEFAULT 0,
            pii_events INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            total_cost_usd REAL NOT NULL DEFAULT 0.0,
            PRIMARY KEY (bucket_start, source, provider, agent)
        );

        CREATE TABLE IF NOT EXISTS merkle_batches (
            batch_id TEXT PRIMARY KEY,
            seq_start INTEGER NOT NULL,
            seq_end INTEGER NOT NULL,
            root_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            signer_did TEXT NOT NULL,
            prev_root TEXT,
            sealed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS key_versions (
            key_id TEXT PRIMARY KEY,
            principal_type TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            did TEXT NOT NULL,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            status TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_event_pairs_request_seq ON event_pairs(request_seq DESC);
        CREATE INDEX IF NOT EXISTS idx_event_pairs_session ON event_pairs(session_id, request_seq DESC);
        CREATE INDEX IF NOT EXISTS idx_event_clusters_request_seq ON event_clusters(request_seq DESC);
        CREATE INDEX IF NOT EXISTS idx_rollups_1m_bucket ON rollups_1m(bucket_start DESC);
        CREATE INDEX IF NOT EXISTS idx_exchange_events_observed_at ON exchange_events(observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_merkle_batches_sealed_at ON merkle_batches(sealed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_key_versions_status ON key_versions(status, created_at DESC);
        "#,
    )
    .map_err(to_io_err)?;
    Ok(())
}

fn read_sqlite_event_payload(
    db_path: &Path,
    event_id: &str,
    part: &str,
) -> std::io::Result<Option<String>> {
    let payload_kind = match part {
        "request" | "response" | "content" => part,
        _ => return Ok(None),
    };

    let conn = open_sqlite_connection(db_path)?;
    ensure_wrap_events_schema(&conn)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT payload
            FROM wrap_event_payloads
            WHERE event_id = ?1 AND payload_kind = ?2
            LIMIT 1
            "#,
        )
        .map_err(to_io_err)?;

    let blob_row = stmt.query_row([event_id, payload_kind], |row| row.get::<_, Vec<u8>>(0));
    match blob_row {
        Ok(bytes) => {
            let decoded = String::from_utf8_lossy(&bytes).to_string();
            return Ok(Some(decoded));
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(error) => return Err(to_io_err(error)),
    }

    let mut exchange_stmt = conn
        .prepare(
            r#"
            SELECT event_json
            FROM exchange_events
            WHERE exchange_id = ?1
            LIMIT 1
            "#,
        )
        .map_err(to_io_err)?;
    let exchange_json = exchange_stmt.query_row([event_id], |row| row.get::<_, String>(0));
    match exchange_json {
        Ok(json) => {
            let exchange = serde_json::from_str::<ExchangeEventV2>(&json)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            Ok(match payload_kind {
                "request" => exchange
                    .request
                    .body
                    .inline
                    .or(exchange.request.body.preview),
                "response" => exchange
                    .response
                    .body
                    .inline
                    .or(exchange.response.body.preview),
                "content" => exchange
                    .response
                    .body
                    .inline
                    .or(exchange.response.body.preview)
                    .or(exchange.request.body.inline)
                    .or(exchange.request.body.preview),
                _ => None,
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(to_io_err(error)),
    }
}

fn has_exchange_rows_conn(conn: &Connection) -> std::io::Result<bool> {
    let table_exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'exchange_events' LIMIT 1",
            [],
            |_row| Ok(true),
        )
        .optional()
        .map_err(to_io_err)?
        .unwrap_or(false);
    if !table_exists {
        return Ok(false);
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM exchange_events", [], |row| row.get(0))
        .map_err(to_io_err)?;
    Ok(count > 0)
}

fn exchange_to_wrap_event(seq: i64, event: ExchangeEventV2) -> WrapEvent {
    let source = match event.source_class {
        ExchangeSourceClass::AiInference => EventSource::AiProxy,
        ExchangeSourceClass::AgentApp => EventSource::AgentApp,
        ExchangeSourceClass::Mcp => EventSource::Mcp,
        ExchangeSourceClass::Collector => EventSource::AgentApp,
    };
    let server_name = event
        .endpoint
        .as_deref()
        .and_then(extract_host_from_endpoint)
        .or_else(|| event.provider.clone())
        .unwrap_or_else(|| "exchange".to_string());
    let direction = if event.status_code.is_some() {
        WrapDirection::Out
    } else {
        WrapDirection::In
    };
    let agent_name = event.agent.clone().unwrap_or_else(|| "Unknown".to_string());
    let mut wrapped = WrapEvent::new(
        event
            .session_id
            .clone()
            .unwrap_or_else(|| "exchange".to_string()),
        server_name,
        direction,
        AgentInfo::new(agent_name, DetectionSource::Unknown),
    )
    .with_source(source);
    wrapped.id = event.exchange_id.clone();
    wrapped.seq = Some(seq);
    wrapped.timestamp = event.observed_at;
    if let Some(provider) = event.provider {
        wrapped.provider = Some(provider);
    }
    if let Some(model) = event.model {
        wrapped.model = Some(model);
    }
    if let Some(method) = event.method.clone() {
        if let Some(endpoint) = event.endpoint.clone() {
            wrapped.method = Some(format!("{method} {endpoint}"));
        } else {
            wrapped.method = Some(method);
        }
    } else {
        wrapped.method = event.endpoint.clone();
    }
    wrapped.status_code = event.status_code;
    wrapped.input_tokens = event.usage.input_tokens;
    wrapped.output_tokens = event.usage.output_tokens;
    wrapped.cache_read_tokens = event.usage.cache_read_tokens;
    wrapped.cache_write_tokens = event.usage.cache_write_tokens;
    wrapped.reasoning_tokens = event.usage.reasoning_tokens;
    wrapped.token_count =
        Some(event.usage.input_tokens.unwrap_or(0) + event.usage.output_tokens.unwrap_or(0));
    wrapped.cost_usd = event.cost.as_ref().map(|value| value.estimated_usd);
    wrapped.request_size_bytes = event.request.body.bytes_raw;
    wrapped.response_size_bytes = event.response.body.bytes_raw;
    wrapped.request_preview = event.request.body.preview.clone();
    wrapped.response_preview = event.response.body.preview.clone();
    wrapped.request_content = event.request.body.inline.clone();
    wrapped.response_content = event.response.body.inline.clone();
    wrapped.request_content_ref = event.request.body.reference.clone();
    wrapped.response_content_ref = event.response.body.reference.clone();
    wrapped.pii_detected = event.flags.pii_detected;
    wrapped.latency_ms = event.duration_ms.or(event.ttfb_ms);
    wrapped.tags = event.tags;
    wrapped.headers = event.request.headers.or(event.response.headers);
    wrapped
}

fn extract_host_from_endpoint(endpoint: &str) -> Option<String> {
    let value = endpoint.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with('/') {
        return None;
    }
    let rest = if let Some((_, rest)) = value.split_once("://") {
        rest
    } else {
        value
    };
    let host = rest.split('/').next().unwrap_or_default().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn open_sqlite_connection(db_path: &Path) -> std::io::Result<Connection> {
    open_sqlite_read_write_with_timeout(db_path, Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
}

fn is_sqlite_lock_error(error: &std::io::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("database is locked")
        || message.contains("database table is locked")
        || message.contains("database busy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::event_logger::{EventLoggerOptions, MerkleLoggingConfig};
    use soth_core::types::{
        AgentInfo, DetectionSource, EventSource, TrafficEnvelope, WrapDirection,
    };
    use soth_core::EventLogger;
    use tempfile::tempdir;

    fn make_event(agent_name: &str, server: &str) -> WrapEvent {
        let agent = AgentInfo::new(agent_name, DetectionSource::McpInitialize);
        WrapEvent::new("sess-123", server, WrapDirection::In, agent).with_method("tools/call")
    }

    #[test]
    fn test_add_event() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.db"));

        let event = make_event("Claude Desktop", "postgres");
        store.add_event(event);

        let summary = store.get_events(10);
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.events[0].agent.name, "Claude Desktop");
    }

    #[test]
    fn test_agent_stats() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.db"));

        store.add_event(make_event("Claude Desktop", "postgres"));
        store.add_event(make_event("Claude Desktop", "filesystem"));
        store.add_event(make_event("Cursor", "postgres"));

        let agents = store.get_agents();
        assert_eq!(agents.total_agents, 2);

        let claude = agents
            .agents
            .iter()
            .find(|a| a.name == "Claude Desktop")
            .unwrap();
        assert_eq!(claude.event_count, 2);
        assert_eq!(claude.servers.len(), 2);
    }

    #[test]
    fn test_event_limit() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.db"));

        // Add more than MAX_EVENTS
        for i in 0..1100 {
            store.add_event(make_event(&format!("Agent{}", i % 10), "server"));
        }

        let summary = store.get_events(2000);
        assert_eq!(summary.total_events, MAX_EVENTS);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.db"));

        let mut rx = store.subscribe();

        // Simulate broadcast
        let event = make_event("Test Agent", "test-server");
        store.event_tx.send(event.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.agent.name, "Test Agent");
    }

    #[tokio::test]
    async fn test_load_initial_from_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event("Claude Desktop", "postgres"));
        logger.log(&make_event("Cursor", "filesystem"));
        logger.close();

        let store = EventStore::new(db_path);
        let count = store.load_initial().await.unwrap();
        assert_eq!(count, 2);

        let summary = store.get_events(10);
        assert_eq!(summary.total_events, 2);
    }

    #[tokio::test]
    async fn test_get_events_since_seq_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event("Claude Desktop", "postgres"));
        logger.log(&make_event("Cursor", "filesystem"));
        logger.log(&make_event("Windsurf", "git"));
        logger.close();

        let store = EventStore::new(db_path);
        store.load_initial().await.unwrap();

        let replay = store.get_events_since_seq(1, 10);
        assert_eq!(replay.events.len(), 2);
        assert!(replay
            .events
            .iter()
            .all(|event| event.seq.map(|seq| seq > 1).unwrap_or(false)));
    }

    #[tokio::test]
    async fn test_get_event_payload_sqlite() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let logger = EventLogger::new(db_path.clone()).unwrap();

        let agent = AgentInfo::new("Claude Desktop", DetectionSource::McpInitialize);
        let request_body = "x".repeat(20 * 1024);
        let event = WrapEvent::new("sess-123", "postgres", WrapDirection::In, agent)
            .with_source(soth_core::types::EventSource::AiProxy)
            .with_method("POST /v1/chat/completions")
            .with_request(request_body.clone(), "");

        let event_id = event.id.clone();
        logger.log(&event);
        logger.close();

        let store = EventStore::new(db_path);
        store.load_initial().await.unwrap();

        let payload = store.get_event_payload(&event_id, "request");
        assert_eq!(payload.as_deref(), Some(request_body.as_str()));
    }

    #[tokio::test]
    async fn test_projection_rebuild_is_idempotent() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let logger = EventLogger::new(db_path.clone()).unwrap();

        let agent = AgentInfo::new("Projection Agent", DetectionSource::McpInitialize);

        let request_body =
            r#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello"}]}"#;
        let response_body = r#"{"id":"msg_123","content":[{"type":"text","text":"hi"}]}"#;

        let request = WrapEvent::new(
            "sess-projection",
            "api.anthropic.com",
            WrapDirection::In,
            agent.clone(),
        )
        .with_source(EventSource::AiProxy)
        .with_provider("anthropic")
        .with_model("claude-sonnet-4")
        .with_method("POST /v1/messages")
        .with_content(request_body)
        .with_traffic_envelope(TrafficEnvelope::proxy(
            "sess-projection",
            "req-proj-1",
            "anthropic",
            "api.anthropic.com",
            "POST",
            "/v1/messages",
            Some("claude-sonnet-4"),
            Some("claude"),
            None,
            None,
            Some(request_body),
        ));

        let response = WrapEvent::new(
            "sess-projection",
            "api.anthropic.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_source(EventSource::AiProxy)
        .with_provider("anthropic")
        .with_model("claude-sonnet-4")
        .with_method("POST /v1/messages")
        .with_content(response_body)
        .with_status_code(200)
        .with_usage_tokens(12, 8)
        .with_cost(0.0024)
        .with_latency(155)
        .with_traffic_envelope(TrafficEnvelope::proxy(
            "sess-projection",
            "req-proj-1",
            "anthropic",
            "api.anthropic.com",
            "POST",
            "/v1/messages",
            Some("claude-sonnet-4"),
            Some("claude"),
            None,
            None,
            Some(request_body),
        ));

        let paired = WrapEvent::new(
            "sess-projection-2",
            "api.openai.com",
            WrapDirection::In,
            agent,
        )
        .with_source(EventSource::AiProxy)
        .with_provider("openai")
        .with_model("gpt-5")
        .with_method("POST /v1/chat/completions")
        .with_request(
            r#"{"model":"gpt-5","messages":[{"role":"user","content":"ping"}]}"#,
            "",
        )
        .with_response(
            r#"{"id":"chatcmpl_123","choices":[{"message":{"role":"assistant","content":"pong"}}]}"#,
            "",
        )
        .with_usage_tokens(20, 10)
        .with_cost(0.01)
        .with_latency(90);

        logger.log(&request);
        logger.log(&response);
        logger.log(&paired);
        logger.close();

        let store = EventStore::new(db_path.clone());
        store.load_initial().await.unwrap();

        let clusters_before = store.get_clusters(32);
        let rollups_before = store.get_rollups_1m(64);
        let cluster_total_before = read_sqlite_cluster_total(&db_path).unwrap();
        let rollup_total_before = read_sqlite_rollup_total(&db_path).unwrap();
        let rollup_events_before: u64 =
            rollups_before.rows.iter().map(|row| row.total_events).sum();
        let rollup_requests_before: u64 = rollups_before.rows.iter().map(|row| row.requests).sum();
        let rollup_responses_before: u64 =
            rollups_before.rows.iter().map(|row| row.responses).sum();
        let rollup_tokens_before: u64 =
            rollups_before.rows.iter().map(|row| row.total_tokens).sum();

        assert_eq!(cluster_total_before, 2);
        assert_eq!(clusters_before.total_clusters, 2);
        assert_eq!(rollup_events_before, 3);
        assert_eq!(rollup_requests_before, 2);
        assert_eq!(rollup_responses_before, 2);
        assert_eq!(rollup_tokens_before, 50);
        assert!(rollup_total_before >= 2);

        let projected_seq = project_sqlite_events(&db_path).unwrap();
        assert!(projected_seq >= 3);

        let clusters_after = store.get_clusters(32);
        let rollups_after = store.get_rollups_1m(64);
        let cluster_total_after = read_sqlite_cluster_total(&db_path).unwrap();
        let rollup_total_after = read_sqlite_rollup_total(&db_path).unwrap();
        let rollup_events_after: u64 = rollups_after.rows.iter().map(|row| row.total_events).sum();
        let rollup_requests_after: u64 = rollups_after.rows.iter().map(|row| row.requests).sum();
        let rollup_responses_after: u64 = rollups_after.rows.iter().map(|row| row.responses).sum();
        let rollup_tokens_after: u64 = rollups_after.rows.iter().map(|row| row.total_tokens).sum();

        assert_eq!(cluster_total_after, cluster_total_before);
        assert_eq!(rollup_total_after, rollup_total_before);
        assert_eq!(
            clusters_after.total_clusters,
            clusters_before.total_clusters
        );
        assert_eq!(rollup_events_after, rollup_events_before);
        assert_eq!(rollup_requests_after, rollup_requests_before);
        assert_eq!(rollup_responses_after, rollup_responses_before);
        assert_eq!(rollup_tokens_after, rollup_tokens_before);
    }

    #[tokio::test]
    async fn test_crypto_status_and_recent_merkle() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let logger = EventLogger::new_with_options(
            db_path.clone(),
            EventLoggerOptions {
                inline_payload_max_bytes: 16 * 1024,
                merkle: MerkleLoggingConfig {
                    enabled: true,
                    seal_interval: std::time::Duration::from_secs(60),
                    max_events_per_batch: 2,
                },
            },
        )
        .unwrap();

        let agent = AgentInfo::new("Crypto Agent", DetectionSource::CommandLine);
        let e1 = WrapEvent::new(
            "sess-crypto",
            "api.openai.com",
            WrapDirection::In,
            agent.clone(),
        )
        .with_source(EventSource::AiProxy)
        .with_provider("openai")
        .with_method("POST /v1/chat/completions")
        .with_traffic_envelope(TrafficEnvelope::proxy(
            "sess-crypto",
            "req-crypto-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-5"),
            Some("codex"),
            Some("did:key:z6Mktest"),
            Some("sig-test-1"),
            None,
        ));
        let e2 = WrapEvent::new(
            "sess-crypto",
            "api.openai.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_source(EventSource::AiProxy)
        .with_provider("openai")
        .with_method("POST /v1/chat/completions");
        let e3 = WrapEvent::new("sess-crypto", "api.anthropic.com", WrapDirection::In, agent)
            .with_source(EventSource::AiProxy)
            .with_provider("anthropic")
            .with_method("POST /v1/messages");

        logger.log(&e1);
        logger.log(&e2);
        logger.log(&e3);
        logger.close();

        let store = EventStore::new(db_path);
        store.load_initial().await.unwrap();

        let status = store.get_crypto_status();
        assert_eq!(status.total_events, 3);
        assert_eq!(status.signed_events, 3);
        assert!(status.signature_coverage_pct > 99.0);
        assert!(status.merkle_batches >= 2);
        assert!(status.latest_batch_id.is_some());
        assert!(status.latest_root_hash.is_some());

        let recent = store.get_crypto_merkle_recent(10);
        assert!(recent.total_batches >= 2);
        assert!(!recent.seals.is_empty());
        assert!(recent
            .seals
            .iter()
            .all(|row| row.verification_status == "ok"
                || row.verification_status == "chain_mismatch"));
    }
}
