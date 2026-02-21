//! Event store - watches event logs and stores recent events for dashboard.
//!
//! Uses SQLite wrap-event storage.
//! Provides real-time event streaming via broadcast channel.

use crate::state::ObserveMetrics;
use parking_lot::RwLock;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use soth_core::event_logger::default_event_log_write_path;
use soth_core::types::exchange::{ExchangeEvent, ExchangeSourceClass};
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

#[path = "event_store_core.rs"]
mod event_store_core;
