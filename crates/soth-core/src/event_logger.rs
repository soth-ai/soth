//! Event logger for writing `WrapEvent`s.
//!
//! The logger writes to SQLite (`events.db`) for low-latency durable writes.
//!
//! Used by both `soth wrap` (stdio interception) and soth proxy (HTTP interception)
//! to emit events that appear in the observability dashboard.

pub use self::event_logger_core::default_event_log_write_path;
use self::event_logger_core::{
    compute_merkle_root, hash_root_link, hex_decode_32, hex_encode, to_io_err,
};
use crate::config::types::{CryptoIdentityConfig, ExchangeV2Config};
use crate::types::exchange_v2::{
    ExchangeBody, ExchangeBodyMode, ExchangeClient, ExchangeCost, ExchangeEventV2, ExchangeFlags,
    ExchangeIntegrity, ExchangeParse, ExchangeSide, ExchangeSourceClass, ExchangeTransport,
    ExchangeUsage,
};
use crate::types::{EventSource, WrapDirection, WrapEvent};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use soth_storage::{open_sqlite_read_write_with_timeout, read_sync_state, write_sync_state};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

pub const EVENT_LOG_SQLITE_FILE: &str = "events.db";
pub const SYNC_KEY_LAST_SYNCED_SEQ: &str = "last_synced_seq";
pub const SYNC_KEY_LAST_BODY_SYNCED_SEQ: &str = "last_body_synced_seq";
pub const SYNC_KEY_LAST_SYNC_TIMESTAMP: &str = "last_sync_timestamp";
pub const SYNC_KEY_SYNC_ERRORS: &str = "sync_errors";

const SQLITE_QUEUE_CAPACITY: usize = 4096;
const SQLITE_BATCH_SIZE: usize = 64;
const SQLITE_FLUSH_INTERVAL_MS: u64 = 20;
const INLINE_PAYLOAD_MAX_BYTES: usize = 16 * 1024;

/// Event logger runtime options.
#[derive(Debug, Clone)]
pub struct EventLoggerOptions {
    pub inline_payload_max_bytes: usize,
    pub merkle: MerkleLoggingConfig,
}

impl Default for EventLoggerOptions {
    fn default() -> Self {
        Self {
            inline_payload_max_bytes: INLINE_PAYLOAD_MAX_BYTES,
            merkle: MerkleLoggingConfig::default(),
        }
    }
}

impl EventLoggerOptions {
    /// Build logger options from observe + crypto config.
    pub fn from_runtime_config(
        inline_payload_max_bytes: usize,
        crypto_identity: &CryptoIdentityConfig,
    ) -> Self {
        Self {
            inline_payload_max_bytes,
            merkle: MerkleLoggingConfig {
                enabled: crypto_identity.enabled && crypto_identity.merkle.enabled,
                seal_interval: crypto_identity.merkle.seal_interval,
                max_events_per_batch: crypto_identity.merkle.max_events_per_batch.max(1),
            },
        }
    }
}

/// Merkle-audit behavior for event logging.
#[derive(Debug, Clone)]
pub struct MerkleLoggingConfig {
    pub enabled: bool,
    pub seal_interval: Duration,
    pub max_events_per_batch: usize,
}

impl Default for MerkleLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            seal_interval: Duration::from_secs(3),
            max_events_per_batch: 500,
        }
    }
}

enum EventLoggerStorage {
    SqliteAsync {
        tx: SyncSender<LoggerCommand>,
        worker: Option<JoinHandle<()>>,
    },
}

enum LoggerCommand {
    Event(Box<WrapEvent>),
    Flush(std::sync::mpsc::Sender<std::io::Result<()>>),
    Shutdown,
}

struct PayloadBlob {
    kind: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PersistedEventMeta {
    seq: i64,
    event_hash: String,
}

struct AuditSigner {
    key: SigningKey,
    did: String,
}

impl AuditSigner {
    fn generate() -> Self {
        let key = SigningKey::generate(&mut OsRng);
        let mut did_bytes = vec![0xed, 0x01];
        did_bytes.extend_from_slice(&key.verifying_key().to_bytes());
        let did = format!("did:key:z{}", bs58::encode(did_bytes).into_string());
        Self { key, did }
    }

    fn did(&self) -> &str {
        &self.did
    }

    fn sign_hex(&self, root: &[u8; 32]) -> String {
        let signature = self.key.sign(root);
        hex_encode(signature.to_bytes().as_ref())
    }
}

struct MerkleAuditState {
    enabled: bool,
    seal_interval: Duration,
    max_events_per_batch: usize,
    last_sealed_at: Instant,
    pending: Vec<PersistedEventMeta>,
    prev_root: Option<[u8; 32]>,
    batch_counter: u64,
    signer: AuditSigner,
}

impl MerkleAuditState {
    fn new(conn: &Connection, cfg: &MerkleLoggingConfig) -> std::io::Result<Self> {
        let prev_root: Option<String> = conn
            .query_row(
                "SELECT root_hash FROM merkle_batches ORDER BY seq_end DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_io_err)?;
        let prev_root = prev_root.as_deref().map(hex_decode_32).transpose()?;

        let batch_counter: i64 = conn
            .query_row("SELECT COUNT(*) FROM merkle_batches", [], |row| row.get(0))
            .map_err(to_io_err)?;

        Ok(Self {
            enabled: cfg.enabled,
            seal_interval: cfg.seal_interval,
            max_events_per_batch: cfg.max_events_per_batch.max(1),
            last_sealed_at: Instant::now(),
            pending: Vec::new(),
            prev_root,
            batch_counter: batch_counter.max(0) as u64,
            signer: AuditSigner::generate(),
        })
    }

    fn on_events_persisted(
        &mut self,
        tx: &rusqlite::Transaction<'_>,
        new_events: Vec<PersistedEventMeta>,
        force: bool,
    ) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !new_events.is_empty() {
            self.pending.extend(new_events);
        }
        self.seal_due_batches(tx, force)
    }

    fn seal_due_batches(
        &mut self,
        tx: &rusqlite::Transaction<'_>,
        force: bool,
    ) -> std::io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let due_to_size = self.pending.len() >= self.max_events_per_batch;
        let due_to_time = self.last_sealed_at.elapsed() >= self.seal_interval;
        if !force && !due_to_size && !due_to_time {
            return Ok(());
        }

        while self.pending.len() >= self.max_events_per_batch {
            self.seal_one_batch(tx, self.max_events_per_batch)?;
        }

        if force || due_to_time {
            while !self.pending.is_empty() {
                let remaining = self.pending.len().min(self.max_events_per_batch);
                self.seal_one_batch(tx, remaining)?;
            }
        }

        Ok(())
    }

    fn seal_one_batch(
        &mut self,
        tx: &rusqlite::Transaction<'_>,
        count: usize,
    ) -> std::io::Result<()> {
        let batch_len = count.min(self.pending.len());
        let leaves: Vec<PersistedEventMeta> =
            self.pending.iter().take(batch_len).cloned().collect();
        if leaves.is_empty() {
            return Ok(());
        }

        let seq_start = leaves.first().map(|leaf| leaf.seq).unwrap_or_default();
        let seq_end = leaves.last().map(|leaf| leaf.seq).unwrap_or_default();
        let leaf_hashes: Vec<[u8; 32]> = leaves
            .iter()
            .map(|leaf| hex_decode_32(&leaf.event_hash))
            .collect::<std::io::Result<Vec<_>>>()?;
        let base_root = compute_merkle_root(&leaf_hashes);

        let chained_root = if let Some(prev_root) = self.prev_root {
            hash_root_link(&prev_root, &base_root)
        } else {
            base_root
        };
        let root_hex = hex_encode(&chained_root);
        let prev_root_hex = self.prev_root.map(|root| hex_encode(&root));
        let signature_hex = self.signer.sign_hex(&chained_root);
        let sealed_at = Utc::now().to_rfc3339();
        let batch_id = format!("mb_{seq_start}_{seq_end}_{}", self.batch_counter + 1);

        tx.execute(
            r#"
            INSERT INTO merkle_batches
              (batch_id, seq_start, seq_end, root_hash, signature, signer_did, prev_root, sealed_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                &batch_id,
                seq_start,
                seq_end,
                &root_hex,
                &signature_hex,
                self.signer.did(),
                prev_root_hex.as_deref(),
                &sealed_at
            ],
        )
        .map_err(to_io_err)?;

        for (leaf_index, leaf) in leaves.iter().enumerate() {
            tx.execute(
                r#"
                UPDATE wrap_events
                SET event_json = json_set(
                    event_json,
                    '$.event_hash', ?2,
                    '$.merkle_batch_id', ?3,
                    '$.merkle_leaf_index', ?4,
                    '$.merkle_root', ?5,
                    '$.merkle_signature', ?6,
                    '$.audit_signer_did', ?7
                )
                WHERE seq = ?1
                "#,
                params![
                    leaf.seq,
                    &leaf.event_hash,
                    &batch_id,
                    leaf_index as u32,
                    &root_hex,
                    &signature_hex,
                    self.signer.did()
                ],
            )
            .map_err(to_io_err)?;
        }

        self.pending.drain(..batch_len);
        self.prev_root = Some(chained_root);
        self.batch_counter += 1;
        self.last_sealed_at = Instant::now();
        Ok(())
    }
}

/// Persistent sync cursors and status state for cloud synchronization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncCursorState {
    pub last_synced_seq: Option<i64>,
    pub last_body_synced_seq: Option<i64>,
    pub last_sync_timestamp: Option<String>,
    pub sync_errors: Option<String>,
}

/// Durable in-flight exchange assembly record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeSpoolEntry {
    pub exchange_id: String,
    pub state_json: String,
    pub started_at: String,
    pub updated_at: String,
    pub finalized_at: Option<String>,
}

/// Durable upload queue row for finalized exchanges awaiting sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeUploadQueueEntry {
    pub exchange_id: String,
    pub payload_json: String,
    pub blobs_json: Option<String>,
    pub attempt_count: u32,
    pub next_attempt_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Event logger that writes `WrapEvent`s to SQLite.
#[derive(Clone)]
pub struct EventLogger {
    inner: Arc<Mutex<Option<EventLoggerStorage>>>,
    path: PathBuf,
}

#[path = "event_logger_core.rs"]
mod event_logger_core;
