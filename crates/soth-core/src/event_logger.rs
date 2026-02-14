//! Event logger for writing `WrapEvent`s.
//!
//! The logger writes to SQLite (`events.db`) for low-latency durable writes.
//!
//! Used by both `soth wrap` (stdio interception) and soth proxy (HTTP interception)
//! to emit events that appear in the observability dashboard.

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
const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;

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

impl EventLogger {
    /// Create a new event logger that writes to the given path.
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        Self::new_with_options(path, EventLoggerOptions::default())
    }

    /// Create a new event logger that writes to the given path using explicit options.
    pub fn new_with_options(path: PathBuf, options: EventLoggerOptions) -> std::io::Result<Self> {
        let inline_payload_max_bytes = options.inline_payload_max_bytes.max(1);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&path).map_err(to_io_err)?;
        init_sqlite_schema(&conn)?;
        drop(conn);

        let (tx, rx) = mpsc::sync_channel(SQLITE_QUEUE_CAPACITY);
        let worker_path = path.clone();
        let worker_options = options.clone();
        let worker = std::thread::Builder::new()
            .name("soth-event-sqlite-writer".to_string())
            .spawn(move || {
                run_sqlite_writer(worker_path, rx, inline_payload_max_bytes, worker_options)
            })
            .map_err(std::io::Error::other)?;

        let storage = EventLoggerStorage::SqliteAsync {
            tx,
            worker: Some(worker),
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(Some(storage))),
            path,
        })
    }

    /// Create a new event logger that writes to the given path and applies a custom
    /// inline payload threshold before side-table offload.
    pub fn new_with_inline_payload_max_bytes(
        path: PathBuf,
        inline_payload_max_bytes: usize,
    ) -> std::io::Result<Self> {
        let options = EventLoggerOptions {
            inline_payload_max_bytes,
            ..EventLoggerOptions::default()
        };
        Self::new_with_options(path, options)
    }

    /// Create an event logger with the default write path (`~/.soth/logs/events.db`).
    pub fn with_default_path() -> std::io::Result<Self> {
        Self::with_default_path_with_inline_payload_max_bytes(INLINE_PAYLOAD_MAX_BYTES)
    }

    /// Create an event logger with the default write path and custom inline threshold.
    pub fn with_default_path_with_inline_payload_max_bytes(
        inline_payload_max_bytes: usize,
    ) -> std::io::Result<Self> {
        let options = EventLoggerOptions {
            inline_payload_max_bytes,
            ..EventLoggerOptions::default()
        };
        Self::new_with_options(default_event_log_write_path()?, options)
    }

    /// Create an event logger configured from runtime settings.
    pub fn with_default_path_from_runtime_config(
        inline_payload_max_bytes: usize,
        crypto_identity: &CryptoIdentityConfig,
    ) -> std::io::Result<Self> {
        let options =
            EventLoggerOptions::from_runtime_config(inline_payload_max_bytes, crypto_identity);
        Self::new_with_options(default_event_log_write_path()?, options)
    }

    /// Get the path this logger writes to.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Read a sync-state value from SQLite.
    pub fn get_sync_state(&self, key: &str) -> std::io::Result<Option<String>> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.query_row(
            "SELECT value FROM sync_state WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(to_io_err)
    }

    /// Upsert a sync-state value in SQLite.
    pub fn set_sync_state(&self, key: &str, value: &str) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.execute(
            r#"
            INSERT INTO sync_state (key, value, updated_at)
            VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
            params![key, value],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Read the current sync cursor snapshot.
    pub fn get_sync_cursor_state(&self) -> std::io::Result<SyncCursorState> {
        Ok(SyncCursorState {
            last_synced_seq: self
                .get_sync_state(SYNC_KEY_LAST_SYNCED_SEQ)?
                .and_then(|value| value.parse::<i64>().ok()),
            last_body_synced_seq: self
                .get_sync_state(SYNC_KEY_LAST_BODY_SYNCED_SEQ)?
                .and_then(|value| value.parse::<i64>().ok()),
            last_sync_timestamp: self.get_sync_state(SYNC_KEY_LAST_SYNC_TIMESTAMP)?,
            sync_errors: self.get_sync_state(SYNC_KEY_SYNC_ERRORS)?,
        })
    }

    /// Insert or update an in-flight exchange spool row.
    pub fn upsert_exchange_spool(
        &self,
        exchange_id: &str,
        state_json: &str,
        started_at: &str,
    ) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.execute(
            r#"
            INSERT INTO exchange_spool (exchange_id, state_json, started_at, updated_at, finalized_at)
            VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL)
            ON CONFLICT(exchange_id) DO UPDATE SET
                state_json = excluded.state_json,
                updated_at = excluded.updated_at
            "#,
            params![exchange_id, state_json, started_at],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Mark a spool row finalized and optionally update final state snapshot.
    pub fn finalize_exchange_spool(
        &self,
        exchange_id: &str,
        final_state_json: Option<&str>,
    ) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        match final_state_json {
            Some(state_json) => {
                conn.execute(
                    r#"
                    UPDATE exchange_spool
                    SET state_json = ?2,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        finalized_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE exchange_id = ?1
                    "#,
                    params![exchange_id, state_json],
                )
                .map_err(to_io_err)?;
            }
            None => {
                conn.execute(
                    r#"
                    UPDATE exchange_spool
                    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        finalized_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE exchange_id = ?1
                    "#,
                    params![exchange_id],
                )
                .map_err(to_io_err)?;
            }
        }
        Ok(())
    }

    /// Remove an exchange spool row.
    pub fn delete_exchange_spool(&self, exchange_id: &str) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.execute(
            "DELETE FROM exchange_spool WHERE exchange_id = ?1",
            params![exchange_id],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// List pending in-flight exchange spool rows (not finalized).
    pub fn load_exchange_spool_pending(
        &self,
        limit: usize,
    ) -> std::io::Result<Vec<ExchangeSpoolEntry>> {
        let conn = self.open_sqlite_metadata_conn()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT exchange_id, state_json, started_at, updated_at, finalized_at
                FROM exchange_spool
                WHERE finalized_at IS NULL
                ORDER BY updated_at ASC
                LIMIT ?1
                "#,
            )
            .map_err(to_io_err)?;
        let rows = stmt
            .query_map([limit.max(1) as i64], |row| {
                Ok(ExchangeSpoolEntry {
                    exchange_id: row.get(0)?,
                    state_json: row.get(1)?,
                    started_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    finalized_at: row.get(4)?,
                })
            })
            .map_err(to_io_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(to_io_err)?);
        }
        Ok(out)
    }

    /// Enqueue or refresh a finalized exchange upload payload.
    pub fn enqueue_exchange_upload(
        &self,
        exchange_id: &str,
        payload_json: &str,
    ) -> std::io::Result<()> {
        self.enqueue_exchange_upload_with_blobs(exchange_id, payload_json, None)
    }

    /// Enqueue or refresh a finalized exchange upload payload, with optional blob material.
    pub fn enqueue_exchange_upload_with_blobs(
        &self,
        exchange_id: &str,
        payload_json: &str,
        blobs_json: Option<&str>,
    ) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        let observed_at =
            extract_exchange_observed_at(payload_json).unwrap_or_else(|| Utc::now().to_rfc3339());
        conn.execute(
            r#"
            INSERT INTO exchange_events (
                exchange_id, observed_at, event_json, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(exchange_id) DO UPDATE SET
                observed_at = excluded.observed_at,
                event_json = excluded.event_json,
                updated_at = excluded.updated_at
            "#,
            params![exchange_id, observed_at, payload_json],
        )
        .map_err(to_io_err)?;
        conn.execute(
            r#"
            INSERT INTO exchange_upload_queue (
                exchange_id, payload_json, blobs_json, attempt_count, next_attempt_at, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, 0, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(exchange_id) DO UPDATE SET
                payload_json = excluded.payload_json,
                blobs_json = excluded.blobs_json,
                updated_at = excluded.updated_at
            "#,
            params![exchange_id, payload_json, blobs_json],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Convert a [`WrapEvent`] into an `exchange.v2` payload and enqueue it for cloud upload.
    ///
    /// This is used by wrap/collector paths so they share the same cloud upload mechanism
    /// as proxy traffic (`exchange_upload_queue` -> `/api/v1/exchanges/batch`).
    pub fn enqueue_exchange_from_wrap_event(
        &self,
        event: &WrapEvent,
        exchange_cfg: &ExchangeV2Config,
        source_class_override: Option<ExchangeSourceClass>,
    ) -> std::io::Result<()> {
        if !exchange_cfg.enabled {
            return Ok(());
        }

        let exchange_id = event.id.clone();
        let payload = wrap_event_to_exchange_v2(event, exchange_cfg, source_class_override);
        let payload_json = serde_json::to_string(&payload)
            .map_err(|error| std::io::Error::other(format!("serialize exchange.v2: {error}")))?;
        self.enqueue_exchange_upload(exchange_id.as_str(), payload_json.as_str())
    }

    /// List upload queue entries that are ready for dispatch.
    pub fn load_exchange_upload_queue_ready(
        &self,
        limit: usize,
    ) -> std::io::Result<Vec<ExchangeUploadQueueEntry>> {
        let conn = self.open_sqlite_metadata_conn()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT exchange_id, payload_json, blobs_json, attempt_count, next_attempt_at, created_at, updated_at
                FROM exchange_upload_queue
                WHERE next_attempt_at IS NULL OR next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                ORDER BY updated_at ASC
                LIMIT ?1
                "#,
            )
            .map_err(to_io_err)?;
        let rows = stmt
            .query_map([limit.max(1) as i64], |row| {
                Ok(ExchangeUploadQueueEntry {
                    exchange_id: row.get(0)?,
                    payload_json: row.get(1)?,
                    blobs_json: row.get(2)?,
                    attempt_count: row.get::<_, i64>(3)? as u32,
                    next_attempt_at: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .map_err(to_io_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(to_io_err)?);
        }
        Ok(out)
    }

    /// Increment upload attempt counters and set a retry delay.
    pub fn mark_exchange_upload_attempt(
        &self,
        exchange_id: &str,
        retry_delay: Duration,
    ) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        let delay_secs = retry_delay.as_secs().max(1);
        conn.execute(
            r#"
            UPDATE exchange_upload_queue
            SET attempt_count = attempt_count + 1,
                next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?2)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE exchange_id = ?1
            "#,
            params![exchange_id, delay_secs],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Remove an upload queue entry after successful sync.
    pub fn delete_exchange_upload(&self, exchange_id: &str) -> std::io::Result<()> {
        let conn = self.open_sqlite_metadata_conn()?;
        conn.execute(
            "DELETE FROM exchange_upload_queue WHERE exchange_id = ?1",
            params![exchange_id],
        )
        .map_err(to_io_err)?;
        Ok(())
    }

    /// Log an event.
    pub fn log(&self, event: &WrapEvent) {
        let _ = self.log_checked(event);
    }

    /// Log an event, returning any error.
    pub fn log_checked(&self, event: &WrapEvent) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        match guard.as_mut() {
            Some(EventLoggerStorage::SqliteAsync { tx, .. }) => {
                let command = LoggerCommand::Event(Box::new(event.clone()));
                match tx.try_send(command) {
                    Ok(()) => {}
                    Err(TrySendError::Full(command)) => tx.send(command).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "Event logger writer is disconnected",
                        )
                    })?,
                    Err(TrySendError::Disconnected(_)) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "Event logger writer is disconnected",
                        ));
                    }
                }
            }
            None => {}
        }

        Ok(())
    }

    /// Flush buffered events to durable storage.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        match guard.as_mut() {
            Some(EventLoggerStorage::SqliteAsync { tx, .. }) => {
                let (ack_tx, ack_rx) = mpsc::channel();
                tx.send(LoggerCommand::Flush(ack_tx)).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SQLite logger disconnected",
                    )
                })?;
                ack_rx.recv().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SQLite logger disconnected",
                    )
                })?
            }
            None => Ok(()),
        }
    }

    /// Close the logger.
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(storage) = guard.take() {
                match storage {
                    EventLoggerStorage::SqliteAsync { tx, mut worker } => {
                        let _ = tx.send(LoggerCommand::Shutdown);
                        if let Some(handle) = worker.take() {
                            let _ = handle.join();
                        }
                    }
                }
            }
        }
    }

    fn open_sqlite_metadata_conn(&self) -> std::io::Result<Connection> {
        let conn = Connection::open(&self.path).map_err(to_io_err)?;
        conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .map_err(to_io_err)?;
        init_sqlite_schema(&conn)?;
        Ok(conn)
    }
}

impl std::fmt::Debug for EventLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLogger")
            .field("path", &self.path)
            .finish()
    }
}

impl Drop for EventLogger {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.close();
        }
    }
}

/// Default path used for new event writes.
pub fn default_event_log_write_path() -> std::io::Result<PathBuf> {
    Ok(default_logs_dir()?.join(EVENT_LOG_SQLITE_FILE))
}

fn default_logs_dir() -> std::io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine home directory",
        )
    })?;
    Ok(home.join(".soth").join("logs"))
}

fn init_sqlite_schema(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-8000;
        PRAGMA foreign_keys=ON;

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
            PRIMARY KEY (event_id, payload_kind),
            FOREIGN KEY (event_id) REFERENCES wrap_events(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_wrap_events_session_ts
            ON wrap_events(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_wrap_events_ts
            ON wrap_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_wrap_events_merkle_batch_id
            ON wrap_events((json_extract(event_json, '$.merkle_batch_id')));
        CREATE INDEX IF NOT EXISTS idx_wrap_event_payloads_event_id
            ON wrap_event_payloads(event_id);

        CREATE TABLE IF NOT EXISTS exchange_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            exchange_id TEXT NOT NULL UNIQUE,
            observed_at TEXT NOT NULL,
            event_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_exchange_events_observed_at
            ON exchange_events(observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_exchange_events_updated_at
            ON exchange_events(updated_at DESC);

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

        CREATE INDEX IF NOT EXISTS idx_merkle_batches_sealed_at
            ON merkle_batches(sealed_at);

        CREATE TABLE IF NOT EXISTS key_versions (
            key_id TEXT PRIMARY KEY,
            principal_type TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            did TEXT NOT NULL,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            status TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_key_versions_principal
            ON key_versions(principal_type, principal_id);

        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS exchange_spool (
            exchange_id TEXT PRIMARY KEY,
            state_json TEXT NOT NULL,
            started_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            finalized_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_exchange_spool_updated_at
            ON exchange_spool(updated_at);
        CREATE INDEX IF NOT EXISTS idx_exchange_spool_finalized_at
            ON exchange_spool(finalized_at);

        CREATE TABLE IF NOT EXISTS exchange_upload_queue (
            exchange_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            blobs_json TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_exchange_upload_queue_next_attempt
            ON exchange_upload_queue(next_attempt_at);
        CREATE INDEX IF NOT EXISTS idx_exchange_upload_queue_updated_at
            ON exchange_upload_queue(updated_at);
        "#,
    )
    .map_err(to_io_err)?;

    // Forward-compatible schema update for existing local DBs.
    if let Err(error) = conn.execute(
        "ALTER TABLE exchange_upload_queue ADD COLUMN blobs_json TEXT",
        [],
    ) {
        let message = error.to_string().to_ascii_lowercase();
        if !message.contains("duplicate column name") {
            return Err(to_io_err(error));
        }
    }

    Ok(())
}

fn run_sqlite_writer(
    path: PathBuf,
    rx: Receiver<LoggerCommand>,
    inline_payload_max_bytes: usize,
    options: EventLoggerOptions,
) {
    let mut conn = match Connection::open(&path) {
        Ok(conn) => conn,
        Err(error) => {
            warn!(
                "Failed to open event logger sqlite at {:?}: {}",
                path, error
            );
            return;
        }
    };

    if let Err(error) = init_sqlite_schema(&conn) {
        warn!(
            "Failed to initialize event logger sqlite schema at {:?}: {}",
            path, error
        );
        return;
    }

    let mut merkle_state = match MerkleAuditState::new(&conn, &options.merkle) {
        Ok(state) => state,
        Err(error) => {
            warn!(
                "Failed to initialize Merkle audit state at {:?}: {}",
                path, error
            );
            return;
        }
    };

    let mut pending = Vec::with_capacity(SQLITE_BATCH_SIZE);
    let flush_interval = Duration::from_millis(SQLITE_FLUSH_INTERVAL_MS);

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(LoggerCommand::Event(event)) => pending.push(*event),
            Ok(LoggerCommand::Flush(ack)) => {
                let result = flush_sqlite_events(
                    &mut conn,
                    &mut pending,
                    inline_payload_max_bytes,
                    &mut merkle_state,
                    true,
                );
                let _ = ack.send(result);
            }
            Ok(LoggerCommand::Shutdown) => {
                if let Err(error) = flush_sqlite_events(
                    &mut conn,
                    &mut pending,
                    inline_payload_max_bytes,
                    &mut merkle_state,
                    true,
                ) {
                    warn!("Failed to flush events during logger shutdown: {}", error);
                }
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Time-based durability/visibility: flush partial batches regularly
                // so low-traffic sessions still appear in observability promptly.
                if !pending.is_empty() {
                    if let Err(error) = flush_sqlite_events(
                        &mut conn,
                        &mut pending,
                        inline_payload_max_bytes,
                        &mut merkle_state,
                        false,
                    ) {
                        warn!("Failed to flush timed events: {}", error);
                    }
                } else if merkle_state.enabled {
                    match conn.transaction().map_err(to_io_err) {
                        Ok(tx) => {
                            if let Err(error) = merkle_state.seal_due_batches(&tx, false) {
                                let _ = tx.rollback();
                                warn!("Failed to seal timed Merkle batches: {}", error);
                            } else if let Err(error) = tx.commit().map_err(to_io_err) {
                                warn!("Failed to commit timed Merkle seal: {}", error);
                            }
                        }
                        Err(error) => warn!("Failed to open timed Merkle transaction: {}", error),
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(error) = flush_sqlite_events(
                    &mut conn,
                    &mut pending,
                    inline_payload_max_bytes,
                    &mut merkle_state,
                    true,
                ) {
                    warn!("Failed to flush events during logger shutdown: {}", error);
                }
                return;
            }
        }

        while pending.len() < SQLITE_BATCH_SIZE {
            match rx.try_recv() {
                Ok(LoggerCommand::Event(event)) => pending.push(*event),
                Ok(LoggerCommand::Flush(ack)) => {
                    let result = flush_sqlite_events(
                        &mut conn,
                        &mut pending,
                        inline_payload_max_bytes,
                        &mut merkle_state,
                        true,
                    );
                    let _ = ack.send(result);
                }
                Ok(LoggerCommand::Shutdown) => {
                    if let Err(error) = flush_sqlite_events(
                        &mut conn,
                        &mut pending,
                        inline_payload_max_bytes,
                        &mut merkle_state,
                        true,
                    ) {
                        warn!("Failed to flush events during logger shutdown: {}", error);
                    }
                    return;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Err(error) = flush_sqlite_events(
                        &mut conn,
                        &mut pending,
                        inline_payload_max_bytes,
                        &mut merkle_state,
                        true,
                    ) {
                        warn!("Failed to flush events during logger shutdown: {}", error);
                    }
                    return;
                }
            }
        }

        if pending.len() >= SQLITE_BATCH_SIZE {
            if let Err(error) = flush_sqlite_events(
                &mut conn,
                &mut pending,
                inline_payload_max_bytes,
                &mut merkle_state,
                false,
            ) {
                warn!("Failed to flush batched events: {}", error);
            }
        }
    }
}

fn flush_sqlite_events(
    conn: &mut Connection,
    pending: &mut Vec<WrapEvent>,
    inline_payload_max_bytes: usize,
    merkle_state: &mut MerkleAuditState,
    force_seal: bool,
) -> std::io::Result<()> {
    if pending.is_empty() && (!merkle_state.enabled || !force_seal) {
        return Ok(());
    }

    let tx = conn.transaction().map_err(to_io_err)?;
    let mut inserted = Vec::new();
    for event in pending.iter().cloned() {
        if let Some(meta) =
            insert_sqlite_event(&tx, event, inline_payload_max_bytes, merkle_state.enabled)?
        {
            inserted.push(meta);
        }
    }
    merkle_state.on_events_persisted(&tx, inserted, force_seal)?;
    tx.commit().map_err(to_io_err)?;
    pending.clear();
    Ok(())
}

fn insert_sqlite_event(
    tx: &rusqlite::Transaction<'_>,
    mut event: WrapEvent,
    inline_payload_max_bytes: usize,
    merkle_enabled: bool,
) -> std::io::Result<Option<PersistedEventMeta>> {
    let mut payloads = Vec::new();
    offload_large_payloads(&mut event, &mut payloads, inline_payload_max_bytes);
    if merkle_enabled && event.event_hash.is_none() {
        let event_hash = compute_event_hash(&event)?;
        event.event_hash = Some(event_hash);
    }
    let event_hash = event.event_hash.clone();

    let json = serde_json::to_string(&event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let inserted_rows = tx
        .execute(
            r#"
        INSERT OR IGNORE INTO wrap_events (id, session_id, timestamp, event_json)
        VALUES (?1, ?2, ?3, ?4)
        "#,
            params![
                &event.id,
                &event.session_id,
                event.timestamp.to_rfc3339(),
                &json
            ],
        )
        .map_err(to_io_err)?;
    if inserted_rows == 0 {
        warn!(
            event_id = %event.id,
            "Dropped duplicate event id to preserve append-only event log semantics"
        );
        return Ok(None);
    }
    let seq = tx.last_insert_rowid();

    for payload in payloads {
        tx.execute(
            r#"
            INSERT INTO wrap_event_payloads (event_id, payload_kind, payload, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                &event.id,
                payload.kind,
                payload.bytes,
                event.timestamp.to_rfc3339()
            ],
        )
        .map_err(to_io_err)?;
    }

    if merkle_enabled {
        Ok(event_hash.map(|hash| PersistedEventMeta {
            seq,
            event_hash: hash,
        }))
    } else {
        Ok(None)
    }
}

fn offload_large_payloads(
    event: &mut WrapEvent,
    payloads: &mut Vec<PayloadBlob>,
    inline_payload_max_bytes: usize,
) {
    maybe_offload_payload(
        &event.id,
        "content",
        &mut event.content,
        &mut event.content_preview,
        &mut event.content_ref,
        payloads,
        inline_payload_max_bytes,
    );
    maybe_offload_payload(
        &event.id,
        "request",
        &mut event.request_content,
        &mut event.request_preview,
        &mut event.request_content_ref,
        payloads,
        inline_payload_max_bytes,
    );
    maybe_offload_payload(
        &event.id,
        "response",
        &mut event.response_content,
        &mut event.response_preview,
        &mut event.response_content_ref,
        payloads,
        inline_payload_max_bytes,
    );

    // Request bodies in traffic_envelope are only needed in-memory for enforcement.
    // Strip before persistence to reduce event_json size growth.
    if let Some(ref mut envelope) = event.traffic_envelope {
        envelope.request_body = None;
    }
}

fn maybe_offload_payload(
    event_id: &str,
    kind: &'static str,
    field: &mut Option<String>,
    preview: &mut Option<String>,
    reference: &mut Option<String>,
    payloads: &mut Vec<PayloadBlob>,
    inline_payload_max_bytes: usize,
) {
    let Some(content) = field.take() else {
        return;
    };

    if content.len() <= inline_payload_max_bytes {
        *field = Some(content);
        return;
    }

    if preview
        .as_ref()
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        *preview = Some(build_preview(&content));
    }
    *reference = Some(build_payload_reference(event_id, kind));
    payloads.push(PayloadBlob {
        kind,
        bytes: content.into_bytes(),
    });
}

fn build_payload_reference(event_id: &str, kind: &str) -> String {
    format!("sqlite://wrap_event_payloads/{event_id}/{kind}")
}

fn build_preview(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut preview = String::new();
    for ch in trimmed.chars().take(256) {
        preview.push(ch);
    }
    if trimmed.chars().count() > 256 {
        preview.push_str("...");
    }
    preview
}

fn compute_event_hash(event: &WrapEvent) -> std::io::Result<String> {
    let mut canonical = event.clone();
    canonical.seq = None;
    canonical.event_hash = None;
    canonical.merkle_batch_id = None;
    canonical.merkle_leaf_index = None;
    canonical.merkle_root = None;
    canonical.merkle_signature = None;
    canonical.audit_signer_did = None;

    let bytes = serde_json::to_vec(&canonical)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(hex_encode(&Sha256::digest(bytes)))
}

fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest([]).into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }
    level[0]
}

fn hash_root_link(prev_root: &[u8; 32], current_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_root);
    hasher.update(current_root);
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_32(value: &str) -> std::io::Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(std::io::Error::other)?;
    if bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected 32-byte hash, got {}", bytes.len()),
        ));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn extract_exchange_observed_at(payload_json: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(payload_json).ok()?;
    value
        .get("observed_at")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn wrap_event_to_exchange_v2(
    event: &WrapEvent,
    exchange_cfg: &ExchangeV2Config,
    source_class_override: Option<ExchangeSourceClass>,
) -> ExchangeEventV2 {
    let source_class = source_class_override.unwrap_or_else(|| source_class_from_wrap_event(event));
    let transport = transport_from_wrap_event(event);
    let mut payload = ExchangeEventV2::new(
        event.id.clone(),
        source_class,
        transport,
        ExchangeBodyMode::MetadataOnly,
        ExchangeBodyMode::MetadataOnly,
    );

    payload.session_id = Some(event.session_id.clone());
    payload.observed_at = event.timestamp;
    payload.started_at = Some(event.timestamp);
    payload.completed_at = Some(event.timestamp);
    payload.duration_ms = event.latency_ms;
    payload.ttfb_ms = event.latency_ms;

    payload.provider = event.provider.clone().or_else(|| {
        event
            .traffic_envelope
            .as_ref()
            .and_then(|envelope| envelope.provider.clone())
    });
    payload.agent = Some(event.agent.name.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            event
                .traffic_envelope
                .as_ref()
                .and_then(|envelope| envelope.agent.clone())
        });
    payload.model = event.model.clone().or_else(|| {
        event
            .traffic_envelope
            .as_ref()
            .and_then(|envelope| envelope.model.clone())
    });
    payload.endpoint = event
        .traffic_envelope
        .as_ref()
        .and_then(|envelope| envelope.path.clone())
        .or_else(|| Some(event.server_name.clone()));
    payload.method = event.method.clone().or_else(|| {
        event
            .traffic_envelope
            .as_ref()
            .map(|envelope| envelope.method.clone())
    });
    payload.status_code = event.status_code;
    payload.client = exchange_client_from_wrap_event(event);

    let request_text = event
        .request_content
        .as_deref()
        .or_else(|| match event.direction {
            WrapDirection::In => event.content.as_deref(),
            WrapDirection::Out => None,
        });
    let response_text = event
        .response_content
        .as_deref()
        .or_else(|| match event.direction {
            WrapDirection::Out => event.content.as_deref(),
            WrapDirection::In => None,
        });

    let (request_body, request_truncated) = exchange_body_from_text(
        request_text,
        event
            .request_preview
            .as_deref()
            .or(event.content_preview.as_deref()),
        event.request_size_bytes,
        None,
        exchange_cfg,
    );
    let (response_body, response_truncated) = exchange_body_from_text(
        response_text,
        event
            .response_preview
            .as_deref()
            .or(event.content_preview.as_deref()),
        event.response_size_bytes,
        None,
        exchange_cfg,
    );

    payload.request = ExchangeSide {
        headers: if request_text.is_some() || event.request_content.is_some() {
            event.headers.clone()
        } else {
            None
        },
        body: request_body,
    };
    payload.response = ExchangeSide {
        headers: if response_text.is_some() || event.response_content.is_some() {
            event.headers.clone()
        } else {
            None
        },
        body: response_body,
    };

    payload.usage = ExchangeUsage {
        input_tokens: event.input_tokens,
        output_tokens: event.output_tokens,
        cache_read_tokens: event.cache_read_tokens,
        cache_write_tokens: event.cache_write_tokens,
        reasoning_tokens: event.reasoning_tokens,
    };
    payload.cost = event.cost_usd.map(|estimated_usd| ExchangeCost {
        estimated_usd,
        currency: "USD".to_string(),
        pricing_version: None,
    });
    payload.flags = ExchangeFlags {
        truncated: request_truncated || response_truncated,
        metadata_only: payload.request.body.mode == ExchangeBodyMode::MetadataOnly
            && payload.response.body.mode == ExchangeBodyMode::MetadataOnly,
        discovery_capture: false,
        blacklist_match: false,
        pii_detected: event.pii_detected,
    };
    payload.pii_types = event.pii_types.clone();
    payload.integrity = Some(ExchangeIntegrity {
        event_hash: event.event_hash.clone(),
        signature: event
            .traffic_envelope
            .as_ref()
            .and_then(|envelope| envelope.signature.clone()),
        signature_key_id: event
            .traffic_envelope
            .as_ref()
            .and_then(|envelope| envelope.key_id.clone()),
    });
    payload.parse = Some(ExchangeParse {
        parser_version: Some("exchange_v2_wrap".to_string()),
        bundle_version: None,
        parse_confidence: None,
        detection_reason: Some(format!("{:?}", event.agent.detected_from).to_ascii_lowercase()),
    });
    payload.tags = merge_exchange_tags(event);

    payload
}

fn source_class_from_wrap_event(event: &WrapEvent) -> ExchangeSourceClass {
    if event.collector_source.is_some() {
        return ExchangeSourceClass::Collector;
    }
    match event.source {
        EventSource::Mcp => ExchangeSourceClass::Mcp,
        EventSource::AiProxy => ExchangeSourceClass::AiInference,
        EventSource::AgentApp => ExchangeSourceClass::AgentApp,
    }
}

fn transport_from_wrap_event(event: &WrapEvent) -> ExchangeTransport {
    use crate::types::TrafficSource;

    if let Some(envelope) = event.traffic_envelope.as_ref() {
        return match envelope.source {
            TrafficSource::McpStdio => ExchangeTransport::Stdio,
            TrafficSource::McpHttp => ExchangeTransport::Jsonrpc,
            TrafficSource::ProxyHudsucker => ExchangeTransport::Https,
        };
    }
    if matches!(event.source, EventSource::Mcp) {
        ExchangeTransport::Stdio
    } else {
        ExchangeTransport::Https
    }
}

fn exchange_client_from_wrap_event(event: &WrapEvent) -> Option<ExchangeClient> {
    let envelope = event.traffic_envelope.as_ref()?;
    let bundle_id = bundle_id_from_executable_path(envelope.process_executable.as_deref());
    Some(ExchangeClient {
        pid: envelope.process_pid,
        bundle_id: bundle_id.clone(),
        process_name: envelope.process_name.clone(),
        app_type: event.collector_source.as_ref().map(|_| "collector".to_string()).or(
            bundle_id
                .as_ref()
                .map(|_| "desktop_app".to_string())
                .or(Some("cli".to_string())),
        ),
        referrer_origin: None,
    })
}

fn bundle_id_from_executable_path(path: Option<&str>) -> Option<String> {
    let path = path?;
    let lower = path.to_ascii_lowercase();
    let idx = lower.find(".app/")?;
    let app_root = &path[..idx + 4];
    let app = app_root
        .rsplit('/')
        .next()
        .unwrap_or(app_root)
        .trim_end_matches(".app")
        .trim();
    if app.is_empty() {
        return None;
    }
    Some(format!(
        "macos.{}",
        app.chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    ch.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
    ))
}

fn exchange_body_from_text(
    text: Option<&str>,
    preview: Option<&str>,
    size_hint: Option<u64>,
    content_type: Option<String>,
    exchange_cfg: &ExchangeV2Config,
) -> (ExchangeBody, bool) {
    if let Some(value) = text {
        let bytes = value.as_bytes();
        if bytes.len() > exchange_cfg.max_body_bytes as usize {
            return (
                ExchangeBody {
                    mode: ExchangeBodyMode::PreviewOnly,
                    inline: None,
                    reference: None,
                    preview: Some(build_preview(value)),
                    bytes_raw: Some(bytes.len() as u64),
                    bytes_gzip: None,
                    sha256: Some(hex_encode(&Sha256::digest(bytes))),
                    content_type,
                    truncated_reason: Some("max_body_bytes_exceeded".to_string()),
                },
                true,
            );
        }
        return (
            ExchangeBody {
                mode: ExchangeBodyMode::Inline,
                inline: Some(value.to_string()),
                reference: None,
                preview: None,
                bytes_raw: Some(bytes.len() as u64),
                bytes_gzip: None,
                sha256: Some(hex_encode(&Sha256::digest(bytes))),
                content_type,
                truncated_reason: None,
            },
            false,
        );
    }

    if let Some(preview) = preview {
        return (
            ExchangeBody {
                mode: ExchangeBodyMode::PreviewOnly,
                inline: None,
                reference: None,
                preview: Some(preview.to_string()),
                bytes_raw: size_hint,
                bytes_gzip: None,
                sha256: None,
                content_type,
                truncated_reason: None,
            },
            false,
        );
    }

    (
        ExchangeBody {
            mode: ExchangeBodyMode::MetadataOnly,
            inline: None,
            reference: None,
            preview: None,
            bytes_raw: size_hint,
            bytes_gzip: None,
            sha256: None,
            content_type,
            truncated_reason: None,
        },
        false,
    )
}

fn merge_exchange_tags(event: &WrapEvent) -> Option<std::collections::BTreeMap<String, String>> {
    let mut tags = event.tags.clone().unwrap_or_default();
    if let Some(source) = event.collector_source.as_ref() {
        tags.entry("collector.source".to_string())
            .or_insert_with(|| source.clone());
    }
    if let Some(offset) = event.collector_offset {
        tags.entry("collector.offset".to_string())
            .or_insert_with(|| offset.to_string());
    }
    if let Some(operation) = event.graphql_operation.as_ref() {
        tags.entry("graphql.operation".to_string())
            .or_insert_with(|| operation.clone());
    }
    if let Some(allowed) = event.policy_allowed {
        tags.entry("policy.allowed".to_string())
            .or_insert_with(|| allowed.to_string());
    }
    if let Some(version) = event.policy_version.as_ref() {
        tags.entry("policy.version".to_string())
            .or_insert_with(|| version.clone());
    }
    if let Some(reason) = event.policy_reason.as_ref() {
        tags.entry("policy.reason".to_string())
            .or_insert_with(|| reason.clone());
    }
    if let Some(tool_name) = event.tool_name.as_ref() {
        tags.entry("mcp.tool_name".to_string())
            .or_insert_with(|| tool_name.clone());
    }
    if let Some(envelope) = event.traffic_envelope.as_ref() {
        if let Some(did) = envelope.did.as_ref() {
            tags.entry("identity.did".to_string())
                .or_insert_with(|| did.clone());
        }
        if let Some(signature_alg) = envelope.signature_alg.as_ref() {
            tags.entry("identity.signature_alg".to_string())
                .or_insert_with(|| signature_alg.clone());
        }
        if let Some(fields_version) = envelope.signed_fields_version.as_ref() {
            tags.entry("identity.signed_fields_version".to_string())
                .or_insert_with(|| fields_version.clone());
        }
        if let Some(executable) = envelope.process_executable.as_ref() {
            tags.entry("client.process_executable".to_string())
                .or_insert_with(|| executable.clone());
        }
    }
    if tags.is_empty() {
        None
    } else {
        Some(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentInfo, DetectionSource, TrafficEnvelope, WrapDirection};
    use tempfile::tempdir;

    #[test]
    fn test_event_logger_sqlite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-1", "test-server", WrapDirection::In, agent)
            .with_method("test/method");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_event_logger_sqlite_flushes_partial_batch_on_timeout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-timeout", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/messages");

        logger.log(&event);

        let deadline = std::time::Instant::now() + Duration::from_millis(800);
        let mut observed = 0i64;
        while std::time::Instant::now() < deadline {
            let conn = Connection::open(&path).unwrap();
            observed = conn
                .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
                .unwrap_or(0);
            if observed >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        logger.close();
        assert!(
            observed >= 1,
            "expected timed flush to persist event without waiting for batch=64"
        );
    }

    #[test]
    fn test_flush_sqlite_events_keeps_pending_when_insert_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let mut conn = Connection::open(path).unwrap();
        init_sqlite_schema(&conn).unwrap();
        conn.execute("DROP TABLE wrap_events", []).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let mut pending =
            vec![
                WrapEvent::new("session-fail", "api.openai.com", WrapDirection::Out, agent)
                    .with_method("POST /v1/chat/completions"),
            ];
        let pending_id = pending[0].id.clone();

        let mut merkle_state =
            MerkleAuditState::new(&conn, &MerkleLoggingConfig::default()).unwrap();
        let result = flush_sqlite_events(
            &mut conn,
            &mut pending,
            INLINE_PAYLOAD_MAX_BYTES,
            &mut merkle_state,
            false,
        );
        assert!(result.is_err(), "expected sqlite insert to fail");
        assert_eq!(pending.len(), 1, "pending events must be retained");
        assert_eq!(pending[0].id, pending_id);
    }

    #[test]
    fn test_merkle_seal_keeps_pending_when_batch_write_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let mut conn = Connection::open(path).unwrap();
        init_sqlite_schema(&conn).unwrap();

        let mut merkle_state = MerkleAuditState::new(
            &conn,
            &MerkleLoggingConfig {
                enabled: true,
                seal_interval: Duration::from_secs(0),
                max_events_per_batch: 1,
            },
        )
        .unwrap();
        conn.execute("DROP TABLE merkle_batches", []).unwrap();

        let tx = conn.transaction().unwrap();
        let event_hash = hex_encode(&[0x11; 32]);
        let result = merkle_state.on_events_persisted(
            &tx,
            vec![PersistedEventMeta { seq: 1, event_hash }],
            true,
        );

        assert!(result.is_err(), "expected merkle batch write to fail");
        assert_eq!(
            merkle_state.pending.len(),
            1,
            "pending leaf must be retained"
        );
        assert_eq!(merkle_state.pending[0].seq, 1);
    }

    #[test]
    fn test_large_payloads_offloaded_to_side_table() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let large_request = "r".repeat(INLINE_PAYLOAD_MAX_BYTES + 1024);
        let large_response = "s".repeat(INLINE_PAYLOAD_MAX_BYTES + 2048);
        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-large", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/chat/completions")
            .with_request(large_request.clone(), "")
            .with_response(large_response.clone(), "");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        assert!(stored_event.request_content.is_none());
        assert!(stored_event.response_content.is_none());
        assert!(stored_event.request_content_ref.is_some());
        assert!(stored_event.response_content_ref.is_some());

        let request_payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM wrap_event_payloads WHERE event_id = ?1 AND payload_kind = 'request'",
                [&event.id],
                |row| row.get(0),
            )
            .unwrap();
        let response_payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM wrap_event_payloads WHERE event_id = ?1 AND payload_kind = 'response'",
                [&event.id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(String::from_utf8(request_payload).unwrap(), large_request);
        assert_eq!(String::from_utf8(response_payload).unwrap(), large_response);
    }

    #[test]
    fn test_custom_inline_threshold_controls_offload_boundary() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let threshold = 256usize;
        let logger =
            EventLogger::new_with_inline_payload_max_bytes(path.clone(), threshold).unwrap();

        let request_payload = "x".repeat(threshold + 1);
        let response_payload = "y".repeat(threshold / 2);
        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-threshold", "test-server", WrapDirection::In, agent)
            .with_method("POST /v1/messages")
            .with_request(request_payload.clone(), "")
            .with_response(response_payload.clone(), "");

        logger.log(&event);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        // Request exceeds threshold and should be offloaded, response should stay inline.
        assert!(stored_event.request_content.is_none());
        assert!(stored_event.request_content_ref.is_some());
        assert_eq!(
            stored_event.response_content.as_deref(),
            Some(response_payload.as_str())
        );
    }

    #[test]
    fn test_persisted_event_strips_traffic_envelope_request_body() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let envelope_request_body = r#"{"secret":"sensitive payload"}"#.to_string();
        let envelope = TrafficEnvelope::proxy(
            "session-envelope",
            "req-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-5"),
            Some("codex"),
            None,
            None,
            Some(&envelope_request_body),
        );

        let event = WrapEvent::new(
            "session-envelope",
            "api.openai.com",
            WrapDirection::In,
            agent,
        )
        .with_method("POST /v1/chat/completions")
        .with_traffic_envelope(envelope);

        logger.log(&event);
        logger.close();

        // In-memory event still has request_body (required for runtime enforcement flow).
        assert_eq!(
            event
                .traffic_envelope
                .as_ref()
                .and_then(|value| value.request_body.as_deref()),
            Some(envelope_request_body.as_str())
        );

        let conn = Connection::open(path).unwrap();
        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let stored_event: WrapEvent = serde_json::from_str(&event_json).unwrap();

        assert!(
            stored_event
                .traffic_envelope
                .as_ref()
                .and_then(|value| value.request_body.as_deref())
                .is_none(),
            "request_body should be stripped before persistence"
        );
    }

    #[test]
    fn test_sync_state_table_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let _logger = EventLogger::new(path.clone()).unwrap();
        let conn = Connection::open(path).unwrap();

        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn test_sync_cursor_state_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path).unwrap();

        logger
            .set_sync_state(SYNC_KEY_LAST_SYNCED_SEQ, "123")
            .unwrap();
        logger
            .set_sync_state(SYNC_KEY_LAST_BODY_SYNCED_SEQ, "77")
            .unwrap();
        logger
            .set_sync_state(SYNC_KEY_LAST_SYNC_TIMESTAMP, "2026-02-01T00:00:00Z")
            .unwrap();
        logger.set_sync_state(SYNC_KEY_SYNC_ERRORS, "none").unwrap();

        let snapshot = logger.get_sync_cursor_state().unwrap();
        assert_eq!(snapshot.last_synced_seq, Some(123));
        assert_eq!(snapshot.last_body_synced_seq, Some(77));
        assert_eq!(
            snapshot.last_sync_timestamp.as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
        assert_eq!(snapshot.sync_errors.as_deref(), Some("none"));
    }

    #[test]
    fn test_duplicate_event_id_is_ignored_without_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path.clone()).unwrap();
        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);

        let first = WrapEvent::new(
            "session-dup",
            "api.openai.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_method("POST /v1/chat/completions")
        .with_content("first-payload");
        let mut duplicate =
            WrapEvent::new("session-dup", "api.openai.com", WrapDirection::Out, agent)
                .with_method("POST /v1/chat/completions")
                .with_content("second-payload");
        duplicate.id = first.id.clone();

        logger.log(&first);
        logger.log(&duplicate);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(row_count, 1);

        let event_json: String = conn
            .query_row("SELECT event_json FROM wrap_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let persisted: WrapEvent = serde_json::from_str(&event_json).unwrap();
        assert_eq!(persisted.content.as_deref(), Some("first-payload"));
    }

    #[test]
    fn test_merkle_batches_are_sealed_and_written_back_to_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let options = EventLoggerOptions {
            inline_payload_max_bytes: INLINE_PAYLOAD_MAX_BYTES,
            merkle: MerkleLoggingConfig {
                enabled: true,
                seal_interval: Duration::from_secs(60),
                max_events_per_batch: 2,
            },
        };
        let logger = EventLogger::new_with_options(path.clone(), options).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event_a = WrapEvent::new(
            "session-merkle",
            "api.openai.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_method("POST /v1/chat/completions");
        let event_b = WrapEvent::new("session-merkle", "api.openai.com", WrapDirection::In, agent)
            .with_method("POST /v1/chat/completions");

        logger.log(&event_a);
        logger.log(&event_b);
        logger.close();

        let conn = Connection::open(path).unwrap();
        let batch_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM merkle_batches", [], |row| row.get(0))
            .unwrap();
        assert_eq!(batch_count, 1);

        let (root_hash, signature, signer_did): (String, String, String) = conn
            .query_row(
                "SELECT root_hash, signature, signer_did FROM merkle_batches LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(!root_hash.is_empty());
        assert!(!signature.is_empty());
        assert!(signer_did.starts_with("did:key:z"));

        let mut stmt = conn
            .prepare("SELECT event_json FROM wrap_events ORDER BY seq ASC")
            .unwrap();
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);

        let first: WrapEvent = serde_json::from_str(&rows[0]).unwrap();
        let second: WrapEvent = serde_json::from_str(&rows[1]).unwrap();
        assert!(first.event_hash.is_some());
        assert!(second.event_hash.is_some());
        assert_eq!(first.merkle_leaf_index, Some(0));
        assert_eq!(second.merkle_leaf_index, Some(1));
        assert_eq!(first.merkle_root, Some(root_hash.clone()));
        assert_eq!(second.merkle_root, Some(root_hash));
        assert_eq!(first.audit_signer_did, Some(signer_did.clone()));
        assert_eq!(second.audit_signer_did, Some(signer_did));
    }

    #[test]
    fn test_exchange_spool_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path).unwrap();

        logger
            .upsert_exchange_spool(
                "ex-1",
                r#"{"state":"inflight","chunks":3}"#,
                "2026-02-01T00:00:00Z",
            )
            .unwrap();

        let pending = logger.load_exchange_spool_pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].exchange_id, "ex-1");
        assert_eq!(pending[0].finalized_at, None);

        logger
            .finalize_exchange_spool("ex-1", Some(r#"{"state":"done"}"#))
            .unwrap();
        let pending_after_finalize = logger.load_exchange_spool_pending(10).unwrap();
        assert!(pending_after_finalize.is_empty());

        logger.delete_exchange_spool("ex-1").unwrap();
        logger.close();
    }

    #[test]
    fn test_exchange_upload_queue_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path).unwrap();

        logger
            .enqueue_exchange_upload_with_blobs(
                "ex-2",
                r#"{"exchange_id":"ex-2"}"#,
                Some(r#"[{"side":"response","reference":"blob://exchange/ex-2/response/abc"}]"#),
            )
            .unwrap();
        let ready = logger.load_exchange_upload_queue_ready(10).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].exchange_id, "ex-2");
        assert!(ready[0].blobs_json.is_some());
        assert_eq!(ready[0].attempt_count, 0);

        logger
            .mark_exchange_upload_attempt("ex-2", Duration::from_secs(30))
            .unwrap();
        let ready_after_backoff = logger.load_exchange_upload_queue_ready(10).unwrap();
        assert!(
            ready_after_backoff.is_empty(),
            "entry should be delayed by retry backoff"
        );

        logger.delete_exchange_upload("ex-2").unwrap();
        let ready_after_delete = logger.load_exchange_upload_queue_ready(10).unwrap();
        assert!(ready_after_delete.is_empty());
        logger.close();
    }

    #[test]
    fn test_enqueue_exchange_from_wrap_event() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.db");
        let logger = EventLogger::new(path).unwrap();

        let mut cfg = ExchangeV2Config::default();
        cfg.enabled = true;

        let event = WrapEvent::new(
            "session-wrap",
            "mcp-server",
            WrapDirection::In,
            AgentInfo::new("claude-code", DetectionSource::CommandLine),
        )
        .with_source(EventSource::Mcp)
        .with_method("tools/call")
        .with_content(r#"{"jsonrpc":"2.0","method":"tools/call"}"#)
        .with_usage_tokens(12, 34)
        .with_cost(0.0042);

        logger
            .enqueue_exchange_from_wrap_event(&event, &cfg, Some(ExchangeSourceClass::Mcp))
            .unwrap();

        let ready = logger.load_exchange_upload_queue_ready(10).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].exchange_id, event.id);
        assert!(ready[0].payload_json.contains("\"schema_version\":\"2.0\""));
        assert!(ready[0].payload_json.contains("\"source_class\":\"mcp\""));
        assert!(ready[0].payload_json.contains("\"method\":\"tools/call\""));
        assert!(ready[0].payload_json.contains("\"input_tokens\":12"));
        assert!(ready[0].payload_json.contains("\"output_tokens\":34"));
    }
}
