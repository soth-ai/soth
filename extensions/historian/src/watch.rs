use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use tokio_stream::StreamExt;
use tracing::{info, trace, warn};

use soth_extensions::TelemetryQueueWriter;

use crate::dedup::DedupChecker;
use crate::enrich::ClassifyEnricher;
use crate::reader::FormatReader;
use crate::session::reconstruct_event;
use crate::types::{AiTool, DiscoveredTool};

/// Default policy decision for historian events — always Allow.
fn allow_decision() -> soth_core::PolicyDecision {
    soth_core::PolicyDecision {
        kind: soth_core::PolicyDecisionKind::Allow,
        matched_rule: None,
        warnings: Vec::new(),
        eval_latency_us: 0,
    }
}

/// File-watch engine that detects new conversation data and emits events.
pub struct WatchEngine {
    readers: Vec<Box<dyn FormatReader>>,
    tools: Vec<DiscoveredTool>,
    dedup: Arc<DedupChecker>,
    writer: TelemetryQueueWriter,
    /// Optional classify enricher. When unset, events ship without
    /// `classify.*` metadata and `TelemetryEvent::from_governable` defaults
    /// `use_case_label_reason` to `historian_not_enriched`, which the sync
    /// sender then logs a WARN per event for. Backfill always wires this;
    /// watch did not until this field was added — see lib.rs and
    /// bin/standalone.rs for the call sites that populate it.
    enricher: Option<Arc<ClassifyEnricher>>,
    debounce: Duration,
    stats: WatchStats,
}

/// Atomic counters for watch engine metrics.
pub struct WatchStats {
    pub events_emitted: AtomicU64,
    pub duplicates_skipped: AtomicU64,
    pub errors: AtomicU64,
    pub fs_events_received: AtomicU64,
    pub process_cycles: AtomicU64,
}

impl Default for WatchStats {
    fn default() -> Self {
        Self {
            events_emitted: AtomicU64::new(0),
            duplicates_skipped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            fs_events_received: AtomicU64::new(0),
            process_cycles: AtomicU64::new(0),
        }
    }
}

impl WatchEngine {
    pub fn new(
        readers: Vec<Box<dyn FormatReader>>,
        tools: Vec<DiscoveredTool>,
        dedup: Arc<DedupChecker>,
        writer: TelemetryQueueWriter,
    ) -> Self {
        Self {
            readers,
            tools,
            dedup,
            writer,
            enricher: None,
            debounce: Duration::from_secs(2),
            stats: WatchStats::default(),
        }
    }

    /// Attach a classify enricher. Mirrors `BackfillEngine::with_enricher`
    /// so both ingest paths run the same enrichment stages.
    pub fn with_enricher(mut self, enricher: ClassifyEnricher) -> Self {
        self.enricher = Some(Arc::new(enricher));
        self
    }

    /// Snapshot of current watch engine stats.
    pub fn stats_snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.stats.events_emitted.load(Ordering::Relaxed),
            self.stats.duplicates_skipped.load(Ordering::Relaxed),
            self.stats.errors.load(Ordering::Relaxed),
            self.stats.fs_events_received.load(Ordering::Relaxed),
            self.stats.process_cycles.load(Ordering::Relaxed),
        )
    }

    pub fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }

    /// Run the watch loop until shutdown is signaled.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let (fs_tx, mut fs_rx) = mpsc::channel::<PathBuf>(256);

        // Build root → tool mapping
        let root_to_tool: HashMap<PathBuf, AiTool> = self
            .tools
            .iter()
            .map(|t| (t.root_path.clone(), t.tool.clone()))
            .collect();

        // Start filesystem watcher
        let watcher_result = setup_watcher(&self.tools, fs_tx);
        let _watcher = match watcher_result {
            Ok(w) => w,
            Err(e) => {
                warn!(err = %e, "failed to start filesystem watcher");
                return;
            }
        };

        info!(roots = self.tools.len(), "watch engine started");

        // Debounce: collect changed paths over the debounce window, then process.
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();

        // Periodic poll fallback. macOS fsevents on `~/Library/Application
        // Support/...` is unreliable for SQLite-WAL-mode writers (Cursor in
        // particular): the live writer holds the .vscdb open and writes
        // through state.vscdb-wal without bumping the main file's mtime,
        // so the OS may never fire a notification we can see. Every
        // POLL_INTERVAL we mark every watched root as "ready to re-scan",
        // regardless of fsevents. The dedup layer downstream keys on
        // content-hash, so re-scanning unchanged sessions is cheap.
        //
        // 60s is a deliberate trade-off: 15s caused noticeable system
        // jitter on M-series Macs while users were active in Cursor (the
        // big composers re-emit and pay classify CPU on every cycle).
        // 60s still picks up new content "within a minute" for monitoring
        // / dashboard purposes — historian is not a hot-path latency
        // signal — while cutting the scan/classify rate 4×.
        const POLL_INTERVAL: Duration = Duration::from_secs(60);
        let mut poll = tokio::time::interval(POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick of `interval` fires immediately; consume it so the
        // initial backfill we just finished doesn't get redone before the
        // watcher even settles.
        poll.tick().await;

        // Hard floor on how often `process_changes` may run, regardless of
        // what triggered it. Without this, an active Cursor session fires
        // fsevents per keystroke; the 2s debounce collapses bursts but not
        // sustained typing, so we'd run a full per-session SQLite scan +
        // event reconstruct ~every 2-5s. That hogs the tokio runtime and
        // starves soth_mitm flow workers (we saw "reaping stale flow
        // state without explicit stream_end" in proxy logs). With this
        // floor, we get *at most* one scan per MIN_CYCLE no matter how
        // many fsevents arrive — fsevents only act as "wake up earlier
        // than the 60s poll if something changed", they can't make us
        // run more often than the poll interval.
        const MIN_CYCLE: Duration = POLL_INTERVAL;
        // Initialize so the first cycle is allowed immediately (we just
        // finished the initial backfill before entering this loop).
        let mut last_processed = Instant::now()
            .checked_sub(MIN_CYCLE)
            .unwrap_or_else(Instant::now);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("watch engine shutting down");
                        break;
                    }
                }
                Some(path) = fs_rx.recv() => {
                    self.stats.fs_events_received.fetch_add(1, Ordering::Relaxed);
                    pending.insert(path, Instant::now());
                }
                _ = poll.tick() => {
                    // Force every watched root into the pending set so the
                    // debounce arm picks them up. Cheap insurance against
                    // fsevents misses on macOS for SQLite-WAL writers.
                    for (root, _) in root_to_tool.iter() {
                        pending.entry(root.clone()).or_insert_with(Instant::now);
                    }
                }
                _ = sleep(self.debounce) => {
                    if pending.is_empty() {
                        continue;
                    }

                    // Throttle: enforce MIN_CYCLE between scans regardless
                    // of how many fsevents/poll ticks queued up paths.
                    // Pending entries stay in the map and will be picked up
                    // on the next allowed cycle.
                    if last_processed.elapsed() < MIN_CYCLE {
                        continue;
                    }

                    let cutoff = Instant::now() - self.debounce;
                    let ready: Vec<PathBuf> = pending
                        .iter()
                        .filter(|(_, ts)| **ts <= cutoff)
                        .map(|(p, _)| p.clone())
                        .collect();

                    for path in &ready {
                        pending.remove(path);
                    }

                    if !ready.is_empty() {
                        self.stats.process_cycles.fetch_add(1, Ordering::Relaxed);
                        self.process_changes(&ready, &root_to_tool).await;
                        last_processed = Instant::now();
                    }
                }
            }
        }
    }

    async fn process_changes(
        &self,
        changed_paths: &[PathBuf],
        root_to_tool: &HashMap<PathBuf, AiTool>,
    ) {
        // Determine which roots are affected
        let mut affected_roots: HashMap<&PathBuf, &AiTool> = HashMap::new();
        for path in changed_paths {
            for (root, tool) in root_to_tool {
                if path.starts_with(root) {
                    affected_roots.insert(root, tool);
                    break;
                }
            }
        }

        for (root, tool) in affected_roots {
            let reader = match self.reader_for_tool(tool) {
                Some(r) => r,
                None => continue,
            };

            trace!(tool = %tool, root = %root.display(), "processing changes");

            // No `since` cutoff: long-lived sessions (Cursor composers,
            // Claude threads) keep growing for days. Filtering by their
            // ORIGINAL createdAt timestamp would drop every conversation
            // older than a minute, leaving the watch loop with nothing
            // to emit. The content-hash dedup downstream prevents
            // re-emitting unchanged sessions, so passing `None` is safe.
            let since = None;
            let mut stream = reader.read_sessions(root, since);

            while let Some(result) = stream.next().await {
                let session = match result {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(tool = %tool, err = %e, "error reading session in watch");
                        continue;
                    }
                };

                let mut event = reconstruct_event(&session);

                // Dedup BEFORE enrichment. The 15s poll re-scans every cursor
                // session each cycle; ~80%+ of those hit dedup as duplicates
                // (unchanged content_hash). `ClassifyEnricher::enrich` runs the
                // ML classify pipeline (~10–50ms each on M-series), which
                // would be wasted on duplicates that are about to be discarded.
                //
                // Safe to dedup first: `conversation_hash` and `semantic_hash`
                // are populated by `reconstruct_event` (see
                // session.rs:81-82), not by the enricher. The enricher only
                // adds `classify.*` keys, which the dedup key never reads.
                let content_hash = event
                    .context
                    .metadata
                    .get("conversation_hash")
                    .cloned()
                    .unwrap_or_default();
                let semantic_hash = event.context.metadata.get("semantic_hash").cloned();

                if self.dedup.is_duplicate(
                    &session.tool,
                    &session.session_id,
                    0,
                    semantic_hash.as_deref(),
                    &content_hash,
                    session.started_at.unwrap_or(0),
                ) {
                    self.stats
                        .duplicates_skipped
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Survived dedup — pay the classify cost.
                // embed_content is `#[serde(skip)]`, so enrichment must run
                // before `writer.enqueue` (post-serialize would lose the
                // classify metadata).
                if let Some(enricher) = self.enricher.as_deref() {
                    enricher.enrich(&mut event);
                }

                match self.writer.enqueue(&event, &allow_decision()) {
                    Ok(()) => {
                        self.stats.events_emitted.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = self.dedup.mark_processed_with_semantic(
                            &session.tool,
                            &session.session_id,
                            0,
                            event.event_id,
                            &content_hash,
                            semantic_hash.as_deref(),
                        ) {
                            warn!(err = %e, "failed to mark processed in watch");
                        }
                    }
                    Err(e) => {
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        warn!(err = %e, "failed to enqueue event from watch");
                    }
                }
            }
        }
    }

    fn reader_for_tool(&self, tool: &AiTool) -> Option<&dyn FormatReader> {
        self.readers
            .iter()
            .find(|r| &r.tool_type() == tool)
            .map(|r| r.as_ref())
    }
}

/// Sidecar files SQLite WAL-mode writers touch on every transaction.
///
/// Cursor opens `state.vscdb` in WAL mode, which means every keystroke that
/// commits a transaction writes to `state.vscdb-wal` and bumps
/// `state.vscdb-shm`. We don't read those files directly — we only read the
/// main `state.vscdb` (read-only, with `busy_timeout`) — so fsevents on the
/// sidecars are pure noise. They were the dominant source of fsevent volume
/// while the user was active in Cursor, and each one used to bypass the
/// poll cadence and trigger a debounced re-scan. Drop them at the watcher
/// boundary so they never reach `pending` in the first place.
fn is_sqlite_sidecar(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
}

fn setup_watcher(
    tools: &[DiscoveredTool],
    tx: mpsc::Sender<PathBuf>,
) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            for path in event.paths {
                if is_sqlite_sidecar(&path) {
                    continue;
                }
                let _ = tx.try_send(path);
            }
        }
    })?;

    for tool in tools {
        if tool.root_path.exists() {
            if let Err(e) = watcher.watch(&tool.root_path, RecursiveMode::Recursive) {
                warn!(
                    root = %tool.root_path.display(),
                    err = %e,
                    "failed to watch root"
                );
            }
        }
    }

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::is_sqlite_sidecar;
    use std::path::PathBuf;

    #[test]
    fn drops_sqlite_sidecar_paths() {
        // Cursor's WAL-mode writer hits these on every keystroke commit;
        // they must not wake the watch loop.
        for f in [
            "state.vscdb-wal",
            "state.vscdb-shm",
            "history.db-journal",
            "/abs/path/to/state.vscdb-wal",
        ] {
            assert!(
                is_sqlite_sidecar(&PathBuf::from(f)),
                "expected {f} to be filtered as a sidecar"
            );
        }
    }

    #[test]
    fn keeps_main_db_and_other_paths() {
        // Anything that isn't a -wal/-shm/-journal must pass through —
        // dropping the main DB or directory events would silently break
        // the watch path.
        for f in [
            "state.vscdb",
            "history.jsonl",
            "/abs/path/to/state.vscdb",
            "/abs/path/to/dir",
            "session-2026-05-06.json",
        ] {
            assert!(
                !is_sqlite_sidecar(&PathBuf::from(f)),
                "expected {f} to pass through, got filtered"
            );
        }
    }
}
