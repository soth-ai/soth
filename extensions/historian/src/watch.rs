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
            debounce: Duration::from_secs(2),
            stats: WatchStats::default(),
        }
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
                _ = sleep(self.debounce) => {
                    if pending.is_empty() {
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

            // Read only recent sessions (last 60 seconds window to catch new data)
            let since = Some(chrono::Utc::now().timestamp_millis() - 60_000);
            let mut stream = reader.read_sessions(root, since);

            while let Some(result) = stream.next().await {
                let session = match result {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(tool = %tool, err = %e, "error reading session in watch");
                        continue;
                    }
                };

                let event = reconstruct_event(&session);
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

fn setup_watcher(
    tools: &[DiscoveredTool],
    tx: mpsc::Sender<PathBuf>,
) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            for path in event.paths {
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
