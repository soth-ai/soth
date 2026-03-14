pub mod backfill;
pub mod db;
pub mod dedup;
pub mod discovery;
pub mod engine;
pub mod enrich;
pub mod error;
pub mod playbook;
pub mod playbooks;
pub mod reader;
pub mod readers;
pub mod session;
pub mod types;
pub mod watch;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use soth_core::ExtensionSource;
use soth_extensions::{
    BackfillProgressSnapshot, Capability, Extension, ExtensionArchetype, ExtensionManifest,
    ExtensionRuntimeContext, ExtensionStatus, LifecycleState, TelemetryQueueWriter,
    ToolBackfillProgress,
};

use crate::backfill::BackfillEngine;
use crate::dedup::DedupChecker;
use crate::discovery::ToolDiscovery;
use crate::engine::PlaybookReader;
use crate::playbooks::load_playbooks;
use crate::watch::WatchEngine;

static HISTORIAN_MANIFEST: ExtensionManifest = ExtensionManifest {
    name: "historian",
    version: env!("CARGO_PKG_VERSION"),
    source: ExtensionSource::Historian,
    capabilities: &[Capability::ObserveOnly],
    archetype: ExtensionArchetype::Governance,
    requires_daemon: false,
    tracing_target: "soth_historian",
};

// ---------------------------------------------------------------------------
// HistorianWorker — owns the backfill + watch work on a spawned task
// ---------------------------------------------------------------------------

struct HistorianWorker {
    db_path: PathBuf,
    discovery: ToolDiscovery,
    state: Arc<Mutex<LifecycleState>>,
}

impl HistorianWorker {
    fn build_readers() -> Vec<Box<dyn crate::reader::FormatReader>> {
        load_playbooks()
            .into_iter()
            .map(|pb| Box::new(PlaybookReader::new(pb)) as Box<dyn crate::reader::FormatReader>)
            .collect()
    }

    async fn run(
        self,
        ctx: Arc<ExtensionRuntimeContext>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        // ── Backfill phase ──────────────────────────────────────────────
        {
            let mut state = self.state.lock().await;
            *state = LifecycleState::Backfilling;
        }

        let report = self.discovery.scan();
        info!(
            tools = report.tools.len(),
            errors = report.errors.len(),
            scan_ms = report.scan_duration_ms,
            "historian discovery complete"
        );

        if !report.tools.is_empty() {
            let conn = match db::open_historian_db(&self.db_path) {
                Ok(c) => c,
                Err(e) => {
                    error!(err = %e, "failed to open historian DB");
                    let mut state = self.state.lock().await;
                    *state = LifecycleState::Stopped;
                    return;
                }
            };

            let dedup = Arc::new(DedupChecker::new(conn));
            let writer = TelemetryQueueWriter::for_extension(&ctx, "historian");
            let readers = Self::build_readers();

            let mut engine = BackfillEngine::new(
                readers,
                report.tools.clone(),
                dedup,
                writer,
                self.db_path.clone(),
            );
            if let Some(enricher) = enrich::ClassifyEnricher::try_new(&ctx) {
                info!("classify enrichment enabled for historian backfill");
                engine = engine.with_enricher(enricher);
            }

            let summary = engine.run(None).await;
            info!(
                sessions = summary.sessions_processed,
                events = summary.events_emitted,
                dups = summary.duplicates_skipped,
                errors = summary.errors,
                ms = summary.duration_ms,
                "historian backfill complete"
            );
        } else {
            info!("no AI tools discovered, nothing to backfill");
        }

        // Check if shutdown was signaled during backfill
        if *shutdown_rx.borrow() {
            let mut state = self.state.lock().await;
            *state = LifecycleState::Stopped;
            return;
        }

        // ── Watch phase ─────────────────────────────────────────────────
        {
            let mut state = self.state.lock().await;
            *state = LifecycleState::Watching;
        }

        let report = self.discovery.scan();
        if report.tools.is_empty() {
            info!("no AI tools discovered, watch engine idle");
            let mut state = self.state.lock().await;
            *state = LifecycleState::Stopped;
            return;
        }

        let conn = match db::open_historian_db(&self.db_path) {
            Ok(c) => c,
            Err(e) => {
                error!(err = %e, "failed to open historian DB for watch");
                let mut state = self.state.lock().await;
                *state = LifecycleState::Stopped;
                return;
            }
        };

        let dedup = Arc::new(DedupChecker::new(conn));
        let writer = TelemetryQueueWriter::for_extension(&ctx, "historian");
        let readers = Self::build_readers();

        let watch = WatchEngine::new(readers, report.tools, dedup, writer);
        watch.run(shutdown_rx).await;

        {
            let mut state = self.state.lock().await;
            *state = LifecycleState::Stopped;
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle handles — stored in the extension for shutdown coordination
// ---------------------------------------------------------------------------

struct LifecycleHandles {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task_handle: tokio::task::JoinHandle<()>,
}

// ---------------------------------------------------------------------------
// HistorianExtension — the public extension type
// ---------------------------------------------------------------------------

/// The Historian extension — discovers and ingests local AI tool history.
pub struct HistorianExtension {
    db_path: PathBuf,
    discovery: ToolDiscovery,
    lifecycle: Mutex<Option<LifecycleHandles>>,
    state: Arc<Mutex<LifecycleState>>,
}

impl HistorianExtension {
    pub fn new(db_path: PathBuf, discovery: ToolDiscovery) -> Self {
        Self {
            db_path,
            discovery,
            lifecycle: Mutex::new(None),
            state: Arc::new(Mutex::new(LifecycleState::Idle)),
        }
    }

    /// Create with default discovery roots and the standard db path.
    pub fn with_defaults() -> Self {
        let db_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".soth")
            .join("historian.db");
        Self::new(db_path, ToolDiscovery::with_defaults())
    }

    /// Build readers from playbook configurations.
    fn build_readers() -> Vec<Box<dyn crate::reader::FormatReader>> {
        load_playbooks()
            .into_iter()
            .map(|pb| Box::new(PlaybookReader::new(pb)) as Box<dyn crate::reader::FormatReader>)
            .collect()
    }

    /// Run the backfill to completion, writing events to the governance queue.
    /// (standalone / CLI entry point — lifecycle-managed proxies use `start()`)
    pub async fn run_backfill(&self, ctx: &ExtensionRuntimeContext) {
        let worker = HistorianWorker {
            db_path: self.db_path.clone(),
            discovery: self.discovery.clone(),
            state: Arc::new(Mutex::new(LifecycleState::Backfilling)),
        };

        let report = worker.discovery.scan();
        info!(
            tools = report.tools.len(),
            errors = report.errors.len(),
            scan_ms = report.scan_duration_ms,
            "historian discovery complete"
        );

        if report.tools.is_empty() {
            info!("no AI tools discovered, nothing to backfill");
            return;
        }

        let conn = match db::open_historian_db(&worker.db_path) {
            Ok(c) => c,
            Err(e) => {
                error!(err = %e, "failed to open historian DB");
                return;
            }
        };

        let dedup = Arc::new(DedupChecker::new(conn));
        let writer = TelemetryQueueWriter::for_extension(ctx, "historian");
        let readers = Self::build_readers();

        let mut engine = BackfillEngine::new(
            readers,
            report.tools.clone(),
            dedup.clone(),
            writer,
            worker.db_path.clone(),
        );
        if let Some(enricher) = enrich::ClassifyEnricher::try_new(ctx) {
            engine = engine.with_enricher(enricher);
        }

        let summary = engine.run(None).await;
        info!(
            sessions = summary.sessions_processed,
            events = summary.events_emitted,
            dups = summary.duplicates_skipped,
            errors = summary.errors,
            ms = summary.duration_ms,
            "backfill complete"
        );
    }

    /// Run the watch engine (blocks until shutdown signaled).
    /// (standalone / CLI entry point — lifecycle-managed proxies use `start()`)
    pub async fn run_watch(
        &self,
        ctx: &ExtensionRuntimeContext,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let report = self.discovery.scan();
        if report.tools.is_empty() {
            info!("no AI tools discovered, watch engine idle");
            return;
        }

        let conn = match db::open_historian_db(&self.db_path) {
            Ok(c) => c,
            Err(e) => {
                error!(err = %e, "failed to open historian DB for watch");
                return;
            }
        };

        let dedup = Arc::new(DedupChecker::new(conn));
        let writer = TelemetryQueueWriter::for_extension(ctx, "historian");
        let readers = Self::build_readers();

        let watch = WatchEngine::new(readers, report.tools, dedup, writer);
        watch.run(shutdown).await;
    }

    /// Query backfill progress from historian.db for status reporting.
    fn backfill_progress_snapshot(&self) -> Option<BackfillProgressSnapshot> {
        let conn = db::open_historian_db(&self.db_path).ok()?;
        let report = self.discovery.scan();
        if report.tools.is_empty() {
            return None;
        }

        let mut snapshot = BackfillProgressSnapshot::default();
        for tool_info in &report.tools {
            let (sessions_total, sessions_done, completed) =
                match db::load_backfill_progress(&conn, tool_info.tool.key()) {
                    Ok(Some((progress, _))) => (
                        progress.sessions_total,
                        progress.sessions_done,
                        progress.completed_at.is_some(),
                    ),
                    _ => (
                        tool_info.session_count_estimate.unwrap_or(0),
                        0,
                        false,
                    ),
                };

            snapshot.total_sessions_estimated += sessions_total;
            snapshot.total_sessions_done += sessions_done;
            snapshot.tools.push(ToolBackfillProgress {
                tool_name: tool_info.tool.key().to_string(),
                sessions_total,
                sessions_done,
                completed,
            });
        }

        Some(snapshot)
    }
}

#[async_trait]
impl Extension for HistorianExtension {
    fn manifest(&self) -> &ExtensionManifest {
        &HISTORIAN_MANIFEST
    }

    fn status(&self, ctx: &ExtensionRuntimeContext) -> ExtensionStatus {
        let queue_path = ctx.governance_queue_file("historian");
        let queue_depth = queue_depth_estimate(&queue_path);

        let report = self.discovery.scan();
        let healthy = report.errors.is_empty();
        let installed = !report.tools.is_empty();

        // Read lifecycle state (try_lock to avoid blocking status queries)
        let lifecycle_state = self
            .state
            .try_lock()
            .map(|s| *s)
            .unwrap_or(LifecycleState::Idle);

        let backfill_progress = self.backfill_progress_snapshot();

        ExtensionStatus {
            name: "historian".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            archetype: ExtensionArchetype::Governance,
            installed,
            enabled: installed,
            healthy,
            lifecycle_state,
            backfill_progress,
            governance_queue_depth: queue_depth,
            warnings: report.errors.clone(),
            ..ExtensionStatus::default()
        }
    }

    async fn start(&self, ctx: Arc<ExtensionRuntimeContext>) {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.is_some() {
            warn!("historian: start() called but already running");
            return;
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let worker = HistorianWorker {
            db_path: self.db_path.clone(),
            discovery: self.discovery.clone(),
            state: self.state.clone(),
        };

        let task_handle = tokio::spawn(async move {
            worker.run(ctx, shutdown_rx).await;
        });

        *lifecycle = Some(LifecycleHandles {
            shutdown_tx,
            task_handle,
        });

        info!("historian: lifecycle started");
    }

    async fn shutdown(&self) {
        let handles = {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.take()
        };

        let Some(handles) = handles else {
            return;
        };

        {
            let mut state = self.state.lock().await;
            *state = LifecycleState::ShuttingDown;
        }

        let _ = handles.shutdown_tx.send(true);

        match tokio::time::timeout(Duration::from_secs(10), handles.task_handle).await {
            Ok(Ok(())) => info!("historian: shutdown complete"),
            Ok(Err(e)) => warn!(error = %e, "historian: task panicked during shutdown"),
            Err(_) => warn!("historian: shutdown timed out after 10s"),
        }

        {
            let mut state = self.state.lock().await;
            *state = LifecycleState::Stopped;
        }
    }
}

/// Rough estimate of pending queue records by counting newlines.
fn queue_depth_estimate(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0)
}
