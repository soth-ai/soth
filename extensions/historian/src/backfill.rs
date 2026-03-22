use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rusqlite::Connection;
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tokio_stream::StreamExt;
use tracing::{trace, info, warn};

use soth_extensions::TelemetryQueueWriter;

use crate::db;
use crate::dedup::DedupChecker;
use crate::enrich::ClassifyEnricher;
use crate::reader::FormatReader;
use crate::session::reconstruct_event;
use crate::types::{AiTool, BackfillProgress, BackfillSummary, DiscoveredTool};

/// Default policy decision for historian events — always Allow since these
/// are historical records, not live requests.
fn allow_decision() -> soth_core::PolicyDecision {
    soth_core::PolicyDecision {
        kind: soth_core::PolicyDecisionKind::Allow,
        matched_rule: None,
        warnings: Vec::new(),
        eval_latency_us: 0,
    }
}

/// Rate-limited backfill engine that processes all discovered sessions.
///
/// Processes tools in parallel using a JoinSet. Persists per-tool progress
/// to `backfill_progress` in historian.db so that an interrupted backfill
/// resumes from where it left off.
pub struct BackfillEngine {
    readers: Arc<Vec<Box<dyn FormatReader>>>,
    tools: Vec<DiscoveredTool>,
    dedup: Arc<DedupChecker>,
    writer: TelemetryQueueWriter,
    enricher: Option<Arc<ClassifyEnricher>>,
    rate_limit_per_sec: u32,
    db_path: PathBuf,
}

impl BackfillEngine {
    pub fn new(
        readers: Vec<Box<dyn FormatReader>>,
        tools: Vec<DiscoveredTool>,
        dedup: Arc<DedupChecker>,
        writer: TelemetryQueueWriter,
        db_path: PathBuf,
    ) -> Self {
        Self {
            readers: Arc::new(readers),
            tools,
            dedup,
            writer,
            enricher: None,
            rate_limit_per_sec: 10,
            db_path,
        }
    }

    pub fn with_enricher(mut self, enricher: ClassifyEnricher) -> Self {
        self.enricher = Some(Arc::new(enricher));
        self
    }

    pub fn with_rate_limit(mut self, events_per_sec: u32) -> Self {
        self.rate_limit_per_sec = events_per_sec;
        self
    }

    /// Run the backfill to completion. Returns a summary of what was processed.
    ///
    /// Tools are processed in parallel. Progress is persisted per-tool so that
    /// an interrupted backfill resumes from where it left off.
    pub async fn run(&self, since: Option<i64>) -> BackfillSummary {
        let start = Instant::now();

        // Filter to tools that still need backfill.
        let pending_tools: Vec<_> = self
            .tools
            .iter()
            .filter(|t| {
                match db::open_historian_db(&self.db_path) {
                    Ok(conn) => {
                        if is_tool_backfill_complete(&conn, t.tool.key()) {
                            trace!(tool = %t.tool, "backfill already complete, skipping");
                            return false;
                        }
                    }
                    Err(e) => {
                        warn!(err = %e, "failed to check backfill progress");
                    }
                }
                true
            })
            .cloned()
            .collect();

        if pending_tools.is_empty() {
            info!("all tools already backfilled");
            return BackfillSummary::default();
        }

        info!(tools = pending_tools.len(), "starting parallel backfill");

        // Spawn a task per tool.
        let mut join_set = JoinSet::new();
        for tool_info in pending_tools {
            let readers = self.readers.clone();
            let dedup = self.dedup.clone();
            let writer = self.writer.clone();
            let enricher = self.enricher.clone();
            let db_path = self.db_path.clone();
            let rate_limit = self.rate_limit_per_sec;

            join_set.spawn(async move {
                backfill_one_tool(
                    &readers,
                    &tool_info,
                    &dedup,
                    &writer,
                    enricher.as_deref(),
                    &db_path,
                    since,
                    rate_limit,
                )
                .await
            });
        }

        // Aggregate results.
        let mut summary = BackfillSummary::default();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(tool_summary) => {
                    summary.sessions_processed += tool_summary.sessions_processed;
                    summary.events_emitted += tool_summary.events_emitted;
                    summary.duplicates_skipped += tool_summary.duplicates_skipped;
                    summary.errors += tool_summary.errors;
                }
                Err(e) => {
                    warn!(err = %e, "backfill task panicked");
                    summary.errors += 1;
                }
            }
        }

        summary.duration_ms = start.elapsed().as_millis() as u64;
        summary
    }

    /// Query current backfill progress for all tools.
    pub fn progress(&self) -> Vec<BackfillProgress> {
        let conn = match db::open_historian_db(&self.db_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        self.tools
            .iter()
            .filter_map(|t| {
                db::load_backfill_progress(&conn, t.tool.key())
                    .ok()
                    .flatten()
                    .map(|(mut p, _)| {
                        p.tool = Some(t.tool.clone());
                        p
                    })
            })
            .collect()
    }
}

/// Process a single tool's backfill to completion. Runs as an independent task.
async fn backfill_one_tool(
    readers: &[Box<dyn FormatReader>],
    tool_info: &DiscoveredTool,
    dedup: &DedupChecker,
    writer: &TelemetryQueueWriter,
    enricher: Option<&ClassifyEnricher>,
    db_path: &PathBuf,
    since: Option<i64>,
    rate_limit_per_sec: u32,
) -> BackfillSummary {
    let mut summary = BackfillSummary::default();
    let interval = if rate_limit_per_sec > 0 {
        Duration::from_millis(1000 / rate_limit_per_sec as u64)
    } else {
        Duration::ZERO
    };

    let reader = match reader_for_tool(readers, &tool_info.tool) {
        Some(r) => r,
        None => {
            trace!(tool = %tool_info.tool, "no reader registered, skipping");
            return summary;
        }
    };

    info!(tool = %tool_info.tool, root = %tool_info.root_path.display(), "starting backfill");

    // Each task opens its own progress DB connection (rusqlite is not Sync).
    let progress_conn = match db::open_historian_db(db_path) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!(err = %e, tool = %tool_info.tool, "failed to open progress DB");
            None
        }
    };

    let tool_start = chrono::Utc::now().timestamp();
    if let Some(ref conn) = progress_conn {
        let progress = BackfillProgress {
            tool: Some(tool_info.tool.clone()),
            sessions_total: tool_info.session_count_estimate.unwrap_or(0),
            sessions_done: 0,
            started_at: Some(tool_start),
            completed_at: None,
        };
        if let Err(e) = db::save_backfill_progress(conn, tool_info.tool.key(), &progress, None) {
            warn!(err = %e, "failed to save backfill start progress");
        }
    }

    let mut tool_sessions: u64 = 0;
    let mut tool_events: u64 = 0;
    let mut tool_errors: u64 = 0;

    let mut stream = reader.read_sessions(&tool_info.root_path, since);
    while let Some(result) = stream.next().await {
        let session = match result {
            Ok(s) => s,
            Err(e) => {
                warn!(tool = %tool_info.tool, err = %e, "error reading session");
                summary.errors += 1;
                tool_errors += 1;
                continue;
            }
        };

        summary.sessions_processed += 1;
        tool_sessions += 1;

        let mut event = reconstruct_event(&session);

        // Run classify enrichment before queue write (embed_content
        // is #[serde(skip)] so it must happen here).
        if let Some(enricher) = enricher {
            enricher.enrich(&mut event);
        }

        let content_hash = event
            .context
            .metadata
            .get("conversation_hash")
            .cloned()
            .unwrap_or_default();
        let semantic_hash = event.context.metadata.get("semantic_hash").cloned();

        if dedup.is_duplicate(
            &session.tool,
            &session.session_id,
            0,
            semantic_hash.as_deref(),
            &content_hash,
            session.started_at.unwrap_or(0),
        ) {
            summary.duplicates_skipped += 1;
            continue;
        }

        match writer.enqueue(&event, &allow_decision()) {
            Ok(()) => {
                summary.events_emitted += 1;
                tool_events += 1;
                if let Err(e) = dedup.mark_processed_with_semantic(
                    &session.tool,
                    &session.session_id,
                    0,
                    event.event_id,
                    &content_hash,
                    semantic_hash.as_deref(),
                ) {
                    warn!(err = %e, "failed to mark processed in dedup DB");
                }
            }
            Err(e) => {
                warn!(err = %e, "failed to enqueue event to queue file");
                summary.errors += 1;
                tool_errors += 1;
            }
        }

        // Periodically save progress (every 50 sessions)
        if tool_sessions % 50 == 0 {
            if let Some(ref conn) = progress_conn {
                let cursor = reader.last_cursor();
                let progress = BackfillProgress {
                    tool: Some(tool_info.tool.clone()),
                    sessions_total: tool_info.session_count_estimate.unwrap_or(0),
                    sessions_done: tool_sessions,
                    started_at: Some(tool_start),
                    completed_at: None,
                };
                if let Err(e) = db::save_backfill_progress(
                    conn,
                    tool_info.tool.key(),
                    &progress,
                    cursor.as_ref(),
                ) {
                    warn!(err = %e, "failed to save interim progress");
                }
            }
        }

        // Rate limit
        if !interval.is_zero() {
            sleep(interval).await;
        }
    }

    // Mark tool backfill complete.
    let tool_end = chrono::Utc::now().timestamp();
    if let Some(ref conn) = progress_conn {
        let cursor = reader.last_cursor();
        let progress = BackfillProgress {
            tool: Some(tool_info.tool.clone()),
            sessions_total: tool_sessions,
            sessions_done: tool_sessions,
            started_at: Some(tool_start),
            completed_at: Some(tool_end),
        };
        if let Err(e) =
            db::save_backfill_progress(conn, tool_info.tool.key(), &progress, cursor.as_ref())
        {
            warn!(err = %e, "failed to save final progress");
        }

        if let Err(e) = db::update_discovery_report(
            conn,
            tool_info.tool.key(),
            &tool_info.root_path.to_string_lossy(),
            tool_sessions,
            tool_errors,
        ) {
            warn!(err = %e, "failed to update discovery report");
        }
    }

    info!(
        tool = %tool_info.tool,
        sessions = tool_sessions,
        events = tool_events,
        errors = tool_errors,
        "backfill complete for tool"
    );

    summary
}

fn reader_for_tool<'a>(
    readers: &'a [Box<dyn FormatReader>],
    tool: &AiTool,
) -> Option<&'a dyn FormatReader> {
    readers
        .iter()
        .find(|r| &r.tool_type() == tool)
        .map(|r| r.as_ref())
}

fn is_tool_backfill_complete(conn: &Connection, tool_key: &str) -> bool {
    db::load_backfill_progress(conn, tool_key)
        .ok()
        .flatten()
        .map(|(p, _)| p.completed_at.is_some())
        .unwrap_or(false)
}
