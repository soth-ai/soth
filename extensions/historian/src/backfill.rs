use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rusqlite::Connection;
use tokio::time::{sleep, Duration};
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

use soth_extensions::ExtensionHandle;

use crate::db;
use crate::dedup::DedupChecker;
use crate::reader::FormatReader;
use crate::session::reconstruct_event;
use crate::types::{AiTool, BackfillProgress, BackfillSummary, DiscoveredTool};

/// Rate-limited backfill engine that processes all discovered sessions once.
///
/// Persists per-tool progress to `backfill_progress` in historian.db so that
/// an interrupted backfill resumes from where it left off.
pub struct BackfillEngine {
    readers: Vec<Box<dyn FormatReader>>,
    tools: Vec<DiscoveredTool>,
    dedup: Arc<DedupChecker>,
    handle: ExtensionHandle,
    rate_limit_per_sec: u32,
    db_path: PathBuf,
}

impl BackfillEngine {
    pub fn new(
        readers: Vec<Box<dyn FormatReader>>,
        tools: Vec<DiscoveredTool>,
        dedup: Arc<DedupChecker>,
        handle: ExtensionHandle,
        db_path: PathBuf,
    ) -> Self {
        Self {
            readers,
            tools,
            dedup,
            handle,
            rate_limit_per_sec: 10,
            db_path,
        }
    }

    pub fn with_rate_limit(mut self, events_per_sec: u32) -> Self {
        self.rate_limit_per_sec = events_per_sec;
        self
    }

    /// Run the backfill to completion. Returns a summary of what was processed.
    ///
    /// Persists progress per-tool — if interrupted and restarted, previously
    /// completed tools are skipped entirely.
    pub async fn run(&self, since: Option<i64>) -> BackfillSummary {
        let start = Instant::now();
        let mut summary = BackfillSummary::default();
        let interval = if self.rate_limit_per_sec > 0 {
            Duration::from_millis(1000 / self.rate_limit_per_sec as u64)
        } else {
            Duration::ZERO
        };

        let progress_conn = match db::open_historian_db(&self.db_path) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(err = %e, "failed to open historian DB for progress tracking");
                None
            }
        };

        for tool_info in &self.tools {
            // Check if this tool's backfill was already completed
            if let Some(ref conn) = progress_conn {
                if is_tool_backfill_complete(conn, tool_info.tool.key()) {
                    debug!(tool = %tool_info.tool, "backfill already complete, skipping");
                    continue;
                }
            }

            let reader = match self.reader_for_tool(&tool_info.tool) {
                Some(r) => r,
                None => {
                    debug!(tool = %tool_info.tool, "no reader registered, skipping");
                    continue;
                }
            };

            info!(tool = %tool_info.tool, root = %tool_info.root_path.display(), "starting backfill");

            // Record backfill start
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

                let event = reconstruct_event(&session);
                let content_hash = event
                    .context
                    .metadata
                    .get("conversation_hash")
                    .cloned()
                    .unwrap_or_default();
                let semantic_hash = event
                    .context
                    .metadata
                    .get("semantic_hash")
                    .cloned();

                if self.dedup.is_duplicate(
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

                match self.handle.submit(event.clone()).await {
                    Ok(()) => {
                        summary.events_emitted += 1;
                        tool_events += 1;
                        if let Err(e) = self.dedup.mark_processed_with_semantic(
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
                        warn!(err = %e, "failed to submit event to pipeline");
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

            // Mark tool backfill complete
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
                if let Err(e) = db::save_backfill_progress(
                    conn,
                    tool_info.tool.key(),
                    &progress,
                    cursor.as_ref(),
                ) {
                    warn!(err = %e, "failed to save final progress");
                }

                // Update discovery report
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

    fn reader_for_tool(&self, tool: &AiTool) -> Option<&dyn FormatReader> {
        self.readers
            .iter()
            .find(|r| &r.tool_type() == tool)
            .map(|r| r.as_ref())
    }
}

fn is_tool_backfill_complete(conn: &Connection, tool_key: &str) -> bool {
    db::load_backfill_progress(conn, tool_key)
        .ok()
        .flatten()
        .map(|(p, _)| p.completed_at.is_some())
        .unwrap_or(false)
}
