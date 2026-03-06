pub mod backfill;
pub mod db;
pub mod dedup;
pub mod discovery;
pub mod error;
pub mod reader;
pub mod readers;
pub mod session;
pub mod types;
pub mod watch;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch as tokio_watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

use soth_core::ExtensionType;
use soth_extensions::capabilities::ExtensionCapabilities;
use soth_extensions::error::ExtensionError;
use soth_extensions::handle::ExtensionHandle;
use soth_extensions::traits::{Extension, ExtensionHealth};

use crate::backfill::BackfillEngine;
use crate::dedup::DedupChecker;
use crate::discovery::ToolDiscovery;
use crate::readers::claude_code::ClaudeCodeReader;
use crate::readers::codex::CodexReader;
use crate::readers::gemini::GeminiReader;
use crate::types::DiscoveredTool;
use crate::watch::WatchEngine;

/// The Historian extension — discovers and ingests local AI tool history.
pub struct HistorianExtension {
    handle: Option<ExtensionHandle>,
    backfill_task: Option<JoinHandle<()>>,
    watch_task: Option<JoinHandle<()>>,
    shutdown_tx: Option<tokio_watch::Sender<bool>>,
    db_path: PathBuf,
    discovery: ToolDiscovery,
    discovered_tools: Vec<DiscoveredTool>,
    backfill_complete: bool,
}

impl HistorianExtension {
    pub fn new(db_path: PathBuf, discovery: ToolDiscovery) -> Self {
        Self {
            handle: None,
            backfill_task: None,
            watch_task: None,
            shutdown_tx: None,
            db_path,
            discovery,
            discovered_tools: Vec::new(),
            backfill_complete: false,
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

    fn build_readers() -> Vec<Box<dyn crate::reader::FormatReader>> {
        vec![
            Box::new(ClaudeCodeReader::new()),
            Box::new(GeminiReader::new()),
            Box::new(CodexReader::new()),
        ]
    }
}

#[async_trait]
impl Extension for HistorianExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::Historian
    }

    fn name(&self) -> &str {
        "historian"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn capabilities(&self) -> ExtensionCapabilities {
        ExtensionCapabilities {
            needs_detect: true,
            needs_classify: true,
            can_block: false,
            emits_telemetry: true,
        }
    }

    async fn start(&mut self) -> Result<(), ExtensionError> {
        let handle = self
            .handle
            .clone()
            .ok_or(ExtensionError::NotStarted)?;

        if self.backfill_task.is_some() || self.watch_task.is_some() {
            return Err(ExtensionError::AlreadyStarted);
        }

        // Open/create historian DB
        let conn =
            db::open_historian_db(&self.db_path).map_err(|e| ExtensionError::Other(e.to_string()))?;

        // Run discovery
        let report = self.discovery.scan();
        info!(
            tools = report.tools.len(),
            errors = report.errors.len(),
            scan_ms = report.scan_duration_ms,
            "historian discovery complete"
        );
        self.discovered_tools = report.tools;

        if self.discovered_tools.is_empty() {
            info!("no AI tools discovered, historian will idle");
            return Ok(());
        }

        let dedup = Arc::new(DedupChecker::new(conn));
        let (shutdown_tx, shutdown_rx) = tokio_watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn backfill, then watch after backfill completes.
        let tools = self.discovered_tools.clone();
        let dedup_clone = Arc::clone(&dedup);
        let handle_clone = handle.clone();
        let db_path = self.db_path.clone();

        self.backfill_task = Some(tokio::spawn(async move {
            let readers = HistorianExtension::build_readers();
            let engine = BackfillEngine::new(
                readers,
                tools.clone(),
                Arc::clone(&dedup_clone),
                handle_clone.clone(),
                db_path.clone(),
            );

            let summary = engine.run(None).await;
            info!(
                sessions = summary.sessions_processed,
                events = summary.events_emitted,
                dups = summary.duplicates_skipped,
                errors = summary.errors,
                ms = summary.duration_ms,
                "backfill complete"
            );

            // After backfill, start watching.
            // Open a new DB connection for the watch engine's dedup.
            let watch_conn = match db::open_historian_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    error!(err = %e, "failed to open historian DB for watch engine");
                    return;
                }
            };
            let watch_dedup = Arc::new(DedupChecker::new(watch_conn));
            let watch_readers = HistorianExtension::build_readers();
            let watch = WatchEngine::new(watch_readers, tools, watch_dedup, handle_clone);
            watch.run(shutdown_rx).await;
        }));

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ExtensionError> {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for tasks to finish
        if let Some(task) = self.backfill_task.take() {
            task.abort();
        }
        if let Some(task) = self.watch_task.take() {
            task.abort();
        }

        self.backfill_complete = false;
        info!("historian extension stopped");
        Ok(())
    }

    async fn health(&self) -> ExtensionHealth {
        if self.discovered_tools.is_empty() {
            return ExtensionHealth::Healthy;
        }

        if self.backfill_task.is_some() {
            if let Some(ref task) = self.backfill_task {
                if task.is_finished() {
                    return ExtensionHealth::Healthy;
                }
            }
            return ExtensionHealth::Degraded {
                reason: "backfill in progress".to_string(),
            };
        }

        ExtensionHealth::Healthy
    }

    fn set_handle(&mut self, handle: ExtensionHandle) {
        self.handle = Some(handle);
    }
}
