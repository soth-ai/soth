use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::watch;
use tracing::{error, info};

use soth_historian::backfill::BackfillEngine;
use soth_historian::db;
use soth_historian::dedup::DedupChecker;
use soth_historian::discovery::ToolDiscovery;
use soth_historian::readers::claude_code::ClaudeCodeReader;
use soth_historian::readers::codex::CodexReader;
use soth_historian::readers::gemini::GeminiReader;
use soth_historian::watch::WatchEngine;

#[derive(Parser)]
#[command(name = "soth-historian", about = "Standalone AI history ingestion")]
struct Cli {
    /// Path to historian.db
    #[arg(long, default_value_os_t = default_db_path())]
    db_path: PathBuf,

    /// Only backfill (no watch), then exit
    #[arg(long)]
    backfill_only: bool,

    /// Only process sessions newer than this epoch-ms timestamp
    #[arg(long)]
    since: Option<i64>,

    /// Override discovery roots (comma-separated)
    #[arg(long, value_delimiter = ',')]
    roots: Vec<PathBuf>,

    /// Events per second rate limit for backfill
    #[arg(long, default_value_t = 10)]
    rate_limit: u32,
}

fn default_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("historian.db")
}

fn build_readers() -> Vec<Box<dyn soth_historian::reader::FormatReader>> {
    vec![
        Box::new(ClaudeCodeReader::new()),
        Box::new(GeminiReader::new()),
        Box::new(CodexReader::new()),
    ]
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Open DB
    let conn = match db::open_historian_db(&cli.db_path) {
        Ok(c) => c,
        Err(e) => {
            error!(err = %e, "failed to open historian DB");
            std::process::exit(1);
        }
    };

    // Discovery
    let discovery = if cli.roots.is_empty() {
        ToolDiscovery::with_defaults()
    } else {
        let mut d = ToolDiscovery::with_defaults();
        d.override_roots(cli.roots);
        d
    };

    let report = discovery.scan();
    info!(
        tools = report.tools.len(),
        errors = report.errors.len(),
        "discovery complete"
    );

    if report.tools.is_empty() {
        info!("no AI tools discovered, nothing to do");
        return;
    }

    // Create a no-op extension handle that just logs
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(256);
    let handle = soth_extensions::ExtensionHandle::new(event_tx);

    // Drain events in background (standalone mode — just count them)
    let drain_task = tokio::spawn(async move {
        let mut count: u64 = 0;
        while event_rx.recv().await.is_some() {
            count += 1;
            if count % 100 == 0 {
                info!(events = count, "events processed");
            }
        }
        info!(total_events = count, "event drain complete");
    });

    let dedup = Arc::new(DedupChecker::new(conn));

    // Backfill
    let readers = build_readers();
    let engine = BackfillEngine::new(
        readers,
        report.tools.clone(),
        Arc::clone(&dedup),
        handle.clone(),
        cli.db_path.clone(),
    )
    .with_rate_limit(cli.rate_limit);

    let summary = engine.run(cli.since).await;
    info!(
        sessions = summary.sessions_processed,
        events = summary.events_emitted,
        dups = summary.duplicates_skipped,
        errors = summary.errors,
        ms = summary.duration_ms,
        "backfill complete"
    );

    if cli.backfill_only {
        drop(handle);
        let _ = drain_task.await;
        return;
    }

    // Watch mode
    info!("starting watch mode (Ctrl+C to stop)");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("received Ctrl+C, shutting down");
        let _ = shutdown_tx_clone.send(true);
    });

    let watch_conn = match db::open_historian_db(&cli.db_path) {
        Ok(c) => c,
        Err(e) => {
            error!(err = %e, "failed to open historian DB for watch");
            return;
        }
    };
    let watch_dedup = Arc::new(DedupChecker::new(watch_conn));
    let watch_readers = build_readers();
    let watch_engine = WatchEngine::new(watch_readers, report.tools, watch_dedup, handle);
    watch_engine.run(shutdown_rx).await;

    drop(shutdown_tx);
    let _ = drain_task.await;
    info!("historian standalone exiting");
}
