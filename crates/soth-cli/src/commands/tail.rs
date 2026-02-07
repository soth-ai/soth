//! Tail command - Stream live events
//!
//! Enhanced version with filtering by agent, server, tool, and output formats.
//! Uses polling against SQLite event storage.

use crate::style;
use anyhow::{Context, Result};
use clap::Args;
use owo_colors::OwoColorize;
use rusqlite::Connection;
use soth_core::event_logger::default_event_log_write_path;
use soth_core::types::WrapEvent;
use std::path::{Path, PathBuf};
use tracing::info;

/// Arguments for the tail command
#[derive(Args, Debug)]
pub struct TailArgs {
    /// Filter by session ID
    #[arg(short, long)]
    pub session: Option<String>,

    /// Filter by method
    #[arg(short, long)]
    pub method: Option<String>,

    /// Filter by agent name
    #[arg(long)]
    pub agent: Option<String>,

    /// Filter by server name
    #[arg(long)]
    pub server: Option<String>,

    /// Filter by tool name
    #[arg(long)]
    pub tool: Option<String>,

    /// Only show events with PII detected
    #[arg(long)]
    pub pii_only: bool,

    /// Only show denied/error events
    #[arg(long)]
    pub denied_only: bool,

    /// Output format (compact, json, verbose)
    #[arg(short, long, default_value = "compact")]
    pub format: String,

    /// Show N historical events first
    #[arg(short = 'n', long, default_value = "0")]
    pub last: usize,
}

/// Get the default log path
fn get_log_path() -> Result<PathBuf> {
    default_event_log_write_path().context("Could not resolve default event log path")
}

/// Run tail command
pub async fn run(args: TailArgs) -> Result<()> {
    let log_path = get_log_path()?;

    if !log_path.exists() {
        style::warning(&format!("Log file not found: {:?}", log_path));
        println!();
        style::info("Start using 'soth wrap' or 'soth install' to generate events.");
        return Ok(());
    }

    info!("Tailing events from {:?}", log_path);

    // Show historical events if requested.
    if args.last > 0 {
        show_historical_events(&log_path, &args).await?;
        println!();
    }

    println!(
        "{} Streaming events ({} to stop)...",
        style::CIRCLE_FILLED.cyan(),
        "Ctrl+C".bold()
    );
    println!();

    // Print header for compact format.
    if args.format == "compact" {
        print_compact_header();
    }

    tail_sqlite(log_path, &args).await?;

    Ok(())
}

async fn tail_sqlite(log_path: PathBuf, args: &TailArgs) -> Result<()> {
    let mut cursor = latest_sqlite_seq(&log_path).await?;
    let mut waiting_for_recreation = false;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
        }

        if !log_path.exists() {
            if !waiting_for_recreation {
                style::warning("Log database unavailable, waiting for recreation...");
                waiting_for_recreation = true;
            }
            cursor = 0;
            continue;
        }

        if waiting_for_recreation {
            style::info("Log database available again.");
            waiting_for_recreation = false;
            cursor = latest_sqlite_seq(&log_path).await?;
        }

        let rows = read_sqlite_events_since(&log_path, cursor).await?;
        for (seq, event) in rows {
            cursor = seq;
            if matches_filters(&event, args) {
                format_event(&event, &args.format);
            }
        }
    }

    Ok(())
}

fn print_compact_header() {
    println!(
        "{:8} {:3} {:15} {:20} {:8} {:>8}",
        "TIME".dimmed(),
        "DIR".dimmed(),
        "AGENT".dimmed(),
        "METHOD/TOOL".dimmed(),
        "STATUS".dimmed(),
        "LATENCY".dimmed()
    );
    println!("{}", "\u{2500}".repeat(70).dimmed());
}

async fn show_historical_events(log_path: &PathBuf, args: &TailArgs) -> Result<()> {
    show_historical_events_sqlite(log_path, args).await
}

async fn show_historical_events_sqlite(log_path: &PathBuf, args: &TailArgs) -> Result<()> {
    let path = log_path.clone();
    let events = tokio::task::spawn_blocking(move || query_all_sqlite_events_desc(path.as_path()))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load historical sqlite events: {e}"))??;

    let mut filtered = Vec::new();
    for event in events {
        if matches_filters(&event, args) {
            filtered.push(event);
            if filtered.len() >= args.last {
                break;
            }
        }
    }

    print_historical_events(&filtered, args);
    Ok(())
}

fn print_historical_events(events: &[WrapEvent], args: &TailArgs) {
    style::subtitle(&format!("Last {} events", events.len()));

    if args.format == "compact" {
        print_compact_header();
    }

    for event in events {
        format_event(event, &args.format);
    }
}

async fn latest_sqlite_seq(path: &Path) -> Result<i64> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let conn = open_wrap_events_db(path.as_path())?;
        let seq = conn
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM wrap_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(to_anyhow_db_err)?;
        Ok::<i64, anyhow::Error>(seq)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to query sqlite sequence: {e}"))?
}

async fn read_sqlite_events_since(path: &Path, cursor: i64) -> Result<Vec<(i64, WrapEvent)>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || query_sqlite_events_since(path.as_path(), cursor))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read sqlite events: {e}"))?
}

#[cfg(test)]
fn query_last_sqlite_events(path: &Path, limit: usize) -> Result<Vec<WrapEvent>> {
    let mut events = query_all_sqlite_events_desc(path)?;
    events.truncate(limit);
    events.reverse();
    Ok(events)
}

fn query_all_sqlite_events_desc(path: &Path) -> Result<Vec<WrapEvent>> {
    let conn = open_wrap_events_db(path)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT event_json
            FROM wrap_events
            ORDER BY seq DESC
            "#,
        )
        .map_err(to_anyhow_db_err)?;

    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(to_anyhow_db_err)?;

    let mut events = Vec::new();
    for row in rows {
        let json = row.map_err(to_anyhow_db_err)?;
        if let Ok(event) = serde_json::from_str::<WrapEvent>(&json) {
            events.push(event);
        }
    }

    Ok(events)
}

fn query_sqlite_events_since(path: &Path, cursor: i64) -> Result<Vec<(i64, WrapEvent)>> {
    let conn = open_wrap_events_db(path)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT seq, event_json
            FROM wrap_events
            WHERE seq > ?1
            ORDER BY seq ASC
            "#,
        )
        .map_err(to_anyhow_db_err)?;

    let rows = stmt
        .query_map([cursor], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(to_anyhow_db_err)?;

    let mut events = Vec::new();
    for row in rows {
        let (seq, json) = row.map_err(to_anyhow_db_err)?;
        if let Ok(event) = serde_json::from_str::<WrapEvent>(&json) {
            events.push((seq, event));
        }
    }

    Ok(events)
}

fn open_wrap_events_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(to_anyhow_db_err)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS wrap_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_json TEXT NOT NULL
        );
        "#,
    )
    .map_err(to_anyhow_db_err)?;

    Ok(conn)
}

fn to_anyhow_db_err(error: rusqlite::Error) -> anyhow::Error {
    anyhow::anyhow!(error.to_string())
}

fn matches_filters(event: &WrapEvent, args: &TailArgs) -> bool {
    // Session filter
    if let Some(ref session) = args.session {
        if !event.session_id.contains(session) {
            return false;
        }
    }

    // Method filter
    if let Some(ref method) = args.method {
        if let Some(ref event_method) = event.method {
            if !event_method.contains(method) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Agent filter
    if let Some(ref agent) = args.agent {
        if !event
            .agent
            .name
            .to_lowercase()
            .contains(&agent.to_lowercase())
        {
            return false;
        }
    }

    // Server filter
    if let Some(ref server) = args.server {
        if !event
            .server_name
            .to_lowercase()
            .contains(&server.to_lowercase())
        {
            return false;
        }
    }

    // Tool filter
    if let Some(ref tool) = args.tool {
        if let Some(ref event_tool) = event.tool_name {
            if !event_tool.to_lowercase().contains(&tool.to_lowercase()) {
                return false;
            }
        } else {
            return false;
        }
    }

    // PII only filter
    if args.pii_only && !event.pii_detected {
        return false;
    }

    // Denied only filter
    if args.denied_only && event.policy_allowed != Some(false) {
        return false;
    }

    true
}

fn format_event(event: &WrapEvent, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(event) {
                println!("{}", json);
            }
        }
        "verbose" => {
            format_verbose(event);
        }
        _ => {
            format_compact(event);
        }
    }
}

fn format_compact(event: &WrapEvent) {
    // Time (HH:MM:SS)
    let time = event.timestamp.format("%H:%M:%S").to_string();

    // Direction with colored arrow
    let dir = match event.direction {
        soth_core::types::WrapDirection::In => "\u{2192}".cyan().to_string(), // →
        soth_core::types::WrapDirection::Out => "\u{2190}".green().to_string(), // ←
    };

    // Agent (truncated)
    let agent = style::truncate(&event.agent.name, 15);

    // Method/Tool
    let method_tool = if let Some(ref tool) = event.tool_name {
        format!("{}/{}", event.server_name, tool)
    } else if let Some(ref method) = event.method {
        method.clone()
    } else {
        "-".to_string()
    };
    let method_tool = style::truncate(&method_tool, 20);

    // Status with icon
    let status = match event.policy_allowed {
        Some(true) => format!("{} ALLOW", style::CHECK.green()),
        Some(false) => format!("{} DENY", style::CROSS.red()),
        None => "-".dimmed().to_string(),
    };

    // Latency
    let latency = event
        .latency_ms
        .map(|ms| format!("{}ms", ms))
        .unwrap_or_else(|| "-".dimmed().to_string());

    // PII indicator
    let pii = if event.pii_detected {
        format!(
            " {}",
            format!("[PII: {}]", event.pii_types.join(",")).yellow()
        )
    } else {
        String::new()
    };

    println!(
        "{} {} {:15} {:20} {:8} {:>8}{}",
        time.dimmed(),
        dir,
        agent,
        method_tool,
        status,
        latency,
        pii
    );
}

fn format_verbose(event: &WrapEvent) {
    println!("{}", "\u{2500}".repeat(60).dimmed());
    println!(
        "{} {} {} {} {}",
        event.timestamp.format("%H:%M:%S").to_string().dimmed(),
        style::CIRCLE_FILLED.cyan(),
        event.agent.name.bold(),
        match event.direction {
            soth_core::types::WrapDirection::In => "\u{2192}".cyan().to_string(),
            soth_core::types::WrapDirection::Out => "\u{2190}".green().to_string(),
        },
        event.server_name.bold()
    );

    style::kv(
        "Session",
        &event.session_id[..8.min(event.session_id.len())],
    );
    style::kv(
        "Agent",
        &format!("{} (via {})", event.agent.name, event.agent.detected_from),
    );
    if let Some(ref v) = event.agent.version {
        style::kv("Version", v);
    }
    style::kv("Server", &event.server_name);

    if let Some(ref method) = event.method {
        style::kv("Method", method);
    }
    if let Some(ref tool) = event.tool_name {
        style::kv("Tool", tool);
    }
    if let Some(ref preview) = event.content_preview {
        style::kv("Content", &style::truncate(preview, 50));
    }

    match event.policy_allowed {
        Some(true) => {
            println!("  {}: {} ALLOW", "Policy".dimmed(), style::CHECK.green());
        }
        Some(false) => {
            println!("  {}: {} DENY", "Policy".dimmed(), style::CROSS.red());
            if let Some(ref reason) = event.policy_reason {
                println!("           {}", reason.red());
            }
        }
        None => {}
    }

    if event.pii_detected {
        println!(
            "  {}: {} detected ({})",
            "PII".dimmed(),
            style::WARNING.yellow(),
            event.pii_types.join(", ").yellow()
        );
    }

    if let Some(tokens) = event.token_count {
        style::kv("Tokens", &style::format_number(tokens as u64));
    }
    if let Some(cost) = event.cost_usd {
        style::kv("Cost", &format!("${:.4}", cost).green().to_string());
    }
    if let Some(latency) = event.latency_ms {
        style::kv("Latency", &format!("{}ms", latency));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection};
    use soth_core::EventLogger;
    use tempfile::tempdir;

    fn make_event() -> WrapEvent {
        let agent = AgentInfo::new("Claude Code", DetectionSource::McpInitialize);
        WrapEvent::new("sess-123", "postgres", WrapDirection::In, agent)
            .with_method("tools/call")
            .with_tool_name("query")
    }

    #[test]
    fn test_matches_filters_all_pass() {
        let event = make_event();
        let args = TailArgs {
            session: None,
            method: None,
            agent: None,
            server: None,
            tool: None,
            pii_only: false,
            denied_only: false,
            format: "compact".to_string(),
            last: 0,
        };
        assert!(matches_filters(&event, &args));
    }

    #[test]
    fn test_matches_filters_agent() {
        let event = make_event();
        let mut args = TailArgs {
            session: None,
            method: None,
            agent: Some("Claude".to_string()),
            server: None,
            tool: None,
            pii_only: false,
            denied_only: false,
            format: "compact".to_string(),
            last: 0,
        };
        assert!(matches_filters(&event, &args));

        args.agent = Some("Cursor".to_string());
        assert!(!matches_filters(&event, &args));
    }

    #[test]
    fn test_matches_filters_tool() {
        let event = make_event();
        let mut args = TailArgs {
            session: None,
            method: None,
            agent: None,
            server: None,
            tool: Some("query".to_string()),
            pii_only: false,
            denied_only: false,
            format: "compact".to_string(),
            last: 0,
        };
        assert!(matches_filters(&event, &args));

        args.tool = Some("delete".to_string());
        assert!(!matches_filters(&event, &args));
    }

    #[test]
    fn test_query_sqlite_events_since() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event().with_method("tools/list"));
        logger.log(&make_event().with_method("tools/call"));
        logger.close();

        let rows = query_sqlite_events_since(&db_path, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].0 < rows[1].0);

        let latest_seq = rows[1].0;
        let no_rows = query_sqlite_events_since(&db_path, latest_seq).unwrap();
        assert!(no_rows.is_empty());
    }

    #[test]
    fn test_query_last_sqlite_events() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let logger = EventLogger::new(db_path.clone()).unwrap();
        logger.log(&make_event().with_method("method-1"));
        logger.log(&make_event().with_method("method-2"));
        logger.log(&make_event().with_method("method-3"));
        logger.close();

        let events = query_last_sqlite_events(&db_path, 2).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].method.as_deref(), Some("method-2"));
        assert_eq!(events[1].method.as_deref(), Some("method-3"));
    }
}
