//! Tail command - Stream live events
//!
//! Enhanced version with filtering by agent, server, tool, and output formats.
//! Uses notify-based file watching for instant event detection (<10ms latency).

use crate::style;
use anyhow::Result;
use clap::Args;
use owo_colors::OwoColorize;
use soth_core::types::WrapEvent;
use soth_core::watch::{FileWatcher, WatchEvent};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info};

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
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home.join(".soth").join("logs").join("events.jsonl"))
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

    // Show historical events if requested
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

    // Print header for compact format
    if args.format == "compact" {
        print_compact_header();
    }

    // Skip to end of file - we only want new events
    let metadata = tokio::fs::metadata(&log_path).await?;
    let mut position = metadata.len();

    // Create file watcher for instant notifications
    let watcher_result = FileWatcher::new(log_path.clone());
    let use_polling = watcher_result.is_err();

    if use_polling {
        style::warning("Using polling mode (file watcher unavailable)");
    } else {
        debug!("Using notify-based file watching for instant events");
    }

    let mut watcher = watcher_result.ok();
    let mut line = String::new();

    loop {
        // Wait for file change - either via notify or polling
        if let Some(ref mut w) = watcher {
            // Use notify for instant detection
            tokio::select! {
                event = w.next() => {
                    match event {
                        Some(WatchEvent::Modified) | Some(WatchEvent::Created) => {
                            // File changed, process new content
                        }
                        Some(WatchEvent::Removed) => {
                            style::warning("Log file removed, waiting for recreation...");
                            continue;
                        }
                        Some(WatchEvent::Error(e)) => {
                            style::warning(&format!("Watch error: {e}"));
                            continue;
                        }
                        None => {
                            // Watcher closed
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        } else {
            // Fallback to polling
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }

        // Check for new content
        let current_metadata = match tokio::fs::metadata(&log_path).await {
            Ok(m) => m,
            Err(_) => continue, // File may have been removed temporarily
        };

        if current_metadata.len() > position {
            // Reopen and read new content
            let file = File::open(&log_path).await?;
            let mut reader = BufReader::new(file);

            // Skip to position
            let mut skipped = 0u64;
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(n) => {
                        skipped += n as u64;
                        if skipped <= position {
                            continue;
                        }

                        // Try to parse as WrapEvent first, fall back to generic JSON
                        if let Ok(event) = serde_json::from_str::<WrapEvent>(&line) {
                            if matches_filters(&event, &args) {
                                format_event(&event, &args.format);
                            }
                        } else if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                            // Legacy format
                            if matches_legacy_filters(&event, &args) {
                                format_legacy_event(&event, &args.format);
                            }
                        }
                    }
                    Err(e) => {
                        style::error(&format!("Read error: {e}"));
                        break;
                    }
                }
            }

            position = current_metadata.len();
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
    let content = tokio::fs::read_to_string(log_path).await?;
    let lines: Vec<&str> = content.lines().collect();

    // Collect matching events
    let mut events: Vec<WrapEvent> = Vec::new();
    for line in lines.iter().rev() {
        if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
            if matches_filters(&event, args) {
                events.push(event);
                if events.len() >= args.last {
                    break;
                }
            }
        }
    }

    // Print in chronological order
    events.reverse();

    style::subtitle(&format!("Last {} events", events.len()));

    if args.format == "compact" {
        print_compact_header();
    }

    for event in events {
        format_event(&event, &args.format);
    }

    Ok(())
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
        if !event.agent.name.to_lowercase().contains(&agent.to_lowercase()) {
            return false;
        }
    }

    // Server filter
    if let Some(ref server) = args.server {
        if !event.server_name.to_lowercase().contains(&server.to_lowercase()) {
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

fn matches_legacy_filters(event: &serde_json::Value, args: &TailArgs) -> bool {
    // Session filter
    if let Some(ref session) = args.session {
        if event.get("session_id").and_then(|s| s.as_str()) != Some(session) {
            return false;
        }
    }

    // Method filter
    if let Some(ref method) = args.method {
        if event.get("method").and_then(|m| m.as_str()) != Some(method) {
            return false;
        }
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
        soth_core::types::WrapDirection::In => "\u{2192}".cyan().to_string(),  // →
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
        format!(" {}", format!("[PII: {}]", event.pii_types.join(",")).yellow())
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
            println!(
                "  {}: {} ALLOW",
                "Policy".dimmed(),
                style::CHECK.green()
            );
        }
        Some(false) => {
            println!(
                "  {}: {} DENY",
                "Policy".dimmed(),
                style::CROSS.red()
            );
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

fn format_legacy_event(event: &serde_json::Value, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(event) {
                println!("{}", json);
            }
        }
        _ => {
            // Simple text format for legacy events
            let timestamp = event
                .get("timestamp")
                .and_then(|t| t.as_str())
                .unwrap_or("-");
            let direction = event
                .get("direction")
                .and_then(|d| d.as_str())
                .unwrap_or("?");
            let method = event
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("-");

            let time = timestamp.split('T').nth(1).unwrap_or(timestamp);
            let time = time.split('.').next().unwrap_or(time);

            let arrow = if direction == "in" {
                "\u{2192}".cyan().to_string()
            } else {
                "\u{2190}".green().to_string()
            };
            println!("{} {} {}", time.dimmed(), arrow, method);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection};

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
}
