//! Session recording and replay commands
//!
//! Commands for managing recorded MCP sessions:
//! - `soth session list` - List all recorded sessions
//! - `soth session show <id>` - Show session details
//! - `soth session replay <id>` - Replay a session
//! - `soth session delete <id>` - Delete a session
//! - `soth session export <id>` - Export session to file

use crate::style;
use clap::Subcommand;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, Table};
use owo_colors::OwoColorize;
use soth_core::{
    MessageDirection, RecordedSession, ReplayEvent, ReplayOptions, ReplaySpeed, SessionRecordError,
    SessionReplayer, SessionStorage,
};
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Subcommand)]
pub enum SessionCommands {
    /// List all recorded sessions
    List {
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Filter by server name
        #[arg(long)]
        server: Option<String>,

        /// Limit number of results
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Show session details
    Show {
        /// Session ID or name
        session: String,

        /// Show full message content
        #[arg(short, long)]
        full: bool,

        /// Filter by method
        #[arg(long)]
        method: Option<String>,

        /// Filter by direction (in/out)
        #[arg(long)]
        direction: Option<String>,
    },

    /// Replay a recorded session
    Replay {
        /// Session ID or name
        session: String,

        /// Replay speed multiplier (e.g., 2 for 2x speed, 0 for instant)
        #[arg(short, long, default_value = "1")]
        speed: f64,

        /// Start from message index
        #[arg(long)]
        from: Option<usize>,

        /// End at message index
        #[arg(long)]
        to: Option<usize>,

        /// Filter by method
        #[arg(long)]
        method: Option<String>,

        /// Step-by-step mode (press Enter for each message)
        #[arg(long)]
        step: bool,

        /// Output format (compact, json, verbose)
        #[arg(short, long, default_value = "compact")]
        format: String,
    },

    /// Delete a recorded session
    Delete {
        /// Session ID or name
        session: String,

        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Export session to file
    Export {
        /// Session ID or name
        session: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Output format (json, jsonl)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Import session from file
    Import {
        /// Input file path
        input: PathBuf,
    },

    /// Show recording statistics
    Stats,
}

pub async fn run(action: SessionCommands) -> anyhow::Result<()> {
    match action {
        SessionCommands::List {
            format,
            server,
            limit,
        } => run_list(format, server, limit).await,
        SessionCommands::Show {
            session,
            full,
            method,
            direction,
        } => run_show(session, full, method, direction).await,
        SessionCommands::Replay {
            session,
            speed,
            from,
            to,
            method,
            step,
            format,
        } => run_replay(session, speed, from, to, method, step, format).await,
        SessionCommands::Delete { session, force } => run_delete(session, force).await,
        SessionCommands::Export {
            session,
            output,
            format,
        } => run_export(session, output, format).await,
        SessionCommands::Import { input } => run_import(input).await,
        SessionCommands::Stats => run_stats().await,
    }
}

async fn run_list(
    format: String,
    server_filter: Option<String>,
    limit: Option<usize>,
) -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let mut sessions = storage.list()?;

    // Apply server filter
    if let Some(ref server) = server_filter {
        sessions.retain(|s| s.server_name.contains(server));
    }

    // Apply limit
    if let Some(limit) = limit {
        sessions.truncate(limit);
    }

    if sessions.is_empty() {
        println!("{}", "No recorded sessions found.".dimmed());
        return Ok(());
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }

    // Table format
    style::header("Recorded Sessions");

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["Name", "Server", "Messages", "Duration", "Started"]);

    for session in sessions {
        let duration = session
            .duration_ms
            .map(|ms| format_duration(ms))
            .unwrap_or_else(|| "-".to_string());

        let started = session.started_at.format("%Y-%m-%d %H:%M").to_string();

        table.add_row(vec![
            Cell::new(&session.name),
            Cell::new(&session.server_name).fg(Color::Cyan),
            Cell::new(session.message_count),
            Cell::new(duration),
            Cell::new(started).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}");
    Ok(())
}

async fn run_show(
    session_id: String,
    full: bool,
    method_filter: Option<String>,
    direction_filter: Option<String>,
) -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let session = find_session(&storage, &session_id)?;

    // Parse direction filter
    let dir_filter = direction_filter.as_ref().map(|d| match d.as_str() {
        "in" | "toserver" | "request" => MessageDirection::ToServer,
        "out" | "toclient" | "response" => MessageDirection::ToClient,
        _ => MessageDirection::ToServer,
    });

    // Header
    style::header(&format!("Session: {}", session.name));

    // Metadata
    println!("  {} {}", "ID:".dimmed(), session.id);
    println!("  {} {}", "Server:".dimmed(), session.metadata.server_name);
    if let Some(ref agent) = session.metadata.agent_name {
        let version = session
            .metadata
            .agent_version
            .as_deref()
            .unwrap_or("unknown");
        println!("  {} {} ({})", "Agent:".dimmed(), agent, version);
    }
    println!(
        "  {} {}",
        "Started:".dimmed(),
        session.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(duration) = session.duration_ms() {
        println!("  {} {}", "Duration:".dimmed(), format_duration(duration));
    }
    println!("  {} {}", "Messages:".dimmed(), session.messages.len());
    if session.metadata.total_tokens > 0 {
        println!(
            "  {} {}",
            "Total Tokens:".dimmed(),
            session.metadata.total_tokens
        );
    }
    if !session.metadata.tags.is_empty() {
        println!(
            "  {} {}",
            "Tags:".dimmed(),
            session.metadata.tags.join(", ")
        );
    }

    style::header("Messages");

    // Filter messages
    let messages: Vec<_> = session
        .messages
        .iter()
        .enumerate()
        .filter(|(_, msg)| {
            if let Some(ref dir) = dir_filter {
                if msg.direction != *dir {
                    return false;
                }
            }
            if let Some(ref method) = method_filter {
                if let Some(msg_method) = msg.method() {
                    if !msg_method.contains(method.as_str()) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        })
        .collect();

    for (idx, msg) in messages {
        let direction_symbol = match msg.direction {
            MessageDirection::ToServer => "→".green().to_string(),
            MessageDirection::ToClient => "←".blue().to_string(),
        };

        let method = msg.method().unwrap_or("-");
        let time = format!("+{}ms", msg.relative_time_ms);

        print!(
            "  {:>4} {} {} {}",
            idx.to_string().dimmed(),
            direction_symbol,
            method.cyan(),
            time.dimmed()
        );

        if msg.metadata.pii_detected {
            print!(" {}", "[PII]".red());
        }
        if msg.metadata.policy_allowed == Some(false) {
            print!(" {}", "[DENIED]".red());
        }

        println!();

        if full {
            let content = serde_json::to_string_pretty(&msg.content)?;
            for line in content.lines() {
                println!("        {}", line.dimmed());
            }
            println!();
        }
    }

    Ok(())
}

async fn run_replay(
    session_id: String,
    speed: f64,
    from: Option<usize>,
    to: Option<usize>,
    method_filter: Option<String>,
    step_mode: bool,
    format: String,
) -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let session = find_session(&storage, &session_id)?;

    let replay_speed = if speed <= 0.0 {
        ReplaySpeed::Fast
    } else if (speed - 1.0).abs() < 0.01 {
        ReplaySpeed::RealTime
    } else {
        ReplaySpeed::Custom(speed)
    };

    let mut options = ReplayOptions {
        speed: replay_speed,
        start_index: from.unwrap_or(0),
        end_index: to,
        direction_filter: None,
        method_filter,
        step_mode,
    };

    if step_mode {
        options.step_mode = true;
    }

    let session_name = session.name.clone();
    let replayer = SessionReplayer::new(session, options);
    let total = replayer.total_messages();

    println!(
        "{} {} ({} messages)",
        "Replaying:".green(),
        session_name,
        total
    );

    let speed_str = match replay_speed {
        ReplaySpeed::RealTime => "1x (real-time)".to_string(),
        ReplaySpeed::Fast => "instant".to_string(),
        ReplaySpeed::Custom(m) => format!("{}x", m),
    };
    println!("  Speed: {}", speed_str);
    println!();

    // Create channel for replay events
    let (tx, mut rx) = mpsc::channel::<ReplayEvent>(100);

    // Spawn replay task
    let replay_handle = tokio::spawn(async move { replayer.run(tx).await });

    // Process events
    while let Some(event) = rx.recv().await {
        match event {
            ReplayEvent::Started {
                session_name,
                total_messages,
                ..
            } => {
                if format != "json" {
                    println!(
                        "{} {} ({} messages)",
                        "Started:".green(),
                        session_name,
                        total_messages
                    );
                }
            }
            ReplayEvent::Message {
                index,
                total,
                message,
            } => {
                if format == "json" {
                    println!("{}", serde_json::to_string(&message.content)?);
                } else if format == "verbose" {
                    print_message_verbose(index, total, &message);
                } else {
                    print_message_compact(index, total, &message);
                }

                // In step mode, wait for user input
                if step_mode {
                    print!("Press Enter to continue...");
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                }
            }
            ReplayEvent::Completed {
                messages_replayed, ..
            } => {
                if format != "json" {
                    println!();
                    println!(
                        "{} {} messages replayed",
                        "Completed:".green(),
                        messages_replayed
                    );
                }
            }
            ReplayEvent::Error { message } => {
                eprintln!("{} {}", "Error:".red(), message);
            }
            _ => {}
        }
    }

    // Wait for replay to complete
    replay_handle.await??;

    Ok(())
}

fn print_message_compact(index: usize, total: usize, msg: &soth_core::RecordedMessage) {
    let direction_symbol = match msg.direction {
        MessageDirection::ToServer => "→".green().to_string(),
        MessageDirection::ToClient => "←".blue().to_string(),
    };

    let method = msg.method().unwrap_or("-");
    let progress = format!("[{}/{}]", index + 1, total);

    println!(
        "  {} {} {} +{}ms",
        progress.dimmed(),
        direction_symbol,
        method.cyan(),
        msg.relative_time_ms
    );
}

fn print_message_verbose(index: usize, total: usize, msg: &soth_core::RecordedMessage) {
    let direction_symbol = match msg.direction {
        MessageDirection::ToServer => "→ TO SERVER".green().to_string(),
        MessageDirection::ToClient => "← TO CLIENT".blue().to_string(),
    };

    let method = msg.method().unwrap_or("-");
    let progress = format!("[{}/{}]", index + 1, total);

    println!(
        "{} {} {} +{}ms",
        progress.dimmed(),
        direction_symbol,
        method.cyan(),
        msg.relative_time_ms
    );

    let content = serde_json::to_string_pretty(&msg.content).unwrap_or_default();
    for line in content.lines() {
        println!("    {}", line.dimmed());
    }
    println!();
}

async fn run_delete(session_id: String, force: bool) -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let session = find_session(&storage, &session_id)?;

    if !force {
        print!(
            "Delete session '{}' with {} messages? [y/N] ",
            session.name,
            session.messages.len()
        );
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    storage.delete(&session.id)?;
    println!("{} Session '{}' deleted", "Success:".green(), session.name);
    Ok(())
}

async fn run_export(session_id: String, output: PathBuf, format: String) -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let session = find_session(&storage, &session_id)?;

    let content = match format.as_str() {
        "jsonl" => {
            let mut lines = Vec::new();
            for msg in &session.messages {
                lines.push(serde_json::to_string(msg)?);
            }
            lines.join("\n")
        }
        _ => serde_json::to_string_pretty(&session)?,
    };

    std::fs::write(&output, content)?;
    println!("{} Exported to {}", "Success:".green(), output.display());
    Ok(())
}

async fn run_import(input: PathBuf) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(&input)?;
    let session: RecordedSession = serde_json::from_str(&content)?;

    let storage = SessionStorage::new()?;
    let path = storage.save(&session)?;

    println!(
        "{} Imported session '{}' ({} messages)",
        "Success:".green(),
        session.name,
        session.messages.len()
    );
    println!("  Saved to: {}", path.display());
    Ok(())
}

async fn run_stats() -> anyhow::Result<()> {
    let storage = SessionStorage::new()?;
    let sessions = storage.list()?;

    let total_sessions = sessions.len();
    let total_messages: usize = sessions.iter().map(|s| s.message_count).sum();
    let total_duration_ms: u64 = sessions.iter().filter_map(|s| s.duration_ms).sum();

    style::header("Recording Statistics");
    println!("  {} {}", "Total Sessions:".dimmed(), total_sessions);
    println!("  {} {}", "Total Messages:".dimmed(), total_messages);
    println!(
        "  {} {}",
        "Total Duration:".dimmed(),
        format_duration(total_duration_ms)
    );

    if !sessions.is_empty() {
        println!();
        println!(
            "  {} {}",
            "Avg Messages/Session:".dimmed(),
            total_messages / total_sessions
        );

        // Top servers
        let mut server_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for session in &sessions {
            *server_counts
                .entry(session.server_name.clone())
                .or_insert(0) += 1;
        }

        let mut servers: Vec<_> = server_counts.into_iter().collect();
        servers.sort_by(|a, b| b.1.cmp(&a.1));

        println!();
        println!("  {}", "Top Servers:".dimmed());
        for (server, count) in servers.iter().take(5) {
            println!("    {} ({})", server.cyan(), count);
        }
    }

    Ok(())
}

/// Find a session by ID or name
fn find_session(
    storage: &SessionStorage,
    id_or_name: &str,
) -> Result<RecordedSession, anyhow::Error> {
    // Try loading by exact ID first
    if let Ok(session) = storage.load(id_or_name) {
        return Ok(session);
    }

    // Search by name
    let sessions = storage.list()?;
    for summary in sessions {
        if summary.name == id_or_name || summary.name.contains(id_or_name) {
            return storage.load(&summary.id).map_err(Into::into);
        }
    }

    Err(SessionRecordError::NotFound(id_or_name.to_string()).into())
}

/// Format duration in human-readable form
fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    }
}
