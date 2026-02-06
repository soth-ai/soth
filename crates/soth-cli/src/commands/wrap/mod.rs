//! Wrap command - Wrap MCP servers for interception
//!
//! Usage:
//!   soth wrap -- npx -y @modelcontextprotocol/server-postgres
//!   soth wrap --name "postgres-prod" -- npx -y @modelcontextprotocol/server-postgres
//!   soth wrap --record -- npx -y @modelcontextprotocol/server-postgres

pub mod agent_detect;

use anyhow::{Context, Result};
use clap::Args;
use soth_core::types::{AgentInfo, DetectionSource, WrapDirection, WrapEvent};
use soth_core::{generate_session_name, MessageDirection, SessionRecorder, SessionStorage};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

/// Arguments for the wrap command
#[derive(Args, Debug)]
pub struct WrapArgs {
    /// Human-readable name for this server
    #[arg(long)]
    pub name: Option<String>,

    /// Override agent detection with a specific agent name
    #[arg(long)]
    pub agent: Option<String>,

    /// Config file path (optional, for policy/observe settings)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Disable event logging
    #[arg(long)]
    pub no_log: bool,

    /// Record full session for replay (stores complete message payloads)
    #[arg(long)]
    pub record: bool,

    /// Session name for recording (auto-generated if not specified)
    #[arg(long)]
    pub session_name: Option<String>,

    /// Command and arguments to wrap (after --)
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Session state shared across tasks
struct WrapSession {
    session_id: String,
    server_name: String,
    agent: RwLock<AgentInfo>,
    log_writer: Option<std::sync::Mutex<BufWriter<File>>>,
    request_times: RwLock<std::collections::HashMap<String, Instant>>,
    /// Session recorder for full message capture (optional)
    recorder: Option<Arc<SessionRecorder>>,
}

impl WrapSession {
    fn new(
        server_name: String,
        agent: AgentInfo,
        log_path: Option<PathBuf>,
        record: bool,
        session_name: Option<String>,
    ) -> Result<Self> {
        let session_id = uuid::Uuid::new_v4().to_string();

        let log_writer = if let Some(path) = log_path {
            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("Failed to open log file: {:?}", path))?;

            Some(std::sync::Mutex::new(BufWriter::new(file)))
        } else {
            None
        };

        // Create session recorder if recording is enabled
        let recorder = if record {
            // Use provided name, or generate a beautiful adjective-noun name
            let name = session_name.unwrap_or_else(generate_session_name);
            info!("Recording session: {}", name);
            Some(Arc::new(SessionRecorder::new(
                session_id.clone(),
                name,
                server_name.clone(),
            )))
        } else {
            None
        };

        Ok(Self {
            session_id,
            server_name,
            agent: RwLock::new(agent),
            log_writer,
            request_times: RwLock::new(std::collections::HashMap::new()),
            recorder,
        })
    }

    async fn log_event(&self, event: &WrapEvent) {
        if let Some(ref writer) = self.log_writer {
            if let Ok(json) = serde_json::to_string(event) {
                if let Ok(mut w) = writer.lock() {
                    let _ = writeln!(w, "{}", json);
                    let _ = w.flush();
                }
            }
        }
    }

    /// Record a message for session replay
    async fn record_message(&self, content: &str, direction: MessageDirection) {
        if let Some(ref recorder) = self.recorder {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                if let Err(e) = recorder.record_message(json, direction).await {
                    debug!("Failed to record message: {}", e);
                }
            }
        }
    }

    async fn update_agent(&self, agent: AgentInfo) {
        let mut current = self.agent.write().await;
        // Only update if we have better detection
        if matches!(current.detected_from, DetectionSource::Unknown)
            || (matches!(current.detected_from, DetectionSource::Environment)
                && matches!(agent.detected_from, DetectionSource::McpInitialize))
        {
            *current = agent.clone();
        }

        // Also update recorder's agent info
        if let Some(ref recorder) = self.recorder {
            recorder
                .set_agent_info(agent.name.clone(), agent.version.clone())
                .await;
        }
    }

    async fn record_request_time(&self, id: &str) {
        let mut times = self.request_times.write().await;
        times.insert(id.to_string(), Instant::now());
    }

    async fn get_latency(&self, id: &str) -> Option<u64> {
        let times = self.request_times.read().await;
        times.get(id).map(|start| start.elapsed().as_millis() as u64)
    }

    /// Finalize the session recording and save to disk
    async fn finalize_recording(&self) -> Result<Option<PathBuf>> {
        if let Some(ref recorder) = self.recorder {
            // Clone the recorder to finalize (consumes it)
            let recorder_clone = Arc::try_unwrap(recorder.clone())
                .unwrap_or_else(|arc| (*arc).clone());

            let session = recorder_clone.finalize().await?;
            let storage = SessionStorage::new()?;
            let path = storage.save(&session)?;

            info!(
                "Session recorded: {} ({} messages)",
                session.name,
                session.messages.len()
            );

            return Ok(Some(path));
        }
        Ok(None)
    }
}

/// Run the wrap command
pub async fn run(args: WrapArgs) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: soth wrap -- <command> [args...]");
    }

    let (cmd, cmd_args) = (&args.command[0], &args.command[1..]);

    // Derive server name
    let server_name = args.name.unwrap_or_else(|| derive_server_name(cmd, cmd_args));

    // Get initial agent info
    let initial_agent = if let Some(ref agent_name) = args.agent {
        AgentInfo::new(agent_name.clone(), DetectionSource::CommandLine)
    } else {
        agent_detect::detect_agent()
    };

    // Set up log path
    let log_path = if args.no_log {
        None
    } else {
        Some(get_default_log_path()?)
    };

    let session = Arc::new(WrapSession::new(
        server_name.clone(),
        initial_agent,
        log_path,
        args.record,
        args.session_name,
    )?);

    info!(
        "Wrapping server '{}' (session: {}{})",
        server_name,
        session.session_id,
        if args.record { ", recording" } else { "" }
    );

    // Spawn the upstream MCP server
    let mut child = spawn_server(cmd, cmd_args)?;

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Set up channels for bidirectional communication
    let (to_server_tx, to_server_rx) = mpsc::channel::<String>(100);
    let (from_server_tx, from_server_rx) = mpsc::channel::<String>(100);

    // Task: Read from our stdin, process, send to server
    let session_clone = session.clone();
    let stdin_task = tokio::spawn(async move {
        read_from_stdin(session_clone, to_server_tx).await;
    });

    // Task: Write to server stdin
    let write_to_server_task = tokio::spawn(async move {
        write_to_child(child_stdin, to_server_rx).await;
    });

    // Task: Read from server stdout, process, send to our stdout
    let session_clone = session.clone();
    let read_from_server_task = tokio::spawn(async move {
        read_from_child(session_clone, child_stdout, from_server_tx).await;
    });

    // Task: Write to our stdout
    let write_to_stdout_task = tokio::spawn(async move {
        write_to_stdout(from_server_rx).await;
    });

    // Wait for server to exit or any task to fail
    tokio::select! {
        status = child.wait() => {
            info!("Server process exited: {:?}", status);
        }
        _ = stdin_task => {
            debug!("Stdin task finished");
        }
        _ = write_to_server_task => {
            debug!("Write to server task finished");
        }
        _ = read_from_server_task => {
            debug!("Read from server task finished");
        }
        _ = write_to_stdout_task => {
            debug!("Write to stdout task finished");
        }
    }

    // Finalize session recording if enabled
    if let Some(path) = session.finalize_recording().await? {
        eprintln!("Session saved to: {}", path.display());
    }

    Ok(())
}

fn spawn_server(cmd: &str, args: &[String]) -> Result<Child> {
    Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit()) // Pass through stderr
        .spawn()
        .with_context(|| format!("Failed to spawn server: {} {:?}", cmd, args))
}

async fn read_from_stdin(session: Arc<WrapSession>, tx: mpsc::Sender<String>) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("EOF on stdin");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Process the message
                process_inbound_message(&session, trimmed).await;

                // Forward to server
                if tx.send(line.clone()).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                error!("Stdin read error: {}", e);
                break;
            }
        }
    }
}

async fn write_to_child(
    mut writer: tokio::process::ChildStdin,
    mut rx: mpsc::Receiver<String>,
) {
    while let Some(line) = rx.recv().await {
        if writer.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
}

async fn read_from_child(
    session: Arc<WrapSession>,
    stdout: tokio::process::ChildStdout,
    tx: mpsc::Sender<String>,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("EOF from server");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Process the message
                process_outbound_message(&session, trimmed).await;

                // Forward to our stdout via channel
                if tx.send(format!("{}\n", trimmed)).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                error!("Server stdout read error: {}", e);
                break;
            }
        }
    }
}

async fn write_to_stdout(mut rx: mpsc::Receiver<String>) {
    let mut stdout = tokio::io::stdout();

    while let Some(line) = rx.recv().await {
        if stdout.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if stdout.flush().await.is_err() {
            break;
        }
    }
}

async fn process_inbound_message(session: &WrapSession, content: &str) {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);

    let agent = session.agent.read().await.clone();
    let mut event = WrapEvent::new(
        &session.session_id,
        &session.server_name,
        WrapDirection::In,
        agent,
    );

    if let Ok(msg) = &parsed {
        // Extract method
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            event = event.with_method(method);

            // Handle initialize message - extract agent info
            if method == "initialize" {
                if let Some(params) = msg.get("params") {
                    if let Some(agent) = agent_detect::detect_from_initialize(params) {
                        session.update_agent(agent).await;
                        // Update event with new agent info
                        let updated_agent = session.agent.read().await.clone();
                        event.agent = updated_agent;
                    }
                }
            }

            // Handle tools/call - extract tool name
            if method == "tools/call" {
                if let Some(params) = msg.get("params") {
                    if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
                        event = event.with_tool_name(name);
                    }
                }
            }
        }

        // Record request time for latency calculation
        if let Some(id) = msg.get("id") {
            let id_str = match id {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => "unknown".to_string(),
            };
            session.record_request_time(&id_str).await;
        }

        // Add full content and preview
        event = event
            .with_content(content)
            .with_content_preview(truncate_content(content, 200));
    }

    // Record full message for session replay
    session.record_message(content, MessageDirection::ToServer).await;

    session.log_event(&event).await;
    debug!("→ {} {}", event.method.as_deref().unwrap_or("-"), event.tool_name.as_deref().unwrap_or(""));
}

async fn process_outbound_message(session: &WrapSession, content: &str) {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);

    let agent = session.agent.read().await.clone();
    let mut event = WrapEvent::new(
        &session.session_id,
        &session.server_name,
        WrapDirection::Out,
        agent,
    );

    if let Ok(msg) = &parsed {
        // Check if it's a response (has result or error)
        let is_response = msg.get("result").is_some() || msg.get("error").is_some();

        if is_response {
            // Calculate latency
            if let Some(id) = msg.get("id") {
                let id_str = match id {
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::String(s) => s.clone(),
                    _ => "unknown".to_string(),
                };
                if let Some(latency) = session.get_latency(&id_str).await {
                    event = event.with_latency(latency);
                }
            }

            // Check for error
            if msg.get("error").is_some() {
                event = event.with_method("error");
            }
        } else {
            // It's a notification from server
            if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                event = event.with_method(method);
            }
        }

        // Add full content and preview
        event = event
            .with_content(content)
            .with_content_preview(truncate_content(content, 200));
    }

    // Record full message for session replay
    session.record_message(content, MessageDirection::ToClient).await;

    session.log_event(&event).await;
    debug!("← {} ({}ms)", event.method.as_deref().unwrap_or("response"), event.latency_ms.unwrap_or(0));
}

fn derive_server_name(cmd: &str, args: &[String]) -> String {
    // Try to find a meaningful name from the command
    let cmd_lower = cmd.to_lowercase();

    // If using npx, look at the package name
    if cmd_lower.contains("npx") {
        for arg in args {
            if arg.starts_with("@") || (!arg.starts_with("-") && arg.contains("/")) {
                // Extract the package name
                let name = arg
                    .trim_start_matches("@")
                    .split('/')
                    .last()
                    .unwrap_or(arg)
                    .trim_start_matches("server-")
                    .trim_end_matches("-server");
                return name.to_string();
            }
        }
    }

    // If using uvx or pipx, similar logic
    if cmd_lower.contains("uvx") || cmd_lower.contains("pipx") {
        for arg in args {
            if !arg.starts_with("-") {
                return arg
                    .trim_start_matches("mcp-")
                    .trim_end_matches("-mcp")
                    .to_string();
            }
        }
    }

    // Default: use the command name
    std::path::Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn get_default_log_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".soth").join("logs").join("events.jsonl"))
}

fn truncate_content(content: &str, max_len: usize) -> String {
    if content.len() <= max_len {
        content.to_string()
    } else {
        format!("{}...", &content[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_server_name_npx() {
        let name = derive_server_name(
            "npx",
            &[
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ],
        );
        assert_eq!(name, "postgres");
    }

    #[test]
    fn test_derive_server_name_npx_filesystem() {
        let name = derive_server_name(
            "npx",
            &[
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
                "/tmp".to_string(),
            ],
        );
        assert_eq!(name, "filesystem");
    }

    #[test]
    fn test_derive_server_name_uvx() {
        let name = derive_server_name("uvx", &["mcp-server-git".to_string()]);
        assert_eq!(name, "server-git");
    }

    #[test]
    fn test_derive_server_name_direct() {
        let name = derive_server_name("/usr/local/bin/my-mcp-server", &[]);
        assert_eq!(name, "my-mcp-server");
    }

    #[test]
    fn test_truncate_content() {
        assert_eq!(truncate_content("short", 10), "short");
        assert_eq!(truncate_content("this is a longer string", 10), "this is a ...");
    }
}
