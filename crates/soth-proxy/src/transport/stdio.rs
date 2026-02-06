//! stdio transport implementation
//!
//! Provides bidirectional communication over stdin/stdout for CLI tools.
//! Based on mcp-reticle's stdio proxy pattern.

use super::{AsyncMessageHandler, Transport, TransportConfig};
use crate::error::ProxyError;
use crate::protocol::JsonRpcMessage;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// stdio transport for MCP communication
pub struct StdioTransport {
    /// Configuration
    config: TransportConfig,
    /// Message handler
    handler: Option<AsyncMessageHandler>,
    /// Child process (if spawned)
    child: Option<Child>,
    /// Sender for outgoing messages
    outgoing_tx: Option<mpsc::Sender<JsonRpcMessage>>,
    /// Whether the transport is running
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl StdioTransport {
    /// Create a new stdio transport
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            handler: None,
            child: None,
            outgoing_tx: None,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Create a stdio transport that spawns a child process
    pub fn with_command(
        command: &str,
        args: &[&str],
        config: TransportConfig,
    ) -> Result<Self, ProxyError> {
        let child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| ProxyError::Transport(format!("Failed to spawn process: {e}")))?;

        Ok(Self {
            config,
            handler: None,
            child: Some(child),
            outgoing_tx: None,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Read loop for incoming messages
    async fn read_loop(
        mut reader: BufReader<ChildStdout>,
        handler: AsyncMessageHandler,
        outgoing_tx: mpsc::Sender<JsonRpcMessage>,
        cancel: CancellationToken,
    ) {
        let mut line = String::new();

        loop {
            line.clear();

            tokio::select! {
                _ = cancel.cancelled() => {
                    debug!("Read loop cancelled");
                    break;
                }
                result = reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => {
                            info!("EOF on stdin, exiting read loop");
                            break;
                        }
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }

                            match JsonRpcMessage::from_json_str(trimmed) {
                                Ok(msg) => {
                                    debug!("Received message: {:?}", msg);

                                    // Process through handler
                                    match handler(msg).await {
                                        Ok(Some(response)) => {
                                            if let Err(e) = outgoing_tx.send(response).await {
                                                error!("Failed to queue response: {}", e);
                                            }
                                        }
                                        Ok(None) => {
                                            // No response needed (notification or forwarded)
                                        }
                                        Err(e) => {
                                            error!("Handler error: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to parse message: {} - {}", e, trimmed);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Write loop for outgoing messages
    async fn write_loop(
        mut writer: ChildStdin,
        mut rx: mpsc::Receiver<JsonRpcMessage>,
        cancel: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    debug!("Write loop cancelled");
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(message) => {
                            match message.to_string() {
                                Ok(json) => {
                                    let line = format!("{json}\n");
                                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                                        error!("Write error: {}", e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        error!("Flush error: {}", e);
                                        break;
                                    }
                                    debug!("Sent message: {}", json);
                                }
                                Err(e) => {
                                    error!("Failed to serialize message: {}", e);
                                }
                            }
                        }
                        None => {
                            debug!("Outgoing channel closed");
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let handler = self
            .handler
            .take()
            .ok_or_else(|| ProxyError::Transport("No handler set".to_string()))?;

        let child = self
            .child
            .as_mut()
            .ok_or_else(|| ProxyError::Transport("No child process".to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ProxyError::Transport("No stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProxyError::Transport("No stdout".to_string()))?;

        let reader = BufReader::new(stdout);
        let (tx, rx) = mpsc::channel(self.config.buffer_size);

        self.outgoing_tx = Some(tx.clone());
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let running = self.running.clone();
        let cancel_clone = cancel.clone();

        // Spawn read task
        tokio::spawn(async move {
            Self::read_loop(reader, handler, tx, cancel_clone).await;
            running.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        // Spawn write task
        tokio::spawn(async move {
            Self::write_loop(stdin, rx, cancel).await;
        });

        info!("stdio transport started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ProxyError> {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);

        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
        }

        info!("stdio transport stopped");
        Ok(())
    }

    async fn send(&self, message: JsonRpcMessage) -> Result<(), ProxyError> {
        if let Some(ref tx) = self.outgoing_tx {
            tx.send(message)
                .await
                .map_err(|e| ProxyError::Transport(format!("Send failed: {e}")))?;
        }
        Ok(())
    }

    fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    fn name(&self) -> &'static str {
        "stdio"
    }
}

/// Stdio proxy that connects a client to an upstream server
pub struct StdioProxy {
    /// Upstream command
    command: String,
    /// Upstream arguments
    args: Vec<String>,
    /// Configuration
    config: TransportConfig,
    /// Pipeline handler
    handler: Option<AsyncMessageHandler>,
}

impl StdioProxy {
    /// Create a new stdio proxy
    pub fn new(command: impl Into<String>, args: Vec<String>, config: TransportConfig) -> Self {
        Self {
            command: command.into(),
            args,
            config,
            handler: None,
        }
    }

    /// Set the pipeline handler
    pub fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    /// Run the proxy, connecting stdin/stdout to the upstream process
    pub async fn run(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let handler = self
            .handler
            .take()
            .ok_or_else(|| ProxyError::Transport("No handler set".to_string()))?;

        // Spawn upstream process
        let mut upstream = Command::new(&self.command)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| ProxyError::Transport(format!("Failed to spawn upstream: {e}")))?;

        let upstream_stdin = upstream
            .stdin
            .take()
            .ok_or_else(|| ProxyError::Transport("No upstream stdin".to_string()))?;
        let upstream_stdout = upstream
            .stdout
            .take()
            .ok_or_else(|| ProxyError::Transport("No upstream stdout".to_string()))?;

        // Set up channels
        let (to_upstream_tx, to_upstream_rx) =
            mpsc::channel::<JsonRpcMessage>(self.config.buffer_size);
        let (from_upstream_tx, mut from_upstream_rx) =
            mpsc::channel::<JsonRpcMessage>(self.config.buffer_size);

        let cancel_clone = cancel.clone();

        // Task: Read from local stdin, process through handler, send to upstream
        let handler_clone = handler.clone();
        let to_upstream_tx_clone = to_upstream_tx.clone();
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut line = String::new();

            loop {
                line.clear();
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = reader.read_line(&mut line) => {
                        match result {
                            Ok(0) => break,
                            Ok(_) => {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }

                                if let Ok(msg) = JsonRpcMessage::from_json_str(trimmed) {
                                    // Process through handler (may modify/filter)
                                    match handler_clone(msg).await {
                                        Ok(Some(processed)) => {
                                            let _ = to_upstream_tx_clone.send(processed).await;
                                        }
                                        Ok(None) => {
                                            // Message filtered out
                                        }
                                        Err(e) => {
                                            error!("Handler error on client message: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Stdin read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Task: Write to upstream stdin
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            Self::write_to_upstream(upstream_stdin, to_upstream_rx, cancel_clone).await;
        });

        // Task: Read from upstream stdout
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            Self::read_from_upstream(upstream_stdout, from_upstream_tx, cancel_clone).await;
        });

        // Task: Write upstream responses to local stdout
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();

            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    msg = from_upstream_rx.recv() => {
                        match msg {
                            Some(message) => {
                                // Process response through handler
                                match handler(message).await {
                                    Ok(Some(processed)) => {
                                        if let Ok(json) = processed.to_string() {
                                            let line = format!("{json}\n");
                                            let _ = stdout.write_all(line.as_bytes()).await;
                                            let _ = stdout.flush().await;
                                        }
                                    }
                                    Ok(None) => {
                                        // Response filtered out
                                    }
                                    Err(e) => {
                                        error!("Handler error on upstream response: {}", e);
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        // Wait for cancellation or upstream to exit
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = upstream.kill().await;
            }
            status = upstream.wait() => {
                info!("Upstream process exited: {:?}", status);
            }
        }

        Ok(())
    }

    async fn write_to_upstream(
        mut writer: tokio::process::ChildStdin,
        mut rx: mpsc::Receiver<JsonRpcMessage>,
        cancel: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => {
                    match msg {
                        Some(message) => {
                            if let Ok(json) = message.to_string() {
                                let line = format!("{json}\n");
                                if writer.write_all(line.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = writer.flush().await;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }

    async fn read_from_upstream(
        stdout: tokio::process::ChildStdout,
        tx: mpsc::Sender<JsonRpcMessage>,
        cancel: CancellationToken,
    ) {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        loop {
            line.clear();
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }

                            if let Ok(msg) = JsonRpcMessage::from_json_str(trimmed) {
                                if tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}
