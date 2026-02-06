//! Event store - watches event log and stores recent events for dashboard
//!
//! Provides real-time event streaming via broadcast channel.
//! Uses notify-based file watching for instant event detection (<10ms latency).

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use soth_core::types::WrapEvent;
use soth_core::watch::{FileWatcher, WatchEvent};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Maximum number of events to keep in memory
const MAX_EVENTS: usize = 1000;

/// Maximum number of agents to track
const MAX_AGENTS: usize = 100;

/// Event store that watches the JSONL log and provides real-time streaming
#[derive(Clone)]
pub struct EventStore {
    inner: Arc<RwLock<EventStoreInner>>,
    log_path: PathBuf,
    event_tx: broadcast::Sender<WrapEvent>,
}

struct EventStoreInner {
    /// Recent events (newest first)
    events: VecDeque<WrapEvent>,
    /// Agent statistics
    agents: HashMap<String, AgentStats>,
    /// File position for watching
    file_position: u64,
}

/// Statistics for a detected agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStats {
    /// Agent name
    pub name: String,
    /// Agent version (if known)
    pub version: Option<String>,
    /// Detection source
    pub detected_from: String,
    /// Number of events from this agent
    pub event_count: u64,
    /// Last seen timestamp
    pub last_seen: String,
    /// Servers this agent has used
    pub servers: Vec<String>,
}

/// Summary of all agents
#[derive(Debug, Clone, Serialize)]
pub struct AgentsSummary {
    pub total_agents: usize,
    pub agents: Vec<AgentStats>,
}

/// Summary of recent events
#[derive(Debug, Clone, Serialize)]
pub struct EventsSummary {
    pub total_events: usize,
    pub events: Vec<WrapEvent>,
}

impl EventStore {
    /// Create a new event store
    pub fn new(log_path: PathBuf) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            inner: Arc::new(RwLock::new(EventStoreInner {
                events: VecDeque::with_capacity(MAX_EVENTS),
                agents: HashMap::new(),
                file_position: 0,
            })),
            log_path,
            event_tx,
        }
    }

    /// Create with default log path (~/.soth/logs/events.jsonl)
    pub fn with_default_path() -> Option<Self> {
        let home = dirs::home_dir()?;
        let log_path = home.join(".soth").join("logs").join("events.jsonl");
        Some(Self::new(log_path))
    }

    /// Subscribe to new events
    pub fn subscribe(&self) -> broadcast::Receiver<WrapEvent> {
        self.event_tx.subscribe()
    }

    /// Get recent events
    pub fn get_events(&self, limit: usize) -> EventsSummary {
        let inner = self.inner.read();
        let events: Vec<WrapEvent> = inner
            .events
            .iter()
            .take(limit.min(MAX_EVENTS))
            .cloned()
            .collect();

        EventsSummary {
            total_events: inner.events.len(),
            events,
        }
    }

    /// Get agent statistics
    pub fn get_agents(&self) -> AgentsSummary {
        let inner = self.inner.read();
        let mut agents: Vec<AgentStats> = inner.agents.values().cloned().collect();

        // Sort by event count (most active first)
        agents.sort_by(|a, b| b.event_count.cmp(&a.event_count));

        AgentsSummary {
            total_agents: agents.len(),
            agents,
        }
    }

    /// Load initial events from the log file
    pub async fn load_initial(&self) -> std::io::Result<usize> {
        if !self.log_path.exists() {
            debug!("Event log does not exist yet: {:?}", self.log_path);
            return Ok(0);
        }

        let content = tokio::fs::read_to_string(&self.log_path).await?;
        let mut count = 0;

        for line in content.lines() {
            if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
                self.add_event(event);
                count += 1;
            }
        }

        // Update file position
        {
            let mut inner = self.inner.write();
            inner.file_position = content.len() as u64;
        }

        info!("Loaded {} initial events from {:?}", count, self.log_path);
        Ok(count)
    }

    /// Watch the log file for new events
    ///
    /// Uses notify-based file watching for instant event detection.
    /// Falls back to polling if file watcher is unavailable.
    pub async fn watch(&self) {
        info!("Starting event log watcher for {:?}", self.log_path);

        // Try to create a file watcher for instant notifications
        let watcher_result = FileWatcher::new(self.log_path.clone());
        let use_polling = watcher_result.is_err();

        if use_polling {
            warn!("File watcher unavailable, falling back to 100ms polling");
        } else {
            info!("Using notify-based file watching for instant events");
        }

        let mut watcher = watcher_result.ok();

        loop {
            // Wait for file change - either via notify or polling
            // Always use a timeout to ensure we check periodically even if notify misses events
            if let Some(ref mut w) = watcher {
                // Use notify with timeout fallback
                let timeout_duration = tokio::time::Duration::from_millis(500);
                match tokio::time::timeout(timeout_duration, w.next()).await {
                    Ok(Some(WatchEvent::Modified)) | Ok(Some(WatchEvent::Created)) => {
                        // File changed via notify, process immediately
                        debug!("File change detected via notify");
                    }
                    Ok(Some(WatchEvent::Removed)) => {
                        debug!("Log file removed, waiting for recreation...");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(Some(WatchEvent::Error(e))) => {
                        warn!("Watch error: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(None) => {
                        // Watcher closed, fall back to polling
                        warn!("File watcher closed, falling back to polling");
                        watcher = None;
                        continue;
                    }
                    Err(_) => {
                        // Timeout - check for events anyway (notify might have missed them)
                        // This is the fallback polling mechanism
                    }
                }
            } else {
                // Pure polling fallback
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if let Err(e) = self.check_for_new_events().await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Error checking event log: {}", e);
                }
            }
        }
    }

    async fn check_for_new_events(&self) -> std::io::Result<()> {
        if !self.log_path.exists() {
            return Ok(());
        }

        let metadata = tokio::fs::metadata(&self.log_path).await?;
        let current_size = metadata.len();

        let file_position = {
            let inner = self.inner.read();
            inner.file_position
        };

        // Handle file truncation/recreation - reset position if file shrunk
        let effective_position = if current_size < file_position {
            debug!("Log file was truncated/recreated, resetting position from {} to 0", file_position);
            let mut inner = self.inner.write();
            inner.file_position = 0;
            inner.events.clear(); // Clear stale events
            0u64 // Process from beginning
        } else if current_size == file_position {
            return Ok(()); // No new content
        } else {
            file_position
        };

        // Read new content
        let content = tokio::fs::read_to_string(&self.log_path).await?;

        // Process lines after the effective position
        let mut bytes_read = 0u64;
        for line in content.lines() {
            let line_bytes = line.len() as u64 + 1; // +1 for newline
            bytes_read += line_bytes;

            if bytes_read <= effective_position {
                continue;
            }

            if let Ok(event) = serde_json::from_str::<WrapEvent>(line) {
                // Broadcast to subscribers
                let _ = self.event_tx.send(event.clone());

                // Store in memory
                self.add_event(event);
            }
        }

        // Update position
        {
            let mut inner = self.inner.write();
            inner.file_position = current_size;
        }

        Ok(())
    }

    fn add_event(&self, event: WrapEvent) {
        let mut inner = self.inner.write();

        // Update agent stats
        let agent_key = event.agent.name.clone();
        let stats = inner.agents.entry(agent_key.clone()).or_insert_with(|| {
            AgentStats {
                name: event.agent.name.clone(),
                version: event.agent.version.clone(),
                detected_from: format!("{:?}", event.agent.detected_from),
                event_count: 0,
                last_seen: event.timestamp.to_rfc3339(),
                servers: Vec::new(),
            }
        });

        stats.event_count += 1;
        stats.last_seen = event.timestamp.to_rfc3339();

        // Track servers
        if !stats.servers.contains(&event.server_name) {
            stats.servers.push(event.server_name.clone());
            // Limit servers list
            if stats.servers.len() > 10 {
                stats.servers.remove(0);
            }
        }

        // Limit agents
        if inner.agents.len() > MAX_AGENTS {
            // Remove least active agent
            if let Some(min_key) = inner
                .agents
                .iter()
                .min_by_key(|(_, s)| s.event_count)
                .map(|(k, _)| k.clone())
            {
                inner.agents.remove(&min_key);
            }
        }

        // Add event to front (newest first)
        inner.events.push_front(event);

        // Trim to max size
        while inner.events.len() > MAX_EVENTS {
            inner.events.pop_back();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection};
    use tempfile::tempdir;

    fn make_event(agent_name: &str, server: &str) -> WrapEvent {
        let agent = AgentInfo::new(agent_name, DetectionSource::McpInitialize);
        WrapEvent::new("sess-123", server, WrapDirection::In, agent)
            .with_method("tools/call")
    }

    #[test]
    fn test_add_event() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        let event = make_event("Claude Desktop", "postgres");
        store.add_event(event);

        let summary = store.get_events(10);
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.events[0].agent.name, "Claude Desktop");
    }

    #[test]
    fn test_agent_stats() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        store.add_event(make_event("Claude Desktop", "postgres"));
        store.add_event(make_event("Claude Desktop", "filesystem"));
        store.add_event(make_event("Cursor", "postgres"));

        let agents = store.get_agents();
        assert_eq!(agents.total_agents, 2);

        let claude = agents.agents.iter().find(|a| a.name == "Claude Desktop").unwrap();
        assert_eq!(claude.event_count, 2);
        assert_eq!(claude.servers.len(), 2);
    }

    #[test]
    fn test_event_limit() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        // Add more than MAX_EVENTS
        for i in 0..1100 {
            store.add_event(make_event(&format!("Agent{}", i % 10), "server"));
        }

        let summary = store.get_events(2000);
        assert_eq!(summary.total_events, MAX_EVENTS);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let dir = tempdir().unwrap();
        let store = EventStore::new(dir.path().join("events.jsonl"));

        let mut rx = store.subscribe();

        // Simulate broadcast
        let event = make_event("Test Agent", "test-server");
        store.event_tx.send(event.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.agent.name, "Test Agent");
    }
}
