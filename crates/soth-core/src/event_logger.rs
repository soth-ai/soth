//! Event logger for writing WrapEvents to the event log file
//!
//! Used by both `soth wrap` (stdio interception) and forward proxy (HTTP interception)
//! to emit events that appear in the observability dashboard.

use crate::types::WrapEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Event logger that writes WrapEvents to a JSONL file
#[derive(Clone)]
pub struct EventLogger {
    inner: Arc<Mutex<Option<BufWriter<File>>>>,
    path: PathBuf,
}

impl EventLogger {
    /// Create a new event logger that writes to the given path
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Some(BufWriter::new(file)))),
            path,
        })
    }

    /// Create an event logger with the default path (~/.soth/logs/events.jsonl)
    pub fn with_default_path() -> std::io::Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine home directory",
            ))?;
        let path = home.join(".soth").join("logs").join("events.jsonl");
        Self::new(path)
    }

    /// Get the path this logger writes to
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Log an event
    pub fn log(&self, event: &WrapEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            if let Ok(mut guard) = self.inner.lock() {
                if let Some(writer) = guard.as_mut() {
                    let _ = writeln!(writer, "{}", json);
                    let _ = writer.flush();
                }
            }
        }
    }

    /// Log an event, returning any error
    pub fn log_checked(&self, event: &WrapEvent) -> std::io::Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut guard = self.inner.lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Lock poisoned"))?;
        if let Some(writer) = guard.as_mut() {
            writeln!(writer, "{}", json)?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Close the logger
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }
}

impl std::fmt::Debug for EventLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLogger")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentInfo, DetectionSource, WrapDirection};
    use tempfile::tempdir;

    #[test]
    fn test_event_logger() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");

        let logger = EventLogger::new(path.clone()).unwrap();

        let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
        let event = WrapEvent::new("session-1", "test-server", WrapDirection::In, agent)
            .with_method("test/method");

        logger.log(&event);
        logger.close();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("session-1"));
        assert!(content.contains("test-server"));
        assert!(content.contains("test/method"));
    }

    #[test]
    fn test_event_logger_multiple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");

        let logger = EventLogger::new(path.clone()).unwrap();

        for i in 0..5 {
            let agent = AgentInfo::new("Test Agent", DetectionSource::CommandLine);
            let event = WrapEvent::new(
                format!("session-{}", i),
                "test-server",
                WrapDirection::In,
                agent,
            );
            logger.log(&event);
        }
        logger.close();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
    }
}
