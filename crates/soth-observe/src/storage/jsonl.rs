//! JSONL (JSON Lines) storage backend

use soth_core::types::observation::ObservationEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

/// JSONL storage backend
pub struct JsonlStorage {
    writer: Mutex<BufWriter<File>>,
}

impl JsonlStorage {
    /// Create a new JSONL storage
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Write an observation event
    pub fn write(&self, event: &ObservationEvent) -> std::io::Result<()> {
        let json = serde_json::to_string(event)?;
        let mut writer = self.writer.lock().unwrap();
        writeln!(writer, "{json}")?;
        Ok(())
    }

    /// Write a generic JSON value
    pub fn write_json(&self, value: &serde_json::Value) -> std::io::Result<()> {
        let json = serde_json::to_string(value)?;
        let mut writer = self.writer.lock().unwrap();
        writeln!(writer, "{json}")?;
        Ok(())
    }

    /// Flush to disk
    pub fn flush(&self) -> std::io::Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.flush()
    }
}

/// JSONL reader for loading logs
pub struct JsonlReader {
    path: std::path::PathBuf,
}

impl JsonlReader {
    /// Create a new reader
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Read all events from the file
    pub fn read_all(&self) -> std::io::Result<Vec<ObservationEvent>> {
        let content = std::fs::read_to_string(&self.path)?;
        let events: Vec<ObservationEvent> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        Ok(events)
    }

    /// Read events with a filter
    pub fn read_filtered<F>(&self, filter: F) -> std::io::Result<Vec<ObservationEvent>>
    where
        F: Fn(&ObservationEvent) -> bool,
    {
        let all = self.read_all()?;
        Ok(all.into_iter().filter(filter).collect())
    }

    /// Read events for a specific session
    pub fn read_session(&self, session_id: &str) -> std::io::Result<Vec<ObservationEvent>> {
        self.read_filtered(|e| e.session_id == session_id)
    }

    /// Iterate over events lazily
    pub fn iter(&self) -> std::io::Result<impl Iterator<Item = ObservationEvent>> {
        let content = std::fs::read_to_string(&self.path)?;
        let events: Vec<ObservationEvent> = content
            .lines()
            .filter_map(|line| {
                if line.trim().is_empty() {
                    None
                } else {
                    serde_json::from_str(line).ok()
                }
            })
            .collect();
        Ok(events.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::observation::{Direction, EventType};
    use tempfile::tempdir;

    #[test]
    fn test_write_and_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        // Write events
        let storage = JsonlStorage::new(&path).unwrap();
        let event1 = ObservationEvent::new("session-1", Direction::In, EventType::Request, "content 1");
        let event2 = ObservationEvent::new("session-1", Direction::Out, EventType::Response, "content 2");

        storage.write(&event1).unwrap();
        storage.write(&event2).unwrap();
        storage.flush().unwrap();

        // Read events
        let reader = JsonlReader::new(&path);
        let events = reader.read_all().unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].content, "content 1");
        assert_eq!(events[1].content, "content 2");
    }

    #[test]
    fn test_read_session() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.jsonl");

        let storage = JsonlStorage::new(&path).unwrap();

        let event1 = ObservationEvent::new("session-1", Direction::In, EventType::Request, "s1");
        let event2 = ObservationEvent::new("session-2", Direction::In, EventType::Request, "s2");
        let event3 = ObservationEvent::new("session-1", Direction::Out, EventType::Response, "s1");

        storage.write(&event1).unwrap();
        storage.write(&event2).unwrap();
        storage.write(&event3).unwrap();
        storage.flush().unwrap();

        let reader = JsonlReader::new(&path);
        let session1_events = reader.read_session("session-1").unwrap();

        assert_eq!(session1_events.len(), 2);
    }

    #[test]
    fn test_append_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("append.jsonl");

        // Write first batch
        {
            let storage = JsonlStorage::new(&path).unwrap();
            let event = ObservationEvent::new("s1", Direction::In, EventType::Request, "first");
            storage.write(&event).unwrap();
            storage.flush().unwrap();
        }

        // Write second batch (should append)
        {
            let storage = JsonlStorage::new(&path).unwrap();
            let event = ObservationEvent::new("s1", Direction::In, EventType::Request, "second");
            storage.write(&event).unwrap();
            storage.flush().unwrap();
        }

        let reader = JsonlReader::new(&path);
        let events = reader.read_all().unwrap();
        assert_eq!(events.len(), 2);
    }
}
