//! JSONL (JSON Lines) storage backend

use soth_core::types::observation::ObservationEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use tracing::warn;

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

        let file = OpenOptions::new().create(true).append(true).open(path)?;

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
        let bytes = std::fs::read(&self.path)?;
        let content = String::from_utf8_lossy(&bytes);
        let events: Vec<ObservationEvent> = content
            .lines()
            .enumerate()
            .filter_map(|(line_no, line)| self.parse_line(line, line_no + 1))
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
        let bytes = std::fs::read(&self.path)?;
        let content = String::from_utf8_lossy(&bytes);
        let events: Vec<ObservationEvent> = content
            .lines()
            .enumerate()
            .filter_map(|(line_no, line)| self.parse_line(line, line_no + 1))
            .collect();
        Ok(events.into_iter())
    }

    fn parse_line(&self, line: &str, line_no: usize) -> Option<ObservationEvent> {
        if line.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<ObservationEvent>(line) {
            Ok(event) => Some(event),
            Err(primary_error) => {
                if let Some(cleaned) = sanitize_json_line(line) {
                    match serde_json::from_str::<ObservationEvent>(&cleaned) {
                        Ok(event) => {
                            warn!(
                                path = %self.path.display(),
                                line_no = line_no,
                                "Recovered malformed JSONL line after sanitization"
                            );
                            return Some(event);
                        }
                        Err(sanitized_error) => {
                            warn!(
                                path = %self.path.display(),
                                line_no = line_no,
                                error = %sanitized_error,
                                "Skipping malformed JSONL observation line (sanitized parse failed)"
                            );
                            return None;
                        }
                    }
                }
                warn!(
                    path = %self.path.display(),
                    line_no = line_no,
                    error = %primary_error,
                    "Skipping malformed JSONL observation line"
                );
                None
            }
        }
    }
}

fn sanitize_json_line(line: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(line.len());

    for ch in line.chars() {
        let should_drop = ch == '\u{FFFD}' || (ch.is_control() && ch != '\t');
        if should_drop {
            changed = true;
            continue;
        }
        out.push(ch);
    }

    if changed { Some(out) } else { None }
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
        let event1 =
            ObservationEvent::new("session-1", Direction::In, EventType::Request, "content 1");
        let event2 = ObservationEvent::new(
            "session-1",
            Direction::Out,
            EventType::Response,
            "content 2",
        );

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

    #[test]
    fn test_recover_malformed_line_by_sanitizing_bad_chars() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recover.jsonl");
        let event = ObservationEvent::new("session-1", Direction::In, EventType::Request, "ok");
        let json = serde_json::to_string(&event).unwrap();

        // Inject a raw invalid UTF-8 byte between JSON tokens.
        let mut bytes = json.into_bytes();
        bytes.insert(1, 0xFF);
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();

        let reader = JsonlReader::new(&path);
        let events = reader.read_all().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id, "session-1");
    }
}
