//! Async observation writer with channel-based buffering

use crate::merkle::TransparencyLog;
use crate::pii::{PiiDetector, PiiRedactor};
use crate::storage::jsonl::JsonlStorage;
use soth_core::types::observation::ObservationEvent;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

/// Message sent to the async writer
enum WriterMessage {
    /// Write an event
    Write(Box<ObservationEvent>),
    /// Flush pending writes
    Flush,
    /// Shutdown the writer
    Shutdown,
}

/// Async writer handle
#[derive(Clone)]
pub struct AsyncWriter {
    sender: mpsc::Sender<WriterMessage>,
}

impl AsyncWriter {
    /// Send an event to be written
    pub async fn write(&self, event: ObservationEvent) -> bool {
        self.sender.send(WriterMessage::Write(Box::new(event))).await.is_ok()
    }

    /// Try to send without blocking (for hot path)
    pub fn try_write(&self, event: ObservationEvent) -> bool {
        self.sender.try_send(WriterMessage::Write(Box::new(event))).is_ok()
    }

    /// Request a flush
    pub async fn flush(&self) {
        let _ = self.sender.send(WriterMessage::Flush).await;
    }

    /// Request shutdown
    pub async fn shutdown(&self) {
        let _ = self.sender.send(WriterMessage::Shutdown).await;
    }
}

/// Configuration for the observation logger
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Buffer size for the channel
    pub buffer_size: usize,
    /// Flush interval
    pub flush_interval: Duration,
    /// Batch size for flushing
    pub batch_size: usize,
    /// Enable PII detection
    pub pii_detection: bool,
    /// Redact PII instead of just detecting
    pub pii_redaction: bool,
    /// Enable tamper-proof logging
    pub tamper_proof: bool,
    /// Log file path
    pub log_path: std::path::PathBuf,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1000,
            flush_interval: Duration::from_secs(1),
            batch_size: 100,
            pii_detection: true,
            pii_redaction: false,
            tamper_proof: false,
            log_path: std::path::PathBuf::from("./logs/observations.jsonl"),
        }
    }
}

/// Observation logger with async writing
pub struct ObservationLogger {
    writer: AsyncWriter,
    _handle: tokio::task::JoinHandle<()>,
}

impl ObservationLogger {
    /// Create a new observation logger
    pub async fn new(config: LoggerConfig) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::channel(config.buffer_size);

        // Ensure log directory exists
        if let Some(parent) = config.log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let handle = tokio::spawn(Self::writer_loop(receiver, config));

        Ok(Self {
            writer: AsyncWriter { sender },
            _handle: handle,
        })
    }

    /// Get a handle to the async writer
    pub fn writer(&self) -> AsyncWriter {
        self.writer.clone()
    }

    /// Write an event (convenience method)
    pub async fn write(&self, event: ObservationEvent) -> bool {
        self.writer.write(event).await
    }

    /// Shutdown the logger
    pub async fn shutdown(&self) {
        self.writer.shutdown().await;
    }

    /// Writer loop running in background
    async fn writer_loop(mut receiver: mpsc::Receiver<WriterMessage>, config: LoggerConfig) {
        let storage = match JsonlStorage::new(&config.log_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to create storage: {}", e);
                return;
            }
        };

        let pii_detector = if config.pii_detection {
            Some(PiiDetector::new())
        } else {
            None
        };

        let pii_redactor = if config.pii_redaction {
            Some(PiiRedactor::new())
        } else {
            None
        };

        let mut transparency_log = if config.tamper_proof {
            Some(TransparencyLog::new())
        } else {
            None
        };

        let mut buffer = Vec::with_capacity(config.batch_size);
        let mut flush_interval = tokio::time::interval(config.flush_interval);

        loop {
            tokio::select! {
                msg = receiver.recv() => {
                    match msg {
                        Some(WriterMessage::Write(event)) => {
                            let mut event = *event;
                            // PII detection/redaction
                            if let Some(detector) = &pii_detector {
                                let types = detector.detect_types(&event.content);
                                if !types.is_empty() {
                                    event.pii_detected = true;
                                    event.pii_types = types;

                                    if let Some(redactor) = &pii_redactor {
                                        let result = redactor.redact(&event.content);
                                        event.content = result.text;
                                    }
                                }
                            }

                            // Add to transparency log
                            if let Some(log) = &mut transparency_log {
                                let entry_bytes = serde_json::to_vec(&event).unwrap_or_default();
                                log.append(&entry_bytes, "observation", None);
                            }

                            buffer.push(event);

                            // Flush if buffer is full
                            if buffer.len() >= config.batch_size {
                                Self::flush_buffer(&storage, &mut buffer);
                            }
                        }
                        Some(WriterMessage::Flush) => {
                            Self::flush_buffer(&storage, &mut buffer);
                        }
                        Some(WriterMessage::Shutdown) | None => {
                            Self::flush_buffer(&storage, &mut buffer);
                            break;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !buffer.is_empty() {
                        Self::flush_buffer(&storage, &mut buffer);
                    }
                }
            }
        }

        tracing::info!("Observation logger shut down");
    }

    fn flush_buffer(storage: &JsonlStorage, buffer: &mut Vec<ObservationEvent>) {
        for event in buffer.drain(..) {
            if let Err(e) = storage.write(&event) {
                tracing::error!("Failed to write event: {}", e);
            }
        }
        if let Err(e) = storage.flush() {
            tracing::error!("Failed to flush storage: {}", e);
        }
    }
}

/// Simple synchronous logger for when async isn't needed
#[allow(dead_code)]
pub struct SyncLogger {
    storage: JsonlStorage,
    detector: Option<PiiDetector>,
    redactor: Option<PiiRedactor>,
    log: Option<TransparencyLog>,
}

#[allow(dead_code)]
impl SyncLogger {
    /// Create a new sync logger
    pub fn new(path: impl AsRef<Path>, pii_detection: bool, tamper_proof: bool) -> std::io::Result<Self> {
        Ok(Self {
            storage: JsonlStorage::new(path)?,
            detector: if pii_detection { Some(PiiDetector::new()) } else { None },
            redactor: None,
            log: if tamper_proof { Some(TransparencyLog::new()) } else { None },
        })
    }

    /// Enable PII redaction
    pub fn with_redaction(mut self) -> Self {
        self.redactor = Some(PiiRedactor::new());
        self
    }

    /// Write an event
    pub fn write(&mut self, mut event: ObservationEvent) -> std::io::Result<()> {
        // PII detection
        if let Some(detector) = &self.detector {
            let types = detector.detect_types(&event.content);
            if !types.is_empty() {
                event.pii_detected = true;
                event.pii_types = types;

                if let Some(redactor) = &self.redactor {
                    let result = redactor.redact(&event.content);
                    event.content = result.text;
                }
            }
        }

        // Transparency log
        if let Some(log) = &mut self.log {
            let entry_bytes = serde_json::to_vec(&event).unwrap_or_default();
            log.append(&entry_bytes, "observation", None);
        }

        self.storage.write(&event)
    }

    /// Flush to disk
    pub fn flush(&self) -> std::io::Result<()> {
        self.storage.flush()
    }

    /// Get the transparency log root hash
    pub fn root_hash(&self) -> Option<String> {
        self.log.as_ref().and_then(|l| l.root_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::observation::{Direction, EventType};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_async_writer() {
        let dir = tempdir().unwrap();
        let config = LoggerConfig {
            log_path: dir.path().join("test.jsonl"),
            pii_detection: false,
            tamper_proof: false,
            ..Default::default()
        };

        let logger = ObservationLogger::new(config).await.unwrap();

        let event = ObservationEvent::new("session-1", Direction::In, EventType::Request, "test content");
        assert!(logger.write(event).await);

        logger.writer.flush().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify file was written
        let content = std::fs::read_to_string(dir.path().join("test.jsonl")).unwrap();
        assert!(content.contains("session-1"));
    }

    #[test]
    fn test_sync_logger() {
        let dir = tempdir().unwrap();
        let mut logger = SyncLogger::new(dir.path().join("sync.jsonl"), true, false).unwrap();

        let event = ObservationEvent::new("session-1", Direction::In, EventType::Request, "test@example.com");
        logger.write(event).unwrap();
        logger.flush().unwrap();

        let content = std::fs::read_to_string(dir.path().join("sync.jsonl")).unwrap();
        assert!(content.contains("pii_detected\":true"));
    }

    #[test]
    fn test_sync_logger_with_redaction() {
        let dir = tempdir().unwrap();
        let mut logger = SyncLogger::new(dir.path().join("redact.jsonl"), true, false)
            .unwrap()
            .with_redaction();

        let event = ObservationEvent::new("session-1", Direction::In, EventType::Request, "SSN: 123-45-6789");
        logger.write(event).unwrap();
        logger.flush().unwrap();

        let content = std::fs::read_to_string(dir.path().join("redact.jsonl")).unwrap();
        assert!(!content.contains("123-45-6789"));
        assert!(content.contains("***"));
    }
}
