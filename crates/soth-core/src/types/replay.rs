//! Session replay functionality
//!
//! Replays recorded MCP sessions with accurate timing for debugging
//! and testing purposes.

use super::session::{MessageDirection, RecordedMessage, RecordedSession, SessionRecordError};
use std::time::Duration;
use tokio::sync::mpsc;

/// Replay speed multiplier
#[derive(Debug, Clone, Copy, Default)]
pub enum ReplaySpeed {
    /// Real-time (1x speed)
    #[default]
    RealTime,
    /// Fast (no delays between messages)
    Fast,
    /// Custom multiplier (e.g., 2.0 for 2x speed, 0.5 for half speed)
    Custom(f64),
}

impl ReplaySpeed {
    /// Calculate the delay for a given relative time difference
    pub fn adjust_delay(&self, delay_ms: u64) -> Duration {
        match self {
            ReplaySpeed::RealTime => Duration::from_millis(delay_ms),
            ReplaySpeed::Fast => Duration::ZERO,
            ReplaySpeed::Custom(multiplier) => {
                if *multiplier <= 0.0 {
                    Duration::ZERO
                } else {
                    Duration::from_millis((delay_ms as f64 / multiplier) as u64)
                }
            }
        }
    }
}

/// Event emitted during replay
#[derive(Debug, Clone)]
pub enum ReplayEvent {
    /// Session replay started
    Started {
        session_id: String,
        session_name: String,
        total_messages: usize,
    },
    /// Message being replayed
    Message {
        index: usize,
        total: usize,
        message: RecordedMessage,
    },
    /// Replay paused
    Paused { at_index: usize },
    /// Replay resumed
    Resumed { from_index: usize },
    /// Session replay completed
    Completed {
        session_id: String,
        messages_replayed: usize,
    },
    /// Error during replay
    Error { message: String },
}

/// Options for session replay
#[derive(Debug, Clone)]
pub struct ReplayOptions {
    /// Replay speed
    pub speed: ReplaySpeed,
    /// Start from message index (0-based)
    pub start_index: usize,
    /// End at message index (exclusive, None for all)
    pub end_index: Option<usize>,
    /// Filter by direction
    pub direction_filter: Option<MessageDirection>,
    /// Filter by method (substring match)
    pub method_filter: Option<String>,
    /// Step-by-step mode (pause after each message)
    pub step_mode: bool,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            speed: ReplaySpeed::RealTime,
            start_index: 0,
            end_index: None,
            direction_filter: None,
            method_filter: None,
            step_mode: false,
        }
    }
}

impl ReplayOptions {
    /// Create options for fast replay (no delays)
    pub fn fast() -> Self {
        Self {
            speed: ReplaySpeed::Fast,
            ..Default::default()
        }
    }

    /// Create options for step-by-step replay
    pub fn step_by_step() -> Self {
        Self {
            step_mode: true,
            ..Default::default()
        }
    }

    /// Set speed multiplier
    pub fn with_speed(mut self, multiplier: f64) -> Self {
        self.speed = ReplaySpeed::Custom(multiplier);
        self
    }

    /// Set start index
    pub fn from_index(mut self, index: usize) -> Self {
        self.start_index = index;
        self
    }

    /// Set end index
    pub fn to_index(mut self, index: usize) -> Self {
        self.end_index = Some(index);
        self
    }

    /// Filter by direction
    pub fn with_direction(mut self, direction: MessageDirection) -> Self {
        self.direction_filter = Some(direction);
        self
    }

    /// Filter by method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method_filter = Some(method.into());
        self
    }
}

/// Session replayer
pub struct SessionReplayer {
    /// The session to replay
    session: RecordedSession,
    /// Replay options
    options: ReplayOptions,
    /// Current message index
    current_index: usize,
    /// Filtered message indices
    filtered_indices: Vec<usize>,
    /// Whether replay is paused
    paused: bool,
}

impl SessionReplayer {
    /// Create a new replayer for a session
    pub fn new(session: RecordedSession, options: ReplayOptions) -> Self {
        // Build filtered indices based on options
        let filtered_indices: Vec<usize> = session
            .messages
            .iter()
            .enumerate()
            .filter(|(i, msg)| {
                // Apply index filter
                if *i < options.start_index {
                    return false;
                }
                if let Some(end) = options.end_index {
                    if *i >= end {
                        return false;
                    }
                }
                // Apply direction filter
                if let Some(dir) = options.direction_filter {
                    if msg.direction != dir {
                        return false;
                    }
                }
                // Apply method filter
                if let Some(ref method) = options.method_filter {
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
            .map(|(i, _)| i)
            .collect();

        Self {
            session,
            options,
            current_index: 0,
            filtered_indices,
            paused: false,
        }
    }

    /// Get session info
    pub fn session(&self) -> &RecordedSession {
        &self.session
    }

    /// Get total messages that will be replayed
    pub fn total_messages(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Get current replay position
    pub fn current_position(&self) -> usize {
        self.current_index
    }

    /// Check if replay is complete
    pub fn is_complete(&self) -> bool {
        self.current_index >= self.filtered_indices.len()
    }

    /// Check if replay is paused
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Pause replay
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume replay
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Skip to specific position
    pub fn seek(&mut self, position: usize) {
        self.current_index = position.min(self.filtered_indices.len());
    }

    /// Get next message without advancing (peek)
    pub fn peek(&self) -> Option<&RecordedMessage> {
        self.filtered_indices
            .get(self.current_index)
            .and_then(|&idx| self.session.messages.get(idx))
    }

    /// Get and advance to next message
    pub fn next_message(&mut self) -> Option<&RecordedMessage> {
        if self.current_index >= self.filtered_indices.len() {
            return None;
        }

        let idx = self.filtered_indices[self.current_index];
        self.current_index += 1;
        self.session.messages.get(idx)
    }

    /// Calculate delay before next message based on timing
    pub fn delay_before_next(&self) -> Duration {
        if self.current_index == 0 {
            return Duration::ZERO;
        }

        if self.current_index >= self.filtered_indices.len() {
            return Duration::ZERO;
        }

        let prev_idx = self.filtered_indices[self.current_index - 1];
        let next_idx = self.filtered_indices[self.current_index];

        let prev_time = self.session.messages[prev_idx].relative_time_ms;
        let next_time = self.session.messages[next_idx].relative_time_ms;

        let delay_ms = next_time.saturating_sub(prev_time);
        self.options.speed.adjust_delay(delay_ms)
    }

    /// Run the replay, sending events to a channel
    pub async fn run(mut self, tx: mpsc::Sender<ReplayEvent>) -> Result<usize, SessionRecordError> {
        let total = self.filtered_indices.len();

        // Send started event
        tx.send(ReplayEvent::Started {
            session_id: self.session.id.clone(),
            session_name: self.session.name.clone(),
            total_messages: total,
        })
        .await
        .map_err(|e| SessionRecordError::Replay(e.to_string()))?;

        let mut messages_replayed = 0;

        while !self.is_complete() {
            // Check if paused
            if self.paused {
                tx.send(ReplayEvent::Paused {
                    at_index: self.current_index,
                })
                .await
                .map_err(|e| SessionRecordError::Replay(e.to_string()))?;

                // Wait for resume (this would need external control in real implementation)
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Apply timing delay
            let delay = self.delay_before_next();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            // Get next message (clone to release borrow before accessing current_index)
            if let Some(message) = self.next_message().cloned() {
                tx.send(ReplayEvent::Message {
                    index: self.current_index - 1,
                    total,
                    message,
                })
                .await
                .map_err(|e| SessionRecordError::Replay(e.to_string()))?;

                messages_replayed += 1;

                // In step mode, pause after each message
                if self.options.step_mode {
                    self.paused = true;
                }
            }
        }

        // Send completed event
        tx.send(ReplayEvent::Completed {
            session_id: self.session.id.clone(),
            messages_replayed,
        })
        .await
        .map_err(|e| SessionRecordError::Replay(e.to_string()))?;

        Ok(messages_replayed)
    }
}

/// Replay a session synchronously (for simple use cases)
pub fn replay_sync(session: &RecordedSession) -> Vec<&RecordedMessage> {
    session.messages.iter().collect()
}

/// Replay messages as an iterator with timing info
pub struct ReplayIterator<'a> {
    messages: &'a [RecordedMessage],
    current: usize,
    speed: ReplaySpeed,
}

impl<'a> ReplayIterator<'a> {
    pub fn new(session: &'a RecordedSession, speed: ReplaySpeed) -> Self {
        Self {
            messages: &session.messages,
            current: 0,
            speed,
        }
    }
}

impl<'a> Iterator for ReplayIterator<'a> {
    type Item = (&'a RecordedMessage, Duration);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.messages.len() {
            return None;
        }

        let message = &self.messages[self.current];
        let delay = if self.current == 0 {
            Duration::ZERO
        } else {
            let prev_time = self.messages[self.current - 1].relative_time_ms;
            let delay_ms = message.relative_time_ms.saturating_sub(prev_time);
            self.speed.adjust_delay(delay_ms)
        };

        self.current += 1;
        Some((message, delay))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_session() -> RecordedSession {
        use super::super::session::{MessageMetadata, SessionMetadata};

        RecordedSession {
            id: "test-session".to_string(),
            name: "Test Session".to_string(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            messages: vec![
                RecordedMessage {
                    id: "msg-0".to_string(),
                    timestamp: Utc::now(),
                    relative_time_ms: 0,
                    direction: MessageDirection::ToServer,
                    content: serde_json::json!({"method": "initialize", "id": 1}),
                    metadata: MessageMetadata::default(),
                },
                RecordedMessage {
                    id: "msg-1".to_string(),
                    timestamp: Utc::now(),
                    relative_time_ms: 100,
                    direction: MessageDirection::ToClient,
                    content: serde_json::json!({"result": {}, "id": 1}),
                    metadata: MessageMetadata::default(),
                },
                RecordedMessage {
                    id: "msg-2".to_string(),
                    timestamp: Utc::now(),
                    relative_time_ms: 200,
                    direction: MessageDirection::ToServer,
                    content: serde_json::json!({"method": "tools/list", "id": 2}),
                    metadata: MessageMetadata::default(),
                },
            ],
            metadata: SessionMetadata::default(),
        }
    }

    #[test]
    fn test_replay_speed() {
        assert_eq!(
            ReplaySpeed::RealTime.adjust_delay(100),
            Duration::from_millis(100)
        );
        assert_eq!(ReplaySpeed::Fast.adjust_delay(100), Duration::ZERO);
        assert_eq!(
            ReplaySpeed::Custom(2.0).adjust_delay(100),
            Duration::from_millis(50)
        );
        assert_eq!(
            ReplaySpeed::Custom(0.5).adjust_delay(100),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn test_replayer_basic() {
        let session = create_test_session();
        let mut replayer = SessionReplayer::new(session, ReplayOptions::fast());

        assert_eq!(replayer.total_messages(), 3);
        assert!(!replayer.is_complete());

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.id, "msg-0");

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.id, "msg-1");

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.id, "msg-2");

        assert!(replayer.is_complete());
        assert!(replayer.next_message().is_none());
    }

    #[test]
    fn test_replayer_direction_filter() {
        let session = create_test_session();
        let options = ReplayOptions::default().with_direction(MessageDirection::ToServer);
        let mut replayer = SessionReplayer::new(session, options);

        assert_eq!(replayer.total_messages(), 2);

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.direction, MessageDirection::ToServer);

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.direction, MessageDirection::ToServer);
    }

    #[test]
    fn test_replayer_method_filter() {
        let session = create_test_session();
        let options = ReplayOptions::default().with_method("tools");
        let mut replayer = SessionReplayer::new(session, options);

        assert_eq!(replayer.total_messages(), 1);

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.method(), Some("tools/list"));
    }

    #[test]
    fn test_replayer_index_range() {
        let session = create_test_session();
        let options = ReplayOptions::default().from_index(1).to_index(3);
        let mut replayer = SessionReplayer::new(session, options);

        assert_eq!(replayer.total_messages(), 2);

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.id, "msg-1");
    }

    #[test]
    fn test_replay_iterator() {
        let session = create_test_session();
        let iter = ReplayIterator::new(&session, ReplaySpeed::RealTime);

        let items: Vec<_> = iter.collect();
        assert_eq!(items.len(), 3);

        // First message has no delay
        assert_eq!(items[0].1, Duration::ZERO);
        // Second message has 100ms delay
        assert_eq!(items[1].1, Duration::from_millis(100));
    }

    #[test]
    fn test_replayer_seek() {
        let session = create_test_session();
        let mut replayer = SessionReplayer::new(session, ReplayOptions::fast());

        replayer.seek(2);
        assert_eq!(replayer.current_position(), 2);

        let msg = replayer.next_message().unwrap();
        assert_eq!(msg.id, "msg-2");
    }

    #[test]
    fn test_replayer_pause_resume() {
        let session = create_test_session();
        let mut replayer = SessionReplayer::new(session, ReplayOptions::fast());

        assert!(!replayer.is_paused());

        replayer.pause();
        assert!(replayer.is_paused());

        replayer.resume();
        assert!(!replayer.is_paused());
    }
}
