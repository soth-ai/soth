//! Event handling for the TUI

use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

/// Application events
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppEvent {
    /// Keyboard input
    Key(KeyEvent),
    /// UI refresh tick
    Tick,
    /// Terminal resize
    Resize(u16, u16),
    /// Time to fetch data from API
    FetchData,
}

/// Event handler that processes terminal and timer events
pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    #[allow(dead_code)]
    tx: mpsc::UnboundedSender<AppEvent>,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(poll_interval_secs: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let event_tx = tx.clone();

        // Spawn event polling task
        tokio::spawn(async move {
            let mut tick_interval = interval(Duration::from_millis(250));
            let mut fetch_interval = interval(Duration::from_secs(poll_interval_secs));

            loop {
                tokio::select! {
                    // Check for terminal events
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if event::poll(Duration::from_millis(0)).unwrap_or(false) {
                            if let Ok(evt) = event::read() {
                                match evt {
                                    Event::Key(key) => {
                                        if event_tx.send(AppEvent::Key(key)).is_err() {
                                            break;
                                        }
                                    }
                                    Event::Resize(w, h) => {
                                        if event_tx.send(AppEvent::Resize(w, h)).is_err() {
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    // UI refresh tick
                    _ = tick_interval.tick() => {
                        if event_tx.send(AppEvent::Tick).is_err() {
                            break;
                        }
                    }
                    // Data fetch interval
                    _ = fetch_interval.tick() => {
                        if event_tx.send(AppEvent::FetchData).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Self { rx, tx }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Result<AppEvent> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}
