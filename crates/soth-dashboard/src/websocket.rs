//! WebSocket handler for real-time event streaming

use crate::event_store::EventStore;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use soth_core::types::WrapEvent;
use std::sync::Arc;
use tracing::{debug, info};

/// WebSocket message wrapper for frontend compatibility
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsMessage {
    /// A wrap event from the event log
    Event { event: WrapEvent },
    /// Connection established
    Connected { message: String },
}

#[derive(Debug, Deserialize)]
pub struct EventStreamQuery {
    pub since_seq: Option<i64>,
    pub limit: Option<usize>,
}

/// WebSocket upgrade handler for event streaming
pub async fn event_stream_handler(
    ws: WebSocketUpgrade,
    State(store): State<Arc<EventStore>>,
    Query(query): Query<EventStreamQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, store, query))
}

async fn handle_socket(socket: WebSocket, store: Arc<EventStore>, query: EventStreamQuery) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to new events
    let mut event_rx = store.subscribe();

    info!("WebSocket client connected");

    // Send connection message
    if let Ok(json) = serde_json::to_string(&WsMessage::Connected {
        message: "Connected to SOTH event stream".to_string(),
    }) {
        let _ = sender.send(Message::Text(json)).await;
    }

    // Replay either:
    // - cursor-based catch-up (since_seq), or
    // - recent history (default).
    let replay_limit = query.limit.unwrap_or(50).clamp(1, 5000);
    let replay_events: Vec<WrapEvent> = if let Some(since_seq) = query.since_seq {
        // get_events_since_seq already returns oldest->newest for replay.
        store.get_events_since_seq(since_seq, replay_limit).events
    } else {
        // get_events returns newest->oldest; reverse for stable playback.
        store
            .get_events(replay_limit)
            .events
            .into_iter()
            .rev()
            .collect()
    };

    for event in replay_events {
        let wrapped = WsMessage::Event { event };
        if let Ok(json) = serde_json::to_string(&wrapped) {
            if sender.send(Message::Text(json)).await.is_err() {
                return;
            }
        }
    }

    // Spawn task to handle incoming messages (for ping/pong and close)
    let mut recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    debug!("WebSocket client requested close");
                    break;
                }
                Ok(Message::Ping(_)) => {
                    debug!("Received ping");
                    // Pong will be sent automatically by axum
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("WebSocket receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Send new events as they arrive
    loop {
        tokio::select! {
            _ = &mut recv_task => {
                // Client disconnected
                break;
            }
            result = event_rx.recv() => {
                match result {
                    Ok(event) => {
                        let wrapped = WsMessage::Event { event };
                        if let Ok(json) = serde_json::to_string(&wrapped) {
                            if sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!("WebSocket client lagged {} events", n);
                        // Continue receiving
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }

    info!("WebSocket client disconnected");
}
