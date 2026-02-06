//! WebSocket handler for real-time event streaming

use crate::event_store::EventStore;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Serialize;
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

/// WebSocket upgrade handler for event streaming
pub async fn event_stream_handler(
    ws: WebSocketUpgrade,
    State(store): State<Arc<EventStore>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, store))
}

async fn handle_socket(socket: WebSocket, store: Arc<EventStore>) {
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

    // Send recent events first (last 50)
    let recent = store.get_events(50);
    for event in recent.events.into_iter().rev() {
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
