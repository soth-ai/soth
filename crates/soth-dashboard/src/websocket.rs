//! WebSocket handler for real-time event streaming

use crate::event_store::EventStore;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::SplitSink, stream::StreamExt};
use serde::{Deserialize, Serialize};
use soth_core::types::WrapEvent;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tracing::{debug, info};

/// WebSocket message wrapper for frontend compatibility
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsMessage {
    /// Seq-ranged event batch.
    Batch {
        seq_start: i64,
        seq_end: i64,
        events: Vec<WrapEvent>,
    },
    /// Connection established
    Connected {
        message: String,
        protocol: String,
        latest_seq: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientWsMessage {
    Ack { seq: i64 },
}

#[derive(Debug, Deserialize)]
pub struct EventStreamQuery {
    pub since_seq: Option<i64>,
    pub limit: Option<usize>,
}

const WS_BATCH_SIZE: usize = 128;
const WS_BACKFILL_LIMIT: usize = 5_000;

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
    let acked_seq = Arc::new(AtomicI64::new(query.since_seq.unwrap_or(0)));
    let last_sent_seq = Arc::new(AtomicI64::new(query.since_seq.unwrap_or(0)));

    // Subscribe to new events
    let mut event_rx = store.subscribe();

    info!("WebSocket client connected");

    // Send connection message
    if let Ok(json) = serde_json::to_string(&WsMessage::Connected {
        message: "Connected to SOTH event stream".to_string(),
        protocol: "seq_batch_v1".to_string(),
        latest_seq: store.latest_seq(),
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

    if !send_events_in_batches(&mut sender, replay_events, &last_sent_seq).await {
        return;
    }

    // Spawn task to handle incoming messages (ack, ping/pong, close)
    let acked_seq_for_recv = acked_seq.clone();
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
                Ok(Message::Text(text)) => {
                    if let Ok(ClientWsMessage::Ack { seq }) =
                        serde_json::from_str::<ClientWsMessage>(&text)
                    {
                        acked_seq_for_recv.store(seq, Ordering::Relaxed);
                    }
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
                        if !send_events_in_batches(&mut sender, vec![event], &last_sent_seq).await {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        store.record_stream_lagged(n as u64);
                        debug!("WebSocket client lagged {} events; replaying from sqlite cursor", n);
                        let mut cursor = acked_seq.load(Ordering::Relaxed);
                        if cursor < 0 {
                            cursor = 0;
                        }
                        loop {
                            let summary = store.get_events_since_seq(cursor, WS_BACKFILL_LIMIT);
                            if summary.events.is_empty() {
                                break;
                            }
                            let len = summary.events.len();
                            store.record_stream_backfill_batch(len as u64);
                            let next_cursor = summary
                                .events
                                .iter()
                                .rev()
                                .find_map(|event| event.seq)
                                .unwrap_or(cursor);
                            if !send_events_in_batches(&mut sender, summary.events, &last_sent_seq).await {
                                return;
                            }
                            cursor = next_cursor;
                            if len < WS_BACKFILL_LIMIT {
                                break;
                            }
                        }
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

async fn send_events_in_batches(
    sender: &mut SplitSink<WebSocket, Message>,
    events: Vec<WrapEvent>,
    last_sent_seq: &Arc<AtomicI64>,
) -> bool {
    if events.is_empty() {
        return true;
    }

    let mut offset = 0usize;
    while offset < events.len() {
        let end = (offset + WS_BATCH_SIZE).min(events.len());
        let batch: Vec<WrapEvent> = events[offset..end].to_vec();
        offset = end;

        let seq_start = batch.iter().find_map(|event| event.seq).unwrap_or(0);
        let seq_end = batch.iter().rev().find_map(|event| event.seq).unwrap_or(seq_start);

        let wrapped = WsMessage::Batch {
            seq_start,
            seq_end,
            events: batch,
        };
        let Ok(json) = serde_json::to_string(&wrapped) else {
            continue;
        };
        if sender.send(Message::Text(json)).await.is_err() {
            return false;
        }
        last_sent_seq.store(seq_end, Ordering::Relaxed);
    }

    true
}
