use crate::types::{StreamSession, StreamTurn, StreamUsage};

/// Process a WebSocket frame for turn lifecycle tracking.
///
/// Turn lifecycle (OpenAI Responses API):
///   1. Client sends `response.create`    → model captured from the REQUEST
///   2. Server sends `response.completed`  → usage captured from the RESPONSE
///   3. Returns `StreamTurn` with model from (1), usage from (2)
pub(super) fn process_websocket_turn(
    payload: &[u8],
    session: &mut StreamSession,
) -> Option<StreamTurn> {
    let text = std::str::from_utf8(payload).ok()?;
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let event_type = value.get("type").and_then(|v| v.as_str())?;

    match event_type {
        // Client → Server: turn request.  Extract model from the request.
        "response.create" => {
            if let Some(model) = value
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|v| v.as_str())
            {
                if !model.is_empty() {
                    session.current_turn_model = Some(model.to_string());
                    session.model = Some(model.to_string());
                }
            }
            None
        }

        // Server → Client: turn complete.  Extract usage, pair with
        // model captured from the request frame.
        "response.completed" => emit_turn_from_response(&value, session, "stop"),

        // Server → Client: turn failed or cancelled.  Emit whatever
        // model/usage we already collected so the turn isn't silently
        // swallowed.
        "response.failed" | "response.cancelled" | "response.incomplete" => {
            let finish = match event_type {
                "response.failed" => "error",
                "response.cancelled" => "cancelled",
                _ => "incomplete",
            };
            emit_turn_from_response(&value, session, finish)
        }

        _ => None,
    }
}

/// Shared logic for emitting a turn from a terminal response event
/// (`response.completed`, `response.failed`, `response.cancelled`, etc.).
fn emit_turn_from_response(
    value: &serde_json::Value,
    session: &mut StreamSession,
    finish_reason: &str,
) -> Option<StreamTurn> {
    let response = value.get("response")?;

    let usage = if let Some(u) = response.get("usage") {
        StreamUsage {
            input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            finish_reason: Some(finish_reason.to_string()),
        }
    } else {
        let mut fallback = session.last_usage.clone().unwrap_or_default();
        fallback.finish_reason = Some(finish_reason.to_string());
        fallback
    };

    let model = session
        .current_turn_model
        .take()
        .or_else(|| {
            response
                .get("model")
                .and_then(|v| v.as_str())
                .filter(|m| !m.is_empty())
                .map(|s| s.to_string())
        })
        .or_else(|| session.model.clone());

    session.turns_emitted += 1;
    session.last_usage = None;
    session.last_finish_reason = None;

    let turn_number = session.turns_emitted;
    let connection_id = session.connection_id;
    let (prompt, content) =
        crate::stream::take_session_turn_payload(session, crate::stream::MAX_TURN_PAYLOAD_BYTES);

    Some(StreamTurn {
        connection_id,
        model,
        usage,
        turn_number,
        prompt,
        content,
    })
}
