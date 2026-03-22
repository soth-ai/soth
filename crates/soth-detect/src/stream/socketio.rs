//! Socket.IO / Engine.IO frame decoder for WebSocket text frames.
//!
//! Socket.IO is a protocol layer on top of WebSocket used by services like
//! Manus.ai.  The wire format prepends a numeric packet type to each frame:
//!
//! | Type | Engine.IO | Meaning |
//! |------|-----------|---------|
//! | `0`  | OPEN      | Handshake (SID, ping interval) |
//! | `1`  | CLOSE     | Connection closed |
//! | `2`  | PING      | Heartbeat (client) |
//! | `3`  | PONG      | Heartbeat (server) |
//! | `4`  | MESSAGE   | Socket.IO payload (has sub-types) |
//!
//! Socket.IO MESSAGE frames (`4…`) have their own sub-type prefix:
//!
//! | Prefix | Socket.IO | Meaning |
//! |--------|-----------|---------|
//! | `40`   | CONNECT   | Namespace connect |
//! | `41`   | DISCONNECT| Namespace disconnect |
//! | `42`   | EVENT     | Named event with JSON array data |
//! | `43`   | ACK       | Event acknowledgement |
//! | `44`   | CONNECT_ERROR | Connection error |
//!
//! The data-bearing frame is `42["event_name", {json_payload}]`.
//! We extract the JSON payload from EVENT frames and pass it through
//! to the normal JSON extraction pipeline.

/// Decoded Socket.IO frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SocketIoFrame<'a> {
    /// Engine.IO control frame (OPEN, CLOSE, PING, PONG).
    Control,
    /// Socket.IO CONNECT or DISCONNECT — no actionable data.
    ConnectControl,
    /// Socket.IO EVENT: `42["event_name", payload]`.
    Event {
        event_name: &'a str,
        /// Raw JSON of the data argument(s) following the event name.
        /// For `42["message",{"text":"hi"}]` this is `{"text":"hi"}`.
        data_json: &'a str,
    },
    /// Socket.IO ACK — typically not interesting for content extraction.
    Ack,
    /// Unrecognised frame.
    Unknown,
}

/// Try to decode a Socket.IO/Engine.IO text frame.
///
/// Returns `None` if the payload is empty or not valid UTF-8.
pub(super) fn decode_socketio_frame(payload: &[u8]) -> Option<SocketIoFrame<'_>> {
    let text = std::str::from_utf8(payload).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let first = text.as_bytes()[0];
    match first {
        // Engine.IO: OPEN(0), CLOSE(1), PING(2), PONG(3)
        b'0' | b'1' | b'2' | b'3' => Some(SocketIoFrame::Control),

        // Engine.IO MESSAGE(4) → Socket.IO sub-type
        b'4' => {
            if text.len() < 2 {
                return Some(SocketIoFrame::Unknown);
            }
            let sub = text.as_bytes()[1];
            match sub {
                // 40 = CONNECT, 41 = DISCONNECT
                b'0' | b'1' => Some(SocketIoFrame::ConnectControl),
                // 42 = EVENT
                b'2' => decode_event(&text[2..]),
                // 43 = ACK
                b'3' => Some(SocketIoFrame::Ack),
                // 44 = CONNECT_ERROR, or unknown
                _ => Some(SocketIoFrame::Unknown),
            }
        }

        _ => Some(SocketIoFrame::Unknown),
    }
}

/// Decode a Socket.IO EVENT payload: the part after the `42` prefix.
///
/// Format: `["event_name", arg0, arg1, ...]`
/// With optional namespace: `/ns,["event_name", arg0]`
///
/// All returned slices borrow from the input `rest` string, avoiding
/// any intermediate heap allocation.
fn decode_event(rest: &str) -> Option<SocketIoFrame<'_>> {
    let rest = rest.trim();

    // Skip optional namespace prefix: `/namespace,`
    let array_str = if rest.starts_with('/') {
        rest.find(',').map(|i| &rest[i + 1..]).unwrap_or(rest)
    } else {
        rest
    }
    .trim();

    // Must be a JSON array: ["event_name", ...]
    if !array_str.starts_with('[') {
        return Some(SocketIoFrame::Unknown);
    }

    // Extract event name and data directly from the string to avoid
    // lifetime issues with serde_json::Value intermediates.
    let inner = array_str.strip_prefix('[')?.strip_suffix(']')?.trim();
    if !inner.starts_with('"') {
        return Some(SocketIoFrame::Unknown);
    }

    // Walk past the opening quote to find the matching close quote,
    // handling escaped characters.
    let mut in_escape = false;
    let mut end_quote = None;
    for (i, ch) in inner[1..].char_indices() {
        if in_escape {
            in_escape = false;
            continue;
        }
        if ch == '\\' {
            in_escape = true;
            continue;
        }
        if ch == '"' {
            end_quote = Some(i + 1);
            break;
        }
    }
    let end_quote = end_quote?;

    // The event name is the substring between the quotes.  For names
    // with escape sequences (rare), do a quick unescape.
    let raw_name = &inner[1..end_quote];
    let event_name = if raw_name.contains('\\') {
        // Slow path: unescape.  We can't return a &str into a new
        // String, so fall back to serde for correctness.
        return decode_event_with_serde(array_str);
    } else {
        raw_name
    };

    // After the closing quote, skip whitespace and comma to find data.
    let after_name = inner[end_quote + 1..].trim_start();
    let data_json = if let Some(after_comma) = after_name.strip_prefix(',') {
        let trimmed = after_comma.trim();
        if trimmed.is_empty() {
            "{}"
        } else {
            trimmed
        }
    } else {
        "{}"
    };

    Some(SocketIoFrame::Event {
        event_name,
        data_json,
    })
}

/// Fallback decoder that uses serde for event names with escape sequences.
/// Returns owned strings via a short-lived parse, but this path is rare.
fn decode_event_with_serde(array_str: &str) -> Option<SocketIoFrame<'_>> {
    let value: serde_json::Value = serde_json::from_str(array_str).ok()?;
    let arr = value.as_array()?;
    if arr.is_empty() {
        return Some(SocketIoFrame::Unknown);
    }
    // For escaped names we can't return a zero-copy &str, so just
    // extract the data portion from the original string and use a
    // placeholder event name.  The caller only needs data_json.
    let data_json = find_data_after_event_name(array_str).unwrap_or("{}");
    // The event name isn't used for content extraction — return a
    // sentinel that identifies it as a Socket.IO event.
    Some(SocketIoFrame::Event {
        event_name: "_socketio_escaped",
        data_json,
    })
}

/// Given `["event_name", {...}]`, return the substring `{...}` (without
/// the trailing `]`).
fn find_data_after_event_name(s: &str) -> Option<&str> {
    // Skip the opening `[`
    let inner = s.strip_prefix('[')?.strip_suffix(']')?.trim();

    // Find the end of the first JSON string (the event name).
    // We need to handle escaped quotes.
    if !inner.starts_with('"') {
        return None;
    }

    let mut in_escape = false;
    let mut end_quote = None;
    for (i, ch) in inner[1..].char_indices() {
        if in_escape {
            in_escape = false;
            continue;
        }
        if ch == '\\' {
            in_escape = true;
            continue;
        }
        if ch == '"' {
            end_quote = Some(i + 1); // +1 because we started at inner[1..]
            break;
        }
    }
    let end_quote = end_quote?;

    // After the closing quote of event_name, skip whitespace and comma.
    let after_name = inner[end_quote + 1..].trim_start();
    let after_comma = after_name.strip_prefix(',')?.trim_start();

    if after_comma.is_empty() {
        None
    } else {
        Some(after_comma)
    }
}

/// Check if a WebSocket text frame looks like a Socket.IO frame.
///
/// Quick heuristic: Socket.IO frames start with a digit 0-4.
/// This avoids full parsing for non-Socket.IO WebSocket traffic.
pub(super) fn looks_like_socketio(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    matches!(payload[0], b'0'..=b'4')
        && (payload.len() < 2 || !payload[1..].starts_with(b"{"))
        // Exclude bare JSON that happens to start with a digit after trim.
        // Socket.IO frames are `4[...]` or `42[...]`, never `4{...}`.
        || (payload.len() >= 3
            && payload[0] == b'4'
            && payload[1] == b'2'
            && (payload[2] == b'[' || payload[2] == b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ping_pong() {
        assert_eq!(decode_socketio_frame(b"2").unwrap(), SocketIoFrame::Control);
        assert_eq!(decode_socketio_frame(b"3").unwrap(), SocketIoFrame::Control);
    }

    #[test]
    fn decode_connect() {
        assert_eq!(
            decode_socketio_frame(b"40").unwrap(),
            SocketIoFrame::ConnectControl
        );
        // With namespace
        assert_eq!(
            decode_socketio_frame(b"40/chat,").unwrap(),
            SocketIoFrame::ConnectControl
        );
    }

    #[test]
    fn decode_simple_event() {
        let frame = br#"42["message",{"text":"hello world"}]"#;
        let decoded = decode_socketio_frame(frame).unwrap();
        match decoded {
            SocketIoFrame::Event {
                event_name,
                data_json,
            } => {
                assert_eq!(event_name, "message");
                assert_eq!(data_json, r#"{"text":"hello world"}"#);
            }
            other => panic!("Expected Event, got {other:?}"),
        }
    }

    #[test]
    fn decode_event_with_namespace() {
        let frame = br#"42/chat,["message",{"text":"hi"}]"#;
        let decoded = decode_socketio_frame(frame).unwrap();
        match decoded {
            SocketIoFrame::Event {
                event_name,
                data_json,
            } => {
                assert_eq!(event_name, "message");
                assert_eq!(data_json, r#"{"text":"hi"}"#);
            }
            other => panic!("Expected Event, got {other:?}"),
        }
    }

    #[test]
    fn decode_event_with_escaped_name() {
        let frame = br#"42["say \"hello\"",{"data":1}]"#;
        let decoded = decode_socketio_frame(frame).unwrap();
        match decoded {
            SocketIoFrame::Event {
                event_name,
                data_json,
            } => {
                // Escaped names use the serde fallback; event_name is a sentinel.
                assert_eq!(event_name, "_socketio_escaped");
                assert_eq!(data_json, r#"{"data":1}"#);
            }
            other => panic!("Expected Event, got {other:?}"),
        }
    }

    #[test]
    fn decode_event_no_data() {
        // EVENT with just the event name, no data arg
        let frame = br#"42["ping"]"#;
        let decoded = decode_socketio_frame(frame).unwrap();
        match decoded {
            SocketIoFrame::Event {
                event_name,
                data_json,
            } => {
                assert_eq!(event_name, "ping");
                assert_eq!(data_json, "{}");
            }
            other => panic!("Expected Event, got {other:?}"),
        }
    }

    #[test]
    fn decode_ack() {
        assert_eq!(decode_socketio_frame(b"43").unwrap(), SocketIoFrame::Ack);
    }

    #[test]
    fn looks_like_socketio_positive() {
        assert!(looks_like_socketio(b"42[\"msg\",{}]"));
        assert!(looks_like_socketio(b"42/ns,[\"msg\",{}]"));
        assert!(looks_like_socketio(b"2"));
        assert!(looks_like_socketio(b"3"));
    }

    #[test]
    fn looks_like_socketio_negative() {
        // Regular JSON WebSocket frame
        assert!(!looks_like_socketio(b"{\"type\":\"response.create\"}"));
        // Empty
        assert!(!looks_like_socketio(b""));
    }
}
