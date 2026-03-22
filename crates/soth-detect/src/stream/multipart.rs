use super::extract_structured_text;

pub(super) fn parse_multipart_payload_text(payload: &[u8]) -> Option<String> {
    if let Some(delta) = extract_structured_text(payload) {
        return Some(delta);
    }

    let text = std::str::from_utf8(payload).ok()?;
    let boundary = text.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("--") && trimmed.len() > 2 {
            Some(trimmed.to_string())
        } else {
            None
        }
    })?;

    for part in text.split(&boundary).skip(1) {
        let trimmed = part.trim();
        if trimmed.is_empty() || trimmed == "--" {
            continue;
        }

        let body = part
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .or_else(|| part.split_once("\n\n").map(|(_, body)| body));
        let Some(body) = body else {
            continue;
        };

        let body = body.trim().trim_end_matches("--").trim();
        if body.is_empty() {
            continue;
        }

        if let Some(delta) = extract_structured_text(body.as_bytes()) {
            return Some(delta);
        }
    }

    None
}
