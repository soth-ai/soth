//! Header sanitation and payload decode helpers for proxy transport.

use brotli::Decompressor as BrotliDecoder;
use flate2::read::GzDecoder;
use hudsucker::hyper::{self, Request};
use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Read};
use tracing::{debug, warn};

use crate::json_security::strip_json_security_prefix_text;

/// Headers to remove from proxied requests to prevent 431 errors.
/// These headers can accumulate or cause issues when passing through a MITM proxy.
const HEADERS_TO_STRIP: &[&str] = &[
    // Proxy hop headers that can accumulate.
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-server",
    "forwarded",
    "x-real-ip",
    // Connection management (we handle these).
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    // These can cause issues with MITM.
    "expect-ct",
    "public-key-pins",
    "public-key-pins-report-only",
    // Alt-Svc can cause connection issues.
    "alt-svc",
    // Cloudflare/CDN headers that can accumulate.
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "true-client-ip",
    "x-cluster-client-ip",
];

/// Keep cookie header reasonably bounded without breaking login/session state.
pub(crate) const CHATGPT_MAX_COOKIE_HEADER_BYTES: usize = 3500;
/// Second-pass cap when total header budget is still too high.
const CHATGPT_STRICT_COOKIE_HEADER_BYTES: usize = 900;
/// Chat UI upstreams can be stricter than generic HTTP servers.
pub(crate) const CHAT_UI_STRICT_TOTAL_HEADER_BYTES: usize = 5200;
const CHAT_UI_MAX_TOTAL_HEADER_BYTES: usize = 3000;
const LARGE_HEADER_DEBUG_BYTES: usize = 8000;
const LARGE_HEADER_WARN_BYTES: usize = 12000;

pub(crate) fn is_chat_ui_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.contains("chatgpt.com") {
        return true;
    }
    if host == "chat.openai.com" || host.ends_with(".chat.openai.com") {
        return true;
    }
    // Include OpenAI web subdomains while excluding the direct API domain.
    if host.ends_with(".openai.com") && !host.starts_with("api.") {
        return true;
    }
    false
}

fn chatgpt_cookie_priority(name: &str) -> u8 {
    match name {
        // NextAuth/Auth.js session and csrf cookies (highest priority for login state).
        "__Secure-next-auth.session-token" => 0,
        "__Host-next-auth.csrf-token" => 0,
        "__Secure-next-auth.callback-url" => 1,
        "__Secure-authjs.session-token" => 0,
        "__Host-authjs.csrf-token" => 0,
        "__Secure-authjs.callback-url" => 1,
        // OpenAI account identifiers.
        "_account" | "_puid" | "oai-did" => 1,
        // Cloudflare access checks.
        "__cf_bm" | "cf_clearance" => 1,
        _ => {
            if name.starts_with("__Secure-") || name.starts_with("__Host-") {
                return 2;
            }
            if name.starts_with("oai-") || name.starts_with("__cf") || name.starts_with("cf_") {
                return 3;
            }
            if name.contains("session") || name.contains("token") || name.contains("auth") {
                return 4;
            }
            10
        }
    }
}

pub(crate) fn trim_cookie_header_for_chatgpt(cookie_str: &str, max_bytes: usize) -> Option<String> {
    let parts: Vec<&str> = cookie_str
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        return None;
    }

    // Deduplicate by name while keeping the last seen value (browser semantics).
    let mut by_name: HashMap<String, (usize, String)> = HashMap::new();
    for (idx, raw_part) in parts.iter().enumerate() {
        let (name, value) = match raw_part.split_once('=') {
            Some((name, value)) => (name.trim(), value.trim()),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        by_name.insert(name.to_string(), (idx, value.to_string()));
    }

    if by_name.is_empty() {
        return None;
    }

    let mut ranked: Vec<(u8, usize, String)> = by_name
        .into_iter()
        .map(|(name, (idx, value))| {
            let prio = chatgpt_cookie_priority(&name);
            (prio, idx, format!("{}={}", name, value))
        })
        .collect();
    ranked.sort_by_key(|(prio, idx, _)| (*prio, *idx));

    let mut kept = Vec::new();
    let mut total_len = 0usize;

    for (_, _, item) in ranked {
        let next_len = if kept.is_empty() {
            item.len()
        } else {
            total_len + 2 + item.len()
        };
        if next_len <= max_bytes {
            total_len = next_len;
            kept.push(item);
        }
    }

    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

pub(crate) fn header_size_bytes(headers: &hyper::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum()
}

pub(crate) fn parse_content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-claude-api-key"
            | "proxy-authorization"
    )
}

pub(crate) fn capture_sanitized_headers(headers: &hyper::HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_ascii_lowercase();
        if matches!(key.as_str(), "cookie" | "set-cookie") {
            continue;
        }
        if is_sensitive_header(&key) {
            out.insert(key, "[REDACTED]".to_string());
            continue;
        }
        if let Ok(text) = value.to_str() {
            out.insert(key, text.to_string());
        }
    }
    out
}

fn is_required_chat_ui_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "user-agent"
            | "accept"
            | "accept-language"
            | "accept-encoding"
            | "content-type"
            | "content-length"
            | "authorization"
            | "cookie"
            | "origin"
            | "referer"
            | "connection"
            | "sec-fetch-site"
            | "sec-fetch-mode"
            | "sec-fetch-dest"
            | "sec-ch-ua"
            | "sec-ch-ua-mobile"
            | "sec-ch-ua-platform"
            | "x-openai-client-fingerprint"
            | "x-openai-assistant-app-id"
            | "x-openai-latency-hint"
    )
}

fn reduce_chat_ui_headers_for_budget<T>(req: &mut Request<T>, path: &str) {
    let headers = req.headers_mut();
    if header_size_bytes(headers) <= CHAT_UI_STRICT_TOTAL_HEADER_BYTES {
        return;
    }

    let names: Vec<hyper::header::HeaderName> = headers.keys().cloned().collect();
    for name in names {
        let key = name.as_str().to_ascii_lowercase();
        if is_required_chat_ui_header(&key) {
            continue;
        }
        headers.remove(&name);
        if header_size_bytes(headers) <= CHAT_UI_STRICT_TOTAL_HEADER_BYTES {
            break;
        }
    }

    if header_size_bytes(headers) > CHAT_UI_STRICT_TOTAL_HEADER_BYTES {
        if let Some(cookie) = headers.get(hyper::header::COOKIE).cloned() {
            if let Ok(cookie_str) = cookie.to_str() {
                if let Some(trimmed) =
                    trim_cookie_header_for_chatgpt(cookie_str, CHATGPT_STRICT_COOKIE_HEADER_BYTES)
                {
                    if let Ok(hv) = hyper::header::HeaderValue::from_str(&trimmed) {
                        headers.insert(hyper::header::COOKIE, hv);
                    } else {
                        headers.remove(hyper::header::COOKIE);
                    }
                } else {
                    headers.remove(hyper::header::COOKIE);
                }
            } else {
                headers.remove(hyper::header::COOKIE);
            }
        }
    }

    if header_size_bytes(headers) > CHAT_UI_MAX_TOTAL_HEADER_BYTES {
        headers.remove(hyper::header::COOKIE);
    }

    if header_size_bytes(headers) > CHAT_UI_MAX_TOTAL_HEADER_BYTES {
        headers.remove(hyper::header::AUTHORIZATION);
    }

    let _ = path;
}

pub(crate) fn sanitize_request_headers<T>(req: &mut Request<T>, host: &str, path: &str) {
    let headers = req.headers_mut();
    let is_chatgpt = is_chat_ui_host(host);
    let is_chat_backend_path = path.contains("/backend-api/");

    for header in HEADERS_TO_STRIP {
        headers.remove(*header);
    }

    if is_chatgpt {
        // Reduce duplicate/oversized cookies first.
        if let Some(cookie) = headers.get(hyper::header::COOKIE).cloned() {
            if let Ok(cookie_str) = cookie.to_str() {
                if cookie_str.len() > CHATGPT_MAX_COOKIE_HEADER_BYTES {
                    if let Some(trimmed) =
                        trim_cookie_header_for_chatgpt(cookie_str, CHATGPT_MAX_COOKIE_HEADER_BYTES)
                    {
                        if let Ok(hv) = hyper::header::HeaderValue::from_str(&trimmed) {
                            headers.insert(hyper::header::COOKIE, hv);
                            debug!(
                                host = %host,
                                path = %path,
                                original = cookie_str.len(),
                                trimmed = trimmed.len(),
                                max = CHATGPT_MAX_COOKIE_HEADER_BYTES,
                                "Trimmed oversized ChatGPT cookie header"
                            );
                        } else {
                            headers.remove(hyper::header::COOKIE);
                        }
                    } else {
                        headers.remove(hyper::header::COOKIE);
                    }
                } else {
                    // Re-pack once to dedupe even when under max.
                    if let Some(trimmed) =
                        trim_cookie_header_for_chatgpt(cookie_str, CHATGPT_MAX_COOKIE_HEADER_BYTES)
                    {
                        if let Ok(hv) = hyper::header::HeaderValue::from_str(&trimmed) {
                            headers.insert(hyper::header::COOKIE, hv);
                        }
                    }
                }
            } else {
                headers.remove(hyper::header::COOKIE);
            }
        }
    }

    // If header budget is still too large, reduce to required Chat UI set.
    if is_chatgpt && is_chat_backend_path {
        let total_size = header_size_bytes(headers);
        if total_size > CHAT_UI_STRICT_TOTAL_HEADER_BYTES {
            reduce_chat_ui_headers_for_budget(req, path);
            debug!(
                host = %host,
                path = %path,
                before = total_size,
                after = header_size_bytes(req.headers()),
                "Reduced Chat UI headers to fit strict upstream budget"
            );
        }
    }

    // Emit visibility when large headers remain (often due to unavoidable auth headers).
    let total_size = header_size_bytes(req.headers());
    if total_size > LARGE_HEADER_DEBUG_BYTES {
        let mut top: Vec<(String, usize)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().len()))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let top = top
            .into_iter()
            .take(3)
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(", ");
        if total_size > LARGE_HEADER_WARN_BYTES {
            warn!(total = total_size, top = %top, host = %host, "Large headers");
        } else {
            debug!(total = total_size, top = %top, host = %host, "Large headers");
        }
    }
}

fn detect_compression_from_bytes(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return Some("gzip");
    }
    if bytes.len() >= 4
        && bytes[0] == 0x28
        && bytes[1] == 0xb5
        && bytes[2] == 0x2f
        && bytes[3] == 0xfd
    {
        return Some("zstd");
    }
    if bytes.len() >= 2 {
        let cmf = bytes[0];
        let flg = bytes[1];
        let is_zlib = cmf == 0x78 && ((u16::from(cmf) << 8) + u16::from(flg)) % 31 == 0;
        if is_zlib {
            return Some("deflate");
        }
    }
    None
}

fn parse_content_encoding_chain(encoding: Option<&str>) -> Vec<String> {
    encoding
        .map(|v| {
            v.split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .filter(|part| !part.is_empty())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

fn decompress_once(bytes: &[u8], encoding: &str) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(Cursor::new(bytes));
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).ok()?;
            Some(output)
        }
        "deflate" => {
            let mut decoder = flate2::read::ZlibDecoder::new(Cursor::new(bytes));
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).ok()?;
            Some(output)
        }
        "br" => {
            let mut decoder = BrotliDecoder::new(Cursor::new(bytes), 4096);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).ok()?;
            Some(output)
        }
        "zstd" => zstd::stream::decode_all(Cursor::new(bytes)).ok(),
        _ => None,
    }
}

fn maybe_binary_placeholder(bytes: &[u8], encoding: Option<&str>) -> Option<String> {
    let lossy = String::from_utf8_lossy(bytes);
    let sample: Vec<char> = lossy.chars().take(4096).collect();
    let chars = sample.len().max(1);
    let replacement_chars = sample.iter().filter(|c| **c == '\u{FFFD}').count();
    let control_chars = sample
        .iter()
        .filter(|c| c.is_control() && **c != '\n' && **c != '\r' && **c != '\t')
        .count();
    let ascii_printable = sample
        .iter()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    let replacement_ratio = replacement_chars as f32 / chars as f32;
    let control_ratio = control_chars as f32 / chars as f32;
    let ascii_printable_ratio = ascii_printable as f32 / chars as f32;

    let has_magic = detect_compression_from_bytes(bytes).is_some();
    let looks_binary = replacement_chars >= 2
        || replacement_ratio >= 0.04
        || control_ratio >= 0.03
        || ascii_printable_ratio < 0.55
        || (has_magic && bytes.len() <= 16);

    if looks_binary {
        let coding = parse_content_encoding_chain(encoding)
            .first()
            .cloned()
            .or_else(|| detect_compression_from_bytes(bytes).map(str::to_string))
            .unwrap_or_else(|| "binary".to_string());
        return Some(format!(
            "[compressed/{} payload: {} bytes]",
            coding,
            bytes.len()
        ));
    }

    None
}

pub(crate) fn try_decompress(bytes: &[u8], encoding: Option<&str>) -> Vec<u8> {
    let encodings = parse_content_encoding_chain(encoding);
    if !encodings.is_empty() {
        let mut current = bytes.to_vec();
        // Encodings are listed in application order; decoding must reverse that order.
        for encoding in encodings.into_iter().rev() {
            if encoding == "identity" {
                continue;
            }
            match decompress_once(&current, &encoding) {
                Some(next) => current = next,
                None => return bytes.to_vec(),
            }
        }
        return current;
    }

    if let Some(magic_encoding) = detect_compression_from_bytes(bytes) {
        if let Some(next) = decompress_once(bytes, magic_encoding) {
            return next;
        }
    }

    bytes.to_vec()
}

fn render_decoded_body_for_logging(decoded: &[u8], encoding: Option<&str>) -> String {
    if let Some(placeholder) = maybe_binary_placeholder(decoded, encoding) {
        return placeholder;
    }
    String::from_utf8_lossy(decoded).to_string()
}

#[cfg(test)]
pub(crate) fn decode_body_for_logging(bytes: &[u8], encoding: Option<&str>) -> String {
    let decoded = try_decompress(bytes, encoding);
    render_decoded_body_for_logging(&decoded, encoding)
}

pub(crate) fn decode_payload_for_logging(
    bytes: &[u8],
    encoding: Option<&str>,
) -> (Vec<u8>, String) {
    let decoded = try_decompress(bytes, encoding);
    let rendered = render_decoded_body_for_logging(&decoded, encoding);
    (decoded, rendered)
}

pub(crate) fn is_gemini_bard_stream_path(path: &str) -> bool {
    path.contains("/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate")
        || path.contains("/batchexecute")
}

fn update_longest_text(candidate: &str, longest: &mut Option<String>) {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }
    let should_replace = longest
        .as_ref()
        .map(|existing| trimmed.len() > existing.len())
        .unwrap_or(true);
    if should_replace {
        *longest = Some(trimmed.to_string());
    }
}

fn collect_bard_response_text(value: &serde_json::Value, longest: &mut Option<String>) {
    match value {
        serde_json::Value::String(text) => update_longest_text(text, longest),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_bard_response_text(item, longest);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_bard_response_text(v, longest);
            }
        }
        _ => {}
    }
}

pub(crate) fn extract_gemini_bard_stream_text(raw: &str) -> Option<String> {
    let mut longest: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        let sanitized = strip_json_security_prefix_text(trimmed);
        if sanitized.is_empty() {
            continue;
        }

        if !sanitized.starts_with('[') {
            // Batch framing length lines are numeric and can be ignored.
            continue;
        }

        let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(sanitized) else {
            continue;
        };

        let Some(records) = wrapper.as_array() else {
            continue;
        };

        for record in records {
            let Some(entry) = record.as_array() else {
                continue;
            };
            if entry.first().and_then(|v| v.as_str()) != Some("wrb.fr") {
                continue;
            }

            let Some(inner_json) = entry.get(2).and_then(|v| v.as_str()) else {
                continue;
            };

            let Ok(inner) = serde_json::from_str::<serde_json::Value>(inner_json) else {
                continue;
            };
            collect_bard_response_text(&inner, &mut longest);
        }
    }

    longest
}
