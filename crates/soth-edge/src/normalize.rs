//! Body content normalization primitives for edge capture.

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE as BASE64_URL_SAFE};
use base64::Engine as _;
use flate2::read::{GzDecoder, ZlibDecoder};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::sync::mpsc;
use std::time::Duration;

const GZIP_MAGIC: &[u8] = b"\x1f\x8b";
const ZSTD_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";
const ZLIB_PREFIXES: [&[u8]; 3] = [b"\x78\x01", b"\x78\x9c", b"\x78\xda"];

const MAX_DECODE_LAYERS: usize = 3;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const MAX_PROTOBUF_MESSAGE_SIZE: usize = 1_000_000;
const MAX_PROTOBUF_RECURSION_DEPTH: usize = 8;
const MAX_MSGPACK_RECURSION_DEPTH: usize = 64;
const MIN_BASE64_LENGTH: usize = 20;
const PROTOBUF_DECODE_TIMEOUT: Duration = Duration::from_secs(2);

const ANTI_HIJACK_PREFIXES: [&[u8]; 5] = [b")]}'\n", b")]}'", b"for(;;);", b"while(1);", b"{}&&"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleStreamFormat {
    Sse,
    Ndjson,
    LengthPrefixed,
    Websocket,
    Unknown,
}

impl BundleStreamFormat {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "sse" => Self::Sse,
            "ndjson" => Self::Ndjson,
            "length_prefixed" => Self::LengthPrefixed,
            "websocket" => Self::Websocket,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleStreamParser {
    pub format: BundleStreamFormat,
    pub prefixes: Vec<String>,
    pub skip_values: Vec<String>,
}

impl BundleStreamParser {
    pub fn sse(prefixes: Vec<String>, skip_values: Vec<String>) -> Self {
        let prefixes = if prefixes.is_empty() {
            vec!["data: ".to_string()]
        } else {
            prefixes
        };

        let skip_values = if skip_values.is_empty() {
            vec!["[DONE]".to_string()]
        } else {
            skip_values
        };

        Self {
            format: BundleStreamFormat::Sse,
            prefixes,
            skip_values,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Gzip,
    Zstd,
    Deflate,
    Base64,
    Base64Url,
    Url,
}

#[derive(Clone, Debug)]
enum MsgpackNode {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    String(String),
    Binary(Vec<u8>),
    Array(Vec<MsgpackNode>),
    Map(Vec<(MsgpackNode, MsgpackNode)>),
    Ext(i8, Vec<u8>),
}

pub fn normalize_body(content: &[u8], content_type: Option<&str>) -> String {
    if content.is_empty() {
        return String::new();
    }

    if content.len() > MAX_BODY_SIZE {
        let preview_len = content.len().min(1_000);
        return format!(
            "{}... [truncated, total {} bytes]",
            to_string_content(&content[..preview_len]),
            content.len()
        );
    }

    if is_grpc_content(content_type) {
        return normalize_grpc(content, content_type);
    }

    if has_anti_hijack_prefix(content) {
        return normalize_anti_hijack_stream(content);
    }

    if is_sse_stream(content_type) {
        let (normalized, _) = normalize_sse(content);
        return normalized;
    }

    if is_msgpack(content) {
        if let Some(decoded) = decode_msgpack(content) {
            return decoded;
        }
    }

    let layered = decode_layers(content);
    to_string_content(&layered)
}

pub fn normalize_body_with_stream_parser(
    content: &[u8],
    content_type: Option<&str>,
    stream_parser: Option<&BundleStreamParser>,
) -> String {
    let Some(stream_parser) = stream_parser else {
        return normalize_body(content, content_type);
    };

    let parser_applies =
        stream_parser.format == BundleStreamFormat::Sse && is_sse_stream(content_type);
    if !parser_applies {
        return normalize_body(content, content_type);
    }

    if let Some(parsed) = normalize_sse_with_parser(content, stream_parser) {
        return parsed;
    }

    normalize_body(content, content_type)
}

pub fn normalize_grpc(content: &[u8], _content_type: Option<&str>) -> String {
    if content.is_empty() {
        return String::new();
    }

    let mut messages = decode_grpc_frames(content);
    if messages.is_empty() {
        messages.push(content);
    }

    let decoded = messages
        .into_iter()
        .map(|message| {
            decode_protobuf_schemaless(message).unwrap_or_else(|| {
                Value::Object(
                    [(
                        "_raw_base64".to_string(),
                        Value::String(BASE64_STANDARD.encode(message)),
                    )]
                    .into_iter()
                    .collect(),
                )
            })
        })
        .collect::<Vec<_>>();

    if decoded.len() == 1 {
        return to_json_string(&decoded[0]);
    }

    to_json_string(&Value::Array(decoded))
}

fn is_grpc_content(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        let lower = value.to_ascii_lowercase();
        lower.contains("application/grpc") || lower.contains("application/x-protobuf")
    })
}

fn decode_grpc_frames(content: &[u8]) -> Vec<&[u8]> {
    let mut messages = Vec::new();
    let mut offset = 0usize;

    while offset + 5 <= content.len() {
        let length = u32::from_be_bytes([
            content[offset + 1],
            content[offset + 2],
            content[offset + 3],
            content[offset + 4],
        ]) as usize;
        offset += 5;

        if offset + length > content.len() {
            break;
        }

        messages.push(&content[offset..offset + length]);
        offset += length;
    }

    messages
}

fn decode_protobuf_schemaless(data: &[u8]) -> Option<Value> {
    if data.len() > MAX_PROTOBUF_MESSAGE_SIZE {
        return None;
    }

    decode_protobuf_with_timeout(data)
}

fn decode_protobuf_with_timeout(data: &[u8]) -> Option<Value> {
    let (sender, receiver) = mpsc::channel();
    let payload = data.to_vec();

    let spawn_result = std::thread::Builder::new()
        .name("soth-edge-protobuf-decode".to_string())
        .spawn(move || {
            let parsed = decode_protobuf_message(&payload, 0).map(Value::Object);
            let _ = sender.send(parsed);
        });

    if spawn_result.is_err() {
        return None;
    }

    receiver
        .recv_timeout(PROTOBUF_DECODE_TIMEOUT)
        .ok()
        .flatten()
}

fn decode_protobuf_message(data: &[u8], depth: usize) -> Option<Map<String, Value>> {
    if data.is_empty() || depth > MAX_PROTOBUF_RECURSION_DEPTH {
        return None;
    }

    let mut fields: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let (key, key_len) = decode_varint(&data[offset..])?;
        if key == 0 {
            return None;
        }

        offset += key_len;
        let field_number = key >> 3;
        let wire_type = (key & 0x07) as u8;
        if field_number == 0 {
            return None;
        }

        let value = match wire_type {
            0 => {
                let (varint, varint_len) = decode_varint(&data[offset..])?;
                offset += varint_len;
                Value::Number(Number::from(varint))
            }
            1 => {
                if offset + 8 > data.len() {
                    return None;
                }
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&data[offset..offset + 8]);
                offset += 8;
                Value::Number(Number::from(u64::from_le_bytes(raw)))
            }
            2 => {
                let (length, length_len) = decode_varint(&data[offset..])?;
                offset += length_len;
                let length = usize::try_from(length).ok()?;
                if offset + length > data.len() {
                    return None;
                }
                let chunk = &data[offset..offset + length];
                offset += length;
                decode_protobuf_length_delimited(chunk, depth + 1)
            }
            5 => {
                if offset + 4 > data.len() {
                    return None;
                }
                let mut raw = [0u8; 4];
                raw.copy_from_slice(&data[offset..offset + 4]);
                offset += 4;
                Value::Number(Number::from(u32::from_le_bytes(raw)))
            }
            _ => return None,
        };

        fields.entry(field_number).or_default().push(value);
    }

    if fields.is_empty() {
        return None;
    }

    let mut output = Map::new();
    for (field, mut values) in fields {
        if values.len() == 1 {
            if let Some(value) = values.pop() {
                output.insert(field.to_string(), value);
            }
        } else {
            output.insert(field.to_string(), Value::Array(values));
        }
    }

    Some(output)
}

fn decode_protobuf_length_delimited(data: &[u8], depth: usize) -> Value {
    if let Ok(text) = std::str::from_utf8(data) {
        return Value::String(text.to_string());
    }

    if looks_like_protobuf_message(data) {
        if let Some(nested) = decode_protobuf_message(data, depth) {
            return Value::Object(nested);
        }
    }

    Value::String(BASE64_STANDARD.encode(data))
}

fn decode_varint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (idx, byte) in input.iter().copied().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, idx + 1));
        }
        shift += 7;
    }

    None
}

fn looks_like_protobuf_message(input: &[u8]) -> bool {
    let Some((key, _)) = decode_varint(input) else {
        return false;
    };

    let wire_type = key & 0x07;
    let field_number = key >> 3;
    field_number > 0 && matches!(wire_type, 0 | 1 | 2 | 5)
}

fn to_string_content(content: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(content) {
        return text.to_string();
    }

    let printable = content
        .iter()
        .filter(|&&byte| (32..127).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r'))
        .count();

    if !content.is_empty() && printable as f64 / content.len() as f64 > 0.8 {
        return String::from_utf8_lossy(content).to_string();
    }

    to_json_string(&Value::Object(
        [(
            "_binary_base64".to_string(),
            Value::String(BASE64_STANDARD.encode(content)),
        )]
        .into_iter()
        .collect(),
    ))
}

fn is_sse_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"))
}

fn has_anti_hijack_prefix(content: &[u8]) -> bool {
    ANTI_HIJACK_PREFIXES
        .iter()
        .any(|prefix| content.starts_with(prefix))
}

fn anti_hijack_prefix(content: &[u8]) -> Option<&[u8]> {
    ANTI_HIJACK_PREFIXES
        .iter()
        .find(|prefix| content.starts_with(prefix))
        .copied()
}

fn normalize_anti_hijack_stream(content: &[u8]) -> String {
    let Ok(mut text) = std::str::from_utf8(content).map(str::to_string) else {
        return to_string_content(content);
    };

    if let Some(prefix) = anti_hijack_prefix(content) {
        text = text[prefix.len()..].trim_start_matches('\n').to_string();
    }

    let lines = text.lines().collect::<Vec<_>>();
    let mut chunks = Vec::<Value>::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx].trim();
        if line.is_empty() {
            idx += 1;
            continue;
        }

        if line.bytes().all(|byte| byte.is_ascii_digit()) {
            let Ok(length) = line.parse::<usize>() else {
                idx += 1;
                continue;
            };

            idx += 1;
            let mut json_lines = Vec::new();
            let mut collected = 0usize;
            while idx < lines.len() && collected < length {
                json_lines.push(lines[idx]);
                collected += lines[idx].len() + 1;
                idx += 1;
            }

            let json_text = json_lines.join("\n").trim().to_string();
            if json_text.is_empty() {
                continue;
            }

            if let Ok(parsed) = serde_json::from_str::<Value>(&json_text) {
                chunks.push(parsed);
            } else {
                chunks.push(Value::String(json_text));
            }

            continue;
        }

        if let Ok(parsed) = serde_json::from_str::<Value>(line) {
            chunks.push(parsed);
        }
        idx += 1;
    }

    if chunks.is_empty() {
        return text;
    }

    to_json_string(&Value::Array(chunks))
}

fn normalize_sse(content: &[u8]) -> (String, Option<String>) {
    let Ok(text) = std::str::from_utf8(content).map(str::to_string) else {
        return (to_string_content(content), None);
    };

    let mut extracted = Vec::new();
    let mut encoding_type = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(':') {
            continue;
        }

        if line == "data: [DONE]" {
            continue;
        }

        if let Some(rest) = line.strip_prefix("event:") {
            encoding_type = Some(rest.trim().to_string());
            continue;
        }

        if let Some(rest) = line.strip_prefix("data:") {
            let data = rest.trim();
            if data.is_empty() {
                continue;
            }

            let _ = serde_json::from_str::<Value>(data);
            extracted.push(data.to_string());
        }
    }

    if extracted.is_empty() {
        return (text, encoding_type);
    }

    (extracted.join(""), encoding_type)
}

fn normalize_sse_with_parser(content: &[u8], parser: &BundleStreamParser) -> Option<String> {
    let Ok(text) = std::str::from_utf8(content).map(str::to_string) else {
        return None;
    };

    let mut extracted = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(':') {
            continue;
        }

        let data = parser
            .prefixes
            .iter()
            .find(|prefix| line.starts_with(prefix.as_str()))
            .map(|prefix| line[prefix.len()..].trim());
        let Some(data) = data else {
            continue;
        };

        if data.is_empty()
            || parser
                .skip_values
                .iter()
                .any(|skip| skip.eq_ignore_ascii_case(data))
        {
            continue;
        }

        extracted.push(data.to_string());
    }

    if extracted.is_empty() {
        None
    } else {
        Some(extracted.join(""))
    }
}

fn is_msgpack(content: &[u8]) -> bool {
    let Some(&first) = content.first() else {
        return false;
    };

    (0x80..=0x9f).contains(&first) || matches!(first, 0xdc..=0xdf)
}

fn decode_msgpack(content: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    let value = parse_msgpack_node(content, &mut offset, 0)?;
    if offset != content.len() {
        return None;
    }

    let json = msgpack_to_json(&value);
    Some(to_json_string(&json))
}

fn parse_msgpack_node(input: &[u8], offset: &mut usize, depth: usize) -> Option<MsgpackNode> {
    if depth > MAX_MSGPACK_RECURSION_DEPTH {
        return None;
    }

    let marker = take_u8(input, offset)?;
    match marker {
        0x00..=0x7f => Some(MsgpackNode::U64(u64::from(marker))),
        0x80..=0x8f => {
            let count = usize::from(marker & 0x0f);
            parse_msgpack_map(input, offset, count, depth + 1).map(MsgpackNode::Map)
        }
        0x90..=0x9f => {
            let count = usize::from(marker & 0x0f);
            parse_msgpack_array(input, offset, count, depth + 1).map(MsgpackNode::Array)
        }
        0xa0..=0xbf => {
            let length = usize::from(marker & 0x1f);
            let bytes = take_exact(input, offset, length)?;
            let value = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string());
            Some(MsgpackNode::String(value))
        }
        0xc0 => Some(MsgpackNode::Null),
        0xc2 => Some(MsgpackNode::Bool(false)),
        0xc3 => Some(MsgpackNode::Bool(true)),
        0xc4 => {
            let length = usize::from(take_u8(input, offset)?);
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Binary(bytes.to_vec()))
        }
        0xc5 => {
            let length = usize::from(take_u16_be(input, offset)?);
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Binary(bytes.to_vec()))
        }
        0xc6 => {
            let length = usize::try_from(take_u32_be(input, offset)?).ok()?;
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Binary(bytes.to_vec()))
        }
        0xc7 => {
            let length = usize::from(take_u8(input, offset)?);
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xc8 => {
            let length = usize::from(take_u16_be(input, offset)?);
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xc9 => {
            let length = usize::try_from(take_u32_be(input, offset)?).ok()?;
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, length)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xca => Some(MsgpackNode::F64(f64::from(f32::from_bits(take_u32_be(
            input, offset,
        )?)))),
        0xcb => Some(MsgpackNode::F64(f64::from_bits(take_u64_be(
            input, offset,
        )?))),
        0xcc => Some(MsgpackNode::U64(u64::from(take_u8(input, offset)?))),
        0xcd => Some(MsgpackNode::U64(u64::from(take_u16_be(input, offset)?))),
        0xce => Some(MsgpackNode::U64(u64::from(take_u32_be(input, offset)?))),
        0xcf => Some(MsgpackNode::U64(take_u64_be(input, offset)?)),
        0xd0 => Some(MsgpackNode::I64(i64::from(take_u8(input, offset)? as i8))),
        0xd1 => Some(MsgpackNode::I64(i64::from(
            take_u16_be(input, offset)? as i16
        ))),
        0xd2 => Some(MsgpackNode::I64(i64::from(
            take_u32_be(input, offset)? as i32
        ))),
        0xd3 => Some(MsgpackNode::I64(take_u64_be(input, offset)? as i64)),
        0xd4 => {
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, 1)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xd5 => {
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, 2)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xd6 => {
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, 4)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xd7 => {
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, 8)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xd8 => {
            let ext_type = take_u8(input, offset)? as i8;
            let bytes = take_exact(input, offset, 16)?;
            Some(MsgpackNode::Ext(ext_type, bytes.to_vec()))
        }
        0xd9 => {
            let length = usize::from(take_u8(input, offset)?);
            let bytes = take_exact(input, offset, length)?;
            let value = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string());
            Some(MsgpackNode::String(value))
        }
        0xda => {
            let length = usize::from(take_u16_be(input, offset)?);
            let bytes = take_exact(input, offset, length)?;
            let value = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string());
            Some(MsgpackNode::String(value))
        }
        0xdb => {
            let length = usize::try_from(take_u32_be(input, offset)?).ok()?;
            let bytes = take_exact(input, offset, length)?;
            let value = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string());
            Some(MsgpackNode::String(value))
        }
        0xdc => {
            let count = usize::from(take_u16_be(input, offset)?);
            parse_msgpack_array(input, offset, count, depth + 1).map(MsgpackNode::Array)
        }
        0xdd => {
            let count = usize::try_from(take_u32_be(input, offset)?).ok()?;
            parse_msgpack_array(input, offset, count, depth + 1).map(MsgpackNode::Array)
        }
        0xde => {
            let count = usize::from(take_u16_be(input, offset)?);
            parse_msgpack_map(input, offset, count, depth + 1).map(MsgpackNode::Map)
        }
        0xdf => {
            let count = usize::try_from(take_u32_be(input, offset)?).ok()?;
            parse_msgpack_map(input, offset, count, depth + 1).map(MsgpackNode::Map)
        }
        0xe0..=0xff => Some(MsgpackNode::I64(i64::from(marker as i8))),
        _ => None,
    }
}

fn parse_msgpack_array(
    input: &[u8],
    offset: &mut usize,
    count: usize,
    depth: usize,
) -> Option<Vec<MsgpackNode>> {
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(parse_msgpack_node(input, offset, depth)?);
    }
    Some(items)
}

fn parse_msgpack_map(
    input: &[u8],
    offset: &mut usize,
    count: usize,
    depth: usize,
) -> Option<Vec<(MsgpackNode, MsgpackNode)>> {
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key = parse_msgpack_node(input, offset, depth)?;
        let value = parse_msgpack_node(input, offset, depth)?;
        entries.push((key, value));
    }
    Some(entries)
}

fn take_u8(input: &[u8], offset: &mut usize) -> Option<u8> {
    if *offset >= input.len() {
        return None;
    }
    let value = input[*offset];
    *offset += 1;
    Some(value)
}

fn take_u16_be(input: &[u8], offset: &mut usize) -> Option<u16> {
    let bytes = take_exact(input, offset, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u32_be(input: &[u8], offset: &mut usize) -> Option<u32> {
    let bytes = take_exact(input, offset, 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take_u64_be(input: &[u8], offset: &mut usize) -> Option<u64> {
    let bytes = take_exact(input, offset, 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn take_exact<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    let bytes = &input[*offset..end];
    *offset = end;
    Some(bytes)
}

fn msgpack_to_json(value: &MsgpackNode) -> Value {
    match value {
        MsgpackNode::Null => Value::Null,
        MsgpackNode::Bool(flag) => Value::Bool(*flag),
        MsgpackNode::I64(number) => Value::Number(Number::from(*number)),
        MsgpackNode::U64(number) => Value::Number(Number::from(*number)),
        MsgpackNode::F64(number) => {
            if let Some(value) = Number::from_f64(*number) {
                Value::Number(value)
            } else {
                Value::String(number.to_string())
            }
        }
        MsgpackNode::String(text) => Value::String(text.to_string()),
        MsgpackNode::Binary(bytes) => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                Value::String(text.to_string())
            } else {
                Value::String(BASE64_STANDARD.encode(bytes))
            }
        }
        MsgpackNode::Array(values) => {
            Value::Array(values.iter().map(msgpack_to_json).collect::<Vec<_>>())
        }
        MsgpackNode::Map(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                map.insert(msgpack_key_to_string(key), msgpack_to_json(value));
            }
            Value::Object(map)
        }
        MsgpackNode::Ext(ty, data) => Value::Object(
            [
                (
                    "_ext_type".to_string(),
                    Value::Number(Number::from(i64::from(*ty))),
                ),
                (
                    "_raw_base64".to_string(),
                    Value::String(BASE64_STANDARD.encode(data)),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

fn msgpack_key_to_string(value: &MsgpackNode) -> String {
    match value {
        MsgpackNode::String(text) => text.to_string(),
        MsgpackNode::I64(number) => number.to_string(),
        MsgpackNode::U64(number) => number.to_string(),
        MsgpackNode::F64(number) => number.to_string(),
        MsgpackNode::Bool(flag) => flag.to_string(),
        MsgpackNode::Null => "null".to_string(),
        MsgpackNode::Binary(bytes) => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                text.to_string()
            } else {
                BASE64_STANDARD.encode(bytes)
            }
        }
        _ => to_json_string(&msgpack_to_json(value)),
    }
}

fn decode_layers(content: &[u8]) -> Vec<u8> {
    let mut current = content.to_vec();

    for _ in 0..MAX_DECODE_LAYERS {
        let Some(encoding) = detect_encoding(&current) else {
            break;
        };

        let Some(decoded) = apply_decoder(&current, encoding) else {
            break;
        };

        if decoded == current {
            break;
        }

        current = decoded;
    }

    current
}

fn detect_encoding(content: &[u8]) -> Option<Encoding> {
    if content.len() < 2 {
        return None;
    }

    if content.starts_with(GZIP_MAGIC) {
        return Some(Encoding::Gzip);
    }

    if content.len() >= 4 && content.starts_with(ZSTD_MAGIC) {
        return Some(Encoding::Zstd);
    }

    if ZLIB_PREFIXES
        .iter()
        .any(|prefix| content.starts_with(prefix))
    {
        return Some(Encoding::Deflate);
    }

    if content.contains(&b'%')
        && has_percent_encoded(content)
        && std::str::from_utf8(content).is_ok()
    {
        return Some(Encoding::Url);
    }

    if content.len() < MIN_BASE64_LENGTH {
        return None;
    }

    if std::str::from_utf8(content).is_err() {
        return None;
    }

    let stripped = trim_ascii_whitespace(content);
    if stripped.is_empty() || stripped.len() % 4 > 2 {
        return None;
    }

    if is_standard_base64(stripped) {
        if decode_base64(stripped).is_some_and(|value| !value.is_empty()) {
            return Some(Encoding::Base64);
        }
    } else if is_urlsafe_base64(stripped)
        && decode_base64_url(stripped).is_some_and(|value| !value.is_empty())
    {
        return Some(Encoding::Base64Url);
    }

    None
}

fn apply_decoder(content: &[u8], encoding: Encoding) -> Option<Vec<u8>> {
    match encoding {
        Encoding::Gzip => {
            let mut reader = GzDecoder::new(content);
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).ok()?;
            Some(decoded)
        }
        Encoding::Deflate => {
            let mut reader = ZlibDecoder::new(content);
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).ok()?;
            Some(decoded)
        }
        Encoding::Zstd => zstd::stream::decode_all(Cursor::new(content)).ok(),
        Encoding::Base64 => decode_base64(content),
        Encoding::Base64Url => decode_base64_url(content),
        Encoding::Url => decode_url(content),
    }
}

fn decode_base64(content: &[u8]) -> Option<Vec<u8>> {
    let text = padded_ascii(content)?;
    BASE64_STANDARD.decode(text).ok()
}

fn decode_base64_url(content: &[u8]) -> Option<Vec<u8>> {
    let text = padded_ascii(content)?;
    BASE64_URL_SAFE.decode(text).ok()
}

fn decode_url(content: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(content).ok()?;
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && is_hex(bytes[idx + 1])
            && is_hex(bytes[idx + 2])
        {
            let high = hex_value(bytes[idx + 1]);
            let low = hex_value(bytes[idx + 2]);
            out.push((high << 4) | low);
            idx += 3;
            continue;
        }

        out.push(bytes[idx]);
        idx += 1;
    }

    Some(out)
}

fn has_percent_encoded(content: &[u8]) -> bool {
    content
        .windows(3)
        .any(|window| window[0] == b'%' && is_hex(window[1]) && is_hex(window[2]))
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn trim_ascii_whitespace(content: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = content.len();

    while start < end && content[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && content[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &content[start..end]
}

fn is_standard_base64(content: &[u8]) -> bool {
    is_base64_with_alphabet(content, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
    })
}

fn is_urlsafe_base64(content: &[u8]) -> bool {
    is_base64_with_alphabet(content, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
    })
}

fn is_base64_with_alphabet(content: &[u8], is_allowed: impl Fn(u8) -> bool) -> bool {
    if content.is_empty() {
        return false;
    }

    let mut equals_started = false;
    let mut equals_count = 0usize;

    for &byte in content {
        if byte == b'=' {
            equals_started = true;
            equals_count += 1;
            if equals_count > 2 {
                return false;
            }
            continue;
        }

        if equals_started {
            return false;
        }

        if !is_allowed(byte) {
            return false;
        }
    }

    true
}

fn padded_ascii(content: &[u8]) -> Option<String> {
    let mut text = std::str::from_utf8(trim_ascii_whitespace(content))
        .ok()?
        .to_string();

    let remainder = text.len() % 4;
    if remainder != 0 {
        let padding = 4 - remainder;
        text.push_str(&"=".repeat(padding));
    }

    Some(text)
}

fn to_json_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn grpc_frame(payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(payload.len() + 5);
        framed.push(0);
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }

    #[test]
    fn normalizes_grpc_framed_protobuf_payload() {
        let protobuf = [0x0a, 0x02, b'h', b'i'];
        let body = grpc_frame(&protobuf);
        let normalized = normalize_body(&body, Some("application/grpc"));
        assert_eq!(normalized, r#"{"1":"hi"}"#);
    }

    #[test]
    fn normalizes_multiple_grpc_frames_into_array() {
        let first = grpc_frame(&[0x0a, 0x02, b'o', b'k']);
        let second = grpc_frame(&[0x08, 0x01]);

        let mut body = Vec::new();
        body.extend_from_slice(&first);
        body.extend_from_slice(&second);

        let normalized = normalize_body(&body, Some("application/grpc+proto"));
        assert_eq!(normalized, r#"[{"1":"ok"},{"1":1}]"#);
    }

    #[test]
    fn normalizes_sse_payloads_by_joining_data_lines() {
        let body = br#"event: message
data: {"type":"delta"}
data: {"text":"hello"}
data: [DONE]
"#;

        let normalized = normalize_body(body, Some("text/event-stream; charset=utf-8"));
        assert_eq!(normalized, r#"{"type":"delta"}{"text":"hello"}"#);
    }

    #[test]
    fn parser_driven_sse_skips_stream_control_values() {
        let body = br#"data: v1
data: {"type":"delta"}
data: {"text":"hello"}
data: [DONE]
"#;

        let parser = BundleStreamParser::sse(
            vec!["data: ".to_string()],
            vec!["[DONE]".to_string(), "v1".to_string(), "v2".to_string()],
        );
        let normalized =
            normalize_body_with_stream_parser(body, Some("text/event-stream"), Some(&parser));
        assert_eq!(normalized, r#"{"type":"delta"}{"text":"hello"}"#);
    }

    #[test]
    fn strips_anti_hijack_prefix_and_parses_json() {
        let body = b")]}'\n{\"ok\":true}\n";
        let normalized = normalize_body(body, None);
        assert_eq!(normalized, r#"[{"ok":true}]"#);
    }

    #[test]
    fn parses_anti_hijack_length_prefixed_chunks() {
        let body = b"for(;;);8\n{\"a\":1}\n";
        let normalized = normalize_body(body, None);
        assert_eq!(normalized, r#"[{"a":1}]"#);
    }

    #[test]
    fn decodes_msgpack_payload() {
        let encoded = vec![
            0x81, 0xa4, b't', b'y', b'p', b'e', 0xa5, b'd', b'e', b'l', b't', b'a',
        ];

        let normalized = normalize_body(&encoded, None);
        assert_eq!(normalized, r#"{"type":"delta"}"#);
    }

    #[test]
    fn decodes_layered_base64_then_gzip() {
        let raw = br#"{"model":"gpt-4o-mini"}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(raw)
            .expect("gzip encoder should accept input");
        let gzip = encoder.finish().expect("gzip should finish");
        let base64 = BASE64_STANDARD.encode(gzip);

        let normalized = normalize_body(base64.as_bytes(), None);
        assert_eq!(normalized, r#"{"model":"gpt-4o-mini"}"#);
    }

    #[test]
    fn decodes_zstd_payload() {
        let raw = br#"{"ok":true}"#;
        let encoded = zstd::stream::encode_all(Cursor::new(raw), 0).expect("zstd should encode");
        let normalized = normalize_body(&encoded, None);
        assert_eq!(normalized, r#"{"ok":true}"#);
    }

    #[test]
    fn decodes_deflate_payload() {
        let raw = br#"{"ok":true}"#;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(raw)
            .expect("zlib encoder should accept input");
        let encoded = encoder.finish().expect("zlib should finish");

        let normalized = normalize_body(&encoded, None);
        assert_eq!(normalized, r#"{"ok":true}"#);
    }

    #[test]
    fn decodes_url_percent_encoded_payload() {
        let normalized = normalize_body(b"%7B%22x%22%3A1%7D", None);
        assert_eq!(normalized, r#"{"x":1}"#);
    }

    #[test]
    fn short_base64_strings_are_not_auto_decoded() {
        let normalized = normalize_body(b"YWJjZA==", None);
        assert_eq!(normalized, "YWJjZA==");
    }
}
