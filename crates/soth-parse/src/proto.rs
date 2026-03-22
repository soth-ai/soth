/// Scan protobuf length-delimited (wire type 2) fields and extract UTF-8 strings.
/// Returns `(field_number, text)` pairs for strings longer than 5 bytes.
pub fn scan_proto_strings(payload: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor < payload.len() {
        let (tag, wire_type, advance) = match read_varint_tag(&payload[cursor..]) {
            Some(data) => data,
            None => break,
        };
        cursor += advance;

        if wire_type == 2 {
            let (len, len_advance) = match read_varint_len(&payload[cursor..]) {
                Some(data) => data,
                None => break,
            };
            cursor += len_advance;

            if cursor + len > payload.len() {
                break;
            }

            let bytes = &payload[cursor..cursor + len];
            if let Ok(text) = std::str::from_utf8(bytes) {
                if text.len() > 5 {
                    out.push((tag >> 3, text.to_string()));
                }
            }
            cursor += len;
        } else {
            let skip = skip_wire_type(wire_type, &payload[cursor..]);
            if skip == 0 {
                break;
            }
            cursor += skip;
        }
    }

    out
}

fn read_varint_tag(bytes: &[u8]) -> Option<(u32, u8, usize)> {
    let (value, advance) = read_varint(bytes)?;
    if value == 0 {
        return None;
    }
    let wire_type = (value & 0x07) as u8;
    Some((value as u32, wire_type, advance))
}

fn read_varint_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let (value, advance) = read_varint(bytes)?;
    Some((value as usize, advance))
}

pub fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().enumerate() {
        let part = (byte & 0x7f) as u64;
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }

    None
}

fn skip_wire_type(wire_type: u8, bytes: &[u8]) -> usize {
    match wire_type {
        0 => read_varint(bytes).map(|(_, n)| n).unwrap_or(0),
        1 => 8,
        2 => {
            if let Some((len, adv)) = read_varint_len(bytes) {
                adv.saturating_add(len)
            } else {
                0
            }
        }
        5 => 4,
        _ => 0,
    }
}
