//! SNI (Server Name Indication) extraction from TLS ClientHello

use crate::error::{Result, TlsError};

/// TLS content types
const TLS_HANDSHAKE: u8 = 0x16;

/// TLS handshake types
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS extension types
const EXTENSION_SNI: u16 = 0x00;

/// SNI name types
const SNI_HOST_NAME: u8 = 0x00;

/// Extract SNI (Server Name Indication) from a TLS ClientHello message
///
/// The ClientHello is the first message sent by the client during a TLS handshake.
/// This function parses the raw bytes to extract the server name that the client
/// is attempting to connect to.
///
/// # Arguments
/// * `data` - Raw bytes containing the TLS ClientHello message
///
/// # Returns
/// * `Ok(Some(String))` - The extracted server name
/// * `Ok(None)` - Valid ClientHello but no SNI extension present
/// * `Err(TlsError)` - Invalid TLS data
pub fn extract_sni(data: &[u8]) -> Result<Option<String>> {
    // Minimum ClientHello size: TLS record header (5) + handshake header (4) + version (2)
    // + random (32) + session_id length (1) = 44 bytes
    if data.len() < 44 {
        return Err(TlsError::sni_extraction("Data too short for ClientHello"));
    }

    // Check TLS record header
    // Byte 0: Content type (should be 0x16 for Handshake)
    if data[0] != TLS_HANDSHAKE {
        return Err(TlsError::sni_extraction(format!(
            "Not a TLS handshake: content type 0x{:02x}",
            data[0]
        )));
    }

    // Bytes 1-2: TLS version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept any version >= TLS 1.0
    let record_version = u16::from_be_bytes([data[1], data[2]]);
    if record_version < 0x0301 {
        return Err(TlsError::sni_extraction(format!(
            "Unsupported TLS version: 0x{:04x}",
            record_version
        )));
    }

    // Bytes 3-4: Record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        return Err(TlsError::sni_extraction("Incomplete TLS record"));
    }

    // Skip TLS record header (5 bytes) to get to handshake message
    let handshake = &data[5..5 + record_length];

    // Check handshake message type
    // Byte 0: Handshake type (should be 0x01 for ClientHello)
    if handshake.is_empty() || handshake[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsError::sni_extraction("Not a ClientHello message"));
    }

    // Bytes 1-3: Handshake message length (24-bit)
    if handshake.len() < 4 {
        return Err(TlsError::sni_extraction("Handshake too short"));
    }
    let handshake_length =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);

    if handshake.len() < 4 + handshake_length {
        return Err(TlsError::sni_extraction("Incomplete ClientHello"));
    }

    // Skip to ClientHello body (after handshake header)
    let client_hello = &handshake[4..4 + handshake_length];
    parse_client_hello(client_hello)
}

/// Parse the ClientHello body to extract SNI
fn parse_client_hello(data: &[u8]) -> Result<Option<String>> {
    let mut pos = 0;

    // Client version (2 bytes)
    if data.len() < pos + 2 {
        return Err(TlsError::sni_extraction("Missing client version"));
    }
    pos += 2;

    // Random (32 bytes)
    if data.len() < pos + 32 {
        return Err(TlsError::sni_extraction("Missing random"));
    }
    pos += 32;

    // Session ID length (1 byte) + session ID
    if data.len() < pos + 1 {
        return Err(TlsError::sni_extraction("Missing session ID length"));
    }
    let session_id_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + session_id_len {
        return Err(TlsError::sni_extraction("Incomplete session ID"));
    }
    pos += session_id_len;

    // Cipher suites length (2 bytes) + cipher suites
    if data.len() < pos + 2 {
        return Err(TlsError::sni_extraction("Missing cipher suites length"));
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + cipher_suites_len {
        return Err(TlsError::sni_extraction("Incomplete cipher suites"));
    }
    pos += cipher_suites_len;

    // Compression methods length (1 byte) + compression methods
    if data.len() < pos + 1 {
        return Err(TlsError::sni_extraction("Missing compression methods length"));
    }
    let compression_methods_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + compression_methods_len {
        return Err(TlsError::sni_extraction("Incomplete compression methods"));
    }
    pos += compression_methods_len;

    // Extensions (optional)
    if pos >= data.len() {
        // No extensions
        return Ok(None);
    }

    // Extensions length (2 bytes)
    if data.len() < pos + 2 {
        return Err(TlsError::sni_extraction("Missing extensions length"));
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if data.len() < pos + extensions_len {
        return Err(TlsError::sni_extraction("Incomplete extensions"));
    }

    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            break;
        }

        if ext_type == EXTENSION_SNI {
            // Parse SNI extension
            let ext_data = &data[pos..pos + ext_len];
            if let Some(name) = parse_sni_extension(ext_data) {
                return Ok(Some(name));
            }
        }

        pos += ext_len;
    }

    Ok(None)
}

/// Parse the SNI extension data
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    // Server name list length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > end {
            break;
        }

        if name_type == SNI_HOST_NAME {
            // Extract hostname
            if let Ok(hostname) = std::str::from_utf8(&data[pos..pos + name_len]) {
                return Some(hostname.to_lowercase());
            }
        }

        pos += name_len;
    }

    None
}

/// Check if data looks like a TLS ClientHello
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }

    // Check content type is Handshake (0x16)
    if data[0] != TLS_HANDSHAKE {
        return false;
    }

    // Check TLS version (bytes 1-2) is reasonable
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0301 || version > 0x0304 {
        return false;
    }

    // Check handshake type at byte 5 is ClientHello (0x01)
    data[5] == HANDSHAKE_CLIENT_HELLO
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid TLS 1.2 ClientHello with SNI extension
    fn create_test_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let hostname_len = hostname_bytes.len();

        // SNI extension data
        let sni_list_len = 3 + hostname_len; // type (1) + length (2) + hostname
        let sni_ext_len = 2 + sni_list_len; // list_length (2) + list

        // Extensions total
        let extensions_len = 4 + sni_ext_len; // ext_type (2) + ext_len (2) + ext_data

        // ClientHello body:
        // version (2) + random (32) + session_id_len (1) + cipher_suites_len (2) +
        // cipher_suites (2) + compression_len (1) + compression (1) + extensions_len (2) + extensions
        let client_hello_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;

        // Handshake message:
        // type (1) + length (3) + body
        let handshake_len = 1 + 3 + client_hello_len;

        // TLS record:
        // type (1) + version (2) + length (2) + handshake
        let mut data = Vec::with_capacity(5 + handshake_len);

        // TLS record header
        data.push(0x16); // Handshake
        data.push(0x03); // TLS 1.2 (0x0303)
        data.push(0x01);
        data.push(((handshake_len >> 8) & 0xff) as u8);
        data.push((handshake_len & 0xff) as u8);

        // Handshake header
        data.push(0x01); // ClientHello
        data.push(0);
        data.push(((client_hello_len >> 8) & 0xff) as u8);
        data.push((client_hello_len & 0xff) as u8);

        // ClientHello body
        data.push(0x03); // Version TLS 1.2
        data.push(0x03);
        data.extend_from_slice(&[0u8; 32]); // Random
        data.push(0); // Session ID length
        data.push(0); // Cipher suites length (2 bytes)
        data.push(2);
        data.push(0x00); // One cipher suite
        data.push(0x2f);
        data.push(1); // Compression methods length
        data.push(0); // Null compression

        // Extensions length
        data.push(((extensions_len >> 8) & 0xff) as u8);
        data.push((extensions_len & 0xff) as u8);

        // SNI extension
        data.push(0); // Extension type (SNI = 0x0000)
        data.push(0);
        data.push(((sni_ext_len >> 8) & 0xff) as u8);
        data.push((sni_ext_len & 0xff) as u8);

        // SNI list length
        data.push(((sni_list_len >> 8) & 0xff) as u8);
        data.push((sni_list_len & 0xff) as u8);

        // SNI entry
        data.push(0); // Host name type
        data.push(((hostname_len >> 8) & 0xff) as u8);
        data.push((hostname_len & 0xff) as u8);
        data.extend_from_slice(hostname_bytes);

        data
    }

    #[test]
    fn test_extract_sni() {
        let data = create_test_client_hello("api.openai.com");
        let sni = extract_sni(&data).unwrap();
        assert_eq!(sni, Some("api.openai.com".to_string()));
    }

    #[test]
    fn test_extract_sni_uppercase() {
        let data = create_test_client_hello("API.OpenAI.COM");
        let sni = extract_sni(&data).unwrap();
        assert_eq!(sni, Some("api.openai.com".to_string())); // Should be lowercase
    }

    #[test]
    fn test_is_tls_client_hello() {
        let data = create_test_client_hello("example.com");
        assert!(is_tls_client_hello(&data));
    }

    #[test]
    fn test_not_tls_client_hello() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_tls_client_hello(data));
    }

    #[test]
    fn test_too_short() {
        let data = &[0x16, 0x03, 0x01];
        assert!(extract_sni(data).is_err());
    }
}
