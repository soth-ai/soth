//! HTTP CONNECT request handling

use crate::error::ProxyError;

/// Parse CONNECT target (host:port)
///
/// Handles formats:
/// - `host:port`
/// - `host` (defaults to port 443)
pub fn parse_connect_target(target: &str) -> Result<(String, u16), ProxyError> {
    let parts: Vec<&str> = target.splitn(2, ':').collect();

    let host = parts[0].to_string();
    if host.is_empty() {
        return Err(ProxyError::protocol("Empty host in CONNECT target"));
    }

    let port = if parts.len() > 1 {
        parts[1]
            .parse::<u16>()
            .map_err(|_| ProxyError::protocol(format!("Invalid port: {}", parts[1])))?
    } else {
        443 // Default HTTPS port
    };

    Ok((host, port))
}

/// Validate a host/domain name
pub fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }

    // Check each label
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Labels must start and end with alphanumeric
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return false;
        }

        // Labels can only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        let (host, port) = parse_connect_target("api.openai.com:443").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_target_default_port() {
        let (host, port) = parse_connect_target("api.openai.com").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_target_custom_port() {
        let (host, port) = parse_connect_target("localhost:8443").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_connect_target_empty() {
        assert!(parse_connect_target(":443").is_err());
    }

    #[test]
    fn test_parse_connect_target_invalid_port() {
        assert!(parse_connect_target("host:invalid").is_err());
    }

    #[test]
    fn test_is_valid_host() {
        assert!(is_valid_host("api.openai.com"));
        assert!(is_valid_host("localhost"));
        assert!(is_valid_host("a-b.c-d.example"));
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("-invalid.com"));
        assert!(!is_valid_host("invalid-.com"));
    }
}
