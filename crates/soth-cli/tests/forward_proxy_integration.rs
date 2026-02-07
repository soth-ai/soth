//! Integration tests for forward proxy functionality

use soth_core::config::{ForwardProxyConfig, HostFilterConfig, HostFilterMode};
use soth_proxy::providers::{HttpRequest, ProviderRegistry};
use soth_tls::CertificateAuthority;
use std::time::Duration;
use tempfile::TempDir;

/// Test CA certificate generation
#[test]
fn test_ca_generation() {
    let temp_dir = TempDir::new().unwrap();
    let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

    // Verify cert files exist
    assert!(temp_dir.path().join("ca.crt").exists());
    assert!(temp_dir.path().join("ca.key").exists());

    // Verify PEM is valid
    let pem = ca.ca_cert_pem();
    assert!(pem.contains("BEGIN CERTIFICATE"));
}

/// Test CA loading
#[test]
fn test_ca_load() {
    let temp_dir = TempDir::new().unwrap();

    // Generate first
    let _ca1 = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

    // Load it back
    let ca2 = CertificateAuthority::load_from_path(temp_dir.path().to_path_buf()).unwrap();
    assert!(!ca2.ca_cert_pem().is_empty());
}

/// Test domain certificate generation
#[test]
fn test_domain_cert_generation() {
    let temp_dir = TempDir::new().unwrap();
    let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

    // Generate cert for domain
    let (cert_der, key_der) = ca.get_or_create_cert("api.openai.com").unwrap();
    assert!(!cert_der.is_empty());
    assert!(!key_der.is_empty());

    // Second call should return cached
    let (cert2, key2) = ca.get_or_create_cert("api.openai.com").unwrap();
    assert_eq!(cert_der, cert2);
    assert_eq!(key_der, key2);
}

/// Test certificate cache
#[test]
fn test_cert_cache() {
    let temp_dir = TempDir::new().unwrap();
    let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

    // Generate certs for multiple domains
    ca.get_or_create_cert("api.openai.com").unwrap();
    ca.get_or_create_cert("api.anthropic.com").unwrap();
    ca.get_or_create_cert("generativelanguage.googleapis.com")
        .unwrap();

    let stats = ca.cache_stats();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.valid, 3);
    assert_eq!(stats.expired, 0);
}

/// Test host filtering - explicit AI host list
#[test]
fn test_host_filter_ai_list() {
    use soth_core::HostAction;

    let filter = HostFilterConfig {
        mode: HostFilterMode::Selective,
        ai_inference: vec![
            "api.openai.com".to_string(),
            "api.anthropic.com".to_string(),
        ],
        mcp: vec![],
        block: vec![],
    };

    // Configured hosts intercepted, others tunneled
    assert_eq!(
        filter.action_for_host("api.openai.com"),
        HostAction::Intercept
    );
    assert_eq!(
        filter.action_for_host("api.anthropic.com"),
        HostAction::Intercept
    );
    assert_eq!(filter.action_for_host("malicious.com"), HostAction::Tunnel);
    assert_eq!(filter.action_for_host("example.com"), HostAction::Tunnel);
}

/// Test host filtering - selective mode (default)
#[test]
fn test_host_filter_selective() {
    use soth_core::HostAction;

    let filter = HostFilterConfig {
        mode: HostFilterMode::Selective,
        ai_inference: vec![
            "api.openai.com".to_string(),
            "api.anthropic.com".to_string(),
        ],
        mcp: vec![],
        block: vec!["blocked.com".to_string()],
    };

    // AI domains intercepted
    assert_eq!(
        filter.action_for_host("api.openai.com"),
        HostAction::Intercept
    );
    assert_eq!(
        filter.action_for_host("api.anthropic.com"),
        HostAction::Intercept
    );

    // Blocked hosts blocked
    assert_eq!(filter.action_for_host("blocked.com"), HostAction::Block);

    // Other hosts tunneled (not blocked!)
    assert_eq!(filter.action_for_host("any.other.host"), HostAction::Tunnel);
    assert_eq!(filter.action_for_host("google.com"), HostAction::Tunnel);
}

/// Test provider registry
#[test]
fn test_provider_registry() {
    let registry = ProviderRegistry::new();

    // Check all default providers are registered
    assert!(registry.has_provider("api.openai.com"));
    assert!(registry.has_provider("api.anthropic.com"));
    assert!(registry.has_provider("generativelanguage.googleapis.com"));
    assert!(!registry.has_provider("unknown.api.com"));
}

/// Test OpenAI provider parsing
#[test]
fn test_openai_provider() {
    let registry = ProviderRegistry::new();
    let provider = registry.find_provider("api.openai.com").unwrap();

    // Test model extraction
    let body = r#"{"model": "gpt-4o", "messages": []}"#;
    let request =
        HttpRequest::new("POST", "/v1/chat/completions").with_body(body.as_bytes().to_vec());
    assert_eq!(provider.extract_model(&request), Some("gpt-4o".to_string()));

    // Test usage extraction
    let response = r#"{
        "id": "chatcmpl-xxx",
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }"#;
    let usage = provider.extract_usage(response.as_bytes()).unwrap();
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
}

/// Test Anthropic provider parsing
#[test]
fn test_anthropic_provider() {
    let registry = ProviderRegistry::new();
    let provider = registry.find_provider("api.anthropic.com").unwrap();

    // Test model extraction
    let body = r#"{"model": "claude-3-5-sonnet", "messages": []}"#;
    let request = HttpRequest::new("POST", "/v1/messages").with_body(body.as_bytes().to_vec());
    assert_eq!(
        provider.extract_model(&request),
        Some("claude-3-5-sonnet".to_string())
    );

    // Test usage extraction
    let response = r#"{
        "id": "msg_xxx",
        "model": "claude-3-5-sonnet",
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_read_input_tokens": 25
        }
    }"#;
    let usage = provider.extract_usage(response.as_bytes()).unwrap();
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
    assert_eq!(usage.cached_tokens, Some(25));
}

/// Test Google provider parsing
#[test]
fn test_google_provider() {
    let registry = ProviderRegistry::new();
    let provider = registry
        .find_provider("generativelanguage.googleapis.com")
        .unwrap();

    // Test model extraction from URL path
    let request = HttpRequest::new(
        "POST",
        "/v1beta/models/gemini-1.5-flash:generateContent?key=xxx",
    );
    assert_eq!(
        provider.extract_model(&request),
        Some("gemini-1.5-flash".to_string())
    );

    // Test usage extraction
    let response = r#"{
        "candidates": [{"content": {"parts": [{"text": "Hello"}]}}],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 50
        }
    }"#;
    let usage = provider.extract_usage(response.as_bytes()).unwrap();
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
}

/// Test config defaults
#[test]
fn test_config_defaults() {
    let config = ForwardProxyConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.port, 8080);
    assert_eq!(config.address, "127.0.0.1");
    assert_eq!(config.request_timeout, Duration::from_secs(300));

    // Check default host actions
    assert_eq!(
        config.hosts.action_for_host("api.openai.com"),
        soth_core::HostAction::Intercept
    );
    assert_eq!(
        config.hosts.action_for_host("api.anthropic.com"),
        soth_core::HostAction::Intercept
    );
    assert_eq!(
        config
            .hosts
            .action_for_host("generativelanguage.googleapis.com"),
        soth_core::HostAction::Intercept
    );
}

/// Test SNI extraction
#[test]
fn test_sni_extraction() {
    use soth_tls::extract_sni;

    // Create a minimal TLS ClientHello with SNI
    let client_hello = create_test_client_hello("api.openai.com");
    let sni = extract_sni(&client_hello).unwrap();
    assert_eq!(sni, Some("api.openai.com".to_string()));
}

/// Helper to create test ClientHello
fn create_test_client_hello(hostname: &str) -> Vec<u8> {
    let hostname_bytes = hostname.as_bytes();
    let hostname_len = hostname_bytes.len();

    // SNI extension data
    let sni_list_len = 3 + hostname_len;
    let sni_ext_len = 2 + sni_list_len;
    let extensions_len = 4 + sni_ext_len;
    let client_hello_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let handshake_len = 1 + 3 + client_hello_len;

    let mut data = Vec::with_capacity(5 + handshake_len);

    // TLS record header
    data.push(0x16); // Handshake
    data.push(0x03);
    data.push(0x01); // TLS 1.0 in record
    data.push(((handshake_len >> 8) & 0xff) as u8);
    data.push((handshake_len & 0xff) as u8);

    // Handshake header
    data.push(0x01); // ClientHello
    data.push(0);
    data.push(((client_hello_len >> 8) & 0xff) as u8);
    data.push((client_hello_len & 0xff) as u8);

    // ClientHello body
    data.push(0x03);
    data.push(0x03); // TLS 1.2
    data.extend_from_slice(&[0u8; 32]); // Random
    data.push(0); // Session ID length
    data.push(0);
    data.push(2); // Cipher suites length
    data.push(0x00);
    data.push(0x2f); // One cipher suite
    data.push(1); // Compression methods length
    data.push(0); // Null compression

    // Extensions
    data.push(((extensions_len >> 8) & 0xff) as u8);
    data.push((extensions_len & 0xff) as u8);

    // SNI extension
    data.push(0);
    data.push(0); // Extension type (SNI)
    data.push(((sni_ext_len >> 8) & 0xff) as u8);
    data.push((sni_ext_len & 0xff) as u8);
    data.push(((sni_list_len >> 8) & 0xff) as u8);
    data.push((sni_list_len & 0xff) as u8);
    data.push(0); // Host name type
    data.push(((hostname_len >> 8) & 0xff) as u8);
    data.push((hostname_len & 0xff) as u8);
    data.extend_from_slice(hostname_bytes);

    data
}

/// Test SSE parsing for OpenAI
#[test]
fn test_sse_parsing_openai() {
    use soth_proxy::providers::openai::OpenAiProvider;
    use soth_proxy::providers::{AiProvider, SseEvent};

    let provider = OpenAiProvider::new();

    // Content event
    let chunk = r#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#;
    match provider.parse_sse_chunk(chunk) {
        Some(SseEvent::Content(text)) => assert_eq!(text, "Hello"),
        _ => panic!("Expected Content event"),
    }

    // Done event
    let chunk = "data: [DONE]";
    match provider.parse_sse_chunk(chunk) {
        Some(SseEvent::Done) => {}
        _ => panic!("Expected Done event"),
    }

    // Usage event
    let chunk = r#"data: {"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
    match provider.parse_sse_chunk(chunk) {
        Some(SseEvent::Usage(usage)) => {
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.output_tokens, 5);
        }
        _ => panic!("Expected Usage event"),
    }
}

/// Test SSE parsing for Anthropic
#[test]
fn test_sse_parsing_anthropic() {
    use soth_proxy::providers::anthropic::AnthropicProvider;
    use soth_proxy::providers::{AiProvider, SseEvent};

    let provider = AnthropicProvider::new();

    // Content delta
    let chunk = r#"event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}"#;
    match provider.parse_sse_chunk(chunk) {
        Some(SseEvent::Content(text)) => assert_eq!(text, "Hi"),
        _ => panic!("Expected Content event"),
    }

    // Message stop
    let chunk = r#"event: message_stop
data: {"type":"message_stop"}"#;
    match provider.parse_sse_chunk(chunk) {
        Some(SseEvent::Done) => {}
        _ => panic!("Expected Done event"),
    }
}
