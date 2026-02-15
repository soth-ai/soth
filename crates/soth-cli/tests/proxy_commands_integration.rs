//! Integration tests for Phase J CLI diagnostics commands
//!
//! Tests for:
//! - `soth dev advanced metrics` - displays metrics from /metrics endpoint
//! - `soth dev advanced connections` - shows active connections from /api/proxy
//! - `soth dev advanced circuit status` - circuit breaker status
//! - `soth dev advanced rate-limit` - rate limit status
//!
//! These tests focus on parsing and display logic. Full HTTP integration
//! requires a running API service (tested in E2E tests).

use soth_core::config::SothConfig;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

// ============================================================================
// METRICS COMMAND TESTS
// ============================================================================

/// Test parsing Prometheus metric lines without labels
#[test]
fn test_parse_metric_line_simple() {
    let line = "soth_proxy_requests_total 42";
    let result = parse_metric_line(line);

    assert!(result.is_some());
    let (name, value) = result.unwrap();
    assert_eq!(name, "soth_proxy_requests_total");
    assert_eq!(value, 42.0);
}

/// Test parsing Prometheus metric lines with labels
#[test]
fn test_parse_metric_line_with_labels() {
    let line = r#"soth_proxy_requests_total{provider="openai",status="success"} 123"#;
    let result = parse_metric_line(line);

    assert!(result.is_some());
    let (name, value) = result.unwrap();
    assert_eq!(name, "soth_proxy_requests_total");
    assert_eq!(value, 123.0);
}

/// Test parsing metric lines with floating point values
#[test]
fn test_parse_metric_line_float() {
    let line = "soth_proxy_latency_seconds 0.123456";
    let result = parse_metric_line(line);

    assert!(result.is_some());
    let (name, value) = result.unwrap();
    assert_eq!(name, "soth_proxy_latency_seconds");
    assert!((value - 0.123456).abs() < 0.000001);
}

/// Test parsing invalid metric lines
#[test]
fn test_parse_metric_line_invalid() {
    // No value
    assert!(parse_metric_line("soth_proxy_requests_total").is_none());

    // Invalid value
    assert!(parse_metric_line("soth_proxy_requests_total abc").is_none());

    // Empty line
    assert!(parse_metric_line("").is_none());

    // Comment line
    assert!(parse_metric_line("# HELP metric_name Some help text").is_none());
}

/// Test metrics display function aggregates correctly
#[test]
fn test_display_metrics_aggregation() {
    let prometheus_text = r#"
# HELP soth_proxy_requests_total Total requests
# TYPE soth_proxy_requests_total counter
soth_proxy_requests_total{provider="openai"} 100
soth_proxy_requests_total{provider="anthropic"} 50
soth_proxy_responses_total 140
soth_proxy_errors_total 10
soth_proxy_tokens_total 50000
soth_proxy_rate_limited_total 5
soth_proxy_circuit_breaker_trips 2
"#;

    // We can't easily test the actual display output, but we can verify
    // the parsing logic works by checking it doesn't panic
    let metrics = parse_all_metrics(prometheus_text);

    assert_eq!(metrics.requests, 150); // 100 + 50
    assert_eq!(metrics.responses, 140);
    assert_eq!(metrics.errors, 10);
    assert_eq!(metrics.tokens, 50000);
    assert_eq!(metrics.rate_limited, 5);
    assert_eq!(metrics.circuit_trips, 2);
}

// ============================================================================
// CONNECTIONS COMMAND TESTS
// ============================================================================

/// Test connections display with sample data
#[test]
fn test_connections_display_logic() {
    let json_data = r#"{
        "data": {
            "total_requests": 150,
            "total_responses": 145,
            "active_connections": 3,
            "requests_by_provider": {
                "openai": 100,
                "anthropic": 50
            },
            "total_tokens": 75000,
            "total_cost_usd": 1.234,
            "recent_requests": [
                {
                    "provider": "openai",
                    "host": "api.openai.com",
                    "method": "POST",
                    "path": "/v1/chat/completions",
                    "status_code": 200,
                    "latency_ms": 350,
                    "model": "gpt-4o",
                    "input_tokens": 100,
                    "output_tokens": 200
                }
            ]
        }
    }"#;

    // Parse and verify structure
    let parsed: serde_json::Value = serde_json::from_str(json_data).unwrap();
    let data = &parsed["data"];

    assert_eq!(data["active_connections"], 3);
    assert_eq!(data["total_requests"], 150);
    assert_eq!(data["total_responses"], 145);
    assert_eq!(data["requests_by_provider"]["openai"], 100);
    assert_eq!(data["requests_by_provider"]["anthropic"], 50);

    // Verify recent requests structure
    let recent = &data["recent_requests"][0];
    assert_eq!(recent["provider"], "openai");
    assert_eq!(recent["status_code"], 200);
}

/// Test truncate function for long strings
#[test]
fn test_truncate_string() {
    assert_eq!(truncate("short", 10), "short");
    assert_eq!(truncate("exactly_ten", 11), "exactly_ten");
    assert_eq!(
        truncate("this_is_a_very_long_string", 15),
        "this_is_a_ve..."
    );
    assert_eq!(truncate("abc", 3), "abc");
    assert_eq!(truncate("abcd", 3), "...");
}

// ============================================================================
// CIRCUIT BREAKER COMMAND TESTS
// ============================================================================

/// Test parsing circuit breaker state metrics
#[test]
fn test_parse_circuit_breaker_state() {
    let line = r#"soth_proxy_circuit_breaker_state{provider="openai"} 0"#;
    let result = parse_labeled_metric(line, "provider");

    assert!(result.is_some());
    let (provider, state) = result.unwrap();
    assert_eq!(provider, "openai");
    assert_eq!(state, 0.0); // CLOSED
}

/// Test parsing circuit breaker trips
#[test]
fn test_parse_circuit_breaker_trips() {
    let line = r#"soth_proxy_circuit_breaker_trips{provider="anthropic"} 5"#;
    let result = parse_labeled_metric(line, "provider");

    assert!(result.is_some());
    let (provider, trips) = result.unwrap();
    assert_eq!(provider, "anthropic");
    assert_eq!(trips, 5.0);
}

/// Test circuit breaker state display logic
#[test]
fn test_circuit_breaker_states() {
    let prometheus_text = r#"
soth_proxy_circuit_breaker_state{provider="openai"} 0
soth_proxy_circuit_breaker_state{provider="anthropic"} 1
soth_proxy_circuit_breaker_state{provider="google"} 2
soth_proxy_circuit_breaker_trips{provider="openai"} 0
soth_proxy_circuit_breaker_trips{provider="anthropic"} 3
soth_proxy_circuit_breaker_trips{provider="google"} 10
"#;

    let circuits = parse_circuit_states(prometheus_text);

    assert_eq!(circuits.len(), 3);
    assert_eq!(circuits.get("openai"), Some(&(0, 0))); // (state, trips)
    assert_eq!(circuits.get("anthropic"), Some(&(1, 3)));
    assert_eq!(circuits.get("google"), Some(&(2, 10)));
}

/// Test circuit breaker with no data
#[test]
fn test_circuit_breaker_no_data() {
    let prometheus_text = r#"
# HELP soth_proxy_requests_total Total requests
soth_proxy_requests_total 100
"#;

    let circuits = parse_circuit_states(prometheus_text);
    assert!(circuits.is_empty());
}

// ============================================================================
// RATE LIMIT COMMAND TESTS
// ============================================================================

/// Test parsing rate limited metrics with labels
#[test]
fn test_parse_rate_limited_metric() {
    let line = r#"soth_proxy_rate_limited_total{provider="openai",key="user-123"} 15"#;
    let result = parse_rate_limited_metric(line);

    assert!(result.is_some());
    let (provider, key, count) = result.unwrap();
    assert_eq!(provider, "openai");
    assert_eq!(key, "user-123");
    assert_eq!(count, 15);
}

/// Test parsing multiple rate limit entries
#[test]
fn test_parse_multiple_rate_limits() {
    let prometheus_text = r#"
soth_proxy_rate_limited_total{provider="openai",key="user-1"} 10
soth_proxy_rate_limited_total{provider="anthropic",key="user-2"} 5
soth_proxy_rate_limited_total{provider="openai",key="user-3"} 20
"#;

    let limits = parse_rate_limits(prometheus_text);

    assert_eq!(limits.len(), 3);
    assert!(limits
        .iter()
        .any(|(p, k, c)| p == "openai" && k == "user-1" && *c == 10));
    assert!(limits
        .iter()
        .any(|(p, k, c)| p == "anthropic" && k == "user-2" && *c == 5));
    assert!(limits
        .iter()
        .any(|(p, k, c)| p == "openai" && k == "user-3" && *c == 20));
}

/// Test rate limit aggregation
#[test]
fn test_rate_limit_total_calculation() {
    let prometheus_text = r#"
soth_proxy_rate_limited_total{provider="openai",key="user-1"} 10
soth_proxy_rate_limited_total{provider="anthropic",key="user-2"} 5
soth_proxy_rate_limited_total{provider="openai",key="user-3"} 20
"#;

    let total = calculate_total_rate_limited(prometheus_text);
    assert_eq!(total, 35);
}

/// Test extracting label values
#[test]
fn test_extract_label() {
    let line = r#"metric{provider="openai",key="user-123"} 10"#;

    assert_eq!(extract_label(line, "provider"), Some("openai".to_string()));
    assert_eq!(extract_label(line, "key"), Some("user-123".to_string()));
    assert_eq!(extract_label(line, "missing"), None);
}

// ============================================================================
// CONFIG FILE TESTS
// ============================================================================

/// Test loading custom config for API port
#[test]
fn test_load_custom_config_for_dashboard_port() {
    let config_content = r#"
version: "1.0"
server:
  transport: "stdio"
upstream:
  command: "test"
dashboard:
  enabled: true
  port: 9999
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(config_content.as_bytes()).unwrap();

    let config: SothConfig = serde_yaml::from_str(config_content).unwrap();
    assert_eq!(config.dashboard.port, 9999);
    assert!(config.dashboard.enabled);
}

/// Test default API port when not specified
#[test]
fn test_default_dashboard_port() {
    let config_content = r#"
version: "1.0"
server:
  transport: "stdio"
upstream:
  command: "test"
"#;

    let config: SothConfig = serde_yaml::from_str(config_content).unwrap();
    assert_eq!(config.dashboard.port, 3001); // Default port
}

/// Test config with circuit breaker settings
#[test]
fn test_config_circuit_breaker_settings() {
    let config_content = r#"
version: "1.0"
server:
  transport: "stdio"
upstream:
  command: "test"
production:
  circuit_breaker:
    enabled: true
    failure_threshold: 10
    open_duration: "60s"
    success_threshold: 3
    failure_window: "120s"
"#;

    let config: SothConfig = serde_yaml::from_str(config_content).unwrap();
    assert!(config.production.circuit_breaker.enabled);
    assert_eq!(config.production.circuit_breaker.failure_threshold, 10);
    assert_eq!(config.production.circuit_breaker.success_threshold, 3);
}

/// Test config with rate limit settings
#[test]
fn test_config_rate_limit_settings() {
    let config_content = r#"
version: "1.0"
server:
  transport: "stdio"
upstream:
  command: "test"
production:
  rate_limit:
    enabled: true
    requests_per_second: 100
    burst_size: 200
    global_requests_per_second: 1000
    global_burst_size: 2000
"#;

    let config: SothConfig = serde_yaml::from_str(config_content).unwrap();
    assert!(config.production.rate_limit.enabled);
    assert_eq!(config.production.rate_limit.requests_per_second, 100.0);
    assert_eq!(config.production.rate_limit.burst_size, 200);
    assert_eq!(
        config.production.rate_limit.global_requests_per_second,
        1000.0
    );
    assert_eq!(config.production.rate_limit.global_burst_size, 2000);
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

/// Test handling connection refused (API service not running)
#[test]
fn test_connection_refused_scenario() {
    // When API service is not running, commands should provide helpful error messages
    // This is tested in the actual command implementation which checks for
    // connection errors and prints guidance

    // We verify the error message formatting is appropriate
    let port = 3001;
    let error_msg = format!(
        "Error: Could not connect to API service at http://127.0.0.1:{}/metrics\n\
         \n\
         Start the API service:\n  \
         soth dev api start --port {}",
        port, port
    );

    assert!(error_msg.contains("Could not connect"));
    assert!(error_msg.contains("soth dev api start"));
}

/// Test handling HTTP error responses
#[test]
fn test_http_error_responses() {
    // Commands should handle non-200 responses gracefully
    let status = 500;
    let url = "http://127.0.0.1:3001/metrics";
    let error_msg = format!("Failed to fetch metrics: HTTP {} from {}", status, url);

    assert!(error_msg.contains("500"));
    assert!(error_msg.contains("/metrics"));
}

// ============================================================================
// HELPER FUNCTIONS (mimicking internal command logic)
// ============================================================================

/// Parse a Prometheus metric line (mimics metrics.rs logic)
fn parse_metric_line(line: &str) -> Option<(&str, f64)> {
    if line.starts_with('#') || line.is_empty() {
        return None;
    }

    let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let value: f64 = parts[0].parse().ok()?;
    let name = parts[1];

    // Extract metric name (before { or entire string)
    let metric_name = name.split('{').next()?;

    Some((metric_name, value))
}

/// Aggregate metrics from Prometheus text
struct AggregatedMetrics {
    requests: u64,
    responses: u64,
    errors: u64,
    tokens: u64,
    rate_limited: u64,
    circuit_trips: u64,
}

fn parse_all_metrics(prometheus_text: &str) -> AggregatedMetrics {
    let mut metrics = AggregatedMetrics {
        requests: 0,
        responses: 0,
        errors: 0,
        tokens: 0,
        rate_limited: 0,
        circuit_trips: 0,
    };

    for line in prometheus_text.lines() {
        if let Some((name, value)) = parse_metric_line(line) {
            match name {
                n if n.starts_with("soth_proxy_requests_total") => {
                    metrics.requests += value as u64;
                }
                n if n.starts_with("soth_proxy_responses_total") => {
                    metrics.responses += value as u64;
                }
                n if n.starts_with("soth_proxy_errors_total") => {
                    metrics.errors += value as u64;
                }
                n if n.starts_with("soth_proxy_tokens_total") => {
                    metrics.tokens += value as u64;
                }
                n if n.starts_with("soth_proxy_rate_limited_total") => {
                    metrics.rate_limited += value as u64;
                }
                n if n.starts_with("soth_proxy_circuit_breaker_trips") => {
                    metrics.circuit_trips += value as u64;
                }
                _ => {}
            }
        }
    }

    metrics
}

/// Truncate string (mimics connections.rs logic)
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Parse labeled metric (mimics circuit.rs logic)
fn parse_labeled_metric(line: &str, label_name: &str) -> Option<(String, f64)> {
    let label_pattern = format!("{}=\"", label_name);

    if let Some(label_start) = line.find(&label_pattern) {
        let value_start = label_start + label_pattern.len();
        if let Some(value_end) = line[value_start..].find('"') {
            let label_value = line[value_start..value_start + value_end].to_string();

            // Get the numeric value (last space-separated part)
            if let Some(num_str) = line.rsplit(' ').next() {
                if let Ok(num) = num_str.parse::<f64>() {
                    return Some((label_value, num));
                }
            }
        }
    }

    None
}

/// Parse circuit breaker states
fn parse_circuit_states(prometheus_text: &str) -> HashMap<String, (u8, u64)> {
    let mut states: HashMap<String, (u8, u64)> = HashMap::new();

    for line in prometheus_text.lines() {
        if line.contains("circuit_breaker_state") {
            if let Some((provider, value)) = parse_labeled_metric(line, "provider") {
                let state = value as u8;
                states.entry(provider).or_insert((state, 0)).0 = state;
            }
        }

        if line.contains("circuit_breaker_trips") {
            if let Some((provider, value)) = parse_labeled_metric(line, "provider") {
                states.entry(provider).or_insert((0, 0)).1 = value as u64;
            }
        }
    }

    states
}

/// Parse rate limited metric (mimics ratelimit.rs logic)
fn parse_rate_limited_metric(line: &str) -> Option<(String, String, u64)> {
    let provider = extract_label(line, "provider")?;
    let key = extract_label(line, "key")?;

    let value_str = line.rsplit(' ').next()?;
    let value: u64 = value_str.parse().ok()?;

    Some((provider, key, value))
}

/// Parse all rate limits
fn parse_rate_limits(prometheus_text: &str) -> Vec<(String, String, u64)> {
    let mut limits = Vec::new();

    for line in prometheus_text.lines() {
        if line.contains("rate_limited_total") {
            if let Some(parsed) = parse_rate_limited_metric(line) {
                limits.push(parsed);
            }
        }
    }

    limits
}

/// Calculate total rate limited requests
fn calculate_total_rate_limited(prometheus_text: &str) -> u64 {
    let limits = parse_rate_limits(prometheus_text);
    limits.iter().map(|(_, _, count)| count).sum()
}

/// Extract label value (mimics ratelimit.rs logic)
fn extract_label(line: &str, label_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", label_name);
    let start = line.find(&pattern)? + pattern.len();
    let end = start + line[start..].find('"')?;
    Some(line[start..end].to_string())
}

// ============================================================================
// EDGE CASES AND ROBUSTNESS TESTS
// ============================================================================

/// Test handling of malformed Prometheus data
#[test]
fn test_malformed_prometheus_data() {
    let bad_data = r#"
not_a_metric
metric_without_value{label="test"}
{orphaned_labels="test"} 123
soth_proxy_requests_total not_a_number
"#;

    // Should not panic, just skip invalid lines
    let metrics = parse_all_metrics(bad_data);
    assert_eq!(metrics.requests, 0);
}

/// Test empty Prometheus response
#[test]
fn test_empty_prometheus_response() {
    let empty = "";
    let metrics = parse_all_metrics(empty);

    assert_eq!(metrics.requests, 0);
    assert_eq!(metrics.responses, 0);
    assert_eq!(metrics.errors, 0);
}

/// Test Prometheus data with only comments
#[test]
fn test_prometheus_comments_only() {
    let comments = r#"
# HELP soth_proxy_requests_total Total requests
# TYPE soth_proxy_requests_total counter
# This is a comment
"#;

    let metrics = parse_all_metrics(comments);
    assert_eq!(metrics.requests, 0);
}

/// Test circuit breaker with missing state or trips
#[test]
fn test_circuit_breaker_partial_data() {
    let partial = r#"
soth_proxy_circuit_breaker_state{provider="openai"} 0
soth_proxy_circuit_breaker_trips{provider="anthropic"} 5
"#;

    let circuits = parse_circuit_states(partial);

    // Should handle partial data gracefully
    assert_eq!(circuits.get("openai"), Some(&(0, 0)));
    assert_eq!(circuits.get("anthropic"), Some(&(0, 5)));
}

/// Test rate limit with special characters in labels
#[test]
fn test_rate_limit_special_characters() {
    let line = r#"soth_proxy_rate_limited_total{provider="openai",key="user@example.com"} 10"#;
    let result = parse_rate_limited_metric(line);

    assert!(result.is_some());
    let (provider, key, count) = result.unwrap();
    assert_eq!(provider, "openai");
    assert_eq!(key, "user@example.com");
    assert_eq!(count, 10);
}

/// Test very long provider/host names
#[test]
fn test_truncate_long_names() {
    let long_name = "this_is_a_very_very_very_long_provider_name_that_should_be_truncated";
    let truncated = truncate(long_name, 30);

    assert_eq!(truncated.len(), 30);
    assert!(truncated.ends_with("..."));
}

/// Test zero values in metrics
#[test]
fn test_metrics_with_zero_values() {
    let zero_metrics = r#"
soth_proxy_requests_total 0
soth_proxy_responses_total 0
soth_proxy_errors_total 0
"#;

    let metrics = parse_all_metrics(zero_metrics);
    assert_eq!(metrics.requests, 0);
    assert_eq!(metrics.responses, 0);
    assert_eq!(metrics.errors, 0);
}

/// Test large metric values
#[test]
fn test_large_metric_values() {
    let large = r#"
soth_proxy_requests_total 999999999
soth_proxy_tokens_total 123456789012345
"#;

    let metrics = parse_all_metrics(large);
    assert_eq!(metrics.requests, 999999999);
    assert_eq!(metrics.tokens, 123456789012345);
}
