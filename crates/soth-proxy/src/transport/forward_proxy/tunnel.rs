//! TLS tunnel for MITM interception

use crate::error::ProxyError;
use crate::metrics;
use crate::pipeline::Pipeline;
use crate::providers::{AiProvider, HttpRequest, ProviderRegistry, ProviderUsage, SseEvent};
use crate::providers::sse::SseStreamParser;

use super::connection_pool::ConnectionPool;
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_core::EventLogger;
use soth_tls::CertificateAuthority;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, trace};

#[cfg(feature = "dashboard")]
use soth_dashboard::DashboardState;

/// Start a TLS tunnel between client and upstream
pub async fn start_tunnel(
    client_stream: TcpStream,
    host: &str,
    port: u16,
    ca: Arc<CertificateAuthority>,
    pipeline: Option<Arc<Pipeline>>,
    providers: Arc<ProviderRegistry>,
    pool: &ConnectionPool,
    request_timeout: Duration,
    #[cfg(feature = "dashboard")] dashboard: Option<DashboardState>,
    event_logger: Option<Arc<EventLogger>>,
) -> Result<(), ProxyError> {
    // Get server config for this domain
    let server_config = ca
        .get_server_config(host)
        .map_err(|e| ProxyError::transport(format!("Failed to get server config: {}", e)))?;

    // Perform TLS handshake with client
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = acceptor
        .accept(client_stream)
        .await
        .map_err(|e| ProxyError::transport(format!("Client TLS handshake failed: {}", e)))?;

    debug!("TLS handshake complete with client for {}", host);

    // Get or create upstream connection
    let upstream_tls = pool
        .get_connection(host, port)
        .await?;

    debug!("Upstream connection established to {}:{}", host, port);

    // Track active connection in metrics
    let provider_name = providers.find_provider(host)
        .map(|p| p.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    metrics::increment_connections(&provider_name);

    // Handle bidirectional communication
    let result = handle_bidirectional(
        client_tls,
        upstream_tls,
        host,
        pipeline,
        providers.clone(),
        request_timeout,
        #[cfg(feature = "dashboard")]
        dashboard,
        event_logger,
    )
    .await;

    // Decrement active connection when tunnel ends
    metrics::decrement_connections(&provider_name);

    result
}

/// Handle bidirectional communication between client and upstream
async fn handle_bidirectional<C, U>(
    client: C,
    upstream: U,
    host: &str,
    _pipeline: Option<Arc<Pipeline>>,
    providers: Arc<ProviderRegistry>,
    _request_timeout: Duration,
    #[cfg(feature = "dashboard")] dashboard: Option<DashboardState>,
    event_logger: Option<Arc<EventLogger>>,
) -> Result<(), ProxyError>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Generate session ID for this connection
    let session_id = uuid::Uuid::new_v4().to_string();
    let (client_read, mut client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let mut client_reader = BufReader::new(client_read);
    let mut upstream_reader = BufReader::new(upstream_read);

    let host = host.to_string();
    let provider = providers.find_provider(&host);
    let provider_name = provider
        .as_ref()
        .map(|p| p.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Simple HTTP/1.1 request-response handling
    // For each request, forward to upstream and collect response
    loop {
        // Read request from client
        let request = match read_http_request(&mut client_reader).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                debug!("Client closed connection");
                break;
            }
            Err(e) => {
                debug!("Error reading request: {}", e);
                metrics::record_error(&provider_name, "read_request");
                #[cfg(feature = "dashboard")]
                if let Some(ref dash) = dashboard {
                    dash.decrement_proxy_connections();
                }
                break;
            }
        };

        trace!("Request: {} {}", request.method, request.path);

        // Convert to HttpRequest for provider parsing
        let http_request = request.to_http_request();

        // Extract info using provider
        let model = provider.as_ref().and_then(|p| p.extract_model(&http_request));
        let _api_key = provider.as_ref().and_then(|p| p.extract_api_key(&http_request));

        debug!(
            "Forwarding request to {}: {} {} (model={:?})",
            host, request.method, request.path, model
        );

        // Record request in dashboard
        #[cfg(feature = "dashboard")]
        if let Some(ref dash) = dashboard {
            dash.record_proxy_request(&provider_name, &host, &request.method, &request.path);
        }

        // Record Prometheus metrics for request
        metrics::record_request(&provider_name, &request.method);

        // Log request event for observability
        if let Some(ref logger) = event_logger {
            let agent = AgentInfo::new(&provider_name, DetectionSource::Environment);
            let content = if let Some(ref body) = request.body {
                String::from_utf8_lossy(body).to_string()
            } else {
                format!("{} {}", request.method, request.path)
            };
            let content_preview = if content.len() > 200 {
                format!("{}...", &content[..200])
            } else {
                content.clone()
            };
            let mut event = WrapEvent::new(&session_id, host.clone(), WrapDirection::In, agent)
                .with_source(EventSource::AiProxy)
                .with_provider(&provider_name)
                .with_method(format!("{} {}", request.method, request.path))
                .with_content(content)
                .with_content_preview(content_preview);
            if let Some(ref m) = model {
                event = event.with_model(m);
            }
            logger.log(&event);
        }

        // Start timing for latency
        let request_start = Instant::now();

        // Forward request to upstream
        let request_bytes = serialize_http_request(&http_request);
        if let Err(e) = upstream_write.write_all(&request_bytes).await {
            error!("Failed to write to upstream: {}", e);
            metrics::record_error(&provider_name, "upstream_write");
            #[cfg(feature = "dashboard")]
            if let Some(ref dash) = dashboard {
                dash.decrement_proxy_connections();
            }
            break;
        }
        upstream_write.flush().await?;

        // Read response from upstream and forward to client
        let is_streaming = http_request
            .header("accept")
            .map(|h| h.contains("text/event-stream"))
            .unwrap_or(false);

        let (usage, status_code) = if is_streaming {
            // SSE streaming response
            let usage = handle_sse_response(
                &mut upstream_reader,
                &mut client_write,
                provider.as_ref().map(|p| Arc::clone(p)),
            )
            .await?;

            debug!(
                "SSE stream complete: {} input, {} output tokens",
                usage.input_tokens, usage.output_tokens
            );
            (Some(usage), 200u16)
        } else {
            // Regular response
            let (status_code, usage) = read_and_forward_response(
                &mut upstream_reader,
                &mut client_write,
                provider.as_ref().map(|p| Arc::clone(p)),
            )
            .await?;

            if let Some(ref usage) = usage {
                debug!(
                    "Response complete: {} input, {} output tokens",
                    usage.input_tokens, usage.output_tokens
                );
            }
            (usage, status_code)
        };

        // Calculate latency
        let latency = request_start.elapsed();

        // Record Prometheus metrics for response
        let status_str = if status_code >= 200 && status_code < 300 {
            "success"
        } else if status_code >= 400 && status_code < 500 {
            "client_error"
        } else if status_code >= 500 {
            "server_error"
        } else {
            "other"
        };
        metrics::record_response(&provider_name, status_str);
        metrics::record_request_duration(&provider_name, latency);
        metrics::record_upstream_latency(&provider_name, latency);

        // Record token metrics
        if let Some(ref u) = usage {
            let model_name = model.as_deref().unwrap_or("unknown");
            metrics::record_tokens(&provider_name, model_name, "input", u.input_tokens);
            metrics::record_tokens(&provider_name, model_name, "output", u.output_tokens);
        }

        // Record response in dashboard
        #[cfg(feature = "dashboard")]
        let (input_tokens, output_tokens, cost_usd) = if let Some(ref u) = usage {
            let cost = calculate_cost(&model, u.input_tokens, u.output_tokens);
            (Some(u.input_tokens), Some(u.output_tokens), Some(cost))
        } else {
            (None, None, None)
        };

        #[cfg(feature = "dashboard")]
        if let Some(ref dash) = dashboard {
            let latency_ms = latency.as_millis() as u64;
            dash.record_proxy_response(
                &provider_name,
                status_code,
                latency_ms,
                model.as_deref(),
                input_tokens,
                output_tokens,
                cost_usd,
            );
        }

        // Log response event for observability
        if let Some(ref logger) = event_logger {
            let agent = AgentInfo::new(&provider_name, DetectionSource::Environment);
            let content_preview = format!(
                "HTTP {} - {} input, {} output tokens",
                status_code,
                usage.as_ref().map(|u| u.input_tokens).unwrap_or(0),
                usage.as_ref().map(|u| u.output_tokens).unwrap_or(0)
            );
            let mut event = WrapEvent::new(&session_id, host.clone(), WrapDirection::Out, agent)
                .with_source(EventSource::AiProxy)
                .with_provider(&provider_name)
                .with_content(content_preview.clone())
                .with_content_preview(content_preview)
                .with_latency(latency.as_millis() as u64);

            // Add model info if available
            if let Some(ref m) = model {
                event = event.with_model(m);
            }

            // Add token info if available
            if let Some(ref u) = usage {
                event = event.with_tokens(u.input_tokens + u.output_tokens);
            }
            #[cfg(feature = "dashboard")]
            if let Some(cost) = cost_usd {
                event = event.with_cost(cost);
            }

            logger.log(&event);
        }
    }

    Ok(())
}

/// HTTP request data for parsing
#[derive(Debug)]
struct ParsedRequest {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, String>,
    body: Option<Vec<u8>>,
}

impl ParsedRequest {
    fn to_http_request(&self) -> HttpRequest {
        let mut req = HttpRequest::new(&self.method, &self.path);
        for (k, v) in &self.headers {
            req = req.with_header(k, v);
        }
        if let Some(body) = &self.body {
            req = req.with_body(body.clone());
        }
        req
    }
}

/// Read an HTTP request from a stream
async fn read_http_request<R>(reader: &mut BufReader<R>) -> Result<Option<ParsedRequest>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Read request line
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }

    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ProxyError::protocol("Invalid request line"));
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Read headers
    let mut headers = std::collections::HashMap::new();
    loop {
        let mut header_line = String::new();
        reader.read_line(&mut header_line).await?;
        let header_line = header_line.trim();

        if header_line.is_empty() {
            break;
        }

        if let Some((key, value)) = header_line.split_once(':') {
            headers.insert(
                key.trim().to_lowercase(),
                value.trim().to_string(),
            );
        }
    }

    // Read body if present
    let body = if let Some(len_str) = headers.get("content-length") {
        let len: usize = len_str
            .parse()
            .map_err(|_| ProxyError::protocol("Invalid Content-Length"))?;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        Some(body)
    } else {
        None
    };

    Ok(Some(ParsedRequest {
        method,
        path,
        headers,
        body,
    }))
}

/// Serialize HTTP request to bytes
fn serialize_http_request(request: &HttpRequest) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Request line
    bytes.extend_from_slice(
        format!("{} {} HTTP/1.1\r\n", request.method, request.path).as_bytes(),
    );

    // Headers
    for (key, value) in &request.headers {
        bytes.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }

    // End of headers
    bytes.extend_from_slice(b"\r\n");

    // Body
    if let Some(body) = &request.body {
        bytes.extend_from_slice(body);
    }

    bytes
}

/// Read response and forward to client, extracting usage
/// Returns (status_code, usage)
async fn read_and_forward_response<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    provider: Option<Arc<dyn AiProvider>>,
) -> Result<(u16, Option<ProviderUsage>), ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut response = Vec::new();

    // Read status line
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    response.extend_from_slice(line.as_bytes());

    // Parse status code from status line (e.g., "HTTP/1.1 200 OK")
    let status_code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Read headers
    let mut content_length: Option<usize> = None;
    let mut chunked = false;

    loop {
        let mut header_line = String::new();
        reader.read_line(&mut header_line).await?;
        response.extend_from_slice(header_line.as_bytes());

        let header_line = header_line.trim();
        if header_line.is_empty() {
            break;
        }

        if let Some((key, value)) = header_line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            if key == "content-length" {
                content_length = value.parse().ok();
            } else if key == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }

    // Read body
    let body = if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        body
    } else if chunked {
        read_chunked_body(reader).await?
    } else {
        Vec::new()
    };

    response.extend_from_slice(&body);

    // Forward to client
    writer.write_all(&response).await?;
    writer.flush().await?;

    // Extract usage
    let usage = provider.and_then(|p| p.extract_usage(&body));

    Ok((status_code, usage))
}

/// Read chunked transfer encoding body
async fn read_chunked_body<R>(reader: &mut BufReader<R>) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        let size = usize::from_str_radix(size_line.trim(), 16)
            .map_err(|_| ProxyError::protocol("Invalid chunk size"))?;

        if size == 0 {
            // Read trailing CRLF
            let mut crlf = String::new();
            reader.read_line(&mut crlf).await?;
            break;
        }

        // Read chunk data
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        // Read trailing CRLF
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
    }

    Ok(body)
}

/// Handle SSE streaming response
async fn handle_sse_response<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    provider: Option<Arc<dyn AiProvider>>,
) -> Result<ProviderUsage, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Read and forward status line and headers first
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    writer.write_all(line.as_bytes()).await?;

    // Read headers
    loop {
        let mut header_line = String::new();
        reader.read_line(&mut header_line).await?;
        writer.write_all(header_line.as_bytes()).await?;

        if header_line.trim().is_empty() {
            break;
        }
    }
    writer.flush().await?;

    // Create SSE parser if we have a provider
    let mut parser = provider.map(|p| SseStreamParser::new(p));
    let mut accumulated_usage = ProviderUsage::default();

    // Stream SSE events
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        // Forward immediately (no buffering for low latency)
        writer.write_all(line.as_bytes()).await?;
        writer.flush().await?;

        // Parse for usage tracking
        if let Some(ref mut parser) = parser {
            let events = parser.process(line.as_bytes());
            for event in events {
                match event {
                    SseEvent::Usage(usage) => {
                        if usage.input_tokens > 0 {
                            accumulated_usage.input_tokens = usage.input_tokens;
                        }
                        if usage.output_tokens > 0 {
                            accumulated_usage.output_tokens = usage.output_tokens;
                        }
                        if usage.model.is_some() {
                            accumulated_usage.model = usage.model;
                        }
                    }
                    SseEvent::Done => {
                        return Ok(accumulated_usage);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(accumulated_usage)
}

/// Calculate cost based on model and token usage
/// Returns approximate cost in USD
fn calculate_cost(model: &Option<String>, input_tokens: u64, output_tokens: u64) -> f64 {
    // Prices per 1M tokens (approximate)
    let (input_price, output_price) = match model.as_deref() {
        // OpenAI
        Some(m) if m.starts_with("gpt-4o") => (2.50, 10.00),
        Some(m) if m.starts_with("gpt-4-turbo") => (10.00, 30.00),
        Some(m) if m.starts_with("gpt-4") => (30.00, 60.00),
        Some(m) if m.starts_with("gpt-3.5") => (0.50, 1.50),
        Some(m) if m.starts_with("o1") => (15.00, 60.00),
        // Anthropic
        Some(m) if m.contains("claude-3-5-sonnet") => (3.00, 15.00),
        Some(m) if m.contains("claude-3-opus") => (15.00, 75.00),
        Some(m) if m.contains("claude-3-sonnet") => (3.00, 15.00),
        Some(m) if m.contains("claude-3-haiku") => (0.25, 1.25),
        // Google
        Some(m) if m.contains("gemini-1.5-pro") => (1.25, 5.00),
        Some(m) if m.contains("gemini-1.5-flash") => (0.075, 0.30),
        Some(m) if m.contains("gemini-2.0") => (0.10, 0.40),
        // Default
        _ => (1.00, 3.00),
    };

    let input_cost = (input_tokens as f64 / 1_000_000.0) * input_price;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * output_price;

    input_cost + output_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_cost() {
        // GPT-4o pricing
        let cost = calculate_cost(&Some("gpt-4o".to_string()), 1000, 500);
        assert!((cost - 0.0075).abs() < 0.001); // (1000/1M * 2.50) + (500/1M * 10.00)

        // Claude pricing
        let cost = calculate_cost(&Some("claude-3-5-sonnet".to_string()), 1000, 500);
        assert!((cost - 0.0105).abs() < 0.001); // (1000/1M * 3.00) + (500/1M * 15.00)
    }

    #[test]
    fn test_serialize_http_request() {
        let request = HttpRequest::new("POST", "/v1/chat/completions")
            .with_header("Content-Type", "application/json")
            .with_header("Authorization", "Bearer xxx")
            .with_body(b"{}".to_vec());

        let bytes = serialize_http_request(&request);
        let text = String::from_utf8_lossy(&bytes);

        assert!(text.contains("POST /v1/chat/completions HTTP/1.1"));
        assert!(text.contains("content-type: application/json"));
        assert!(text.contains("authorization: Bearer xxx"));
        assert!(text.ends_with("{}"));
    }
}
