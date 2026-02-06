//! HTTP/HTTPS Forward Proxy Transport
//!
//! Intercepts HTTP CONNECT requests for TLS MITM, enabling inspection
//! of AI provider traffic (OpenAI, Anthropic, Google).
//!
//! ## Flow
//!
//! 1. Client sends HTTP CONNECT request
//! 2. Proxy checks if domain is allowed
//! 3. Proxy responds with "200 Connection Established"
//! 4. Proxy performs TLS handshake with client using MITM cert
//! 5. Proxy establishes TLS connection to upstream
//! 6. Proxy forwards decrypted traffic through pipeline layers
//!
//! ## Usage
//!
//! ```rust,ignore
//! use soth_proxy::transport::forward_proxy::ForwardProxyTransport;
//! use soth_tls::CertificateAuthority;
//!
//! let ca = CertificateAuthority::load_or_generate(ca_path)?;
//! let transport = ForwardProxyTransport::new(config, ca, pipeline);
//! transport.start(cancel_token).await?;
//! ```

pub mod blind_tunnel;
pub mod connect;
pub mod connection_pool;
pub mod tunnel;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerResult};
use crate::error::ProxyError;
use crate::metrics;
use crate::pipeline::Pipeline;
use crate::providers::ProviderRegistry;
use crate::rate_limit::{RateLimiter, RateLimitResult};
use crate::shutdown::ShutdownCoordinator;
use crate::transport::{AsyncMessageHandler, Transport};

use async_trait::async_trait;
#[cfg(feature = "dashboard")]
use soth_dashboard::DashboardState;
use connection_pool::ConnectionPool;
use dashmap::DashMap;
use soth_core::config::{ForwardProxyConfig, HostAction};
use soth_core::EventLogger;
use soth_tls::CertificateAuthority;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Forward proxy transport for intercepting HTTPS traffic
pub struct ForwardProxyTransport {
    /// Configuration
    config: ForwardProxyConfig,
    /// Certificate authority for MITM
    ca: Arc<CertificateAuthority>,
    /// Pipeline for processing messages
    pipeline: Option<Arc<Pipeline>>,
    /// Provider registry for parsing AI traffic
    providers: Arc<ProviderRegistry>,
    /// Connection pool for upstream connections
    pool: ConnectionPool,
    /// Rate limiter for request throttling
    rate_limiter: Option<Arc<RateLimiter>>,
    /// Circuit breaker for upstream protection
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    /// Shutdown coordinator for graceful termination
    shutdown: ShutdownCoordinator,
    /// Active connections
    connections: DashMap<String, ConnectionInfo>,
    /// Message handler (not used for forward proxy, but required by trait)
    handler: Option<AsyncMessageHandler>,
    /// Cancellation token
    cancel: Option<CancellationToken>,
    /// Dashboard state for metrics reporting
    #[cfg(feature = "dashboard")]
    dashboard: Option<DashboardState>,
    /// Event logger for observability
    event_logger: Option<Arc<EventLogger>>,
}

/// Connection info for tracking
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Target host
    pub target_host: String,
    /// Target port
    pub target_port: u16,
    /// Connection time
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

impl ForwardProxyTransport {
    /// Create a new forward proxy transport
    pub fn new(config: ForwardProxyConfig, ca: CertificateAuthority) -> Self {
        let pool = ConnectionPool::new(
            config.pool.max_connections_per_host,
            config.pool.idle_timeout,
            config.pool.connect_timeout,
        );

        // Use server's graceful_shutdown timeout if available, otherwise default
        let shutdown_timeout = std::time::Duration::from_secs(30);

        Self {
            config,
            ca: Arc::new(ca),
            pipeline: None,
            providers: Arc::new(ProviderRegistry::new()),
            pool,
            rate_limiter: None,
            circuit_breaker: None,
            shutdown: ShutdownCoordinator::new(shutdown_timeout),
            connections: DashMap::new(),
            handler: None,
            cancel: None,
            #[cfg(feature = "dashboard")]
            dashboard: None,
            event_logger: None,
        }
    }

    /// Set the pipeline for processing requests
    pub fn with_pipeline(mut self, pipeline: Arc<Pipeline>) -> Self {
        self.pipeline = Some(pipeline);
        self
    }

    /// Set custom provider registry
    pub fn with_providers(mut self, providers: ProviderRegistry) -> Self {
        self.providers = Arc::new(providers);
        self
    }

    /// Set dashboard state for metrics reporting
    #[cfg(feature = "dashboard")]
    pub fn with_dashboard(mut self, dashboard: DashboardState) -> Self {
        self.dashboard = Some(dashboard);
        self
    }

    /// Set event logger for observability
    pub fn with_event_logger(mut self, logger: EventLogger) -> Self {
        self.event_logger = Some(Arc::new(logger));
        self
    }

    /// Set rate limiter for request throttling
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Set circuit breaker for upstream protection
    pub fn with_circuit_breaker(mut self, breaker: CircuitBreaker) -> Self {
        self.circuit_breaker = Some(Arc::new(breaker));
        self
    }

    /// Set custom shutdown timeout
    pub fn with_shutdown_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.shutdown = ShutdownCoordinator::new(timeout);
        self
    }

    /// Get shutdown coordinator (for external shutdown initiation)
    pub fn shutdown_coordinator(&self) -> &ShutdownCoordinator {
        &self.shutdown
    }

    /// Subscribe to shutdown signal
    /// External systems (like dashboard) can use this to be notified of shutdown
    /// and take appropriate action (e.g., set readiness to false)
    pub fn shutdown_signal(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    /// Get dashboard state reference (for passing to tunnel)
    #[cfg(feature = "dashboard")]
    pub fn dashboard(&self) -> Option<&DashboardState> {
        self.dashboard.as_ref()
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> String {
        self.config.socket_addr()
    }

    /// Determine the action for a host
    fn action_for_host(&self, host: &str) -> HostAction {
        self.config.hosts.action_for_host(host)
    }

    /// Check if a host is allowed (for compatibility)
    #[allow(dead_code)]
    fn is_host_allowed(&self, host: &str) -> bool {
        self.config.hosts.is_allowed(host)
    }

    /// Handle incoming connection
    async fn handle_connection(
        self: Arc<Self>,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();

        // Read the first line to determine request type
        reader
            .read_line(&mut request_line)
            .await
            .map_err(|e| ProxyError::transport(format!("Failed to read request: {}", e)))?;

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ProxyError::protocol("Invalid HTTP request line"));
        }

        let method = parts[0];
        let target = parts[1].to_string();

        // Read ALL remaining headers here before dispatching
        // This ensures we don't lose buffered data
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Now safe to get the stream - all headers consumed
        let stream = reader.into_inner();

        if method == "CONNECT" {
            // HTTPS tunnel request
            self.handle_connect(stream, remote_addr, &target)
                .await
        } else {
            // Regular HTTP request (not typically used for AI APIs)
            self.handle_http(stream, remote_addr, method, &target)
                .await
        }
    }

    /// Handle HTTP CONNECT request (HTTPS tunnel)
    async fn handle_connect(
        self: Arc<Self>,
        mut stream: TcpStream,
        remote_addr: SocketAddr,
        target: &str,
    ) -> Result<(), ProxyError> {
        // Parse target (host:port)
        let (host, port) = connect::parse_connect_target(target)?;

        debug!(
            "CONNECT request from {} to {}:{}",
            remote_addr, host, port
        );

        // Determine action for this host
        let action = self.action_for_host(&host);

        match action {
            HostAction::Block => {
                warn!("Host blocked: {}", host);
                let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            HostAction::Tunnel => {
                // Blind tunnel: just pass TCP bytes through, no inspection
                debug!("Blind tunnel to {} (non-AI domain)", host);
                return self.handle_blind_tunnel(stream, &host, port).await;
            }
            HostAction::Intercept => {
                // Full MITM: continue with TLS termination + inspection
                debug!("MITM intercept to {} (AI domain)", host);
            }
        }

        // --- From here: MITM intercept flow (AI domains only) ---

        // Rate limiting check (use remote IP as key)
        let rate_limit_key = remote_addr.ip().to_string();
        if let Some(ref limiter) = self.rate_limiter {
            match limiter.check(&rate_limit_key) {
                RateLimitResult::Allowed => {}
                RateLimitResult::Limited { retry_after, reason } => {
                    warn!(
                        "Rate limited {} for {}: {:?}",
                        remote_addr, host, reason
                    );
                    metrics::record_rate_limited(&host, &rate_limit_key);
                    let response = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {}\r\n\r\n",
                        retry_after.as_secs()
                    );
                    stream.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
        }

        // Circuit breaker check
        if let Some(ref breaker) = self.circuit_breaker {
            match breaker.allow_request(&host) {
                CircuitBreakerResult::Allowed => {}
                CircuitBreakerResult::Rejected { retry_after } => {
                    warn!(
                        "Circuit breaker open for {}, retry after {:?}",
                        host, retry_after
                    );
                    let response = format!(
                        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: {}\r\n\r\n",
                        retry_after.as_secs()
                    );
                    stream.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
        }

        // Register connection with shutdown coordinator
        let _connection_guard = match self.shutdown.register() {
            Some(guard) => guard,
            None => {
                // Shutdown in progress, reject new connection
                warn!("Rejecting connection during shutdown: {}", host);
                let response = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n";
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // Headers already consumed by handle_connection
        // Send connection established response
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        // Track connection
        let conn_id = uuid::Uuid::new_v4().to_string();
        self.connections.insert(
            conn_id.clone(),
            ConnectionInfo {
                remote_addr,
                target_host: host.clone(),
                target_port: port,
                connected_at: chrono::Utc::now(),
                bytes_sent: 0,
                bytes_received: 0,
            },
        );

        // Start TLS tunnel with MITM
        let result = tunnel::start_tunnel(
            stream,
            &host,
            port,
            Arc::clone(&self.ca),
            self.pipeline.clone(),
            Arc::clone(&self.providers),
            &self.pool,
            self.config.request_timeout,
            #[cfg(feature = "dashboard")]
            self.dashboard.clone(),
            self.event_logger.clone(),
        )
        .await;

        // Remove connection tracking
        self.connections.remove(&conn_id);

        // Record circuit breaker outcome
        if let Some(ref breaker) = self.circuit_breaker {
            match &result {
                Ok(_) => breaker.record_success(&host),
                Err(_) => breaker.record_failure(&host),
            }
        }

        result
    }

    /// Handle blind TCP tunnel (non-AI domains)
    ///
    /// Simply passes TCP bytes through without TLS termination or inspection.
    /// Note: Headers are already consumed by handle_connection before this is called.
    async fn handle_blind_tunnel(
        &self,
        mut stream: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(), ProxyError> {
        // Register connection with shutdown coordinator
        let _connection_guard = match self.shutdown.register() {
            Some(guard) => guard,
            None => {
                warn!("Rejecting connection during shutdown: {}", host);
                let response = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n";
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // Headers already consumed by handle_connection
        // Send connection established response
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        // Start blind tunnel (no TLS termination)
        blind_tunnel::start_blind_tunnel(
            stream,
            host,
            port,
            self.config.pool.connect_timeout,
        )
        .await
    }

    /// Handle regular HTTP request (passthrough or block)
    async fn handle_http(
        self: Arc<Self>,
        mut stream: TcpStream,
        remote_addr: SocketAddr,
        method: &str,
        target: &str,
    ) -> Result<(), ProxyError> {
        // For non-CONNECT requests, we could proxy them directly
        // but AI APIs all use HTTPS, so we typically block plain HTTP
        debug!(
            "HTTP {} request from {} to {} (blocked)",
            method, remote_addr, target
        );

        let response =
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nUse HTTPS (CONNECT method) for AI API requests\r\n";
        stream.write_all(response.as_bytes()).await?;

        Ok(())
    }
}

#[async_trait]
impl Transport for ForwardProxyTransport {
    async fn start(&mut self, cancel: CancellationToken) -> Result<(), ProxyError> {
        let addr = self.config.socket_addr();
        info!("Starting forward proxy on {}", addr);

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| ProxyError::transport(format!("Failed to bind to {}: {}", addr, e)))?;

        info!("Forward proxy listening on {}", addr);

        self.cancel = Some(cancel.clone());

        // Create dummy config for replacement (needed for Arc pattern)
        let dummy_config = ForwardProxyConfig::default();
        let dummy_ca = CertificateAuthority::generate_new(std::path::PathBuf::from("/tmp/soth-dummy"))
            .map_err(|e| ProxyError::transport(e.to_string()))?;
        let mut dummy = ForwardProxyTransport::new(dummy_config, dummy_ca);
        dummy.rate_limiter = None;
        dummy.circuit_breaker = None;
        dummy.event_logger = None;
        #[cfg(feature = "dashboard")]
        {
            dummy.dashboard = None;
        }

        let this = Arc::new(std::mem::replace(self, dummy));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Forward proxy shutdown requested, initiating graceful shutdown");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let this = Arc::clone(&this);
                            tokio::spawn(async move {
                                if let Err(e) = this.handle_connection(stream, addr).await {
                                    debug!("Connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }

        // Perform graceful shutdown - wait for in-flight requests
        let result = this.shutdown.shutdown().await;
        match result {
            crate::shutdown::ShutdownResult::Clean => {
                info!("Forward proxy shutdown complete (all connections closed cleanly)");
            }
            crate::shutdown::ShutdownResult::Timeout { remaining } => {
                warn!(
                    "Forward proxy shutdown complete (timeout with {} connections remaining)",
                    remaining
                );
            }
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ProxyError> {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        info!("Forward proxy stopped");
        Ok(())
    }

    async fn send(&self, _message: crate::protocol::JsonRpcMessage) -> Result<(), ProxyError> {
        // Forward proxy doesn't send JSON-RPC messages directly
        Err(ProxyError::protocol(
            "Forward proxy does not support direct message sending",
        ))
    }

    fn set_handler(&mut self, handler: AsyncMessageHandler) {
        self.handler = Some(handler);
    }

    fn name(&self) -> &'static str {
        "forward_proxy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_breaker::CircuitBreakerConfig;
    use crate::rate_limit::RateLimitConfig;
    use tempfile::TempDir;
    use std::time::Duration;

    #[test]
    fn test_host_action_default() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();
        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca);

        // AI domains should be intercepted
        assert_eq!(transport.action_for_host("api.openai.com"), HostAction::Intercept);
        assert_eq!(transport.action_for_host("api.anthropic.com"), HostAction::Intercept);
        assert_eq!(transport.action_for_host("generativelanguage.googleapis.com"), HostAction::Intercept);

        // Non-AI domains should be tunneled (not blocked!)
        assert_eq!(transport.action_for_host("example.com"), HostAction::Tunnel);
        assert_eq!(transport.action_for_host("google.com"), HostAction::Tunnel);
    }

    #[test]
    fn test_host_allowed_selective_mode() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();
        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca);

        // In selective mode, all non-blocked hosts are "allowed"
        assert!(transport.is_host_allowed("api.openai.com"));
        assert!(transport.is_host_allowed("api.anthropic.com"));
        assert!(transport.is_host_allowed("example.com")); // tunneled, but allowed
    }

    #[test]
    fn test_listen_addr() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();
        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca);

        assert_eq!(transport.listen_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn test_with_rate_limiter() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10.0,
            burst_size: 20,
            enabled: true,
        });

        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca)
            .with_rate_limiter(limiter);

        assert!(transport.rate_limiter.is_some());
    }

    #[test]
    fn test_with_circuit_breaker() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        let breaker = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(30),
            success_threshold: 2,
            failure_window: Duration::from_secs(60),
            enabled: true,
        });

        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca)
            .with_circuit_breaker(breaker);

        assert!(transport.circuit_breaker.is_some());
    }

    #[test]
    fn test_transport_with_all_production_features() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 100.0,
            burst_size: 200,
            enabled: true,
        });

        let breaker = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
            enabled: true,
        });

        let transport = ForwardProxyTransport::new(ForwardProxyConfig::default(), ca)
            .with_rate_limiter(limiter)
            .with_circuit_breaker(breaker);

        assert!(transport.rate_limiter.is_some());
        assert!(transport.circuit_breaker.is_some());
        assert_eq!(transport.name(), "forward_proxy");
    }
}
