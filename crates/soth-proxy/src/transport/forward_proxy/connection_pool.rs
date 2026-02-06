//! Connection pool for upstream TLS connections

use crate::error::ProxyError;
use dashmap::DashMap;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, trace};

/// Pooled connection
pub struct PooledConnection {
    /// The TLS stream
    pub stream: TlsStream<TcpStream>,
    /// When this connection was created
    pub created_at: Instant,
    /// When this connection was last used
    pub last_used: Instant,
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
}

impl PooledConnection {
    /// Check if connection is stale based on idle timeout
    pub fn is_stale(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }
}

/// Connection pool entry
struct PoolEntry {
    connections: Vec<PooledConnection>,
}

/// Connection pool for upstream connections
pub struct ConnectionPool {
    /// Pooled connections by host:port
    pools: DashMap<String, Mutex<PoolEntry>>,
    /// Maximum connections per host
    max_per_host: usize,
    /// Idle timeout
    idle_timeout: Duration,
    /// Connect timeout
    connect_timeout: Duration,
    /// TLS connector (lazily initialized)
    tls_connector: once_cell::sync::OnceCell<TlsConnector>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(max_per_host: usize, idle_timeout: Duration, connect_timeout: Duration) -> Self {
        Self {
            pools: DashMap::new(),
            max_per_host,
            idle_timeout,
            connect_timeout,
            tls_connector: once_cell::sync::OnceCell::new(),
        }
    }

    /// Get the TLS connector
    fn get_connector(&self) -> &TlsConnector {
        self.tls_connector.get_or_init(|| {
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            TlsConnector::from(Arc::new(config))
        })
    }

    /// Get a connection from the pool or create a new one
    pub async fn get_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TlsStream<TcpStream>, ProxyError> {
        let key = format!("{}:{}", host, port);

        // Try to get from pool
        if let Some(entry) = self.pools.get(&key) {
            let mut entry = entry.lock().await;

            // Remove stale connections
            entry
                .connections
                .retain(|c| !c.is_stale(self.idle_timeout));

            // Return first available connection
            if let Some(mut conn) = entry.connections.pop() {
                trace!("Reusing pooled connection to {}", key);
                conn.last_used = Instant::now();
                return Ok(conn.stream);
            }
        }

        // Create new connection
        debug!("Creating new connection to {}", key);
        self.create_connection(host, port).await
    }

    /// Create a new TLS connection
    async fn create_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TlsStream<TcpStream>, ProxyError> {
        let addr = format!("{}:{}", host, port);

        // TCP connect with timeout
        let tcp_stream = tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ProxyError::timeout(self.connect_timeout.as_millis() as u64))?
        .map_err(|e| ProxyError::transport(format!("TCP connect failed: {}", e)))?;

        // TLS handshake
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| ProxyError::transport(format!("Invalid server name: {}", e)))?;

        let connector = self.get_connector();
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| ProxyError::transport(format!("TLS handshake failed: {}", e)))?;

        debug!("TLS connection established to {}:{}", host, port);
        Ok(tls_stream)
    }

    /// Return a connection to the pool
    pub async fn return_connection(&self, stream: TlsStream<TcpStream>, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);

        let entry = self.pools.entry(key.clone()).or_insert_with(|| {
            Mutex::new(PoolEntry {
                connections: Vec::new(),
            })
        });

        let mut entry = entry.lock().await;

        // Remove stale connections
        entry
            .connections
            .retain(|c| !c.is_stale(self.idle_timeout));

        // Only keep up to max_per_host
        if entry.connections.len() < self.max_per_host {
            trace!("Returning connection to pool: {}", key);
            entry.connections.push(PooledConnection {
                stream,
                created_at: Instant::now(),
                last_used: Instant::now(),
                host: host.to_string(),
                port,
            });
        } else {
            trace!("Pool full, dropping connection: {}", key);
            // Connection will be dropped
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let mut total = 0;
        let mut by_host = std::collections::HashMap::new();

        for entry in self.pools.iter() {
            // We can't easily count without async lock, just count keys
            by_host.insert(entry.key().clone(), 0);
            total += 1;
        }

        PoolStats {
            total_hosts: total,
            max_per_host: self.max_per_host,
        }
    }

    /// Clear all pooled connections
    pub fn clear(&self) {
        self.pools.clear();
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of hosts with pooled connections
    pub total_hosts: usize,
    /// Maximum connections per host
    pub max_per_host: usize,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(
            10,
            Duration::from_secs(90),
            Duration::from_secs(10),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = ConnectionPool::new(
            5,
            Duration::from_secs(60),
            Duration::from_secs(10),
        );

        assert_eq!(pool.max_per_host, 5);
    }

    #[test]
    fn test_pool_stats() {
        let pool = ConnectionPool::default();
        let stats = pool.stats();

        assert_eq!(stats.total_hosts, 0);
        assert_eq!(stats.max_per_host, 10);
    }
}
