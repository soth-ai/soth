//! Blind TCP tunnel for non-AI domains
//!
//! This module provides a simple TCP passthrough without TLS termination.
//! Used for domains that don't need inspection (non-AI traffic).

use crate::error::ProxyError;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Start a blind TCP tunnel (no TLS termination)
///
/// This simply connects to the upstream and copies bytes bidirectionally.
/// No inspection, no modification - just a transparent TCP proxy.
pub async fn start_blind_tunnel(
    mut client_stream: TcpStream,
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<(), ProxyError> {
    debug!("Starting blind tunnel to {}:{}", host, port);

    // Connect to upstream
    let upstream_addr = format!("{}:{}", host, port);
    let mut upstream_stream = tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(&upstream_addr),
    )
    .await
    .map_err(|_| ProxyError::transport(format!("Connection timeout to {}", upstream_addr)))?
    .map_err(|e| ProxyError::transport(format!("Failed to connect to {}: {}", upstream_addr, e)))?;

    info!(
        "Blind tunnel established to {} (passthrough, no inspection)",
        host
    );

    // Copy bidirectionally until either side closes
    match copy_bidirectional(&mut client_stream, &mut upstream_stream).await {
        Ok((client_to_upstream, upstream_to_client)) => {
            debug!(
                "Blind tunnel to {} closed: {} bytes up, {} bytes down",
                host, client_to_upstream, upstream_to_client
            );
        }
        Err(e) => {
            debug!("Blind tunnel to {} error: {}", host, e);
        }
    }

    // Try to gracefully close connections
    let _ = client_stream.shutdown().await;
    let _ = upstream_stream.shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_blind_tunnel_basic() {
        // Start a mock upstream server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        // Server task: echo back what it receives
        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.shutdown().await.ok();
        });

        // Create a client connection pair
        let (client_stream, mut mock_client) = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client_addr = listener.local_addr().unwrap();

            let connect_future = TcpStream::connect(client_addr);
            let accept_future = listener.accept();

            let (mock_client, (proxy_client, _)) =
                tokio::try_join!(connect_future, accept_future).unwrap();
            (proxy_client, mock_client)
        };

        // Start the blind tunnel in a separate task
        let tunnel_handle = tokio::spawn(async move {
            start_blind_tunnel(
                client_stream,
                "127.0.0.1",
                upstream_addr.port(),
                Duration::from_secs(5),
            )
            .await
        });

        // Send data through the tunnel
        mock_client.write_all(b"Hello, tunnel!").await.unwrap();

        // Read the echoed response
        let mut response = vec![0u8; 1024];
        let n = mock_client.read(&mut response).await.unwrap();
        assert_eq!(&response[..n], b"Hello, tunnel!");

        // Clean up
        mock_client.shutdown().await.ok();
        server_handle.await.ok();
        tunnel_handle.await.ok();
    }
}
