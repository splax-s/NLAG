//! QUIC transport implementation
//!
//! QUIC provides several advantages for NLAG:
//! - Built-in encryption (TLS 1.3)
//! - Stream multiplexing
//! - Connection migration
//! - Low-latency connection establishment (0-RTT)
//! - Built-in congestion control

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, RecvStream, SendStream,
    ServerConfig as QuinnServerConfig, TransportConfig,
};

use crate::crypto::tls::{create_client_config, create_server_config, TlsConfig};
use crate::error::{NlagError, Result};

/// QUIC client for establishing connections to edge servers
pub struct QuicClient {
    endpoint: Endpoint,
    server_name: String,
}

impl QuicClient {
    /// Create a new QUIC client
    ///
    /// # Arguments
    /// * `bind_addr` - Local address to bind to (use 0.0.0.0:0 for any)
    /// * `tls_config` - TLS configuration
    pub fn new(bind_addr: SocketAddr, tls_config: &TlsConfig) -> Result<Self> {
        // Create TLS client config
        let tls = create_client_config(tls_config)?;

        // Configure QUIC client
        let mut client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| NlagError::TlsError(format!("QUIC TLS config error: {}", e)))?,
        ));

        // Configure transport
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(60)
                .try_into()
                .expect("valid duration"),
        ));
        client_config.transport_config(Arc::new(transport));

        // Create endpoint
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            server_name: tls_config
                .server_name
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
        })
    }

    /// Connect to a remote QUIC server
    pub async fn connect(&self, addr: SocketAddr) -> Result<QuicConnection> {
        tracing::debug!("Connecting to {} (SNI: {})", addr, self.server_name);

        let connection = self
            .endpoint
            .connect(addr, &self.server_name)
            .map_err(|e| NlagError::ConnectionFailed(e.to_string()))?
            .await?;

        tracing::info!(
            "Connected to {} (protocol: {:?})",
            addr,
            connection.handshake_data().and_then(|h| {
                h.downcast::<quinn::crypto::rustls::HandshakeData>()
                    .ok()
                    .map(|h| h.protocol)
            })
        );

        Ok(QuicConnection::new(connection))
    }

    /// Close the endpoint
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"client closing");
    }
}

/// QUIC server for accepting agent connections
pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    /// Create a new QUIC server
    ///
    /// # Arguments
    /// * `bind_addr` - Address to bind to
    /// * `cert_pem` - PEM-encoded certificate
    /// * `key_pem` - PEM-encoded private key
    pub fn new(bind_addr: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<Self> {
        // Create TLS server config
        let tls = create_server_config(cert_pem, key_pem)?;

        // Configure QUIC server
        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)
                .map_err(|e| NlagError::TlsError(format!("QUIC TLS config error: {}", e)))?,
        ));

        // Configure transport
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(90)
                .try_into()
                .expect("valid duration"),
        ));
        // Allow reasonable concurrent streams
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(100u32.into());
        server_config.transport_config(Arc::new(transport));

        // Create endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)?;

        tracing::info!("QUIC server listening on {}", bind_addr);

        Ok(Self { endpoint })
    }

    /// Accept the next incoming connection
    pub async fn accept(&self) -> Option<QuicConnection> {
        let incoming = self.endpoint.accept().await?;
        match incoming.await {
            Ok(connection) => {
                tracing::debug!(
                    "Accepted connection from {}",
                    connection.remote_address()
                );
                Some(QuicConnection::new(connection))
            }
            Err(e) => {
                tracing::warn!("Failed to accept connection: {}", e);
                None
            }
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| NlagError::Internal(e.to_string()))
    }

    /// Close the server
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"server closing");
    }
}

/// Wrapper around a QUIC connection with NLAG-specific methods
#[derive(Debug)]
pub struct QuicConnection {
    inner: Connection,
}

impl QuicConnection {
    /// Create a new QuicConnection wrapper
    pub fn new(connection: Connection) -> Self {
        Self { inner: connection }
    }

    /// Get the remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Check if the connection is still open
    pub fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    /// Open a new bidirectional stream
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.inner
            .open_bi()
            .await
            .map_err(|e| NlagError::QuicError(format!("Failed to open stream: {}", e)))
    }

    /// Accept a bidirectional stream from the peer
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.inner
            .accept_bi()
            .await
            .map_err(|e| NlagError::QuicError(format!("Failed to accept stream: {}", e)))
    }

    /// Close the connection
    pub fn close(&self, code: u32, reason: &str) {
        self.inner
            .close(quinn::VarInt::from_u32(code), reason.as_bytes());
    }

    /// Get the underlying quinn Connection
    pub fn inner(&self) -> &Connection {
        &self.inner
    }

    /// Wait for the connection to be closed
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }
}

impl Clone for QuicConnection {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::generate_self_signed_cert;

    #[tokio::test]
    async fn test_quic_client_creation() {
        let tls_config = TlsConfig {
            insecure_skip_verify: true,
            server_name: Some("localhost".to_string()),
            ..Default::default()
        };

        let client = QuicClient::new("0.0.0.0:0".parse().unwrap(), &tls_config);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_quic_server_creation() {
        let cert_info = generate_self_signed_cert("localhost", &[], &[], 1, false).unwrap();

        let server =
            QuicServer::new("127.0.0.1:0".parse().unwrap(), &cert_info.cert_pem, &cert_info.key_pem);
        assert!(server.is_ok());

        if let Ok(s) = server {
            assert!(s.local_addr().is_ok());
        }
    }
}
