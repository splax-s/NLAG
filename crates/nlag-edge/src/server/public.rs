//! Public traffic handler
//!
//! Handles incoming public traffic (HTTP/TCP) and routes it to
//! the appropriate agent tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use nlag_common::{
    protocol::{
        codec::quic::{read_message, write_message},
        message::{DataFrame, Message, StreamCloseMessage, StreamMetadata, StreamOpenMessage},
    },
    types::StreamId,
};

use crate::config::{DomainConfig, RateLimitConfig};
use crate::logging::HttpRequestLog;
use crate::metrics;
use crate::registry::Registry;
use crate::server::rate_limit::RateLimiter;
use crate::server::ShutdownSignal;

/// Public traffic listener
pub struct PublicListener {
    listener: TcpListener,
    registry: Arc<Registry>,
    rate_limiter: RateLimiter,
    domain_config: DomainConfig,
    stream_counter: AtomicU64,
    shutdown: ShutdownSignal,
}

impl PublicListener {
    /// Create a new public listener
    pub fn new(
        bind_addr: SocketAddr,
        registry: Arc<Registry>,
        rate_config: RateLimitConfig,
        domain_config: DomainConfig,
        shutdown: ShutdownSignal,
    ) -> anyhow::Result<Self> {
        let listener = std::net::TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;

        let rate_limiter = RateLimiter::new(rate_config);

        Ok(Self {
            listener,
            registry,
            rate_limiter,
            domain_config,
            stream_counter: AtomicU64::new(0),
            shutdown,
        })
    }

    /// Run the public listener loop
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Public listener started");

        loop {
            // Check for shutdown
            if self.shutdown.is_shutdown() {
                info!("Public listener shutting down");
                break;
            }

            tracing::trace!("Waiting for public connection...");
            
            // Accept with timeout to check shutdown periodically
            let (stream, addr) = tokio::select! {
                result = self.listener.accept() => {
                    match result {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Accept error: {}", e);
                            continue;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    continue; // Check shutdown flag
                }
            };

            info!("New public connection from {}", addr);

            let registry = self.registry.clone();
            let domain_config = self.domain_config.clone();
            let rate_limiter = self.rate_limiter.clone();
            let stream_id = StreamId(self.stream_counter.fetch_add(1, Ordering::Relaxed));

            // Spawn handler for this connection
            tokio::spawn(async move {
                if let Err(e) =
                    handle_public_connection(stream, addr, registry, domain_config, rate_limiter, stream_id)
                        .await
                {
                    debug!("Public connection from {} ended: {}", addr, e);
                }
            });
        }
        
        Ok(())
    }
}

/// Handle a single public connection
async fn handle_public_connection(
    mut stream: TcpStream,
    source_addr: SocketAddr,
    registry: Arc<Registry>,
    domain_config: DomainConfig,
    rate_limiter: RateLimiter,
    stream_id: StreamId,
) -> anyhow::Result<()> {
    let request_start = Instant::now();

    // Read initial data to determine routing
    // For HTTP, we peek at the Host header
    // For TCP, we use a default tunnel or SNI

    let mut peek_buf = [0u8; 4096];
    let n = stream.peek(&mut peek_buf).await?;

    if n == 0 {
        return Err(anyhow::anyhow!("Empty connection"));
    }

    // Try to parse as HTTP to extract Host header
    let request_method = extract_http_method(&peek_buf[..n]);
    let (tunnel_id, metadata) = match extract_http_host(&peek_buf[..n]) {
        Some(host) => {
            // Extract subdomain from host
            let subdomain = extract_subdomain(&host, &domain_config.base_domain);

            if let Some(subdomain) = subdomain {
                // Check rate limit
                if !rate_limiter.check(&subdomain) {
                    // Send 429 Too Many Requests
                    let response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded\n";
                    stream.write_all(response.as_bytes()).await?;
                    metrics::record_request(request_method.as_deref().unwrap_or("UNKNOWN"), 429);
                    return Err(anyhow::anyhow!("Rate limit exceeded"));
                }

                // Look up tunnel
                match registry.get_tunnel_by_subdomain(&subdomain) {
                    Some(tid) => {
                        // Check for WebSocket upgrade
                        let is_websocket = is_websocket_upgrade(&peek_buf[..n]);
                        let mut headers = vec![];
                        
                        if is_websocket {
                            headers.push(("Upgrade".to_string(), "websocket".to_string()));
                            if let Some(ws_key) = extract_websocket_key(&peek_buf[..n]) {
                                headers.push(("Sec-WebSocket-Key".to_string(), ws_key));
                            }
                            debug!("WebSocket upgrade request detected");
                        }
                        
                        let metadata = StreamMetadata {
                            host: Some(host.clone()),
                            path: extract_http_path(&peek_buf[..n]),
                            method: request_method.clone(),
                            headers,
                        };
                        (tid, Some(metadata))
                    }
                    None => {
                        // Tunnel not found - send 404
                        let response =
                            "HTTP/1.1 404 Not Found\r\n\r\nTunnel not found\n";
                        stream.write_all(response.as_bytes()).await?;
                        metrics::record_request(request_method.as_deref().unwrap_or("UNKNOWN"), 404);
                        return Err(anyhow::anyhow!("Tunnel not found: {}", subdomain));
                    }
                }
            } else {
                // No valid subdomain - send 400
                let response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid host\n";
                stream.write_all(response.as_bytes()).await?;
                return Err(anyhow::anyhow!("Invalid host: {}", host));
            }
        }
        None => {
            // Not HTTP - try SNI-based routing for TLS connections
            if let Some(sni_host) = extract_tls_sni(&peek_buf[..n]) {
                debug!("TLS connection with SNI: {}", sni_host);
                
                // Extract subdomain from SNI hostname
                if let Some(subdomain) = extract_subdomain(&sni_host, &domain_config.base_domain) {
                    // Check rate limit
                    if !rate_limiter.check(&subdomain) {
                        // For TLS, we can't send HTTP response, just close connection
                        return Err(anyhow::anyhow!("Rate limit exceeded for SNI host: {}", sni_host));
                    }

                    match registry.get_tunnel_by_subdomain(&subdomain) {
                        Some(tid) => {
                            let metadata = StreamMetadata {
                                host: Some(sni_host),
                                path: None,
                                method: None,
                                headers: vec![],
                            };
                            (tid, Some(metadata))
                        }
                        None => {
                            return Err(anyhow::anyhow!("Tunnel not found for SNI: {}", subdomain));
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("Invalid SNI hostname: {}", sni_host));
                }
            } else {
                // Neither HTTP nor TLS with SNI - can't route
                let response = "HTTP/1.1 400 Bad Request\r\n\r\nCould not determine tunnel\n";
                stream.write_all(response.as_bytes()).await?;
                return Err(anyhow::anyhow!("Could not determine tunnel (non-HTTP, no SNI)"));
            }
        }
    };

    // Get the subdomain for metrics
    let subdomain = metadata.as_ref()
        .and_then(|m| m.host.as_ref())
        .and_then(|h| extract_subdomain(h, &domain_config.base_domain))
        .unwrap_or_default();

    // Extract values for logging before metadata is moved
    let log_method = metadata.as_ref().and_then(|m| m.method.clone());
    let log_path = metadata.as_ref().and_then(|m| m.path.clone());
    let log_host = metadata.as_ref().and_then(|m| m.host.clone());

    // Get connection to agent
    let agent_conn = match registry.get_tunnel_connection(&tunnel_id) {
        Some(conn) => conn,
        None => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\nAgent disconnected\n";
            stream.write_all(response.as_bytes()).await?;
            metrics::record_request(log_method.as_deref().unwrap_or("UNKNOWN"), 502);
            return Err(anyhow::anyhow!("Agent not connected"));
        }
    };

    debug!("Routing connection to tunnel {}", tunnel_id);

    // Open stream to agent
    let (mut agent_send, mut agent_recv) = agent_conn.open_bi().await?;

    // Send stream open message
    let open_msg = Message::StreamOpen(StreamOpenMessage {
        tunnel_id,
        stream_id,
        source_addr: source_addr.to_string(),
        metadata,
    });
    write_message(&mut agent_send, &open_msg).await?;

    // Bidirectional forwarding with byte counting
    let (mut client_read, mut client_write) = stream.split();
    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let response_status = Arc::new(AtomicU64::new(200)); // Default to 200

    // Client -> Agent
    let bytes_in_clone = bytes_in.clone();
    let client_to_agent = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!("Client read error: {}", e);
                    break;
                }
            };

            bytes_in_clone.fetch_add(n as u64, Ordering::Relaxed);

            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if let Err(e) = write_message(&mut agent_send, &frame).await {
                debug!("Agent write error: {}", e);
                break;
            }
        }

        // Send close
        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut agent_send, &close).await;
    };

    // Agent -> Client
    let bytes_out_clone = bytes_out.clone();
    let response_status_clone = response_status.clone();
    let agent_to_client = async move {
        let mut first_data = true;
        loop {
            let msg = match read_message(&mut agent_recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("Agent read error: {}", e);
                    break;
                }
            };

            match msg {
                Message::Data(frame) => {
                    bytes_out_clone.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);

                    // Extract HTTP status from first response
                    if first_data {
                        first_data = false;
                        if let Some(status) = extract_http_status(&frame.payload) {
                            response_status_clone.store(status as u64, Ordering::Relaxed);
                        }
                    }

                    if let Err(e) = client_write.write_all(&frame.payload).await {
                        debug!("Client write error: {}", e);
                        break;
                    }
                }
                Message::StreamClose(_) => {
                    break;
                }
                other => {
                    debug!("Unexpected message: {:?}", other.message_type());
                }
            }
        }

        let _ = client_write.shutdown().await;
    };

    // Run both directions
    tokio::join!(client_to_agent, agent_to_client);

    // Record metrics
    let status = response_status.load(Ordering::Relaxed) as u16;
    let total_bytes_in = bytes_in.load(Ordering::Relaxed);
    let total_bytes_out = bytes_out.load(Ordering::Relaxed);
    let latency = request_start.elapsed();

    // Record request with method
    let method = log_method.as_deref().unwrap_or("UNKNOWN");
    metrics::record_request(method, status);
    metrics::record_request_latency("http", latency.as_secs_f64());
    metrics::record_bytes(total_bytes_in, total_bytes_out);

    // Structured request logging
    let mut log_builder = HttpRequestLog::new(tunnel_id, stream_id, source_addr.to_string());
    if let Some(method) = log_method {
        log_builder = log_builder.method(method);
    }
    if let Some(path) = log_path {
        log_builder = log_builder.path(path);
    }
    if let Some(host) = log_host {
        log_builder = log_builder.host(host);
    }
    log_builder = log_builder.status(status);
    log_builder.add_bytes_in(total_bytes_in);
    log_builder.add_bytes_out(total_bytes_out);
    log_builder.finish();

    debug!("Stream {} closed", stream_id);
    Ok(())
}

/// Extract Host header from HTTP request
fn extract_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;

    // Find Host header (case-insensitive)
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            let host = line[5..].trim();
            // Remove port if present
            let host = host.split(':').next().unwrap_or(host);
            return Some(host.to_string());
        }
    }

    None
}

/// Extract subdomain from full host
fn extract_subdomain(host: &str, base_domain: &str) -> Option<String> {
    // Handle localhost case for development
    if host == "localhost" || host == "127.0.0.1" {
        // For localhost, we need a different routing mechanism
        // For now, return None
        return None;
    }

    // Check if host ends with base domain
    if host.ends_with(base_domain) {
        let prefix = &host[..host.len() - base_domain.len()];
        let prefix = prefix.trim_end_matches('.');
        if !prefix.is_empty() {
            return Some(prefix.to_string());
        }
    }

    // Also support subdomain.localhost pattern for development
    if host.ends_with(".localhost") {
        let subdomain = &host[..host.len() - ".localhost".len()];
        if !subdomain.is_empty() {
            return Some(subdomain.to_string());
        }
    }

    None
}

/// Extract HTTP method from request
fn extract_http_method(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let first_line = text.lines().next()?;
    let method = first_line.split_whitespace().next()?;
    Some(method.to_string())
}

/// Extract HTTP path from request
fn extract_http_path(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next(); // Skip method
    parts.next().map(|s| s.to_string())
}

/// Extract HTTP status code from response
fn extract_http_status(data: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(data).ok()?;
    let first_line = text.lines().next()?;

    // HTTP/1.x NNN ...
    if first_line.starts_with("HTTP/") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    None
}

/// Check if the request is a WebSocket upgrade request
fn is_websocket_upgrade(data: &[u8]) -> bool {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t.to_lowercase(),
        Err(_) => return false,
    };

    // WebSocket upgrade requires:
    // 1. Upgrade: websocket header
    // 2. Connection: upgrade header
    let has_upgrade = text.lines().any(|line| {
        line.to_lowercase().starts_with("upgrade:") && 
        line.to_lowercase().contains("websocket")
    });
    
    let has_connection_upgrade = text.lines().any(|line| {
        line.to_lowercase().starts_with("connection:") && 
        line.to_lowercase().contains("upgrade")
    });

    has_upgrade && has_connection_upgrade
}

/// Extract WebSocket key from request (for logging/debugging)
fn extract_websocket_key(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("sec-websocket-key:") {
            return Some(line[18..].trim().to_string());
        }
    }
    None
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello message
///
/// TLS ClientHello structure:
/// - Record layer: 5 bytes (type=0x16, version, length)
/// - Handshake header: 4 bytes (type=0x01 for ClientHello, length)
/// - Client version: 2 bytes
/// - Random: 32 bytes
/// - Session ID: 1 byte length + data
/// - Cipher suites: 2 byte length + data
/// - Compression methods: 1 byte length + data
/// - Extensions: 2 byte length, then extension list
/// - SNI extension (type 0x0000): contains hostname
fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // Minimum TLS record: 5 byte header + 4 byte handshake header
    if data.len() < 9 {
        return None;
    }

    // Check TLS record layer
    // Content type: 0x16 (Handshake)
    if data[0] != 0x16 {
        return None;
    }

    // Check record version (TLS 1.0/1.1/1.2/1.3 all use 0x0301 in record layer)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    if data[1] != 0x03 || data[2] > 0x04 {
        return None;
    }

    // Record length
    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + record_len {
        return None; // Incomplete record
    }

    // Handshake type: 0x01 (ClientHello)
    if data[5] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    let handshake_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | (data[8] as usize);
    if data.len() < 9 + handshake_len {
        return None;
    }

    let mut pos = 9; // Start of ClientHello body

    // Skip client version (2 bytes)
    pos += 2;
    if pos + 32 > data.len() {
        return None;
    }

    // Skip random (32 bytes)
    pos += 32;

    // Session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > data.len() {
        return None;
    }

    // Cipher suites
    let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_suites_len;
    if pos >= data.len() {
        return None;
    }

    // Compression methods
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;
    if pos + 2 > data.len() {
        return None;
    }

    // Extensions length
    let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() {
        return None;
    }

    // Parse extensions looking for SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension
            // SNI list length (2 bytes)
            if ext_len < 5 {
                return None;
            }

            let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            let name_type = data[pos + 2];
            let name_len = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if name_type == 0 && pos + 5 + name_len <= extensions_end {
                // Host name type
                return std::str::from_utf8(&data[pos + 5..pos + 5 + name_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http_host() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(request), Some("example.com".to_string()));

        let request = b"GET / HTTP/1.1\r\nhost: TEST.COM\r\n\r\n";
        assert_eq!(extract_http_host(request), Some("TEST.COM".to_string()));

        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(request), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            extract_subdomain("test.example.com", "example.com"),
            Some("test".to_string())
        );
        assert_eq!(
            extract_subdomain("sub.test.example.com", "example.com"),
            Some("sub.test".to_string())
        );
        assert_eq!(
            extract_subdomain("example.com", "example.com"),
            None
        );
        assert_eq!(
            extract_subdomain("test.localhost", "localhost"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_extract_http_method() {
        let request = b"GET / HTTP/1.1\r\n";
        assert_eq!(extract_http_method(request), Some("GET".to_string()));

        let request = b"POST /api HTTP/1.1\r\n";
        assert_eq!(extract_http_method(request), Some("POST".to_string()));
    }

    #[test]
    fn test_extract_http_status() {
        let response = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(extract_http_status(response), Some(200));

        let response = b"HTTP/1.0 404 Not Found\r\n";
        assert_eq!(extract_http_status(response), Some(404));

        let response = b"HTTP/2 500 Internal Server Error\r\n";
        assert_eq!(extract_http_status(response), Some(500));
    }

    #[test]
    fn test_websocket_detection() {
        let ws_request = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert!(is_websocket_upgrade(ws_request));

        let normal_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_websocket_upgrade(normal_request));

        let partial_ws = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
        assert!(!is_websocket_upgrade(partial_ws)); // Missing Connection: Upgrade
    }

    #[test]
    fn test_extract_websocket_key() {
        let ws_request = b"GET /ws HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(
            extract_websocket_key(ws_request),
            Some("dGhlIHNhbXBsZSBub25jZQ==".to_string())
        );
    }
}
