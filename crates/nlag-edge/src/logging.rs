//! Request logging for NLAG Edge
//!
//! Provides structured JSON logging for all HTTP requests flowing through tunnels.

use std::time::Instant;

use serde::Serialize;
use tracing::info;

use nlag_common::types::{StreamId, TunnelId};

/// HTTP request log entry
#[derive(Debug, Serialize)]
pub struct HttpRequestLog {
    /// Timestamp in ISO 8601 format
    pub timestamp: String,
    /// Tunnel ID
    pub tunnel_id: String,
    /// Stream/connection ID
    pub stream_id: u64,
    /// Client source address
    pub source_addr: String,
    /// HTTP method
    pub method: Option<String>,
    /// Request path
    pub path: Option<String>,
    /// Host header
    pub host: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Content length
    pub content_length: Option<u64>,
    /// Response status code (if available)
    pub status: Option<u16>,
    /// Request duration in milliseconds
    pub duration_ms: u64,
    /// Bytes received from client
    pub bytes_in: u64,
    /// Bytes sent to client
    pub bytes_out: u64,
    /// Error message if any
    pub error: Option<String>,
}

impl HttpRequestLog {
    /// Create a new request log builder
    pub fn new(tunnel_id: TunnelId, stream_id: StreamId, source_addr: String) -> HttpRequestLogBuilder {
        HttpRequestLogBuilder {
            tunnel_id,
            stream_id,
            source_addr,
            start_time: Instant::now(),
            method: None,
            path: None,
            host: None,
            user_agent: None,
            content_length: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            error: None,
        }
    }
}

/// Builder for HTTP request logs
pub struct HttpRequestLogBuilder {
    tunnel_id: TunnelId,
    stream_id: StreamId,
    source_addr: String,
    start_time: Instant,
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
    user_agent: Option<String>,
    content_length: Option<u64>,
    status: Option<u16>,
    bytes_in: u64,
    bytes_out: u64,
    error: Option<String>,
}

impl HttpRequestLogBuilder {
    /// Set HTTP method
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set request path
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set host header
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set user agent
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set content length
    pub fn content_length(mut self, len: u64) -> Self {
        self.content_length = Some(len);
        self
    }

    /// Set response status
    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Add bytes received
    pub fn add_bytes_in(&mut self, bytes: u64) {
        self.bytes_in += bytes;
    }

    /// Add bytes sent
    pub fn add_bytes_out(&mut self, bytes: u64) {
        self.bytes_out += bytes;
    }

    /// Set error message
    pub fn error(mut self, err: impl Into<String>) -> Self {
        self.error = Some(err.into());
        self
    }

    /// Finalize and log the request
    pub fn finish(self) {
        let duration = self.start_time.elapsed();
        
        let _log = HttpRequestLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tunnel_id: self.tunnel_id.to_string(),
            stream_id: self.stream_id.0,
            source_addr: self.source_addr,
            method: self.method.clone(),
            path: self.path.clone(),
            host: self.host.clone(),
            user_agent: self.user_agent,
            content_length: self.content_length,
            status: self.status,
            duration_ms: duration.as_millis() as u64,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            error: self.error,
        };

        // Log as structured JSON
        info!(
            tunnel_id = %self.tunnel_id,
            stream_id = self.stream_id.0,
            method = ?self.method,
            path = ?self.path,
            host = ?self.host,
            status = ?self.status,
            duration_ms = duration.as_millis() as u64,
            bytes_in = self.bytes_in,
            bytes_out = self.bytes_out,
            "HTTP request"
        );
    }
}

/// TCP connection log entry
#[derive(Debug, Serialize)]
pub struct TcpConnectionLog {
    /// Timestamp in ISO 8601 format
    pub timestamp: String,
    /// Tunnel ID
    pub tunnel_id: String,
    /// Stream/connection ID
    pub stream_id: u64,
    /// Client source address
    pub source_addr: String,
    /// Destination port on edge
    pub dest_port: u16,
    /// Connection duration in milliseconds
    pub duration_ms: u64,
    /// Bytes received from client
    pub bytes_in: u64,
    /// Bytes sent to client
    pub bytes_out: u64,
    /// Error message if any
    pub error: Option<String>,
}

/// Builder for TCP connection logs
pub struct TcpConnectionLogBuilder {
    tunnel_id: TunnelId,
    stream_id: StreamId,
    source_addr: String,
    dest_port: u16,
    start_time: Instant,
    bytes_in: u64,
    bytes_out: u64,
    error: Option<String>,
}

impl TcpConnectionLogBuilder {
    /// Create a new TCP connection log builder
    pub fn new(tunnel_id: TunnelId, stream_id: StreamId, source_addr: String, dest_port: u16) -> Self {
        Self {
            tunnel_id,
            stream_id,
            source_addr,
            dest_port,
            start_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            error: None,
        }
    }

    /// Add bytes received
    pub fn add_bytes_in(&mut self, bytes: u64) {
        self.bytes_in += bytes;
    }

    /// Add bytes sent
    pub fn add_bytes_out(&mut self, bytes: u64) {
        self.bytes_out += bytes;
    }

    /// Set error message
    pub fn error(mut self, err: impl Into<String>) -> Self {
        self.error = Some(err.into());
        self
    }

    /// Finalize and log the connection
    pub fn finish(self) {
        let duration = self.start_time.elapsed();

        info!(
            tunnel_id = %self.tunnel_id,
            stream_id = self.stream_id.0,
            source_addr = %self.source_addr,
            dest_port = self.dest_port,
            duration_ms = duration.as_millis() as u64,
            bytes_in = self.bytes_in,
            bytes_out = self.bytes_out,
            "TCP connection"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlag_common::types::{StreamId, TunnelId};

    #[test]
    fn test_http_log_builder() {
        let builder = HttpRequestLog::new(
            TunnelId::new(),
            StreamId(1),
            "127.0.0.1:12345".to_string(),
        )
        .method("GET")
        .path("/api/test")
        .host("example.localhost")
        .status(200);

        // Just verify it doesn't panic
        builder.finish();
    }
}
