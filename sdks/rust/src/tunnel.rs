//! Tunnel types and management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Notify;

/// Supported tunnel protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP protocol
    #[default]
    Http,
    /// HTTPS protocol
    Https,
    /// Raw TCP
    Tcp,
    /// Raw UDP
    Udp,
    /// gRPC
    Grpc,
    /// WebSocket
    WebSocket,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Grpc => write!(f, "grpc"),
            Protocol::WebSocket => write!(f, "websocket"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "grpc" => Ok(Protocol::Grpc),
            "websocket" | "ws" => Ok(Protocol::WebSocket),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

/// Tunnel connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    /// Connecting to edge server
    Connecting,
    /// Connected and forwarding traffic
    Connected,
    /// Reconnecting after disconnect
    Reconnecting,
    /// Disconnected from edge server
    Disconnected,
    /// Tunnel has been closed
    Closed,
    /// Tunnel is in error state
    Error,
}

impl Default for TunnelState {
    fn default() -> Self {
        TunnelState::Connecting
    }
}

/// Configuration for creating a tunnel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Protocol to use
    #[serde(default)]
    pub protocol: Protocol,

    /// Local host to forward to
    #[serde(default = "default_local_host")]
    pub local_host: String,

    /// Local port to forward to
    pub local_port: u16,

    /// Requested subdomain
    #[serde(default)]
    pub subdomain: Option<String>,

    /// Basic auth credentials (username -> password)
    #[serde(default)]
    pub basic_auth: Option<HashMap<String, String>>,

    /// IP allowlist (CIDR notation)
    #[serde(default)]
    pub ip_allow: Option<Vec<String>>,

    /// IP denylist (CIDR notation)
    #[serde(default)]
    pub ip_deny: Option<Vec<String>>,

    /// Custom headers to add
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Enable request inspection
    #[serde(default = "default_true")]
    pub inspect: bool,

    /// Custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

fn default_local_host() -> String {
    "127.0.0.1".to_string()
}

fn default_true() -> bool {
    true
}

/// Tunnel usage metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelMetrics {
    /// Total number of requests
    pub requests_total: u64,
    /// Bytes received
    pub bytes_in: u64,
    /// Bytes sent
    pub bytes_out: u64,
    /// Currently active connections
    pub connections_active: u32,
    /// Average latency in milliseconds
    pub latency_avg_ms: f64,
    /// 99th percentile latency in milliseconds
    pub latency_p99_ms: f64,
    /// Total number of errors
    pub errors_total: u64,
    /// Last request timestamp
    pub last_request_at: Option<DateTime<Utc>>,
}

/// Information about an existing tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// Unique tunnel ID
    pub id: String,
    /// Public URL
    pub public_url: String,
    /// Protocol
    pub protocol: Protocol,
    /// Local address being forwarded
    pub local_address: String,
    /// Current state
    pub state: TunnelState,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Tunnel metrics
    pub metrics: TunnelMetrics,
    /// Custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Represents an active tunnel connection.
///
/// # Example
///
/// ```rust,no_run
/// # use nlag_sdk::{Client, TunnelConfig};
/// # async fn example() -> anyhow::Result<()> {
/// let client = Client::new().await?;
/// let tunnel = client.expose(TunnelConfig {
///     local_port: 8080,
///     ..Default::default()
/// }).await?;
///
/// println!("URL: {}", tunnel.public_url());
///
/// // Wait for tunnel to be closed
/// tunnel.wait().await?;
/// # Ok(())
/// # }
/// ```
pub struct Tunnel {
    id: String,
    public_url: String,
    config: TunnelConfig,
    state: parking_lot::RwLock<TunnelState>,
    metrics: parking_lot::RwLock<TunnelMetrics>,
    created_at: DateTime<Utc>,
    close_notify: Arc<Notify>,
}

impl Tunnel {
    /// Create a new tunnel instance.
    pub(crate) fn new(id: String, public_url: String, config: TunnelConfig) -> Self {
        Self {
            id,
            public_url,
            config,
            state: parking_lot::RwLock::new(TunnelState::Connecting),
            metrics: parking_lot::RwLock::new(TunnelMetrics::default()),
            created_at: Utc::now(),
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Get the tunnel ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the public URL.
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// Get the tunnel configuration.
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// Get the current state.
    pub fn state(&self) -> TunnelState {
        *self.state.read()
    }

    /// Get the current metrics.
    pub fn metrics(&self) -> TunnelMetrics {
        self.metrics.read().clone()
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Wait for the tunnel to be closed.
    pub async fn wait(&self) -> crate::Result<()> {
        self.close_notify.notified().await;
        Ok(())
    }

    /// Close the tunnel.
    pub async fn close(&self) -> crate::Result<()> {
        *self.state.write() = TunnelState::Closed;
        self.close_notify.notify_waiters();
        Ok(())
    }

    /// Refresh metrics from the edge server.
    pub async fn refresh_metrics(&self) -> crate::Result<TunnelMetrics> {
        // TODO: Fetch from connection
        Ok(self.metrics.read().clone())
    }

    /// Update the tunnel state.
    pub(crate) fn set_state(&self, state: TunnelState) {
        *self.state.write() = state;
        if state == TunnelState::Closed {
            self.close_notify.notify_waiters();
        }
    }

    /// Update metrics.
    pub(crate) fn update_metrics(&self, metrics: TunnelMetrics) {
        *self.metrics.write() = metrics;
    }
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("id", &self.id)
            .field("public_url", &self.public_url)
            .field("state", &self.state())
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Http.to_string(), "http");
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Grpc.to_string(), "grpc");
    }

    #[test]
    fn test_protocol_parse() {
        assert_eq!("http".parse::<Protocol>().unwrap(), Protocol::Http);
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("ws".parse::<Protocol>().unwrap(), Protocol::WebSocket);
    }

    #[test]
    fn test_tunnel_config_default() {
        let config = TunnelConfig::default();
        assert_eq!(config.protocol, Protocol::Http);
        assert_eq!(config.local_host, "127.0.0.1");
        assert!(config.inspect);
    }

    #[tokio::test]
    async fn test_tunnel_state() {
        let tunnel = Tunnel::new(
            "test-id".to_string(),
            "https://test.nlag.dev".to_string(),
            TunnelConfig::default(),
        );

        assert_eq!(tunnel.state(), TunnelState::Connecting);
        
        tunnel.set_state(TunnelState::Connected);
        assert_eq!(tunnel.state(), TunnelState::Connected);
    }
}
