//! Core type definitions for NLAG
//!
//! These types are shared across all NLAG components and form the
//! fundamental building blocks of the system.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for an agent instance
///
/// Each agent generates a new ID on startup. This ID is used for:
/// - Connection tracking
/// - Metrics attribution
/// - Audit logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(Uuid);

impl AgentId {
    /// Generate a new random agent ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a tunnel
///
/// A tunnel represents a single exposed service. An agent can have
/// multiple tunnels (e.g., exposing both HTTP and TCP on different ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(Uuid);

impl TunnelId {
    /// Generate a new random tunnel ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for TunnelId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stream identifier within a tunnel
///
/// Each individual connection through a tunnel gets a stream ID.
/// This allows multiplexing many connections over a single QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId(pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Protocol types supported by NLAG
///
/// This determines how the edge server handles incoming traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Raw TCP passthrough
    Tcp,
    /// HTTP/1.1 with header inspection
    Http,
    /// HTTPS with TLS termination at edge
    Https,
    /// HTTP/2 support
    Http2,
    /// WebSocket upgrade support
    Websocket,
    // TODO: Add gRPC, UDP support for enterprise
}

impl Protocol {
    /// Check if this protocol requires TLS termination at edge
    pub fn requires_tls_termination(&self) -> bool {
        matches!(self, Protocol::Https | Protocol::Http2)
    }

    /// Get default port for this protocol
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Tcp => 0,      // No default for raw TCP
            Protocol::Http => 80,
            Protocol::Https => 443,
            Protocol::Http2 => 443,
            Protocol::Websocket => 80,
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            "http2" | "h2" => Ok(Protocol::Http2),
            "websocket" | "ws" => Ok(Protocol::Websocket),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Http => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
            Protocol::Http2 => write!(f, "http2"),
            Protocol::Websocket => write!(f, "websocket"),
        }
    }
}

/// Configuration for a single tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Unique identifier for this tunnel
    pub tunnel_id: TunnelId,

    /// Protocol to expose
    pub protocol: Protocol,

    /// Local port to forward to
    pub local_port: u16,

    /// Local host (defaults to 127.0.0.1)
    pub local_host: String,

    /// Optional subdomain request (may be overridden by edge)
    pub subdomain: Option<String>,

    /// Optional custom domain (requires DNS setup)
    pub custom_domain: Option<String>,

    // TODO: Add authentication options for enterprise
    // pub auth: Option<TunnelAuth>,
    // pub ip_allowlist: Option<Vec<IpNetwork>>,
}

impl TunnelConfig {
    /// Create a new tunnel configuration
    pub fn new(protocol: Protocol, local_port: u16) -> Self {
        Self {
            tunnel_id: TunnelId::new(),
            protocol,
            local_port,
            local_host: "127.0.0.1".to_string(),
            subdomain: None,
            custom_domain: None,
        }
    }

    /// Set the local host
    pub fn with_local_host(mut self, host: impl Into<String>) -> Self {
        self.local_host = host.into();
        self
    }

    /// Set the subdomain
    pub fn with_subdomain(mut self, subdomain: impl Into<String>) -> Self {
        self.subdomain = Some(subdomain.into());
        self
    }

    /// Get the local address to connect to
    pub fn local_addr(&self) -> String {
        format!("{}:{}", self.local_host, self.local_port)
    }
}

/// Agent authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    /// Agent's unique identifier
    pub agent_id: AgentId,

    /// Authentication token (short-lived)
    pub auth_token: String,

    /// Token expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,

    // TODO: Add certificate fingerprint for mTLS binding
    // pub cert_fingerprint: Option<String>,
}

impl AgentCredentials {
    /// Check if the credentials have expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() >= self.expires_at
    }
}

/// Tunnel status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// Tunnel ID
    pub tunnel_id: TunnelId,

    /// Current state
    pub state: TunnelState,

    /// Assigned public URL (if active)
    pub public_url: Option<String>,

    /// Number of active connections
    pub active_connections: u32,

    /// Total bytes transferred
    pub bytes_in: u64,
    pub bytes_out: u64,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// State of a tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelState {
    /// Tunnel is being established
    Connecting,
    /// Tunnel is active and accepting traffic
    Active,
    /// Tunnel is temporarily disconnected (will reconnect)
    Reconnecting,
    /// Tunnel has been closed
    Closed,
    /// Tunnel encountered an error
    Error,
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelState::Connecting => write!(f, "connecting"),
            TunnelState::Active => write!(f, "active"),
            TunnelState::Reconnecting => write!(f, "reconnecting"),
            TunnelState::Closed => write!(f, "closed"),
            TunnelState::Error => write!(f, "error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_generation() {
        let id1 = AgentId::new();
        let id2 = AgentId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_protocol_parsing() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("HTTP".parse::<Protocol>().unwrap(), Protocol::Http);
        assert_eq!("h2".parse::<Protocol>().unwrap(), Protocol::Http2);
        assert!("invalid".parse::<Protocol>().is_err());
    }

    #[test]
    fn test_tunnel_config() {
        let config = TunnelConfig::new(Protocol::Http, 8080)
            .with_local_host("localhost")
            .with_subdomain("myapp");

        assert_eq!(config.local_addr(), "localhost:8080");
        assert_eq!(config.subdomain, Some("myapp".to_string()));
    }
}
