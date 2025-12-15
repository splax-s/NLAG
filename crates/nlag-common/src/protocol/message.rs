//! Protocol message definitions
//!
//! All messages that can be sent over the NLAG wire protocol.

use serde::{Deserialize, Serialize};

use crate::types::{AgentId, StreamId, TunnelConfig, TunnelId, TunnelStatus};

/// Protocol version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u8);

impl ProtocolVersion {
    pub const V1: Self = Self(1);

    pub fn current() -> Self {
        Self(super::CURRENT_PROTOCOL_VERSION)
    }

    pub fn is_compatible(&self, other: &Self) -> bool {
        // For now, exact match required. In the future, we might support
        // backward compatibility within major versions.
        self.0 == other.0
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::current()
    }
}

/// Message type discriminator
///
/// Using explicit u8 values for wire compatibility and debugging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // === Authentication (0x01 - 0x0F) ===
    /// Initial authentication request from agent
    Auth = 0x01,
    /// Authentication response from edge
    AuthResponse = 0x02,

    // === Tunnel Management (0x10 - 0x1F) ===
    /// Request to open a new tunnel
    OpenTunnel = 0x10,
    /// Tunnel opened successfully
    TunnelOpened = 0x11,
    /// Request to close a tunnel
    CloseTunnel = 0x12,
    /// Tunnel closed confirmation
    TunnelClosed = 0x13,
    /// Tunnel status update
    TunnelStatus = 0x14,

    // === Data Transfer (0x20 - 0x2F) ===
    /// Data frame
    Data = 0x20,
    /// Data acknowledgment (for flow control)
    DataAck = 0x21,
    /// Stream opened (new connection through tunnel)
    StreamOpen = 0x22,
    /// Stream closed
    StreamClose = 0x23,

    // === Control (0x30 - 0x3F) ===
    /// Heartbeat ping
    Ping = 0x30,
    /// Heartbeat pong
    Pong = 0x31,
    /// Error message
    Error = 0x32,
    /// Graceful shutdown notification
    Shutdown = 0x33,

    // Reserved for future use: 0x40-0xFF
}

impl TryFrom<u8> for MessageType {
    type Error = crate::error::NlagError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(MessageType::Auth),
            0x02 => Ok(MessageType::AuthResponse),
            0x10 => Ok(MessageType::OpenTunnel),
            0x11 => Ok(MessageType::TunnelOpened),
            0x12 => Ok(MessageType::CloseTunnel),
            0x13 => Ok(MessageType::TunnelClosed),
            0x14 => Ok(MessageType::TunnelStatus),
            0x20 => Ok(MessageType::Data),
            0x21 => Ok(MessageType::DataAck),
            0x22 => Ok(MessageType::StreamOpen),
            0x23 => Ok(MessageType::StreamClose),
            0x30 => Ok(MessageType::Ping),
            0x31 => Ok(MessageType::Pong),
            0x32 => Ok(MessageType::Error),
            0x33 => Ok(MessageType::Shutdown),
            _ => Err(crate::error::NlagError::InvalidMessageType(value)),
        }
    }
}

/// Main message enum containing all protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // === Authentication ===
    /// Agent authentication request
    Auth(AuthMessage),
    /// Edge authentication response
    AuthResponse(AuthResponseMessage),

    // === Tunnel Management ===
    /// Open a new tunnel
    OpenTunnel(OpenTunnelMessage),
    /// Tunnel opened successfully
    TunnelOpened(TunnelOpenedMessage),
    /// Close a tunnel
    CloseTunnel(CloseTunnelMessage),
    /// Tunnel closed
    TunnelClosed(TunnelClosedMessage),
    /// Tunnel status update
    TunnelStatus(TunnelStatusMessage),

    // === Data Transfer ===
    /// Data frame
    Data(DataFrame),
    /// Data acknowledgment
    DataAck(DataAckMessage),
    /// New stream opened
    StreamOpen(StreamOpenMessage),
    /// Stream closed
    StreamClose(StreamCloseMessage),

    // === Control ===
    /// Heartbeat ping
    Ping(PingMessage),
    /// Heartbeat pong
    Pong(PongMessage),
    /// Error
    Error(ErrorMessage),
    /// Shutdown notification
    Shutdown(ShutdownMessage),
}

impl Message {
    /// Get the message type for this message
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Auth(_) => MessageType::Auth,
            Message::AuthResponse(_) => MessageType::AuthResponse,
            Message::OpenTunnel(_) => MessageType::OpenTunnel,
            Message::TunnelOpened(_) => MessageType::TunnelOpened,
            Message::CloseTunnel(_) => MessageType::CloseTunnel,
            Message::TunnelClosed(_) => MessageType::TunnelClosed,
            Message::TunnelStatus(_) => MessageType::TunnelStatus,
            Message::Data(_) => MessageType::Data,
            Message::DataAck(_) => MessageType::DataAck,
            Message::StreamOpen(_) => MessageType::StreamOpen,
            Message::StreamClose(_) => MessageType::StreamClose,
            Message::Ping(_) => MessageType::Ping,
            Message::Pong(_) => MessageType::Pong,
            Message::Error(_) => MessageType::Error,
            Message::Shutdown(_) => MessageType::Shutdown,
        }
    }

    /// Check if this is a control message (non-data)
    pub fn is_control(&self) -> bool {
        !matches!(self, Message::Data(_))
    }
}

// === Authentication Messages ===

/// Authentication request from agent to edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    /// Agent's unique identifier
    pub agent_id: AgentId,
    /// Authentication token (from control plane)
    pub auth_token: String,
    /// Client version string for compatibility checking
    pub client_version: String,
    /// Requested capabilities (for feature negotiation)
    pub capabilities: Vec<String>,
}

/// Authentication response from edge to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponseMessage {
    /// Whether authentication succeeded
    pub success: bool,
    /// Error message if auth failed
    pub error: Option<String>,
    /// Session ID for this connection
    pub session_id: Option<String>,
    /// Enabled capabilities (intersection of requested and supported)
    pub capabilities: Vec<String>,
    /// Server version
    pub server_version: String,
}

// === Tunnel Management Messages ===

/// Request to open a new tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTunnelMessage {
    /// Tunnel configuration
    pub config: TunnelConfig,
}

/// Tunnel opened successfully
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelOpenedMessage {
    /// Tunnel ID (may be different from requested if reassigned)
    pub tunnel_id: TunnelId,
    /// Assigned public URL
    pub public_url: String,
    /// Assigned subdomain
    pub subdomain: String,
}

/// Request to close a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseTunnelMessage {
    /// Tunnel to close
    pub tunnel_id: TunnelId,
    /// Optional reason for closing
    pub reason: Option<String>,
}

/// Tunnel closed confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClosedMessage {
    /// Closed tunnel ID
    pub tunnel_id: TunnelId,
    /// Reason for closure
    pub reason: String,
}

/// Tunnel status update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatusMessage {
    /// Status information
    pub status: TunnelStatus,
}

// === Data Transfer Messages ===

/// Data frame for tunnel traffic
///
/// This is the hot path - keep it minimal for performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFrame {
    /// Which tunnel this data belongs to
    pub tunnel_id: TunnelId,
    /// Stream ID within the tunnel (for multiplexing)
    pub stream_id: StreamId,
    /// The actual data
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// Data acknowledgment for flow control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAckMessage {
    /// Stream being acknowledged
    pub stream_id: StreamId,
    /// Number of bytes acknowledged
    pub bytes_acked: u64,
    /// Current receive window size
    pub window_size: u32,
}

/// New stream opened (incoming connection to tunnel)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamOpenMessage {
    /// Tunnel receiving the connection
    pub tunnel_id: TunnelId,
    /// New stream ID
    pub stream_id: StreamId,
    /// Source information (for logging/security)
    pub source_addr: String,
    /// Protocol-specific metadata (e.g., HTTP headers)
    pub metadata: Option<StreamMetadata>,
}

/// Protocol-specific stream metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetadata {
    /// For HTTP: the Host header
    pub host: Option<String>,
    /// For HTTP: the request path
    pub path: Option<String>,
    /// For HTTP: the request method
    pub method: Option<String>,
    /// Additional headers (limited set for security)
    pub headers: Vec<(String, String)>,
}

/// Stream closed notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCloseMessage {
    /// Stream that was closed
    pub stream_id: StreamId,
    /// Whether close was graceful
    pub graceful: bool,
    /// Error message if not graceful
    pub error: Option<String>,
}

// === Control Messages ===

/// Heartbeat ping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingMessage {
    /// Timestamp for RTT calculation
    pub timestamp: u64,
    /// Sequence number for ordering
    pub seq: u32,
}

/// Heartbeat pong
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongMessage {
    /// Echo of ping timestamp
    pub timestamp: u64,
    /// Echo of ping sequence
    pub seq: u32,
}

/// Error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Error code for programmatic handling
    pub code: ErrorCode,
    /// Human-readable message
    pub message: String,
    /// Optional context (tunnel ID, stream ID, etc.)
    pub context: Option<String>,
    /// Whether the connection should be terminated
    pub fatal: bool,
}

/// Error codes for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum ErrorCode {
    /// Unknown error
    Unknown = 0,
    /// Authentication failed
    AuthFailed = 1,
    /// Rate limit exceeded
    RateLimited = 2,
    /// Tunnel not found
    TunnelNotFound = 3,
    /// Stream not found
    StreamNotFound = 4,
    /// Protocol error
    ProtocolError = 5,
    /// Internal server error
    InternalError = 6,
    /// Service unavailable
    Unavailable = 7,
    /// Resource exhausted
    ResourceExhausted = 8,
}

/// Shutdown notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownMessage {
    /// Reason for shutdown
    pub reason: String,
    /// Grace period in seconds before forced disconnect
    pub grace_period_secs: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        let types = [
            MessageType::Auth,
            MessageType::Data,
            MessageType::Ping,
            MessageType::Error,
        ];

        for msg_type in types {
            let value = msg_type as u8;
            let parsed = MessageType::try_from(value).unwrap();
            assert_eq!(msg_type, parsed);
        }
    }

    #[test]
    fn test_invalid_message_type() {
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::Ping(PingMessage {
            timestamp: 12345,
            seq: 1,
        });

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: Message = bincode::deserialize(&encoded).unwrap();

        match decoded {
            Message::Ping(ping) => {
                assert_eq!(ping.timestamp, 12345);
                assert_eq!(ping.seq, 1);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
