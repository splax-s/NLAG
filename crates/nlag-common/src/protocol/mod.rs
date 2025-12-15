//! Wire protocol definitions for NLAG
//!
//! ## Protocol Design Principles
//!
//! 1. **Binary format**: Using bincode for efficiency and speed
//! 2. **Versioned**: All messages include protocol version for compatibility
//! 3. **Framed**: Length-prefixed messages for reliable parsing
//! 4. **Extensible**: Reserved fields and message types for future expansion
//!
//! ## Message Format
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+...
//! | Length (4 bytes, big-endian)     | Version| Type   | Payload...
//! +--------+--------+--------+--------+--------+--------+...
//! ```
//!
//! ## Security
//!
//! This protocol MUST only be used over encrypted transports (QUIC/TLS).
//! No authentication data should be present in the protocol itself - that
//! is handled at the transport layer via mTLS.

pub mod codec;
pub mod message;

pub use codec::MessageCodec;
pub use message::{Message, MessageType, ProtocolVersion};

/// Maximum message size (16 MB)
/// This is generous for most use cases while preventing memory exhaustion
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Minimum message size (header only)
pub const MIN_MESSAGE_SIZE: usize = 6; // 4 bytes length + 1 byte version + 1 byte type

/// Current protocol version
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

/// Heartbeat interval in seconds
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Connection timeout in seconds
pub const CONNECTION_TIMEOUT_SECS: u64 = 90;
