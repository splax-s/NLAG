//! # nlag-common
//!
//! Shared components for the NLAG secure tunneling platform.
//!
//! This crate contains:
//! - Wire protocol definitions and codec
//! - TLS/crypto utilities
//! - Shared types and error definitions
//! - Transport abstractions
//!
//! ## Architecture
//!
//! The common crate is designed to be minimal and stable. All protocol changes
//! should be backward-compatible to support rolling upgrades in production.

pub mod crypto;
pub mod error;
pub mod protocol;
pub mod transport;
pub mod types;

// Re-export commonly used items at crate root
pub use error::{NlagError, Result};
pub use protocol::{Message, MessageType, ProtocolVersion};
pub use types::{AgentId, TunnelId, TunnelConfig, Protocol};
