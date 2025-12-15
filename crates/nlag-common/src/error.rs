//! Error types for NLAG
//!
//! We use `thiserror` for structured error types that can be matched on,
//! and `anyhow` for error propagation in application code.

use thiserror::Error;

/// Central error type for NLAG operations
#[derive(Error, Debug)]
pub enum NlagError {
    // === Protocol Errors ===
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    ProtocolVersionMismatch { expected: u8, actual: u8 },

    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Malformed message: {0}")]
    MalformedMessage(String),

    #[error("Unexpected message: expected {expected}, got {actual}")]
    UnexpectedMessage { expected: String, actual: String },

    // === Authentication Errors ===
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid credentials")]
    InvalidCredentials,

    // === Transport Errors ===
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("QUIC transport error: {0}")]
    QuicError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    // === Tunnel Errors ===
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),

    #[error("Tunnel already exists: {0}")]
    TunnelAlreadyExists(String),

    #[error("Maximum tunnels exceeded")]
    MaxTunnelsExceeded,

    #[error("Local service unavailable: {0}")]
    LocalServiceUnavailable(String),

    // === Rate Limiting ===
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    // === I/O Errors ===
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // === Serialization ===
    #[error("Serialization error: {0}")]
    Serialization(String),

    // === Configuration ===
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // === Internal ===
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias using NlagError
pub type Result<T> = std::result::Result<T, NlagError>;

// Conversion from bincode errors
impl From<bincode::Error> for NlagError {
    fn from(err: bincode::Error) -> Self {
        NlagError::Serialization(err.to_string())
    }
}

// Conversion from quinn errors
impl From<quinn::ConnectionError> for NlagError {
    fn from(err: quinn::ConnectionError) -> Self {
        NlagError::QuicError(err.to_string())
    }
}

impl From<quinn::ConnectError> for NlagError {
    fn from(err: quinn::ConnectError) -> Self {
        NlagError::ConnectionFailed(err.to_string())
    }
}

impl From<quinn::WriteError> for NlagError {
    fn from(err: quinn::WriteError) -> Self {
        NlagError::QuicError(format!("Write error: {}", err))
    }
}

impl From<quinn::ReadExactError> for NlagError {
    fn from(err: quinn::ReadExactError) -> Self {
        NlagError::QuicError(format!("Read error: {}", err))
    }
}

impl From<rustls::Error> for NlagError {
    fn from(err: rustls::Error) -> Self {
        NlagError::TlsError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NlagError::ProtocolVersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let nlag_err: NlagError = io_err.into();
        assert!(matches!(nlag_err, NlagError::Io(_)));
    }
}
