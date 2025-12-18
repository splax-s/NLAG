//! Error types for NLAG SDK.

use thiserror::Error;

/// Result type for NLAG SDK operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using the NLAG SDK.
#[derive(Error, Debug)]
pub enum Error {
    /// Authentication failed.
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Connection to edge server failed.
    #[error("Connection failed: {0}")]
    Connection(String),

    /// Tunnel operation failed.
    #[error("Tunnel error: {0}")]
    Tunnel(String),

    /// Invalid configuration.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded, retry after {retry_after:?} seconds")]
    RateLimit { retry_after: Option<u64> },

    /// Quota exceeded.
    #[error("Quota exceeded for {quota_type}: {current}/{limit}")]
    QuotaExceeded {
        quota_type: String,
        limit: u64,
        current: u64,
    },

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error from serde_json.
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// JSON parsing/decoding error (generic).
    #[error("JSON error: {0}")]
    Json(String),

    /// QUIC connection error.
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),

    /// HTTP client error.
    #[cfg(feature = "control-api")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl Error {
    /// Create an authentication error.
    pub fn auth(msg: impl Into<String>) -> Self {
        Error::Authentication(msg.into())
    }

    /// Create a connection error.
    pub fn connection(msg: impl Into<String>) -> Self {
        Error::Connection(msg.into())
    }

    /// Create a tunnel error.
    pub fn tunnel(msg: impl Into<String>) -> Self {
        Error::Tunnel(msg.into())
    }

    /// Create a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Configuration(msg.into())
    }
}
