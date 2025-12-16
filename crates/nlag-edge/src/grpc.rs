//! gRPC Tunneling Support
//!
//! This module provides support for tunneling gRPC traffic through the edge server.
//! gRPC uses HTTP/2, so we need to handle HTTP/2 protocol specifics.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// gRPC specific errors
#[derive(Debug, Error)]
pub enum GrpcError {
    #[error("Invalid gRPC request: {0}")]
    InvalidRequest(String),
    
    #[error("gRPC timeout")]
    Timeout,
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type Result<T> = std::result::Result<T, GrpcError>;

/// gRPC status codes (matching google.rpc.Code)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Get HTTP status code for gRPC status
    pub fn http_status(&self) -> StatusCode {
        match self {
            GrpcStatus::Ok => StatusCode::OK,
            GrpcStatus::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
            GrpcStatus::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::InvalidArgument => StatusCode::BAD_REQUEST,
            GrpcStatus::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            GrpcStatus::NotFound => StatusCode::NOT_FOUND,
            GrpcStatus::AlreadyExists => StatusCode::CONFLICT,
            GrpcStatus::PermissionDenied => StatusCode::FORBIDDEN,
            GrpcStatus::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            GrpcStatus::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            GrpcStatus::Aborted => StatusCode::CONFLICT,
            GrpcStatus::OutOfRange => StatusCode::BAD_REQUEST,
            GrpcStatus::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            GrpcStatus::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            GrpcStatus::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::Unauthenticated => StatusCode::UNAUTHORIZED,
        }
    }
    
    /// Create from integer
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => GrpcStatus::Ok,
            1 => GrpcStatus::Cancelled,
            2 => GrpcStatus::Unknown,
            3 => GrpcStatus::InvalidArgument,
            4 => GrpcStatus::DeadlineExceeded,
            5 => GrpcStatus::NotFound,
            6 => GrpcStatus::AlreadyExists,
            7 => GrpcStatus::PermissionDenied,
            8 => GrpcStatus::ResourceExhausted,
            9 => GrpcStatus::FailedPrecondition,
            10 => GrpcStatus::Aborted,
            11 => GrpcStatus::OutOfRange,
            12 => GrpcStatus::Unimplemented,
            13 => GrpcStatus::Internal,
            14 => GrpcStatus::Unavailable,
            15 => GrpcStatus::DataLoss,
            16 => GrpcStatus::Unauthenticated,
            _ => GrpcStatus::Unknown,
        }
    }
}

/// gRPC message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcMessageType {
    /// Unary RPC - single request, single response
    Unary,
    /// Server streaming - single request, stream of responses
    ServerStreaming,
    /// Client streaming - stream of requests, single response
    ClientStreaming,
    /// Bidirectional streaming - stream of requests, stream of responses
    BidirectionalStreaming,
}

/// gRPC request metadata
#[derive(Debug, Clone)]
pub struct GrpcMetadata {
    /// Service name (e.g., "helloworld.Greeter")
    pub service: String,
    /// Method name (e.g., "SayHello")
    pub method: String,
    /// Content type (usually "application/grpc")
    pub content_type: String,
    /// Custom metadata headers
    pub metadata: HeaderMap,
    /// Timeout if specified
    pub timeout: Option<std::time::Duration>,
    /// Message type
    pub message_type: GrpcMessageType,
}

impl GrpcMetadata {
    /// Parse gRPC metadata from an HTTP/2 request
    pub fn from_request<B>(request: &Request<B>) -> Result<Self> {
        // gRPC uses POST method
        if request.method() != http::Method::POST {
            return Err(GrpcError::InvalidRequest(
                "gRPC requires POST method".to_string()
            ));
        }
        
        // Check content-type
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        if !content_type.starts_with("application/grpc") {
            return Err(GrpcError::InvalidRequest(format!(
                "Invalid content-type: {}, expected application/grpc*",
                content_type
            )));
        }
        
        // Parse path to get service and method
        // gRPC path format: /package.Service/Method
        let path = request.uri().path();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        
        if parts.len() != 2 {
            return Err(GrpcError::InvalidRequest(format!(
                "Invalid gRPC path: {}, expected /Service/Method",
                path
            )));
        }
        
        let service = parts[0].to_string();
        let method = parts[1].to_string();
        
        // Parse timeout from grpc-timeout header
        let timeout = request
            .headers()
            .get("grpc-timeout")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_grpc_timeout);
        
        // Clone metadata headers (exclude standard headers)
        let mut metadata = HeaderMap::new();
        for (key, value) in request.headers() {
            if key.as_str().starts_with("grpc-") 
                || key == http::header::CONTENT_TYPE
                || key == http::header::TE
                || key == http::header::HOST
            {
                continue;
            }
            metadata.insert(key.clone(), value.clone());
        }
        
        Ok(GrpcMetadata {
            service,
            method,
            content_type: content_type.to_string(),
            metadata,
            timeout,
            message_type: GrpcMessageType::Unary, // Default, may be updated based on streaming
        })
    }
}

/// Parse gRPC timeout header
/// Format: value + unit (n=nanos, u=micros, m=millis, S=seconds, M=minutes, H=hours)
fn parse_grpc_timeout(value: &str) -> Option<std::time::Duration> {
    if value.is_empty() {
        return None;
    }
    
    let (num_str, unit) = value.split_at(value.len() - 1);
    let num: u64 = num_str.parse().ok()?;
    
    match unit {
        "n" => Some(std::time::Duration::from_nanos(num)),
        "u" => Some(std::time::Duration::from_micros(num)),
        "m" => Some(std::time::Duration::from_millis(num)),
        "S" => Some(std::time::Duration::from_secs(num)),
        "M" => Some(std::time::Duration::from_secs(num * 60)),
        "H" => Some(std::time::Duration::from_secs(num * 3600)),
        _ => None,
    }
}

/// gRPC request handler
pub struct GrpcHandler {
    /// Maximum message size in bytes
    max_message_size: usize,
    /// Enable message compression
    compression_enabled: bool,
}

impl Default for GrpcHandler {
    fn default() -> Self {
        Self {
            max_message_size: 4 * 1024 * 1024, // 4MB default
            compression_enabled: true,
        }
    }
}

impl GrpcHandler {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }
    
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }
    
    /// Check if a request is a gRPC request
    pub fn is_grpc_request<B>(request: &Request<B>) -> bool {
        request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("application/grpc"))
            .unwrap_or(false)
    }
    
    /// Check if connection supports HTTP/2 (required for gRPC)
    pub fn is_http2<B>(request: &Request<B>) -> bool {
        request.version() == http::Version::HTTP_2
    }
    
    /// Create a gRPC error response
    pub fn error_response(status: GrpcStatus, message: &str) -> Response<Full<Bytes>> {
        let mut response = Response::builder()
            .status(status.http_status())
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("grpc-status", (status as u8).to_string())
            .header("grpc-message", message)
            .body(Full::new(Bytes::new()))
            .unwrap();
        
        response
    }
    
    /// Create gRPC trailers
    pub fn create_trailers(status: GrpcStatus, message: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "grpc-status",
            HeaderValue::from_str(&(status as u8).to_string()).unwrap(),
        );
        if let Some(msg) = message {
            if let Ok(value) = HeaderValue::from_str(msg) {
                headers.insert("grpc-message", value);
            }
        }
        headers
    }
    
    /// Decode a gRPC message frame
    /// Format: [compressed:1][length:4][message:length]
    pub fn decode_frame(data: &[u8]) -> Result<(bool, &[u8])> {
        if data.len() < 5 {
            return Err(GrpcError::InvalidRequest("Frame too short".to_string()));
        }
        
        let compressed = data[0] != 0;
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        
        if data.len() < 5 + length {
            return Err(GrpcError::InvalidRequest(format!(
                "Frame incomplete: expected {} bytes, got {}",
                length,
                data.len() - 5
            )));
        }
        
        Ok((compressed, &data[5..5 + length]))
    }
    
    /// Encode a gRPC message frame
    pub fn encode_frame(message: &[u8], compressed: bool) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + message.len());
        frame.push(if compressed { 1 } else { 0 });
        frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
        frame.extend_from_slice(message);
        frame
    }
}

/// gRPC configuration for the edge server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Enable gRPC tunneling support
    #[serde(default = "default_grpc_enabled")]
    pub enabled: bool,
    
    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    
    /// Enable message compression
    #[serde(default = "default_compression")]
    pub compression_enabled: bool,
    
    /// Default timeout in seconds
    #[serde(default = "default_timeout")]
    pub default_timeout_secs: u64,
    
    /// Enable reflection service
    #[serde(default)]
    pub reflection_enabled: bool,
}

fn default_grpc_enabled() -> bool {
    true
}

fn default_max_message_size() -> usize {
    4 * 1024 * 1024 // 4MB
}

fn default_compression() -> bool {
    true
}

fn default_timeout() -> u64 {
    300 // 5 minutes
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: default_grpc_enabled(),
            max_message_size: default_max_message_size(),
            compression_enabled: default_compression(),
            default_timeout_secs: default_timeout(),
            reflection_enabled: false,
        }
    }
}

/// gRPC-specific metrics
#[derive(Debug, Default)]
pub struct GrpcMetrics {
    /// Total gRPC requests
    pub requests_total: u64,
    /// Unary requests
    pub unary_requests: u64,
    /// Streaming requests
    pub streaming_requests: u64,
    /// Failed requests by status
    pub failed_by_status: std::collections::HashMap<u8, u64>,
    /// Average message size
    pub avg_message_size: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_grpc_timeout() {
        assert_eq!(
            parse_grpc_timeout("100m"),
            Some(std::time::Duration::from_millis(100))
        );
        assert_eq!(
            parse_grpc_timeout("5S"),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(
            parse_grpc_timeout("1M"),
            Some(std::time::Duration::from_secs(60))
        );
        assert_eq!(
            parse_grpc_timeout("1H"),
            Some(std::time::Duration::from_secs(3600))
        );
    }
    
    #[test]
    fn test_encode_decode_frame() {
        let message = b"Hello, gRPC!";
        let frame = GrpcHandler::encode_frame(message, false);
        
        let (compressed, decoded) = GrpcHandler::decode_frame(&frame).unwrap();
        assert!(!compressed);
        assert_eq!(decoded, message);
    }
    
    #[test]
    fn test_grpc_status_codes() {
        assert_eq!(GrpcStatus::Ok.http_status(), StatusCode::OK);
        assert_eq!(GrpcStatus::NotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(GrpcStatus::Internal.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
