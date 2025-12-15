//! Cryptographic utilities for NLAG
//!
//! This module provides:
//! - TLS configuration for client and server
//! - Certificate generation for development
//! - Certificate validation utilities
//!
//! ## Security Design
//!
//! - TLS 1.3 only (no downgrade)
//! - Strong cipher suites only
//! - Certificate pinning support
//! - Short-lived certificates recommended

pub mod cert;
pub mod tls;

pub use cert::{generate_self_signed_cert, CertificateInfo};
pub use tls::{create_client_config, create_server_config, TlsConfig};
