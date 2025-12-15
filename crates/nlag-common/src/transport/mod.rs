//! Transport abstractions for NLAG
//!
//! This module provides transport-agnostic abstractions for the NLAG protocol,
//! allowing the same code to work over QUIC or TCP+TLS.

pub mod quic;

pub use quic::{QuicClient, QuicServer};
