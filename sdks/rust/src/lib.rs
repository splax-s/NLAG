//! NLAG Rust SDK - Expose local services through secure tunnels
//!
//! This SDK provides a programmatic interface to the NLAG tunneling platform,
//! allowing you to create and manage tunnels from Rust applications.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use nlag_sdk::{Client, TunnelConfig, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = Client::new().await?;
//!     
//!     let tunnel = client.expose(TunnelConfig {
//!         protocol: Protocol::Http,
//!         local_port: 8080,
//!         subdomain: Some("myapp".to_string()),
//!         ..Default::default()
//!     }).await?;
//!     
//!     println!("Tunnel URL: {}", tunnel.public_url());
//!     tunnel.wait().await?;
//!     
//!     Ok(())
//! }
//! ```

mod auth;
mod client;
mod error;
mod tunnel;

pub use auth::{
    authenticate, authenticate_with_token, delete_credentials, load_credentials, logout,
    refresh_token, save_credentials, Credentials,
};
pub use client::{Client, ClientConfig};
pub use error::{Error, Result};
pub use tunnel::{Protocol, Tunnel, TunnelConfig, TunnelInfo, TunnelMetrics, TunnelState};
