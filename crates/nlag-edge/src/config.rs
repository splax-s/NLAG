//! Edge server configuration

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::auth::AuthConfig;

/// Edge server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Address for agent QUIC connections
    #[serde(default = "default_agent_addr")]
    pub agent_listen_addr: SocketAddr,

    /// Address for public HTTP/TCP traffic
    #[serde(default = "default_public_addr")]
    pub public_listen_addr: SocketAddr,

    /// Address for metrics HTTP endpoint
    #[serde(default = "default_metrics_addr")]
    pub metrics_listen_addr: SocketAddr,

    /// TLS certificate configuration
    pub tls: TlsConfig,

    /// Domain configuration
    #[serde(default)]
    pub domain: DomainConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,
}

fn default_agent_addr() -> SocketAddr {
    "0.0.0.0:4443".parse().unwrap()
}

fn default_public_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}

fn default_metrics_addr() -> SocketAddr {
    "0.0.0.0:9090".parse().unwrap()
}

/// TLS certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate PEM file
    pub cert_path: String,

    /// Path to private key PEM file
    pub key_path: String,
}

/// Domain configuration for tunnel URLs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Base domain for tunnels (e.g., "tunnels.example.com")
    #[serde(default = "default_base_domain")]
    pub base_domain: String,

    /// URL scheme (http or https)
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_base_domain() -> String {
    "localhost".to_string()
}

fn default_scheme() -> String {
    "http".to_string()
}

impl Default for DomainConfig {
    fn default() -> Self {
        Self {
            base_domain: default_base_domain(),
            scheme: default_scheme(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per second per tunnel
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst capacity
    #[serde(default = "default_burst")]
    pub burst_size: u32,

    /// Maximum concurrent connections per tunnel
    #[serde(default = "default_max_connections")]
    pub max_connections_per_tunnel: u32,
}

fn default_requests_per_second() -> u32 {
    1000
}

fn default_burst() -> u32 {
    100
}

fn default_max_connections() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst(),
            max_connections_per_tunnel: default_max_connections(),
        }
    }
}

impl EdgeConfig {
    /// Load configuration from file
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        // Try to load from file if it exists
        if path.exists() {
            let builder = config::Config::builder()
                .add_source(config::File::from(path))
                .add_source(
                    config::Environment::with_prefix("NLAG_EDGE")
                        .separator("__")
                        .try_parsing(true),
                );

            let config: EdgeConfig = builder.build()?.try_deserialize()?;
            return Ok(config);
        }

        // Generate development config if no file exists
        tracing::warn!(
            "Configuration file not found at {:?}, using development defaults",
            path
        );

        Self::development_config()
    }

    /// Create a development configuration with self-signed certs
    pub fn development_config() -> anyhow::Result<Self> {
        use nlag_common::crypto::cert::generate_self_signed_cert;

        // Generate self-signed certificate
        let cert_info = generate_self_signed_cert(
            "nlag-edge.local",
            &["localhost".to_string()],
            &[
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            30, // 30 days
            false,
        )?;

        // Write to temp directory
        let temp_dir = std::env::temp_dir().join("nlag-dev");
        std::fs::create_dir_all(&temp_dir)?;

        let cert_path = temp_dir.join("edge.crt");
        let key_path = temp_dir.join("edge.key");

        std::fs::write(&cert_path, &cert_info.cert_pem)?;
        std::fs::write(&key_path, &cert_info.key_pem)?;

        tracing::info!("Generated development certificates in {:?}", temp_dir);

        Ok(Self {
            agent_listen_addr: default_agent_addr(),
            public_listen_addr: default_public_addr(),
            metrics_listen_addr: default_metrics_addr(),
            tls: TlsConfig {
                cert_path: cert_path.to_string_lossy().to_string(),
                key_path: key_path.to_string_lossy().to_string(),
            },
            domain: DomainConfig::default(),
            rate_limit: RateLimitConfig::default(),
            auth: AuthConfig::default(), // Disabled in dev mode
        })
    }
}
