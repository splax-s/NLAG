//! Edge server configuration

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::acme::AcmeConfig;
use crate::audit::AuditConfig;
use crate::auth::AuthConfig;
use crate::grpc::GrpcConfig;
use crate::region::MultiRegionConfig;
use crate::replay::ReplayConfig;
use crate::udp::UdpConfig;

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

    /// Address for inspection UI (optional)
    #[serde(default)]
    pub inspect_listen_addr: Option<SocketAddr>,

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

    /// Request inspection configuration
    #[serde(default)]
    pub inspect: InspectConfig,

    /// Warning page configuration
    #[serde(default)]
    pub warning: WarningConfig,

    /// Load balancer configuration
    #[serde(default)]
    pub load_balancer: LoadBalancerConfigFile,

    /// ACME (Let's Encrypt) automatic TLS configuration
    #[serde(default)]
    pub acme: AcmeConfig,

    /// gRPC tunneling configuration
    #[serde(default)]
    pub grpc: GrpcConfig,

    /// UDP tunneling configuration
    #[serde(default)]
    pub udp: UdpConfig,

    /// Multi-region deployment configuration
    #[serde(default)]
    pub multi_region: MultiRegionConfig,

    /// Audit logging configuration
    #[serde(default)]
    pub audit: AuditConfig,

    /// Replay protection configuration
    #[serde(default)]
    pub replay: ReplayConfig,

    /// Unique identifier for this edge server
    #[serde(default)]
    pub edge_id: Option<String>,

    /// Region configuration for multi-region deployments
    #[serde(default)]
    pub region: Option<RegionConfig>,
}

/// Region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionConfig {
    /// Region identifier (e.g., "us-east-1")
    pub region_id: String,
    
    /// Human-readable region name
    #[serde(default)]
    pub display_name: Option<String>,
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

    /// Public port for tunnel URLs (None uses default based on scheme)
    #[serde(default)]
    pub public_port: Option<u16>,
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
            public_port: None,
        }
    }
}

impl DomainConfig {
    /// Get the public port for URLs
    /// Returns the configured port, or the default port for the scheme (80/443)
    pub fn get_public_port(&self) -> u16 {
        self.public_port.unwrap_or_else(|| {
            match self.scheme.as_str() {
                "https" => 443,
                _ => 80,
            }
        })
    }

    /// Build a public URL for a subdomain
    pub fn build_public_url(&self, subdomain: &str) -> String {
        let port = self.get_public_port();
        let default_port = match self.scheme.as_str() {
            "https" => 443,
            _ => 80,
        };

        if port == default_port {
            // Omit port if it's the default for the scheme
            format!("{}://{}.{}", self.scheme, subdomain, self.base_domain)
        } else {
            format!("{}://{}.{}:{}", self.scheme, subdomain, self.base_domain, port)
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

/// Request inspection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectConfig {
    /// Enable request inspection
    #[serde(default = "default_inspect_enabled")]
    pub enabled: bool,

    /// Maximum body size to capture (bytes)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Maximum requests to store per tunnel
    #[serde(default = "default_max_requests")]
    pub max_requests_per_tunnel: usize,
}

fn default_inspect_enabled() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_max_requests() -> usize {
    500
}

impl Default for InspectConfig {
    fn default() -> Self {
        Self {
            enabled: default_inspect_enabled(),
            max_body_size: default_max_body_size(),
            max_requests_per_tunnel: default_max_requests(),
        }
    }
}

/// Warning page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningConfig {
    /// Enable warning page for first-time browser visits
    #[serde(default = "default_warning_enabled")]
    pub enabled: bool,

    /// Custom warning title
    pub title: Option<String>,

    /// Custom warning message
    pub message: Option<String>,

    /// Hosts that bypass the warning (e.g., trusted internal domains)
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
}

fn default_warning_enabled() -> bool {
    true
}

impl Default for WarningConfig {
    fn default() -> Self {
        Self {
            enabled: default_warning_enabled(),
            title: None,
            message: None,
            bypass_hosts: Vec::new(),
        }
    }
}

/// Load balancer configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfigFile {
    /// Load balancing strategy
    #[serde(default = "default_lb_strategy")]
    pub strategy: String,

    /// Health check interval in seconds
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
}

fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

fn default_health_check_interval() -> u64 {
    30
}

impl Default for LoadBalancerConfigFile {
    fn default() -> Self {
        Self {
            strategy: default_lb_strategy(),
            health_check_interval_secs: default_health_check_interval(),
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

    /// Generate a sample configuration file
    pub fn generate_sample_config() -> String {
        r#"# NLAG Edge Server Configuration

# Address for agent QUIC connections
agent_listen_addr = "0.0.0.0:4443"

# Address for public HTTP/TCP traffic
public_listen_addr = "0.0.0.0:8080"

# Address for metrics HTTP endpoint
metrics_listen_addr = "0.0.0.0:9090"

# Address for inspection UI (optional, similar to ngrok inspect)
inspect_listen_addr = "0.0.0.0:4040"

[tls]
# Path to TLS certificate (PEM format)
cert_path = "/etc/nlag/edge.crt"

# Path to TLS private key (PEM format)
key_path = "/etc/nlag/edge.key"

[domain]
# Base domain for tunnel subdomains
base_domain = "tunnels.example.com"

# URL scheme (http or https)
scheme = "https"

[rate_limit]
# Maximum requests per second per tunnel
requests_per_second = 1000

# Burst capacity for rate limiting
burst_size = 100

# Maximum concurrent connections per tunnel
max_connections_per_tunnel = 100

[auth]
# Enable authentication (disable for development)
enabled = false

# JWT algorithm: HS256 or RS256
# algorithm = "HS256"

# JWT secret for HS256 (base64 encoded)
# jwt_secret = "base64-encoded-secret"

# JWT public key path for RS256
# jwt_public_key = "/etc/nlag/jwt-public.pem"

[inspect]
# Enable request inspection
enabled = true

# Maximum body size to capture (bytes)
max_body_size = 1048576

# Maximum requests to store per tunnel
max_requests_per_tunnel = 500

[warning]
# Show warning page for first-time browser visits
enabled = true

# Custom warning page title
# title = "Security Warning"

# Custom warning message
# message = "You are about to visit a tunnel..."

# Hosts that bypass the warning page
bypass_hosts = []

[load_balancer]
# Load balancing strategy: round_robin, least_connections, random
strategy = "round_robin"

# Health check interval in seconds
health_check_interval_secs = 30

[acme]
# Enable automatic TLS via Let's Encrypt
enabled = false

# ACME directory URL (use staging for testing)
# directory_url = "https://acme-v02.api.letsencrypt.org/directory"

# Account email for Let's Encrypt notifications
email = "admin@example.com"

# Storage path for certificates and account keys
storage_path = "/var/lib/nlag/acme"

# Challenge type: http-01, tls-alpn-01, or dns-01
challenge_type = "http-01"

# Accept Let's Encrypt Terms of Service
accept_tos = false

# Renew certificates if expiring within this many days
renewal_days = 30

# Use Let's Encrypt staging environment for testing
staging = true

[grpc]
# Enable gRPC tunneling support
enabled = true

# Maximum message size in bytes (default 4MB)
max_message_size = 4194304

# Enable message compression
compression_enabled = true

# Default timeout in seconds
default_timeout_secs = 300

# Enable gRPC reflection service
reflection_enabled = false

[udp]
# Enable UDP tunneling (disabled by default)
enabled = false

# UDP listen address
listen_addr = "0.0.0.0:4444"

# Maximum packet size in bytes
max_packet_size = 65535

# Session timeout in seconds
session_timeout_secs = 300

# Maximum concurrent sessions
max_sessions = 10000

# Buffer size per session (bytes)
buffer_size = 1048576

[multi_region]
# Enable multi-region edge deployment
enabled = false

# This edge's region ID
region = "us-east-1"

# Discovery service URL for finding other edges
# discovery_url = "https://control.example.com/api/discovery"

# Health check interval in seconds
health_check_interval_secs = 30

# Routing strategy: round_robin, least_connections, lowest_latency, weighted_random
routing_strategy = "least_connections"

# Enable cross-region failover
enable_failover = true

[audit]
# Enable audit logging
enabled = true

# Minimum severity to log: debug, info, notice, warning, error, critical
min_severity = "info"

# Audit log file path
# log_path = "/var/log/nlag/audit.log"

# Buffer size for async logging
buffer_size = 10000

# Include sensitive data (IPs, user agents)
include_sensitive = false

# HTTP endpoint for log shipping (e.g., Elasticsearch)
# http_endpoint = "https://logs.example.com/api/audit"

# HTTP authorization header
# http_auth_header = "Bearer your-token"

[replay]
# Enable replay protection
enabled = false

# Time window for nonce validity (seconds)
window_secs = 300

# Maximum clock skew allowed (seconds)
max_clock_skew_secs = 60

# Maximum number of nonces to track
max_nonces = 1000000

# Require HMAC signature
require_signature = false

# HMAC secret (base64 encoded)
# hmac_secret = "your-base64-secret"

# Header name for nonce
nonce_header = "X-Nonce"

# Header name for timestamp
timestamp_header = "X-Timestamp"

# Header name for signature
signature_header = "X-Signature"
"#.to_string()
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
            inspect_listen_addr: Some("0.0.0.0:4040".parse().unwrap()),
            tls: TlsConfig {
                cert_path: cert_path.to_string_lossy().to_string(),
                key_path: key_path.to_string_lossy().to_string(),
            },
            domain: DomainConfig::default(),
            rate_limit: RateLimitConfig::default(),
            auth: AuthConfig::default(), // Disabled in dev mode
            inspect: InspectConfig::default(),
            warning: WarningConfig::default(),
            load_balancer: LoadBalancerConfigFile::default(),
            acme: AcmeConfig::default(),
            grpc: GrpcConfig::default(),
            udp: UdpConfig::default(),
            multi_region: MultiRegionConfig::default(),
            audit: AuditConfig::default(),
            replay: ReplayConfig::default(),
            edge_id: None,
            region: None,
        })
    }
}
