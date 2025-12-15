//! Agent configuration management
//!
//! Configuration is loaded from:
//! 1. Default values
//! 2. Config file (~/.nlag/config.toml)
//! 3. Environment variables (NLAG_*)
//! 4. Command line arguments (highest priority)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nlag_common::Protocol;

/// Main agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Edge server address
    #[serde(default = "default_edge_addr")]
    pub edge_addr: String,

    /// Authentication token (from NLAG control plane)
    pub auth_token: Option<String>,

    /// TLS configuration
    #[serde(default)]
    pub tls: TlsSettings,

    /// Connection settings
    #[serde(default)]
    pub connection: ConnectionSettings,
}

fn default_edge_addr() -> String {
    "localhost:4443".to_string()
}

/// TLS-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Skip TLS verification (DANGEROUS - dev only)
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// Path to CA certificate
    pub ca_cert: Option<String>,

    /// Path to client certificate (for mTLS)
    pub client_cert: Option<String>,

    /// Path to client key
    pub client_key: Option<String>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            insecure_skip_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        }
    }
}

/// Connection behavior settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSettings {
    /// Initial reconnect delay in milliseconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_ms: u64,

    /// Maximum reconnect delay in milliseconds
    #[serde(default = "default_max_reconnect_delay")]
    pub max_reconnect_delay_ms: u64,

    /// Maximum reconnect attempts (0 = infinite)
    #[serde(default = "default_max_attempts")]
    pub max_reconnect_attempts: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

fn default_reconnect_delay() -> u64 {
    1000
}

fn default_max_reconnect_delay() -> u64 {
    30000
}

fn default_max_attempts() -> u32 {
    0 // Infinite
}

fn default_connect_timeout() -> u64 {
    30
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            reconnect_delay_ms: default_reconnect_delay(),
            max_reconnect_delay_ms: default_max_reconnect_delay(),
            max_reconnect_attempts: default_max_attempts(),
            connect_timeout_secs: default_connect_timeout(),
        }
    }
}

impl AgentConfig {
    /// Load configuration from file and environment
    pub fn load() -> Result<Self, anyhow::Error> {
        let config_path = Self::config_path()?;

        let mut builder = config::Config::builder()
            // Set defaults
            .set_default("edge_addr", default_edge_addr())?
            .set_default("tls.insecure_skip_verify", false)?
            .set_default("connection.reconnect_delay_ms", default_reconnect_delay() as i64)?
            .set_default("connection.max_reconnect_delay_ms", default_max_reconnect_delay() as i64)?
            .set_default("connection.max_reconnect_attempts", default_max_attempts() as i64)?
            .set_default("connection.connect_timeout_secs", default_connect_timeout() as i64)?;

        // Load from config file if it exists
        if config_path.exists() {
            builder = builder.add_source(config::File::from(config_path).required(false));
        }

        // Load from environment
        builder = builder.add_source(
            config::Environment::with_prefix("NLAG")
                .separator("__")
                .try_parsing(true),
        );

        let config: AgentConfig = builder.build()?.try_deserialize()?;

        Ok(config)
    }

    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf, anyhow::Error> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("nlag");

        Ok(config_dir.join("config.toml"))
    }

    /// Create default configuration file
    #[allow(dead_code)] // Reserved for init command
    pub fn create_default_config() -> Result<PathBuf, anyhow::Error> {
        let path = Self::config_path()?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let default_config = r#"# NLAG Agent Configuration

# Edge server address
edge_addr = "localhost:4443"

# Authentication token (obtain from control plane)
# auth_token = "your-token-here"

[tls]
# Skip TLS verification (DANGEROUS - development only!)
insecure_skip_verify = true

# Custom CA certificate
# ca_cert = "/path/to/ca.pem"

# Client certificate for mTLS
# client_cert = "/path/to/client.pem"
# client_key = "/path/to/client-key.pem"

[connection]
# Initial reconnect delay (milliseconds)
reconnect_delay_ms = 1000

# Maximum reconnect delay (milliseconds)
max_reconnect_delay_ms = 30000

# Maximum reconnect attempts (0 = infinite)
max_reconnect_attempts = 0

# Connection timeout (seconds)
connect_timeout_secs = 30
"#;

        std::fs::write(&path, default_config)?;
        Ok(path)
    }
}

/// Options for a specific tunnel
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    pub protocol: Protocol,
    pub local_port: u16,
    pub local_host: String,
    pub subdomain: Option<String>,
}

impl TunnelOptions {
    /// Build a TunnelConfig from options
    pub fn to_tunnel_config(&self) -> nlag_common::types::TunnelConfig {
        let mut config = nlag_common::types::TunnelConfig::new(self.protocol, self.local_port);
        config = config.with_local_host(&self.local_host);
        if let Some(ref subdomain) = self.subdomain {
            config = config.with_subdomain(subdomain);
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::load().unwrap_or_else(|_| AgentConfig {
            edge_addr: default_edge_addr(),
            auth_token: None,
            tls: TlsSettings::default(),
            connection: ConnectionSettings::default(),
        });

        assert!(!config.edge_addr.is_empty());
    }

    #[test]
    fn test_tunnel_options() {
        let opts = TunnelOptions {
            protocol: Protocol::Http,
            local_port: 8080,
            local_host: "localhost".to_string(),
            subdomain: Some("test".to_string()),
        };

        let config = opts.to_tunnel_config();
        assert_eq!(config.local_port, 8080);
        assert_eq!(config.subdomain, Some("test".to_string()));
    }
}
