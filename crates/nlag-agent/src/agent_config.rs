//! Agent Configuration Module
//!
//! Start multiple tunnels from a YAML/TOML configuration file:
//! - Multi-tunnel support
//! - Labeled endpoints
//! - Environment variable interpolation
//! - Tunnel groups

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Tunnel protocol type
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    /// HTTP tunnel
    #[default]
    Http,
    /// HTTPS tunnel
    Https,
    /// TCP tunnel
    Tcp,
    /// UDP tunnel
    Udp,
    /// TLS passthrough
    Tls,
}

/// Authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Auth token
    pub token: Option<String>,
    /// API key
    pub api_key: Option<String>,
    /// OAuth client ID
    pub oauth_client_id: Option<String>,
    /// OAuth client secret
    pub oauth_client_secret: Option<String>,
}

/// Basic auth credentials for a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelBasicAuth {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

/// IP restriction configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpRestriction {
    /// Allowed IPs/CIDRs
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied IPs/CIDRs
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Header modification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderMod {
    /// Add/set headers
    #[serde(default)]
    pub add: HashMap<String, String>,
    /// Remove headers
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Webhook configuration for tunnel events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelWebhook {
    /// Webhook URL
    pub url: String,
    /// Secret for signing
    pub secret: Option<String>,
    /// Event types to send
    #[serde(default)]
    pub events: Vec<String>,
}

/// Single tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel name/label
    pub name: Option<String>,
    /// Local address to forward to
    pub addr: String,
    /// Protocol
    #[serde(default)]
    pub proto: TunnelProtocol,
    /// Custom subdomain (if reserved)
    pub subdomain: Option<String>,
    /// Custom domain
    pub domain: Option<String>,
    /// Hostname override for requests
    pub host_header: Option<String>,
    /// Basic auth credentials
    pub basic_auth: Option<TunnelBasicAuth>,
    /// OAuth protection
    pub oauth: Option<OAuthConfig>,
    /// IP restrictions
    #[serde(default)]
    pub ip_restriction: IpRestriction,
    /// Request headers
    #[serde(default)]
    pub request_headers: HeaderMod,
    /// Response headers
    #[serde(default)]
    pub response_headers: HeaderMod,
    /// Webhook for tunnel events
    pub webhook: Option<TunnelWebhook>,
    /// Circuit breaker config
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// Metadata tags
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Enable request inspection
    #[serde(default)]
    pub inspect: bool,
    /// Enable traffic logging
    #[serde(default)]
    pub log_traffic: bool,
}

/// OAuth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// OAuth provider (google, github, etc.)
    pub provider: String,
    /// Allowed email domains
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Allowed emails
    #[serde(default)]
    pub allowed_emails: Vec<String>,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Error threshold percentage
    pub error_threshold: Option<f64>,
    /// Consecutive failures to open
    pub failure_count: Option<u32>,
    /// Timeout before half-open in seconds
    pub timeout_secs: Option<u64>,
}

/// Simplified tunnel config for starting tunnels
#[derive(Debug, Clone)]
pub struct SimpleTunnelConfig {
    /// Tunnel name
    pub name: Option<String>,
    /// Local host
    pub local_host: Option<String>,
    /// Local port
    pub local_port: u16,
    /// Protocol (http, https, tcp, etc.)
    pub protocol: Option<String>,
    /// Subdomain
    pub subdomain: Option<String>,
    /// Custom domain
    pub domain: Option<String>,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// API version
    #[serde(default = "default_version")]
    pub version: String,
    /// Auth configuration
    #[serde(default)]
    pub auth: AuthConfig,
    /// Control plane URL
    pub control_url: Option<String>,
    /// Edge server URL
    pub edge_url: Option<String>,
    /// Region preference
    pub region: Option<String>,
    /// Log level
    pub log_level: Option<String>,
    /// Tunnels to start
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
    /// Named tunnel groups
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    /// Global request headers (applied to all tunnels)
    #[serde(default)]
    pub global_request_headers: HeaderMod,
    /// Global response headers (applied to all tunnels)
    #[serde(default)]
    pub global_response_headers: HeaderMod,
    /// Global metadata (merged with tunnel metadata)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_version() -> String {
    "1".to_string()
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            name: None,
            addr: "127.0.0.1:8080".to_string(),
            proto: TunnelProtocol::Http,
            subdomain: None,
            domain: None,
            host_header: None,
            basic_auth: None,
            oauth: None,
            ip_restriction: IpRestriction::default(),
            request_headers: HeaderMod { add: HashMap::new(), remove: Vec::new() },
            response_headers: HeaderMod { add: HashMap::new(), remove: Vec::new() },
            webhook: None,
            circuit_breaker: None,
            metadata: HashMap::new(),
            inspect: false,
            log_traffic: false,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            auth: AuthConfig::default(),
            control_url: None,
            edge_url: None,
            region: None,
            log_level: None,
            tunnels: Vec::new(),
            groups: HashMap::new(),
            global_request_headers: HeaderMod { add: HashMap::new(), remove: Vec::new() },
            global_response_headers: HeaderMod { add: HashMap::new(), remove: Vec::new() },
            metadata: HashMap::new(),
        }
    }
}

impl AgentConfig {
    /// Load configuration from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_yaml(&content)
    }

    /// Load configuration from YAML string
    pub fn from_yaml(content: &str) -> Result<Self, ConfigError> {
        let interpolated = Self::interpolate_env(content);
        serde_yaml::from_str(&interpolated)
            .map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load configuration from a TOML file
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&content)
    }

    /// Load configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let interpolated = Self::interpolate_env(content);
        toml::from_str(&interpolated)
            .map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load from file (auto-detect format)
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext.to_lowercase().as_str() {
            "yaml" | "yml" => Self::from_yaml_file(path),
            "toml" => Self::from_toml_file(path),
            _ => Err(ConfigError::UnsupportedFormat(ext.to_string())),
        }
    }

    /// Load configuration from path (alias for from_file for compatibility)
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_file(path)
    }

    /// Get default config file path
    pub fn default_config_path() -> Result<std::path::PathBuf, ConfigError> {
        // Try current directory first
        let current_dir = std::env::current_dir()
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        
        for filename in ["nlag.yaml", "nlag.yml", "nlag.toml", ".nlag.yaml", ".nlag.yml", ".nlag.toml"] {
            let path = current_dir.join(filename);
            if path.exists() {
                return Ok(path);
            }
        }
        
        // Try home directory
        if let Some(home) = dirs::home_dir() {
            let config_dir = home.join(".config").join("nlag");
            for filename in ["config.yaml", "config.yml", "config.toml"] {
                let path = config_dir.join(filename);
                if path.exists() {
                    return Ok(path);
                }
            }
        }
        
        // Default to nlag.yaml in current directory
        Ok(current_dir.join("nlag.yaml"))
    }

    /// Generate example configuration
    pub fn example_config(format: &str) -> String {
        if format == "toml" {
            r#"# NLAG Agent Configuration
version = "1"

# Authentication
[auth]
# token = "${NLAG_TOKEN}"
# api_key = "your-api-key"

# Edge server (optional, uses default if not set)
# edge_url = "wss://edge.nlag.dev"

# Global request headers (applied to all tunnels)
[global_request_headers.add]
X-Forwarded-Proto = "https"

# Tunnel definitions
[[tunnels]]
name = "web"
addr = "127.0.0.1:8080"
proto = "http"
subdomain = "myapp"
inspect = true

[[tunnels]]
name = "api"
addr = "127.0.0.1:3000"
proto = "http"
subdomain = "api"

[tunnels.basic_auth]
username = "admin"
password = "${API_PASSWORD:-secret}"

# Tunnel groups
[groups]
development = ["web", "api"]
"#.to_string()
        } else {
            r#"# NLAG Agent Configuration
version: "1"

# Authentication
auth:
  # token: "${NLAG_TOKEN}"
  # api_key: your-api-key

# Edge server (optional, uses default if not set)
# edge_url: wss://edge.nlag.dev

# Global request headers (applied to all tunnels)
global_request_headers:
  add:
    X-Forwarded-Proto: https

# Tunnel definitions
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
    proto: http
    subdomain: myapp
    inspect: true

  - name: api
    addr: "127.0.0.1:3000"
    proto: http
    subdomain: api
    basic_auth:
      username: admin
      password: "${API_PASSWORD:-secret}"

# Tunnel groups
groups:
  development:
    - web
    - api
"#.to_string()
        }
    }

    /// Get tunnels to start based on filters
    pub fn get_tunnels_to_start(&self, group: Option<&str>, tunnel_name: Option<&str>) -> Vec<SimpleTunnelConfig> {
        let tunnels: Vec<&TunnelConfig> = if let Some(group_name) = group {
            self.get_group(group_name)
        } else if let Some(name) = tunnel_name {
            self.get_tunnel(name).into_iter().collect()
        } else {
            self.tunnels.iter().collect()
        };

        tunnels.into_iter().map(|t| {
            // Parse addr to extract host and port
            let (host, port) = Self::parse_addr(&t.addr);
            
            SimpleTunnelConfig {
                name: t.name.clone(),
                local_host: Some(host),
                local_port: port,
                protocol: Some(format!("{:?}", t.proto).to_lowercase()),
                subdomain: t.subdomain.clone(),
                domain: t.domain.clone(),
            }
        }).collect()
    }

    /// Parse address into host and port
    fn parse_addr(addr: &str) -> (String, u16) {
        // Handle URL format
        if addr.starts_with("http://") || addr.starts_with("https://") {
            if let Ok(url) = url::Url::parse(addr) {
                let host = url.host_str().unwrap_or("127.0.0.1").to_string();
                let port = url.port().unwrap_or(if addr.starts_with("https://") { 443 } else { 80 });
                return (host, port);
            }
        }
        
        // Handle host:port format
        if let Some((host, port_str)) = addr.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
        
        // Fallback
        (addr.to_string(), 80)
    }

    /// Interpolate environment variables in config string
    /// Supports ${VAR} and ${VAR:-default} syntax
    fn interpolate_env(content: &str) -> String {
        let re = regex::Regex::new(r"\$\{([^}:]+)(?::-([^}]*))?\}").unwrap();
        
        re.replace_all(content, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let default = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            
            std::env::var(var_name).unwrap_or_else(|_| default.to_string())
        }).to_string()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (i, tunnel) in self.tunnels.iter().enumerate() {
            // Validate address format
            if tunnel.addr.is_empty() {
                return Err(ConfigError::Validation(
                    format!("Tunnel {} has empty address", i)
                ));
            }

            // Validate protocol-specific requirements
            match tunnel.proto {
                TunnelProtocol::Http | TunnelProtocol::Https => {
                    // HTTP tunnels should have host:port format
                    if !tunnel.addr.contains(':') && !tunnel.addr.starts_with("http") {
                        return Err(ConfigError::Validation(
                            format!("Tunnel {} address should be host:port or URL", i)
                        ));
                    }
                }
                TunnelProtocol::Tcp | TunnelProtocol::Udp => {
                    // TCP/UDP tunnels need host:port
                    if !tunnel.addr.contains(':') {
                        return Err(ConfigError::Validation(
                            format!("Tunnel {} requires host:port format for {:?}", i, tunnel.proto)
                        ));
                    }
                }
                TunnelProtocol::Tls => {}
            }

            // Validate basic auth
            if let Some(ref auth) = tunnel.basic_auth {
                if auth.username.is_empty() || auth.password.is_empty() {
                    return Err(ConfigError::Validation(
                        format!("Tunnel {} basic auth has empty username or password", i)
                    ));
                }
            }
        }

        // Validate groups reference existing tunnels
        for (group_name, tunnel_names) in &self.groups {
            for tunnel_name in tunnel_names {
                let exists = self.tunnels.iter()
                    .any(|t| t.name.as_ref() == Some(tunnel_name));
                if !exists {
                    return Err(ConfigError::Validation(
                        format!("Group '{}' references unknown tunnel '{}'", group_name, tunnel_name)
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get tunnels by group name
    pub fn get_group(&self, group_name: &str) -> Vec<&TunnelConfig> {
        match self.groups.get(group_name) {
            Some(tunnel_names) => {
                self.tunnels.iter()
                    .filter(|t| {
                        t.name.as_ref()
                            .map(|n| tunnel_names.contains(n))
                            .unwrap_or(false)
                    })
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Get tunnel by name
    pub fn get_tunnel(&self, name: &str) -> Option<&TunnelConfig> {
        self.tunnels.iter()
            .find(|t| t.name.as_ref() == Some(&name.to_string()))
    }

    /// Merge global headers into tunnel config
    pub fn effective_tunnel_config(&self, tunnel: &TunnelConfig) -> TunnelConfig {
        let mut config = tunnel.clone();
        
        // Merge global request headers
        for (k, v) in &self.global_request_headers.add {
            config.request_headers.add.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for header in &self.global_request_headers.remove {
            if !config.request_headers.remove.contains(header) {
                config.request_headers.remove.push(header.clone());
            }
        }
        
        // Merge global response headers
        for (k, v) in &self.global_response_headers.add {
            config.response_headers.add.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for header in &self.global_response_headers.remove {
            if !config.response_headers.remove.contains(header) {
                config.response_headers.remove.push(header.clone());
            }
        }
        
        // Merge global metadata
        for (k, v) in &self.metadata {
            config.metadata.entry(k.clone()).or_insert_with(|| v.clone());
        }
        
        config
    }
}

/// Configuration errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// IO error
    Io(String),
    /// Parse error
    Parse(String),
    /// Validation error
    Validation(String),
    /// Unsupported format
    UnsupportedFormat(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::Validation(e) => write!(f, "Validation error: {}", e),
            ConfigError::UnsupportedFormat(e) => write!(f, "Unsupported format: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Runtime configuration manager
pub struct ConfigManager {
    /// Current configuration
    config: RwLock<AgentConfig>,
    /// Configuration file path (for reloading)
    config_path: Option<std::path::PathBuf>,
}

impl ConfigManager {
    /// Create a new config manager
    pub fn new(config: AgentConfig) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            config_path: None,
        })
    }

    /// Create from file
    pub fn from_file(path: &Path) -> Result<Arc<Self>, ConfigError> {
        let config = AgentConfig::from_file(path)?;
        config.validate()?;
        
        Ok(Arc::new(Self {
            config: RwLock::new(config),
            config_path: Some(path.to_path_buf()),
        }))
    }

    /// Get current configuration
    pub fn config(&self) -> AgentConfig {
        self.config.read().clone()
    }

    /// Reload configuration from file
    pub fn reload(&self) -> Result<(), ConfigError> {
        let Some(ref path) = self.config_path else {
            return Err(ConfigError::Io("No config file path".to_string()));
        };

        let new_config = AgentConfig::from_file(path)?;
        new_config.validate()?;
        
        *self.config.write() = new_config;
        Ok(())
    }

    /// Update configuration
    pub fn update(&self, config: AgentConfig) -> Result<(), ConfigError> {
        config.validate()?;
        *self.config.write() = config;
        Ok(())
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self {
            config: RwLock::new(AgentConfig::default()),
            config_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_config() {
        let yaml = r#"
version: "1"
auth:
  token: my-token
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
    proto: http
    subdomain: myapp
  - name: api
    addr: "127.0.0.1:3000"
    proto: http
    subdomain: api
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.tunnels.len(), 2);
        assert_eq!(config.tunnels[0].name, Some("web".to_string()));
        assert_eq!(config.tunnels[1].addr, "127.0.0.1:3000");
    }

    #[test]
    fn test_parse_toml_config() {
        let toml = r#"
version = "1"

[auth]
token = "my-token"

[[tunnels]]
name = "web"
addr = "127.0.0.1:8080"
proto = "http"
subdomain = "myapp"

[[tunnels]]
name = "api"
addr = "127.0.0.1:3000"
proto = "http"
"#;

        let config = AgentConfig::from_toml(toml).unwrap();
        assert_eq!(config.tunnels.len(), 2);
        assert_eq!(config.auth.token, Some("my-token".to_string()));
    }

    #[test]
    fn test_env_interpolation() {
        std::env::set_var("TEST_TOKEN", "secret-token");
        std::env::set_var("TEST_PORT", "9090");

        let yaml = r#"
auth:
  token: ${TEST_TOKEN}
tunnels:
  - addr: "127.0.0.1:${TEST_PORT}"
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.auth.token, Some("secret-token".to_string()));
        assert_eq!(config.tunnels[0].addr, "127.0.0.1:9090");

        std::env::remove_var("TEST_TOKEN");
        std::env::remove_var("TEST_PORT");
    }

    #[test]
    fn test_env_interpolation_with_default() {
        let yaml = r#"
auth:
  token: ${NONEXISTENT_VAR:-default-token}
tunnels:
  - addr: "127.0.0.1:${MISSING_PORT:-8080}"
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.auth.token, Some("default-token".to_string()));
        assert_eq!(config.tunnels[0].addr, "127.0.0.1:8080");
    }

    #[test]
    fn test_validation_empty_address() {
        let config = AgentConfig {
            tunnels: vec![TunnelConfig {
                addr: "".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_invalid_tcp_address() {
        let config = AgentConfig {
            tunnels: vec![TunnelConfig {
                addr: "localhost".to_string(),
                proto: TunnelProtocol::Tcp,
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_tunnel_groups() {
        let yaml = r#"
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
  - name: api
    addr: "127.0.0.1:3000"
  - name: admin
    addr: "127.0.0.1:4000"
groups:
  frontend:
    - web
  backend:
    - api
    - admin
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        config.validate().unwrap();

        let frontend = config.get_group("frontend");
        assert_eq!(frontend.len(), 1);
        
        let backend = config.get_group("backend");
        assert_eq!(backend.len(), 2);
    }

    #[test]
    fn test_get_tunnel_by_name() {
        let yaml = r#"
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
  - name: api
    addr: "127.0.0.1:3000"
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        
        let tunnel = config.get_tunnel("api");
        assert!(tunnel.is_some());
        assert_eq!(tunnel.unwrap().addr, "127.0.0.1:3000");

        let missing = config.get_tunnel("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_global_headers_merge() {
        let yaml = r#"
global_request_headers:
  add:
    X-Global: "value"
global_response_headers:
  add:
    X-Powered-By: "NLAG"
metadata:
  environment: production
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
    request_headers:
      add:
        X-Tunnel: "web"
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        let tunnel = &config.tunnels[0];
        let effective = config.effective_tunnel_config(tunnel);
        
        // Should have both global and tunnel headers
        assert!(effective.request_headers.add.contains_key("X-Global"));
        assert!(effective.request_headers.add.contains_key("X-Tunnel"));
        assert!(effective.response_headers.add.contains_key("X-Powered-By"));
        assert!(effective.metadata.contains_key("environment"));
    }

    #[test]
    fn test_basic_auth_config() {
        let yaml = r#"
tunnels:
  - name: protected
    addr: "127.0.0.1:8080"
    basic_auth:
      username: admin
      password: secret123
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        config.validate().unwrap();
        
        let tunnel = &config.tunnels[0];
        assert!(tunnel.basic_auth.is_some());
        
        let auth = tunnel.basic_auth.as_ref().unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password, "secret123");
    }

    #[test]
    fn test_oauth_config() {
        let yaml = r#"
tunnels:
  - name: protected
    addr: "127.0.0.1:8080"
    oauth:
      provider: google
      allowed_domains:
        - example.com
        - company.org
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        
        let tunnel = &config.tunnels[0];
        assert!(tunnel.oauth.is_some());
        
        let oauth = tunnel.oauth.as_ref().unwrap();
        assert_eq!(oauth.provider, "google");
        assert_eq!(oauth.allowed_domains.len(), 2);
    }

    #[test]
    fn test_ip_restriction() {
        let yaml = r#"
tunnels:
  - name: restricted
    addr: "127.0.0.1:8080"
    ip_restriction:
      allow:
        - 10.0.0.0/8
        - 192.168.1.0/24
      deny:
        - 0.0.0.0/0
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        
        let tunnel = &config.tunnels[0];
        assert_eq!(tunnel.ip_restriction.allow.len(), 2);
        assert_eq!(tunnel.ip_restriction.deny.len(), 1);
    }

    #[test]
    fn test_webhook_config() {
        let yaml = r#"
tunnels:
  - name: web
    addr: "127.0.0.1:8080"
    webhook:
      url: "https://example.com/webhook"
      secret: "webhook-secret"
      events:
        - tunnel_started
        - request_received
"#;

        let config = AgentConfig::from_yaml(yaml).unwrap();
        
        let tunnel = &config.tunnels[0];
        assert!(tunnel.webhook.is_some());
        
        let webhook = tunnel.webhook.as_ref().unwrap();
        assert_eq!(webhook.url, "https://example.com/webhook");
        assert_eq!(webhook.events.len(), 2);
    }

    #[test]
    fn test_config_manager() {
        let config = AgentConfig {
            tunnels: vec![TunnelConfig {
                name: Some("test".to_string()),
                addr: "127.0.0.1:8080".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let manager = ConfigManager::new(config);
        
        let current = manager.config();
        assert_eq!(current.tunnels.len(), 1);
        
        // Update config
        let new_config = AgentConfig {
            tunnels: vec![
                TunnelConfig {
                    name: Some("test1".to_string()),
                    addr: "127.0.0.1:8080".to_string(),
                    ..Default::default()
                },
                TunnelConfig {
                    name: Some("test2".to_string()),
                    addr: "127.0.0.1:9090".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        
        manager.update(new_config).unwrap();
        assert_eq!(manager.config().tunnels.len(), 2);
    }
}
