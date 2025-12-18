//! NLAG client for creating and managing tunnels.

use crate::{
    auth::Credentials,
    error::{Error, Result},
    tunnel::{Protocol, Tunnel, TunnelConfig, TunnelInfo},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// Client configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// API URL (default: https://api.nlag.dev)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Edge server URL (default: wss://connect.nlag.dev)
    #[serde(default = "default_edge_url")]
    pub edge_url: String,

    /// Auth token (optional, uses stored credentials if not provided)
    pub auth_token: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Enable automatic reconnection
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    /// Maximum reconnection attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Enable TLS verification
    #[serde(default = "default_true")]
    pub verify_tls: bool,

    /// Custom CA certificate (PEM format)
    pub ca_cert: Option<String>,

    /// Region preference
    pub region: Option<String>,
}

fn default_api_url() -> String {
    "https://api.nlag.dev".to_string()
}

fn default_edge_url() -> String {
    "wss://connect.nlag.dev".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

fn default_max_retries() -> u32 {
    5
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            edge_url: default_edge_url(),
            auth_token: None,
            timeout_secs: default_timeout(),
            auto_reconnect: true,
            max_retries: default_max_retries(),
            verify_tls: true,
            ca_cert: None,
            region: None,
        }
    }
}

/// NLAG client for creating tunnels.
///
/// # Example
///
/// ```rust,no_run
/// use nlag_sdk::{Client, ClientConfig, TunnelConfig, Protocol};
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // Create client with default config
///     let client = Client::new().await?;
///
///     // Or with custom config
///     let client = Client::with_config(ClientConfig {
///         region: Some("us-west".to_string()),
///         ..Default::default()
///     }).await?;
///
///     // Expose a local port
///     let tunnel = client.expose(TunnelConfig {
///         protocol: Protocol::Http,
///         local_port: 8080,
///         subdomain: Some("myapp".to_string()),
///         ..Default::default()
///     }).await?;
///
///     println!("Tunnel URL: {}", tunnel.public_url());
///
///     // Keep running until Ctrl+C
///     tokio::signal::ctrl_c().await?;
///     tunnel.close().await?;
///
///     Ok(())
/// }
/// ```
pub struct Client {
    config: ClientConfig,
    credentials: Option<Credentials>,
    http_client: reqwest::Client,
    tunnels: Arc<RwLock<Vec<Arc<Tunnel>>>>,
}

impl Client {
    /// Create a new client with default configuration.
    ///
    /// Loads stored credentials automatically.
    pub async fn new() -> Result<Self> {
        Self::with_config(ClientConfig::default()).await
    }

    /// Create a client with custom configuration.
    pub async fn with_config(config: ClientConfig) -> Result<Self> {
        // Load credentials
        let credentials = if let Some(ref token) = config.auth_token {
            Some(Credentials {
                access_token: token.clone(),
                refresh_token: None,
                expires_at: None,
            })
        } else {
            crate::auth::load_credentials().await.ok()
        };

        // Build HTTP client
        let mut http_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs));

        if !config.verify_tls {
            http_builder = http_builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref ca_cert) = config.ca_cert {
            let cert = reqwest::Certificate::from_pem(ca_cert.as_bytes())
                .map_err(|e| Error::Configuration(format!("Invalid CA cert: {}", e)))?;
            http_builder = http_builder.add_root_certificate(cert);
        }

        let http_client = http_builder
            .build()
            .map_err(|e| Error::Configuration(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self {
            config,
            credentials,
            http_client,
            tunnels: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Expose a local port through a tunnel.
    pub async fn expose(&self, config: TunnelConfig) -> Result<Arc<Tunnel>> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(Error::Authentication("Not authenticated".to_string()))?;

        // Request tunnel from API
        let response = self
            .http_client
            .post(format!("{}/tunnels", self.config.api_url))
            .bearer_auth(&credentials.access_token)
            .json(&TunnelRequest {
                protocol: config.protocol,
                subdomain: config.subdomain.clone(),
                local_port: config.local_port,
                basic_auth: config.basic_auth.clone(),
                ip_allow: config.ip_allow.clone(),
                ip_deny: config.ip_deny.clone(),
                headers: config.headers.clone(),
                region: self.config.region.clone(),
                metadata: config.metadata.clone(),
            })
            .send()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Tunnel(format!(
                "Failed to create tunnel: {} - {}",
                status, body
            )));
        }

        let tunnel_response: TunnelResponse = response
            .json()
            .await
            .map_err(|e| Error::Json(e.to_string()))?;

        let tunnel = Arc::new(Tunnel::new(
            tunnel_response.id,
            tunnel_response.public_url,
            config,
        ));

        // Store tunnel reference
        self.tunnels.write().await.push(tunnel.clone());

        // TODO: Start QUIC connection for data forwarding

        Ok(tunnel)
    }

    /// List all active tunnels.
    pub async fn list_tunnels(&self) -> Result<Vec<TunnelInfo>> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(Error::Authentication("Not authenticated".to_string()))?;

        let response = self
            .http_client
            .get(format!("{}/tunnels", self.config.api_url))
            .bearer_auth(&credentials.access_token)
            .send()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Tunnel("Failed to list tunnels".to_string()));
        }

        let tunnels: Vec<TunnelInfo> = response
            .json()
            .await
            .map_err(|e| Error::Json(e.to_string()))?;

        Ok(tunnels)
    }

    /// Get a specific tunnel by ID.
    pub async fn get_tunnel(&self, tunnel_id: &str) -> Result<TunnelInfo> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(Error::Authentication("Not authenticated".to_string()))?;

        let response = self
            .http_client
            .get(format!("{}/tunnels/{}", self.config.api_url, tunnel_id))
            .bearer_auth(&credentials.access_token)
            .send()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Tunnel(format!("Tunnel not found: {}", tunnel_id)));
        }

        let tunnel: TunnelInfo = response
            .json()
            .await
            .map_err(|e| Error::Json(e.to_string()))?;

        Ok(tunnel)
    }

    /// Close a tunnel by ID.
    pub async fn close_tunnel(&self, tunnel_id: &str) -> Result<()> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(Error::Authentication("Not authenticated".to_string()))?;

        let response = self
            .http_client
            .delete(format!("{}/tunnels/{}", self.config.api_url, tunnel_id))
            .bearer_auth(&credentials.access_token)
            .send()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Tunnel(format!(
                "Failed to close tunnel: {}",
                tunnel_id
            )));
        }

        // Remove from local list
        let mut tunnels = self.tunnels.write().await;
        tunnels.retain(|t| t.id() != tunnel_id);

        Ok(())
    }

    /// Close all tunnels.
    pub async fn close_all(&self) -> Result<()> {
        let tunnels = self.tunnels.read().await.clone();
        for tunnel in tunnels {
            tunnel.close().await?;
        }
        self.tunnels.write().await.clear();
        Ok(())
    }

    /// Get the client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Check if authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.credentials.is_some()
    }

    /// Get current credentials.
    pub fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    /// Set credentials.
    pub fn set_credentials(&mut self, credentials: Credentials) {
        self.credentials = Some(credentials);
    }
}

#[derive(Debug, Serialize)]
struct TunnelRequest {
    protocol: Protocol,
    subdomain: Option<String>,
    local_port: u16,
    basic_auth: Option<std::collections::HashMap<String, String>>,
    ip_allow: Option<Vec<String>>,
    ip_deny: Option<Vec<String>>,
    headers: Option<std::collections::HashMap<String, String>>,
    region: Option<String>,
    metadata: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TunnelResponse {
    id: String,
    public_url: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("api_url", &self.config.api_url)
            .field("authenticated", &self.is_authenticated())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.api_url, "https://api.nlag.dev");
        assert_eq!(config.edge_url, "wss://connect.nlag.dev");
        assert!(config.auto_reconnect);
        assert_eq!(config.max_retries, 5);
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = Client::with_config(ClientConfig {
            api_url: "http://localhost:8080".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

        assert!(!client.is_authenticated());
        assert_eq!(client.config().api_url, "http://localhost:8080");
    }
}
