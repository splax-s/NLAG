//! SSH Reverse Tunnel Module
//!
//! Allows users to create tunnels via SSH, similar to `ssh -R`.
//! This provides an alternative to the QUIC-based agent for users
//! who prefer or require SSH-based tunneling.
//!
//! ## Usage
//!
//! ```bash
//! # Forward local port 3000 to edge server
//! ssh -R 80:localhost:3000 tunnel@edge.nlag.io
//!
//! # Forward with custom subdomain
//! ssh -R myapp:80:localhost:3000 tunnel@edge.nlag.io
//!
//! # Multiple forwards
//! ssh -R api:80:localhost:3000 -R ws:80:localhost:8080 tunnel@edge.nlag.io
//! ```
//!
//! ## Features
//!
//! - Public key authentication
//! - Dynamic subdomain assignment
//! - Multiple port forwards per session
//! - Automatic reconnection info
//! - Rate limiting per user

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use nlag_common::types::TunnelId;

/// SSH tunnel errors
#[derive(Debug, Error)]
pub enum SshTunnelError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Invalid forward request: {0}")]
    InvalidForward(String),
    
    #[error("Port already in use: {0}")]
    PortInUse(u16),
    
    #[error("Max tunnels reached for user")]
    TunnelLimitReached,
    
    #[error("Subdomain not available: {0}")]
    SubdomainUnavailable(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Session terminated")]
    SessionTerminated,
    
    #[error("Rate limited")]
    RateLimited,
}

pub type Result<T> = std::result::Result<T, SshTunnelError>;

/// SSH authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Public key authentication
    PublicKey {
        /// SSH public key fingerprint
        fingerprint: String,
        /// Key type (ssh-rsa, ssh-ed25519, etc.)
        key_type: String,
    },
    /// Token-based authentication (for automation)
    Token {
        /// API token
        token: String,
    },
    /// Password authentication (discouraged)
    Password {
        /// Username
        username: String,
    },
}

/// SSH forward binding specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardBinding {
    /// Subdomain or port binding on edge server
    pub bind_address: String,
    /// Bind port on edge server (0 for dynamic)
    pub bind_port: u16,
    /// Target host on agent side
    pub target_host: String,
    /// Target port on agent side
    pub target_port: u16,
}

impl ForwardBinding {
    /// Parse an SSH -R style forward specification
    /// Formats:
    /// - `80:localhost:3000` - Bind port 80 to localhost:3000
    /// - `myapp:80:localhost:3000` - Bind subdomain:port to localhost:3000
    /// - `0:localhost:3000` - Dynamic port assignment
    pub fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.split(':').collect();
        
        match parts.len() {
            // 80:localhost:3000
            3 => {
                let bind_port: u16 = parts[0].parse()
                    .map_err(|_| SshTunnelError::InvalidForward(
                        format!("Invalid port: {}", parts[0])
                    ))?;
                let target_host = parts[1].to_string();
                let target_port: u16 = parts[2].parse()
                    .map_err(|_| SshTunnelError::InvalidForward(
                        format!("Invalid target port: {}", parts[2])
                    ))?;
                
                Ok(Self {
                    bind_address: "".to_string(),
                    bind_port,
                    target_host,
                    target_port,
                })
            }
            // myapp:80:localhost:3000
            4 => {
                let bind_address = parts[0].to_string();
                let bind_port: u16 = parts[1].parse()
                    .map_err(|_| SshTunnelError::InvalidForward(
                        format!("Invalid port: {}", parts[1])
                    ))?;
                let target_host = parts[2].to_string();
                let target_port: u16 = parts[3].parse()
                    .map_err(|_| SshTunnelError::InvalidForward(
                        format!("Invalid target port: {}", parts[3])
                    ))?;
                
                Ok(Self {
                    bind_address,
                    bind_port,
                    target_host,
                    target_port,
                })
            }
            _ => Err(SshTunnelError::InvalidForward(
                format!("Invalid forward specification: {}", spec)
            )),
        }
    }
    
    /// Get the full binding string
    pub fn binding_string(&self) -> String {
        if self.bind_address.is_empty() {
            format!(":{}", self.bind_port)
        } else {
            format!("{}:{}", self.bind_address, self.bind_port)
        }
    }
}

/// An active SSH tunnel session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    /// Session ID
    pub id: String,
    
    /// User ID (from authentication)
    pub user_id: String,
    
    /// Client IP address
    pub client_ip: IpAddr,
    
    /// Authentication method used
    pub auth_method: AuthMethod,
    
    /// Active forward bindings
    pub forwards: Vec<SshForward>,
    
    /// When the session started
    pub started_at: chrono::DateTime<chrono::Utc>,
    
    /// Last activity timestamp
    pub last_activity: chrono::DateTime<chrono::Utc>,
    
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

/// An active SSH forward within a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshForward {
    /// Forward ID
    pub id: String,
    
    /// Tunnel ID (for routing)
    pub tunnel_id: TunnelId,
    
    /// Forward binding spec
    pub binding: ForwardBinding,
    
    /// Assigned subdomain (if any)
    pub subdomain: Option<String>,
    
    /// Assigned port (for TCP forwards)
    pub assigned_port: Option<u16>,
    
    /// Public URL for this forward
    pub public_url: String,
    
    /// Number of active connections
    pub active_connections: u64,
    
    /// Total bytes transferred
    pub bytes_transferred: u64,
    
    /// When this forward was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Configuration for SSH tunnel server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshServerConfig {
    /// Listen address for SSH server
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    
    /// Server host key path
    #[serde(default)]
    pub host_key_path: Option<String>,
    
    /// Maximum sessions per user
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_user: u32,
    
    /// Maximum forwards per session
    #[serde(default = "default_max_forwards")]
    pub max_forwards_per_session: u32,
    
    /// Idle timeout (seconds)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    
    /// Banner message
    #[serde(default = "default_banner")]
    pub banner: String,
    
    /// Base domain for subdomains
    #[serde(default = "default_base_domain")]
    pub base_domain: String,
    
    /// Enable password authentication (not recommended)
    #[serde(default)]
    pub allow_password_auth: bool,
    
    /// Require registered public keys only
    #[serde(default = "default_true")]
    pub require_registered_keys: bool,
}

fn default_listen_addr() -> String { "0.0.0.0:2222".to_string() }
fn default_max_sessions() -> u32 { 5 }
fn default_max_forwards() -> u32 { 10 }
fn default_idle_timeout() -> u64 { 3600 }
fn default_base_domain() -> String { "tunnels.localhost".to_string() }
fn default_true() -> bool { true }
fn default_banner() -> String {
    r#"
╔═══════════════════════════════════════════════════════════════╗
║                    NLAG SSH Tunnel Server                     ║
╠═══════════════════════════════════════════════════════════════╣
║  Use -R to create reverse tunnels:                            ║
║    ssh -R 80:localhost:3000 tunnel@edge.nlag.io               ║
║    ssh -R myapp:80:localhost:3000 tunnel@edge.nlag.io         ║
║                                                               ║
║  Documentation: https://nlag.io/docs/ssh                      ║
╚═══════════════════════════════════════════════════════════════╝
"#.to_string()
}

impl Default for SshServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            host_key_path: None,
            max_sessions_per_user: default_max_sessions(),
            max_forwards_per_session: default_max_forwards(),
            idle_timeout_secs: default_idle_timeout(),
            banner: default_banner(),
            base_domain: default_base_domain(),
            allow_password_auth: false,
            require_registered_keys: true,
        }
    }
}

/// Statistics for SSH tunnel server
#[derive(Debug, Default)]
pub struct SshServerStats {
    /// Total sessions created
    pub total_sessions: AtomicU64,
    /// Currently active sessions
    pub active_sessions: AtomicU64,
    /// Total forwards created
    pub total_forwards: AtomicU64,
    /// Currently active forwards
    pub active_forwards: AtomicU64,
    /// Total bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
}

impl SshServerStats {
    pub fn snapshot(&self) -> SshServerStatsSnapshot {
        SshServerStatsSnapshot {
            total_sessions: self.total_sessions.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            total_forwards: self.total_forwards.load(Ordering::Relaxed),
            active_forwards: self.active_forwards.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of SSH server statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshServerStatsSnapshot {
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub total_forwards: u64,
    pub active_forwards: u64,
    pub bytes_transferred: u64,
    pub auth_failures: u64,
}

/// Registered SSH public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// Key ID
    pub id: String,
    /// User ID who owns this key
    pub user_id: String,
    /// Key fingerprint (SHA256)
    pub fingerprint: String,
    /// Key type (ssh-rsa, ssh-ed25519, etc.)
    pub key_type: String,
    /// Key comment/label
    pub comment: Option<String>,
    /// When the key was added
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last time this key was used
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Is this key enabled
    pub enabled: bool,
}

/// SSH tunnel server manager
pub struct SshTunnelServer {
    /// Server configuration
    config: RwLock<SshServerConfig>,
    
    /// Active sessions by ID
    sessions: DashMap<String, SshSession>,
    
    /// Sessions by user ID
    user_sessions: DashMap<String, Vec<String>>,
    
    /// Registered public keys by fingerprint
    registered_keys: DashMap<String, RegisteredKey>,
    
    /// Active tunnels by tunnel ID
    tunnel_forwards: DashMap<TunnelId, String>, // tunnel_id -> session_id
    
    /// Reserved subdomains
    reserved_subdomains: DashMap<String, String>, // subdomain -> session_id
    
    /// Allocated TCP ports
    allocated_ports: DashMap<u16, String>, // port -> session_id
    
    /// Server statistics
    stats: Arc<SshServerStats>,
    
    /// Shutdown signal
    shutdown: RwLock<Option<mpsc::Sender<()>>>,
}

impl SshTunnelServer {
    /// Create a new SSH tunnel server
    pub fn new(config: SshServerConfig) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            registered_keys: DashMap::new(),
            tunnel_forwards: DashMap::new(),
            reserved_subdomains: DashMap::new(),
            allocated_ports: DashMap::new(),
            stats: Arc::new(SshServerStats::default()),
            shutdown: RwLock::new(None),
        })
    }
    
    /// Get server configuration
    pub fn config(&self) -> SshServerConfig {
        self.config.read().clone()
    }
    
    /// Update server configuration
    pub fn update_config(&self, config: SshServerConfig) {
        *self.config.write() = config;
    }
    
    /// Register a public key for a user
    pub fn register_key(&self, user_id: &str, fingerprint: &str, key_type: &str, comment: Option<&str>) -> RegisteredKey {
        let key = RegisteredKey {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            fingerprint: fingerprint.to_string(),
            key_type: key_type.to_string(),
            comment: comment.map(|s| s.to_string()),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            enabled: true,
        };
        
        self.registered_keys.insert(fingerprint.to_string(), key.clone());
        info!("Registered SSH key {} for user {}", fingerprint, user_id);
        key
    }
    
    /// Verify a public key and get user ID
    pub fn verify_key(&self, fingerprint: &str) -> Option<String> {
        self.registered_keys.get(fingerprint).and_then(|key| {
            if key.enabled {
                Some(key.user_id.clone())
            } else {
                None
            }
        })
    }
    
    /// Create a new session
    pub fn create_session(&self, user_id: &str, client_ip: IpAddr, auth_method: AuthMethod) -> Result<SshSession> {
        let config = self.config.read();
        
        // Check session limit
        let user_session_count = self.user_sessions
            .get(user_id)
            .map(|s| s.len())
            .unwrap_or(0);
        
        if user_session_count >= config.max_sessions_per_user as usize {
            return Err(SshTunnelError::TunnelLimitReached);
        }
        
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        
        let session = SshSession {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            client_ip,
            auth_method,
            forwards: Vec::new(),
            started_at: now,
            last_activity: now,
            metadata: HashMap::new(),
        };
        
        self.sessions.insert(session_id.clone(), session.clone());
        self.user_sessions
            .entry(user_id.to_string())
            .or_default()
            .push(session_id);
        
        self.stats.total_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.active_sessions.fetch_add(1, Ordering::Relaxed);
        
        info!("Created SSH session {} for user {} from {}", session.id, user_id, client_ip);
        
        Ok(session)
    }
    
    /// Add a forward to a session
    pub fn add_forward(&self, session_id: &str, binding: ForwardBinding) -> Result<SshForward> {
        let mut session = self.sessions.get_mut(session_id)
            .ok_or(SshTunnelError::SessionTerminated)?;
        
        let config = self.config.read();
        
        // Check forward limit
        if session.forwards.len() >= config.max_forwards_per_session as usize {
            return Err(SshTunnelError::TunnelLimitReached);
        }
        
        // Generate tunnel ID and subdomain
        let tunnel_id = TunnelId::new();
        let subdomain = if binding.bind_address.is_empty() {
            // Generate random subdomain
            Some(generate_subdomain())
        } else {
            // Check if subdomain is available
            let subdomain = binding.bind_address.to_lowercase();
            if self.reserved_subdomains.contains_key(&subdomain) {
                return Err(SshTunnelError::SubdomainUnavailable(subdomain));
            }
            self.reserved_subdomains.insert(subdomain.clone(), session_id.to_string());
            Some(subdomain)
        };
        
        // Build public URL
        let public_url = if let Some(ref sub) = subdomain {
            format!("https://{}.{}", sub, config.base_domain)
        } else {
            format!("tcp://{}:{}", config.base_domain, binding.bind_port)
        };
        
        let forward = SshForward {
            id: uuid::Uuid::new_v4().to_string(),
            tunnel_id: tunnel_id.clone(),
            binding,
            subdomain,
            assigned_port: None,
            public_url: public_url.clone(),
            active_connections: 0,
            bytes_transferred: 0,
            created_at: chrono::Utc::now(),
        };
        
        // Register tunnel
        self.tunnel_forwards.insert(tunnel_id, session_id.to_string());
        
        session.forwards.push(forward.clone());
        session.last_activity = chrono::Utc::now();
        
        self.stats.total_forwards.fetch_add(1, Ordering::Relaxed);
        self.stats.active_forwards.fetch_add(1, Ordering::Relaxed);
        
        info!("Added SSH forward {} -> {}", public_url, forward.binding.binding_string());
        
        Ok(forward)
    }
    
    /// Remove a forward from a session
    pub fn remove_forward(&self, session_id: &str, forward_id: &str) -> Result<()> {
        let mut session = self.sessions.get_mut(session_id)
            .ok_or(SshTunnelError::SessionTerminated)?;
        
        let idx = session.forwards.iter().position(|f| f.id == forward_id);
        if let Some(idx) = idx {
            let forward = session.forwards.remove(idx);
            
            // Cleanup
            self.tunnel_forwards.remove(&forward.tunnel_id);
            if let Some(ref sub) = forward.subdomain {
                self.reserved_subdomains.remove(sub);
            }
            if let Some(port) = forward.assigned_port {
                self.allocated_ports.remove(&port);
            }
            
            self.stats.active_forwards.fetch_sub(1, Ordering::Relaxed);
            
            info!("Removed SSH forward {}", forward.public_url);
        }
        
        Ok(())
    }
    
    /// Close a session
    pub fn close_session(&self, session_id: &str) -> Result<()> {
        let session = self.sessions.remove(session_id)
            .ok_or(SshTunnelError::SessionTerminated)?.1;
        
        // Cleanup all forwards
        for forward in &session.forwards {
            self.tunnel_forwards.remove(&forward.tunnel_id);
            if let Some(ref sub) = forward.subdomain {
                self.reserved_subdomains.remove(sub);
            }
            if let Some(port) = forward.assigned_port {
                self.allocated_ports.remove(&port);
            }
        }
        
        // Remove from user sessions
        if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.user_id) {
            user_sessions.retain(|id| id != session_id);
        }
        
        self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
        self.stats.active_forwards.fetch_sub(session.forwards.len() as u64, Ordering::Relaxed);
        
        info!("Closed SSH session {} for user {}", session_id, session.user_id);
        
        Ok(())
    }
    
    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Option<SshSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }
    
    /// Get session by tunnel ID
    pub fn get_session_by_tunnel(&self, tunnel_id: &TunnelId) -> Option<SshSession> {
        self.tunnel_forwards
            .get(tunnel_id)
            .and_then(|session_id| self.sessions.get(session_id.value()).map(|s| s.clone()))
    }
    
    /// List sessions for a user
    pub fn list_user_sessions(&self, user_id: &str) -> Vec<SshSession> {
        self.user_sessions
            .get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sessions.get(id).map(|s| s.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<SshSession> {
        self.sessions.iter().map(|e| e.clone()).collect()
    }
    
    /// Get server statistics
    pub fn stats(&self) -> SshServerStatsSnapshot {
        self.stats.snapshot()
    }
    
    /// Get registered keys for a user
    pub fn list_user_keys(&self, user_id: &str) -> Vec<RegisteredKey> {
        self.registered_keys
            .iter()
            .filter(|k| k.user_id == user_id)
            .map(|k| k.clone())
            .collect()
    }
    
    /// Revoke a key
    pub fn revoke_key(&self, fingerprint: &str) -> bool {
        if let Some(mut key) = self.registered_keys.get_mut(fingerprint) {
            key.enabled = false;
            info!("Revoked SSH key {}", fingerprint);
            true
        } else {
            false
        }
    }
    
    /// Delete a key
    pub fn delete_key(&self, fingerprint: &str) -> bool {
        self.registered_keys.remove(fingerprint).is_some()
    }
    
    /// Cleanup expired sessions
    pub fn cleanup_expired(&self) {
        let config = self.config.read();
        let timeout = Duration::from_secs(config.idle_timeout_secs);
        let now = Instant::now();
        
        let expired: Vec<String> = self.sessions
            .iter()
            .filter(|s| {
                let last = s.last_activity;
                let elapsed = chrono::Utc::now().signed_duration_since(last);
                elapsed.to_std().map_or(false, |d| d > timeout)
            })
            .map(|s| s.id.clone())
            .collect();
        
        for session_id in expired {
            let _ = self.close_session(&session_id);
            debug!("Cleaned up expired SSH session {}", session_id);
        }
    }
}

/// Generate a random subdomain
fn generate_subdomain() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    chars
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_forward_binding_parse_3_parts() {
        let binding = ForwardBinding::parse("80:localhost:3000").unwrap();
        assert_eq!(binding.bind_port, 80);
        assert_eq!(binding.target_host, "localhost");
        assert_eq!(binding.target_port, 3000);
        assert!(binding.bind_address.is_empty());
    }
    
    #[test]
    fn test_forward_binding_parse_4_parts() {
        let binding = ForwardBinding::parse("myapp:80:localhost:3000").unwrap();
        assert_eq!(binding.bind_address, "myapp");
        assert_eq!(binding.bind_port, 80);
        assert_eq!(binding.target_host, "localhost");
        assert_eq!(binding.target_port, 3000);
    }
    
    #[test]
    fn test_forward_binding_invalid() {
        assert!(ForwardBinding::parse("invalid").is_err());
        assert!(ForwardBinding::parse("abc:def").is_err());
        assert!(ForwardBinding::parse("80:localhost").is_err());
    }
    
    #[test]
    fn test_session_creation() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let session = server.create_session(
            "user1",
            "127.0.0.1".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        assert_eq!(session.user_id, "user1");
        assert!(server.get_session(&session.id).is_some());
    }
    
    #[test]
    fn test_session_limit() {
        let config = SshServerConfig {
            max_sessions_per_user: 2,
            ..Default::default()
        };
        let server = SshTunnelServer::new(config);
        
        let auth = AuthMethod::PublicKey {
            fingerprint: "SHA256:abc123".to_string(),
            key_type: "ssh-ed25519".to_string(),
        };
        
        server.create_session("user1", "127.0.0.1".parse().unwrap(), auth.clone()).unwrap();
        server.create_session("user1", "127.0.0.1".parse().unwrap(), auth.clone()).unwrap();
        
        let result = server.create_session("user1", "127.0.0.1".parse().unwrap(), auth);
        assert!(matches!(result, Err(SshTunnelError::TunnelLimitReached)));
    }
    
    #[test]
    fn test_add_forward() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let session = server.create_session(
            "user1",
            "127.0.0.1".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        let binding = ForwardBinding::parse("80:localhost:3000").unwrap();
        let forward = server.add_forward(&session.id, binding).unwrap();
        
        assert!(forward.subdomain.is_some());
        assert!(forward.public_url.starts_with("https://"));
        
        let stats = server.stats();
        assert_eq!(stats.active_forwards, 1);
    }
    
    #[test]
    fn test_subdomain_reservation() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let session = server.create_session(
            "user1",
            "127.0.0.1".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        // Reserve a specific subdomain
        let binding = ForwardBinding::parse("myapp:80:localhost:3000").unwrap();
        let forward = server.add_forward(&session.id, binding).unwrap();
        assert_eq!(forward.subdomain, Some("myapp".to_string()));
        
        // Try to reserve same subdomain
        let binding2 = ForwardBinding::parse("myapp:80:localhost:4000").unwrap();
        let result = server.add_forward(&session.id, binding2);
        assert!(matches!(result, Err(SshTunnelError::SubdomainUnavailable(_))));
    }
    
    #[test]
    fn test_close_session() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let session = server.create_session(
            "user1",
            "127.0.0.1".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        let binding = ForwardBinding::parse("testapp:80:localhost:3000").unwrap();
        server.add_forward(&session.id, binding).unwrap();
        
        server.close_session(&session.id).unwrap();
        
        assert!(server.get_session(&session.id).is_none());
        
        // Subdomain should be released
        let session2 = server.create_session(
            "user2",
            "127.0.0.2".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:def456".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        let binding2 = ForwardBinding::parse("testapp:80:localhost:5000").unwrap();
        assert!(server.add_forward(&session2.id, binding2).is_ok());
    }
    
    #[test]
    fn test_key_registration() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let key = server.register_key(
            "user1",
            "SHA256:abc123",
            "ssh-ed25519",
            Some("my laptop"),
        );
        
        assert!(key.enabled);
        assert_eq!(server.verify_key("SHA256:abc123"), Some("user1".to_string()));
        
        server.revoke_key("SHA256:abc123");
        assert_eq!(server.verify_key("SHA256:abc123"), None);
    }
    
    #[test]
    fn test_stats() {
        let server = SshTunnelServer::new(SshServerConfig::default());
        
        let stats = server.stats();
        assert_eq!(stats.active_sessions, 0);
        
        let session = server.create_session(
            "user1",
            "127.0.0.1".parse().unwrap(),
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123".to_string(),
                key_type: "ssh-ed25519".to_string(),
            },
        ).unwrap();
        
        let stats = server.stats();
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.total_sessions, 1);
        
        server.close_session(&session.id).unwrap();
        
        let stats = server.stats();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.total_sessions, 1);
    }
}
