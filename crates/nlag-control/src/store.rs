//! Data store for NLAG Control Plane
//!
//! Provides in-memory storage for:
//! - Users
//! - Tokens
//! - Tunnels
//! - Agents
//!
//! Production: Replace with PostgreSQL implementation

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use uuid::Uuid;

use crate::api::{AgentResponse, StatsResponse, TokenResponse, TunnelResponse};

/// User record
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String, // In production: use bcrypt/argon2
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Tunnel configuration record
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub protocol: String,
    pub subdomain: String,
    pub custom_domain: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Agent record
#[derive(Debug, Clone)]
pub struct Agent {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub status: String,
    pub tunnels: Vec<String>,
}

/// API token record
#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// In-memory data store
pub struct Store {
    users: RwLock<HashMap<String, User>>,
    users_by_email: RwLock<HashMap<String, String>>, // email -> user_id
    tunnels: RwLock<HashMap<String, TunnelConfig>>,
    agents: RwLock<HashMap<String, Agent>>,
    tokens: RwLock<HashMap<String, ApiToken>>,
    subdomains: RwLock<HashMap<String, String>>, // subdomain -> tunnel_id
    // Metrics tracking
    bytes_transferred_total: AtomicU64,
    requests_total: AtomicU64,
    active_connections: AtomicU64,
}

impl Store {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            users_by_email: RwLock::new(HashMap::new()),
            tunnels: RwLock::new(HashMap::new()),
            agents: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
            subdomains: RwLock::new(HashMap::new()),
            bytes_transferred_total: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }

    // === User Operations ===

    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        name: Option<&str>,
    ) -> Result<User> {
        let mut users = self.users.write().unwrap();
        let mut users_by_email = self.users_by_email.write().unwrap();

        if users_by_email.contains_key(email) {
            return Err(anyhow!("Email already registered"));
        }

        // Hash the password with bcrypt
        let password_hash = hash(password, DEFAULT_COST)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

        let user = User {
            id: Uuid::new_v4().to_string(),
            email: email.to_string(),
            password_hash,
            name: name.map(String::from),
            created_at: Utc::now(),
        };

        users_by_email.insert(email.to_string(), user.id.clone());
        users.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        let users_by_email = self.users_by_email.read().unwrap();
        let users = self.users.read().unwrap();

        let user_id = users_by_email
            .get(email)
            .ok_or_else(|| anyhow!("User not found"))?;

        users
            .get(user_id)
            .cloned()
            .ok_or_else(|| anyhow!("User not found"))
    }

    pub async fn verify_password(&self, user_id: &str, password: &str) -> bool {
        let users = self.users.read().unwrap();
        users
            .get(user_id)
            .map(|u| verify(password, &u.password_hash).unwrap_or(false))
            .unwrap_or(false)
    }

    // === Tunnel Operations ===

    pub async fn create_tunnel(
        &self,
        user_id: &str,
        name: &str,
        protocol: &str,
        subdomain: Option<&str>,
        custom_domain: Option<&str>,
    ) -> Result<TunnelResponse> {
        let mut tunnels = self.tunnels.write().unwrap();
        let mut subdomains = self.subdomains.write().unwrap();

        // Generate or validate subdomain
        let subdomain = subdomain
            .map(String::from)
            .unwrap_or_else(|| generate_subdomain());

        if subdomains.contains_key(&subdomain) {
            return Err(anyhow!("Subdomain already in use"));
        }

        let tunnel = TunnelConfig {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            protocol: protocol.to_string(),
            subdomain: subdomain.clone(),
            custom_domain: custom_domain.map(String::from),
            status: "inactive".to_string(),
            created_at: Utc::now(),
        };

        subdomains.insert(subdomain.clone(), tunnel.id.clone());
        tunnels.insert(tunnel.id.clone(), tunnel.clone());

        Ok(tunnel_to_response(&tunnel))
    }

    pub async fn list_tunnels(&self, user_id: &str) -> Result<Vec<TunnelResponse>> {
        let tunnels = self.tunnels.read().unwrap();
        
        Ok(tunnels
            .values()
            .filter(|t| t.user_id == user_id)
            .map(tunnel_to_response)
            .collect())
    }

    pub async fn get_tunnel(&self, id: &str) -> Result<TunnelResponse> {
        let tunnels = self.tunnels.read().unwrap();
        
        tunnels
            .get(id)
            .map(tunnel_to_response)
            .ok_or_else(|| anyhow!("Tunnel not found"))
    }

    pub async fn delete_tunnel(&self, id: &str) -> Result<()> {
        let mut tunnels = self.tunnels.write().unwrap();
        let mut subdomains = self.subdomains.write().unwrap();

        if let Some(tunnel) = tunnels.remove(id) {
            subdomains.remove(&tunnel.subdomain);
        }

        Ok(())
    }

    // === Agent Operations ===

    pub async fn list_agents(&self, user_id: &str) -> Result<Vec<AgentResponse>> {
        let agents = self.agents.read().unwrap();
        
        Ok(agents
            .values()
            .filter(|a| a.user_id == user_id)
            .map(agent_to_response)
            .collect())
    }

    pub async fn revoke_agent(&self, id: &str) -> Result<()> {
        let mut agents = self.agents.write().unwrap();
        
        if let Some(agent) = agents.get_mut(id) {
            agent.status = "revoked".to_string();
        }

        Ok(())
    }

    pub async fn register_agent(&self, user_id: &str, name: Option<&str>) -> Result<Agent> {
        let mut agents = self.agents.write().unwrap();

        let agent = Agent {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            name: name.map(String::from),
            last_seen: Utc::now(),
            status: "connected".to_string(),
            tunnels: vec![],
        };

        agents.insert(agent.id.clone(), agent.clone());
        Ok(agent)
    }

    // === Token Operations ===

    pub async fn create_token(
        &self,
        user_id: &str,
        name: &str,
        scopes: &[String],
        expires_in_days: Option<u32>,
    ) -> Result<TokenResponse> {
        let mut tokens = self.tokens.write().unwrap();

        let raw_token = Uuid::new_v4().to_string();
        let token_id = Uuid::new_v4().to_string();

        // Hash the token using SHA-256 for storage
        let mut hasher = Sha256::new();
        hasher.update(raw_token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());
        
        let expires_at = expires_in_days.map(|days| {
            Utc::now() + chrono::Duration::days(days as i64)
        });

        let token = ApiToken {
            id: token_id.clone(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            token_hash,
            scopes: scopes.to_vec(),
            created_at: Utc::now(),
            expires_at,
            revoked: false,
        };

        tokens.insert(token_id.clone(), token.clone());

        Ok(TokenResponse {
            id: token_id,
            name: name.to_string(),
            token: Some(raw_token), // Only returned on creation
            scopes: scopes.to_vec(),
            created_at: token.created_at.to_rfc3339(),
            expires_at: expires_at.map(|e| e.to_rfc3339()),
        })
    }

    pub async fn list_tokens(&self, user_id: &str) -> Result<Vec<TokenResponse>> {
        let tokens = self.tokens.read().unwrap();
        
        Ok(tokens
            .values()
            .filter(|t| t.user_id == user_id && !t.revoked)
            .map(|t| TokenResponse {
                id: t.id.clone(),
                name: t.name.clone(),
                token: None, // Never return token after creation
                scopes: t.scopes.clone(),
                created_at: t.created_at.to_rfc3339(),
                expires_at: t.expires_at.map(|e| e.to_rfc3339()),
            })
            .collect())
    }

    pub async fn revoke_token(&self, id: &str) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap();
        
        if let Some(token) = tokens.get_mut(id) {
            token.revoked = true;
        }

        Ok(())
    }

    // === Stats ===

    pub async fn get_stats(&self) -> Result<StatsResponse> {
        let users = self.users.read().unwrap();
        let agents = self.agents.read().unwrap();
        let tunnels = self.tunnels.read().unwrap();

        let active_agents = agents.values().filter(|a| a.status == "connected").count();

        Ok(StatsResponse {
            total_users: users.len() as u64,
            total_agents: agents.len() as u64,
            total_tunnels: tunnels.len() as u64,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_transferred_24h: self.bytes_transferred_total.load(Ordering::Relaxed),
        })
    }

    // === Metrics Recording ===

    /// Record bytes transferred
    pub fn record_bytes_transferred(&self, bytes: u64) {
        self.bytes_transferred_total.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a request
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment active connections
    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> (u64, u64, u64) {
        (
            self.bytes_transferred_total.load(Ordering::Relaxed),
            self.requests_total.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
        )
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

// === Helper Functions ===

fn generate_subdomain() -> String {
    // Generate a random 8-character subdomain
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut subdomain = String::with_capacity(8);
    
    for _ in 0..8 {
        let idx = (rand_u64() % chars.len() as u64) as usize;
        subdomain.push(chars[idx]);
    }
    
    subdomain
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

fn tunnel_to_response(tunnel: &TunnelConfig) -> TunnelResponse {
    let public_url = if let Some(ref domain) = tunnel.custom_domain {
        format!("https://{}", domain)
    } else {
        format!("https://{}.nlag.io", tunnel.subdomain)
    };

    TunnelResponse {
        id: tunnel.id.clone(),
        name: tunnel.name.clone(),
        protocol: tunnel.protocol.clone(),
        subdomain: tunnel.subdomain.clone(),
        public_url,
        status: tunnel.status.clone(),
        created_at: tunnel.created_at.to_rfc3339(),
    }
}

fn agent_to_response(agent: &Agent) -> AgentResponse {
    AgentResponse {
        id: agent.id.clone(),
        name: agent.name.clone(),
        last_seen: agent.last_seen.to_rfc3339(),
        status: agent.status.clone(),
        tunnels: agent.tunnels.clone(),
    }
}
