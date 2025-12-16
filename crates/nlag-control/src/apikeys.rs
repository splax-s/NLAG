//! API Key Management
//!
//! This module provides API key creation, validation, and management
//! for programmatic access to the NLAG control plane.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// API Key errors
#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("API key not found")]
    NotFound,
    
    #[error("API key expired")]
    Expired,
    
    #[error("API key revoked")]
    Revoked,
    
    #[error("Invalid API key format")]
    InvalidFormat,
    
    #[error("Rate limit exceeded")]
    RateLimited,
    
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, ApiKeyError>;

/// API Key prefix for identification
pub const API_KEY_PREFIX: &str = "nlag_";

/// API Key scopes/permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Full access to all resources
    Admin,
    /// Read and write tunnels
    TunnelReadWrite,
    /// Read-only tunnel access
    TunnelRead,
    /// Manage domains
    DomainManage,
    /// View metrics only
    MetricsRead,
    /// View audit logs
    AuditRead,
    /// Manage billing
    BillingManage,
}

impl ApiKeyScope {
    /// Check if this scope includes another scope
    pub fn includes(&self, other: &ApiKeyScope) -> bool {
        match self {
            ApiKeyScope::Admin => true, // Admin includes all
            ApiKeyScope::TunnelReadWrite => matches!(
                other,
                ApiKeyScope::TunnelReadWrite | ApiKeyScope::TunnelRead
            ),
            _ => self == other,
        }
    }
}

/// API Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique key ID (not the secret)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Key prefix (first 8 chars of the full key)
    pub prefix: String,
    /// Hashed secret (never store the raw key)
    pub secret_hash: String,
    /// Owner user ID
    pub user_id: String,
    /// Organization ID (if applicable)
    pub organization_id: Option<String>,
    /// Granted scopes
    pub scopes: Vec<ApiKeyScope>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// Is this key revoked
    pub revoked: bool,
    /// Revocation timestamp
    pub revoked_at: Option<DateTime<Utc>>,
    /// IP allowlist (optional)
    pub allowed_ips: Vec<String>,
    /// Usage count
    pub usage_count: u64,
    /// Rate limit per minute
    pub rate_limit_per_minute: Option<u32>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl ApiKey {
    /// Check if key is valid (not expired or revoked)
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        
        if let Some(expires_at) = self.expires_at {
            if Utc::now() >= expires_at {
                return false;
            }
        }
        
        true
    }
    
    /// Check if key has a specific scope
    pub fn has_scope(&self, scope: &ApiKeyScope) -> bool {
        self.scopes.iter().any(|s| s.includes(scope))
    }
    
    /// Check if request IP is allowed
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true;
        }
        self.allowed_ips.iter().any(|allowed| allowed == ip)
    }
}

/// Created API key (includes the secret, only returned once)
#[derive(Debug, Clone, Serialize)]
pub struct CreatedApiKey {
    /// The full API key secret (only returned once!)
    pub key: String,
    /// Key metadata
    #[serde(flatten)]
    pub metadata: ApiKey,
}

/// API Key creation request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyRequest {
    /// Human-readable name
    pub name: String,
    /// Requested scopes
    pub scopes: Vec<ApiKeyScope>,
    /// Expiration in days (optional)
    pub expires_in_days: Option<u32>,
    /// IP allowlist
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Rate limit per minute
    pub rate_limit_per_minute: Option<u32>,
    /// Custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// API Key manager
pub struct ApiKeyManager {
    /// In-memory key store (would be database in production)
    keys: DashMap<String, ApiKey>,
    /// Keys by user
    keys_by_user: DashMap<String, Vec<String>>,
    /// Rate limit tracking
    rate_limits: DashMap<String, (u64, DateTime<Utc>)>,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            keys: DashMap::new(),
            keys_by_user: DashMap::new(),
            rate_limits: DashMap::new(),
        })
    }
    
    /// Create a new API key
    pub fn create_key(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
        request: CreateApiKeyRequest,
    ) -> CreatedApiKey {
        use rand::RngCore;
        
        // Generate random key secret
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret = hex::encode(secret_bytes);
        
        // Create full key with prefix
        let full_key = format!("{}{}", API_KEY_PREFIX, secret);
        let prefix = full_key[..12].to_string();
        
        // Hash the secret for storage
        let secret_hash = Self::hash_secret(&secret);
        
        // Generate key ID
        let id = uuid::Uuid::new_v4().to_string();
        
        // Calculate expiration
        let expires_at = request.expires_in_days.map(|days| {
            Utc::now() + chrono::Duration::days(days as i64)
        });
        
        let key = ApiKey {
            id: id.clone(),
            name: request.name,
            prefix: prefix.clone(),
            secret_hash,
            user_id: user_id.to_string(),
            organization_id: organization_id.map(|s| s.to_string()),
            scopes: request.scopes,
            created_at: Utc::now(),
            expires_at,
            last_used_at: None,
            revoked: false,
            revoked_at: None,
            allowed_ips: request.allowed_ips,
            usage_count: 0,
            rate_limit_per_minute: request.rate_limit_per_minute,
            metadata: request.metadata,
        };
        
        // Store key
        self.keys.insert(id.clone(), key.clone());
        
        // Add to user's keys
        self.keys_by_user
            .entry(user_id.to_string())
            .or_default()
            .push(id);
        
        info!("Created API key {} for user {}", prefix, user_id);
        
        CreatedApiKey {
            key: full_key,
            metadata: key,
        }
    }
    
    /// Validate an API key
    pub fn validate_key(&self, key: &str, required_scope: Option<&ApiKeyScope>, ip: Option<&str>) -> Result<ApiKey> {
        // Check format
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(ApiKeyError::InvalidFormat);
        }
        
        let secret = &key[API_KEY_PREFIX.len()..];
        let secret_hash = Self::hash_secret(secret);
        
        // Find key by hash
        let api_key = self.keys
            .iter()
            .find(|e| e.secret_hash == secret_hash)
            .map(|e| e.value().clone())
            .ok_or(ApiKeyError::NotFound)?;
        
        // Check if valid
        if api_key.revoked {
            return Err(ApiKeyError::Revoked);
        }
        
        if let Some(expires_at) = api_key.expires_at {
            if Utc::now() >= expires_at {
                return Err(ApiKeyError::Expired);
            }
        }
        
        // Check IP allowlist
        if let Some(ip) = ip {
            if !api_key.is_ip_allowed(ip) {
                warn!("API key {} used from non-allowed IP {}", api_key.prefix, ip);
                return Err(ApiKeyError::InsufficientPermissions);
            }
        }
        
        // Check scope
        if let Some(scope) = required_scope {
            if !api_key.has_scope(scope) {
                return Err(ApiKeyError::InsufficientPermissions);
            }
        }
        
        // Check rate limit
        if let Some(limit) = api_key.rate_limit_per_minute {
            if !self.check_rate_limit(&api_key.id, limit) {
                return Err(ApiKeyError::RateLimited);
            }
        }
        
        // Update last used
        if let Some(mut entry) = self.keys.get_mut(&api_key.id) {
            entry.last_used_at = Some(Utc::now());
            entry.usage_count += 1;
        }
        
        Ok(api_key)
    }
    
    /// Check rate limit
    fn check_rate_limit(&self, key_id: &str, limit: u32) -> bool {
        let now = Utc::now();
        let minute_ago = now - chrono::Duration::minutes(1);
        
        let mut entry = self.rate_limits.entry(key_id.to_string()).or_insert((0, now));
        
        // Reset if window expired
        if entry.1 < minute_ago {
            *entry = (1, now);
            return true;
        }
        
        // Check limit
        if entry.0 >= limit as u64 {
            return false;
        }
        
        entry.0 += 1;
        true
    }
    
    /// Revoke an API key
    pub fn revoke_key(&self, key_id: &str, user_id: &str) -> Result<()> {
        let mut key = self.keys
            .get_mut(key_id)
            .ok_or(ApiKeyError::NotFound)?;
        
        // Check ownership
        if key.user_id != user_id {
            return Err(ApiKeyError::InsufficientPermissions);
        }
        
        key.revoked = true;
        key.revoked_at = Some(Utc::now());
        
        info!("Revoked API key {}", key.prefix);
        
        Ok(())
    }
    
    /// List keys for a user
    pub fn list_keys(&self, user_id: &str) -> Vec<ApiKey> {
        self.keys_by_user
            .get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.keys.get(id).map(|k| k.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get key by ID
    pub fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        self.keys.get(key_id).map(|k| k.clone())
    }
    
    /// Hash a secret for storage
    fn hash_secret(secret: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        // Add some salt for security
        "nlag-api-key-salt".hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    
    /// Clean up expired rate limit entries
    pub fn cleanup(&self) {
        let cutoff = Utc::now() - chrono::Duration::minutes(5);
        
        self.rate_limits.retain(|_, (_, time)| *time > cutoff);
    }
    
    /// Start cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                self.cleanup();
            }
        });
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self {
            keys: DashMap::new(),
            keys_by_user: DashMap::new(),
            rate_limits: DashMap::new(),
        }
    }
}

/// API Key statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyStats {
    pub total_keys: usize,
    pub active_keys: usize,
    pub revoked_keys: usize,
    pub expired_keys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_and_validate_key() {
        let manager = ApiKeyManager::new();
        
        let request = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            scopes: vec![ApiKeyScope::TunnelReadWrite],
            expires_in_days: Some(30),
            allowed_ips: vec![],
            rate_limit_per_minute: None,
            metadata: HashMap::new(),
        };
        
        let created = manager.create_key("user-1", None, request);
        
        assert!(created.key.starts_with(API_KEY_PREFIX));
        
        // Validate the key
        let validated = manager.validate_key(&created.key, None, None).unwrap();
        assert_eq!(validated.id, created.metadata.id);
        assert_eq!(validated.user_id, "user-1");
    }
    
    #[test]
    fn test_key_scopes() {
        let key = ApiKey {
            id: "test".to_string(),
            name: "test".to_string(),
            prefix: "nlag_abc".to_string(),
            secret_hash: "hash".to_string(),
            user_id: "user".to_string(),
            organization_id: None,
            scopes: vec![ApiKeyScope::Admin],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked: false,
            revoked_at: None,
            allowed_ips: vec![],
            usage_count: 0,
            rate_limit_per_minute: None,
            metadata: HashMap::new(),
        };
        
        // Admin should have all scopes
        assert!(key.has_scope(&ApiKeyScope::TunnelRead));
        assert!(key.has_scope(&ApiKeyScope::MetricsRead));
        assert!(key.has_scope(&ApiKeyScope::BillingManage));
    }
    
    #[test]
    fn test_revoke_key() {
        let manager = ApiKeyManager::new();
        
        let request = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            scopes: vec![ApiKeyScope::TunnelRead],
            expires_in_days: None,
            allowed_ips: vec![],
            rate_limit_per_minute: None,
            metadata: HashMap::new(),
        };
        
        let created = manager.create_key("user-1", None, request);
        
        // Revoke the key
        manager.revoke_key(&created.metadata.id, "user-1").unwrap();
        
        // Validation should fail
        assert!(manager.validate_key(&created.key, None, None).is_err());
    }
    
    #[test]
    fn test_ip_allowlist() {
        let key = ApiKey {
            id: "test".to_string(),
            name: "test".to_string(),
            prefix: "nlag_abc".to_string(),
            secret_hash: "hash".to_string(),
            user_id: "user".to_string(),
            organization_id: None,
            scopes: vec![],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked: false,
            revoked_at: None,
            allowed_ips: vec!["192.168.1.100".to_string()],
            usage_count: 0,
            rate_limit_per_minute: None,
            metadata: HashMap::new(),
        };
        
        assert!(key.is_ip_allowed("192.168.1.100"));
        assert!(!key.is_ip_allowed("10.0.0.1"));
    }
}
