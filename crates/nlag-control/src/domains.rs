//! Reserved/Persistent Domains
//!
//! Allows users to reserve subdomains that persist across tunnel sessions.
//! Reserved domains can be:
//! - Standard reserved subdomains (e.g., myapp.nlag.io)
//! - Custom domains with CNAME verification
//! - Wildcard domains (premium feature)
//!
//! ## Features
//!
//! - Domain reservation with ownership verification
//! - CNAME and TXT record verification for custom domains
//! - Domain transfer between users
//! - Automatic cleanup of expired reservations
//! - Premium domain features (shorter names, wildcards)

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Domain management errors
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Domain already reserved: {0}")]
    AlreadyReserved(String),
    
    #[error("Domain not found: {0}")]
    NotFound(String),
    
    #[error("Domain verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),
    
    #[error("Domain reserved by another user")]
    NotOwner,
    
    #[error("Reservation expired")]
    Expired,
    
    #[error("Feature requires premium subscription")]
    PremiumRequired,
    
    #[error("Domain limit reached for user")]
    LimitReached,
    
    #[error("DNS lookup failed: {0}")]
    DnsError(String),
}

pub type Result<T> = std::result::Result<T, DomainError>;

/// Domain type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomainType {
    /// Subdomain on our main domain (e.g., myapp.nlag.io)
    Subdomain,
    /// Custom domain with CNAME pointing to us
    Custom,
    /// Wildcard subdomain (*.myapp.nlag.io)
    Wildcard,
}

/// Domain verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Pending verification
    Pending,
    /// Verified and active
    Verified,
    /// Verification failed
    Failed,
    /// Verification expired (needs re-verification)
    Expired,
}

/// Reserved domain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservedDomain {
    /// Domain ID
    pub id: String,
    
    /// Full domain name (e.g., myapp.nlag.io or api.example.com)
    pub domain: String,
    
    /// User ID who owns this domain
    pub user_id: String,
    
    /// Domain type
    pub domain_type: DomainType,
    
    /// Verification status
    pub status: VerificationStatus,
    
    /// Verification token (for TXT record verification)
    #[serde(default)]
    pub verification_token: Option<String>,
    
    /// Expected CNAME target (for custom domains)
    #[serde(default)]
    pub cname_target: Option<String>,
    
    /// When the domain was reserved
    pub created_at: DateTime<Utc>,
    
    /// When the domain expires (for non-premium users)
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Last verification attempt
    #[serde(default)]
    pub last_verified_at: Option<DateTime<Utc>>,
    
    /// Tunnel ID currently using this domain
    #[serde(default)]
    pub active_tunnel_id: Option<String>,
    
    /// SSL/TLS certificate ID
    #[serde(default)]
    pub certificate_id: Option<String>,
    
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl ReservedDomain {
    /// Create a new subdomain reservation
    pub fn new_subdomain(subdomain: &str, base_domain: &str, user_id: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            domain: format!("{}.{}", subdomain, base_domain),
            user_id: user_id.to_string(),
            domain_type: DomainType::Subdomain,
            status: VerificationStatus::Verified, // Subdomains are auto-verified
            verification_token: None,
            cname_target: None,
            created_at: Utc::now(),
            expires_at: None,
            last_verified_at: Some(Utc::now()),
            active_tunnel_id: None,
            certificate_id: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Create a new custom domain reservation
    pub fn new_custom(domain: &str, user_id: &str, cname_target: &str) -> Self {
        let verification_token = generate_verification_token();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            domain: domain.to_string(),
            user_id: user_id.to_string(),
            domain_type: DomainType::Custom,
            status: VerificationStatus::Pending,
            verification_token: Some(verification_token),
            cname_target: Some(cname_target.to_string()),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(7)), // 7 day verification window
            last_verified_at: None,
            active_tunnel_id: None,
            certificate_id: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Check if domain is verified and active
    pub fn is_active(&self) -> bool {
        self.status == VerificationStatus::Verified
            && self.expires_at.map_or(true, |exp| exp > Utc::now())
    }
    
    /// Check if domain needs re-verification
    pub fn needs_reverification(&self) -> bool {
        match self.domain_type {
            DomainType::Subdomain => false,
            DomainType::Custom | DomainType::Wildcard => {
                self.last_verified_at
                    .map_or(true, |v| Utc::now() - v > Duration::days(30))
            }
        }
    }
}

/// Domain reservation limits per tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainLimits {
    /// Maximum subdomains
    pub max_subdomains: u32,
    /// Maximum custom domains
    pub max_custom_domains: u32,
    /// Allow wildcard domains
    pub allow_wildcards: bool,
    /// Minimum subdomain length
    pub min_subdomain_length: usize,
    /// Reservation duration (None = unlimited)
    pub reservation_duration_days: Option<u32>,
}

impl Default for DomainLimits {
    fn default() -> Self {
        Self {
            max_subdomains: 3,
            max_custom_domains: 0,
            allow_wildcards: false,
            min_subdomain_length: 6,
            reservation_duration_days: Some(30),
        }
    }
}

impl DomainLimits {
    /// Free tier limits
    pub fn free() -> Self {
        Self::default()
    }
    
    /// Pro tier limits
    pub fn pro() -> Self {
        Self {
            max_subdomains: 10,
            max_custom_domains: 5,
            allow_wildcards: false,
            min_subdomain_length: 4,
            reservation_duration_days: None,
        }
    }
    
    /// Enterprise tier limits
    pub fn enterprise() -> Self {
        Self {
            max_subdomains: 100,
            max_custom_domains: 50,
            allow_wildcards: true,
            min_subdomain_length: 1,
            reservation_duration_days: None,
        }
    }
}

/// Domain manager
pub struct DomainManager {
    /// Reserved domains by ID
    domains: DashMap<String, ReservedDomain>,
    
    /// Domain name to ID mapping
    domain_index: DashMap<String, String>,
    
    /// User ID to domain IDs mapping
    user_domains: DashMap<String, Vec<String>>,
    
    /// Base domain for subdomains (e.g., "nlag.io")
    base_domain: String,
    
    /// CNAME target for custom domains
    cname_target: String,
    
    /// Reserved/blocked subdomain names
    blocked_subdomains: Vec<String>,
}

impl DomainManager {
    /// Create a new domain manager
    pub fn new(base_domain: &str, cname_target: &str) -> Arc<Self> {
        Arc::new(Self {
            domains: DashMap::new(),
            domain_index: DashMap::new(),
            user_domains: DashMap::new(),
            base_domain: base_domain.to_string(),
            cname_target: cname_target.to_string(),
            blocked_subdomains: default_blocked_subdomains(),
        })
    }
    
    /// Reserve a subdomain
    pub fn reserve_subdomain(
        &self,
        subdomain: &str,
        user_id: &str,
        limits: &DomainLimits,
    ) -> Result<ReservedDomain> {
        // Validate subdomain
        self.validate_subdomain(subdomain, limits)?;
        
        // Check user limits
        let user_domain_count = self.get_user_subdomain_count(user_id);
        if user_domain_count >= limits.max_subdomains as usize {
            return Err(DomainError::LimitReached);
        }
        
        let full_domain = format!("{}.{}", subdomain.to_lowercase(), self.base_domain);
        
        // Check if already reserved
        if self.domain_index.contains_key(&full_domain) {
            return Err(DomainError::AlreadyReserved(full_domain));
        }
        
        // Create reservation
        let mut domain = ReservedDomain::new_subdomain(subdomain, &self.base_domain, user_id);
        
        // Set expiration if applicable
        if let Some(days) = limits.reservation_duration_days {
            domain.expires_at = Some(Utc::now() + Duration::days(days as i64));
        }
        
        info!("Reserved subdomain {} for user {}", full_domain, user_id);
        
        // Store
        self.store_domain(domain.clone());
        
        Ok(domain)
    }
    
    /// Reserve a custom domain
    pub fn reserve_custom_domain(
        &self,
        domain: &str,
        user_id: &str,
        limits: &DomainLimits,
    ) -> Result<ReservedDomain> {
        // Validate domain
        self.validate_custom_domain(domain)?;
        
        // Check user limits
        let user_domain_count = self.get_user_custom_domain_count(user_id);
        if user_domain_count >= limits.max_custom_domains as usize {
            if limits.max_custom_domains == 0 {
                return Err(DomainError::PremiumRequired);
            }
            return Err(DomainError::LimitReached);
        }
        
        let domain_lower = domain.to_lowercase();
        
        // Check if already reserved
        if self.domain_index.contains_key(&domain_lower) {
            return Err(DomainError::AlreadyReserved(domain_lower));
        }
        
        // Create reservation
        let reserved = ReservedDomain::new_custom(&domain_lower, user_id, &self.cname_target);
        
        info!(
            "Custom domain {} pending verification for user {} (token: {})",
            domain_lower,
            user_id,
            reserved.verification_token.as_ref().unwrap()
        );
        
        // Store
        self.store_domain(reserved.clone());
        
        Ok(reserved)
    }
    
    /// Verify a custom domain
    pub async fn verify_custom_domain(&self, domain_id: &str) -> Result<ReservedDomain> {
        let mut domain = self.domains.get_mut(domain_id)
            .ok_or_else(|| DomainError::NotFound(domain_id.to_string()))?;
        
        if domain.domain_type == DomainType::Subdomain {
            // Subdomains don't need verification
            return Ok(domain.clone());
        }
        
        // Check CNAME record
        let cname_ok = self.verify_cname(&domain.domain, domain.cname_target.as_deref().unwrap_or(""))
            .await?;
        
        // Check TXT record for verification token
        let txt_ok = if let Some(ref token) = domain.verification_token {
            self.verify_txt_record(&domain.domain, token).await?
        } else {
            false
        };
        
        if cname_ok || txt_ok {
            domain.status = VerificationStatus::Verified;
            domain.last_verified_at = Some(Utc::now());
            domain.expires_at = None; // Remove expiration on verification
            
            info!("Domain {} verified successfully", domain.domain);
            Ok(domain.clone())
        } else {
            domain.status = VerificationStatus::Failed;
            Err(DomainError::VerificationFailed(format!(
                "CNAME should point to {} or add TXT record with value {}",
                domain.cname_target.as_ref().unwrap_or(&String::new()),
                domain.verification_token.as_ref().unwrap_or(&String::new())
            )))
        }
    }
    
    /// Verify CNAME record
    async fn verify_cname(&self, domain: &str, expected_target: &str) -> Result<bool> {
        // In production, use actual DNS lookups
        // For now, simulate
        debug!("Verifying CNAME for {} -> {}", domain, expected_target);
        
        #[cfg(feature = "dns-verification")]
        {
            use trust_dns_resolver::TokioAsyncResolver;
            let resolver = TokioAsyncResolver::tokio_from_system_conf()
                .map_err(|e| DomainError::DnsError(e.to_string()))?;
            
            let response = resolver.cname_lookup(domain).await
                .map_err(|e| DomainError::DnsError(e.to_string()))?;
            
            for record in response.iter() {
                if record.to_lowercase() == expected_target.to_lowercase() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        
        #[cfg(not(feature = "dns-verification"))]
        {
            // Placeholder - always return false in dev mode
            Ok(false)
        }
    }
    
    /// Verify TXT record
    async fn verify_txt_record(&self, domain: &str, expected_value: &str) -> Result<bool> {
        debug!("Verifying TXT record for {} with value {}", domain, expected_value);
        
        #[cfg(feature = "dns-verification")]
        {
            use trust_dns_resolver::TokioAsyncResolver;
            let resolver = TokioAsyncResolver::tokio_from_system_conf()
                .map_err(|e| DomainError::DnsError(e.to_string()))?;
            
            // Check _nlag-verify subdomain
            let verify_domain = format!("_nlag-verify.{}", domain);
            let response = resolver.txt_lookup(&verify_domain).await
                .map_err(|e| DomainError::DnsError(e.to_string()))?;
            
            for record in response.iter() {
                let txt_data = record.to_string();
                if txt_data.contains(expected_value) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        
        #[cfg(not(feature = "dns-verification"))]
        {
            let _ = (domain, expected_value);
            Ok(false)
        }
    }
    
    /// Get a domain by ID
    pub fn get_domain(&self, domain_id: &str) -> Option<ReservedDomain> {
        self.domains.get(domain_id).map(|d| d.clone())
    }
    
    /// Get a domain by name
    pub fn get_domain_by_name(&self, domain: &str) -> Option<ReservedDomain> {
        self.domain_index
            .get(&domain.to_lowercase())
            .and_then(|id| self.domains.get(id.value()).map(|d| d.clone()))
    }
    
    /// List domains for a user
    pub fn list_user_domains(&self, user_id: &str) -> Vec<ReservedDomain> {
        self.user_domains
            .get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.domains.get(id).map(|d| d.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Release/delete a domain reservation
    pub fn release_domain(&self, domain_id: &str, user_id: &str) -> Result<()> {
        let domain = self.domains.get(domain_id)
            .ok_or_else(|| DomainError::NotFound(domain_id.to_string()))?;
        
        if domain.user_id != user_id {
            return Err(DomainError::NotOwner);
        }
        
        let domain_name = domain.domain.clone();
        drop(domain); // Release the lock
        
        // Remove from indices
        self.domain_index.remove(&domain_name);
        self.domains.remove(domain_id);
        
        // Remove from user's domain list
        if let Some(mut ids) = self.user_domains.get_mut(user_id) {
            ids.retain(|id| id != domain_id);
        }
        
        info!("Released domain {} for user {}", domain_name, user_id);
        
        Ok(())
    }
    
    /// Assign a tunnel to a domain
    pub fn assign_tunnel(&self, domain_id: &str, tunnel_id: &str, user_id: &str) -> Result<()> {
        let mut domain = self.domains.get_mut(domain_id)
            .ok_or_else(|| DomainError::NotFound(domain_id.to_string()))?;
        
        if domain.user_id != user_id {
            return Err(DomainError::NotOwner);
        }
        
        if !domain.is_active() {
            return Err(DomainError::VerificationFailed("Domain not verified".to_string()));
        }
        
        domain.active_tunnel_id = Some(tunnel_id.to_string());
        
        info!("Assigned tunnel {} to domain {}", tunnel_id, domain.domain);
        
        Ok(())
    }
    
    /// Unassign tunnel from domain
    pub fn unassign_tunnel(&self, domain_id: &str) -> Result<()> {
        let mut domain = self.domains.get_mut(domain_id)
            .ok_or_else(|| DomainError::NotFound(domain_id.to_string()))?;
        
        domain.active_tunnel_id = None;
        
        Ok(())
    }
    
    /// Find domain for incoming request
    pub fn find_domain_for_request(&self, hostname: &str) -> Option<ReservedDomain> {
        let hostname_lower = hostname.to_lowercase();
        
        // Direct match
        if let Some(domain) = self.get_domain_by_name(&hostname_lower) {
            if domain.is_active() {
                return Some(domain);
            }
        }
        
        // Wildcard match (*.example.com)
        if let Some(dot_pos) = hostname_lower.find('.') {
            let parent = &hostname_lower[dot_pos + 1..];
            let wildcard = format!("*.{}", parent);
            
            if let Some(domain) = self.get_domain_by_name(&wildcard) {
                if domain.is_active() {
                    return Some(domain);
                }
            }
        }
        
        None
    }
    
    /// Cleanup expired domains
    pub fn cleanup_expired(&self) -> Vec<String> {
        let now = Utc::now();
        let mut expired = Vec::new();
        
        for entry in self.domains.iter() {
            if let Some(expires) = entry.expires_at {
                if expires < now {
                    expired.push(entry.id.clone());
                }
            }
        }
        
        for id in &expired {
            if let Some((_, domain)) = self.domains.remove(id) {
                self.domain_index.remove(&domain.domain);
                
                if let Some(mut ids) = self.user_domains.get_mut(&domain.user_id) {
                    ids.retain(|i| i != id);
                }
                
                warn!("Expired domain reservation: {}", domain.domain);
            }
        }
        
        expired
    }
    
    /// Start cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let expired = self.cleanup_expired();
                if !expired.is_empty() {
                    info!("Cleaned up {} expired domain reservations", expired.len());
                }
            }
        });
    }
    
    // Private helper methods
    
    fn validate_subdomain(&self, subdomain: &str, limits: &DomainLimits) -> Result<()> {
        let subdomain = subdomain.to_lowercase();
        
        // Length check
        if subdomain.len() < limits.min_subdomain_length {
            return Err(DomainError::InvalidDomain(format!(
                "Subdomain must be at least {} characters",
                limits.min_subdomain_length
            )));
        }
        
        if subdomain.len() > 63 {
            return Err(DomainError::InvalidDomain(
                "Subdomain cannot exceed 63 characters".to_string()
            ));
        }
        
        // Character validation
        if !subdomain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(DomainError::InvalidDomain(
                "Subdomain can only contain alphanumeric characters and hyphens".to_string()
            ));
        }
        
        if subdomain.starts_with('-') || subdomain.ends_with('-') {
            return Err(DomainError::InvalidDomain(
                "Subdomain cannot start or end with a hyphen".to_string()
            ));
        }
        
        // Reserved names
        if self.blocked_subdomains.contains(&subdomain) {
            return Err(DomainError::InvalidDomain(format!(
                "Subdomain '{}' is reserved",
                subdomain
            )));
        }
        
        Ok(())
    }
    
    fn validate_custom_domain(&self, domain: &str) -> Result<()> {
        let domain = domain.to_lowercase();
        
        // Basic validation
        if domain.is_empty() || domain.len() > 253 {
            return Err(DomainError::InvalidDomain("Invalid domain length".to_string()));
        }
        
        // Must have at least one dot
        if !domain.contains('.') {
            return Err(DomainError::InvalidDomain(
                "Domain must have at least one dot".to_string()
            ));
        }
        
        // Cannot be our base domain
        if domain == self.base_domain || domain.ends_with(&format!(".{}", self.base_domain)) {
            return Err(DomainError::InvalidDomain(
                "Cannot reserve subdomain of our base domain as custom domain".to_string()
            ));
        }
        
        // Validate each label
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DomainError::InvalidDomain(
                    "Invalid domain label length".to_string()
                ));
            }
            
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(DomainError::InvalidDomain(
                    "Domain labels can only contain alphanumeric characters and hyphens".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    fn store_domain(&self, domain: ReservedDomain) {
        let id = domain.id.clone();
        let domain_name = domain.domain.clone();
        let user_id = domain.user_id.clone();
        
        self.domains.insert(id.clone(), domain);
        self.domain_index.insert(domain_name, id.clone());
        
        self.user_domains
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(id);
    }
    
    fn get_user_subdomain_count(&self, user_id: &str) -> usize {
        self.list_user_domains(user_id)
            .iter()
            .filter(|d| d.domain_type == DomainType::Subdomain)
            .count()
    }
    
    fn get_user_custom_domain_count(&self, user_id: &str) -> usize {
        self.list_user_domains(user_id)
            .iter()
            .filter(|d| d.domain_type == DomainType::Custom || d.domain_type == DomainType::Wildcard)
            .count()
    }
}

/// Generate a verification token
fn generate_verification_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "nlag-verify-{}",
        (0..32)
            .map(|_| {
                let idx: usize = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx as u8) as char
                } else {
                    (b'a' + (idx - 10) as u8) as char
                }
            })
            .collect::<String>()
    )
}

/// Default blocked subdomains
fn default_blocked_subdomains() -> Vec<String> {
    vec![
        "www", "api", "app", "admin", "dashboard", "control", "edge",
        "mail", "email", "smtp", "imap", "pop", "ftp", "sftp",
        "ns1", "ns2", "dns", "mx", "ssl", "tls", "cdn",
        "status", "health", "metrics", "stats", "monitor",
        "auth", "oauth", "login", "signup", "register",
        "billing", "payment", "pay", "invoice",
        "support", "help", "docs", "documentation",
        "blog", "news", "marketing", "promo",
        "test", "testing", "staging", "dev", "development", "prod", "production",
        "internal", "private", "secure", "root", "system",
        "nlag", "tunnel", "tunnels", "agent", "agents",
    ].into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reserve_subdomain() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default();
        
        let result = manager.reserve_subdomain("myapp123", "user1", &limits);
        assert!(result.is_ok());
        
        let domain = result.unwrap();
        assert_eq!(domain.domain, "myapp123.nlag.io");
        assert_eq!(domain.status, VerificationStatus::Verified);
    }
    
    #[test]
    fn test_subdomain_too_short() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default(); // min_subdomain_length = 6
        
        let result = manager.reserve_subdomain("abc", "user1", &limits);
        assert!(matches!(result, Err(DomainError::InvalidDomain(_))));
    }
    
    #[test]
    fn test_blocked_subdomain() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default();
        
        let result = manager.reserve_subdomain("admin", "user1", &limits);
        assert!(matches!(result, Err(DomainError::InvalidDomain(_))));
    }
    
    #[test]
    fn test_duplicate_subdomain() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default();
        
        manager.reserve_subdomain("mytest1", "user1", &limits).unwrap();
        
        let result = manager.reserve_subdomain("mytest1", "user2", &limits);
        assert!(matches!(result, Err(DomainError::AlreadyReserved(_))));
    }
    
    #[test]
    fn test_domain_limits() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits {
            max_subdomains: 2,
            ..Default::default()
        };
        
        manager.reserve_subdomain("testaa1", "user1", &limits).unwrap();
        manager.reserve_subdomain("testaa2", "user1", &limits).unwrap();
        
        let result = manager.reserve_subdomain("testaa3", "user1", &limits);
        assert!(matches!(result, Err(DomainError::LimitReached)));
    }
    
    #[test]
    fn test_custom_domain_reservation() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::pro();
        
        let result = manager.reserve_custom_domain("api.example.com", "user1", &limits);
        assert!(result.is_ok());
        
        let domain = result.unwrap();
        assert_eq!(domain.status, VerificationStatus::Pending);
        assert!(domain.verification_token.is_some());
    }
    
    #[test]
    fn test_release_domain() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default();
        
        let domain = manager.reserve_subdomain("torelease", "user1", &limits).unwrap();
        assert!(manager.get_domain(&domain.id).is_some());
        
        manager.release_domain(&domain.id, "user1").unwrap();
        assert!(manager.get_domain(&domain.id).is_none());
    }
    
    #[test]
    fn test_release_not_owner() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        let limits = DomainLimits::default();
        
        let domain = manager.reserve_subdomain("mydom123", "user1", &limits).unwrap();
        
        let result = manager.release_domain(&domain.id, "user2");
        assert!(matches!(result, Err(DomainError::NotOwner)));
    }
    
    #[test]
    fn test_wildcard_matching() {
        let manager = DomainManager::new("nlag.io", "edge.nlag.io");
        
        // Manually insert a wildcard domain
        let wildcard = ReservedDomain {
            id: "wildcard1".to_string(),
            domain: "*.example.com".to_string(),
            user_id: "user1".to_string(),
            domain_type: DomainType::Wildcard,
            status: VerificationStatus::Verified,
            verification_token: None,
            cname_target: None,
            created_at: Utc::now(),
            expires_at: None,
            last_verified_at: Some(Utc::now()),
            active_tunnel_id: Some("tunnel1".to_string()),
            certificate_id: None,
            metadata: HashMap::new(),
        };
        
        manager.domains.insert(wildcard.id.clone(), wildcard.clone());
        manager.domain_index.insert(wildcard.domain.clone(), wildcard.id.clone());
        
        // Test wildcard match
        let found = manager.find_domain_for_request("api.example.com");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "wildcard1");
    }
}
