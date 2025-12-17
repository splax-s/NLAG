//! Custom domain management
//!
//! Allows users to map their own domains to tunnels via:
//! - CNAME records pointing to the edge server
//! - DNS TXT record verification for ownership
//! - SNI-based routing for HTTPS traffic

#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use nlag_common::types::TunnelId;

/// Custom domain entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDomain {
    /// The custom domain (e.g., "api.mycompany.com")
    pub domain: String,

    /// The tunnel ID this domain routes to
    pub tunnel_id: TunnelId,

    /// Verification status
    pub verified: bool,

    /// Verification token (for DNS TXT record)
    pub verification_token: String,

    /// When the domain was added
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When verification was last checked
    pub last_verified_at: Option<chrono::DateTime<chrono::Utc>>,

    /// SSL/TLS certificate (PEM)
    pub tls_cert: Option<String>,

    /// SSL/TLS private key (PEM)
    pub tls_key: Option<String>,

    /// Whether to auto-provision TLS via ACME
    pub auto_tls: bool,
}

/// Result of domain verification
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Domain is verified
    Verified,
    /// Verification pending - token not found
    TokenNotFound,
    /// DNS lookup failed
    DnsError(String),
    /// Domain points to wrong target
    WrongTarget { expected: String, actual: String },
}

/// Custom domain manager
pub struct DomainManager {
    /// Custom domains by domain name
    domains: DashMap<String, CustomDomain>,

    /// Cache of domain -> tunnel_id for fast lookups
    routing_cache: DashMap<String, (TunnelId, Instant)>,

    /// Expected CNAME target for verification
    expected_cname_target: String,

    /// Cache TTL
    cache_ttl: Duration,
}

impl std::fmt::Debug for DomainManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainManager")
            .field("domains_count", &self.domains.len())
            .field("expected_cname_target", &self.expected_cname_target)
            .finish()
    }
}

impl DomainManager {
    /// Create a new domain manager
    pub fn new(expected_cname_target: String) -> Arc<Self> {
        Arc::new(Self {
            domains: DashMap::new(),
            routing_cache: DashMap::new(),
            expected_cname_target,
            cache_ttl: Duration::from_secs(300), // 5 minutes
        })
    }

    /// Register a custom domain
    pub fn register_domain(
        &self,
        domain: String,
        tunnel_id: TunnelId,
        auto_tls: bool,
    ) -> Result<CustomDomain, DomainError> {
        // Normalize domain
        let domain = domain.to_lowercase();

        // Check if already registered
        if self.domains.contains_key(&domain) {
            return Err(DomainError::AlreadyRegistered(domain));
        }

        // Generate verification token
        let verification_token = generate_verification_token();

        let custom_domain = CustomDomain {
            domain: domain.clone(),
            tunnel_id,
            verified: false,
            verification_token,
            created_at: chrono::Utc::now(),
            last_verified_at: None,
            tls_cert: None,
            tls_key: None,
            auto_tls,
        };

        self.domains.insert(domain.clone(), custom_domain.clone());
        info!("Registered custom domain: {}", domain);

        Ok(custom_domain)
    }

    /// Remove a custom domain
    pub fn remove_domain(&self, domain: &str) {
        let domain = domain.to_lowercase();
        if self.domains.remove(&domain).is_some() {
            self.routing_cache.remove(&domain);
            info!("Removed custom domain: {}", domain);
        }
    }

    /// Verify domain ownership via DNS TXT record
    pub async fn verify_domain(&self, domain: &str) -> Result<VerificationResult, DomainError> {
        let domain = domain.to_lowercase();

        let entry = self
            .domains
            .get(&domain)
            .ok_or_else(|| DomainError::NotFound(domain.clone()))?;

        let expected_token = entry.verification_token.clone();
        let tunnel_id = entry.tunnel_id;
        drop(entry); // Release lock before async DNS lookup

        // Check for TXT record
        let txt_record_name = format!("_nlag-verify.{}", domain);
        match dns_lookup_txt(&txt_record_name).await {
            Ok(records) => {
                let expected_value = format!("nlag-verify={}", expected_token);
                if records.iter().any(|r| r == &expected_value) {
                    // Token found - mark as verified
                    if let Some(mut entry) = self.domains.get_mut(&domain) {
                        entry.verified = true;
                        entry.last_verified_at = Some(chrono::Utc::now());
                    }

                    // Update routing cache
                    self.routing_cache
                        .insert(domain.clone(), (tunnel_id, Instant::now()));

                    info!("Domain {} verified successfully", domain);
                    Ok(VerificationResult::Verified)
                } else {
                    debug!(
                        "Domain {} verification failed: token not found in TXT records",
                        domain
                    );
                    Ok(VerificationResult::TokenNotFound)
                }
            }
            Err(e) => Ok(VerificationResult::DnsError(e)),
        }
    }

    /// Check CNAME record points to correct target
    pub async fn verify_cname(&self, domain: &str) -> Result<VerificationResult, DomainError> {
        let domain = domain.to_lowercase();

        match dns_lookup_cname(&domain).await {
            Ok(cname) => {
                if cname.trim_end_matches('.') == self.expected_cname_target {
                    Ok(VerificationResult::Verified)
                } else {
                    Ok(VerificationResult::WrongTarget {
                        expected: self.expected_cname_target.clone(),
                        actual: cname,
                    })
                }
            }
            Err(e) => Ok(VerificationResult::DnsError(e)),
        }
    }

    /// Look up tunnel ID for a domain (with caching)
    pub fn lookup_tunnel(&self, domain: &str) -> Option<TunnelId> {
        let domain = domain.to_lowercase();

        // Check cache first
        if let Some(entry) = self.routing_cache.get(&domain) {
            let (tunnel_id, cached_at) = entry.value();
            if cached_at.elapsed() < self.cache_ttl {
                return Some(*tunnel_id);
            }
        }

        // Check domain registry
        if let Some(entry) = self.domains.get(&domain) {
            if entry.verified {
                // Update cache
                self.routing_cache
                    .insert(domain.clone(), (entry.tunnel_id, Instant::now()));
                return Some(entry.tunnel_id);
            }
        }

        None
    }

    /// Get domain info
    pub fn get_domain(&self, domain: &str) -> Option<CustomDomain> {
        self.domains.get(&domain.to_lowercase()).map(|e| e.clone())
    }

    /// List all registered domains
    pub fn list_domains(&self) -> Vec<CustomDomain> {
        self.domains.iter().map(|e| e.value().clone()).collect()
    }

    /// Set TLS certificate for a domain
    pub fn set_tls_cert(
        &self,
        domain: &str,
        cert_pem: String,
        key_pem: String,
    ) -> Result<(), DomainError> {
        let domain = domain.to_lowercase();

        let mut entry = self
            .domains
            .get_mut(&domain)
            .ok_or_else(|| DomainError::NotFound(domain.clone()))?;

        entry.tls_cert = Some(cert_pem);
        entry.tls_key = Some(key_pem);

        info!("Updated TLS certificate for domain: {}", domain);
        Ok(())
    }

    /// Get TLS credentials for a domain (for SNI)
    pub fn get_tls_credentials(&self, domain: &str) -> Option<(String, String)> {
        let domain = domain.to_lowercase();

        self.domains.get(&domain).and_then(|entry| {
            match (&entry.tls_cert, &entry.tls_key) {
                (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
                _ => None,
            }
        })
    }
}

/// Errors that can occur during domain operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum DomainError {
    #[error("Domain already registered: {0}")]
    AlreadyRegistered(String),

    #[error("Domain not found: {0}")]
    NotFound(String),

    #[error("Domain not verified: {0}")]
    NotVerified(String),

    #[error("DNS lookup error: {0}")]
    DnsError(String),

    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),
}

/// Generate a random verification token
fn generate_verification_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

/// Look up TXT records for a domain
async fn dns_lookup_txt(domain: &str) -> Result<Vec<String>, String> {
    // Use hickory-dns (formerly trust-dns) for async DNS lookups
    // For now, use a simple sync lookup wrapped in spawn_blocking
    let domain = domain.to_string();

    tokio::task::spawn_blocking(move || {
        use std::process::Command;

        // Use dig for DNS lookup (works on macOS/Linux)
        let output = Command::new("dig")
            .args(["+short", "TXT", &domain])
            .output()
            .map_err(|e| format!("Failed to execute dig: {}", e))?;

        if !output.status.success() {
            return Err("dig command failed".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let records: Vec<String> = stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.trim_matches('"').to_string())
            .collect();

        Ok(records)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

/// Look up CNAME record for a domain
async fn dns_lookup_cname(domain: &str) -> Result<String, String> {
    let domain = domain.to_string();

    tokio::task::spawn_blocking(move || {
        use std::process::Command;

        let output = Command::new("dig")
            .args(["+short", "CNAME", &domain])
            .output()
            .map_err(|e| format!("Failed to execute dig: {}", e))?;

        if !output.status.success() {
            return Err("dig command failed".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| "No CNAME record found".to_string())
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_domain() {
        let manager = DomainManager::new("edge.example.com".to_string());
        let tunnel_id = TunnelId::new();

        let result = manager.register_domain("api.test.com".to_string(), tunnel_id, false);
        assert!(result.is_ok());

        let domain = result.unwrap();
        assert_eq!(domain.domain, "api.test.com");
        assert!(!domain.verified);
        assert!(!domain.verification_token.is_empty());
    }

    #[test]
    fn test_duplicate_domain() {
        let manager = DomainManager::new("edge.example.com".to_string());
        let tunnel_id = TunnelId::new();

        manager
            .register_domain("api.test.com".to_string(), tunnel_id, false)
            .unwrap();

        let result = manager.register_domain("api.test.com".to_string(), tunnel_id, false);
        assert!(matches!(result, Err(DomainError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_lookup_unverified() {
        let manager = DomainManager::new("edge.example.com".to_string());
        let tunnel_id = TunnelId::new();

        manager
            .register_domain("api.test.com".to_string(), tunnel_id, false)
            .unwrap();

        // Unverified domain should not be routable
        assert!(manager.lookup_tunnel("api.test.com").is_none());
    }

    #[test]
    fn test_domain_normalization() {
        let manager = DomainManager::new("edge.example.com".to_string());
        let tunnel_id = TunnelId::new();

        manager
            .register_domain("API.Test.COM".to_string(), tunnel_id, false)
            .unwrap();

        // Should be normalized to lowercase
        assert!(manager.get_domain("api.test.com").is_some());
    }
}
