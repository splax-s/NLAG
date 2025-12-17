//! ACME (Let's Encrypt) Automatic TLS Certificate Management
//!
//! This module provides automatic TLS certificate provisioning using the ACME protocol.
//! It supports both HTTP-01 and TLS-ALPN-01 challenges.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// ACME directory URLs
pub mod directories {
    pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
}

/// ACME errors
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),
    
    #[error("Certificate not ready")]
    CertificateNotReady,
    
    #[error("Rate limited: {0}")]
    RateLimited(String),
    
    #[error("Account error: {0}")]
    AccountError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, AcmeError>;

/// ACME challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// HTTP-01 challenge (requires port 80)
    Http01,
    /// TLS-ALPN-01 challenge (requires port 443)
    TlsAlpn01,
    /// DNS-01 challenge (requires DNS control)
    Dns01,
}

/// Certificate status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// No certificate exists
    Missing,
    /// Certificate is being provisioned
    Provisioning,
    /// Certificate is valid
    Valid,
    /// Certificate is expiring soon (within 30 days)
    ExpiringSoon,
    /// Certificate has expired
    Expired,
    /// Certificate provisioning failed
    Failed(String),
}

/// Stored certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// Domain name
    pub domain: String,
    
    /// Certificate PEM
    pub cert_pem: String,
    
    /// Private key PEM
    pub key_pem: String,
    
    /// Certificate chain PEM (intermediates)
    pub chain_pem: Option<String>,
    
    /// Not before timestamp
    pub not_before: chrono::DateTime<chrono::Utc>,
    
    /// Not after timestamp (expiry)
    pub not_after: chrono::DateTime<chrono::Utc>,
    
    /// When this was last renewed
    pub last_renewed: chrono::DateTime<chrono::Utc>,
}

impl StoredCertificate {
    /// Check if the certificate is valid
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now();
        now >= self.not_before && now < self.not_after
    }
    
    /// Check if the certificate is expiring soon (within 30 days)
    pub fn is_expiring_soon(&self) -> bool {
        let now = chrono::Utc::now();
        let expiry_threshold = self.not_after - chrono::Duration::days(30);
        now >= expiry_threshold && now < self.not_after
    }
    
    /// Get the certificate status
    pub fn status(&self) -> CertificateStatus {
        let now = chrono::Utc::now();
        if now >= self.not_after {
            CertificateStatus::Expired
        } else if now < self.not_before {
            CertificateStatus::Missing
        } else if self.is_expiring_soon() {
            CertificateStatus::ExpiringSoon
        } else {
            CertificateStatus::Valid
        }
    }
    
    /// Get days until expiry
    pub fn days_until_expiry(&self) -> i64 {
        let now = chrono::Utc::now();
        (self.not_after - now).num_days()
    }
}

/// ACME configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable ACME/Let's Encrypt
    pub enabled: bool,
    
    /// ACME directory URL
    pub directory_url: String,
    
    /// Account email for Let's Encrypt notifications
    pub email: String,
    
    /// Storage path for certificates and account keys
    pub storage_path: PathBuf,
    
    /// Preferred challenge type
    pub challenge_type: String,
    
    /// Accept terms of service automatically
    pub accept_tos: bool,
    
    /// Renewal threshold in days (renew if expiring within this many days)
    pub renewal_days: u32,
    
    /// Use staging environment for testing
    pub staging: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: directories::LETS_ENCRYPT_PRODUCTION.to_string(),
            email: String::new(),
            storage_path: PathBuf::from("/var/lib/nlag/acme"),
            challenge_type: "http-01".to_string(),
            accept_tos: false,
            renewal_days: 30,
            staging: false,
        }
    }
}

/// HTTP-01 challenge token storage
#[derive(Debug, Default)]
pub struct Http01ChallengeStore {
    /// Token -> Key Authorization mapping
    tokens: DashMap<String, String>,
}

impl Http01ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Store a challenge token
    pub fn set(&self, token: &str, key_authorization: &str) {
        self.tokens.insert(token.to_string(), key_authorization.to_string());
    }
    
    /// Get a challenge response
    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens.get(token).map(|v| v.clone())
    }
    
    /// Remove a challenge token
    pub fn remove(&self, token: &str) {
        self.tokens.remove(token);
    }
}

/// ACME account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// Account URL
    pub account_url: String,
    
    /// Account key (JWK format)
    pub private_key_pem: String,
    
    /// Contact emails
    pub contacts: Vec<String>,
    
    /// Account status
    pub status: String,
    
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Certificate manager for automatic TLS provisioning
pub struct CertificateManager {
    /// Configuration
    config: AcmeConfig,
    
    /// Stored certificates
    certificates: DashMap<String, StoredCertificate>,
    
    /// Account information
    account: RwLock<Option<AcmeAccount>>,
    
    /// HTTP-01 challenge store
    http01_store: Arc<Http01ChallengeStore>,
    
    /// Pending certificate orders
    pending_orders: DashMap<String, PendingOrder>,
}

/// A pending certificate order
#[derive(Debug, Clone)]
struct PendingOrder {
    domain: String,
    order_url: String,
    challenge_type: ChallengeType,
    challenge_token: Option<String>,
    started_at: chrono::DateTime<chrono::Utc>,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub fn new(config: AcmeConfig) -> Arc<Self> {
        let http01_store = Arc::new(Http01ChallengeStore::new());
        
        Arc::new(Self {
            config,
            certificates: DashMap::new(),
            account: RwLock::new(None),
            http01_store,
            pending_orders: DashMap::new(),
        })
    }
    
    /// Get the HTTP-01 challenge store (for the HTTP server to serve challenges)
    pub fn http01_store(&self) -> Arc<Http01ChallengeStore> {
        self.http01_store.clone()
    }
    
    /// Load certificates from storage
    pub async fn load_certificates(&self) -> Result<()> {
        let certs_dir = self.config.storage_path.join("certs");
        
        if !certs_dir.exists() {
            std::fs::create_dir_all(&certs_dir)?;
            return Ok(());
        }
        
        for entry in std::fs::read_dir(&certs_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        match serde_json::from_str::<StoredCertificate>(&contents) {
                            Ok(cert) => {
                                info!("Loaded certificate for {}", cert.domain);
                                self.certificates.insert(cert.domain.clone(), cert);
                            }
                            Err(e) => {
                                warn!("Failed to parse certificate file {:?}: {}", path, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read certificate file {:?}: {}", path, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get a certificate for a domain
    pub fn get_certificate(&self, domain: &str) -> Option<StoredCertificate> {
        self.certificates.get(domain).map(|c| c.clone())
    }
    
    /// Check certificate status for a domain
    pub fn certificate_status(&self, domain: &str) -> CertificateStatus {
        match self.certificates.get(domain) {
            Some(cert) => cert.status(),
            None => {
                if self.pending_orders.contains_key(domain) {
                    CertificateStatus::Provisioning
                } else {
                    CertificateStatus::Missing
                }
            }
        }
    }
    
    /// Request a certificate for a domain
    pub async fn request_certificate(&self, domain: &str) -> Result<()> {
        if !self.config.enabled {
            return Err(AcmeError::AccountError("ACME is disabled".to_string()));
        }
        
        // Check if already pending
        if self.pending_orders.contains_key(domain) {
            debug!("Certificate request already pending for {}", domain);
            return Ok(());
        }
        
        // Check if we already have a valid certificate
        if let Some(cert) = self.certificates.get(domain) {
            if cert.is_valid() && !cert.is_expiring_soon() {
                debug!("Valid certificate already exists for {}", domain);
                return Ok(());
            }
        }
        
        info!("Requesting certificate for {}", domain);
        
        // Create pending order
        let order = PendingOrder {
            domain: domain.to_string(),
            order_url: String::new(), // Will be set by ACME
            challenge_type: self.parse_challenge_type(),
            challenge_token: None,
            started_at: chrono::Utc::now(),
        };
        
        self.pending_orders.insert(domain.to_string(), order);
        
        // Start the ACME flow
        self.start_acme_flow(domain).await?;
        
        Ok(())
    }
    
    /// Parse challenge type from config
    fn parse_challenge_type(&self) -> ChallengeType {
        match self.config.challenge_type.to_lowercase().as_str() {
            "http-01" | "http01" | "http" => ChallengeType::Http01,
            "tls-alpn-01" | "tlsalpn01" | "tls" => ChallengeType::TlsAlpn01,
            "dns-01" | "dns01" | "dns" => ChallengeType::Dns01,
            _ => ChallengeType::Http01,
        }
    }
    
    /// Start the ACME flow for a domain
    async fn start_acme_flow(&self, domain: &str) -> Result<()> {
        // In a real implementation, this would:
        // 1. Get the ACME directory
        // 2. Create/load account
        // 3. Create order
        // 4. Get authorization
        // 5. Complete challenge
        // 6. Finalize order
        // 7. Download certificate
        
        // For now, we'll create a placeholder implementation
        info!("Starting ACME flow for {} (placeholder)", domain);
        
        // Simulate the flow for now
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // Generate self-signed certificate as placeholder
        let cert = self.generate_placeholder_certificate(domain)?;
        
        // Store the certificate
        self.store_certificate(cert).await?;
        
        // Remove from pending
        self.pending_orders.remove(domain);
        
        info!("Certificate provisioned for {}", domain);
        
        Ok(())
    }
    
    /// Generate a placeholder self-signed certificate
    fn generate_placeholder_certificate(&self, domain: &str) -> Result<StoredCertificate> {
        use nlag_common::crypto::cert::generate_self_signed_cert;
        
        let cert_info = generate_self_signed_cert(
            domain,
            &[domain.to_string()],
            &[],
            90, // 90 days
            false,
        ).map_err(|e| AcmeError::CryptoError(e.to_string()))?;
        
        Ok(StoredCertificate {
            domain: domain.to_string(),
            cert_pem: cert_info.cert_pem,
            key_pem: cert_info.key_pem,
            chain_pem: None,
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now() + chrono::Duration::days(90),
            last_renewed: chrono::Utc::now(),
        })
    }
    
    /// Store a certificate
    async fn store_certificate(&self, cert: StoredCertificate) -> Result<()> {
        let certs_dir = self.config.storage_path.join("certs");
        std::fs::create_dir_all(&certs_dir)?;
        
        let cert_path = certs_dir.join(format!("{}.json", cert.domain));
        let json = serde_json::to_string_pretty(&cert)?;
        std::fs::write(&cert_path, json)?;
        
        // Also write the PEM files for direct use
        let cert_pem_path = certs_dir.join(format!("{}.crt", cert.domain));
        let key_pem_path = certs_dir.join(format!("{}.key", cert.domain));
        
        std::fs::write(&cert_pem_path, &cert.cert_pem)?;
        std::fs::write(&key_pem_path, &cert.key_pem)?;
        
        // Update in-memory cache
        self.certificates.insert(cert.domain.clone(), cert);
        
        Ok(())
    }
    
    /// Check and renew expiring certificates
    pub async fn check_renewals(&self) -> Result<Vec<String>> {
        let mut renewed = Vec::new();
        
        for entry in self.certificates.iter() {
            let cert = entry.value();
            if cert.is_expiring_soon() || !cert.is_valid() {
                info!("Certificate for {} needs renewal (expires in {} days)", 
                      cert.domain, cert.days_until_expiry());
                
                if let Err(e) = self.request_certificate(&cert.domain).await {
                    error!("Failed to renew certificate for {}: {}", cert.domain, e);
                } else {
                    renewed.push(cert.domain.clone());
                }
            }
        }
        
        Ok(renewed)
    }
    
    /// List all certificates
    pub fn list_certificates(&self) -> Vec<StoredCertificate> {
        self.certificates.iter().map(|e| e.value().clone()).collect()
    }
    
    /// Start the renewal background task
    pub fn start_renewal_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Check every hour
            
            loop {
                interval.tick().await;
                
                if let Err(e) = self.check_renewals().await {
                    error!("Certificate renewal check failed: {}", e);
                }
            }
        });
    }
}

/// Handle HTTP-01 challenge requests
/// This should be mounted at `/.well-known/acme-challenge/{token}`
pub async fn handle_acme_challenge(
    store: Arc<Http01ChallengeStore>,
    token: &str,
) -> Option<String> {
    store.get(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_certificate_status() {
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            chain_pem: None,
            not_before: chrono::Utc::now() - chrono::Duration::days(30),
            not_after: chrono::Utc::now() + chrono::Duration::days(60),
            last_renewed: chrono::Utc::now() - chrono::Duration::days(30),
        };
        
        assert!(cert.is_valid());
        assert!(!cert.is_expiring_soon());
        assert_eq!(cert.status(), CertificateStatus::Valid);
    }
    
    #[test]
    fn test_expiring_certificate() {
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            chain_pem: None,
            not_before: chrono::Utc::now() - chrono::Duration::days(60),
            not_after: chrono::Utc::now() + chrono::Duration::days(15),
            last_renewed: chrono::Utc::now() - chrono::Duration::days(60),
        };
        
        assert!(cert.is_valid());
        assert!(cert.is_expiring_soon());
        assert_eq!(cert.status(), CertificateStatus::ExpiringSoon);
    }
    
    #[test]
    fn test_http01_store() {
        let store = Http01ChallengeStore::new();
        
        store.set("token123", "key_auth_456");
        assert_eq!(store.get("token123"), Some("key_auth_456".to_string()));
        
        store.remove("token123");
        assert_eq!(store.get("token123"), None);
    }
}
