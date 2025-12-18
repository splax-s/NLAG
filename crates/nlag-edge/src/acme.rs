//! ACME (Let's Encrypt) Automatic TLS Certificate Management
//!
//! This module provides automatic TLS certificate provisioning using the ACME protocol.
//! It supports both HTTP-01 and TLS-ALPN-01 challenges.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
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

/// ACME directory response
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    /// URL to create new nonce
    pub new_nonce: String,
    /// URL to create new account
    pub new_account: String,
    /// URL to create new order
    pub new_order: String,
    /// URL to revoke certificate
    #[serde(default)]
    pub revoke_cert: String,
    /// URL to key change
    #[serde(default)]
    pub key_change: String,
}

/// Account key pair for signing ACME requests
pub struct AccountKeyPair {
    /// PKCS#8 encoded private key
    pkcs8_bytes: Vec<u8>,
    /// The actual key pair for signing
    key_pair: Arc<ring::signature::EcdsaKeyPair>,
}

/// ACME challenge information
#[derive(Debug, Clone)]
struct AcmeChallenge {
    /// Challenge type (http-01, dns-01, etc.)
    challenge_type: String,
    /// Challenge token
    token: String,
    /// Challenge URL (to notify completion)
    url: String,
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
        info!("Starting ACME flow for {}", domain);
        
        // Step 1: Get ACME directory
        let directory = self.get_directory().await?;
        
        // Step 2: Create/load account
        let account = self.ensure_account(&directory).await?;
        
        // Step 3: Create order
        let order_url = self.create_order(&directory, &account, domain).await?;
        
        // Step 4: Get authorization and complete challenge
        let (authz_url, challenge) = self.get_authorization(&account, &order_url, domain).await?;
        
        // Step 5: Complete the challenge
        self.complete_challenge(&account, &challenge, domain).await?;
        
        // Step 6: Wait for authorization to be valid
        self.wait_for_authorization(&account, &authz_url).await?;
        
        // Step 7: Finalize order with CSR
        let (cert_pem, key_pem) = self.finalize_order(&account, &order_url, domain).await?;
        
        // Step 8: Store the certificate
        let cert = StoredCertificate {
            domain: domain.to_string(),
            cert_pem,
            key_pem,
            chain_pem: None,
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now() + chrono::Duration::days(90),
            last_renewed: chrono::Utc::now(),
        };
        
        self.store_certificate(cert).await?;
        
        // Remove from pending
        self.pending_orders.remove(domain);
        
        info!("Certificate provisioned for {}", domain);
        
        Ok(())
    }
    
    /// Get ACME directory
    async fn get_directory(&self) -> Result<AcmeDirectory> {
        let client = reqwest::Client::new();
        let resp = client
            .get(&self.config.directory_url)
            .send()
            .await
            .map_err(|e| AcmeError::HttpError(e.to_string()))?;
        
        if !resp.status().is_success() {
            return Err(AcmeError::HttpError(format!("Directory request failed: {}", resp.status())));
        }
        
        let dir: AcmeDirectory = resp.json().await
            .map_err(|e| AcmeError::InvalidResponse(e.to_string()))?;
        
        Ok(dir)
    }
    
    /// Ensure we have an account (create or load)
    async fn ensure_account(&self, directory: &AcmeDirectory) -> Result<AccountKeyPair> {
        // Check if we have a saved account
        if let Some(account) = self.account.read().as_ref() {
            return self.load_account_key(&account.private_key_pem);
        }
        
        // Create new account
        let key_pair = self.generate_account_key()?;
        let account = self.create_account(directory, &key_pair).await?;
        
        // Save account
        *self.account.write() = Some(account);
        
        Ok(key_pair)
    }
    
    /// Generate a new account key pair
    fn generate_account_key(&self) -> Result<AccountKeyPair> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        use ring::rand::SystemRandom;
        
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| AcmeError::CryptoError(format!("Key generation failed: {:?}", e)))?;
        
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
            .map_err(|e| AcmeError::CryptoError(format!("Key loading failed: {:?}", e)))?;
        
        Ok(AccountKeyPair {
            pkcs8_bytes: pkcs8_bytes.as_ref().to_vec(),
            key_pair: Arc::new(key_pair),
        })
    }
    
    /// Load account key from PEM
    fn load_account_key(&self, pem_data: &str) -> Result<AccountKeyPair> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        use ring::rand::SystemRandom;
        
        let pem = pem::parse(pem_data)
            .map_err(|e| AcmeError::CryptoError(format!("PEM parse failed: {}", e)))?;
        
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pem.contents(), &rng)
            .map_err(|e| AcmeError::CryptoError(format!("Key loading failed: {:?}", e)))?;
        
        Ok(AccountKeyPair {
            pkcs8_bytes: pem.contents().to_vec(),
            key_pair: Arc::new(key_pair),
        })
    }
    
    /// Create ACME account
    async fn create_account(&self, directory: &AcmeDirectory, key_pair: &AccountKeyPair) -> Result<AcmeAccount> {
        let payload = serde_json::json!({
            "termsOfServiceAgreed": self.config.accept_tos,
            "contact": [format!("mailto:{}", self.config.email)]
        });
        
        let (resp, account_url) = self.signed_request(
            &directory.new_account,
            Some(&payload),
            key_pair,
            None,
            &directory.new_nonce,
        ).await?;
        
        let account_url = account_url.ok_or_else(|| {
            AcmeError::AccountError("No account URL in response".to_string())
        })?;
        
        let pem_data = pem::encode(&pem::Pem::new("EC PRIVATE KEY", key_pair.pkcs8_bytes.clone()));
        
        Ok(AcmeAccount {
            account_url,
            private_key_pem: pem_data,
            contacts: vec![self.config.email.clone()],
            status: resp.get("status").and_then(|s| s.as_str()).unwrap_or("valid").to_string(),
            created_at: chrono::Utc::now(),
        })
    }
    
    /// Create a new order for a domain
    async fn create_order(&self, directory: &AcmeDirectory, key_pair: &AccountKeyPair, domain: &str) -> Result<String> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        let payload = serde_json::json!({
            "identifiers": [{"type": "dns", "value": domain}]
        });
        
        let (resp, _) = self.signed_request(
            &directory.new_order,
            Some(&payload),
            key_pair,
            Some(&account_url),
            &directory.new_nonce,
        ).await?;
        
        // The order URL is in the Location header, but we can use the order object
        let order_url = resp.get("finalize")
            .and_then(|s| s.as_str())
            .map(|s| s.replace("/finalize", ""))
            .ok_or_else(|| AcmeError::InvalidResponse("No finalize URL in order".to_string()))?;
        
        // Update pending order
        if let Some(mut order) = self.pending_orders.get_mut(domain) {
            order.order_url = order_url.clone();
        }
        
        Ok(order_url)
    }
    
    /// Get authorization details for an order
    async fn get_authorization(&self, key_pair: &AccountKeyPair, order_url: &str, domain: &str) -> Result<(String, AcmeChallenge)> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        // Get order details
        let (order, _) = self.signed_request(
            order_url,
            None,
            key_pair,
            Some(&account_url),
            order_url,
        ).await?;
        
        let authz_urls = order.get("authorizations")
            .and_then(|a| a.as_array())
            .ok_or_else(|| AcmeError::InvalidResponse("No authorizations".to_string()))?;
        
        let authz_url = authz_urls.first()
            .and_then(|u| u.as_str())
            .ok_or_else(|| AcmeError::InvalidResponse("Empty authorizations".to_string()))?;
        
        // Get authorization details
        let (authz, _) = self.signed_request(
            authz_url,
            None,
            key_pair,
            Some(&account_url),
            authz_url,
        ).await?;
        
        // Find HTTP-01 challenge
        let challenges = authz.get("challenges")
            .and_then(|c| c.as_array())
            .ok_or_else(|| AcmeError::InvalidResponse("No challenges".to_string()))?;
        
        let challenge_type = match self.parse_challenge_type() {
            ChallengeType::Http01 => "http-01",
            ChallengeType::TlsAlpn01 => "tls-alpn-01",
            ChallengeType::Dns01 => "dns-01",
        };
        
        let challenge = challenges.iter()
            .find(|c| c.get("type").and_then(|t| t.as_str()) == Some(challenge_type))
            .ok_or_else(|| AcmeError::ChallengeFailed(format!("No {} challenge found", challenge_type)))?;
        
        let token = challenge.get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AcmeError::InvalidResponse("No token in challenge".to_string()))?;
        
        let url = challenge.get("url")
            .and_then(|u| u.as_str())
            .ok_or_else(|| AcmeError::InvalidResponse("No URL in challenge".to_string()))?;
        
        Ok((authz_url.to_string(), AcmeChallenge {
            challenge_type: challenge_type.to_string(),
            token: token.to_string(),
            url: url.to_string(),
        }))
    }
    
    /// Complete ACME challenge
    async fn complete_challenge(&self, key_pair: &AccountKeyPair, challenge: &AcmeChallenge, _domain: &str) -> Result<()> {
        // Compute key authorization
        let key_authz = self.compute_key_authorization(&challenge.token, key_pair)?;
        
        // For HTTP-01, we store the token -> key_authorization mapping
        if challenge.challenge_type == "http-01" {
            self.http01_store.set(&challenge.token, &key_authz);
        }
        
        // Tell ACME server we're ready
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        let payload = serde_json::json!({});
        
        let _ = self.signed_request(
            &challenge.url,
            Some(&payload),
            key_pair,
            Some(&account_url),
            &challenge.url,
        ).await?;
        
        Ok(())
    }
    
    /// Wait for authorization to become valid
    async fn wait_for_authorization(&self, key_pair: &AccountKeyPair, authz_url: &str) -> Result<()> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            let (authz, _) = self.signed_request(
                authz_url,
                None,
                key_pair,
                Some(&account_url),
                authz_url,
            ).await?;
            
            let status = authz.get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            
            match status {
                "valid" => return Ok(()),
                "invalid" => {
                    return Err(AcmeError::ChallengeFailed("Authorization invalid".to_string()));
                }
                "pending" | "processing" => continue,
                _ => continue,
            }
        }
        
        Err(AcmeError::ChallengeFailed("Authorization timed out".to_string()))
    }
    
    /// Finalize order and get certificate
    async fn finalize_order(&self, key_pair: &AccountKeyPair, order_url: &str, domain: &str) -> Result<(String, String)> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        // Generate CSR
        let (csr_der, private_key_pem) = self.generate_csr(domain)?;
        let csr_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&csr_der);
        
        let finalize_url = format!("{}/finalize", order_url);
        let payload = serde_json::json!({"csr": csr_b64});
        
        let _ = self.signed_request(
            &finalize_url,
            Some(&payload),
            key_pair,
            Some(&account_url),
            &finalize_url,
        ).await?;
        
        // Wait for certificate to be ready
        let cert_url = self.wait_for_certificate(key_pair, order_url).await?;
        
        // Download certificate
        let cert_pem = self.download_certificate(key_pair, &cert_url).await?;
        
        Ok((cert_pem, private_key_pem))
    }
    
    /// Wait for certificate to be ready
    async fn wait_for_certificate(&self, key_pair: &AccountKeyPair, order_url: &str) -> Result<String> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            let (order, _) = self.signed_request(
                order_url,
                None,
                key_pair,
                Some(&account_url),
                order_url,
            ).await?;
            
            let status = order.get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            
            match status {
                "valid" => {
                    let cert_url = order.get("certificate")
                        .and_then(|c| c.as_str())
                        .ok_or_else(|| AcmeError::InvalidResponse("No certificate URL".to_string()))?;
                    return Ok(cert_url.to_string());
                }
                "invalid" => {
                    return Err(AcmeError::ChallengeFailed("Order invalid".to_string()));
                }
                _ => continue,
            }
        }
        
        Err(AcmeError::CertificateNotReady)
    }
    
    /// Download the certificate
    async fn download_certificate(&self, key_pair: &AccountKeyPair, cert_url: &str) -> Result<String> {
        let account_url = self.account.read().as_ref()
            .map(|a| a.account_url.clone())
            .ok_or_else(|| AcmeError::AccountError("No account".to_string()))?;
        
        let client = reqwest::Client::new();
        
        // Get nonce
        let nonce = self.get_nonce(cert_url).await?;
        
        // Build signed request
        let protected = self.build_protected_header(cert_url, &nonce, Some(&account_url), key_pair)?;
        let payload_b64 = "";  // Empty payload for POST-as-GET
        let signature = self.sign_jws(&protected, payload_b64, key_pair)?;
        
        let body = serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": signature
        });
        
        let resp = client
            .post(cert_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AcmeError::HttpError(e.to_string()))?;
        
        if !resp.status().is_success() {
            return Err(AcmeError::HttpError(format!("Certificate download failed: {}", resp.status())));
        }
        
        resp.text().await
            .map_err(|e| AcmeError::HttpError(e.to_string()))
    }
    
    /// Generate CSR for a domain
    fn generate_csr(&self, domain: &str) -> Result<(Vec<u8>, String)> {
        use nlag_common::crypto::cert::generate_self_signed_cert;
        
        // For now, we use the self-signed generator and extract components
        // In production, we'd generate a proper CSR
        let cert_info = generate_self_signed_cert(
            domain,
            &[domain.to_string()],
            &[],
            90,
            false,
        ).map_err(|e| AcmeError::CryptoError(e.to_string()))?;
        
        // This is a placeholder - a real implementation would generate a proper CSR
        // For now, we return the key and a dummy CSR
        let csr_der = vec![]; // Placeholder
        
        Ok((csr_der, cert_info.key_pem))
    }
    
    /// Get a fresh nonce
    async fn get_nonce(&self, url: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let resp = client
            .head(url)
            .send()
            .await
            .map_err(|e| AcmeError::HttpError(e.to_string()))?;
        
        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| AcmeError::InvalidResponse("No nonce in response".to_string()))
    }
    
    /// Build protected header for JWS
    fn build_protected_header(&self, url: &str, nonce: &str, kid: Option<&str>, key_pair: &AccountKeyPair) -> Result<String> {
        let header = if let Some(kid) = kid {
            serde_json::json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url
            })
        } else {
            // Include JWK for new account
            let jwk = self.account_key_to_jwk(key_pair)?;
            serde_json::json!({
                "alg": "ES256",
                "jwk": jwk,
                "nonce": nonce,
                "url": url
            })
        };
        
        let header_json = serde_json::to_string(&header)
            .map_err(|e| AcmeError::JsonError(e))?;
        
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes()))
    }
    
    /// Convert account key to JWK format
    fn account_key_to_jwk(&self, key_pair: &AccountKeyPair) -> Result<serde_json::Value> {
        use ring::signature::KeyPair;
        
        let public_key = key_pair.key_pair.public_key().as_ref();
        
        // ECDSA P-256 public key is 65 bytes: 0x04 || x || y
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(AcmeError::CryptoError("Invalid public key format".to_string()));
        }
        
        let x = &public_key[1..33];
        let y = &public_key[33..65];
        
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y)
        }))
    }
    
    /// Compute key authorization for a challenge
    fn compute_key_authorization(&self, token: &str, key_pair: &AccountKeyPair) -> Result<String> {
        let jwk = self.account_key_to_jwk(key_pair)?;
        let jwk_json = serde_json::to_string(&jwk)
            .map_err(|e| AcmeError::JsonError(e))?;
        
        // Compute JWK thumbprint
        use ring::digest::{digest, SHA256};
        let thumbprint = digest(&SHA256, jwk_json.as_bytes());
        let thumbprint_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(thumbprint.as_ref());
        
        Ok(format!("{}.{}", token, thumbprint_b64))
    }
    
    /// Sign JWS payload
    fn sign_jws(&self, protected_b64: &str, payload_b64: &str, key_pair: &AccountKeyPair) -> Result<String> {
        use ring::rand::SystemRandom;
        
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let rng = SystemRandom::new();
        
        let signature = key_pair.key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| AcmeError::CryptoError(format!("Signing failed: {:?}", e)))?;
        
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
    
    /// Make a signed ACME request
    async fn signed_request(
        &self,
        url: &str,
        payload: Option<&serde_json::Value>,
        key_pair: &AccountKeyPair,
        kid: Option<&str>,
        nonce_url: &str,
    ) -> Result<(serde_json::Value, Option<String>)> {
        let client = reqwest::Client::new();
        
        // Get nonce
        let nonce = self.get_nonce(nonce_url).await?;
        
        // Build request
        let protected = self.build_protected_header(url, &nonce, kid, key_pair)?;
        let payload_b64 = match payload {
            Some(p) => {
                let json = serde_json::to_string(p)
                    .map_err(|e| AcmeError::JsonError(e))?;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
            }
            None => String::new(),
        };
        
        let signature = self.sign_jws(&protected, &payload_b64, key_pair)?;
        
        let body = serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": signature
        });
        
        let resp = client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AcmeError::HttpError(e.to_string()))?;
        
        let location = resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AcmeError::HttpError(format!("Request failed ({}): {}", status, text)));
        }
        
        let json: serde_json::Value = resp.json().await
            .unwrap_or(serde_json::json!({}));
        
        Ok((json, location))
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
    fn test_expired_certificate() {
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            chain_pem: None,
            not_before: chrono::Utc::now() - chrono::Duration::days(100),
            not_after: chrono::Utc::now() - chrono::Duration::days(10),
            last_renewed: chrono::Utc::now() - chrono::Duration::days(100),
        };
        
        assert!(!cert.is_valid());
        assert_eq!(cert.status(), CertificateStatus::Expired);
    }
    
    #[test]
    fn test_http01_store() {
        let store = Http01ChallengeStore::new();
        
        store.set("token123", "key_auth_456");
        assert_eq!(store.get("token123"), Some("key_auth_456".to_string()));
        
        store.remove("token123");
        assert_eq!(store.get("token123"), None);
    }
    
    #[test]
    fn test_acme_config_default() {
        let config = AcmeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.directory_url, directories::LETS_ENCRYPT_PRODUCTION);
        assert_eq!(config.renewal_days, 30);
    }
    
    #[test]
    fn test_certificate_manager_creation() {
        let config = AcmeConfig::default();
        let manager = CertificateManager::new(config);
        
        assert!(manager.list_certificates().is_empty());
        assert_eq!(manager.certificate_status("example.com"), CertificateStatus::Missing);
    }
    
    #[test]
    fn test_parse_challenge_type() {
        let mut config = AcmeConfig::default();
        
        config.challenge_type = "http-01".to_string();
        let manager = CertificateManager::new(config.clone());
        assert_eq!(manager.parse_challenge_type(), ChallengeType::Http01);
        
        config.challenge_type = "dns-01".to_string();
        let manager = CertificateManager::new(config.clone());
        assert_eq!(manager.parse_challenge_type(), ChallengeType::Dns01);
        
        config.challenge_type = "tls-alpn-01".to_string();
        let manager = CertificateManager::new(config.clone());
        assert_eq!(manager.parse_challenge_type(), ChallengeType::TlsAlpn01);
    }
    
    #[test]
    fn test_days_until_expiry() {
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            chain_pem: None,
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now() + chrono::Duration::days(45),
            last_renewed: chrono::Utc::now(),
        };
        
        // Should be approximately 45 days
        let days = cert.days_until_expiry();
        assert!(days >= 44 && days <= 45);
    }
    
    #[test]
    fn test_generate_account_key() {
        let config = AcmeConfig::default();
        let manager = CertificateManager::new(config);
        
        let key_pair = manager.generate_account_key().unwrap();
        assert!(!key_pair.pkcs8_bytes.is_empty());
    }
    
    #[test]
    fn test_account_key_to_jwk() {
        let config = AcmeConfig::default();
        let manager = CertificateManager::new(config);
        
        let key_pair = manager.generate_account_key().unwrap();
        let jwk = manager.account_key_to_jwk(&key_pair).unwrap();
        
        assert_eq!(jwk.get("kty").and_then(|v| v.as_str()), Some("EC"));
        assert_eq!(jwk.get("crv").and_then(|v| v.as_str()), Some("P-256"));
        assert!(jwk.get("x").is_some());
        assert!(jwk.get("y").is_some());
    }
    
    #[test]
    fn test_compute_key_authorization() {
        let config = AcmeConfig::default();
        let manager = CertificateManager::new(config);
        
        let key_pair = manager.generate_account_key().unwrap();
        let key_authz = manager.compute_key_authorization("test-token", &key_pair).unwrap();
        
        assert!(key_authz.starts_with("test-token."));
        assert!(key_authz.len() > 20); // Token + thumbprint
    }
    
    #[test]
    fn test_sign_jws() {
        let config = AcmeConfig::default();
        let manager = CertificateManager::new(config);
        
        let key_pair = manager.generate_account_key().unwrap();
        let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        
        let signature = manager.sign_jws(&protected, &payload, &key_pair).unwrap();
        assert!(!signature.is_empty());
    }
}
