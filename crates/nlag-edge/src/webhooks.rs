//! Webhook Verification Module
//!
//! Validates incoming webhooks from popular services:
//! - GitHub (HMAC-SHA256)
//! - Stripe (HMAC-SHA256 with timestamp)
//! - Slack (HMAC-SHA256 with timestamp)
//! - Twilio (HMAC-SHA1)
//! - Shopify (HMAC-SHA256)
//! - Discord (Ed25519)
//! - Custom HMAC-based signatures

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::KeyInit};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Webhook provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookProvider {
    /// GitHub webhooks
    GitHub,
    /// Stripe webhooks
    Stripe,
    /// Slack webhooks
    Slack,
    /// Twilio webhooks
    Twilio,
    /// Shopify webhooks
    Shopify,
    /// Discord interactions
    Discord,
    /// Generic HMAC-SHA256
    HmacSha256,
    /// Generic HMAC-SHA1
    HmacSha1,
    /// Custom verification (user-defined)
    Custom,
}

impl std::fmt::Display for WebhookProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookProvider::GitHub => write!(f, "github"),
            WebhookProvider::Stripe => write!(f, "stripe"),
            WebhookProvider::Slack => write!(f, "slack"),
            WebhookProvider::Twilio => write!(f, "twilio"),
            WebhookProvider::Shopify => write!(f, "shopify"),
            WebhookProvider::Discord => write!(f, "discord"),
            WebhookProvider::HmacSha256 => write!(f, "hmac-sha256"),
            WebhookProvider::HmacSha1 => write!(f, "hmac-sha1"),
            WebhookProvider::Custom => write!(f, "custom"),
        }
    }
}

/// Webhook verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Provider type
    pub provider: WebhookProvider,
    /// Secret key for signature verification
    pub secret: String,
    /// Header name for signature (provider-specific default if not set)
    pub signature_header: Option<String>,
    /// Header name for timestamp (if applicable)
    pub timestamp_header: Option<String>,
    /// Maximum age of webhook in seconds (default: 300)
    pub max_age_secs: Option<u64>,
    /// Whether verification is enabled
    pub enabled: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            provider: WebhookProvider::HmacSha256,
            secret: String::new(),
            signature_header: None,
            timestamp_header: None,
            max_age_secs: Some(300),
            enabled: true,
        }
    }
}

/// Result of webhook verification
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Webhook is valid
    Valid,
    /// Signature is invalid
    InvalidSignature,
    /// Timestamp is too old
    ExpiredTimestamp,
    /// Missing required header
    MissingHeader(String),
    /// Invalid header format
    InvalidFormat(String),
    /// Verification error
    Error(String),
    /// Verification disabled
    Disabled,
}

impl VerificationResult {
    /// Check if verification passed
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid | VerificationResult::Disabled)
    }
}

/// Webhook verifier
pub struct WebhookVerifier {
    /// Configurations by tunnel and path
    configs: RwLock<HashMap<String, WebhookConfig>>,
}

impl WebhookVerifier {
    /// Create a new webhook verifier
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
        }
    }

    /// Add a webhook configuration
    /// Key format: "tunnel_id:path" or just "tunnel_id" for all paths
    pub fn add_config(&self, key: &str, config: WebhookConfig) {
        self.configs.write().insert(key.to_string(), config);
    }

    /// Remove a webhook configuration
    pub fn remove_config(&self, key: &str) {
        self.configs.write().remove(key);
    }

    /// Get a webhook configuration
    pub fn get_config(&self, tunnel_id: &str, path: &str) -> Option<WebhookConfig> {
        let configs = self.configs.read();
        
        // Try exact match first: tunnel_id:path
        let exact_key = format!("{}:{}", tunnel_id, path);
        if let Some(config) = configs.get(&exact_key) {
            return Some(config.clone());
        }
        
        // Try path prefix match
        for (key, config) in configs.iter() {
            if key.starts_with(&format!("{}:", tunnel_id)) {
                let pattern = key.strip_prefix(&format!("{}:", tunnel_id)).unwrap();
                if path.starts_with(pattern) {
                    return Some(config.clone());
                }
            }
        }
        
        // Try tunnel-wide config
        if let Some(config) = configs.get(tunnel_id) {
            return Some(config.clone());
        }
        
        None
    }

    /// Verify a webhook request
    pub fn verify(
        &self,
        tunnel_id: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let config = match self.get_config(tunnel_id, path) {
            Some(c) => c,
            None => return VerificationResult::Valid, // No config = no verification needed
        };

        if !config.enabled {
            return VerificationResult::Disabled;
        }

        match config.provider {
            WebhookProvider::GitHub => self.verify_github(&config, headers, body),
            WebhookProvider::Stripe => self.verify_stripe(&config, headers, body),
            WebhookProvider::Slack => self.verify_slack(&config, headers, body),
            WebhookProvider::Twilio => self.verify_twilio(&config, headers, body),
            WebhookProvider::Shopify => self.verify_shopify(&config, headers, body),
            WebhookProvider::Discord => self.verify_discord(&config, headers, body),
            WebhookProvider::HmacSha256 => self.verify_hmac_sha256(&config, headers, body),
            WebhookProvider::HmacSha1 => self.verify_hmac_sha1(&config, headers, body),
            WebhookProvider::Custom => VerificationResult::Valid, // Custom logic handled externally
        }
    }

    /// Verify GitHub webhook
    /// Header: X-Hub-Signature-256
    /// Format: sha256=<hex>
    fn verify_github(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("x-hub-signature-256");
        
        let signature = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        let signature = match signature.strip_prefix("sha256=") {
            Some(s) => s,
            None => return VerificationResult::InvalidFormat("Expected sha256= prefix".to_string()),
        };

        self.verify_hmac_signature::<HmacSha256>(&config.secret, body, signature)
    }

    /// Verify Stripe webhook
    /// Header: Stripe-Signature
    /// Format: t=<timestamp>,v1=<signature>
    fn verify_stripe(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("stripe-signature");
        
        let signature_header = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        // Parse Stripe signature format: t=timestamp,v1=signature
        let mut timestamp: Option<u64> = None;
        let mut signature: Option<&str> = None;

        for part in signature_header.split(',') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("t"), Some(t)) => timestamp = t.parse().ok(),
                (Some("v1"), Some(s)) => signature = Some(s),
                _ => {}
            }
        }

        let timestamp = match timestamp {
            Some(t) => t,
            None => return VerificationResult::InvalidFormat("Missing timestamp (t=)".to_string()),
        };

        let signature = match signature {
            Some(s) => s,
            None => return VerificationResult::InvalidFormat("Missing signature (v1=)".to_string()),
        };

        // Check timestamp age
        if let Some(max_age) = config.max_age_secs {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if now.saturating_sub(timestamp) > max_age {
                return VerificationResult::ExpiredTimestamp;
            }
        }

        // Stripe signs: timestamp + "." + body
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(body));
        self.verify_hmac_signature::<HmacSha256>(&config.secret, signed_payload.as_bytes(), signature)
    }

    /// Verify Slack webhook
    /// Headers: X-Slack-Signature, X-Slack-Request-Timestamp
    /// Format: v0=<signature>
    fn verify_slack(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let sig_header = config.signature_header
            .as_deref()
            .unwrap_or("x-slack-signature");
        let ts_header = config.timestamp_header
            .as_deref()
            .unwrap_or("x-slack-request-timestamp");

        let signature = match headers.get(sig_header) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(sig_header.to_string()),
        };

        let timestamp = match headers.get(ts_header) {
            Some(t) => t,
            None => return VerificationResult::MissingHeader(ts_header.to_string()),
        };

        let signature = match signature.strip_prefix("v0=") {
            Some(s) => s,
            None => return VerificationResult::InvalidFormat("Expected v0= prefix".to_string()),
        };

        // Check timestamp age
        if let Some(max_age) = config.max_age_secs {
            if let Ok(ts) = timestamp.parse::<u64>() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                if now.saturating_sub(ts) > max_age {
                    return VerificationResult::ExpiredTimestamp;
                }
            }
        }

        // Slack signs: "v0:" + timestamp + ":" + body
        let base_string = format!("v0:{}:{}", timestamp, String::from_utf8_lossy(body));
        self.verify_hmac_signature::<HmacSha256>(&config.secret, base_string.as_bytes(), signature)
    }

    /// Verify Twilio webhook (HMAC-SHA1)
    /// Header: X-Twilio-Signature
    fn verify_twilio(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("x-twilio-signature");
        
        let signature = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        // Twilio uses base64-encoded HMAC-SHA1
        self.verify_hmac_signature_base64::<HmacSha1>(&config.secret, body, signature)
    }

    /// Verify Shopify webhook
    /// Header: X-Shopify-Hmac-Sha256
    fn verify_shopify(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("x-shopify-hmac-sha256");
        
        let signature = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        // Shopify uses base64-encoded HMAC-SHA256
        self.verify_hmac_signature_base64::<HmacSha256>(&config.secret, body, signature)
    }

    /// Verify Discord interaction (Ed25519)
    /// Headers: X-Signature-Ed25519, X-Signature-Timestamp
    fn verify_discord(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let sig_header = config.signature_header
            .as_deref()
            .unwrap_or("x-signature-ed25519");
        let ts_header = config.timestamp_header
            .as_deref()
            .unwrap_or("x-signature-timestamp");

        let signature = match headers.get(sig_header) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(sig_header.to_string()),
        };

        let timestamp = match headers.get(ts_header) {
            Some(t) => t,
            None => return VerificationResult::MissingHeader(ts_header.to_string()),
        };

        // Discord signs: timestamp + body
        let message = format!("{}{}", timestamp, String::from_utf8_lossy(body));
        
        // Decode public key and signature from hex
        let public_key_bytes = match hex::decode(&config.secret) {
            Ok(b) if b.len() == 32 => b,
            _ => return VerificationResult::InvalidFormat("Invalid public key (expected 32-byte hex)".to_string()),
        };

        let signature_bytes = match hex::decode(signature) {
            Ok(b) if b.len() == 64 => b,
            _ => return VerificationResult::InvalidFormat("Invalid signature (expected 64-byte hex)".to_string()),
        };

        // Use ed25519-dalek for verification
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        
        let pk_array: [u8; 32] = match public_key_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return VerificationResult::InvalidFormat("Invalid public key length".to_string()),
        };
        
        let public_key = match VerifyingKey::from_bytes(&pk_array) {
            Ok(pk) => pk,
            Err(_) => return VerificationResult::InvalidFormat("Invalid Ed25519 public key".to_string()),
        };

        let sig_array: [u8; 64] = match signature_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return VerificationResult::InvalidFormat("Invalid signature length".to_string()),
        };
        
        let sig = Signature::from_bytes(&sig_array);

        match public_key.verify(message.as_bytes(), &sig) {
            Ok(_) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }

    /// Verify generic HMAC-SHA256
    fn verify_hmac_sha256(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("x-signature");
        
        let signature = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        self.verify_hmac_signature::<HmacSha256>(&config.secret, body, signature)
    }

    /// Verify generic HMAC-SHA1
    fn verify_hmac_sha1(
        &self,
        config: &WebhookConfig,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> VerificationResult {
        let header_name = config.signature_header
            .as_deref()
            .unwrap_or("x-signature");
        
        let signature = match headers.get(header_name) {
            Some(s) => s,
            None => return VerificationResult::MissingHeader(header_name.to_string()),
        };

        self.verify_hmac_signature::<HmacSha1>(&config.secret, body, signature)
    }

    /// Verify HMAC signature (hex-encoded)
    fn verify_hmac_signature<M>(&self, secret: &str, data: &[u8], signature: &str) -> VerificationResult
    where
        M: Mac + KeyInit,
    {
        let expected = match hex::decode(signature) {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat("Invalid hex signature".to_string()),
        };

        let mut mac = match <M as KeyInit>::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return VerificationResult::Error("Invalid secret key".to_string()),
        };

        mac.update(data);
        
        match mac.verify_slice(&expected) {
            Ok(_) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }

    /// Verify HMAC signature (base64-encoded)
    fn verify_hmac_signature_base64<M>(&self, secret: &str, data: &[u8], signature: &str) -> VerificationResult
    where
        M: Mac + KeyInit,
    {
        use base64::{Engine, engine::general_purpose::STANDARD};
        
        let expected = match STANDARD.decode(signature) {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat("Invalid base64 signature".to_string()),
        };

        let mut mac = match <M as KeyInit>::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return VerificationResult::Error("Invalid secret key".to_string()),
        };

        mac.update(data);
        
        match mac.verify_slice(&expected) {
            Ok(_) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }
}

impl Default for WebhookVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe webhook verifier
pub type SharedWebhookVerifier = Arc<WebhookVerifier>;

/// Create a GitHub webhook config
pub fn github_webhook(secret: &str) -> WebhookConfig {
    WebhookConfig {
        provider: WebhookProvider::GitHub,
        secret: secret.to_string(),
        enabled: true,
        ..Default::default()
    }
}

/// Create a Stripe webhook config
pub fn stripe_webhook(secret: &str) -> WebhookConfig {
    WebhookConfig {
        provider: WebhookProvider::Stripe,
        secret: secret.to_string(),
        enabled: true,
        ..Default::default()
    }
}

/// Create a Slack webhook config
pub fn slack_webhook(secret: &str) -> WebhookConfig {
    WebhookConfig {
        provider: WebhookProvider::Slack,
        secret: secret.to_string(),
        enabled: true,
        ..Default::default()
    }
}

/// Create a Discord webhook config
pub fn discord_webhook(public_key: &str) -> WebhookConfig {
    WebhookConfig {
        provider: WebhookProvider::Discord,
        secret: public_key.to_string(),
        enabled: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_hmac_sha256(secret: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(WebhookProvider::GitHub.to_string(), "github");
        assert_eq!(WebhookProvider::Stripe.to_string(), "stripe");
        assert_eq!(WebhookProvider::Slack.to_string(), "slack");
    }

    #[test]
    fn test_github_webhook_verification() {
        let verifier = WebhookVerifier::new();
        
        let secret = "test_secret";
        let body = b"test body";
        
        // Compute expected signature
        let sig_bytes = compute_hmac_sha256(secret.as_bytes(), body);
        let signature = hex::encode(sig_bytes);
        
        verifier.add_config("tunnel-1:/webhook", github_webhook(secret));
        
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), format!("sha256={}", signature));
        
        let result = verifier.verify("tunnel-1", "/webhook", &headers, body);
        assert!(result.is_valid());
    }

    #[test]
    fn test_github_invalid_signature() {
        let verifier = WebhookVerifier::new();
        verifier.add_config("tunnel-1", github_webhook("secret"));
        
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), "sha256=invalid".to_string());
        
        let result = verifier.verify("tunnel-1", "/webhook", &headers, b"body");
        assert!(matches!(result, VerificationResult::InvalidFormat(_)));
    }

    #[test]
    fn test_missing_header() {
        let verifier = WebhookVerifier::new();
        verifier.add_config("tunnel-1", github_webhook("secret"));
        
        let headers = HashMap::new();
        let result = verifier.verify("tunnel-1", "/webhook", &headers, b"body");
        assert!(matches!(result, VerificationResult::MissingHeader(_)));
    }

    #[test]
    fn test_no_config_passes() {
        let verifier = WebhookVerifier::new();
        let headers = HashMap::new();
        
        // No config means no verification required
        let result = verifier.verify("tunnel-1", "/webhook", &headers, b"body");
        assert!(result.is_valid());
    }

    #[test]
    fn test_disabled_verification() {
        let verifier = WebhookVerifier::new();
        
        let mut config = github_webhook("secret");
        config.enabled = false;
        verifier.add_config("tunnel-1", config);
        
        let headers = HashMap::new();
        let result = verifier.verify("tunnel-1", "/webhook", &headers, b"body");
        assert!(matches!(result, VerificationResult::Disabled));
    }

    #[test]
    fn test_stripe_webhook_verification() {
        let verifier = WebhookVerifier::new();
        
        let secret = "whsec_test";
        let body = b"{\"type\":\"payment_intent.succeeded\"}";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Compute Stripe signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(body));
        let sig_bytes = compute_hmac_sha256(secret.as_bytes(), signed_payload.as_bytes());
        let signature = hex::encode(sig_bytes);
        
        verifier.add_config("tunnel-1:/stripe/webhook", stripe_webhook(secret));
        
        let mut headers = HashMap::new();
        headers.insert("stripe-signature".to_string(), format!("t={},v1={}", timestamp, signature));
        
        let result = verifier.verify("tunnel-1", "/stripe/webhook", &headers, body);
        assert!(result.is_valid());
    }

    #[test]
    fn test_stripe_expired_timestamp() {
        let verifier = WebhookVerifier::new();
        
        let secret = "whsec_test";
        let body = b"{}";
        let old_timestamp = 1000; // Very old timestamp
        
        let signed_payload = format!("{}.{}", old_timestamp, String::from_utf8_lossy(body));
        let sig_bytes = compute_hmac_sha256(secret.as_bytes(), signed_payload.as_bytes());
        let signature = hex::encode(sig_bytes);
        
        verifier.add_config("tunnel-1", stripe_webhook(secret));
        
        let mut headers = HashMap::new();
        headers.insert("stripe-signature".to_string(), format!("t={},v1={}", old_timestamp, signature));
        
        let result = verifier.verify("tunnel-1", "/webhook", &headers, body);
        assert!(matches!(result, VerificationResult::ExpiredTimestamp));
    }

    #[test]
    fn test_slack_webhook_verification() {
        let verifier = WebhookVerifier::new();
        
        let secret = "slack_signing_secret";
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Compute Slack signature
        let base_string = format!("v0:{}:{}", timestamp, String::from_utf8_lossy(body));
        let sig_bytes = compute_hmac_sha256(secret.as_bytes(), base_string.as_bytes());
        let signature = hex::encode(sig_bytes);
        
        verifier.add_config("tunnel-1", slack_webhook(secret));
        
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), format!("v0={}", signature));
        headers.insert("x-slack-request-timestamp".to_string(), timestamp.to_string());
        
        let result = verifier.verify("tunnel-1", "/slack", &headers, body);
        assert!(result.is_valid());
    }

    #[test]
    fn test_shopify_webhook_verification() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        
        let verifier = WebhookVerifier::new();
        
        let secret = "shopify_secret";
        let body = b"{\"id\":123}";
        
        // Compute Shopify signature (base64)
        let sig_bytes = compute_hmac_sha256(secret.as_bytes(), body);
        let signature = STANDARD.encode(sig_bytes);
        
        verifier.add_config("tunnel-1:/shopify", WebhookConfig {
            provider: WebhookProvider::Shopify,
            secret: secret.to_string(),
            enabled: true,
            ..Default::default()
        });
        
        let mut headers = HashMap::new();
        headers.insert("x-shopify-hmac-sha256".to_string(), signature);
        
        let result = verifier.verify("tunnel-1", "/shopify", &headers, body);
        assert!(result.is_valid());
    }

    #[test]
    fn test_path_matching() {
        let verifier = WebhookVerifier::new();
        
        // Add config for specific path
        verifier.add_config("tunnel-1:/api/webhooks", github_webhook("secret1"));
        
        // Add config for all paths on another tunnel
        verifier.add_config("tunnel-2", github_webhook("secret2"));
        
        // Check path matching
        assert!(verifier.get_config("tunnel-1", "/api/webhooks/github").is_some());
        assert!(verifier.get_config("tunnel-1", "/other").is_none());
        assert!(verifier.get_config("tunnel-2", "/any/path").is_some());
    }

    #[test]
    fn test_config_removal() {
        let verifier = WebhookVerifier::new();
        
        verifier.add_config("tunnel-1", github_webhook("secret"));
        assert!(verifier.get_config("tunnel-1", "/").is_some());
        
        verifier.remove_config("tunnel-1");
        assert!(verifier.get_config("tunnel-1", "/").is_none());
    }
}
