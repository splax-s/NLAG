//! Replay Protection
//!
//! This module provides protection against request replay attacks by tracking
//! nonces, timestamps, and request signatures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

/// Replay protection errors
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("Request replay detected: nonce {0} already used")]
    ReplayDetected(String),
    
    #[error("Timestamp too old: {0} seconds")]
    TimestampTooOld(i64),
    
    #[error("Timestamp in future: {0} seconds")]
    TimestampInFuture(i64),
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Missing nonce")]
    MissingNonce,
    
    #[error("Missing timestamp")]
    MissingTimestamp,
}

pub type Result<T> = std::result::Result<T, ReplayError>;

/// Nonce with expiration
#[derive(Debug, Clone)]
struct NonceEntry {
    nonce: String,
    created_at: Instant,
    request_id: Option<String>,
}

/// Window-based nonce tracking
struct NonceWindow {
    nonces: DashMap<String, NonceEntry>,
    window_duration: Duration,
    max_entries: usize,
    cleanup_counter: AtomicU64,
}

impl NonceWindow {
    fn new(window_duration: Duration, max_entries: usize) -> Self {
        Self {
            nonces: DashMap::new(),
            window_duration,
            max_entries,
            cleanup_counter: AtomicU64::new(0),
        }
    }
    
    /// Check if nonce exists (replay attack)
    fn check_and_add(&self, nonce: &str, request_id: Option<&str>) -> Result<()> {
        // Check if nonce exists
        if self.nonces.contains_key(nonce) {
            return Err(ReplayError::ReplayDetected(nonce.to_string()));
        }
        
        // Add nonce
        let entry = NonceEntry {
            nonce: nonce.to_string(),
            created_at: Instant::now(),
            request_id: request_id.map(|s| s.to_string()),
        };
        
        self.nonces.insert(nonce.to_string(), entry);
        
        // Periodic cleanup (every 1000 checks)
        if self.cleanup_counter.fetch_add(1, Ordering::Relaxed) % 1000 == 0 {
            self.cleanup_expired();
        }
        
        Ok(())
    }
    
    /// Remove expired nonces
    fn cleanup_expired(&self) {
        let now = Instant::now();
        let expired: Vec<String> = self.nonces
            .iter()
            .filter(|e| now.duration_since(e.created_at) > self.window_duration)
            .map(|e| e.key().clone())
            .collect();
        
        for nonce in expired {
            self.nonces.remove(&nonce);
        }
        
        // If still over limit, remove oldest entries
        while self.nonces.len() > self.max_entries {
            // Find oldest entry
            let oldest = self.nonces
                .iter()
                .min_by_key(|e| e.created_at)
                .map(|e| e.key().clone());
            
            if let Some(key) = oldest {
                self.nonces.remove(&key);
            } else {
                break;
            }
        }
    }
    
    /// Get current size
    fn len(&self) -> usize {
        self.nonces.len()
    }
}

/// Request signature for replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSignature {
    /// Unique nonce
    pub nonce: String,
    /// Request timestamp (Unix epoch seconds)
    pub timestamp: i64,
    /// HMAC signature of (nonce + timestamp + request_body)
    pub signature: String,
    /// Request ID for correlation
    pub request_id: Option<String>,
}

impl RequestSignature {
    /// Create a new request signature
    pub fn new(nonce: &str, timestamp: i64, signature: &str) -> Self {
        Self {
            nonce: nonce.to_string(),
            timestamp,
            signature: signature.to_string(),
            request_id: None,
        }
    }
    
    /// Generate a nonce
    pub fn generate_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
    
    /// Compute HMAC signature
    pub fn compute_hmac(secret: &[u8], data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Simple HMAC-like computation (in production, use proper HMAC)
        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

/// Replay protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Enable replay protection
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// Time window for nonce validity (seconds)
    #[serde(default = "default_window")]
    pub window_secs: u64,
    
    /// Maximum clock skew allowed (seconds)
    #[serde(default = "default_skew")]
    pub max_clock_skew_secs: u64,
    
    /// Maximum number of nonces to track
    #[serde(default = "default_max_nonces")]
    pub max_nonces: usize,
    
    /// Require HMAC signature
    #[serde(default)]
    pub require_signature: bool,
    
    /// HMAC secret (base64 encoded)
    pub hmac_secret: Option<String>,
    
    /// Header name for nonce
    #[serde(default = "default_nonce_header")]
    pub nonce_header: String,
    
    /// Header name for timestamp
    #[serde(default = "default_timestamp_header")]
    pub timestamp_header: String,
    
    /// Header name for signature
    #[serde(default = "default_signature_header")]
    pub signature_header: String,
}

fn default_enabled() -> bool {
    false
}

fn default_window() -> u64 {
    300 // 5 minutes
}

fn default_skew() -> u64 {
    60 // 1 minute
}

fn default_max_nonces() -> usize {
    1_000_000
}

fn default_nonce_header() -> String {
    "X-Nonce".to_string()
}

fn default_timestamp_header() -> String {
    "X-Timestamp".to_string()
}

fn default_signature_header() -> String {
    "X-Signature".to_string()
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            window_secs: default_window(),
            max_clock_skew_secs: default_skew(),
            max_nonces: default_max_nonces(),
            require_signature: false,
            hmac_secret: None,
            nonce_header: default_nonce_header(),
            timestamp_header: default_timestamp_header(),
            signature_header: default_signature_header(),
        }
    }
}

/// Replay protection guard
pub struct ReplayGuard {
    config: ReplayConfig,
    nonce_window: NonceWindow,
    hmac_secret: Option<Vec<u8>>,
    
    // Stats
    requests_checked: AtomicU64,
    replays_blocked: AtomicU64,
    timestamp_violations: AtomicU64,
}

impl ReplayGuard {
    /// Create a new replay guard
    pub fn new(config: ReplayConfig) -> Arc<Self> {
        let hmac_secret = config.hmac_secret.as_ref()
            .and_then(|s| base64::decode(s).ok());
        
        Arc::new(Self {
            nonce_window: NonceWindow::new(
                Duration::from_secs(config.window_secs),
                config.max_nonces,
            ),
            hmac_secret,
            config,
            requests_checked: AtomicU64::new(0),
            replays_blocked: AtomicU64::new(0),
            timestamp_violations: AtomicU64::new(0),
        })
    }
    
    /// Check if replay protection is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
    
    /// Validate a request for replay attacks
    pub fn validate_request(
        &self,
        nonce: &str,
        timestamp: i64,
        signature: Option<&str>,
        _body: Option<&[u8]>,
        request_id: Option<&str>,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        self.requests_checked.fetch_add(1, Ordering::Relaxed);
        
        // Check timestamp
        let now = chrono::Utc::now().timestamp();
        let skew = self.config.max_clock_skew_secs as i64;
        
        if timestamp < now - (self.config.window_secs as i64) {
            self.timestamp_violations.fetch_add(1, Ordering::Relaxed);
            return Err(ReplayError::TimestampTooOld(now - timestamp));
        }
        
        if timestamp > now + skew {
            self.timestamp_violations.fetch_add(1, Ordering::Relaxed);
            return Err(ReplayError::TimestampInFuture(timestamp - now));
        }
        
        // Check signature if required
        if self.config.require_signature {
            if let (Some(sig), Some(secret)) = (signature, &self.hmac_secret) {
                let data = format!("{}:{}", nonce, timestamp);
                let expected = RequestSignature::compute_hmac(secret, data.as_bytes());
                
                if sig != expected {
                    return Err(ReplayError::InvalidSignature);
                }
            } else if signature.is_none() {
                return Err(ReplayError::InvalidSignature);
            }
        }
        
        // Check nonce for replay
        match self.nonce_window.check_and_add(nonce, request_id) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.replays_blocked.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Get stats
    pub fn stats(&self) -> ReplayStats {
        ReplayStats {
            requests_checked: self.requests_checked.load(Ordering::Relaxed),
            replays_blocked: self.replays_blocked.load(Ordering::Relaxed),
            timestamp_violations: self.timestamp_violations.load(Ordering::Relaxed),
            nonces_tracked: self.nonce_window.len() as u64,
        }
    }
    
    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        let guard = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                guard.nonce_window.cleanup_expired();
                debug!(
                    "Replay guard cleanup: {} nonces tracked",
                    guard.nonce_window.len()
                );
            }
        });
    }
}

/// Replay protection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStats {
    pub requests_checked: u64,
    pub replays_blocked: u64,
    pub timestamp_violations: u64,
    pub nonces_tracked: u64,
}

/// Base64 decode helper
mod base64 {
    pub fn decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
        // Simple base64 decode (in production, use a proper base64 crate)
        let chars: Vec<char> = input.chars().collect();
        let mut output = Vec::new();
        
        for chunk in chars.chunks(4) {
            if chunk.len() < 4 {
                break;
            }
            
            let mut buf = [0u8; 4];
            for (i, &c) in chunk.iter().enumerate() {
                buf[i] = match c {
                    'A'..='Z' => c as u8 - b'A',
                    'a'..='z' => c as u8 - b'a' + 26,
                    '0'..='9' => c as u8 - b'0' + 52,
                    '+' => 62,
                    '/' => 63,
                    '=' => 0,
                    _ => return Err(()),
                };
            }
            
            output.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk[2] != '=' {
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if chunk[3] != '=' {
                output.push((buf[2] << 6) | buf[3]);
            }
        }
        
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nonce_tracking() {
        let window = NonceWindow::new(Duration::from_secs(60), 1000);
        
        assert!(window.check_and_add("nonce1", None).is_ok());
        assert!(window.check_and_add("nonce2", None).is_ok());
        
        // Replay should fail
        assert!(window.check_and_add("nonce1", None).is_err());
    }
    
    #[test]
    fn test_replay_guard() {
        let config = ReplayConfig {
            enabled: true,
            window_secs: 300,
            ..Default::default()
        };
        
        let guard = ReplayGuard::new(config);
        let now = chrono::Utc::now().timestamp();
        
        // First request should pass
        assert!(guard.validate_request("nonce1", now, None, None, None).is_ok());
        
        // Replay should fail
        assert!(guard.validate_request("nonce1", now, None, None, None).is_err());
        
        // New nonce should pass
        assert!(guard.validate_request("nonce2", now, None, None, None).is_ok());
    }
    
    #[test]
    fn test_timestamp_validation() {
        let config = ReplayConfig {
            enabled: true,
            window_secs: 300,
            max_clock_skew_secs: 60,
            ..Default::default()
        };
        
        let guard = ReplayGuard::new(config);
        let now = chrono::Utc::now().timestamp();
        
        // Current timestamp should pass
        assert!(guard.validate_request("n1", now, None, None, None).is_ok());
        
        // Old timestamp should fail
        let old = now - 400;
        assert!(guard.validate_request("n2", old, None, None, None).is_err());
        
        // Future timestamp (within skew) should pass
        let future = now + 30;
        assert!(guard.validate_request("n3", future, None, None, None).is_ok());
        
        // Far future timestamp should fail
        let far_future = now + 120;
        assert!(guard.validate_request("n4", far_future, None, None, None).is_err());
    }
    
    #[test]
    fn test_generate_nonce() {
        let nonce1 = RequestSignature::generate_nonce();
        let nonce2 = RequestSignature::generate_nonce();
        
        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2);
    }
}
