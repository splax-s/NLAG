//! Agent authentication for NLAG Edge
//!
//! Validates JWT tokens provided by agents during connection.
//! Tokens are issued by the control plane.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Agent token claims (must match control plane format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Token ID
    pub jti: String,
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Allowed scopes (e.g., "tunnel:create", "tunnel:http", "tunnel:tcp")
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional: allowed subdomains (empty = any)
    #[serde(default)]
    pub allowed_subdomains: Vec<String>,
    /// Optional: maximum tunnels allowed
    #[serde(default)]
    pub max_tunnels: Option<u32>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication (false = dev mode, accept all)
    #[serde(default)]
    pub enabled: bool,
    /// JWT secret for HS256 (shared with control plane)
    pub jwt_secret: Option<String>,
    /// JWT public key for RS256 (alternative to secret)
    pub jwt_public_key: Option<String>,
    /// Algorithm to use (HS256 or RS256)
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "HS256".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for development
            jwt_secret: None,
            jwt_public_key: None,
            algorithm: default_algorithm(),
        }
    }
}

/// Agent authenticator
pub struct AgentAuthenticator {
    config: AuthConfig,
    decoding_key: Option<DecodingKey>,
    validation: Validation,
}

impl AgentAuthenticator {
    /// Create a new authenticator from config
    pub fn new(config: AuthConfig) -> Result<Self> {
        let (decoding_key, validation) = if config.enabled {
            let key = match (&config.jwt_secret, &config.jwt_public_key, config.algorithm.as_str()) {
                (Some(secret), _, "HS256") => {
                    DecodingKey::from_secret(secret.as_bytes())
                }
                (_, Some(public_key), "RS256") => {
                    DecodingKey::from_rsa_pem(public_key.as_bytes())
                        .map_err(|e| anyhow!("Invalid RSA public key: {}", e))?
                }
                _ => {
                    return Err(anyhow!(
                        "Authentication enabled but no valid key configured. \
                         Set jwt_secret for HS256 or jwt_public_key for RS256"
                    ));
                }
            };

            let mut validation = match config.algorithm.as_str() {
                "HS256" => Validation::new(Algorithm::HS256),
                "RS256" => Validation::new(Algorithm::RS256),
                other => return Err(anyhow!("Unsupported algorithm: {}", other)),
            };
            validation.validate_exp = true;
            validation.validate_nbf = false;
            validation.required_spec_claims.clear();

            (Some(key), validation)
        } else {
            debug!("Authentication disabled - running in development mode");
            (None, Validation::default())
        };

        Ok(Self {
            config,
            decoding_key,
            validation,
        })
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Validate an agent token
    pub fn validate_token(&self, token: &str) -> Result<AgentClaims> {
        if !self.config.enabled {
            // In dev mode, return dummy claims
            return Ok(AgentClaims {
                jti: "dev-mode".to_string(),
                sub: "dev-user".to_string(),
                exp: u64::MAX,
                iat: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                scopes: vec!["*".to_string()],
                allowed_subdomains: vec![],
                max_tunnels: None,
            });
        }

        let decoding_key = self.decoding_key.as_ref()
            .ok_or_else(|| anyhow!("Authentication misconfigured: no decoding key"))?;

        let token_data: TokenData<AgentClaims> = decode(token, decoding_key, &self.validation)
            .map_err(|e| {
                warn!("Token validation failed: {}", e);
                anyhow!("Invalid or expired token: {}", e)
            })?;

        debug!("Token validated for user: {}", token_data.claims.sub);
        Ok(token_data.claims)
    }

    /// Check if claims allow a specific subdomain
    pub fn check_subdomain(&self, claims: &AgentClaims, subdomain: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        // Empty allowed_subdomains means any subdomain is allowed
        if claims.allowed_subdomains.is_empty() {
            return true;
        }

        // Check if subdomain matches any allowed pattern
        claims.allowed_subdomains.iter().any(|pattern| {
            if pattern == "*" {
                true
            } else if pattern.starts_with("*.") {
                // Wildcard pattern like "*.mycompany"
                subdomain.ends_with(&pattern[1..])
            } else {
                subdomain == pattern
            }
        })
    }

    /// Check if claims have a specific scope
    pub fn has_scope(&self, claims: &AgentClaims, scope: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        claims.scopes.iter().any(|s| s == "*" || s == scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_mode_auth() {
        let config = AuthConfig::default();
        let auth = AgentAuthenticator::new(config).unwrap();
        
        assert!(!auth.is_enabled());
        
        // Any token should work in dev mode
        let claims = auth.validate_token("any-token").unwrap();
        assert_eq!(claims.sub, "dev-user");
        assert!(auth.has_scope(&claims, "anything"));
        assert!(auth.check_subdomain(&claims, "anything"));
    }

    #[test]
    fn test_subdomain_check() {
        let claims = AgentClaims {
            jti: "test".to_string(),
            sub: "user".to_string(),
            exp: u64::MAX,
            iat: 0,
            scopes: vec![],
            allowed_subdomains: vec!["myapp".to_string(), "*.company".to_string()],
            max_tunnels: None,
        };

        let config = AuthConfig {
            enabled: true,
            jwt_secret: Some("test-secret-key-at-least-32-chars".to_string()),
            jwt_public_key: None,
            algorithm: "HS256".to_string(),
        };
        let auth = AgentAuthenticator::new(config).unwrap();

        assert!(auth.check_subdomain(&claims, "myapp"));
        assert!(auth.check_subdomain(&claims, "test.company"));
        assert!(!auth.check_subdomain(&claims, "other"));
    }

    #[test]
    fn test_scope_check() {
        let claims = AgentClaims {
            jti: "test".to_string(),
            sub: "user".to_string(),
            exp: u64::MAX,
            iat: 0,
            scopes: vec!["tunnel:http".to_string()],
            allowed_subdomains: vec![],
            max_tunnels: None,
        };

        let config = AuthConfig {
            enabled: true,
            jwt_secret: Some("test-secret-key-at-least-32-chars".to_string()),
            jwt_public_key: None,
            algorithm: "HS256".to_string(),
        };
        let auth = AgentAuthenticator::new(config).unwrap();

        assert!(auth.has_scope(&claims, "tunnel:http"));
        assert!(!auth.has_scope(&claims, "tunnel:tcp"));
    }
}
