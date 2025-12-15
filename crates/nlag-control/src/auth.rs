//! Authentication module for NLAG Control Plane
//!
//! Provides:
//! - JWT token generation and validation
//! - Token refresh mechanism
//! - Agent authentication via tokens

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Token type (access or refresh)
    pub typ: String,
    /// Token scopes
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Agent token claims for tunnel authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Token ID
    pub jti: String,
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time
    pub exp: u64,
    /// Issued at
    pub iat: u64,
    /// Allowed scopes
    pub scopes: Vec<String>,
}

/// Authentication service
pub struct AuthService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

impl AuthService {
    /// Create a new AuthService with the given secret
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            access_token_ttl: Duration::from_secs(3600),       // 1 hour
            refresh_token_ttl: Duration::from_secs(86400 * 7), // 7 days
        }
    }

    /// Create access and refresh tokens for a user
    pub fn create_tokens(&self, user_id: &str) -> Result<(String, String, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let access_exp = now + self.access_token_ttl.as_secs();
        let refresh_exp = now + self.refresh_token_ttl.as_secs();

        let access_claims = Claims {
            sub: user_id.to_string(),
            exp: access_exp,
            iat: now,
            typ: "access".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let refresh_claims = Claims {
            sub: user_id.to_string(),
            exp: refresh_exp,
            iat: now,
            typ: "refresh".to_string(),
            scopes: vec![],
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to create access token: {}", e))?;

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to create refresh token: {}", e))?;

        Ok((access_token, refresh_token, self.access_token_ttl.as_secs()))
    }

    /// Refresh tokens using a valid refresh token
    pub fn refresh_tokens(&self, refresh_token: &str) -> Result<(String, String, u64)> {
        let claims = self.validate_token(refresh_token)?;
        
        if claims.typ != "refresh" {
            return Err(anyhow!("Invalid token type for refresh"));
        }

        self.create_tokens(&claims.sub)
    }

    /// Validate a token and return its claims
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::default();
        
        let token_data: TokenData<Claims> = decode(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Invalid token: {}", e))?;

        Ok(token_data.claims)
    }

    /// Create an agent authentication token
    pub fn create_agent_token(
        &self,
        token_id: &str,
        user_id: &str,
        scopes: &[String],
        expires_in_days: Option<u32>,
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = expires_in_days
            .map(|days| now + (days as u64 * 86400))
            .unwrap_or(now + 365 * 86400); // Default: 1 year

        let claims = AgentClaims {
            jti: token_id.to_string(),
            sub: user_id.to_string(),
            exp,
            iat: now,
            scopes: scopes.to_vec(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to create agent token: {}", e))
    }

    /// Validate an agent token
    pub fn validate_agent_token(&self, token: &str) -> Result<AgentClaims> {
        let validation = Validation::default();
        
        let token_data: TokenData<AgentClaims> = decode(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Invalid agent token: {}", e))?;

        Ok(token_data.claims)
    }
}
