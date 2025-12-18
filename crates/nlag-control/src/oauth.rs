//! OAuth/OIDC Integration
//!
//! Provides OAuth 2.0 and OpenID Connect authentication for:
//! - Google
//! - GitHub
//! - Azure AD (Microsoft)
//! - Generic OIDC providers
//!
//! ## Usage
//!
//! Configure providers in the control plane, then users can authenticate
//! via the dashboard or API endpoints.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// OAuth/OIDC errors
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    
    #[error("Invalid state parameter")]
    InvalidState,
    
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),
    
    #[error("User info fetch failed: {0}")]
    UserInfoFailed(String),
    
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    
    #[error("HTTP error: {0}")]
    HttpError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, OAuthError>;

/// OAuth 2.0 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    /// Provider ID (e.g., "google", "github")
    pub id: String,
    
    /// Display name
    pub name: String,
    
    /// Provider type
    pub provider_type: ProviderType,
    
    /// Client ID
    pub client_id: String,
    
    /// Client Secret
    #[serde(default, skip_serializing)]
    pub client_secret: String,
    
    /// Authorization endpoint
    pub auth_url: String,
    
    /// Token endpoint
    pub token_url: String,
    
    /// User info endpoint (optional, for non-OIDC)
    #[serde(default)]
    pub userinfo_url: Option<String>,
    
    /// OIDC discovery URL (optional)
    #[serde(default)]
    pub discovery_url: Option<String>,
    
    /// Scopes to request
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    
    /// Redirect URI
    pub redirect_uri: String,
    
    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Additional parameters for auth URL
    #[serde(default)]
    pub extra_params: HashMap<String, String>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
}

fn default_true() -> bool { true }

/// OAuth provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Google OAuth
    Google,
    /// GitHub OAuth
    GitHub,
    /// Microsoft / Azure AD
    Microsoft,
    /// Generic OAuth 2.0
    OAuth2,
    /// Generic OIDC
    Oidc,
}

impl OAuthProvider {
    /// Create a Google OAuth provider
    pub fn google(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self {
            id: "google".to_string(),
            name: "Google".to_string(),
            provider_type: ProviderType::Google,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
            discovery_url: Some("https://accounts.google.com/.well-known/openid-configuration".to_string()),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            redirect_uri: redirect_uri.to_string(),
            enabled: true,
            extra_params: HashMap::new(),
        }
    }
    
    /// Create a GitHub OAuth provider
    pub fn github(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self {
            id: "github".to_string(),
            name: "GitHub".to_string(),
            provider_type: ProviderType::GitHub,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: Some("https://api.github.com/user".to_string()),
            discovery_url: None,
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            redirect_uri: redirect_uri.to_string(),
            enabled: true,
            extra_params: HashMap::new(),
        }
    }
    
    /// Create a Microsoft/Azure AD OAuth provider
    pub fn microsoft(client_id: &str, client_secret: &str, redirect_uri: &str, tenant: &str) -> Self {
        let tenant = if tenant.is_empty() { "common" } else { tenant };
        Self {
            id: "microsoft".to_string(),
            name: "Microsoft".to_string(),
            provider_type: ProviderType::Microsoft,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!("https://login.microsoftonline.com/{}/oauth2/v2.0/authorize", tenant),
            token_url: format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant),
            userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            discovery_url: Some(format!(
                "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
                tenant
            )),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            redirect_uri: redirect_uri.to_string(),
            enabled: true,
            extra_params: HashMap::new(),
        }
    }
}

/// OAuth state for CSRF protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// Random state value
    pub state: String,
    /// Provider ID
    pub provider_id: String,
    /// Timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Redirect after login
    pub redirect_to: Option<String>,
    /// PKCE code verifier (if used)
    pub code_verifier: Option<String>,
}

/// User info from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Provider ID
    pub provider: String,
    /// Provider-specific user ID
    pub provider_id: String,
    /// Email address
    pub email: Option<String>,
    /// Whether email is verified
    pub email_verified: bool,
    /// Display name
    pub name: Option<String>,
    /// Given name
    pub given_name: Option<String>,
    /// Family name
    pub family_name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Locale
    pub locale: Option<String>,
    /// Raw claims from provider
    pub raw_claims: serde_json::Value,
}

/// Token response from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expires in seconds
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// Refresh token
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// ID token (OIDC)
    #[serde(default)]
    pub id_token: Option<String>,
    /// Scope
    #[serde(default)]
    pub scope: Option<String>,
}

/// OAuth manager for handling authentication flows
pub struct OAuthManager {
    /// Configured providers
    providers: RwLock<HashMap<String, OAuthProvider>>,
    
    /// Pending OAuth states (for CSRF protection)
    pending_states: dashmap::DashMap<String, OAuthState>,
    
    /// HTTP client
    client: reqwest::Client,
}

impl OAuthManager {
    /// Create a new OAuth manager
    pub fn new() -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Arc::new(Self {
            providers: RwLock::new(HashMap::new()),
            pending_states: dashmap::DashMap::new(),
            client,
        })
    }
    
    /// Add a provider
    pub fn add_provider(&self, provider: OAuthProvider) {
        info!("Adding OAuth provider: {} ({})", provider.name, provider.id);
        self.providers.write().insert(provider.id.clone(), provider);
    }
    
    /// Remove a provider
    pub fn remove_provider(&self, id: &str) {
        self.providers.write().remove(id);
    }
    
    /// Get a provider by ID
    pub fn get_provider(&self, id: &str) -> Option<OAuthProvider> {
        self.providers.read().get(id).cloned()
    }
    
    /// List all providers
    pub fn list_providers(&self) -> Vec<OAuthProvider> {
        self.providers.read().values().cloned().collect()
    }
    
    /// Generate authorization URL
    pub fn get_auth_url(&self, provider_id: &str, redirect_to: Option<&str>) -> Result<(String, String)> {
        let provider = self.providers.read()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| OAuthError::ProviderNotFound(provider_id.to_string()))?;
        
        // Generate state
        let state = generate_random_string(32);
        
        // Generate PKCE (for enhanced security)
        let code_verifier = generate_random_string(64);
        let code_challenge = base64_url_encode(&sha256(code_verifier.as_bytes()));
        
        // Store state
        let oauth_state = OAuthState {
            state: state.clone(),
            provider_id: provider_id.to_string(),
            created_at: chrono::Utc::now(),
            redirect_to: redirect_to.map(String::from),
            code_verifier: Some(code_verifier),
        };
        self.pending_states.insert(state.clone(), oauth_state);
        
        // Build auth URL
        let mut url = url::Url::parse(&provider.auth_url)
            .map_err(|e| OAuthError::ConfigError(format!("Invalid auth URL: {}", e)))?;
        
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &provider.client_id);
            query.append_pair("redirect_uri", &provider.redirect_uri);
            query.append_pair("response_type", "code");
            query.append_pair("scope", &provider.scopes.join(" "));
            query.append_pair("state", &state);
            
            // Add PKCE for providers that support it
            if matches!(provider.provider_type, ProviderType::Google | ProviderType::Microsoft | ProviderType::Oidc) {
                query.append_pair("code_challenge", &code_challenge);
                query.append_pair("code_challenge_method", "S256");
            }
            
            // Add extra params
            for (key, value) in &provider.extra_params {
                query.append_pair(key, value);
            }
        }
        
        Ok((url.to_string(), state))
    }
    
    /// Exchange authorization code for tokens
    pub async fn exchange_code(&self, code: &str, state: &str) -> Result<(TokenResponse, OAuthUserInfo)> {
        // Validate state
        let oauth_state = self.pending_states.remove(state)
            .map(|(_, v)| v)
            .ok_or(OAuthError::InvalidState)?;
        
        // Check state age (max 10 minutes)
        let age = chrono::Utc::now() - oauth_state.created_at;
        if age.num_minutes() > 10 {
            return Err(OAuthError::InvalidState);
        }
        
        let provider = self.get_provider(&oauth_state.provider_id)
            .ok_or_else(|| OAuthError::ProviderNotFound(oauth_state.provider_id.clone()))?;
        
        // Build token request
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("client_id", provider.client_id.clone()),
            ("client_secret", provider.client_secret.clone()),
            ("redirect_uri", provider.redirect_uri.clone()),
        ];
        
        // Add PKCE verifier if present
        if let Some(verifier) = oauth_state.code_verifier {
            form.push(("code_verifier", verifier));
        }
        
        debug!("Exchanging code for tokens with {}", provider.name);
        
        let mut request = self.client.post(&provider.token_url)
            .form(&form);
        
        // GitHub requires Accept header
        if provider.provider_type == ProviderType::GitHub {
            request = request.header("Accept", "application/json");
        }
        
        let resp = request.send().await
            .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
        
        if !resp.status().is_success() {
            let error = resp.text().await.unwrap_or_default();
            return Err(OAuthError::TokenExchangeFailed(error));
        }
        
        let tokens: TokenResponse = resp.json().await
            .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
        
        // Get user info
        let user_info = self.get_user_info(&provider, &tokens).await?;
        
        info!("OAuth login successful for {} via {}", 
              user_info.email.as_deref().unwrap_or("unknown"),
              provider.name);
        
        Ok((tokens, user_info))
    }
    
    /// Get user info from provider
    async fn get_user_info(&self, provider: &OAuthProvider, tokens: &TokenResponse) -> Result<OAuthUserInfo> {
        // Try to extract from ID token first (OIDC)
        if let Some(ref id_token) = tokens.id_token {
            if let Some(info) = self.parse_id_token(provider, id_token)? {
                return Ok(info);
            }
        }
        
        // Fall back to userinfo endpoint
        let userinfo_url = provider.userinfo_url.as_ref()
            .ok_or_else(|| OAuthError::ConfigError("No userinfo URL configured".to_string()))?;
        
        let resp = self.client.get(userinfo_url)
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
        
        if !resp.status().is_success() {
            let error = resp.text().await.unwrap_or_default();
            return Err(OAuthError::UserInfoFailed(error));
        }
        
        let claims: serde_json::Value = resp.json().await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
        
        self.parse_claims(provider, claims)
    }
    
    /// Parse ID token (OIDC)
    fn parse_id_token(&self, provider: &OAuthProvider, id_token: &str) -> Result<Option<OAuthUserInfo>> {
        // Split JWT
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Ok(None);
        }
        
        // Decode payload (we're not validating signature here - that should be done by a proper JWT lib)
        let payload = base64_url_decode(parts[1])
            .map_err(|_| OAuthError::InvalidToken("Invalid base64 in ID token".to_string()))?;
        
        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| OAuthError::InvalidToken(format!("Invalid JSON in ID token: {}", e)))?;
        
        self.parse_claims(provider, claims).map(Some)
    }
    
    /// Parse claims into user info
    fn parse_claims(&self, provider: &OAuthProvider, claims: serde_json::Value) -> Result<OAuthUserInfo> {
        // Extract standard claims - try "sub" first, then "id" as string, then "id" as i64
        let provider_id = claims.get("sub")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| claims.get("id").and_then(|v| v.as_str()).map(String::from))
            .or_else(|| claims.get("id").and_then(|v| v.as_i64()).map(|v| v.to_string()))
            .ok_or_else(|| OAuthError::MissingClaim("sub or id".to_string()))?;
        
        let email = claims.get("email")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        let email_verified = claims.get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let name = claims.get("name")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        let given_name = claims.get("given_name")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        let family_name = claims.get("family_name")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        let picture = claims.get("picture")
            .or_else(|| claims.get("avatar_url"))
            .and_then(|v| v.as_str())
            .map(String::from);
        
        let locale = claims.get("locale")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        // GitHub specific: get email from separate endpoint if not in claims
        let email = if email.is_none() && provider.provider_type == ProviderType::GitHub {
            claims.get("login").and_then(|v| v.as_str()).map(|s| format!("{}@users.noreply.github.com", s))
        } else {
            email
        };
        
        Ok(OAuthUserInfo {
            provider: provider.id.clone(),
            provider_id,
            email,
            email_verified,
            name,
            given_name,
            family_name,
            picture,
            locale,
            raw_claims: claims,
        })
    }
    
    /// Cleanup expired states
    pub fn cleanup_expired_states(&self) {
        let now = chrono::Utc::now();
        let max_age = chrono::Duration::minutes(15);
        
        self.pending_states.retain(|_, state| {
            now - state.created_at < max_age
        });
    }
    
    /// Start cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup_expired_states();
            }
        });
    }
}

impl Default for OAuthManager {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            providers: RwLock::new(HashMap::new()),
            pending_states: dashmap::DashMap::new(),
            client,
        }
    }
}

/// Generate a random alphanumeric string
fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// SHA-256 hash
fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest::{digest, SHA256};
    digest(&SHA256, data).as_ref().to_vec()
}

/// Base64 URL encode
fn base64_url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

/// Base64 URL decode
fn base64_url_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_google_provider() {
        let provider = OAuthProvider::google("client_id", "client_secret", "http://localhost/callback");
        assert_eq!(provider.provider_type, ProviderType::Google);
        assert!(provider.scopes.contains(&"openid".to_string()));
    }
    
    #[test]
    fn test_github_provider() {
        let provider = OAuthProvider::github("client_id", "client_secret", "http://localhost/callback");
        assert_eq!(provider.provider_type, ProviderType::GitHub);
        assert!(provider.scopes.contains(&"read:user".to_string()));
    }
    
    #[test]
    fn test_microsoft_provider() {
        let provider = OAuthProvider::microsoft("client_id", "client_secret", "http://localhost/callback", "common");
        assert_eq!(provider.provider_type, ProviderType::Microsoft);
        assert!(provider.auth_url.contains("common"));
    }
    
    #[test]
    fn test_auth_url_generation() {
        let manager = OAuthManager::new();
        manager.add_provider(OAuthProvider::google(
            "test_client_id",
            "test_secret",
            "http://localhost:3000/auth/callback",
        ));
        
        let (url, state) = manager.get_auth_url("google", Some("/dashboard")).unwrap();
        
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("test_client_id"));
        assert!(url.contains(&state));
        assert!(!state.is_empty());
    }
    
    #[test]
    fn test_state_cleanup() {
        let manager = OAuthManager::new();
        
        // Add an old state
        manager.pending_states.insert("old_state".to_string(), OAuthState {
            state: "old_state".to_string(),
            provider_id: "google".to_string(),
            created_at: chrono::Utc::now() - chrono::Duration::minutes(20),
            redirect_to: None,
            code_verifier: None,
        });
        
        // Add a new state
        manager.pending_states.insert("new_state".to_string(), OAuthState {
            state: "new_state".to_string(),
            provider_id: "google".to_string(),
            created_at: chrono::Utc::now(),
            redirect_to: None,
            code_verifier: None,
        });
        
        assert_eq!(manager.pending_states.len(), 2);
        
        manager.cleanup_expired_states();
        
        assert_eq!(manager.pending_states.len(), 1);
        assert!(manager.pending_states.contains_key("new_state"));
    }
}
