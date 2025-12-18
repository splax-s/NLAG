//! Basic Authentication Middleware
//!
//! Provides HTTP Basic Authentication for tunnel endpoints:
//! - Username/password verification
//! - Realm configuration
//! - Multiple credential sets
//! - Optional password hashing

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Password storage format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordFormat {
    /// Plain text password
    Plain,
    /// SHA256 hashed password (hex encoded)
    Sha256,
    /// Bcrypt hashed password
    Bcrypt,
}

impl Default for PasswordFormat {
    fn default() -> Self {
        Self::Plain
    }
}

/// A single credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Username
    pub username: String,
    /// Password (format depends on password_format)
    pub password: String,
    /// Password format
    #[serde(default)]
    pub format: PasswordFormat,
}

/// Basic auth configuration for a tunnel/path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    /// Authentication realm (shown in browser prompt)
    #[serde(default = "default_realm")]
    pub realm: String,
    /// List of valid credentials
    pub credentials: Vec<Credential>,
    /// Paths to exclude from auth (exact match or prefix)
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Custom unauthorized message
    pub unauthorized_message: Option<String>,
    /// Whether authentication is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_realm() -> String {
    "Restricted Area".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for BasicAuthConfig {
    fn default() -> Self {
        Self {
            realm: default_realm(),
            credentials: Vec::new(),
            exclude_paths: Vec::new(),
            unauthorized_message: None,
            enabled: true,
        }
    }
}

/// Result of authentication attempt
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication successful
    Authenticated {
        username: String,
    },
    /// No credentials provided
    NoCredentials,
    /// Invalid credentials
    InvalidCredentials,
    /// Path is excluded from auth
    Excluded,
    /// Auth is disabled
    Disabled,
}

impl AuthResult {
    /// Check if authentication was successful or path was excluded
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthResult::Authenticated { .. } | AuthResult::Excluded | AuthResult::Disabled)
    }

    /// Get the authenticated username if any
    pub fn username(&self) -> Option<&str> {
        match self {
            AuthResult::Authenticated { username } => Some(username),
            _ => None,
        }
    }
}

/// Basic authentication middleware
pub struct BasicAuth {
    /// Configurations by tunnel ID
    configs: RwLock<HashMap<String, BasicAuthConfig>>,
}

impl BasicAuth {
    /// Create a new BasicAuth middleware
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            configs: RwLock::new(HashMap::new()),
        })
    }

    /// Add a configuration for a tunnel/path
    pub fn add_config(&self, key: &str, config: BasicAuthConfig) {
        self.configs.write().insert(key.to_string(), config);
    }

    /// Remove a configuration
    pub fn remove_config(&self, key: &str) {
        self.configs.write().remove(key);
    }

    /// Get configuration for a tunnel
    pub fn get_config(&self, tunnel_id: &str) -> Option<BasicAuthConfig> {
        self.configs.read().get(tunnel_id).cloned()
    }

    /// Authenticate a request
    ///
    /// # Arguments
    /// * `tunnel_id` - The tunnel identifier
    /// * `path` - The request path
    /// * `authorization_header` - The Authorization header value (if present)
    pub fn authenticate(
        &self,
        tunnel_id: &str,
        path: &str,
        authorization_header: Option<&str>,
    ) -> AuthResult {
        let configs = self.configs.read();
        
        // Find matching config
        let config = match configs.get(tunnel_id) {
            Some(c) => c,
            None => return AuthResult::Disabled,
        };

        if !config.enabled {
            return AuthResult::Disabled;
        }

        // Check if path is excluded
        for exclude_path in &config.exclude_paths {
            if path == exclude_path || path.starts_with(&format!("{}/", exclude_path)) {
                return AuthResult::Excluded;
            }
        }

        // No authorization header
        let Some(auth_header) = authorization_header else {
            return AuthResult::NoCredentials;
        };

        // Parse Basic auth header
        let (username, password) = match Self::parse_basic_auth(auth_header) {
            Some((u, p)) => (u, p),
            None => return AuthResult::InvalidCredentials,
        };

        // Verify credentials
        for cred in &config.credentials {
            if cred.username != username {
                continue;
            }

            let valid = match cred.format {
                PasswordFormat::Plain => cred.password == password,
                PasswordFormat::Sha256 => Self::verify_sha256(&password, &cred.password),
                PasswordFormat::Bcrypt => Self::verify_bcrypt(&password, &cred.password),
            };

            if valid {
                return AuthResult::Authenticated {
                    username: username.to_string(),
                };
            }
        }

        AuthResult::InvalidCredentials
    }

    /// Generate WWW-Authenticate header value
    pub fn www_authenticate_header(&self, tunnel_id: &str) -> String {
        let realm = self.configs
            .read()
            .get(tunnel_id)
            .map(|c| c.realm.clone())
            .unwrap_or_else(default_realm);

        format!("Basic realm=\"{}\"", realm)
    }

    /// Generate unauthorized response body
    pub fn unauthorized_body(&self, tunnel_id: &str) -> String {
        self.configs
            .read()
            .get(tunnel_id)
            .and_then(|c| c.unauthorized_message.clone())
            .unwrap_or_else(|| "401 Unauthorized".to_string())
    }

    /// Parse Basic authentication header
    fn parse_basic_auth(header: &str) -> Option<(String, String)> {
        // Must start with "Basic "
        let encoded = header.strip_prefix("Basic ")?;
        
        // Decode base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        
        let decoded_str = String::from_utf8(decoded).ok()?;
        
        // Split on first colon
        let (username, password) = decoded_str.split_once(':')?;
        
        Some((username.to_string(), password.to_string()))
    }

    /// Verify SHA256 hashed password
    fn verify_sha256(password: &str, hash: &str) -> bool {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let computed = hex::encode(result);
        
        computed.eq_ignore_ascii_case(hash)
    }

    /// Verify bcrypt hashed password
    fn verify_bcrypt(password: &str, hash: &str) -> bool {
        // Use bcrypt verify
        bcrypt::verify(password, hash).unwrap_or(false)
    }

    /// Hash a password with SHA256
    pub fn hash_sha256(password: &str) -> String {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Hash a password with bcrypt
    pub fn hash_bcrypt(password: &str) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    }
}

impl Default for BasicAuth {
    fn default() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
        }
    }
}

/// Shared BasicAuth instance
pub type SharedBasicAuth = Arc<BasicAuth>;

/// Builder for creating BasicAuth configurations
pub struct BasicAuthBuilder {
    config: BasicAuthConfig,
}

impl BasicAuthBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: BasicAuthConfig::default(),
        }
    }

    /// Set the realm
    pub fn realm(mut self, realm: &str) -> Self {
        self.config.realm = realm.to_string();
        self
    }

    /// Add a credential (plain text)
    pub fn add_user(mut self, username: &str, password: &str) -> Self {
        self.config.credentials.push(Credential {
            username: username.to_string(),
            password: password.to_string(),
            format: PasswordFormat::Plain,
        });
        self
    }

    /// Add a credential with SHA256 hashed password
    pub fn add_user_sha256(mut self, username: &str, password_hash: &str) -> Self {
        self.config.credentials.push(Credential {
            username: username.to_string(),
            password: password_hash.to_string(),
            format: PasswordFormat::Sha256,
        });
        self
    }

    /// Add a credential with bcrypt hashed password
    pub fn add_user_bcrypt(mut self, username: &str, password_hash: &str) -> Self {
        self.config.credentials.push(Credential {
            username: username.to_string(),
            password: password_hash.to_string(),
            format: PasswordFormat::Bcrypt,
        });
        self
    }

    /// Exclude a path from authentication
    pub fn exclude_path(mut self, path: &str) -> Self {
        self.config.exclude_paths.push(path.to_string());
        self
    }

    /// Set custom unauthorized message
    pub fn unauthorized_message(mut self, message: &str) -> Self {
        self.config.unauthorized_message = Some(message.to_string());
        self
    }

    /// Disable authentication
    pub fn disabled(mut self) -> Self {
        self.config.enabled = false;
        self
    }

    /// Build the configuration
    pub fn build(self) -> BasicAuthConfig {
        self.config
    }
}

impl Default for BasicAuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to encode Basic auth header
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    format!("Basic {}", encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_credentials() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .realm("Test Realm")
            .add_user("admin", "secret123")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = encode_basic_auth("admin", "secret123");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        
        assert!(result.is_allowed());
        assert_eq!(result.username(), Some("admin"));
    }

    #[test]
    fn test_invalid_credentials() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "secret123")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = encode_basic_auth("admin", "wrong_password");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        
        assert!(!result.is_allowed());
        assert!(matches!(result, AuthResult::InvalidCredentials));
    }

    #[test]
    fn test_no_credentials() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "secret")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let result = auth.authenticate("tunnel-1", "/", None);
        
        assert!(!result.is_allowed());
        assert!(matches!(result, AuthResult::NoCredentials));
    }

    #[test]
    fn test_excluded_path() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "secret")
            .exclude_path("/health")
            .exclude_path("/public")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        // Exact match
        let result = auth.authenticate("tunnel-1", "/health", None);
        assert!(result.is_allowed());
        assert!(matches!(result, AuthResult::Excluded));
        
        // Prefix match
        let result = auth.authenticate("tunnel-1", "/public/file.txt", None);
        assert!(result.is_allowed());
        
        // Not excluded
        let result = auth.authenticate("tunnel-1", "/api/users", None);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_disabled_auth() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "secret")
            .disabled()
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let result = auth.authenticate("tunnel-1", "/", None);
        assert!(result.is_allowed());
        assert!(matches!(result, AuthResult::Disabled));
    }

    #[test]
    fn test_unknown_tunnel() {
        let auth = BasicAuth::new();
        
        let result = auth.authenticate("unknown", "/", None);
        assert!(result.is_allowed()); // No config = disabled
    }

    #[test]
    fn test_sha256_password() {
        let auth = BasicAuth::new();
        
        // Hash of "secret123"
        let password_hash = BasicAuth::hash_sha256("secret123");
        
        let config = BasicAuthBuilder::new()
            .add_user_sha256("admin", &password_hash)
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = encode_basic_auth("admin", "secret123");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        
        assert!(result.is_allowed());
    }

    #[test]
    fn test_bcrypt_password() {
        let auth = BasicAuth::new();
        
        // Hash password with bcrypt
        let password_hash = BasicAuth::hash_bcrypt("secret123").unwrap();
        
        let config = BasicAuthBuilder::new()
            .add_user_bcrypt("admin", &password_hash)
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = encode_basic_auth("admin", "secret123");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        
        assert!(result.is_allowed());
    }

    #[test]
    fn test_multiple_users() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("alice", "password1")
            .add_user("bob", "password2")
            .add_user("charlie", "password3")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        // All users should work
        for (user, pass) in [("alice", "password1"), ("bob", "password2"), ("charlie", "password3")] {
            let header = encode_basic_auth(user, pass);
            let result = auth.authenticate("tunnel-1", "/", Some(&header));
            assert!(result.is_allowed(), "User {} should authenticate", user);
        }
        
        // Wrong password should fail
        let header = encode_basic_auth("alice", "wrong");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_www_authenticate_header() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .realm("My API")
            .add_user("user", "pass")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = auth.www_authenticate_header("tunnel-1");
        assert_eq!(header, "Basic realm=\"My API\"");
    }

    #[test]
    fn test_custom_unauthorized_message() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("user", "pass")
            .unauthorized_message("Access Denied. Please contact support.")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let body = auth.unauthorized_body("tunnel-1");
        assert_eq!(body, "Access Denied. Please contact support.");
    }

    #[test]
    fn test_malformed_auth_header() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "secret")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        // Not base64
        let result = auth.authenticate("tunnel-1", "/", Some("Basic not-base64!@#"));
        assert!(matches!(result, AuthResult::InvalidCredentials));
        
        // No colon separator
        let encoded = base64::engine::general_purpose::STANDARD.encode("usernopassword");
        let result = auth.authenticate("tunnel-1", "/", Some(&format!("Basic {}", encoded)));
        assert!(matches!(result, AuthResult::InvalidCredentials));
        
        // Wrong scheme
        let result = auth.authenticate("tunnel-1", "/", Some("Bearer token123"));
        assert!(matches!(result, AuthResult::InvalidCredentials));
    }

    #[test]
    fn test_password_with_colon() {
        let auth = BasicAuth::new();
        
        let config = BasicAuthBuilder::new()
            .add_user("admin", "pass:word:with:colons")
            .build();
        
        auth.add_config("tunnel-1", config);
        
        let header = encode_basic_auth("admin", "pass:word:with:colons");
        let result = auth.authenticate("tunnel-1", "/", Some(&header));
        
        assert!(result.is_allowed());
    }
}
