//! Authentication module for NLAG agent
//!
//! Handles user authentication, credential storage, and token management.
//! Credentials are stored in `~/.nlag/credentials.json`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Stored user credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// User's email address
    pub email: String,
    /// JWT access token
    pub access_token: String,
    /// Token expiration timestamp (Unix epoch seconds)
    pub expires_at: u64,
    /// Control plane server URL
    pub server: String,
    /// User tier (free, pro, enterprise)
    pub tier: UserTier,
    /// Maximum tunnels allowed
    pub max_tunnels: u32,
}

/// User subscription tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserTier {
    /// Free tier - 1 tunnel max
    Free,
    /// Pro tier - 10 tunnels max
    Pro,
    /// Enterprise tier - unlimited tunnels
    Enterprise,
}

impl Default for UserTier {
    fn default() -> Self {
        Self::Free
    }
}

impl std::fmt::Display for UserTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Free => write!(f, "Free"),
            Self::Pro => write!(f, "Pro"),
            Self::Enterprise => write!(f, "Enterprise"),
        }
    }
}

impl UserTier {
    /// Get the maximum number of tunnels allowed for this tier
    pub fn max_tunnels(&self) -> u32 {
        match self {
            Self::Free => 1,
            Self::Pro => 10,
            Self::Enterprise => u32::MAX,
        }
    }
}

/// Get the NLAG configuration directory path
pub fn config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".nlag"))
}

/// Get the credentials file path
pub fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials.json"))
}

/// Check if the user is authenticated
pub fn is_authenticated() -> bool {
    load_credentials().is_ok()
}

/// Load stored credentials from disk
pub fn load_credentials() -> Result<Credentials> {
    let path = credentials_path()?;
    
    if !path.exists() {
        anyhow::bail!("Not logged in. Run `nlag login` to authenticate.");
    }
    
    let content = fs::read_to_string(&path)
        .context("Failed to read credentials file")?;
    
    let creds: Credentials = serde_json::from_str(&content)
        .context("Failed to parse credentials file")?;
    
    // Check if token is expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if creds.expires_at < now {
        anyhow::bail!("Session expired. Run `nlag login` to re-authenticate.");
    }
    
    Ok(creds)
}

/// Save credentials to disk
pub fn save_credentials(creds: &Credentials) -> Result<()> {
    let dir = config_dir()?;
    
    // Create directory if it doesn't exist
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .context("Failed to create config directory")?;
    }
    
    let path = credentials_path()?;
    let content = serde_json::to_string_pretty(creds)
        .context("Failed to serialize credentials")?;
    
    fs::write(&path, content)
        .context("Failed to write credentials file")?;
    
    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)
            .context("Failed to set file permissions")?;
    }
    
    Ok(())
}

/// Clear stored credentials (logout)
pub fn clear_credentials() -> Result<()> {
    let path = credentials_path()?;
    
    if path.exists() {
        fs::remove_file(&path)
            .context("Failed to remove credentials file")?;
    }
    
    Ok(())
}

/// Login request payload
#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response from control plane
#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_at: u64,
    pub user: UserInfo,
}

/// User information from login response
#[derive(Debug, Deserialize)]
pub struct UserInfo {
    pub email: String,
    pub tier: String,
    pub max_tunnels: u32,
}

impl UserInfo {
    /// Convert tier string to UserTier enum
    pub fn to_user_tier(&self) -> UserTier {
        match self.tier.to_lowercase().as_str() {
            "pro" | "team" | "business" => UserTier::Pro,
            "enterprise" => UserTier::Enterprise,
            _ => UserTier::Free,
        }
    }
}

/// Authenticate with the control plane
pub async fn login(server: &str, email: &str, password: &str) -> Result<Credentials> {
    let client = reqwest::Client::new();
    
    let request = LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
    };
    
    let response = client
        .post(format!("{}/api/v1/auth/login", server))
        .json(&request)
        .send()
        .await
        .context("Failed to connect to control plane")?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Login failed ({}): {}", status, body);
    }
    
    let login_response: LoginResponse = response
        .json()
        .await
        .context("Failed to parse login response")?;
    
    let tier = login_response.user.to_user_tier();
    
    let creds = Credentials {
        email: login_response.user.email,
        access_token: login_response.access_token,
        expires_at: login_response.expires_at,
        server: server.to_string(),
        tier,
        max_tunnels: login_response.user.max_tunnels,
    };
    
    save_credentials(&creds)?;
    
    Ok(creds)
}

/// Get the current user's tunnel count from the control plane
pub async fn get_tunnel_count(creds: &Credentials) -> Result<u32> {
    let client = reqwest::Client::new();
    
    let response = client
        .get(format!("{}/api/v1/tunnels/count", creds.server))
        .bearer_auth(&creds.access_token)
        .send()
        .await
        .context("Failed to get tunnel count")?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to get tunnel count: {}", response.status());
    }
    
    #[derive(Deserialize)]
    struct CountResponse {
        count: u32,
    }
    
    let count: CountResponse = response.json().await?;
    Ok(count.count)
}

/// Check if the user can create a new tunnel
pub async fn can_create_tunnel(creds: &Credentials) -> Result<bool> {
    let current = get_tunnel_count(creds).await?;
    Ok(current < creds.max_tunnels)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_tier_max_tunnels() {
        assert_eq!(UserTier::Free.max_tunnels(), 1);
        assert_eq!(UserTier::Pro.max_tunnels(), 10);
        assert_eq!(UserTier::Enterprise.max_tunnels(), u32::MAX);
    }
    
    #[test]
    fn test_user_tier_display() {
        assert_eq!(UserTier::Free.to_string(), "Free");
        assert_eq!(UserTier::Pro.to_string(), "Pro");
        assert_eq!(UserTier::Enterprise.to_string(), "Enterprise");
    }
    
    #[test]
    fn test_credentials_serialization() {
        let creds = Credentials {
            email: "test@example.com".to_string(),
            access_token: "token123".to_string(),
            expires_at: 1700000000,
            server: "https://api.nlag.dev".to_string(),
            tier: UserTier::Pro,
            max_tunnels: 10,
        };
        
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.email, creds.email);
        assert_eq!(parsed.tier, UserTier::Pro);
    }
}
