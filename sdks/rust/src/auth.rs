//! Authentication utilities.

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authentication credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// Access token for API requests
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,
    /// Token expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

impl Credentials {
    /// Check if the credentials are expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| exp < Utc::now())
            .unwrap_or(false)
    }

    /// Check if the credentials will expire soon (within 5 minutes).
    pub fn expires_soon(&self) -> bool {
        self.expires_at
            .map(|exp| exp < Utc::now() + chrono::Duration::minutes(5))
            .unwrap_or(false)
    }
}

/// Get the credentials file path.
pub fn credentials_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| Error::Configuration("Could not find config directory".to_string()))?;
    Ok(config_dir.join("nlag").join("credentials.json"))
}

/// Load stored credentials from disk.
pub async fn load_credentials() -> Result<Credentials> {
    let path = credentials_path()?;
    
    let contents = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| Error::Authentication(format!("Failed to read credentials: {}", e)))?;

    let credentials: Credentials = serde_json::from_str(&contents)
        .map_err(|e| Error::Authentication(format!("Invalid credentials file: {}", e)))?;

    Ok(credentials)
}

/// Save credentials to disk.
pub async fn save_credentials(credentials: &Credentials) -> Result<()> {
    let path = credentials_path()?;

    // Create directory if needed
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| Error::Configuration(format!("Failed to create config dir: {}", e)))?;
    }

    let contents = serde_json::to_string_pretty(credentials)
        .map_err(|e| Error::Json(e.to_string()))?;

    tokio::fs::write(&path, contents)
        .await
        .map_err(|e| Error::Authentication(format!("Failed to save credentials: {}", e)))?;

    // Set file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| Error::Configuration(format!("Failed to set permissions: {}", e)))?;
    }

    Ok(())
}

/// Delete stored credentials.
pub async fn delete_credentials() -> Result<()> {
    let path = credentials_path()?;
    
    if path.exists() {
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| Error::Authentication(format!("Failed to delete credentials: {}", e)))?;
    }

    Ok(())
}

/// Authenticate with email and password.
pub async fn authenticate(
    api_url: &str,
    email: &str,
    password: &str,
) -> Result<Credentials> {
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/auth/login", api_url))
        .json(&LoginRequest { email, password })
        .send()
        .await
        .map_err(|e| Error::Connection(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(Error::Authentication(format!(
            "Login failed: {} - {}",
            status, body
        )));
    }

    let auth_response: AuthResponse = response
        .json()
        .await
        .map_err(|e| Error::Json(e.to_string()))?;

    let credentials = Credentials {
        access_token: auth_response.access_token,
        refresh_token: auth_response.refresh_token,
        expires_at: auth_response.expires_at,
    };

    // Save credentials for future use
    save_credentials(&credentials).await?;

    Ok(credentials)
}

/// Authenticate with an API token.
pub async fn authenticate_with_token(
    api_url: &str,
    api_token: &str,
) -> Result<Credentials> {
    let client = reqwest::Client::new();

    // Validate the token
    let response = client
        .get(format!("{}/auth/me", api_url))
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| Error::Connection(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::Authentication("Invalid API token".to_string()));
    }

    let credentials = Credentials {
        access_token: api_token.to_string(),
        refresh_token: None,
        expires_at: None,
    };

    save_credentials(&credentials).await?;

    Ok(credentials)
}

/// Refresh an access token using the refresh token.
pub async fn refresh_token(
    api_url: &str,
    refresh_token: &str,
) -> Result<Credentials> {
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/auth/refresh", api_url))
        .json(&RefreshRequest { refresh_token })
        .send()
        .await
        .map_err(|e| Error::Connection(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::Authentication("Failed to refresh token".to_string()));
    }

    let auth_response: AuthResponse = response
        .json()
        .await
        .map_err(|e| Error::Json(e.to_string()))?;

    let credentials = Credentials {
        access_token: auth_response.access_token,
        refresh_token: auth_response.refresh_token,
        expires_at: auth_response.expires_at,
    };

    save_credentials(&credentials).await?;

    Ok(credentials)
}

/// Log out and delete stored credentials.
pub async fn logout() -> Result<()> {
    delete_credentials().await
}

#[derive(Debug, Serialize)]
struct LoginRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_expired() {
        let expired = Credentials {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };
        assert!(expired.is_expired());

        let valid = Credentials {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_credentials_expires_soon() {
        let soon = Credentials {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(Utc::now() + chrono::Duration::minutes(2)),
        };
        assert!(soon.expires_soon());

        let later = Credentials {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        assert!(!later.expires_soon());
    }

    #[test]
    fn test_credentials_path() {
        let path = credentials_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.ends_with("nlag/credentials.json"));
    }
}
