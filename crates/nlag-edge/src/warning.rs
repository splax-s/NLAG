//! First-Visit Warning Page
//!
//! Shows a warning page to users visiting tunnel URLs in a browser for the first time.
//! This helps protect users from phishing and malicious content.
//! 
//! API calls (detected via Accept header, X-Requested-With, etc.) bypass the warning.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::RwLock;

use nlag_common::types::TunnelId;

/// Cookie name for tracking acknowledgment
pub const WARNING_COOKIE_NAME: &str = "nlag_warning_ack";

/// Header to bypass warning (for programmatic access)
pub const BYPASS_HEADER: &str = "X-NLAG-Skip-Warning";

/// How long the warning acknowledgment is valid
const ACK_DURATION: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// Configuration for the warning page
#[derive(Debug, Clone)]
pub struct WarningPageConfig {
    /// Whether the warning page is enabled
    pub enabled: bool,
    
    /// Custom warning message
    pub message: Option<String>,
    
    /// Custom title
    pub title: Option<String>,
    
    /// Allowed hosts that bypass warning (e.g., internal domains)
    pub bypass_hosts: HashSet<String>,
    
    /// User agents that bypass warning (API clients, etc.)
    pub bypass_user_agents: Vec<String>,
}

impl Default for WarningPageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            message: None,
            title: None,
            bypass_hosts: HashSet::new(),
            bypass_user_agents: vec![
                "curl".to_string(),
                "wget".to_string(),
                "httpie".to_string(),
                "PostmanRuntime".to_string(),
                "axios".to_string(),
                "node-fetch".to_string(),
                "python-requests".to_string(),
                "Go-http-client".to_string(),
                "okhttp".to_string(),
            ],
        }
    }
}

/// Request classification for warning page logic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    /// Browser navigation request
    Browser,
    /// API/programmatic request
    Api,
    /// Asset request (images, CSS, JS, etc.)
    Asset,
    /// WebSocket upgrade
    WebSocket,
}

/// Warning page manager
pub struct WarningPageManager {
    /// Configuration
    config: RwLock<WarningPageConfig>,
    
    /// Acknowledged client -> expiration time
    /// Key format: "{tunnel_id}:{client_ip}" or "{tunnel_id}:{cookie_value}"
    acknowledgments: DashMap<String, u64>,
    
    /// Secret for generating secure cookie values
    cookie_secret: [u8; 32],
}

impl WarningPageManager {
    /// Create a new warning page manager
    pub fn new(config: WarningPageConfig) -> Arc<Self> {
        let mut cookie_secret = [0u8; 32];
        getrandom::fill(&mut cookie_secret);
        
        Arc::new(Self {
            config: RwLock::new(config),
            acknowledgments: DashMap::new(),
            cookie_secret,
        })
    }
    
    /// Check if warning page is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }
    
    /// Update configuration
    pub fn update_config(&self, config: WarningPageConfig) {
        *self.config.write() = config;
    }
    
    /// Classify a request based on headers
    pub fn classify_request(&self, headers: &[(String, String)]) -> RequestType {
        let get_header = |name: &str| -> Option<&str> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        
        // Check for WebSocket upgrade
        if let Some(upgrade) = get_header("upgrade") {
            if upgrade.eq_ignore_ascii_case("websocket") {
                return RequestType::WebSocket;
            }
        }
        
        // Check for bypass header
        if get_header(BYPASS_HEADER).is_some() {
            return RequestType::Api;
        }
        
        // Check X-Requested-With (AJAX)
        if get_header("x-requested-with").is_some() {
            return RequestType::Api;
        }
        
        // Check User-Agent for known API clients
        if let Some(ua) = get_header("user-agent") {
            let ua_lower = ua.to_lowercase();
            let config = self.config.read();
            for bypass_ua in &config.bypass_user_agents {
                if ua_lower.contains(&bypass_ua.to_lowercase()) {
                    return RequestType::Api;
                }
            }
        }
        
        // Check Accept header
        if let Some(accept) = get_header("accept") {
            let accept_lower = accept.to_lowercase();
            
            // API requests typically want JSON, XML, etc.
            if accept_lower.contains("application/json")
                || accept_lower.contains("application/xml")
                || accept_lower.contains("text/xml")
            {
                // But browsers also send these with lower priority
                // Check if HTML is NOT in the accept header
                if !accept_lower.contains("text/html") {
                    return RequestType::Api;
                }
            }
            
            // Asset requests
            if accept_lower.starts_with("image/")
                || accept_lower.starts_with("font/")
                || accept_lower.contains("text/css")
                || accept_lower.contains("application/javascript")
            {
                return RequestType::Asset;
            }
        }
        
        RequestType::Browser
    }
    
    /// Check if a request should show the warning page
    pub fn should_show_warning(
        &self,
        tunnel_id: &TunnelId,
        client_ip: &str,
        headers: &[(String, String)],
        _path: &str,
    ) -> bool {
        let config = self.config.read();
        
        // Check if warning is enabled
        if !config.enabled {
            return false;
        }
        
        // Check host bypass
        if let Some(host) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())
        {
            if config.bypass_hosts.contains(host) {
                return false;
            }
        }
        
        drop(config);
        
        // Classify the request
        let request_type = self.classify_request(headers);
        
        // Only show warning for browser requests
        if request_type != RequestType::Browser {
            return false;
        }
        
        // Check for acknowledgment cookie
        if let Some(cookie_value) = self.get_cookie_value(headers) {
            if self.verify_acknowledgment(tunnel_id, &cookie_value) {
                return false;
            }
        }
        
        // Check IP-based acknowledgment
        let ip_key = format!("{}:ip:{}", tunnel_id, client_ip);
        if let Some(expiry) = self.acknowledgments.get(&ip_key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if *expiry > now {
                return false;
            }
        }
        
        true
    }
    
    /// Record an acknowledgment
    pub fn acknowledge(&self, tunnel_id: &TunnelId, client_ip: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiry = now + ACK_DURATION.as_secs();
        
        // Generate cookie value
        let cookie_value = self.generate_cookie_value(tunnel_id);
        
        // Store IP-based acknowledgment
        let ip_key = format!("{}:ip:{}", tunnel_id, client_ip);
        self.acknowledgments.insert(ip_key, expiry);
        
        // Store cookie-based acknowledgment
        let cookie_key = format!("{}:cookie:{}", tunnel_id, cookie_value);
        self.acknowledgments.insert(cookie_key, expiry);
        
        cookie_value
    }
    
    /// Generate the warning page HTML
    pub fn generate_warning_page(&self, tunnel_id: &TunnelId, host: &str, path: &str) -> String {
        let config = self.config.read();
        
        let title = config.title.as_deref().unwrap_or("Security Warning");
        let message = config.message.as_deref().unwrap_or(
            "You are about to visit a tunnel hosted on this server. \
             This content is provided by a third party and may not be trustworthy."
        );
        
        let continue_url = format!("/_nlag/warning/continue?tunnel={}&path={}", 
            tunnel_id, 
            urlencoding::encode(path)
        );
        
        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            padding: 30px;
            text-align: center;
        }}
        .warning-icon {{
            width: 60px;
            height: 60px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
        }}
        .warning-icon svg {{
            width: 32px;
            height: 32px;
            fill: #fff;
        }}
        h1 {{
            color: #fff;
            font-size: 24px;
            font-weight: 600;
        }}
        .content {{
            padding: 30px;
        }}
        .message {{
            color: #4a5568;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .details {{
            background: #f7fafc;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 25px;
        }}
        .detail-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }}
        .detail-row:last-child {{
            border-bottom: none;
        }}
        .detail-label {{
            color: #718096;
            font-size: 14px;
        }}
        .detail-value {{
            color: #2d3748;
            font-weight: 500;
            font-size: 14px;
            word-break: break-all;
        }}
        .buttons {{
            display: flex;
            gap: 15px;
        }}
        .btn {{
            flex: 1;
            padding: 14px 20px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
            text-decoration: none;
            text-align: center;
        }}
        .btn-back {{
            background: #e2e8f0;
            color: #4a5568;
        }}
        .btn-back:hover {{
            background: #cbd5e0;
        }}
        .btn-continue {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
        }}
        .btn-continue:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }}
        .footer {{
            text-align: center;
            padding: 15px 30px 25px;
            color: #a0aec0;
            font-size: 12px;
        }}
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="warning-icon">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L1 21h22L12 2zm0 3.5L19.5 19h-15L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/>
                </svg>
            </div>
            <h1>{title}</h1>
        </div>
        <div class="content">
            <p class="message">{message}</p>
            <div class="details">
                <div class="detail-row">
                    <span class="detail-label">Host</span>
                    <span class="detail-value">{host}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Path</span>
                    <span class="detail-value">{path}</span>
                </div>
            </div>
            <div class="buttons">
                <a href="javascript:history.back()" class="btn btn-back">Go Back</a>
                <a href="{continue_url}" class="btn btn-continue">Continue Anyway</a>
            </div>
        </div>
        <div class="footer">
            Powered by <a href="https://github.com/your-repo/nlag">NLAG</a>
        </div>
    </div>
</body>
</html>"#)
    }
    
    /// Generate a secure cookie value
    fn generate_cookie_value(&self, tunnel_id: &TunnelId) -> String {
        use std::hash::{Hash, Hasher};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create a simple HMAC-like signature
        let mut data = Vec::new();
        data.extend_from_slice(&self.cookie_secret);
        data.extend_from_slice(tunnel_id.to_string().as_bytes());
        data.extend_from_slice(&now.to_le_bytes());
        
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();
        
        format!("{:016x}{:016x}", now, hash)
    }
    
    /// Extract cookie value from headers
    fn get_cookie_value(&self, headers: &[(String, String)]) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .and_then(|(_, v)| {
                for part in v.split(';') {
                    let part = part.trim();
                    if let Some(value) = part.strip_prefix(&format!("{}=", WARNING_COOKIE_NAME)) {
                        return Some(value.to_string());
                    }
                }
                None
            })
    }
    
    /// Verify an acknowledgment cookie
    fn verify_acknowledgment(&self, tunnel_id: &TunnelId, cookie_value: &str) -> bool {
        let cookie_key = format!("{}:cookie:{}", tunnel_id, cookie_value);
        
        if let Some(expiry) = self.acknowledgments.get(&cookie_key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            return *expiry > now;
        }
        
        false
    }
    
    /// Clean up expired acknowledgments
    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.acknowledgments.retain(|_, expiry| *expiry > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_request_classification() {
        let manager = WarningPageManager::new(WarningPageConfig::default());
        
        // Browser request
        let headers = vec![
            ("Accept".to_string(), "text/html,application/xhtml+xml".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ];
        assert_eq!(manager.classify_request(&headers), RequestType::Browser);
        
        // API request (curl)
        let headers = vec![
            ("Accept".to_string(), "*/*".to_string()),
            ("User-Agent".to_string(), "curl/7.64.1".to_string()),
        ];
        assert_eq!(manager.classify_request(&headers), RequestType::Api);
        
        // API request (JSON accept)
        let headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ];
        assert_eq!(manager.classify_request(&headers), RequestType::Api);
        
        // WebSocket
        let headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
        ];
        assert_eq!(manager.classify_request(&headers), RequestType::WebSocket);
        
        // Asset
        let headers = vec![
            ("Accept".to_string(), "image/webp,image/png,image/*".to_string()),
        ];
        assert_eq!(manager.classify_request(&headers), RequestType::Asset);
    }
    
    #[test]
    fn test_acknowledgment() {
        let manager = WarningPageManager::new(WarningPageConfig::default());
        let tunnel_id = TunnelId::new();
        let client_ip = "192.168.1.1";
        
        // Should show warning before acknowledgment
        let headers = vec![
            ("Accept".to_string(), "text/html".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ];
        assert!(manager.should_show_warning(&tunnel_id, client_ip, &headers, "/"));
        
        // Acknowledge
        let _cookie = manager.acknowledge(&tunnel_id, client_ip);
        
        // Should not show warning after acknowledgment (IP-based)
        assert!(!manager.should_show_warning(&tunnel_id, client_ip, &headers, "/"));
    }
}
