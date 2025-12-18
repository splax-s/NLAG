//! Custom Error Pages Module
//!
//! Provides branded, customizable error pages for various HTTP error conditions.
//! Supports:
//! - Custom HTML templates
//! - Variable interpolation (status code, message, request ID)
//! - Per-tunnel configuration
//! - Default fallback pages

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Error page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPageConfig {
    /// Whether custom error pages are enabled
    pub enabled: bool,
    /// Brand name to display
    pub brand_name: String,
    /// Support email address
    pub support_email: Option<String>,
    /// Support URL
    pub support_url: Option<String>,
    /// Logo URL (for HTML pages)
    pub logo_url: Option<String>,
    /// Primary brand color (hex)
    pub primary_color: String,
    /// Custom CSS to inject
    pub custom_css: Option<String>,
}

impl Default for ErrorPageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            brand_name: "NLAG".to_string(),
            support_email: None,
            support_url: None,
            logo_url: None,
            primary_color: "#3498db".to_string(),
            custom_css: None,
        }
    }
}

/// Variables available for template interpolation
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// HTTP status code
    pub status_code: u16,
    /// Status text (e.g., "Not Found")
    pub status_text: String,
    /// Human-readable error message
    pub message: String,
    /// Detailed error description
    pub details: Option<String>,
    /// Request ID for tracking
    pub request_id: Option<String>,
    /// Tunnel ID if available
    pub tunnel_id: Option<String>,
    /// Requested path
    pub path: String,
    /// Request method
    pub method: String,
    /// Timestamp of the error
    pub timestamp: String,
}

/// Error page template
#[derive(Debug, Clone)]
pub struct ErrorTemplate {
    /// Template HTML content
    pub html: String,
    /// Content-Type header value
    pub content_type: String,
}

/// Error page manager
pub struct ErrorPageManager {
    /// Global configuration
    config: ErrorPageConfig,
    /// Custom templates by status code
    templates: RwLock<HashMap<u16, ErrorTemplate>>,
    /// Per-tunnel configurations
    tunnel_configs: RwLock<HashMap<String, ErrorPageConfig>>,
}

impl ErrorPageManager {
    /// Create a new error page manager
    pub fn new(config: ErrorPageConfig) -> Self {
        Self {
            config,
            templates: RwLock::new(HashMap::new()),
            tunnel_configs: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ErrorPageConfig::default())
    }

    /// Set a custom template for a specific status code
    pub fn set_template(&self, status_code: u16, template: ErrorTemplate) {
        self.templates.write().insert(status_code, template);
    }

    /// Set tunnel-specific configuration
    pub fn set_tunnel_config(&self, tunnel_id: &str, config: ErrorPageConfig) {
        self.tunnel_configs.write().insert(tunnel_id.to_string(), config);
    }

    /// Remove tunnel-specific configuration
    pub fn remove_tunnel_config(&self, tunnel_id: &str) {
        self.tunnel_configs.write().remove(tunnel_id);
    }

    /// Get the configuration for a tunnel (or global default)
    pub fn get_config(&self, tunnel_id: Option<&str>) -> ErrorPageConfig {
        if let Some(id) = tunnel_id {
            if let Some(config) = self.tunnel_configs.read().get(id) {
                return config.clone();
            }
        }
        self.config.clone()
    }

    /// Render an error page
    pub fn render(&self, context: &ErrorContext, tunnel_id: Option<&str>) -> (String, String) {
        let config = self.get_config(tunnel_id);
        
        if !config.enabled {
            // Return minimal plain text response
            return (
                format!("{} {}", context.status_code, context.status_text),
                "text/plain".to_string(),
            );
        }

        // Check for custom template
        if let Some(template) = self.templates.read().get(&context.status_code) {
            let html = self.interpolate(&template.html, context, &config);
            return (html, template.content_type.clone());
        }

        // Use default template
        let html = self.render_default(context, &config);
        (html, "text/html; charset=utf-8".to_string())
    }

    /// Render the default error page
    fn render_default(&self, context: &ErrorContext, config: &ErrorPageConfig) -> String {
        let emoji = match context.status_code {
            400..=499 => "🔍",
            500..=599 => "⚠️",
            _ => "ℹ️",
        };

        let custom_css = config.custom_css.as_deref().unwrap_or("");
        
        let support_section = if let Some(ref email) = config.support_email {
            format!(r#"<p class="support">Need help? Contact <a href="mailto:{}">{}</a></p>"#, email, email)
        } else if let Some(ref url) = config.support_url {
            format!(r#"<p class="support">Need help? Visit <a href="{}">{}</a></p>"#, url, url)
        } else {
            String::new()
        };

        let request_id_section = if let Some(ref id) = context.request_id {
            format!(r#"<p class="request-id">Request ID: <code>{}</code></p>"#, id)
        } else {
            String::new()
        };

        let details_section = if let Some(ref details) = context.details {
            format!(r#"<div class="details"><p>{}</p></div>"#, html_escape(details))
        } else {
            String::new()
        };

        let logo_section = if let Some(ref logo_url) = config.logo_url {
            format!(r#"<img src="{}" alt="{}" class="logo">"#, logo_url, config.brand_name)
        } else {
            format!(r#"<h1 class="brand">{}</h1>"#, config.brand_name)
        };

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} {status_text} - {brand_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            padding: 20px;
        }}
        .container {{
            text-align: center;
            max-width: 600px;
        }}
        .logo {{
            max-width: 150px;
            margin-bottom: 20px;
        }}
        .brand {{
            font-size: 1.5rem;
            color: {primary_color};
            margin-bottom: 20px;
        }}
        .emoji {{
            font-size: 4rem;
            margin-bottom: 20px;
        }}
        .status-code {{
            font-size: 6rem;
            font-weight: 700;
            color: {primary_color};
            line-height: 1;
        }}
        .status-text {{
            font-size: 1.5rem;
            color: #ccc;
            margin-bottom: 20px;
        }}
        .message {{
            font-size: 1.1rem;
            color: #aaa;
            margin-bottom: 30px;
            line-height: 1.6;
        }}
        .details {{
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            text-align: left;
            font-family: monospace;
            font-size: 0.9rem;
            color: #888;
        }}
        .request-info {{
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 0.85rem;
            color: #666;
        }}
        .request-info code {{
            background: rgba(255,255,255,0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }}
        .request-id {{
            font-size: 0.8rem;
            color: #555;
            margin-top: 20px;
        }}
        .request-id code {{
            background: rgba(255,255,255,0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .support {{
            margin-top: 30px;
            font-size: 0.9rem;
        }}
        .support a {{
            color: {primary_color};
            text-decoration: none;
        }}
        .support a:hover {{
            text-decoration: underline;
        }}
        .back-btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: {primary_color};
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: opacity 0.2s;
        }}
        .back-btn:hover {{
            opacity: 0.9;
        }}
        .timestamp {{
            font-size: 0.75rem;
            color: #444;
            margin-top: 30px;
        }}
        {custom_css}
    </style>
</head>
<body>
    <div class="container">
        {logo_section}
        <div class="emoji">{emoji}</div>
        <div class="status-code">{status_code}</div>
        <div class="status-text">{status_text}</div>
        <p class="message">{message}</p>
        {details_section}
        <div class="request-info">
            <code>{method}</code> <code>{path}</code>
        </div>
        <a href="javascript:history.back()" class="back-btn">Go Back</a>
        {request_id_section}
        {support_section}
        <p class="timestamp">{timestamp}</p>
    </div>
</body>
</html>"#,
            status_code = context.status_code,
            status_text = html_escape(&context.status_text),
            brand_name = html_escape(&config.brand_name),
            primary_color = &config.primary_color,
            emoji = emoji,
            message = html_escape(&context.message),
            method = html_escape(&context.method),
            path = html_escape(&context.path),
            timestamp = html_escape(&context.timestamp),
            custom_css = custom_css,
            logo_section = logo_section,
            details_section = details_section,
            request_id_section = request_id_section,
            support_section = support_section,
        )
    }

    /// Interpolate variables in a custom template
    fn interpolate(&self, template: &str, context: &ErrorContext, config: &ErrorPageConfig) -> String {
        template
            .replace("{{status_code}}", &context.status_code.to_string())
            .replace("{{status_text}}", &html_escape(&context.status_text))
            .replace("{{message}}", &html_escape(&context.message))
            .replace("{{details}}", &html_escape(context.details.as_deref().unwrap_or("")))
            .replace("{{request_id}}", context.request_id.as_deref().unwrap_or(""))
            .replace("{{tunnel_id}}", context.tunnel_id.as_deref().unwrap_or(""))
            .replace("{{path}}", &html_escape(&context.path))
            .replace("{{method}}", &html_escape(&context.method))
            .replace("{{timestamp}}", &html_escape(&context.timestamp))
            .replace("{{brand_name}}", &html_escape(&config.brand_name))
            .replace("{{primary_color}}", &config.primary_color)
            .replace("{{support_email}}", config.support_email.as_deref().unwrap_or(""))
            .replace("{{support_url}}", config.support_url.as_deref().unwrap_or(""))
            .replace("{{logo_url}}", config.logo_url.as_deref().unwrap_or(""))
    }
}

/// HTML escape helper
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Common error page generators
impl ErrorPageManager {
    /// Generate a 400 Bad Request page
    pub fn bad_request(&self, message: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 400,
            status_text: "Bad Request".to_string(),
            message: message.to_string(),
            details: None,
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 400)
    }

    /// Generate a 401 Unauthorized page
    pub fn unauthorized(&self, message: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 401,
            status_text: "Unauthorized".to_string(),
            message: message.to_string(),
            details: Some("Please provide valid authentication credentials.".to_string()),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 401)
    }

    /// Generate a 403 Forbidden page
    pub fn forbidden(&self, message: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 403,
            status_text: "Forbidden".to_string(),
            message: message.to_string(),
            details: Some("You don't have permission to access this resource.".to_string()),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 403)
    }

    /// Generate a 404 Not Found page
    pub fn not_found(&self, path: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 404,
            status_text: "Not Found".to_string(),
            message: "The requested resource could not be found.".to_string(),
            details: None,
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: path.to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 404)
    }

    /// Generate a 429 Too Many Requests page
    pub fn rate_limited(&self, retry_after: Option<u64>, request_id: Option<&str>) -> (String, String, u16) {
        let message = if let Some(secs) = retry_after {
            format!("You've made too many requests. Please try again in {} seconds.", secs)
        } else {
            "You've made too many requests. Please slow down and try again later.".to_string()
        };
        
        let context = ErrorContext {
            status_code: 429,
            status_text: "Too Many Requests".to_string(),
            message,
            details: None,
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 429)
    }

    /// Generate a 500 Internal Server Error page
    pub fn internal_error(&self, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 500,
            status_text: "Internal Server Error".to_string(),
            message: "Something went wrong on our end. We've been notified and are working on it.".to_string(),
            details: None,
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 500)
    }

    /// Generate a 502 Bad Gateway page
    pub fn bad_gateway(&self, tunnel_id: Option<&str>, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 502,
            status_text: "Bad Gateway".to_string(),
            message: "The tunnel endpoint is not responding. The local service may be down.".to_string(),
            details: tunnel_id.map(|id| format!("Tunnel: {}", id)),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: tunnel_id.map(|s| s.to_string()),
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, tunnel_id);
        (html, content_type, 502)
    }

    /// Generate a 503 Service Unavailable page
    pub fn service_unavailable(&self, message: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 503,
            status_text: "Service Unavailable".to_string(),
            message: message.to_string(),
            details: Some("The service is temporarily unavailable. Please try again later.".to_string()),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 503)
    }

    /// Generate a 504 Gateway Timeout page
    pub fn gateway_timeout(&self, tunnel_id: Option<&str>, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 504,
            status_text: "Gateway Timeout".to_string(),
            message: "The tunnel endpoint took too long to respond.".to_string(),
            details: tunnel_id.map(|id| format!("Tunnel: {}", id)),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: tunnel_id.map(|s| s.to_string()),
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, tunnel_id);
        (html, content_type, 504)
    }

    /// Generate a tunnel not found page
    pub fn tunnel_not_found(&self, subdomain: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 404,
            status_text: "Tunnel Not Found".to_string(),
            message: format!("No active tunnel found for '{}'.", subdomain),
            details: Some("The tunnel may have been closed or never existed.".to_string()),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, None);
        (html, content_type, 404)
    }

    /// Generate a tunnel offline page
    pub fn tunnel_offline(&self, tunnel_id: &str, request_id: Option<&str>) -> (String, String, u16) {
        let context = ErrorContext {
            status_code: 503,
            status_text: "Tunnel Offline".to_string(),
            message: "This tunnel is currently offline.".to_string(),
            details: Some("The agent is not connected. Please start the agent to bring the tunnel online.".to_string()),
            request_id: request_id.map(|s| s.to_string()),
            tunnel_id: Some(tunnel_id.to_string()),
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let (html, content_type) = self.render(&context, Some(tunnel_id));
        (html, content_type, 503)
    }
}

/// Thread-safe error page manager
pub type SharedErrorPageManager = Arc<ErrorPageManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ErrorPageConfig::default();
        assert!(config.enabled);
        assert_eq!(config.brand_name, "NLAG");
        assert_eq!(config.primary_color, "#3498db");
    }

    #[test]
    fn test_render_404() {
        let manager = ErrorPageManager::with_defaults();
        let (html, content_type, status) = manager.not_found("/test/path", Some("req-123"));
        
        assert_eq!(status, 404);
        assert!(content_type.contains("text/html"));
        assert!(html.contains("404"));
        assert!(html.contains("Not Found"));
        assert!(html.contains("req-123"));
    }

    #[test]
    fn test_render_500() {
        let manager = ErrorPageManager::with_defaults();
        let (html, content_type, status) = manager.internal_error(Some("req-456"));
        
        assert_eq!(status, 500);
        assert!(content_type.contains("text/html"));
        assert!(html.contains("500"));
        assert!(html.contains("Internal Server Error"));
    }

    #[test]
    fn test_custom_template() {
        let manager = ErrorPageManager::with_defaults();
        manager.set_template(404, ErrorTemplate {
            html: "<h1>{{status_code}} - {{message}}</h1>".to_string(),
            content_type: "text/html".to_string(),
        });
        
        let context = ErrorContext {
            status_code: 404,
            status_text: "Not Found".to_string(),
            message: "Custom message".to_string(),
            details: None,
            request_id: None,
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        
        let (html, _) = manager.render(&context, None);
        assert_eq!(html, "<h1>404 - Custom message</h1>");
    }

    #[test]
    fn test_tunnel_config() {
        let manager = ErrorPageManager::with_defaults();
        
        let custom_config = ErrorPageConfig {
            brand_name: "My App".to_string(),
            primary_color: "#ff0000".to_string(),
            ..Default::default()
        };
        
        manager.set_tunnel_config("tunnel-1", custom_config);
        
        let config = manager.get_config(Some("tunnel-1"));
        assert_eq!(config.brand_name, "My App");
        assert_eq!(config.primary_color, "#ff0000");
        
        let default_config = manager.get_config(Some("tunnel-2"));
        assert_eq!(default_config.brand_name, "NLAG");
    }

    #[test]
    fn test_disabled_pages() {
        let config = ErrorPageConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = ErrorPageManager::new(config);
        
        let context = ErrorContext {
            status_code: 500,
            status_text: "Internal Server Error".to_string(),
            message: "Error".to_string(),
            details: None,
            request_id: None,
            tunnel_id: None,
            path: "/".to_string(),
            method: "GET".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        
        let (body, content_type) = manager.render(&context, None);
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "500 Internal Server Error");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert('xss')</script>"), 
                   "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    #[test]
    fn test_rate_limited() {
        let manager = ErrorPageManager::with_defaults();
        let (html, _, status) = manager.rate_limited(Some(60), None);
        
        assert_eq!(status, 429);
        assert!(html.contains("429"));
        assert!(html.contains("60 seconds"));
    }

    #[test]
    fn test_bad_gateway() {
        let manager = ErrorPageManager::with_defaults();
        let (html, _, status) = manager.bad_gateway(Some("tunnel-123"), Some("req-789"));
        
        assert_eq!(status, 502);
        assert!(html.contains("502"));
        assert!(html.contains("tunnel-123"));
    }
}
