//! Middleware Orchestration
//!
//! This module coordinates all middleware components in the request/response pipeline:
//! - Basic Auth (per-tunnel authentication)
//! - URL Rewriting (path/host rewriting)
//! - Wildcard Domain Routing
//! - Event Webhooks (tunnel lifecycle events)
//! - Error Pages (custom error responses)
//! - IP Restrictions (allow/deny lists)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use nlag_common::types::TunnelId;

use crate::basic_auth::{BasicAuth, AuthResult};
use crate::error_pages::{ErrorPageManager, ErrorPageConfig, ErrorContext};
use crate::event_webhooks::{EventWebhooks, EventType, Event};
use crate::url_rewrite::{RewriteEngine, RewriteContext, RewriteResult};
use crate::wildcard::WildcardRouter;

/// Middleware pipeline configuration for a tunnel
#[derive(Debug, Clone)]
pub struct TunnelMiddleware {
    /// Tunnel ID
    pub tunnel_id: TunnelId,
    /// IP restrictions
    pub ip_restriction: Option<IpRestrictionConfig>,
}

/// IP restriction configuration
#[derive(Debug, Clone)]
pub struct IpRestrictionConfig {
    /// Allowed IPs/CIDRs
    pub allow: Vec<String>,
    /// Denied IPs/CIDRs
    pub deny: Vec<String>,
}

/// Result of middleware processing
#[derive(Debug)]
pub enum MiddlewareResult {
    /// Continue processing the request
    Continue {
        /// Modified path
        path: String,
        /// Modified headers
        headers: Vec<(String, String)>,
    },
    /// Return an HTTP response immediately
    Response {
        /// HTTP status code
        status: u16,
        /// Response headers
        headers: Vec<(String, String)>,
        /// Response body
        body: String,
    },
    /// Redirect to another URL
    Redirect {
        /// Target URL
        location: String,
        /// Permanent (301) or temporary (302)
        permanent: bool,
    },
}

/// Middleware pipeline manager
pub struct MiddlewarePipeline {
    /// Per-tunnel middleware configuration
    tunnel_configs: RwLock<HashMap<TunnelId, TunnelMiddleware>>,
    /// Global basic auth
    basic_auth: Arc<BasicAuth>,
    /// Global rewrite engine
    rewrite: Arc<RewriteEngine>,
    /// Global error pages
    error_pages: Arc<ErrorPageManager>,
    /// Wildcard domain router
    wildcard_router: Arc<WildcardRouter>,
    /// Event webhooks
    event_webhooks: Arc<EventWebhooks>,
}

impl MiddlewarePipeline {
    /// Create a new middleware pipeline
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tunnel_configs: RwLock::new(HashMap::new()),
            basic_auth: BasicAuth::new(),
            rewrite: RewriteEngine::new(),
            error_pages: Arc::new(ErrorPageManager::new(ErrorPageConfig::default())),
            wildcard_router: WildcardRouter::new(),
            event_webhooks: EventWebhooks::new(),
        })
    }

    /// Create with custom components
    pub fn with_components(
        basic_auth: Arc<BasicAuth>,
        rewrite: Arc<RewriteEngine>,
        error_pages: Arc<ErrorPageManager>,
        wildcard_router: Arc<WildcardRouter>,
        event_webhooks: Arc<EventWebhooks>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tunnel_configs: RwLock::new(HashMap::new()),
            basic_auth,
            rewrite,
            error_pages,
            wildcard_router,
            event_webhooks,
        })
    }

    /// Register middleware configuration for a tunnel
    pub fn register_tunnel(&self, config: TunnelMiddleware) {
        self.tunnel_configs.write().insert(config.tunnel_id, config);
    }

    /// Remove middleware configuration for a tunnel
    pub fn unregister_tunnel(&self, tunnel_id: &TunnelId) {
        self.tunnel_configs.write().remove(tunnel_id);
    }

    /// Get the basic auth component
    pub fn basic_auth(&self) -> &BasicAuth {
        &self.basic_auth
    }

    /// Get the rewrite engine
    pub fn rewrite(&self) -> &RewriteEngine {
        &self.rewrite
    }

    /// Get the error pages component
    pub fn error_pages(&self) -> &ErrorPageManager {
        &self.error_pages
    }

    /// Get the event webhooks component
    pub fn event_webhooks(&self) -> &EventWebhooks {
        &self.event_webhooks
    }

    /// Get the wildcard router
    pub fn wildcard_router(&self) -> &WildcardRouter {
        &self.wildcard_router
    }

    /// Process an incoming request through the middleware pipeline
    pub fn process_request(
        &self,
        tunnel_id: &TunnelId,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(String, String)],
        client_ip: &IpAddr,
    ) -> MiddlewareResult {
        let configs = self.tunnel_configs.read();
        let tunnel_key = format!("{}", tunnel_id);
        
        // Check IP restrictions first
        if let Some(config) = configs.get(tunnel_id) {
            if let Some(ref ip_config) = config.ip_restriction {
                if !self.check_ip_allowed(client_ip, ip_config) {
                    return MiddlewareResult::Response {
                        status: 403,
                        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                        body: "Forbidden: IP not allowed".to_string(),
                    };
                }
            }
        }

        // Check basic auth
        let auth_header = headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());

        let auth_result = self.basic_auth.authenticate(&tunnel_key, path, auth_header);
        if !auth_result.is_allowed() {
            match auth_result {
                AuthResult::NoCredentials | AuthResult::InvalidCredentials => {
                    let realm = self.basic_auth.get_config(&tunnel_key)
                        .map(|c| c.realm.clone())
                        .unwrap_or_else(|| "NLAG".to_string());
                    return MiddlewareResult::Response {
                        status: 401,
                        headers: vec![
                            ("WWW-Authenticate".to_string(), format!("Basic realm=\"{}\"", realm)),
                            ("Content-Type".to_string(), "text/plain".to_string()),
                        ],
                        body: "Unauthorized".to_string(),
                    };
                }
                _ => {}
            }
        }

        // Apply URL rewriting
        let mut current_path = path.to_string();
        let mut final_headers: Vec<(String, String)> = headers.to_vec();

        // Build rewrite context
        let headers_map: HashMap<String, String> = headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let rewrite_ctx = RewriteContext::new(method, path, None, host)
            .with_headers(headers_map);

        let rewrite_result = self.rewrite.evaluate(&tunnel_key, &rewrite_ctx);
        match rewrite_result {
            RewriteResult::Rewrite { path: new_path, headers: new_headers, .. } => {
                current_path = new_path;
                for (k, v) in new_headers {
                    final_headers.push((k, v));
                }
            }
            RewriteResult::Redirect { location, status } => {
                return MiddlewareResult::Redirect {
                    location,
                    permanent: status == 301 || status == 308,
                };
            }
            RewriteResult::Proxy { target, headers: new_headers } => {
                current_path = target;
                for (k, v) in new_headers {
                    final_headers.push((k, v));
                }
            }
            RewriteResult::NoMatch => {
                // No rewrite needed
            }
        }

        MiddlewareResult::Continue {
            path: current_path,
            headers: final_headers,
        }
    }

    /// Generate an error response
    pub fn error_response(&self, tunnel_id: &TunnelId, status: u16, path: &str, method: &str, error_message: &str) -> (Vec<(String, String)>, String) {
        let status_text = match status {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Error",
        };

        let context = ErrorContext {
            status_code: status,
            status_text: status_text.to_string(),
            message: error_message.to_string(),
            details: None,
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            tunnel_id: Some(format!("{}", tunnel_id)),
            path: path.to_string(),
            method: method.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let tunnel_key = format!("{}", tunnel_id);
        let (body, content_type) = self.error_pages.render(&context, Some(&tunnel_key));
        
        let headers = vec![
            ("Content-Type".to_string(), content_type),
            ("Content-Length".to_string(), body.len().to_string()),
        ];

        (headers, body)
    }

    /// Route a wildcard domain to a tunnel
    pub fn route_wildcard(&self, host: &str) -> Option<String> {
        self.wildcard_router.match_hostname(host).map(|m| m.target)
    }

    /// Emit a tunnel event
    pub fn emit_event(&self, event_type: EventType, tunnel_id: TunnelId, metadata: HashMap<String, serde_json::Value>) {
        let data = crate::event_webhooks::EventData::Generic(serde_json::json!({}));
        let mut event = Event::new(event_type, data)
            .with_tunnel(&format!("{}", tunnel_id));
        event.metadata = metadata;
        self.event_webhooks.emit(event);
    }

    /// Check if an IP is allowed based on restriction config
    fn check_ip_allowed(&self, ip: &IpAddr, config: &IpRestrictionConfig) -> bool {
        // If deny list exists, check if IP is denied
        for deny in &config.deny {
            if self.ip_matches(ip, deny) {
                return false;
            }
        }

        // If allow list exists and is not empty, IP must be in allow list
        if !config.allow.is_empty() {
            for allow in &config.allow {
                if self.ip_matches(ip, allow) {
                    return true;
                }
            }
            return false;
        }

        // Default: allow
        true
    }

    /// Check if an IP matches a pattern (IP or CIDR)
    fn ip_matches(&self, ip: &IpAddr, pattern: &str) -> bool {
        // Try exact IP match
        if let Ok(pattern_ip) = pattern.parse::<IpAddr>() {
            return ip == &pattern_ip;
        }

        // Try CIDR match
        if let Some((network, prefix_len)) = pattern.split_once('/') {
            if let (Ok(network_ip), Ok(prefix)) = (network.parse::<IpAddr>(), prefix_len.parse::<u8>()) {
                return self.cidr_contains(&network_ip, prefix, ip);
            }
        }

        false
    }

    /// Check if an IP is in a CIDR range
    fn cidr_contains(&self, network: &IpAddr, prefix_len: u8, ip: &IpAddr) -> bool {
        match (network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if prefix_len > 32 {
                    return false;
                }
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                (u32::from(*net) & mask) == (u32::from(*addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if prefix_len > 128 {
                    return false;
                }
                let net_bits = u128::from(*net);
                let addr_bits = u128::from(*addr);
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

impl Default for MiddlewarePipeline {
    fn default() -> Self {
        Self {
            tunnel_configs: RwLock::new(HashMap::new()),
            basic_auth: BasicAuth::new(),
            rewrite: RewriteEngine::new(),
            error_pages: Arc::new(ErrorPageManager::new(ErrorPageConfig::default())),
            wildcard_router: WildcardRouter::new(),
            event_webhooks: EventWebhooks::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_creation() {
        let pipeline = MiddlewarePipeline::new();
        assert!(pipeline.tunnel_configs.read().is_empty());
    }

    #[test]
    fn test_register_tunnel() {
        let pipeline = MiddlewarePipeline::new();
        let tunnel_id = TunnelId::new();
        
        let config = TunnelMiddleware {
            tunnel_id,
            ip_restriction: None,
        };

        pipeline.register_tunnel(config);
        assert!(pipeline.tunnel_configs.read().contains_key(&tunnel_id));

        pipeline.unregister_tunnel(&tunnel_id);
        assert!(!pipeline.tunnel_configs.read().contains_key(&tunnel_id));
    }

    #[test]
    fn test_process_request_no_middleware() {
        let pipeline = MiddlewarePipeline::new();
        let tunnel_id = TunnelId::new();
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        let result = pipeline.process_request(
            &tunnel_id,
            "GET",
            "/api/users",
            "example.com",
            &[("Host".to_string(), "example.com".to_string())],
            &client_ip,
        );

        match result {
            MiddlewareResult::Continue { path, headers } => {
                assert_eq!(path, "/api/users");
                assert!(!headers.is_empty());
            }
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_ip_restriction_deny() {
        let pipeline = MiddlewarePipeline::new();
        let tunnel_id = TunnelId::new();

        let config = TunnelMiddleware {
            tunnel_id,
            ip_restriction: Some(IpRestrictionConfig {
                allow: vec![],
                deny: vec!["192.168.1.0/24".to_string()],
            }),
        };

        pipeline.register_tunnel(config);

        let blocked_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let result = pipeline.process_request(
            &tunnel_id,
            "GET",
            "/",
            "example.com",
            &[],
            &blocked_ip,
        );

        match result {
            MiddlewareResult::Response { status, .. } => {
                assert_eq!(status, 403);
            }
            _ => panic!("Expected 403 response"),
        }
    }

    #[test]
    fn test_ip_restriction_allow_list() {
        let pipeline = MiddlewarePipeline::new();
        let tunnel_id = TunnelId::new();

        let config = TunnelMiddleware {
            tunnel_id,
            ip_restriction: Some(IpRestrictionConfig {
                allow: vec!["10.0.0.0/8".to_string()],
                deny: vec![],
            }),
        };

        pipeline.register_tunnel(config);

        // Allowed IP
        let allowed_ip: IpAddr = "10.1.2.3".parse().unwrap();
        let result = pipeline.process_request(&tunnel_id, "GET", "/", "example.com", &[], &allowed_ip);
        assert!(matches!(result, MiddlewareResult::Continue { .. }));

        // Not allowed IP
        let not_allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let result = pipeline.process_request(&tunnel_id, "GET", "/", "example.com", &[], &not_allowed_ip);
        assert!(matches!(result, MiddlewareResult::Response { status: 403, .. }));
    }

    #[test]
    fn test_error_response_generation() {
        let pipeline = MiddlewarePipeline::new();
        let tunnel_id = TunnelId::new();

        let (headers, body) = pipeline.error_response(&tunnel_id, 500, "/api", "GET", "Internal server error");
        
        assert!(headers.iter().any(|(k, _)| k == "Content-Type"));
        assert!(!body.is_empty());
    }

    #[test]
    fn test_cidr_contains_v4() {
        let pipeline = MiddlewarePipeline::default();
        
        let network: IpAddr = "192.168.1.0".parse().unwrap();
        let in_range: IpAddr = "192.168.1.100".parse().unwrap();
        let out_of_range: IpAddr = "192.168.2.1".parse().unwrap();

        assert!(pipeline.cidr_contains(&network, 24, &in_range));
        assert!(!pipeline.cidr_contains(&network, 24, &out_of_range));
    }

    #[test]
    fn test_cidr_contains_v6() {
        let pipeline = MiddlewarePipeline::default();
        
        let network: IpAddr = "2001:db8::".parse().unwrap();
        let in_range: IpAddr = "2001:db8::1".parse().unwrap();
        let out_of_range: IpAddr = "2001:db9::1".parse().unwrap();

        assert!(pipeline.cidr_contains(&network, 32, &in_range));
        assert!(!pipeline.cidr_contains(&network, 32, &out_of_range));
    }
}
