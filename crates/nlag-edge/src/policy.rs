//! Traffic Policy Engine
//!
//! YAML/JSON configurable rules for:
//! - Request routing and matching
//! - Authentication requirements
//! - Rate limiting per path
//! - Request/Response transformations
//! - IP allowlists/blocklists
//! - Webhook verification
//!
//! ## Policy Format
//!
//! ```yaml
//! policies:
//!   - name: "api-rate-limit"
//!     match:
//!       path: "/api/*"
//!       methods: ["POST", "PUT", "DELETE"]
//!     actions:
//!       rate_limit:
//!         requests_per_second: 100
//!         burst: 50
//!
//!   - name: "require-auth"
//!     match:
//!       path: "/admin/*"
//!     actions:
//!       require_auth:
//!         type: "bearer"
//!
//!   - name: "block-ips"
//!     match:
//!       path: "/*"
//!     actions:
//!       ip_policy:
//!         deny: ["192.168.1.0/24"]
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore, clock::DefaultClock, middleware::NoOpMiddleware};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

/// Policy errors
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy denied: {0}")]
    Denied(String),
    
    #[error("Rate limited: {0}")]
    RateLimited(String),
    
    #[error("Authentication required: {0}")]
    AuthRequired(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("IP blocked: {0}")]
    IpBlocked(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

/// Policy decision after evaluation
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow the request
    Allow,
    /// Deny with status code and message
    Deny { status: u16, message: String },
    /// Redirect to another URL
    Redirect { url: String, status: u16 },
    /// Require authentication
    RequireAuth { auth_type: String, realm: String },
    /// Rate limited - retry after seconds
    RateLimited { retry_after: u64 },
}

/// Request context for policy evaluation
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Client IP address
    pub client_ip: Option<IpAddr>,
    /// Tunnel ID
    pub tunnel_id: String,
    /// Subdomain
    pub subdomain: Option<String>,
    /// Host header
    pub host: Option<String>,
}

/// Modifications to apply to the request
#[derive(Debug, Clone, Default)]
pub struct RequestModifications {
    /// Headers to add
    pub add_headers: HashMap<String, String>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// Path rewrite (if any)
    pub rewrite_path: Option<String>,
    /// Host rewrite (if any)
    pub rewrite_host: Option<String>,
}

/// Modifications to apply to the response
#[derive(Debug, Clone, Default)]
pub struct ResponseModifications {
    /// Headers to add
    pub add_headers: HashMap<String, String>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// Compression settings (if enabled)
    pub compression: Option<CompressionSettings>,
    /// Caching settings (if enabled)
    pub caching: Option<CachingSettings>,
}

/// Compression settings for response
#[derive(Debug, Clone)]
pub struct CompressionSettings {
    /// Algorithm: gzip, br, deflate
    pub algorithm: String,
    /// Minimum size to compress (bytes)
    pub min_size: usize,
    /// Content types to compress (glob patterns)
    pub types: Vec<String>,
}

/// Caching settings for response
#[derive(Debug, Clone)]
pub struct CachingSettings {
    /// Cache TTL in seconds
    pub ttl: u64,
    /// Cache key
    pub key: String,
    /// Methods to cache
    pub methods: Vec<String>,
}

// ============================================================================
// Policy Configuration Types
// ============================================================================

/// Root policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// List of policies
    #[serde(default)]
    pub policies: Vec<Policy>,
    
    /// Global settings
    #[serde(default)]
    pub global: GlobalSettings,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policies: Vec::new(),
            global: GlobalSettings::default(),
        }
    }
}

/// Global policy settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalSettings {
    /// Default rate limit (requests per second)
    #[serde(default)]
    pub default_rate_limit: Option<u32>,
    
    /// Enable request logging
    #[serde(default = "default_true")]
    pub log_requests: bool,
    
    /// Maximum request body size (bytes)
    #[serde(default = "default_body_size")]
    pub max_body_size: usize,
    
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool { true }
fn default_body_size() -> usize { 10 * 1024 * 1024 } // 10MB
fn default_timeout() -> u64 { 60 }

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name (for debugging)
    pub name: String,
    
    /// Match conditions
    #[serde(rename = "match")]
    pub match_conditions: MatchConditions,
    
    /// Actions to apply
    pub actions: PolicyActions,
    
    /// Priority (higher = evaluated first)
    #[serde(default)]
    pub priority: i32,
    
    /// Whether this policy is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Conditions to match a request
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchConditions {
    /// Path pattern (supports * and ** wildcards)
    #[serde(default)]
    pub path: Option<String>,
    
    /// Regex pattern for path
    #[serde(default)]
    pub path_regex: Option<String>,
    
    /// HTTP methods to match
    #[serde(default)]
    pub methods: Vec<String>,
    
    /// Header conditions
    #[serde(default)]
    pub headers: HashMap<String, String>,
    
    /// Host/subdomain to match
    #[serde(default)]
    pub hosts: Vec<String>,
    
    /// Source IP CIDRs to match
    #[serde(default)]
    pub source_ips: Vec<String>,
}

/// Actions to take when policy matches
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyActions {
    /// Rate limiting
    #[serde(default)]
    pub rate_limit: Option<RateLimitAction>,
    
    /// Authentication requirement
    #[serde(default)]
    pub require_auth: Option<AuthAction>,
    
    /// IP policy (allow/deny lists)
    #[serde(default)]
    pub ip_policy: Option<IpPolicyAction>,
    
    /// Request transformation
    #[serde(default)]
    pub transform_request: Option<TransformAction>,
    
    /// Response transformation
    #[serde(default)]
    pub transform_response: Option<TransformAction>,
    
    /// URL rewrite
    #[serde(default)]
    pub rewrite: Option<RewriteAction>,
    
    /// Redirect
    #[serde(default)]
    pub redirect: Option<RedirectAction>,
    
    /// Custom response
    #[serde(default)]
    pub custom_response: Option<CustomResponseAction>,
    
    /// Webhook verification
    #[serde(default)]
    pub verify_webhook: Option<WebhookVerifyAction>,
    
    /// Compression
    #[serde(default)]
    pub compress: Option<CompressAction>,
    
    /// Caching
    #[serde(default)]
    pub cache: Option<CacheAction>,
    
    /// Custom timeout
    #[serde(default)]
    pub timeout: Option<TimeoutAction>,
    
    /// Deny the request
    #[serde(default)]
    pub deny: Option<DenyAction>,
}

/// Rate limit action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAction {
    /// Requests per second
    pub requests_per_second: u32,
    /// Burst size
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Key for rate limiting (ip, path, header:X-Api-Key)
    #[serde(default = "default_key")]
    pub key: String,
}

fn default_burst() -> u32 { 10 }
fn default_key() -> String { "ip".to_string() }

/// Authentication action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAction {
    /// Auth type: bearer, basic, api_key, oauth
    #[serde(rename = "type")]
    pub auth_type: String,
    /// Realm for WWW-Authenticate header
    #[serde(default = "default_realm")]
    pub realm: String,
    /// Users for basic auth
    #[serde(default)]
    pub users: HashMap<String, String>,
    /// API key header name
    #[serde(default)]
    pub api_key_header: Option<String>,
    /// Valid API keys
    #[serde(default)]
    pub api_keys: Vec<String>,
}

fn default_realm() -> String { "Restricted".to_string() }

/// IP allow/deny policy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpPolicyAction {
    /// Allowed IP CIDRs
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied IP CIDRs
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Request/Response transformation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransformAction {
    /// Headers to add
    #[serde(default)]
    pub add_headers: HashMap<String, String>,
    /// Headers to remove
    #[serde(default)]
    pub remove_headers: Vec<String>,
    /// Headers to rename (old -> new)
    #[serde(default)]
    pub rename_headers: HashMap<String, String>,
}

/// URL rewrite action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteAction {
    /// Path rewrite (supports $1, $2 capture groups)
    #[serde(default)]
    pub path: Option<String>,
    /// Host rewrite
    #[serde(default)]
    pub host: Option<String>,
    /// Strip path prefix
    #[serde(default)]
    pub strip_prefix: Option<String>,
    /// Add path prefix
    #[serde(default)]
    pub add_prefix: Option<String>,
}

/// Redirect action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectAction {
    /// Redirect URL
    pub url: String,
    /// Status code (301, 302, 307, 308)
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

fn default_redirect_status() -> u16 { 302 }

/// Custom response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResponseAction {
    /// Status code
    pub status: u16,
    /// Response body
    #[serde(default)]
    pub body: String,
    /// Content-Type header
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// Additional headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_content_type() -> String { "text/plain".to_string() }

/// Webhook verification action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookVerifyAction {
    /// Provider: stripe, github, slack, generic
    pub provider: String,
    /// Secret for HMAC verification
    pub secret: String,
    /// Header containing the signature
    #[serde(default)]
    pub signature_header: Option<String>,
}

/// Compression action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressAction {
    /// Compression algorithm: gzip, br, deflate
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Minimum size to compress (bytes)
    #[serde(default = "default_min_size")]
    pub min_size: usize,
    /// Content types to compress
    #[serde(default = "default_compress_types")]
    pub types: Vec<String>,
}

fn default_algorithm() -> String { "gzip".to_string() }
fn default_min_size() -> usize { 1024 }
fn default_compress_types() -> Vec<String> {
    vec![
        "text/*".to_string(),
        "application/json".to_string(),
        "application/javascript".to_string(),
    ]
}

/// Cache action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheAction {
    /// Cache TTL in seconds
    pub ttl: u64,
    /// Cache key template
    #[serde(default = "default_cache_key")]
    pub key: String,
    /// Methods to cache
    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,
}

fn default_cache_key() -> String { "$method:$path".to_string() }
fn default_cache_methods() -> Vec<String> { vec!["GET".to_string()] }

/// Timeout action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutAction {
    /// Request timeout in seconds
    pub seconds: u64,
}

/// Deny action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyAction {
    /// Status code
    #[serde(default = "default_deny_status")]
    pub status: u16,
    /// Response message
    #[serde(default = "default_deny_message")]
    pub message: String,
}

fn default_deny_status() -> u16 { 403 }
fn default_deny_message() -> String { "Access denied".to_string() }

// ============================================================================
// Policy Engine Implementation
// ============================================================================

type PolicyRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock, NoOpMiddleware>;

/// Policy engine for evaluating traffic rules
pub struct PolicyEngine {
    /// Policy configuration
    config: RwLock<PolicyConfig>,
    
    /// Rate limiters by policy name and key
    rate_limiters: DashMap<String, Arc<PolicyRateLimiter>>,
    
    /// Compiled path patterns
    patterns: RwLock<Vec<CompiledPattern>>,
}

/// Compiled pattern for fast matching
struct CompiledPattern {
    policy_index: usize,
    path_regex: Option<regex::Regex>,
    methods: Vec<String>,
}

impl PolicyEngine {
    /// Create a new policy engine with default config
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(PolicyConfig::default()),
            rate_limiters: DashMap::new(),
            patterns: RwLock::new(Vec::new()),
        })
    }
    
    /// Load policies from a YAML file
    pub fn load_from_file(&self, path: &Path) -> Result<()> {
        let contents = std::fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&contents)?;
        self.set_config(config);
        info!("Loaded {} policies from {:?}", self.config.read().policies.len(), path);
        Ok(())
    }
    
    /// Load policies from a YAML string
    pub fn load_from_string(&self, yaml: &str) -> Result<()> {
        let config: PolicyConfig = serde_yaml::from_str(yaml)?;
        self.set_config(config);
        Ok(())
    }
    
    /// Set the policy configuration
    pub fn set_config(&self, mut config: PolicyConfig) {
        // Sort by priority (higher first)
        config.policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Compile patterns
        let mut patterns = Vec::new();
        for (i, policy) in config.policies.iter().enumerate() {
            if !policy.enabled {
                continue;
            }
            
            let path_regex = policy.match_conditions.path.as_ref().map(|p| {
                // Convert glob pattern to regex
                let regex_str = glob_to_regex(p);
                regex::Regex::new(&regex_str).ok()
            }).flatten().or_else(|| {
                policy.match_conditions.path_regex.as_ref().and_then(|r| {
                    regex::Regex::new(r).ok()
                })
            });
            
            patterns.push(CompiledPattern {
                policy_index: i,
                path_regex,
                methods: policy.match_conditions.methods.clone(),
            });
        }
        
        *self.patterns.write() = patterns;
        *self.config.write() = config;
    }
    
    /// Get the current configuration
    pub fn config(&self) -> PolicyConfig {
        self.config.read().clone()
    }
    
    /// Evaluate policies for a request
    pub fn evaluate(&self, ctx: &RequestContext) -> (PolicyDecision, RequestModifications, ResponseModifications) {
        let config = self.config.read();
        let patterns = self.patterns.read();
        
        let mut modifications = RequestModifications::default();
        let mut response_modifications = ResponseModifications::default();
        
        for pattern in patterns.iter() {
            let policy = &config.policies[pattern.policy_index];
            
            // Check if request matches
            if !self.matches_policy(ctx, policy, pattern) {
                continue;
            }
            
            debug!("Request matched policy: {}", policy.name);
            
            // Apply actions
            if let Some(decision) = self.apply_actions(ctx, &policy.actions, &mut modifications, &mut response_modifications) {
                return (decision, modifications, response_modifications);
            }
        }
        
        (PolicyDecision::Allow, modifications, response_modifications)
    }
    
    /// Check if a request matches a policy
    fn matches_policy(&self, ctx: &RequestContext, policy: &Policy, pattern: &CompiledPattern) -> bool {
        // Check path
        if let Some(ref regex) = pattern.path_regex {
            if !regex.is_match(&ctx.path) {
                return false;
            }
        }
        
        // Check methods
        if !pattern.methods.is_empty() {
            if !pattern.methods.iter().any(|m| m.eq_ignore_ascii_case(&ctx.method)) {
                return false;
            }
        }
        
        // Check hosts
        if !policy.match_conditions.hosts.is_empty() {
            let host_match = ctx.host.as_ref().map(|h| {
                policy.match_conditions.hosts.iter().any(|pattern| {
                    if pattern.starts_with('*') {
                        h.ends_with(&pattern[1..])
                    } else {
                        h == pattern
                    }
                })
            }).unwrap_or(false);
            
            if !host_match {
                return false;
            }
        }
        
        // Check headers
        for (key, expected) in &policy.match_conditions.headers {
            let header_match = ctx.headers.get(key).map(|v| v == expected).unwrap_or(false);
            if !header_match {
                return false;
            }
        }
        
        // Check source IPs
        if !policy.match_conditions.source_ips.is_empty() {
            if let Some(ip) = ctx.client_ip {
                let ip_match = policy.match_conditions.source_ips.iter().any(|cidr| {
                    cidr_contains(cidr, ip)
                });
                if !ip_match {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        true
    }
    
    /// Apply policy actions
    fn apply_actions(
        &self,
        ctx: &RequestContext,
        actions: &PolicyActions,
        modifications: &mut RequestModifications,
        response_mods: &mut ResponseModifications,
    ) -> Option<PolicyDecision> {
        // Check deny first
        if let Some(deny) = &actions.deny {
            return Some(PolicyDecision::Deny {
                status: deny.status,
                message: deny.message.clone(),
            });
        }
        
        // Check IP policy
        if let Some(ip_policy) = &actions.ip_policy {
            if let Some(ip) = ctx.client_ip {
                // Check deny list first
                for cidr in &ip_policy.deny {
                    if cidr_contains(cidr, ip) {
                        return Some(PolicyDecision::Deny {
                            status: 403,
                            message: "IP address blocked".to_string(),
                        });
                    }
                }
                
                // If allow list is specified, check it
                if !ip_policy.allow.is_empty() {
                    let allowed = ip_policy.allow.iter().any(|cidr| cidr_contains(cidr, ip));
                    if !allowed {
                        return Some(PolicyDecision::Deny {
                            status: 403,
                            message: "IP address not in allowlist".to_string(),
                        });
                    }
                }
            }
        }
        
        // Check rate limit
        if let Some(rate_limit) = &actions.rate_limit {
            if let Some(decision) = self.check_rate_limit(ctx, rate_limit) {
                return Some(decision);
            }
        }
        
        // Check authentication
        if let Some(auth) = &actions.require_auth {
            if let Some(decision) = self.check_auth(ctx, auth) {
                return Some(decision);
            }
        }
        
        // Check redirect
        if let Some(redirect) = &actions.redirect {
            return Some(PolicyDecision::Redirect {
                url: redirect.url.clone(),
                status: redirect.status,
            });
        }
        
        // Check custom response
        if let Some(custom) = &actions.custom_response {
            return Some(PolicyDecision::Deny {
                status: custom.status,
                message: custom.body.clone(),
            });
        }
        
        // Apply transformations
        if let Some(transform) = &actions.transform_request {
            for (key, value) in &transform.add_headers {
                modifications.add_headers.insert(key.clone(), value.clone());
            }
            modifications.remove_headers.extend(transform.remove_headers.clone());
        }
        
        // Apply rewrites
        if let Some(rewrite) = &actions.rewrite {
            if let Some(ref path) = rewrite.path {
                modifications.rewrite_path = Some(path.clone());
            }
            if let Some(ref host) = rewrite.host {
                modifications.rewrite_host = Some(host.clone());
            }
            if let Some(ref prefix) = rewrite.strip_prefix {
                if ctx.path.starts_with(prefix) {
                    let new_path = ctx.path[prefix.len()..].to_string();
                    modifications.rewrite_path = Some(if new_path.is_empty() { "/".to_string() } else { new_path });
                }
            }
            if let Some(ref prefix) = rewrite.add_prefix {
                let current = modifications.rewrite_path.as_ref().unwrap_or(&ctx.path);
                modifications.rewrite_path = Some(format!("{}{}", prefix, current));
            }
        }
        
        // Apply compression settings
        if let Some(compress) = &actions.compress {
            response_mods.compression = Some(CompressionSettings {
                algorithm: compress.algorithm.clone(),
                min_size: compress.min_size,
                types: compress.types.clone(),
            });
        }
        
        // Apply caching settings
        if let Some(cache) = &actions.cache {
            // Generate cache key from template
            let cache_key = cache.key
                .replace("$method", &ctx.method)
                .replace("$path", &ctx.path)
                .replace("$tunnel", &ctx.tunnel_id);
            
            response_mods.caching = Some(CachingSettings {
                ttl: cache.ttl,
                key: cache_key,
                methods: cache.methods.clone(),
            });
        }
        
        None // Continue processing
    }
    
    /// Check rate limit
    fn check_rate_limit(&self, ctx: &RequestContext, config: &RateLimitAction) -> Option<PolicyDecision> {
        // Generate rate limit key
        let key = match config.key.as_str() {
            "ip" => ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string()),
            "path" => ctx.path.clone(),
            "tunnel" => ctx.tunnel_id.clone(),
            key if key.starts_with("header:") => {
                let header_name = &key[7..];
                ctx.headers.get(header_name).cloned().unwrap_or_else(|| "unknown".to_string())
            }
            _ => "global".to_string(),
        };
        
        let limiter_key = format!("{}:{}", config.requests_per_second, config.burst);
        
        // Get or create rate limiter
        let limiter = self.rate_limiters.entry(limiter_key.clone()).or_insert_with(|| {
            let quota = Quota::per_second(std::num::NonZeroU32::new(config.requests_per_second).unwrap())
                .allow_burst(std::num::NonZeroU32::new(config.burst).unwrap());
            Arc::new(RateLimiter::keyed(quota))
        });
        
        match limiter.check_key(&key) {
            Ok(_) => None,
            Err(_) => Some(PolicyDecision::RateLimited {
                retry_after: 1,
            }),
        }
    }
    
    /// Check authentication
    fn check_auth(&self, ctx: &RequestContext, config: &AuthAction) -> Option<PolicyDecision> {
        match config.auth_type.as_str() {
            "bearer" => {
                let has_bearer = ctx.headers.get("authorization")
                    .map(|v| v.to_lowercase().starts_with("bearer "))
                    .unwrap_or(false);
                
                if !has_bearer {
                    return Some(PolicyDecision::RequireAuth {
                        auth_type: "bearer".to_string(),
                        realm: config.realm.clone(),
                    });
                }
            }
            "basic" => {
                if let Some(auth) = ctx.headers.get("authorization") {
                    if let Some(creds) = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic ")) {
                        if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, creds) {
                            if let Ok(creds_str) = String::from_utf8(decoded) {
                                if let Some((user, pass)) = creds_str.split_once(':') {
                                    if let Some(expected_pass) = config.users.get(user) {
                                        if expected_pass == pass {
                                            return None; // Auth OK
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Some(PolicyDecision::RequireAuth {
                    auth_type: "basic".to_string(),
                    realm: config.realm.clone(),
                });
            }
            "api_key" => {
                let header_name = config.api_key_header.as_deref().unwrap_or("X-Api-Key");
                let has_valid_key = ctx.headers.get(&header_name.to_lowercase())
                    .map(|key| config.api_keys.contains(key))
                    .unwrap_or(false);
                
                if !has_valid_key {
                    return Some(PolicyDecision::Deny {
                        status: 401,
                        message: "Invalid or missing API key".to_string(),
                    });
                }
            }
            _ => {}
        }
        
        None
    }
    
    /// Get response modifications for a policy
    pub fn get_response_modifications(&self, ctx: &RequestContext) -> ResponseModifications {
        let config = self.config.read();
        let patterns = self.patterns.read();
        
        let mut modifications = ResponseModifications::default();
        
        for pattern in patterns.iter() {
            let policy = &config.policies[pattern.policy_index];
            
            if !self.matches_policy(ctx, policy, pattern) {
                continue;
            }
            
            if let Some(transform) = &policy.actions.transform_response {
                for (key, value) in &transform.add_headers {
                    modifications.add_headers.insert(key.clone(), value.clone());
                }
                modifications.remove_headers.extend(transform.remove_headers.clone());
            }
        }
        
        modifications
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            config: RwLock::new(PolicyConfig::default()),
            rate_limiters: DashMap::new(),
            patterns: RwLock::new(Vec::new()),
        }
    }
}

/// Convert glob pattern to regex
fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    regex.push_str(".*"); // ** matches anything including /
                } else {
                    regex.push_str("[^/]*"); // * matches anything except /
                }
            }
            '?' => regex.push('.'),
            '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }
    
    regex.push('$');
    regex
}

/// Check if an IP is contained in a CIDR
fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    // Simple implementation - parse CIDR and check
    if let Some((network, prefix_len)) = cidr.split_once('/') {
        if let (Ok(network_ip), Ok(prefix)) = (network.parse::<IpAddr>(), prefix_len.parse::<u8>()) {
            return match (network_ip, ip) {
                (IpAddr::V4(net), IpAddr::V4(check)) => {
                    let net_bits = u32::from(net);
                    let check_bits = u32::from(check);
                    let mask = !0u32 << (32 - prefix);
                    (net_bits & mask) == (check_bits & mask)
                }
                (IpAddr::V6(net), IpAddr::V6(check)) => {
                    let net_bits = u128::from(net);
                    let check_bits = u128::from(check);
                    let mask = !0u128 << (128 - prefix);
                    (net_bits & mask) == (check_bits & mask)
                }
                _ => false,
            };
        }
    } else if let Ok(single_ip) = cidr.parse::<IpAddr>() {
        return ip == single_ip;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_glob_to_regex() {
        assert_eq!(glob_to_regex("/api/*"), "^/api/[^/]*$");
        assert_eq!(glob_to_regex("/api/**"), "^/api/.*$");
        assert_eq!(glob_to_regex("/users/?.json"), "^/users/.\\.json$");
    }
    
    #[test]
    fn test_cidr_contains() {
        use std::str::FromStr;
        
        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        assert!(cidr_contains("192.168.1.0/24", ip));
        assert!(!cidr_contains("192.168.2.0/24", ip));
        assert!(cidr_contains("192.168.1.100", ip));
    }
    
    #[test]
    fn test_policy_matching() {
        let engine = PolicyEngine::new();
        
        let yaml = r#"
policies:
  - name: "block-admin"
    match:
      path: "/admin/*"
    actions:
      deny:
        status: 403
        message: "Admin access denied"
"#;
        
        engine.load_from_string(yaml).unwrap();
        
        let ctx = RequestContext {
            path: "/admin/users".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            client_ip: None,
            tunnel_id: "test".to_string(),
            subdomain: None,
            host: None,
        };
        
        let (decision, _, _) = engine.evaluate(&ctx);
        
        match decision {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 403),
            _ => panic!("Expected Deny"),
        }
    }
    
    #[test]
    fn test_rate_limit() {
        let engine = PolicyEngine::new();
        
        let yaml = r#"
policies:
  - name: "rate-limit-api"
    match:
      path: "/api/*"
    actions:
      rate_limit:
        requests_per_second: 1
        burst: 1
        key: "ip"
"#;
        
        engine.load_from_string(yaml).unwrap();
        
        let ctx = RequestContext {
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            client_ip: Some("127.0.0.1".parse().unwrap()),
            tunnel_id: "test".to_string(),
            subdomain: None,
            host: None,
        };
        
        // First request should pass
        let (decision, _, _) = engine.evaluate(&ctx);
        assert!(matches!(decision, PolicyDecision::Allow));
        
        // Second immediate request should be rate limited
        let (decision, _, _) = engine.evaluate(&ctx);
        assert!(matches!(decision, PolicyDecision::RateLimited { .. }));
    }
    
    #[test]
    fn test_compression_action() {
        let engine = PolicyEngine::new();
        
        let yaml = r#"
policies:
  - name: "compress-api"
    match:
      path: "/api/*"
    actions:
      compress:
        algorithm: "gzip"
        min_size: 1024
        types:
          - "application/json"
"#;
        
        engine.load_from_string(yaml).unwrap();
        
        let ctx = RequestContext {
            path: "/api/data".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            client_ip: None,
            tunnel_id: "test".to_string(),
            subdomain: None,
            host: None,
        };
        
        let (decision, _, response_mods) = engine.evaluate(&ctx);
        assert!(matches!(decision, PolicyDecision::Allow));
        
        let compression = response_mods.compression.unwrap();
        assert_eq!(compression.algorithm, "gzip");
        assert_eq!(compression.min_size, 1024);
        assert!(compression.types.contains(&"application/json".to_string()));
    }
    
    #[test]
    fn test_cache_action() {
        let engine = PolicyEngine::new();
        
        let yaml = r#"
policies:
  - name: "cache-static"
    match:
      path: "/static/*"
      methods: ["GET"]
    actions:
      cache:
        ttl: 3600
        key: "$method:$path"
"#;
        
        engine.load_from_string(yaml).unwrap();
        
        let ctx = RequestContext {
            path: "/static/image.png".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            client_ip: None,
            tunnel_id: "test".to_string(),
            subdomain: None,
            host: None,
        };
        
        let (decision, _, response_mods) = engine.evaluate(&ctx);
        assert!(matches!(decision, PolicyDecision::Allow));
        
        let caching = response_mods.caching.unwrap();
        assert_eq!(caching.ttl, 3600);
        assert_eq!(caching.key, "GET:/static/image.png");
    }
}
