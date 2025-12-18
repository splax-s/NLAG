//! Request/Response Transformation Module
//!
//! Provides middleware for modifying HTTP requests and responses:
//! - Add/remove/modify headers
//! - Rewrite paths and query strings
//! - Body transformations
//! - Variable interpolation

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Header operation type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderOperation {
    /// Set header (overwrites if exists)
    Set,
    /// Add header (appends if exists)
    Add,
    /// Remove header
    Remove,
    /// Append to existing header value
    Append,
    /// Replace value using regex
    Replace,
}

/// Header transformation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRule {
    /// Header name (case-insensitive)
    pub name: String,
    /// Operation to perform
    pub operation: HeaderOperation,
    /// Value for set/add/append operations (supports variables)
    pub value: Option<String>,
    /// Pattern for replace operation
    pub pattern: Option<String>,
    /// Replacement for replace operation
    pub replacement: Option<String>,
    /// Only apply if condition matches
    pub condition: Option<RuleCondition>,
}

/// Path rewrite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRewriteRule {
    /// Regex pattern to match
    pub pattern: String,
    /// Replacement string (supports capture groups: $1, $2, etc.)
    pub replacement: String,
    /// Only apply if condition matches
    pub condition: Option<RuleCondition>,
}

/// Query parameter transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRule {
    /// Parameter name
    pub name: String,
    /// Operation (set, add, remove)
    pub operation: HeaderOperation,
    /// Value (supports variables)
    pub value: Option<String>,
}

/// Body transformation type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyTransform {
    /// Replace entire body
    Replace { content: String, content_type: Option<String> },
    /// JSON path manipulation
    JsonPatch { operations: Vec<JsonPatchOp> },
    /// Template-based transformation
    Template { template: String },
}

/// JSON Patch operation (RFC 6902 subset)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatchOp {
    /// Operation type
    pub op: String,
    /// JSON path
    pub path: String,
    /// Value for add/replace operations
    pub value: Option<serde_json::Value>,
}

/// Condition for applying rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// Match if path matches pattern
    pub path_pattern: Option<String>,
    /// Match if method equals
    pub method: Option<String>,
    /// Match if header exists/equals
    pub header: Option<HeaderCondition>,
    /// Match if status code in range (for response rules)
    pub status_range: Option<(u16, u16)>,
    /// Match if content-type matches
    pub content_type: Option<String>,
}

/// Header condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderCondition {
    /// Header name
    pub name: String,
    /// Required value (None = just check existence)
    pub value: Option<String>,
    /// Negate the condition
    pub negate: bool,
}

/// Request transformation configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestTransform {
    /// Header transformations
    #[serde(default)]
    pub headers: Vec<HeaderRule>,
    /// Path rewrite rules (applied in order)
    #[serde(default)]
    pub path_rewrites: Vec<PathRewriteRule>,
    /// Query parameter transformations
    #[serde(default)]
    pub query_params: Vec<QueryRule>,
    /// Body transformation
    pub body: Option<BodyTransform>,
}

/// Response transformation configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseTransform {
    /// Header transformations
    #[serde(default)]
    pub headers: Vec<HeaderRule>,
    /// Body transformation
    pub body: Option<BodyTransform>,
}

/// Complete transformation configuration for a tunnel/path
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Request transformations
    #[serde(default)]
    pub request: RequestTransform,
    /// Response transformations
    #[serde(default)]
    pub response: ResponseTransform,
    /// Whether transformations are enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

/// Variables available for interpolation
#[derive(Debug, Clone, Default)]
pub struct TransformContext {
    /// Request method
    pub method: String,
    /// Request path
    pub path: String,
    /// Original host
    pub host: String,
    /// Client IP
    pub client_ip: String,
    /// Tunnel ID
    pub tunnel_id: String,
    /// Request ID
    pub request_id: String,
    /// Timestamp
    pub timestamp: String,
    /// Custom variables
    pub variables: HashMap<String, String>,
}

/// Transformation engine
pub struct TransformEngine {
    /// Configurations by tunnel ID and optional path prefix
    configs: RwLock<HashMap<String, TransformConfig>>,
    /// Compiled regex patterns (cached)
    patterns: RwLock<HashMap<String, Regex>>,
}

impl TransformEngine {
    /// Create a new transformation engine
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            configs: RwLock::new(HashMap::new()),
            patterns: RwLock::new(HashMap::new()),
        })
    }

    /// Add a transformation configuration
    pub fn add_config(&self, key: &str, config: TransformConfig) {
        // Pre-compile patterns
        for rule in &config.request.path_rewrites {
            self.compile_pattern(&rule.pattern);
        }
        for rule in &config.request.headers {
            if let Some(ref pattern) = rule.pattern {
                self.compile_pattern(pattern);
            }
        }
        
        self.configs.write().insert(key.to_string(), config);
    }

    /// Remove a transformation configuration
    pub fn remove_config(&self, key: &str) {
        self.configs.write().remove(key);
    }

    /// Get configuration for a tunnel/path
    pub fn get_config(&self, tunnel_id: &str, path: &str) -> Option<TransformConfig> {
        let configs = self.configs.read();
        
        // Try exact match first
        let exact_key = format!("{}:{}", tunnel_id, path);
        if let Some(config) = configs.get(&exact_key) {
            return Some(config.clone());
        }
        
        // Try path prefix match
        for (key, config) in configs.iter() {
            if key.starts_with(&format!("{}:", tunnel_id)) {
                let prefix = key.strip_prefix(&format!("{}:", tunnel_id)).unwrap();
                if path.starts_with(prefix) {
                    return Some(config.clone());
                }
            }
        }
        
        // Try tunnel-wide config
        if let Some(config) = configs.get(tunnel_id) {
            return Some(config.clone());
        }
        
        None
    }

    /// Transform request headers
    pub fn transform_request_headers(
        &self,
        headers: &mut HashMap<String, String>,
        config: &RequestTransform,
        ctx: &TransformContext,
    ) {
        for rule in &config.headers {
            if !self.check_request_condition(&rule.condition, headers, ctx) {
                continue;
            }
            
            let name_lower = rule.name.to_lowercase();
            
            match rule.operation {
                HeaderOperation::Set => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers.insert(name_lower, interpolated);
                    }
                }
                HeaderOperation::Add => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers.insert(name_lower, interpolated);
                    }
                }
                HeaderOperation::Remove => {
                    headers.remove(&name_lower);
                }
                HeaderOperation::Append => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers
                            .entry(name_lower)
                            .and_modify(|v| {
                                v.push_str(", ");
                                v.push_str(&interpolated);
                            })
                            .or_insert(interpolated);
                    }
                }
                HeaderOperation::Replace => {
                    if let (Some(ref pattern), Some(ref replacement)) = (&rule.pattern, &rule.replacement) {
                        if let Some(existing) = headers.get(&name_lower) {
                            if let Some(regex) = self.get_pattern(pattern) {
                                let new_value = regex.replace_all(existing, replacement.as_str());
                                headers.insert(name_lower, new_value.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Transform request path
    pub fn transform_path(
        &self,
        path: &str,
        config: &RequestTransform,
        ctx: &TransformContext,
        headers: &HashMap<String, String>,
    ) -> String {
        let mut result = path.to_string();
        
        for rule in &config.path_rewrites {
            if !self.check_request_condition(&rule.condition, headers, ctx) {
                continue;
            }
            
            if let Some(regex) = self.get_pattern(&rule.pattern) {
                let replacement = self.interpolate(&rule.replacement, ctx);
                result = regex.replace_all(&result, replacement.as_str()).to_string();
            }
        }
        
        result
    }

    /// Transform query parameters
    pub fn transform_query(
        &self,
        query: &mut HashMap<String, String>,
        config: &RequestTransform,
        ctx: &TransformContext,
    ) {
        for rule in &config.query_params {
            match rule.operation {
                HeaderOperation::Set | HeaderOperation::Add => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        query.insert(rule.name.clone(), interpolated);
                    }
                }
                HeaderOperation::Remove => {
                    query.remove(&rule.name);
                }
                _ => {}
            }
        }
    }

    /// Transform response headers
    pub fn transform_response_headers(
        &self,
        headers: &mut HashMap<String, String>,
        status_code: u16,
        config: &ResponseTransform,
        ctx: &TransformContext,
    ) {
        for rule in &config.headers {
            if !self.check_response_condition(&rule.condition, headers, status_code, ctx) {
                continue;
            }
            
            let name_lower = rule.name.to_lowercase();
            
            match rule.operation {
                HeaderOperation::Set => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers.insert(name_lower, interpolated);
                    }
                }
                HeaderOperation::Add => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers.insert(name_lower, interpolated);
                    }
                }
                HeaderOperation::Remove => {
                    headers.remove(&name_lower);
                }
                HeaderOperation::Append => {
                    if let Some(ref value) = rule.value {
                        let interpolated = self.interpolate(value, ctx);
                        headers
                            .entry(name_lower)
                            .and_modify(|v| {
                                v.push_str(", ");
                                v.push_str(&interpolated);
                            })
                            .or_insert(interpolated);
                    }
                }
                HeaderOperation::Replace => {
                    if let (Some(ref pattern), Some(ref replacement)) = (&rule.pattern, &rule.replacement) {
                        if let Some(existing) = headers.get(&name_lower) {
                            if let Some(regex) = self.get_pattern(pattern) {
                                let new_value = regex.replace_all(existing, replacement.as_str());
                                headers.insert(name_lower, new_value.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Interpolate variables in a string
    fn interpolate(&self, template: &str, ctx: &TransformContext) -> String {
        let mut result = template.to_string();
        
        // Built-in variables
        result = result.replace("$method", &ctx.method);
        result = result.replace("$path", &ctx.path);
        result = result.replace("$host", &ctx.host);
        result = result.replace("$client_ip", &ctx.client_ip);
        result = result.replace("$tunnel_id", &ctx.tunnel_id);
        result = result.replace("$request_id", &ctx.request_id);
        result = result.replace("$timestamp", &ctx.timestamp);
        
        // Custom variables
        for (key, value) in &ctx.variables {
            result = result.replace(&format!("${{{}}}", key), value);
        }
        
        result
    }

    /// Check if a request condition matches
    fn check_request_condition(
        &self,
        condition: &Option<RuleCondition>,
        headers: &HashMap<String, String>,
        ctx: &TransformContext,
    ) -> bool {
        let Some(cond) = condition else {
            return true; // No condition = always match
        };
        
        // Check path pattern
        if let Some(ref pattern) = cond.path_pattern {
            if let Some(regex) = self.get_pattern(pattern) {
                if !regex.is_match(&ctx.path) {
                    return false;
                }
            }
        }
        
        // Check method
        if let Some(ref method) = cond.method {
            if !ctx.method.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        
        // Check header condition
        if let Some(ref header_cond) = cond.header {
            let name_lower = header_cond.name.to_lowercase();
            let exists = headers.contains_key(&name_lower);
            let matches = if let Some(ref value) = header_cond.value {
                headers.get(&name_lower).map(|v| v == value).unwrap_or(false)
            } else {
                exists
            };
            
            if header_cond.negate {
                if matches {
                    return false;
                }
            } else if !matches {
                return false;
            }
        }
        
        // Check content-type
        if let Some(ref ct) = cond.content_type {
            let actual = headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
            if !actual.contains(ct) {
                return false;
            }
        }
        
        true
    }

    /// Check if a response condition matches
    fn check_response_condition(
        &self,
        condition: &Option<RuleCondition>,
        headers: &HashMap<String, String>,
        status_code: u16,
        ctx: &TransformContext,
    ) -> bool {
        let Some(cond) = condition else {
            return true;
        };
        
        // Check status range
        if let Some((min, max)) = cond.status_range {
            if status_code < min || status_code > max {
                return false;
            }
        }
        
        // Reuse request condition checks for other fields
        self.check_request_condition(condition, headers, ctx)
    }

    /// Compile and cache a regex pattern
    fn compile_pattern(&self, pattern: &str) -> Option<Regex> {
        let mut patterns = self.patterns.write();
        if let Some(regex) = patterns.get(pattern) {
            return Some(regex.clone());
        }
        
        match Regex::new(pattern) {
            Ok(regex) => {
                patterns.insert(pattern.to_string(), regex.clone());
                Some(regex)
            }
            Err(_) => None,
        }
    }

    /// Get a cached regex pattern
    fn get_pattern(&self, pattern: &str) -> Option<Regex> {
        if let Some(regex) = self.patterns.read().get(pattern) {
            return Some(regex.clone());
        }
        self.compile_pattern(pattern)
    }
}

impl Default for TransformEngine {
    fn default() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            patterns: RwLock::new(HashMap::new()),
        }
    }
}

/// Shared transformation engine
pub type SharedTransformEngine = Arc<TransformEngine>;

/// Builder for creating transformation configurations
pub struct TransformBuilder {
    config: TransformConfig,
}

impl TransformBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: TransformConfig::default(),
        }
    }

    /// Add a request header
    pub fn add_request_header(mut self, name: &str, value: &str) -> Self {
        self.config.request.headers.push(HeaderRule {
            name: name.to_string(),
            operation: HeaderOperation::Set,
            value: Some(value.to_string()),
            pattern: None,
            replacement: None,
            condition: None,
        });
        self
    }

    /// Remove a request header
    pub fn remove_request_header(mut self, name: &str) -> Self {
        self.config.request.headers.push(HeaderRule {
            name: name.to_string(),
            operation: HeaderOperation::Remove,
            value: None,
            pattern: None,
            replacement: None,
            condition: None,
        });
        self
    }

    /// Add a response header
    pub fn add_response_header(mut self, name: &str, value: &str) -> Self {
        self.config.response.headers.push(HeaderRule {
            name: name.to_string(),
            operation: HeaderOperation::Set,
            value: Some(value.to_string()),
            pattern: None,
            replacement: None,
            condition: None,
        });
        self
    }

    /// Add CORS headers
    pub fn enable_cors(mut self, origin: &str) -> Self {
        self.config.response.headers.extend(vec![
            HeaderRule {
                name: "access-control-allow-origin".to_string(),
                operation: HeaderOperation::Set,
                value: Some(origin.to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
            HeaderRule {
                name: "access-control-allow-methods".to_string(),
                operation: HeaderOperation::Set,
                value: Some("GET, POST, PUT, DELETE, OPTIONS".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
            HeaderRule {
                name: "access-control-allow-headers".to_string(),
                operation: HeaderOperation::Set,
                value: Some("Content-Type, Authorization".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
        ]);
        self
    }

    /// Add security headers
    pub fn add_security_headers(mut self) -> Self {
        self.config.response.headers.extend(vec![
            HeaderRule {
                name: "x-content-type-options".to_string(),
                operation: HeaderOperation::Set,
                value: Some("nosniff".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
            HeaderRule {
                name: "x-frame-options".to_string(),
                operation: HeaderOperation::Set,
                value: Some("DENY".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
            HeaderRule {
                name: "x-xss-protection".to_string(),
                operation: HeaderOperation::Set,
                value: Some("1; mode=block".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
            HeaderRule {
                name: "referrer-policy".to_string(),
                operation: HeaderOperation::Set,
                value: Some("strict-origin-when-cross-origin".to_string()),
                pattern: None,
                replacement: None,
                condition: None,
            },
        ]);
        self
    }

    /// Rewrite path
    pub fn rewrite_path(mut self, pattern: &str, replacement: &str) -> Self {
        self.config.request.path_rewrites.push(PathRewriteRule {
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
            condition: None,
        });
        self
    }

    /// Strip path prefix
    pub fn strip_prefix(mut self, prefix: &str) -> Self {
        let pattern = format!("^{}", regex::escape(prefix));
        self.config.request.path_rewrites.push(PathRewriteRule {
            pattern,
            replacement: "".to_string(),
            condition: None,
        });
        self
    }

    /// Add path prefix
    pub fn add_prefix(mut self, prefix: &str) -> Self {
        self.config.request.path_rewrites.push(PathRewriteRule {
            pattern: "^(.*)$".to_string(),
            replacement: format!("{prefix}$1"),
            condition: None,
        });
        self
    }

    /// Build the configuration
    pub fn build(self) -> TransformConfig {
        self.config
    }
}

impl Default for TransformBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_header() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .add_request_header("x-custom", "value")
            .build();
        
        engine.add_config("tunnel-1", config.clone());
        
        let ctx = TransformContext {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            ..Default::default()
        };
        
        let mut headers = HashMap::new();
        engine.transform_request_headers(&mut headers, &config.request, &ctx);
        
        assert_eq!(headers.get("x-custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_remove_header() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .remove_request_header("x-remove-me")
            .build();
        
        let ctx = TransformContext::default();
        
        let mut headers = HashMap::new();
        headers.insert("x-remove-me".to_string(), "value".to_string());
        headers.insert("x-keep".to_string(), "kept".to_string());
        
        engine.transform_request_headers(&mut headers, &config.request, &ctx);
        
        assert!(!headers.contains_key("x-remove-me"));
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn test_variable_interpolation() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .add_request_header("x-forwarded-for", "$client_ip")
            .add_request_header("x-request-id", "$request_id")
            .build();
        
        let ctx = TransformContext {
            client_ip: "192.168.1.1".to_string(),
            request_id: "req-123".to_string(),
            ..Default::default()
        };
        
        let mut headers = HashMap::new();
        engine.transform_request_headers(&mut headers, &config.request, &ctx);
        
        assert_eq!(headers.get("x-forwarded-for"), Some(&"192.168.1.1".to_string()));
        assert_eq!(headers.get("x-request-id"), Some(&"req-123".to_string()));
    }

    #[test]
    fn test_path_rewrite() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .rewrite_path("^/api/v1/(.*)$", "/v2/$1")
            .build();
        
        engine.add_config("tunnel-1", config.clone());
        
        let ctx = TransformContext::default();
        let headers = HashMap::new();
        
        let result = engine.transform_path("/api/v1/users", &config.request, &ctx, &headers);
        assert_eq!(result, "/v2/users");
    }

    #[test]
    fn test_strip_prefix() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .strip_prefix("/api")
            .build();
        
        let ctx = TransformContext::default();
        let headers = HashMap::new();
        
        let result = engine.transform_path("/api/users/123", &config.request, &ctx, &headers);
        assert_eq!(result, "/users/123");
    }

    #[test]
    fn test_add_prefix() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .add_prefix("/service")
            .build();
        
        let ctx = TransformContext::default();
        let headers = HashMap::new();
        
        let result = engine.transform_path("/users", &config.request, &ctx, &headers);
        assert_eq!(result, "/service/users");
    }

    #[test]
    fn test_cors_headers() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .enable_cors("*")
            .build();
        
        let ctx = TransformContext::default();
        let mut headers = HashMap::new();
        
        engine.transform_response_headers(&mut headers, 200, &config.response, &ctx);
        
        assert_eq!(headers.get("access-control-allow-origin"), Some(&"*".to_string()));
        assert!(headers.contains_key("access-control-allow-methods"));
    }

    #[test]
    fn test_security_headers() {
        let engine = TransformEngine::new();
        
        let config = TransformBuilder::new()
            .add_security_headers()
            .build();
        
        let ctx = TransformContext::default();
        let mut headers = HashMap::new();
        
        engine.transform_response_headers(&mut headers, 200, &config.response, &ctx);
        
        assert_eq!(headers.get("x-content-type-options"), Some(&"nosniff".to_string()));
        assert_eq!(headers.get("x-frame-options"), Some(&"DENY".to_string()));
    }

    #[test]
    fn test_conditional_transform() {
        let engine = TransformEngine::new();
        
        let mut config = TransformConfig::default();
        config.request.headers.push(HeaderRule {
            name: "x-api-version".to_string(),
            operation: HeaderOperation::Set,
            value: Some("v2".to_string()),
            pattern: None,
            replacement: None,
            condition: Some(RuleCondition {
                path_pattern: Some("^/api/.*".to_string()),
                method: None,
                header: None,
                status_range: None,
                content_type: None,
            }),
        });
        
        engine.add_config("tunnel-1", config.clone());
        
        let ctx = TransformContext {
            path: "/api/users".to_string(),
            ..Default::default()
        };
        
        let mut headers = HashMap::new();
        engine.transform_request_headers(&mut headers, &config.request, &ctx);
        assert_eq!(headers.get("x-api-version"), Some(&"v2".to_string()));
        
        // Non-matching path
        let ctx2 = TransformContext {
            path: "/other/path".to_string(),
            ..Default::default()
        };
        let mut headers2 = HashMap::new();
        engine.transform_request_headers(&mut headers2, &config.request, &ctx2);
        assert!(!headers2.contains_key("x-api-version"));
    }

    #[test]
    fn test_query_transform() {
        let engine = TransformEngine::new();
        
        let mut config = TransformConfig::default();
        config.request.query_params.push(QueryRule {
            name: "api_key".to_string(),
            operation: HeaderOperation::Set,
            value: Some("secret123".to_string()),
        });
        config.request.query_params.push(QueryRule {
            name: "debug".to_string(),
            operation: HeaderOperation::Remove,
            value: None,
        });
        
        let ctx = TransformContext::default();
        let mut query = HashMap::new();
        query.insert("debug".to_string(), "true".to_string());
        query.insert("existing".to_string(), "value".to_string());
        
        engine.transform_query(&mut query, &config.request, &ctx);
        
        assert_eq!(query.get("api_key"), Some(&"secret123".to_string()));
        assert!(!query.contains_key("debug"));
        assert!(query.contains_key("existing"));
    }

    #[test]
    fn test_config_lookup() {
        let engine = TransformEngine::new();
        
        let config1 = TransformBuilder::new()
            .add_request_header("x-tunnel", "1")
            .build();
        let config2 = TransformBuilder::new()
            .add_request_header("x-tunnel", "2")
            .build();
        
        engine.add_config("tunnel-1", config1);
        engine.add_config("tunnel-2:/api", config2);
        
        // Tunnel-wide config
        let found1 = engine.get_config("tunnel-1", "/any/path");
        assert!(found1.is_some());
        
        // Path-specific config
        let found2 = engine.get_config("tunnel-2", "/api/users");
        assert!(found2.is_some());
        
        // No match
        let not_found = engine.get_config("tunnel-2", "/other/path");
        assert!(not_found.is_none());
    }
}
