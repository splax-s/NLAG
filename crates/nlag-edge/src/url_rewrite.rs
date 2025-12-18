//! URL Rewriting Module
//!
//! Advanced URL rewriting and routing:
//! - Path-based routing
//! - Host-based routing
//! - Regex pattern matching with capture groups
//! - Query string manipulation
//! - Redirect rules

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Rewrite action type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RewriteAction {
    /// Rewrite the URL internally (client doesn't see change)
    Rewrite,
    /// Redirect with 301 (Permanent)
    RedirectPermanent,
    /// Redirect with 302 (Temporary)
    RedirectTemporary,
    /// Redirect with 307 (Preserve method)
    RedirectPreserveMethod,
    /// Redirect with 308 (Permanent, preserve method)
    RedirectPermanentPreserveMethod,
    /// Proxy to a different backend
    Proxy,
}

/// Match type for conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    /// Exact string match
    Exact,
    /// Prefix match
    Prefix,
    /// Suffix match
    Suffix,
    /// Regex match
    Regex,
    /// Contains substring
    Contains,
}

/// URL match condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    /// Match type
    #[serde(default = "default_match_type")]
    pub match_type: MatchType,
    /// Pattern to match
    pub pattern: String,
    /// Case insensitive matching
    #[serde(default)]
    pub case_insensitive: bool,
    /// Negate the match
    #[serde(default)]
    pub negate: bool,
}

fn default_match_type() -> MatchType {
    MatchType::Prefix
}

/// A single rewrite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    /// Rule name (for logging/debugging)
    pub name: String,
    /// Priority (higher = evaluated first)
    #[serde(default)]
    pub priority: i32,
    /// Enabled flag
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path condition
    pub path: Option<MatchCondition>,
    /// Host condition
    pub host: Option<MatchCondition>,
    /// Method condition (GET, POST, etc.)
    pub method: Option<String>,
    /// Header conditions
    #[serde(default)]
    pub headers: HashMap<String, MatchCondition>,
    /// Query parameter conditions
    #[serde(default)]
    pub query_params: HashMap<String, MatchCondition>,
    /// Action to perform
    pub action: RewriteAction,
    /// Target URL/path (supports $1, $2 capture groups and ${var} variables)
    pub target: String,
    /// Additional headers to set on rewrite
    #[serde(default)]
    pub set_headers: HashMap<String, String>,
    /// Headers to remove on rewrite
    #[serde(default)]
    pub remove_headers: Vec<String>,
    /// Query params to add
    #[serde(default)]
    pub add_query_params: HashMap<String, String>,
    /// Query params to remove
    #[serde(default)]
    pub remove_query_params: Vec<String>,
    /// Stop processing further rules if this matches
    #[serde(default = "default_true")]
    pub stop: bool,
}

fn default_true() -> bool {
    true
}

/// Result of a rewrite operation
#[derive(Debug, Clone)]
pub enum RewriteResult {
    /// No rewrite needed
    NoMatch,
    /// Internal rewrite (URL changed but no redirect)
    Rewrite {
        path: String,
        query: Option<String>,
        headers: HashMap<String, String>,
    },
    /// Client redirect
    Redirect {
        location: String,
        status: u16,
    },
    /// Proxy to different backend
    Proxy {
        target: String,
        headers: HashMap<String, String>,
    },
}

/// Request context for rewrite evaluation
#[derive(Debug, Clone)]
pub struct RewriteContext {
    /// Request method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request query string
    pub query: Option<String>,
    /// Request host
    pub host: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Parsed query parameters
    pub query_params: HashMap<String, String>,
    /// Additional variables for interpolation
    pub variables: HashMap<String, String>,
}

impl RewriteContext {
    /// Create a new context from request parts
    pub fn new(method: &str, path: &str, query: Option<&str>, host: &str) -> Self {
        let query_params = query
            .map(|q| Self::parse_query(q))
            .unwrap_or_default();

        Self {
            method: method.to_string(),
            path: path.to_string(),
            query: query.map(|s| s.to_string()),
            host: host.to_string(),
            headers: HashMap::new(),
            query_params,
            variables: HashMap::new(),
        }
    }

    /// Add headers to context
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Add variables to context
    pub fn with_variables(mut self, variables: HashMap<String, String>) -> Self {
        self.variables = variables;
        self
    }

    /// Parse query string into map
    fn parse_query(query: &str) -> HashMap<String, String> {
        query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((
                    parts.next()?.to_string(),
                    parts.next().unwrap_or("").to_string(),
                ))
            })
            .collect()
    }
}

/// URL rewrite engine
pub struct RewriteEngine {
    /// Rules organized by tunnel/route
    rules: RwLock<HashMap<String, Vec<RewriteRule>>>,
    /// Compiled regex patterns
    patterns: RwLock<HashMap<String, Regex>>,
}

impl RewriteEngine {
    /// Create a new rewrite engine
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rules: RwLock::new(HashMap::new()),
            patterns: RwLock::new(HashMap::new()),
        })
    }

    /// Add rules for a tunnel/route
    pub fn add_rules(&self, key: &str, mut rules: Vec<RewriteRule>) {
        // Sort by priority (higher first)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Pre-compile patterns
        for rule in &rules {
            if let Some(ref cond) = rule.path {
                if matches!(cond.match_type, MatchType::Regex) {
                    self.compile_pattern(&cond.pattern, cond.case_insensitive);
                }
            }
            if let Some(ref cond) = rule.host {
                if matches!(cond.match_type, MatchType::Regex) {
                    self.compile_pattern(&cond.pattern, cond.case_insensitive);
                }
            }
        }

        self.rules.write().insert(key.to_string(), rules);
    }

    /// Remove rules for a tunnel/route
    pub fn remove_rules(&self, key: &str) {
        self.rules.write().remove(key);
    }

    /// Evaluate rules and return rewrite result
    pub fn evaluate(&self, key: &str, ctx: &RewriteContext) -> RewriteResult {
        let rules = self.rules.read();
        let Some(rule_list) = rules.get(key) else {
            return RewriteResult::NoMatch;
        };

        for rule in rule_list {
            if !rule.enabled {
                continue;
            }

            // Check all conditions
            let captures = match self.check_conditions(rule, ctx) {
                Some(caps) => caps,
                None => continue,
            };

            // Build result based on action
            let result = self.apply_rule(rule, ctx, &captures);

            if rule.stop {
                return result;
            }
        }

        RewriteResult::NoMatch
    }

    /// Check all conditions for a rule
    fn check_conditions(
        &self,
        rule: &RewriteRule,
        ctx: &RewriteContext,
    ) -> Option<HashMap<String, String>> {
        let mut captures = HashMap::new();

        // Check method
        if let Some(ref method) = rule.method {
            if !ctx.method.eq_ignore_ascii_case(method) {
                return None;
            }
        }

        // Check path
        if let Some(ref cond) = rule.path {
            if !self.check_condition(cond, &ctx.path, &mut captures, "path") {
                return None;
            }
        }

        // Check host
        if let Some(ref cond) = rule.host {
            if !self.check_condition(cond, &ctx.host, &mut captures, "host") {
                return None;
            }
        }

        // Check headers
        for (name, cond) in &rule.headers {
            let value = ctx.headers.get(&name.to_lowercase()).map(|s| s.as_str()).unwrap_or("");
            if !self.check_condition(cond, value, &mut captures, name) {
                return None;
            }
        }

        // Check query params
        for (name, cond) in &rule.query_params {
            let value = ctx.query_params.get(name).map(|s| s.as_str()).unwrap_or("");
            if !self.check_condition(cond, value, &mut captures, name) {
                return None;
            }
        }

        Some(captures)
    }

    /// Check a single condition
    fn check_condition(
        &self,
        cond: &MatchCondition,
        value: &str,
        captures: &mut HashMap<String, String>,
        prefix: &str,
    ) -> bool {
        let value_cmp = if cond.case_insensitive {
            value.to_lowercase()
        } else {
            value.to_string()
        };
        let pattern_cmp = if cond.case_insensitive {
            cond.pattern.to_lowercase()
        } else {
            cond.pattern.clone()
        };

        let matched = match cond.match_type {
            MatchType::Exact => value_cmp == pattern_cmp,
            MatchType::Prefix => value_cmp.starts_with(&pattern_cmp),
            MatchType::Suffix => value_cmp.ends_with(&pattern_cmp),
            MatchType::Contains => value_cmp.contains(&pattern_cmp),
            MatchType::Regex => {
                if let Some(regex) = self.get_pattern(&cond.pattern, cond.case_insensitive) {
                    if let Some(caps) = regex.captures(value) {
                        // Store numbered captures
                        for (i, cap) in caps.iter().enumerate() {
                            if let Some(m) = cap {
                                captures.insert(format!("{}_{}", prefix, i), m.as_str().to_string());
                            }
                        }
                        // Store named captures
                        for name in regex.capture_names().flatten() {
                            if let Some(m) = caps.name(name) {
                                captures.insert(name.to_string(), m.as_str().to_string());
                            }
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };

        if cond.negate { !matched } else { matched }
    }

    /// Apply a matching rule
    fn apply_rule(
        &self,
        rule: &RewriteRule,
        ctx: &RewriteContext,
        captures: &HashMap<String, String>,
    ) -> RewriteResult {
        let target = self.interpolate(&rule.target, ctx, captures);

        // Build headers
        let mut headers = HashMap::new();
        for (name, value) in &rule.set_headers {
            headers.insert(name.clone(), self.interpolate(value, ctx, captures));
        }

        match rule.action {
            RewriteAction::Rewrite => {
                let (path, query) = Self::split_path_query(&target);
                
                // Merge query params
                let mut new_query_params = ctx.query_params.clone();
                for param in &rule.remove_query_params {
                    new_query_params.remove(param);
                }
                for (k, v) in &rule.add_query_params {
                    new_query_params.insert(k.clone(), self.interpolate(v, ctx, captures));
                }
                
                let final_query = if new_query_params.is_empty() {
                    query
                } else {
                    let qs: Vec<String> = new_query_params
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    Some(qs.join("&"))
                };

                RewriteResult::Rewrite { path, query: final_query, headers }
            }
            RewriteAction::RedirectPermanent => {
                RewriteResult::Redirect { location: target, status: 301 }
            }
            RewriteAction::RedirectTemporary => {
                RewriteResult::Redirect { location: target, status: 302 }
            }
            RewriteAction::RedirectPreserveMethod => {
                RewriteResult::Redirect { location: target, status: 307 }
            }
            RewriteAction::RedirectPermanentPreserveMethod => {
                RewriteResult::Redirect { location: target, status: 308 }
            }
            RewriteAction::Proxy => {
                RewriteResult::Proxy { target, headers }
            }
        }
    }

    /// Split path and query from URL
    fn split_path_query(url: &str) -> (String, Option<String>) {
        if let Some(idx) = url.find('?') {
            (url[..idx].to_string(), Some(url[idx + 1..].to_string()))
        } else {
            (url.to_string(), None)
        }
    }

    /// Interpolate variables in a string
    fn interpolate(
        &self,
        template: &str,
        ctx: &RewriteContext,
        captures: &HashMap<String, String>,
    ) -> String {
        let mut result = template.to_string();

        // Replace numbered captures ($1, $2, etc.) - from path regex
        for i in 0..10 {
            let placeholder = format!("${}", i);
            let key = format!("path_{}", i);
            if let Some(value) = captures.get(&key) {
                result = result.replace(&placeholder, value);
            }
        }

        // Replace named captures
        for (name, value) in captures {
            let placeholder = format!("${{{}}}", name);
            result = result.replace(&placeholder, value);
        }

        // Replace built-in variables
        result = result.replace("${method}", &ctx.method);
        result = result.replace("${path}", &ctx.path);
        result = result.replace("${host}", &ctx.host);
        result = result.replace("${query}", ctx.query.as_deref().unwrap_or(""));

        // Replace custom variables
        for (key, value) in &ctx.variables {
            let placeholder = format!("${{{}}}", key);
            result = result.replace(&placeholder, value);
        }

        result
    }

    /// Compile a regex pattern
    fn compile_pattern(&self, pattern: &str, case_insensitive: bool) -> Option<Regex> {
        let key = format!("{}{}", pattern, if case_insensitive { "_i" } else { "" });
        
        let mut patterns = self.patterns.write();
        if let Some(regex) = patterns.get(&key) {
            return Some(regex.clone());
        }

        let pat = if case_insensitive {
            format!("(?i){}", pattern)
        } else {
            pattern.to_string()
        };

        match Regex::new(&pat) {
            Ok(regex) => {
                patterns.insert(key, regex.clone());
                Some(regex)
            }
            Err(_) => None,
        }
    }

    /// Get a cached regex pattern
    fn get_pattern(&self, pattern: &str, case_insensitive: bool) -> Option<Regex> {
        let key = format!("{}{}", pattern, if case_insensitive { "_i" } else { "" });
        
        if let Some(regex) = self.patterns.read().get(&key) {
            return Some(regex.clone());
        }
        self.compile_pattern(pattern, case_insensitive)
    }
}

impl Default for RewriteEngine {
    fn default() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            patterns: RwLock::new(HashMap::new()),
        }
    }
}

/// Shared rewrite engine
pub type SharedRewriteEngine = Arc<RewriteEngine>;

/// Builder for creating rewrite rules
pub struct RuleBuilder {
    rule: RewriteRule,
}

impl RuleBuilder {
    /// Create a new rule builder
    pub fn new(name: &str) -> Self {
        Self {
            rule: RewriteRule {
                name: name.to_string(),
                priority: 0,
                enabled: true,
                path: None,
                host: None,
                method: None,
                headers: HashMap::new(),
                query_params: HashMap::new(),
                action: RewriteAction::Rewrite,
                target: String::new(),
                set_headers: HashMap::new(),
                remove_headers: Vec::new(),
                add_query_params: HashMap::new(),
                remove_query_params: Vec::new(),
                stop: true,
            },
        }
    }

    /// Set priority
    pub fn priority(mut self, priority: i32) -> Self {
        self.rule.priority = priority;
        self
    }

    /// Match path with prefix
    pub fn path_prefix(mut self, prefix: &str) -> Self {
        self.rule.path = Some(MatchCondition {
            match_type: MatchType::Prefix,
            pattern: prefix.to_string(),
            case_insensitive: false,
            negate: false,
        });
        self
    }

    /// Match path with exact match
    pub fn path_exact(mut self, path: &str) -> Self {
        self.rule.path = Some(MatchCondition {
            match_type: MatchType::Exact,
            pattern: path.to_string(),
            case_insensitive: false,
            negate: false,
        });
        self
    }

    /// Match path with regex
    pub fn path_regex(mut self, pattern: &str) -> Self {
        self.rule.path = Some(MatchCondition {
            match_type: MatchType::Regex,
            pattern: pattern.to_string(),
            case_insensitive: false,
            negate: false,
        });
        self
    }

    /// Match host
    pub fn host(mut self, host: &str) -> Self {
        self.rule.host = Some(MatchCondition {
            match_type: MatchType::Exact,
            pattern: host.to_string(),
            case_insensitive: true,
            negate: false,
        });
        self
    }

    /// Match method
    pub fn method(mut self, method: &str) -> Self {
        self.rule.method = Some(method.to_string());
        self
    }

    /// Set action to rewrite
    pub fn rewrite_to(mut self, target: &str) -> Self {
        self.rule.action = RewriteAction::Rewrite;
        self.rule.target = target.to_string();
        self
    }

    /// Set action to redirect 301
    pub fn redirect_permanent(mut self, target: &str) -> Self {
        self.rule.action = RewriteAction::RedirectPermanent;
        self.rule.target = target.to_string();
        self
    }

    /// Set action to redirect 302
    pub fn redirect_temporary(mut self, target: &str) -> Self {
        self.rule.action = RewriteAction::RedirectTemporary;
        self.rule.target = target.to_string();
        self
    }

    /// Set action to proxy
    pub fn proxy_to(mut self, target: &str) -> Self {
        self.rule.action = RewriteAction::Proxy;
        self.rule.target = target.to_string();
        self
    }

    /// Add a header
    pub fn set_header(mut self, name: &str, value: &str) -> Self {
        self.rule.set_headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Continue processing rules
    pub fn continue_rules(mut self) -> Self {
        self.rule.stop = false;
        self
    }

    /// Build the rule
    pub fn build(self) -> RewriteRule {
        self.rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_match() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("strip-api")
            .path_prefix("/api/v1")
            .rewrite_to("/v1")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/api/v1/users", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Rewrite { path, .. } => {
                assert_eq!(path, "/v1");
            }
            _ => panic!("Expected rewrite result"),
        }
    }

    #[test]
    fn test_regex_match_with_capture() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("version-rewrite")
            .path_regex("^/api/v(\\d+)/(.*)$")
            .rewrite_to("/api/$1/$2")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/api/v2/users/123", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Rewrite { path, .. } => {
                assert_eq!(path, "/api/2/users/123");
            }
            _ => panic!("Expected rewrite result"),
        }
    }

    #[test]
    fn test_redirect_permanent() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("old-to-new")
            .path_prefix("/old")
            .redirect_permanent("/new")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/old/page", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Redirect { location, status } => {
                assert_eq!(location, "/new");
                assert_eq!(status, 301);
            }
            _ => panic!("Expected redirect result"),
        }
    }

    #[test]
    fn test_host_based_routing() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("api-subdomain")
            .host("api.example.com")
            .path_prefix("/")
            .proxy_to("http://api-backend:8080${path}")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/users", None, "api.example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Proxy { target, .. } => {
                assert_eq!(target, "http://api-backend:8080/users");
            }
            _ => panic!("Expected proxy result"),
        }
    }

    #[test]
    fn test_method_match() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("post-only")
            .method("POST")
            .path_prefix("/submit")
            .rewrite_to("/api/submit")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        // POST should match
        let ctx = RewriteContext::new("POST", "/submit", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);
        assert!(matches!(result, RewriteResult::Rewrite { .. }));

        // GET should not match
        let ctx2 = RewriteContext::new("GET", "/submit", None, "example.com");
        let result2 = engine.evaluate("tunnel-1", &ctx2);
        assert!(matches!(result2, RewriteResult::NoMatch));
    }

    #[test]
    fn test_no_match() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("specific-path")
            .path_prefix("/specific")
            .rewrite_to("/other")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/different/path", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        assert!(matches!(result, RewriteResult::NoMatch));
    }

    #[test]
    fn test_priority_ordering() {
        let engine = RewriteEngine::new();

        let rule1 = RuleBuilder::new("catch-all")
            .priority(0)
            .path_prefix("/")
            .rewrite_to("/default")
            .build();

        let rule2 = RuleBuilder::new("specific")
            .priority(100)
            .path_prefix("/api")
            .rewrite_to("/api-handler")
            .build();

        // Add in wrong order to test sorting
        engine.add_rules("tunnel-1", vec![rule1, rule2]);

        let ctx = RewriteContext::new("GET", "/api/users", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Rewrite { path, .. } => {
                assert_eq!(path, "/api-handler"); // Higher priority wins
            }
            _ => panic!("Expected rewrite result"),
        }
    }

    #[test]
    fn test_query_param_manipulation() {
        let engine = RewriteEngine::new();

        let mut rule = RuleBuilder::new("add-params")
            .path_prefix("/")
            .rewrite_to("/target")
            .build();
        rule.add_query_params.insert("added".to_string(), "value".to_string());
        rule.remove_query_params.push("removed".to_string());

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/source", Some("existing=1&removed=2"), "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Rewrite { query, .. } => {
                let q = query.unwrap();
                assert!(q.contains("added=value"));
                assert!(q.contains("existing=1"));
                assert!(!q.contains("removed=2"));
            }
            _ => panic!("Expected rewrite result"),
        }
    }

    #[test]
    fn test_header_matching() {
        let engine = RewriteEngine::new();

        let mut rule = RuleBuilder::new("json-only")
            .path_prefix("/api")
            .rewrite_to("/json-api")
            .build();
        rule.headers.insert("content-type".to_string(), MatchCondition {
            match_type: MatchType::Contains,
            pattern: "json".to_string(),
            case_insensitive: true,
            negate: false,
        });

        engine.add_rules("tunnel-1", vec![rule]);

        // With JSON content-type
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let ctx = RewriteContext::new("POST", "/api/data", None, "example.com")
            .with_headers(headers);
        let result = engine.evaluate("tunnel-1", &ctx);
        assert!(matches!(result, RewriteResult::Rewrite { .. }));

        // Without JSON content-type
        let mut headers2 = HashMap::new();
        headers2.insert("content-type".to_string(), "text/html".to_string());
        let ctx2 = RewriteContext::new("POST", "/api/data", None, "example.com")
            .with_headers(headers2);
        let result2 = engine.evaluate("tunnel-1", &ctx2);
        assert!(matches!(result2, RewriteResult::NoMatch));
    }

    #[test]
    fn test_set_headers() {
        let engine = RewriteEngine::new();

        let rule = RuleBuilder::new("add-header")
            .path_prefix("/")
            .rewrite_to("/target")
            .set_header("X-Rewritten", "true")
            .build();

        engine.add_rules("tunnel-1", vec![rule]);

        let ctx = RewriteContext::new("GET", "/source", None, "example.com");
        let result = engine.evaluate("tunnel-1", &ctx);

        match result {
            RewriteResult::Rewrite { headers, .. } => {
                assert_eq!(headers.get("X-Rewritten"), Some(&"true".to_string()));
            }
            _ => panic!("Expected rewrite result"),
        }
    }
}
