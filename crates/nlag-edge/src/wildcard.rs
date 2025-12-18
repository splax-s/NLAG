//! Wildcard Domains Module
//!
//! Route wildcard domains (*.example.com) to tunnels:
//! - Pattern matching for subdomains
//! - Multi-level wildcard support
//! - Priority-based routing
//! - Domain validation

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Wildcard domain pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardPattern {
    /// The pattern (e.g., "*.example.com", "*.*.example.com")
    pub pattern: String,
    /// Target tunnel ID or backend
    pub target: String,
    /// Priority (higher = matched first)
    #[serde(default)]
    pub priority: i32,
    /// Whether this pattern is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Match result from wildcard lookup
#[derive(Debug, Clone)]
pub struct WildcardMatch {
    /// The matched pattern
    pub pattern: String,
    /// Target tunnel/backend
    pub target: String,
    /// Captured wildcard parts (e.g., ["api"] for "api.example.com" matching "*.example.com")
    pub captures: Vec<String>,
    /// The full hostname that was matched
    pub hostname: String,
    /// Pattern metadata
    pub metadata: HashMap<String, String>,
}

/// Compiled wildcard pattern for efficient matching
struct CompiledPattern {
    /// Original pattern
    original: String,
    /// Compiled regex
    regex: Regex,
    /// Target tunnel/backend
    target: String,
    /// Priority
    priority: i32,
    /// Enabled flag
    enabled: bool,
    /// Metadata
    metadata: HashMap<String, String>,
}

/// Wildcard domain router
pub struct WildcardRouter {
    /// Compiled patterns sorted by priority
    patterns: RwLock<Vec<CompiledPattern>>,
    /// Cache of recent matches
    cache: RwLock<HashMap<String, Option<WildcardMatch>>>,
    /// Maximum cache size
    max_cache_size: usize,
}

impl WildcardRouter {
    /// Create a new wildcard router
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            patterns: RwLock::new(Vec::new()),
            cache: RwLock::new(HashMap::new()),
            max_cache_size: 10000,
        })
    }

    /// Create with custom cache size
    pub fn with_cache_size(max_cache_size: usize) -> Arc<Self> {
        Arc::new(Self {
            patterns: RwLock::new(Vec::new()),
            cache: RwLock::new(HashMap::new()),
            max_cache_size,
        })
    }

    /// Add a wildcard pattern
    pub fn add_pattern(&self, pattern: WildcardPattern) -> Result<(), String> {
        if !pattern.enabled {
            return Ok(());
        }

        let compiled = Self::compile_pattern(&pattern)?;
        
        let mut patterns = self.patterns.write();
        patterns.push(compiled);
        patterns.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Clear cache when patterns change
        self.cache.write().clear();
        
        Ok(())
    }

    /// Remove a pattern by its original string
    pub fn remove_pattern(&self, pattern: &str) {
        let mut patterns = self.patterns.write();
        patterns.retain(|p| p.original != pattern);
        self.cache.write().clear();
    }

    /// Add multiple patterns
    pub fn add_patterns(&self, patterns: Vec<WildcardPattern>) -> Result<(), String> {
        for pattern in patterns {
            self.add_pattern(pattern)?;
        }
        Ok(())
    }

    /// Match a hostname against patterns
    pub fn match_hostname(&self, hostname: &str) -> Option<WildcardMatch> {
        let hostname_lower = hostname.to_lowercase();
        
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&hostname_lower) {
                return cached.clone();
            }
        }

        // Find matching pattern
        let patterns = self.patterns.read();
        let result = patterns.iter().find_map(|pattern| {
            if !pattern.enabled {
                return None;
            }

            if let Some(captures) = pattern.regex.captures(&hostname_lower) {
                // Extract captured groups (the wildcard parts)
                let captured: Vec<String> = captures
                    .iter()
                    .skip(1) // Skip the full match
                    .filter_map(|m| m.map(|m| m.as_str().to_string()))
                    .collect();

                Some(WildcardMatch {
                    pattern: pattern.original.clone(),
                    target: pattern.target.clone(),
                    captures: captured,
                    hostname: hostname_lower.clone(),
                    metadata: pattern.metadata.clone(),
                })
            } else {
                None
            }
        });

        // Update cache
        {
            let mut cache = self.cache.write();
            if cache.len() >= self.max_cache_size {
                // Simple eviction: clear half the cache
                let keys_to_remove: Vec<String> = cache
                    .keys()
                    .take(self.max_cache_size / 2)
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
            cache.insert(hostname_lower, result.clone());
        }

        result
    }

    /// List all patterns
    pub fn list_patterns(&self) -> Vec<WildcardPattern> {
        self.patterns
            .read()
            .iter()
            .map(|p| WildcardPattern {
                pattern: p.original.clone(),
                target: p.target.clone(),
                priority: p.priority,
                enabled: p.enabled,
                metadata: p.metadata.clone(),
            })
            .collect()
    }

    /// Clear all patterns
    pub fn clear(&self) {
        self.patterns.write().clear();
        self.cache.write().clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read();
        let hits = cache.values().filter(|v| v.is_some()).count();
        (cache.len(), hits)
    }

    /// Compile a wildcard pattern to regex
    fn compile_pattern(pattern: &WildcardPattern) -> Result<CompiledPattern, String> {
        let regex_str = Self::pattern_to_regex(&pattern.pattern)?;
        let regex = Regex::new(&regex_str)
            .map_err(|e| format!("Invalid pattern '{}': {}", pattern.pattern, e))?;

        Ok(CompiledPattern {
            original: pattern.pattern.clone(),
            regex,
            target: pattern.target.clone(),
            priority: pattern.priority,
            enabled: pattern.enabled,
            metadata: pattern.metadata.clone(),
        })
    }

    /// Convert a wildcard pattern to a regex
    fn pattern_to_regex(pattern: &str) -> Result<String, String> {
        // Validate the pattern
        if pattern.is_empty() {
            return Err("Empty pattern".to_string());
        }

        let mut regex = String::from("^");
        let parts: Vec<&str> = pattern.split('.').collect();

        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                regex.push_str("\\.");
            }

            if *part == "*" {
                // Single-level wildcard: matches one subdomain level
                regex.push_str("([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)");
            } else if *part == "**" {
                // Multi-level wildcard: matches one or more subdomain levels
                regex.push_str("([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)");
            } else if part.contains('*') {
                // Partial wildcard like "api-*" or "*-backend"
                let escaped = regex::escape(part);
                let replaced = escaped.replace("\\*", "([a-z0-9-]*)");
                regex.push_str(&replaced);
            } else {
                // Literal part
                regex.push_str(&regex::escape(part));
            }
        }

        regex.push('$');
        Ok(regex)
    }
}

impl Default for WildcardRouter {
    fn default() -> Self {
        Self {
            patterns: RwLock::new(Vec::new()),
            cache: RwLock::new(HashMap::new()),
            max_cache_size: 10000,
        }
    }
}

/// Shared wildcard router
pub type SharedWildcardRouter = Arc<WildcardRouter>;

/// Builder for creating wildcard patterns
pub struct PatternBuilder {
    pattern: WildcardPattern,
}

impl PatternBuilder {
    /// Create a new pattern builder
    pub fn new(pattern: &str, target: &str) -> Self {
        Self {
            pattern: WildcardPattern {
                pattern: pattern.to_string(),
                target: target.to_string(),
                priority: 0,
                enabled: true,
                metadata: HashMap::new(),
            },
        }
    }

    /// Set priority
    pub fn priority(mut self, priority: i32) -> Self {
        self.pattern.priority = priority;
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.pattern.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Disable the pattern
    pub fn disabled(mut self) -> Self {
        self.pattern.enabled = false;
        self
    }

    /// Build the pattern
    pub fn build(self) -> WildcardPattern {
        self.pattern
    }
}

/// Validate a domain name
pub fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.is_empty() || parts.len() > 127 {
        return false;
    }

    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }

        // Check first and last characters
        let bytes = part.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return false;
        }

        // Check all characters
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_wildcard() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        // Should match
        let result = router.match_hostname("api.example.com");
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.target, "tunnel-1");
        assert_eq!(m.captures, vec!["api"]);
        
        // Should match different subdomain
        let result = router.match_hostname("web.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().captures, vec!["web"]);
        
        // Should not match bare domain
        let result = router.match_hostname("example.com");
        assert!(result.is_none());
        
        // Should not match nested subdomain (single wildcard)
        let result = router.match_hostname("api.v1.example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_multi_level_wildcard() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("**.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        // Should match single level
        let result = router.match_hostname("api.example.com");
        assert!(result.is_some());
        
        // Should match multiple levels
        let result = router.match_hostname("api.v1.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().captures, vec!["api.v1"]);
        
        // Should match deep nesting
        let result = router.match_hostname("a.b.c.d.example.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_partial_wildcard() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("api-*.example.com", "api-tunnel").build();
        router.add_pattern(pattern).unwrap();
        
        // Should match
        let result = router.match_hostname("api-v1.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().captures, vec!["v1"]);
        
        let result = router.match_hostname("api-staging.example.com");
        assert!(result.is_some());
        
        // Should not match without prefix
        let result = router.match_hostname("v1.example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_priority_ordering() {
        let router = WildcardRouter::new();
        
        // Add catch-all with low priority
        let pattern1 = PatternBuilder::new("*.example.com", "default")
            .priority(0)
            .build();
        router.add_pattern(pattern1).unwrap();
        
        // Add specific pattern with high priority
        let pattern2 = PatternBuilder::new("api.example.com", "api-tunnel")
            .priority(100)
            .build();
        router.add_pattern(pattern2).unwrap();
        
        // Specific pattern should win
        let result = router.match_hostname("api.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().target, "api-tunnel");
        
        // Other subdomains should match catch-all
        let result = router.match_hostname("web.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().target, "default");
    }

    #[test]
    fn test_case_insensitive() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        // Should match regardless of case
        assert!(router.match_hostname("API.Example.COM").is_some());
        assert!(router.match_hostname("api.example.com").is_some());
        assert!(router.match_hostname("Api.EXAMPLE.com").is_some());
    }

    #[test]
    fn test_no_match() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        // Different domain
        assert!(router.match_hostname("api.other.com").is_none());
        
        // Similar but different domain
        assert!(router.match_hostname("api.myexample.com").is_none());
    }

    #[test]
    fn test_multiple_patterns() {
        let router = WildcardRouter::new();
        
        let patterns = vec![
            PatternBuilder::new("*.api.example.com", "api-tunnel").priority(10).build(),
            PatternBuilder::new("*.web.example.com", "web-tunnel").priority(10).build(),
            PatternBuilder::new("*.example.com", "default-tunnel").priority(0).build(),
        ];
        
        router.add_patterns(patterns).unwrap();
        
        assert_eq!(router.match_hostname("v1.api.example.com").unwrap().target, "api-tunnel");
        assert_eq!(router.match_hostname("prod.web.example.com").unwrap().target, "web-tunnel");
        assert_eq!(router.match_hostname("other.example.com").unwrap().target, "default-tunnel");
    }

    #[test]
    fn test_exact_domain_pattern() {
        let router = WildcardRouter::new();
        
        // Exact domain (no wildcard)
        let pattern = PatternBuilder::new("api.example.com", "api-tunnel").build();
        router.add_pattern(pattern).unwrap();
        
        assert!(router.match_hostname("api.example.com").is_some());
        assert!(router.match_hostname("other.example.com").is_none());
    }

    #[test]
    fn test_metadata() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1")
            .metadata("environment", "production")
            .metadata("team", "platform")
            .build();
        router.add_pattern(pattern).unwrap();
        
        let result = router.match_hostname("api.example.com").unwrap();
        assert_eq!(result.metadata.get("environment"), Some(&"production".to_string()));
        assert_eq!(result.metadata.get("team"), Some(&"platform".to_string()));
    }

    #[test]
    fn test_caching() {
        let router = WildcardRouter::with_cache_size(100);
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        // First lookup
        let result1 = router.match_hostname("api.example.com");
        assert!(result1.is_some());
        
        // Second lookup should come from cache
        let result2 = router.match_hostname("api.example.com");
        assert!(result2.is_some());
        
        let (total, hits) = router.cache_stats();
        assert!(total >= 1);
        assert!(hits >= 1);
    }

    #[test]
    fn test_validate_domain() {
        // Valid domains
        assert!(validate_domain("example.com"));
        assert!(validate_domain("api.example.com"));
        assert!(validate_domain("my-app.example.com"));
        assert!(validate_domain("a.b.c.d.e.example.com"));
        
        // Invalid domains
        assert!(!validate_domain("")); // Empty
        assert!(!validate_domain("-example.com")); // Starts with hyphen
        assert!(!validate_domain("example-.com")); // Ends with hyphen
        assert!(!validate_domain("exa mple.com")); // Contains space
        assert!(!validate_domain("example..com")); // Double dot
    }

    #[test]
    fn test_remove_pattern() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*.example.com", "tunnel-1").build();
        router.add_pattern(pattern).unwrap();
        
        assert!(router.match_hostname("api.example.com").is_some());
        
        router.remove_pattern("*.example.com");
        
        assert!(router.match_hostname("api.example.com").is_none());
    }

    #[test]
    fn test_list_patterns() {
        let router = WildcardRouter::new();
        
        router.add_pattern(PatternBuilder::new("*.a.com", "a").build()).unwrap();
        router.add_pattern(PatternBuilder::new("*.b.com", "b").build()).unwrap();
        
        let patterns = router.list_patterns();
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn test_suffix_wildcard() {
        let router = WildcardRouter::new();
        
        let pattern = PatternBuilder::new("*-api.example.com", "api-tunnel").build();
        router.add_pattern(pattern).unwrap();
        
        assert!(router.match_hostname("v1-api.example.com").is_some());
        assert!(router.match_hostname("staging-api.example.com").is_some());
        assert!(router.match_hostname("api.example.com").is_none()); // No prefix
    }
}
