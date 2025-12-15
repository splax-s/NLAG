//! Rate limiting for public traffic
//!
//! Uses the governor crate for efficient token bucket rate limiting.

use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovRateLimiter,
};

use crate::config::RateLimitConfig;

/// Rate limiter for public traffic
#[derive(Clone)]
pub struct RateLimiter {
    /// Global rate limiter
    global: Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// Per-tunnel rate limiters
    per_tunnel: Arc<DashMap<String, Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let global_quota = Quota::per_second(
            NonZeroU32::new(config.requests_per_second * 10).unwrap_or(NonZeroU32::MIN),
        )
        .allow_burst(
            NonZeroU32::new(config.burst_size * 10).unwrap_or(NonZeroU32::MIN),
        );

        let global = Arc::new(GovRateLimiter::direct(global_quota));

        Self {
            global,
            per_tunnel: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check if a request is allowed for a given tunnel
    pub fn check(&self, tunnel_subdomain: &str) -> bool {
        // Check global limit first
        if self.global.check().is_err() {
            return false;
        }

        // Get or create per-tunnel limiter
        let limiter = self.per_tunnel
            .entry(tunnel_subdomain.to_string())
            .or_insert_with(|| {
                let quota = Quota::per_second(
                    NonZeroU32::new(self.config.requests_per_second).unwrap_or(NonZeroU32::MIN),
                )
                .allow_burst(
                    NonZeroU32::new(self.config.burst_size).unwrap_or(NonZeroU32::MIN),
                );
                Arc::new(GovRateLimiter::direct(quota))
            })
            .clone();

        limiter.check().is_ok()
    }

    /// Clean up old rate limiters for tunnels that no longer exist
    #[allow(dead_code)] // Reserved for periodic cleanup task
    pub fn cleanup(&self, active_tunnels: &[String]) {
        self.per_tunnel.retain(|k, _| active_tunnels.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let config = RateLimitConfig {
            requests_per_second: 100,
            burst_size: 10,
            max_connections_per_tunnel: 50,
        };

        let limiter = RateLimiter::new(config);
        assert!(limiter.check("test-tunnel"));
    }

    #[test]
    fn test_rate_limiter_per_tunnel() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            max_connections_per_tunnel: 50,
        };

        let limiter = RateLimiter::new(config);

        // First request should succeed
        assert!(limiter.check("test-tunnel"));

        // Second request should fail (exceeded rate)
        assert!(!limiter.check("test-tunnel"));

        // Different tunnel should succeed
        assert!(limiter.check("other-tunnel"));
    }
}
