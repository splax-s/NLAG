//! Load Balancing Module
//!
//! Provides load balancing strategies for distributing traffic
//! across multiple agents serving the same subdomain.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{info, warn};

use nlag_common::types::{AgentId, TunnelId};

/// Load balancing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// Round-robin distribution
    RoundRobin,

    /// Least connections
    LeastConnections,

    /// Weighted round-robin based on agent capacity
    Weighted,

    /// Random selection
    Random,

    /// IP hash for sticky sessions
    IpHash,

    /// Response time based (fastest first)
    ResponseTime,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::RoundRobin
    }
}

/// Configuration for load balancing
#[derive(Debug, Clone)]
pub struct LoadBalancerConfig {
    /// Strategy to use
    pub strategy: LoadBalanceStrategy,

    /// Health check interval
    pub health_check_interval: Duration,

    /// Number of consecutive failures before marking unhealthy
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy
    pub healthy_threshold: u32,

    /// Connection timeout for health checks
    pub health_check_timeout: Duration,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(10),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            health_check_timeout: Duration::from_secs(5),
        }
    }
}

/// Information about a backend agent
#[derive(Debug, Clone)]
pub struct Backend {
    /// Agent ID
    pub agent_id: AgentId,

    /// Tunnel ID
    pub tunnel_id: TunnelId,

    /// Weight for weighted load balancing (1-100)
    pub weight: u32,

    /// Whether this backend is healthy
    pub healthy: bool,

    /// Current number of active connections
    pub active_connections: Arc<AtomicU64>,

    /// Total requests served
    pub total_requests: Arc<AtomicU64>,

    /// Average response time in milliseconds
    pub avg_response_time_ms: Arc<AtomicU64>,

    /// Last health check result
    pub last_health_check: Option<Instant>,

    /// Consecutive health check failures
    pub consecutive_failures: u32,

    /// Consecutive health check successes
    pub consecutive_successes: u32,
}

impl Backend {
    /// Create a new backend
    pub fn new(agent_id: AgentId, tunnel_id: TunnelId) -> Self {
        Self {
            agent_id,
            tunnel_id,
            weight: 100, // Default weight
            healthy: true,
            active_connections: Arc::new(AtomicU64::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            avg_response_time_ms: Arc::new(AtomicU64::new(0)),
            last_health_check: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }

    /// Increment active connections
    pub fn connection_started(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections and record response time
    pub fn connection_ended(&self, response_time_ms: u64) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Update running average
        let current = self.avg_response_time_ms.load(Ordering::Relaxed);
        let new_avg = if current == 0 {
            response_time_ms
        } else {
            // Exponential moving average with alpha = 0.1
            (current * 9 + response_time_ms) / 10
        };
        self.avg_response_time_ms.store(new_avg, Ordering::Relaxed);
    }
}

/// Backend group for a subdomain
pub struct BackendGroup {
    /// The subdomain this group serves
    pub subdomain: String,

    /// Available backends
    backends: RwLock<Vec<Backend>>,

    /// Round-robin counter
    rr_counter: AtomicUsize,

    /// Configuration
    config: LoadBalancerConfig,
}

impl BackendGroup {
    /// Create a new backend group
    pub fn new(subdomain: String, config: LoadBalancerConfig) -> Self {
        Self {
            subdomain,
            backends: RwLock::new(Vec::new()),
            rr_counter: AtomicUsize::new(0),
            config,
        }
    }

    /// Add a backend to the group
    pub fn add_backend(&self, backend: Backend) {
        let mut backends = self.backends.write();
        
        // Check if backend already exists
        if backends.iter().any(|b| b.agent_id == backend.agent_id) {
            return;
        }

        info!(
            subdomain = %self.subdomain,
            agent_id = %backend.agent_id,
            "Added backend to group"
        );
        backends.push(backend);
    }

    /// Remove a backend from the group
    pub fn remove_backend(&self, agent_id: &AgentId) {
        let mut backends = self.backends.write();
        if let Some(idx) = backends.iter().position(|b| &b.agent_id == agent_id) {
            backends.remove(idx);
            info!(
                subdomain = %self.subdomain,
                agent_id = %agent_id,
                "Removed backend from group"
            );
        }
    }

    /// Select a backend based on the configured strategy
    pub fn select_backend(&self, client_ip: Option<&str>) -> Option<Backend> {
        let backends = self.backends.read();
        let healthy_backends: Vec<_> = backends.iter().filter(|b| b.healthy).collect();

        if healthy_backends.is_empty() {
            warn!(subdomain = %self.subdomain, "No healthy backends available");
            return None;
        }

        match self.config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                self.select_round_robin(&healthy_backends)
            }
            LoadBalanceStrategy::LeastConnections => {
                self.select_least_connections(&healthy_backends)
            }
            LoadBalanceStrategy::Weighted => {
                self.select_weighted(&healthy_backends)
            }
            LoadBalanceStrategy::Random => {
                self.select_random(&healthy_backends)
            }
            LoadBalanceStrategy::IpHash => {
                self.select_ip_hash(&healthy_backends, client_ip)
            }
            LoadBalanceStrategy::ResponseTime => {
                self.select_response_time(&healthy_backends)
            }
        }
    }

    fn select_round_robin(&self, backends: &[&Backend]) -> Option<Backend> {
        if backends.is_empty() {
            return None;
        }

        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[idx].clone())
    }

    fn select_least_connections(&self, backends: &[&Backend]) -> Option<Backend> {
        backends
            .iter()
            .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
            .map(|b| (*b).clone())
    }

    fn select_weighted(&self, backends: &[&Backend]) -> Option<Backend> {
        if backends.is_empty() {
            return None;
        }

        let total_weight: u32 = backends.iter().map(|b| b.weight).sum();
        if total_weight == 0 {
            return self.select_round_robin(backends);
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut point = rng.gen_range(0..total_weight);

        for backend in backends {
            if point < backend.weight {
                return Some((*backend).clone());
            }
            point -= backend.weight;
        }

        backends.first().map(|b| (*b).clone())
    }

    fn select_random(&self, backends: &[&Backend]) -> Option<Backend> {
        if backends.is_empty() {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..backends.len());
        Some(backends[idx].clone())
    }

    fn select_ip_hash(&self, backends: &[&Backend], client_ip: Option<&str>) -> Option<Backend> {
        if backends.is_empty() {
            return None;
        }

        let hash = match client_ip {
            Some(ip) => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                ip.hash(&mut hasher);
                hasher.finish() as usize
            }
            None => 0,
        };

        let idx = hash % backends.len();
        Some(backends[idx].clone())
    }

    fn select_response_time(&self, backends: &[&Backend]) -> Option<Backend> {
        backends
            .iter()
            .min_by_key(|b| b.avg_response_time_ms.load(Ordering::Relaxed))
            .map(|b| (*b).clone())
    }

    /// Mark a backend as unhealthy
    pub fn mark_unhealthy(&self, agent_id: &AgentId) {
        let mut backends = self.backends.write();
        if let Some(backend) = backends.iter_mut().find(|b| &b.agent_id == agent_id) {
            backend.consecutive_failures += 1;
            backend.consecutive_successes = 0;

            if backend.consecutive_failures >= self.config.unhealthy_threshold {
                if backend.healthy {
                    backend.healthy = false;
                    warn!(
                        subdomain = %self.subdomain,
                        agent_id = %agent_id,
                        "Backend marked unhealthy"
                    );
                }
            }
        }
    }

    /// Mark a backend as healthy
    pub fn mark_healthy(&self, agent_id: &AgentId) {
        let mut backends = self.backends.write();
        if let Some(backend) = backends.iter_mut().find(|b| &b.agent_id == agent_id) {
            backend.consecutive_successes += 1;
            backend.consecutive_failures = 0;
            backend.last_health_check = Some(Instant::now());

            if backend.consecutive_successes >= self.config.healthy_threshold {
                if !backend.healthy {
                    backend.healthy = true;
                    info!(
                        subdomain = %self.subdomain,
                        agent_id = %agent_id,
                        "Backend marked healthy"
                    );
                }
            }
        }
    }

    /// Get the number of backends
    pub fn backend_count(&self) -> usize {
        self.backends.read().len()
    }

    /// Get the number of healthy backends
    pub fn healthy_backend_count(&self) -> usize {
        self.backends.read().iter().filter(|b| b.healthy).count()
    }

    /// Get all backends (for monitoring)
    pub fn get_backends(&self) -> Vec<Backend> {
        self.backends.read().clone()
    }
}

/// Load balancer managing multiple backend groups
pub struct LoadBalancer {
    /// Backend groups by subdomain
    groups: DashMap<String, Arc<BackendGroup>>,

    /// Configuration
    config: LoadBalancerConfig,
}

impl std::fmt::Debug for LoadBalancer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancer")
            .field("groups_count", &self.groups.len())
            .field("strategy", &self.config.strategy)
            .finish()
    }
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(config: LoadBalancerConfig) -> Arc<Self> {
        Arc::new(Self {
            groups: DashMap::new(),
            config,
        })
    }

    /// Get or create a backend group for a subdomain
    pub fn get_or_create_group(&self, subdomain: &str) -> Arc<BackendGroup> {
        self.groups
            .entry(subdomain.to_string())
            .or_insert_with(|| {
                Arc::new(BackendGroup::new(subdomain.to_string(), self.config.clone()))
            })
            .clone()
    }

    /// Add a backend to a subdomain
    pub fn add_backend(&self, subdomain: &str, backend: Backend) {
        let group = self.get_or_create_group(subdomain);
        group.add_backend(backend);
    }

    /// Remove a backend from a subdomain
    pub fn remove_backend(&self, subdomain: &str, agent_id: &AgentId) {
        if let Some(group) = self.groups.get(subdomain) {
            group.remove_backend(agent_id);

            // Clean up empty groups
            if group.backend_count() == 0 {
                drop(group);
                self.groups.remove(subdomain);
            }
        }
    }

    /// Select a backend for a request
    pub fn select(&self, subdomain: &str, client_ip: Option<&str>) -> Option<Backend> {
        self.groups
            .get(subdomain)
            .and_then(|group| group.select_backend(client_ip))
    }

    /// Mark a backend as unhealthy
    pub fn mark_unhealthy(&self, subdomain: &str, agent_id: &AgentId) {
        if let Some(group) = self.groups.get(subdomain) {
            group.mark_unhealthy(agent_id);
        }
    }

    /// Mark a backend as healthy
    pub fn mark_healthy(&self, subdomain: &str, agent_id: &AgentId) {
        if let Some(group) = self.groups.get(subdomain) {
            group.mark_healthy(agent_id);
        }
    }

    /// Get statistics for a subdomain
    pub fn get_group_stats(&self, subdomain: &str) -> Option<GroupStats> {
        self.groups.get(subdomain).map(|group| {
            let backends = group.get_backends();
            GroupStats {
                subdomain: subdomain.to_string(),
                total_backends: backends.len(),
                healthy_backends: backends.iter().filter(|b| b.healthy).count(),
                total_connections: backends
                    .iter()
                    .map(|b| b.active_connections.load(Ordering::Relaxed))
                    .sum(),
                total_requests: backends
                    .iter()
                    .map(|b| b.total_requests.load(Ordering::Relaxed))
                    .sum(),
            }
        })
    }

    /// List all subdomain groups
    pub fn list_groups(&self) -> Vec<String> {
        self.groups.iter().map(|e| e.key().clone()).collect()
    }
}

/// Statistics for a backend group
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub subdomain: String,
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub total_connections: u64,
    pub total_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let config = LoadBalancerConfig {
            strategy: LoadBalanceStrategy::RoundRobin,
            ..Default::default()
        };
        let group = BackendGroup::new("test".to_string(), config);

        // Add backends
        for i in 0..3 {
            let backend = Backend::new(AgentId::new(), TunnelId::new());
            group.add_backend(backend);
        }

        // Select should cycle through backends
        let mut selections = Vec::new();
        for _ in 0..6 {
            if let Some(b) = group.select_backend(None) {
                selections.push(b.agent_id);
            }
        }

        // Should have cycled through twice
        assert_eq!(selections.len(), 6);
        assert_eq!(selections[0], selections[3]);
        assert_eq!(selections[1], selections[4]);
        assert_eq!(selections[2], selections[5]);
    }

    #[test]
    fn test_least_connections() {
        let config = LoadBalancerConfig {
            strategy: LoadBalanceStrategy::LeastConnections,
            ..Default::default()
        };
        let group = BackendGroup::new("test".to_string(), config);

        let b1 = Backend::new(AgentId::new(), TunnelId::new());
        let b2 = Backend::new(AgentId::new(), TunnelId::new());

        // Give b1 more connections
        b1.active_connections.store(10, Ordering::Relaxed);
        b2.active_connections.store(2, Ordering::Relaxed);

        let agent1 = b1.agent_id;
        let agent2 = b2.agent_id;

        group.add_backend(b1);
        group.add_backend(b2);

        // Should select b2 (fewer connections)
        let selected = group.select_backend(None).unwrap();
        assert_eq!(selected.agent_id, agent2);
    }

    #[test]
    fn test_health_check() {
        let config = LoadBalancerConfig {
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            ..Default::default()
        };
        let group = BackendGroup::new("test".to_string(), config);

        let backend = Backend::new(AgentId::new(), TunnelId::new());
        let agent_id = backend.agent_id;
        group.add_backend(backend);

        // Mark unhealthy multiple times
        group.mark_unhealthy(&agent_id);
        group.mark_unhealthy(&agent_id);
        assert!(group.select_backend(None).is_some()); // Still healthy

        group.mark_unhealthy(&agent_id);
        assert!(group.select_backend(None).is_none()); // Now unhealthy

        // Mark healthy
        group.mark_healthy(&agent_id);
        assert!(group.select_backend(None).is_none()); // Not yet healthy

        group.mark_healthy(&agent_id);
        assert!(group.select_backend(None).is_some()); // Now healthy again
    }
}
