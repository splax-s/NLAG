//! Agent and tunnel registry
//!
//! This module maintains the state of connected agents and their tunnels,
//! enabling routing of incoming traffic to the correct agent.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use nlag_common::{
    transport::quic::QuicConnection,
    types::{AgentId, TunnelConfig, TunnelId, TunnelState, TunnelStatus},
};

/// Registry of all connected agents and tunnels
#[derive(Debug)]
pub struct Registry {
    /// Agents by ID
    agents: DashMap<AgentId, AgentEntry>,

    /// Tunnels by ID
    tunnels: DashMap<TunnelId, TunnelEntry>,

    /// Subdomain -> TunnelId mapping for routing
    subdomain_map: DashMap<String, TunnelId>,

    /// Statistics
    stats: RegistryStats,
}

/// Statistics for the registry
#[derive(Debug, Default)]
#[allow(dead_code)] // Fields reserved for metrics/monitoring
pub struct RegistryStats {
    pub total_agents: AtomicU32,
    pub total_tunnels: AtomicU32,
    pub total_connections: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
}

/// Entry for a connected agent
#[derive(Debug)]
#[allow(dead_code)] // Fields used for monitoring and debugging
pub struct AgentEntry {
    /// Agent ID
    pub agent_id: AgentId,
    /// QUIC connection to the agent
    pub connection: QuicConnection,
    /// Session ID
    pub session_id: String,
    /// When the agent connected
    pub connected_at: Instant,
    /// Tunnels owned by this agent
    pub tunnels: Vec<TunnelId>,
    /// Active stream count
    pub active_streams: AtomicU32,
}

/// Entry for an active tunnel
#[allow(dead_code)] // Fields used for monitoring and status reporting
#[derive(Debug)]
pub struct TunnelEntry {
    /// Tunnel ID
    pub tunnel_id: TunnelId,
    /// Owning agent
    pub agent_id: AgentId,
    /// Tunnel configuration
    pub config: TunnelConfig,
    /// Current state
    pub state: TunnelState,
    /// Assigned subdomain
    pub subdomain: String,
    /// Public URL
    pub public_url: String,
    /// When the tunnel was created
    pub created_at: Instant,
    /// Statistics
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub connection_count: AtomicU64,
}

impl Registry {
    /// Create a new registry
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            agents: DashMap::new(),
            tunnels: DashMap::new(),
            subdomain_map: DashMap::new(),
            stats: RegistryStats::default(),
        })
    }

    /// Register a new agent
    pub fn register_agent(
        &self,
        agent_id: AgentId,
        connection: QuicConnection,
        session_id: String,
    ) -> Result<(), RegistryError> {
        if self.agents.contains_key(&agent_id) {
            return Err(RegistryError::AgentAlreadyExists(agent_id));
        }

        let entry = AgentEntry {
            agent_id,
            connection,
            session_id,
            connected_at: Instant::now(),
            tunnels: Vec::new(),
            active_streams: AtomicU32::new(0),
        };

        self.agents.insert(agent_id, entry);
        self.stats.total_agents.fetch_add(1, Ordering::Relaxed);

        tracing::info!("Agent {} registered", agent_id);
        Ok(())
    }

    /// Unregister an agent and all its tunnels
    pub fn unregister_agent(&self, agent_id: &AgentId) {
        if let Some((_, agent)) = self.agents.remove(agent_id) {
            // Remove all tunnels owned by this agent
            for tunnel_id in &agent.tunnels {
                self.remove_tunnel(tunnel_id);
            }
            self.stats.total_agents.fetch_sub(1, Ordering::Relaxed);
            tracing::info!("Agent {} unregistered", agent_id);
        }
    }

    /// Get an agent by ID
    #[allow(dead_code)] // Reserved for admin API
    pub fn get_agent(&self, agent_id: &AgentId) -> Option<dashmap::mapref::one::Ref<'_, AgentId, AgentEntry>> {
        self.agents.get(agent_id)
    }

    /// Register a new tunnel
    pub fn register_tunnel(
        &self,
        agent_id: AgentId,
        config: TunnelConfig,
        subdomain: String,
        public_url: String,
    ) -> Result<TunnelId, RegistryError> {
        // Check if subdomain is already taken
        if self.subdomain_map.contains_key(&subdomain) {
            return Err(RegistryError::SubdomainTaken(subdomain));
        }

        let tunnel_id = config.tunnel_id;

        // Check if agent exists
        let mut agent = self
            .agents
            .get_mut(&agent_id)
            .ok_or(RegistryError::AgentNotFound(agent_id))?;

        let entry = TunnelEntry {
            tunnel_id,
            agent_id,
            config,
            state: TunnelState::Active,
            subdomain: subdomain.clone(),
            public_url,
            created_at: Instant::now(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            connection_count: AtomicU64::new(0),
        };

        // Add to agent's tunnel list
        agent.tunnels.push(tunnel_id);

        // Register tunnel
        self.tunnels.insert(tunnel_id, entry);
        self.subdomain_map.insert(subdomain.clone(), tunnel_id);
        self.stats.total_tunnels.fetch_add(1, Ordering::Relaxed);

        tracing::info!("Tunnel {} registered for agent {} (subdomain: {})", tunnel_id, agent_id, subdomain);
        Ok(tunnel_id)
    }

    /// Remove a tunnel
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        if let Some((_, tunnel)) = self.tunnels.remove(tunnel_id) {
            self.subdomain_map.remove(&tunnel.subdomain);
            self.stats.total_tunnels.fetch_sub(1, Ordering::Relaxed);
            tracing::info!("Tunnel {} removed", tunnel_id);
        }
    }

    /// Get a tunnel by ID
    #[allow(dead_code)] // Reserved for admin API
    pub fn get_tunnel(&self, tunnel_id: &TunnelId) -> Option<dashmap::mapref::one::Ref<'_, TunnelId, TunnelEntry>> {
        self.tunnels.get(tunnel_id)
    }

    /// Look up tunnel by subdomain
    pub fn get_tunnel_by_subdomain(&self, subdomain: &str) -> Option<TunnelId> {
        self.subdomain_map.get(subdomain).map(|r| *r.value())
    }

    /// Get connection for a tunnel
    pub fn get_tunnel_connection(&self, tunnel_id: &TunnelId) -> Option<QuicConnection> {
        let tunnel = self.tunnels.get(tunnel_id)?;
        let agent = self.agents.get(&tunnel.agent_id)?;
        Some(agent.connection.clone())
    }

    /// Get tunnel status
    #[allow(dead_code)] // Reserved for status API
    pub fn get_tunnel_status(&self, tunnel_id: &TunnelId) -> Option<TunnelStatus> {
        let tunnel = self.tunnels.get(tunnel_id)?;

        Some(TunnelStatus {
            tunnel_id: tunnel.tunnel_id,
            state: tunnel.state,
            public_url: Some(tunnel.public_url.clone()),
            active_connections: 0, // TODO: Track this properly
            bytes_in: tunnel.bytes_in.load(Ordering::Relaxed),
            bytes_out: tunnel.bytes_out.load(Ordering::Relaxed),
            created_at: chrono::Utc::now(), // TODO: Store actual time
        })
    }

    /// Generate a unique subdomain
    pub fn generate_subdomain(&self) -> String {
        loop {
            let subdomain = generate_random_subdomain();
            if !self.subdomain_map.contains_key(&subdomain) {
                return subdomain;
            }
        }
    }

    /// Get registry statistics
    #[allow(dead_code)] // Reserved for metrics API
    pub fn stats(&self) -> &RegistryStats {
        &self.stats
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            agents: DashMap::new(),
            tunnels: DashMap::new(),
            subdomain_map: DashMap::new(),
            stats: RegistryStats::default(),
        }
    }
}

/// Errors that can occur in registry operations
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // All variants needed for complete error handling
pub enum RegistryError {
    #[error("Agent {0} already exists")]
    AgentAlreadyExists(AgentId),

    #[error("Agent {0} not found")]
    AgentNotFound(AgentId),

    #[error("Tunnel {0} not found")]
    TunnelNotFound(TunnelId),

    #[error("Subdomain '{0}' is already taken")]
    SubdomainTaken(String),
}

/// Generate a random subdomain
fn generate_random_subdomain() -> String {
    // Using adjective-noun-number format for memorable subdomains
    const ADJECTIVES: &[&str] = &[
        "quick", "lazy", "happy", "clever", "bright", "swift", "calm", "bold",
        "kind", "warm", "cool", "fresh", "neat", "smart", "fair", "wise",
    ];
    const NOUNS: &[&str] = &[
        "fox", "dog", "cat", "owl", "bee", "ant", "elk", "ram",
        "jay", "cod", "bat", "emu", "yak", "koi", "ape", "pug",
    ];

    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;

    let adj = ADJECTIVES[seed % ADJECTIVES.len()];
    let noun = NOUNS[(seed / 16) % NOUNS.len()];
    let num = (seed / 256) % 1000;

    format!("{}-{}-{}", adj, noun, num)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_generation() {
        let subdomain = generate_random_subdomain();
        assert!(!subdomain.is_empty());
        assert!(subdomain.contains('-'));
    }

    #[test]
    fn test_registry_creation() {
        let registry = Registry::new();
        assert_eq!(registry.stats.total_agents.load(Ordering::Relaxed), 0);
        assert_eq!(registry.stats.total_tunnels.load(Ordering::Relaxed), 0);
    }
}
