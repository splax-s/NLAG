//! Multi-Region Edge Server Support
//!
//! This module provides support for deploying edge servers across multiple regions
//! with region-aware routing, failover, and health checking.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, warn};

/// Multi-region errors
#[derive(Debug, Error)]
pub enum RegionError {
    #[error("Region not found: {0}")]
    RegionNotFound(String),
    
    #[error("Edge server not found: {0}")]
    EdgeNotFound(String),
    
    #[error("No healthy edge servers in region: {0}")]
    NoHealthyEdges(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, RegionError>;

/// Geographic region identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl std::fmt::Display for RegionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Predefined regions
pub mod regions {
    use super::RegionId;
    
    pub const US_EAST: &str = "us-east-1";
    pub const US_WEST: &str = "us-west-1";
    pub const EU_WEST: &str = "eu-west-1";
    pub const EU_CENTRAL: &str = "eu-central-1";
    pub const AP_NORTHEAST: &str = "ap-northeast-1";
    pub const AP_SOUTHEAST: &str = "ap-southeast-1";
    pub const SA_EAST: &str = "sa-east-1";
    
    pub fn all() -> Vec<RegionId> {
        vec![
            RegionId::new(US_EAST),
            RegionId::new(US_WEST),
            RegionId::new(EU_WEST),
            RegionId::new(EU_CENTRAL),
            RegionId::new(AP_NORTHEAST),
            RegionId::new(AP_SOUTHEAST),
            RegionId::new(SA_EAST),
        ]
    }
}

/// Region metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    /// Region identifier
    pub id: RegionId,
    /// Human-readable name
    pub name: String,
    /// Geographic location description
    pub location: String,
    /// Latitude for geographic calculations
    pub latitude: f64,
    /// Longitude for geographic calculations
    pub longitude: f64,
    /// Is this region currently active
    pub active: bool,
    /// Priority (lower = higher priority for routing)
    pub priority: u32,
}

impl Region {
    /// Calculate distance to another region (Haversine formula)
    pub fn distance_to(&self, other: &Region) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;
        
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();
        
        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();
        
        EARTH_RADIUS_KM * c
    }
}

/// Edge server status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeStatus {
    /// Edge is healthy and accepting connections
    Healthy,
    /// Edge is degraded but still functional
    Degraded,
    /// Edge is unhealthy
    Unhealthy,
    /// Edge is draining connections
    Draining,
    /// Edge is offline
    Offline,
}

/// Edge server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeServer {
    /// Unique edge identifier
    pub id: String,
    /// Region this edge belongs to
    pub region: RegionId,
    /// Public endpoint address
    pub endpoint: SocketAddr,
    /// Internal endpoint (for inter-edge communication)
    pub internal_endpoint: Option<SocketAddr>,
    /// QUIC endpoint for agents
    pub quic_endpoint: SocketAddr,
    /// Current status
    pub status: EdgeStatus,
    /// Last health check time
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
    /// Current connection count
    pub connection_count: u64,
    /// Maximum connections
    pub max_connections: u64,
    /// Weight for load balancing (higher = more traffic)
    pub weight: u32,
    /// Edge version
    pub version: String,
}

impl EdgeServer {
    /// Check if edge is available for new connections
    pub fn is_available(&self) -> bool {
        matches!(self.status, EdgeStatus::Healthy | EdgeStatus::Degraded)
            && self.connection_count < self.max_connections
    }
    
    /// Get load percentage
    pub fn load_percentage(&self) -> f64 {
        if self.max_connections == 0 {
            return 100.0;
        }
        (self.connection_count as f64 / self.max_connections as f64) * 100.0
    }
}

/// Edge server runtime state
pub struct EdgeState {
    /// Edge server info
    pub info: RwLock<EdgeServer>,
    /// Connection count (atomic for fast updates)
    connections: AtomicU64,
    /// Total requests handled
    requests_total: AtomicU64,
    /// Failed requests
    requests_failed: AtomicU64,
    /// Last ping latency in microseconds
    latency_us: AtomicU64,
    /// Consecutive health check failures
    health_failures: AtomicUsize,
}

impl EdgeState {
    pub fn new(info: EdgeServer) -> Self {
        Self {
            info: RwLock::new(info),
            connections: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
            health_failures: AtomicUsize::new(0),
        }
    }
    
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
    
    pub fn add_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn remove_connection(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }
    
    pub fn record_request(&self, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    pub fn update_latency(&self, latency_us: u64) {
        self.latency_us.store(latency_us, Ordering::Relaxed);
    }
    
    pub fn latency(&self) -> Duration {
        Duration::from_micros(self.latency_us.load(Ordering::Relaxed))
    }
    
    pub fn record_health_check(&self, success: bool) {
        if success {
            self.health_failures.store(0, Ordering::Relaxed);
        } else {
            self.health_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    pub fn health_failures(&self) -> usize {
        self.health_failures.load(Ordering::Relaxed)
    }
}

/// Region registry for managing edges across regions
pub struct RegionRegistry {
    /// Local region ID
    local_region: RegionId,
    /// All known regions
    regions: DashMap<RegionId, Region>,
    /// Edge servers by region
    edges_by_region: DashMap<RegionId, Vec<Arc<EdgeState>>>,
    /// All edges by ID
    edges_by_id: DashMap<String, Arc<EdgeState>>,
    /// Region routing preferences
    routing_preferences: RwLock<RoutingPreferences>,
}

impl RegionRegistry {
    /// Create a new region registry
    pub fn new(local_region: RegionId) -> Arc<Self> {
        Arc::new(Self {
            local_region,
            regions: DashMap::new(),
            edges_by_region: DashMap::new(),
            edges_by_id: DashMap::new(),
            routing_preferences: RwLock::new(RoutingPreferences::default()),
        })
    }
    
    /// Get the local region
    pub fn local_region(&self) -> &RegionId {
        &self.local_region
    }
    
    /// Register a region
    pub fn register_region(&self, region: Region) {
        info!("Registering region: {} ({})", region.id, region.name);
        self.regions.insert(region.id.clone(), region);
    }
    
    /// Register an edge server
    pub fn register_edge(&self, edge: EdgeServer) {
        let region = edge.region.clone();
        let id = edge.id.clone();
        
        let state = Arc::new(EdgeState::new(edge));
        
        // Add to edges by ID
        self.edges_by_id.insert(id.clone(), state.clone());
        
        // Add to region's edge list
        self.edges_by_region
            .entry(region.clone())
            .or_default()
            .push(state);
        
        info!("Registered edge {} in region {}", id, region);
    }
    
    /// Get edge by ID
    pub fn get_edge(&self, id: &str) -> Option<Arc<EdgeState>> {
        self.edges_by_id.get(id).map(|e| e.clone())
    }
    
    /// Get all edges in a region
    pub fn get_edges_in_region(&self, region: &RegionId) -> Vec<Arc<EdgeState>> {
        self.edges_by_region
            .get(region)
            .map(|e| e.clone())
            .unwrap_or_default()
    }
    
    /// Get healthy edges in a region
    pub fn get_healthy_edges(&self, region: &RegionId) -> Vec<Arc<EdgeState>> {
        self.get_edges_in_region(region)
            .into_iter()
            .filter(|e| {
                let info = e.info.read();
                info.is_available()
            })
            .collect()
    }
    
    /// Select best edge for a connection based on routing preferences
    pub fn select_edge(&self, preferred_region: Option<&RegionId>) -> Result<Arc<EdgeState>> {
        let prefs = self.routing_preferences.read();
        
        // Try preferred region first
        if let Some(region) = preferred_region {
            let edges = self.get_healthy_edges(region);
            if let Some(edge) = self.select_from_edges(&edges, &prefs) {
                return Ok(edge);
            }
        }
        
        // Try local region
        let local_edges = self.get_healthy_edges(&self.local_region);
        if let Some(edge) = self.select_from_edges(&local_edges, &prefs) {
            return Ok(edge);
        }
        
        // Try any region based on preference order
        for region_entry in self.regions.iter() {
            let region = region_entry.key();
            if *region != self.local_region {
                let edges = self.get_healthy_edges(region);
                if let Some(edge) = self.select_from_edges(&edges, &prefs) {
                    return Ok(edge);
                }
            }
        }
        
        Err(RegionError::NoHealthyEdges("all regions".to_string()))
    }
    
    /// Select edge from list based on routing strategy
    fn select_from_edges(&self, edges: &[Arc<EdgeState>], prefs: &RoutingPreferences) -> Option<Arc<EdgeState>> {
        if edges.is_empty() {
            return None;
        }
        
        match prefs.strategy {
            RoutingStrategy::RoundRobin => {
                // Simple round robin using atomic counter
                static COUNTER: AtomicUsize = AtomicUsize::new(0);
                let idx = COUNTER.fetch_add(1, Ordering::Relaxed) % edges.len();
                Some(edges[idx].clone())
            }
            RoutingStrategy::LeastConnections => {
                edges
                    .iter()
                    .min_by_key(|e| e.connection_count())
                    .cloned()
            }
            RoutingStrategy::LowestLatency => {
                edges
                    .iter()
                    .min_by_key(|e| e.latency_us.load(Ordering::Relaxed))
                    .cloned()
            }
            RoutingStrategy::WeightedRandom => {
                let total_weight: u32 = edges.iter().map(|e| e.info.read().weight).sum();
                if total_weight == 0 {
                    return edges.first().cloned();
                }
                
                let mut rng_val = rand::random::<u32>() % total_weight;
                for edge in edges {
                    let weight = edge.info.read().weight;
                    if rng_val < weight {
                        return Some(edge.clone());
                    }
                    rng_val -= weight;
                }
                edges.first().cloned()
            }
        }
    }
    
    /// Update routing preferences
    pub fn set_routing_preferences(&self, prefs: RoutingPreferences) {
        *self.routing_preferences.write() = prefs;
    }
    
    /// Get region count
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
    
    /// Get total edge count
    pub fn edge_count(&self) -> usize {
        self.edges_by_id.len()
    }
    
    /// Get all regions
    pub fn list_regions(&self) -> Vec<Region> {
        self.regions.iter().map(|e| e.value().clone()).collect()
    }
    
    /// Start health check task for all edges
    pub fn start_health_checks(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            
            loop {
                interval.tick().await;
                
                for edge in self.edges_by_id.iter() {
                    let edge = edge.value().clone();
                    let start = Instant::now();
                    
                    // Simulate health check (in real impl, would ping the edge)
                    let healthy = edge.info.read().status == EdgeStatus::Healthy;
                    
                    edge.record_health_check(healthy);
                    edge.update_latency(start.elapsed().as_micros() as u64);
                    
                    // Update status based on health failures
                    if edge.health_failures() >= 3 {
                        let mut info = edge.info.write();
                        if info.status == EdgeStatus::Healthy {
                            info.status = EdgeStatus::Degraded;
                            warn!("Edge {} marked as degraded after {} health check failures",
                                info.id, edge.health_failures());
                        } else if info.status == EdgeStatus::Degraded && edge.health_failures() >= 5 {
                            info.status = EdgeStatus::Unhealthy;
                            error!("Edge {} marked as unhealthy", info.id);
                        }
                    }
                }
            }
        });
    }
}

/// Routing strategy for edge selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingStrategy {
    /// Round-robin across edges
    RoundRobin,
    /// Route to edge with fewest connections
    LeastConnections,
    /// Route to edge with lowest latency
    LowestLatency,
    /// Weighted random selection
    WeightedRandom,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::LeastConnections
    }
}

/// Routing preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPreferences {
    /// Routing strategy
    pub strategy: RoutingStrategy,
    /// Prefer local region
    pub prefer_local: bool,
    /// Failover to other regions
    pub enable_failover: bool,
    /// Maximum latency threshold (ms) for routing decisions
    pub max_latency_ms: Option<u64>,
    /// Regions to avoid (for compliance/data residency)
    pub excluded_regions: Vec<RegionId>,
}

impl Default for RoutingPreferences {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::default(),
            prefer_local: true,
            enable_failover: true,
            max_latency_ms: None,
            excluded_regions: Vec::new(),
        }
    }
}

/// Multi-region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRegionConfig {
    /// Enable multi-region support
    #[serde(default)]
    pub enabled: bool,
    
    /// This edge's region ID
    #[serde(default = "default_region")]
    pub region: String,
    
    /// Discovery service URL (for finding other edges)
    pub discovery_url: Option<String>,
    
    /// Health check interval in seconds
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,
    
    /// Routing strategy
    #[serde(default = "default_routing_strategy")]
    pub routing_strategy: String,
    
    /// Enable cross-region failover
    #[serde(default = "default_failover")]
    pub enable_failover: bool,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_health_interval() -> u64 {
    30
}

fn default_routing_strategy() -> String {
    "least_connections".to_string()
}

fn default_failover() -> bool {
    true
}

impl Default for MultiRegionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region: default_region(),
            discovery_url: None,
            health_check_interval_secs: default_health_interval(),
            routing_strategy: default_routing_strategy(),
            enable_failover: default_failover(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_region() -> Region {
        Region {
            id: RegionId::new("us-east-1"),
            name: "US East".to_string(),
            location: "Virginia, USA".to_string(),
            latitude: 38.9,
            longitude: -77.0,
            active: true,
            priority: 1,
        }
    }
    
    fn create_test_edge(id: &str, region: &str) -> EdgeServer {
        EdgeServer {
            id: id.to_string(),
            region: RegionId::new(region),
            endpoint: "127.0.0.1:8080".parse().unwrap(),
            internal_endpoint: None,
            quic_endpoint: "127.0.0.1:4443".parse().unwrap(),
            status: EdgeStatus::Healthy,
            last_health_check: None,
            connection_count: 0,
            max_connections: 1000,
            weight: 100,
            version: "1.0.0".to_string(),
        }
    }
    
    #[test]
    fn test_region_distance() {
        let ny = Region {
            id: RegionId::new("us-east-1"),
            name: "New York".to_string(),
            location: "".to_string(),
            latitude: 40.7128,
            longitude: -74.0060,
            active: true,
            priority: 1,
        };
        
        let london = Region {
            id: RegionId::new("eu-west-1"),
            name: "London".to_string(),
            location: "".to_string(),
            latitude: 51.5074,
            longitude: -0.1278,
            active: true,
            priority: 2,
        };
        
        let distance = ny.distance_to(&london);
        // Should be approximately 5570 km
        assert!(distance > 5500.0 && distance < 5700.0);
    }
    
    #[test]
    fn test_region_registry() {
        let registry = RegionRegistry::new(RegionId::new("us-east-1"));
        
        registry.register_region(create_test_region());
        registry.register_edge(create_test_edge("edge-1", "us-east-1"));
        registry.register_edge(create_test_edge("edge-2", "us-east-1"));
        
        assert_eq!(registry.region_count(), 1);
        assert_eq!(registry.edge_count(), 2);
        
        let edges = registry.get_edges_in_region(&RegionId::new("us-east-1"));
        assert_eq!(edges.len(), 2);
    }
    
    #[test]
    fn test_edge_selection() {
        let registry = RegionRegistry::new(RegionId::new("us-east-1"));
        
        registry.register_region(create_test_region());
        registry.register_edge(create_test_edge("edge-1", "us-east-1"));
        
        let edge = registry.select_edge(None).unwrap();
        assert_eq!(edge.info.read().id, "edge-1");
    }
    
    #[test]
    fn test_edge_availability() {
        let mut edge = create_test_edge("edge-1", "us-east-1");
        assert!(edge.is_available());
        
        edge.status = EdgeStatus::Unhealthy;
        assert!(!edge.is_available());
        
        edge.status = EdgeStatus::Healthy;
        edge.connection_count = edge.max_connections;
        assert!(!edge.is_available());
    }
}
