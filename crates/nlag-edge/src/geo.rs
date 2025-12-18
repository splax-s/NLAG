//! Geo-Restriction Module
//!
//! Provides geographic access control for tunnels based on IP geolocation.
//!
//! ## Features
//!
//! - Country allow/deny lists
//! - Region/state-level restrictions
//! - ASN (Autonomous System Number) blocking
//! - IP range blocking
//! - VPN/proxy detection
//! - Tor exit node blocking
//! - Custom geographic rules

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Geo-restriction errors
#[derive(Debug, Error)]
pub enum GeoError {
    #[error("GeoIP lookup failed: {0}")]
    LookupFailed(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("Invalid country code: {0}")]
    InvalidCountryCode(String),
    
    #[error("Database not loaded")]
    DatabaseNotLoaded,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, GeoError>;

/// Geo location data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoLocation {
    /// IP address
    pub ip: String,
    
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    
    /// Country name
    pub country_name: Option<String>,
    
    /// Region/state code
    pub region_code: Option<String>,
    
    /// Region/state name
    pub region_name: Option<String>,
    
    /// City
    pub city: Option<String>,
    
    /// Postal code
    pub postal_code: Option<String>,
    
    /// Latitude
    pub latitude: Option<f64>,
    
    /// Longitude
    pub longitude: Option<f64>,
    
    /// Timezone
    pub timezone: Option<String>,
    
    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,
    
    /// ASN organization
    pub asn_org: Option<String>,
    
    /// Is VPN/proxy
    pub is_proxy: bool,
    
    /// Is Tor exit node
    pub is_tor: bool,
    
    /// Is hosting/datacenter
    pub is_hosting: bool,
}

/// Access decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allow,
    Deny,
    Challenge,
}

/// Geo policy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Allow by default, block specific countries/regions
    Allowlist,
    /// Deny by default, allow specific countries/regions
    Denylist,
}

/// Geo-restriction policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPolicy {
    /// Policy ID
    pub id: String,
    
    /// Policy name
    pub name: String,
    
    /// Policy mode
    pub mode: PolicyMode,
    
    /// Country codes (allow or deny based on mode)
    #[serde(default)]
    pub countries: HashSet<String>,
    
    /// Region codes (format: "US-CA" for California, USA)
    #[serde(default)]
    pub regions: HashSet<String>,
    
    /// Blocked ASNs
    #[serde(default)]
    pub blocked_asns: HashSet<u32>,
    
    /// Blocked IP ranges (CIDR notation)
    #[serde(default)]
    pub blocked_ip_ranges: Vec<String>,
    
    /// Block VPN/proxy
    #[serde(default)]
    pub block_proxy: bool,
    
    /// Block Tor
    #[serde(default)]
    pub block_tor: bool,
    
    /// Block hosting/datacenter IPs
    #[serde(default)]
    pub block_hosting: bool,
    
    /// Custom message for blocked requests
    #[serde(default)]
    pub block_message: Option<String>,
    
    /// Redirect URL for blocked requests
    #[serde(default)]
    pub redirect_url: Option<String>,
    
    /// Log blocked requests
    #[serde(default = "default_true")]
    pub log_blocked: bool,
    
    /// Enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

impl Default for GeoPolicy {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Default Policy".to_string(),
            mode: PolicyMode::Allowlist,
            countries: HashSet::new(),
            regions: HashSet::new(),
            blocked_asns: HashSet::new(),
            blocked_ip_ranges: Vec::new(),
            block_proxy: false,
            block_tor: false,
            block_hosting: false,
            block_message: None,
            redirect_url: None,
            log_blocked: true,
            enabled: true,
        }
    }
}

impl GeoPolicy {
    /// Create an allow-all policy
    pub fn allow_all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mode: PolicyMode::Allowlist,
            ..Default::default()
        }
    }
    
    /// Create a deny-all policy
    pub fn deny_all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mode: PolicyMode::Denylist,
            ..Default::default()
        }
    }
    
    /// Create a country allowlist
    pub fn allow_countries(name: &str, countries: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            mode: PolicyMode::Denylist,
            countries: countries.iter().map(|s| s.to_uppercase()).collect(),
            ..Default::default()
        }
    }
    
    /// Create a country blocklist
    pub fn block_countries(name: &str, countries: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            mode: PolicyMode::Allowlist,
            countries: countries.iter().map(|s| s.to_uppercase()).collect(),
            ..Default::default()
        }
    }
    
    /// Check access for a location
    pub fn check_access(&self, location: &GeoLocation) -> GeoAccessResult {
        if !self.enabled {
            return GeoAccessResult::allowed();
        }
        
        // Check proxy/VPN
        if self.block_proxy && location.is_proxy {
            return GeoAccessResult::denied("VPN/Proxy detected", self);
        }
        
        // Check Tor
        if self.block_tor && location.is_tor {
            return GeoAccessResult::denied("Tor exit node detected", self);
        }
        
        // Check hosting
        if self.block_hosting && location.is_hosting {
            return GeoAccessResult::denied("Datacenter IP detected", self);
        }
        
        // Check ASN
        if let Some(asn) = location.asn {
            if self.blocked_asns.contains(&asn) {
                return GeoAccessResult::denied(
                    &format!("ASN {} is blocked", asn),
                    self,
                );
            }
        }
        
        // Check IP ranges
        if let Ok(ip) = location.ip.parse::<IpAddr>() {
            for range in &self.blocked_ip_ranges {
                if ip_in_cidr(ip, range) {
                    return GeoAccessResult::denied("IP range blocked", self);
                }
            }
        }
        
        // Check country
        if let Some(ref country) = location.country_code {
            let country_upper = country.to_uppercase();
            let in_list = self.countries.contains(&country_upper);
            
            match self.mode {
                PolicyMode::Allowlist => {
                    // Block if in list
                    if in_list {
                        return GeoAccessResult::denied(
                            &format!("Country {} is blocked", country),
                            self,
                        );
                    }
                }
                PolicyMode::Denylist => {
                    // Block if NOT in list
                    if !in_list && !self.countries.is_empty() {
                        return GeoAccessResult::denied(
                            &format!("Country {} is not allowed", country),
                            self,
                        );
                    }
                }
            }
        }
        
        // Check region
        if let (Some(ref country), Some(ref region)) = (&location.country_code, &location.region_code) {
            let region_key = format!("{}-{}", country.to_uppercase(), region.to_uppercase());
            
            if !self.regions.is_empty() {
                let in_list = self.regions.contains(&region_key);
                
                match self.mode {
                    PolicyMode::Allowlist => {
                        if in_list {
                            return GeoAccessResult::denied(
                                &format!("Region {} is blocked", region_key),
                                self,
                            );
                        }
                    }
                    PolicyMode::Denylist => {
                        if !in_list {
                            return GeoAccessResult::denied(
                                &format!("Region {} is not allowed", region_key),
                                self,
                            );
                        }
                    }
                }
            }
        }
        
        GeoAccessResult::allowed()
    }
}

/// Access check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAccessResult {
    pub decision: AccessDecision,
    pub reason: Option<String>,
    pub block_message: Option<String>,
    pub redirect_url: Option<String>,
}

impl GeoAccessResult {
    pub fn allowed() -> Self {
        Self {
            decision: AccessDecision::Allow,
            reason: None,
            block_message: None,
            redirect_url: None,
        }
    }
    
    pub fn denied(reason: &str, policy: &GeoPolicy) -> Self {
        Self {
            decision: AccessDecision::Deny,
            reason: Some(reason.to_string()),
            block_message: policy.block_message.clone(),
            redirect_url: policy.redirect_url.clone(),
        }
    }
    
    pub fn is_allowed(&self) -> bool {
        self.decision == AccessDecision::Allow
    }
}

/// GeoIP database provider trait
pub trait GeoIpProvider: Send + Sync {
    fn lookup(&self, ip: &str) -> Result<GeoLocation>;
}

/// Mock GeoIP provider for testing
pub struct MockGeoIpProvider {
    locations: HashMap<String, GeoLocation>,
}

impl MockGeoIpProvider {
    pub fn new() -> Self {
        let mut locations = HashMap::new();
        
        // Add some test IPs
        locations.insert("8.8.8.8".to_string(), GeoLocation {
            ip: "8.8.8.8".to_string(),
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region_code: Some("CA".to_string()),
            region_name: Some("California".to_string()),
            city: Some("Mountain View".to_string()),
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
            ..Default::default()
        });
        
        locations.insert("1.1.1.1".to_string(), GeoLocation {
            ip: "1.1.1.1".to_string(),
            country_code: Some("AU".to_string()),
            country_name: Some("Australia".to_string()),
            asn: Some(13335),
            asn_org: Some("Cloudflare".to_string()),
            ..Default::default()
        });
        
        Self { locations }
    }
    
    pub fn add_location(&mut self, ip: &str, location: GeoLocation) {
        self.locations.insert(ip.to_string(), location);
    }
}

impl Default for MockGeoIpProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpProvider for MockGeoIpProvider {
    fn lookup(&self, ip: &str) -> Result<GeoLocation> {
        self.locations.get(ip)
            .cloned()
            .ok_or_else(|| GeoError::LookupFailed(format!("IP {} not found", ip)))
    }
}

/// Cached GeoIP provider wrapper
pub struct CachedGeoIpProvider<P: GeoIpProvider> {
    inner: P,
    cache: DashMap<String, (GeoLocation, Instant)>,
    cache_duration: Duration,
}

impl<P: GeoIpProvider> CachedGeoIpProvider<P> {
    pub fn new(inner: P, cache_duration: Duration) -> Self {
        Self {
            inner,
            cache: DashMap::new(),
            cache_duration,
        }
    }
    
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl<P: GeoIpProvider> GeoIpProvider for CachedGeoIpProvider<P> {
    fn lookup(&self, ip: &str) -> Result<GeoLocation> {
        // Check cache
        if let Some(entry) = self.cache.get(ip) {
            if entry.1.elapsed() < self.cache_duration {
                return Ok(entry.0.clone());
            }
        }
        
        // Lookup
        let location = self.inner.lookup(ip)?;
        
        // Cache
        self.cache.insert(ip.to_string(), (location.clone(), Instant::now()));
        
        Ok(location)
    }
}

/// Geo-restriction manager
pub struct GeoManager {
    /// GeoIP provider
    provider: Arc<dyn GeoIpProvider>,
    
    /// Policies by ID
    policies: DashMap<String, GeoPolicy>,
    
    /// Tunnel to policy mapping
    tunnel_policies: DashMap<String, Vec<String>>,
    
    /// Global blocked IPs (quick deny list)
    global_blocked_ips: RwLock<HashSet<String>>,
    
    /// Known Tor exit nodes
    tor_exits: RwLock<HashSet<String>>,
    
    /// Statistics
    stats: RwLock<GeoStats>,
}

/// Geo-restriction statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoStats {
    pub total_checks: u64,
    pub allowed: u64,
    pub denied: u64,
    pub denied_by_country: HashMap<String, u64>,
    pub denied_by_reason: HashMap<String, u64>,
}

impl GeoManager {
    /// Create a new geo manager
    pub fn new(provider: Arc<dyn GeoIpProvider>) -> Arc<Self> {
        Arc::new(Self {
            provider,
            policies: DashMap::new(),
            tunnel_policies: DashMap::new(),
            global_blocked_ips: RwLock::new(HashSet::new()),
            tor_exits: RwLock::new(HashSet::new()),
            stats: RwLock::new(GeoStats::default()),
        })
    }
    
    /// Create with mock provider (for testing)
    pub fn with_mock() -> Arc<Self> {
        Self::new(Arc::new(MockGeoIpProvider::new()))
    }
    
    /// Add a policy
    pub fn add_policy(&self, policy: GeoPolicy) {
        info!("Added geo policy: {} ({})", policy.name, policy.id);
        self.policies.insert(policy.id.clone(), policy);
    }
    
    /// Get a policy
    pub fn get_policy(&self, id: &str) -> Option<GeoPolicy> {
        self.policies.get(id).map(|p| p.clone())
    }
    
    /// Remove a policy
    pub fn remove_policy(&self, id: &str) -> bool {
        self.policies.remove(id).is_some()
    }
    
    /// Assign policies to tunnel
    pub fn assign_policies(&self, tunnel_id: &str, policy_ids: Vec<String>) {
        self.tunnel_policies.insert(tunnel_id.to_string(), policy_ids);
    }
    
    /// Check access for an IP to a tunnel
    pub fn check_access(&self, tunnel_id: &str, ip: &str) -> GeoAccessResult {
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_checks += 1;
        }
        
        // Check global blocklist first
        if self.global_blocked_ips.read().contains(ip) {
            self.record_denial("global_blocked");
            return GeoAccessResult {
                decision: AccessDecision::Deny,
                reason: Some("IP globally blocked".to_string()),
                block_message: None,
                redirect_url: None,
            };
        }
        
        // Get policies for tunnel
        let policy_ids = self.tunnel_policies.get(tunnel_id)
            .map(|p| p.clone())
            .unwrap_or_default();
        
        if policy_ids.is_empty() {
            // No policies = allow
            self.stats.write().allowed += 1;
            return GeoAccessResult::allowed();
        }
        
        // Lookup IP
        let location = match self.provider.lookup(ip) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("GeoIP lookup failed for {}: {}", ip, e);
                // Allow on lookup failure (fail open)
                self.stats.write().allowed += 1;
                return GeoAccessResult::allowed();
            }
        };
        
        // Check Tor - create a mutable copy if needed
        let location = if self.tor_exits.read().contains(ip) {
            let mut loc = location;
            loc.is_tor = true;
            loc
        } else {
            location
        };
        
        // Check each policy
        for policy_id in policy_ids {
            if let Some(policy) = self.policies.get(&policy_id) {
                let result = policy.check_access(&location);
                
                if !result.is_allowed() {
                    self.record_denial(result.reason.as_deref().unwrap_or("unknown"));
                    if let Some(ref country) = location.country_code {
                        let mut stats = self.stats.write();
                        *stats.denied_by_country.entry(country.clone()).or_default() += 1;
                    }
                    return result;
                }
            }
        }
        
        // All policies passed
        self.stats.write().allowed += 1;
        GeoAccessResult::allowed()
    }
    
    fn record_denial(&self, reason: &str) {
        let mut stats = self.stats.write();
        stats.denied += 1;
        *stats.denied_by_reason.entry(reason.to_string()).or_default() += 1;
    }
    
    /// Lookup IP location
    pub fn lookup(&self, ip: &str) -> Result<GeoLocation> {
        self.provider.lookup(ip)
    }
    
    /// Block an IP globally
    pub fn block_ip(&self, ip: &str) {
        self.global_blocked_ips.write().insert(ip.to_string());
    }
    
    /// Unblock an IP
    pub fn unblock_ip(&self, ip: &str) -> bool {
        self.global_blocked_ips.write().remove(ip)
    }
    
    /// Add Tor exit nodes
    pub fn add_tor_exits(&self, ips: &[&str]) {
        let mut exits = self.tor_exits.write();
        for ip in ips {
            exits.insert(ip.to_string());
        }
    }
    
    /// Get statistics
    pub fn stats(&self) -> GeoStats {
        self.stats.read().clone()
    }
    
    /// List all policies
    pub fn list_policies(&self) -> Vec<GeoPolicy> {
        self.policies.iter().map(|p| p.clone()).collect()
    }
}

/// Check if IP is in CIDR range
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let network: IpAddr = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 { return false; }
            let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 { return false; }
            let ip_bytes = ip.octets();
            let net_bytes = net.octets();
            
            let full_bytes = (prefix_len / 8) as usize;
            let remaining_bits = prefix_len % 8;
            
            // Check full bytes
            if ip_bytes[..full_bytes] != net_bytes[..full_bytes] {
                return false;
            }
            
            // Check remaining bits
            if remaining_bits > 0 && full_bytes < 16 {
                let mask = !0u8 << (8 - remaining_bits);
                if (ip_bytes[full_bytes] & mask) != (net_bytes[full_bytes] & mask) {
                    return false;
                }
            }
            
            true
        }
        _ => false, // Mixed v4/v6
    }
}

/// Country code validation
pub fn validate_country_code(code: &str) -> bool {
    // ISO 3166-1 alpha-2 codes
    const VALID_CODES: &[&str] = &[
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
        "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
        "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
        "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
        "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
        "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
        "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
        "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
        "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
        "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
        "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
        "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
        "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
        "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
        "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
        "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
    ];
    
    VALID_CODES.contains(&code.to_uppercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn mock_us_location() -> GeoLocation {
        GeoLocation {
            ip: "8.8.8.8".to_string(),
            country_code: Some("US".to_string()),
            region_code: Some("CA".to_string()),
            ..Default::default()
        }
    }
    
    fn mock_cn_location() -> GeoLocation {
        GeoLocation {
            ip: "1.2.3.4".to_string(),
            country_code: Some("CN".to_string()),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_allow_all_policy() {
        let policy = GeoPolicy::allow_all("test");
        
        assert!(policy.check_access(&mock_us_location()).is_allowed());
        assert!(policy.check_access(&mock_cn_location()).is_allowed());
    }
    
    #[test]
    fn test_block_countries() {
        let policy = GeoPolicy::block_countries("test", &["CN", "RU"]);
        
        assert!(policy.check_access(&mock_us_location()).is_allowed());
        assert!(!policy.check_access(&mock_cn_location()).is_allowed());
    }
    
    #[test]
    fn test_allow_countries() {
        let policy = GeoPolicy::allow_countries("test", &["US", "CA", "GB"]);
        
        assert!(policy.check_access(&mock_us_location()).is_allowed());
        assert!(!policy.check_access(&mock_cn_location()).is_allowed());
    }
    
    #[test]
    fn test_block_proxy() {
        let mut policy = GeoPolicy::allow_all("test");
        policy.block_proxy = true;
        
        let mut loc = mock_us_location();
        assert!(policy.check_access(&loc).is_allowed());
        
        loc.is_proxy = true;
        assert!(!policy.check_access(&loc).is_allowed());
    }
    
    #[test]
    fn test_block_tor() {
        let mut policy = GeoPolicy::allow_all("test");
        policy.block_tor = true;
        
        let mut loc = mock_us_location();
        loc.is_tor = true;
        
        assert!(!policy.check_access(&loc).is_allowed());
    }
    
    #[test]
    fn test_block_asn() {
        let mut policy = GeoPolicy::allow_all("test");
        policy.blocked_asns.insert(12345);
        
        let mut loc = mock_us_location();
        assert!(policy.check_access(&loc).is_allowed());
        
        loc.asn = Some(12345);
        assert!(!policy.check_access(&loc).is_allowed());
    }
    
    #[test]
    fn test_ip_in_cidr_v4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        
        assert!(ip_in_cidr(ip, "192.168.1.0/24"));
        assert!(ip_in_cidr(ip, "192.168.0.0/16"));
        assert!(!ip_in_cidr(ip, "192.168.2.0/24"));
        assert!(!ip_in_cidr(ip, "10.0.0.0/8"));
    }
    
    #[test]
    fn test_ip_in_cidr_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        
        assert!(ip_in_cidr(ip, "2001:db8::/32"));
        assert!(!ip_in_cidr(ip, "2001:db9::/32"));
    }
    
    #[test]
    fn test_validate_country_code() {
        assert!(validate_country_code("US"));
        assert!(validate_country_code("us"));
        assert!(validate_country_code("GB"));
        assert!(!validate_country_code("XX"));
        assert!(!validate_country_code("USA"));
    }
    
    #[test]
    fn test_geo_manager() {
        let manager = GeoManager::with_mock();
        
        // Add a policy
        let policy = GeoPolicy::block_countries("test", &["CN"]);
        let policy_id = policy.id.clone();
        manager.add_policy(policy);
        
        // Assign to tunnel
        manager.assign_policies("tunnel1", vec![policy_id]);
        
        // Check access
        let result = manager.check_access("tunnel1", "8.8.8.8");
        assert!(result.is_allowed());
    }
    
    #[test]
    fn test_global_block() {
        let manager = GeoManager::with_mock();
        
        manager.block_ip("1.2.3.4");
        
        let result = manager.check_access("any-tunnel", "1.2.3.4");
        assert!(!result.is_allowed());
        assert_eq!(result.reason, Some("IP globally blocked".to_string()));
    }
    
    #[test]
    fn test_disabled_policy() {
        let mut policy = GeoPolicy::block_countries("test", &["US"]);
        policy.enabled = false;
        
        // Even though US is blocked, policy is disabled
        assert!(policy.check_access(&mock_us_location()).is_allowed());
    }
    
    #[test]
    fn test_custom_block_message() {
        let mut policy = GeoPolicy::block_countries("test", &["CN"]);
        policy.block_message = Some("Access denied from your region".to_string());
        policy.redirect_url = Some("https://blocked.example.com".to_string());
        
        let result = policy.check_access(&mock_cn_location());
        
        assert!(!result.is_allowed());
        assert_eq!(result.block_message, Some("Access denied from your region".to_string()));
        assert_eq!(result.redirect_url, Some("https://blocked.example.com".to_string()));
    }
}
