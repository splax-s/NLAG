//! Usage Analytics Dashboard Module
//!
//! Provides comprehensive analytics and usage metrics with aggregation and visualization.
//!
//! ## Features
//!
//! - Request/bandwidth tracking
//! - Real-time metrics
//! - Historical aggregation (hourly, daily, monthly)
//! - Top endpoints, countries, user agents
//! - Error rate tracking
//! - Performance metrics (latency percentiles)
//! - Dashboard API endpoints

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc, Timelike, Datelike};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

/// Analytics errors
#[derive(Debug, Error)]
pub enum AnalyticsError {
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),
    
    #[error("Invalid time range")]
    InvalidTimeRange,
    
    #[error("Data not available: {0}")]
    DataNotAvailable(String),
}

pub type Result<T> = std::result::Result<T, AnalyticsError>;

/// Time granularity for aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeGranularity {
    Minute,
    Hour,
    Day,
    Week,
    Month,
}

impl TimeGranularity {
    pub fn duration(&self) -> Duration {
        match self {
            Self::Minute => Duration::from_secs(60),
            Self::Hour => Duration::from_secs(3600),
            Self::Day => Duration::from_secs(86400),
            Self::Week => Duration::from_secs(604800),
            Self::Month => Duration::from_secs(2592000), // 30 days
        }
    }
    
    pub fn bucket_key(&self, dt: DateTime<Utc>) -> String {
        match self {
            Self::Minute => dt.format("%Y-%m-%d %H:%M").to_string(),
            Self::Hour => dt.format("%Y-%m-%d %H:00").to_string(),
            Self::Day => dt.format("%Y-%m-%d").to_string(),
            Self::Week => {
                let week = dt.iso_week().week();
                format!("{}-W{:02}", dt.year(), week)
            }
            Self::Month => dt.format("%Y-%m").to_string(),
        }
    }
}

/// Single request event for analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEvent {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Tunnel ID
    pub tunnel_id: String,
    
    /// HTTP method
    pub method: String,
    
    /// Request path
    pub path: String,
    
    /// Status code
    pub status_code: u16,
    
    /// Request size (bytes)
    pub request_size: u64,
    
    /// Response size (bytes)
    pub response_size: u64,
    
    /// Latency (milliseconds)
    pub latency_ms: f64,
    
    /// Client IP country code
    pub country_code: Option<String>,
    
    /// User agent
    pub user_agent: Option<String>,
    
    /// Referer
    pub referer: Option<String>,
    
    /// Is error (4xx/5xx)
    pub is_error: bool,
}

/// Aggregated metrics bucket
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsBucket {
    /// Bucket key (time period identifier)
    pub bucket: String,
    
    /// Total requests
    pub requests: u64,
    
    /// Successful requests (2xx, 3xx)
    pub success: u64,
    
    /// Client errors (4xx)
    pub client_errors: u64,
    
    /// Server errors (5xx)
    pub server_errors: u64,
    
    /// Total bytes in
    pub bytes_in: u64,
    
    /// Total bytes out
    pub bytes_out: u64,
    
    /// Sum of latencies (for average)
    latency_sum: f64,
    
    /// Min latency
    pub latency_min: f64,
    
    /// Max latency
    pub latency_max: f64,
    
    /// Latency histogram buckets
    latency_buckets: Vec<u64>,
    
    /// Unique IPs (approximate using HyperLogLog would be better for production)
    unique_ips: u32,
}

impl MetricsBucket {
    const LATENCY_BUCKETS: [u32; 10] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];
    
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            latency_min: f64::MAX,
            latency_max: 0.0,
            latency_buckets: vec![0; Self::LATENCY_BUCKETS.len() + 1],
            ..Default::default()
        }
    }
    
    /// Record a request
    pub fn record(&mut self, event: &RequestEvent) {
        self.requests += 1;
        self.bytes_in += event.request_size;
        self.bytes_out += event.response_size;
        
        // Status codes
        match event.status_code {
            200..=399 => self.success += 1,
            400..=499 => self.client_errors += 1,
            500..=599 => self.server_errors += 1,
            _ => {}
        }
        
        // Latency
        self.latency_sum += event.latency_ms;
        self.latency_min = self.latency_min.min(event.latency_ms);
        self.latency_max = self.latency_max.max(event.latency_ms);
        
        // Add to histogram
        let bucket = Self::LATENCY_BUCKETS.iter()
            .position(|&b| event.latency_ms <= b as f64)
            .unwrap_or(Self::LATENCY_BUCKETS.len());
        self.latency_buckets[bucket] += 1;
    }
    
    /// Get average latency
    pub fn latency_avg(&self) -> f64 {
        if self.requests == 0 { 0.0 } else { self.latency_sum / self.requests as f64 }
    }
    
    /// Get error rate
    pub fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            ((self.client_errors + self.server_errors) as f64 / self.requests as f64) * 100.0
        }
    }
    
    /// Get percentile latency
    pub fn latency_percentile(&self, p: f64) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        
        let target = (self.requests as f64 * p / 100.0).ceil() as u64;
        let mut cumulative = 0u64;
        
        for (i, &count) in self.latency_buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                if i < Self::LATENCY_BUCKETS.len() {
                    return Self::LATENCY_BUCKETS[i] as f64;
                } else {
                    return self.latency_max;
                }
            }
        }
        
        self.latency_max
    }
    
    pub fn p50(&self) -> f64 { self.latency_percentile(50.0) }
    pub fn p95(&self) -> f64 { self.latency_percentile(95.0) }
    pub fn p99(&self) -> f64 { self.latency_percentile(99.0) }
}

/// Top N counter
#[derive(Debug, Clone, Default)]
pub struct TopCounter {
    counts: HashMap<String, u64>,
    max_entries: usize,
}

impl TopCounter {
    pub fn new(max_entries: usize) -> Self {
        Self {
            counts: HashMap::new(),
            max_entries,
        }
    }
    
    pub fn increment(&mut self, key: &str) {
        *self.counts.entry(key.to_string()).or_default() += 1;
        
        // Prune if too many entries
        if self.counts.len() > self.max_entries * 2 {
            self.prune();
        }
    }
    
    fn prune(&mut self) {
        let mut entries: Vec<_> = self.counts.drain().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(self.max_entries);
        self.counts = entries.into_iter().collect();
    }
    
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut entries: Vec<_> = self.counts.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }
}

/// Per-tunnel analytics
#[derive(Debug)]
pub struct TunnelAnalytics {
    /// Tunnel ID
    pub tunnel_id: String,
    
    /// Hourly buckets (last 24 hours)
    hourly: DashMap<String, MetricsBucket>,
    
    /// Daily buckets (last 30 days)
    daily: DashMap<String, MetricsBucket>,
    
    /// Monthly buckets (last 12 months)
    monthly: DashMap<String, MetricsBucket>,
    
    /// Top endpoints
    top_endpoints: RwLock<TopCounter>,
    
    /// Top countries
    top_countries: RwLock<TopCounter>,
    
    /// Top user agents
    top_user_agents: RwLock<TopCounter>,
    
    /// Top referers
    top_referers: RwLock<TopCounter>,
    
    /// Status code distribution
    status_codes: DashMap<u16, u64>,
    
    /// Real-time counter (last minute)
    realtime: RwLock<RealtimeCounter>,
}

/// Real-time metrics (sliding window)
#[derive(Debug, Default)]
pub struct RealtimeCounter {
    /// Requests in current window
    pub requests: u64,
    
    /// Errors in current window
    pub errors: u64,
    
    /// Bytes in current window
    pub bytes: u64,
    
    /// Window start
    pub window_start: Option<Instant>,
}

impl RealtimeCounter {
    pub fn record(&mut self, event: &RequestEvent) {
        let now = Instant::now();
        
        // Reset if window expired
        if let Some(start) = self.window_start {
            if now.duration_since(start) > Duration::from_secs(60) {
                self.requests = 0;
                self.errors = 0;
                self.bytes = 0;
                self.window_start = Some(now);
            }
        } else {
            self.window_start = Some(now);
        }
        
        self.requests += 1;
        if event.is_error {
            self.errors += 1;
        }
        self.bytes += event.request_size + event.response_size;
    }
    
    pub fn requests_per_second(&self) -> f64 {
        let elapsed = self.window_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(60.0)
            .max(1.0);
        
        self.requests as f64 / elapsed
    }
}

impl TunnelAnalytics {
    pub fn new(tunnel_id: &str) -> Self {
        Self {
            tunnel_id: tunnel_id.to_string(),
            hourly: DashMap::new(),
            daily: DashMap::new(),
            monthly: DashMap::new(),
            top_endpoints: RwLock::new(TopCounter::new(100)),
            top_countries: RwLock::new(TopCounter::new(50)),
            top_user_agents: RwLock::new(TopCounter::new(50)),
            top_referers: RwLock::new(TopCounter::new(50)),
            status_codes: DashMap::new(),
            realtime: RwLock::new(RealtimeCounter::default()),
        }
    }
    
    /// Record a request event
    pub fn record(&self, event: &RequestEvent) {
        let now = event.timestamp;
        
        // Update hourly bucket
        let hour_key = TimeGranularity::Hour.bucket_key(now);
        self.hourly
            .entry(hour_key.clone())
            .or_insert_with(|| MetricsBucket::new(&hour_key))
            .record(event);
        
        // Update daily bucket
        let day_key = TimeGranularity::Day.bucket_key(now);
        self.daily
            .entry(day_key.clone())
            .or_insert_with(|| MetricsBucket::new(&day_key))
            .record(event);
        
        // Update monthly bucket
        let month_key = TimeGranularity::Month.bucket_key(now);
        self.monthly
            .entry(month_key.clone())
            .or_insert_with(|| MetricsBucket::new(&month_key))
            .record(event);
        
        // Update top counters
        self.top_endpoints.write().increment(&event.path);
        
        if let Some(ref country) = event.country_code {
            self.top_countries.write().increment(country);
        }
        
        if let Some(ref ua) = event.user_agent {
            // Simplify user agent
            let ua_short = simplify_user_agent(ua);
            self.top_user_agents.write().increment(&ua_short);
        }
        
        if let Some(ref referer) = event.referer {
            if !referer.is_empty() && referer != "-" {
                self.top_referers.write().increment(referer);
            }
        }
        
        // Status codes
        *self.status_codes.entry(event.status_code).or_default() += 1;
        
        // Real-time
        self.realtime.write().record(event);
    }
    
    /// Get metrics for time range
    pub fn get_metrics(&self, granularity: TimeGranularity, count: usize) -> Vec<MetricsBucket> {
        let buckets = match granularity {
            TimeGranularity::Minute | TimeGranularity::Hour => &self.hourly,
            TimeGranularity::Day | TimeGranularity::Week => &self.daily,
            TimeGranularity::Month => &self.monthly,
        };
        
        let mut results: Vec<_> = buckets.iter()
            .map(|b| b.clone())
            .collect();
        
        results.sort_by(|a, b| b.bucket.cmp(&a.bucket));
        results.truncate(count);
        results.reverse();
        
        results
    }
    
    /// Get summary statistics
    pub fn get_summary(&self) -> AnalyticsSummary {
        let mut total_requests = 0u64;
        let mut total_bytes_in = 0u64;
        let mut total_bytes_out = 0u64;
        let mut total_errors = 0u64;
        
        for bucket in self.daily.iter() {
            total_requests += bucket.requests;
            total_bytes_in += bucket.bytes_in;
            total_bytes_out += bucket.bytes_out;
            total_errors += bucket.client_errors + bucket.server_errors;
        }
        
        let realtime = self.realtime.read();
        
        AnalyticsSummary {
            total_requests,
            total_bytes_in,
            total_bytes_out,
            total_errors,
            error_rate: if total_requests > 0 {
                (total_errors as f64 / total_requests as f64) * 100.0
            } else { 0.0 },
            requests_per_second: realtime.requests_per_second(),
            top_endpoints: self.top_endpoints.read().top(10),
            top_countries: self.top_countries.read().top(10),
            top_user_agents: self.top_user_agents.read().top(10),
            status_codes: self.status_codes.iter()
                .map(|e| (*e.key(), *e.value()))
                .collect(),
        }
    }
    
    /// Cleanup old data
    pub fn cleanup(&self, max_hourly_age: Duration, max_daily_age: Duration) {
        let now = Utc::now();
        
        // Cleanup hourly (keep last 24 hours by default)
        let cutoff_hourly = now - chrono::Duration::from_std(max_hourly_age).unwrap();
        let hourly_cutoff = TimeGranularity::Hour.bucket_key(cutoff_hourly);
        
        let old_hourly: Vec<String> = self.hourly.iter()
            .filter(|b| b.bucket < hourly_cutoff)
            .map(|b| b.bucket.clone())
            .collect();
        
        for key in old_hourly {
            self.hourly.remove(&key);
        }
        
        // Cleanup daily (keep last 30 days by default)
        let cutoff_daily = now - chrono::Duration::from_std(max_daily_age).unwrap();
        let daily_cutoff = TimeGranularity::Day.bucket_key(cutoff_daily);
        
        let old_daily: Vec<String> = self.daily.iter()
            .filter(|b| b.bucket < daily_cutoff)
            .map(|b| b.bucket.clone())
            .collect();
        
        for key in old_daily {
            self.daily.remove(&key);
        }
    }
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    pub total_requests: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub requests_per_second: f64,
    pub top_endpoints: Vec<(String, u64)>,
    pub top_countries: Vec<(String, u64)>,
    pub top_user_agents: Vec<(String, u64)>,
    pub status_codes: HashMap<u16, u64>,
}

/// Analytics manager
pub struct AnalyticsManager {
    /// Per-tunnel analytics
    tunnels: DashMap<String, Arc<TunnelAnalytics>>,
    
    /// Global analytics
    global: Arc<TunnelAnalytics>,
}

impl AnalyticsManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tunnels: DashMap::new(),
            global: Arc::new(TunnelAnalytics::new("global")),
        })
    }
    
    /// Record a request
    pub fn record(&self, event: RequestEvent) {
        // Record to tunnel
        let tunnel = self.tunnels
            .entry(event.tunnel_id.clone())
            .or_insert_with(|| Arc::new(TunnelAnalytics::new(&event.tunnel_id)));
        tunnel.record(&event);
        
        // Record to global
        self.global.record(&event);
    }
    
    /// Get tunnel analytics
    pub fn get_tunnel(&self, tunnel_id: &str) -> Option<Arc<TunnelAnalytics>> {
        self.tunnels.get(tunnel_id).map(|t| Arc::clone(&t))
    }
    
    /// Get global analytics
    pub fn get_global(&self) -> Arc<TunnelAnalytics> {
        Arc::clone(&self.global)
    }
    
    /// Get dashboard data for tunnel
    pub fn get_dashboard(&self, tunnel_id: &str) -> Result<DashboardData> {
        let tunnel = self.tunnels.get(tunnel_id)
            .ok_or_else(|| AnalyticsError::TunnelNotFound(tunnel_id.to_string()))?;
        
        Ok(DashboardData {
            tunnel_id: tunnel_id.to_string(),
            summary: tunnel.get_summary(),
            hourly: tunnel.get_metrics(TimeGranularity::Hour, 24),
            daily: tunnel.get_metrics(TimeGranularity::Day, 30),
        })
    }
    
    /// Get global dashboard
    pub fn get_global_dashboard(&self) -> DashboardData {
        DashboardData {
            tunnel_id: "global".to_string(),
            summary: self.global.get_summary(),
            hourly: self.global.get_metrics(TimeGranularity::Hour, 24),
            daily: self.global.get_metrics(TimeGranularity::Day, 30),
        }
    }
    
    /// Cleanup old data
    pub fn cleanup(&self) {
        let hourly_age = Duration::from_secs(24 * 3600);
        let daily_age = Duration::from_secs(30 * 24 * 3600);
        
        for tunnel in self.tunnels.iter() {
            tunnel.cleanup(hourly_age, daily_age);
        }
        
        self.global.cleanup(hourly_age, daily_age);
    }
    
    /// List all tunnels with analytics
    pub fn list_tunnels(&self) -> Vec<String> {
        self.tunnels.iter().map(|t| t.tunnel_id.clone()).collect()
    }
}

impl Default for AnalyticsManager {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|arc| (*arc).clone())
    }
}

impl Clone for AnalyticsManager {
    fn clone(&self) -> Self {
        Self {
            tunnels: self.tunnels.clone(),
            global: Arc::clone(&self.global),
        }
    }
}

/// Dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub tunnel_id: String,
    pub summary: AnalyticsSummary,
    pub hourly: Vec<MetricsBucket>,
    pub daily: Vec<MetricsBucket>,
}

/// Simplify user agent to browser/client name
fn simplify_user_agent(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();
    
    if ua_lower.contains("curl") {
        "curl".to_string()
    } else if ua_lower.contains("wget") {
        "wget".to_string()
    } else if ua_lower.contains("python") {
        "Python".to_string()
    } else if ua_lower.contains("node") || ua_lower.contains("axios") {
        "Node.js".to_string()
    } else if ua_lower.contains("chrome") {
        if ua_lower.contains("edg") {
            "Edge".to_string()
        } else {
            "Chrome".to_string()
        }
    } else if ua_lower.contains("firefox") {
        "Firefox".to_string()
    } else if ua_lower.contains("safari") {
        "Safari".to_string()
    } else if ua_lower.contains("postman") {
        "Postman".to_string()
    } else if ua_lower.contains("insomnia") {
        "Insomnia".to_string()
    } else if ua_lower.contains("bot") || ua_lower.contains("crawl") || ua_lower.contains("spider") {
        "Bot".to_string()
    } else {
        "Other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_event(status: u16, latency: f64) -> RequestEvent {
        RequestEvent {
            timestamp: Utc::now(),
            tunnel_id: "test-tunnel".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            status_code: status,
            request_size: 100,
            response_size: 500,
            latency_ms: latency,
            country_code: Some("US".to_string()),
            user_agent: Some("Mozilla/5.0 Chrome/100".to_string()),
            referer: None,
            is_error: status >= 400,
        }
    }
    
    #[test]
    fn test_metrics_bucket() {
        let mut bucket = MetricsBucket::new("2024-01-01 12:00");
        
        bucket.record(&test_event(200, 50.0));
        bucket.record(&test_event(200, 100.0));
        bucket.record(&test_event(404, 25.0));
        bucket.record(&test_event(500, 200.0));
        
        assert_eq!(bucket.requests, 4);
        assert_eq!(bucket.success, 2);
        assert_eq!(bucket.client_errors, 1);
        assert_eq!(bucket.server_errors, 1);
        assert!((bucket.error_rate() - 50.0).abs() < 0.1);
    }
    
    #[test]
    fn test_latency_percentiles() {
        let mut bucket = MetricsBucket::new("test");
        
        for i in 1..=100 {
            let mut event = test_event(200, i as f64);
            bucket.record(&event);
        }
        
        // P50 should be around 50ms
        let p50 = bucket.p50();
        assert!(p50 >= 25.0 && p50 <= 100.0);
        
        // P99 should be high
        let p99 = bucket.p99();
        assert!(p99 >= 50.0);
    }
    
    #[test]
    fn test_top_counter() {
        let mut counter = TopCounter::new(5);
        
        for _ in 0..100 {
            counter.increment("/api/users");
        }
        for _ in 0..50 {
            counter.increment("/api/posts");
        }
        for _ in 0..25 {
            counter.increment("/api/comments");
        }
        
        let top = counter.top(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, "/api/users");
        assert_eq!(top[0].1, 100);
    }
    
    #[test]
    fn test_time_granularity() {
        let dt = chrono::DateTime::parse_from_rfc3339("2024-01-15T14:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        
        assert_eq!(TimeGranularity::Hour.bucket_key(dt), "2024-01-15 14:00");
        assert_eq!(TimeGranularity::Day.bucket_key(dt), "2024-01-15");
        assert_eq!(TimeGranularity::Month.bucket_key(dt), "2024-01");
    }
    
    #[test]
    fn test_tunnel_analytics() {
        let analytics = TunnelAnalytics::new("test-tunnel");
        
        analytics.record(&test_event(200, 50.0));
        analytics.record(&test_event(200, 100.0));
        analytics.record(&test_event(500, 200.0));
        
        let summary = analytics.get_summary();
        assert_eq!(summary.total_requests, 3);
        assert_eq!(summary.total_errors, 1);
    }
    
    #[test]
    fn test_analytics_manager() {
        let manager = AnalyticsManager::new();
        
        manager.record(test_event(200, 50.0));
        manager.record(test_event(200, 100.0));
        
        let global = manager.get_global();
        let summary = global.get_summary();
        
        assert_eq!(summary.total_requests, 2);
    }
    
    #[test]
    fn test_simplify_user_agent() {
        assert_eq!(simplify_user_agent("Mozilla/5.0 Chrome/100.0"), "Chrome");
        assert_eq!(simplify_user_agent("Mozilla/5.0 Firefox/100.0"), "Firefox");
        assert_eq!(simplify_user_agent("curl/7.68.0"), "curl");
        assert_eq!(simplify_user_agent("python-requests/2.28.0"), "Python");
        assert_eq!(simplify_user_agent("Googlebot/2.1"), "Bot");
    }
    
    #[test]
    fn test_error_rate() {
        let mut bucket = MetricsBucket::new("test");
        
        // No requests = 0% error rate
        assert_eq!(bucket.error_rate(), 0.0);
        
        bucket.record(&test_event(200, 50.0));
        bucket.record(&test_event(500, 50.0));
        
        assert!((bucket.error_rate() - 50.0).abs() < 0.1);
    }
    
    #[test]
    fn test_dashboard_data() {
        let manager = AnalyticsManager::new();
        
        manager.record(test_event(200, 50.0));
        
        let dashboard = manager.get_dashboard("test-tunnel").unwrap();
        
        assert_eq!(dashboard.tunnel_id, "test-tunnel");
        assert_eq!(dashboard.summary.total_requests, 1);
    }
}
