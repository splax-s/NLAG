//! SLA Monitoring Module
//!
//! Provides real-time SLA monitoring with uptime tracking and alerting.
//!
//! ## Features
//!
//! - Uptime tracking per tunnel
//! - Latency percentile tracking (P50, P95, P99)
//! - Error rate monitoring
//! - SLA violation detection
//! - Alerting via webhooks
//! - Historical reporting

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// SLA monitoring errors
#[derive(Debug, Error)]
pub enum SlaError {
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),
    
    #[error("SLA not configured: {0}")]
    SlaNotConfigured(String),
    
    #[error("Alert delivery failed: {0}")]
    AlertFailed(String),
}

pub type Result<T> = std::result::Result<T, SlaError>;

/// SLA tier definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaTier {
    /// Tier name
    pub name: String,
    
    /// Target uptime percentage (e.g., 99.9)
    pub uptime_target: f64,
    
    /// Max allowed downtime per month in minutes
    pub max_downtime_minutes: u32,
    
    /// P99 latency target (milliseconds)
    pub latency_p99_target_ms: u32,
    
    /// Max error rate percentage
    pub max_error_rate: f64,
    
    /// Whether violations trigger alerts
    pub alert_on_violation: bool,
}

impl SlaTier {
    /// Free tier - best effort
    pub fn free() -> Self {
        Self {
            name: "free".to_string(),
            uptime_target: 95.0,
            max_downtime_minutes: 2160, // ~36 hours/month
            latency_p99_target_ms: 500,
            max_error_rate: 5.0,
            alert_on_violation: false,
        }
    }
    
    /// Pro tier - 99.5% uptime
    pub fn pro() -> Self {
        Self {
            name: "pro".to_string(),
            uptime_target: 99.5,
            max_downtime_minutes: 219, // ~3.65 hours/month
            latency_p99_target_ms: 200,
            max_error_rate: 1.0,
            alert_on_violation: true,
        }
    }
    
    /// Team tier - 99.9% uptime
    pub fn team() -> Self {
        Self {
            name: "team".to_string(),
            uptime_target: 99.9,
            max_downtime_minutes: 43, // ~43 minutes/month
            latency_p99_target_ms: 100,
            max_error_rate: 0.5,
            alert_on_violation: true,
        }
    }
    
    /// Business tier - 99.95% uptime
    pub fn business() -> Self {
        Self {
            name: "business".to_string(),
            uptime_target: 99.95,
            max_downtime_minutes: 22, // ~22 minutes/month
            latency_p99_target_ms: 50,
            max_error_rate: 0.1,
            alert_on_violation: true,
        }
    }
    
    /// Enterprise tier - 99.99% uptime
    pub fn enterprise() -> Self {
        Self {
            name: "enterprise".to_string(),
            uptime_target: 99.99,
            max_downtime_minutes: 4, // ~4 minutes/month
            latency_p99_target_ms: 25,
            max_error_rate: 0.01,
            alert_on_violation: true,
        }
    }
}

/// Health check result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Latency statistics using streaming algorithm
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Sample count
    pub count: u64,
    
    /// Sum for average calculation
    pub sum_ms: f64,
    
    /// Min latency
    pub min_ms: f64,
    
    /// Max latency
    pub max_ms: f64,
    
    /// Approximate percentiles using t-digest or similar
    /// Simplified: track histogram buckets
    buckets: Vec<u64>,
}

impl LatencyStats {
    const BUCKETS: [u32; 12] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
    
    pub fn new() -> Self {
        Self {
            count: 0,
            sum_ms: 0.0,
            min_ms: f64::MAX,
            max_ms: 0.0,
            buckets: vec![0; Self::BUCKETS.len() + 1],
        }
    }
    
    /// Record a latency sample
    pub fn record(&mut self, latency_ms: f64) {
        self.count += 1;
        self.sum_ms += latency_ms;
        self.min_ms = self.min_ms.min(latency_ms);
        self.max_ms = self.max_ms.max(latency_ms);
        
        // Add to bucket
        let bucket = Self::BUCKETS.iter()
            .position(|&b| latency_ms <= b as f64)
            .unwrap_or(Self::BUCKETS.len());
        self.buckets[bucket] += 1;
    }
    
    /// Get average latency
    pub fn average(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.sum_ms / self.count as f64 }
    }
    
    /// Estimate percentile (approximate)
    pub fn percentile(&self, p: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        
        let target = (self.count as f64 * p / 100.0).ceil() as u64;
        let mut cumulative = 0u64;
        
        for (i, &count) in self.buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                if i < Self::BUCKETS.len() {
                    return Self::BUCKETS[i] as f64;
                } else {
                    return self.max_ms;
                }
            }
        }
        
        self.max_ms
    }
    
    /// Get P50
    pub fn p50(&self) -> f64 { self.percentile(50.0) }
    
    /// Get P95
    pub fn p95(&self) -> f64 { self.percentile(95.0) }
    
    /// Get P99
    pub fn p99(&self) -> f64 { self.percentile(99.0) }
}

/// Uptime tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeTracker {
    /// Total monitored duration (seconds)
    pub total_seconds: u64,
    
    /// Up duration (seconds)
    pub up_seconds: u64,
    
    /// Number of outages
    pub outage_count: u32,
    
    /// Current status
    pub current_status: HealthStatus,
    
    /// Status since
    pub status_since: DateTime<Utc>,
    
    /// Last check time
    pub last_check: DateTime<Utc>,
    
    /// Outage history (last N)
    #[serde(default)]
    pub outages: Vec<OutageRecord>,
}

/// Record of an outage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutageRecord {
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub reason: Option<String>,
}

impl UptimeTracker {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            total_seconds: 0,
            up_seconds: 0,
            outage_count: 0,
            current_status: HealthStatus::Unknown,
            status_since: now,
            last_check: now,
            outages: Vec::new(),
        }
    }
    
    /// Record a health check result
    pub fn record_check(&mut self, status: HealthStatus, reason: Option<&str>) {
        let now = Utc::now();
        let elapsed = (now - self.last_check).num_seconds().max(0) as u64;
        
        self.total_seconds += elapsed;
        
        // If was healthy, add to up time
        if self.current_status == HealthStatus::Healthy {
            self.up_seconds += elapsed;
        }
        
        // Detect status change
        if status != self.current_status {
            if status == HealthStatus::Unhealthy || status == HealthStatus::Degraded {
                // Starting an outage
                self.outage_count += 1;
                self.outages.push(OutageRecord {
                    started_at: now,
                    ended_at: None,
                    duration_seconds: None,
                    reason: reason.map(|s| s.to_string()),
                });
                
                // Keep only last 100 outages
                if self.outages.len() > 100 {
                    self.outages.remove(0);
                }
            } else if self.current_status == HealthStatus::Unhealthy 
                   || self.current_status == HealthStatus::Degraded 
            {
                // Ending an outage
                if let Some(outage) = self.outages.last_mut() {
                    outage.ended_at = Some(now);
                    outage.duration_seconds = Some((now - outage.started_at).num_seconds().max(0) as u64);
                }
            }
            
            self.current_status = status;
            self.status_since = now;
        }
        
        self.last_check = now;
    }
    
    /// Get uptime percentage
    pub fn uptime_percentage(&self) -> f64 {
        if self.total_seconds == 0 {
            100.0
        } else {
            (self.up_seconds as f64 / self.total_seconds as f64) * 100.0
        }
    }
    
    /// Get current downtime duration if in outage
    pub fn current_downtime(&self) -> Option<Duration> {
        if self.current_status == HealthStatus::Unhealthy 
            || self.current_status == HealthStatus::Degraded 
        {
            Some(Duration::from_secs((Utc::now() - self.status_since).num_seconds().max(0) as u64))
        } else {
            None
        }
    }
}

impl Default for UptimeTracker {
    fn default() -> Self { Self::new() }
}

/// SLA metrics for a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSlaMetrics {
    /// Tunnel ID
    pub tunnel_id: String,
    
    /// Uptime tracking
    pub uptime: UptimeTracker,
    
    /// Latency stats
    pub latency: LatencyStats,
    
    /// Request count
    pub request_count: u64,
    
    /// Error count
    pub error_count: u64,
    
    /// SLA tier
    pub tier: String,
    
    /// Current violations
    #[serde(default)]
    pub violations: Vec<SlaViolation>,
    
    /// Period start
    pub period_start: DateTime<Utc>,
}

impl TunnelSlaMetrics {
    pub fn new(tunnel_id: &str, tier: &str) -> Self {
        Self {
            tunnel_id: tunnel_id.to_string(),
            uptime: UptimeTracker::new(),
            latency: LatencyStats::new(),
            request_count: 0,
            error_count: 0,
            tier: tier.to_string(),
            violations: Vec::new(),
            period_start: Utc::now(),
        }
    }
    
    /// Get error rate percentage
    pub fn error_rate(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            (self.error_count as f64 / self.request_count as f64) * 100.0
        }
    }
    
    /// Check SLA compliance
    pub fn check_compliance(&self, tier: &SlaTier) -> SlaStatus {
        let mut violations = Vec::new();
        
        // Check uptime
        let uptime = self.uptime.uptime_percentage();
        if uptime < tier.uptime_target {
            violations.push(SlaViolation {
                violation_type: ViolationType::Uptime,
                target: tier.uptime_target,
                actual: uptime,
                detected_at: Utc::now(),
                message: format!("Uptime {:.2}% below target {:.2}%", uptime, tier.uptime_target),
            });
        }
        
        // Check latency
        let p99 = self.latency.p99();
        if p99 > tier.latency_p99_target_ms as f64 {
            violations.push(SlaViolation {
                violation_type: ViolationType::Latency,
                target: tier.latency_p99_target_ms as f64,
                actual: p99,
                detected_at: Utc::now(),
                message: format!("P99 latency {:.0}ms exceeds target {}ms", p99, tier.latency_p99_target_ms),
            });
        }
        
        // Check error rate
        let error_rate = self.error_rate();
        if error_rate > tier.max_error_rate {
            violations.push(SlaViolation {
                violation_type: ViolationType::ErrorRate,
                target: tier.max_error_rate,
                actual: error_rate,
                detected_at: Utc::now(),
                message: format!("Error rate {:.2}% exceeds target {:.2}%", error_rate, tier.max_error_rate),
            });
        }
        
        SlaStatus {
            compliant: violations.is_empty(),
            uptime_percentage: uptime,
            latency_p99_ms: p99,
            error_rate_percentage: error_rate,
            violations,
        }
    }
}

/// SLA violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaViolation {
    pub violation_type: ViolationType,
    pub target: f64,
    pub actual: f64,
    pub detected_at: DateTime<Utc>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    Uptime,
    Latency,
    ErrorRate,
}

/// SLA compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaStatus {
    pub compliant: bool,
    pub uptime_percentage: f64,
    pub latency_p99_ms: f64,
    pub error_rate_percentage: f64,
    pub violations: Vec<SlaViolation>,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Alert ID
    pub id: String,
    
    /// Webhook URL
    pub webhook_url: String,
    
    /// Alert on uptime violations
    #[serde(default = "default_true")]
    pub on_uptime: bool,
    
    /// Alert on latency violations
    #[serde(default = "default_true")]
    pub on_latency: bool,
    
    /// Alert on error rate violations
    #[serde(default = "default_true")]
    pub on_error_rate: bool,
    
    /// Alert on recovery
    #[serde(default = "default_true")]
    pub on_recovery: bool,
    
    /// Minimum time between alerts (seconds)
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    
    /// Enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }
fn default_cooldown() -> u64 { 300 }

/// SLA alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaAlert {
    pub id: String,
    pub tunnel_id: String,
    pub alert_type: AlertType,
    pub message: String,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    UptimeViolation,
    LatencyViolation,
    ErrorRateViolation,
    Recovery,
}

/// SLA Monitor
pub struct SlaMonitor {
    /// SLA tiers
    tiers: HashMap<String, SlaTier>,
    
    /// Tunnel metrics
    metrics: DashMap<String, TunnelSlaMetrics>,
    
    /// Alert configurations per tunnel
    alerts: DashMap<String, Vec<AlertConfig>>,
    
    /// Last alert times (for cooldown)
    last_alerts: DashMap<(String, AlertType), Instant>,
    
    /// HTTP client for alerts
    client: reqwest::Client,
    
    /// Event channel
    event_tx: mpsc::Sender<SlaEvent>,
}

/// Internal SLA events
#[derive(Debug)]
enum SlaEvent {
    HealthCheck { tunnel_id: String, status: HealthStatus, reason: Option<String> },
    Request { tunnel_id: String, latency_ms: f64, error: bool },
    SendAlert { tunnel_id: String, alert: SlaAlert },
}

impl SlaMonitor {
    /// Create a new SLA monitor
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(10000);
        
        let mut tiers = HashMap::new();
        tiers.insert("free".to_string(), SlaTier::free());
        tiers.insert("pro".to_string(), SlaTier::pro());
        tiers.insert("team".to_string(), SlaTier::team());
        tiers.insert("business".to_string(), SlaTier::business());
        tiers.insert("enterprise".to_string(), SlaTier::enterprise());
        
        let monitor = Arc::new(Self {
            tiers,
            metrics: DashMap::new(),
            alerts: DashMap::new(),
            last_alerts: DashMap::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            event_tx: tx,
        });
        
        // Start event processor
        let mon = Arc::clone(&monitor);
        tokio::spawn(async move {
            mon.process_events(rx).await;
        });
        
        monitor
    }
    
    /// Register a tunnel for monitoring
    pub fn register_tunnel(&self, tunnel_id: &str, tier: &str) {
        self.metrics.insert(
            tunnel_id.to_string(),
            TunnelSlaMetrics::new(tunnel_id, tier),
        );
        debug!("Registered tunnel {} for SLA monitoring (tier: {})", tunnel_id, tier);
    }
    
    /// Unregister a tunnel
    pub fn unregister_tunnel(&self, tunnel_id: &str) {
        self.metrics.remove(tunnel_id);
        self.alerts.remove(tunnel_id);
    }
    
    /// Add alert configuration for tunnel
    pub fn add_alert_config(&self, tunnel_id: &str, config: AlertConfig) {
        self.alerts
            .entry(tunnel_id.to_string())
            .or_default()
            .push(config);
    }
    
    /// Record health check
    pub fn record_health_check(&self, tunnel_id: &str, status: HealthStatus, reason: Option<&str>) {
        let _ = self.event_tx.try_send(SlaEvent::HealthCheck {
            tunnel_id: tunnel_id.to_string(),
            status,
            reason: reason.map(|s| s.to_string()),
        });
    }
    
    /// Record request
    pub fn record_request(&self, tunnel_id: &str, latency_ms: f64, error: bool) {
        let _ = self.event_tx.try_send(SlaEvent::Request {
            tunnel_id: tunnel_id.to_string(),
            latency_ms,
            error,
        });
    }
    
    /// Get metrics for tunnel
    pub fn get_metrics(&self, tunnel_id: &str) -> Option<TunnelSlaMetrics> {
        self.metrics.get(tunnel_id).map(|m| m.clone())
    }
    
    /// Get SLA status for tunnel
    pub fn get_status(&self, tunnel_id: &str) -> Result<SlaStatus> {
        let metrics = self.metrics.get(tunnel_id)
            .ok_or_else(|| SlaError::TunnelNotFound(tunnel_id.to_string()))?;
        
        let tier = self.tiers.get(&metrics.tier)
            .ok_or_else(|| SlaError::SlaNotConfigured(metrics.tier.clone()))?;
        
        Ok(metrics.check_compliance(tier))
    }
    
    /// Get all tunnel statuses
    pub fn get_all_statuses(&self) -> HashMap<String, SlaStatus> {
        self.metrics.iter()
            .filter_map(|entry| {
                let tier = self.tiers.get(&entry.tier)?;
                Some((entry.tunnel_id.clone(), entry.check_compliance(tier)))
            })
            .collect()
    }
    
    /// Process events
    async fn process_events(self: Arc<Self>, mut rx: mpsc::Receiver<SlaEvent>) {
        while let Some(event) = rx.recv().await {
            match event {
                SlaEvent::HealthCheck { tunnel_id, status, reason } => {
                    self.handle_health_check(&tunnel_id, status, reason.as_deref()).await;
                }
                SlaEvent::Request { tunnel_id, latency_ms, error } => {
                    self.handle_request(&tunnel_id, latency_ms, error);
                }
                SlaEvent::SendAlert { tunnel_id, alert } => {
                    self.send_alert(&tunnel_id, &alert).await;
                }
            }
        }
    }
    
    /// Handle health check event
    async fn handle_health_check(&self, tunnel_id: &str, status: HealthStatus, reason: Option<&str>) {
        let previous_status;
        
        // Update metrics
        if let Some(mut metrics) = self.metrics.get_mut(tunnel_id) {
            previous_status = metrics.uptime.current_status;
            metrics.uptime.record_check(status, reason);
            
            // Check for violations
            if let Some(tier) = self.tiers.get(&metrics.tier) {
                let compliance = metrics.check_compliance(tier);
                metrics.violations = compliance.violations.clone();
                
                // Trigger alerts
                if tier.alert_on_violation {
                    for violation in &compliance.violations {
                        let alert_type = match violation.violation_type {
                            ViolationType::Uptime => AlertType::UptimeViolation,
                            ViolationType::Latency => AlertType::LatencyViolation,
                            ViolationType::ErrorRate => AlertType::ErrorRateViolation,
                        };
                        
                        self.maybe_send_alert(tunnel_id, alert_type, &violation.message).await;
                    }
                }
            }
        } else {
            return;
        }
        
        // Check for recovery
        if previous_status == HealthStatus::Unhealthy && status == HealthStatus::Healthy {
            self.maybe_send_alert(tunnel_id, AlertType::Recovery, "Service recovered").await;
        }
    }
    
    /// Handle request event
    fn handle_request(&self, tunnel_id: &str, latency_ms: f64, error: bool) {
        if let Some(mut metrics) = self.metrics.get_mut(tunnel_id) {
            metrics.request_count += 1;
            if error {
                metrics.error_count += 1;
            }
            metrics.latency.record(latency_ms);
        }
    }
    
    /// Maybe send alert (respecting cooldown)
    async fn maybe_send_alert(&self, tunnel_id: &str, alert_type: AlertType, message: &str) {
        let key = (tunnel_id.to_string(), alert_type);
        
        // Check cooldown
        if let Some(last) = self.last_alerts.get(&key) {
            if last.elapsed() < Duration::from_secs(300) {
                return;
            }
        }
        
        // Update last alert time
        self.last_alerts.insert(key, Instant::now());
        
        let alert = SlaAlert {
            id: uuid::Uuid::new_v4().to_string(),
            tunnel_id: tunnel_id.to_string(),
            alert_type,
            message: message.to_string(),
            details: serde_json::json!({}),
            created_at: Utc::now(),
        };
        
        // Send alert in background
        let _ = self.event_tx.try_send(SlaEvent::SendAlert {
            tunnel_id: tunnel_id.to_string(),
            alert,
        });
    }
    
    /// Send alert to webhooks
    async fn send_alert(&self, tunnel_id: &str, alert: &SlaAlert) {
        if let Some(configs) = self.alerts.get(tunnel_id) {
            for config in configs.iter() {
                if !config.enabled {
                    continue;
                }
                
                // Check if this alert type is enabled
                let should_send = match alert.alert_type {
                    AlertType::UptimeViolation => config.on_uptime,
                    AlertType::LatencyViolation => config.on_latency,
                    AlertType::ErrorRateViolation => config.on_error_rate,
                    AlertType::Recovery => config.on_recovery,
                };
                
                if !should_send {
                    continue;
                }
                
                // Send webhook
                match self.client.post(&config.webhook_url)
                    .json(alert)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("Sent SLA alert to {}", config.webhook_url);
                    }
                    Ok(resp) => {
                        warn!("Alert webhook returned {}: {}", resp.status(), config.webhook_url);
                    }
                    Err(e) => {
                        warn!("Failed to send alert: {}", e);
                    }
                }
            }
        }
    }
    
    /// Generate SLA report for a period
    pub fn generate_report(&self, tunnel_id: &str) -> Result<SlaReport> {
        let metrics = self.metrics.get(tunnel_id)
            .ok_or_else(|| SlaError::TunnelNotFound(tunnel_id.to_string()))?;
        
        let tier = self.tiers.get(&metrics.tier)
            .ok_or_else(|| SlaError::SlaNotConfigured(metrics.tier.clone()))?;
        
        let status = metrics.check_compliance(tier);
        
        Ok(SlaReport {
            tunnel_id: tunnel_id.to_string(),
            tier: metrics.tier.clone(),
            period_start: metrics.period_start,
            period_end: Utc::now(),
            uptime: UptimeReport {
                target_percentage: tier.uptime_target,
                actual_percentage: status.uptime_percentage,
                total_seconds: metrics.uptime.total_seconds,
                up_seconds: metrics.uptime.up_seconds,
                outage_count: metrics.uptime.outage_count,
            },
            latency: LatencyReport {
                p50_ms: metrics.latency.p50(),
                p95_ms: metrics.latency.p95(),
                p99_ms: metrics.latency.p99(),
                p99_target_ms: tier.latency_p99_target_ms as f64,
                average_ms: metrics.latency.average(),
                min_ms: if metrics.latency.count > 0 { metrics.latency.min_ms } else { 0.0 },
                max_ms: metrics.latency.max_ms,
            },
            requests: RequestReport {
                total: metrics.request_count,
                errors: metrics.error_count,
                error_rate: status.error_rate_percentage,
                error_rate_target: tier.max_error_rate,
            },
            compliance: status.compliant,
            violations: status.violations,
        })
    }
}

/// SLA Report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaReport {
    pub tunnel_id: String,
    pub tier: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub uptime: UptimeReport,
    pub latency: LatencyReport,
    pub requests: RequestReport,
    pub compliance: bool,
    pub violations: Vec<SlaViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeReport {
    pub target_percentage: f64,
    pub actual_percentage: f64,
    pub total_seconds: u64,
    pub up_seconds: u64,
    pub outage_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyReport {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub p99_target_ms: f64,
    pub average_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestReport {
    pub total: u64,
    pub errors: u64,
    pub error_rate: f64,
    pub error_rate_target: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_latency_stats() {
        let mut stats = LatencyStats::new();
        
        // Add some samples
        for i in 1..=100 {
            stats.record(i as f64);
        }
        
        assert_eq!(stats.count, 100);
        assert_eq!(stats.min_ms, 1.0);
        assert_eq!(stats.max_ms, 100.0);
        assert!((stats.average() - 50.5).abs() < 0.1);
    }
    
    #[test]
    fn test_uptime_tracker() {
        let mut tracker = UptimeTracker::new();
        
        // Simulate healthy checks
        tracker.record_check(HealthStatus::Healthy, None);
        tracker.record_check(HealthStatus::Healthy, None);
        
        assert_eq!(tracker.current_status, HealthStatus::Healthy);
        assert_eq!(tracker.outage_count, 0);
        
        // Simulate outage
        tracker.record_check(HealthStatus::Unhealthy, Some("Connection refused"));
        
        assert_eq!(tracker.current_status, HealthStatus::Unhealthy);
        assert_eq!(tracker.outage_count, 1);
        assert_eq!(tracker.outages.len(), 1);
        
        // Recovery
        tracker.record_check(HealthStatus::Healthy, None);
        
        assert_eq!(tracker.current_status, HealthStatus::Healthy);
        assert!(tracker.outages.last().unwrap().ended_at.is_some());
    }
    
    #[test]
    fn test_sla_compliance_passing() {
        let metrics = TunnelSlaMetrics::new("test-tunnel", "pro");
        let tier = SlaTier::pro();
        
        let status = metrics.check_compliance(&tier);
        
        // Fresh metrics should be compliant (100% uptime, 0 errors)
        assert!(status.compliant);
        assert!(status.violations.is_empty());
    }
    
    #[test]
    fn test_sla_compliance_failing_uptime() {
        let mut metrics = TunnelSlaMetrics::new("test-tunnel", "pro");
        
        // Simulate 50% uptime
        metrics.uptime.total_seconds = 1000;
        metrics.uptime.up_seconds = 500;
        
        let tier = SlaTier::pro();
        let status = metrics.check_compliance(&tier);
        
        assert!(!status.compliant);
        assert!(status.violations.iter().any(|v| v.violation_type == ViolationType::Uptime));
    }
    
    #[test]
    fn test_sla_compliance_failing_error_rate() {
        let mut metrics = TunnelSlaMetrics::new("test-tunnel", "pro");
        
        // Simulate 5% error rate (pro allows 1%)
        metrics.request_count = 100;
        metrics.error_count = 5;
        
        let tier = SlaTier::pro();
        let status = metrics.check_compliance(&tier);
        
        assert!(!status.compliant);
        assert!(status.violations.iter().any(|v| v.violation_type == ViolationType::ErrorRate));
    }
    
    #[test]
    fn test_sla_tiers() {
        let free = SlaTier::free();
        let enterprise = SlaTier::enterprise();
        
        assert!(free.uptime_target < enterprise.uptime_target);
        assert!(free.max_downtime_minutes > enterprise.max_downtime_minutes);
        assert!(free.latency_p99_target_ms > enterprise.latency_p99_target_ms);
    }
    
    #[test]
    fn test_error_rate_calculation() {
        let mut metrics = TunnelSlaMetrics::new("test", "pro");
        
        metrics.request_count = 0;
        assert_eq!(metrics.error_rate(), 0.0);
        
        metrics.request_count = 1000;
        metrics.error_count = 10;
        assert!((metrics.error_rate() - 1.0).abs() < 0.001);
    }
    
    #[test]
    fn test_uptime_percentage() {
        let mut tracker = UptimeTracker::new();
        
        // 0 total = 100%
        assert_eq!(tracker.uptime_percentage(), 100.0);
        
        tracker.total_seconds = 1000;
        tracker.up_seconds = 999;
        
        assert!((tracker.uptime_percentage() - 99.9).abs() < 0.01);
    }
}
