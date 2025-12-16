//! Billing Integration
//!
//! This module provides usage metering, subscription management,
//! and billing webhook integration.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Billing errors
#[derive(Debug, Error)]
pub enum BillingError {
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Subscription not found")]
    SubscriptionNotFound,
    
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    
    #[error("Payment required")]
    PaymentRequired,
    
    #[error("Webhook error: {0}")]
    WebhookError(String),
    
    #[error("API error: {0}")]
    ApiError(String),
}

pub type Result<T> = std::result::Result<T, BillingError>;

/// Subscription tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionTier {
    /// Free tier with limited features
    Free,
    /// Pro tier for individual developers
    Pro,
    /// Team tier for small teams
    Team,
    /// Business tier for companies
    Business,
    /// Enterprise tier with custom limits
    Enterprise,
}

impl Default for SubscriptionTier {
    fn default() -> Self {
        Self::Free
    }
}

impl SubscriptionTier {
    /// Get tier limits
    pub fn limits(&self) -> TierLimits {
        match self {
            Self::Free => TierLimits {
                max_tunnels: 1,
                max_connections_per_tunnel: 10,
                max_bandwidth_gb_per_month: 1,
                max_requests_per_minute: 100,
                custom_domains: false,
                tcp_tunnels: false,
                team_members: 0,
                sla_uptime: 0.0,
                priority_support: false,
            },
            Self::Pro => TierLimits {
                max_tunnels: 5,
                max_connections_per_tunnel: 100,
                max_bandwidth_gb_per_month: 50,
                max_requests_per_minute: 1000,
                custom_domains: true,
                tcp_tunnels: true,
                team_members: 0,
                sla_uptime: 99.0,
                priority_support: false,
            },
            Self::Team => TierLimits {
                max_tunnels: 20,
                max_connections_per_tunnel: 500,
                max_bandwidth_gb_per_month: 200,
                max_requests_per_minute: 5000,
                custom_domains: true,
                tcp_tunnels: true,
                team_members: 5,
                sla_uptime: 99.5,
                priority_support: false,
            },
            Self::Business => TierLimits {
                max_tunnels: 100,
                max_connections_per_tunnel: 2000,
                max_bandwidth_gb_per_month: 1000,
                max_requests_per_minute: 20000,
                custom_domains: true,
                tcp_tunnels: true,
                team_members: 25,
                sla_uptime: 99.9,
                priority_support: true,
            },
            Self::Enterprise => TierLimits {
                max_tunnels: u32::MAX,
                max_connections_per_tunnel: u32::MAX,
                max_bandwidth_gb_per_month: u64::MAX,
                max_requests_per_minute: u32::MAX,
                custom_domains: true,
                tcp_tunnels: true,
                team_members: u32::MAX,
                sla_uptime: 99.99,
                priority_support: true,
            },
        }
    }
    
    /// Get monthly price in cents
    pub fn monthly_price_cents(&self) -> u64 {
        match self {
            Self::Free => 0,
            Self::Pro => 2000,      // $20/month
            Self::Team => 7500,     // $75/month
            Self::Business => 25000, // $250/month
            Self::Enterprise => 0,   // Custom pricing
        }
    }
}

/// Tier limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierLimits {
    pub max_tunnels: u32,
    pub max_connections_per_tunnel: u32,
    pub max_bandwidth_gb_per_month: u64,
    pub max_requests_per_minute: u32,
    pub custom_domains: bool,
    pub tcp_tunnels: bool,
    pub team_members: u32,
    pub sla_uptime: f64,
    pub priority_support: bool,
}

/// User subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Subscription ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Organization ID (if applicable)
    pub organization_id: Option<String>,
    /// Subscription tier
    pub tier: SubscriptionTier,
    /// Subscription status
    pub status: SubscriptionStatus,
    /// Current billing period start
    pub period_start: DateTime<Utc>,
    /// Current billing period end
    pub period_end: DateTime<Utc>,
    /// External subscription ID (e.g., Stripe)
    pub external_id: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Cancelled at
    pub cancelled_at: Option<DateTime<Utc>>,
    /// Custom limits override
    pub custom_limits: Option<TierLimits>,
}

impl Subscription {
    /// Get effective limits (custom or tier-based)
    pub fn limits(&self) -> TierLimits {
        self.custom_limits.clone().unwrap_or_else(|| self.tier.limits())
    }
    
    /// Check if subscription is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, SubscriptionStatus::Active | SubscriptionStatus::Trialing)
            && Utc::now() < self.period_end
    }
}

/// Subscription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Active subscription
    Active,
    /// Trial period
    Trialing,
    /// Past due (payment failed)
    PastDue,
    /// Cancelled
    Cancelled,
    /// Expired
    Expired,
    /// Paused
    Paused,
}

/// Usage metrics for a user/organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetrics {
    /// User ID
    pub user_id: String,
    /// Billing period start
    pub period_start: DateTime<Utc>,
    /// Billing period end
    pub period_end: DateTime<Utc>,
    /// Total requests
    pub total_requests: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Active tunnels
    pub active_tunnels: u32,
    /// Peak concurrent connections
    pub peak_connections: u32,
    /// Custom domain count
    pub custom_domains: u32,
    /// Usage by tunnel
    pub tunnel_usage: HashMap<String, TunnelUsage>,
}

/// Usage for a single tunnel
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelUsage {
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub peak_connections: u32,
    pub error_count: u64,
}

/// Real-time usage counter
pub struct UsageCounter {
    user_id: String,
    period_start: DateTime<Utc>,
    requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    connections: AtomicU64,
    peak_connections: AtomicU64,
}

impl UsageCounter {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            period_start: Utc::now(),
            requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            peak_connections: AtomicU64::new(0),
        }
    }
    
    pub fn record_request(&self, bytes_in: u64, bytes_out: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }
    
    pub fn add_connection(&self) {
        let current = self.connections.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peak = self.peak_connections.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_connections.compare_exchange_weak(
                peak, current, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }
    
    pub fn remove_connection(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }
    
    pub fn snapshot(&self) -> UsageSnapshot {
        UsageSnapshot {
            user_id: self.user_id.clone(),
            period_start: self.period_start,
            requests: self.requests.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            peak_connections: self.peak_connections.load(Ordering::Relaxed),
        }
    }
}

/// Usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub user_id: String,
    pub period_start: DateTime<Utc>,
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
    pub peak_connections: u64,
}

/// Billing manager
pub struct BillingManager {
    /// Subscriptions by user ID
    subscriptions: DashMap<String, Subscription>,
    /// Usage counters by user ID
    usage: DashMap<String, Arc<UsageCounter>>,
    /// Webhook secret for verifying incoming webhooks
    webhook_secret: Option<String>,
}

impl BillingManager {
    /// Create a new billing manager
    pub fn new(webhook_secret: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            subscriptions: DashMap::new(),
            usage: DashMap::new(),
            webhook_secret,
        })
    }
    
    /// Get or create a subscription (defaults to free tier)
    pub fn get_or_create_subscription(&self, user_id: &str) -> Subscription {
        if let Some(sub) = self.subscriptions.get(user_id) {
            return sub.clone();
        }
        
        // Create free tier subscription
        let subscription = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            organization_id: None,
            tier: SubscriptionTier::Free,
            status: SubscriptionStatus::Active,
            period_start: Utc::now(),
            period_end: Utc::now() + chrono::Duration::days(30),
            external_id: None,
            created_at: Utc::now(),
            cancelled_at: None,
            custom_limits: None,
        };
        
        self.subscriptions.insert(user_id.to_string(), subscription.clone());
        subscription
    }
    
    /// Update subscription tier
    pub fn update_subscription(&self, user_id: &str, tier: SubscriptionTier) -> Result<Subscription> {
        let mut sub = self.subscriptions
            .get_mut(user_id)
            .ok_or_else(|| BillingError::UserNotFound(user_id.to_string()))?;
        
        sub.tier = tier;
        sub.status = SubscriptionStatus::Active;
        
        info!("Updated subscription for {} to {:?}", user_id, tier);
        
        Ok(sub.clone())
    }
    
    /// Check if user has quota for an operation
    pub fn check_quota(&self, user_id: &str, check: QuotaCheck) -> Result<()> {
        let subscription = self.get_or_create_subscription(user_id);
        
        if !subscription.is_active() {
            return Err(BillingError::PaymentRequired);
        }
        
        let limits = subscription.limits();
        
        match check {
            QuotaCheck::Tunnel { current_count } => {
                if current_count >= limits.max_tunnels {
                    return Err(BillingError::QuotaExceeded(format!(
                        "Maximum {} tunnels for {:?} tier",
                        limits.max_tunnels, subscription.tier
                    )));
                }
            }
            QuotaCheck::Connection { current_count } => {
                if current_count >= limits.max_connections_per_tunnel {
                    return Err(BillingError::QuotaExceeded(format!(
                        "Maximum {} connections per tunnel for {:?} tier",
                        limits.max_connections_per_tunnel, subscription.tier
                    )));
                }
            }
            QuotaCheck::CustomDomain => {
                if !limits.custom_domains {
                    return Err(BillingError::QuotaExceeded(
                        "Custom domains not available on your plan".to_string()
                    ));
                }
            }
            QuotaCheck::TcpTunnel => {
                if !limits.tcp_tunnels {
                    return Err(BillingError::QuotaExceeded(
                        "TCP tunnels not available on your plan".to_string()
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Get usage counter for a user
    pub fn get_usage_counter(&self, user_id: &str) -> Arc<UsageCounter> {
        self.usage
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(UsageCounter::new(user_id)))
            .clone()
    }
    
    /// Get usage snapshot for a user
    pub fn get_usage(&self, user_id: &str) -> Option<UsageSnapshot> {
        self.usage.get(user_id).map(|c| c.snapshot())
    }
    
    /// Handle webhook from payment provider
    pub fn handle_webhook(&self, event_type: &str, payload: &serde_json::Value) -> Result<()> {
        debug!("Received billing webhook: {}", event_type);
        
        match event_type {
            "subscription.created" | "subscription.updated" => {
                // Update subscription from webhook
                if let Some(user_id) = payload.get("user_id").and_then(|v| v.as_str()) {
                    let tier = payload.get("tier")
                        .and_then(|v| v.as_str())
                        .and_then(|s| match s {
                            "pro" => Some(SubscriptionTier::Pro),
                            "team" => Some(SubscriptionTier::Team),
                            "business" => Some(SubscriptionTier::Business),
                            "enterprise" => Some(SubscriptionTier::Enterprise),
                            _ => None,
                        })
                        .unwrap_or(SubscriptionTier::Free);
                    
                    self.update_subscription(user_id, tier)?;
                }
            }
            "subscription.cancelled" => {
                if let Some(user_id) = payload.get("user_id").and_then(|v| v.as_str()) {
                    if let Some(mut sub) = self.subscriptions.get_mut(user_id) {
                        sub.status = SubscriptionStatus::Cancelled;
                        sub.cancelled_at = Some(Utc::now());
                    }
                }
            }
            "payment.failed" => {
                if let Some(user_id) = payload.get("user_id").and_then(|v| v.as_str()) {
                    if let Some(mut sub) = self.subscriptions.get_mut(user_id) {
                        sub.status = SubscriptionStatus::PastDue;
                        warn!("Payment failed for user {}", user_id);
                    }
                }
            }
            _ => {
                debug!("Unhandled webhook event: {}", event_type);
            }
        }
        
        Ok(())
    }
    
    /// Get billing stats
    pub fn stats(&self) -> BillingStats {
        let mut stats = BillingStats::default();
        
        for sub in self.subscriptions.iter() {
            stats.total_subscriptions += 1;
            
            match sub.tier {
                SubscriptionTier::Free => stats.free_tier += 1,
                SubscriptionTier::Pro => stats.pro_tier += 1,
                SubscriptionTier::Team => stats.team_tier += 1,
                SubscriptionTier::Business => stats.business_tier += 1,
                SubscriptionTier::Enterprise => stats.enterprise_tier += 1,
            }
            
            if sub.is_active() {
                stats.active_subscriptions += 1;
            }
        }
        
        stats
    }
}

impl Default for BillingManager {
    fn default() -> Self {
        Self {
            subscriptions: DashMap::new(),
            usage: DashMap::new(),
            webhook_secret: None,
        }
    }
}

/// Quota check types
#[derive(Debug, Clone)]
pub enum QuotaCheck {
    Tunnel { current_count: u32 },
    Connection { current_count: u32 },
    CustomDomain,
    TcpTunnel,
}

/// Billing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BillingStats {
    pub total_subscriptions: u64,
    pub active_subscriptions: u64,
    pub free_tier: u64,
    pub pro_tier: u64,
    pub team_tier: u64,
    pub business_tier: u64,
    pub enterprise_tier: u64,
}

/// Billing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingConfig {
    /// Enable billing
    #[serde(default)]
    pub enabled: bool,
    
    /// Webhook secret for verifying incoming webhooks
    pub webhook_secret: Option<String>,
    
    /// Payment provider (stripe, paddle, etc.)
    #[serde(default = "default_provider")]
    pub provider: String,
    
    /// API key for payment provider
    pub api_key: Option<String>,
    
    /// Usage reporting interval in seconds
    #[serde(default = "default_report_interval")]
    pub report_interval_secs: u64,
}

fn default_provider() -> String {
    "stripe".to_string()
}

fn default_report_interval() -> u64 {
    3600 // 1 hour
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_secret: None,
            provider: default_provider(),
            api_key: None,
            report_interval_secs: default_report_interval(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tier_limits() {
        let free = SubscriptionTier::Free.limits();
        let pro = SubscriptionTier::Pro.limits();
        
        assert_eq!(free.max_tunnels, 1);
        assert!(!free.custom_domains);
        
        assert_eq!(pro.max_tunnels, 5);
        assert!(pro.custom_domains);
    }
    
    #[test]
    fn test_usage_counter() {
        let counter = UsageCounter::new("user-1");
        
        counter.record_request(100, 200);
        counter.record_request(50, 100);
        
        let snapshot = counter.snapshot();
        assert_eq!(snapshot.requests, 2);
        assert_eq!(snapshot.bytes_in, 150);
        assert_eq!(snapshot.bytes_out, 300);
    }
    
    #[test]
    fn test_quota_check() {
        let manager = BillingManager::new(None);
        
        // Free tier should have limited tunnels
        let result = manager.check_quota("user-1", QuotaCheck::Tunnel { current_count: 0 });
        assert!(result.is_ok());
        
        let result = manager.check_quota("user-1", QuotaCheck::Tunnel { current_count: 1 });
        assert!(result.is_err());
    }
    
    #[test]
    fn test_subscription_update() {
        let manager = BillingManager::new(None);
        
        // Create initial subscription
        let sub = manager.get_or_create_subscription("user-1");
        assert_eq!(sub.tier, SubscriptionTier::Free);
        
        // Upgrade to pro
        let sub = manager.update_subscription("user-1", SubscriptionTier::Pro).unwrap();
        assert_eq!(sub.tier, SubscriptionTier::Pro);
        
        // Pro tier should allow custom domains
        let result = manager.check_quota("user-1", QuotaCheck::CustomDomain);
        assert!(result.is_ok());
    }
}
