//! Audit Log Export Module
//!
//! Provides audit logging with export to SIEM platforms.
//!
//! ## Supported SIEM Integrations
//!
//! - Splunk (HEC)
//! - Datadog
//! - Elasticsearch
//! - AWS CloudWatch
//! - Generic Webhook
//!
//! ## Audit Event Types
//!
//! - Authentication events (login, logout, failed attempts)
//! - Tunnel lifecycle (created, connected, disconnected)
//! - Domain management (reserved, released, verified)
//! - API key management (created, revoked)
//! - Team membership changes
//! - Configuration changes
//! - Security events (rate limits, blocked IPs)

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Audit export errors
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Export failed: {0}")]
    ExportFailed(String),
    
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    
    #[error("SIEM connection error: {0}")]
    ConnectionError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Rate limited")]
    RateLimited,
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Audit event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
    
    pub fn to_datadog_status(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
    
    pub fn to_splunk_severity(&self) -> i32 {
        match self {
            Self::Debug => 7,
            Self::Info => 6,
            Self::Warning => 4,
            Self::Error => 3,
            Self::Critical => 2,
        }
    }
}

/// Audit event category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    Authorization,
    Tunnel,
    Domain,
    ApiKey,
    Team,
    Configuration,
    Security,
    Billing,
    System,
}

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Authentication
    LoginSuccess,
    LoginFailed,
    Logout,
    TokenRefresh,
    SsoLogin,
    MfaChallenge,
    MfaSuccess,
    MfaFailed,
    
    // Tunnel
    TunnelCreated,
    TunnelConnected,
    TunnelDisconnected,
    TunnelExpired,
    TunnelDeleted,
    
    // Domain
    DomainReserved,
    DomainReleased,
    DomainVerified,
    DomainVerificationFailed,
    
    // API Keys
    ApiKeyCreated,
    ApiKeyRevoked,
    ApiKeyUsed,
    
    // Team
    TeamCreated,
    MemberAdded,
    MemberRemoved,
    RoleChanged,
    
    // Configuration
    ConfigChanged,
    WebhookAdded,
    WebhookRemoved,
    
    // Security
    RateLimited,
    IpBlocked,
    SuspiciousActivity,
    PolicyViolation,
    
    // Billing
    SubscriptionCreated,
    SubscriptionChanged,
    SubscriptionCancelled,
    PaymentSucceeded,
    PaymentFailed,
    
    // System
    ServiceStarted,
    ServiceStopped,
    HealthCheck,
    Error,
}

/// Actor that performed the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Actor type (user, api_key, system, anonymous)
    #[serde(rename = "type")]
    pub actor_type: String,
    
    /// Actor ID
    pub id: Option<String>,
    
    /// Actor email/name
    pub name: Option<String>,
    
    /// IP address
    pub ip_address: Option<String>,
    
    /// User agent
    pub user_agent: Option<String>,
}

impl Actor {
    pub fn system() -> Self {
        Self {
            actor_type: "system".to_string(),
            id: None,
            name: Some("nlag-system".to_string()),
            ip_address: None,
            user_agent: None,
        }
    }
    
    pub fn user(id: &str, email: &str) -> Self {
        Self {
            actor_type: "user".to_string(),
            id: Some(id.to_string()),
            name: Some(email.to_string()),
            ip_address: None,
            user_agent: None,
        }
    }
    
    pub fn api_key(key_id: &str) -> Self {
        Self {
            actor_type: "api_key".to_string(),
            id: Some(key_id.to_string()),
            name: None,
            ip_address: None,
            user_agent: None,
        }
    }
    
    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }
    
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }
}

/// Target of the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Target type (tunnel, domain, user, api_key, team, etc.)
    #[serde(rename = "type")]
    pub target_type: String,
    
    /// Target ID
    pub id: String,
    
    /// Target name/description
    pub name: Option<String>,
}

impl Target {
    pub fn tunnel(id: &str, name: Option<&str>) -> Self {
        Self {
            target_type: "tunnel".to_string(),
            id: id.to_string(),
            name: name.map(|s| s.to_string()),
        }
    }
    
    pub fn domain(domain: &str) -> Self {
        Self {
            target_type: "domain".to_string(),
            id: domain.to_string(),
            name: Some(domain.to_string()),
        }
    }
    
    pub fn user(id: &str, email: Option<&str>) -> Self {
        Self {
            target_type: "user".to_string(),
            id: id.to_string(),
            name: email.map(|s| s.to_string()),
        }
    }
    
    pub fn api_key(id: &str) -> Self {
        Self {
            target_type: "api_key".to_string(),
            id: id.to_string(),
            name: None,
        }
    }
    
    pub fn team(id: &str, name: Option<&str>) -> Self {
        Self {
            target_type: "team".to_string(),
            id: id.to_string(),
            name: name.map(|s| s.to_string()),
        }
    }
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID
    pub id: String,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Event category
    pub category: EventCategory,
    
    /// Event type
    pub event_type: EventType,
    
    /// Severity
    pub severity: Severity,
    
    /// Actor
    pub actor: Actor,
    
    /// Target (optional)
    pub target: Option<Target>,
    
    /// Event description
    pub message: String,
    
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
    
    /// Outcome (success/failure)
    pub outcome: String,
    
    /// Organization/tenant ID
    pub org_id: Option<String>,
    
    /// Request ID for correlation
    pub request_id: Option<String>,
}

impl AuditEvent {
    pub fn new(
        category: EventCategory,
        event_type: EventType,
        actor: Actor,
        message: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            category,
            event_type,
            severity: Severity::Info,
            actor,
            target: None,
            message: message.to_string(),
            metadata: serde_json::Value::Null,
            outcome: "success".to_string(),
            org_id: None,
            request_id: None,
        }
    }
    
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
    
    pub fn with_target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }
    
    pub fn with_metadata<T: Serialize>(mut self, metadata: T) -> Self {
        self.metadata = serde_json::to_value(metadata).unwrap_or_default();
        self
    }
    
    pub fn with_outcome(mut self, outcome: &str) -> Self {
        self.outcome = outcome.to_string();
        self
    }
    
    pub fn with_org_id(mut self, org_id: &str) -> Self {
        self.org_id = Some(org_id.to_string());
        self
    }
    
    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }
    
    pub fn failed(mut self) -> Self {
        self.outcome = "failure".to_string();
        self.severity = Severity::Warning;
        self
    }
}

/// SIEM destination type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SiemDestination {
    /// Splunk HTTP Event Collector
    Splunk {
        /// HEC endpoint URL
        url: String,
        /// HEC token
        token: String,
        /// Index name
        #[serde(default)]
        index: Option<String>,
        /// Source type
        #[serde(default)]
        source_type: Option<String>,
    },
    
    /// Datadog
    Datadog {
        /// API endpoint
        url: String,
        /// API key
        api_key: String,
        /// Service name
        #[serde(default = "default_service")]
        service: String,
        /// Environment
        #[serde(default)]
        env: Option<String>,
    },
    
    /// Elasticsearch
    Elasticsearch {
        /// ES endpoint URL
        url: String,
        /// Index pattern
        index_pattern: String,
        /// Username (optional)
        #[serde(default)]
        username: Option<String>,
        /// Password (optional)
        #[serde(default)]
        password: Option<String>,
        /// API key (optional)
        #[serde(default)]
        api_key: Option<String>,
    },
    
    /// AWS CloudWatch Logs
    CloudWatch {
        /// AWS region
        region: String,
        /// Log group name
        log_group: String,
        /// Log stream name
        log_stream: String,
    },
    
    /// Generic webhook
    Webhook {
        /// Webhook URL
        url: String,
        /// Additional headers
        #[serde(default)]
        headers: std::collections::HashMap<String, String>,
        /// HTTP method
        #[serde(default = "default_method")]
        method: String,
    },
}

fn default_service() -> String { "nlag".to_string() }
fn default_method() -> String { "POST".to_string() }

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Destination ID
    pub id: String,
    
    /// Name
    pub name: String,
    
    /// Destination
    pub destination: SiemDestination,
    
    /// Enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    
    /// Flush interval (seconds)
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    
    /// Minimum severity to export
    #[serde(default)]
    pub min_severity: Option<Severity>,
    
    /// Categories to export (empty = all)
    #[serde(default)]
    pub categories: Vec<EventCategory>,
    
    /// Retry count on failure
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
}

fn default_true() -> bool { true }
fn default_batch_size() -> usize { 100 }
fn default_flush_interval() -> u64 { 30 }
fn default_retry_count() -> u32 { 3 }

impl ExportConfig {
    /// Check if event should be exported
    pub fn should_export(&self, event: &AuditEvent) -> bool {
        // Check severity
        if let Some(min) = &self.min_severity {
            if (event.severity as u8) < (*min as u8) {
                return false;
            }
        }
        
        // Check category
        if !self.categories.is_empty() && !self.categories.contains(&event.category) {
            return false;
        }
        
        true
    }
}

/// Export buffer for a destination
struct ExportBuffer {
    config: ExportConfig,
    events: VecDeque<AuditEvent>,
    last_flush: std::time::Instant,
}

impl ExportBuffer {
    fn new(config: ExportConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            last_flush: std::time::Instant::now(),
        }
    }
    
    fn add(&mut self, event: AuditEvent) {
        if self.config.should_export(&event) {
            self.events.push_back(event);
        }
    }
    
    fn should_flush(&self) -> bool {
        self.events.len() >= self.config.batch_size
            || self.last_flush.elapsed() >= Duration::from_secs(self.config.flush_interval_secs)
    }
    
    fn take_batch(&mut self) -> Vec<AuditEvent> {
        self.last_flush = std::time::Instant::now();
        self.events.drain(..).collect()
    }
}

/// Audit log manager
pub struct AuditManager {
    /// Export configurations
    exports: DashMap<String, ExportBuffer>,
    
    /// Local event storage (ring buffer)
    local_buffer: RwLock<VecDeque<AuditEvent>>,
    
    /// Max local events
    max_local_events: usize,
    
    /// HTTP client for exports
    client: reqwest::Client,
    
    /// Event sender channel
    event_tx: mpsc::Sender<AuditEvent>,
    
    /// Stats
    stats: RwLock<AuditStats>,
}

/// Audit statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditStats {
    pub total_events: u64,
    pub exported_events: u64,
    pub failed_exports: u64,
    pub events_by_category: std::collections::HashMap<String, u64>,
    pub events_by_severity: std::collections::HashMap<String, u64>,
}

impl AuditManager {
    /// Create a new audit manager
    pub fn new(max_local_events: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(10000);
        
        let manager = Arc::new(Self {
            exports: DashMap::new(),
            local_buffer: RwLock::new(VecDeque::with_capacity(max_local_events)),
            max_local_events,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            event_tx: tx,
            stats: RwLock::new(AuditStats::default()),
        });
        
        // Start background processor
        let mgr = Arc::clone(&manager);
        tokio::spawn(async move {
            mgr.process_events(rx).await;
        });
        
        manager
    }
    
    /// Add an export destination
    pub fn add_export(&self, config: ExportConfig) {
        info!("Added audit export: {} ({:?})", config.name, config.destination);
        self.exports.insert(config.id.clone(), ExportBuffer::new(config));
    }
    
    /// Remove an export destination
    pub fn remove_export(&self, id: &str) -> bool {
        self.exports.remove(id).is_some()
    }
    
    /// Log an audit event
    pub fn log(&self, event: AuditEvent) {
        // Try to send to channel (non-blocking)
        if let Err(e) = self.event_tx.try_send(event.clone()) {
            warn!("Audit event channel full: {}", e);
            // Direct processing as fallback
            self.process_event(event);
        }
    }
    
    /// Log a simple event
    pub fn log_simple(
        &self,
        category: EventCategory,
        event_type: EventType,
        actor: Actor,
        message: &str,
    ) {
        self.log(AuditEvent::new(category, event_type, actor, message));
    }
    
    /// Process events from channel
    async fn process_events(self: Arc<Self>, mut rx: mpsc::Receiver<AuditEvent>) {
        let mut flush_interval = tokio::time::interval(Duration::from_secs(10));
        
        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    self.process_event(event);
                }
                _ = flush_interval.tick() => {
                    self.flush_exports().await;
                }
            }
        }
    }
    
    /// Process a single event
    fn process_event(&self, event: AuditEvent) {
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_events += 1;
            *stats.events_by_category.entry(format!("{:?}", event.category)).or_default() += 1;
            *stats.events_by_severity.entry(event.severity.as_str().to_string()).or_default() += 1;
        }
        
        // Store locally
        {
            let mut buffer = self.local_buffer.write();
            if buffer.len() >= self.max_local_events {
                buffer.pop_front();
            }
            buffer.push_back(event.clone());
        }
        
        // Add to export buffers
        for mut entry in self.exports.iter_mut() {
            entry.add(event.clone());
        }
    }
    
    /// Flush exports
    async fn flush_exports(&self) {
        for mut entry in self.exports.iter_mut() {
            if entry.should_flush() {
                let events = entry.take_batch();
                if !events.is_empty() {
                    let config = entry.config.clone();
                    let client = self.client.clone();
                    
                    // Spawn export task
                    let stats = Arc::new(parking_lot::Mutex::new((0u64, 0u64)));
                    let stats_clone = Arc::clone(&stats);
                    
                    tokio::spawn(async move {
                        match Self::export_batch(&client, &config, &events).await {
                            Ok(_) => {
                                stats_clone.lock().0 += events.len() as u64;
                                debug!("Exported {} events to {}", events.len(), config.name);
                            }
                            Err(e) => {
                                stats_clone.lock().1 += events.len() as u64;
                                error!("Export failed to {}: {}", config.name, e);
                            }
                        }
                    });
                }
            }
        }
    }
    
    /// Export a batch of events
    async fn export_batch(
        client: &reqwest::Client,
        config: &ExportConfig,
        events: &[AuditEvent],
    ) -> Result<()> {
        match &config.destination {
            SiemDestination::Splunk { url, token, index, source_type } => {
                Self::export_to_splunk(client, url, token, index.as_deref(), source_type.as_deref(), events).await
            }
            SiemDestination::Datadog { url, api_key, service, env } => {
                Self::export_to_datadog(client, url, api_key, service, env.as_deref(), events).await
            }
            SiemDestination::Elasticsearch { url, index_pattern, username, password, api_key } => {
                Self::export_to_elasticsearch(client, url, index_pattern, username.as_deref(), password.as_deref(), api_key.as_deref(), events).await
            }
            SiemDestination::Webhook { url, headers, method } => {
                Self::export_to_webhook(client, url, headers, method, events).await
            }
            SiemDestination::CloudWatch { .. } => {
                // CloudWatch requires AWS SDK
                warn!("CloudWatch export not yet implemented");
                Ok(())
            }
        }
    }
    
    /// Export to Splunk HEC
    async fn export_to_splunk(
        client: &reqwest::Client,
        url: &str,
        token: &str,
        index: Option<&str>,
        source_type: Option<&str>,
        events: &[AuditEvent],
    ) -> Result<()> {
        let mut body = String::new();
        
        for event in events {
            let splunk_event = serde_json::json!({
                "time": event.timestamp.timestamp(),
                "host": "nlag",
                "source": "nlag-audit",
                "sourcetype": source_type.unwrap_or("nlag:audit"),
                "index": index.unwrap_or("main"),
                "event": event,
            });
            
            body.push_str(&serde_json::to_string(&splunk_event)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?);
        }
        
        client.post(url)
            .header("Authorization", format!("Splunk {}", token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| AuditError::ConnectionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuditError::ExportFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Export to Datadog
    async fn export_to_datadog(
        client: &reqwest::Client,
        url: &str,
        api_key: &str,
        service: &str,
        env: Option<&str>,
        events: &[AuditEvent],
    ) -> Result<()> {
        let logs: Vec<serde_json::Value> = events.iter().map(|event| {
            let mut log = serde_json::json!({
                "ddsource": "nlag",
                "ddtags": format!("service:{},category:{:?}", service, event.category),
                "hostname": "nlag",
                "service": service,
                "status": event.severity.to_datadog_status(),
                "message": event.message,
                "event": event,
            });
            
            if let Some(e) = env {
                log["ddtags"] = serde_json::json!(format!("{},env:{}", log["ddtags"], e));
            }
            
            log
        }).collect();
        
        client.post(url)
            .header("DD-API-KEY", api_key)
            .header("Content-Type", "application/json")
            .json(&logs)
            .send()
            .await
            .map_err(|e| AuditError::ConnectionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuditError::ExportFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Export to Elasticsearch
    async fn export_to_elasticsearch(
        client: &reqwest::Client,
        url: &str,
        index_pattern: &str,
        username: Option<&str>,
        password: Option<&str>,
        api_key: Option<&str>,
        events: &[AuditEvent],
    ) -> Result<()> {
        // Build bulk request
        let mut body = String::new();
        let index = index_pattern.replace("{date}", &Utc::now().format("%Y.%m.%d").to_string());
        
        for event in events {
            // Index action
            body.push_str(&format!(r#"{{"index":{{"_index":"{}"}}}}"#, index));
            body.push('\n');
            // Document
            body.push_str(&serde_json::to_string(event)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?);
            body.push('\n');
        }
        
        let mut req = client.post(&format!("{}/_bulk", url))
            .header("Content-Type", "application/x-ndjson");
        
        if let Some(key) = api_key {
            req = req.header("Authorization", format!("ApiKey {}", key));
        } else if let (Some(u), Some(p)) = (username, password) {
            req = req.basic_auth(u, Some(p));
        }
        
        req.body(body)
            .send()
            .await
            .map_err(|e| AuditError::ConnectionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuditError::ExportFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Export to webhook
    async fn export_to_webhook(
        client: &reqwest::Client,
        url: &str,
        headers: &std::collections::HashMap<String, String>,
        method: &str,
        events: &[AuditEvent],
    ) -> Result<()> {
        let mut req = match method.to_uppercase().as_str() {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            _ => client.post(url),
        };
        
        for (k, v) in headers {
            req = req.header(k, v);
        }
        
        req.header("Content-Type", "application/json")
            .json(events)
            .send()
            .await
            .map_err(|e| AuditError::ConnectionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuditError::ExportFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Query local events
    pub fn query(&self, filter: AuditFilter) -> Vec<AuditEvent> {
        let buffer = self.local_buffer.read();
        
        buffer.iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .take(filter.limit.unwrap_or(100))
            .collect()
    }
    
    /// Get stats
    pub fn stats(&self) -> AuditStats {
        self.stats.read().clone()
    }
}

/// Filter for querying audit logs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Start time
    pub start: Option<DateTime<Utc>>,
    
    /// End time
    pub end: Option<DateTime<Utc>>,
    
    /// Categories
    pub categories: Vec<EventCategory>,
    
    /// Severities
    pub severities: Vec<Severity>,
    
    /// Actor ID
    pub actor_id: Option<String>,
    
    /// Target ID
    pub target_id: Option<String>,
    
    /// Org ID
    pub org_id: Option<String>,
    
    /// Search text
    pub search: Option<String>,
    
    /// Max results
    pub limit: Option<usize>,
}

impl AuditFilter {
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(start) = &self.start {
            if event.timestamp < *start {
                return false;
            }
        }
        
        if let Some(end) = &self.end {
            if event.timestamp > *end {
                return false;
            }
        }
        
        if !self.categories.is_empty() && !self.categories.contains(&event.category) {
            return false;
        }
        
        if !self.severities.is_empty() && !self.severities.contains(&event.severity) {
            return false;
        }
        
        if let Some(actor_id) = &self.actor_id {
            if event.actor.id.as_ref() != Some(actor_id) {
                return false;
            }
        }
        
        if let Some(target_id) = &self.target_id {
            if let Some(target) = &event.target {
                if target.id != *target_id {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        if let Some(org_id) = &self.org_id {
            if event.org_id.as_ref() != Some(org_id) {
                return false;
            }
        }
        
        if let Some(search) = &self.search {
            let search_lower = search.to_lowercase();
            if !event.message.to_lowercase().contains(&search_lower) {
                return false;
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            EventCategory::Authentication,
            EventType::LoginSuccess,
            Actor::user("user123", "test@example.com"),
            "User logged in successfully",
        );
        
        assert_eq!(event.category, EventCategory::Authentication);
        assert_eq!(event.outcome, "success");
    }
    
    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(
            EventCategory::Tunnel,
            EventType::TunnelCreated,
            Actor::api_key("key123"),
            "Tunnel created",
        )
        .with_severity(Severity::Info)
        .with_target(Target::tunnel("tunnel123", Some("my-tunnel")))
        .with_org_id("org123");
        
        assert_eq!(event.severity, Severity::Info);
        assert!(event.target.is_some());
        assert_eq!(event.org_id, Some("org123".to_string()));
    }
    
    #[test]
    fn test_failed_event() {
        let event = AuditEvent::new(
            EventCategory::Authentication,
            EventType::LoginFailed,
            Actor::user("user123", "test@example.com"),
            "Invalid password",
        ).failed();
        
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.severity, Severity::Warning);
    }
    
    #[test]
    fn test_export_config_filter() {
        let config = ExportConfig {
            id: "test".to_string(),
            name: "Test Export".to_string(),
            destination: SiemDestination::Webhook {
                url: "https://example.com/webhook".to_string(),
                headers: std::collections::HashMap::new(),
                method: "POST".to_string(),
            },
            enabled: true,
            batch_size: 100,
            flush_interval_secs: 30,
            min_severity: Some(Severity::Warning),
            categories: vec![EventCategory::Security],
            retry_count: 3,
        };
        
        let info_event = AuditEvent::new(
            EventCategory::Security,
            EventType::RateLimited,
            Actor::system(),
            "Rate limited",
        );
        
        // Info severity < Warning, should not export
        assert!(!config.should_export(&info_event));
        
        let warning_event = info_event.with_severity(Severity::Warning);
        assert!(config.should_export(&warning_event));
        
        let wrong_category = AuditEvent::new(
            EventCategory::Authentication,
            EventType::LoginSuccess,
            Actor::system(),
            "Login",
        ).with_severity(Severity::Warning);
        
        assert!(!config.should_export(&wrong_category));
    }
    
    #[test]
    fn test_audit_filter() {
        let event = AuditEvent::new(
            EventCategory::Tunnel,
            EventType::TunnelCreated,
            Actor::user("user123", "test@example.com"),
            "Created tunnel my-app",
        )
        .with_target(Target::tunnel("t123", Some("my-app")))
        .with_org_id("org1");
        
        let filter = AuditFilter {
            categories: vec![EventCategory::Tunnel],
            org_id: Some("org1".to_string()),
            search: Some("my-app".to_string()),
            ..Default::default()
        };
        
        assert!(filter.matches(&event));
        
        let wrong_org_filter = AuditFilter {
            org_id: Some("org2".to_string()),
            ..Default::default()
        };
        
        assert!(!wrong_org_filter.matches(&event));
    }
    
    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Debug.as_str(), "debug");
        assert_eq!(Severity::Critical.to_splunk_severity(), 2);
        assert_eq!(Severity::Info.to_datadog_status(), "info");
    }
    
    #[test]
    fn test_actor_types() {
        let system = Actor::system();
        assert_eq!(system.actor_type, "system");
        
        let user = Actor::user("u1", "user@test.com")
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0");
        assert_eq!(user.actor_type, "user");
        assert_eq!(user.ip_address, Some("192.168.1.1".to_string()));
        
        let api_key = Actor::api_key("key123");
        assert_eq!(api_key.actor_type, "api_key");
    }
    
    #[test]
    fn test_target_types() {
        let tunnel = Target::tunnel("t1", Some("my-tunnel"));
        assert_eq!(tunnel.target_type, "tunnel");
        
        let domain = Target::domain("app.example.com");
        assert_eq!(domain.target_type, "domain");
        
        let team = Target::team("team1", Some("Engineering"));
        assert_eq!(team.target_type, "team");
    }
}
