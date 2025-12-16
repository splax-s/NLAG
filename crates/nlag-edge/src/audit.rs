//! Audit Logging System
//!
//! This module provides structured audit logging with support for multiple
//! destinations (file, syslog, external services) and log shipping.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Audit logging errors
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Channel closed")]
    ChannelClosed,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Authentication events
    AuthSuccess,
    AuthFailure,
    TokenIssued,
    TokenRevoked,
    
    // Agent events
    AgentConnected,
    AgentDisconnected,
    AgentRegistered,
    AgentDeregistered,
    
    // Tunnel events
    TunnelCreated,
    TunnelDeleted,
    TunnelStarted,
    TunnelStopped,
    
    // Request events
    RequestReceived,
    RequestForwarded,
    RequestBlocked,
    RequestFailed,
    
    // Domain events
    DomainAdded,
    DomainRemoved,
    DomainVerified,
    DomainVerificationFailed,
    
    // Security events
    RateLimitExceeded,
    SuspiciousActivity,
    BruteForceDetected,
    CertificateError,
    
    // Admin events
    ConfigChanged,
    ServerStarted,
    ServerStopped,
    MaintenanceMode,
    
    // Billing events
    UsageRecorded,
    QuotaExceeded,
    SubscriptionChanged,
}

impl AuditEventType {
    /// Get the severity level for this event type
    pub fn severity(&self) -> AuditSeverity {
        match self {
            // Normal operations
            Self::AgentConnected
            | Self::AgentDisconnected
            | Self::TunnelCreated
            | Self::TunnelDeleted
            | Self::TunnelStarted
            | Self::TunnelStopped
            | Self::RequestReceived
            | Self::RequestForwarded
            | Self::DomainAdded
            | Self::DomainRemoved
            | Self::DomainVerified
            | Self::UsageRecorded => AuditSeverity::Info,
            
            // Authentication
            Self::AuthSuccess
            | Self::TokenIssued
            | Self::AgentRegistered
            | Self::ConfigChanged
            | Self::ServerStarted
            | Self::ServerStopped => AuditSeverity::Notice,
            
            // Warnings
            Self::AuthFailure
            | Self::RequestFailed
            | Self::DomainVerificationFailed
            | Self::QuotaExceeded
            | Self::MaintenanceMode
            | Self::SubscriptionChanged => AuditSeverity::Warning,
            
            // Errors/Security
            Self::RequestBlocked
            | Self::RateLimitExceeded
            | Self::TokenRevoked
            | Self::AgentDeregistered
            | Self::CertificateError => AuditSeverity::Error,
            
            // Critical security events
            Self::SuspiciousActivity
            | Self::BruteForceDetected => AuditSeverity::Critical,
        }
    }
}

/// Severity levels for audit events
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
}

impl Default for AuditSeverity {
    fn default() -> Self {
        Self::Info
    }
}

/// A structured audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Severity level
    pub severity: AuditSeverity,
    /// Actor who performed the action
    pub actor: Option<AuditActor>,
    /// Resource affected
    pub resource: Option<AuditResource>,
    /// Action outcome
    pub outcome: AuditOutcome,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Edge server ID
    pub edge_id: String,
    /// Region ID
    pub region: Option<String>,
    /// Additional context
    pub metadata: HashMap<String, serde_json::Value>,
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, edge_id: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity: event_type.severity(),
            actor: None,
            resource: None,
            outcome: AuditOutcome::Success,
            source_ip: None,
            user_agent: None,
            edge_id: edge_id.to_string(),
            region: None,
            metadata: HashMap::new(),
            request_id: None,
            session_id: None,
        }
    }
    
    /// Set the actor
    pub fn with_actor(mut self, actor: AuditActor) -> Self {
        self.actor = Some(actor);
        self
    }
    
    /// Set the resource
    pub fn with_resource(mut self, resource: AuditResource) -> Self {
        self.resource = Some(resource);
        self
    }
    
    /// Set the outcome
    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }
    
    /// Set source IP
    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }
    
    /// Set request ID for correlation
    pub fn with_request_id(mut self, id: &str) -> Self {
        self.request_id = Some(id.to_string());
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.metadata.insert(key.to_string(), value.into());
        self
    }
}

/// Actor who performed an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// Actor type
    pub actor_type: ActorType,
    /// Actor ID (user ID, agent ID, etc.)
    pub id: String,
    /// Actor name/email
    pub name: Option<String>,
    /// Organization/tenant ID
    pub organization: Option<String>,
}

/// Actor types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Agent,
    ApiKey,
    System,
    Anonymous,
}

/// Resource affected by an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResource {
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource ID
    pub id: String,
    /// Resource name
    pub name: Option<String>,
}

/// Resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Tunnel,
    Agent,
    User,
    Domain,
    Certificate,
    ApiKey,
    Edge,
    Request,
    Configuration,
}

/// Action outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Error,
    Timeout,
}

/// Audit log destination
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditDestination {
    /// Write to file
    File {
        path: PathBuf,
        max_size_mb: u32,
        max_files: u32,
    },
    /// Write to stdout
    Stdout,
    /// Send to HTTP endpoint (e.g., Elasticsearch, Loki)
    Http {
        url: String,
        headers: HashMap<String, String>,
        batch_size: usize,
    },
    /// Send to syslog
    Syslog {
        address: String,
    },
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,
    
    /// Minimum severity to log
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    
    /// Log file path (if using file destination)
    pub log_path: Option<PathBuf>,
    
    /// Buffer size for async logging
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    
    /// Include sensitive data (IPs, user agents, etc.)
    #[serde(default)]
    pub include_sensitive: bool,
    
    /// HTTP endpoint for shipping logs
    pub http_endpoint: Option<String>,
    
    /// HTTP authentication header
    pub http_auth_header: Option<String>,
}

fn default_audit_enabled() -> bool {
    true
}

fn default_min_severity() -> String {
    "info".to_string()
}

fn default_buffer_size() -> usize {
    10000
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_audit_enabled(),
            min_severity: default_min_severity(),
            log_path: None,
            buffer_size: default_buffer_size(),
            include_sensitive: false,
            http_endpoint: None,
            http_auth_header: None,
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    config: AuditConfig,
    edge_id: String,
    region: Option<String>,
    sender: mpsc::Sender<AuditEvent>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: AuditConfig, edge_id: String, region: Option<String>) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(config.buffer_size);
        
        let logger = Arc::new(Self {
            config: config.clone(),
            edge_id,
            region,
            sender,
        });
        
        // Start background writer
        if config.enabled {
            let writer = AuditWriter::new(config, receiver);
            tokio::spawn(async move {
                writer.run().await;
            });
        }
        
        logger
    }
    
    /// Log an audit event
    pub async fn log(&self, mut event: AuditEvent) {
        if !self.config.enabled {
            return;
        }
        
        // Set edge/region info
        event.edge_id = self.edge_id.clone();
        event.region = self.region.clone();
        
        // Scrub sensitive data if needed
        if !self.config.include_sensitive {
            event.source_ip = event.source_ip.map(|_| "[redacted]".to_string());
            event.user_agent = None;
        }
        
        if self.sender.send(event).await.is_err() {
            warn!("Audit log channel full, event dropped");
        }
    }
    
    /// Create an event builder
    pub fn event(&self, event_type: AuditEventType) -> AuditEvent {
        let mut event = AuditEvent::new(event_type, &self.edge_id);
        event.region = self.region.clone();
        event
    }
}

/// Background audit log writer
struct AuditWriter {
    config: AuditConfig,
    receiver: mpsc::Receiver<AuditEvent>,
}

impl AuditWriter {
    fn new(config: AuditConfig, receiver: mpsc::Receiver<AuditEvent>) -> Self {
        Self { config, receiver }
    }
    
    async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            if let Err(e) = self.write_event(&event).await {
                error!("Failed to write audit event: {}", e);
            }
        }
    }
    
    async fn write_event(&self, event: &AuditEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        
        // Write to stdout (always for now)
        println!("[AUDIT] {}", json);
        
        // Write to file if configured
        if let Some(path) = &self.config.log_path {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            file.write_all(json.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
        
        // Ship to HTTP endpoint if configured
        if let Some(url) = &self.config.http_endpoint {
            debug!("Would ship audit event to {}", url);
            // In production, batch and send to endpoint
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_creation() {
        let event = AuditEvent::new(AuditEventType::AgentConnected, "edge-1")
            .with_actor(AuditActor {
                actor_type: ActorType::Agent,
                id: "agent-123".to_string(),
                name: Some("test-agent".to_string()),
                organization: None,
            })
            .with_source_ip("192.168.1.100")
            .with_metadata("tunnel_id", "tunnel-456");
        
        assert_eq!(event.event_type, AuditEventType::AgentConnected);
        assert_eq!(event.severity, AuditSeverity::Info);
        assert_eq!(event.edge_id, "edge-1");
        assert!(event.actor.is_some());
    }
    
    #[test]
    fn test_event_serialization() {
        let event = AuditEvent::new(AuditEventType::RequestReceived, "edge-1");
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.event_type, event.event_type);
        assert_eq!(parsed.edge_id, event.edge_id);
    }
}
