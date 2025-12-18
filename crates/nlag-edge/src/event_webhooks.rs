//! Event Webhooks Module
//!
//! Send tunnel events to external services:
//! - Tunnel start/stop events
//! - Request/response events
//! - Error events
//! - Custom events
//! - Retry and batching support

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Tunnel started
    TunnelStarted,
    /// Tunnel stopped
    TunnelStopped,
    /// Request received
    RequestReceived,
    /// Response sent
    ResponseSent,
    /// Error occurred
    Error,
    /// Rate limit triggered
    RateLimited,
    /// Connection established
    ConnectionEstablished,
    /// Connection closed
    ConnectionClosed,
    /// Custom event
    Custom(String),
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::TunnelStarted => write!(f, "tunnel_started"),
            EventType::TunnelStopped => write!(f, "tunnel_stopped"),
            EventType::RequestReceived => write!(f, "request_received"),
            EventType::ResponseSent => write!(f, "response_sent"),
            EventType::Error => write!(f, "error"),
            EventType::RateLimited => write!(f, "rate_limited"),
            EventType::ConnectionEstablished => write!(f, "connection_established"),
            EventType::ConnectionClosed => write!(f, "connection_closed"),
            EventType::Custom(name) => write!(f, "custom_{}", name),
        }
    }
}

/// Event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    pub id: String,
    /// Event type
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Tunnel ID (if applicable)
    pub tunnel_id: Option<String>,
    /// Request ID (if applicable)
    pub request_id: Option<String>,
    /// Event data
    pub data: EventData,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: EventType, data: EventData) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            tunnel_id: None,
            request_id: None,
            data,
            metadata: HashMap::new(),
        }
    }

    /// Set tunnel ID
    pub fn with_tunnel(mut self, tunnel_id: &str) -> Self {
        self.tunnel_id = Some(tunnel_id.to_string());
        self
    }

    /// Set request ID
    pub fn with_request(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }
}

/// Event data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    /// Tunnel event
    Tunnel(TunnelEventData),
    /// Request event
    Request(RequestEventData),
    /// Error event
    Error(ErrorEventData),
    /// Generic event
    Generic(serde_json::Value),
}

/// Tunnel event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEventData {
    /// Subdomain
    pub subdomain: Option<String>,
    /// Public URL
    pub public_url: Option<String>,
    /// Local address
    pub local_addr: Option<String>,
    /// Protocol (http, https, tcp)
    pub protocol: Option<String>,
    /// Region
    pub region: Option<String>,
}

/// Request event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEventData {
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Response status code
    pub status: Option<u16>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Request size in bytes
    pub request_size: Option<u64>,
    /// Response size in bytes
    pub response_size: Option<u64>,
    /// Client IP
    pub client_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
}

/// Error event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEventData {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Stack trace (if available)
    pub stack: Option<String>,
    /// Additional context
    #[serde(default)]
    pub context: HashMap<String, String>,
}

/// Webhook endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Unique endpoint ID
    pub id: String,
    /// Webhook URL
    pub url: String,
    /// Secret for signing requests
    pub secret: Option<String>,
    /// Event types to subscribe to
    #[serde(default)]
    pub events: Vec<EventType>,
    /// Custom headers to include
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Whether the endpoint is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum retries
    #[serde(default = "default_retries")]
    pub max_retries: u32,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Batch size (0 = no batching)
    #[serde(default)]
    pub batch_size: usize,
    /// Batch timeout in milliseconds
    #[serde(default = "default_batch_timeout")]
    pub batch_timeout_ms: u64,
}

fn default_true() -> bool { true }
fn default_retries() -> u32 { 3 }
fn default_timeout() -> u64 { 30 }
fn default_batch_timeout() -> u64 { 1000 }

/// Delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Pending delivery
    Pending,
    /// Successfully delivered
    Delivered,
    /// Delivery failed
    Failed { error: String, attempts: u32 },
    /// Queued for retry
    Retrying { attempt: u32, next_retry: DateTime<Utc> },
}

/// Delivery record for tracking
#[derive(Debug, Clone)]
pub struct DeliveryRecord {
    /// Event ID
    pub event_id: String,
    /// Endpoint ID
    pub endpoint_id: String,
    /// Status
    pub status: DeliveryStatus,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Response status code (if delivered)
    pub response_status: Option<u16>,
    /// Response body preview
    pub response_body: Option<String>,
}

/// Event webhook manager
pub struct EventWebhooks {
    /// Registered endpoints
    endpoints: RwLock<HashMap<String, WebhookEndpoint>>,
    /// Delivery history (limited)
    history: RwLock<Vec<DeliveryRecord>>,
    /// Maximum history size
    max_history: usize,
    /// Event sender for async processing
    event_tx: Option<mpsc::UnboundedSender<(Event, String)>>,
}

impl EventWebhooks {
    /// Create a new event webhook manager
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            endpoints: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
            max_history: 1000,
            event_tx: None,
        })
    }

    /// Create with event channel for async processing
    pub fn with_channel() -> (Arc<Self>, mpsc::UnboundedReceiver<(Event, String)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let manager = Arc::new(Self {
            endpoints: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
            max_history: 1000,
            event_tx: Some(tx),
        });
        (manager, rx)
    }

    /// Register an endpoint
    pub fn register_endpoint(&self, endpoint: WebhookEndpoint) {
        self.endpoints.write().insert(endpoint.id.clone(), endpoint);
    }

    /// Unregister an endpoint
    pub fn unregister_endpoint(&self, endpoint_id: &str) {
        self.endpoints.write().remove(endpoint_id);
    }

    /// Get an endpoint
    pub fn get_endpoint(&self, endpoint_id: &str) -> Option<WebhookEndpoint> {
        self.endpoints.read().get(endpoint_id).cloned()
    }

    /// List all endpoints
    pub fn list_endpoints(&self) -> Vec<WebhookEndpoint> {
        self.endpoints.read().values().cloned().collect()
    }

    /// Emit an event to all subscribed endpoints
    pub fn emit(&self, event: Event) {
        let endpoints = self.endpoints.read();
        
        for endpoint in endpoints.values() {
            if !endpoint.enabled {
                continue;
            }

            // Check if endpoint is subscribed to this event type
            if !endpoint.events.is_empty() && !endpoint.events.contains(&event.event_type) {
                continue;
            }

            // Send to channel for async processing
            if let Some(ref tx) = self.event_tx {
                let _ = tx.send((event.clone(), endpoint.id.clone()));
            }
        }
    }

    /// Emit a tunnel started event
    pub fn emit_tunnel_started(&self, tunnel_id: &str, subdomain: Option<&str>, public_url: Option<&str>) {
        let event = Event::new(
            EventType::TunnelStarted,
            EventData::Tunnel(TunnelEventData {
                subdomain: subdomain.map(|s| s.to_string()),
                public_url: public_url.map(|s| s.to_string()),
                local_addr: None,
                protocol: Some("http".to_string()),
                region: None,
            }),
        ).with_tunnel(tunnel_id);
        
        self.emit(event);
    }

    /// Emit a tunnel stopped event
    pub fn emit_tunnel_stopped(&self, tunnel_id: &str) {
        let event = Event::new(
            EventType::TunnelStopped,
            EventData::Tunnel(TunnelEventData {
                subdomain: None,
                public_url: None,
                local_addr: None,
                protocol: None,
                region: None,
            }),
        ).with_tunnel(tunnel_id);
        
        self.emit(event);
    }

    /// Emit a request event
    pub fn emit_request(
        &self,
        tunnel_id: &str,
        request_id: &str,
        method: &str,
        path: &str,
        client_ip: Option<&str>,
    ) {
        let event = Event::new(
            EventType::RequestReceived,
            EventData::Request(RequestEventData {
                method: method.to_string(),
                path: path.to_string(),
                status: None,
                response_time_ms: None,
                request_size: None,
                response_size: None,
                client_ip: client_ip.map(|s| s.to_string()),
                user_agent: None,
            }),
        )
        .with_tunnel(tunnel_id)
        .with_request(request_id);
        
        self.emit(event);
    }

    /// Emit a response event
    pub fn emit_response(
        &self,
        tunnel_id: &str,
        request_id: &str,
        status: u16,
        response_time_ms: u64,
    ) {
        let event = Event::new(
            EventType::ResponseSent,
            EventData::Request(RequestEventData {
                method: String::new(),
                path: String::new(),
                status: Some(status),
                response_time_ms: Some(response_time_ms),
                request_size: None,
                response_size: None,
                client_ip: None,
                user_agent: None,
            }),
        )
        .with_tunnel(tunnel_id)
        .with_request(request_id);
        
        self.emit(event);
    }

    /// Emit an error event
    pub fn emit_error(&self, tunnel_id: Option<&str>, code: &str, message: &str) {
        let mut event = Event::new(
            EventType::Error,
            EventData::Error(ErrorEventData {
                code: code.to_string(),
                message: message.to_string(),
                stack: None,
                context: HashMap::new(),
            }),
        );
        
        if let Some(tid) = tunnel_id {
            event = event.with_tunnel(tid);
        }
        
        self.emit(event);
    }

    /// Record a delivery attempt
    pub fn record_delivery(&self, record: DeliveryRecord) {
        let mut history = self.history.write();
        
        if history.len() >= self.max_history {
            history.remove(0);
        }
        
        history.push(record);
    }

    /// Get delivery history for an endpoint
    pub fn get_history(&self, endpoint_id: Option<&str>) -> Vec<DeliveryRecord> {
        let history = self.history.read();
        
        match endpoint_id {
            Some(id) => history.iter()
                .filter(|r| r.endpoint_id == id)
                .cloned()
                .collect(),
            None => history.clone(),
        }
    }

    /// Sign an event payload
    pub fn sign_payload(secret: &str, payload: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload);
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Build webhook request headers
    pub fn build_headers(
        endpoint: &WebhookEndpoint,
        event: &Event,
        payload: &[u8],
    ) -> HashMap<String, String> {
        let mut headers = endpoint.headers.clone();
        
        // Standard headers
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Webhook-Event".to_string(), event.event_type.to_string());
        headers.insert("X-Webhook-Event-Id".to_string(), event.id.clone());
        headers.insert("X-Webhook-Timestamp".to_string(), Utc::now().timestamp().to_string());
        
        // Signature if secret is set
        if let Some(ref secret) = endpoint.secret {
            let signature = Self::sign_payload(secret, payload);
            headers.insert("X-Webhook-Signature".to_string(), format!("sha256={}", signature));
        }
        
        headers
    }
}

impl Default for EventWebhooks {
    fn default() -> Self {
        Self {
            endpoints: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
            max_history: 1000,
            event_tx: None,
        }
    }
}

/// Shared event webhooks instance
pub type SharedEventWebhooks = Arc<EventWebhooks>;

/// Builder for webhook endpoints
pub struct EndpointBuilder {
    endpoint: WebhookEndpoint,
}

impl EndpointBuilder {
    /// Create a new endpoint builder
    pub fn new(id: &str, url: &str) -> Self {
        Self {
            endpoint: WebhookEndpoint {
                id: id.to_string(),
                url: url.to_string(),
                secret: None,
                events: Vec::new(),
                headers: HashMap::new(),
                enabled: true,
                max_retries: 3,
                timeout_secs: 30,
                batch_size: 0,
                batch_timeout_ms: 1000,
            },
        }
    }

    /// Set secret
    pub fn secret(mut self, secret: &str) -> Self {
        self.endpoint.secret = Some(secret.to_string());
        self
    }

    /// Subscribe to event type
    pub fn subscribe(mut self, event_type: EventType) -> Self {
        self.endpoint.events.push(event_type);
        self
    }

    /// Subscribe to multiple event types
    pub fn subscribe_all(mut self, events: Vec<EventType>) -> Self {
        self.endpoint.events.extend(events);
        self
    }

    /// Add custom header
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.endpoint.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Set max retries
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.endpoint.max_retries = retries;
        self
    }

    /// Set timeout
    pub fn timeout(mut self, secs: u64) -> Self {
        self.endpoint.timeout_secs = secs;
        self
    }

    /// Enable batching
    pub fn batch(mut self, size: usize, timeout_ms: u64) -> Self {
        self.endpoint.batch_size = size;
        self.endpoint.batch_timeout_ms = timeout_ms;
        self
    }

    /// Disable the endpoint
    pub fn disabled(mut self) -> Self {
        self.endpoint.enabled = false;
        self
    }

    /// Build the endpoint
    pub fn build(self) -> WebhookEndpoint {
        self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Event::new(
            EventType::TunnelStarted,
            EventData::Tunnel(TunnelEventData {
                subdomain: Some("test".to_string()),
                public_url: Some("https://test.nlag.io".to_string()),
                local_addr: Some("127.0.0.1:8080".to_string()),
                protocol: Some("http".to_string()),
                region: Some("us-east".to_string()),
            }),
        )
        .with_tunnel("tunnel-123")
        .with_metadata("source", serde_json::json!("test"));

        assert!(!event.id.is_empty());
        assert_eq!(event.tunnel_id, Some("tunnel-123".to_string()));
        assert!(event.metadata.contains_key("source"));
    }

    #[test]
    fn test_endpoint_registration() {
        let webhooks = EventWebhooks::new();

        let endpoint = EndpointBuilder::new("slack-notifier", "https://hooks.slack.com/services/xxx")
            .secret("webhook-secret")
            .subscribe(EventType::TunnelStarted)
            .subscribe(EventType::TunnelStopped)
            .subscribe(EventType::Error)
            .build();

        webhooks.register_endpoint(endpoint);

        let retrieved = webhooks.get_endpoint("slack-notifier");
        assert!(retrieved.is_some());
        
        let ep = retrieved.unwrap();
        assert_eq!(ep.url, "https://hooks.slack.com/services/xxx");
        assert_eq!(ep.events.len(), 3);
    }

    #[test]
    fn test_endpoint_filtering() {
        let webhooks = EventWebhooks::new();

        let endpoint = EndpointBuilder::new("errors-only", "https://example.com/webhook")
            .subscribe(EventType::Error)
            .build();

        webhooks.register_endpoint(endpoint);

        let endpoints = webhooks.list_endpoints();
        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].events.contains(&EventType::Error));
        assert!(!endpoints[0].events.contains(&EventType::TunnelStarted));
    }

    #[test]
    fn test_event_emission_with_channel() {
        let (webhooks, mut rx) = EventWebhooks::with_channel();

        let endpoint = EndpointBuilder::new("test-endpoint", "https://example.com/webhook")
            .subscribe(EventType::TunnelStarted)
            .build();

        webhooks.register_endpoint(endpoint);
        webhooks.emit_tunnel_started("tunnel-1", Some("test"), Some("https://test.nlag.io"));

        // Event should be queued
        let received = rx.try_recv();
        assert!(received.is_ok());
        
        let (event, endpoint_id) = received.unwrap();
        assert_eq!(endpoint_id, "test-endpoint");
        assert!(matches!(event.event_type, EventType::TunnelStarted));
    }

    #[test]
    fn test_payload_signing() {
        let secret = "my-webhook-secret";
        let payload = b"test payload";
        
        let signature = EventWebhooks::sign_payload(secret, payload);
        
        // Should be consistent
        let signature2 = EventWebhooks::sign_payload(secret, payload);
        assert_eq!(signature, signature2);
        
        // Different payload = different signature
        let signature3 = EventWebhooks::sign_payload(secret, b"different payload");
        assert_ne!(signature, signature3);
    }

    #[test]
    fn test_build_headers() {
        let endpoint = EndpointBuilder::new("test", "https://example.com")
            .secret("secret123")
            .header("X-Custom", "value")
            .build();

        let event = Event::new(EventType::TunnelStarted, EventData::Generic(serde_json::json!({})));
        let payload = serde_json::to_vec(&event).unwrap();
        
        let headers = EventWebhooks::build_headers(&endpoint, &event, &payload);
        
        assert!(headers.contains_key("Content-Type"));
        assert!(headers.contains_key("X-Webhook-Event"));
        assert!(headers.contains_key("X-Webhook-Signature"));
        assert_eq!(headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_delivery_history() {
        let webhooks = EventWebhooks::new();

        webhooks.record_delivery(DeliveryRecord {
            event_id: "event-1".to_string(),
            endpoint_id: "endpoint-1".to_string(),
            status: DeliveryStatus::Delivered,
            timestamp: Utc::now(),
            response_status: Some(200),
            response_body: Some("OK".to_string()),
        });

        webhooks.record_delivery(DeliveryRecord {
            event_id: "event-2".to_string(),
            endpoint_id: "endpoint-2".to_string(),
            status: DeliveryStatus::Failed {
                error: "Connection refused".to_string(),
                attempts: 3,
            },
            timestamp: Utc::now(),
            response_status: None,
            response_body: None,
        });

        let all_history = webhooks.get_history(None);
        assert_eq!(all_history.len(), 2);

        let endpoint1_history = webhooks.get_history(Some("endpoint-1"));
        assert_eq!(endpoint1_history.len(), 1);
    }

    #[test]
    fn test_emit_convenience_methods() {
        let (webhooks, mut rx) = EventWebhooks::with_channel();

        // Register catch-all endpoint
        let endpoint = EndpointBuilder::new("all-events", "https://example.com/webhook").build();
        webhooks.register_endpoint(endpoint);

        webhooks.emit_tunnel_started("tunnel-1", Some("test"), None);
        assert!(rx.try_recv().is_ok());

        webhooks.emit_tunnel_stopped("tunnel-1");
        assert!(rx.try_recv().is_ok());

        webhooks.emit_request("tunnel-1", "req-1", "GET", "/api/users", Some("127.0.0.1"));
        assert!(rx.try_recv().is_ok());

        webhooks.emit_response("tunnel-1", "req-1", 200, 42);
        assert!(rx.try_recv().is_ok());

        webhooks.emit_error(Some("tunnel-1"), "ERR001", "Something went wrong");
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_disabled_endpoint() {
        let (webhooks, mut rx) = EventWebhooks::with_channel();

        let endpoint = EndpointBuilder::new("disabled", "https://example.com/webhook")
            .disabled()
            .build();

        webhooks.register_endpoint(endpoint);
        webhooks.emit_tunnel_started("tunnel-1", None, None);

        // Should not receive anything
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_event_type_filtering() {
        let (webhooks, mut rx) = EventWebhooks::with_channel();

        // Only errors
        let endpoint = EndpointBuilder::new("errors-only", "https://example.com/webhook")
            .subscribe(EventType::Error)
            .build();

        webhooks.register_endpoint(endpoint);

        // This should not trigger
        webhooks.emit_tunnel_started("tunnel-1", None, None);
        assert!(rx.try_recv().is_err());

        // This should trigger
        webhooks.emit_error(None, "ERR", "test");
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_unregister_endpoint() {
        let webhooks = EventWebhooks::new();

        let endpoint = EndpointBuilder::new("temp", "https://example.com/webhook").build();
        webhooks.register_endpoint(endpoint);

        assert!(webhooks.get_endpoint("temp").is_some());

        webhooks.unregister_endpoint("temp");

        assert!(webhooks.get_endpoint("temp").is_none());
    }

    #[test]
    fn test_endpoint_builder() {
        let endpoint = EndpointBuilder::new("full-config", "https://example.com/webhook")
            .secret("secret123")
            .subscribe(EventType::TunnelStarted)
            .subscribe(EventType::TunnelStopped)
            .header("Authorization", "Bearer token")
            .max_retries(5)
            .timeout(60)
            .batch(10, 500)
            .build();

        assert_eq!(endpoint.id, "full-config");
        assert_eq!(endpoint.secret, Some("secret123".to_string()));
        assert_eq!(endpoint.events.len(), 2);
        assert_eq!(endpoint.max_retries, 5);
        assert_eq!(endpoint.timeout_secs, 60);
        assert_eq!(endpoint.batch_size, 10);
        assert_eq!(endpoint.batch_timeout_ms, 500);
    }
}
