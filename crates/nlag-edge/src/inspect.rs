//! Request Inspection Module
//!
//! Captures and stores HTTP requests/responses for live inspection,
//! similar to ngrok's inspect interface.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use nlag_common::types::TunnelId;

/// Maximum number of requests to keep per tunnel
const MAX_REQUESTS_PER_TUNNEL: usize = 500;

/// How long to keep requests before expiring
const REQUEST_RETENTION: Duration = Duration::from_secs(3600); // 1 hour

/// A captured HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    /// Unique request ID
    pub id: u64,

    /// Tunnel ID this request belongs to
    pub tunnel_id: TunnelId,

    /// When the request was received
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Request duration in milliseconds (if completed)
    pub duration_ms: Option<u64>,

    /// HTTP method (GET, POST, etc.)
    pub method: String,

    /// Request path
    pub path: String,

    /// Query string
    pub query: Option<String>,

    /// HTTP version
    pub http_version: String,

    /// Request headers
    pub request_headers: Vec<(String, String)>,

    /// Request body (truncated if too large)
    pub request_body: Option<String>,

    /// Request body size in bytes
    pub request_body_size: usize,

    /// Response status code
    pub response_status: Option<u16>,

    /// Response status text
    pub response_status_text: Option<String>,

    /// Response headers
    pub response_headers: Vec<(String, String)>,

    /// Response body (truncated if too large)
    pub response_body: Option<String>,

    /// Response body size in bytes
    pub response_body_size: usize,

    /// Client IP address
    pub client_ip: String,

    /// Whether this is a WebSocket upgrade
    pub is_websocket: bool,

    /// Error message if request failed
    pub error: Option<String>,

    /// Request state
    pub state: RequestState,
}

/// State of a captured request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestState {
    /// Request in progress
    Pending,
    /// Request completed successfully
    Completed,
    /// Request failed
    Failed,
    /// Request timed out
    Timeout,
}

impl CapturedRequest {
    /// Create a new captured request
    pub fn new(
        id: u64,
        tunnel_id: TunnelId,
        method: String,
        path: String,
        client_ip: String,
    ) -> Self {
        Self {
            id,
            tunnel_id,
            timestamp: chrono::Utc::now(),
            duration_ms: None,
            method,
            path,
            query: None,
            http_version: "HTTP/1.1".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            request_body_size: 0,
            response_status: None,
            response_status_text: None,
            response_headers: Vec::new(),
            response_body: None,
            response_body_size: 0,
            client_ip,
            is_websocket: false,
            error: None,
            state: RequestState::Pending,
        }
    }

    /// Mark the request as completed with response info
    pub fn complete(&mut self, status: u16, status_text: &str, duration_ms: u64) {
        self.response_status = Some(status);
        self.response_status_text = Some(status_text.to_string());
        self.duration_ms = Some(duration_ms);
        self.state = RequestState::Completed;
    }

    /// Mark the request as failed
    pub fn fail(&mut self, error: &str, duration_ms: u64) {
        self.error = Some(error.to_string());
        self.duration_ms = Some(duration_ms);
        self.state = RequestState::Failed;
    }
}

/// Event sent when requests change
#[derive(Debug, Clone, Serialize)]
pub enum InspectorEvent {
    /// New request started
    RequestStarted(CapturedRequest),
    /// Request completed
    RequestCompleted(CapturedRequest),
    /// Request failed
    RequestFailed(CapturedRequest),
    /// Request cleared
    RequestsCleared(TunnelId),
}

/// Per-tunnel request storage
struct TunnelRequests {
    /// Recent requests (ring buffer)
    requests: RwLock<VecDeque<CapturedRequest>>,
    /// Total request count
    total_count: AtomicU64,
    /// Next request ID
    next_id: AtomicU64,
}

impl TunnelRequests {
    fn new() -> Self {
        Self {
            requests: RwLock::new(VecDeque::with_capacity(MAX_REQUESTS_PER_TUNNEL)),
            total_count: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn add(&self, request: CapturedRequest) {
        let mut requests = self.requests.write();
        if requests.len() >= MAX_REQUESTS_PER_TUNNEL {
            requests.pop_front();
        }
        requests.push_back(request);
        self.total_count.fetch_add(1, Ordering::Relaxed);
    }

    fn update(&self, id: u64, updater: impl FnOnce(&mut CapturedRequest)) {
        let mut requests = self.requests.write();
        if let Some(req) = requests.iter_mut().rev().find(|r| r.id == id) {
            updater(req);
        }
    }

    fn get(&self, id: u64) -> Option<CapturedRequest> {
        let requests = self.requests.read();
        requests.iter().find(|r| r.id == id).cloned()
    }

    fn list(&self, limit: usize, offset: usize) -> Vec<CapturedRequest> {
        let requests = self.requests.read();
        requests
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.requests.write().clear();
    }

    fn len(&self) -> usize {
        self.requests.read().len()
    }
}

/// Request inspector for capturing and viewing HTTP traffic
pub struct RequestInspector {
    /// Per-tunnel request storage
    tunnels: DashMap<TunnelId, Arc<TunnelRequests>>,

    /// Event broadcaster for real-time updates
    event_tx: broadcast::Sender<InspectorEvent>,

    /// Maximum body size to capture (in bytes)
    max_body_size: usize,

    /// Whether inspection is enabled
    enabled: bool,
}

impl RequestInspector {
    /// Create a new request inspector
    pub fn new(enabled: bool) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1000);

        Arc::new(Self {
            tunnels: DashMap::new(),
            event_tx,
            max_body_size: 1024 * 1024, // 1MB
            enabled,
        })
    }

    /// Check if inspection is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Subscribe to request events
    pub fn subscribe(&self) -> broadcast::Receiver<InspectorEvent> {
        self.event_tx.subscribe()
    }

    /// Start capturing a new request
    pub fn start_request(
        &self,
        tunnel_id: TunnelId,
        method: &str,
        path: &str,
        client_ip: &str,
    ) -> Option<u64> {
        if !self.enabled {
            return None;
        }

        let storage = self.get_or_create_tunnel(tunnel_id);
        let id = storage.next_id();

        let request = CapturedRequest::new(
            id,
            tunnel_id,
            method.to_string(),
            path.to_string(),
            client_ip.to_string(),
        );

        storage.add(request.clone());
        let _ = self.event_tx.send(InspectorEvent::RequestStarted(request));

        Some(id)
    }

    /// Add request headers
    pub fn set_request_headers(&self, tunnel_id: TunnelId, request_id: u64, headers: Vec<(String, String)>) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.request_headers = headers;
                // Check for WebSocket upgrade
                req.is_websocket = req.request_headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket")
                });
            });
        }
    }

    /// Add request body
    pub fn set_request_body(&self, tunnel_id: TunnelId, request_id: u64, body: &[u8]) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.request_body_size = body.len();
                if body.len() <= self.max_body_size {
                    // Try to convert to string, otherwise store as base64
                    req.request_body = String::from_utf8(body.to_vec())
                        .ok()
                        .or_else(|| Some(format!("[binary: {} bytes]", body.len())));
                } else {
                    req.request_body = Some(format!("[truncated: {} bytes]", body.len()));
                }
            });
        }
    }

    /// Complete a request with response info
    pub fn complete_request(
        &self,
        tunnel_id: TunnelId,
        request_id: u64,
        status: u16,
        status_text: &str,
        duration_ms: u64,
    ) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.complete(status, status_text, duration_ms);
            });

            if let Some(request) = storage.get(request_id) {
                let _ = self.event_tx.send(InspectorEvent::RequestCompleted(request));
            }
        }
    }

    /// Set response headers
    pub fn set_response_headers(&self, tunnel_id: TunnelId, request_id: u64, headers: Vec<(String, String)>) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.response_headers = headers;
            });
        }
    }

    /// Set response body
    pub fn set_response_body(&self, tunnel_id: TunnelId, request_id: u64, body: &[u8]) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.response_body_size = body.len();
                if body.len() <= self.max_body_size {
                    req.response_body = String::from_utf8(body.to_vec())
                        .ok()
                        .or_else(|| Some(format!("[binary: {} bytes]", body.len())));
                } else {
                    req.response_body = Some(format!("[truncated: {} bytes]", body.len()));
                }
            });
        }
    }

    /// Mark a request as failed
    pub fn fail_request(&self, tunnel_id: TunnelId, request_id: u64, error: &str, duration_ms: u64) {
        if !self.enabled {
            return;
        }

        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.update(request_id, |req| {
                req.fail(error, duration_ms);
            });

            if let Some(request) = storage.get(request_id) {
                let _ = self.event_tx.send(InspectorEvent::RequestFailed(request));
            }
        }
    }

    /// Get a specific request
    pub fn get_request(&self, tunnel_id: TunnelId, request_id: u64) -> Option<CapturedRequest> {
        self.tunnels
            .get(&tunnel_id)
            .and_then(|storage| storage.get(request_id))
    }

    /// List recent requests for a tunnel
    pub fn list_requests(&self, tunnel_id: TunnelId, limit: usize, offset: usize) -> Vec<CapturedRequest> {
        self.tunnels
            .get(&tunnel_id)
            .map(|storage| storage.list(limit, offset))
            .unwrap_or_default()
    }

    /// Clear all requests for a tunnel
    pub fn clear_requests(&self, tunnel_id: TunnelId) {
        if let Some(storage) = self.tunnels.get(&tunnel_id) {
            storage.clear();
            let _ = self.event_tx.send(InspectorEvent::RequestsCleared(tunnel_id));
        }
    }

    /// Get statistics for a tunnel
    pub fn get_stats(&self, tunnel_id: TunnelId) -> TunnelInspectorStats {
        self.tunnels
            .get(&tunnel_id)
            .map(|storage| TunnelInspectorStats {
                captured_count: storage.len(),
                total_count: storage.total_count.load(Ordering::Relaxed),
            })
            .unwrap_or_default()
    }

    /// Remove a tunnel's inspection data
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        self.tunnels.remove(tunnel_id);
    }

    fn get_or_create_tunnel(&self, tunnel_id: TunnelId) -> Arc<TunnelRequests> {
        self.tunnels
            .entry(tunnel_id)
            .or_insert_with(|| Arc::new(TunnelRequests::new()))
            .clone()
    }
}

/// Statistics for tunnel inspection
#[derive(Debug, Clone, Default, Serialize)]
pub struct TunnelInspectorStats {
    /// Number of requests currently captured
    pub captured_count: usize,
    /// Total requests processed
    pub total_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_request() {
        let inspector = RequestInspector::new(true);
        let tunnel_id = TunnelId::new();

        let request_id = inspector
            .start_request(tunnel_id, "GET", "/api/test", "127.0.0.1")
            .unwrap();

        inspector.set_request_headers(
            tunnel_id,
            request_id,
            vec![("Content-Type".to_string(), "application/json".to_string())],
        );

        inspector.complete_request(tunnel_id, request_id, 200, "OK", 50);

        let request = inspector.get_request(tunnel_id, request_id).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.response_status, Some(200));
        assert_eq!(request.state, RequestState::Completed);
    }

    #[test]
    fn test_request_list() {
        let inspector = RequestInspector::new(true);
        let tunnel_id = TunnelId::new();

        for i in 0..10 {
            let id = inspector
                .start_request(tunnel_id, "GET", &format!("/path/{}", i), "127.0.0.1")
                .unwrap();
            inspector.complete_request(tunnel_id, id, 200, "OK", 10);
        }

        let requests = inspector.list_requests(tunnel_id, 5, 0);
        assert_eq!(requests.len(), 5);
        // Should be in reverse order (most recent first)
        assert_eq!(requests[0].path, "/path/9");
    }

    #[test]
    fn test_disabled_inspector() {
        let inspector = RequestInspector::new(false);
        let tunnel_id = TunnelId::new();

        let request_id = inspector.start_request(tunnel_id, "GET", "/test", "127.0.0.1");
        assert!(request_id.is_none());
    }
}
