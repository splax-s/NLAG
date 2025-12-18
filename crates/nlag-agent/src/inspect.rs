//! Local Traffic Inspector
//!
//! Captures HTTP requests/responses flowing through tunnels and provides
//! a local web UI at http://localhost:4040 for inspection.
//!
//! Traffic is captured locally AND synced to the dashboard for permanent storage.

use anyhow::Result;
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use axum::extract::ws::{Message, WebSocket};
use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Maximum number of requests to keep in memory per tunnel
const MAX_REQUESTS_PER_TUNNEL: usize = 1000;

/// Captured HTTP request
#[derive(Debug, Clone, Serialize)]
pub struct CapturedRequest {
    /// Unique request ID
    pub id: String,
    /// Tunnel ID this request belongs to
    pub tunnel_id: String,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: Vec<(String, String)>,
    /// Request body (if captured)
    pub body: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Content length
    pub content_length: Option<usize>,
    /// Response status code (if response received)
    pub response_status: Option<u16>,
    /// Response headers
    pub response_headers: Option<Vec<(String, String)>>,
    /// Response body (if captured)
    pub response_body: Option<String>,
    /// Response time in milliseconds
    pub duration_ms: Option<u64>,
    /// Client address
    pub client_addr: Option<String>,
}

/// Traffic inspector event for live updates
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InspectorEvent {
    /// New request started
    RequestStarted(CapturedRequest),
    /// Response received
    ResponseReceived {
        request_id: String,
        status: u16,
        duration_ms: u64,
    },
    /// Request cleared
    RequestsCleared { tunnel_id: String },
}

/// Traffic statistics for a tunnel
#[derive(Debug, Default, Clone, Serialize)]
pub struct TunnelStats {
    /// Total requests received
    pub total_requests: u64,
    /// Requests in last minute
    pub requests_per_minute: u64,
    /// Average response time
    pub avg_response_ms: f64,
    /// Status code distribution
    pub status_codes: std::collections::HashMap<u16, u64>,
    /// Last request time
    pub last_request: Option<DateTime<Utc>>,
}

/// Local traffic inspector
pub struct LocalInspector {
    /// Captured requests per tunnel
    requests: RwLock<std::collections::HashMap<String, VecDeque<CapturedRequest>>>,
    /// Statistics per tunnel
    stats: RwLock<std::collections::HashMap<String, TunnelStats>>,
    /// Broadcast channel for live updates
    events_tx: broadcast::Sender<InspectorEvent>,
    /// Dashboard sync endpoint (if authenticated)
    sync_endpoint: RwLock<Option<String>>,
    /// Auth token for sync
    auth_token: RwLock<Option<String>>,
}

impl LocalInspector {
    /// Create a new local inspector
    pub fn new() -> Arc<Self> {
        let (events_tx, _) = broadcast::channel(1000);
        
        Arc::new(Self {
            requests: RwLock::new(std::collections::HashMap::new()),
            stats: RwLock::new(std::collections::HashMap::new()),
            events_tx,
            sync_endpoint: RwLock::new(None),
            auth_token: RwLock::new(None),
        })
    }
    
    /// Configure dashboard sync
    pub fn configure_sync(&self, endpoint: String, token: String) {
        *self.sync_endpoint.write() = Some(endpoint);
        *self.auth_token.write() = Some(token);
    }
    
    /// Record a new request
    pub fn record_request(&self, request: CapturedRequest) {
        let tunnel_id = request.tunnel_id.clone();
        
        // Add to local storage
        {
            let mut requests = self.requests.write();
            let tunnel_requests = requests.entry(tunnel_id.clone()).or_insert_with(VecDeque::new);
            
            // Remove oldest if at capacity
            if tunnel_requests.len() >= MAX_REQUESTS_PER_TUNNEL {
                tunnel_requests.pop_front();
            }
            
            tunnel_requests.push_back(request.clone());
        }
        
        // Update stats
        {
            let mut stats = self.stats.write();
            let tunnel_stats = stats.entry(tunnel_id).or_default();
            tunnel_stats.total_requests += 1;
            tunnel_stats.last_request = Some(request.timestamp);
        }
        
        // Broadcast event
        let _ = self.events_tx.send(InspectorEvent::RequestStarted(request.clone()));
        
        // Sync to dashboard in background
        self.sync_to_dashboard(request);
    }
    
    /// Update request with response
    pub fn record_response(&self, request_id: &str, status: u16, duration_ms: u64, 
                          headers: Vec<(String, String)>, body: Option<String>) {
        let mut requests = self.requests.write();
        
        for tunnel_requests in requests.values_mut() {
            if let Some(req) = tunnel_requests.iter_mut().find(|r| r.id == request_id) {
                req.response_status = Some(status);
                req.response_headers = Some(headers);
                req.response_body = body;
                req.duration_ms = Some(duration_ms);
                
                // Update stats
                let mut stats = self.stats.write();
                if let Some(tunnel_stats) = stats.get_mut(&req.tunnel_id) {
                    *tunnel_stats.status_codes.entry(status).or_insert(0) += 1;
                    
                    // Update average response time
                    let total = tunnel_stats.total_requests;
                    let old_avg = tunnel_stats.avg_response_ms;
                    tunnel_stats.avg_response_ms = old_avg + ((duration_ms as f64 - old_avg) / total as f64);
                }
                
                break;
            }
        }
        
        let _ = self.events_tx.send(InspectorEvent::ResponseReceived {
            request_id: request_id.to_string(),
            status,
            duration_ms,
        });
    }
    
    /// Get requests for a tunnel
    pub fn get_requests(&self, tunnel_id: &str, limit: usize, offset: usize) -> Vec<CapturedRequest> {
        let requests = self.requests.read();
        
        requests.get(tunnel_id)
            .map(|reqs| {
                reqs.iter()
                    .rev()  // newest first
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get a specific request
    pub fn get_request(&self, tunnel_id: &str, request_id: &str) -> Option<CapturedRequest> {
        let requests = self.requests.read();
        
        requests.get(tunnel_id)
            .and_then(|reqs| reqs.iter().find(|r| r.id == request_id).cloned())
    }
    
    /// Clear requests for a tunnel
    pub fn clear_requests(&self, tunnel_id: &str) {
        let mut requests = self.requests.write();
        requests.remove(tunnel_id);
        
        let mut stats = self.stats.write();
        if let Some(s) = stats.get_mut(tunnel_id) {
            *s = TunnelStats::default();
        }
        
        let _ = self.events_tx.send(InspectorEvent::RequestsCleared {
            tunnel_id: tunnel_id.to_string(),
        });
    }
    
    /// Get stats for a tunnel
    pub fn get_stats(&self, tunnel_id: &str) -> TunnelStats {
        self.stats.read()
            .get(tunnel_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Get list of active tunnels
    pub fn list_tunnels(&self) -> Vec<String> {
        self.requests.read().keys().cloned().collect()
    }
    
    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<InspectorEvent> {
        self.events_tx.subscribe()
    }
    
    /// Sync request to dashboard (async, fire-and-forget)
    fn sync_to_dashboard(&self, request: CapturedRequest) {
        let endpoint = self.sync_endpoint.read().clone();
        let token = self.auth_token.read().clone();
        
        if let (Some(endpoint), Some(token)) = (endpoint, token) {
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("{}/api/v1/traffic/sync", endpoint))
                    .bearer_auth(&token)
                    .json(&request)
                    .send()
                    .await;
            });
        }
    }
}

impl Default for LocalInspector {
    fn default() -> Self {
        let (events_tx, _) = broadcast::channel(1000);
        Self {
            requests: RwLock::new(std::collections::HashMap::new()),
            stats: RwLock::new(std::collections::HashMap::new()),
            events_tx,
            sync_endpoint: RwLock::new(None),
            auth_token: RwLock::new(None),
        }
    }
}

/// State for the inspect UI routes
pub struct InspectState {
    pub inspector: Arc<LocalInspector>,
}

/// Create the local inspect router
pub fn create_inspect_router(inspector: Arc<LocalInspector>) -> Router {
    let state = Arc::new(InspectState { inspector });

    Router::new()
        // Main UI
        .route("/", get(inspect_home))
        .route("/inspect", get(inspect_ui))
        .route("/inspect/:tunnel_id", get(inspect_tunnel_ui))
        
        // API endpoints
        .route("/api/tunnels", get(list_tunnels))
        .route("/api/tunnels/:tunnel_id/requests", get(list_requests))
        .route("/api/tunnels/:tunnel_id/requests/:request_id", get(get_request))
        .route("/api/tunnels/:tunnel_id/clear", post(clear_requests))
        .route("/api/tunnels/:tunnel_id/stats", get(get_stats))
        
        // WebSocket for live updates
        .route("/ws/:tunnel_id", get(websocket_handler))
        
        // Static assets
        .route("/assets/style.css", get(style_css))
        .with_state(state)
}

/// Run the local inspect server
pub async fn run_inspect_server(inspector: Arc<LocalInspector>, bind: &str, port: u16) -> Result<()> {
    let router = create_inspect_router(inspector);
    
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    tracing::info!("Inspect UI running at http://{}", addr);
    
    axum::serve(listener, router).await?;
    
    Ok(())
}

// ============================================================================
// Route handlers
// ============================================================================

async fn inspect_home() -> impl IntoResponse {
    Html(HOME_HTML)
}

async fn inspect_ui(State(state): State<Arc<InspectState>>) -> impl IntoResponse {
    let tunnels = state.inspector.list_tunnels();
    let html = UI_HTML.replace("{{TUNNELS_JSON}}", &serde_json::to_string(&tunnels).unwrap_or_default());
    Html(html)
}

async fn inspect_tunnel_ui(
    State(_state): State<Arc<InspectState>>,
    Path(tunnel_id): Path<String>,
) -> impl IntoResponse {
    let html = TUNNEL_HTML
        .replace("{{TUNNEL_ID}}", &tunnel_id);
    Html(html)
}

async fn list_tunnels(State(state): State<Arc<InspectState>>) -> impl IntoResponse {
    let tunnels = state.inspector.list_tunnels();
    Json(tunnels)
}

#[derive(Deserialize)]
struct ListParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize { 50 }

async fn list_requests(
    State(state): State<Arc<InspectState>>,
    Path(tunnel_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<ListParams>,
) -> impl IntoResponse {
    let requests = state.inspector.get_requests(&tunnel_id, params.limit, params.offset);
    Json(requests)
}

async fn get_request(
    State(state): State<Arc<InspectState>>,
    Path((tunnel_id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.inspector.get_request(&tunnel_id, &request_id) {
        Some(req) => Json(req).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clear_requests(
    State(state): State<Arc<InspectState>>,
    Path(tunnel_id): Path<String>,
) -> impl IntoResponse {
    state.inspector.clear_requests(&tunnel_id);
    StatusCode::NO_CONTENT
}

async fn get_stats(
    State(state): State<Arc<InspectState>>,
    Path(tunnel_id): Path<String>,
) -> impl IntoResponse {
    let stats = state.inspector.get_stats(&tunnel_id);
    Json(stats)
}

async fn websocket_handler(
    State(state): State<Arc<InspectState>>,
    Path(tunnel_id): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let inspector = state.inspector.clone();
    ws.on_upgrade(move |socket| handle_websocket(socket, inspector, tunnel_id))
}

async fn handle_websocket(socket: WebSocket, inspector: Arc<LocalInspector>, tunnel_id: String) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = inspector.subscribe();
    
    // Send events for this tunnel
    let tid = tunnel_id.clone();
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            // Filter events for this tunnel
            let should_send = match &event {
                InspectorEvent::RequestStarted(req) => req.tunnel_id == tid,
                InspectorEvent::ResponseReceived { .. } => {
                    // This is a simplification - in production we'd track request->tunnel mapping
                    true
                }
                InspectorEvent::RequestsCleared { tunnel_id: t } => *t == tid,
            };
            
            if should_send {
                if let Ok(json) = serde_json::to_string(&event) {
                    let msg: Message = Message::Text(json.into());
                    if sender.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    
    // Handle incoming messages (ping/pong, close)
    while let Some(result) = receiver.next().await {
        match result {
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }
    
    send_task.abort();
}

async fn style_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], CSS_CONTENT)
}

// ============================================================================
// HTML Templates
// ============================================================================

const HOME_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Inspector</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 NLAG Inspector</h1>
            <p>Local traffic inspection for your tunnels</p>
        </header>
        <main>
            <a href="/inspect" class="btn btn-primary">View Active Tunnels</a>
        </main>
    </div>
</body>
</html>"#;

const UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Inspector - Tunnels</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 NLAG Inspector</h1>
            <a href="/">Home</a>
        </header>
        <main>
            <h2>Active Tunnels</h2>
            <div id="tunnels" class="tunnel-list"></div>
        </main>
    </div>
    <script>
        const tunnels = {{TUNNELS_JSON}};
        const container = document.getElementById('tunnels');
        
        if (tunnels.length === 0) {
            container.innerHTML = '<p class="empty">No active tunnels. Start a tunnel with <code>nlag expose</code></p>';
        } else {
            tunnels.forEach(id => {
                const link = document.createElement('a');
                link.href = `/inspect/${id}`;
                link.className = 'tunnel-card';
                link.innerHTML = `
                    <span class="tunnel-id">${id}</span>
                    <span class="arrow">→</span>
                `;
                container.appendChild(link);
            });
        }
    </script>
</body>
</html>"#;

const TUNNEL_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Inspector - {{TUNNEL_ID}}</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Tunnel: <span class="tunnel-id">{{TUNNEL_ID}}</span></h1>
            <nav>
                <a href="/">Home</a>
                <a href="/inspect">All Tunnels</a>
                <button onclick="clearRequests()" class="btn btn-danger">Clear</button>
            </nav>
        </header>
        <main>
            <div class="stats" id="stats">Loading stats...</div>
            <div class="request-list" id="requests">
                <p class="loading">Loading requests...</p>
            </div>
        </main>
        <aside id="detail" class="detail-panel hidden">
            <button class="close-btn" onclick="closeDetail()">×</button>
            <div id="detail-content"></div>
        </aside>
    </div>
    <script>
        const tunnelId = '{{TUNNEL_ID}}';
        let requests = [];
        
        async function loadRequests() {
            const res = await fetch(`/api/tunnels/${tunnelId}/requests`);
            requests = await res.json();
            renderRequests();
        }
        
        async function loadStats() {
            const res = await fetch(`/api/tunnels/${tunnelId}/stats`);
            const stats = await res.json();
            document.getElementById('stats').innerHTML = `
                <div class="stat">Total: <strong>${stats.total_requests}</strong></div>
                <div class="stat">Avg Response: <strong>${stats.avg_response_ms.toFixed(1)}ms</strong></div>
            `;
        }
        
        function renderRequests() {
            const container = document.getElementById('requests');
            if (requests.length === 0) {
                container.innerHTML = '<p class="empty">No requests yet. Traffic will appear here.</p>';
                return;
            }
            
            container.innerHTML = requests.map(req => `
                <div class="request-row ${getStatusClass(req.response_status)}" onclick="showDetail('${req.id}')">
                    <span class="method ${req.method.toLowerCase()}">${req.method}</span>
                    <span class="path">${req.path}</span>
                    <span class="status">${req.response_status || 'pending'}</span>
                    <span class="duration">${req.duration_ms ? req.duration_ms + 'ms' : '-'}</span>
                    <span class="time">${new Date(req.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('');
        }
        
        function getStatusClass(status) {
            if (!status) return '';
            if (status < 300) return 'success';
            if (status < 400) return 'redirect';
            if (status < 500) return 'client-error';
            return 'server-error';
        }
        
        async function showDetail(id) {
            const res = await fetch(`/api/tunnels/${tunnelId}/requests/${id}`);
            const req = await res.json();
            
            document.getElementById('detail-content').innerHTML = `
                <h3>${req.method} ${req.path}</h3>
                <p class="timestamp">${new Date(req.timestamp).toLocaleString()}</p>
                
                <h4>Request Headers</h4>
                <pre>${req.headers.map(([k,v]) => `${k}: ${v}`).join('\n')}</pre>
                
                ${req.body ? `<h4>Request Body</h4><pre>${req.body}</pre>` : ''}
                
                ${req.response_status ? `
                    <h4>Response: ${req.response_status}</h4>
                    <p>Duration: ${req.duration_ms}ms</p>
                    ${req.response_headers ? `<h4>Response Headers</h4><pre>${req.response_headers.map(([k,v]) => `${k}: ${v}`).join('\n')}</pre>` : ''}
                    ${req.response_body ? `<h4>Response Body</h4><pre>${req.response_body}</pre>` : ''}
                ` : '<p class="pending">Response pending...</p>'}
            `;
            
            document.getElementById('detail').classList.remove('hidden');
        }
        
        function closeDetail() {
            document.getElementById('detail').classList.add('hidden');
        }
        
        async function clearRequests() {
            await fetch(`/api/tunnels/${tunnelId}/clear`, { method: 'POST' });
            requests = [];
            renderRequests();
        }
        
        // WebSocket for live updates
        const ws = new WebSocket(`ws://${location.host}/ws/${tunnelId}`);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'request_started') {
                requests.unshift(data);
                renderRequests();
            } else if (data.type === 'response_received') {
                const req = requests.find(r => r.id === data.request_id);
                if (req) {
                    req.response_status = data.status;
                    req.duration_ms = data.duration_ms;
                    renderRequests();
                }
            } else if (data.type === 'requests_cleared') {
                requests = [];
                renderRequests();
            }
            loadStats();
        };
        
        // Initial load
        loadRequests();
        loadStats();
    </script>
</body>
</html>"#;

const CSS_CONTENT: &str = r#"
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #1a1a2e;
    color: #eee;
    min-height: 100vh;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 0;
    border-bottom: 1px solid #333;
    margin-bottom: 20px;
}

header h1 { font-size: 1.5rem; }
header a { color: #888; text-decoration: none; margin-left: 20px; }
header a:hover { color: #fff; }

.btn {
    padding: 8px 16px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}

.btn-primary { background: #4f46e5; color: white; }
.btn-danger { background: #dc2626; color: white; }

.tunnel-list {
    display: grid;
    gap: 10px;
}

.tunnel-card {
    display: flex;
    justify-content: space-between;
    padding: 15px 20px;
    background: #252540;
    border-radius: 8px;
    text-decoration: none;
    color: #fff;
    transition: background 0.2s;
}

.tunnel-card:hover { background: #333358; }

.stats {
    display: flex;
    gap: 30px;
    padding: 15px 0;
    border-bottom: 1px solid #333;
    margin-bottom: 20px;
}

.stat strong { color: #4f46e5; }

.request-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.request-row {
    display: grid;
    grid-template-columns: 60px 1fr 80px 80px 100px;
    gap: 10px;
    padding: 10px 15px;
    background: #252540;
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.2s;
    border-left: 3px solid transparent;
}

.request-row:hover { background: #333358; }
.request-row.success { border-left-color: #22c55e; }
.request-row.redirect { border-left-color: #f59e0b; }
.request-row.client-error { border-left-color: #ef4444; }
.request-row.server-error { border-left-color: #dc2626; }

.method {
    font-weight: bold;
    font-size: 12px;
}

.method.get { color: #22c55e; }
.method.post { color: #3b82f6; }
.method.put { color: #f59e0b; }
.method.delete { color: #ef4444; }

.path { color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.status { text-align: center; }
.duration { text-align: right; color: #888; }
.time { text-align: right; color: #666; font-size: 12px; }

.detail-panel {
    position: fixed;
    top: 0;
    right: 0;
    width: 500px;
    height: 100vh;
    background: #1e1e32;
    padding: 20px;
    overflow-y: auto;
    box-shadow: -5px 0 20px rgba(0,0,0,0.5);
}

.detail-panel.hidden { display: none; }

.close-btn {
    position: absolute;
    top: 10px;
    right: 10px;
    background: none;
    border: none;
    color: #888;
    font-size: 24px;
    cursor: pointer;
}

.detail-panel h3 { margin-bottom: 10px; }
.detail-panel h4 { margin-top: 20px; margin-bottom: 10px; color: #888; }
.detail-panel pre {
    background: #252540;
    padding: 10px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
}

.empty { color: #666; text-align: center; padding: 40px; }
.empty code { background: #333; padding: 2px 6px; border-radius: 4px; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_local_inspector_creation() {
        let inspector = LocalInspector::new();
        assert!(inspector.list_tunnels().is_empty());
    }
    
    #[test]
    fn test_record_request() {
        let inspector = LocalInspector::new();
        
        let request = CapturedRequest {
            id: "req-1".to_string(),
            tunnel_id: "tunnel-1".to_string(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: None,
            content_type: None,
            content_length: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            duration_ms: None,
            client_addr: None,
        };
        
        inspector.record_request(request);
        
        let tunnels = inspector.list_tunnels();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0], "tunnel-1");
        
        let requests = inspector.get_requests("tunnel-1", 10, 0);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/test");
    }
    
    #[test]
    fn test_record_response() {
        let inspector = LocalInspector::new();
        
        let request = CapturedRequest {
            id: "req-1".to_string(),
            tunnel_id: "tunnel-1".to_string(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: vec![],
            body: None,
            content_type: None,
            content_length: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            duration_ms: None,
            client_addr: None,
        };
        
        inspector.record_request(request);
        inspector.record_response("req-1", 200, 42, vec![], Some("OK".to_string()));
        
        let req = inspector.get_request("tunnel-1", "req-1").unwrap();
        assert_eq!(req.response_status, Some(200));
        assert_eq!(req.duration_ms, Some(42));
    }
    
    #[test]
    fn test_clear_requests() {
        let inspector = LocalInspector::new();
        
        let request = CapturedRequest {
            id: "req-1".to_string(),
            tunnel_id: "tunnel-1".to_string(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: vec![],
            body: None,
            content_type: None,
            content_length: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            duration_ms: None,
            client_addr: None,
        };
        
        inspector.record_request(request);
        assert_eq!(inspector.get_requests("tunnel-1", 10, 0).len(), 1);
        
        inspector.clear_requests("tunnel-1");
        assert!(inspector.get_requests("tunnel-1", 10, 0).is_empty());
    }
}
