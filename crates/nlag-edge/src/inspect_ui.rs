//! Inspection Web UI
//!
//! Provides a web-based interface for viewing live HTTP requests,
//! similar to ngrok's inspect feature.

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;

use nlag_common::types::TunnelId;

use crate::inspect::{InspectorEvent, RequestInspector};

/// State for the inspection UI
pub struct InspectUiState {
    pub inspector: Arc<RequestInspector>,
}

/// Create the inspection UI router
pub fn create_inspect_router(inspector: Arc<RequestInspector>) -> Router {
    let state = Arc::new(InspectUiState { inspector });

    Router::new()
        // Main inspect UI
        .route("/inspect", get(inspect_home))
        .route("/inspect/ui", get(inspect_ui))
        .route("/inspect/ui/:tunnel_id", get(inspect_tunnel_ui))
        
        // API endpoints
        .route("/inspect/api/tunnels", get(list_tunnels))
        .route("/inspect/api/tunnels/:tunnel_id/requests", get(list_requests))
        .route("/inspect/api/tunnels/:tunnel_id/requests/:request_id", get(get_request))
        .route("/inspect/api/tunnels/:tunnel_id/requests", post(clear_requests))
        .route("/inspect/api/tunnels/:tunnel_id/stats", get(get_stats))
        
        // WebSocket for live updates
        .route("/inspect/ws/:tunnel_id", get(websocket_handler))
        
        // Static assets
        .route("/inspect/assets/style.css", get(style_css))
        .with_state(state)
}

/// Query parameters for list requests
#[derive(Debug, Deserialize)]
pub struct ListRequestsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

/// Inspect home page
async fn inspect_home() -> impl IntoResponse {
    Html(INSPECT_HOME_HTML)
}

/// Main inspect UI
async fn inspect_ui() -> impl IntoResponse {
    Html(INSPECT_UI_HTML)
}

/// Tunnel-specific inspect UI
async fn inspect_tunnel_ui(Path(tunnel_id): Path<String>) -> impl IntoResponse {
    let html = INSPECT_TUNNEL_HTML.replace("{{TUNNEL_ID}}", &tunnel_id);
    Html(html)
}

/// List tunnels with captured requests
async fn list_tunnels(State(state): State<Arc<InspectUiState>>) -> impl IntoResponse {
    let tunnels = state.inspector.list_tunnels_with_data();
    Json(serde_json::json!({
        "tunnels": tunnels
    }))
}

/// List requests for a tunnel
async fn list_requests(
    State(state): State<Arc<InspectUiState>>,
    Path(tunnel_id): Path<String>,
    Query(query): Query<ListRequestsQuery>,
) -> impl IntoResponse {
    let tunnel_id = match tunnel_id.parse::<TunnelId>() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid tunnel ID"
            }))).into_response();
        }
    };

    let requests = state.inspector.list_requests(tunnel_id, query.limit, query.offset);
    let stats = state.inspector.get_stats(tunnel_id);

    Json(serde_json::json!({
        "requests": requests,
        "total": stats.total_count,
        "captured": stats.captured_count,
    })).into_response()
}

/// Get a specific request
async fn get_request(
    State(state): State<Arc<InspectUiState>>,
    Path((tunnel_id, request_id)): Path<(String, u64)>,
) -> impl IntoResponse {
    let tunnel_id = match tunnel_id.parse::<TunnelId>() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid tunnel ID"
            }))).into_response();
        }
    };

    match state.inspector.get_request(tunnel_id, request_id) {
        Some(request) => Json(request).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Request not found"
        }))).into_response(),
    }
}

/// Clear requests for a tunnel
async fn clear_requests(
    State(state): State<Arc<InspectUiState>>,
    Path(tunnel_id): Path<String>,
) -> impl IntoResponse {
    let tunnel_id = match tunnel_id.parse::<TunnelId>() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid tunnel ID"
            }))).into_response();
        }
    };

    state.inspector.clear_requests(tunnel_id);
    Json(serde_json::json!({ "success": true })).into_response()
}

/// Get stats for a tunnel
async fn get_stats(
    State(state): State<Arc<InspectUiState>>,
    Path(tunnel_id): Path<String>,
) -> impl IntoResponse {
    let tunnel_id = match tunnel_id.parse::<TunnelId>() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid tunnel ID"
            }))).into_response();
        }
    };

    let stats = state.inspector.get_stats(tunnel_id);
    Json(stats).into_response()
}

/// WebSocket handler for live updates
async fn websocket_handler(
    State(state): State<Arc<InspectUiState>>,
    Path(tunnel_id): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let tunnel_id = match tunnel_id.parse::<TunnelId>() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid tunnel ID").into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_websocket(socket, state, tunnel_id))
        .into_response()
}

/// Handle WebSocket connection
async fn handle_websocket(socket: WebSocket, state: Arc<InspectUiState>, tunnel_id: TunnelId) {
    let (mut sender, mut receiver) = socket.split();
    
    // Subscribe to events
    let mut event_rx = state.inspector.subscribe();
    
    // Send events to client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            // Filter events for this tunnel
            let matches = match &event {
                InspectorEvent::RequestStarted(req) => req.tunnel_id == tunnel_id,
                InspectorEvent::RequestCompleted(req) => req.tunnel_id == tunnel_id,
                InspectorEvent::RequestFailed(req) => req.tunnel_id == tunnel_id,
                InspectorEvent::RequestsCleared(id) => *id == tunnel_id,
            };
            
            if matches {
                if let Ok(json) = serde_json::to_string(&event) {
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    
    // Handle incoming messages (ping/pong, close)
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Ping(_data)) => {
                    // Pong is automatically sent by axum
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    });
    
    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}

/// CSS styles
async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        INSPECT_CSS,
    )
}

/// Inspect home HTML
const INSPECT_HOME_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Inspect</title>
    <link rel="stylesheet" href="/inspect/assets/style.css">
    <style>
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 2rem; }
        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .header p { color: #666; }
        .tunnels-section { margin-bottom: 2rem; }
        .tunnels-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 1rem; }
        .tunnel-card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 1.5rem; cursor: pointer; transition: all 0.2s; }
        .tunnel-card:hover { border-color: #4f46e5; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.15); transform: translateY(-2px); }
        .tunnel-id { font-family: monospace; font-size: 0.9rem; color: #4f46e5; word-break: break-all; margin-bottom: 0.75rem; }
        .tunnel-stats { display: flex; gap: 1.5rem; color: #666; font-size: 0.875rem; }
        .tunnel-stat { display: flex; align-items: center; gap: 0.25rem; }
        .stat-icon { font-size: 1rem; }
        .empty-state { text-align: center; padding: 3rem; background: #f9fafb; border-radius: 8px; color: #666; }
        .empty-icon { font-size: 3rem; margin-bottom: 1rem; }
        .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
        .card h2 { margin-top: 0; margin-bottom: 1rem; font-size: 1.25rem; }
        .card ol, .card ul { margin: 0; padding-left: 1.5rem; }
        .card li { margin-bottom: 0.5rem; }
        .card code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-size: 0.875rem; }
        .footer { text-align: center; color: #999; margin-top: 2rem; font-size: 0.875rem; }
        .loading { text-align: center; padding: 2rem; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔍 NLAG Inspect</h1>
            <p>Real-time HTTP request inspection</p>
        </header>
        
        <main class="main">
            <section class="tunnels-section">
                <h2>Active Tunnels</h2>
                <div id="tunnels-container" class="loading">
                    Loading tunnels...
                </div>
            </section>
            
            <div class="card">
                <h2>How to Use</h2>
                <p>The inspector captures HTTP requests/responses passing through your tunnels.</p>
                <ol>
                    <li>Start a tunnel with your agent: <code>nlag expose http 3000</code></li>
                    <li>Click on any active tunnel above to see live requests</li>
                    <li>Or visit <code>/inspect/ui/{tunnel_id}</code> directly</li>
                </ol>
            </div>
            
            <div class="card">
                <h2>Features</h2>
                <ul>
                    <li>✅ Live request/response viewing</li>
                    <li>✅ Request headers and bodies</li>
                    <li>✅ Response timing</li>
                    <li>✅ WebSocket connections</li>
                    <li>✅ Request replay</li>
                </ul>
            </div>
        </main>
        
        <footer class="footer">
            NLAG Edge Server
        </footer>
    </div>
    
    <script>
        async function loadTunnels() {
            try {
                const response = await fetch('/inspect/api/tunnels');
                const data = await response.json();
                renderTunnels(data.tunnels || []);
            } catch (e) {
                document.getElementById('tunnels-container').innerHTML = 
                    '<div class="empty-state"><p>Failed to load tunnels</p></div>';
            }
        }
        
        function renderTunnels(tunnels) {
            const container = document.getElementById('tunnels-container');
            
            if (tunnels.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">📡</div>
                        <h3>No Active Tunnels</h3>
                        <p>Start an agent to create a tunnel and see it here</p>
                    </div>
                `;
                return;
            }
            
            container.className = 'tunnels-grid';
            container.innerHTML = tunnels.map(t => `
                <div class="tunnel-card" onclick="window.location.href='/inspect/ui/${t.tunnel_id}'">
                    <div class="tunnel-id">${t.tunnel_id}</div>
                    <div class="tunnel-stats">
                        <span class="tunnel-stat">
                            <span class="stat-icon">📨</span>
                            ${t.request_count} captured
                        </span>
                        <span class="tunnel-stat">
                            <span class="stat-icon">📊</span>
                            ${t.total_requests} total
                        </span>
                    </div>
                </div>
            `).join('');
        }
        
        // Load tunnels on page load and refresh every 5 seconds
        loadTunnels();
        setInterval(loadTunnels, 5000);
    </script>
</body>
</html>"#;

/// Main inspect UI HTML
const INSPECT_UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Inspect</title>
    <link rel="stylesheet" href="/inspect/assets/style.css">
    <style>
        .tunnel-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; padding: 1rem; }
        .tunnel-item { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; cursor: pointer; transition: all 0.2s; }
        .tunnel-item:hover { border-color: #4f46e5; box-shadow: 0 2px 8px rgba(79, 70, 229, 0.15); }
        .tunnel-item-id { font-family: monospace; font-size: 0.8rem; color: #4f46e5; word-break: break-all; margin-bottom: 0.5rem; }
        .tunnel-item-stats { font-size: 0.875rem; color: #666; }
    </style>
</head>
<body>
    <div class="inspect-app">
        <header class="inspect-header">
            <div class="header-left">
                <a href="/inspect" class="back-link">← Home</a>
                <h1>🔍 NLAG Inspect</h1>
            </div>
            <div class="header-right">
                <input type="text" id="tunnel-input" placeholder="Enter Tunnel ID..." class="tunnel-input">
                <button onclick="connectTunnel()" class="btn btn-primary">Connect</button>
            </div>
        </header>
        
        <main class="inspect-main">
            <div id="tunnel-list" class="tunnel-list">
                <p style="text-align: center; color: #666; grid-column: 1 / -1;">Loading tunnels...</p>
            </div>
        </main>
    </div>
    
    <script>
        function connectTunnel() {
            const tunnelId = document.getElementById('tunnel-input').value.trim();
            if (tunnelId) {
                window.location.href = '/inspect/ui/' + encodeURIComponent(tunnelId);
            }
        }
        
        document.getElementById('tunnel-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') connectTunnel();
        });
        
        async function loadTunnels() {
            try {
                const response = await fetch('/inspect/api/tunnels');
                const data = await response.json();
                renderTunnelList(data.tunnels || []);
            } catch (e) {
                document.getElementById('tunnel-list').innerHTML = 
                    '<p style="text-align: center; color: #666; grid-column: 1 / -1;">Failed to load tunnels</p>';
            }
        }
        
        function renderTunnelList(tunnels) {
            const container = document.getElementById('tunnel-list');
            
            if (tunnels.length === 0) {
                container.innerHTML = `
                    <div class="empty-state" style="grid-column: 1 / -1;">
                        <div class="empty-icon">📡</div>
                        <h2>No Active Tunnels</h2>
                        <p>Start an agent to create a tunnel, or enter a tunnel ID above</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = tunnels.map(t => `
                <div class="tunnel-item" onclick="window.location.href='/inspect/ui/${t.tunnel_id}'">
                    <div class="tunnel-item-id">${t.tunnel_id}</div>
                    <div class="tunnel-item-stats">
                        📨 ${t.request_count} captured &nbsp; 📊 ${t.total_requests} total
                    </div>
                </div>
            `).join('');
        }
        
        loadTunnels();
        setInterval(loadTunnels, 5000);
    </script>
</body>
</html>"#;

/// Tunnel-specific inspect UI HTML
const INSPECT_TUNNEL_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inspect - {{TUNNEL_ID}}</title>
    <link rel="stylesheet" href="/inspect/assets/style.css">
</head>
<body>
    <div class="inspect-app">
        <header class="inspect-header">
            <div class="header-left">
                <a href="/inspect/ui" class="back-link">← Back</a>
                <h1>🔍 Tunnel Inspector</h1>
                <span class="tunnel-id" id="tunnel-id">{{TUNNEL_ID}}</span>
            </div>
            <div class="header-right">
                <span class="connection-status" id="connection-status">
                    <span class="status-dot disconnected"></span>
                    Connecting...
                </span>
                <button onclick="clearRequests()" class="btn btn-secondary">Clear</button>
            </div>
        </header>
        
        <main class="inspect-content">
            <!-- Request List -->
            <aside class="request-list" id="request-list">
                <div class="list-header">
                    <span class="request-count" id="request-count">0 requests</span>
                </div>
                <div class="list-items" id="list-items">
                    <div class="empty-list">
                        <p>No requests yet</p>
                        <p class="hint">Make a request to your tunnel to see it here</p>
                    </div>
                </div>
            </aside>
            
            <!-- Request Detail -->
            <section class="request-detail" id="request-detail">
                <div class="detail-empty">
                    <p>Select a request to view details</p>
                </div>
            </section>
        </main>
    </div>
    
    <script>
        const tunnelId = '{{TUNNEL_ID}}';
        let ws = null;
        let requests = [];
        let selectedRequest = null;
        
        // Connect WebSocket
        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/inspect/ws/${tunnelId}`);
            
            ws.onopen = () => {
                updateConnectionStatus(true);
                loadInitialRequests();
            };
            
            ws.onclose = () => {
                updateConnectionStatus(false);
                setTimeout(connect, 3000);
            };
            
            ws.onerror = () => {
                updateConnectionStatus(false);
            };
            
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleEvent(data);
            };
        }
        
        function updateConnectionStatus(connected) {
            const status = document.getElementById('connection-status');
            status.innerHTML = connected
                ? '<span class="status-dot connected"></span> Connected'
                : '<span class="status-dot disconnected"></span> Disconnected';
        }
        
        async function loadInitialRequests() {
            try {
                const response = await fetch(`/inspect/api/tunnels/${tunnelId}/requests`);
                const data = await response.json();
                requests = data.requests || [];
                renderRequestList();
            } catch (e) {
                console.error('Failed to load requests:', e);
            }
        }
        
        function handleEvent(event) {
            if (event.RequestStarted) {
                requests.unshift(event.RequestStarted);
                renderRequestList();
            } else if (event.RequestCompleted) {
                updateRequest(event.RequestCompleted);
            } else if (event.RequestFailed) {
                updateRequest(event.RequestFailed);
            } else if (event.RequestsCleared) {
                requests = [];
                selectedRequest = null;
                renderRequestList();
                renderRequestDetail();
            }
        }
        
        function updateRequest(updated) {
            const idx = requests.findIndex(r => r.id === updated.id);
            if (idx >= 0) {
                requests[idx] = updated;
                renderRequestList();
                if (selectedRequest && selectedRequest.id === updated.id) {
                    selectedRequest = updated;
                    renderRequestDetail();
                }
            }
        }
        
        function renderRequestList() {
            const container = document.getElementById('list-items');
            const count = document.getElementById('request-count');
            
            count.textContent = `${requests.length} requests`;
            
            if (requests.length === 0) {
                container.innerHTML = `
                    <div class="empty-list">
                        <p>No requests yet</p>
                        <p class="hint">Make a request to your tunnel to see it here</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = requests.map(req => `
                <div class="request-item ${selectedRequest?.id === req.id ? 'selected' : ''} ${req.state}" 
                     onclick="selectRequest(${req.id})">
                    <div class="request-method ${getMethodClass(req.method)}">${req.method}</div>
                    <div class="request-info">
                        <div class="request-path">${req.path}</div>
                        <div class="request-meta">
                            <span class="status-badge ${getStatusClass(req.response_status)}">${req.response_status || '...'}</span>
                            <span class="duration">${req.duration_ms ? req.duration_ms + 'ms' : ''}</span>
                            <span class="time">${formatTime(req.timestamp)}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        function selectRequest(id) {
            selectedRequest = requests.find(r => r.id === id);
            renderRequestList();
            renderRequestDetail();
        }
        
        function renderRequestDetail() {
            const container = document.getElementById('request-detail');
            
            if (!selectedRequest) {
                container.innerHTML = `
                    <div class="detail-empty">
                        <p>Select a request to view details</p>
                    </div>
                `;
                return;
            }
            
            const req = selectedRequest;
            
            container.innerHTML = `
                <div class="detail-header">
                    <div class="detail-title">
                        <span class="request-method ${getMethodClass(req.method)}">${req.method}</span>
                        <span class="detail-path">${req.path}${req.query ? '?' + req.query : ''}</span>
                    </div>
                    <div class="detail-meta">
                        <span class="status-badge ${getStatusClass(req.response_status)}">${req.response_status || 'Pending'} ${req.response_status_text || ''}</span>
                        <span class="duration">${req.duration_ms ? req.duration_ms + 'ms' : ''}</span>
                    </div>
                </div>
                
                <div class="detail-tabs">
                    <button class="tab active" onclick="showTab('request')">Request</button>
                    <button class="tab" onclick="showTab('response')">Response</button>
                    <button class="tab" onclick="showTab('timing')">Timing</button>
                </div>
                
                <div class="detail-content">
                    <div class="tab-panel active" id="tab-request">
                        <div class="section">
                            <h3>Headers</h3>
                            <table class="headers-table">
                                ${req.request_headers.map(([k, v]) => `
                                    <tr>
                                        <td class="header-name">${escapeHtml(k)}</td>
                                        <td class="header-value">${escapeHtml(v)}</td>
                                    </tr>
                                `).join('') || '<tr><td colspan="2">No headers</td></tr>'}
                            </table>
                        </div>
                        
                        ${req.request_body ? `
                            <div class="section">
                                <h3>Body <span class="body-size">(${req.request_body_size} bytes)</span></h3>
                                <pre class="body-content">${escapeHtml(req.request_body)}</pre>
                            </div>
                        ` : ''}
                    </div>
                    
                    <div class="tab-panel" id="tab-response">
                        <div class="section">
                            <h3>Headers</h3>
                            <table class="headers-table">
                                ${req.response_headers.map(([k, v]) => `
                                    <tr>
                                        <td class="header-name">${escapeHtml(k)}</td>
                                        <td class="header-value">${escapeHtml(v)}</td>
                                    </tr>
                                `).join('') || '<tr><td colspan="2">No headers</td></tr>'}
                            </table>
                        </div>
                        
                        ${req.response_body ? `
                            <div class="section">
                                <h3>Body <span class="body-size">(${req.response_body_size} bytes)</span></h3>
                                <pre class="body-content">${escapeHtml(req.response_body)}</pre>
                            </div>
                        ` : ''}
                        
                        ${req.error ? `
                            <div class="section error-section">
                                <h3>Error</h3>
                                <pre class="error-content">${escapeHtml(req.error)}</pre>
                            </div>
                        ` : ''}
                    </div>
                    
                    <div class="tab-panel" id="tab-timing">
                        <div class="section">
                            <h3>Timing Information</h3>
                            <div class="timing-info">
                                <div class="timing-row">
                                    <span class="timing-label">Started</span>
                                    <span class="timing-value">${new Date(req.timestamp).toLocaleString()}</span>
                                </div>
                                <div class="timing-row">
                                    <span class="timing-label">Duration</span>
                                    <span class="timing-value">${req.duration_ms ? req.duration_ms + ' ms' : 'In progress...'}</span>
                                </div>
                                <div class="timing-row">
                                    <span class="timing-label">Client IP</span>
                                    <span class="timing-value">${req.client_ip}</span>
                                </div>
                                <div class="timing-row">
                                    <span class="timing-label">State</span>
                                    <span class="timing-value state-${req.state}">${req.state}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            
            document.querySelector(`.tab[onclick="showTab('${tabName}')"]`).classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
        }
        
        function getMethodClass(method) {
            const classes = {
                'GET': 'method-get',
                'POST': 'method-post',
                'PUT': 'method-put',
                'DELETE': 'method-delete',
                'PATCH': 'method-patch',
            };
            return classes[method] || 'method-other';
        }
        
        function getStatusClass(status) {
            if (!status) return 'status-pending';
            if (status < 300) return 'status-success';
            if (status < 400) return 'status-redirect';
            if (status < 500) return 'status-client-error';
            return 'status-server-error';
        }
        
        function formatTime(timestamp) {
            return new Date(timestamp).toLocaleTimeString();
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
        
        async function clearRequests() {
            try {
                await fetch(`/inspect/api/tunnels/${tunnelId}/requests`, { method: 'POST' });
            } catch (e) {
                console.error('Failed to clear requests:', e);
            }
        }
        
        // Start connection
        connect();
    </script>
</body>
</html>"#;

/// CSS styles for inspect UI
const INSPECT_CSS: &str = r#"
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f0f23;
    color: #e0e0e0;
    min-height: 100vh;
}

/* Home page styles */
.container {
    max-width: 800px;
    margin: 0 auto;
    padding: 40px 20px;
}

.header {
    text-align: center;
    margin-bottom: 40px;
}

.header h1 {
    font-size: 2.5rem;
    margin-bottom: 10px;
}

.header p {
    color: #888;
    font-size: 1.2rem;
}

.card {
    background: #1a1a2e;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}

.card h2 {
    margin-bottom: 16px;
    color: #fff;
}

.card p, .card li {
    color: #b0b0b0;
    line-height: 1.6;
}

.card ol, .card ul {
    margin-left: 24px;
}

.card li {
    margin: 8px 0;
}

.card code {
    background: #2a2a4a;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'SF Mono', Monaco, monospace;
    color: #66d9ef;
}

.footer {
    text-align: center;
    color: #666;
    margin-top: 40px;
}

/* Inspect App Styles */
.inspect-app {
    display: flex;
    flex-direction: column;
    height: 100vh;
}

.inspect-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
}

.header-left {
    display: flex;
    align-items: center;
    gap: 16px;
}

.header-left h1 {
    font-size: 1.25rem;
}

.back-link {
    color: #888;
    text-decoration: none;
    font-size: 0.9rem;
}

.back-link:hover {
    color: #fff;
}

.tunnel-id {
    background: #2a2a4a;
    padding: 4px 12px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.9rem;
    color: #66d9ef;
}

.header-right {
    display: flex;
    align-items: center;
    gap: 12px;
}

.tunnel-input {
    background: #2a2a4a;
    border: 1px solid #3a3a5a;
    border-radius: 6px;
    padding: 8px 12px;
    color: #fff;
    width: 300px;
}

.tunnel-input:focus {
    outline: none;
    border-color: #667eea;
}

.connection-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
    color: #888;
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}

.status-dot.connected {
    background: #22c55e;
    box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
}

.status-dot.disconnected {
    background: #ef4444;
}

.btn {
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff;
}

.btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.btn-secondary {
    background: #2a2a4a;
    color: #e0e0e0;
    border: 1px solid #3a3a5a;
}

.btn-secondary:hover {
    background: #3a3a5a;
}

/* Empty state */
.inspect-main {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
}

.empty-state {
    text-align: center;
}

.empty-icon {
    font-size: 4rem;
    margin-bottom: 20px;
}

.empty-state h2 {
    font-size: 1.5rem;
    margin-bottom: 8px;
}

.empty-state p {
    color: #888;
}

/* Inspect content layout */
.inspect-content {
    flex: 1;
    display: flex;
    overflow: hidden;
}

/* Request list */
.request-list {
    width: 400px;
    background: #1a1a2e;
    border-right: 1px solid #2a2a4a;
    display: flex;
    flex-direction: column;
}

.list-header {
    padding: 12px 16px;
    border-bottom: 1px solid #2a2a4a;
}

.request-count {
    font-size: 0.85rem;
    color: #888;
}

.list-items {
    flex: 1;
    overflow-y: auto;
}

.empty-list {
    padding: 40px 20px;
    text-align: center;
    color: #666;
}

.empty-list .hint {
    font-size: 0.85rem;
    margin-top: 8px;
}

.request-item {
    display: flex;
    padding: 12px 16px;
    border-bottom: 1px solid #2a2a4a;
    cursor: pointer;
    transition: background 0.15s;
}

.request-item:hover {
    background: #222244;
}

.request-item.selected {
    background: #2a2a5a;
    border-left: 3px solid #667eea;
}

.request-item.failed {
    border-left: 3px solid #ef4444;
}

.request-method {
    font-family: monospace;
    font-size: 0.75rem;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: 4px;
    margin-right: 12px;
}

.method-get { background: #22c55e20; color: #22c55e; }
.method-post { background: #3b82f620; color: #3b82f6; }
.method-put { background: #f59e0b20; color: #f59e0b; }
.method-delete { background: #ef444420; color: #ef4444; }
.method-patch { background: #8b5cf620; color: #8b5cf6; }
.method-other { background: #6b728020; color: #9ca3af; }

.request-info {
    flex: 1;
    min-width: 0;
}

.request-path {
    font-size: 0.9rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.request-meta {
    display: flex;
    gap: 12px;
    margin-top: 4px;
    font-size: 0.8rem;
    color: #888;
}

.status-badge {
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
}

.status-pending { background: #6b728020; color: #9ca3af; }
.status-success { background: #22c55e20; color: #22c55e; }
.status-redirect { background: #3b82f620; color: #3b82f6; }
.status-client-error { background: #f59e0b20; color: #f59e0b; }
.status-server-error { background: #ef444420; color: #ef4444; }

/* Request detail */
.request-detail {
    flex: 1;
    background: #0f0f23;
    overflow-y: auto;
}

.detail-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #666;
}

.detail-header {
    padding: 16px 20px;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
}

.detail-title {
    display: flex;
    align-items: center;
    gap: 12px;
}

.detail-path {
    font-family: monospace;
    font-size: 1rem;
    word-break: break-all;
}

.detail-meta {
    display: flex;
    gap: 16px;
    margin-top: 8px;
}

.duration {
    color: #888;
}

/* Tabs */
.detail-tabs {
    display: flex;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
}

.tab {
    padding: 12px 20px;
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 0.9rem;
    border-bottom: 2px solid transparent;
}

.tab:hover {
    color: #e0e0e0;
}

.tab.active {
    color: #fff;
    border-bottom-color: #667eea;
}

.tab-panel {
    display: none;
    padding: 20px;
}

.tab-panel.active {
    display: block;
}

.section {
    margin-bottom: 24px;
}

.section h3 {
    font-size: 0.9rem;
    font-weight: 600;
    margin-bottom: 12px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.body-size {
    font-weight: normal;
    text-transform: none;
}

/* Headers table */
.headers-table {
    width: 100%;
    border-collapse: collapse;
}

.headers-table tr {
    border-bottom: 1px solid #2a2a4a;
}

.headers-table td {
    padding: 8px 0;
    vertical-align: top;
}

.header-name {
    color: #66d9ef;
    font-family: monospace;
    font-size: 0.85rem;
    width: 200px;
}

.header-value {
    font-family: monospace;
    font-size: 0.85rem;
    word-break: break-all;
}

/* Body content */
.body-content {
    background: #1a1a2e;
    padding: 16px;
    border-radius: 8px;
    font-family: monospace;
    font-size: 0.85rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.error-section h3 {
    color: #ef4444;
}

.error-content {
    background: #2a1a1a;
    border: 1px solid #ef444440;
    color: #ef4444;
}

/* Timing info */
.timing-info {
    background: #1a1a2e;
    border-radius: 8px;
    padding: 16px;
}

.timing-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #2a2a4a;
}

.timing-row:last-child {
    border-bottom: none;
}

.timing-label {
    color: #888;
}

.timing-value {
    font-family: monospace;
}

.state-pending { color: #f59e0b; }
.state-completed { color: #22c55e; }
.state-failed { color: #ef4444; }
.state-timeout { color: #ef4444; }
"#;
