//! Dashboard UI Module
//!
//! Provides a simple web-based dashboard for monitoring NLAG.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::api::ApiState;

/// Create the dashboard router
pub fn create_dashboard_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/data", get(dashboard_data))
        .route("/dashboard/agents", get(agents_page))
        .route("/dashboard/tunnels", get(tunnels_page))
        .with_state(state)
}

/// Dashboard data for frontend
#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub stats: DashboardStats,
    pub recent_events: Vec<DashboardEvent>,
    pub agents: Vec<AgentSummary>,
    pub tunnels: Vec<TunnelSummary>,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_agents: u64,
    pub active_agents: u64,
    pub total_tunnels: u64,
    pub active_tunnels: u64,
    pub requests_per_minute: u64,
    pub bytes_transferred: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardEvent {
    pub timestamp: String,
    pub event_type: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub tunnels: u64,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct TunnelSummary {
    pub id: String,
    pub subdomain: String,
    pub protocol: String,
    pub status: String,
    pub requests: u64,
}

/// Main dashboard page
async fn dashboard_page(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// Agents management page
async fn agents_page(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    Html(AGENTS_HTML)
}

/// Tunnels management page
async fn tunnels_page(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    Html(TUNNELS_HTML)
}

/// Get dashboard data as JSON
async fn dashboard_data(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    // Get stats from store
    let stats = state.store.get_stats().await.unwrap_or(crate::api::StatsResponse {
        total_users: 0,
        total_agents: 0,
        total_tunnels: 0,
        active_connections: 0,
        bytes_transferred_24h: 0,
    });

    // Get metrics from store
    let (bytes_transferred, requests, _active_connections) = state.store.get_metrics();

    // Calculate uptime (assuming server start time is tracked)
    static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let uptime = START_TIME.get_or_init(std::time::Instant::now).elapsed().as_secs();

    // Get agents from store
    let agents_list = state.store.list_agents("__all__").await.unwrap_or_default();
    let agents: Vec<AgentSummary> = agents_list.iter().map(|a| AgentSummary {
        id: a.id.clone(),
        name: a.name.clone().unwrap_or_else(|| "Unnamed".to_string()),
        status: a.status.clone(),
        tunnels: a.tunnels.len() as u64,
        last_seen: a.last_seen.clone(),
    }).collect();

    // Get tunnels from store (using a placeholder user for now)
    let tunnels_list = state.store.list_tunnels("__all__").await.unwrap_or_default();
    let tunnels: Vec<TunnelSummary> = tunnels_list.iter().map(|t| TunnelSummary {
        id: t.id.clone(),
        subdomain: t.subdomain.clone(),
        protocol: t.protocol.clone(),
        status: t.status.clone(),
        requests: 0, // Would need per-tunnel request tracking
    }).collect();

    let active_agents = agents.iter().filter(|a| a.status == "connected").count();
    let active_tunnels = tunnels.iter().filter(|t| t.status == "active").count();

    let data = DashboardData {
        stats: DashboardStats {
            total_agents: stats.total_agents,
            active_agents: active_agents as u64,
            total_tunnels: stats.total_tunnels,
            active_tunnels: active_tunnels as u64,
            requests_per_minute: requests / (uptime.max(1) / 60).max(1),
            bytes_transferred,
            uptime_seconds: uptime,
        },
        recent_events: vec![
            DashboardEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                event_type: "info".to_string(),
                message: "Control plane started".to_string(),
                severity: "info".to_string(),
            },
        ],
        agents,
        tunnels,
    };

    Json(data)
}

/// Main dashboard HTML template
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        .stat-card { @apply bg-white rounded-lg shadow p-6; }
        .stat-value { @apply text-3xl font-bold text-gray-900; }
        .stat-label { @apply text-sm font-medium text-gray-500 mt-1; }
        .status-active { @apply text-green-600 bg-green-100 px-2 py-1 rounded-full text-xs; }
        .status-inactive { @apply text-gray-600 bg-gray-100 px-2 py-1 rounded-full text-xs; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white shadow-sm border-b border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex">
                    <div class="flex-shrink-0 flex items-center">
                        <span class="text-2xl font-bold text-indigo-600">NLAG</span>
                    </div>
                    <div class="hidden sm:ml-6 sm:flex sm:space-x-8">
                        <a href="/dashboard" class="border-indigo-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Dashboard</a>
                        <a href="/dashboard/agents" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Agents</a>
                        <a href="/dashboard/tunnels" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Tunnels</a>
                    </div>
                </div>
                <div class="flex items-center">
                    <span class="text-sm text-gray-500">Control Plane</span>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div class="mb-8">
            <h1 class="text-2xl font-semibold text-gray-900">Dashboard</h1>
            <p class="mt-1 text-sm text-gray-500">Overview of your NLAG infrastructure</p>
        </div>

        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" id="stats-container">
            <div class="stat-card">
                <div class="stat-value" id="stat-agents">-</div>
                <div class="stat-label">Active Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-tunnels">-</div>
                <div class="stat-label">Active Tunnels</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-rpm">-</div>
                <div class="stat-label">Requests/min</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-bytes">-</div>
                <div class="stat-label">Data Transferred</div>
            </div>
        </div>

        <!-- Recent Events -->
        <div class="bg-white rounded-lg shadow mb-8">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-medium text-gray-900">Recent Events</h2>
            </div>
            <div class="px-6 py-4" id="events-container">
                <p class="text-gray-500 text-sm">No recent events</p>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-medium text-gray-900 mb-4">Active Agents</h3>
                <div id="agents-list" class="space-y-3">
                    <p class="text-gray-500 text-sm">No agents connected</p>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-medium text-gray-900 mb-4">Active Tunnels</h3>
                <div id="tunnels-list" class="space-y-3">
                    <p class="text-gray-500 text-sm">No tunnels active</p>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="border-t border-gray-200 py-4 mt-8">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-gray-500">
            NLAG Control Plane v0.1.0
        </div>
    </footer>

    <script>
        // Format bytes to human readable
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        // Fetch and update dashboard data
        async function updateDashboard() {
            try {
                const response = await fetch('/dashboard/data');
                const data = await response.json();

                // Update stats
                document.getElementById('stat-agents').textContent = data.stats.active_agents;
                document.getElementById('stat-tunnels').textContent = data.stats.active_tunnels;
                document.getElementById('stat-rpm').textContent = data.stats.requests_per_minute;
                document.getElementById('stat-bytes').textContent = formatBytes(data.stats.bytes_transferred);

                // Update events
                const eventsContainer = document.getElementById('events-container');
                if (data.recent_events.length > 0) {
                    eventsContainer.innerHTML = data.recent_events.map(e => `
                        <div class="flex items-center py-2 border-b border-gray-100 last:border-0">
                            <span class="text-xs text-gray-400 w-48">${new Date(e.timestamp).toLocaleString()}</span>
                            <span class="text-sm ${e.severity === 'error' ? 'text-red-600' : 'text-gray-700'}">${e.message}</span>
                        </div>
                    `).join('');
                }

                // Update agents list
                const agentsList = document.getElementById('agents-list');
                if (data.agents.length > 0) {
                    agentsList.innerHTML = data.agents.map(a => `
                        <div class="flex items-center justify-between py-2">
                            <span class="font-medium text-gray-900">${a.name || a.id.slice(0, 8)}</span>
                            <span class="${a.status === 'active' ? 'status-active' : 'status-inactive'}">${a.status}</span>
                        </div>
                    `).join('');
                }

                // Update tunnels list
                const tunnelsList = document.getElementById('tunnels-list');
                if (data.tunnels.length > 0) {
                    tunnelsList.innerHTML = data.tunnels.map(t => `
                        <div class="flex items-center justify-between py-2">
                            <span class="font-medium text-gray-900">${t.subdomain}</span>
                            <span class="${t.status === 'active' ? 'status-active' : 'status-inactive'}">${t.protocol}</span>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Failed to update dashboard:', error);
            }
        }

        // Initial load
        updateDashboard();
        
        // Refresh every 5 seconds
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>"#;

/// Agents management page HTML
const AGENTS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG - Agents</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white shadow-sm border-b border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex">
                    <div class="flex-shrink-0 flex items-center">
                        <span class="text-2xl font-bold text-indigo-600">NLAG</span>
                    </div>
                    <div class="hidden sm:ml-6 sm:flex sm:space-x-8">
                        <a href="/dashboard" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Dashboard</a>
                        <a href="/dashboard/agents" class="border-indigo-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Agents</a>
                        <a href="/dashboard/tunnels" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Tunnels</a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div class="mb-8 flex justify-between items-center">
            <div>
                <h1 class="text-2xl font-semibold text-gray-900">Agents</h1>
                <p class="mt-1 text-sm text-gray-500">Manage connected agents</p>
            </div>
            <button class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 text-sm font-medium">
                Create Agent Token
            </button>
        </div>

        <div class="bg-white rounded-lg shadow overflow-hidden">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Agent ID</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tunnels</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Seen</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                </thead>
                <tbody id="agents-table" class="bg-white divide-y divide-gray-200">
                    <tr>
                        <td colspan="6" class="px-6 py-4 text-center text-gray-500">No agents connected</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>"#;

/// Tunnels management page HTML
const TUNNELS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NLAG - Tunnels</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white shadow-sm border-b border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex">
                    <div class="flex-shrink-0 flex items-center">
                        <span class="text-2xl font-bold text-indigo-600">NLAG</span>
                    </div>
                    <div class="hidden sm:ml-6 sm:flex sm:space-x-8">
                        <a href="/dashboard" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Dashboard</a>
                        <a href="/dashboard/agents" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Agents</a>
                        <a href="/dashboard/tunnels" class="border-indigo-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Tunnels</a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div class="mb-8">
            <h1 class="text-2xl font-semibold text-gray-900">Tunnels</h1>
            <p class="mt-1 text-sm text-gray-500">View and manage active tunnels</p>
        </div>

        <div class="bg-white rounded-lg shadow overflow-hidden">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subdomain</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public URL</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requests</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                </thead>
                <tbody id="tunnels-table" class="bg-white divide-y divide-gray-200">
                    <tr>
                        <td colspan="6" class="px-6 py-4 text-center text-gray-500">No active tunnels</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>"#;
