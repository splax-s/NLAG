//! Dashboard UI Module
//!
//! Provides a web-based dashboard for NLAG with:
//! - User authentication (login/signup)
//! - Tunnel management
//! - Billing and subscription management
//! - API token management

use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::api::ApiState;

/// Create the dashboard router
pub fn create_dashboard_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // Public auth pages
        .route("/", get(landing_page))
        .route("/login", get(login_page))
        .route("/signup", get(signup_page))
        // Protected dashboard pages (auth checked via JS)
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/data", get(dashboard_data))
        .route("/dashboard/tunnels", get(tunnels_page))
        .route("/dashboard/billing", get(billing_page))
        .route("/dashboard/tokens", get(tokens_page))
        .route("/dashboard/settings", get(settings_page))
        .with_state(state)
}

/// Dashboard data for frontend
#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub stats: DashboardStats,
    pub recent_events: Vec<DashboardEvent>,
    pub tunnels: Vec<TunnelSummary>,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_tunnels: u64,
    pub active_tunnels: u64,
    pub requests_per_minute: u64,
    pub bytes_transferred: u64,
    pub max_tunnels: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardEvent {
    pub timestamp: String,
    pub event_type: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct TunnelSummary {
    pub id: String,
    pub subdomain: String,
    pub protocol: String,
    pub status: String,
    pub requests: u64,
}

/// Landing page - redirect to login or dashboard
async fn landing_page() -> impl IntoResponse {
    Redirect::to("/login")
}

/// Login page
async fn login_page() -> impl IntoResponse {
    Html(LOGIN_HTML)
}

/// Signup page
async fn signup_page() -> impl IntoResponse {
    Html(SIGNUP_HTML)
}

/// Main dashboard page
async fn dashboard_page() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// Tunnels page
async fn tunnels_page() -> impl IntoResponse {
    Html(TUNNELS_HTML)
}

/// Billing page
async fn billing_page() -> impl IntoResponse {
    Html(BILLING_HTML)
}

/// Tokens page
async fn tokens_page() -> impl IntoResponse {
    Html(TOKENS_HTML)
}

/// Settings page
async fn settings_page() -> impl IntoResponse {
    Html(SETTINGS_HTML)
}

/// Get dashboard data as JSON
async fn dashboard_data(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let stats = state.store.get_stats().await.unwrap_or(crate::api::StatsResponse {
        total_users: 0,
        total_agents: 0,
        total_tunnels: 0,
        active_connections: 0,
        bytes_transferred_24h: 0,
    });

    let (bytes_transferred, requests, _) = state.store.get_metrics();

    static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let uptime = START_TIME.get_or_init(std::time::Instant::now).elapsed().as_secs();

    let tunnels_list = state.store.list_tunnels("__all__").await.unwrap_or_default();
    let tunnels: Vec<TunnelSummary> = tunnels_list.iter().map(|t| TunnelSummary {
        id: t.id.clone(),
        subdomain: t.subdomain.clone(),
        protocol: t.protocol.clone(),
        status: t.status.clone(),
        requests: 0,
    }).collect();

    let active_tunnels = tunnels.iter().filter(|t| t.status == "active").count();

    let data = DashboardData {
        stats: DashboardStats {
            total_tunnels: stats.total_tunnels,
            active_tunnels: active_tunnels as u64,
            requests_per_minute: requests / (uptime.max(1) / 60).max(1),
            bytes_transferred,
            max_tunnels: 10, // Default, will be overridden by user's tier
        },
        recent_events: vec![
            DashboardEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                event_type: "info".to_string(),
                message: "Dashboard loaded".to_string(),
                severity: "info".to_string(),
            },
        ],
        tunnels,
    };

    Json(data)
}

// ============================================================================
// ============================================================================
// Login Page
// ============================================================================

const LOGIN_HTML: &str = concat!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - NLAG</title>
"#, r#"
<style>
    * { box-sizing: border-box; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #0f0f23;
        color: #e0e0e0;
        margin: 0;
        min-height: 100vh;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
    .btn { 
        padding: 12px 24px; 
        border: none; 
        border-radius: 8px; 
        cursor: pointer; 
        font-size: 14px;
        font-weight: 600;
        transition: all 0.2s;
    }
    .btn-primary { background: #6366f1; color: white; }
    .btn-primary:hover { background: #4f46e5; }
    .input {
        width: 100%;
        padding: 12px 16px;
        background: #252540;
        border: 1px solid #374151;
        border-radius: 8px;
        color: white;
        font-size: 14px;
        margin-bottom: 16px;
    }
    .input:focus { outline: none; border-color: #6366f1; }
    .input::placeholder { color: #6b7280; }
    .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
    .error { color: #ef4444; font-size: 14px; margin-top: 8px; }
    a { color: #6366f1; text-decoration: none; }
    a:hover { text-decoration: underline; }
</style>
</head>
<body>
    <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center;">
        <div style="width: 100%; max-width: 400px; padding: 20px;">
            <div class="card">
                <div style="text-align: center; margin-bottom: 32px;">
                    <h1 style="font-size: 32px; font-weight: bold; color: #6366f1; margin: 0;">NLAG</h1>
                    <p style="color: #9ca3af; margin-top: 8px;">Sign in to your account</p>
                </div>
                
                <form id="loginForm">
                    <label class="label">Email</label>
                    <input type="email" id="email" class="input" placeholder="you@example.com" required>
                    
                    <label class="label">Password</label>
                    <input type="password" id="password" class="input" placeholder="••••••••" required>
                    
                    <div id="error" class="error" style="display: none;"></div>
                    
                    <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 16px;">
                        Sign In
                    </button>
                </form>
                
                <div style="text-align: center; margin-top: 24px; color: #9ca3af;">
                    Don't have an account? <a href="/signup">Sign up</a>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function setAuth(token, user) {
            localStorage.setItem('nlag_token', token);
            localStorage.setItem('nlag_user', JSON.stringify(user));
        }
        
        if (getToken()) { window.location.href = '/dashboard'; }
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('error');
            
            try {
                const response = await fetch('/api/v1/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    errorEl.textContent = data.message || 'Login failed';
                    errorEl.style.display = 'block';
                    return;
                }
                
                setAuth(data.access_token, data.user);
                window.location.href = '/dashboard';
            } catch (err) {
                errorEl.textContent = 'Network error. Please try again.';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>"#);

// ============================================================================
// Signup Page
// ============================================================================

const SIGNUP_HTML: &str = concat!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - NLAG</title>
"#, r#"
<style>
    * { box-sizing: border-box; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #0f0f23;
        color: #e0e0e0;
        margin: 0;
        min-height: 100vh;
    }
    .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
    .btn { 
        padding: 12px 24px; 
        border: none; 
        border-radius: 8px; 
        cursor: pointer; 
        font-size: 14px;
        font-weight: 600;
        transition: all 0.2s;
    }
    .btn-primary { background: #6366f1; color: white; }
    .btn-primary:hover { background: #4f46e5; }
    .input {
        width: 100%;
        padding: 12px 16px;
        background: #252540;
        border: 1px solid #374151;
        border-radius: 8px;
        color: white;
        font-size: 14px;
        margin-bottom: 16px;
    }
    .input:focus { outline: none; border-color: #6366f1; }
    .input::placeholder { color: #6b7280; }
    .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
    .error { color: #ef4444; font-size: 14px; margin-top: 8px; }
    .success { color: #22c55e; font-size: 14px; margin-top: 8px; }
    a { color: #6366f1; text-decoration: none; }
    a:hover { text-decoration: underline; }
</style>
</head>
<body>
    <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center;">
        <div style="width: 100%; max-width: 400px; padding: 20px;">
            <div class="card">
                <div style="text-align: center; margin-bottom: 32px;">
                    <h1 style="font-size: 32px; font-weight: bold; color: #6366f1; margin: 0;">NLAG</h1>
                    <p style="color: #9ca3af; margin-top: 8px;">Create your account</p>
                </div>
                
                <form id="signupForm">
                    <label class="label">Email</label>
                    <input type="email" id="email" class="input" placeholder="you@example.com" required>
                    
                    <label class="label">Password</label>
                    <input type="password" id="password" class="input" placeholder="••••••••" required minlength="8">
                    
                    <label class="label">Confirm Password</label>
                    <input type="password" id="confirmPassword" class="input" placeholder="••••••••" required>
                    
                    <div id="error" class="error" style="display: none;"></div>
                    <div id="success" class="success" style="display: none;"></div>
                    
                    <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 16px;">
                        Create Account
                    </button>
                </form>
                
                <div style="text-align: center; margin-top: 24px; color: #9ca3af;">
                    Already have an account? <a href="/login">Sign in</a>
                </div>
                
                <div style="margin-top: 24px; padding-top: 24px; border-top: 1px solid #374151; text-align: center;">
                    <p style="font-size: 12px; color: #6b7280;">
                        By signing up, you agree to our Terms of Service and Privacy Policy.
                    </p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        if (getToken()) { window.location.href = '/dashboard'; }
        
        document.getElementById('signupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const errorEl = document.getElementById('error');
            const successEl = document.getElementById('success');
            
            errorEl.style.display = 'none';
            successEl.style.display = 'none';
            
            if (password !== confirmPassword) {
                errorEl.textContent = 'Passwords do not match';
                errorEl.style.display = 'block';
                return;
            }
            
            if (password.length < 8) {
                errorEl.textContent = 'Password must be at least 8 characters';
                errorEl.style.display = 'block';
                return;
            }
            
            try {
                const response = await fetch('/api/v1/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    errorEl.textContent = data.message || 'Registration failed';
                    errorEl.style.display = 'block';
                    return;
                }
                
                successEl.textContent = 'Account created! Redirecting to login...';
                successEl.style.display = 'block';
                
                setTimeout(() => { window.location.href = '/login'; }, 1500);
            } catch (err) {
                errorEl.textContent = 'Network error. Please try again.';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>"#);

// ============================================================================
// Dashboard Page
// ============================================================================

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        a { color: #6366f1; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; text-decoration: none; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px; }
        .stat-card { background: #1a1a2e; border-radius: 12px; padding: 20px; }
        .stat-value { font-size: 32px; font-weight: bold; color: white; }
        .stat-label { font-size: 14px; color: #9ca3af; margin-top: 4px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-success { background: #064e3b; color: #34d399; }
        .badge-warning { background: #78350f; color: #fbbf24; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link active">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/tokens" class="nav-link">API Tokens</a>
                <a href="/dashboard/billing" class="nav-link">Billing</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0;">
            <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Dashboard</h1>
            <p style="color: #9ca3af; margin-top: 4px;">Welcome back! Here's an overview of your tunnels.</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="stat-tunnels">-</div>
                <div class="stat-label">Active Tunnels</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-limit">-</div>
                <div class="stat-label">Tunnel Limit</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-requests">-</div>
                <div class="stat-label">Requests / min</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-bandwidth">-</div>
                <div class="stat-label">Bandwidth Used</div>
            </div>
        </div>
        
        <div class="card">
            <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 16px 0;">Quick Start</h2>
            <p style="color: #9ca3af; margin-bottom: 16px;">Start a tunnel from your terminal:</p>
            <div style="background: #252540; padding: 16px; border-radius: 8px; font-family: monospace; overflow-x: auto;">
                <code style="color: #22c55e;">$</code> <code>nlag login</code><br>
                <code style="color: #22c55e;">$</code> <code>nlag expose http 8080</code>
            </div>
        </div>
        
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h2 style="font-size: 18px; font-weight: 600; margin: 0;">Recent Tunnels</h2>
                <a href="/dashboard/tunnels" class="btn btn-secondary" style="padding: 8px 16px;">View All</a>
            </div>
            <div id="tunnelsList">
                <p style="color: #6b7280; text-align: center; padding: 32px;">No tunnels yet. Start one with <code>nlag expose</code></p>
            </div>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        function formatBytes(bytes) { if (bytes === 0) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]; }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; throw new Error('Unauthorized'); }
            return response;
        }
        
        async function loadDashboard() {
            try {
                const subResponse = await apiCall('/api/v1/billing/subscription');
                const subscription = await subResponse.json();
                const tunnelsResponse = await apiCall('/api/v1/tunnels');
                const tunnels = await tunnelsResponse.json();
                
                document.getElementById('stat-tunnels').textContent = tunnels.length || 0;
                document.getElementById('stat-limit').textContent = subscription.limits?.max_tunnels || user?.max_tunnels || '1';
                document.getElementById('stat-requests').textContent = '-';
                document.getElementById('stat-bandwidth').textContent = '-';
                
                const tunnelsList = document.getElementById('tunnelsList');
                if (tunnels.length > 0) {
                    tunnelsList.innerHTML = tunnels.slice(0, 5).map(t => '<div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #252540;"><div><div style="font-weight: 500;">' + t.subdomain + '</div><div style="font-size: 12px; color: #6b7280;">' + (t.public_url || '') + '</div></div><span class="badge ' + (t.status === 'active' ? 'badge-success' : 'badge-warning') + '">' + t.status + '</span></div>').join('');
                }
            } catch (err) { console.error('Failed to load dashboard:', err); }
        }
        loadDashboard();
    </script>
</body>
</html>"#;

// ============================================================================
// Tunnels Page
// ============================================================================

const TUNNELS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tunnels - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-danger:hover { background: #b91c1c; }
        a { color: #6366f1; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; text-decoration: none; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .table tr:hover td { background: #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-success { background: #064e3b; color: #34d399; }
        .badge-warning { background: #78350f; color: #fbbf24; }
        .badge-info { background: #1e3a5f; color: #60a5fa; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link active">Tunnels</a>
                <a href="/dashboard/tokens" class="nav-link">API Tokens</a>
                <a href="/dashboard/billing" class="nav-link">Billing</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Tunnels</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Manage your tunnel configurations</p>
            </div>
            <div id="tunnelUsage" style="color: #9ca3af;"></div>
        </div>
        
        <div class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Protocol</th>
                        <th>Public URL</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="tunnelsTable">
                    <tr><td colspan="6" style="text-align: center; color: #6b7280;">Loading tunnels...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; throw new Error('Unauthorized'); }
            return response;
        }
        
        async function loadTunnels() {
            try {
                const response = await apiCall('/api/v1/tunnels');
                const tunnels = await response.json();
                const subResponse = await apiCall('/api/v1/billing/subscription');
                const subscription = await subResponse.json();
                const maxTunnels = subscription.limits?.max_tunnels || 1;
                
                document.getElementById('tunnelUsage').textContent = (tunnels.length || 0) + ' / ' + maxTunnels + ' tunnels used';
                
                const tbody = document.getElementById('tunnelsTable');
                if (!tunnels.length) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No tunnels. Start one with <code>nlag expose http 8080</code></td></tr>';
                } else {
                    tbody.innerHTML = tunnels.map(t => '<tr><td><strong>' + t.subdomain + '</strong></td><td><span class="badge badge-info">' + (t.protocol || 'HTTP').toUpperCase() + '</span></td><td><a href="' + (t.public_url || '#') + '" target="_blank">' + (t.public_url || '-') + '</a></td><td><span class="badge ' + (t.status === 'active' ? 'badge-success' : 'badge-warning') + '">' + t.status + '</span></td><td style="color: #6b7280;">' + new Date(t.created_at).toLocaleDateString() + '</td><td style="text-align: right;"><button onclick="deleteTunnel(\'' + t.id + '\')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Delete</button></td></tr>').join('');
                }
            } catch (err) { console.error('Failed to load tunnels:', err); }
        }
        
        async function deleteTunnel(id) {
            if (!confirm('Are you sure you want to delete this tunnel?')) return;
            try { await apiCall('/api/v1/tunnels/' + id, { method: 'DELETE' }); loadTunnels(); } catch (err) { alert('Failed to delete tunnel'); }
        }
        
        loadTunnels();
    </script>
</body>
</html>"#;

// ============================================================================
// Billing Page
// ============================================================================

const BILLING_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Billing - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; text-decoration: none; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; }
        .pricing-card { background: #1a1a2e; border-radius: 12px; padding: 32px; border: 2px solid transparent; transition: all 0.2s; }
        .pricing-card:hover { border-color: #374151; }
        .pricing-card.featured { border-color: #6366f1; }
        .pricing-title { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
        .pricing-price { font-size: 48px; font-weight: bold; margin: 16px 0; }
        .pricing-price span { font-size: 16px; color: #9ca3af; }
        .pricing-features { list-style: none; padding: 0; margin: 24px 0; }
        .pricing-features li { padding: 8px 0; color: #9ca3af; display: flex; align-items: center; gap: 8px; }
        .pricing-features li::before { content: "✓"; color: #22c55e; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/tokens" class="nav-link">API Tokens</a>
                <a href="/dashboard/billing" class="nav-link active">Billing</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0;">
            <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Billing & Subscription</h1>
            <p style="color: #9ca3af; margin-top: 4px;">Manage your subscription and payment methods</p>
        </div>
        
        <div class="card" style="margin-bottom: 32px;">
            <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 16px 0;">Current Plan</h2>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div id="currentTier" style="font-size: 24px; font-weight: bold; color: #6366f1;">Free</div>
                    <div id="currentLimits" style="color: #9ca3af; margin-top: 4px;">1 tunnel, 1GB bandwidth/month</div>
                </div>
            </div>
        </div>
        
        <div class="card" style="margin-bottom: 32px;">
            <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 16px 0;">Current Usage</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 24px;">
                <div>
                    <div style="color: #9ca3af; font-size: 14px;">Tunnels</div>
                    <div id="usageTunnels" style="font-size: 24px; font-weight: bold; margin-top: 4px;">0 / 1</div>
                </div>
                <div>
                    <div style="color: #9ca3af; font-size: 14px;">Requests</div>
                    <div id="usageRequests" style="font-size: 24px; font-weight: bold; margin-top: 4px;">0</div>
                </div>
                <div>
                    <div style="color: #9ca3af; font-size: 14px;">Bandwidth</div>
                    <div id="usageBandwidth" style="font-size: 24px; font-weight: bold; margin-top: 4px;">0 B</div>
                </div>
            </div>
        </div>
        
        <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 24px 0;">Available Plans</h2>
        <div class="pricing-grid">
            <div class="pricing-card" id="plan-free">
                <div class="pricing-title">Free</div>
                <div style="color: #9ca3af;">For personal projects</div>
                <div class="pricing-price">$0<span>/month</span></div>
                <ul class="pricing-features">
                    <li>1 tunnel</li>
                    <li>10 connections per tunnel</li>
                    <li>1 GB bandwidth/month</li>
                    <li>HTTP tunnels only</li>
                    <li>Community support</li>
                </ul>
                <button onclick="selectPlan('free')" class="btn btn-secondary" style="width: 100%;">Current Plan</button>
            </div>
            
            <div class="pricing-card featured" id="plan-pro">
                <div class="pricing-title">Pro</div>
                <div style="color: #9ca3af;">For professional developers</div>
                <div class="pricing-price">$10<span>/month</span></div>
                <ul class="pricing-features">
                    <li>10 tunnels</li>
                    <li>100 connections per tunnel</li>
                    <li>50 GB bandwidth/month</li>
                    <li>TCP & HTTP tunnels</li>
                    <li>Custom domains</li>
                    <li>Priority support</li>
                </ul>
                <button onclick="selectPlan('pro')" class="btn btn-primary" style="width: 100%;">Upgrade to Pro</button>
            </div>
            
            <div class="pricing-card" id="plan-team">
                <div class="pricing-title">Team</div>
                <div style="color: #9ca3af;">For growing teams</div>
                <div class="pricing-price">$25<span>/month</span></div>
                <ul class="pricing-features">
                    <li>20 tunnels</li>
                    <li>500 connections per tunnel</li>
                    <li>200 GB bandwidth/month</li>
                    <li>All Pro features</li>
                    <li>5 team members</li>
                    <li>99.5% SLA</li>
                </ul>
                <button onclick="selectPlan('team')" class="btn btn-primary" style="width: 100%;">Upgrade to Team</button>
            </div>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        function formatBytes(bytes) { if (bytes === 0) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]; }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; throw new Error('Unauthorized'); }
            return response;
        }
        
        async function loadBilling() {
            try {
                const subResponse = await apiCall('/api/v1/billing/subscription');
                const subscription = await subResponse.json();
                const usageResponse = await apiCall('/api/v1/billing/usage');
                const usage = await usageResponse.json();
                const tunnelsResponse = await apiCall('/api/v1/tunnels');
                const tunnels = await tunnelsResponse.json();
                
                document.getElementById('currentTier').textContent = subscription.tier || 'Free';
                document.getElementById('currentLimits').textContent = (subscription.limits?.max_tunnels || 1) + ' tunnels, ' + (subscription.limits?.max_bandwidth_gb_per_month || 1) + ' GB bandwidth/month';
                document.getElementById('usageTunnels').textContent = (tunnels.length || 0) + ' / ' + (subscription.limits?.max_tunnels || 1);
                document.getElementById('usageRequests').textContent = usage.requests || 0;
                document.getElementById('usageBandwidth').textContent = formatBytes((usage.bytes_in || 0) + (usage.bytes_out || 0));
            } catch (err) { console.error('Failed to load billing:', err); }
        }
        
        async function selectPlan(tier) {
            if (!confirm('Upgrade to ' + tier.charAt(0).toUpperCase() + tier.slice(1) + ' plan?')) return;
            try {
                await apiCall('/api/v1/billing/subscription', { method: 'POST', body: JSON.stringify({ tier }) });
                alert('Plan updated successfully!');
                loadBilling();
            } catch (err) { alert('Failed to update plan. Please try again.'); }
        }
        
        loadBilling();
    </script>
</body>
</html>"#;

// ============================================================================
// API Tokens Page
// ============================================================================

const TOKENS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Tokens - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-danger:hover { background: #b91c1c; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .input:focus { outline: none; border-color: #6366f1; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; text-decoration: none; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .table tr:hover td { background: #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-info { background: #1e3a5f; color: #60a5fa; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 100; align-items: center; justify-content: center; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/tokens" class="nav-link active">API Tokens</a>
                <a href="/dashboard/billing" class="nav-link">Billing</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">API Tokens</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Manage your authentication tokens for the CLI</p>
            </div>
            <button onclick="showCreateModal()" class="btn btn-primary">Create Token</button>
        </div>
        
        <div id="newTokenDisplay" class="card" style="display: none; background: #064e3b; border: 1px solid #22c55e;">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div>
                    <h3 style="margin: 0 0 8px 0; color: #22c55e;">Token Created!</h3>
                    <p style="color: #9ca3af; margin: 0 0 16px 0;">Copy this token now. You won't be able to see it again.</p>
                    <code id="newTokenValue" style="display: block; background: #1a1a2e; padding: 16px; border-radius: 8px; word-break: break-all;"></code>
                </div>
                <button onclick="hideNewToken()" style="background: none; border: none; color: #9ca3af; cursor: pointer; font-size: 20px;">×</button>
            </div>
        </div>
        
        <div class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Scopes</th>
                        <th>Created</th>
                        <th>Expires</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="tokensTable">
                    <tr><td colspan="5" style="text-align: center; color: #6b7280;">Loading tokens...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div id="createModal" class="modal">
            <div class="card" style="width: 100%; max-width: 500px;">
                <h2 style="margin: 0 0 24px 0;">Create API Token</h2>
                <form id="createTokenForm">
                    <label class="label">Token Name</label>
                    <input type="text" id="tokenName" class="input" placeholder="My Token" required>
                    
                    <label class="label">Scopes</label>
                    <div style="display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" name="scopes" value="tunnel:read" checked> tunnel:read
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" name="scopes" value="tunnel:write" checked> tunnel:write
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" name="scopes" value="agent:connect" checked> agent:connect
                        </label>
                    </div>
                    
                    <label class="label">Expires In (days, optional)</label>
                    <input type="number" id="expiresIn" class="input" placeholder="365" min="1" max="365">
                    
                    <div style="display: flex; gap: 12px; margin-top: 24px;">
                        <button type="button" onclick="hideCreateModal()" class="btn btn-secondary" style="flex: 1;">Cancel</button>
                        <button type="submit" class="btn btn-primary" style="flex: 1;">Create Token</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; throw new Error('Unauthorized'); }
            return response;
        }
        
        async function loadTokens() {
            try {
                const response = await apiCall('/api/v1/tokens');
                const tokens = await response.json();
                const tbody = document.getElementById('tokensTable');
                if (!tokens.length) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #6b7280; padding: 48px;">No tokens yet. Create one to use with the CLI.</td></tr>';
                } else {
                    tbody.innerHTML = tokens.map(t => '<tr><td><strong>' + t.name + '</strong></td><td>' + (t.scopes || []).map(s => '<span class="badge badge-info" style="margin-right: 4px;">' + s + '</span>').join('') + '</td><td style="color: #6b7280;">' + new Date(t.created_at).toLocaleDateString() + '</td><td style="color: #6b7280;">' + (t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Never') + '</td><td style="text-align: right;"><button onclick="deleteToken(\'' + t.id + '\')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Revoke</button></td></tr>').join('');
                }
            } catch (err) { console.error('Failed to load tokens:', err); }
        }
        
        function showCreateModal() { document.getElementById('createModal').style.display = 'flex'; }
        function hideCreateModal() { document.getElementById('createModal').style.display = 'none'; document.getElementById('createTokenForm').reset(); }
        function hideNewToken() { document.getElementById('newTokenDisplay').style.display = 'none'; }
        
        document.getElementById('createTokenForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('tokenName').value;
            const scopes = Array.from(document.querySelectorAll('input[name="scopes"]:checked')).map(cb => cb.value);
            const expiresIn = document.getElementById('expiresIn').value;
            try {
                const response = await apiCall('/api/v1/tokens', { method: 'POST', body: JSON.stringify({ name, scopes, expires_in_days: expiresIn ? parseInt(expiresIn) : null }) });
                const token = await response.json();
                hideCreateModal();
                if (token.token) {
                    document.getElementById('newTokenValue').textContent = token.token;
                    document.getElementById('newTokenDisplay').style.display = 'block';
                }
                loadTokens();
            } catch (err) { alert('Failed to create token'); }
        });
        
        async function deleteToken(id) {
            if (!confirm('Are you sure you want to revoke this token?')) return;
            try { await apiCall('/api/v1/tokens/' + id, { method: 'DELETE' }); loadTokens(); } catch (err) { alert('Failed to revoke token'); }
        }
        
        loadTokens();
    </script>
</body>
</html>"#;

// ============================================================================
// Settings Page
// ============================================================================

const SETTINGS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-danger:hover { background: #b91c1c; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; text-decoration: none; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/tokens" class="nav-link">API Tokens</a>
                <a href="/dashboard/billing" class="nav-link">Billing</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0;">
            <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Settings</h1>
            <p style="color: #9ca3af; margin-top: 4px;">Manage your account settings</p>
        </div>
        
        <div class="card">
            <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 24px 0;">Account</h2>
            <div style="margin-bottom: 24px;">
                <label class="label">Email</label>
                <input type="email" id="email" class="input" disabled>
            </div>
            <div style="margin-bottom: 24px;">
                <label class="label">Account Created</label>
                <input type="text" id="createdAt" class="input" disabled>
            </div>
        </div>
        
        <div class="card" style="border: 1px solid #7f1d1d;">
            <h2 style="font-size: 18px; font-weight: 600; margin: 0 0 16px 0; color: #f87171;">Danger Zone</h2>
            <p style="color: #9ca3af; margin-bottom: 16px;">Once you delete your account, there is no going back.</p>
            <button class="btn btn-danger">Delete Account</button>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        document.getElementById('email').value = user?.email || '';
        document.getElementById('createdAt').value = 'N/A';
    </script>
</body>
</html>"#;
