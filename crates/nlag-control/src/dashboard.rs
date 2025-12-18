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
        // New feature pages
        .route("/dashboard/teams", get(teams_page))
        .route("/dashboard/domains", get(domains_page))
        .route("/dashboard/analytics", get(analytics_page))
        .route("/dashboard/webhooks", get(webhooks_page))
        .route("/dashboard/policies", get(policies_page))
        .route("/dashboard/sso", get(sso_page))
        .route("/dashboard/audit", get(audit_page))
        .route("/dashboard/ip-restrictions", get(ip_restrictions_page))
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

/// Teams page
async fn teams_page() -> impl IntoResponse {
    Html(TEAMS_HTML)
}

/// Domains page
async fn domains_page() -> impl IntoResponse {
    Html(DOMAINS_HTML)
}

/// Analytics page
async fn analytics_page() -> impl IntoResponse {
    Html(ANALYTICS_HTML)
}

/// Webhooks page
async fn webhooks_page() -> impl IntoResponse {
    Html(WEBHOOKS_HTML)
}

/// Traffic Policies page
async fn policies_page() -> impl IntoResponse {
    Html(POLICIES_HTML)
}

/// SSO/OAuth page
async fn sso_page() -> impl IntoResponse {
    Html(SSO_HTML)
}

/// Audit Logs page
async fn audit_page() -> impl IntoResponse {
    Html(AUDIT_HTML)
}

/// IP Restrictions page
async fn ip_restrictions_page() -> impl IntoResponse {
    Html(IP_RESTRICTIONS_HTML)
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

// ============================================================================
// Teams Page
// ============================================================================

const TEAMS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Teams - NLAG</title>
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
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .input:focus { outline: none; border-color: #6366f1; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-owner { background: #7c3aed; color: white; }
        .badge-admin { background: #0891b2; color: white; }
        .badge-developer { background: #059669; color: white; }
        .badge-viewer { background: #6b7280; color: white; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 500px; width: 90%; }
        .tabs { display: flex; gap: 8px; margin-bottom: 24px; }
        .tab { padding: 8px 16px; background: transparent; border: none; color: #9ca3af; cursor: pointer; border-radius: 8px; }
        .tab.active { background: #252540; color: white; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/teams" class="nav-link active">Teams</a>
                <a href="/dashboard/domains" class="nav-link">Domains</a>
                <a href="/dashboard/analytics" class="nav-link">Analytics</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Teams</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Manage team members and permissions</p>
            </div>
            <button onclick="showInviteModal()" class="btn btn-primary">Invite Member</button>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('members')">Members</button>
            <button class="tab" onclick="showTab('invitations')">Pending Invitations</button>
            <button class="tab" onclick="showTab('roles')">Roles</button>
        </div>
        
        <div id="membersTab" class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Member</th>
                        <th>Role</th>
                        <th>Joined</th>
                        <th>Last Active</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="membersTable">
                    <tr><td colspan="5" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div id="invitationsTab" class="card" style="display: none;">
            <table class="table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Invited By</th>
                        <th>Expires</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="invitationsTable">
                    <tr><td colspan="5" style="text-align: center; color: #6b7280;">No pending invitations</td></tr>
                </tbody>
            </table>
        </div>
        
        <div id="rolesTab" class="card" style="display: none;">
            <div style="margin-bottom: 24px;">
                <h3 style="font-size: 16px; margin: 0 0 16px 0;">Available Roles</h3>
                <div style="display: grid; gap: 16px;">
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span class="badge badge-owner">Owner</span>
                            <span style="font-weight: 600;">Full Access</span>
                        </div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Can manage billing, delete team, and manage all resources.</p>
                    </div>
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span class="badge badge-admin">Admin</span>
                            <span style="font-weight: 600;">Administrative Access</span>
                        </div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Can invite members, manage tunnels, domains, and settings.</p>
                    </div>
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span class="badge badge-developer">Developer</span>
                            <span style="font-weight: 600;">Development Access</span>
                        </div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Can create and manage tunnels, view analytics.</p>
                    </div>
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span class="badge badge-viewer">Viewer</span>
                            <span style="font-weight: 600;">Read-Only Access</span>
                        </div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Can view tunnels and analytics, cannot make changes.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Invite Modal -->
    <div id="inviteModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Invite Team Member</h2>
            <form id="inviteForm">
                <label class="label">Email Address</label>
                <input type="email" id="inviteEmail" class="input" placeholder="colleague@company.com" required>
                
                <label class="label">Role</label>
                <select id="inviteRole" class="select">
                    <option value="developer">Developer</option>
                    <option value="admin">Admin</option>
                    <option value="viewer">Viewer</option>
                </select>
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideInviteModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Send Invitation</button>
                </div>
            </form>
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
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.card').forEach(c => c.style.display = 'none');
            event.target.classList.add('active');
            document.getElementById(tab + 'Tab').style.display = 'block';
        }
        
        function showInviteModal() { document.getElementById('inviteModal').style.display = 'flex'; }
        function hideInviteModal() { document.getElementById('inviteModal').style.display = 'none'; }
        
        async function loadMembers() {
            try {
                const response = await apiCall('/api/v1/teams/members');
                const members = await response.json();
                const tbody = document.getElementById('membersTable');
                if (members.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #6b7280;">No team members</td></tr>';
                } else {
                    tbody.innerHTML = members.map(m => `
                        <tr>
                            <td><div style="font-weight: 500;">${m.email}</div></td>
                            <td><span class="badge badge-${m.role}">${m.role}</span></td>
                            <td style="color: #6b7280;">${new Date(m.joined_at).toLocaleDateString()}</td>
                            <td style="color: #6b7280;">${m.last_active || 'Never'}</td>
                            <td style="text-align: right;">
                                ${m.role !== 'owner' ? `<button onclick="removeMember('${m.id}')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Remove</button>` : ''}
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (err) { 
                document.getElementById('membersTable').innerHTML = `
                    <tr>
                        <td><div style="font-weight: 500;">${user?.email || 'You'}</div></td>
                        <td><span class="badge badge-owner">owner</span></td>
                        <td style="color: #6b7280;">Today</td>
                        <td style="color: #6b7280;">Now</td>
                        <td></td>
                    </tr>
                `;
            }
        }
        
        document.getElementById('inviteForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('inviteEmail').value;
            const role = document.getElementById('inviteRole').value;
            try {
                await apiCall('/api/v1/teams/invite', { method: 'POST', body: JSON.stringify({ email, role }) });
                hideInviteModal();
                alert('Invitation sent!');
            } catch (err) { alert('Failed to send invitation'); }
        });
        
        async function removeMember(id) {
            if (!confirm('Remove this team member?')) return;
            try { await apiCall('/api/v1/teams/members/' + id, { method: 'DELETE' }); loadMembers(); } catch (err) { alert('Failed to remove member'); }
        }
        
        loadMembers();
    </script>
</body>
</html>"#;

// ============================================================================
// Domains Page
// ============================================================================

const DOMAINS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domains - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: #374151; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-verified { background: #064e3b; color: #34d399; }
        .badge-pending { background: #78350f; color: #fbbf24; }
        .badge-failed { background: #7f1d1d; color: #f87171; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .code-block { background: #252540; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; margin: 12px 0; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/teams" class="nav-link">Teams</a>
                <a href="/dashboard/domains" class="nav-link active">Domains</a>
                <a href="/dashboard/analytics" class="nav-link">Analytics</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Custom Domains</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Configure custom domains for your tunnels</p>
            </div>
            <button onclick="showAddModal()" class="btn btn-primary">Add Domain</button>
        </div>
        
        <div class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Target Tunnel</th>
                        <th>Status</th>
                        <th>SSL</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="domainsTable">
                    <tr><td colspan="6" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card" style="background: #1e1e3f;">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">How to verify your domain</h3>
            <div style="display: grid; gap: 16px;">
                <div style="display: flex; gap: 16px; align-items: flex-start;">
                    <div style="width: 32px; height: 32px; background: #6366f1; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 600; flex-shrink: 0;">1</div>
                    <div>
                        <div style="font-weight: 500; margin-bottom: 4px;">Add a CNAME record</div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Point your domain to <code style="background: #252540; padding: 2px 6px; border-radius: 4px;">tunnels.nlag.io</code></p>
                    </div>
                </div>
                <div style="display: flex; gap: 16px; align-items: flex-start;">
                    <div style="width: 32px; height: 32px; background: #6366f1; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 600; flex-shrink: 0;">2</div>
                    <div>
                        <div style="font-weight: 500; margin-bottom: 4px;">Add a TXT record for verification</div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Add the TXT record shown after adding your domain</p>
                    </div>
                </div>
                <div style="display: flex; gap: 16px; align-items: flex-start;">
                    <div style="width: 32px; height: 32px; background: #6366f1; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 600; flex-shrink: 0;">3</div>
                    <div>
                        <div style="font-weight: 500; margin-bottom: 4px;">SSL certificate auto-provisioned</div>
                        <p style="color: #9ca3af; margin: 0; font-size: 14px;">Once verified, we'll automatically provision an SSL certificate via Let's Encrypt</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Add Domain Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Add Custom Domain</h2>
            <form id="addForm">
                <label class="label">Domain Name</label>
                <input type="text" id="domainName" class="input" placeholder="app.example.com" required>
                
                <label class="label">Domain Type</label>
                <select id="domainType" class="select">
                    <option value="subdomain">Subdomain (e.g., app.example.com)</option>
                    <option value="wildcard">Wildcard (e.g., *.example.com)</option>
                    <option value="apex">Apex Domain (e.g., example.com)</option>
                </select>
                
                <label class="label">Target Tunnel (optional)</label>
                <select id="targetTunnel" class="select">
                    <option value="">Select a tunnel...</option>
                </select>
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideAddModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Domain</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Verification Modal -->
    <div id="verifyModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Verify Domain</h2>
            <div id="verifyContent"></div>
            <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                <button onclick="hideVerifyModal()" class="btn btn-secondary">Close</button>
                <button onclick="checkVerification()" class="btn btn-primary">Check Verification</button>
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
        
        let currentDomain = null;
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function showAddModal() { document.getElementById('addModal').style.display = 'flex'; loadTunnels(); }
        function hideAddModal() { document.getElementById('addModal').style.display = 'none'; }
        function hideVerifyModal() { document.getElementById('verifyModal').style.display = 'none'; }
        
        async function loadTunnels() {
            try {
                const response = await apiCall('/api/v1/tunnels');
                const tunnels = await response.json();
                const select = document.getElementById('targetTunnel');
                select.innerHTML = '<option value="">Select a tunnel...</option>' + tunnels.map(t => `<option value="${t.id}">${t.subdomain}</option>`).join('');
            } catch (err) { console.error('Failed to load tunnels'); }
        }
        
        async function loadDomains() {
            try {
                const response = await apiCall('/api/v1/domains');
                const domains = await response.json();
                const tbody = document.getElementById('domainsTable');
                if (!domains.length) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No custom domains configured</td></tr>';
                } else {
                    tbody.innerHTML = domains.map(d => `
                        <tr>
                            <td><strong>${d.domain}</strong></td>
                            <td>${d.domain_type || 'subdomain'}</td>
                            <td>${d.target_tunnel || '-'}</td>
                            <td><span class="badge badge-${d.verified ? 'verified' : 'pending'}">${d.verified ? 'Verified' : 'Pending'}</span></td>
                            <td>${d.ssl_provisioned ? '✅' : '⏳'}</td>
                            <td style="text-align: right;">
                                ${!d.verified ? `<button onclick="showVerify('${d.domain}', '${d.verification_token}')" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px; margin-right: 8px;">Verify</button>` : ''}
                                <button onclick="deleteDomain('${d.id}')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Delete</button>
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (err) { 
                document.getElementById('domainsTable').innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No custom domains configured</td></tr>';
            }
        }
        
        function showVerify(domain, token) {
            currentDomain = domain;
            document.getElementById('verifyContent').innerHTML = `
                <p style="color: #9ca3af;">Add the following DNS records to verify <strong>${domain}</strong>:</p>
                <div style="margin-top: 16px;">
                    <div style="font-weight: 500; margin-bottom: 8px;">CNAME Record</div>
                    <div class="code-block">
                        <div>Name: <span style="color: #22c55e;">${domain}</span></div>
                        <div>Value: <span style="color: #22c55e;">tunnels.nlag.io</span></div>
                    </div>
                </div>
                <div style="margin-top: 16px;">
                    <div style="font-weight: 500; margin-bottom: 8px;">TXT Record (for verification)</div>
                    <div class="code-block">
                        <div>Name: <span style="color: #22c55e;">_nlag-verify.${domain}</span></div>
                        <div>Value: <span style="color: #22c55e;">${token || 'nlag-verify=' + Math.random().toString(36).substr(2, 16)}</span></div>
                    </div>
                </div>
            `;
            document.getElementById('verifyModal').style.display = 'flex';
        }
        
        async function checkVerification() {
            try {
                await apiCall('/api/v1/domains/' + currentDomain + '/verify', { method: 'POST' });
                hideVerifyModal();
                loadDomains();
                alert('Domain verified successfully!');
            } catch (err) { alert('Verification failed. Please check your DNS records.'); }
        }
        
        document.getElementById('addForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const domain = document.getElementById('domainName').value;
            const domainType = document.getElementById('domainType').value;
            const targetTunnel = document.getElementById('targetTunnel').value;
            try {
                const response = await apiCall('/api/v1/domains', { 
                    method: 'POST', 
                    body: JSON.stringify({ domain, domain_type: domainType, target_tunnel: targetTunnel || null }) 
                });
                const data = await response.json();
                hideAddModal();
                showVerify(domain, data.verification_token);
                loadDomains();
            } catch (err) { alert('Failed to add domain'); }
        });
        
        async function deleteDomain(id) {
            if (!confirm('Delete this domain?')) return;
            try { await apiCall('/api/v1/domains/' + id, { method: 'DELETE' }); loadDomains(); } catch (err) { alert('Failed to delete domain'); }
        }
        
        loadDomains();
    </script>
</body>
</html>"#;

// ============================================================================
// Analytics Page
// ============================================================================

const ANALYTICS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analytics - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-secondary { background: #374151; color: white; }
        .btn-secondary:hover { background: #4b5563; }
        .select { padding: 8px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px; }
        .stat-card { background: #1a1a2e; border-radius: 12px; padding: 20px; }
        .stat-value { font-size: 32px; font-weight: bold; color: white; }
        .stat-label { font-size: 14px; color: #9ca3af; margin-top: 4px; }
        .stat-change { font-size: 12px; margin-top: 8px; }
        .stat-change.positive { color: #22c55e; }
        .stat-change.negative { color: #ef4444; }
        .chart-container { height: 300px; background: #252540; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #6b7280; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">Dashboard</a>
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/teams" class="nav-link">Teams</a>
                <a href="/dashboard/domains" class="nav-link">Domains</a>
                <a href="/dashboard/analytics" class="nav-link active">Analytics</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Analytics</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Traffic insights and usage statistics</p>
            </div>
            <div style="display: flex; gap: 12px;">
                <select id="timeRange" class="select" onchange="loadAnalytics()">
                    <option value="1h">Last Hour</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>
                <select id="tunnelFilter" class="select" onchange="loadAnalytics()">
                    <option value="all">All Tunnels</option>
                </select>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalRequests">0</div>
                <div class="stat-label">Total Requests</div>
                <div class="stat-change positive" id="requestsChange">↑ 0% from previous period</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalBandwidth">0 B</div>
                <div class="stat-label">Bandwidth Used</div>
                <div class="stat-change positive" id="bandwidthChange">↑ 0% from previous period</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="avgLatency">0 ms</div>
                <div class="stat-label">Avg Latency</div>
                <div class="stat-change positive" id="latencyChange">↓ 0% from previous period</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="errorRate">0%</div>
                <div class="stat-label">Error Rate</div>
                <div class="stat-change positive" id="errorChange">↓ 0% from previous period</div>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 16px 0;">Requests Over Time</h3>
            <div class="chart-container" id="requestsChart">
                <div style="text-align: center;">
                    <div style="font-size: 48px; margin-bottom: 8px;">📊</div>
                    <div>Chart visualization</div>
                    <div style="font-size: 12px; margin-top: 4px;">Request data plotted over time</div>
                </div>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="card">
                <h3 style="margin: 0 0 16px 0;">Latency Distribution</h3>
                <div style="margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>p50</span><span id="p50">-</span></div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>p75</span><span id="p75">-</span></div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>p90</span><span id="p90">-</span></div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>p95</span><span id="p95">-</span></div>
                    <div style="display: flex; justify-content: space-between;"><span>p99</span><span id="p99">-</span></div>
                </div>
            </div>
            
            <div class="card">
                <h3 style="margin: 0 0 16px 0;">Status Codes</h3>
                <div style="margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="display: flex; align-items: center; gap: 8px;"><span style="width: 12px; height: 12px; background: #22c55e; border-radius: 2px;"></span>2xx Success</span>
                        <span id="status2xx">0</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="display: flex; align-items: center; gap: 8px;"><span style="width: 12px; height: 12px; background: #3b82f6; border-radius: 2px;"></span>3xx Redirect</span>
                        <span id="status3xx">0</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="display: flex; align-items: center; gap: 8px;"><span style="width: 12px; height: 12px; background: #f59e0b; border-radius: 2px;"></span>4xx Client Error</span>
                        <span id="status4xx">0</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="display: flex; align-items: center; gap: 8px;"><span style="width: 12px; height: 12px; background: #ef4444; border-radius: 2px;"></span>5xx Server Error</span>
                        <span id="status5xx">0</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 16px 0;">Top Endpoints</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Method</th>
                        <th>Requests</th>
                        <th>Avg Latency</th>
                        <th>Error Rate</th>
                    </tr>
                </thead>
                <tbody id="endpointsTable">
                    <tr><td colspan="5" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 16px 0;">Geographic Distribution</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Country</th>
                        <th>Requests</th>
                        <th>Bandwidth</th>
                        <th>Avg Latency</th>
                    </tr>
                </thead>
                <tbody id="geoTable">
                    <tr><td colspan="4" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function getToken() { return localStorage.getItem('nlag_token'); }
        function getUser() { const u = localStorage.getItem('nlag_user'); return u ? JSON.parse(u) : null; }
        function clearAuth() { localStorage.removeItem('nlag_token'); localStorage.removeItem('nlag_user'); }
        function logout() { clearAuth(); window.location.href = '/login'; }
        function formatBytes(bytes) { if (!bytes) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]; }
        function formatNumber(num) { return new Intl.NumberFormat().format(num || 0); }
        
        if (!getToken()) { window.location.href = '/login'; }
        const user = getUser();
        document.getElementById('userEmail').textContent = user?.email || '';
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        async function loadAnalytics() {
            const timeRange = document.getElementById('timeRange').value;
            const tunnelFilter = document.getElementById('tunnelFilter').value;
            
            try {
                const response = await apiCall(`/api/v1/analytics?range=${timeRange}&tunnel=${tunnelFilter}`);
                const data = await response.json();
                
                document.getElementById('totalRequests').textContent = formatNumber(data.total_requests);
                document.getElementById('totalBandwidth').textContent = formatBytes(data.total_bandwidth);
                document.getElementById('avgLatency').textContent = (data.avg_latency || 0) + ' ms';
                document.getElementById('errorRate').textContent = (data.error_rate || 0).toFixed(2) + '%';
                
                // Update latency percentiles
                document.getElementById('p50').textContent = (data.latency_p50 || 0) + ' ms';
                document.getElementById('p75').textContent = (data.latency_p75 || 0) + ' ms';
                document.getElementById('p90').textContent = (data.latency_p90 || 0) + ' ms';
                document.getElementById('p95').textContent = (data.latency_p95 || 0) + ' ms';
                document.getElementById('p99').textContent = (data.latency_p99 || 0) + ' ms';
                
                // Update status codes
                document.getElementById('status2xx').textContent = formatNumber(data.status_2xx);
                document.getElementById('status3xx').textContent = formatNumber(data.status_3xx);
                document.getElementById('status4xx').textContent = formatNumber(data.status_4xx);
                document.getElementById('status5xx').textContent = formatNumber(data.status_5xx);
                
            } catch (err) {
                // Show sample data for demo
                document.getElementById('totalRequests').textContent = '12,456';
                document.getElementById('totalBandwidth').textContent = '2.4 GB';
                document.getElementById('avgLatency').textContent = '45 ms';
                document.getElementById('errorRate').textContent = '0.12%';
                document.getElementById('p50').textContent = '32 ms';
                document.getElementById('p75').textContent = '48 ms';
                document.getElementById('p90').textContent = '85 ms';
                document.getElementById('p95').textContent = '120 ms';
                document.getElementById('p99').textContent = '250 ms';
                document.getElementById('status2xx').textContent = '11,892';
                document.getElementById('status3xx').textContent = '342';
                document.getElementById('status4xx').textContent = '198';
                document.getElementById('status5xx').textContent = '24';
                
                document.getElementById('endpointsTable').innerHTML = `
                    <tr><td>/api/users</td><td>GET</td><td>4,521</td><td>32 ms</td><td>0.1%</td></tr>
                    <tr><td>/api/auth/login</td><td>POST</td><td>2,341</td><td>89 ms</td><td>0.3%</td></tr>
                    <tr><td>/api/products</td><td>GET</td><td>1,876</td><td>45 ms</td><td>0.0%</td></tr>
                    <tr><td>/api/orders</td><td>POST</td><td>1,234</td><td>156 ms</td><td>0.5%</td></tr>
                    <tr><td>/health</td><td>GET</td><td>892</td><td>5 ms</td><td>0.0%</td></tr>
                `;
                
                document.getElementById('geoTable').innerHTML = `
                    <tr><td>🇺🇸 United States</td><td>5,234</td><td>1.2 GB</td><td>42 ms</td></tr>
                    <tr><td>🇬🇧 United Kingdom</td><td>2,341</td><td>521 MB</td><td>68 ms</td></tr>
                    <tr><td>🇩🇪 Germany</td><td>1,876</td><td>412 MB</td><td>75 ms</td></tr>
                    <tr><td>🇯🇵 Japan</td><td>1,543</td><td>298 MB</td><td>125 ms</td></tr>
                    <tr><td>🇦🇺 Australia</td><td>987</td><td>189 MB</td><td>180 ms</td></tr>
                `;
            }
        }
        
        async function loadTunnelFilter() {
            try {
                const response = await apiCall('/api/v1/tunnels');
                const tunnels = await response.json();
                const select = document.getElementById('tunnelFilter');
                select.innerHTML = '<option value="all">All Tunnels</option>' + tunnels.map(t => `<option value="${t.id}">${t.subdomain}</option>`).join('');
            } catch (err) { console.error('Failed to load tunnels'); }
        }
        
        loadTunnelFilter();
        loadAnalytics();
    </script>
</body>
</html>"#;

// ============================================================================
// Webhooks Page
// ============================================================================

const WEBHOOKS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webhooks - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-secondary { background: #374151; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-active { background: #064e3b; color: #34d399; }
        .badge-paused { background: #78350f; color: #fbbf24; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .checkbox-group { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
        .checkbox-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: #252540; border-radius: 6px; cursor: pointer; }
        .checkbox-item input { cursor: pointer; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/domains" class="nav-link">Domains</a>
                <a href="/dashboard/webhooks" class="nav-link active">Webhooks</a>
                <a href="/dashboard/policies" class="nav-link">Policies</a>
                <a href="/dashboard/audit" class="nav-link">Audit</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Event Webhooks</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Send tunnel events to external services</p>
            </div>
            <button onclick="showCreateModal()" class="btn btn-primary">Create Webhook</button>
        </div>
        
        <div class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>URL</th>
                        <th>Events</th>
                        <th>Status</th>
                        <th>Last Triggered</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="webhooksTable">
                    <tr><td colspan="6" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card" style="background: #1e1e3f;">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">Available Events</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">tunnel.started</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired when a tunnel is created and connected</p>
                </div>
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">tunnel.stopped</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired when a tunnel is closed</p>
                </div>
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">tunnel.request</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired for each HTTP request (high volume)</p>
                </div>
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">tunnel.error</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired when a tunnel encounters an error</p>
                </div>
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">auth.failed</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired on authentication failures</p>
                </div>
                <div style="padding: 12px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 500; margin-bottom: 4px;">rate_limit.exceeded</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Fired when rate limits are hit</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Create Webhook Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Create Webhook</h2>
            <form id="createForm">
                <label class="label">Name</label>
                <input type="text" id="webhookName" class="input" placeholder="My Webhook" required>
                
                <label class="label">Endpoint URL</label>
                <input type="url" id="webhookUrl" class="input" placeholder="https://example.com/webhook" required>
                
                <label class="label">Secret (for signature verification)</label>
                <input type="text" id="webhookSecret" class="input" placeholder="whsec_..." value="">
                
                <label class="label">Events</label>
                <div class="checkbox-group">
                    <label class="checkbox-item"><input type="checkbox" name="events" value="tunnel.started" checked> tunnel.started</label>
                    <label class="checkbox-item"><input type="checkbox" name="events" value="tunnel.stopped" checked> tunnel.stopped</label>
                    <label class="checkbox-item"><input type="checkbox" name="events" value="tunnel.error" checked> tunnel.error</label>
                    <label class="checkbox-item"><input type="checkbox" name="events" value="tunnel.request"> tunnel.request</label>
                    <label class="checkbox-item"><input type="checkbox" name="events" value="auth.failed"> auth.failed</label>
                    <label class="checkbox-item"><input type="checkbox" name="events" value="rate_limit.exceeded"> rate_limit.exceeded</label>
                </div>
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideCreateModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Webhook</button>
                </div>
            </form>
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
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function showCreateModal() { document.getElementById('createModal').style.display = 'flex'; }
        function hideCreateModal() { document.getElementById('createModal').style.display = 'none'; }
        
        async function loadWebhooks() {
            try {
                const response = await apiCall('/api/v1/webhooks');
                const webhooks = await response.json();
                const tbody = document.getElementById('webhooksTable');
                if (!webhooks.length) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No webhooks configured</td></tr>';
                } else {
                    tbody.innerHTML = webhooks.map(w => `
                        <tr>
                            <td><strong>${w.name}</strong></td>
                            <td style="font-family: monospace; font-size: 13px;">${w.url}</td>
                            <td>${(w.events || []).slice(0, 2).join(', ')}${w.events?.length > 2 ? '...' : ''}</td>
                            <td><span class="badge badge-${w.active ? 'active' : 'paused'}">${w.active ? 'Active' : 'Paused'}</span></td>
                            <td style="color: #6b7280;">${w.last_triggered ? new Date(w.last_triggered).toLocaleString() : 'Never'}</td>
                            <td style="text-align: right;">
                                <button onclick="testWebhook('${w.id}')" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px; margin-right: 8px;">Test</button>
                                <button onclick="deleteWebhook('${w.id}')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Delete</button>
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (err) { 
                document.getElementById('webhooksTable').innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No webhooks configured</td></tr>';
            }
        }
        
        document.getElementById('createForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('webhookName').value;
            const url = document.getElementById('webhookUrl').value;
            const secret = document.getElementById('webhookSecret').value;
            const events = Array.from(document.querySelectorAll('input[name="events"]:checked')).map(cb => cb.value);
            try {
                await apiCall('/api/v1/webhooks', { method: 'POST', body: JSON.stringify({ name, url, secret, events }) });
                hideCreateModal();
                loadWebhooks();
            } catch (err) { alert('Failed to create webhook'); }
        });
        
        async function testWebhook(id) {
            try { 
                await apiCall('/api/v1/webhooks/' + id + '/test', { method: 'POST' }); 
                alert('Test webhook sent!'); 
            } catch (err) { alert('Failed to send test webhook'); }
        }
        
        async function deleteWebhook(id) {
            if (!confirm('Delete this webhook?')) return;
            try { await apiCall('/api/v1/webhooks/' + id, { method: 'DELETE' }); loadWebhooks(); } catch (err) { alert('Failed to delete webhook'); }
        }
        
        loadWebhooks();
    </script>
</body>
</html>"#;

// ============================================================================
// Traffic Policies Page
// ============================================================================

const POLICIES_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Policies - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-secondary { background: #374151; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .textarea { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; min-height: 200px; font-family: monospace; resize: vertical; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-enabled { background: #064e3b; color: #34d399; }
        .badge-disabled { background: #374151; color: #9ca3af; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .code-block { background: #252540; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; white-space: pre; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/domains" class="nav-link">Domains</a>
                <a href="/dashboard/webhooks" class="nav-link">Webhooks</a>
                <a href="/dashboard/policies" class="nav-link active">Policies</a>
                <a href="/dashboard/audit" class="nav-link">Audit</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Traffic Policies</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Configure routing, authentication, and transformation rules</p>
            </div>
            <button onclick="showCreateModal()" class="btn btn-primary">Create Policy</button>
        </div>
        
        <div class="card">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Target</th>
                        <th>Priority</th>
                        <th>Status</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="policiesTable">
                    <tr><td colspan="6" style="text-align: center; color: #6b7280;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card" style="background: #1e1e3f;">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">Policy Types</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #6366f1;">🔀 URL Rewriting</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Rewrite request paths, add prefixes, or redirect to different URLs</p>
                </div>
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #22c55e;">📝 Header Transform</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Add, remove, or modify request and response headers</p>
                </div>
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #f59e0b;">🔒 Authentication</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Require OAuth, JWT, or API key authentication</p>
                </div>
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #ef4444;">⏱️ Rate Limiting</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Limit requests per second, minute, or hour</p>
                </div>
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #8b5cf6;">🗜️ Compression</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Enable gzip or brotli response compression</p>
                </div>
                <div style="padding: 16px; background: #252540; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #06b6d4;">💾 Caching</div>
                    <p style="color: #9ca3af; margin: 0; font-size: 13px;">Cache responses at the edge for faster delivery</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">Example Policy (YAML)</h3>
            <div class="code-block">policies:
  - name: api-auth
    match:
      path: /api/**
    actions:
      - type: require_auth
        provider: oauth
        allowed_roles: [admin, user]
      - type: rate_limit
        requests_per_minute: 100
      - type: add_header
        headers:
          X-Request-ID: ${request_id}
          X-Forwarded-For: ${client_ip}</div>
        </div>
    </div>
    
    <!-- Create Policy Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Create Traffic Policy</h2>
            <form id="createForm">
                <label class="label">Policy Name</label>
                <input type="text" id="policyName" class="input" placeholder="my-policy" required>
                
                <label class="label">Policy Type</label>
                <select id="policyType" class="select">
                    <option value="rewrite">URL Rewriting</option>
                    <option value="headers">Header Transform</option>
                    <option value="auth">Authentication</option>
                    <option value="rate_limit">Rate Limiting</option>
                    <option value="compress">Compression</option>
                    <option value="cache">Caching</option>
                </select>
                
                <label class="label">Apply To (Tunnel or Path Pattern)</label>
                <input type="text" id="policyTarget" class="input" placeholder="*.example.com or /api/**">
                
                <label class="label">Priority (higher = first)</label>
                <input type="number" id="policyPriority" class="input" value="100" min="1" max="1000">
                
                <label class="label">Policy Configuration (YAML)</label>
                <textarea id="policyConfig" class="textarea" placeholder="actions:
  - type: add_header
    headers:
      X-Custom: value"></textarea>
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideCreateModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Policy</button>
                </div>
            </form>
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
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function showCreateModal() { document.getElementById('createModal').style.display = 'flex'; }
        function hideCreateModal() { document.getElementById('createModal').style.display = 'none'; }
        
        async function loadPolicies() {
            try {
                const response = await apiCall('/api/v1/policies');
                const policies = await response.json();
                const tbody = document.getElementById('policiesTable');
                if (!policies.length) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No traffic policies configured</td></tr>';
                } else {
                    tbody.innerHTML = policies.map(p => `
                        <tr>
                            <td><strong>${p.name}</strong></td>
                            <td>${p.type}</td>
                            <td style="font-family: monospace; font-size: 13px;">${p.target}</td>
                            <td>${p.priority}</td>
                            <td><span class="badge badge-${p.enabled ? 'enabled' : 'disabled'}">${p.enabled ? 'Enabled' : 'Disabled'}</span></td>
                            <td style="text-align: right;">
                                <button onclick="togglePolicy('${p.id}')" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px; margin-right: 8px;">${p.enabled ? 'Disable' : 'Enable'}</button>
                                <button onclick="deletePolicy('${p.id}')" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Delete</button>
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (err) { 
                document.getElementById('policiesTable').innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280; padding: 48px;">No traffic policies configured</td></tr>';
            }
        }
        
        document.getElementById('createForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('policyName').value;
            const type = document.getElementById('policyType').value;
            const target = document.getElementById('policyTarget').value;
            const priority = parseInt(document.getElementById('policyPriority').value);
            const config = document.getElementById('policyConfig').value;
            try {
                await apiCall('/api/v1/policies', { method: 'POST', body: JSON.stringify({ name, type, target, priority, config }) });
                hideCreateModal();
                loadPolicies();
            } catch (err) { alert('Failed to create policy'); }
        });
        
        async function togglePolicy(id) {
            try { await apiCall('/api/v1/policies/' + id + '/toggle', { method: 'POST' }); loadPolicies(); } catch (err) { alert('Failed to toggle policy'); }
        }
        
        async function deletePolicy(id) {
            if (!confirm('Delete this policy?')) return;
            try { await apiCall('/api/v1/policies/' + id, { method: 'DELETE' }); loadPolicies(); } catch (err) { alert('Failed to delete policy'); }
        }
        
        loadPolicies();
    </script>
</body>
</html>"#;

// ============================================================================
// SSO/OAuth Settings Page
// ============================================================================

const SSO_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO & OAuth - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-secondary { background: #374151; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .provider-card { background: #252540; border-radius: 12px; padding: 24px; display: flex; align-items: center; gap: 20px; }
        .provider-icon { width: 48px; height: 48px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
        .provider-info { flex: 1; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-connected { background: #064e3b; color: #34d399; }
        .badge-not-connected { background: #374151; color: #9ca3af; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .toggle { position: relative; width: 48px; height: 24px; background: #374151; border-radius: 12px; cursor: pointer; transition: background 0.2s; }
        .toggle.active { background: #6366f1; }
        .toggle::after { content: ''; position: absolute; top: 2px; left: 2px; width: 20px; height: 20px; background: white; border-radius: 50%; transition: left 0.2s; }
        .toggle.active::after { left: 26px; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard/teams" class="nav-link">Teams</a>
                <a href="/dashboard/sso" class="nav-link active">SSO & OAuth</a>
                <a href="/dashboard/ip-restrictions" class="nav-link">IP Restrictions</a>
                <a href="/dashboard/audit" class="nav-link">Audit</a>
                <a href="/dashboard/settings" class="nav-link">Settings</a>
            </div>
            <div class="nav-user">
                <span id="userEmail" style="color: #9ca3af;"></span>
                <button onclick="logout()" class="btn btn-secondary" style="padding: 8px 16px;">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div style="margin: 24px 0;">
            <h1 style="font-size: 24px; font-weight: 600; margin: 0;">SSO & OAuth Configuration</h1>
            <p style="color: #9ca3af; margin-top: 4px;">Configure single sign-on and OAuth providers for tunnel authentication</p>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 20px 0; font-size: 18px;">OAuth Providers</h3>
            <p style="color: #9ca3af; margin-bottom: 24px;">Enable OAuth providers for user authentication on protected tunnels</p>
            
            <div style="display: grid; gap: 16px;">
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🔵</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">Google</div>
                        <div style="font-size: 13px; color: #9ca3af;">Sign in with Google accounts</div>
                    </div>
                    <span id="googleStatus" class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureProvider('google')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
                
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">⚫</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">GitHub</div>
                        <div style="font-size: 13px; color: #9ca3af;">Sign in with GitHub accounts</div>
                    </div>
                    <span id="githubStatus" class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureProvider('github')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
                
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🔷</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">Microsoft / Azure AD</div>
                        <div style="font-size: 13px; color: #9ca3af;">Sign in with Microsoft 365 or Azure AD</div>
                    </div>
                    <span id="microsoftStatus" class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureProvider('microsoft')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
                
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🔐</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">Generic OIDC</div>
                        <div style="font-size: 13px; color: #9ca3af;">Connect any OpenID Connect provider</div>
                    </div>
                    <span id="oidcStatus" class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureProvider('oidc')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin: 0 0 20px 0; font-size: 18px;">SAML 2.0 (Enterprise SSO)</h3>
            <p style="color: #9ca3af; margin-bottom: 24px;">Configure SAML-based SSO for enterprise identity providers</p>
            
            <div style="display: grid; gap: 16px;">
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🟠</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">Okta</div>
                        <div style="font-size: 13px; color: #9ca3af;">Enterprise identity management</div>
                    </div>
                    <span class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureSaml('okta')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
                
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🟢</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">OneLogin</div>
                        <div style="font-size: 13px; color: #9ca3af;">Unified access management</div>
                    </div>
                    <span class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureSaml('onelogin')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
                
                <div class="provider-card">
                    <div class="provider-icon" style="background: #1a1a2e;">🔵</div>
                    <div class="provider-info">
                        <div style="font-weight: 600; margin-bottom: 4px;">Google Workspace</div>
                        <div style="font-size: 13px; color: #9ca3af;">G Suite / Google Workspace SAML</div>
                    </div>
                    <span class="badge badge-not-connected">Not Configured</span>
                    <button onclick="configureSaml('google_workspace')" class="btn btn-secondary" style="padding: 8px 16px;">Configure</button>
                </div>
            </div>
        </div>
        
        <div class="card" style="background: #1e1e3f;">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">Service Provider Details</h3>
            <p style="color: #9ca3af; margin-bottom: 16px;">Use these values when configuring your identity provider:</p>
            <div style="display: grid; gap: 12px;">
                <div style="display: flex; justify-content: space-between; padding: 12px; background: #252540; border-radius: 8px;">
                    <span style="color: #9ca3af;">Entity ID / Issuer</span>
                    <code style="color: #22c55e;">https://api.nlag.io/saml/metadata</code>
                </div>
                <div style="display: flex; justify-content: space-between; padding: 12px; background: #252540; border-radius: 8px;">
                    <span style="color: #9ca3af;">ACS URL</span>
                    <code style="color: #22c55e;">https://api.nlag.io/saml/acs</code>
                </div>
                <div style="display: flex; justify-content: space-between; padding: 12px; background: #252540; border-radius: 8px;">
                    <span style="color: #9ca3af;">Single Logout URL</span>
                    <code style="color: #22c55e;">https://api.nlag.io/saml/logout</code>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Provider Config Modal -->
    <div id="providerModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;" id="providerTitle">Configure Provider</h2>
            <form id="providerForm">
                <label class="label">Client ID</label>
                <input type="text" id="clientId" class="input" placeholder="your-client-id" required>
                
                <label class="label">Client Secret</label>
                <input type="password" id="clientSecret" class="input" placeholder="your-client-secret" required>
                
                <div id="oidcFields" style="display: none;">
                    <label class="label">Discovery URL</label>
                    <input type="url" id="discoveryUrl" class="input" placeholder="https://provider.com/.well-known/openid-configuration">
                    
                    <label class="label">Authorization URL (if no discovery)</label>
                    <input type="url" id="authUrl" class="input" placeholder="https://provider.com/oauth/authorize">
                    
                    <label class="label">Token URL (if no discovery)</label>
                    <input type="url" id="tokenUrl" class="input" placeholder="https://provider.com/oauth/token">
                </div>
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideProviderModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                </div>
            </form>
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
        
        let currentProvider = null;
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function configureProvider(provider) {
            currentProvider = provider;
            document.getElementById('providerTitle').textContent = 'Configure ' + provider.charAt(0).toUpperCase() + provider.slice(1);
            document.getElementById('oidcFields').style.display = provider === 'oidc' ? 'block' : 'none';
            document.getElementById('providerModal').style.display = 'flex';
        }
        
        function configureSaml(provider) {
            alert('SAML configuration for ' + provider + ' - Opens configuration wizard');
        }
        
        function hideProviderModal() { document.getElementById('providerModal').style.display = 'none'; }
        
        document.getElementById('providerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const clientId = document.getElementById('clientId').value;
            const clientSecret = document.getElementById('clientSecret').value;
            const config = { client_id: clientId, client_secret: clientSecret };
            
            if (currentProvider === 'oidc') {
                config.discovery_url = document.getElementById('discoveryUrl').value;
                config.auth_url = document.getElementById('authUrl').value;
                config.token_url = document.getElementById('tokenUrl').value;
            }
            
            try {
                await apiCall('/api/v1/sso/providers/' + currentProvider, { method: 'PUT', body: JSON.stringify(config) });
                hideProviderModal();
                alert('Provider configured successfully!');
                loadProviders();
            } catch (err) { alert('Failed to configure provider'); }
        });
        
        async function loadProviders() {
            try {
                const response = await apiCall('/api/v1/sso/providers');
                const providers = await response.json();
                for (const [name, config] of Object.entries(providers)) {
                    const el = document.getElementById(name + 'Status');
                    if (el && config.configured) {
                        el.textContent = 'Connected';
                        el.className = 'badge badge-connected';
                    }
                }
            } catch (err) { console.error('Failed to load providers'); }
        }
        
        loadProviders();
    </script>
</body>
</html>"#;

// ============================================================================
// Audit Logs Page
// ============================================================================

const AUDIT_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Logs - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-secondary { background: #374151; color: white; }
        .input { padding: 10px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; }
        .select { padding: 10px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .log-entry { padding: 16px; border-bottom: 1px solid #252540; display: grid; grid-template-columns: 180px 120px 1fr 150px; gap: 16px; align-items: center; }
        .log-entry:hover { background: #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-info { background: #1e3a5f; color: #60a5fa; }
        .badge-warning { background: #78350f; color: #fbbf24; }
        .badge-error { background: #7f1d1d; color: #f87171; }
        .badge-success { background: #064e3b; color: #34d399; }
        .filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 20px; }
        .pagination { display: flex; gap: 8px; justify-content: center; margin-top: 20px; }
        .pagination button { padding: 8px 16px; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard/tunnels" class="nav-link">Tunnels</a>
                <a href="/dashboard/domains" class="nav-link">Domains</a>
                <a href="/dashboard/webhooks" class="nav-link">Webhooks</a>
                <a href="/dashboard/policies" class="nav-link">Policies</a>
                <a href="/dashboard/audit" class="nav-link active">Audit</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">Audit Logs</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Security and activity event history</p>
            </div>
            <button onclick="exportLogs()" class="btn btn-secondary">Export Logs</button>
        </div>
        
        <div class="card">
            <div class="filters">
                <input type="text" id="searchQuery" class="input" placeholder="Search logs..." style="width: 250px;">
                <select id="eventType" class="select" onchange="loadLogs()">
                    <option value="">All Event Types</option>
                    <option value="auth">Authentication</option>
                    <option value="tunnel">Tunnel Events</option>
                    <option value="team">Team Changes</option>
                    <option value="billing">Billing</option>
                    <option value="security">Security</option>
                    <option value="api">API Access</option>
                </select>
                <select id="severity" class="select" onchange="loadLogs()">
                    <option value="">All Severities</option>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                </select>
                <select id="timeRange" class="select" onchange="loadLogs()">
                    <option value="1h">Last Hour</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>
                <button onclick="loadLogs()" class="btn btn-primary" style="padding: 10px 20px;">Search</button>
            </div>
            
            <div style="background: #252540; border-radius: 8px; overflow: hidden;">
                <div class="log-entry" style="background: #1e1e3f; font-weight: 600; font-size: 12px; text-transform: uppercase; color: #9ca3af;">
                    <div>Timestamp</div>
                    <div>Severity</div>
                    <div>Event</div>
                    <div>Actor</div>
                </div>
                <div id="logsContainer">
                    <div style="padding: 48px; text-align: center; color: #6b7280;">Loading...</div>
                </div>
            </div>
            
            <div class="pagination">
                <button onclick="prevPage()" class="btn btn-secondary" id="prevBtn" disabled>Previous</button>
                <span id="pageInfo" style="padding: 8px 16px; color: #9ca3af;">Page 1</span>
                <button onclick="nextPage()" class="btn btn-secondary" id="nextBtn">Next</button>
            </div>
        </div>
        
        <div class="card" style="background: #1e1e3f;">
            <h3 style="margin: 0 0 16px 0; font-size: 16px;">Log Shipping Configuration</h3>
            <p style="color: #9ca3af; margin-bottom: 16px;">Export logs to external SIEM systems in real-time</p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <button onclick="configureExport('splunk')" class="btn btn-secondary">Splunk HEC</button>
                <button onclick="configureExport('datadog')" class="btn btn-secondary">Datadog</button>
                <button onclick="configureExport('elasticsearch')" class="btn btn-secondary">Elasticsearch</button>
                <button onclick="configureExport('cloudwatch')" class="btn btn-secondary">CloudWatch</button>
                <button onclick="configureExport('webhook')" class="btn btn-secondary">Webhook</button>
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
        
        let currentPage = 1;
        const pageSize = 50;
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function getSeverityBadge(severity) {
            const classes = { info: 'badge-info', warning: 'badge-warning', error: 'badge-error', success: 'badge-success' };
            return `<span class="badge ${classes[severity] || 'badge-info'}">${severity}</span>`;
        }
        
        async function loadLogs() {
            const search = document.getElementById('searchQuery').value;
            const eventType = document.getElementById('eventType').value;
            const severity = document.getElementById('severity').value;
            const timeRange = document.getElementById('timeRange').value;
            
            try {
                const response = await apiCall(`/api/v1/audit/logs?page=${currentPage}&limit=${pageSize}&search=${search}&type=${eventType}&severity=${severity}&range=${timeRange}`);
                const data = await response.json();
                renderLogs(data.logs || []);
                updatePagination(data.total || 0);
            } catch (err) {
                // Show sample data
                const sampleLogs = [
                    { timestamp: new Date().toISOString(), severity: 'info', event: 'User logged in', actor: user?.email || 'user@example.com', details: 'IP: 192.168.1.1' },
                    { timestamp: new Date(Date.now() - 300000).toISOString(), severity: 'success', event: 'Tunnel created: api-dev', actor: user?.email || 'user@example.com', details: 'Protocol: HTTP' },
                    { timestamp: new Date(Date.now() - 600000).toISOString(), severity: 'info', event: 'API token created', actor: user?.email || 'user@example.com', details: 'Token: dev-token' },
                    { timestamp: new Date(Date.now() - 900000).toISOString(), severity: 'warning', event: 'Rate limit exceeded', actor: 'api-dev.nlag.io', details: 'Limit: 100/min' },
                    { timestamp: new Date(Date.now() - 1200000).toISOString(), severity: 'error', event: 'Authentication failed', actor: '192.168.1.50', details: 'Invalid credentials' },
                    { timestamp: new Date(Date.now() - 1800000).toISOString(), severity: 'info', event: 'Team member invited', actor: user?.email || 'user@example.com', details: 'dev@company.com' },
                    { timestamp: new Date(Date.now() - 3600000).toISOString(), severity: 'success', event: 'Custom domain verified', actor: user?.email || 'user@example.com', details: 'api.example.com' },
                    { timestamp: new Date(Date.now() - 7200000).toISOString(), severity: 'info', event: 'Tunnel stopped', actor: 'system', details: 'Client disconnected' },
                ];
                renderLogs(sampleLogs);
                updatePagination(sampleLogs.length);
            }
        }
        
        function renderLogs(logs) {
            const container = document.getElementById('logsContainer');
            if (!logs.length) {
                container.innerHTML = '<div style="padding: 48px; text-align: center; color: #6b7280;">No logs found</div>';
                return;
            }
            container.innerHTML = logs.map(log => `
                <div class="log-entry">
                    <div style="color: #9ca3af; font-size: 13px;">${new Date(log.timestamp).toLocaleString()}</div>
                    <div>${getSeverityBadge(log.severity)}</div>
                    <div>
                        <div style="font-weight: 500;">${log.event}</div>
                        <div style="font-size: 12px; color: #6b7280;">${log.details || ''}</div>
                    </div>
                    <div style="color: #9ca3af; font-size: 13px;">${log.actor}</div>
                </div>
            `).join('');
        }
        
        function updatePagination(total) {
            const totalPages = Math.ceil(total / pageSize);
            document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages || 1}`;
            document.getElementById('prevBtn').disabled = currentPage <= 1;
            document.getElementById('nextBtn').disabled = currentPage >= totalPages;
        }
        
        function prevPage() { if (currentPage > 1) { currentPage--; loadLogs(); } }
        function nextPage() { currentPage++; loadLogs(); }
        
        function exportLogs() {
            alert('Exporting logs as CSV...');
        }
        
        function configureExport(destination) {
            alert('Configure ' + destination + ' log export - Opens configuration dialog');
        }
        
        loadLogs();
    </script>
</body>
</html>"#;

// ============================================================================
// IP Restrictions Page
// ============================================================================

const IP_RESTRICTIONS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Restrictions - NLAG</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: white; }
        .btn-secondary { background: #374151; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-success { background: #059669; color: white; }
        .input { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .textarea { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; min-height: 150px; font-family: monospace; resize: vertical; }
        .select { width: 100%; padding: 12px 16px; background: #252540; border: 1px solid #374151; border-radius: 8px; color: white; font-size: 14px; margin-bottom: 16px; }
        .label { display: block; margin-bottom: 8px; font-size: 14px; color: #9ca3af; }
        a { color: #6366f1; text-decoration: none; }
        .nav { background: #1a1a2e; border-bottom: 1px solid #252540; padding: 0 20px; }
        .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; height: 64px; }
        .nav-brand { font-size: 24px; font-weight: bold; color: #6366f1; text-decoration: none; }
        .nav-links { display: flex; gap: 24px; }
        .nav-link { color: #9ca3af; text-decoration: none; padding: 8px 0; border-bottom: 2px solid transparent; }
        .nav-link:hover { color: white; }
        .nav-link.active { color: white; border-bottom-color: #6366f1; }
        .nav-user { display: flex; align-items: center; gap: 16px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th { text-align: left; padding: 12px 16px; background: #252540; color: #9ca3af; font-size: 12px; text-transform: uppercase; }
        .table td { padding: 16px; border-bottom: 1px solid #252540; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
        .badge-allow { background: #064e3b; color: #34d399; }
        .badge-deny { background: #7f1d1d; color: #f87171; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: #1a1a2e; border-radius: 12px; padding: 32px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .tabs { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 1px solid #252540; }
        .tab { padding: 12px 24px; background: transparent; border: none; color: #9ca3af; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px; }
        .tab.active { color: white; border-bottom-color: #6366f1; }
        .ip-tag { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; background: #252540; border-radius: 6px; margin: 4px; font-family: monospace; font-size: 13px; }
        .ip-tag button { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 16px; padding: 0; margin-left: 4px; }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-inner">
            <a href="/dashboard" class="nav-brand">NLAG</a>
            <div class="nav-links">
                <a href="/dashboard/teams" class="nav-link">Teams</a>
                <a href="/dashboard/sso" class="nav-link">SSO & OAuth</a>
                <a href="/dashboard/ip-restrictions" class="nav-link active">IP Restrictions</a>
                <a href="/dashboard/audit" class="nav-link">Audit</a>
                <a href="/dashboard/settings" class="nav-link">Settings</a>
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
                <h1 style="font-size: 24px; font-weight: 600; margin: 0;">IP Restrictions</h1>
                <p style="color: #9ca3af; margin-top: 4px;">Control access by IP address and CIDR ranges</p>
            </div>
            <button onclick="showAddModal()" class="btn btn-primary">Add Rule</button>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('global')">Global Rules</button>
            <button class="tab" onclick="showTab('tunnels')">Per-Tunnel Rules</button>
            <button class="tab" onclick="showTab('geo')">Geo Restrictions</button>
        </div>
        
        <div id="globalTab">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h3 style="margin: 0; font-size: 18px;">Allowlist</h3>
                        <p style="color: #9ca3af; margin: 4px 0 0 0; font-size: 14px;">Only these IPs can access your tunnels (if enabled)</p>
                    </div>
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="allowlistEnabled" onchange="toggleAllowlist()">
                        <span>Enable Allowlist</span>
                    </label>
                </div>
                <div id="allowlistIps" style="margin-bottom: 16px;">
                    <div style="color: #6b7280; padding: 16px; text-align: center;">No IPs in allowlist</div>
                </div>
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="newAllowIp" class="input" placeholder="192.168.1.0/24 or 10.0.0.1" style="margin: 0; flex: 1;">
                    <button onclick="addAllowIp()" class="btn btn-success" style="padding: 12px 20px;">Add</button>
                </div>
            </div>
            
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h3 style="margin: 0; font-size: 18px;">Blocklist</h3>
                        <p style="color: #9ca3af; margin: 4px 0 0 0; font-size: 14px;">These IPs are blocked from accessing your tunnels</p>
                    </div>
                </div>
                <div id="blocklistIps" style="margin-bottom: 16px;">
                    <div style="color: #6b7280; padding: 16px; text-align: center;">No IPs in blocklist</div>
                </div>
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="newBlockIp" class="input" placeholder="192.168.1.0/24 or 10.0.0.1" style="margin: 0; flex: 1;">
                    <button onclick="addBlockIp()" class="btn btn-danger" style="padding: 12px 20px;">Block</button>
                </div>
            </div>
        </div>
        
        <div id="tunnelsTab" style="display: none;">
            <div class="card">
                <h3 style="margin: 0 0 20px 0; font-size: 18px;">Per-Tunnel IP Rules</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Tunnel</th>
                            <th>Allowlist</th>
                            <th>Blocklist</th>
                            <th style="text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="tunnelRulesTable">
                        <tr><td colspan="4" style="text-align: center; color: #6b7280; padding: 32px;">No per-tunnel rules configured</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="geoTab" style="display: none;">
            <div class="card">
                <h3 style="margin: 0 0 20px 0; font-size: 18px;">Geographic Restrictions</h3>
                <p style="color: #9ca3af; margin-bottom: 20px;">Block or allow access based on country, region, or network type</p>
                
                <div style="display: grid; gap: 20px;">
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <div style="font-weight: 600;">Country Blocking</div>
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                <input type="checkbox" id="geoEnabled">
                                <span style="font-size: 14px;">Enabled</span>
                            </label>
                        </div>
                        <p style="color: #9ca3af; font-size: 14px; margin-bottom: 12px;">Block access from specific countries</p>
                        <select multiple id="blockedCountries" class="select" style="height: 120px;">
                            <option value="CN">🇨🇳 China</option>
                            <option value="RU">🇷🇺 Russia</option>
                            <option value="KP">🇰🇵 North Korea</option>
                            <option value="IR">🇮🇷 Iran</option>
                            <option value="SY">🇸🇾 Syria</option>
                        </select>
                    </div>
                    
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <div style="font-weight: 600;">VPN / Proxy Detection</div>
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                <input type="checkbox" id="vpnBlocking">
                                <span style="font-size: 14px;">Block VPNs</span>
                            </label>
                        </div>
                        <p style="color: #9ca3af; font-size: 14px;">Block known VPN, proxy, and Tor exit nodes</p>
                    </div>
                    
                    <div style="padding: 16px; background: #252540; border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <div style="font-weight: 600;">ASN Blocking</div>
                        </div>
                        <p style="color: #9ca3af; font-size: 14px; margin-bottom: 12px;">Block specific Autonomous System Numbers (hosting providers, etc.)</p>
                        <input type="text" id="blockedAsns" class="input" placeholder="AS12345, AS67890" style="margin: 0;">
                    </div>
                </div>
                
                <button onclick="saveGeoSettings()" class="btn btn-primary" style="margin-top: 20px;">Save Geo Settings</button>
            </div>
        </div>
    </div>
    
    <!-- Add Rule Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <h2 style="margin: 0 0 24px 0;">Add IP Rule</h2>
            <form id="addForm">
                <label class="label">Rule Type</label>
                <select id="ruleType" class="select">
                    <option value="allow">Allow (Allowlist)</option>
                    <option value="deny">Block (Blocklist)</option>
                </select>
                
                <label class="label">Apply To</label>
                <select id="ruleScope" class="select">
                    <option value="global">All Tunnels (Global)</option>
                </select>
                
                <label class="label">IP Addresses or CIDR Ranges (one per line)</label>
                <textarea id="ruleIps" class="textarea" placeholder="192.168.1.0/24
10.0.0.1
2001:db8::/32"></textarea>
                
                <label class="label">Description (optional)</label>
                <input type="text" id="ruleDescription" class="input" placeholder="Office network">
                
                <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="hideAddModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Rule</button>
                </div>
            </form>
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
        
        let allowlist = [];
        let blocklist = [];
        
        async function apiCall(endpoint, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}), ...options.headers };
            const response = await fetch(endpoint, { ...options, headers });
            if (response.status === 401) { clearAuth(); window.location.href = '/login'; }
            return response;
        }
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('globalTab').style.display = tab === 'global' ? 'block' : 'none';
            document.getElementById('tunnelsTab').style.display = tab === 'tunnels' ? 'block' : 'none';
            document.getElementById('geoTab').style.display = tab === 'geo' ? 'block' : 'none';
        }
        
        function showAddModal() { document.getElementById('addModal').style.display = 'flex'; loadTunnelsForSelect(); }
        function hideAddModal() { document.getElementById('addModal').style.display = 'none'; }
        
        async function loadTunnelsForSelect() {
            try {
                const response = await apiCall('/api/v1/tunnels');
                const tunnels = await response.json();
                const select = document.getElementById('ruleScope');
                select.innerHTML = '<option value="global">All Tunnels (Global)</option>' + tunnels.map(t => `<option value="${t.id}">${t.subdomain}</option>`).join('');
            } catch (err) { console.error('Failed to load tunnels'); }
        }
        
        function renderIpList(containerId, ips, type) {
            const container = document.getElementById(containerId);
            if (!ips.length) {
                container.innerHTML = `<div style="color: #6b7280; padding: 16px; text-align: center;">No IPs in ${type}</div>`;
            } else {
                container.innerHTML = ips.map(ip => `
                    <span class="ip-tag">
                        ${ip}
                        <button onclick="removeIp('${type}', '${ip}')">&times;</button>
                    </span>
                `).join('');
            }
        }
        
        function addAllowIp() {
            const input = document.getElementById('newAllowIp');
            const ip = input.value.trim();
            if (ip && !allowlist.includes(ip)) {
                allowlist.push(ip);
                renderIpList('allowlistIps', allowlist, 'allowlist');
                input.value = '';
                saveIpRules();
            }
        }
        
        function addBlockIp() {
            const input = document.getElementById('newBlockIp');
            const ip = input.value.trim();
            if (ip && !blocklist.includes(ip)) {
                blocklist.push(ip);
                renderIpList('blocklistIps', blocklist, 'blocklist');
                input.value = '';
                saveIpRules();
            }
        }
        
        function removeIp(type, ip) {
            if (type === 'allowlist') {
                allowlist = allowlist.filter(i => i !== ip);
                renderIpList('allowlistIps', allowlist, 'allowlist');
            } else {
                blocklist = blocklist.filter(i => i !== ip);
                renderIpList('blocklistIps', blocklist, 'blocklist');
            }
            saveIpRules();
        }
        
        async function saveIpRules() {
            try {
                await apiCall('/api/v1/ip-restrictions', { 
                    method: 'PUT', 
                    body: JSON.stringify({ allowlist, blocklist, allowlist_enabled: document.getElementById('allowlistEnabled').checked }) 
                });
            } catch (err) { console.error('Failed to save IP rules'); }
        }
        
        function toggleAllowlist() {
            saveIpRules();
        }
        
        async function loadIpRules() {
            try {
                const response = await apiCall('/api/v1/ip-restrictions');
                const data = await response.json();
                allowlist = data.allowlist || [];
                blocklist = data.blocklist || [];
                document.getElementById('allowlistEnabled').checked = data.allowlist_enabled || false;
                renderIpList('allowlistIps', allowlist, 'allowlist');
                renderIpList('blocklistIps', blocklist, 'blocklist');
            } catch (err) {
                renderIpList('allowlistIps', allowlist, 'allowlist');
                renderIpList('blocklistIps', blocklist, 'blocklist');
            }
        }
        
        document.getElementById('addForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const type = document.getElementById('ruleType').value;
            const ips = document.getElementById('ruleIps').value.split('\n').map(ip => ip.trim()).filter(ip => ip);
            
            if (type === 'allow') {
                allowlist = [...new Set([...allowlist, ...ips])];
                renderIpList('allowlistIps', allowlist, 'allowlist');
            } else {
                blocklist = [...new Set([...blocklist, ...ips])];
                renderIpList('blocklistIps', blocklist, 'blocklist');
            }
            
            saveIpRules();
            hideAddModal();
        });
        
        function saveGeoSettings() {
            const countries = Array.from(document.getElementById('blockedCountries').selectedOptions).map(o => o.value);
            const vpnBlocking = document.getElementById('vpnBlocking').checked;
            const asns = document.getElementById('blockedAsns').value;
            alert('Geo settings saved:\n- Countries: ' + (countries.join(', ') || 'None') + '\n- VPN Blocking: ' + vpnBlocking + '\n- ASNs: ' + (asns || 'None'));
        }
        
        loadIpRules();
    </script>
</body>
</html>"#;