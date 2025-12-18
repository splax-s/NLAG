//! REST API for NLAG Control Plane
//!
//! Provides endpoints for:
//! - Authentication (login, register, token refresh)
//! - Tunnel management (list, create, delete)
//! - Agent management (list, revoke)
//! - Admin operations (stats, config)
//! - API Key management
//! - Billing and subscription management

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::apikeys::{ApiKeyManager, CreateApiKeyRequest as ApiKeyCreateRequest, ApiKeyScope};
use crate::auth::AuthService;
use crate::billing::{BillingManager, SubscriptionTier};
use crate::store::Store;
use crate::traffic::{TrafficRecord, TrafficStore, TrafficQuery};

/// API state shared across handlers
pub struct ApiState {
    pub auth: Arc<AuthService>,
    pub store: Arc<Store>,
    pub api_keys: Arc<ApiKeyManager>,
    pub billing: Arc<BillingManager>,
    pub traffic_store: Arc<dyn TrafficStore>,
}

/// Authenticated user extracted from JWT token
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub scopes: Vec<String>,
}

/// Extractor for authenticated users
///
/// Extracts and validates the Bearer token from the Authorization header.
impl FromRequestParts<Arc<ApiState>> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<ApiState>) -> Result<Self, Self::Rejection> {
        // Get Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| ApiError {
                error: "missing_authorization".to_string(),
                message: "Authorization header required".to_string(),
                code: "unauthorized".to_string(),
            })?;

        // Extract Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or_else(|| ApiError {
                error: "invalid_authorization".to_string(),
                message: "Bearer token required".to_string(),
                code: "unauthorized".to_string(),
            })?;

        // Validate token
        let claims = state.auth.validate_token(token)
            .map_err(|e| ApiError {
                error: "invalid_token".to_string(),
                message: e.to_string(),
                code: "unauthorized".to_string(),
            })?;

        // Ensure it's an access token
        if claims.typ != "access" {
            return Err(ApiError {
                error: "invalid_token_type".to_string(),
                message: "Access token required".to_string(),
                code: "unauthorized".to_string(),
            });
        }

        Ok(AuthenticatedUser {
            user_id: claims.sub,
            scopes: claims.scopes,
        })
    }
}

/// Create the API router
pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // Public endpoints
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh_token))
        // Authenticated endpoints
        .route("/api/v1/tunnels", get(list_tunnels))
        .route("/api/v1/tunnels", post(create_tunnel))
        .route("/api/v1/tunnels/count", get(get_tunnel_count))
        .route("/api/v1/tunnels/{id}", get(get_tunnel))
        .route("/api/v1/tunnels/{id}", delete(delete_tunnel))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{id}", delete(revoke_agent))
        .route("/api/v1/tokens", get(list_tokens))
        .route("/api/v1/tokens", post(create_token))
        .route("/api/v1/tokens/{id}", delete(revoke_token))
        // Traffic sync endpoint (from agent)
        .route("/api/v1/traffic/sync", post(sync_traffic))
        // Traffic query endpoints (for dashboard)
        .route("/api/v1/traffic", get(query_traffic))
        .route("/api/v1/traffic/metrics", get(get_traffic_metrics))
        // API Key management endpoints
        .route("/api/v1/apikeys", get(list_api_keys))
        .route("/api/v1/apikeys", post(create_api_key))
        .route("/api/v1/apikeys/{id}", delete(revoke_api_key))
        // Billing endpoints
        .route("/api/v1/billing/subscription", get(get_subscription))
        .route("/api/v1/billing/subscription", post(update_subscription))
        .route("/api/v1/billing/usage", get(get_usage))
        .route("/api/v1/billing/webhook", post(billing_webhook))
        // Admin endpoints
        .route("/api/v1/admin/stats", get(admin_stats))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// === Request/Response Types ===

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub expires_at: u64,
    pub token_type: String,
    pub user: UserInfoResponse,
}

#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub email: String,
    pub tier: String,
    pub max_tunnels: u32,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub expires_at: u64,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTunnelRequest {
    pub name: String,
    pub protocol: String,
    pub subdomain: Option<String>,
    pub custom_domain: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TunnelResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub subdomain: String,
    pub public_url: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub id: String,
    pub name: Option<String>,
    pub last_seen: String,
    pub status: String,
    pub tunnels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>, // Only returned on creation
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_users: u64,
    pub total_agents: u64,
    pub total_tunnels: u64,
    pub active_connections: u64,
    pub bytes_transferred_24h: u64,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub code: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.code.as_str() {
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "forbidden" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "conflict" => StatusCode::CONFLICT,
            "validation_error" => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

// === Handlers ===

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn register(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let user = state.store.create_user(&req.email, &req.password, req.name.as_deref())
        .await
        .map_err(|e| ApiError {
            error: "registration_failed".to_string(),
            message: e.to_string(),
            code: "conflict".to_string(),
        })?;

    Ok(Json(RegisterResponse {
        user_id: user.id.clone(),
        email: user.email.clone(),
    }))
}

async fn login(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let user = state.store.get_user_by_email(&req.email)
        .await
        .map_err(|_| ApiError {
            error: "invalid_credentials".to_string(),
            message: "Invalid email or password".to_string(),
            code: "unauthorized".to_string(),
        })?;

    // Verify password (in production, use bcrypt/argon2)
    if !state.store.verify_password(&user.id, &req.password).await {
        return Err(ApiError {
            error: "invalid_credentials".to_string(),
            message: "Invalid email or password".to_string(),
            code: "unauthorized".to_string(),
        });
    }

    let (access_token, refresh_token, expires_in) = state.auth.create_tokens(&user.id)
        .map_err(|e| ApiError {
            error: "token_creation_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    // Get user subscription tier
    let subscription = state.billing.get_or_create_subscription(&user.id);
    let limits = subscription.tier.limits();
    let tier_name = format!("{:?}", subscription.tier).to_lowercase();

    // Calculate expires_at
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now + expires_in;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in,
        expires_at,
        token_type: "Bearer".to_string(),
        user: UserInfoResponse {
            email: user.email.clone(),
            tier: tier_name,
            max_tunnels: limits.max_tunnels,
        },
    }))
}

async fn refresh_token(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshTokenResponse>, ApiError> {
    let (access_token, refresh_token, expires_in) = state.auth.refresh_tokens(&req.refresh_token)
        .map_err(|e| ApiError {
            error: "refresh_failed".to_string(),
            message: e.to_string(),
            code: "unauthorized".to_string(),
        })?;

    // Calculate expires_at
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now + expires_in;

    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token,
        expires_in,
        expires_at,
        token_type: "Bearer".to_string(),
    }))
}

async fn list_tunnels(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<TunnelResponse>>, ApiError> {
    let tunnels = state.store.list_tunnels(&user.user_id)
        .await
        .map_err(|e| ApiError {
            error: "list_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(tunnels))
}

async fn create_tunnel(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Json(req): Json<CreateTunnelRequest>,
) -> Result<Json<TunnelResponse>, ApiError> {
    // Check tunnel limit for this user
    let subscription = state.billing.get_or_create_subscription(&user.user_id);
    let limits = subscription.tier.limits();
    
    let current_tunnels = state.store.list_tunnels(&user.user_id)
        .await
        .map_err(|e| ApiError {
            error: "check_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;
    
    if current_tunnels.len() >= limits.max_tunnels as usize {
        return Err(ApiError {
            error: "tunnel_limit_exceeded".to_string(),
            message: format!(
                "Tunnel limit reached. Your {} plan allows {} tunnel(s). Upgrade to create more.",
                format!("{:?}", subscription.tier),
                limits.max_tunnels
            ),
            code: "forbidden".to_string(),
        });
    }

    let tunnel = state.store.create_tunnel(
        &user.user_id,
        &req.name,
        &req.protocol,
        req.subdomain.as_deref(),
        req.custom_domain.as_deref(),
    )
    .await
    .map_err(|e| ApiError {
        error: "creation_failed".to_string(),
        message: e.to_string(),
        code: "conflict".to_string(),
    })?;

    Ok(Json(tunnel))
}

async fn get_tunnel(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tunnel = state.store.get_tunnel(&id)
        .await
        .map_err(|_| ApiError {
            error: "not_found".to_string(),
            message: "Tunnel not found".to_string(),
            code: "not_found".to_string(),
        })?;

    Ok(Json(tunnel))
}

async fn delete_tunnel(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.store.delete_tunnel(&id)
        .await
        .map_err(|_| ApiError {
            error: "delete_failed".to_string(),
            message: "Failed to delete tunnel".to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_agents(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<AgentResponse>>, ApiError> {
    let agents = state.store.list_agents(&user.user_id)
        .await
        .map_err(|e| ApiError {
            error: "list_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(agents))
}

async fn revoke_agent(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.store.revoke_agent(&id)
        .await
        .map_err(|_| ApiError {
            error: "revoke_failed".to_string(),
            message: "Failed to revoke agent".to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_tokens(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<TokenResponse>>, ApiError> {
    let tokens = state.store.list_tokens(&user.user_id)
        .await
        .map_err(|e| ApiError {
            error: "list_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(tokens))
}

async fn create_token(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let token = state.store.create_token(
        &user.user_id,
        &req.name,
        &req.scopes,
        req.expires_in_days,
    )
    .await
    .map_err(|e| ApiError {
        error: "creation_failed".to_string(),
        message: e.to_string(),
        code: "internal_error".to_string(),
    })?;

    Ok(Json(token))
}

async fn revoke_token(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.store.revoke_token(&id)
        .await
        .map_err(|_| ApiError {
            error: "revoke_failed".to_string(),
            message: "Failed to revoke token".to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn admin_stats(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<StatsResponse>, ApiError> {
    let stats = state.store.get_stats()
        .await
        .map_err(|e| ApiError {
            error: "stats_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(stats))
}

// === API Key Handlers ===

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<u32>,
}

async fn list_api_keys(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    let keys = state.api_keys.list_keys(&user.user_id);
    let responses: Vec<ApiKeyResponse> = keys.iter().map(|k| ApiKeyResponse {
        id: k.id.clone(),
        name: k.name.clone(),
        prefix: k.prefix.clone(),
        secret: None, // Never return the secret after creation
        scopes: k.scopes.iter().map(|s| format!("{:?}", s)).collect(),
        created_at: k.created_at.to_rfc3339(),
        expires_at: k.expires_at.map(|d: chrono::DateTime<chrono::Utc>| d.to_rfc3339()),
    }).collect();

    Ok(Json(responses))
}

async fn create_api_key(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    let scopes: Vec<ApiKeyScope> = req.scopes.iter()
        .filter_map(|s| match s.as_str() {
            "admin" => Some(ApiKeyScope::Admin),
            "tunnels:read" => Some(ApiKeyScope::TunnelRead),
            "tunnels:write" => Some(ApiKeyScope::TunnelReadWrite),
            "domains" => Some(ApiKeyScope::DomainManage),
            "metrics" => Some(ApiKeyScope::MetricsRead),
            "audit" => Some(ApiKeyScope::AuditRead),
            "billing" => Some(ApiKeyScope::BillingManage),
            _ => None,
        })
        .collect();

    let create_req = ApiKeyCreateRequest {
        name: req.name.clone(),
        scopes,
        expires_in_days: req.expires_in_days,
        allowed_ips: vec![],
        rate_limit_per_minute: None,
        metadata: std::collections::HashMap::new(),
    };

    let created = state.api_keys.create_key(&user.user_id, None, create_req);

    Ok(Json(ApiKeyResponse {
        id: created.metadata.id.clone(),
        name: created.metadata.name.clone(),
        prefix: created.metadata.prefix.clone(),
        secret: Some(created.key.clone()), // Return secret only on creation
        scopes: created.metadata.scopes.iter().map(|s| format!("{:?}", s)).collect(),
        created_at: created.metadata.created_at.to_rfc3339(),
        expires_at: created.metadata.expires_at.map(|d: chrono::DateTime<chrono::Utc>| d.to_rfc3339()),
    }))
}

async fn revoke_api_key(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.api_keys.revoke_key(&id, &user.user_id)
        .map_err(|e| ApiError {
            error: "revoke_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

// === Billing Handlers ===

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub tier: String,
    pub status: String,
    pub current_period_end: Option<String>,
    pub limits: TierLimitsResponse,
}

#[derive(Debug, Serialize)]
pub struct TierLimitsResponse {
    pub max_tunnels: u32,
    pub max_bandwidth_gb: u64,
    pub max_connections: u32,
    pub max_requests_per_minute: u32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct UsageResponse {
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
}

async fn get_subscription(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let subscription = state.billing.get_or_create_subscription(&user.user_id);
    let limits = subscription.limits();

    Ok(Json(SubscriptionResponse {
        tier: format!("{:?}", subscription.tier),
        status: format!("{:?}", subscription.status),
        current_period_end: Some(subscription.period_end.to_rfc3339()),
        limits: TierLimitsResponse {
            max_tunnels: limits.max_tunnels,
            max_bandwidth_gb: limits.max_bandwidth_gb_per_month,
            max_connections: limits.max_connections_per_tunnel,
            max_requests_per_minute: limits.max_requests_per_minute,
        },
    }))
}

async fn update_subscription(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let tier = match req.tier.to_lowercase().as_str() {
        "free" => SubscriptionTier::Free,
        "pro" => SubscriptionTier::Pro,
        "team" => SubscriptionTier::Team,
        "business" => SubscriptionTier::Business,
        "enterprise" => SubscriptionTier::Enterprise,
        _ => return Err(ApiError {
            error: "invalid_tier".to_string(),
            message: "Invalid subscription tier".to_string(),
            code: "validation_error".to_string(),
        }),
    };

    let subscription = state.billing.update_subscription(&user.user_id, tier)
        .map_err(|e| ApiError {
            error: "update_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    let limits = subscription.limits();

    Ok(Json(SubscriptionResponse {
        tier: format!("{:?}", subscription.tier),
        status: format!("{:?}", subscription.status),
        current_period_end: Some(subscription.period_end.to_rfc3339()),
        limits: TierLimitsResponse {
            max_tunnels: limits.max_tunnels,
            max_bandwidth_gb: limits.max_bandwidth_gb_per_month,
            max_connections: limits.max_connections_per_tunnel,
            max_requests_per_minute: limits.max_requests_per_minute,
        },
    }))
}

async fn get_usage(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<UsageResponse>, ApiError> {
    let usage = state.billing.get_usage(&user.user_id);
    
    match usage {
        Some(snapshot) => Ok(Json(UsageResponse {
            requests: snapshot.requests,
            bytes_in: snapshot.bytes_in,
            bytes_out: snapshot.bytes_out,
            connections: snapshot.connections,
        })),
        None => Ok(Json(UsageResponse {
            requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            connections: 0,
        })),
    }
}

async fn billing_webhook(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<StatusCode, ApiError> {
    let event_type = payload.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    state.billing.handle_webhook(event_type, &payload)
        .map_err(|e| ApiError {
            error: "webhook_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(StatusCode::OK)
}

// === Tunnel Count Endpoint ===

#[derive(Debug, Serialize)]
pub struct TunnelCountResponse {
    pub count: u32,
}

async fn get_tunnel_count(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
) -> Result<Json<TunnelCountResponse>, ApiError> {
    let tunnels = state.store.list_tunnels(&user.user_id)
        .await
        .map_err(|e| ApiError {
            error: "count_failed".to_string(),
            message: e.to_string(),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(TunnelCountResponse {
        count: tunnels.len() as u32,
    }))
}

// === Traffic Sync Endpoint ===

/// Captured traffic request from agent
#[derive(Debug, Deserialize)]
pub struct TrafficSyncRequest {
    pub id: String,
    pub tunnel_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub response_status: Option<u16>,
    pub response_headers: Option<Vec<(String, String)>>,
    pub response_body: Option<String>,
    pub duration_ms: Option<u64>,
    pub client_addr: Option<String>,
}

async fn sync_traffic(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    Json(req): Json<TrafficSyncRequest>,
) -> Result<StatusCode, ApiError> {
    // Verify the tunnel belongs to this user
    let _tunnel = state.store.get_tunnel(&req.tunnel_id)
        .await
        .map_err(|_| ApiError {
            error: "tunnel_not_found".to_string(),
            message: "Tunnel not found".to_string(),
            code: "not_found".to_string(),
        })?;

    // Parse timestamp
    let timestamp = chrono::DateTime::parse_from_rfc3339(&req.timestamp)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    // Create traffic record for storage
    let record = TrafficRecord {
        id: req.id,
        user_id: user.user_id.clone(),
        tunnel_id: req.tunnel_id.clone(),
        timestamp,
        method: req.method.clone(),
        path: req.path.clone(),
        headers: req.headers,
        body: req.body,
        content_type: req.content_type,
        content_length: req.content_length.map(|v| v as i64),
        response_status: req.response_status.map(|v| v as i16),
        response_headers: req.response_headers,
        response_body: req.response_body,
        duration_ms: req.duration_ms.map(|v| v as i64),
        client_addr: req.client_addr,
    };

    // Store in persistent storage
    state.traffic_store.insert(record).await
        .map_err(|e| ApiError {
            error: "storage_error".to_string(),
            message: format!("Failed to store traffic: {}", e),
            code: "internal_error".to_string(),
        })?;

    tracing::debug!(
        user_id = %user.user_id,
        tunnel_id = %req.tunnel_id,
        method = %req.method,
        path = %req.path,
        status = ?req.response_status,
        "Traffic synced and stored"
    );

    Ok(StatusCode::ACCEPTED)
}

// === Traffic Query Endpoints ===

#[derive(Debug, Deserialize)]
pub struct TrafficQueryParams {
    /// Filter by tunnel ID
    tunnel_id: Option<String>,
    /// Filter by HTTP method
    method: Option<String>,
    /// Filter by path prefix
    path_prefix: Option<String>,
    /// Filter by minimum status code
    status_min: Option<i16>,
    /// Filter by maximum status code
    status_max: Option<i16>,
    /// Start time (RFC3339 format)
    start_time: Option<String>,
    /// End time (RFC3339 format)
    end_time: Option<String>,
    /// Maximum number of results (default: 100)
    limit: Option<i64>,
    /// Offset for pagination
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TrafficQueryResponse {
    pub records: Vec<TrafficRecordResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct TrafficRecordResponse {
    pub id: String,
    pub tunnel_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub response_status: Option<i16>,
    pub response_headers: Option<Vec<(String, String)>>,
    pub response_body: Option<String>,
    pub duration_ms: Option<i64>,
    pub client_addr: Option<String>,
}

async fn query_traffic(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    axum::extract::Query(params): axum::extract::Query<TrafficQueryParams>,
) -> Result<Json<TrafficQueryResponse>, ApiError> {
    let start_time = params.start_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    
    let end_time = params.end_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let query = TrafficQuery {
        user_id: Some(user.user_id),
        tunnel_id: params.tunnel_id,
        method: params.method,
        path_prefix: params.path_prefix,
        status_min: params.status_min,
        status_max: params.status_max,
        start_time,
        end_time,
        limit: params.limit.or(Some(100)),
        offset: params.offset,
    };

    let records = state.traffic_store.query(query).await
        .map_err(|e| ApiError {
            error: "query_failed".to_string(),
            message: format!("Failed to query traffic: {}", e),
            code: "internal_error".to_string(),
        })?;

    let response_records: Vec<TrafficRecordResponse> = records.iter()
        .map(|r| TrafficRecordResponse {
            id: r.id.clone(),
            tunnel_id: r.tunnel_id.clone(),
            timestamp: r.timestamp.to_rfc3339(),
            method: r.method.clone(),
            path: r.path.clone(),
            headers: r.headers.clone(),
            body: r.body.clone(),
            content_type: r.content_type.clone(),
            content_length: r.content_length,
            response_status: r.response_status,
            response_headers: r.response_headers.clone(),
            response_body: r.response_body.clone(),
            duration_ms: r.duration_ms,
            client_addr: r.client_addr.clone(),
        })
        .collect();

    let total = response_records.len();

    Ok(Json(TrafficQueryResponse {
        records: response_records,
        total,
    }))
}

#[derive(Debug, Deserialize)]
pub struct TrafficMetricsParams {
    /// Filter by tunnel ID
    tunnel_id: Option<String>,
    /// Start time (RFC3339 format)
    start_time: Option<String>,
    /// End time (RFC3339 format)
    end_time: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrafficMetricsResponse {
    pub total_requests: i64,
    pub requests_2xx: i64,
    pub requests_3xx: i64,
    pub requests_4xx: i64,
    pub requests_5xx: i64,
    pub avg_duration_ms: f64,
    pub p50_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub total_bytes: i64,
    pub unique_clients: i64,
}

async fn get_traffic_metrics(
    State(state): State<Arc<ApiState>>,
    user: AuthenticatedUser,
    axum::extract::Query(params): axum::extract::Query<TrafficMetricsParams>,
) -> Result<Json<TrafficMetricsResponse>, ApiError> {
    let start_time = params.start_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    
    let end_time = params.end_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let query = TrafficQuery {
        user_id: Some(user.user_id),
        tunnel_id: params.tunnel_id,
        start_time,
        end_time,
        ..Default::default()
    };

    let metrics = state.traffic_store.get_metrics(query).await
        .map_err(|e| ApiError {
            error: "metrics_failed".to_string(),
            message: format!("Failed to get metrics: {}", e),
            code: "internal_error".to_string(),
        })?;

    Ok(Json(TrafficMetricsResponse {
        total_requests: metrics.total_requests,
        requests_2xx: metrics.requests_2xx,
        requests_3xx: metrics.requests_3xx,
        requests_4xx: metrics.requests_4xx,
        requests_5xx: metrics.requests_5xx,
        avg_duration_ms: metrics.avg_duration_ms,
        p50_duration_ms: metrics.p50_duration_ms,
        p95_duration_ms: metrics.p95_duration_ms,
        p99_duration_ms: metrics.p99_duration_ms,
        total_bytes: metrics.total_bytes,
        unique_clients: metrics.unique_clients,
    }))
}
