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

/// API state shared across handlers
pub struct ApiState {
    pub auth: Arc<AuthService>,
    pub store: Arc<Store>,
    pub api_keys: Arc<ApiKeyManager>,
    pub billing: Arc<BillingManager>,
}

/// Authenticated user extracted from JWT token
#[derive(Debug, Clone)]
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
        .route("/api/v1/tunnels/:id", get(get_tunnel))
        .route("/api/v1/tunnels/:id", delete(delete_tunnel))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/:id", delete(revoke_agent))
        .route("/api/v1/tokens", get(list_tokens))
        .route("/api/v1/tokens", post(create_token))
        .route("/api/v1/tokens/:id", delete(revoke_token))
        // API Key management endpoints
        .route("/api/v1/apikeys", get(list_api_keys))
        .route("/api/v1/apikeys", post(create_api_key))
        .route("/api/v1/apikeys/:id", delete(revoke_api_key))
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
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
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

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in,
        token_type: "Bearer".to_string(),
    }))
}

async fn refresh_token(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let (access_token, refresh_token, expires_in) = state.auth.refresh_tokens(&req.refresh_token)
        .map_err(|e| ApiError {
            error: "refresh_failed".to_string(),
            message: e.to_string(),
            code: "unauthorized".to_string(),
        })?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in,
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
