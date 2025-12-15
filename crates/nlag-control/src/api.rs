//! REST API for NLAG Control Plane
//!
//! Provides endpoints for:
//! - Authentication (login, register, token refresh)
//! - Tunnel management (list, create, delete)
//! - Agent management (list, revoke)
//! - Admin operations (stats, config)

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::AuthService;
use crate::store::Store;

/// API state shared across handlers
pub struct ApiState {
    pub auth: Arc<AuthService>,
    pub store: Arc<Store>,
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
    // TODO: Extract user from JWT
) -> Result<Json<Vec<TunnelResponse>>, ApiError> {
    let tunnels = state.store.list_tunnels("user_id_placeholder")
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
    Json(req): Json<CreateTunnelRequest>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tunnel = state.store.create_tunnel(
        "user_id_placeholder",
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
) -> Result<Json<Vec<AgentResponse>>, ApiError> {
    let agents = state.store.list_agents("user_id_placeholder")
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
) -> Result<Json<Vec<TokenResponse>>, ApiError> {
    let tokens = state.store.list_tokens("user_id_placeholder")
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
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let token = state.store.create_token(
        "user_id_placeholder",
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
