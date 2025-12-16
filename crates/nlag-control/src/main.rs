//! NLAG Control Plane
//!
//! The control plane service handles:
//! - User authentication and authorization
//! - Agent token issuance and validation
//! - Tunnel configuration management
//! - Metrics and monitoring
//! - Admin API
//! - API Key management
//! - Billing and usage tracking
//!
//! ## Architecture
//!
//! The control plane is separate from the edge servers to allow:
//! - Independent scaling
//! - High availability through replication
//! - Separation of concerns (auth vs traffic)

use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

mod api;
mod apikeys;
mod auth;
mod billing;
mod dashboard;
mod store;

use apikeys::ApiKeyManager;
use billing::BillingManager;

/// NLAG Control Plane
#[derive(Parser, Debug)]
#[command(name = "nlag-control")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value = "8081")]
    port: u16,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = if cli.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        };
        EnvFilter::new(format!("nlag={}", level))
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    tracing::info!(
        "NLAG Control Plane v{} starting on port {}",
        env!("CARGO_PKG_VERSION"),
        cli.port
    );

    // Initialize services
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set, using insecure default for development");
        "insecure-dev-secret-change-in-production".to_string()
    });

    let webhook_secret = std::env::var("BILLING_WEBHOOK_SECRET").ok();
    if webhook_secret.is_none() {
        tracing::warn!("BILLING_WEBHOOK_SECRET not set, webhook verification disabled");
    }

    let auth_service = std::sync::Arc::new(auth::AuthService::new(&jwt_secret));
    let store = std::sync::Arc::new(store::Store::new());
    
    // Initialize API key manager
    let api_key_manager = ApiKeyManager::new();
    api_key_manager.clone().start_cleanup_task();
    tracing::info!("API key manager initialized");
    
    // Initialize billing manager
    let billing_manager = BillingManager::new(webhook_secret);
    tracing::info!("Billing manager initialized");

    let api_state = std::sync::Arc::new(api::ApiState {
        auth: auth_service,
        store,
        api_keys: api_key_manager,
        billing: billing_manager,
    });

    // Combine API and Dashboard routers
    let router = api::create_router(api_state.clone())
        .merge(dashboard::create_dashboard_router(api_state));

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", cli.port).parse()?;
    tracing::info!("API server listening on {}", addr);
    tracing::info!("Dashboard available at http://{}/dashboard", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutting down");
        })
        .await?;

    Ok(())
}
