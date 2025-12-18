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

mod analytics;
mod api;
mod apikeys;
mod audit;
mod auth;
mod billing;
mod dashboard;
mod domains;
mod oauth;
mod sla;
mod sso;
mod store;
mod teams;
mod traffic;

use apikeys::ApiKeyManager;
use billing::BillingManager;
use traffic::MemoryTrafficStore;

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

    // Initialize traffic store
    // Use in-memory store by default, PostgreSQL when 'postgres' feature is enabled
    let traffic_store: std::sync::Arc<dyn traffic::TrafficStore> = {
        #[cfg(feature = "postgres")]
        {
            if let Ok(database_url) = std::env::var("DATABASE_URL") {
                match traffic::postgres::PgTrafficStore::new(&database_url).await {
                    Ok(pg_store) => {
                        if let Err(e) = pg_store.init_schema().await {
                            tracing::error!("Failed to initialize database schema: {}", e);
                            tracing::warn!("Falling back to in-memory traffic store");
                            std::sync::Arc::new(MemoryTrafficStore::new())
                        } else {
                            tracing::info!("PostgreSQL traffic store initialized with TimescaleDB");
                            std::sync::Arc::new(pg_store)
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to PostgreSQL: {}", e);
                        tracing::warn!("Falling back to in-memory traffic store");
                        std::sync::Arc::new(MemoryTrafficStore::new())
                    }
                }
            } else {
                tracing::info!("DATABASE_URL not set, using in-memory traffic store");
                std::sync::Arc::new(MemoryTrafficStore::new())
            }
        }
        
        #[cfg(not(feature = "postgres"))]
        {
            tracing::info!("Using in-memory traffic store (enable 'postgres' feature for persistent storage)");
            std::sync::Arc::new(MemoryTrafficStore::new())
        }
    };

    let api_state = std::sync::Arc::new(api::ApiState {
        auth: auth_service,
        store,
        api_keys: api_key_manager,
        billing: billing_manager,
        traffic_store,
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
