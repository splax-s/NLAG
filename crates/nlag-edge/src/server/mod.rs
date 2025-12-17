//! Edge server implementation
//!
//! This module contains the main server logic:
//! - QUIC listener for agent connections
//! - HTTP/TCP listener for public traffic
//! - Traffic routing between them
//! - Audit logging and replay protection
//! - ACME certificate management
//! - Multi-region support

pub mod agent;
pub mod public;
pub mod rate_limit;
pub mod tcp;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

use nlag_common::crypto::cert::generate_self_signed_cert;

use crate::acme::CertificateManager;
use crate::audit::{AuditLogger, AuditEventType};
use crate::auth::AgentAuthenticator;
use crate::config::EdgeConfig;
use crate::inspect::RequestInspector;
use crate::inspect_ui::create_inspect_router;
use crate::region::{RegionRegistry, RegionId};
use crate::registry::Registry;
use crate::replay::ReplayGuard;

/// Shutdown signal broadcaster
#[derive(Clone)]
pub struct ShutdownSignal {
    receiver: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Check if shutdown has been signaled
    pub fn is_shutdown(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Wait for shutdown signal
    pub async fn wait(&mut self) {
        // If already shutdown, return immediately
        if *self.receiver.borrow() {
            return;
        }
        // Wait for the value to change to true
        let _ = self.receiver.changed().await;
    }
}

/// Run the edge server
pub async fn run_server(config: EdgeConfig) -> anyhow::Result<()> {
    // Create shared registry
    let registry = Registry::new();

    // Create request inspector
    let inspector = RequestInspector::new(config.inspect.enabled);

    // Create shutdown signal channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_signal = ShutdownSignal { receiver: shutdown_rx };

    // Create authenticator
    let authenticator = Arc::new(AgentAuthenticator::new(config.auth.clone())?);
    if authenticator.is_enabled() {
        info!("Agent authentication enabled");
    } else {
        warn!("Agent authentication DISABLED - development mode");
    }

    // Initialize audit logger
    let edge_id = config.edge_id.clone().unwrap_or_else(|| {
        uuid::Uuid::new_v4().to_string()
    });
    let audit_logger = AuditLogger::new(
        config.audit.clone(),
        edge_id.clone(),
        config.region.as_ref().map(|r| r.region_id.clone()),
    );
    info!("Audit logging initialized");

    // Initialize replay protection guard
    let replay_guard = ReplayGuard::new(config.replay.clone());
    if replay_guard.is_enabled() {
        info!("Replay protection enabled");
        replay_guard.clone().start_cleanup_task();
    }

    // Initialize region registry for multi-region support
    let region_id = config.region.as_ref()
        .map(|r| RegionId::new(&r.region_id))
        .unwrap_or_else(|| RegionId::new("default"));
    let region_registry = RegionRegistry::new(region_id);
    info!("Region registry initialized");

    // Initialize ACME certificate manager if enabled
    let cert_manager = if config.acme.enabled {
        let manager = CertificateManager::new(config.acme.clone());
        if let Err(e) = manager.load_certificates().await {
            warn!("Failed to load existing certificates: {}", e);
        }
        manager.clone().start_renewal_task();
        info!("ACME certificate manager enabled");
        Some(manager)
    } else {
        None
    };

    // Log server startup audit event
    audit_logger.log(
        audit_logger.event(AuditEventType::ServerStarted)
            .with_metadata("version", env!("CARGO_PKG_VERSION"))
            .with_metadata("edge_id", edge_id.clone())
    ).await;

    // Ensure TLS certificates are present (generate dev certs if missing)
    ensure_tls_certificates(&config.tls)?;

    // Load TLS certificates
    let cert_pem = std::fs::read_to_string(&config.tls.cert_path)?;
    let key_pem = std::fs::read_to_string(&config.tls.key_path)?;

    // Start agent listener
    let agent_listener = agent::AgentListener::new(
        config.agent_listen_addr,
        &cert_pem,
        &key_pem,
        registry.clone(),
        config.domain.clone(),
        shutdown_signal.clone(),
        authenticator.clone(),
    )?;

    // Start public listener
    let public_listener = public::PublicListener::new(
        config.public_listen_addr,
        registry.clone(),
        config.rate_limit.clone(),
        config.domain.clone(),
        shutdown_signal.clone(),
        inspector.clone(),
    )?;

    info!("NLAG Edge server started");
    info!("  Edge ID: {}", edge_id);
    info!("  Agent listener: {}", config.agent_listen_addr);
    info!("  Public listener: {}", config.public_listen_addr);
    
    // Log optional features
    if cert_manager.is_some() {
        info!("  ACME: enabled");
    }
    if replay_guard.is_enabled() {
        info!("  Replay protection: enabled");
    }

    // Store references for future use (e.g., hot-reload, health checks)
    let _region_registry = region_registry;
    let _replay_guard = replay_guard;
    let _cert_manager = cert_manager;
    let _inspector = inspector.clone();

    // Start inspection UI if configured
    let inspect_handle = if let Some(inspect_addr) = config.inspect_listen_addr {
        info!("  Inspect UI: http://{}", inspect_addr);
        let inspect_router = create_inspect_router(inspector.clone());
        let inspect_app = axum::Router::new()
            .merge(inspect_router)
            .route("/health", axum::routing::get(health_check))
            .route("/ready", axum::routing::get(readiness_check));
        
        Some(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(inspect_addr).await.unwrap();
            if let Err(e) = axum::serve(listener, inspect_app).await {
                error!("Inspect UI error: {}", e);
            }
        }))
    } else {
        None
    };

    // Run both listeners concurrently
    let agent_handle = tokio::spawn(async move {
        if let Err(e) = agent_listener.run().await {
            error!("Agent listener error: {}", e);
        }
    });

    let public_handle = tokio::spawn(async move {
        if let Err(e) = public_listener.run().await {
            error!("Public listener error: {}", e);
        }
    });

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Log shutdown event
    audit_logger.log(
        audit_logger.event(AuditEventType::ServerStopped)
            .with_metadata("reason", "graceful_shutdown")
    ).await;

    info!("Initiating graceful shutdown...");
    
    // Signal all components to stop accepting new connections
    let _ = shutdown_tx.send(true);

    // Give existing connections time to complete (drain period)
    let drain_timeout = Duration::from_secs(30);
    info!("Waiting up to {:?} for connections to drain...", drain_timeout);

    tokio::select! {
        _ = tokio::time::sleep(drain_timeout) => {
            warn!("Drain timeout reached, forcing shutdown");
        }
        _ = async {
            let _ = agent_handle.await;
            let _ = public_handle.await;
            if let Some(handle) = inspect_handle {
                let _ = handle.await;
            }
        } => {
            info!("All connections drained successfully");
        }
    }

    info!("Shutdown complete");
    Ok(())
}

/// Ensure TLS certificate and key exist; generate self-signed dev certs if missing
fn ensure_tls_certificates(tls: &crate::config::TlsConfig) -> anyhow::Result<()> {
    let cert_path = Path::new(&tls.cert_path);
    let key_path = Path::new(&tls.key_path);

    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    warn!(
        "TLS certificates missing at {:?} and {:?}, generating self-signed development certs",
        cert_path,
        key_path
    );

    if let Some(dir) = cert_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(dir) = key_path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let cert_info = generate_self_signed_cert(
        "nlag-edge.local",
        &vec!["localhost".to_string()],
        &vec!["127.0.0.1".parse()?, "::1".parse()?],
        30,
        false,
    )?;

    std::fs::write(cert_path, &cert_info.cert_pem)?;
    std::fs::write(key_path, &cert_info.key_pem)?;

    Ok(())
}

/// Health check endpoint - returns 200 if server is running
async fn health_check() -> axum::response::Response {
    axum::response::Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
    })).into_response()
}

/// Readiness check endpoint - returns 200 if server is ready to accept traffic
async fn readiness_check() -> axum::response::Response {
    axum::response::Json(serde_json::json!({
        "status": "ready",
    })).into_response()
}

use axum::response::IntoResponse;

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
    }
}
