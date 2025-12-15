//! Edge server implementation
//!
//! This module contains the main server logic:
//! - QUIC listener for agent connections
//! - HTTP/TCP listener for public traffic
//! - Traffic routing between them

pub mod agent;
pub mod public;
pub mod rate_limit;
pub mod tcp;

use std::sync::Arc;
use std::time::Duration;

use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::auth::AgentAuthenticator;
use crate::config::EdgeConfig;
use crate::registry::Registry;

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
    )?;

    info!("NLAG Edge server started");
    info!("  Agent listener: {}", config.agent_listen_addr);
    info!("  Public listener: {}", config.public_listen_addr);

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
        } => {
            info!("All connections drained successfully");
        }
    }

    info!("Shutdown complete");
    Ok(())
}

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
