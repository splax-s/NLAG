//! Agent connection handler
//!
//! Handles QUIC connections from agents:
//! - Authentication
//! - Tunnel management
//! - Message routing

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};
use uuid::Uuid;

use nlag_common::{
    protocol::{
        codec::quic::{read_message, write_message},
        message::{
            AuthResponseMessage, CloseTunnelMessage, ErrorCode, ErrorMessage, Message,
            OpenTunnelMessage, PongMessage, TunnelClosedMessage, TunnelOpenedMessage,
        },
    },
    transport::quic::{QuicConnection, QuicServer},
    types::AgentId,
};

use crate::auth::AgentAuthenticator;
use crate::config::DomainConfig;
use crate::metrics;
use crate::registry::Registry;
use crate::server::ShutdownSignal;

/// Agent connection listener
pub struct AgentListener {
    server: QuicServer,
    registry: Arc<Registry>,
    domain_config: DomainConfig,
    shutdown: ShutdownSignal,
    authenticator: Arc<AgentAuthenticator>,
}

impl AgentListener {
    /// Create a new agent listener
    pub fn new(
        bind_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        registry: Arc<Registry>,
        domain_config: DomainConfig,
        shutdown: ShutdownSignal,
        authenticator: Arc<AgentAuthenticator>,
    ) -> anyhow::Result<Self> {
        let server = QuicServer::new(bind_addr, cert_pem, key_pem)?;

        Ok(Self {
            server,
            registry,
            domain_config,
            shutdown,
            authenticator,
        })
    }

    /// Run the agent listener loop
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Agent listener started");

        loop {
            // Check for shutdown
            if self.shutdown.is_shutdown() {
                info!("Agent listener shutting down");
                break;
            }

            // Accept new connection with timeout to check shutdown periodically
            let connection = tokio::select! {
                conn = self.server.accept() => {
                    match conn {
                        Some(c) => c,
                        None => {
                            warn!("Agent listener accept returned None, stopping");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    continue; // Check shutdown flag
                }
            };

            let registry = self.registry.clone();
            let domain_config = self.domain_config.clone();
            let authenticator = self.authenticator.clone();

            // Spawn handler for this connection
            tokio::spawn(async move {
                if let Err(e) = handle_agent_connection(connection, registry, domain_config, authenticator).await {
                    debug!("Agent connection ended: {}", e);
                }
            });
        }

        Ok(())
    }
}

/// Handle a single agent connection
async fn handle_agent_connection(
    connection: QuicConnection,
    registry: Arc<Registry>,
    domain_config: DomainConfig,
    authenticator: Arc<AgentAuthenticator>,
) -> anyhow::Result<()> {
    let remote_addr = connection.remote_address();
    info!("New agent connection from {}", remote_addr);
    metrics::record_agent_connect();

    // Wait for control stream
    let (mut send, mut recv) = connection.accept_bi().await?;

    // Read authentication message
    let msg = read_message(&mut recv).await?;

    let (agent_id, _session_id, claims) = match msg {
        Message::Auth(auth) => {
            info!(
                "Agent {} authenticating (version: {})",
                auth.agent_id, auth.client_version
            );

            // Validate auth token
            let claims = match authenticator.validate_token(&auth.auth_token) {
                Ok(c) => c,
                Err(e) => {
                    let error_msg = Message::AuthResponse(AuthResponseMessage {
                        success: false,
                        error: Some(format!("Authentication failed: {}", e)),
                        session_id: None,
                        capabilities: vec![],
                        server_version: env!("CARGO_PKG_VERSION").to_string(),
                    });
                    write_message(&mut send, &error_msg).await?;
                    return Err(anyhow::anyhow!("Authentication failed: {}", e));
                }
            };

            let session_id = Uuid::new_v4().to_string();

            // Register the agent
            if let Err(e) = registry.register_agent(auth.agent_id, connection.clone(), session_id.clone()) {
                let error_msg = Message::AuthResponse(AuthResponseMessage {
                    success: false,
                    error: Some(e.to_string()),
                    session_id: None,
                    capabilities: vec![],
                    server_version: env!("CARGO_PKG_VERSION").to_string(),
                });
                write_message(&mut send, &error_msg).await?;
                return Err(anyhow::anyhow!("Registration failed: {}", e));
            }

            // Send success response
            let response = Message::AuthResponse(AuthResponseMessage {
                success: true,
                error: None,
                session_id: Some(session_id.clone()),
                capabilities: vec!["quic".to_string(), "multiplex".to_string()],
                server_version: env!("CARGO_PKG_VERSION").to_string(),
            });
            write_message(&mut send, &response).await?;

            info!("Agent {} authenticated (session: {}, subject: {})", auth.agent_id, session_id, claims.sub);
            (auth.agent_id, session_id, claims)
        }
        other => {
            let error_msg = Message::Error(ErrorMessage {
                code: ErrorCode::ProtocolError,
                message: format!("Expected Auth message, got {:?}", other.message_type()),
                context: None,
                fatal: true,
            });
            write_message(&mut send, &error_msg).await?;
            return Err(anyhow::anyhow!("Protocol error: expected Auth message"));
        }
    };

    // Main message loop
    let result = message_loop(
        &mut send,
        &mut recv,
        agent_id,
        registry.clone(),
        &domain_config,
        &authenticator,
        &claims,
    )
    .await;

    // Cleanup on disconnect
    info!("Agent {} disconnected", agent_id);
    registry.unregister_agent(&agent_id);
    metrics::record_agent_disconnect();

    result
}

/// Main message handling loop for an agent
async fn message_loop(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    agent_id: AgentId,
    registry: Arc<Registry>,
    domain_config: &DomainConfig,
    authenticator: &AgentAuthenticator,
    claims: &crate::auth::AgentClaims,
) -> anyhow::Result<()> {
    loop {
        let msg = match read_message(recv).await {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Read error for agent {}: {}", agent_id, e);
                break;
            }
        };

        match msg {
            Message::OpenTunnel(open) => {
                handle_open_tunnel(send, agent_id, open, registry.clone(), domain_config, authenticator, claims).await?;
            }

            Message::CloseTunnel(close) => {
                handle_close_tunnel(send, close, registry.clone()).await?;
            }

            Message::Ping(ping) => {
                let pong = Message::Pong(PongMessage {
                    timestamp: ping.timestamp,
                    seq: ping.seq,
                });
                write_message(send, &pong).await?;
            }

            Message::Shutdown(shutdown) => {
                info!(
                    "Agent {} requested shutdown: {}",
                    agent_id, shutdown.reason
                );
                break;
            }

            other => {
                warn!(
                    "Unexpected message from agent {}: {:?}",
                    agent_id,
                    other.message_type()
                );
            }
        }
    }

    Ok(())
}

/// Handle tunnel open request
async fn handle_open_tunnel(
    send: &mut quinn::SendStream,
    agent_id: AgentId,
    open: OpenTunnelMessage,
    registry: Arc<Registry>,
    domain_config: &DomainConfig,
    authenticator: &AgentAuthenticator,
    claims: &crate::auth::AgentClaims,
) -> anyhow::Result<()> {
    let tunnel_config = open.config;

    // Generate or use requested subdomain
    let subdomain = tunnel_config
        .subdomain
        .clone()
        .unwrap_or_else(|| registry.generate_subdomain());

    // Check subdomain authorization
    if !authenticator.check_subdomain(claims, &subdomain) {
        let error_msg = Message::Error(ErrorMessage {
            code: ErrorCode::PermissionDenied,
            message: format!("Not authorized to use subdomain: {}", subdomain),
            context: Some(format!("subdomain:{}", subdomain)),
            fatal: false,
        });
        write_message(send, &error_msg).await?;
        warn!("Agent {} unauthorized for subdomain {}", agent_id, subdomain);
        return Ok(());
    }

    // Check max tunnels limit
    if let Some(max) = claims.max_tunnels {
        let current_count = registry.agent_tunnel_count(agent_id);
        if current_count >= max as usize {
            let error_msg = Message::Error(ErrorMessage {
                code: ErrorCode::ResourceExhausted,
                message: format!("Maximum tunnel limit reached ({}/{})", current_count, max),
                context: Some("max_tunnels".to_string()),
                fatal: false,
            });
            write_message(send, &error_msg).await?;
            warn!("Agent {} reached max tunnels limit", agent_id);
            return Ok(());
        }
    }

    // Build public URL
    let public_url = domain_config.build_public_url(&subdomain);

    // Register the tunnel
    match registry.register_tunnel(agent_id, tunnel_config.clone(), subdomain.clone(), public_url.clone()) {
        Ok(tunnel_id) => {
            let response = Message::TunnelOpened(TunnelOpenedMessage {
                tunnel_id,
                public_url,
                subdomain,
            });
            write_message(send, &response).await?;
            metrics::record_tunnel_created();
            info!("Tunnel {} opened for agent {}", tunnel_id, agent_id);
        }
        Err(e) => {
            let error_msg = Message::Error(ErrorMessage {
                code: ErrorCode::ResourceExhausted,
                message: e.to_string(),
                context: Some(format!("tunnel:{}", tunnel_config.tunnel_id)),
                fatal: false,
            });
            write_message(send, &error_msg).await?;
            warn!("Failed to open tunnel for agent {}: {}", agent_id, e);
        }
    }

    Ok(())
}

/// Handle tunnel close request
async fn handle_close_tunnel(
    send: &mut quinn::SendStream,
    close: CloseTunnelMessage,
    registry: Arc<Registry>,
) -> anyhow::Result<()> {
    registry.remove_tunnel(&close.tunnel_id);
    metrics::record_tunnel_closed();

    let response = Message::TunnelClosed(TunnelClosedMessage {
        tunnel_id: close.tunnel_id,
        reason: close.reason.unwrap_or_else(|| "Requested by agent".to_string()),
    });
    write_message(send, &response).await?;

    Ok(())
}
