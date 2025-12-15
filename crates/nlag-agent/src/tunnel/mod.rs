//! Tunnel management for the NLAG agent
//!
//! This module handles:
//! - Establishing connections to edge servers
//! - Protocol negotiation and authentication
//! - Traffic forwarding
//! - Reconnection logic

pub mod client;
pub mod forwarder;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tracing::{error, info, warn};

use nlag_common::{
    crypto::tls::TlsConfig,
    protocol::{
        codec::quic::{read_message, write_message},
        message::{
            AuthMessage, Message, OpenTunnelMessage, PingMessage,
        },
    },
    transport::quic::QuicClient,
    types::AgentId,
};

use crate::config::{AgentConfig, TunnelOptions};
use crate::ui::{self, UiEvent, UiHandle, TunnelInfo, HttpRequest};

/// Run tunnel with the beautiful TUI
pub async fn run_tunnel_with_ui(config: AgentConfig, tunnel_opts: TunnelOptions) -> anyhow::Result<()> {
    let local_addr = format!("{}:{}", tunnel_opts.local_host, tunnel_opts.local_port);
    let edge_addr = config.edge_addr.clone();

    // Create UI channel
    let (ui_handle, event_rx) = ui::create_ui_channel();

    // Spawn the tunnel task
    let tunnel_handle = {
        let config = config.clone();
        let tunnel_opts = tunnel_opts.clone();
        let ui_handle = ui_handle.clone();
        tokio::spawn(async move {
            run_tunnel_with_handle(config, tunnel_opts, ui_handle).await
        })
    };

    // Run the UI (blocking)
    let ui_result = ui::run_ui(event_rx, local_addr, edge_addr).await;

    // Cancel the tunnel task when UI exits
    tunnel_handle.abort();

    ui_result
}

/// Run tunnel with UI handle for sending events
async fn run_tunnel_with_handle(
    config: AgentConfig,
    tunnel_opts: TunnelOptions,
    ui_handle: UiHandle,
) -> anyhow::Result<()> {
    let agent_id = AgentId::new();

    // Verify local service is reachable
    let local_addr = format!("{}:{}", tunnel_opts.local_host, tunnel_opts.local_port);
    if TcpStream::connect(&local_addr).await.is_err() {
        ui_handle.error(format!("Warning: Local service at {} not reachable", local_addr));
    }

    // Reconnection loop
    let mut attempt = 0u32;
    let mut delay = Duration::from_millis(config.connection.reconnect_delay_ms);
    let max_delay = Duration::from_millis(config.connection.max_reconnect_delay_ms);

    loop {
        attempt += 1;

        if config.connection.max_reconnect_attempts > 0
            && attempt > config.connection.max_reconnect_attempts
        {
            ui_handle.error("Maximum reconnection attempts reached");
            return Err(anyhow::anyhow!("Maximum reconnection attempts exceeded"));
        }

        match run_tunnel_once_with_ui(&config, &tunnel_opts, agent_id, &ui_handle).await {
            Ok(()) => break,
            Err(e) => {
                ui_handle.error(format!("Tunnel error: {}", e));
                ui_handle.disconnected();
                tokio::time::sleep(delay).await;
                let jitter = rand_delay();
                delay = std::cmp::min(delay * 2 + jitter, max_delay);
            }
        }
    }

    Ok(())
}

/// Run single tunnel session with UI updates
async fn run_tunnel_once_with_ui(
    config: &AgentConfig,
    tunnel_opts: &TunnelOptions,
    agent_id: AgentId,
    ui_handle: &UiHandle,
) -> anyhow::Result<()> {
    let connect_start = Instant::now();

    // Parse edge address
    let edge_addr: SocketAddr = if let Ok(addr) = config.edge_addr.parse() {
        addr
    } else {
        use tokio::net::lookup_host;
        lookup_host(&config.edge_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resolve edge address: {}", e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("No addresses found"))?
    };

    let server_name = config.edge_addr.split(':').next().unwrap_or("localhost").to_string();

    let tls_config = TlsConfig {
        server_name: Some(server_name),
        insecure_skip_verify: config.tls.insecure_skip_verify,
        ca_cert_path: config.tls.ca_cert.clone(),
        cert_path: config.tls.client_cert.clone(),
        key_path: config.tls.client_key.clone(),
    };

    let client = QuicClient::new("0.0.0.0:0".parse()?, &tls_config)?;

    let connection = tokio::time::timeout(
        Duration::from_secs(config.connection.connect_timeout_secs),
        client.connect(edge_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    let latency_ms = connect_start.elapsed().as_millis() as u64;

    let (mut send, mut recv) = connection.open_bi().await?;

    // Authenticate
    let auth_msg = Message::Auth(AuthMessage {
        agent_id,
        auth_token: config.auth_token.clone().unwrap_or_default(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec!["quic".to_string(), "multiplex".to_string()],
    });

    write_message(&mut send, &auth_msg).await?;

    let response = read_message(&mut recv).await?;
    let session_id = match response {
        Message::AuthResponse(auth_resp) => {
            if !auth_resp.success {
                return Err(anyhow::anyhow!(
                    "Authentication failed: {}",
                    auth_resp.error.unwrap_or_default()
                ));
            }
            auth_resp.session_id.unwrap_or_else(|| "unknown".to_string())
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unexpected response: {:?}",
                other.message_type()
            ));
        }
    };

    ui_handle.connected(session_id, latency_ms);

    // Open tunnel
    let tunnel_config = tunnel_opts.to_tunnel_config();
    let open_msg = Message::OpenTunnel(OpenTunnelMessage {
        config: tunnel_config.clone(),
    });

    write_message(&mut send, &open_msg).await?;

    let response = read_message(&mut recv).await?;
    let tunnel_id = match response {
        Message::TunnelOpened(opened) => {
            ui_handle.tunnel_opened(TunnelInfo {
                tunnel_id: opened.tunnel_id.to_string(),
                public_url: opened.public_url.clone(),
                protocol: format!("{}", tunnel_opts.protocol),
                subdomain: opened.public_url
                    .split("://")
                    .nth(1)
                    .and_then(|s| s.split('.').next())
                    .unwrap_or("unknown")
                    .to_string(),
            });
            opened.tunnel_id
        }
        Message::Error(err) => {
            return Err(anyhow::anyhow!("Failed to open tunnel: {}", err.message));
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unexpected response: {:?}",
                other.message_type()
            ));
        }
    };

    let local_addr = format!("{}:{}", tunnel_opts.local_host, tunnel_opts.local_port);
    forwarder::forward_loop_with_ui(connection.clone(), tunnel_id, &local_addr, ui_handle.clone()).await
}

/// Run the main tunnel loop (no TUI)
///
/// This function:
/// 1. Establishes connection to edge
/// 2. Authenticates
/// 3. Opens tunnel
/// 4. Forwards traffic
/// 5. Handles reconnection on failure
pub async fn run_tunnel(config: AgentConfig, tunnel_opts: TunnelOptions) -> anyhow::Result<()> {
    let agent_id = AgentId::new();
    info!("Agent ID: {}", agent_id);
    info!(
        "Exposing {} on {}:{} via {}",
        tunnel_opts.protocol, tunnel_opts.local_host, tunnel_opts.local_port, config.edge_addr
    );

    // Verify local service is reachable
    let local_addr = format!("{}:{}", tunnel_opts.local_host, tunnel_opts.local_port);
    match TcpStream::connect(&local_addr).await {
        Ok(_) => info!("Local service at {} is reachable", local_addr),
        Err(e) => {
            warn!(
                "Could not connect to local service at {}: {}. Tunnel will be established but traffic may fail.",
                local_addr, e
            );
        }
    }

    // Reconnection loop
    let mut attempt = 0u32;
    let mut delay = Duration::from_millis(config.connection.reconnect_delay_ms);
    let max_delay = Duration::from_millis(config.connection.max_reconnect_delay_ms);

    loop {
        attempt += 1;

        // Check max attempts
        if config.connection.max_reconnect_attempts > 0
            && attempt > config.connection.max_reconnect_attempts
        {
            error!("Maximum reconnection attempts reached");
            return Err(anyhow::anyhow!("Maximum reconnection attempts exceeded"));
        }

        if attempt > 1 {
            info!("Reconnecting (attempt {})...", attempt);
        }

        match run_tunnel_once(&config, &tunnel_opts, agent_id).await {
            Ok(()) => {
                info!("Tunnel closed gracefully");
                break;
            }
            Err(e) => {
                error!("Tunnel error: {:#}", e);

                // Wait before reconnecting
                info!("Reconnecting in {:?}...", delay);
                tokio::time::sleep(delay).await;

                // Exponential backoff with jitter
                let jitter = rand_delay();
                delay = std::cmp::min(delay * 2 + jitter, max_delay);
            }
        }
    }

    Ok(())
}

/// Run multiple tunnels simultaneously
///
/// This function establishes a single connection and opens multiple tunnels
pub async fn run_multi_tunnel(
    config: AgentConfig,
    tunnel_opts: Vec<TunnelOptions>,
) -> anyhow::Result<()> {
    let agent_id = AgentId::new();
    info!("Agent ID: {}", agent_id);
    info!("Exposing {} services:", tunnel_opts.len());
    for opt in &tunnel_opts {
        info!("  - {} on {}:{}", opt.protocol, opt.local_host, opt.local_port);
    }

    // Reconnection loop
    let mut attempt = 0u32;
    let mut delay = Duration::from_millis(config.connection.reconnect_delay_ms);
    let max_delay = Duration::from_millis(config.connection.max_reconnect_delay_ms);

    loop {
        attempt += 1;

        if config.connection.max_reconnect_attempts > 0
            && attempt > config.connection.max_reconnect_attempts
        {
            error!("Maximum reconnection attempts reached");
            return Err(anyhow::anyhow!("Maximum reconnection attempts exceeded"));
        }

        if attempt > 1 {
            info!("Reconnecting (attempt {})...", attempt);
        }

        match run_multi_tunnel_once(&config, &tunnel_opts, agent_id).await {
            Ok(()) => {
                info!("Tunnels closed gracefully");
                break;
            }
            Err(e) => {
                error!("Tunnel error: {:#}", e);
                info!("Reconnecting in {:?}...", delay);
                tokio::time::sleep(delay).await;
                let jitter = rand_delay();
                delay = std::cmp::min(delay * 2 + jitter, max_delay);
            }
        }
    }

    Ok(())
}

/// Run multiple tunnels in a single session
async fn run_multi_tunnel_once(
    config: &AgentConfig,
    tunnel_opts: &[TunnelOptions],
    agent_id: AgentId,
) -> anyhow::Result<()> {
    // Parse edge address
    let edge_addr: SocketAddr = if let Ok(addr) = config.edge_addr.parse() {
        addr
    } else {
        use tokio::net::lookup_host;
        lookup_host(&config.edge_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resolve edge address '{}': {}", config.edge_addr, e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("No addresses found for '{}'", config.edge_addr))?
    };

    let server_name = config
        .edge_addr
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    let tls_config = TlsConfig {
        server_name: Some(server_name),
        insecure_skip_verify: config.tls.insecure_skip_verify,
        ca_cert_path: config.tls.ca_cert.clone(),
        cert_path: config.tls.client_cert.clone(),
        key_path: config.tls.client_key.clone(),
    };

    let client = QuicClient::new("0.0.0.0:0".parse()?, &tls_config)?;

    info!("Connecting to edge server at {}...", edge_addr);
    let connection = tokio::time::timeout(
        Duration::from_secs(config.connection.connect_timeout_secs),
        client.connect(edge_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    info!("Connected to edge server");

    // Open control stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Authenticate
    let auth_msg = Message::Auth(AuthMessage {
        agent_id,
        auth_token: config.auth_token.clone().unwrap_or_default(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec!["quic".to_string(), "multiplex".to_string()],
    });

    write_message(&mut send, &auth_msg).await?;
    info!("Sent authentication request");

    let response = read_message(&mut recv).await?;
    match response {
        Message::AuthResponse(auth_resp) => {
            if !auth_resp.success {
                return Err(anyhow::anyhow!(
                    "Authentication failed: {}",
                    auth_resp.error.unwrap_or_default()
                ));
            }
            info!(
                "Authenticated successfully (session: {})",
                auth_resp.session_id.as_deref().unwrap_or("none")
            );
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unexpected response: expected AuthResponse, got {:?}",
                other.message_type()
            ));
        }
    }

    // Open all tunnels and collect their info
    let mut tunnel_mappings = Vec::new();

    for opt in tunnel_opts {
        let tunnel_config = opt.to_tunnel_config();
        let open_msg = Message::OpenTunnel(OpenTunnelMessage {
            config: tunnel_config.clone(),
        });

        write_message(&mut send, &open_msg).await?;
        info!("Requested tunnel for {}:{}", opt.protocol, opt.local_port);

        let response = read_message(&mut recv).await?;
        match response {
            Message::TunnelOpened(opened) => {
                info!("✓ Tunnel opened!");
                info!("  Public URL: {}", opened.public_url);
                info!("  Forwarding to: {}:{}", opt.local_host, opt.local_port);
                tunnel_mappings.push((
                    opened.tunnel_id,
                    format!("{}:{}", opt.local_host, opt.local_port),
                ));
            }
            Message::Error(err) => {
                error!("Failed to open tunnel for {}:{}: {}", opt.protocol, opt.local_port, err.message);
                // Continue with other tunnels
            }
            other => {
                error!(
                    "Unexpected response: expected TunnelOpened, got {:?}",
                    other.message_type()
                );
            }
        }
    }

    if tunnel_mappings.is_empty() {
        return Err(anyhow::anyhow!("No tunnels were opened successfully"));
    }

    info!("All tunnels ready. {} active.", tunnel_mappings.len());

    // Run forward loops for all tunnels
    let result = forwarder::multi_forward_loop(connection.clone(), tunnel_mappings).await;

    if let Err(e) = &result {
        warn!("Multi-forward loop ended: {}", e);
    }

    Ok(())
}

/// Run a single tunnel session
async fn run_tunnel_once(
    config: &AgentConfig,
    tunnel_opts: &TunnelOptions,
    agent_id: AgentId,
) -> anyhow::Result<()> {
    // Parse edge address (support both IP:port and hostname:port)
    let edge_addr: SocketAddr = if let Ok(addr) = config.edge_addr.parse() {
        addr
    } else {
        // Try DNS resolution
        use tokio::net::lookup_host;
        lookup_host(&config.edge_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resolve edge address '{}': {}", config.edge_addr, e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("No addresses found for '{}'", config.edge_addr))?
    };

    // Extract server name for TLS (hostname without port if present)
    let server_name = config
        .edge_addr
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    // Create TLS config
    let tls_config = TlsConfig {
        server_name: Some(server_name),
        insecure_skip_verify: config.tls.insecure_skip_verify,
        ca_cert_path: config.tls.ca_cert.clone(),
        cert_path: config.tls.client_cert.clone(),
        key_path: config.tls.client_key.clone(),
    };

    // Create QUIC client
    let client = QuicClient::new("0.0.0.0:0".parse()?, &tls_config)?;

    // Connect to edge
    info!("Connecting to edge server at {}...", edge_addr);
    let connection = tokio::time::timeout(
        Duration::from_secs(config.connection.connect_timeout_secs),
        client.connect(edge_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    info!("Connected to edge server");

    // Open control stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Authenticate
    let auth_msg = Message::Auth(AuthMessage {
        agent_id,
        auth_token: config.auth_token.clone().unwrap_or_default(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec!["quic".to_string(), "multiplex".to_string()],
    });

    write_message(&mut send, &auth_msg).await?;
    info!("Sent authentication request");

    // Wait for auth response
    let response = read_message(&mut recv).await?;
    match response {
        Message::AuthResponse(auth_resp) => {
            if !auth_resp.success {
                return Err(anyhow::anyhow!(
                    "Authentication failed: {}",
                    auth_resp.error.unwrap_or_default()
                ));
            }
            info!(
                "Authenticated successfully (session: {})",
                auth_resp.session_id.as_deref().unwrap_or("none")
            );
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unexpected response: expected AuthResponse, got {:?}",
                other.message_type()
            ));
        }
    }

    // Open tunnel
    let tunnel_config = tunnel_opts.to_tunnel_config();
    let open_msg = Message::OpenTunnel(OpenTunnelMessage {
        config: tunnel_config.clone(),
    });

    write_message(&mut send, &open_msg).await?;
    info!("Requested tunnel for {}:{}", tunnel_opts.protocol, tunnel_opts.local_port);

    // Wait for tunnel confirmation
    let response = read_message(&mut recv).await?;
    let (tunnel_id, _public_url) = match response {
        Message::TunnelOpened(opened) => {
            info!("✓ Tunnel opened!");
            info!("  Public URL: {}", opened.public_url);
            info!("  Forwarding to: {}:{}", tunnel_opts.local_host, tunnel_opts.local_port);
            (opened.tunnel_id, opened.public_url)
        }
        Message::Error(err) => {
            return Err(anyhow::anyhow!("Failed to open tunnel: {}", err.message));
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unexpected response: expected TunnelOpened, got {:?}",
                other.message_type()
            ));
        }
    };

    // Main event loop - handle incoming streams
    let local_addr = format!("{}:{}", tunnel_opts.local_host, tunnel_opts.local_port);

    // Handle incoming streams (new connections to forward)
    // QUIC transport already has built-in keepalive
    let result = forwarder::forward_loop(connection.clone(), tunnel_id, &local_addr).await;

    if let Err(e) = &result {
        warn!("Forward loop ended: {}", e);
    }

    Ok(())
}

/// Heartbeat loop to keep connection alive (currently unused - QUIC transport handles keepalive)
#[allow(dead_code)]
async fn heartbeat_loop(
    connection: nlag_common::transport::quic::QuicConnection,
) -> anyhow::Result<()> {
    let mut seq = 0u32;
    let mut interval = tokio::time::interval(Duration::from_secs(
        nlag_common::protocol::HEARTBEAT_INTERVAL_SECS,
    ));

    loop {
        interval.tick().await;

        // Check if connection is still open
        if connection.is_closed() {
            return Err(anyhow::anyhow!("Connection closed"));
        }

        // Open a new stream for heartbeat
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                warn!("Failed to open heartbeat stream: {}", e);
                continue;
            }
        };

        // Send ping
        let ping = Message::Ping(PingMessage {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            seq,
        });

        if let Err(e) = write_message(&mut send, &ping).await {
            warn!("Failed to send heartbeat: {}", e);
            continue;
        }

        // Wait for pong
        match tokio::time::timeout(Duration::from_secs(10), read_message(&mut recv)).await {
            Ok(Ok(Message::Pong(pong))) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let rtt = now.saturating_sub(pong.timestamp);
                tracing::debug!("Heartbeat OK (RTT: {}ms, seq: {})", rtt, pong.seq);
            }
            Ok(Ok(other)) => {
                warn!("Unexpected heartbeat response: {:?}", other.message_type());
            }
            Ok(Err(e)) => {
                warn!("Failed to read heartbeat response: {}", e);
            }
            Err(_) => {
                warn!("Heartbeat timeout");
            }
        }

        seq = seq.wrapping_add(1);
    }
}

/// Generate a random delay for jitter
fn rand_delay() -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    Duration::from_millis((nanos % 1000) as u64)
}
