//! Raw TCP tunnel handler
//!
//! Handles raw TCP connections routed by port number.
//! Each TCP tunnel gets an assigned port on the edge server.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use nlag_common::{
    protocol::{
        codec::quic::{read_message, write_message},
        message::{DataFrame, Message, StreamCloseMessage, StreamOpenMessage},
    },
    types::{StreamId, TunnelId},
};

use crate::logging::TcpConnectionLogBuilder;
use crate::metrics;
use crate::registry::Registry;

/// Configuration for TCP tunnel port allocation
#[derive(Debug, Clone)]
pub struct TcpPortConfig {
    /// Start of port range for TCP tunnels
    pub port_range_start: u16,
    /// End of port range (exclusive)
    pub port_range_end: u16,
    /// Address to bind TCP listeners to
    pub bind_addr: String,
}

impl Default for TcpPortConfig {
    fn default() -> Self {
        Self {
            port_range_start: 10000,
            port_range_end: 20000,
            bind_addr: "0.0.0.0".to_string(),
        }
    }
}

/// Manages TCP tunnel port assignments and listeners
pub struct TcpTunnelManager {
    config: TcpPortConfig,
    registry: Arc<Registry>,
    /// Port -> TunnelId mapping
    port_map: Arc<RwLock<HashMap<u16, TunnelId>>>,
    /// Next port to try allocating
    next_port: Arc<AtomicU64>,
    stream_counter: AtomicU64,
}

impl TcpTunnelManager {
    /// Create a new TCP tunnel manager
    pub fn new(config: TcpPortConfig, registry: Arc<Registry>) -> Self {
        Self {
            next_port: Arc::new(AtomicU64::new(config.port_range_start as u64)),
            config,
            registry,
            port_map: Arc::new(RwLock::new(HashMap::new())),
            stream_counter: AtomicU64::new(0),
        }
    }

    /// Allocate a port for a TCP tunnel
    pub fn allocate_port(&self, tunnel_id: TunnelId) -> Option<u16> {
        let mut port_map = self.port_map.write();
        
        // Find next available port
        let start = self.next_port.load(Ordering::Relaxed) as u16;
        let range_size = self.config.port_range_end - self.config.port_range_start;
        
        for offset in 0..range_size {
            let port = self.config.port_range_start + ((start - self.config.port_range_start + offset) % range_size);
            
            if let std::collections::hash_map::Entry::Vacant(e) = port_map.entry(port) {
                e.insert(tunnel_id);
                self.next_port.store((port + 1) as u64, Ordering::Relaxed);
                return Some(port);
            }
        }
        
        None // No ports available
    }

    /// Release a port
    pub fn release_port(&self, port: u16) {
        self.port_map.write().remove(&port);
    }

    /// Get tunnel ID for a port
    pub fn get_tunnel(&self, port: u16) -> Option<TunnelId> {
        self.port_map.read().get(&port).copied()
    }

    /// Start a listener for a specific TCP tunnel port
    pub async fn start_listener(&self, port: u16) -> anyhow::Result<()> {
        let bind_addr: SocketAddr = format!("{}:{}", self.config.bind_addr, port).parse()?;
        let listener = TcpListener::bind(bind_addr).await?;
        
        info!("TCP tunnel listener started on port {}", port);
        
        let registry = self.registry.clone();
        let port_map = self.port_map.clone();
        let stream_counter = &self.stream_counter;
        
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(result) => result,
                Err(e) => {
                    error!("TCP accept error on port {}: {}", port, e);
                    continue;
                }
            };
            
            debug!("New TCP connection from {} on port {}", addr, port);
            
            // Look up tunnel
            let tunnel_id = match port_map.read().get(&port).copied() {
                Some(tid) => tid,
                None => {
                    warn!("No tunnel registered for port {}", port);
                    continue;
                }
            };
            
            let registry = registry.clone();
            let stream_id = StreamId(stream_counter.fetch_add(1, Ordering::Relaxed));
            
            tokio::spawn(async move {
                if let Err(e) = handle_tcp_connection(stream, addr, tunnel_id, stream_id, registry, port).await {
                    debug!("TCP connection ended: {}", e);
                }
            });
        }
    }
}

/// Handle a single TCP connection
async fn handle_tcp_connection(
    mut stream: TcpStream,
    source_addr: SocketAddr,
    tunnel_id: TunnelId,
    stream_id: StreamId,
    registry: Arc<Registry>,
    port: u16,
) -> anyhow::Result<()> {
    let _start_time = Instant::now();
    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));

    // Get connection to agent
    let agent_conn = match registry.get_tunnel_connection(&tunnel_id) {
        Some(conn) => conn,
        None => {
            return Err(anyhow::anyhow!("Agent not connected"));
        }
    };

    debug!("Routing TCP connection to tunnel {}", tunnel_id);

    // Open stream to agent
    let (mut agent_send, mut agent_recv) = agent_conn.open_bi().await?;

    // Send stream open message (no HTTP metadata for TCP)
    let open_msg = Message::StreamOpen(StreamOpenMessage {
        tunnel_id,
        stream_id,
        source_addr: source_addr.to_string(),
        metadata: None,
    });
    write_message(&mut agent_send, &open_msg).await?;

    // Bidirectional forwarding
    let (mut client_read, mut client_write) = stream.split();

    // Client -> Agent
    let bytes_in_clone = bytes_in.clone();
    let client_to_agent = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!("TCP client read error: {}", e);
                    break;
                }
            };

            bytes_in_clone.fetch_add(n as u64, Ordering::Relaxed);

            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if let Err(e) = write_message(&mut agent_send, &frame).await {
                debug!("TCP agent write error: {}", e);
                break;
            }
        }

        // Send close
        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut agent_send, &close).await;
    };

    // Agent -> Client
    let bytes_out_clone = bytes_out.clone();
    let agent_to_client = async move {
        loop {
            let msg = match read_message(&mut agent_recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("TCP agent read error: {}", e);
                    break;
                }
            };

            match msg {
                Message::Data(frame) => {
                    bytes_out_clone.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                    if let Err(e) = client_write.write_all(&frame.payload).await {
                        debug!("TCP client write error: {}", e);
                        break;
                    }
                }
                Message::StreamClose(_) => {
                    break;
                }
                other => {
                    debug!("Unexpected message: {:?}", other.message_type());
                }
            }
        }

        let _ = client_write.shutdown().await;
    };

    // Run both directions
    tokio::join!(client_to_agent, agent_to_client);

    // Record metrics and logging
    let total_bytes_in = bytes_in.load(Ordering::Relaxed);
    let total_bytes_out = bytes_out.load(Ordering::Relaxed);
    
    // Record bytes for TCP tunnel
    metrics::record_bytes(total_bytes_in, total_bytes_out);

    // TCP connection logging
    let mut log_builder = TcpConnectionLogBuilder::new(
        tunnel_id,
        stream_id,
        source_addr.to_string(),
        port,
    );
    log_builder.add_bytes_in(total_bytes_in);
    log_builder.add_bytes_out(total_bytes_out);
    log_builder.finish();

    debug!("TCP stream {} closed", stream_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_config_default() {
        let config = TcpPortConfig::default();
        assert_eq!(config.port_range_start, 10000);
        assert_eq!(config.port_range_end, 20000);
    }
}
