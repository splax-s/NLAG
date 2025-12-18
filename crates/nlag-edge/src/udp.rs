//! UDP Tunneling Support
//!
//! This module provides support for tunneling UDP traffic through the edge server.
//! UDP packets are encapsulated and transmitted over the QUIC connection.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// UDP tunneling errors
#[derive(Debug, Error)]
pub enum UdpError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Buffer full")]
    BufferFull,
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Channel closed")]
    ChannelClosed,
}

pub type Result<T> = std::result::Result<T, UdpError>;

/// UDP session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpSessionId(pub u64);

impl UdpSessionId {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

impl Default for UdpSessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// A UDP packet for tunneling
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// Session ID for this UDP connection
    pub session_id: UdpSessionId,
    /// Source address (original client)
    pub source: SocketAddr,
    /// Destination port (on the agent side)
    pub dest_port: u16,
    /// Packet data
    pub data: Bytes,
    /// Timestamp when received
    pub timestamp: Instant,
}

impl UdpPacket {
    /// Create a new UDP packet
    pub fn new(session_id: UdpSessionId, source: SocketAddr, dest_port: u16, data: Bytes) -> Self {
        Self {
            session_id,
            source,
            dest_port,
            data,
            timestamp: Instant::now(),
        }
    }
    
    /// Encode packet for transmission over QUIC
    /// 
    /// Format: `[session_id:8][source_type:1][source:4|16][source_port:2][dest_port:2][length:2][data:length]`
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32 + self.data.len());
        
        // Session ID (8 bytes)
        buf.put_u64(self.session_id.0);
        
        // Source address
        match self.source {
            SocketAddr::V4(addr) => {
                buf.put_u8(4); // IPv4
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6); // IPv6
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }
        
        // Destination port
        buf.put_u16(self.dest_port);
        
        // Data length and data
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);
        
        buf.freeze()
    }
    
    /// Decode packet from QUIC transmission
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 15 {
            return Err(UdpError::InvalidPacket("Packet too short".to_string()));
        }
        
        // Session ID
        let session_id = UdpSessionId(data.get_u64());
        
        // Source address type
        let addr_type = data.get_u8();
        
        let source = match addr_type {
            4 => {
                if data.len() < 8 {
                    return Err(UdpError::InvalidPacket("IPv4 packet too short".to_string()));
                }
                let mut octets = [0u8; 4];
                data.copy_to_slice(&mut octets);
                let port = data.get_u16();
                SocketAddr::from((octets, port))
            }
            6 => {
                if data.len() < 20 {
                    return Err(UdpError::InvalidPacket("IPv6 packet too short".to_string()));
                }
                let mut octets = [0u8; 16];
                data.copy_to_slice(&mut octets);
                let port = data.get_u16();
                SocketAddr::from((octets, port))
            }
            _ => {
                return Err(UdpError::InvalidPacket(format!(
                    "Invalid address type: {}",
                    addr_type
                )));
            }
        };
        
        // Destination port
        if data.len() < 4 {
            return Err(UdpError::InvalidPacket("Missing dest port/length".to_string()));
        }
        let dest_port = data.get_u16();
        
        // Data length and data
        let length = data.get_u16() as usize;
        if data.len() < length {
            return Err(UdpError::InvalidPacket(format!(
                "Data truncated: expected {} bytes, got {}",
                length,
                data.len()
            )));
        }
        
        let packet_data = data.slice(..length);
        
        Ok(Self {
            session_id,
            source,
            dest_port,
            data: packet_data,
            timestamp: Instant::now(),
        })
    }
}

/// UDP session state
#[derive(Debug)]
pub struct UdpSession {
    /// Session ID
    pub id: UdpSessionId,
    /// Remote client address
    pub client_addr: SocketAddr,
    /// Target port on the agent
    pub target_port: u16,
    /// Last activity time
    pub last_activity: RwLock<Instant>,
    /// Bytes received
    pub bytes_received: AtomicU64,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Packets received
    pub packets_received: AtomicU64,
    /// Packets sent  
    pub packets_sent: AtomicU64,
}

impl UdpSession {
    pub fn new(client_addr: SocketAddr, target_port: u16) -> Self {
        Self {
            id: UdpSessionId::new(),
            client_addr,
            target_port,
            last_activity: RwLock::new(Instant::now()),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
        }
    }
    
    /// Update last activity time
    pub fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }
    
    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.read().elapsed() > timeout
    }
    
    /// Record received bytes
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }
    
    /// Record sent bytes
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }
}

/// UDP tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpConfig {
    /// Enable UDP tunneling
    #[serde(default = "default_udp_enabled")]
    pub enabled: bool,
    
    /// UDP listen address
    #[serde(default = "default_udp_addr")]
    pub listen_addr: String,
    
    /// Maximum packet size in bytes
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,
    
    /// Session timeout in seconds
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
    
    /// Maximum concurrent sessions
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    
    /// Buffer size for each session
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_udp_enabled() -> bool {
    false // Disabled by default
}

fn default_udp_addr() -> String {
    "0.0.0.0:4444".to_string()
}

fn default_max_packet_size() -> usize {
    65535 // Maximum UDP packet size
}

fn default_session_timeout() -> u64 {
    300 // 5 minutes
}

fn default_max_sessions() -> usize {
    10000
}

fn default_buffer_size() -> usize {
    1024 * 1024 // 1MB per session
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: default_udp_enabled(),
            listen_addr: default_udp_addr(),
            max_packet_size: default_max_packet_size(),
            session_timeout_secs: default_session_timeout(),
            max_sessions: default_max_sessions(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// UDP tunnel manager
pub struct UdpTunnelManager {
    /// Configuration
    config: UdpConfig,
    /// Active sessions by client address
    sessions: DashMap<SocketAddr, Arc<UdpSession>>,
    /// Sessions by ID for quick lookup
    sessions_by_id: DashMap<UdpSessionId, Arc<UdpSession>>,
    /// Packet sender channel to agent
    packet_tx: mpsc::Sender<UdpPacket>,
}

impl UdpTunnelManager {
    /// Create a new UDP tunnel manager
    pub fn new(config: UdpConfig, packet_tx: mpsc::Sender<UdpPacket>) -> Arc<Self> {
        Arc::new(Self {
            config,
            sessions: DashMap::new(),
            sessions_by_id: DashMap::new(),
            packet_tx,
        })
    }
    
    /// Get or create a session for a client
    pub fn get_or_create_session(
        &self,
        client_addr: SocketAddr,
        target_port: u16,
    ) -> Result<Arc<UdpSession>> {
        if let Some(session) = self.sessions.get(&client_addr) {
            session.touch();
            return Ok(session.clone());
        }
        
        // Check session limit
        if self.sessions.len() >= self.config.max_sessions {
            return Err(UdpError::BufferFull);
        }
        
        // Create new session
        let session = Arc::new(UdpSession::new(client_addr, target_port));
        self.sessions.insert(client_addr, session.clone());
        self.sessions_by_id.insert(session.id, session.clone());
        
        info!(
            "Created UDP session {} for {} -> port {}",
            session.id.0, client_addr, target_port
        );
        
        Ok(session)
    }
    
    /// Get session by ID
    pub fn get_session(&self, id: UdpSessionId) -> Option<Arc<UdpSession>> {
        self.sessions_by_id.get(&id).map(|s| s.clone())
    }
    
    /// Remove expired sessions
    pub fn cleanup_expired(&self) {
        let timeout = Duration::from_secs(self.config.session_timeout_secs);
        let mut expired = Vec::new();
        
        for entry in self.sessions.iter() {
            if entry.is_expired(timeout) {
                expired.push(*entry.key());
            }
        }
        
        for addr in expired {
            if let Some((_, session)) = self.sessions.remove(&addr) {
                self.sessions_by_id.remove(&session.id);
                info!("Removed expired UDP session {} for {}", session.id.0, addr);
            }
        }
    }
    
    /// Handle incoming UDP packet from client
    pub async fn handle_incoming(&self, source: SocketAddr, target_port: u16, data: Bytes) -> Result<()> {
        let session = self.get_or_create_session(source, target_port)?;
        
        let packet = UdpPacket::new(session.id, source, target_port, data.clone());
        session.record_received(data.len() as u64);
        
        self.packet_tx.send(packet).await.map_err(|_| UdpError::ChannelClosed)?;
        
        Ok(())
    }
    
    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    
    /// Get total stats
    pub fn get_stats(&self) -> UdpStats {
        let mut stats = UdpStats::default();
        
        for entry in self.sessions.iter() {
            let session = entry.value();
            stats.active_sessions += 1;
            stats.bytes_received += session.bytes_received.load(Ordering::Relaxed);
            stats.bytes_sent += session.bytes_sent.load(Ordering::Relaxed);
            stats.packets_received += session.packets_received.load(Ordering::Relaxed);
            stats.packets_sent += session.packets_sent.load(Ordering::Relaxed);
        }
        
        stats
    }
    
    /// Start cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                self.cleanup_expired();
            }
        });
    }
}

/// UDP statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UdpStats {
    pub active_sessions: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub packets_sent: u64,
}

/// UDP listener for receiving packets
pub struct UdpListener {
    socket: Arc<UdpSocket>,
    manager: Arc<UdpTunnelManager>,
    max_packet_size: usize,
}

impl UdpListener {
    /// Create a new UDP listener
    pub async fn bind(addr: &str, manager: Arc<UdpTunnelManager>, max_packet_size: usize) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!("UDP listener bound to {}", addr);
        
        Ok(Self {
            socket: Arc::new(socket),
            manager,
            max_packet_size,
        })
    }
    
    /// Run the listener
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; self.max_packet_size];
        
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, source)) => {
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    
                    // Extract target port from first 2 bytes if present
                    // Otherwise use a default port
                    let (target_port, packet_data) = if len >= 2 {
                        let port = u16::from_be_bytes([buf[0], buf[1]]);
                        if port > 0 && port < 65535 {
                            (port, data.slice(2..))
                        } else {
                            (0, data)
                        }
                    } else {
                        (0, data)
                    };
                    
                    if let Err(e) = self.manager.handle_incoming(source, target_port, packet_data).await {
                        warn!("Failed to handle UDP packet from {}: {}", source, e);
                    }
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                }
            }
        }
    }
    
    /// Send a packet back to a client
    pub async fn send_to(&self, addr: SocketAddr, data: &[u8]) -> Result<usize> {
        let sent = self.socket.send_to(data, addr).await?;
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_encode_decode_ipv4() {
        let packet = UdpPacket::new(
            UdpSessionId(12345),
            "192.168.1.100:5000".parse().unwrap(),
            8080,
            Bytes::from("Hello UDP"),
        );
        
        let encoded = packet.encode();
        let decoded = UdpPacket::decode(encoded).unwrap();
        
        assert_eq!(decoded.session_id.0, 12345);
        assert_eq!(decoded.source.to_string(), "192.168.1.100:5000");
        assert_eq!(decoded.dest_port, 8080);
        assert_eq!(&decoded.data[..], b"Hello UDP");
    }
    
    #[test]
    fn test_packet_encode_decode_ipv6() {
        let packet = UdpPacket::new(
            UdpSessionId(99999),
            "[::1]:5000".parse().unwrap(),
            9000,
            Bytes::from("IPv6 test"),
        );
        
        let encoded = packet.encode();
        let decoded = UdpPacket::decode(encoded).unwrap();
        
        assert_eq!(decoded.session_id.0, 99999);
        assert_eq!(decoded.source.to_string(), "[::1]:5000");
        assert_eq!(decoded.dest_port, 9000);
        assert_eq!(&decoded.data[..], b"IPv6 test");
    }
    
    #[test]
    fn test_session_expiry() {
        let session = UdpSession::new("127.0.0.1:1234".parse().unwrap(), 8080);
        
        assert!(!session.is_expired(Duration::from_secs(10)));
        
        // Manually set last_activity to the past
        *session.last_activity.write() = Instant::now() - Duration::from_secs(20);
        
        assert!(session.is_expired(Duration::from_secs(10)));
    }
}
