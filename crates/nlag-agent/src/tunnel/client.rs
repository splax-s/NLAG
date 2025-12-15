//! QUIC client wrapper for agent connections
//!
//! Provides a higher-level interface over the raw QUIC transport
//! with agent-specific functionality.

// Reserved for advanced connection management features
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use nlag_common::{
    crypto::tls::TlsConfig,
    transport::quic::{QuicClient as RawQuicClient, QuicConnection},
    types::AgentId,
    Result,
};

/// State of the client connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/// Agent QUIC client with connection management
pub struct AgentClient {
    /// Raw QUIC client
    client: RawQuicClient,
    /// Current connection (if any)
    connection: Arc<RwLock<Option<QuicConnection>>>,
    /// Connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Agent ID
    agent_id: AgentId,
    /// Edge server address
    edge_addr: SocketAddr,
}

impl AgentClient {
    /// Create a new agent client
    pub fn new(
        edge_addr: SocketAddr,
        tls_config: &TlsConfig,
        agent_id: AgentId,
    ) -> Result<Self> {
        let client = RawQuicClient::new("0.0.0.0:0".parse().unwrap(), tls_config)?;

        Ok(Self {
            client,
            connection: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            agent_id,
            edge_addr,
        })
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Get agent ID
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Connect to the edge server
    pub async fn connect(&self) -> Result<QuicConnection> {
        *self.state.write() = ConnectionState::Connecting;

        match self.client.connect(self.edge_addr).await {
            Ok(conn) => {
                *self.connection.write() = Some(conn.clone());
                *self.state.write() = ConnectionState::Connected;
                Ok(conn)
            }
            Err(e) => {
                *self.state.write() = ConnectionState::Disconnected;
                Err(e)
            }
        }
    }

    /// Get current connection if available
    pub fn connection(&self) -> Option<QuicConnection> {
        self.connection.read().clone()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection
            .read()
            .as_ref()
            .map(|c| !c.is_closed())
            .unwrap_or(false)
    }

    /// Disconnect
    pub fn disconnect(&self) {
        if let Some(conn) = self.connection.write().take() {
            conn.close(0, "client disconnect");
        }
        *self.state.write() = ConnectionState::Disconnected;
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}
