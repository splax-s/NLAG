//! Connection Pool Management
//!
//! Provides connection pooling for agent connections to reduce latency
//! and overhead from establishing new QUIC streams.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tracing::{debug, info};

use nlag_common::types::TunnelId;

/// Configuration for connection pooling
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per tunnel
    pub max_connections_per_tunnel: usize,

    /// Minimum connections to keep warm per tunnel
    pub min_connections_per_tunnel: usize,

    /// Maximum idle time before closing a connection
    pub idle_timeout: Duration,

    /// Maximum connection lifetime
    pub max_lifetime: Duration,

    /// How often to check for stale connections
    pub cleanup_interval: Duration,

    /// Maximum time to wait for a connection
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_tunnel: 100,
            min_connections_per_tunnel: 5,
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(30),
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

/// A pooled connection wrapper
pub struct PooledConnection<C> {
    /// The underlying connection
    pub connection: C,

    /// When this connection was created
    created_at: Instant,

    /// When this connection was last used
    last_used: Instant,

    /// Number of times this connection has been used
    use_count: u64,
}

impl<C> PooledConnection<C> {
    /// Create a new pooled connection
    pub fn new(connection: C) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
            use_count: 0,
        }
    }

    /// Check if this connection is still valid
    pub fn is_valid(&self, config: &PoolConfig) -> bool {
        let now = Instant::now();

        // Check idle timeout
        if now.duration_since(self.last_used) > config.idle_timeout {
            return false;
        }

        // Check max lifetime
        if now.duration_since(self.created_at) > config.max_lifetime {
            return false;
        }

        true
    }

    /// Mark the connection as used
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }
}

/// A pool of connections for a specific tunnel
struct TunnelPool<C> {
    /// Available connections
    connections: Mutex<VecDeque<PooledConnection<C>>>,

    /// Semaphore to limit total connections
    semaphore: Semaphore,

    /// Number of active (checked out) connections
    active_count: AtomicU64,

    /// Statistics
    stats: PoolStats,
}

/// Pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total connections created
    pub connections_created: AtomicU64,

    /// Total connections reused
    pub connections_reused: AtomicU64,

    /// Total connections closed
    pub connections_closed: AtomicU64,

    /// Number of times we had to wait for a connection
    pub wait_count: AtomicU64,

    /// Total wait time in milliseconds
    pub total_wait_ms: AtomicU64,
}

impl<C> TunnelPool<C> {
    fn new(max_connections: usize) -> Self {
        Self {
            connections: Mutex::new(VecDeque::new()),
            semaphore: Semaphore::new(max_connections),
            active_count: AtomicU64::new(0),
            stats: PoolStats::default(),
        }
    }
}

/// Connection pool manager
pub struct ConnectionPool<C> {
    /// Per-tunnel connection pools
    pools: DashMap<TunnelId, Arc<TunnelPool<C>>>,

    /// Configuration
    config: PoolConfig,

    /// Global statistics
    global_stats: PoolStats,
}

impl<C: Clone + Send + 'static> ConnectionPool<C> {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Arc<Self> {
        let pool = Arc::new(Self {
            pools: DashMap::new(),
            config,
            global_stats: PoolStats::default(),
        });

        // Start background cleanup task
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.cleanup_loop().await;
        });

        pool
    }

    /// Get or create a pool for a tunnel
    fn get_or_create_pool(&self, tunnel_id: TunnelId) -> Arc<TunnelPool<C>> {
        self.pools
            .entry(tunnel_id)
            .or_insert_with(|| Arc::new(TunnelPool::new(self.config.max_connections_per_tunnel)))
            .clone()
    }

    /// Acquire a connection from the pool
    pub async fn acquire<F, Fut>(
        &self,
        tunnel_id: TunnelId,
        create_connection: F,
    ) -> Result<PooledConnection<C>, PoolError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<C, PoolError>>,
    {
        let pool = self.get_or_create_pool(tunnel_id);

        // Try to get a permit (limits total connections)
        let permit_result = tokio::time::timeout(
            self.config.acquire_timeout,
            pool.semaphore.acquire(),
        )
        .await;

        let _permit = match permit_result {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(PoolError::PoolClosed),
            Err(_) => {
                pool.stats.wait_count.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::AcquireTimeout);
            }
        };

        // Try to get an existing connection
        {
            let mut connections = pool.connections.lock();
            while let Some(mut conn) = connections.pop_front() {
                if conn.is_valid(&self.config) {
                    conn.touch();
                    pool.active_count.fetch_add(1, Ordering::Relaxed);
                    pool.stats.connections_reused.fetch_add(1, Ordering::Relaxed);
                    self.global_stats.connections_reused.fetch_add(1, Ordering::Relaxed);
                    debug!(tunnel_id = %tunnel_id, "Reusing pooled connection");
                    return Ok(conn);
                } else {
                    // Connection expired, close it
                    pool.stats.connections_closed.fetch_add(1, Ordering::Relaxed);
                    self.global_stats.connections_closed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // No valid connection available, create a new one
        let connection = create_connection().await?;
        pool.active_count.fetch_add(1, Ordering::Relaxed);
        pool.stats.connections_created.fetch_add(1, Ordering::Relaxed);
        self.global_stats.connections_created.fetch_add(1, Ordering::Relaxed);
        debug!(tunnel_id = %tunnel_id, "Created new pooled connection");

        Ok(PooledConnection::new(connection))
    }

    /// Return a connection to the pool
    pub fn release(&self, tunnel_id: TunnelId, mut connection: PooledConnection<C>) {
        if let Some(pool) = self.pools.get(&tunnel_id) {
            pool.active_count.fetch_sub(1, Ordering::Relaxed);

            // Check if connection is still valid
            if connection.is_valid(&self.config) {
                connection.touch();
                let mut connections = pool.connections.lock();
                connections.push_back(connection);
                debug!(tunnel_id = %tunnel_id, "Returned connection to pool");
            } else {
                pool.stats.connections_closed.fetch_add(1, Ordering::Relaxed);
                self.global_stats.connections_closed.fetch_add(1, Ordering::Relaxed);
                debug!(tunnel_id = %tunnel_id, "Connection expired, not returning to pool");
            }
        }
    }

    /// Remove a pool for a tunnel (when tunnel is closed)
    pub fn remove_pool(&self, tunnel_id: &TunnelId) {
        if let Some((_, pool)) = self.pools.remove(tunnel_id) {
            let connections = pool.connections.lock();
            let closed_count = connections.len() as u64;
            self.global_stats.connections_closed.fetch_add(closed_count, Ordering::Relaxed);
            info!(tunnel_id = %tunnel_id, closed = closed_count, "Removed connection pool");
        }
    }

    /// Get pool statistics for a tunnel
    pub fn get_pool_stats(&self, tunnel_id: &TunnelId) -> Option<TunnelPoolStats> {
        self.pools.get(tunnel_id).map(|pool| TunnelPoolStats {
            available: pool.connections.lock().len(),
            active: pool.active_count.load(Ordering::Relaxed) as usize,
            created: pool.stats.connections_created.load(Ordering::Relaxed),
            reused: pool.stats.connections_reused.load(Ordering::Relaxed),
            closed: pool.stats.connections_closed.load(Ordering::Relaxed),
        })
    }

    /// Get global statistics
    pub fn get_global_stats(&self) -> GlobalPoolStats {
        GlobalPoolStats {
            total_pools: self.pools.len(),
            total_created: self.global_stats.connections_created.load(Ordering::Relaxed),
            total_reused: self.global_stats.connections_reused.load(Ordering::Relaxed),
            total_closed: self.global_stats.connections_closed.load(Ordering::Relaxed),
        }
    }

    /// Background cleanup loop
    async fn cleanup_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.cleanup_interval);

        loop {
            interval.tick().await;

            let mut total_cleaned = 0usize;

            for entry in self.pools.iter() {
                let pool = entry.value();
                let mut connections = pool.connections.lock();

                // Remove expired connections while keeping minimum
                let to_remove: Vec<_> = connections
                    .iter()
                    .enumerate()
                    .filter(|(i, conn)| {
                        // Keep minimum connections even if they're idle
                        *i >= self.config.min_connections_per_tunnel
                            && !conn.is_valid(&self.config)
                    })
                    .map(|(i, _)| i)
                    .collect();

                // Remove from back to front to maintain indices
                for idx in to_remove.into_iter().rev() {
                    connections.remove(idx);
                    total_cleaned += 1;
                }
            }

            if total_cleaned > 0 {
                debug!(cleaned = total_cleaned, "Cleaned up expired connections");
            }
        }
    }
}

/// Statistics for a single tunnel's pool
#[derive(Debug, Clone)]
pub struct TunnelPoolStats {
    pub available: usize,
    pub active: usize,
    pub created: u64,
    pub reused: u64,
    pub closed: u64,
}

/// Global pool statistics
#[derive(Debug, Clone)]
pub struct GlobalPoolStats {
    pub total_pools: usize,
    pub total_created: u64,
    pub total_reused: u64,
    pub total_closed: u64,
}

/// Errors that can occur with the connection pool
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    #[error("Timeout waiting for connection")]
    AcquireTimeout,

    #[error("Pool is closed")]
    PoolClosed,

    #[error("Connection creation failed: {0}")]
    ConnectionFailed(String),

    #[error("Pool exhausted")]
    Exhausted,
}

/// A guard that returns a connection to the pool when dropped
pub struct ConnectionGuard<'a, C: Clone + Send + 'static> {
    pool: &'a ConnectionPool<C>,
    tunnel_id: TunnelId,
    connection: Option<PooledConnection<C>>,
}

impl<'a, C: Clone + Send + 'static> ConnectionGuard<'a, C> {
    /// Create a new connection guard
    pub fn new(
        pool: &'a ConnectionPool<C>,
        tunnel_id: TunnelId,
        connection: PooledConnection<C>,
    ) -> Self {
        Self {
            pool,
            tunnel_id,
            connection: Some(connection),
        }
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &C {
        &self.connection.as_ref().unwrap().connection
    }

    /// Get a mutable reference to the underlying connection
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection.as_mut().unwrap().connection
    }

    /// Take the connection without returning it to the pool
    /// (for when the connection is broken)
    pub fn take(mut self) -> PooledConnection<C> {
        self.connection.take().unwrap()
    }
}

impl<'a, C: Clone + Send + 'static> Drop for ConnectionGuard<'a, C> {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            self.pool.release(self.tunnel_id, conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_acquire_and_release() {
        let config = PoolConfig {
            max_connections_per_tunnel: 10,
            ..Default::default()
        };
        let pool: Arc<ConnectionPool<String>> = ConnectionPool::new(config);
        let tunnel_id = TunnelId::new();

        // Acquire a connection
        let conn = pool
            .acquire(tunnel_id, || async { Ok("test_connection".to_string()) })
            .await
            .unwrap();

        assert_eq!(conn.connection, "test_connection");
        assert_eq!(conn.use_count, 0);

        // Release it
        pool.release(tunnel_id, conn);

        // Stats should reflect this
        let stats = pool.get_pool_stats(&tunnel_id).unwrap();
        assert_eq!(stats.available, 1);
        assert_eq!(stats.created, 1);
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let config = PoolConfig {
            max_connections_per_tunnel: 10,
            ..Default::default()
        };
        let pool: Arc<ConnectionPool<String>> = ConnectionPool::new(config);
        let tunnel_id = TunnelId::new();

        // Acquire and release
        let conn1 = pool
            .acquire(tunnel_id, || async { Ok("conn1".to_string()) })
            .await
            .unwrap();
        pool.release(tunnel_id, conn1);

        // Acquire again - should get reused connection
        let conn2 = pool
            .acquire(tunnel_id, || async { Ok("conn2".to_string()) })
            .await
            .unwrap();

        // Should be the same connection (reused)
        assert_eq!(conn2.connection, "conn1");

        let stats = pool.get_pool_stats(&tunnel_id).unwrap();
        assert_eq!(stats.reused, 1);
    }

    #[test]
    fn test_connection_validity() {
        let config = PoolConfig {
            idle_timeout: Duration::from_millis(100),
            max_lifetime: Duration::from_secs(3600),
            ..Default::default()
        };

        let mut conn = PooledConnection::new("test".to_string());
        assert!(conn.is_valid(&config));

        // Simulate time passing
        conn.last_used = Instant::now() - Duration::from_millis(200);
        assert!(!conn.is_valid(&config));
    }
}
