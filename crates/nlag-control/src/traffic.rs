//! Traffic Storage Module
//!
//! Provides persistent storage for HTTP traffic logs with:
//! - PostgreSQL + TimescaleDB for time-series metrics
//! - Forever retention policy (configurable)
//! - Efficient querying by user, tunnel, time range
//!
//! Schema designed for TimescaleDB hypertables for optimal
//! time-series performance.

use std::collections::VecDeque;
use std::sync::RwLock;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum traffic records to keep in memory (fallback mode)
const MAX_MEMORY_RECORDS: usize = 10_000;

/// Traffic record stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    /// Unique request ID
    pub id: String,
    /// User who owns the tunnel
    pub user_id: String,
    /// Tunnel ID
    pub tunnel_id: String,
    /// Timestamp of the request
    pub timestamp: DateTime<Utc>,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers (JSON encoded)
    pub headers: Vec<(String, String)>,
    /// Request body (optional, truncated for large bodies)
    pub body: Option<String>,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Length header
    pub content_length: Option<i64>,
    /// Response status code
    pub response_status: Option<i16>,
    /// Response headers
    pub response_headers: Option<Vec<(String, String)>>,
    /// Response body (optional, truncated)
    pub response_body: Option<String>,
    /// Request duration in milliseconds
    pub duration_ms: Option<i64>,
    /// Client IP address
    pub client_addr: Option<String>,
}

/// Query parameters for traffic search
#[derive(Debug, Clone, Default)]
pub struct TrafficQuery {
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by tunnel ID
    pub tunnel_id: Option<String>,
    /// Filter by HTTP method
    pub method: Option<String>,
    /// Filter by path prefix
    pub path_prefix: Option<String>,
    /// Filter by minimum status code
    pub status_min: Option<i16>,
    /// Filter by maximum status code
    pub status_max: Option<i16>,
    /// Start time (inclusive)
    pub start_time: Option<DateTime<Utc>>,
    /// End time (exclusive)
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Traffic metrics aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMetrics {
    /// Total number of requests
    pub total_requests: i64,
    /// Requests by status code range
    pub requests_2xx: i64,
    pub requests_3xx: i64,
    pub requests_4xx: i64,
    pub requests_5xx: i64,
    /// Average response time in milliseconds
    pub avg_duration_ms: f64,
    /// P50 response time
    pub p50_duration_ms: f64,
    /// P95 response time
    pub p95_duration_ms: f64,
    /// P99 response time
    pub p99_duration_ms: f64,
    /// Total bytes transferred (estimated from content_length)
    pub total_bytes: i64,
    /// Unique client IPs
    pub unique_clients: i64,
}

/// Traffic store trait for different backends
#[async_trait]
pub trait TrafficStore: Send + Sync {
    /// Insert a traffic record
    async fn insert(&self, record: TrafficRecord) -> Result<()>;
    
    /// Query traffic records
    async fn query(&self, query: TrafficQuery) -> Result<Vec<TrafficRecord>>;
    
    /// Get aggregated metrics
    async fn get_metrics(&self, query: TrafficQuery) -> Result<TrafficMetrics>;
    
    /// Delete old records (for retention policy)
    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64>;
}

/// In-memory traffic store (fallback when PostgreSQL is not available)
pub struct MemoryTrafficStore {
    records: RwLock<VecDeque<TrafficRecord>>,
}

impl MemoryTrafficStore {
    /// Create a new in-memory traffic store
    pub fn new() -> Self {
        Self {
            records: RwLock::new(VecDeque::with_capacity(MAX_MEMORY_RECORDS)),
        }
    }
}

impl Default for MemoryTrafficStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrafficStore for MemoryTrafficStore {
    async fn insert(&self, record: TrafficRecord) -> Result<()> {
        let mut records = self.records.write().unwrap();
        
        // Remove oldest records if we're at capacity
        while records.len() >= MAX_MEMORY_RECORDS {
            records.pop_front();
        }
        
        records.push_back(record);
        Ok(())
    }
    
    async fn query(&self, query: TrafficQuery) -> Result<Vec<TrafficRecord>> {
        let records = self.records.read().unwrap();
        
        let mut results: Vec<TrafficRecord> = records
            .iter()
            .filter(|r| {
                // Apply filters
                if let Some(ref user_id) = query.user_id {
                    if &r.user_id != user_id {
                        return false;
                    }
                }
                if let Some(ref tunnel_id) = query.tunnel_id {
                    if &r.tunnel_id != tunnel_id {
                        return false;
                    }
                }
                if let Some(ref method) = query.method {
                    if &r.method != method {
                        return false;
                    }
                }
                if let Some(ref prefix) = query.path_prefix {
                    if !r.path.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(min) = query.status_min {
                    if let Some(status) = r.response_status {
                        if status < min {
                            return false;
                        }
                    }
                }
                if let Some(max) = query.status_max {
                    if let Some(status) = r.response_status {
                        if status > max {
                            return false;
                        }
                    }
                }
                if let Some(start) = query.start_time {
                    if r.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = query.end_time {
                    if r.timestamp >= end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        
        // Sort by timestamp descending (most recent first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Apply pagination
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.unwrap_or(100) as usize;
        
        Ok(results.into_iter().skip(offset).take(limit).collect())
    }
    
    async fn get_metrics(&self, query: TrafficQuery) -> Result<TrafficMetrics> {
        let records = self.query(TrafficQuery { limit: Some(10000), ..query }).await?;
        
        let total = records.len() as i64;
        let mut requests_2xx = 0i64;
        let mut requests_3xx = 0i64;
        let mut requests_4xx = 0i64;
        let mut requests_5xx = 0i64;
        let mut durations: Vec<f64> = Vec::new();
        let mut total_bytes = 0i64;
        let mut clients: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        for record in &records {
            if let Some(status) = record.response_status {
                match status {
                    200..=299 => requests_2xx += 1,
                    300..=399 => requests_3xx += 1,
                    400..=499 => requests_4xx += 1,
                    500..=599 => requests_5xx += 1,
                    _ => {}
                }
            }
            
            if let Some(duration) = record.duration_ms {
                durations.push(duration as f64);
            }
            
            if let Some(len) = record.content_length {
                total_bytes += len;
            }
            
            if let Some(ref addr) = record.client_addr {
                clients.insert(addr.clone());
            }
        }
        
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let avg_duration = if durations.is_empty() {
            0.0
        } else {
            durations.iter().sum::<f64>() / durations.len() as f64
        };
        
        let percentile = |p: f64| -> f64 {
            if durations.is_empty() {
                return 0.0;
            }
            let idx = ((p / 100.0) * (durations.len() - 1) as f64).round() as usize;
            durations[idx.min(durations.len() - 1)]
        };
        
        Ok(TrafficMetrics {
            total_requests: total,
            requests_2xx,
            requests_3xx,
            requests_4xx,
            requests_5xx,
            avg_duration_ms: avg_duration,
            p50_duration_ms: percentile(50.0),
            p95_duration_ms: percentile(95.0),
            p99_duration_ms: percentile(99.0),
            total_bytes,
            unique_clients: clients.len() as i64,
        })
    }
    
    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64> {
        let mut records = self.records.write().unwrap();
        let before_len = records.len();
        records.retain(|r| r.timestamp >= timestamp);
        Ok((before_len - records.len()) as u64)
    }
}

// ============================================================================
// PostgreSQL + TimescaleDB Implementation
// ============================================================================

#[cfg(feature = "postgres")]
pub mod postgres {
    use super::*;
    use async_trait::async_trait;
    use sqlx::{PgPool, postgres::PgPoolOptions, Row};
    
    /// PostgreSQL traffic store with TimescaleDB support
    pub struct PgTrafficStore {
        pool: PgPool,
    }
    
    impl PgTrafficStore {
        /// Create a new PostgreSQL traffic store
        pub async fn new(database_url: &str) -> Result<Self> {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(database_url)
                .await?;
            
            Ok(Self { pool })
        }
        
        /// Initialize the database schema (run migrations)
        pub async fn init_schema(&self) -> Result<()> {
            // Create the traffic_logs table
            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    tunnel_id TEXT NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    headers JSONB,
                    body TEXT,
                    content_type TEXT,
                    content_length BIGINT,
                    response_status SMALLINT,
                    response_headers JSONB,
                    response_body TEXT,
                    duration_ms BIGINT,
                    client_addr TEXT,
                    PRIMARY KEY (id, timestamp)
                );
            "#)
            .execute(&self.pool)
            .await?;
            
            // Create indexes for common queries
            sqlx::query(r#"
                CREATE INDEX IF NOT EXISTS idx_traffic_user_time 
                ON traffic_logs (user_id, timestamp DESC);
            "#)
            .execute(&self.pool)
            .await?;
            
            sqlx::query(r#"
                CREATE INDEX IF NOT EXISTS idx_traffic_tunnel_time 
                ON traffic_logs (tunnel_id, timestamp DESC);
            "#)
            .execute(&self.pool)
            .await?;
            
            sqlx::query(r#"
                CREATE INDEX IF NOT EXISTS idx_traffic_status 
                ON traffic_logs (response_status);
            "#)
            .execute(&self.pool)
            .await?;
            
            // Try to convert to TimescaleDB hypertable (if extension is available)
            let result = sqlx::query(r#"
                SELECT create_hypertable('traffic_logs', 'timestamp', 
                    if_not_exists => TRUE,
                    migrate_data => TRUE
                );
            "#)
            .execute(&self.pool)
            .await;
            
            match result {
                Ok(_) => tracing::info!("TimescaleDB hypertable created/verified"),
                Err(e) => tracing::warn!("TimescaleDB not available, using standard PostgreSQL: {}", e),
            }
            
            Ok(())
        }
        
        /// Get the connection pool
        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }
    
    #[async_trait]
    impl TrafficStore for PgTrafficStore {
        async fn insert(&self, record: TrafficRecord) -> Result<()> {
            let headers_json = serde_json::to_value(&record.headers)?;
            let response_headers_json = record.response_headers
                .as_ref()
                .map(|h| serde_json::to_value(h))
                .transpose()?;
            
            sqlx::query(r#"
                INSERT INTO traffic_logs (
                    id, user_id, tunnel_id, timestamp, method, path,
                    headers, body, content_type, content_length,
                    response_status, response_headers, response_body,
                    duration_ms, client_addr
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (id, timestamp) DO NOTHING
            "#)
            .bind(&record.id)
            .bind(&record.user_id)
            .bind(&record.tunnel_id)
            .bind(record.timestamp)
            .bind(&record.method)
            .bind(&record.path)
            .bind(headers_json)
            .bind(&record.body)
            .bind(&record.content_type)
            .bind(record.content_length)
            .bind(record.response_status)
            .bind(response_headers_json)
            .bind(&record.response_body)
            .bind(record.duration_ms)
            .bind(&record.client_addr)
            .execute(&self.pool)
            .await?;
            
            Ok(())
        }
        
        async fn query(&self, query: TrafficQuery) -> Result<Vec<TrafficRecord>> {
            let mut sql = String::from(
                "SELECT id, user_id, tunnel_id, timestamp, method, path, \
                 headers, body, content_type, content_length, \
                 response_status, response_headers, response_body, \
                 duration_ms, client_addr \
                 FROM traffic_logs WHERE 1=1"
            );
            
            let mut params: Vec<String> = Vec::new();
            let mut param_idx = 1;
            
            if let Some(ref user_id) = query.user_id {
                sql.push_str(&format!(" AND user_id = ${}", param_idx));
                params.push(user_id.clone());
                param_idx += 1;
            }
            
            if let Some(ref tunnel_id) = query.tunnel_id {
                sql.push_str(&format!(" AND tunnel_id = ${}", param_idx));
                params.push(tunnel_id.clone());
                param_idx += 1;
            }
            
            if let Some(ref method) = query.method {
                sql.push_str(&format!(" AND method = ${}", param_idx));
                params.push(method.clone());
                param_idx += 1;
            }
            
            if let Some(ref prefix) = query.path_prefix {
                sql.push_str(&format!(" AND path LIKE ${}", param_idx));
                params.push(format!("{}%", prefix));
                param_idx += 1;
            }
            
            if query.status_min.is_some() || query.status_max.is_some() {
                if let Some(min) = query.status_min {
                    sql.push_str(&format!(" AND response_status >= ${}", param_idx));
                    params.push(min.to_string());
                    param_idx += 1;
                }
                if let Some(max) = query.status_max {
                    sql.push_str(&format!(" AND response_status <= ${}", param_idx));
                    params.push(max.to_string());
                    let _ = param_idx; // silence unused warning
                }
            }
            
            sql.push_str(" ORDER BY timestamp DESC");
            
            if let Some(limit) = query.limit {
                sql.push_str(&format!(" LIMIT {}", limit));
            } else {
                sql.push_str(" LIMIT 100");
            }
            
            if let Some(offset) = query.offset {
                sql.push_str(&format!(" OFFSET {}", offset));
            }
            
            // Build and execute dynamic query
            let mut query_builder = sqlx::query(&sql);
            for param in &params {
                query_builder = query_builder.bind(param);
            }
            
            let rows = query_builder.fetch_all(&self.pool).await?;
            
            let records: Vec<TrafficRecord> = rows
                .into_iter()
                .map(|row| {
                    let headers: serde_json::Value = row.get("headers");
                    let response_headers: Option<serde_json::Value> = row.get("response_headers");
                    
                    TrafficRecord {
                        id: row.get("id"),
                        user_id: row.get("user_id"),
                        tunnel_id: row.get("tunnel_id"),
                        timestamp: row.get("timestamp"),
                        method: row.get("method"),
                        path: row.get("path"),
                        headers: serde_json::from_value(headers).unwrap_or_default(),
                        body: row.get("body"),
                        content_type: row.get("content_type"),
                        content_length: row.get("content_length"),
                        response_status: row.get("response_status"),
                        response_headers: response_headers
                            .and_then(|v| serde_json::from_value(v).ok()),
                        response_body: row.get("response_body"),
                        duration_ms: row.get("duration_ms"),
                        client_addr: row.get("client_addr"),
                    }
                })
                .collect();
            
            Ok(records)
        }
        
        async fn get_metrics(&self, query: TrafficQuery) -> Result<TrafficMetrics> {
            let mut sql = String::from(r#"
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(*) FILTER (WHERE response_status >= 200 AND response_status < 300) as requests_2xx,
                    COUNT(*) FILTER (WHERE response_status >= 300 AND response_status < 400) as requests_3xx,
                    COUNT(*) FILTER (WHERE response_status >= 400 AND response_status < 500) as requests_4xx,
                    COUNT(*) FILTER (WHERE response_status >= 500 AND response_status < 600) as requests_5xx,
                    COALESCE(AVG(duration_ms), 0) as avg_duration_ms,
                    COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms), 0) as p50_duration_ms,
                    COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms), 0) as p95_duration_ms,
                    COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms), 0) as p99_duration_ms,
                    COALESCE(SUM(content_length), 0) as total_bytes,
                    COUNT(DISTINCT client_addr) as unique_clients
                FROM traffic_logs
                WHERE 1=1
            "#);
            
            if let Some(ref user_id) = query.user_id {
                sql.push_str(&format!(" AND user_id = '{}'", user_id.replace('\'', "''")));
            }
            if let Some(ref tunnel_id) = query.tunnel_id {
                sql.push_str(&format!(" AND tunnel_id = '{}'", tunnel_id.replace('\'', "''")));
            }
            if let Some(start) = query.start_time {
                sql.push_str(&format!(" AND timestamp >= '{}'", start.to_rfc3339()));
            }
            if let Some(end) = query.end_time {
                sql.push_str(&format!(" AND timestamp < '{}'", end.to_rfc3339()));
            }
            
            let row = sqlx::query(&sql)
                .fetch_one(&self.pool)
                .await?;
            
            Ok(TrafficMetrics {
                total_requests: row.get("total_requests"),
                requests_2xx: row.get("requests_2xx"),
                requests_3xx: row.get("requests_3xx"),
                requests_4xx: row.get("requests_4xx"),
                requests_5xx: row.get("requests_5xx"),
                avg_duration_ms: row.get("avg_duration_ms"),
                p50_duration_ms: row.get("p50_duration_ms"),
                p95_duration_ms: row.get("p95_duration_ms"),
                p99_duration_ms: row.get("p99_duration_ms"),
                total_bytes: row.get("total_bytes"),
                unique_clients: row.get("unique_clients"),
            })
        }
        
        async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64> {
            let result = sqlx::query("DELETE FROM traffic_logs WHERE timestamp < $1")
                .bind(timestamp)
                .execute(&self.pool)
                .await?;
            
            Ok(result.rows_affected())
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_store_insert_and_query() {
        let store = MemoryTrafficStore::new();
        
        let record = TrafficRecord {
            id: "test-1".to_string(),
            user_id: "user-1".to_string(),
            tunnel_id: "tunnel-1".to_string(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: None,
            content_type: Some("application/json".to_string()),
            content_length: Some(100),
            response_status: Some(200),
            response_headers: None,
            response_body: None,
            duration_ms: Some(50),
            client_addr: Some("192.168.1.1".to_string()),
        };
        
        store.insert(record).await.unwrap();
        
        let results = store.query(TrafficQuery {
            user_id: Some("user-1".to_string()),
            ..Default::default()
        }).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/api/test");
    }
    
    #[tokio::test]
    async fn test_memory_store_metrics() {
        let store = MemoryTrafficStore::new();
        
        for i in 0..10 {
            let record = TrafficRecord {
                id: format!("test-{}", i),
                user_id: "user-1".to_string(),
                tunnel_id: "tunnel-1".to_string(),
                timestamp: Utc::now(),
                method: "GET".to_string(),
                path: "/api/test".to_string(),
                headers: vec![],
                body: None,
                content_type: None,
                content_length: Some(100),
                response_status: Some(if i < 8 { 200 } else { 500 }),
                response_headers: None,
                response_body: None,
                duration_ms: Some(50 + i * 10),
                client_addr: Some(format!("192.168.1.{}", i)),
            };
            store.insert(record).await.unwrap();
        }
        
        let metrics = store.get_metrics(TrafficQuery::default()).await.unwrap();
        
        assert_eq!(metrics.total_requests, 10);
        assert_eq!(metrics.requests_2xx, 8);
        assert_eq!(metrics.requests_5xx, 2);
        assert_eq!(metrics.unique_clients, 10);
    }
    
    #[tokio::test]
    async fn test_memory_store_capacity_limit() {
        let store = MemoryTrafficStore::new();
        
        // Insert more than MAX_MEMORY_RECORDS
        for i in 0..(MAX_MEMORY_RECORDS + 100) {
            let record = TrafficRecord {
                id: format!("test-{}", i),
                user_id: "user-1".to_string(),
                tunnel_id: "tunnel-1".to_string(),
                timestamp: Utc::now(),
                method: "GET".to_string(),
                path: format!("/api/test/{}", i),
                headers: vec![],
                body: None,
                content_type: None,
                content_length: None,
                response_status: Some(200),
                response_headers: None,
                response_body: None,
                duration_ms: None,
                client_addr: None,
            };
            store.insert(record).await.unwrap();
        }
        
        let results = store.query(TrafficQuery {
            limit: Some(20000),
            ..Default::default()
        }).await.unwrap();
        
        // Should be capped at MAX_MEMORY_RECORDS
        assert!(results.len() <= MAX_MEMORY_RECORDS);
    }
}
