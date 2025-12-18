//! Prometheus metrics for NLAG Edge
//!
//! Exposes metrics at /metrics endpoint for Prometheus scraping.

#![allow(dead_code)]

use std::net::SocketAddr;

use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use bytes::Bytes;
use prometheus::{
    Counter, CounterVec, Gauge, Histogram, HistogramVec,
    Encoder, TextEncoder,
    register_counter, register_counter_vec, register_gauge,
    register_histogram, register_histogram_vec,
};
use lazy_static::lazy_static;
use tokio::net::TcpListener;
use tracing::{error, info};

lazy_static! {
    // Connection metrics
    pub static ref AGENTS_CONNECTED: Gauge = register_gauge!(
        "nlag_agents_connected",
        "Number of currently connected agents"
    ).unwrap();
    
    pub static ref AGENTS_TOTAL: Counter = register_counter!(
        "nlag_agents_total",
        "Total number of agent connections"
    ).unwrap();
    
    pub static ref TUNNELS_ACTIVE: Gauge = register_gauge!(
        "nlag_tunnels_active",
        "Number of currently active tunnels"
    ).unwrap();
    
    pub static ref TUNNELS_TOTAL: Counter = register_counter!(
        "nlag_tunnels_total",
        "Total number of tunnels created"
    ).unwrap();
    
    // Traffic metrics
    pub static ref BYTES_IN: Counter = register_counter!(
        "nlag_bytes_in_total",
        "Total bytes received from public connections"
    ).unwrap();
    
    pub static ref BYTES_OUT: Counter = register_counter!(
        "nlag_bytes_out_total",
        "Total bytes sent to public connections"
    ).unwrap();
    
    pub static ref REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "nlag_requests_total",
        "Total HTTP requests by method and status",
        &["method", "status"]
    ).unwrap();
    
    pub static ref CONNECTIONS_ACTIVE: Gauge = register_gauge!(
        "nlag_connections_active",
        "Number of active public connections"
    ).unwrap();
    
    pub static ref CONNECTIONS_TOTAL: Counter = register_counter!(
        "nlag_connections_total",
        "Total public connections"
    ).unwrap();
    
    // Latency metrics
    pub static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "nlag_request_duration_seconds",
        "Request latency in seconds",
        &["protocol"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();
    
    pub static ref TUNNEL_SETUP_DURATION: Histogram = register_histogram!(
        "nlag_tunnel_setup_seconds",
        "Tunnel setup latency in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).unwrap();
    
    // Rate limiting metrics
    pub static ref RATE_LIMIT_HITS: CounterVec = register_counter_vec!(
        "nlag_rate_limit_hits_total",
        "Rate limit hits by tunnel",
        &["subdomain"]
    ).unwrap();
    
    // Error metrics
    pub static ref ERRORS_TOTAL: CounterVec = register_counter_vec!(
        "nlag_errors_total",
        "Total errors by type",
        &["type"]
    ).unwrap();
}

/// Start the metrics HTTP server
pub async fn start_metrics_server(bind_addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("Metrics server listening on {}", bind_addr);
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_metrics))
                .await
            {
                error!("Metrics server error: {}", e);
            }
        });
    }
}

/// Handle metrics endpoint requests
async fn handle_metrics(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    
    match path {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();
            
            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                error!("Failed to encode metrics: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Failed to encode metrics")))
                    .unwrap());
            }
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap())
        }
        "/health" => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        }
        "/ready" => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap())
        }
    }
}

/// Record an agent connection
pub fn record_agent_connect() {
    AGENTS_CONNECTED.inc();
    AGENTS_TOTAL.inc();
}

/// Record an agent disconnection
pub fn record_agent_disconnect() {
    AGENTS_CONNECTED.dec();
}

/// Record a tunnel creation
pub fn record_tunnel_created() {
    TUNNELS_ACTIVE.inc();
    TUNNELS_TOTAL.inc();
}

/// Record a tunnel closure
pub fn record_tunnel_closed() {
    TUNNELS_ACTIVE.dec();
}

/// Record bytes transferred
pub fn record_bytes(bytes_in: u64, bytes_out: u64) {
    BYTES_IN.inc_by(bytes_in as f64);
    BYTES_OUT.inc_by(bytes_out as f64);
}

/// Record a public connection
pub fn record_connection_start() {
    CONNECTIONS_ACTIVE.inc();
    CONNECTIONS_TOTAL.inc();
}

/// Record a connection end
pub fn record_connection_end() {
    CONNECTIONS_ACTIVE.dec();
}

/// Record an HTTP request
pub fn record_request(method: &str, status: u16) {
    REQUESTS_TOTAL.with_label_values(&[method, &status.to_string()]).inc();
}

/// Record request latency
pub fn record_request_latency(protocol: &str, duration_secs: f64) {
    REQUEST_DURATION.with_label_values(&[protocol]).observe(duration_secs);
}

/// Record a rate limit hit
pub fn record_rate_limit(subdomain: &str) {
    RATE_LIMIT_HITS.with_label_values(&[subdomain]).inc();
}

/// Record an error
pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_recording() {
        record_agent_connect();
        assert!(AGENTS_CONNECTED.get() >= 1.0);
        
        record_tunnel_created();
        assert!(TUNNELS_ACTIVE.get() >= 1.0);
    }
}
