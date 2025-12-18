//! Traffic forwarding between tunnel and local service
//!
//! This module handles the bidirectional forwarding of data between
//! QUIC streams (from the edge) and local TCP connections.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use nlag_common::{
    protocol::{
        codec::quic::{read_message, write_message},
        message::{DataFrame, Message, StreamCloseMessage},
    },
    transport::quic::QuicConnection,
    types::TunnelId,
};

use crate::ui::{UiHandle, HttpRequest};
use super::DashboardSync;

/// Statistics for forwarding
#[derive(Debug, Default)]
pub struct ForwardStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub streams_opened: AtomicU64,
    pub streams_closed: AtomicU64,
}

/// Run the forwarding loop - accept incoming streams and forward to local service
pub async fn forward_loop(
    connection: QuicConnection,
    tunnel_id: TunnelId,
    local_addr: &str,
    dashboard_sync: Option<DashboardSync>,
) -> anyhow::Result<()> {
    let stats = Arc::new(ForwardStats::default());
    let local_addr = local_addr.to_string();
    let dashboard_sync = dashboard_sync.map(Arc::new);

    info!("Starting forwarding loop for tunnel {}", tunnel_id);

    loop {
        // Accept incoming stream from edge
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                if connection.is_closed() {
                    info!("Connection closed, stopping forward loop");
                    break;
                }
                warn!("Failed to accept stream: {}", e);
                continue;
            }
        };

        let local_addr = local_addr.clone();
        let stats = stats.clone();
        let dashboard_sync = dashboard_sync.clone();

        // Spawn task to handle this stream
        tokio::spawn(async move {
            if let Err(e) = handle_stream_with_dashboard(send, recv, tunnel_id, &local_addr, stats, dashboard_sync).await {
                debug!("Stream handling error: {}", e);
            }
        });
    }

    Ok(())
}

/// Run the forwarding loop with UI updates
pub async fn forward_loop_with_ui(
    connection: QuicConnection,
    tunnel_id: TunnelId,
    local_addr: &str,
    ui_handle: UiHandle,
) -> anyhow::Result<()> {
    let stats = Arc::new(ForwardStats::default());
    let local_addr = local_addr.to_string();

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(_e) => {
                if connection.is_closed() {
                    break;
                }
                continue;
            }
        };

        let local_addr = local_addr.clone();
        let stats = stats.clone();
        let ui_handle = ui_handle.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_stream_with_ui(send, recv, tunnel_id, &local_addr, stats, ui_handle).await {
                debug!("Stream handling error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle stream with UI updates for HTTP request logging
async fn handle_stream_with_ui(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    tunnel_id: TunnelId,
    local_addr: &str,
    stats: Arc<ForwardStats>,
    ui_handle: UiHandle,
) -> anyhow::Result<()> {
    let start_time = Instant::now();
    
    // Read stream open message
    let msg = read_message(&mut quic_recv).await?;

    let (stream_id, metadata) = match msg {
        Message::StreamOpen(open) => {
            stats.streams_opened.fetch_add(1, Ordering::Relaxed);
            (open.stream_id, open.metadata)
        }
        _other => {
            return Err(anyhow::anyhow!("Unexpected message type"));
        }
    };

    // Extract HTTP info from metadata for UI
    let (method, path) = metadata
        .as_ref()
        .map(|m| {
            (
                m.method.clone().unwrap_or_else(|| "???".to_string()),
                m.path.clone().unwrap_or_else(|| "/".to_string()),
            )
        })
        .unwrap_or_else(|| ("TCP".to_string(), format!(":{}", local_addr.split(':').next_back().unwrap_or("0"))));

    // Create initial request entry (status 0 = in progress)
    let mut request = HttpRequest::new(&method, &path);

    // Connect to local service
    let mut local = match TcpStream::connect(local_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            request = request.with_status(502);
            ui_handle.http_request(request);

            let close = Message::StreamClose(StreamCloseMessage {
                stream_id,
                graceful: false,
                error: Some(format!("Local service unavailable: {}", e)),
            });
            let _ = write_message(&mut quic_send, &close).await;

            stats.streams_closed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Local connection failed"));
        }
    };

    let (mut local_read, mut local_write) = local.split();

    let stats_clone = stats.clone();
    let mut captured_status = 200u16; // Default success

    // Forward: edge -> local
    let edge_to_local = async {
        let mut total_bytes = 0u64;

        loop {
            let msg = match read_message(&mut quic_recv).await {
                Ok(msg) => msg,
                Err(_) => break,
            };

            match msg {
                Message::Data(frame) => {
                    if frame.stream_id != stream_id {
                        continue;
                    }
                    if (local_write.write_all(&frame.payload).await).is_err() {
                        break;
                    }
                    total_bytes += frame.payload.len() as u64;
                }
                Message::StreamClose(_) => break,
                _ => {}
            }
        }

        stats_clone.bytes_in.fetch_add(total_bytes, Ordering::Relaxed);
        let _ = local_write.shutdown().await;
    };

    // Forward: local -> edge
    let local_to_edge = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total_bytes = 0u64;
        let mut first_read = true;

        loop {
            let n = match local_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            // Try to extract HTTP status from first response chunk
            if first_read && method != "TCP" {
                first_read = false;
                if let Some(status) = extract_http_status(&buf[..n]) {
                    captured_status = status;
                }
            }

            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if write_message(&mut quic_send, &frame).await.is_err() {
                break;
            }

            total_bytes += n as u64;
        }

        stats.bytes_out.fetch_add(total_bytes, Ordering::Relaxed);

        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut quic_send, &close).await;
        
        captured_status
    };

    let (_, status) = tokio::join!(edge_to_local, local_to_edge);

    // Send final request with status to UI
    let duration_ms = start_time.elapsed().as_millis() as u64;
    request = request.with_status(status).with_duration(duration_ms);
    ui_handle.http_request(request);

    stats.streams_closed.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Try to extract HTTP status code from response bytes
fn extract_http_status(data: &[u8]) -> Option<u16> {
    // Look for "HTTP/1.x NNN" pattern
    if data.len() < 12 {
        return None;
    }
    
    let s = std::str::from_utf8(&data[..std::cmp::min(data.len(), 20)]).ok()?;
    
    if s.starts_with("HTTP/") {
        // Find the status code after the space
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    
    None
}

/// Run the multi-tunnel forwarding loop - handles multiple tunnels on one connection
pub async fn multi_forward_loop(
    connection: QuicConnection,
    tunnel_mappings: Vec<(TunnelId, String)>,
) -> anyhow::Result<()> {
    let stats = Arc::new(ForwardStats::default());
    
    // Create a map from tunnel_id to local_addr
    let tunnel_map: Arc<HashMap<TunnelId, String>> = Arc::new(
        tunnel_mappings.into_iter().collect()
    );

    info!("Starting multi-forward loop for {} tunnels", tunnel_map.len());

    loop {
        // Accept incoming stream from edge
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                if connection.is_closed() {
                    info!("Connection closed, stopping multi-forward loop");
                    break;
                }
                warn!("Failed to accept stream: {}", e);
                continue;
            }
        };

        let tunnel_map = tunnel_map.clone();
        let stats = stats.clone();

        // Spawn task to handle this stream
        tokio::spawn(async move {
            if let Err(e) = handle_multi_stream(send, recv, tunnel_map, stats).await {
                debug!("Multi-stream handling error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle a stream for multi-tunnel - determines which local service to connect to
async fn handle_multi_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    tunnel_map: Arc<HashMap<TunnelId, String>>,
    stats: Arc<ForwardStats>,
) -> anyhow::Result<()> {
    // Read the stream open message to get stream info
    let msg = read_message(&mut quic_recv).await?;

    let (stream_id, tunnel_id, _metadata) = match msg {
        Message::StreamOpen(open) => {
            debug!(
                "Stream {} opened from {} for tunnel {}",
                open.stream_id, open.source_addr, open.tunnel_id
            );
            stats.streams_opened.fetch_add(1, Ordering::Relaxed);
            (open.stream_id, open.tunnel_id, open.metadata)
        }
        other => {
            warn!("Expected StreamOpen, got {:?}", other.message_type());
            return Err(anyhow::anyhow!("Unexpected message type"));
        }
    };

    // Look up the local address for this tunnel
    let local_addr = tunnel_map.get(&tunnel_id).ok_or_else(|| {
        anyhow::anyhow!("Unknown tunnel ID: {}", tunnel_id)
    })?;

    // Connect to local service
    let mut local = match TcpStream::connect(local_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to local service at {}: {}", local_addr, e);

            let close = Message::StreamClose(StreamCloseMessage {
                stream_id,
                graceful: false,
                error: Some(format!("Local service unavailable: {}", e)),
            });
            let _ = write_message(&mut quic_send, &close).await;

            stats.streams_closed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Local connection failed"));
        }
    };

    debug!("Connected to local service at {} for tunnel {}", local_addr, tunnel_id);

    // Split streams for bidirectional forwarding
    let (mut local_read, mut local_write) = local.split();

    // Forward: edge -> local
    let edge_to_local = async {
        let mut total_bytes = 0u64;

        loop {
            let msg = match read_message(&mut quic_recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("Edge read ended: {}", e);
                    break;
                }
            };

            match msg {
                Message::Data(frame) => {
                    if frame.stream_id != stream_id {
                        warn!("Received data for wrong stream");
                        continue;
                    }

                    if let Err(e) = local_write.write_all(&frame.payload).await {
                        debug!("Local write failed: {}", e);
                        break;
                    }

                    total_bytes += frame.payload.len() as u64;
                }
                Message::StreamClose(close) => {
                    debug!("Stream {} closed by edge: {:?}", stream_id, close.error);
                    break;
                }
                other => {
                    debug!("Unexpected message: {:?}", other.message_type());
                }
            }
        }

        stats.bytes_in.fetch_add(total_bytes, Ordering::Relaxed);
        let _ = local_write.shutdown().await;
    };

    // Forward: local -> edge
    let local_to_edge = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total_bytes = 0u64;

        loop {
            let n = match local_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("Local service closed connection");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    debug!("Local read failed: {}", e);
                    break;
                }
            };

            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if let Err(e) = write_message(&mut quic_send, &frame).await {
                debug!("Edge write failed: {}", e);
                break;
            }

            total_bytes += n as u64;
        }

        stats.bytes_out.fetch_add(total_bytes, Ordering::Relaxed);

        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut quic_send, &close).await;
    };

    tokio::join!(edge_to_local, local_to_edge);

    stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    debug!("Stream {} closed", stream_id);

    Ok(())
}

/// Handle a single stream - forward traffic to/from local service
async fn handle_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    tunnel_id: TunnelId,
    local_addr: &str,
    stats: Arc<ForwardStats>,
) -> anyhow::Result<()> {
    // Read the stream open message to get stream info
    let msg = read_message(&mut quic_recv).await?;

    let (stream_id, _metadata) = match msg {
        Message::StreamOpen(open) => {
            debug!(
                "Stream {} opened from {}",
                open.stream_id, open.source_addr
            );
            stats.streams_opened.fetch_add(1, Ordering::Relaxed);
            (open.stream_id, open.metadata)
        }
        other => {
            warn!("Expected StreamOpen, got {:?}", other.message_type());
            return Err(anyhow::anyhow!("Unexpected message type"));
        }
    };

    // Connect to local service
    let mut local = match TcpStream::connect(local_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to local service at {}: {}", local_addr, e);

            // Send error back to edge
            let close = Message::StreamClose(StreamCloseMessage {
                stream_id,
                graceful: false,
                error: Some(format!("Local service unavailable: {}", e)),
            });
            let _ = write_message(&mut quic_send, &close).await;

            stats.streams_closed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Local connection failed"));
        }
    };

    debug!("Connected to local service at {}", local_addr);

    // Split streams for bidirectional forwarding
    let (mut local_read, mut local_write) = local.split();

    // Forward: edge -> local
    let edge_to_local = async {
        #[allow(unused_variables)]
        let buf = vec![0u8; 64 * 1024]; // 64KB buffer (reserved for future flow control)
        let mut total_bytes = 0u64;

        loop {
            // Read message from edge
            let msg = match read_message(&mut quic_recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("Edge read ended: {}", e);
                    break;
                }
            };

            match msg {
                Message::Data(frame) => {
                    if frame.stream_id != stream_id {
                        warn!("Received data for wrong stream");
                        continue;
                    }

                    // Write to local service
                    if let Err(e) = local_write.write_all(&frame.payload).await {
                        debug!("Local write failed: {}", e);
                        break;
                    }

                    total_bytes += frame.payload.len() as u64;
                }
                Message::StreamClose(close) => {
                    debug!("Stream {} closed by edge: {:?}", stream_id, close.error);
                    break;
                }
                other => {
                    debug!("Unexpected message: {:?}", other.message_type());
                }
            }
        }

        stats.bytes_in.fetch_add(total_bytes, Ordering::Relaxed);
        let _ = local_write.shutdown().await;
    };

    // Forward: local -> edge
    let local_to_edge = async {
        let mut buf = vec![0u8; 64 * 1024]; // 64KB buffer
        let mut total_bytes = 0u64;

        loop {
            // Read from local service
            let n = match local_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("Local service closed connection");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    debug!("Local read failed: {}", e);
                    break;
                }
            };

            // Send to edge
            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if let Err(e) = write_message(&mut quic_send, &frame).await {
                debug!("Edge write failed: {}", e);
                break;
            }

            total_bytes += n as u64;
        }

        stats.bytes_out.fetch_add(total_bytes, Ordering::Relaxed);

        // Send close message
        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut quic_send, &close).await;
    };

    // Run both directions concurrently
    tokio::join!(edge_to_local, local_to_edge);

    stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    debug!("Stream {} closed", stream_id);

    Ok(())
}

/// Handle a single stream with dashboard sync - forward traffic and sync stats
async fn handle_stream_with_dashboard(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    tunnel_id: TunnelId,
    local_addr: &str,
    stats: Arc<ForwardStats>,
    dashboard_sync: Option<Arc<DashboardSync>>,
) -> anyhow::Result<()> {
    let start_time = Instant::now();
    
    // Read the stream open message to get stream info
    let msg = read_message(&mut quic_recv).await?;

    let (stream_id, metadata) = match msg {
        Message::StreamOpen(open) => {
            debug!(
                "Stream {} opened from {}",
                open.stream_id, open.source_addr
            );
            stats.streams_opened.fetch_add(1, Ordering::Relaxed);
            (open.stream_id, open.metadata)
        }
        other => {
            warn!("Expected StreamOpen, got {:?}", other.message_type());
            return Err(anyhow::anyhow!("Unexpected message type"));
        }
    };

    // Connect to local service
    let mut local = match TcpStream::connect(local_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to local service at {}: {}", local_addr, e);

            // Sync error to dashboard
            if let Some(sync) = dashboard_sync {
                let duration = start_time.elapsed().as_millis() as u64;
                sync.sync_request(metadata.clone(), 502, duration).await;
            }

            let close = Message::StreamClose(StreamCloseMessage {
                stream_id,
                graceful: false,
                error: Some(format!("Local service unavailable: {}", e)),
            });
            let _ = write_message(&mut quic_send, &close).await;

            stats.streams_closed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Local connection failed"));
        }
    };

    debug!("Connected to local service at {}", local_addr);

    let (mut local_read, mut local_write) = local.split();

    let stats_clone = stats.clone();
    let mut captured_status = 200u16;

    // Forward: edge -> local
    let edge_to_local = async {
        let mut total_bytes = 0u64;

        loop {
            let msg = match read_message(&mut quic_recv).await {
                Ok(msg) => msg,
                Err(_) => break,
            };

            match msg {
                Message::Data(frame) => {
                    if frame.stream_id != stream_id {
                        continue;
                    }
                    if local_write.write_all(&frame.payload).await.is_err() {
                        break;
                    }
                    total_bytes += frame.payload.len() as u64;
                }
                Message::StreamClose(_) => break,
                _ => {}
            }
        }

        stats_clone.bytes_in.fetch_add(total_bytes, Ordering::Relaxed);
        let _ = local_write.shutdown().await;
    };

    // Forward: local -> edge
    let local_to_edge = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total_bytes = 0u64;
        let mut first_read = true;

        loop {
            let n = match local_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            // Try to extract HTTP status from first response chunk
            if first_read {
                first_read = false;
                if let Some(status) = extract_http_status(&buf[..n]) {
                    captured_status = status;
                }
            }

            let frame = Message::Data(DataFrame {
                tunnel_id,
                stream_id,
                payload: buf[..n].to_vec(),
            });

            if write_message(&mut quic_send, &frame).await.is_err() {
                break;
            }

            total_bytes += n as u64;
        }

        stats.bytes_out.fetch_add(total_bytes, Ordering::Relaxed);

        let close = Message::StreamClose(StreamCloseMessage {
            stream_id,
            graceful: true,
            error: None,
        });
        let _ = write_message(&mut quic_send, &close).await;
        
        captured_status
    };

    let (_, status) = tokio::join!(edge_to_local, local_to_edge);

    // Sync to dashboard
    if let Some(sync) = dashboard_sync {
        let duration = start_time.elapsed().as_millis() as u64;
        sync.sync_request(metadata, status, duration).await;
    }

    stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    debug!("Stream {} closed", stream_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_stats() {
        let stats = ForwardStats::default();
        stats.bytes_in.fetch_add(100, Ordering::Relaxed);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 100);
    }
}
