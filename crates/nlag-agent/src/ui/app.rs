//! Application state for the TUI

#![allow(dead_code)]

use std::collections::VecDeque;
use chrono::Local;

use super::UiEvent;
use super::widgets::{WidgetConfig, RateTracker};

/// Maximum number of requests to keep in history
const MAX_REQUESTS: usize = 100;

/// Tunnel information
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub public_url: String,
    pub protocol: String,
    pub subdomain: String,
}

/// HTTP request entry for display
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
            method: method.into(),
            path: path.into(),
            status: 0,
            duration_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub open_connections: u64,
    pub rate_1m: f64,
    pub rate_5m: f64,
    pub p50_latency: f64,
    pub p90_latency: f64,
}

/// Application state
pub struct AppState {
    pub is_connected: bool,
    pub session_id: Option<String>,
    pub local_addr: String,
    pub edge_addr: String,
    pub latency_ms: u64,
    pub tunnel_info: Option<TunnelInfo>,
    pub stats: ConnectionStats,
    pub requests: VecDeque<HttpRequest>,
    pub scroll_offset: usize,
    pub errors: VecDeque<String>,
    /// Widget configuration from CLI flags
    pub widget_config: WidgetConfig,
    /// Rate tracker for sparkline
    pub rate_tracker: RateTracker,
}

impl AppState {
    pub fn new(local_addr: String, edge_addr: String) -> Self {
        Self {
            is_connected: false,
            session_id: None,
            local_addr,
            edge_addr,
            latency_ms: 0,
            tunnel_info: None,
            stats: ConnectionStats::default(),
            requests: VecDeque::with_capacity(MAX_REQUESTS),
            scroll_offset: 0,
            errors: VecDeque::new(),
            widget_config: WidgetConfig::default(),
            rate_tracker: RateTracker::default(),
        }
    }
    
    pub fn with_widget_config(mut self, config: WidgetConfig) -> Self {
        self.widget_config = config;
        self
    }

    pub fn handle_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::TunnelOpened(info) => {
                self.tunnel_info = Some(info);
            }
            UiEvent::Connected { session_id, latency_ms } => {
                self.is_connected = true;
                self.session_id = Some(session_id);
                self.latency_ms = latency_ms;
            }
            UiEvent::HttpRequest(req) => {
                self.add_request(req);
            }
            UiEvent::StatsUpdate(stats) => {
                self.stats = stats;
            }
            UiEvent::Error(msg) => {
                self.errors.push_back(msg);
                if self.errors.len() > 10 {
                    self.errors.pop_front();
                }
            }
            UiEvent::Disconnected => {
                self.is_connected = false;
            }
            UiEvent::LatencyUpdate(latency_ms) => {
                self.latency_ms = latency_ms;
            }
        }
    }

    pub fn add_request(&mut self, request: HttpRequest) {
        if self.requests.len() >= MAX_REQUESTS {
            self.requests.pop_front();
        }
        self.requests.push_back(request);
        
        // Update stats
        self.stats.total_connections += 1;
        
        // Track rate for sparkline
        self.rate_tracker.record();
    }
    
    /// Tick the rate tracker (call every second)
    pub fn tick_rate(&mut self) {
        self.rate_tracker.tick();
    }

    pub fn clear_requests(&mut self) {
        self.requests.clear();
        self.scroll_offset = 0;
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        if self.scroll_offset < self.requests.len().saturating_sub(1) {
            self.scroll_offset += 1;
        }
    }
}
