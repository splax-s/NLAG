//! Custom widgets for NLAG TUI
//!
//! Optional widgets that can be enabled via CLI flags:
//! - Sparkline: Request rate visualization
//! - Latency gauge: Visual latency indicator
//! - Status badges: Styled HTTP status indicators
//! - Request details: Expanded request view

#![allow(dead_code)]

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

/// Configuration for which widgets to display
#[derive(Debug, Clone, Default)]
pub struct WidgetConfig {
    /// Show sparkline for request rate
    pub sparkline: bool,
    /// Show latency gauge
    pub latency_gauge: bool,
    /// Show detailed request cards
    pub request_details: bool,
    /// Show connection health indicator
    pub health_indicator: bool,
}

impl WidgetConfig {
    pub fn any_enabled(&self) -> bool {
        self.sparkline || self.latency_gauge || self.request_details || self.health_indicator
    }
}

// ============================================================================
// Sparkline Widget - Shows request rate over time
// ============================================================================

/// A mini sparkline graph showing values over time
pub struct Sparkline<'a> {
    /// Data points to display (most recent last)
    data: &'a [u64],
    /// Maximum value for scaling (auto if None)
    max: Option<u64>,
    /// Style for the sparkline
    style: Style,
    /// Character set for drawing
    bar_set: BarSet,
}

#[derive(Clone, Copy)]
pub struct BarSet {
    pub empty: char,
    pub one_eighth: char,
    pub one_quarter: char,
    pub three_eighths: char,
    pub half: char,
    pub five_eighths: char,
    pub three_quarters: char,
    pub seven_eighths: char,
    pub full: char,
}

impl Default for BarSet {
    fn default() -> Self {
        Self {
            empty: ' ',
            one_eighth: '▁',
            one_quarter: '▂',
            three_eighths: '▃',
            half: '▄',
            five_eighths: '▅',
            three_quarters: '▆',
            seven_eighths: '▇',
            full: '█',
        }
    }
}

impl<'a> Sparkline<'a> {
    pub fn new(data: &'a [u64]) -> Self {
        Self {
            data,
            max: None,
            style: Style::default().fg(Color::Cyan),
            bar_set: BarSet::default(),
        }
    }

    #[allow(dead_code)]
    pub fn max(mut self, max: u64) -> Self {
        self.max = Some(max);
        self
    }

    #[allow(dead_code)]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl Widget for Sparkline<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 || self.data.is_empty() {
            return;
        }

        let max = self.max.unwrap_or_else(|| *self.data.iter().max().unwrap_or(&1));
        let max = max.max(1); // Avoid division by zero

        // Take the last N data points that fit in the area
        let data_len = self.data.len().min(area.width as usize);
        let data = &self.data[self.data.len().saturating_sub(data_len)..];

        for (i, &value) in data.iter().enumerate() {
            let x = area.x + i as u16;
            if x >= area.x + area.width {
                break;
            }

            // Calculate bar height (0-8 scale for Unicode blocks)
            let ratio = (value as f64 / max as f64).min(1.0);
            let bar_char = match (ratio * 8.0).round() as u8 {
                0 => self.bar_set.empty,
                1 => self.bar_set.one_eighth,
                2 => self.bar_set.one_quarter,
                3 => self.bar_set.three_eighths,
                4 => self.bar_set.half,
                5 => self.bar_set.five_eighths,
                6 => self.bar_set.three_quarters,
                7 => self.bar_set.seven_eighths,
                _ => self.bar_set.full,
            };

            buf.set_string(x, area.y, bar_char.to_string(), self.style);
        }
    }
}

// ============================================================================
// Gauge Widget - Visual progress/level indicator
// ============================================================================

/// A horizontal gauge for showing values like latency
pub struct Gauge {
    /// Current value
    value: u64,
    /// Maximum value (100% of gauge)
    max: u64,
    /// Label to display
    label: String,
    /// Color thresholds: (threshold, color)
    thresholds: Vec<(u64, Color)>,
}

impl Gauge {
    pub fn new(value: u64, max: u64) -> Self {
        Self {
            value,
            max,
            label: String::new(),
            thresholds: vec![
                (30, Color::Green),   // Good
                (100, Color::Yellow), // Warning
                (u64::MAX, Color::Red), // Critical
            ],
        }
    }

    #[allow(dead_code)]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    #[allow(dead_code)]
    pub fn thresholds(mut self, thresholds: Vec<(u64, Color)>) -> Self {
        self.thresholds = thresholds;
        self
    }

    fn get_color(&self) -> Color {
        for (threshold, color) in &self.thresholds {
            if self.value <= *threshold {
                return *color;
            }
        }
        Color::White
    }
}

impl Widget for Gauge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 5 || area.height == 0 {
            return;
        }

        let color = self.get_color();
        let ratio = (self.value as f64 / self.max as f64).min(1.0);
        let filled_width = ((area.width as f64 - 2.0) * ratio) as u16;

        // Draw frame
        buf.set_string(area.x, area.y, "[", Style::default().fg(Color::DarkGray));
        buf.set_string(area.x + area.width - 1, area.y, "]", Style::default().fg(Color::DarkGray));

        // Draw filled portion
        for i in 0..filled_width {
            buf.set_string(area.x + 1 + i, area.y, "█", Style::default().fg(color));
        }

        // Draw empty portion
        for i in filled_width..(area.width - 2) {
            buf.set_string(area.x + 1 + i, area.y, "░", Style::default().fg(Color::DarkGray));
        }

        // Overlay label if it fits
        if !self.label.is_empty() && area.width > self.label.len() as u16 + 4 {
            let label_x = area.x + (area.width - self.label.len() as u16) / 2;
            buf.set_string(label_x, area.y, &self.label, Style::default().fg(Color::White));
        }
    }
}

// ============================================================================
// StatusBadge Widget - Colored HTTP status indicator
// ============================================================================

/// A styled badge showing HTTP status codes
pub struct StatusBadge {
    status: u16,
    badge_style: BadgeStyle,
}

#[derive(Clone, Copy, Default)]
pub enum BadgeStyle {
    #[default]
    Compact,    // "200"
    Short,      // "2XX"
    Full,       // "200 OK"
    Pill,       // "[200]"
}

impl StatusBadge {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            badge_style: BadgeStyle::Compact,
        }
    }

    #[allow(dead_code)]
    pub fn badge_style(mut self, style: BadgeStyle) -> Self {
        self.badge_style = style;
        self
    }

    pub fn color(&self) -> Color {
        match self.status / 100 {
            1 => Color::Cyan,    // Informational
            2 => Color::Green,   // Success
            3 => Color::Yellow,  // Redirect
            4 => Color::Red,     // Client Error
            5 => Color::Magenta, // Server Error
            _ => Color::White,
        }
    }

    #[allow(dead_code)]
    pub fn text(&self) -> String {
        match self.badge_style {
            BadgeStyle::Compact => format!("{}", self.status),
            BadgeStyle::Short => format!("{}XX", self.status / 100),
            BadgeStyle::Full => format!("{} {}", self.status, status_reason(self.status)),
            BadgeStyle::Pill => format!("[{}]", self.status),
        }
    }
}

impl Widget for StatusBadge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }

        let text = self.text();
        let color = self.color();
        buf.set_string(area.x, area.y, &text, Style::default().fg(color));
    }
}

// ============================================================================
// HealthIndicator Widget - Connection health display
// ============================================================================

/// Shows connection health with animated indicator
pub struct HealthIndicator {
    is_connected: bool,
    latency_ms: u64,
    packet_loss: f64, // 0.0 - 1.0
}

impl HealthIndicator {
    pub fn new(is_connected: bool, latency_ms: u64) -> Self {
        Self {
            is_connected,
            latency_ms,
            packet_loss: 0.0,
        }
    }

    #[allow(dead_code)]
    pub fn packet_loss(mut self, loss: f64) -> Self {
        self.packet_loss = loss;
        self
    }

    fn health_level(&self) -> (&str, Color) {
        if !self.is_connected {
            return ("●", Color::Red);
        }

        if self.packet_loss > 0.1 {
            return ("◐", Color::Yellow);
        }

        match self.latency_ms {
            0..=50 => ("●", Color::Green),
            51..=150 => ("●", Color::Yellow),
            _ => ("●", Color::Red),
        }
    }
}

impl Widget for HealthIndicator {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }

        let (symbol, color) = self.health_level();
        buf.set_string(area.x, area.y, symbol, Style::default().fg(color));
    }
}

// ============================================================================
// RequestCard Widget - Detailed request display
// ============================================================================

/// A card showing detailed request information
pub struct RequestCard<'a> {
    method: &'a str,
    path: &'a str,
    status: u16,
    duration_ms: u64,
    size_bytes: Option<u64>,
}

impl<'a> RequestCard<'a> {
    pub fn new(method: &'a str, path: &'a str, status: u16, duration_ms: u64) -> Self {
        Self {
            method,
            path,
            status,
            duration_ms,
            size_bytes: None,
        }
    }

    #[allow(dead_code)]
    pub fn size(mut self, bytes: u64) -> Self {
        self.size_bytes = Some(bytes);
        self
    }

    fn method_color(&self) -> Color {
        match self.method {
            "GET" => Color::Green,
            "POST" => Color::Blue,
            "PUT" => Color::Yellow,
            "DELETE" => Color::Red,
            "PATCH" => Color::Magenta,
            _ => Color::White,
        }
    }

    fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{}B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1}KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

impl Widget for RequestCard<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 20 || area.height == 0 {
            return;
        }

        let method_style = Style::default().fg(self.method_color());
        let status_color = StatusBadge::new(self.status).color();

        // Method
        let method_width = self.method.len().min(7);
        buf.set_string(area.x, area.y, &self.method[..method_width], method_style);

        // Path (truncated)
        let path_start = area.x + 8;
        let path_max_len = (area.width as usize).saturating_sub(25);
        let path = if self.path.len() > path_max_len {
            format!("{}…", &self.path[..path_max_len.saturating_sub(1)])
        } else {
            self.path.to_string()
        };
        buf.set_string(path_start, area.y, &path, Style::default().fg(Color::White));

        // Status
        let status_x = area.x + area.width - 12;
        buf.set_string(
            status_x,
            area.y,
            format!("{}", self.status),
            Style::default().fg(status_color),
        );

        // Duration
        let duration_x = area.x + area.width - 7;
        let duration_str = if self.duration_ms < 1000 {
            format!("{:>4}ms", self.duration_ms)
        } else {
            format!("{:>4.1}s", self.duration_ms as f64 / 1000.0)
        };
        buf.set_string(duration_x, area.y, &duration_str, Style::default().fg(Color::DarkGray));

        // Size (if available and space permits)
        if let Some(bytes) = self.size_bytes {
            if area.width > 40 {
                let size_str = Self::format_size(bytes);
                let size_x = area.x + area.width - 20;
                buf.set_string(size_x, area.y, &size_str, Style::default().fg(Color::DarkGray));
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get HTTP status reason phrase
fn status_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

// ============================================================================
// Request Rate Tracker for Sparkline
// ============================================================================

/// Tracks request rate over time for sparkline display
#[derive(Debug, Clone)]
pub struct RateTracker {
    /// Samples (requests per interval)
    samples: Vec<u64>,
    /// Current interval count
    current_count: u64,
    /// Maximum samples to keep
    max_samples: usize,
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new(60) // 60 samples = 1 minute at 1s intervals
    }
}

impl RateTracker {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples),
            current_count: 0,
            max_samples,
        }
    }

    /// Record a request
    pub fn record(&mut self) {
        self.current_count += 1;
    }

    /// Tick the tracker (call every interval, e.g., every second)
    pub fn tick(&mut self) {
        self.samples.push(self.current_count);
        self.current_count = 0;

        if self.samples.len() > self.max_samples {
            self.samples.remove(0);
        }
    }

    /// Get samples for sparkline
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    /// Get current rate (requests in current interval)
    #[allow(dead_code)]
    pub fn current_rate(&self) -> u64 {
        self.current_count
    }

    /// Get average rate
    #[allow(dead_code)]
    pub fn average_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<u64>() as f64 / self.samples.len() as f64
    }
}
