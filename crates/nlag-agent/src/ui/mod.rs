//! Terminal User Interface for NLAG Agent
//!
//! Provides a beautiful ngrok-style TUI showing:
//! - Session status and connection info
//! - Live request logs
//! - Connection statistics

pub mod app;
pub mod widgets;

use std::io;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use tokio::sync::mpsc;

pub use app::{AppState, ConnectionStats, HttpRequest, TunnelInfo};
pub use widgets::WidgetConfig;

/// Events that can be sent to the UI
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum UiEvent {
    /// Tunnel successfully opened
    TunnelOpened(TunnelInfo),
    /// Connection established
    Connected { session_id: String, latency_ms: u64 },
    /// New HTTP request received
    HttpRequest(HttpRequest),
    /// Connection stats updated
    StatsUpdate(ConnectionStats),
    /// Error occurred
    Error(String),
    /// Connection closed
    Disconnected,
    /// Latency measurement
    LatencyUpdate(u64),
}

/// UI handle for sending events from tunnel code
#[derive(Clone)]
pub struct UiHandle {
    sender: mpsc::UnboundedSender<UiEvent>,
}

impl UiHandle {
    pub fn send(&self, event: UiEvent) {
        let _ = self.sender.send(event);
    }

    pub fn tunnel_opened(&self, info: TunnelInfo) {
        self.send(UiEvent::TunnelOpened(info));
    }

    pub fn connected(&self, session_id: String, latency_ms: u64) {
        self.send(UiEvent::Connected { session_id, latency_ms });
    }

    pub fn http_request(&self, req: HttpRequest) {
        self.send(UiEvent::HttpRequest(req));
    }

    #[allow(dead_code)]
    pub fn stats_update(&self, stats: ConnectionStats) {
        self.send(UiEvent::StatsUpdate(stats));
    }

    pub fn error(&self, msg: impl Into<String>) {
        self.send(UiEvent::Error(msg.into()));
    }

    pub fn disconnected(&self) {
        self.send(UiEvent::Disconnected);
    }

    #[allow(dead_code)]
    pub fn latency_update(&self, latency_ms: u64) {
        self.send(UiEvent::LatencyUpdate(latency_ms));
    }
}

/// Create a new UI channel
pub fn create_ui_channel() -> (UiHandle, mpsc::UnboundedReceiver<UiEvent>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (UiHandle { sender: tx }, rx)
}

/// Run the TUI application
pub async fn run_ui(
    mut event_rx: mpsc::UnboundedReceiver<UiEvent>,
    local_addr: String,
    edge_addr: String,
    widget_config: WidgetConfig,
) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize app state with widget config
    let mut app = AppState::new(local_addr, edge_addr).with_widget_config(widget_config);
    
    // Track time for rate tracker ticking
    let mut last_rate_tick = Instant::now();

    // Main loop - prioritize data events over keyboard
    loop {
        // Process ALL pending UI events first (non-blocking) - this is the priority
        let mut had_events = false;
        while let Ok(event) = event_rx.try_recv() {
            app.handle_event(event);
            had_events = true;
        }
        
        // Tick rate tracker every second (for sparkline)
        if app.widget_config.sparkline && last_rate_tick.elapsed() >= Duration::from_secs(1) {
            app.tick_rate();
            last_rate_tick = Instant::now();
        }
        
        // Draw UI
        terminal.draw(|f| draw_ui(f, &app))?;

        // Check for keyboard input with very short timeout (1ms)
        // This makes the loop responsive to both keyboard and data events
        if crossterm::event::poll(Duration::from_millis(1))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('c') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') => app.clear_requests(),
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        _ => {}
                    }
                }
            }
        }
        
        // Small sleep to prevent CPU spinning when idle
        if !had_events {
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Draw the main UI
fn draw_ui(frame: &mut Frame, app: &AppState) {
    let size = frame.area();
    
    // Adjust layout based on enabled widgets
    let has_extra_widgets = app.widget_config.sparkline || app.widget_config.latency_gauge;

    // Main layout: header, status, connections, [optional widgets], requests
    let constraints = if has_extra_widgets {
        vec![
            Constraint::Length(3),  // Header
            Constraint::Length(9),  // Status panel
            Constraint::Length(5),  // Connection stats
            Constraint::Length(3),  // Optional widgets row
            Constraint::Min(8),     // HTTP requests
            Constraint::Length(1),  // Footer
        ]
    } else {
        vec![
            Constraint::Length(3),  // Header
            Constraint::Length(9),  // Status panel
            Constraint::Length(5),  // Connection stats
            Constraint::Min(8),     // HTTP requests
            Constraint::Length(1),  // Footer
        ]
    };
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(constraints)
        .split(size);

    // Header
    draw_header(frame, chunks[0], app);

    // Status panel
    draw_status(frame, chunks[1], app);

    // Connection stats
    draw_connections(frame, chunks[2], app);

    if has_extra_widgets {
        // Optional widgets row
        draw_extra_widgets(frame, chunks[3], app);
        
        // HTTP requests
        draw_requests(frame, chunks[4], app);

        // Footer
        draw_footer(frame, chunks[5]);
    } else {
        // HTTP requests
        draw_requests(frame, chunks[3], app);

        // Footer
        draw_footer(frame, chunks[4]);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &AppState) {
    let title = [Span::styled("n", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("lag", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        )];

    let status_indicator = if app.is_connected {
        Span::styled(" ● ", Style::default().fg(Color::Green))
    } else {
        Span::styled(" ● ", Style::default().fg(Color::Red))
    };

    let header = Paragraph::new(Line::from(vec![
        status_indicator,
        Span::raw(" "),
        title[0].clone(),
        title[1].clone(),
        title[2].clone(),
        title[3].clone(),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title_alignment(ratatui::layout::Alignment::Center),
    );

    frame.render_widget(header, area);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &AppState) {
    let status_text = if app.is_connected { "online" } else { "offline" };
    let status_color = if app.is_connected { Color::Green } else { Color::Red };

    // Pre-compute formatted strings to avoid lifetime issues
    let session_id = app.session_id.clone().unwrap_or_else(|| "-".to_string());
    let latency = format!("{}ms", app.latency_ms);
    let forwarding = app.tunnel_info.as_ref().map(|t| {
        format!("{} → {}", t.public_url, app.local_addr)
    });

    let mut rows = vec![
        create_status_row("Session Status", status_text, status_color),
        create_status_row("Session ID", &session_id, Color::White),
        create_status_row("Version", env!("CARGO_PKG_VERSION"), Color::White),
        create_status_row("Latency", &latency, Color::White),
        create_status_row("Edge Server", &app.edge_addr, Color::White),
    ];

    // Add tunnel info if available
    if let Some(fwd) = &forwarding {
        rows.push(create_status_row("Forwarding", fwd, Color::Cyan));
    }

    let widths = [Constraint::Length(20), Constraint::Min(40)];
    let table = Table::new(rows, widths)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Session ")
                .title_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(table, area);
}

fn create_status_row<'a>(label: &'a str, value: &'a str, value_color: Color) -> Row<'a> {
    Row::new(vec![
        Cell::from(label).style(Style::default().fg(Color::DarkGray)),
        Cell::from(value).style(Style::default().fg(value_color)),
    ])
}

fn draw_connections(frame: &mut Frame, area: Rect, app: &AppState) {
    let stats = &app.stats;

    let header = Row::new(vec!["ttl", "opn", "rt1", "rt5", "p50", "p90"])
        .style(Style::default().fg(Color::DarkGray))
        .bottom_margin(1);

    let data = Row::new(vec![
        Cell::from(format!("{}", stats.total_connections)),
        Cell::from(format!("{}", stats.open_connections)),
        Cell::from(format!("{:.2}", stats.rate_1m)),
        Cell::from(format!("{:.2}", stats.rate_5m)),
        Cell::from(format!("{:.2}", stats.p50_latency)),
        Cell::from(format!("{:.2}", stats.p90_latency)),
    ])
    .style(Style::default().fg(Color::White));

    let widths = [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ];

    let table = Table::new(vec![data], widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Connections ")
                .title_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(table, area);
}

/// Draw optional extra widgets (sparkline, latency gauge, health indicator)
fn draw_extra_widgets(frame: &mut Frame, area: Rect, app: &AppState) {
    use widgets::{Sparkline, Gauge, HealthIndicator};
    
    // Split the area based on which widgets are enabled
    let mut constraints = Vec::new();
    
    if app.widget_config.sparkline {
        constraints.push(Constraint::Percentage(40));
    }
    if app.widget_config.latency_gauge {
        constraints.push(Constraint::Percentage(40));
    }
    if app.widget_config.health_indicator {
        constraints.push(Constraint::Length(3));
    }
    // Fill remaining space
    if constraints.is_empty() {
        return;
    }
    constraints.push(Constraint::Min(0));
    
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);
    
    let mut chunk_idx = 0;
    
    // Sparkline for request rate
    if app.widget_config.sparkline {
        let sparkline_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Rate/s ")
            .title_style(Style::default().fg(Color::Cyan));
        
        let inner = sparkline_block.inner(chunks[chunk_idx]);
        frame.render_widget(sparkline_block, chunks[chunk_idx]);
        
        let samples = app.rate_tracker.samples();
        if !samples.is_empty() {
            let sparkline = Sparkline::new(samples);
            frame.render_widget(sparkline, inner);
        }
        chunk_idx += 1;
    }
    
    // Latency gauge
    if app.widget_config.latency_gauge {
        let gauge_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(format!(" Latency: {}ms ", app.latency_ms))
            .title_style(Style::default().fg(Color::Cyan));
        
        let inner = gauge_block.inner(chunks[chunk_idx]);
        frame.render_widget(gauge_block, chunks[chunk_idx]);
        
        let gauge = Gauge::new(app.latency_ms, 500); // 500ms max
        frame.render_widget(gauge, inner);
        chunk_idx += 1;
    }
    
    // Health indicator
    if app.widget_config.health_indicator {
        let health = HealthIndicator::new(app.is_connected, app.latency_ms);
        frame.render_widget(health, chunks[chunk_idx]);
    }
}

fn draw_requests(frame: &mut Frame, area: Rect, app: &AppState) {
    let title = format!(" HTTP Requests ({}) ", app.requests.len());

    if app.requests.is_empty() {
        let empty = Paragraph::new(Text::styled(
            "\n  Waiting for requests...",
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(title)
                .title_style(Style::default().fg(Color::Cyan)),
        );
        frame.render_widget(empty, area);
        return;
    }

    let visible_count = (area.height as usize).saturating_sub(2);
    let start = app.scroll_offset.min(app.requests.len().saturating_sub(visible_count));
    let visible_requests: Vec<_> = app.requests.iter().rev().skip(start).take(visible_count).collect();

    let rows: Vec<Row> = visible_requests
        .iter()
        .map(|req| {
            let status_color = match req.status / 100 {
                2 => Color::Green,
                3 => Color::Yellow,
                4 => Color::Red,
                5 => Color::Magenta,
                _ => Color::White,
            };

            let status_text = if req.status == 0 {
                "...".to_string()
            } else {
                format!("{} {}", req.status, status_reason(req.status))
            };

            Row::new(vec![
                Cell::from(req.timestamp.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(req.method.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(truncate_path(&req.path, 40)).style(Style::default().fg(Color::White)),
                Cell::from(status_text).style(Style::default().fg(status_color)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Min(20),
        Constraint::Length(20),
    ];

    let table = Table::new(rows, widths)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(title)
                .title_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(table, area);
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let help = Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::styled("c", Style::default().fg(Color::Cyan)),
        Span::raw(" clear  "),
        Span::styled("↑↓", Style::default().fg(Color::Cyan)),
        Span::raw(" scroll  "),
        Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
        Span::raw(" exit"),
    ]);

    let footer = Paragraph::new(help)
        .style(Style::default().fg(Color::DarkGray));

    frame.render_widget(footer, area);
}

fn status_reason(status: u16) -> &'static str {
    match status {
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
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("{}...", &path[..max_len - 3])
    }
}
