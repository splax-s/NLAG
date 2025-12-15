//! Terminal User Interface for NLAG Agent
//!
//! Provides a beautiful ngrok-style TUI showing:
//! - Session status and connection info
//! - Live request logs
//! - Connection statistics

pub mod app;
pub mod widgets;

use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use tokio::sync::mpsc;

pub use app::{AppState, ConnectionStats, HttpRequest, TunnelInfo};

/// Events that can be sent to the UI
#[derive(Debug, Clone)]
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

    pub fn stats_update(&self, stats: ConnectionStats) {
        self.send(UiEvent::StatsUpdate(stats));
    }

    pub fn error(&self, msg: impl Into<String>) {
        self.send(UiEvent::Error(msg.into()));
    }

    pub fn disconnected(&self) {
        self.send(UiEvent::Disconnected);
    }

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
) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize app state
    let mut app = AppState::new(local_addr, edge_addr);

    // Main loop
    let tick_rate = Duration::from_millis(100);
    
    loop {
        // Draw UI
        terminal.draw(|f| draw_ui(f, &app))?;

        // Handle events with timeout
        if crossterm::event::poll(tick_rate)? {
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

        // Process UI events (non-blocking)
        while let Ok(event) = event_rx.try_recv() {
            app.handle_event(event);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Draw the main UI
fn draw_ui(frame: &mut Frame, app: &AppState) {
    let size = frame.area();

    // Main layout: header, status, connections, requests
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(9),  // Status panel
            Constraint::Length(5),  // Connection stats
            Constraint::Min(8),     // HTTP requests
            Constraint::Length(1),  // Footer
        ])
        .split(size);

    // Header
    draw_header(frame, chunks[0], app);

    // Status panel
    draw_status(frame, chunks[1], app);

    // Connection stats
    draw_connections(frame, chunks[2], app);

    // HTTP requests
    draw_requests(frame, chunks[3], app);

    // Footer
    draw_footer(frame, chunks[4]);
}

fn draw_header(frame: &mut Frame, area: Rect, app: &AppState) {
    let title = vec![
        Span::styled("n", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("lag", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        ),
    ];

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
