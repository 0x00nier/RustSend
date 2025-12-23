//! Repeater view - BurpSuite-like packet replay interface
//!
//! Provides a three-pane view for managing and resending packets:
//! - Left: List of saved requests
//! - Middle: Request details
//! - Right: Response details

use crate::app::{App, RepeaterEntry, RepeaterPane, RepeaterRequest, ResponseStatus, ParsedResponse};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

/// Render the repeater popup overlay
pub fn render_repeater(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate popup area (80% width, 85% height, centered)
    let popup_width = (area.width as f32 * 0.85) as u16;
    let popup_height = (area.height as f32 * 0.85) as u16;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear background and render popup
    frame.render_widget(Clear, popup_area);

    // Main layout: header, content, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(10),     // Content
            Constraint::Length(3),   // Footer/help
        ])
        .split(popup_area);

    // Render header
    render_header(frame, app, chunks[0]);

    // Render three-pane content
    render_content(frame, app, chunks[1]);

    // Render footer with keybindings
    render_footer(frame, app, chunks[2]);
}

/// Render the header
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let entry_count = app.repeater_entries.len();
    let title = format!(" Repeater ({} entries) ", entry_count);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("* ", Style::default().fg(colors.accent)),
            Span::styled(title, Style::default().fg(colors.fg_primary).add_modifier(Modifier::BOLD)),
        ]),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(colors.border_active))
            .style(Style::default().bg(colors.bg)),
    );

    frame.render_widget(header, area);
}

/// Render the three-pane content area
fn render_content(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),  // Entry list
            Constraint::Percentage(37),  // Request view
            Constraint::Percentage(38),  // Response view
        ])
        .split(area);

    // Render each pane
    render_entry_list(frame, app, chunks[0]);
    render_request_view(frame, app, chunks[1]);
    render_response_view(frame, app, chunks[2]);
}

/// Format a single repeater entry for the list view
fn format_entry_item(entry: &RepeaterEntry, is_selected: bool, colors: &crate::ui::theme::ThemeColors) -> Line<'static> {
    let prefix = if is_selected { "> " } else { "  " };
    let summary = entry.request.summary();

    let summary_style = if is_selected {
        Style::default().fg(colors.accent_bright).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(colors.fg_secondary)
    };

    // Show send count with INFO color when entry has been resent
    let send_info = if entry.send_count > 1 {
        Span::styled(format!(" ({}x)", entry.send_count), Style::default().fg(colors.info))
    } else {
        Span::styled("", Style::default())
    };

    Line::from(vec![
        Span::styled(prefix.to_string(), summary_style),
        Span::styled(summary, summary_style),
        send_info,
    ])
}

/// Render the entry list pane
fn render_entry_list(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let is_focused = app.repeater_pane_focus == RepeaterPane::List;
    let border_color = if is_focused { colors.border_active } else { colors.border_inactive };

    let items: Vec<ListItem> = app
        .repeater_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = i == app.repeater_selected;
            ListItem::new(format_entry_item(entry, is_selected, &colors))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(" History ", Style::default().fg(if is_focused { colors.accent } else { colors.fg_dim })))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .style(Style::default().bg(colors.bg)),
        );

    frame.render_widget(list, area);
}

/// Render the request view pane
fn render_request_view(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let is_focused = app.repeater_pane_focus == RepeaterPane::Request;
    let border_color = if is_focused { colors.border_active } else { colors.border_inactive };

    let content = if let Some(entry) = app.repeater_entries.get(app.repeater_selected) {
        format_request(&entry.request, &entry.target_host, entry.target_port)
    } else {
        "(no entry selected)".to_string()
    };

    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(Span::styled(" Request ", Style::default().fg(if is_focused { colors.accent } else { colors.fg_dim })))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .style(Style::default().bg(colors.bg)),
        )
        .style(Style::default().fg(colors.fg_primary));

    frame.render_widget(paragraph, area);
}

/// Render the response view pane
fn render_response_view(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let is_focused = app.repeater_pane_focus == RepeaterPane::Response;
    let border_color = if is_focused { colors.border_active } else { colors.border_inactive };

    let (content, status_color) = if let Some(entry) = app.repeater_entries.get(app.repeater_selected) {
        if let Some(ref response) = entry.response {
            (format_response(response), get_status_color(&response.status, &colors))
        } else {
            ("(no response yet - press 'r' to send)".to_string(), colors.fg_dim)
        }
    } else {
        ("(no entry selected)".to_string(), colors.fg_dim)
    };

    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(Span::styled(" Response ", Style::default().fg(if is_focused { colors.accent } else { colors.fg_dim })))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .style(Style::default().bg(colors.bg)),
        )
        .style(Style::default().fg(status_color));

    frame.render_widget(paragraph, area);
}

/// Render the footer with keybindings
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let hints = vec![
        ("r", "Resend"),
        ("j/k", "Navigate"),
        ("Tab", "Switch Pane"),
        ("d", "Delete"),
        ("n", "New"),
        ("q/Esc", "Close"),
    ];

    let spans: Vec<Span> = hints
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(*key, Style::default().fg(colors.accent)),
                Span::styled(format!(" {} ", desc), Style::default().fg(colors.fg_secondary)),
                Span::styled("| ", Style::default().fg(colors.fg_dim)),
            ]
        })
        .collect();

    let footer = Paragraph::new(Line::from(spans))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(colors.border_inactive))
                .style(Style::default().bg(colors.bg)),
        );

    frame.render_widget(footer, area);
}

/// Format a request for display
fn format_request(request: &RepeaterRequest, host: &str, port: u16) -> String {
    match request {
        RepeaterRequest::Http { method, path, headers, body } => {
            let mut lines = vec![
                format!("{} {} HTTP/1.1", method, path),
                format!("Host: {}:{}", host, port),
            ];
            for (key, value) in headers {
                lines.push(format!("{}: {}", key, value));
            }
            if let Some(body) = body {
                lines.push(String::new());
                if let Ok(text) = String::from_utf8(body.clone()) {
                    lines.push(text);
                } else {
                    lines.push(format!("[Binary: {} bytes]", body.len()));
                }
            }
            lines.join("\n")
        }
        RepeaterRequest::Tcp { flags, seq_num, ack_num, window_size, payload } => {
            let flag_names = format_tcp_flags(*flags);
            let mut lines = vec![
                format!("TCP → {}:{}", host, port),
                format!("Flags: {} (0x{:02X})", flag_names, flags),
                format!("Seq: {}", seq_num),
                format!("Ack: {}", ack_num),
                format!("Window: {}", window_size),
            ];
            if !payload.is_empty() {
                lines.push(format!("Payload: {} bytes", payload.len()));
            }
            lines.join("\n")
        }
        RepeaterRequest::Udp { payload } => {
            format!("UDP → {}:{}\nPayload: {} bytes", host, port, payload.len())
        }
        RepeaterRequest::Dns { query_type, domain } => {
            let type_name = match *query_type {
                1 => "A",
                28 => "AAAA",
                15 => "MX",
                16 => "TXT",
                _ => "?",
            };
            format!("DNS {} query for {}\nServer: {}:{}", type_name, domain, host, port)
        }
        RepeaterRequest::Icmp { icmp_type, icmp_code, id, seq } => {
            let type_name = match *icmp_type {
                0 => "Echo Reply",
                8 => "Echo Request",
                _ => "Other",
            };
            format!("ICMP {} (type={}, code={})\nID: {}, Seq: {}\nTarget: {}",
                type_name, icmp_type, icmp_code, id, seq, host)
        }
        RepeaterRequest::Raw { data } => {
            format!("Raw packet to {}:{}\n{} bytes", host, port, data.len())
        }
    }
}

/// Format a response for display
fn format_response(response: &crate::app::RepeaterResponse) -> String {
    let mut lines = vec![
        format!("Status: {:?}", response.status),
        format!("RTT: {:.2}ms", response.rtt_ms),
        format!("Received: {}", response.timestamp.format("%H:%M:%S")),
        String::new(),
    ];

    if let Some(ref parsed) = response.parsed {
        match parsed {
            ParsedResponse::Http { status_code, status_text, headers, body } => {
                lines.push(format!("HTTP/1.1 {} {}", status_code, status_text));
                for (key, value) in headers {
                    lines.push(format!("{}: {}", key, value));
                }
                if let Some(body) = body {
                    lines.push(String::new());
                    if let Ok(text) = String::from_utf8(body.clone()) {
                        // Truncate long bodies
                        if text.len() > 500 {
                            lines.push(format!("{}...", &text[..500]));
                        } else {
                            lines.push(text);
                        }
                    } else {
                        lines.push(format!("[Binary: {} bytes]", body.len()));
                    }
                }
            }
            ParsedResponse::Dns { answers } => {
                lines.push("DNS Answers:".to_string());
                for answer in answers {
                    lines.push(format!("  {}", answer));
                }
            }
            ParsedResponse::Raw { data } => {
                lines.push(format!("Raw data: {} bytes", data.len()));
                // Show hex preview
                let preview: String = data.iter().take(32).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                lines.push(preview);
            }
        }
    } else {
        lines.push(format!("Raw: {} bytes", response.raw_data.len()));
    }

    lines.join("\n")
}

/// Format TCP flags for display
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x02 != 0 { parts.push("SYN"); }
    if flags & 0x10 != 0 { parts.push("ACK"); }
    if flags & 0x01 != 0 { parts.push("FIN"); }
    if flags & 0x04 != 0 { parts.push("RST"); }
    if flags & 0x08 != 0 { parts.push("PSH"); }
    if flags & 0x20 != 0 { parts.push("URG"); }
    if parts.is_empty() { "---".to_string() } else { parts.join(",") }
}

/// Get color based on response status
fn get_status_color(status: &ResponseStatus, colors: &crate::ui::theme::ThemeColors) -> Color {
    match status {
        ResponseStatus::Success => colors.success,
        ResponseStatus::Timeout => colors.warning,
        ResponseStatus::ConnectionRefused => colors.error,
        ResponseStatus::NetworkUnreachable => colors.error,
        ResponseStatus::Error(_) => colors.error,
    }
}
