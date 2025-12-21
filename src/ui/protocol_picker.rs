//! Protocol picker popup
//!
//! Provides a searchable popup for selecting protocols

use crate::app::App;
use crate::config::Protocol;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

// Color scheme matching the rest of the app
const BG_COLOR: Color = Color::Rgb(0, 0, 0);
const FG_PRIMARY: Color = Color::White;
const FG_SECONDARY: Color = Color::Rgb(128, 128, 128);
const FG_DIM: Color = Color::Rgb(80, 80, 80);
const ACCENT: Color = Color::Rgb(80, 200, 100);
const ACCENT_BRIGHT: Color = Color::Rgb(100, 255, 120);

/// Get all available protocols
pub fn all_protocols() -> Vec<Protocol> {
    vec![
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Http,
        Protocol::Https,
        Protocol::Dns,
        Protocol::Ntp,
        Protocol::Snmp,
        Protocol::Ssdp,
        Protocol::Smb,
        Protocol::Ldap,
        Protocol::NetBios,
        Protocol::Dhcp,
        Protocol::Kerberos,
        Protocol::Arp,
        Protocol::Raw,
    ]
}

/// Get protocol description
fn protocol_description(proto: &Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "Transmission Control Protocol",
        Protocol::Udp => "User Datagram Protocol",
        Protocol::Icmp => "Internet Control Message Protocol",
        Protocol::Http => "Hypertext Transfer Protocol",
        Protocol::Https => "HTTP over TLS/SSL",
        Protocol::Dns => "Domain Name System",
        Protocol::Ntp => "Network Time Protocol",
        Protocol::Snmp => "Simple Network Management Protocol",
        Protocol::Ssdp => "Simple Service Discovery Protocol",
        Protocol::Smb => "Server Message Block",
        Protocol::Ldap => "Lightweight Directory Access Protocol",
        Protocol::NetBios => "Network Basic Input/Output System",
        Protocol::Dhcp => "Dynamic Host Configuration Protocol",
        Protocol::Kerberos => "Kerberos Authentication",
        Protocol::Arp => "Address Resolution Protocol",
        Protocol::Raw => "Raw packet mode",
    }
}

/// Get default port for protocol
fn protocol_port(proto: &Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "-",
        Protocol::Udp => "-",
        Protocol::Icmp => "-",
        Protocol::Http => "80",
        Protocol::Https => "443",
        Protocol::Dns => "53",
        Protocol::Ntp => "123",
        Protocol::Snmp => "161",
        Protocol::Ssdp => "1900",
        Protocol::Smb => "445",
        Protocol::Ldap => "389",
        Protocol::NetBios => "137-139",
        Protocol::Dhcp => "67/68",
        Protocol::Kerberos => "88",
        Protocol::Arp => "-",
        Protocol::Raw => "-",
    }
}

/// Filter protocols by search query
pub fn filter_protocols(query: &str) -> Vec<Protocol> {
    let query_lower = query.to_lowercase();
    all_protocols()
        .into_iter()
        .filter(|p| {
            let name = format!("{}", p).to_lowercase();
            let desc = protocol_description(p).to_lowercase();
            name.contains(&query_lower) || desc.contains(&query_lower)
        })
        .collect()
}

/// Render the protocol picker popup
pub fn render_protocol_picker(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate popup size
    let popup_width = (area.width * 60 / 100).min(60).max(45);
    let popup_height = (area.height * 70 / 100).min(22).max(16);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block with search filter in title if active
    let title = if app.protocol_picker_filter.is_empty() {
        " Select Protocol ".to_string()
    } else {
        format!(" Select Protocol [{}] ", app.protocol_picker_filter)
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(ACCENT_BRIGHT).bold())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::uniform(1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Split inner area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Protocol list
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Get filtered protocols
    let protocols = filter_protocols(&app.protocol_picker_filter);

    // Render protocol list
    render_protocol_list(frame, app, chunks[0], &protocols);

    // Render help text
    render_help_text(frame, chunks[2]);
}

/// Render the protocol list
fn render_protocol_list(frame: &mut Frame, app: &App, area: Rect, protocols: &[Protocol]) {
    if protocols.is_empty() {
        let msg = Paragraph::new("No matching protocols")
            .style(Style::default().fg(FG_DIM))
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let rows: Vec<Row> = protocols.iter().enumerate().map(|(idx, proto)| {
        let is_selected = idx == app.protocol_picker_index;
        let is_current = *proto == app.selected_protocol;

        let indicator = if is_selected { "▶" } else if is_current { "●" } else { " " };
        let indicator_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT)
        } else if is_current {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(BG_COLOR)
        };

        let name_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT).bold()
        } else if is_current {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(FG_PRIMARY)
        };

        let port_style = Style::default().fg(FG_SECONDARY);
        let desc_style = Style::default().fg(FG_DIM);

        Row::new(vec![
            Span::styled(indicator, indicator_style),
            Span::styled(format!("{:8}", proto), name_style),
            Span::styled(format!("{:10}", protocol_port(proto)), port_style),
            Span::styled(protocol_description(proto), desc_style),
        ])
    }).collect();

    // Calculate visible window based on selection
    let max_visible = (area.height as usize).saturating_sub(1);
    let start_idx = if app.protocol_picker_index >= max_visible {
        app.protocol_picker_index - max_visible + 1
    } else {
        0
    };

    let visible_rows: Vec<Row> = rows.into_iter().skip(start_idx).take(max_visible).collect();

    let table = Table::new(
        visible_rows,
        [
            Constraint::Length(2),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Min(20),
        ],
    )
    .column_spacing(1);

    frame.render_widget(table, area);
}

/// Render help text at the bottom
fn render_help_text(frame: &mut Frame, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled("j/k", Style::default().fg(ACCENT)),
        Span::styled(" navigate  ", Style::default().fg(FG_DIM)),
        Span::styled("Enter", Style::default().fg(ACCENT)),
        Span::styled(" select  ", Style::default().fg(FG_DIM)),
        Span::styled("Type", Style::default().fg(ACCENT)),
        Span::styled(" to filter  ", Style::default().fg(FG_DIM)),
        Span::styled("Esc", Style::default().fg(ACCENT)),
        Span::styled(" close", Style::default().fg(FG_DIM)),
    ]);

    let paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}

/// Helper function to create a centered rectangle
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect { x, y, width, height }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_protocols_count() {
        assert_eq!(all_protocols().len(), 16);
    }

    #[test]
    fn test_filter_protocols() {
        let tcp = filter_protocols("tcp");
        assert!(tcp.contains(&Protocol::Tcp));

        let http = filter_protocols("http");
        assert!(http.contains(&Protocol::Http));
        assert!(http.contains(&Protocol::Https));

        let empty = filter_protocols("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_protocol_descriptions() {
        for proto in all_protocols() {
            let desc = protocol_description(&proto);
            assert!(!desc.is_empty());
        }
    }
}
