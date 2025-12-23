//! Template picker popup
//!
//! Provides a searchable popup for selecting packet templates

use crate::app::App;
use crate::config::PacketTemplate;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

/// Get template description
fn template_description(template: &PacketTemplate) -> &'static str {
    match template {
        PacketTemplate::TcpSyn => "TCP handshake initiation",
        PacketTemplate::TcpSynAck => "TCP handshake response",
        PacketTemplate::TcpAck => "TCP acknowledgment",
        PacketTemplate::TcpFin => "TCP connection close",
        PacketTemplate::TcpRst => "TCP connection reset",
        PacketTemplate::TcpXmas => "TCP Christmas tree scan",
        PacketTemplate::TcpNull => "TCP null flags scan",
        PacketTemplate::HttpGet => "HTTP GET request",
        PacketTemplate::HttpHead => "HTTP HEAD request",
        PacketTemplate::HttpPost => "HTTP POST request",
        PacketTemplate::HttpOptions => "HTTP OPTIONS preflight",
        PacketTemplate::HttpSmuggleCLTE => "CL.TE request smuggling",
        PacketTemplate::HttpSmuggleTECL => "TE.CL request smuggling",
        PacketTemplate::HttpSmuggleTETE => "TE.TE obfuscation attack",
        PacketTemplate::HttpHostOverride => "Host header injection",
        PacketTemplate::WebSocketUpgrade => "WebSocket upgrade request",
        PacketTemplate::DnsQueryA => "DNS A record lookup",
        PacketTemplate::DnsQueryAAAA => "DNS IPv6 address lookup",
        PacketTemplate::DnsQueryMX => "DNS mail exchange lookup",
        PacketTemplate::DnsQueryTXT => "DNS TXT record lookup",
        PacketTemplate::IcmpPing => "ICMP echo request (ping)",
        PacketTemplate::NtpRequest => "NTP time sync request",
        PacketTemplate::Custom => "Custom raw packet",
    }
}

/// Get template category for display
fn template_category(template: &PacketTemplate) -> &'static str {
    match template {
        PacketTemplate::TcpSyn
        | PacketTemplate::TcpSynAck
        | PacketTemplate::TcpAck
        | PacketTemplate::TcpFin
        | PacketTemplate::TcpRst
        | PacketTemplate::TcpXmas
        | PacketTemplate::TcpNull => "TCP",
        PacketTemplate::HttpGet
        | PacketTemplate::HttpHead
        | PacketTemplate::HttpPost
        | PacketTemplate::HttpOptions => "HTTP",
        PacketTemplate::HttpSmuggleCLTE
        | PacketTemplate::HttpSmuggleTECL
        | PacketTemplate::HttpSmuggleTETE
        | PacketTemplate::HttpHostOverride
        | PacketTemplate::WebSocketUpgrade => "ATTACK",
        PacketTemplate::DnsQueryA
        | PacketTemplate::DnsQueryAAAA
        | PacketTemplate::DnsQueryMX
        | PacketTemplate::DnsQueryTXT => "DNS",
        PacketTemplate::IcmpPing => "ICMP",
        PacketTemplate::NtpRequest => "NTP",
        PacketTemplate::Custom => "RAW",
    }
}

/// Filter templates by search query
pub fn filter_templates(query: &str) -> Vec<PacketTemplate> {
    let query_lower = query.to_lowercase();
    PacketTemplate::all()
        .into_iter()
        .filter(|t| {
            let name = t.name().to_lowercase();
            let desc = template_description(t).to_lowercase();
            let cat = template_category(t).to_lowercase();
            name.contains(&query_lower) || desc.contains(&query_lower) || cat.contains(&query_lower)
        })
        .collect()
}

/// Render the template picker popup
pub fn render_template_picker(frame: &mut Frame, app: &App) {
    let colors = app.current_theme.colors();
    let area = frame.area();

    // Calculate popup size
    let popup_width = (area.width * 70 / 100).min(75).max(55);
    let popup_height = (area.height * 75 / 100).min(24).max(18);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block with search filter in title if active
    let title = if app.template_picker_filter.is_empty() {
        " Select Template ".to_string()
    } else {
        format!(" Select Template [{}] ", app.template_picker_filter)
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(colors.accent_bright).bold())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(colors.accent))
        .style(Style::default().bg(colors.bg))
        .padding(Padding::uniform(1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Split inner area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Template list
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Get filtered templates
    let templates = filter_templates(&app.template_picker_filter);

    // Render template list
    render_template_list(frame, app, chunks[0], &templates);

    // Render help text
    render_help_text(frame, app, chunks[2]);
}

/// Render the template list
fn render_template_list(frame: &mut Frame, app: &App, area: Rect, templates: &[PacketTemplate]) {
    let colors = app.current_theme.colors();

    if templates.is_empty() {
        let msg = Paragraph::new("No matching templates")
            .style(Style::default().fg(colors.fg_dim))
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let rows: Vec<Row> = templates.iter().enumerate().map(|(idx, template)| {
        let is_selected = idx == app.template_picker_index;

        let indicator = if is_selected { ">" } else { " " };
        let indicator_style = if is_selected {
            Style::default().fg(colors.accent_bright)
        } else {
            Style::default().fg(colors.bg)
        };

        let name_style = if is_selected {
            Style::default().fg(colors.accent_bright).bold()
        } else {
            Style::default().fg(colors.fg_primary)
        };

        let cat_style = if is_selected {
            Style::default().fg(colors.accent)
        } else {
            Style::default().fg(colors.fg_secondary)
        };

        let shortcut = template.shortcut();
        let shortcut_style = if shortcut != "-" {
            Style::default().fg(colors.accent)
        } else {
            Style::default().fg(colors.fg_dim)
        };

        let desc_style = Style::default().fg(colors.fg_dim);

        Row::new(vec![
            Span::styled(indicator, indicator_style),
            Span::styled(format!("{:6}", template_category(template)), cat_style),
            Span::styled(format!("{:16}", template.name()), name_style),
            Span::styled(format!("{:4}", shortcut), shortcut_style),
            Span::styled(template_description(template), desc_style),
        ])
    }).collect();

    // Calculate visible window based on selection
    let max_visible = (area.height as usize).saturating_sub(1);
    let start_idx = if app.template_picker_index >= max_visible {
        app.template_picker_index - max_visible + 1
    } else {
        0
    };

    let visible_rows: Vec<Row> = rows.into_iter().skip(start_idx).take(max_visible).collect();

    let table = Table::new(
        visible_rows,
        [
            Constraint::Length(2),   // Indicator
            Constraint::Length(7),   // Category
            Constraint::Length(17),  // Name
            Constraint::Length(5),   // Shortcut
            Constraint::Min(20),     // Description
        ],
    )
    .column_spacing(1);

    frame.render_widget(table, area);
}

/// Render help text at the bottom
fn render_help_text(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();

    let help_text = Line::from(vec![
        Span::styled("j/k", Style::default().fg(colors.accent)),
        Span::styled(" navigate  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Enter", Style::default().fg(colors.accent)),
        Span::styled(" apply  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Type", Style::default().fg(colors.accent)),
        Span::styled(" to filter  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Esc", Style::default().fg(colors.accent)),
        Span::styled(" close", Style::default().fg(colors.fg_dim)),
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
    fn test_all_templates_have_descriptions() {
        for template in PacketTemplate::all() {
            let desc = template_description(&template);
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_filter_templates() {
        let tcp = filter_templates("tcp");
        assert!(tcp.iter().any(|t| matches!(t, PacketTemplate::TcpSyn)));

        let http = filter_templates("http");
        assert!(http.iter().any(|t| matches!(t, PacketTemplate::HttpGet)));

        let dns = filter_templates("dns");
        assert!(dns.iter().any(|t| matches!(t, PacketTemplate::DnsQueryA)));

        let empty = filter_templates("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_template_categories() {
        for template in PacketTemplate::all() {
            let cat = template_category(&template);
            assert!(!cat.is_empty());
        }
    }
}
