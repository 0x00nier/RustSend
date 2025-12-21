//! Packet metadata editor popup
//!
//! Provides a popup for editing packet fields like ports, TTL, sequence numbers, etc.

use crate::app::{App, PacketEditorField};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
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
const WARNING: Color = Color::Rgb(200, 180, 80);

/// Render the packet editor popup
pub fn render_packet_editor(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate popup size (60% width, 50% height, max 70x20)
    let popup_width = (area.width * 60 / 100).min(70).max(50);
    let popup_height = (area.height * 50 / 100).min(20).max(14);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block
    let title = if app.packet_editor.editing {
        format!(" Packet Editor - Editing {} ", app.packet_editor.current_field.label())
    } else {
        " Packet Editor ".to_string()
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
            Constraint::Min(8),    // Fields
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Render fields
    render_fields(frame, app, chunks[0]);

    // Render help text
    render_help_text(frame, app, chunks[2]);
}

/// Render the editable fields
fn render_fields(frame: &mut Frame, app: &App, area: Rect) {
    let fields = [
        PacketEditorField::SourcePort,
        PacketEditorField::DestPort,
        PacketEditorField::Ttl,
        PacketEditorField::SeqNum,
        PacketEditorField::AckNum,
        PacketEditorField::WindowSize,
        PacketEditorField::Payload,
    ];

    let rows: Vec<Row> = fields.iter().map(|field| {
        let is_selected = *field == app.packet_editor.current_field;
        let is_editing = is_selected && app.packet_editor.editing;

        let label_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT).bold()
        } else {
            Style::default().fg(FG_SECONDARY)
        };

        let value = if is_editing {
            format!("{}▌", app.packet_editor.field_buffer)
        } else {
            match field {
                PacketEditorField::SourcePort => app.packet_editor.source_port.to_string(),
                PacketEditorField::DestPort => app.packet_editor.dest_port.to_string(),
                PacketEditorField::Ttl => app.packet_editor.ttl.to_string(),
                PacketEditorField::SeqNum => app.packet_editor.seq_num.to_string(),
                PacketEditorField::AckNum => app.packet_editor.ack_num.to_string(),
                PacketEditorField::WindowSize => app.packet_editor.window_size.to_string(),
                PacketEditorField::Payload => {
                    if app.packet_editor.payload_hex.is_empty() {
                        "(empty)".to_string()
                    } else {
                        format_hex_preview(&app.packet_editor.payload_hex, 20)
                    }
                }
            }
        };

        let value_style = if is_editing {
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD)
        } else if is_selected {
            Style::default().fg(ACCENT_BRIGHT)
        } else {
            Style::default().fg(FG_PRIMARY)
        };

        let indicator = if is_selected { "▶ " } else { "  " };
        let indicator_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT)
        } else {
            Style::default().fg(BG_COLOR)
        };

        Row::new(vec![
            Span::styled(indicator, indicator_style),
            Span::styled(format!("{:14}", field.label()), label_style),
            Span::styled(value, value_style),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(15),
            Constraint::Min(20),
        ],
    )
    .column_spacing(1);

    frame.render_widget(table, area);
}

/// Render help text at the bottom
fn render_help_text(frame: &mut Frame, app: &App, area: Rect) {
    let help_text = if app.packet_editor.editing {
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(ACCENT)),
            Span::styled(" save  ", Style::default().fg(FG_DIM)),
            Span::styled("Esc", Style::default().fg(ACCENT)),
            Span::styled(" cancel", Style::default().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("j/k", Style::default().fg(ACCENT)),
            Span::styled(" navigate  ", Style::default().fg(FG_DIM)),
            Span::styled("Enter/i", Style::default().fg(ACCENT)),
            Span::styled(" edit  ", Style::default().fg(FG_DIM)),
            Span::styled("r", Style::default().fg(ACCENT)),
            Span::styled(" randomize  ", Style::default().fg(FG_DIM)),
            Span::styled("Esc/q", Style::default().fg(ACCENT)),
            Span::styled(" close", Style::default().fg(FG_DIM)),
        ])
    };

    let paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}

/// Format hex string with ellipsis for preview
fn format_hex_preview(hex: &str, max_len: usize) -> String {
    if hex.len() <= max_len {
        // Add spaces between byte pairs for readability
        hex.chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let truncated: String = hex.chars().take(max_len).collect();
        let formatted = truncated.chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        format!("{}...", formatted)
    }
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
    fn test_format_hex_preview_short() {
        let hex = "48656c6c6f";
        let result = format_hex_preview(hex, 20);
        assert_eq!(result, "48 65 6c 6c 6f");
    }

    #[test]
    fn test_format_hex_preview_truncated() {
        let hex = "48656c6c6f576f726c64";
        let result = format_hex_preview(hex, 8);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_centered_rect() {
        let area = Rect { x: 0, y: 0, width: 100, height: 50 };
        let centered = centered_rect(40, 20, area);
        assert_eq!(centered.x, 30);
        assert_eq!(centered.y, 15);
        assert_eq!(centered.width, 40);
        assert_eq!(centered.height, 20);
    }
}
