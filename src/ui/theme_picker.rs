//! Theme picker popup
//!
//! Provides a popup for selecting UI color themes

use crate::app::App;
use crate::ui::theme::ThemeType;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

/// Render the theme picker popup
pub fn render_theme_picker(frame: &mut Frame, app: &App) {
    let colors = app.current_theme.colors();
    let area = frame.area();

    // Calculate popup size
    let popup_width = (area.width * 50 / 100).min(50).max(40);
    let popup_height = (area.height * 60 / 100).min(16).max(12);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block
    let block = Block::default()
        .title(" Select Theme ")
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
            Constraint::Min(6),    // Theme list
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Render theme list
    render_theme_list(frame, app, chunks[0]);

    // Render help text
    render_help_text(frame, app, chunks[2]);
}

/// Render the theme list
fn render_theme_list(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();
    let themes = ThemeType::all();

    let rows: Vec<Row> = themes
        .iter()
        .enumerate()
        .map(|(idx, theme)| {
            let is_selected = idx == app.theme_picker_index;
            let is_current = *theme == app.current_theme;

            let indicator = if is_selected { ">" } else { " " };
            let indicator_style = if is_selected {
                Style::default().fg(colors.accent_bright)
            } else {
                Style::default().fg(colors.bg)
            };

            let current_marker = if is_current { "*" } else { " " };
            let marker_style = if is_current {
                Style::default().fg(colors.success)
            } else {
                Style::default().fg(colors.fg_dim)
            };

            let name_style = if is_selected {
                Style::default().fg(colors.accent_bright).bold()
            } else if is_current {
                Style::default().fg(colors.success)
            } else {
                Style::default().fg(colors.fg_primary)
            };

            let desc_style = Style::default().fg(colors.fg_dim);

            Row::new(vec![
                Span::styled(indicator, indicator_style),
                Span::styled(current_marker, marker_style),
                Span::styled(format!("{:12}", theme.name()), name_style),
                Span::styled(theme.description(), desc_style),
            ])
        })
        .collect();

    // Calculate visible window based on selection
    let max_visible = (area.height as usize).saturating_sub(1);
    let start_idx = if app.theme_picker_index >= max_visible {
        app.theme_picker_index - max_visible + 1
    } else {
        0
    };

    let visible_rows: Vec<Row> = rows.into_iter().skip(start_idx).take(max_visible).collect();

    let table = Table::new(
        visible_rows,
        [
            Constraint::Length(2),  // Indicator
            Constraint::Length(2),  // Current marker
            Constraint::Length(13), // Name
            Constraint::Min(20),    // Description
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
