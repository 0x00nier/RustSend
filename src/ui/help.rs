//! Help system with which-key.nvim style popup
//!
//! Provides contextual help based on current mode and pending keys

use crate::app::App;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};

// Color scheme: minimal dark with neon green accents
const BG_COLOR: Color = Color::Rgb(0, 0, 0);            // True black
const FG_PRIMARY: Color = Color::White;
const FG_SECONDARY: Color = Color::Rgb(128, 128, 128);
const FG_DIM: Color = Color::Rgb(60, 60, 60);
const ACCENT: Color = Color::Rgb(80, 200, 100);
const ACCENT_BRIGHT: Color = Color::Rgb(100, 255, 120);

/// Help entry structure
pub struct HelpEntry {
    pub key: &'static str,
    pub description: &'static str,
    pub category: HelpCategory,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HelpCategory {
    Navigation,
    Actions,
    Modes,
    Protocols,
    ScanTypes,
    Commands,
}

impl HelpCategory {
    pub fn name(&self) -> &'static str {
        match self {
            HelpCategory::Navigation => "Navigation",
            HelpCategory::Actions => "Actions",
            HelpCategory::Modes => "Modes",
            HelpCategory::Protocols => "Protocols",
            HelpCategory::ScanTypes => "Scan Types",
            HelpCategory::Commands => "Commands",
        }
    }

    pub fn color(&self) -> Color {
        // All categories use the green accent for consistency
        ACCENT
    }
}

/// Get all help entries
fn get_help_entries() -> Vec<HelpEntry> {
    vec![
        // Navigation
        HelpEntry {
            key: "h/←",
            description: "Move left / Previous pane",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "j/↓",
            description: "Move down / Next item",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "k/↑",
            description: "Move up / Previous item",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "l/→",
            description: "Move right / Next pane",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "gg",
            description: "Go to top",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "G",
            description: "Go to bottom",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+d",
            description: "Half page down",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+u",
            description: "Half page up",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Tab",
            description: "Next pane",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Shift+Tab",
            description: "Previous pane",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+h",
            description: "Pane left",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+j",
            description: "Pane down",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+k",
            description: "Pane up",
            category: HelpCategory::Navigation,
        },
        HelpEntry {
            key: "Ctrl+l",
            description: "Pane right",
            category: HelpCategory::Navigation,
        },
        // Actions
        HelpEntry {
            key: "Enter",
            description: "Select / Toggle",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "Space+n",
            description: "New session",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "Space+]",
            description: "Next session",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "Space+[",
            description: "Previous session",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "Space+x",
            description: "Close session",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "s",
            description: "Send packet(s)",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "r",
            description: "Retry failed",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "c",
            description: "Clear logs",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "e",
            description: "Packet editor",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "P",
            description: "Protocol picker",
            category: HelpCategory::Actions,
        },
        HelpEntry {
            key: "q",
            description: "Quit",
            category: HelpCategory::Actions,
        },
        // Modes
        HelpEntry {
            key: "i",
            description: "Insert mode (edit target)",
            category: HelpCategory::Modes,
        },
        HelpEntry {
            key: ":",
            description: "Command mode",
            category: HelpCategory::Modes,
        },
        HelpEntry {
            key: "/",
            description: "Search mode",
            category: HelpCategory::Modes,
        },
        HelpEntry {
            key: "?",
            description: "Toggle help",
            category: HelpCategory::Modes,
        },
        HelpEntry {
            key: "Esc",
            description: "Return to normal mode",
            category: HelpCategory::Modes,
        },
        // Protocols
        HelpEntry {
            key: "1",
            description: "TCP protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "2",
            description: "UDP protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "3",
            description: "ICMP protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "4",
            description: "HTTP protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "5",
            description: "HTTPS protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "6",
            description: "DNS protocol",
            category: HelpCategory::Protocols,
        },
        HelpEntry {
            key: "7",
            description: "NTP protocol",
            category: HelpCategory::Protocols,
        },
        // Scan Types
        HelpEntry {
            key: "F1",
            description: "SYN scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F2",
            description: "Connect scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F3",
            description: "FIN scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F4",
            description: "NULL scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F5",
            description: "X-Mas scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F6",
            description: "ACK scan",
            category: HelpCategory::ScanTypes,
        },
        HelpEntry {
            key: "F7",
            description: "UDP scan",
            category: HelpCategory::ScanTypes,
        },
        // Commands
        HelpEntry {
            key: ":q",
            description: "Quit",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":target <host>",
            description: "Set target host",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":port <ports>",
            description: "Set target ports",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":scan <type>",
            description: "Set scan type",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":send",
            description: "Send packets",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":count <n>",
            description: "Set packet count",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":clear",
            description: "Clear logs/captures",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":stats",
            description: "Show statistics",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":debug",
            description: "Toggle debug mode",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":packet",
            description: "Open packet editor",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":payload <hex>",
            description: "Set/show payload",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":srcport <n>",
            description: "Set source port",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":dstport <n>",
            description: "Set dest port",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":ttl <n>",
            description: "Set TTL (0-255)",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":seq <n>",
            description: "Set sequence number",
            category: HelpCategory::Commands,
        },
        HelpEntry {
            key: ":randseq",
            description: "Randomize seq number",
            category: HelpCategory::Commands,
        },
    ]
}

/// Render the help popup (which-key style)
pub fn render_help_popup(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate popup size (80% of screen, max 100x40)
    let popup_width = (area.width * 80 / 100).min(100);
    let popup_height = (area.height * 80 / 100).min(40);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block
    let block = Block::default()
        .title(" Keybindings ")
        .title_style(Style::default().fg(ACCENT_BRIGHT).bold())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::uniform(1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Split into columns for categories
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(inner);

    let entries = get_help_entries();

    // Use help_filter from app for filtering entries
    let filter = &app.help_filter;

    // Column 1: Navigation + Actions
    render_help_column(
        frame,
        columns[0],
        &entries,
        &[HelpCategory::Navigation, HelpCategory::Actions],
        filter,
    );

    // Column 2: Modes + Protocols
    render_help_column(
        frame,
        columns[1],
        &entries,
        &[HelpCategory::Modes, HelpCategory::Protocols],
        filter,
    );

    // Column 3: Scan Types + Commands
    render_help_column(
        frame,
        columns[2],
        &entries,
        &[HelpCategory::ScanTypes, HelpCategory::Commands],
        filter,
    );
}

/// Render a help column with multiple categories
fn render_help_column(
    frame: &mut Frame,
    area: Rect,
    entries: &[HelpEntry],
    categories: &[HelpCategory],
    filter: &str,
) {
    let mut lines: Vec<Line> = Vec::new();

    for (i, category) in categories.iter().enumerate() {
        // Filter entries by help_filter if set
        let filtered_entries: Vec<_> = entries.iter()
            .filter(|e| e.category == *category)
            .filter(|e| filter.is_empty() ||
                e.key.to_lowercase().contains(&filter.to_lowercase()) ||
                e.description.to_lowercase().contains(&filter.to_lowercase()))
            .collect();

        if filtered_entries.is_empty() {
            continue;
        }

        if i > 0 && !lines.is_empty() {
            lines.push(Line::from(""));
        }

        // Category header
        lines.push(Line::from(vec![
            Span::styled(
                format!("━━ {} ━━", category.name()),
                Style::default()
                    .fg(category.color())
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        // Entries for this category (filtered)
        for entry in filtered_entries {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:14}", entry.key),
                    Style::default().fg(ACCENT_BRIGHT),
                ),
                Span::styled(entry.description, Style::default().fg(FG_PRIMARY)),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

/// Render contextual help based on pending keys
pub fn render_key_hint(frame: &mut Frame, app: &App) {
    if app.pending_keys.is_empty() || !app.should_show_key_help() {
        return;
    }

    let pending: String = app.pending_keys.iter().collect();
    let area = frame.area();

    // Small popup near the bottom
    let popup_width = 40;
    let popup_height = 8;
    let popup_area = Rect {
        x: area.width.saturating_sub(popup_width + 2),
        y: area.height.saturating_sub(popup_height + 4),
        width: popup_width,
        height: popup_height,
    };

    frame.render_widget(Clear, popup_area);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Pending: ", Style::default().fg(FG_SECONDARY)),
            Span::styled(&pending, Style::default().fg(ACCENT_BRIGHT).bold()),
        ]),
        Line::from(""),
    ];

    // Show possible completions based on pending keys
    match pending.as_str() {
        "g" => {
            lines.push(Line::from(vec![
                Span::styled("g", Style::default().fg(ACCENT_BRIGHT)),
                Span::styled(" → Go to top", Style::default().fg(FG_PRIMARY)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Press ", Style::default().fg(FG_DIM)),
                Span::styled("Esc", Style::default().fg(FG_SECONDARY)),
                Span::styled(" to cancel", Style::default().fg(FG_DIM)),
            ]));
        }
        _ => {
            lines.push(Line::from(vec![
                Span::styled("Unknown sequence", Style::default().fg(FG_DIM)),
            ]));
        }
    }

    let block = Block::default()
        .title(" Which Key? ")
        .title_style(Style::default().fg(ACCENT))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .style(Style::default().bg(BG_COLOR));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, popup_area);
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
    fn test_help_entries_exist() {
        let entries = get_help_entries();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_help_categories() {
        let entries = get_help_entries();
        let nav_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.category == HelpCategory::Navigation)
            .collect();
        assert!(!nav_entries.is_empty());
    }

    #[test]
    fn test_centered_rect() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 50,
        };
        let centered = centered_rect(40, 20, area);

        assert_eq!(centered.x, 30);
        assert_eq!(centered.y, 15);
        assert_eq!(centered.width, 40);
        assert_eq!(centered.height, 20);
    }
}
