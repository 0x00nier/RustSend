//! Custom widgets for RustSend TUI

use ratatui::{
    layout::Rect,
    prelude::*,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};

/// A styled card widget with title and content
pub struct Card<'a> {
    title: &'a str,
    content: Vec<Line<'a>>,
    border_color: Color,
    is_active: bool,
}

impl<'a> Card<'a> {
    pub fn new(title: &'a str) -> Self {
        Self {
            title,
            content: Vec::new(),
            border_color: Color::DarkGray,
            is_active: false,
        }
    }

    pub fn content(mut self, content: Vec<Line<'a>>) -> Self {
        self.content = content;
        self
    }

    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = color;
        self
    }

    pub fn active(mut self, active: bool) -> Self {
        self.is_active = active;
        if active {
            self.border_color = Color::Cyan;
        }
        self
    }
}

impl<'a> Widget for Card<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_type = if self.is_active {
            BorderType::Double
        } else {
            BorderType::Rounded
        };

        let block = Block::default()
            .title(format!(" {} ", self.title))
            .title_style(
                Style::default()
                    .fg(if self.is_active { Color::Cyan } else { Color::White })
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(border_type)
            .border_style(Style::default().fg(self.border_color));

        let paragraph = Paragraph::new(self.content).block(block);
        paragraph.render(area, buf);
    }
}

/// A progress indicator widget
pub struct ProgressIndicator<'a> {
    label: &'a str,
    progress: f64, // 0.0 to 1.0
    color: Color,
    show_percentage: bool,
}

impl<'a> ProgressIndicator<'a> {
    pub fn new(label: &'a str, progress: f64) -> Self {
        Self {
            label,
            progress: progress.clamp(0.0, 1.0),
            color: Color::Green,
            show_percentage: true,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn show_percentage(mut self, show: bool) -> Self {
        self.show_percentage = show;
        self
    }
}

impl<'a> Widget for ProgressIndicator<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 1 {
            return;
        }

        // Label
        let label_width = self.label.len() as u16 + 2;
        buf.set_string(
            area.x,
            area.y,
            self.label,
            Style::default().fg(Color::White),
        );

        // Progress bar area
        let bar_start = area.x + label_width;
        let bar_width = if self.show_percentage {
            area.width.saturating_sub(label_width + 6)
        } else {
            area.width.saturating_sub(label_width + 1)
        };

        let filled_width = (bar_width as f64 * self.progress) as u16;

        // Draw bar background
        buf.set_string(
            bar_start,
            area.y,
            "░".repeat(bar_width as usize),
            Style::default().fg(Color::DarkGray),
        );

        // Draw filled portion
        buf.set_string(
            bar_start,
            area.y,
            "█".repeat(filled_width as usize),
            Style::default().fg(self.color),
        );

        // Draw percentage
        if self.show_percentage {
            let percentage = format!("{:3.0}%", self.progress * 100.0);
            buf.set_string(
                area.x + area.width.saturating_sub(4),
                area.y,
                &percentage,
                Style::default().fg(Color::White),
            );
        }
    }
}

/// A key-value display widget
pub struct KeyValue<'a> {
    items: Vec<(&'a str, String, Color)>,
}

impl<'a> KeyValue<'a> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn add(mut self, key: &'a str, value: impl Into<String>) -> Self {
        self.items.push((key, value.into(), Color::White));
        self
    }

    pub fn add_colored(mut self, key: &'a str, value: impl Into<String>, color: Color) -> Self {
        self.items.push((key, value.into(), color));
        self
    }
}

impl<'a> Widget for KeyValue<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let max_key_len = self
            .items
            .iter()
            .map(|(k, _, _)| k.len())
            .max()
            .unwrap_or(0) as u16;

        for (i, (key, value, color)) in self.items.iter().enumerate() {
            let y = area.y + i as u16;
            if y >= area.y + area.height {
                break;
            }

            // Key
            buf.set_string(
                area.x,
                y,
                key,
                Style::default().fg(Color::DarkGray),
            );

            // Separator
            buf.set_string(
                area.x + max_key_len + 1,
                y,
                ":",
                Style::default().fg(Color::DarkGray),
            );

            // Value
            buf.set_string(
                area.x + max_key_len + 3,
                y,
                value,
                Style::default().fg(*color),
            );
        }
    }
}

impl<'a> Default for KeyValue<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// A status badge widget
pub struct StatusBadge<'a> {
    text: &'a str,
    style: BadgeStyle,
}

#[derive(Clone, Copy)]
pub enum BadgeStyle {
    Success,
    Warning,
    Error,
    Info,
    Default,
}

impl<'a> StatusBadge<'a> {
    pub fn new(text: &'a str, style: BadgeStyle) -> Self {
        Self { text, style }
    }

    pub fn success(text: &'a str) -> Self {
        Self::new(text, BadgeStyle::Success)
    }

    pub fn warning(text: &'a str) -> Self {
        Self::new(text, BadgeStyle::Warning)
    }

    pub fn error(text: &'a str) -> Self {
        Self::new(text, BadgeStyle::Error)
    }

    pub fn info(text: &'a str) -> Self {
        Self::new(text, BadgeStyle::Info)
    }
}

impl<'a> Widget for StatusBadge<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (fg, bg) = match self.style {
            BadgeStyle::Success => (Color::Black, Color::Green),
            BadgeStyle::Warning => (Color::Black, Color::Yellow),
            BadgeStyle::Error => (Color::White, Color::Red),
            BadgeStyle::Info => (Color::White, Color::Blue),
            BadgeStyle::Default => (Color::White, Color::DarkGray),
        };

        let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);
        let text = format!(" {} ", self.text);
        buf.set_string(area.x, area.y, &text, style);
    }
}

/// A sparkline-style mini chart
pub struct MiniChart<'a> {
    data: &'a [f64],
    color: Color,
    max_value: Option<f64>,
}

impl<'a> MiniChart<'a> {
    pub fn new(data: &'a [f64]) -> Self {
        Self {
            data,
            color: Color::Cyan,
            max_value: None,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn max(mut self, max: f64) -> Self {
        self.max_value = Some(max);
        self
    }
}

impl<'a> Widget for MiniChart<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 1 || self.data.is_empty() {
            return;
        }

        let max = self
            .max_value
            .unwrap_or_else(|| self.data.iter().cloned().fold(f64::MIN, f64::max));

        if max <= 0.0 {
            return;
        }

        // Characters for different heights (8 levels)
        const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

        for (i, &value) in self.data.iter().enumerate() {
            let x = area.x + i as u16;
            if x >= area.x + area.width {
                break;
            }

            let normalized = (value / max).clamp(0.0, 1.0);
            let bar_idx = (normalized * 7.0) as usize;
            let bar_char = BARS[bar_idx];

            buf.set_string(x, area.y, bar_char.to_string(), Style::default().fg(self.color));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_indicator() {
        let progress = ProgressIndicator::new("Test", 0.5)
            .color(Color::Green)
            .show_percentage(true);

        assert_eq!(progress.progress, 0.5);
    }

    #[test]
    fn test_progress_clamping() {
        let progress = ProgressIndicator::new("Test", 1.5);
        assert_eq!(progress.progress, 1.0);

        let progress = ProgressIndicator::new("Test", -0.5);
        assert_eq!(progress.progress, 0.0);
    }

    #[test]
    fn test_key_value() {
        let kv = KeyValue::new()
            .add("Key1", "Value1")
            .add_colored("Key2", "Value2", Color::Green);

        assert_eq!(kv.items.len(), 2);
    }

    #[test]
    fn test_status_badge() {
        let badge = StatusBadge::success("OK");
        // Just verify it creates without panic
        assert!(matches!(badge.style, BadgeStyle::Success));
    }
}
