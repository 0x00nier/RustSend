//! TUI module - Terminal User Interface for NoirCast
//!
//! Provides the main event loop, terminal setup, and rendering
//! using Ratatui and Crossterm.

pub mod event;
pub mod handler;

use crate::app::App;
use crate::ui;
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::{stdout, Stdout};
use std::time::Duration;

/// Terminal type alias
type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initialize the terminal
fn init_terminal() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore the terminal to its original state
fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Main TUI run loop
pub async fn run(app: &mut App) -> Result<()> {
    // Initialize terminal
    let mut terminal = init_terminal()?;

    // Initialize packet sender
    if let Err(e) = app.init_sender().await {
        app.log_error(format!("Failed to initialize packet sender: {}", e));
    }

    app.log_info("NoirCast TUI initialized. Press '?' for help.");

    // Create event handler
    let mut events = event::EventHandler::new(Duration::from_millis(100));

    // Main loop
    let result = run_app(&mut terminal, app, &mut events).await;

    // Restore terminal on exit
    restore_terminal(&mut terminal)?;

    result
}

/// Run the application loop
async fn run_app(
    terminal: &mut Tui,
    app: &mut App,
    events: &mut event::EventHandler,
) -> Result<()> {
    while app.running {
        // Draw UI
        terminal.draw(|frame| {
            ui::render(frame, app);
        })?;

        // Handle flood mode - send packets continuously
        if app.flood_mode {
            if let Some(sender) = &app.packet_sender.clone() {
                // Send a burst of packets
                if let Some(ip) = app.target.ip {
                    let ports = app.target.ports.clone();
                    let scan_type = app.selected_scan_type;
                    let flags = app.selected_flags.clone();
                    // Send batch of packets (flood mode)
                    let _ = sender.send_batch(ip, &ports, scan_type, &flags).await;
                    // Count all packets sent in this batch
                    app.flood_count += ports.len() as u64;
                }
            }
        }

        // Handle events (non-blocking in flood mode)
        match events.next().await? {
            event::Event::Tick => {
                // Update application state on tick
                app.clear_expired_status();

                // Check for pending key timeouts
                if !app.pending_keys.is_empty()
                    && app.last_key_time.elapsed() > app.key_timeout
                {
                    app.clear_pending_keys();
                }

                // Update flood stats display
                if app.flood_mode {
                    let (count, duration, rate) = app.get_flood_stats();
                    app.set_status(
                        format!("FLOODING: {} pkts | {:.1}s | {:.0} pps", count, duration, rate),
                        crate::app::LogLevel::Warning,
                    );
                }
            }
            event::Event::Key(key_event) => {
                // In flood mode, 'q' stops the flood
                if app.flood_mode {
                    match key_event.code {
                        crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => {
                            app.stop_flood();
                        }
                        _ => {}
                    }
                } else {
                    handler::handle_key_event(app, key_event).await;
                }
            }
            event::Event::Mouse(mouse_event) => {
                handler::handle_mouse_event(app, mouse_event);
            }
            event::Event::Resize(width, height) => {
                tracing::debug!("Terminal resized to {}x{}", width, height);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // TUI tests are integration tests that require a terminal
    // These are placeholder tests for the module structure
    #[test]
    fn test_module_exists() {
        // Module compiles successfully
        assert!(true);
    }
}
