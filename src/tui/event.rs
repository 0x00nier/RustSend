//! Event handling for the TUI
//!
//! Provides async event handling using crossterm's event stream

use anyhow::Result;
use crossterm::event::{Event as CrosstermEvent, KeyEvent, MouseEvent};
use futures::{FutureExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;

/// Terminal events
#[derive(Debug, Clone)]
pub enum Event {
    /// Terminal tick (for animations and updates)
    Tick,
    /// Key press event
    Key(KeyEvent),
    /// Mouse event
    Mouse(MouseEvent),
    /// Terminal resize event
    Resize(u16, u16),
}

/// Event handler that manages terminal events
pub struct EventHandler {
    /// Event receiver
    rx: mpsc::UnboundedReceiver<Event>,
    /// Tick rate
    _tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler with the specified tick rate
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn event polling task
        let tick_rate_clone = tick_rate;
        tokio::spawn(async move {
            let mut reader = crossterm::event::EventStream::new();
            let mut tick_interval = tokio::time::interval(tick_rate_clone);

            loop {
                let tick_delay = tick_interval.tick();
                let crossterm_event = reader.next().fuse();

                tokio::select! {
                    _ = tick_delay => {
                        if tx.send(Event::Tick).is_err() {
                            break;
                        }
                    }
                    Some(Ok(event)) = crossterm_event => {
                        let event = match event {
                            CrosstermEvent::Key(key) => Event::Key(key),
                            CrosstermEvent::Mouse(mouse) => Event::Mouse(mouse),
                            CrosstermEvent::Resize(w, h) => Event::Resize(w, h),
                            _ => continue,
                        };
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            rx,
            _tick_rate: tick_rate,
        }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Result<Event> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_variants() {
        // Verify event enum variants exist
        let _tick = Event::Tick;
        let _resize = Event::Resize(80, 24);
    }
}
