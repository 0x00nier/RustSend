//! RustSend - A powerful TUI-based packet crafting and sending tool
//!
//! Features:
//! - Customizable packet crafting (TCP, UDP, ICMP, etc.)
//! - Vim-like navigation with which-key style help
//! - Multithreaded async packet sending
//! - Response tracking and retry functionality
//! - HTTP stream viewing

mod app;
mod cli;
mod config;
mod logging;
mod network;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    logging::init_logging(&args)?;

    tracing::info!("Starting RustSend v{}", env!("CARGO_PKG_VERSION"));
    tracing::debug!("Debug mode: {}", args.debug);
    tracing::debug!("Workers: {}, Batch size: {}", args.workers, args.batch_size);

    // Initialize and run the application
    let mut app = app::App::new(args)?;

    // Run the TUI
    tui::run(&mut app).await?;

    tracing::info!("RustSend shutdown complete");
    Ok(())
}
