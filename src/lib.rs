//! RustSend Library
//!
//! A high-performance packet crafting and sending library for network security tools.
//! This module exposes the core functionality for use in benchmarks and external integrations.

pub mod app;
pub mod cli;
pub mod config;
pub mod logging;
pub mod network;
pub mod tui;
pub mod ui;

// Re-export Args for convenience
pub use cli::Args;
