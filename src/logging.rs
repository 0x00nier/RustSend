//! Logging configuration for NoirCast
//!
//! Provides structured logging with file output and optional debug mode

use crate::cli::Args;
use anyhow::Result;
use std::sync::OnceLock;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

pub fn init_logging(args: &Args) -> Result<()> {
    let log_level = if args.debug { "debug" } else { "info" };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("noircast={}", log_level)));

    // Get log directory and ensure it exists
    let default_dir = std::path::PathBuf::from(".");
    let log_dir = args.log_file
        .parent()
        .unwrap_or(&default_dir);

    // Create directory if it doesn't exist
    if !log_dir.as_os_str().is_empty() && log_dir != std::path::Path::new(".") {
        std::fs::create_dir_all(log_dir)?;
    }

    // Create file appender
    let file_appender = tracing_appender::rolling::daily(
        log_dir,
        args.log_file.file_name().unwrap_or_default(),
    );
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Store guard to keep logging alive
    let _ = LOG_GUARD.set(guard);

    // Build subscriber with file logging
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .init();

    Ok(())
}

#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}

#[macro_export]
macro_rules! info_log {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {
        tracing::error!($($arg)*)
    };
}
