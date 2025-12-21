//! Command-line argument parsing for NoirCast

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "noircast")]
#[command(author = "NoirCast Contributors")]
#[command(version = "0.1.0")]
#[command(about = "A powerful TUI-based packet crafting and sending tool", long_about = None)]
pub struct Args {
    /// Enable debug logging
    #[arg(short, long, default_value_t = false)]
    pub debug: bool,

    /// Log file path
    #[arg(short, long, default_value = "noircast.log")]
    pub log_file: PathBuf,

    /// Number of worker threads for packet sending
    #[arg(short = 'w', long, default_value_t = num_cpus())]
    pub workers: usize,

    /// Batch size for concurrent packet sending
    #[arg(short, long, default_value_t = 1000)]
    pub batch_size: usize,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 3000)]
    pub timeout: u64,

    /// Target host (optional, can be set in TUI)
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// Target port (optional, can be set in TUI)
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            debug: false,
            log_file: PathBuf::from("noircast.log"),
            workers: num_cpus(),
            batch_size: 1000,
            timeout: 3000,
            host: None,
            port: None,
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
