//! Application state management for NoirCast

use crate::config::{Config, PacketTemplate, Protocol, ScanType, Target, TcpFlag};
use crate::network::packet::{PacketResponse, PacketStats};
use crate::network::sender::PacketSender;
use crate::cli::Args;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Direction of captured packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

impl std::fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketDirection::Sent => write!(f, "TX"),
            PacketDirection::Received => write!(f, "RX"),
        }
    }
}

/// Captured packet for display in capture pane
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are for detailed packet inspection (future feature)
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub direction: PacketDirection,
    pub protocol: Protocol,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub flags: Vec<TcpFlag>,
    pub flags_raw: u8,
    pub seq_num: Option<u32>,
    pub ack_num: Option<u32>,
    pub payload_size: usize,
    pub payload_preview: String,
    pub rtt_ms: Option<f64>,
    pub status: String,
}

/// Input mode for the TUI (vim-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Insert,
    Command,
    Help,
    Search,
}

impl std::fmt::Display for InputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputMode::Normal => write!(f, "NORMAL"),
            InputMode::Insert => write!(f, "INSERT"),
            InputMode::Command => write!(f, "COMMAND"),
            InputMode::Help => write!(f, "HELP"),
            InputMode::Search => write!(f, "SEARCH"),
        }
    }
}

/// Active pane in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivePane {
    #[default]
    PacketConfig,
    FlagSelection,
    TargetConfig,
    ResponseLog,
    PacketCapture,
    HttpStream,
    Statistics,
}

impl ActivePane {
    pub fn next(&self) -> Self {
        match self {
            ActivePane::PacketConfig => ActivePane::FlagSelection,
            ActivePane::FlagSelection => ActivePane::TargetConfig,
            ActivePane::TargetConfig => ActivePane::ResponseLog,
            ActivePane::ResponseLog => ActivePane::PacketCapture,
            ActivePane::PacketCapture => ActivePane::HttpStream,
            ActivePane::HttpStream => ActivePane::Statistics,
            ActivePane::Statistics => ActivePane::PacketConfig,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ActivePane::PacketConfig => ActivePane::Statistics,
            ActivePane::FlagSelection => ActivePane::PacketConfig,
            ActivePane::TargetConfig => ActivePane::FlagSelection,
            ActivePane::ResponseLog => ActivePane::TargetConfig,
            ActivePane::PacketCapture => ActivePane::ResponseLog,
            ActivePane::HttpStream => ActivePane::PacketCapture,
            ActivePane::Statistics => ActivePane::HttpStream,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ActivePane::PacketConfig => "Packet Config",
            ActivePane::FlagSelection => "TCP Flags",
            ActivePane::TargetConfig => "Target",
            ActivePane::ResponseLog => "Responses",
            ActivePane::PacketCapture => "Packet Capture",
            ActivePane::HttpStream => "HTTP Stream",
            ActivePane::Statistics => "Statistics",
        }
    }
}

/// HTTP Stream entry for viewing
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields for HTTP stream inspection (future feature)
pub struct HttpStreamEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub direction: HttpDirection,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants for HTTP stream direction (future feature)
pub enum HttpDirection {
    Request,
    Response,
}

/// Log entry for response tracking
#[derive(Debug, Clone)]
#[allow(dead_code)] // details field for expandable log entries (future feature)
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug,
}

impl LogLevel {
    pub fn symbol(&self) -> &'static str {
        match self {
            LogLevel::Info => "ℹ",
            LogLevel::Success => "✓",
            LogLevel::Warning => "⚠",
            LogLevel::Error => "✗",
            LogLevel::Debug => "⚙",
        }
    }
}

/// Session state for multi-window support
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are used for session state management (future feature)
pub struct Session {
    pub id: usize,
    pub name: String,
    pub target: Target,
    pub protocol: Protocol,
    pub scan_type: ScanType,
    pub flags: Vec<TcpFlag>,
    pub captured_packets: VecDeque<CapturedPacket>,
    pub logs: VecDeque<LogEntry>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            name: format!("Session {}", id + 1),
            target: Target::default(),
            protocol: Protocol::Tcp,
            scan_type: ScanType::SynScan,
            flags: vec![TcpFlag::Syn],
            captured_packets: VecDeque::new(),
            logs: VecDeque::new(),
            created_at: chrono::Utc::now(),
        }
    }
}

/// Packet sending job
#[derive(Debug, Clone)]
#[allow(dead_code)] // Job tracking fields for async job management (future feature)
pub struct SendJob {
    pub id: uuid::Uuid,
    pub target: Target,
    pub protocol: Protocol,
    pub scan_type: ScanType,
    pub flags: Vec<TcpFlag>,
    pub packet_count: usize,
    pub status: JobStatus,
    pub responses: Vec<PacketResponse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Job status variants for async job tracking (future feature)
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Pending => write!(f, "Pending"),
            JobStatus::Running => write!(f, "Running"),
            JobStatus::Completed => write!(f, "Completed"),
            JobStatus::Failed => write!(f, "Failed"),
            JobStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Main application state
pub struct App {
    // Application state
    pub running: bool,
    pub config: Config,
    pub args: Args,

    // TUI state
    pub input_mode: InputMode,
    pub active_pane: ActivePane,
    pub command_buffer: String,
    pub search_buffer: String,
    pub input_buffer: String,
    pub cursor_position: usize,

    // Help system (which-key style)
    pub show_help: bool,
    pub help_filter: String,
    pub pending_keys: Vec<char>,
    pub key_timeout: std::time::Duration,
    pub last_key_time: std::time::Instant,

    // Packet configuration
    pub selected_protocol: Protocol,
    pub selected_scan_type: ScanType,
    pub selected_flags: Vec<TcpFlag>,
    pub custom_payload: Option<Vec<u8>>,
    pub packet_count: usize,

    // ICMP-specific options
    pub icmp_type: u8,      // 8 = Echo Request, 0 = Echo Reply, etc.
    pub icmp_code: u8,      // Usually 0
    pub icmp_id: u16,       // Identifier
    pub icmp_seq: u16,      // Sequence number

    // DNS-specific options
    pub dns_query_type: u16,     // A=1, AAAA=28, MX=15, etc.
    pub dns_domain: String,       // Domain to query

    // HTTP-specific options
    pub http_method: String,      // GET, POST, HEAD, etc.
    pub http_path: String,        // Request path

    // Target configuration
    pub target: Target,
    pub target_input_field: TargetField,

    // Selection indices for lists
    pub flag_list_index: usize,
    pub scan_type_index: usize,
    pub protocol_index: usize,
    pub log_scroll: usize,
    pub http_scroll: usize,

    // Network state
    pub packet_sender: Option<Arc<PacketSender>>,
    pub stats: Arc<RwLock<PacketStats>>,

    // Response tracking
    pub responses: Arc<RwLock<VecDeque<PacketResponse>>>,
    pub max_responses: usize,

    // Jobs
    pub jobs: Vec<SendJob>,
    pub current_job: Option<uuid::Uuid>,

    // Logs
    pub logs: VecDeque<LogEntry>,
    pub max_logs: usize,

    // HTTP Stream
    pub http_stream: VecDeque<HttpStreamEntry>,
    pub max_http_entries: usize,

    // Packet Capture
    pub captured_packets: VecDeque<CapturedPacket>,
    pub max_captured: usize,
    pub capture_scroll: usize,
    pub capture_selected: usize,
    pub next_capture_id: u64,

    // Status message
    pub status_message: Option<(String, LogLevel)>,
    pub status_time: std::time::Instant,

    // Flood mode (like hping3 --flood)
    pub flood_mode: bool,
    pub flood_count: u64,       // packets sent in flood mode
    pub flood_rate: u64,        // target packets per second (0 = unlimited)
    pub flood_start: Option<std::time::Instant>,

    // Multi-session support (Space+n to create new session)
    pub sessions: Vec<Session>,
    pub active_session: usize,
    pub next_session_id: usize,

    // Statistics scroll for Statistics pane
    pub stats_scroll: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetField {
    #[default]
    Host,
    Port,
}

impl App {
    pub fn new(args: Args) -> Result<Self> {
        let config = Config::default();

        Ok(Self {
            running: true,
            config,
            args,

            input_mode: InputMode::Normal,
            active_pane: ActivePane::PacketConfig,
            command_buffer: String::new(),
            search_buffer: String::new(),
            input_buffer: String::new(),
            cursor_position: 0,

            show_help: false,
            help_filter: String::new(),
            pending_keys: Vec::new(),
            key_timeout: std::time::Duration::from_millis(500),
            last_key_time: std::time::Instant::now(),

            selected_protocol: Protocol::Tcp,
            selected_scan_type: ScanType::SynScan,
            selected_flags: vec![TcpFlag::Syn],
            custom_payload: None,
            packet_count: 1,

            // ICMP defaults
            icmp_type: 8,  // Echo Request
            icmp_code: 0,
            icmp_id: 1,
            icmp_seq: 1,

            // DNS defaults
            dns_query_type: 1,  // A record
            dns_domain: String::new(),

            // HTTP defaults
            http_method: "GET".to_string(),
            http_path: "/".to_string(),

            target: Target::default(),
            target_input_field: TargetField::Host,

            flag_list_index: 0,
            scan_type_index: 0,
            protocol_index: 0,
            log_scroll: 0,
            http_scroll: 0,

            packet_sender: None,
            stats: Arc::new(RwLock::new(PacketStats::default())),

            responses: Arc::new(RwLock::new(VecDeque::new())),
            max_responses: 1000,

            jobs: Vec::new(),
            current_job: None,

            logs: VecDeque::new(),
            max_logs: 500,

            http_stream: VecDeque::new(),
            max_http_entries: 100,

            captured_packets: VecDeque::new(),
            max_captured: 500,
            capture_scroll: 0,
            capture_selected: 0,
            next_capture_id: 1,

            status_message: None,
            status_time: std::time::Instant::now(),

            flood_mode: false,
            flood_count: 0,
            flood_rate: 0,  // unlimited by default
            flood_start: None,

            // Session management
            sessions: vec![Session::new(0)],
            active_session: 0,
            next_session_id: 1,

            // Stats scroll
            stats_scroll: 0,
        })
    }

    /// Initialize the packet sender
    pub async fn init_sender(&mut self) -> Result<()> {
        let sender = PacketSender::new(
            self.args.workers,
            self.args.batch_size,
            self.args.timeout,
        ).await?;
        self.packet_sender = Some(Arc::new(sender));
        self.log_info("Packet sender initialized");
        Ok(())
    }

    /// Add a log entry
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level,
            message: message.into(),
            details: None,
        };
        self.logs.push_back(entry);
        while self.logs.len() > self.max_logs {
            self.logs.pop_front();
        }
    }

    pub fn log_info(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Info, message);
    }

    pub fn log_success(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Success, message);
    }

    pub fn log_warning(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Warning, message);
    }

    pub fn log_error(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Error, message);
    }

    pub fn log_debug(&mut self, message: impl Into<String>) {
        if self.args.debug {
            self.log(LogLevel::Debug, message);
        }
    }

    /// Set status message
    pub fn set_status(&mut self, message: impl Into<String>, level: LogLevel) {
        self.status_message = Some((message.into(), level));
        self.status_time = std::time::Instant::now();
    }

    /// Clear status if expired
    pub fn clear_expired_status(&mut self) {
        if self.status_time.elapsed() > std::time::Duration::from_secs(5) {
            self.status_message = None;
        }
    }

    /// Toggle a TCP flag
    pub fn toggle_flag(&mut self, flag: TcpFlag) {
        if self.selected_flags.contains(&flag) {
            self.selected_flags.retain(|f| f != &flag);
        } else {
            self.selected_flags.push(flag);
        }
        self.selected_scan_type = ScanType::Custom;
    }

    /// Set scan type and update flags accordingly
    pub fn set_scan_type(&mut self, scan_type: ScanType) {
        self.selected_scan_type = scan_type;
        if scan_type != ScanType::Custom {
            self.selected_flags = scan_type.flags();
        }
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.selected_protocol = protocol;
        // Reset scan_type_index to prevent out-of-bounds when switching protocols
        self.scan_type_index = 0;
        self.log_info(format!("Protocol set to: {}", protocol));
    }

    /// Parse target from string (host:port or just host)
    pub fn parse_target(&mut self, input: &str) -> Result<()> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(());
        }

        if let Some((host, port_str)) = input.rsplit_once(':') {
            self.target.host = host.to_string();
            if let Ok(port) = port_str.parse::<u16>() {
                self.target.ports = vec![port];
            }
        } else {
            self.target.host = input.to_string();
        }

        // Try to parse the host (not original input) as IP address
        if let Ok(ip) = self.target.host.parse::<IpAddr>() {
            self.target.ip = Some(ip);
        }

        Ok(())
    }

    /// Get current flags as bitmask
    pub fn flags_bitmask(&self) -> u8 {
        self.selected_flags.iter().fold(0u8, |acc, f| acc | f.to_bit())
    }

    /// Get filtered scan types based on current protocol
    pub fn get_filtered_scan_types(&self) -> Vec<ScanType> {
        ScanType::all()
            .into_iter()
            .filter(|st| match self.selected_protocol {
                Protocol::Tcp => !matches!(st, ScanType::UdpScan),
                Protocol::Udp => matches!(st, ScanType::UdpScan),
                _ => true,
            })
            .collect()
    }

    /// Get count of filtered scan types for current protocol
    pub fn get_filtered_scan_types_count(&self) -> usize {
        match self.selected_protocol {
            Protocol::Tcp => ScanType::all().len() - 1, // Exclude UdpScan
            Protocol::Udp => 1, // Only UdpScan
            Protocol::Icmp => 5, // ICMP types
            Protocol::Dns => 6, // DNS query types
            Protocol::Http | Protocol::Https => 6, // HTTP methods
            Protocol::Ntp | Protocol::Raw => PacketTemplate::all().len(),
        }
    }

    /// Create a new send job
    pub fn create_job(&mut self) -> SendJob {
        let job = SendJob {
            id: uuid::Uuid::new_v4(),
            target: self.target.clone(),
            protocol: self.selected_protocol,
            scan_type: self.selected_scan_type,
            flags: self.selected_flags.clone(),
            packet_count: self.packet_count,
            status: JobStatus::Pending,
            responses: Vec::new(),
            created_at: chrono::Utc::now(),
        };
        self.jobs.push(job.clone());
        self.current_job = Some(job.id);
        job
    }

    /// Add HTTP stream entry
    pub fn add_http_entry(&mut self, entry: HttpStreamEntry) {
        self.http_stream.push_back(entry);
        while self.http_stream.len() > self.max_http_entries {
            self.http_stream.pop_front();
        }
    }

    /// Add response
    pub async fn add_response(&self, response: PacketResponse) {
        let mut responses = self.responses.write().await;
        responses.push_back(response);
        while responses.len() > self.max_responses {
            responses.pop_front();
        }
    }

    /// Add captured packet for display
    pub fn capture_packet(
        &mut self,
        direction: PacketDirection,
        protocol: Protocol,
        source_ip: Option<IpAddr>,
        source_port: Option<u16>,
        dest_ip: Option<IpAddr>,
        dest_port: Option<u16>,
        flags: Vec<TcpFlag>,
        flags_raw: u8,
        seq_num: Option<u32>,
        ack_num: Option<u32>,
        payload: &[u8],
        rtt_ms: Option<f64>,
        status: impl Into<String>,
    ) {
        let payload_preview = if payload.is_empty() {
            String::new()
        } else {
            let preview_bytes = &payload[..payload.len().min(32)];
            // Try to show as ASCII if printable, otherwise hex
            if preview_bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                String::from_utf8_lossy(preview_bytes).to_string()
            } else {
                preview_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
        };

        let packet = CapturedPacket {
            id: self.next_capture_id,
            timestamp: chrono::Utc::now(),
            direction,
            protocol,
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            flags,
            flags_raw,
            seq_num,
            ack_num,
            payload_size: payload.len(),
            payload_preview,
            rtt_ms,
            status: status.into(),
        };

        self.next_capture_id += 1;
        self.captured_packets.push_back(packet);
        while self.captured_packets.len() > self.max_captured {
            self.captured_packets.pop_front();
        }
    }

    /// Clear all captured packets
    pub fn clear_captures(&mut self) {
        self.captured_packets.clear();
        self.capture_scroll = 0;
        self.capture_selected = 0;
    }

    /// Get all protocols as list
    #[allow(dead_code)]
    pub fn protocols() -> Vec<Protocol> {
        vec![
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmp,
            Protocol::Http,
            Protocol::Https,
            Protocol::Dns,
            Protocol::Ntp,
            Protocol::Raw,
        ]
    }

    /// Check if key sequence should show help
    pub fn should_show_key_help(&self) -> bool {
        !self.pending_keys.is_empty() &&
            self.last_key_time.elapsed() > std::time::Duration::from_millis(200)
    }

    /// Clear pending keys
    pub fn clear_pending_keys(&mut self) {
        self.pending_keys.clear();
    }

    /// Add pending key
    pub fn add_pending_key(&mut self, key: char) {
        self.pending_keys.push(key);
        self.last_key_time = std::time::Instant::now();
    }

    /// Move selection up in current pane
    pub fn move_up(&mut self) {
        self.move_up_by(1);
    }

    /// Move selection up by a specified amount
    pub fn move_up_by(&mut self, amount: usize) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                self.flag_list_index = self.flag_list_index.saturating_sub(amount);
            }
            ActivePane::PacketConfig => {
                self.scan_type_index = self.scan_type_index.saturating_sub(amount);
            }
            ActivePane::ResponseLog => {
                self.log_scroll = self.log_scroll.saturating_sub(amount);
            }
            ActivePane::HttpStream => {
                self.http_scroll = self.http_scroll.saturating_sub(amount);
            }
            ActivePane::PacketCapture => {
                self.capture_scroll = self.capture_scroll.saturating_sub(amount);
            }
            ActivePane::Statistics => {
                self.stats_scroll = self.stats_scroll.saturating_sub(amount);
            }
            ActivePane::TargetConfig => {
                // No scrolling needed for target config
            }
        }
    }

    /// Move selection down in current pane
    pub fn move_down(&mut self) {
        self.move_down_by(1);
    }

    /// Move selection down by a specified amount
    pub fn move_down_by(&mut self, amount: usize) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                let max = TcpFlag::all().len().saturating_sub(1);
                self.flag_list_index = (self.flag_list_index + amount).min(max);
            }
            ActivePane::PacketConfig => {
                let max_scan = self.get_filtered_scan_types_count().saturating_sub(1);
                self.scan_type_index = (self.scan_type_index + amount).min(max_scan);
            }
            ActivePane::ResponseLog => {
                let max = self.logs.len().saturating_sub(1);
                self.log_scroll = (self.log_scroll + amount).min(max);
            }
            ActivePane::HttpStream => {
                let max = self.http_stream.len().saturating_sub(1);
                self.http_scroll = (self.http_scroll + amount).min(max);
            }
            ActivePane::PacketCapture => {
                let max = self.captured_packets.len().saturating_sub(1);
                self.capture_scroll = (self.capture_scroll + amount).min(max);
            }
            ActivePane::Statistics => {
                // Stats has max 20 or so lines typically
                let max = 20usize;
                self.stats_scroll = (self.stats_scroll + amount).min(max);
            }
            ActivePane::TargetConfig => {
                // No scrolling needed for target config
            }
        }
    }

    /// Page down (half page)
    pub fn page_down(&mut self) {
        self.move_down_by(10);
    }

    /// Page up (half page)
    pub fn page_up(&mut self) {
        self.move_up_by(10);
    }

    /// Handle selection in current pane
    #[allow(dead_code)]
    pub fn select(&mut self) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                let flags = TcpFlag::all();
                if let Some(flag) = flags.get(self.flag_list_index) {
                    self.toggle_flag(*flag);
                }
            }
            ActivePane::PacketConfig => {
                // Could toggle between protocol and scan type selection
            }
            _ => {}
        }
    }

    /// Start flood mode (like hping3 --flood)
    pub fn start_flood(&mut self) {
        self.flood_mode = true;
        self.flood_count = 0;
        self.flood_start = Some(std::time::Instant::now());
        self.log_warning("FLOOD MODE STARTED - Press 'q' to stop");
    }

    /// Stop flood mode
    pub fn stop_flood(&mut self) {
        if self.flood_mode {
            self.flood_mode = false;
            let duration = self.flood_start
                .map(|s| s.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            let rate = if duration > 0.0 {
                self.flood_count as f64 / duration
            } else {
                0.0
            };
            self.log_success(format!(
                "FLOOD STOPPED: {} packets in {:.2}s ({:.0} pps)",
                self.flood_count, duration, rate
            ));
            self.flood_start = None;
        }
    }

    /// Increment flood counter
    #[allow(dead_code)]
    pub fn increment_flood_count(&mut self) {
        self.flood_count += 1;
    }

    /// Get flood stats for display
    pub fn get_flood_stats(&self) -> (u64, f64, f64) {
        let duration = self.flood_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        let rate = if duration > 0.0 {
            self.flood_count as f64 / duration
        } else {
            0.0
        };
        (self.flood_count, duration, rate)
    }

    /// Quit the application
    pub fn quit(&mut self) {
        if self.flood_mode {
            self.stop_flood();
        }
        self.running = false;
    }

    /// Create a new session
    pub fn create_new_session(&mut self) {
        let new_session = Session::new(self.next_session_id);
        self.next_session_id += 1;
        self.sessions.push(new_session);
        self.active_session = self.sessions.len() - 1;
        self.log_success(format!("Created new session: Session {}", self.active_session + 1));
    }

    /// Switch to next session
    pub fn next_session(&mut self) {
        if self.sessions.len() > 1 {
            self.active_session = (self.active_session + 1) % self.sessions.len();
            self.log_info(format!("Switched to: Session {}", self.active_session + 1));
        }
    }

    /// Switch to previous session
    pub fn prev_session(&mut self) {
        if self.sessions.len() > 1 {
            if self.active_session == 0 {
                self.active_session = self.sessions.len() - 1;
            } else {
                self.active_session -= 1;
            }
            self.log_info(format!("Switched to: Session {}", self.active_session + 1));
        }
    }

    /// Close current session (if more than one exists)
    pub fn close_session(&mut self) {
        if self.sessions.len() > 1 {
            let closed_id = self.active_session;
            self.sessions.remove(self.active_session);
            if self.active_session >= self.sessions.len() {
                self.active_session = self.sessions.len() - 1;
            }
            self.log_info(format!("Closed session {}, now on Session {}", closed_id + 1, self.active_session + 1));
        } else {
            self.log_warning("Cannot close last session");
        }
    }

    /// Get current session count
    #[allow(dead_code)]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get current session name
    #[allow(dead_code)]
    pub fn current_session_name(&self) -> &str {
        self.sessions.get(self.active_session)
            .map(|s| s.name.as_str())
            .unwrap_or("Session 1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args() -> Args {
        Args {
            debug: false,
            log_file: std::path::PathBuf::from("test.log"),
            workers: 4,
            batch_size: 100,
            timeout: 1000,
            host: None,
            port: None,
        }
    }

    #[test]
    fn test_app_creation() {
        let args = create_test_args();
        let app = App::new(args).unwrap();
        assert!(app.running);
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    #[test]
    fn test_flag_toggle() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.selected_flags.clear();
        app.toggle_flag(TcpFlag::Syn);
        assert!(app.selected_flags.contains(&TcpFlag::Syn));

        app.toggle_flag(TcpFlag::Syn);
        assert!(!app.selected_flags.contains(&TcpFlag::Syn));
    }

    #[test]
    fn test_scan_type_flags() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.set_scan_type(ScanType::XmasScan);
        assert!(app.selected_flags.contains(&TcpFlag::Fin));
        assert!(app.selected_flags.contains(&TcpFlag::Psh));
        assert!(app.selected_flags.contains(&TcpFlag::Urg));
    }

    #[test]
    fn test_flags_bitmask() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.selected_flags = vec![TcpFlag::Syn, TcpFlag::Ack];
        let bitmask = app.flags_bitmask();
        assert_eq!(bitmask, 0x02 | 0x10); // SYN | ACK
    }

    #[test]
    fn test_pane_navigation() {
        assert_eq!(ActivePane::PacketConfig.next(), ActivePane::FlagSelection);
        assert_eq!(ActivePane::Statistics.next(), ActivePane::PacketConfig);
        assert_eq!(ActivePane::PacketConfig.prev(), ActivePane::Statistics);
    }

    #[test]
    fn test_parse_target() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.parse_target("192.168.1.1:80").unwrap();
        assert_eq!(app.target.host, "192.168.1.1");
        assert_eq!(app.target.ports, vec![80]);
    }

    #[test]
    fn test_logging() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.log_info("Test message");
        assert_eq!(app.logs.len(), 1);
        assert_eq!(app.logs[0].level, LogLevel::Info);
    }
}
