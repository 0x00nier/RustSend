//! Packet crafting and building module
//!
//! Provides structures and builders for crafting custom network packets
//! including TCP, UDP, ICMP, and other protocols.

use crate::config::{Protocol, TcpFlag};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::udp::{self, MutableUdpPacket};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// TCP Options per RFC 793/7323
/// These options are placed in the TCP header after the standard 20 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    /// End of options list (Kind=0)
    End,
    /// No-operation padding (Kind=1)
    Nop,
    /// Maximum Segment Size (Kind=2, Length=4)
    /// Used during connection setup to specify max segment size
    Mss(u16),
    /// Window Scale factor (Kind=3, Length=3)
    /// Allows window sizes larger than 64KB (shift count 0-14)
    WindowScale(u8),
    /// SACK Permitted (Kind=4, Length=2)
    /// Indicates selective acknowledgment support
    SackPermitted,
    /// Selective Acknowledgment (Kind=5, Length=variable)
    /// Contains blocks of (left_edge, right_edge) for out-of-order data
    Sack(Vec<(u32, u32)>),
    /// Timestamps (Kind=8, Length=10)
    /// Used for RTT calculation and PAWS (Protection Against Wrapped Sequences)
    Timestamps {
        /// Timestamp value (sender's timestamp)
        tsval: u32,
        /// Timestamp echo reply (echoed from peer)
        tsecr: u32,
    },
}

impl TcpOption {
    /// Get the kind byte for this option
    pub fn kind(&self) -> u8 {
        match self {
            TcpOption::End => 0,
            TcpOption::Nop => 1,
            TcpOption::Mss(_) => 2,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 4,
            TcpOption::Sack(_) => 5,
            TcpOption::Timestamps { .. } => 8,
        }
    }

    /// Get the display name for this option
    pub fn name(&self) -> &'static str {
        match self {
            TcpOption::End => "End",
            TcpOption::Nop => "NOP",
            TcpOption::Mss(_) => "MSS",
            TcpOption::WindowScale(_) => "Window Scale",
            TcpOption::SackPermitted => "SACK Permitted",
            TcpOption::Sack(_) => "SACK",
            TcpOption::Timestamps { .. } => "Timestamps",
        }
    }

    /// Encode this option to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TcpOption::End => vec![0],
            TcpOption::Nop => vec![1],
            TcpOption::Mss(mss) => {
                let mut bytes = vec![2, 4];
                bytes.extend_from_slice(&mss.to_be_bytes());
                bytes
            }
            TcpOption::WindowScale(shift) => vec![3, 3, *shift],
            TcpOption::SackPermitted => vec![4, 2],
            TcpOption::Sack(blocks) => {
                let mut bytes = vec![5, 2 + (blocks.len() * 8) as u8];
                for (left, right) in blocks {
                    bytes.extend_from_slice(&left.to_be_bytes());
                    bytes.extend_from_slice(&right.to_be_bytes());
                }
                bytes
            }
            TcpOption::Timestamps { tsval, tsecr } => {
                let mut bytes = vec![8, 10];
                bytes.extend_from_slice(&tsval.to_be_bytes());
                bytes.extend_from_slice(&tsecr.to_be_bytes());
                bytes
            }
        }
    }

    /// Get all standard option types for display
    pub fn all_types() -> Vec<&'static str> {
        vec!["MSS", "Window Scale", "SACK Permitted", "Timestamps"]
    }
}

/// Encode a list of TCP options to bytes, padded to 4-byte boundary
pub fn encode_tcp_options(options: &[TcpOption]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for opt in options {
        bytes.extend(opt.encode());
    }
    // Pad to 4-byte boundary with NOPs
    while bytes.len() % 4 != 0 {
        bytes.push(1); // NOP padding
    }
    bytes
}

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Invalid packet size: expected at least {expected} bytes, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    #[error("Failed to build {packet_type} packet: {details}")]
    BuildError { packet_type: String, details: String },

    #[error("Invalid IP address '{address}': {reason}")]
    InvalidAddress { address: String, reason: String },

    #[error("Protocol not supported: {0}")]
    UnsupportedProtocol(String),

    #[error("Checksum calculation failed for {packet_type}")]
    ChecksumError { packet_type: String },

    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },
}

impl PacketError {
    pub fn build_error(packet_type: impl Into<String>, details: impl Into<String>) -> Self {
        PacketError::BuildError {
            packet_type: packet_type.into(),
            details: details.into()
        }
    }

    pub fn buffer_too_small(needed: usize, available: usize) -> Self {
        PacketError::BufferTooSmall { needed, available }
    }
}

/// Statistics for packet operations
#[derive(Debug, Clone, Default)]
pub struct PacketStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub retries: u64,
    pub open_ports: u64,
    pub closed_ports: u64,
    pub filtered_ports: u64,
    pub avg_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
}

impl PacketStats {
    pub fn record_sent(&mut self, bytes: u64) {
        self.packets_sent += 1;
        self.bytes_sent += bytes;
    }

    pub fn record_received(&mut self, bytes: u64, rtt_ms: f64) {
        self.packets_received += 1;
        self.bytes_received += bytes;

        // Update RTT statistics
        if self.packets_received == 1 {
            self.avg_rtt_ms = rtt_ms;
            self.min_rtt_ms = rtt_ms;
            self.max_rtt_ms = rtt_ms;
        } else {
            self.avg_rtt_ms = (self.avg_rtt_ms * (self.packets_received - 1) as f64 + rtt_ms)
                / self.packets_received as f64;
            self.min_rtt_ms = self.min_rtt_ms.min(rtt_ms);
            self.max_rtt_ms = self.max_rtt_ms.max(rtt_ms);
        }
    }

    pub fn record_failed(&mut self) {
        self.packets_failed += 1;
    }

    pub fn record_retry(&mut self) {
        self.retries += 1;
    }

    pub fn success_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_received as f64 / self.packets_sent as f64 * 100.0
        }
    }
}

/// Response from a sent packet
#[derive(Debug, Clone)]
pub struct PacketResponse {
    pub id: uuid::Uuid,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: Protocol,
    pub status: ResponseStatus,
    pub flags_received: Option<Vec<TcpFlag>>,
    pub rtt_ms: Option<f64>,
    pub raw_response: Option<Vec<u8>>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unfiltered,
    NoResponse,
    Error,
}

impl std::fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseStatus::Open => write!(f, "Open"),
            ResponseStatus::Closed => write!(f, "Closed"),
            ResponseStatus::Filtered => write!(f, "Filtered"),
            ResponseStatus::OpenFiltered => write!(f, "Open|Filtered"),
            ResponseStatus::Unfiltered => write!(f, "Unfiltered"),
            ResponseStatus::NoResponse => write!(f, "No Response"),
            ResponseStatus::Error => write!(f, "Error"),
        }
    }
}

/// TCP packet builder
#[derive(Debug, Clone)]
pub struct TcpPacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    urgent_ptr: u16,
    payload: Vec<u8>,
    ttl: u8,
    // IP fragmentation fields (RFC 791)
    ip_flags: u8,           // Bit 1: DF (Don't Fragment), Bit 2: MF (More Fragments)
    fragment_offset: u16,   // Fragment offset in 8-byte units (13 bits, max 8191)
    ip_id: u16,             // Identification for fragment reassembly
    // IP header extensions
    dscp: u8,               // Differentiated Services Code Point (6 bits)
    ecn: u8,                // Explicit Congestion Notification (2 bits)
    // TCP Options (RFC 793/7323)
    tcp_options: Vec<TcpOption>,
}

impl TcpPacketBuilder {
    pub fn new() -> Self {
        Self {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
            source_port: 0,
            dest_port: 80,
            flags: 0,
            seq_num: rand::random(),
            ack_num: 0,
            window: 65535,
            urgent_ptr: 0,
            payload: Vec::new(),
            ttl: 64,
            ip_flags: 0,
            fragment_offset: 0,
            ip_id: rand::random(),
            dscp: 0,
            ecn: 0,
            tcp_options: Vec::new(),
        }
    }

    pub fn source_ip(mut self, ip: Ipv4Addr) -> Self {
        self.source_ip = ip;
        self
    }

    pub fn dest_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dest_ip = ip;
        self
    }

    pub fn source_port(mut self, port: u16) -> Self {
        self.source_port = port;
        self
    }

    pub fn dest_port(mut self, port: u16) -> Self {
        self.dest_port = port;
        self
    }

    pub fn flags(mut self, flags: &[TcpFlag]) -> Self {
        self.flags = flags.iter().fold(0u8, |acc, f| acc | f.to_bit());
        self
    }

    pub fn flags_raw(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn syn(mut self) -> Self {
        self.flags |= TcpFlags::SYN as u8;
        self
    }

    pub fn ack(mut self) -> Self {
        self.flags |= TcpFlags::ACK as u8;
        self
    }

    pub fn fin(mut self) -> Self {
        self.flags |= TcpFlags::FIN as u8;
        self
    }

    pub fn rst(mut self) -> Self {
        self.flags |= TcpFlags::RST as u8;
        self
    }

    pub fn psh(mut self) -> Self {
        self.flags |= TcpFlags::PSH as u8;
        self
    }

    pub fn urg(mut self) -> Self {
        self.flags |= TcpFlags::URG as u8;
        self
    }

    pub fn xmas(mut self) -> Self {
        self.flags = TcpFlags::FIN as u8 | TcpFlags::PSH as u8 | TcpFlags::URG as u8;
        self
    }

    pub fn null(mut self) -> Self {
        self.flags = 0;
        self
    }

    pub fn seq_num(mut self, seq: u32) -> Self {
        self.seq_num = seq;
        self
    }

    pub fn ack_num(mut self, ack: u32) -> Self {
        self.ack_num = ack;
        self
    }

    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Set IP flags (RFC 791: Bit 1 = DF, Bit 2 = MF)
    pub fn ip_flags(mut self, flags: u8) -> Self {
        self.ip_flags = flags & 0x07; // Only 3 bits valid
        self
    }

    /// Set Don't Fragment flag
    pub fn dont_fragment(mut self) -> Self {
        self.ip_flags |= 0x02;
        self
    }

    /// Set More Fragments flag
    pub fn more_fragments(mut self) -> Self {
        self.ip_flags |= 0x01;
        self
    }

    /// Set fragment offset (in 8-byte units, max 8191)
    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset & 0x1FFF; // 13 bits max
        self
    }

    /// Set IP identification for fragment reassembly
    pub fn ip_id(mut self, id: u16) -> Self {
        self.ip_id = id;
        self
    }

    /// Set DSCP (Differentiated Services Code Point, 6 bits)
    pub fn dscp(mut self, dscp: u8) -> Self {
        self.dscp = dscp & 0x3F; // 6 bits
        self
    }

    /// Set ECN (Explicit Congestion Notification, 2 bits)
    pub fn ecn(mut self, ecn: u8) -> Self {
        self.ecn = ecn & 0x03; // 2 bits
        self
    }

    /// Set TCP options (RFC 793/7323)
    pub fn tcp_options(mut self, options: Vec<TcpOption>) -> Self {
        self.tcp_options = options;
        self
    }

    /// Add a single TCP option
    pub fn add_tcp_option(mut self, option: TcpOption) -> Self {
        self.tcp_options.push(option);
        self
    }

    /// Set common SYN options (MSS, Window Scale, SACK Permitted, Timestamps)
    pub fn syn_options(mut self, mss: u16, window_scale: u8, tsval: u32) -> Self {
        self.tcp_options = vec![
            TcpOption::Mss(mss),
            TcpOption::WindowScale(window_scale),
            TcpOption::SackPermitted,
            TcpOption::Timestamps { tsval, tsecr: 0 },
        ];
        self
    }

    /// Build the TCP packet with IP header
    pub fn build(&self) -> Result<Vec<u8>, PacketError> {
        // Encode TCP options and calculate header length
        let options_bytes = encode_tcp_options(&self.tcp_options);
        let options_len = options_bytes.len();
        let tcp_header_len = 20 + options_len; // Base TCP header + options
        let data_offset = (tcp_header_len / 4) as u8; // Data offset in 32-bit words

        // Validate data offset (must be 5-15)
        if data_offset < 5 || data_offset > 15 {
            return Err(PacketError::build_error("TCP", format!(
                "Invalid data offset {}: TCP options too large ({} bytes)",
                data_offset, options_len
            )));
        }

        let tcp_total_len = tcp_header_len + self.payload.len(); // TCP header + options + payload
        let ip_len = 20 + tcp_total_len; // IP header + TCP

        let mut buffer = vec![0u8; ip_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..])
                .ok_or_else(|| PacketError::build_error("IPv4", "Buffer too small for IP header"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(self.dscp);
            ip_packet.set_ecn(self.ecn);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(self.ip_id);
            ip_packet.set_flags(self.ip_flags);
            ip_packet.set_fragment_offset(self.fragment_offset);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);

            let checksum = ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build TCP header with options
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[20..])
                .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP header"))?;

            tcp_packet.set_source(self.source_port);
            tcp_packet.set_destination(self.dest_port);
            tcp_packet.set_sequence(self.seq_num);
            tcp_packet.set_acknowledgement(self.ack_num);
            tcp_packet.set_data_offset(data_offset);
            tcp_packet.set_reserved(0);
            tcp_packet.set_flags(self.flags);
            tcp_packet.set_window(self.window);
            tcp_packet.set_urgent_ptr(self.urgent_ptr);

            // Write options bytes directly after the 20-byte TCP header
            // pnet's set_options expects pnet::TcpOption, so we write raw bytes
            if !options_bytes.is_empty() {
                buffer[40..40 + options_len].copy_from_slice(&options_bytes);
            }

            // Write payload after options
            let payload_start = 40 + options_len;
            buffer[payload_start..payload_start + self.payload.len()].copy_from_slice(&self.payload);

            // Recalculate checksum with the full TCP segment (header + options + payload)
            let tcp_packet = MutableTcpPacket::new(&mut buffer[20..])
                .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP checksum"))?;
            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &self.dest_ip);
            // Write checksum at offset 16-17 in TCP header (bytes 36-37 in full packet)
            buffer[36..38].copy_from_slice(&checksum.to_be_bytes());
        }

        Ok(buffer)
    }

    /// Build just the TCP segment (without IP header)
    pub fn build_segment(&self) -> Result<Vec<u8>, PacketError> {
        let options_bytes = encode_tcp_options(&self.tcp_options);
        let tcp_header_len = 20 + options_bytes.len();
        let tcp_len = tcp_header_len + self.payload.len();
        let mut buffer = vec![0u8; tcp_len];
        self.build_segment_into(&mut buffer)?;
        Ok(buffer)
    }

    /// Build TCP segment into an existing buffer
    /// Returns an error if the buffer is too small
    pub fn build_segment_into(&self, buffer: &mut [u8]) -> Result<usize, PacketError> {
        let options_bytes = encode_tcp_options(&self.tcp_options);
        let options_len = options_bytes.len();
        let tcp_header_len = 20 + options_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let tcp_len = tcp_header_len + self.payload.len();

        if buffer.len() < tcp_len {
            return Err(PacketError::buffer_too_small(tcp_len, buffer.len()));
        }

        {
            let mut tcp_packet = MutableTcpPacket::new(buffer)
                .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP header"))?;

            tcp_packet.set_source(self.source_port);
            tcp_packet.set_destination(self.dest_port);
            tcp_packet.set_sequence(self.seq_num);
            tcp_packet.set_acknowledgement(self.ack_num);
            tcp_packet.set_data_offset(data_offset);
            tcp_packet.set_reserved(0);
            tcp_packet.set_flags(self.flags);
            tcp_packet.set_window(self.window);
            tcp_packet.set_urgent_ptr(self.urgent_ptr);
        }

        // Write options bytes directly after the 20-byte TCP header
        if !options_bytes.is_empty() {
            buffer[20..20 + options_len].copy_from_slice(&options_bytes);
        }

        // Write payload after options
        let payload_start = 20 + options_len;
        buffer[payload_start..payload_start + self.payload.len()].copy_from_slice(&self.payload);

        // Recalculate checksum with the full TCP segment
        let tcp_packet = MutableTcpPacket::new(buffer)
            .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP checksum"))?;
        let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &self.dest_ip);
        // Write checksum at offset 16-17 in TCP header
        buffer[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(tcp_len)
    }
}

impl Default for TcpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// UDP packet builder
#[derive(Debug, Clone)]
pub struct UdpPacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: Vec<u8>,
    ttl: u8,
    // IP fragmentation fields (RFC 791)
    ip_flags: u8,
    fragment_offset: u16,
    ip_id: u16,
    dscp: u8,
    ecn: u8,
}

impl UdpPacketBuilder {
    pub fn new() -> Self {
        Self {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
            source_port: 0,
            dest_port: 53,
            payload: Vec::new(),
            ttl: 64,
            ip_flags: 0,
            fragment_offset: 0,
            ip_id: rand::random(),
            dscp: 0,
            ecn: 0,
        }
    }

    pub fn source_ip(mut self, ip: Ipv4Addr) -> Self {
        self.source_ip = ip;
        self
    }

    pub fn dest_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dest_ip = ip;
        self
    }

    pub fn source_port(mut self, port: u16) -> Self {
        self.source_port = port;
        self
    }

    pub fn dest_port(mut self, port: u16) -> Self {
        self.dest_port = port;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Set IP flags (RFC 791: Bit 1 = DF, Bit 2 = MF)
    pub fn ip_flags(mut self, flags: u8) -> Self {
        self.ip_flags = flags & 0x07;
        self
    }

    /// Set Don't Fragment flag
    pub fn dont_fragment(mut self) -> Self {
        self.ip_flags |= 0x02;
        self
    }

    /// Set More Fragments flag
    pub fn more_fragments(mut self) -> Self {
        self.ip_flags |= 0x01;
        self
    }

    /// Set fragment offset (in 8-byte units, max 8191)
    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset & 0x1FFF;
        self
    }

    /// Set IP identification for fragment reassembly
    pub fn ip_id(mut self, id: u16) -> Self {
        self.ip_id = id;
        self
    }

    /// Set DSCP (6 bits)
    pub fn dscp(mut self, dscp: u8) -> Self {
        self.dscp = dscp & 0x3F;
        self
    }

    /// Set ECN (2 bits)
    pub fn ecn(mut self, ecn: u8) -> Self {
        self.ecn = ecn & 0x03;
        self
    }

    /// Build UDP packet with IP header
    pub fn build(&self) -> Result<Vec<u8>, PacketError> {
        let udp_len = 8 + self.payload.len(); // UDP header + payload
        let ip_len = 20 + udp_len;

        let mut buffer = vec![0u8; ip_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..])
                .ok_or_else(|| PacketError::build_error("IPv4", "Buffer too small for IP header"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(self.dscp);
            ip_packet.set_ecn(self.ecn);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(self.ip_id);
            ip_packet.set_flags(self.ip_flags);
            ip_packet.set_fragment_offset(self.fragment_offset);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);

            let checksum = ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build UDP header
        {
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[20..])
                .ok_or_else(|| PacketError::build_error("UDP", "Buffer too small for UDP header"))?;

            udp_packet.set_source(self.source_port);
            udp_packet.set_destination(self.dest_port);
            udp_packet.set_length(udp_len as u16);
            udp_packet.set_payload(&self.payload);

            let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &self.source_ip, &self.dest_ip);
            udp_packet.set_checksum(checksum);
        }

        Ok(buffer)
    }
}

impl Default for UdpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// ICMP packet builder
#[derive(Debug, Clone)]
pub struct IcmpPacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
    ttl: u8,
    // IP fragmentation fields (RFC 791)
    ip_flags: u8,
    fragment_offset: u16,
    ip_id: u16,
    dscp: u8,
    ecn: u8,
}

impl IcmpPacketBuilder {
    pub fn new() -> Self {
        Self {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
            icmp_type: 8, // Echo Request
            icmp_code: 0,
            identifier: rand::random(),
            sequence: 1,
            payload: Vec::new(),
            ttl: 64,
            ip_flags: 0,
            fragment_offset: 0,
            ip_id: rand::random(),
            dscp: 0,
            ecn: 0,
        }
    }

    pub fn source_ip(mut self, ip: Ipv4Addr) -> Self {
        self.source_ip = ip;
        self
    }

    pub fn dest_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dest_ip = ip;
        self
    }

    pub fn echo_request(mut self) -> Self {
        self.icmp_type = 8;
        self.icmp_code = 0;
        self
    }

    pub fn echo_reply(mut self) -> Self {
        self.icmp_type = 0;
        self.icmp_code = 0;
        self
    }

    pub fn icmp_type(mut self, t: u8) -> Self {
        self.icmp_type = t;
        self
    }

    pub fn icmp_code(mut self, c: u8) -> Self {
        self.icmp_code = c;
        self
    }

    pub fn identifier(mut self, id: u16) -> Self {
        self.identifier = id;
        self
    }

    pub fn sequence(mut self, seq: u16) -> Self {
        self.sequence = seq;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Set IP flags (RFC 791: Bit 1 = DF, Bit 2 = MF)
    pub fn ip_flags(mut self, flags: u8) -> Self {
        self.ip_flags = flags & 0x07;
        self
    }

    /// Set Don't Fragment flag
    pub fn dont_fragment(mut self) -> Self {
        self.ip_flags |= 0x02;
        self
    }

    /// Set More Fragments flag
    pub fn more_fragments(mut self) -> Self {
        self.ip_flags |= 0x01;
        self
    }

    /// Set fragment offset (in 8-byte units, max 8191)
    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset & 0x1FFF;
        self
    }

    /// Set IP identification for fragment reassembly
    pub fn ip_id(mut self, id: u16) -> Self {
        self.ip_id = id;
        self
    }

    /// Set DSCP (6 bits)
    pub fn dscp(mut self, dscp: u8) -> Self {
        self.dscp = dscp & 0x3F;
        self
    }

    /// Set ECN (2 bits)
    pub fn ecn(mut self, ecn: u8) -> Self {
        self.ecn = ecn & 0x03;
        self
    }

    /// Build ICMP packet with IP header
    pub fn build(&self) -> Result<Vec<u8>, PacketError> {
        let icmp_len = 8 + self.payload.len(); // ICMP header + payload
        let ip_len = 20 + icmp_len;

        let mut buffer = vec![0u8; ip_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..])
                .ok_or_else(|| PacketError::build_error("IPv4", "Buffer too small for IP header"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(self.dscp);
            ip_packet.set_ecn(self.ecn);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(self.ip_id);
            ip_packet.set_flags(self.ip_flags);
            ip_packet.set_fragment_offset(self.fragment_offset);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);

            let checksum = ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build ICMP header manually to avoid borrow issues
        // ICMP Type (1 byte)
        buffer[20] = self.icmp_type;
        // ICMP Code (1 byte)
        buffer[21] = self.icmp_code;
        // Checksum placeholder (2 bytes) - will calculate after
        buffer[22] = 0;
        buffer[23] = 0;
        // Identifier (2 bytes)
        buffer[24..26].copy_from_slice(&self.identifier.to_be_bytes());
        // Sequence (2 bytes)
        buffer[26..28].copy_from_slice(&self.sequence.to_be_bytes());

        // Copy payload
        if !self.payload.is_empty() {
            buffer[28..28 + self.payload.len()].copy_from_slice(&self.payload);
        }

        // Calculate ICMP checksum over the ICMP portion
        let checksum = Self::calculate_icmp_checksum(&buffer[20..]);
        buffer[22..24].copy_from_slice(&checksum.to_be_bytes());

        Ok(buffer)
    }

    /// Calculate ICMP checksum
    fn calculate_icmp_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() - 1 {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }

        if data.len() % 2 == 1 {
            sum += (data[data.len() - 1] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }
}

impl Default for IcmpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic packet builder that can create various packet types
pub struct PacketBuilder;

impl PacketBuilder {
    pub fn tcp() -> TcpPacketBuilder {
        TcpPacketBuilder::new()
    }

    pub fn udp() -> UdpPacketBuilder {
        UdpPacketBuilder::new()
    }

    pub fn icmp() -> IcmpPacketBuilder {
        IcmpPacketBuilder::new()
    }

    /// Create a TCP SYN packet
    pub fn syn_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Result<Vec<u8>, PacketError> {
        TcpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .syn()
            .build()
    }

    /// Create an X-Mas packet (FIN+PSH+URG)
    pub fn xmas_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Result<Vec<u8>, PacketError> {
        TcpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .xmas()
            .build()
    }

    /// Create a NULL packet (no flags)
    pub fn null_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Result<Vec<u8>, PacketError> {
        TcpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .null()
            .build()
    }

    /// Create a FIN packet
    pub fn fin_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Result<Vec<u8>, PacketError> {
        TcpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .fin()
            .build()
    }

    /// Create an ACK packet
    pub fn ack_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16, ack_num: u32) -> Result<Vec<u8>, PacketError> {
        TcpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .ack()
            .ack_num(ack_num)
            .build()
    }

    /// Create an ICMP Echo Request (ping)
    pub fn ping_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Result<Vec<u8>, PacketError> {
        IcmpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .echo_request()
            .payload(b"NoirCast Ping".to_vec())
            .build()
    }

    /// Create a UDP packet
    pub fn udp_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16, payload: Vec<u8>) -> Result<Vec<u8>, PacketError> {
        UdpPacketBuilder::new()
            .source_ip(source_ip)
            .dest_ip(dest_ip)
            .source_port(source_port)
            .dest_port(dest_port)
            .payload(payload)
            .build()
    }
}

/// Parse TCP flags from a received packet
pub fn parse_tcp_flags(flags: u16) -> Vec<TcpFlag> {
    let mut result = Vec::new();

    if flags & TcpFlags::SYN as u16 != 0 {
        result.push(TcpFlag::Syn);
    }
    if flags & TcpFlags::ACK as u16 != 0 {
        result.push(TcpFlag::Ack);
    }
    if flags & TcpFlags::FIN as u16 != 0 {
        result.push(TcpFlag::Fin);
    }
    if flags & TcpFlags::RST as u16 != 0 {
        result.push(TcpFlag::Rst);
    }
    if flags & TcpFlags::PSH as u16 != 0 {
        result.push(TcpFlag::Psh);
    }
    if flags & TcpFlags::URG as u16 != 0 {
        result.push(TcpFlag::Urg);
    }
    if flags & TcpFlags::ECE as u16 != 0 {
        result.push(TcpFlag::Ece);
    }
    if flags & TcpFlags::CWR as u16 != 0 {
        result.push(TcpFlag::Cwr);
    }

    result
}

/// Format flags as a string
pub fn format_flags(flags: &[TcpFlag]) -> String {
    if flags.is_empty() {
        return "NONE".to_string();
    }
    flags.iter().map(|f| f.name()).collect::<Vec<_>>().join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_packet_builder() {
        let packet = TcpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .source_port(12345)
            .dest_port(80)
            .syn()
            .build()
            .unwrap();

        assert!(!packet.is_empty());
        assert_eq!(packet.len(), 40); // 20 IP + 20 TCP
    }

    #[test]
    fn test_xmas_packet() {
        let packet = PacketBuilder::xmas_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            12345,
            80,
        ).unwrap();

        assert!(!packet.is_empty());
    }

    #[test]
    fn test_udp_packet_builder() {
        let packet = UdpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .source_port(12345)
            .dest_port(53)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        assert!(!packet.is_empty());
        assert_eq!(packet.len(), 20 + 8 + 4); // IP + UDP + payload
    }

    #[test]
    fn test_icmp_packet_builder() {
        let packet = IcmpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .echo_request()
            .build()
            .unwrap();

        assert!(!packet.is_empty());
    }

    #[test]
    fn test_packet_stats() {
        let mut stats = PacketStats::default();
        stats.record_sent(100);
        stats.record_received(50, 10.0);
        stats.record_received(50, 20.0);

        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 2);
        assert_eq!(stats.avg_rtt_ms, 15.0);
        assert_eq!(stats.min_rtt_ms, 10.0);
        assert_eq!(stats.max_rtt_ms, 20.0);
    }

    #[test]
    fn test_parse_tcp_flags() {
        let flags = TcpFlags::SYN as u16 | TcpFlags::ACK as u16;
        let parsed = parse_tcp_flags(flags);

        assert!(parsed.contains(&TcpFlag::Syn));
        assert!(parsed.contains(&TcpFlag::Ack));
        assert!(!parsed.contains(&TcpFlag::Fin));
    }

    #[test]
    fn test_format_flags() {
        let flags = vec![TcpFlag::Syn, TcpFlag::Ack];
        let formatted = format_flags(&flags);
        assert_eq!(formatted, "SYN|ACK");

        let empty_flags: Vec<TcpFlag> = vec![];
        assert_eq!(format_flags(&empty_flags), "NONE");
    }

    #[test]
    fn test_build_segment_into_buffer_too_small() {
        let builder = TcpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .source_port(12345)
            .dest_port(80)
            .syn();

        // Buffer too small (needs at least 20 bytes for TCP header)
        let mut small_buffer = [0u8; 10];
        let result = builder.build_segment_into(&mut small_buffer);

        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::BufferTooSmall { needed, available } => {
                assert_eq!(needed, 20);
                assert_eq!(available, 10);
            }
            _ => panic!("Expected BufferTooSmall error"),
        }

        // Adequate buffer works fine
        let mut adequate_buffer = [0u8; 40];
        let result = builder.build_segment_into(&mut adequate_buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 20);
    }

    #[test]
    fn test_tcp_ip_fragmentation_fields() {
        let packet = TcpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .source_port(12345)
            .dest_port(80)
            .syn()
            .ip_flags(0x02)  // DF flag
            .ip_id(0x1234)
            .fragment_offset(0)
            .dscp(46)        // EF DSCP
            .ecn(0x01)       // ECT(1)
            .dont_fragment()
            .build()
            .unwrap();

        assert!(!packet.is_empty());
        // IP flags are at offset 6 (upper 3 bits)
        assert_eq!(packet[6] >> 5, 0x02); // DF flag set
    }

    #[test]
    fn test_tcp_more_fragments_flag() {
        let packet = TcpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(10, 0, 0, 1))
            .dest_ip(Ipv4Addr::new(10, 0, 0, 2))
            .source_port(1234)
            .dest_port(443)
            .syn()
            .more_fragments()
            .fragment_offset(185)  // 185 * 8 = 1480 bytes offset
            .ip_id(0xABCD)
            .build()
            .unwrap();

        assert!(!packet.is_empty());
    }

    #[test]
    fn test_udp_ip_fragmentation_fields() {
        let packet = UdpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .source_port(12345)
            .dest_port(53)
            .payload(b"test".to_vec())
            .ip_flags(0x02)
            .ip_id(0x5678)
            .fragment_offset(0)
            .dscp(0)
            .ecn(0)
            .dont_fragment()
            .more_fragments()
            .build()
            .unwrap();

        assert!(!packet.is_empty());
    }

    #[test]
    fn test_icmp_ip_fragmentation_fields() {
        let packet = IcmpPacketBuilder::new()
            .source_ip(Ipv4Addr::new(192, 168, 1, 1))
            .dest_ip(Ipv4Addr::new(192, 168, 1, 2))
            .echo_request()
            .ip_flags(0x00)
            .ip_id(0x9ABC)
            .fragment_offset(0)
            .dscp(0)
            .ecn(0)
            .dont_fragment()
            .more_fragments()
            .build()
            .unwrap();

        assert!(!packet.is_empty());
    }

    #[test]
    fn test_tcp_option_encoding() {
        // Test MSS
        let mss = TcpOption::Mss(1460);
        assert_eq!(mss.kind(), 2);
        assert_eq!(mss.name(), "MSS");
        let encoded = mss.encode();
        assert_eq!(encoded, vec![2, 4, 0x05, 0xB4]); // 1460 = 0x05B4

        // Test Window Scale
        let ws = TcpOption::WindowScale(7);
        assert_eq!(ws.kind(), 3);
        assert_eq!(ws.name(), "Window Scale");
        let encoded = ws.encode();
        assert_eq!(encoded, vec![3, 3, 7]);

        // Test SACK Permitted
        let sack_perm = TcpOption::SackPermitted;
        assert_eq!(sack_perm.kind(), 4);
        assert_eq!(sack_perm.name(), "SACK Permitted");
        let encoded = sack_perm.encode();
        assert_eq!(encoded, vec![4, 2]);

        // Test Timestamps
        let ts = TcpOption::Timestamps { tsval: 123456, tsecr: 654321 };
        assert_eq!(ts.kind(), 8);
        assert_eq!(ts.name(), "Timestamps");
        let encoded = ts.encode();
        assert_eq!(encoded.len(), 10);

        // Test NOP and End
        let nop = TcpOption::Nop;
        assert_eq!(nop.encode(), vec![1]);
        let end = TcpOption::End;
        assert_eq!(end.encode(), vec![0]);

        // Test SACK with blocks
        let sack = TcpOption::Sack(vec![(1000, 2000), (3000, 4000)]);
        assert_eq!(sack.kind(), 5);
        let encoded = sack.encode();
        assert_eq!(encoded.len(), 2 + 16); // kind + len + 2 blocks * 8 bytes
    }

    #[test]
    fn test_encode_tcp_options_with_padding() {
        let options = vec![
            TcpOption::Mss(1460),      // 4 bytes
            TcpOption::WindowScale(7),  // 3 bytes
        ];
        let encoded = encode_tcp_options(&options);
        // Should be padded to 4-byte boundary: 7 bytes -> 8 bytes
        assert_eq!(encoded.len() % 4, 0);
    }

    #[test]
    fn test_tcp_option_all_types() {
        let types = TcpOption::all_types();
        assert!(types.contains(&"MSS"));
        assert!(types.contains(&"Window Scale"));
        assert!(types.contains(&"SACK Permitted"));
        assert!(types.contains(&"Timestamps"));
    }
}
