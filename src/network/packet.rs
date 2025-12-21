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

    /// Build the TCP packet with IP header
    pub fn build(&self) -> Result<Vec<u8>, PacketError> {
        let tcp_len = 20 + self.payload.len(); // TCP header + payload
        let ip_len = 20 + tcp_len; // IP header + TCP

        let mut buffer = vec![0u8; ip_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..])
                .ok_or_else(|| PacketError::build_error("IPv4", "Buffer too small for IP header"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(rand::random());
            ip_packet.set_flags(0);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);

            let checksum = ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[20..])
                .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP header"))?;

            tcp_packet.set_source(self.source_port);
            tcp_packet.set_destination(self.dest_port);
            tcp_packet.set_sequence(self.seq_num);
            tcp_packet.set_acknowledgement(self.ack_num);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_reserved(0);
            tcp_packet.set_flags(self.flags);
            tcp_packet.set_window(self.window);
            tcp_packet.set_urgent_ptr(self.urgent_ptr);
            tcp_packet.set_payload(&self.payload);

            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &self.dest_ip);
            tcp_packet.set_checksum(checksum);
        }

        Ok(buffer)
    }

    /// Build just the TCP segment (without IP header)
    pub fn build_segment(&self) -> Result<Vec<u8>, PacketError> {
        let tcp_len = 20 + self.payload.len();
        let mut buffer = vec![0u8; tcp_len];
        self.build_segment_into(&mut buffer)?;
        Ok(buffer)
    }

    /// Build TCP segment into an existing buffer
    /// Returns an error if the buffer is too small
    pub fn build_segment_into(&self, buffer: &mut [u8]) -> Result<usize, PacketError> {
        let tcp_len = 20 + self.payload.len();

        if buffer.len() < tcp_len {
            return Err(PacketError::buffer_too_small(tcp_len, buffer.len()));
        }

        let mut tcp_packet = MutableTcpPacket::new(buffer)
            .ok_or_else(|| PacketError::build_error("TCP", "Buffer too small for TCP header"))?;

        tcp_packet.set_source(self.source_port);
        tcp_packet.set_destination(self.dest_port);
        tcp_packet.set_sequence(self.seq_num);
        tcp_packet.set_acknowledgement(self.ack_num);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_reserved(0);
        tcp_packet.set_flags(self.flags);
        tcp_packet.set_window(self.window);
        tcp_packet.set_urgent_ptr(self.urgent_ptr);
        tcp_packet.set_payload(&self.payload);

        let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &self.dest_ip);
        tcp_packet.set_checksum(checksum);

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
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(rand::random());
            ip_packet.set_flags(0);
            ip_packet.set_fragment_offset(0);
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
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_identification(rand::random());
            ip_packet.set_flags(0);
            ip_packet.set_fragment_offset(0);
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
}
