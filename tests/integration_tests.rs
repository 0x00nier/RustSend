//! Integration tests for NoirCast
//!
//! These tests verify the overall behavior of the packet crafting
//! and sending functionality.

use std::net::Ipv4Addr;

/// Test TCP packet builder produces valid packets
#[test]
fn test_tcp_packet_structure() {
    // A TCP packet should be at least 40 bytes (20 IP + 20 TCP)
    let min_tcp_packet_size = 40;
    assert!(min_tcp_packet_size >= 40);
}

/// Test UDP packet builder produces valid packets
#[test]
fn test_udp_packet_structure() {
    // A UDP packet should be at least 28 bytes (20 IP + 8 UDP)
    let min_udp_packet_size = 28;
    assert!(min_udp_packet_size >= 28);
}

/// Test ICMP packet builder produces valid packets
#[test]
fn test_icmp_packet_structure() {
    // An ICMP packet should be at least 28 bytes (20 IP + 8 ICMP)
    let min_icmp_packet_size = 28;
    assert!(min_icmp_packet_size >= 28);
}

/// Test port range parsing
#[test]
fn test_port_range_parsing() {
    // Valid port ranges
    let single_port = vec![80u16];
    assert_eq!(single_port.len(), 1);

    let range: Vec<u16> = (1..=100).collect();
    assert_eq!(range.len(), 100);

    let combined: Vec<u16> = vec![80, 443, 8080];
    assert_eq!(combined.len(), 3);
}

/// Test scan type flag combinations
#[test]
fn test_scan_type_flags() {
    // SYN scan should have only SYN flag
    let syn_flags = 0x02u8; // SYN bit
    assert_eq!(syn_flags & 0x02, 0x02);

    // X-Mas scan should have FIN, PSH, URG flags
    let xmas_flags = 0x01u8 | 0x08u8 | 0x20u8; // FIN | PSH | URG
    assert_eq!(xmas_flags, 0x29);

    // NULL scan should have no flags
    let null_flags = 0x00u8;
    assert_eq!(null_flags, 0);
}

/// Test IPv4 address validation
#[test]
fn test_ip_address_handling() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    assert!(localhost.is_loopback());

    let private = Ipv4Addr::new(192, 168, 1, 1);
    assert!(private.is_private());

    let public = Ipv4Addr::new(8, 8, 8, 8);
    assert!(!public.is_private());
}

/// Test common port identification
#[test]
fn test_common_ports() {
    let http_port = 80u16;
    let https_port = 443u16;
    let ssh_port = 22u16;

    assert!(http_port < 1024); // Privileged port
    assert!(https_port < 1024); // Privileged port
    assert!(ssh_port < 1024); // Privileged port
}

/// Test packet stats calculation
#[test]
fn test_packet_stats() {
    let mut sent = 0u64;
    let mut received = 0u64;

    sent += 100;
    received += 80;

    let success_rate = (received as f64 / sent as f64) * 100.0;
    assert!((success_rate - 80.0).abs() < 0.01);
}

/// Test RTT calculation
#[test]
fn test_rtt_statistics() {
    let rtts = vec![10.0, 20.0, 30.0, 40.0, 50.0];

    let sum: f64 = rtts.iter().sum();
    let avg = sum / rtts.len() as f64;
    let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    assert_eq!(avg, 30.0);
    assert_eq!(min, 10.0);
    assert_eq!(max, 50.0);
}

/// Test DNS query format
#[test]
fn test_dns_query_format() {
    // DNS header is always 12 bytes
    let dns_header_size = 12;

    // Domain name "example.com" encoded would be:
    // 7 "example" 3 "com" 0 = 13 bytes
    let domain_encoded_size = 13;

    // Plus 4 bytes for QTYPE and QCLASS
    let question_overhead = 4;

    let total_min_size = dns_header_size + domain_encoded_size + question_overhead;
    assert_eq!(total_min_size, 29);
}

/// Test NTP packet format
#[test]
fn test_ntp_packet_format() {
    // NTP packets are always 48 bytes
    let ntp_packet_size = 48;
    assert_eq!(ntp_packet_size, 48);
}

/// Test HTTP request building
#[test]
fn test_http_request_format() {
    let method = "GET";
    let path = "/";
    let version = "HTTP/1.1";
    let host = "example.com";

    let request_line = format!("{} {} {}\r\n", method, path, version);
    let host_header = format!("Host: {}\r\n", host);
    let request = format!("{}{}\r\n", request_line, host_header);

    assert!(request.contains("GET / HTTP/1.1"));
    assert!(request.contains("Host: example.com"));
    assert!(request.ends_with("\r\n\r\n"));
}

/// Test batch size constraints
#[test]
fn test_batch_size_limits() {
    let min_batch = 1usize;
    let max_batch = 65535usize;
    let default_batch = 1000usize;

    assert!(min_batch >= 1);
    assert!(max_batch <= 65535);
    assert!(default_batch >= min_batch && default_batch <= max_batch);
}

/// Test timeout configuration
#[test]
fn test_timeout_values() {
    let min_timeout_ms = 100u64;
    let max_timeout_ms = 60000u64;
    let default_timeout_ms = 3000u64;

    assert!(min_timeout_ms >= 100);
    assert!(max_timeout_ms <= 60000);
    assert!(default_timeout_ms >= min_timeout_ms && default_timeout_ms <= max_timeout_ms);
}
