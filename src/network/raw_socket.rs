//! Raw socket utilities and privilege detection
//!
//! This module provides cross-platform detection of raw socket capabilities
//! and proper ICMP packet construction using pnet.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};

/// Cached result of raw socket capability check
static RAW_SOCKET_AVAILABLE: OnceLock<bool> = OnceLock::new();
static RAW_SOCKET_CHECK_RAN: AtomicBool = AtomicBool::new(false);

/// Result of raw socket capability check
#[derive(Debug, Clone)]
pub struct RawSocketCapability {
    pub available: bool,
    pub reason: String,
    pub is_root: bool,
    pub has_cap_net_raw: bool,
}

impl RawSocketCapability {
    /// Get a human-readable explanation of the capability status
    pub fn explanation(&self) -> String {
        if self.available {
            if self.is_root {
                "Running as root - raw sockets available".to_string()
            } else if self.has_cap_net_raw {
                "CAP_NET_RAW capability set - raw sockets available".to_string()
            } else {
                "Raw sockets available (unknown reason)".to_string()
            }
        } else {
            format!(
                "Raw sockets unavailable: {}. Try: sudo setcap cap_net_raw+ep <binary>",
                self.reason
            )
        }
    }
}

/// Check if raw sockets are available on the current system
pub fn check_raw_socket_capability() -> RawSocketCapability {
    // Check cached result first
    if let Some(&cached) = RAW_SOCKET_AVAILABLE.get() {
        return RawSocketCapability {
            available: cached,
            reason: if cached { "cached: available".into() } else { "cached: unavailable".into() },
            is_root: false,
            has_cap_net_raw: false,
        };
    }

    let result = do_capability_check();

    // Cache the result
    let _ = RAW_SOCKET_AVAILABLE.set(result.available);
    RAW_SOCKET_CHECK_RAN.store(true, Ordering::SeqCst);

    result
}

#[cfg(unix)]
fn do_capability_check() -> RawSocketCapability {
    use nix::unistd::Uid;

    let is_root = Uid::effective().is_root();

    if is_root {
        return RawSocketCapability {
            available: true,
            reason: "Running as root".to_string(),
            is_root: true,
            has_cap_net_raw: false,
        };
    }

    // Try to actually create a raw socket to test capabilities
    // This is the most reliable way to check
    match try_create_raw_socket() {
        Ok(()) => RawSocketCapability {
            available: true,
            reason: "Raw socket creation succeeded (CAP_NET_RAW or other privilege)".to_string(),
            is_root: false,
            has_cap_net_raw: true,
        },
        Err(e) => RawSocketCapability {
            available: false,
            reason: format!("Raw socket creation failed: {}", e),
            is_root: false,
            has_cap_net_raw: false,
        },
    }
}

#[cfg(not(unix))]
fn do_capability_check() -> RawSocketCapability {
    // On Windows, raw sockets typically require administrator privileges
    // Try to create a raw socket to test
    match try_create_raw_socket() {
        Ok(()) => RawSocketCapability {
            available: true,
            reason: "Raw socket creation succeeded (Administrator privileges)".to_string(),
            is_root: true,
            has_cap_net_raw: false,
        },
        Err(e) => RawSocketCapability {
            available: false,
            reason: format!("Raw socket creation failed: {} (Run as Administrator)", e),
            is_root: false,
            has_cap_net_raw: false,
        },
    }
}

/// Attempt to create a raw socket to verify capabilities
fn try_create_raw_socket() -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Try to create a raw ICMP socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| anyhow::anyhow!("Failed to create raw socket: {}", e))?;

    // Socket created successfully
    drop(socket);
    Ok(())
}

/// Check if we have run the capability check
#[allow(dead_code)]
pub fn has_checked_capabilities() -> bool {
    RAW_SOCKET_CHECK_RAN.load(Ordering::SeqCst)
}

/// Get the cached raw socket availability (returns None if not checked yet)
pub fn get_cached_availability() -> Option<bool> {
    RAW_SOCKET_AVAILABLE.get().copied()
}

/// ICMP packet result
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are for detailed ICMP analysis
pub struct IcmpResult {
    pub target: IpAddr,
    pub seq: u16,
    pub received: bool,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u8>,
    pub icmp_type: u8,
    pub icmp_code: u8,
}

/// Send ICMP echo request using pnet raw sockets
pub fn send_icmp_echo_raw(
    target: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    timeout: Duration,
) -> Result<IcmpResult> {
    let target_v4 = match target {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(anyhow::anyhow!("IPv6 ICMP not yet supported")),
    };

    // Calculate packet size: ICMP header (8 bytes) + payload
    let packet_size = 8 + payload.len();

    // Create transport channel for ICMP
    let (mut tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    ).map_err(|e| anyhow::anyhow!("Failed to create transport channel: {}", e))?;

    // Build ICMP echo request
    let mut buffer = vec![0u8; packet_size];
    let mut echo_request = MutableEchoRequestPacket::new(&mut buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to create ICMP packet"))?;

    echo_request.set_icmp_type(IcmpTypes::EchoRequest);
    echo_request.set_icmp_code(IcmpCode::new(0));
    echo_request.set_identifier(identifier);
    echo_request.set_sequence_number(sequence);

    // Copy payload
    echo_request.set_payload(payload);

    // Calculate checksum - need to convert to IcmpPacket for the checksum function
    // First set checksum to 0, then calculate
    echo_request.set_checksum(0);
    let icmp_packet = IcmpPacket::new(echo_request.packet())
        .ok_or_else(|| anyhow::anyhow!("Failed to create ICMP packet for checksum"))?;
    let checksum = pnet::packet::icmp::checksum(&icmp_packet);
    echo_request.set_checksum(checksum);

    // Record start time
    let start = std::time::Instant::now();

    // Send the packet
    tx.send_to(echo_request.to_immutable(), target)
        .map_err(|e| anyhow::anyhow!("Failed to send ICMP packet: {}", e))?;

    // Wait for reply
    let mut iter = icmp_packet_iter(&mut rx);
    let deadline = start + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(IcmpResult {
                target,
                seq: sequence,
                received: false,
                rtt_ms: None,
                ttl: None,
                icmp_type: 0,
                icmp_code: 0,
            });
        }

        // Set timeout for next receive
        match iter.next_with_timeout(remaining) {
            Ok(Some((packet, addr))) => {
                if addr == target_v4 {
                    if let Some(echo_reply) = EchoReplyPacket::new(packet.packet()) {
                        if echo_reply.get_identifier() == identifier
                            && echo_reply.get_sequence_number() == sequence
                        {
                            let rtt = start.elapsed().as_secs_f64() * 1000.0;
                            return Ok(IcmpResult {
                                target,
                                seq: sequence,
                                received: true,
                                rtt_ms: Some(rtt),
                                ttl: None, // TTL is in IP header, not easily accessible here
                                icmp_type: packet.get_icmp_type().0,
                                icmp_code: packet.get_icmp_code().0,
                            });
                        }
                    }
                }
            }
            Ok(None) => continue,
            Err(_) => {
                return Ok(IcmpResult {
                    target,
                    seq: sequence,
                    received: false,
                    rtt_ms: None,
                    ttl: None,
                    icmp_type: 0,
                    icmp_code: 0,
                });
            }
        }
    }
}

/// Send ICMP echo request using unprivileged UDP (fallback)
/// This won't work for actual ICMP but can detect connectivity
pub async fn send_icmp_fallback(
    target: IpAddr,
    identifier: u16,
    sequence: u16,
    timeout_ms: u64,
) -> IcmpResult {
    use tokio::net::UdpSocket;
    use std::net::SocketAddr;

    // Use UDP echo port as fallback
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            return IcmpResult {
                target,
                seq: sequence,
                received: false,
                rtt_ms: None,
                ttl: None,
                icmp_type: 0,
                icmp_code: 0,
            };
        }
    };

    // Build pseudo-ICMP payload
    let mut payload = vec![8u8, 0u8, 0u8, 0u8]; // Type 8 (echo request), Code 0
    payload.extend_from_slice(&identifier.to_be_bytes());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(b"NoirCast");

    // Try UDP port 7 (echo) - this rarely works but is the safest fallback
    let target_addr = SocketAddr::new(target, 7);
    let start = std::time::Instant::now();

    let _ = socket.send_to(&payload, target_addr).await;

    let mut buf = [0u8; 1024];
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf)
    ).await {
        Ok(Ok((len, _))) => IcmpResult {
            target,
            seq: sequence,
            received: len > 0,
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            ttl: None,
            icmp_type: 0,
            icmp_code: 0,
        },
        _ => IcmpResult {
            target,
            seq: sequence,
            received: false,
            rtt_ms: None,
            ttl: None,
            icmp_type: 0,
            icmp_code: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_check() {
        let cap = check_raw_socket_capability();
        // Just verify it doesn't panic
        println!("Raw socket capability: {:?}", cap);
        println!("Explanation: {}", cap.explanation());
    }

    #[test]
    fn test_cached_check() {
        // Run check twice to test caching
        let cap1 = check_raw_socket_capability();
        let cap2 = check_raw_socket_capability();
        assert_eq!(cap1.available, cap2.available);
    }
}
