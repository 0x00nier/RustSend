//! Protocol handler trait and registry
//!
//! Provides a curl-inspired unified interface for all protocol implementations.
//! Each protocol implements the ProtocolHandler trait for consistent behavior.

use crate::config::Protocol;
use anyhow::Result;
use std::net::SocketAddr;

/// Protocol-specific features and capabilities
#[derive(Debug, Clone, Default)]
pub struct ProtocolFeatures {
    /// Whether this protocol requires authentication
    pub requires_authentication: bool,
    /// Whether this protocol supports TLS/SSL
    pub supports_tls: bool,
    /// Whether this protocol is stateful (TCP) vs stateless (UDP)
    pub stateful: bool,
    /// Whether responses can span multiple packets
    pub multipart_response: bool,
    /// Whether this protocol supports version negotiation
    pub version_negotiation: bool,
    /// Whether connections can be reused
    pub supports_connection_reuse: bool,
}

/// Protocol metadata for configuration and defaults
#[derive(Debug, Clone)]
pub struct ProtocolMetadata {
    /// Human-readable protocol name
    pub name: &'static str,
    /// Default port for this protocol
    pub default_port: u16,
    /// Default timeout in milliseconds
    pub default_timeout_ms: u64,
    /// Maximum packet/message size
    pub max_packet_size: usize,
    /// Transport layer (TCP, UDP, ICMP, etc.)
    pub transport: Transport,
}

/// Transport layer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Raw,
}

/// Unified protocol handler trait inspired by curl's protocol handlers
pub trait ProtocolHandler: Send + Sync {
    /// Get protocol metadata
    fn metadata(&self) -> ProtocolMetadata;

    /// Get protocol features
    fn features(&self) -> ProtocolFeatures;

    /// Build the packet/request payload for this protocol
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>>;

    /// Parse the response from raw bytes
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse>;

    /// Validate packet before sending (curl-inspired validation)
    fn validate_packet(&self, packet: &[u8]) -> Result<()>;

    /// Check if connection can be reused for another request
    fn can_reuse_connection(&self, prev_target: &SocketAddr, new_target: &SocketAddr) -> bool;

    /// Get protocol identifier
    fn protocol(&self) -> Protocol;
}

/// Protocol-specific configuration passed to build_packet
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Target address
    pub target: SocketAddr,
    /// Source port (if applicable)
    pub source_port: Option<u16>,
    /// TTL value
    pub ttl: u8,
    /// Custom payload
    pub payload: Option<Vec<u8>>,
    /// Protocol-specific options
    pub options: ProtocolOptions,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            target: SocketAddr::from(([127, 0, 0, 1], 80)),
            source_port: None,
            ttl: 64,
            payload: None,
            options: ProtocolOptions::None,
        }
    }
}

/// Protocol-specific options
#[derive(Debug, Clone)]
pub enum ProtocolOptions {
    None,
    Tcp(TcpOptions),
    Icmp(IcmpOptions),
    Dns(DnsOptions),
    Http(HttpOptions),
    Snmp(SnmpOptions),
    Ldap(LdapOptions),
    Smb(SmbOptions),
    Dhcp(DhcpOptions),
    Kerberos(KerberosOptions),
    Arp(ArpOptions),
}

#[derive(Debug, Clone)]
pub struct TcpOptions {
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,
    pub flags: Vec<crate::config::TcpFlag>,
}

#[derive(Debug, Clone)]
pub struct IcmpOptions {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
}

#[derive(Debug, Clone)]
pub struct DnsOptions {
    pub query_type: u16,
    pub domain: String,
    pub recursion_desired: bool,
}

#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SnmpOptions {
    pub version: u8,
    pub community: String,
    pub oid: String,
}

#[derive(Debug, Clone)]
pub struct LdapOptions {
    pub scope: u8,
    pub base_dn: String,
    pub filter: String,
}

#[derive(Debug, Clone)]
pub struct SmbOptions {
    pub version: u8,
}

#[derive(Debug, Clone)]
pub struct DhcpOptions {
    pub message_type: u8,
}

#[derive(Debug, Clone)]
pub struct KerberosOptions {
    pub realm: String,
    pub principal: String,
}

#[derive(Debug, Clone)]
pub struct ArpOptions {
    pub operation: u16,
    pub target_ip: std::net::Ipv4Addr,
    pub sender_mac: [u8; 6],
    pub sender_ip: std::net::Ipv4Addr,
}

/// Parsed protocol response
#[derive(Debug, Clone)]
pub struct ProtocolResponse {
    /// Whether the response indicates success
    pub success: bool,
    /// Protocol-specific status code
    pub status_code: Option<i32>,
    /// Human-readable status message
    pub status_message: String,
    /// Parsed response data
    pub data: Option<ResponseData>,
    /// Raw response bytes
    pub raw_bytes: Vec<u8>,
}

/// Protocol-specific response data
#[derive(Debug, Clone)]
pub enum ResponseData {
    Tcp { flags: Vec<crate::config::TcpFlag>, window: u16 },
    Icmp { icmp_type: u8, code: u8, id: u16, seq: u16 },
    Dns { answers: Vec<String>, rcode: u8 },
    Http { status: u16, headers: std::collections::HashMap<String, String>, body: Vec<u8> },
    Snmp { oid_values: std::collections::HashMap<String, String> },
    Ldap { entries: Vec<String> },
    Smb { dialect: String },
    Ntp { stratum: u8, precision: i8 },
    Generic { bytes: Vec<u8> },
}

/// Protocol registry for looking up handlers
pub struct ProtocolRegistry;

impl ProtocolRegistry {
    /// Get the handler for a given protocol
    pub fn get(protocol: Protocol) -> &'static dyn ProtocolHandler {
        match protocol {
            Protocol::Tcp => &TcpHandler,
            Protocol::Udp => &UdpHandler,
            Protocol::Icmp => &IcmpHandler,
            Protocol::Dns => &DnsHandler,
            Protocol::Http | Protocol::Https => &HttpHandler,
            Protocol::Ntp => &NtpHandler,
            Protocol::Snmp => &SnmpHandler,
            Protocol::Ssdp => &SsdpHandler,
            Protocol::Smb => &SmbHandler,
            Protocol::Ldap => &LdapHandler,
            Protocol::NetBios => &NetBiosHandler,
            Protocol::Dhcp => &DhcpHandler,
            Protocol::Kerberos => &KerberosHandler,
            Protocol::Arp => &ArpHandler,
            Protocol::Raw => &RawHandler,
        }
    }

    /// Get metadata for a protocol
    pub fn metadata(protocol: Protocol) -> ProtocolMetadata {
        Self::get(protocol).metadata()
    }

    /// Get features for a protocol
    pub fn features(protocol: Protocol) -> ProtocolFeatures {
        Self::get(protocol).features()
    }
}

// Protocol handler implementations

struct TcpHandler;
impl ProtocolHandler for TcpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "TCP",
            default_port: 80,
            default_timeout_ms: 3000,
            max_packet_size: 65535,
            transport: Transport::Tcp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures {
            stateful: true,
            supports_connection_reuse: true,
            ..Default::default()
        }
    }

    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        // TCP packet construction delegated to packet.rs
        let payload = config.payload.clone().unwrap_or_default();
        Ok(payload)
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse {
            success: !data.is_empty(),
            status_code: None,
            status_message: "TCP response received".to_string(),
            data: Some(ResponseData::Generic { bytes: data.to_vec() }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > 65535 {
            anyhow::bail!("TCP packet too large: {} bytes", packet.len());
        }
        Ok(())
    }

    fn can_reuse_connection(&self, prev: &SocketAddr, new: &SocketAddr) -> bool {
        prev.ip() == new.ip() && prev.port() == new.port()
    }

    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }
}

struct UdpHandler;
impl ProtocolHandler for UdpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "UDP",
            default_port: 53,
            default_timeout_ms: 3000,
            max_packet_size: 65507,
            transport: Transport::Udp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures {
            stateful: false,
            supports_connection_reuse: true,
            ..Default::default()
        }
    }

    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        Ok(config.payload.clone().unwrap_or_default())
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse {
            success: !data.is_empty(),
            status_code: None,
            status_message: "UDP response received".to_string(),
            data: Some(ResponseData::Generic { bytes: data.to_vec() }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > 65507 {
            anyhow::bail!("UDP packet too large: {} bytes (max 65507)", packet.len());
        }
        Ok(())
    }

    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool {
        true // UDP is connectionless
    }

    fn protocol(&self) -> Protocol {
        Protocol::Udp
    }
}

struct IcmpHandler;
impl ProtocolHandler for IcmpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "ICMP",
            default_port: 0,
            default_timeout_ms: 5000,
            max_packet_size: 65535,
            transport: Transport::Icmp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures {
            stateful: false,
            ..Default::default()
        }
    }

    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Icmp(opts) = &config.options {
            let mut packet = Vec::with_capacity(8 + config.payload.as_ref().map(|p| p.len()).unwrap_or(0));
            packet.push(opts.icmp_type);
            packet.push(opts.icmp_code);
            packet.extend_from_slice(&[0, 0]); // Checksum placeholder
            packet.extend_from_slice(&opts.icmp_id.to_be_bytes());
            packet.extend_from_slice(&opts.icmp_seq.to_be_bytes());
            if let Some(payload) = &config.payload {
                packet.extend_from_slice(payload);
            }
            // Calculate checksum
            let checksum = Self::calculate_checksum(&packet);
            packet[2..4].copy_from_slice(&checksum.to_be_bytes());
            Ok(packet)
        } else {
            anyhow::bail!("ICMP options required for ICMP packet")
        }
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        if data.len() < 8 {
            anyhow::bail!("ICMP response too short");
        }
        let icmp_type = data[0];
        let code = data[1];
        let id = u16::from_be_bytes([data[4], data[5]]);
        let seq = u16::from_be_bytes([data[6], data[7]]);

        Ok(ProtocolResponse {
            success: icmp_type == 0 || icmp_type == 8, // Echo reply or request
            status_code: Some(icmp_type as i32),
            status_message: format!("ICMP type={} code={}", icmp_type, code),
            data: Some(ResponseData::Icmp { icmp_type, code, id, seq }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 8 {
            anyhow::bail!("ICMP packet too short: {} bytes (min 8)", packet.len());
        }
        Ok(())
    }

    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool {
        false // ICMP doesn't use connections
    }

    fn protocol(&self) -> Protocol {
        Protocol::Icmp
    }
}

impl IcmpHandler {
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

struct DnsHandler;
impl ProtocolHandler for DnsHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "DNS",
            default_port: 53,
            default_timeout_ms: 5000,
            max_packet_size: 512, // Standard DNS, EDNS allows larger
            transport: Transport::Udp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures {
            supports_tls: true, // DNS-over-TLS
            ..Default::default()
        }
    }

    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Dns(opts) = &config.options {
            use crate::network::protocols::{DnsQuery, DnsType};
            let dns_type = match opts.query_type {
                1 => DnsType::A,
                2 => DnsType::Ns,
                5 => DnsType::Cname,
                15 => DnsType::Mx,
                16 => DnsType::Txt,
                28 => DnsType::Aaaa,
                _ => DnsType::A,
            };
            let query = DnsQuery::new().add_question(&opts.domain, dns_type);
            Ok(query.build())
        } else {
            anyhow::bail!("DNS options required for DNS packet")
        }
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        if data.len() < 12 {
            anyhow::bail!("DNS response too short");
        }
        let rcode = data[3] & 0x0f;
        let answer_count = u16::from_be_bytes([data[6], data[7]]);

        Ok(ProtocolResponse {
            success: rcode == 0 && answer_count > 0,
            status_code: Some(rcode as i32),
            status_message: format!("DNS rcode={} answers={}", rcode, answer_count),
            data: Some(ResponseData::Dns {
                answers: vec![], // Full parsing would extract answers
                rcode,
            }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 12 {
            anyhow::bail!("DNS packet too short: {} bytes (min 12)", packet.len());
        }
        Ok(())
    }

    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool {
        true // UDP is connectionless
    }

    fn protocol(&self) -> Protocol {
        Protocol::Dns
    }
}

struct HttpHandler;
impl ProtocolHandler for HttpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "HTTP",
            default_port: 80,
            default_timeout_ms: 30000,
            max_packet_size: 1048576, // 1MB default
            transport: Transport::Tcp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures {
            requires_authentication: false, // Optional
            supports_tls: true,
            stateful: true,
            multipart_response: true,
            version_negotiation: true,
            supports_connection_reuse: true,
        }
    }

    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Http(opts) = &config.options {
            let mut request = format!("{} {} HTTP/1.1\r\n", opts.method, opts.path);
            for (key, value) in &opts.headers {
                request.push_str(&format!("{}: {}\r\n", key, value));
            }
            if let Some(ref body) = opts.body {
                request.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }
            request.push_str("\r\n");

            let mut packet = request.into_bytes();
            if let Some(ref body) = opts.body {
                packet.extend_from_slice(body);
            }
            Ok(packet)
        } else {
            anyhow::bail!("HTTP options required for HTTP packet")
        }
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        let response_str = String::from_utf8_lossy(data);
        let status = if let Some(status_line) = response_str.lines().next() {
            if status_line.starts_with("HTTP/") {
                status_line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        Ok(ProtocolResponse {
            success: (200..300).contains(&status),
            status_code: Some(status as i32),
            status_message: format!("HTTP {}", status),
            data: Some(ResponseData::Http {
                status,
                headers: std::collections::HashMap::new(),
                body: data.to_vec(),
            }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        let s = String::from_utf8_lossy(packet);
        if !s.contains("\r\n\r\n") {
            anyhow::bail!("HTTP request missing header terminator");
        }
        Ok(())
    }

    fn can_reuse_connection(&self, prev: &SocketAddr, new: &SocketAddr) -> bool {
        prev.ip() == new.ip() && prev.port() == new.port()
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http
    }
}

struct NtpHandler;
impl ProtocolHandler for NtpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "NTP",
            default_port: 123,
            default_timeout_ms: 5000,
            max_packet_size: 68,
            transport: Transport::Udp,
        }
    }

    fn features(&self) -> ProtocolFeatures {
        ProtocolFeatures::default()
    }

    fn build_packet(&self, _config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::NtpPacket;
        Ok(NtpPacket::new().build())
    }

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        if data.len() < 48 {
            anyhow::bail!("NTP response too short");
        }
        let stratum = data[1];
        let precision = data[2] as i8;

        Ok(ProtocolResponse {
            success: true,
            status_code: Some(stratum as i32),
            status_message: format!("NTP stratum={}", stratum),
            data: Some(ResponseData::Ntp { stratum, precision }),
            raw_bytes: data.to_vec(),
        })
    }

    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 48 {
            anyhow::bail!("NTP packet too short: {} bytes (need 48)", packet.len());
        }
        Ok(())
    }

    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool {
        true
    }

    fn protocol(&self) -> Protocol {
        Protocol::Ntp
    }
}

// Minimal implementations for remaining protocols
struct SnmpHandler;
impl ProtocolHandler for SnmpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "SNMP", default_port: 161, default_timeout_ms: 5000, max_packet_size: 65507, transport: Transport::Udp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Snmp(opts) = &config.options {
            use crate::network::protocols::SnmpGetRequest;
            Ok(SnmpGetRequest::new(&opts.community).add_oid(&opts.oid).build())
        } else {
            Ok(crate::network::protocols::SnmpGetRequest::new("public").add_oid("1.3.6.1.2.1.1.1.0").build())
        }
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "SNMP response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { true }
    fn protocol(&self) -> Protocol { Protocol::Snmp }
}

struct SsdpHandler;
impl ProtocolHandler for SsdpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "SSDP", default_port: 1900, default_timeout_ms: 3000, max_packet_size: 65507, transport: Transport::Udp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, _config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::SsdpRequest;
        Ok(SsdpRequest::m_search().build())
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "SSDP response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { true }
    fn protocol(&self) -> Protocol { Protocol::Ssdp }
}

struct SmbHandler;
impl ProtocolHandler for SmbHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "SMB", default_port: 445, default_timeout_ms: 10000, max_packet_size: 65535, transport: Transport::Tcp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures { stateful: true, requires_authentication: true, version_negotiation: true, ..Default::default() } }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::SmbNegotiatePacket;
        if let ProtocolOptions::Smb(opts) = &config.options {
            let smb = match opts.version {
                1 => SmbNegotiatePacket::smb1_only(),
                2 => SmbNegotiatePacket::smb2_only(),
                _ => SmbNegotiatePacket::new(),
            };
            Ok(smb.build())
        } else {
            Ok(SmbNegotiatePacket::new().build())
        }
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "SMB response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, prev: &SocketAddr, new: &SocketAddr) -> bool { prev == new }
    fn protocol(&self) -> Protocol { Protocol::Smb }
}

struct LdapHandler;
impl ProtocolHandler for LdapHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "LDAP", default_port: 389, default_timeout_ms: 10000, max_packet_size: 65535, transport: Transport::Tcp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures { stateful: true, supports_tls: true, requires_authentication: true, ..Default::default() } }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::{LdapSearchRequest, LdapScope};
        if let ProtocolOptions::Ldap(opts) = &config.options {
            let scope = match opts.scope {
                0 => LdapScope::BaseObject,
                1 => LdapScope::SingleLevel,
                _ => LdapScope::WholeSubtree,
            };
            Ok(LdapSearchRequest::new(&opts.base_dn).scope(scope).filter(&opts.filter).build())
        } else {
            Ok(LdapSearchRequest::rootdse_query().build())
        }
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "LDAP response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, prev: &SocketAddr, new: &SocketAddr) -> bool { prev == new }
    fn protocol(&self) -> Protocol { Protocol::Ldap }
}

struct NetBiosHandler;
impl ProtocolHandler for NetBiosHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "NetBIOS", default_port: 137, default_timeout_ms: 5000, max_packet_size: 576, transport: Transport::Udp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, _config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::NetBiosNsPacket;
        Ok(NetBiosNsPacket::node_status_query("*").build())
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "NetBIOS response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { true }
    fn protocol(&self) -> Protocol { Protocol::NetBios }
}

struct DhcpHandler;
impl ProtocolHandler for DhcpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "DHCP", default_port: 67, default_timeout_ms: 5000, max_packet_size: 576, transport: Transport::Udp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, _config: &ProtocolConfig) -> Result<Vec<u8>> {
        use crate::network::protocols::DhcpDiscoverPacket;
        // Use a random MAC address for discovery
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        Ok(DhcpDiscoverPacket::new(mac).build())
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "DHCP response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { true }
    fn protocol(&self) -> Protocol { Protocol::Dhcp }
}

struct KerberosHandler;
impl ProtocolHandler for KerberosHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "Kerberos", default_port: 88, default_timeout_ms: 10000, max_packet_size: 65535, transport: Transport::Tcp }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures { stateful: true, requires_authentication: true, ..Default::default() } }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Kerberos(opts) = &config.options {
            use crate::network::protocols::KerberosAsReq;
            Ok(KerberosAsReq::new(&opts.realm, &opts.principal).build())
        } else {
            Ok(crate::network::protocols::KerberosAsReq::new("REALM", "user").build())
        }
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "Kerberos response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, prev: &SocketAddr, new: &SocketAddr) -> bool { prev == new }
    fn protocol(&self) -> Protocol { Protocol::Kerberos }
}

struct ArpHandler;
impl ProtocolHandler for ArpHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "ARP", default_port: 0, default_timeout_ms: 3000, max_packet_size: 42, transport: Transport::Raw }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        if let ProtocolOptions::Arp(opts) = &config.options {
            use crate::network::protocols::ArpPacket;
            let sender_ip: [u8; 4] = opts.sender_ip.octets();
            let target_ip: [u8; 4] = opts.target_ip.octets();
            Ok(ArpPacket::new_request(opts.sender_mac, sender_ip, target_ip).build())
        } else {
            anyhow::bail!("ARP options required for ARP packet")
        }
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "ARP response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 28 {
            anyhow::bail!("ARP packet too short: {} bytes (need 28)", packet.len());
        }
        Ok(())
    }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { false }
    fn protocol(&self) -> Protocol { Protocol::Arp }
}

struct RawHandler;
impl ProtocolHandler for RawHandler {
    fn metadata(&self) -> ProtocolMetadata {
        ProtocolMetadata { name: "Raw", default_port: 0, default_timeout_ms: 3000, max_packet_size: 65535, transport: Transport::Raw }
    }
    fn features(&self) -> ProtocolFeatures { ProtocolFeatures::default() }
    fn build_packet(&self, config: &ProtocolConfig) -> Result<Vec<u8>> {
        Ok(config.payload.clone().unwrap_or_default())
    }
    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse> {
        Ok(ProtocolResponse { success: !data.is_empty(), status_code: None, status_message: "Raw response".to_string(), data: Some(ResponseData::Generic { bytes: data.to_vec() }), raw_bytes: data.to_vec() })
    }
    fn validate_packet(&self, _packet: &[u8]) -> Result<()> { Ok(()) }
    fn can_reuse_connection(&self, _prev: &SocketAddr, _new: &SocketAddr) -> bool { false }
    fn protocol(&self) -> Protocol { Protocol::Raw }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_registry() {
        let handler = ProtocolRegistry::get(Protocol::Tcp);
        assert_eq!(handler.protocol(), Protocol::Tcp);
        assert_eq!(handler.metadata().name, "TCP");
    }

    #[test]
    fn test_protocol_metadata() {
        let meta = ProtocolRegistry::metadata(Protocol::Dns);
        assert_eq!(meta.default_port, 53);
        assert_eq!(meta.transport, Transport::Udp);
    }

    #[test]
    fn test_icmp_checksum() {
        // Echo request type=8, code=0, checksum=0, id=1, seq=1
        let data = vec![8, 0, 0, 0, 0, 1, 0, 1];
        let checksum = IcmpHandler::calculate_checksum(&data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_icmp_packet_validation() {
        let handler = IcmpHandler;
        assert!(handler.validate_packet(&[0u8; 8]).is_ok());
        assert!(handler.validate_packet(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_dns_packet_validation() {
        let handler = DnsHandler;
        assert!(handler.validate_packet(&[0u8; 12]).is_ok());
        assert!(handler.validate_packet(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_protocol_features() {
        let tcp_features = ProtocolRegistry::features(Protocol::Tcp);
        assert!(tcp_features.stateful);
        assert!(tcp_features.supports_connection_reuse);

        let udp_features = ProtocolRegistry::features(Protocol::Udp);
        assert!(!udp_features.stateful);
    }

    #[test]
    fn test_http_features() {
        let features = ProtocolRegistry::features(Protocol::Http);
        assert!(features.supports_tls);
        assert!(features.version_negotiation);
        assert!(features.multipart_response);
    }

    #[test]
    fn test_connection_reuse() {
        let tcp = TcpHandler;
        let addr1: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.2:80".parse().unwrap();

        assert!(tcp.can_reuse_connection(&addr1, &addr2));
        assert!(!tcp.can_reuse_connection(&addr1, &addr3));
    }
}
