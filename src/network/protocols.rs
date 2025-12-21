//! Protocol-specific utilities and packet builders
//!
//! Provides helpers for building protocol-specific packets
//! including DNS, NTP, and other common protocols.

/// DNS query builder
pub struct DnsQuery {
    transaction_id: u16,
    flags: u16,
    questions: Vec<DnsQuestion>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsType,
    pub qclass: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Any = 255,
}

impl DnsQuery {
    pub fn new() -> Self {
        Self {
            transaction_id: rand::random(),
            flags: 0x0100, // Standard query with recursion desired
            questions: Vec::new(),
        }
    }

    pub fn transaction_id(mut self, id: u16) -> Self {
        self.transaction_id = id;
        self
    }

    pub fn add_question(mut self, name: &str, qtype: DnsType) -> Self {
        self.questions.push(DnsQuestion {
            name: name.to_string(),
            qtype,
            qclass: 1, // IN (Internet)
        });
        self
    }

    /// Encode domain name in DNS format
    fn encode_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0); // Null terminator
        encoded
    }

    /// Build the DNS query packet
    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&self.transaction_id.to_be_bytes());

        // Flags
        packet.extend_from_slice(&self.flags.to_be_bytes());

        // Question count
        packet.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());

        // Answer, Authority, Additional counts (all 0 for query)
        packet.extend_from_slice(&[0u8; 6]);

        // Questions
        for question in &self.questions {
            packet.extend(Self::encode_name(&question.name));
            packet.extend_from_slice(&(question.qtype as u16).to_be_bytes());
            packet.extend_from_slice(&question.qclass.to_be_bytes());
        }

        packet
    }

    /// Create a simple A record query
    pub fn a_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::A)
    }

    /// Create an AAAA (IPv6) record query
    pub fn aaaa_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Aaaa)
    }

    /// Create an MX record query
    pub fn mx_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Mx)
    }

    /// Create a TXT record query
    pub fn txt_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Txt)
    }
}

impl Default for DnsQuery {
    fn default() -> Self {
        Self::new()
    }
}

/// NTP packet builder (Simple NTP Mode 3 Client)
pub struct NtpPacket {
    li_vn_mode: u8,
    stratum: u8,
    poll: u8,
    precision: i8,
    root_delay: u32,
    root_dispersion: u32,
    reference_id: [u8; 4],
    reference_timestamp: u64,
    originate_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
}

impl NtpPacket {
    pub fn new() -> Self {
        Self {
            li_vn_mode: 0x1b, // LI=0, VN=3, Mode=3 (client)
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_timestamp: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: Self::current_ntp_timestamp(),
        }
    }

    /// Get current time as NTP timestamp
    fn current_ntp_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        // NTP epoch is January 1, 1900, Unix epoch is January 1, 1970
        // Difference is 2208988800 seconds
        const NTP_UNIX_OFFSET: u64 = 2208988800;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let secs = now.as_secs() + NTP_UNIX_OFFSET;
        // Parentheses required: shift first, then divide
        let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;

        (secs << 32) | frac
    }

    /// Build the NTP packet
    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(48);

        packet.push(self.li_vn_mode);
        packet.push(self.stratum);
        packet.push(self.poll);
        packet.push(self.precision as u8);
        packet.extend_from_slice(&self.root_delay.to_be_bytes());
        packet.extend_from_slice(&self.root_dispersion.to_be_bytes());
        packet.extend_from_slice(&self.reference_id);
        packet.extend_from_slice(&self.reference_timestamp.to_be_bytes());
        packet.extend_from_slice(&self.originate_timestamp.to_be_bytes());
        packet.extend_from_slice(&self.receive_timestamp.to_be_bytes());
        packet.extend_from_slice(&self.transmit_timestamp.to_be_bytes());

        packet
    }
}

impl Default for NtpPacket {
    fn default() -> Self {
        Self::new()
    }
}

/// SNMP v1/v2c get-request builder
pub struct SnmpGetRequest {
    version: u8,
    community: String,
    request_id: u32,
    oids: Vec<String>,
}

impl SnmpGetRequest {
    pub fn new(community: &str) -> Self {
        Self {
            version: 1, // SNMP v2c
            community: community.to_string(),
            request_id: rand::random(),
            oids: Vec::new(),
        }
    }

    pub fn add_oid(mut self, oid: &str) -> Self {
        self.oids.push(oid.to_string());
        self
    }

    /// Encode an OID to ASN.1 format
    fn encode_oid(oid: &str) -> Vec<u8> {
        let parts: Vec<u32> = oid
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        if parts.len() < 2 {
            return vec![];
        }

        let mut encoded = vec![(parts[0] * 40 + parts[1]) as u8];

        for &part in &parts[2..] {
            if part < 128 {
                encoded.push(part as u8);
            } else {
                // Multi-byte encoding
                let mut temp = Vec::new();
                let mut val = part;
                while val > 0 {
                    temp.push((val & 0x7f) as u8);
                    val >>= 7;
                }
                temp.reverse();
                let temp_len = temp.len();
                for (i, b) in temp.iter_mut().enumerate() {
                    if i < temp_len - 1 {
                        *b |= 0x80;
                    }
                }
                encoded.extend(temp);
            }
        }

        encoded
    }

    /// Build the SNMP packet (simplified)
    pub fn build(&self) -> Vec<u8> {
        // This is a simplified SNMP packet builder
        // A full implementation would require proper ASN.1/BER encoding

        let mut packet = Vec::new();

        // SNMP message sequence
        packet.push(0x30); // SEQUENCE

        // Version
        let version_tlv = vec![0x02, 0x01, self.version];

        // Community string
        let mut community_tlv = vec![0x04, self.community.len() as u8];
        community_tlv.extend_from_slice(self.community.as_bytes());

        // GetRequest PDU
        let mut pdu = vec![0xa0]; // GetRequest-PDU tag

        // Request ID
        let mut request_id_tlv = vec![0x02, 0x04];
        request_id_tlv.extend_from_slice(&self.request_id.to_be_bytes());

        // Error status (0)
        let error_status = vec![0x02, 0x01, 0x00];

        // Error index (0)
        let error_index = vec![0x02, 0x01, 0x00];

        // Variable bindings
        let mut varbinds = vec![0x30]; // SEQUENCE

        let mut varbind_data = Vec::new();
        for oid in &self.oids {
            let encoded_oid = Self::encode_oid(oid);
            // VarBind SEQUENCE
            let mut varbind = vec![0x30];
            // OID
            let mut oid_tlv = vec![0x06, encoded_oid.len() as u8];
            oid_tlv.extend(encoded_oid);
            // NULL value
            let null_tlv = vec![0x05, 0x00];

            let varbind_content_len = oid_tlv.len() + null_tlv.len();
            varbind.push(varbind_content_len as u8);
            varbind.extend(oid_tlv);
            varbind.extend(null_tlv);

            varbind_data.extend(varbind);
        }

        varbinds.push(varbind_data.len() as u8);
        varbinds.extend(varbind_data);

        // Calculate PDU length
        let pdu_content_len = request_id_tlv.len()
            + error_status.len()
            + error_index.len()
            + varbinds.len();
        pdu.push(pdu_content_len as u8);
        pdu.extend(request_id_tlv);
        pdu.extend(error_status);
        pdu.extend(error_index);
        pdu.extend(varbinds);

        // Calculate total length
        let total_len = version_tlv.len() + community_tlv.len() + pdu.len();
        packet.push(total_len as u8);
        packet.extend(version_tlv);
        packet.extend(community_tlv);
        packet.extend(pdu);

        packet
    }
}

/// SSDP (Simple Service Discovery Protocol) request builder
pub struct SsdpRequest {
    method: String,
    host: String,
    man: String,
    mx: u8,
    st: String,
}

impl SsdpRequest {
    /// Create an M-SEARCH request for UPnP discovery
    pub fn m_search() -> Self {
        Self {
            method: "M-SEARCH".to_string(),
            host: "239.255.255.250:1900".to_string(),
            man: "\"ssdp:discover\"".to_string(),
            mx: 3,
            st: "ssdp:all".to_string(),
        }
    }

    pub fn search_target(mut self, target: &str) -> Self {
        self.st = target.to_string();
        self
    }

    pub fn mx(mut self, seconds: u8) -> Self {
        self.mx = seconds;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let request = format!(
            "{} * HTTP/1.1\r\n\
             HOST: {}\r\n\
             MAN: {}\r\n\
             MX: {}\r\n\
             ST: {}\r\n\
             \r\n",
            self.method, self.host, self.man, self.mx, self.st
        );
        request.into_bytes()
    }
}

/// Well-known ports and their services
pub struct ServiceInfo {
    pub port: u16,
    pub name: &'static str,
    pub protocol: &'static str,
    pub description: &'static str,
}

pub const COMMON_SERVICES: &[ServiceInfo] = &[
    ServiceInfo { port: 21, name: "FTP", protocol: "TCP", description: "File Transfer Protocol" },
    ServiceInfo { port: 22, name: "SSH", protocol: "TCP", description: "Secure Shell" },
    ServiceInfo { port: 23, name: "Telnet", protocol: "TCP", description: "Telnet" },
    ServiceInfo { port: 25, name: "SMTP", protocol: "TCP", description: "Simple Mail Transfer Protocol" },
    ServiceInfo { port: 53, name: "DNS", protocol: "TCP/UDP", description: "Domain Name System" },
    ServiceInfo { port: 80, name: "HTTP", protocol: "TCP", description: "Hypertext Transfer Protocol" },
    ServiceInfo { port: 110, name: "POP3", protocol: "TCP", description: "Post Office Protocol v3" },
    ServiceInfo { port: 123, name: "NTP", protocol: "UDP", description: "Network Time Protocol" },
    ServiceInfo { port: 143, name: "IMAP", protocol: "TCP", description: "Internet Message Access Protocol" },
    ServiceInfo { port: 161, name: "SNMP", protocol: "UDP", description: "Simple Network Management Protocol" },
    ServiceInfo { port: 443, name: "HTTPS", protocol: "TCP", description: "HTTP Secure" },
    ServiceInfo { port: 445, name: "SMB", protocol: "TCP", description: "Server Message Block" },
    ServiceInfo { port: 993, name: "IMAPS", protocol: "TCP", description: "IMAP over SSL" },
    ServiceInfo { port: 995, name: "POP3S", protocol: "TCP", description: "POP3 over SSL" },
    ServiceInfo { port: 1433, name: "MSSQL", protocol: "TCP", description: "Microsoft SQL Server" },
    ServiceInfo { port: 1900, name: "SSDP", protocol: "UDP", description: "Simple Service Discovery Protocol" },
    ServiceInfo { port: 3306, name: "MySQL", protocol: "TCP", description: "MySQL Database" },
    ServiceInfo { port: 3389, name: "RDP", protocol: "TCP", description: "Remote Desktop Protocol" },
    ServiceInfo { port: 5432, name: "PostgreSQL", protocol: "TCP", description: "PostgreSQL Database" },
    ServiceInfo { port: 5900, name: "VNC", protocol: "TCP", description: "Virtual Network Computing" },
    ServiceInfo { port: 6379, name: "Redis", protocol: "TCP", description: "Redis Database" },
    ServiceInfo { port: 8080, name: "HTTP-Alt", protocol: "TCP", description: "HTTP Alternate" },
    ServiceInfo { port: 8443, name: "HTTPS-Alt", protocol: "TCP", description: "HTTPS Alternate" },
    ServiceInfo { port: 27017, name: "MongoDB", protocol: "TCP", description: "MongoDB Database" },
];

/// Get service info by port
pub fn get_service_by_port(port: u16) -> Option<&'static ServiceInfo> {
    COMMON_SERVICES.iter().find(|s| s.port == port)
}

/// Get service name by port
pub fn get_service_name(port: u16) -> &'static str {
    get_service_by_port(port).map(|s| s.name).unwrap_or("Unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_build() {
        let query = DnsQuery::a_query("example.com");
        let packet = query.build();

        // DNS header is 12 bytes
        assert!(packet.len() >= 12);

        // Check question count
        assert_eq!(packet[4], 0);
        assert_eq!(packet[5], 1);
    }

    #[test]
    fn test_dns_name_encoding() {
        let encoded = DnsQuery::encode_name("example.com");
        // "example" = 7 bytes + length, "com" = 3 bytes + length, null terminator
        assert_eq!(encoded.len(), 13);
        assert_eq!(encoded[0], 7); // Length of "example"
        assert_eq!(encoded[8], 3); // Length of "com"
        assert_eq!(encoded[12], 0); // Null terminator
    }

    #[test]
    fn test_ntp_packet_build() {
        let ntp = NtpPacket::new();
        let packet = ntp.build();

        assert_eq!(packet.len(), 48);
        assert_eq!(packet[0], 0x1b); // LI=0, VN=3, Mode=3
    }

    #[test]
    fn test_ssdp_request() {
        let request = SsdpRequest::m_search();
        let packet = request.build();
        let text = String::from_utf8(packet).unwrap();

        assert!(text.contains("M-SEARCH"));
        assert!(text.contains("239.255.255.250:1900"));
    }

    #[test]
    fn test_service_lookup() {
        assert_eq!(get_service_name(80), "HTTP");
        assert_eq!(get_service_name(443), "HTTPS");
        assert_eq!(get_service_name(12345), "Unknown");
    }
}
