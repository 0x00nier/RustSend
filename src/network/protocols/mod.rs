//! Protocol-specific utilities and packet builders
//!
//! Provides helpers for building protocol-specific packets
//! including DNS, NTP, SMB, LDAP, and other common protocols.

mod dns;
mod ntp;
mod snmp;
mod ssdp;
mod arp;
mod netbios;
mod smb;
mod ldap;
mod dhcp;
mod kerberos;
mod services;

// Re-export all public types
pub use dns::{DnsQuery, DnsQuestion, DnsType};
pub use ntp::NtpPacket;
pub use snmp::SnmpGetRequest;
pub use ssdp::SsdpRequest;
pub use arp::ArpPacket;
pub use netbios::NetBiosNsPacket;
pub use smb::SmbNegotiatePacket;
pub use ldap::{LdapSearchRequest, LdapScope};
pub use dhcp::DhcpDiscoverPacket;
pub use kerberos::KerberosAsReq;
pub use services::{ServiceInfo, COMMON_SERVICES, get_service_by_port, get_service_name};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_build() {
        let query = DnsQuery::a_query("example.com");
        let packet = query.build();
        assert!(packet.len() >= 12);
        assert_eq!(packet[4], 0);
        assert_eq!(packet[5], 1);
    }

    #[test]
    fn test_dns_name_encoding() {
        let query = DnsQuery::a_query("example.com");
        let packet = query.build();
        assert!(packet.len() > 12);
    }

    #[test]
    fn test_ntp_packet_build() {
        let ntp = NtpPacket::new();
        let packet = ntp.build();
        assert_eq!(packet.len(), 48);
        assert_eq!(packet[0], 0x1b);
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

    #[test]
    fn test_snmp_request_build() {
        let snmp = SnmpGetRequest::new("public")
            .add_oid("1.3.6.1.2.1.1.1.0");
        let packet = snmp.build();
        assert!(packet.len() > 10);
        assert_eq!(packet[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_smb_negotiate_build() {
        let smb = SmbNegotiatePacket::new();
        let packet = smb.build();
        assert!(packet.len() > 32);
        // Check SMB signature
        assert_eq!(&packet[4..8], b"\xffSMB");
    }

    #[test]
    fn test_smb_versions() {
        let smb1 = SmbNegotiatePacket::smb1_only();
        let smb2 = SmbNegotiatePacket::smb2_only();
        assert!(smb1.build().len() > 0);
        assert!(smb2.build().len() > 0);
    }

    #[test]
    fn test_ldap_search_build() {
        let ldap = LdapSearchRequest::new("dc=example,dc=com")
            .scope(LdapScope::WholeSubtree)
            .filter("(objectClass=*)")
            .message_id(1);
        let packet = ldap.build();
        assert!(packet.len() > 10);
        assert_eq!(packet[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_ldap_rootdse() {
        let ldap = LdapSearchRequest::rootdse_query();
        let packet = ldap.build();
        assert!(packet.len() > 10);
    }

    #[test]
    fn test_netbios_name_query() {
        let netbios = NetBiosNsPacket::name_query("WORKGROUP");
        let packet = netbios.build();
        assert!(packet.len() > 12);
    }

    #[test]
    fn test_netbios_node_status() {
        let netbios = NetBiosNsPacket::node_status_query("*");
        let packet = netbios.build();
        assert!(packet.len() > 12);
    }

    #[test]
    fn test_dhcp_discover_build() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dhcp = DhcpDiscoverPacket::new(mac)
            .with_hostname("testhost")
            .with_transaction_id(12345);
        let packet = dhcp.build();
        assert!(packet.len() >= 300);
        // Check DHCP magic cookie
        assert_eq!(&packet[236..240], &[0x63, 0x82, 0x53, 0x63]);
    }

    #[test]
    fn test_kerberos_asreq_build() {
        let krb = KerberosAsReq::new("EXAMPLE.COM", "testuser");
        let packet = krb.build();
        assert!(packet.len() > 50);
        assert_eq!(packet[0], 0x6a); // AS-REQ tag
    }

    #[test]
    fn test_arp_request_build() {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = [192, 168, 1, 100];
        let target_ip = [192, 168, 1, 1];
        let arp = ArpPacket::new_request(sender_mac, sender_ip, target_ip);
        let packet = arp.build();
        assert_eq!(packet.len(), 28); // Standard ARP packet size
        // Check hardware type (Ethernet = 1)
        assert_eq!(&packet[0..2], &[0x00, 0x01]);
        // Check protocol type (IPv4 = 0x0800)
        assert_eq!(&packet[2..4], &[0x08, 0x00]);
    }

    #[test]
    fn test_arp_reply_build() {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = [192, 168, 1, 100];
        let target_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_ip = [192, 168, 1, 1];
        let arp = ArpPacket::new_reply(sender_mac, sender_ip, target_mac, target_ip);
        let packet = arp.build();
        assert_eq!(packet.len(), 28);
        // Check operation (Reply = 2)
        assert_eq!(&packet[6..8], &[0x00, 0x02]);
    }
}
