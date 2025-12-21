//! Common network services and port mappings

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub name: &'static str,
    pub protocol: &'static str,
    pub description: &'static str,
}

pub const COMMON_SERVICES: &[ServiceInfo] = &[
    ServiceInfo { port: 20, name: "FTP-DATA", protocol: "TCP", description: "FTP Data Transfer" },
    ServiceInfo { port: 21, name: "FTP", protocol: "TCP", description: "FTP Control" },
    ServiceInfo { port: 22, name: "SSH", protocol: "TCP", description: "Secure Shell" },
    ServiceInfo { port: 23, name: "Telnet", protocol: "TCP", description: "Telnet" },
    ServiceInfo { port: 25, name: "SMTP", protocol: "TCP", description: "Simple Mail Transfer" },
    ServiceInfo { port: 53, name: "DNS", protocol: "TCP/UDP", description: "Domain Name System" },
    ServiceInfo { port: 67, name: "DHCP", protocol: "UDP", description: "DHCP Server" },
    ServiceInfo { port: 68, name: "DHCP", protocol: "UDP", description: "DHCP Client" },
    ServiceInfo { port: 69, name: "TFTP", protocol: "UDP", description: "Trivial File Transfer" },
    ServiceInfo { port: 80, name: "HTTP", protocol: "TCP", description: "Hypertext Transfer" },
    ServiceInfo { port: 88, name: "Kerberos", protocol: "TCP/UDP", description: "Kerberos Authentication" },
    ServiceInfo { port: 110, name: "POP3", protocol: "TCP", description: "Post Office Protocol v3" },
    ServiceInfo { port: 119, name: "NNTP", protocol: "TCP", description: "Network News Transfer" },
    ServiceInfo { port: 123, name: "NTP", protocol: "UDP", description: "Network Time Protocol" },
    ServiceInfo { port: 135, name: "RPC", protocol: "TCP", description: "Microsoft RPC" },
    ServiceInfo { port: 137, name: "NetBIOS-NS", protocol: "UDP", description: "NetBIOS Name Service" },
    ServiceInfo { port: 138, name: "NetBIOS-DGM", protocol: "UDP", description: "NetBIOS Datagram" },
    ServiceInfo { port: 139, name: "NetBIOS-SSN", protocol: "TCP", description: "NetBIOS Session" },
    ServiceInfo { port: 143, name: "IMAP", protocol: "TCP", description: "Internet Message Access" },
    ServiceInfo { port: 161, name: "SNMP", protocol: "UDP", description: "Simple Network Management" },
    ServiceInfo { port: 162, name: "SNMPTRAP", protocol: "UDP", description: "SNMP Trap" },
    ServiceInfo { port: 389, name: "LDAP", protocol: "TCP", description: "Lightweight Directory Access" },
    ServiceInfo { port: 443, name: "HTTPS", protocol: "TCP", description: "HTTP over TLS/SSL" },
    ServiceInfo { port: 445, name: "SMB", protocol: "TCP", description: "Server Message Block" },
    ServiceInfo { port: 464, name: "Kerberos", protocol: "TCP/UDP", description: "Kerberos Password Change" },
    ServiceInfo { port: 465, name: "SMTPS", protocol: "TCP", description: "SMTP over SSL" },
    ServiceInfo { port: 500, name: "IKE", protocol: "UDP", description: "Internet Key Exchange" },
    ServiceInfo { port: 514, name: "Syslog", protocol: "UDP", description: "System Logging" },
    ServiceInfo { port: 515, name: "LPD", protocol: "TCP", description: "Line Printer Daemon" },
    ServiceInfo { port: 520, name: "RIP", protocol: "UDP", description: "Routing Information Protocol" },
    ServiceInfo { port: 587, name: "Submission", protocol: "TCP", description: "Mail Submission" },
    ServiceInfo { port: 636, name: "LDAPS", protocol: "TCP", description: "LDAP over SSL" },
    ServiceInfo { port: 993, name: "IMAPS", protocol: "TCP", description: "IMAP over SSL" },
    ServiceInfo { port: 995, name: "POP3S", protocol: "TCP", description: "POP3 over SSL" },
    ServiceInfo { port: 1433, name: "MSSQL", protocol: "TCP", description: "Microsoft SQL Server" },
    ServiceInfo { port: 1521, name: "Oracle", protocol: "TCP", description: "Oracle Database" },
    ServiceInfo { port: 1723, name: "PPTP", protocol: "TCP", description: "Point-to-Point Tunneling" },
    ServiceInfo { port: 1900, name: "SSDP", protocol: "UDP", description: "Simple Service Discovery" },
    ServiceInfo { port: 2049, name: "NFS", protocol: "TCP/UDP", description: "Network File System" },
    ServiceInfo { port: 3306, name: "MySQL", protocol: "TCP", description: "MySQL Database" },
    ServiceInfo { port: 3389, name: "RDP", protocol: "TCP", description: "Remote Desktop Protocol" },
    ServiceInfo { port: 5060, name: "SIP", protocol: "TCP/UDP", description: "Session Initiation Protocol" },
    ServiceInfo { port: 5432, name: "PostgreSQL", protocol: "TCP", description: "PostgreSQL Database" },
    ServiceInfo { port: 5900, name: "VNC", protocol: "TCP", description: "Virtual Network Computing" },
    ServiceInfo { port: 6379, name: "Redis", protocol: "TCP", description: "Redis Database" },
    ServiceInfo { port: 8080, name: "HTTP-Alt", protocol: "TCP", description: "HTTP Alternate" },
    ServiceInfo { port: 8443, name: "HTTPS-Alt", protocol: "TCP", description: "HTTPS Alternate" },
    ServiceInfo { port: 27017, name: "MongoDB", protocol: "TCP", description: "MongoDB Database" },
];

pub fn get_service_by_port(port: u16) -> Option<&'static ServiceInfo> {
    COMMON_SERVICES.iter().find(|s| s.port == port)
}

pub fn get_service_name(port: u16) -> &'static str {
    get_service_by_port(port).map(|s| s.name).unwrap_or("Unknown")
}
