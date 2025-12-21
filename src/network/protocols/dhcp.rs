//! DHCP protocol packet builder

pub struct DhcpDiscoverPacket {
    transaction_id: u32,
    client_mac: [u8; 6],
    hostname: Option<String>,
}

impl DhcpDiscoverPacket {
    pub fn new(client_mac: [u8; 6]) -> Self {
        Self {
            transaction_id: rand::random(),
            client_mac,
            hostname: None,
        }
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    pub fn with_transaction_id(mut self, xid: u32) -> Self {
        self.transaction_id = xid;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(300);
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0x06);
        packet.push(0x00);
        packet.extend_from_slice(&self.transaction_id.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x80, 0x00]);
        packet.extend_from_slice(&[0x00; 4]);
        packet.extend_from_slice(&[0x00; 4]);
        packet.extend_from_slice(&[0x00; 4]);
        packet.extend_from_slice(&[0x00; 4]);
        packet.extend_from_slice(&self.client_mac);
        packet.extend_from_slice(&[0x00; 10]);
        packet.extend_from_slice(&[0x00; 64]);
        packet.extend_from_slice(&[0x00; 128]);
        packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        packet.extend_from_slice(&[53, 1, 1]);
        packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
        if let Some(ref hostname) = self.hostname {
            let name_bytes = hostname.as_bytes();
            let len = std::cmp::min(name_bytes.len(), 255);
            packet.push(12);
            packet.push(len as u8);
            packet.extend_from_slice(&name_bytes[..len]);
        }
        packet.push(255);
        while packet.len() < 300 {
            packet.push(0);
        }
        packet
    }
}
