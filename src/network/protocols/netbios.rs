//! NetBIOS Name Service protocol packet builder

pub struct NetBiosNsPacket {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    name: String,
}

impl NetBiosNsPacket {
    pub fn name_query(name: &str) -> Self {
        Self {
            transaction_id: rand::random(),
            flags: 0x0010,
            questions: 1,
            name: name.to_string(),
        }
    }

    pub fn node_status_query(name: &str) -> Self {
        Self {
            transaction_id: rand::random(),
            flags: 0x0000,
            questions: 1,
            name: name.to_string(),
        }
    }

    fn encode_netbios_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(34);
        encoded.push(32);
        let padded: String = format!("{:<15}", name.to_uppercase())
            .chars()
            .take(15)
            .collect();
        let with_suffix = format!("{}\x00", padded);
        for byte in with_suffix.bytes() {
            encoded.push(((byte >> 4) & 0x0f) + 0x41);
            encoded.push((byte & 0x0f) + 0x41);
        }
        encoded.push(0);
        encoded
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.transaction_id.to_be_bytes());
        packet.extend_from_slice(&self.flags.to_be_bytes());
        packet.extend_from_slice(&self.questions.to_be_bytes());
        packet.extend_from_slice(&[0u8; 6]);
        packet.extend(Self::encode_netbios_name(&self.name));
        packet.extend_from_slice(&[0x00, 0x21]);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet
    }
}
