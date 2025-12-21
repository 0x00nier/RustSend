//! SMB protocol packet builder

pub struct SmbNegotiatePacket {
    dialects: Vec<String>,
}

impl SmbNegotiatePacket {
    pub fn new() -> Self {
        Self {
            dialects: vec![
                "NT LM 0.12".to_string(),
                "SMB 2.002".to_string(),
                "SMB 2.???".to_string(),
            ],
        }
    }

    pub fn smb1_only() -> Self {
        Self {
            dialects: vec!["NT LM 0.12".to_string()],
        }
    }

    pub fn smb2_only() -> Self {
        Self {
            dialects: vec!["SMB 2.002".to_string(), "SMB 2.???".to_string()],
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(b"\xffSMB");
        packet.push(0x72);
        packet.extend_from_slice(&[0x00; 4]);
        packet.push(0x18);
        packet.extend_from_slice(&[0x53, 0xc0]);
        packet.extend_from_slice(&[0x00; 12]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0xff, 0xff]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x00]);
        let mut dialect_bytes = Vec::new();
        for dialect in &self.dialects {
            dialect_bytes.push(0x02);
            dialect_bytes.extend_from_slice(dialect.as_bytes());
            dialect_bytes.push(0x00);
        }
        let byte_count = dialect_bytes.len() as u16;
        packet.extend_from_slice(&byte_count.to_le_bytes());
        packet.extend(dialect_bytes);
        let len = (packet.len() - 4) as u32;
        packet[2] = ((len >> 8) & 0xff) as u8;
        packet[3] = (len & 0xff) as u8;
        packet
    }
}

impl Default for SmbNegotiatePacket {
    fn default() -> Self {
        Self::new()
    }
}
