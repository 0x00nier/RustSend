//! ARP protocol packet builder

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
}

pub struct ArpPacket {
    hardware_type: u16,
    protocol_type: u16,
    hardware_len: u8,
    protocol_len: u8,
    operation: ArpOperation,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn new_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: 6,
            protocol_len: 4,
            operation: ArpOperation::Request,
            sender_mac,
            sender_ip,
            target_mac: [0xff; 6],
            target_ip,
        }
    }

    pub fn new_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: 6,
            protocol_len: 4,
            operation: ArpOperation::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(28);
        packet.extend_from_slice(&self.hardware_type.to_be_bytes());
        packet.extend_from_slice(&self.protocol_type.to_be_bytes());
        packet.push(self.hardware_len);
        packet.push(self.protocol_len);
        packet.extend_from_slice(&(self.operation as u16).to_be_bytes());
        packet.extend_from_slice(&self.sender_mac);
        packet.extend_from_slice(&self.sender_ip);
        packet.extend_from_slice(&self.target_mac);
        packet.extend_from_slice(&self.target_ip);
        packet
    }
}
