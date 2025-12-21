//! NTP protocol packet builder

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
            li_vn_mode: 0x1b,
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

    fn current_ntp_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        const NTP_UNIX_OFFSET: u64 = 2208988800;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs() + NTP_UNIX_OFFSET;
        let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
        (secs << 32) | frac
    }

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
