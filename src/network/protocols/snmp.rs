//! SNMP protocol packet builder

pub struct SnmpGetRequest {
    version: u8,
    community: String,
    request_id: u32,
    oids: Vec<String>,
}

impl SnmpGetRequest {
    pub fn new(community: &str) -> Self {
        Self {
            version: 1,
            community: community.to_string(),
            request_id: rand::random(),
            oids: Vec::new(),
        }
    }

    pub fn add_oid(mut self, oid: &str) -> Self {
        self.oids.push(oid.to_string());
        self
    }

    fn encode_oid(oid: &str) -> Vec<u8> {
        let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() < 2 { return vec![]; }
        let mut encoded = vec![(parts[0] * 40 + parts[1]) as u8];
        for &part in &parts[2..] {
            if part < 128 {
                encoded.push(part as u8);
            } else {
                let mut temp = Vec::new();
                let mut val = part;
                while val > 0 {
                    temp.push((val & 0x7f) as u8);
                    val >>= 7;
                }
                temp.reverse();
                let temp_len = temp.len();
                for (i, b) in temp.iter_mut().enumerate() {
                    if i < temp_len - 1 { *b |= 0x80; }
                }
                encoded.extend(temp);
            }
        }
        encoded
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x30);
        let version_tlv = vec![0x02, 0x01, self.version];
        let mut community_tlv = vec![0x04, self.community.len() as u8];
        community_tlv.extend_from_slice(self.community.as_bytes());
        let mut pdu = vec![0xa0];
        let mut request_id_tlv = vec![0x02, 0x04];
        request_id_tlv.extend_from_slice(&self.request_id.to_be_bytes());
        let error_status = vec![0x02, 0x01, 0x00];
        let error_index = vec![0x02, 0x01, 0x00];
        let mut varbinds = vec![0x30];
        let mut varbind_data = Vec::new();
        for oid in &self.oids {
            let encoded_oid = Self::encode_oid(oid);
            let mut varbind = vec![0x30];
            let mut oid_tlv = vec![0x06, encoded_oid.len() as u8];
            oid_tlv.extend(encoded_oid);
            let null_tlv = vec![0x05, 0x00];
            let varbind_content_len = oid_tlv.len() + null_tlv.len();
            varbind.push(varbind_content_len as u8);
            varbind.extend(oid_tlv);
            varbind.extend(null_tlv);
            varbind_data.extend(varbind);
        }
        varbinds.push(varbind_data.len() as u8);
        varbinds.extend(varbind_data);
        let pdu_content_len = request_id_tlv.len() + error_status.len() + error_index.len() + varbinds.len();
        pdu.push(pdu_content_len as u8);
        pdu.extend(request_id_tlv);
        pdu.extend(error_status);
        pdu.extend(error_index);
        pdu.extend(varbinds);
        let total_len = version_tlv.len() + community_tlv.len() + pdu.len();
        packet.push(total_len as u8);
        packet.extend(version_tlv);
        packet.extend(community_tlv);
        packet.extend(pdu);
        packet
    }
}
