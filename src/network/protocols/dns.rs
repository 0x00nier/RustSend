//! DNS protocol packet builder

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
            flags: 0x0100,
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
            qclass: 1,
        });
        self
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.transaction_id.to_be_bytes());
        packet.extend_from_slice(&self.flags.to_be_bytes());
        packet.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[0u8; 6]);
        for question in &self.questions {
            packet.extend(Self::encode_name(&question.name));
            packet.extend_from_slice(&(question.qtype as u16).to_be_bytes());
            packet.extend_from_slice(&question.qclass.to_be_bytes());
        }
        packet
    }

    pub fn a_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::A)
    }

    pub fn aaaa_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Aaaa)
    }

    pub fn mx_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Mx)
    }

    pub fn txt_query(domain: &str) -> Self {
        Self::new().add_question(domain, DnsType::Txt)
    }
}

impl Default for DnsQuery {
    fn default() -> Self {
        Self::new()
    }
}
