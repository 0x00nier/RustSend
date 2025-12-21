//! Kerberos protocol packet builder

pub struct KerberosAsReq {
    realm: String,
    cname: String,
    sname: String,
}

impl KerberosAsReq {
    pub fn new(realm: &str, username: &str) -> Self {
        Self {
            realm: realm.to_uppercase(),
            cname: username.to_string(),
            sname: format!("krbtgt/{}", realm.to_uppercase()),
        }
    }

    fn encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8]
        }
    }

    fn encode_integer(value: i32) -> Vec<u8> {
        let mut result = vec![0x02];
        if value >= 0 && value < 128 {
            result.push(1);
            result.push(value as u8);
        } else {
            let bytes = value.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0 && b != 0xff).unwrap_or(3);
            let len = 4 - start;
            result.push(len as u8);
            result.extend_from_slice(&bytes[start..]);
        }
        result
    }

    fn encode_string(s: &str) -> Vec<u8> {
        let mut result = vec![0x1b];
        result.extend(Self::encode_length(s.len()));
        result.extend_from_slice(s.as_bytes());
        result
    }

    fn encode_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut result = vec![0xa0 | tag];
        result.extend(Self::encode_length(content.len()));
        result.extend_from_slice(content);
        result
    }

    fn encode_sequence(content: &[u8]) -> Vec<u8> {
        let mut result = vec![0x30];
        result.extend(Self::encode_length(content.len()));
        result.extend_from_slice(content);
        result
    }

    fn encode_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
        let type_field = Self::encode_context_tag(0, &Self::encode_integer(name_type));
        let mut name_strings = Vec::new();
        for name in names {
            name_strings.extend(Self::encode_string(name));
        }
        let names_seq = Self::encode_sequence(&name_strings);
        let names_field = Self::encode_context_tag(1, &names_seq);
        let mut content = Vec::new();
        content.extend(type_field);
        content.extend(names_field);
        Self::encode_sequence(&content)
    }

    pub fn build(&self) -> Vec<u8> {
        let pvno = Self::encode_context_tag(1, &Self::encode_integer(5));
        let msg_type = Self::encode_context_tag(2, &Self::encode_integer(10));
        let kdc_options_bits = vec![0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10];
        let kdc_options = Self::encode_context_tag(0, &kdc_options_bits);
        let cname = Self::encode_context_tag(1, &Self::encode_principal_name(1, &[&self.cname]));
        let realm = Self::encode_context_tag(2, &Self::encode_string(&self.realm));
        let sname_parts: Vec<&str> = self.sname.split('/').collect();
        let sname = Self::encode_context_tag(3, &Self::encode_principal_name(2, &sname_parts));
        let till = Self::encode_context_tag(5, &[0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a]);
        let nonce_val: u32 = rand::random();
        let nonce = Self::encode_context_tag(7, &Self::encode_integer(nonce_val as i32));
        let etypes = Self::encode_context_tag(8, &Self::encode_sequence(&[
            Self::encode_integer(18).as_slice(),
            Self::encode_integer(17).as_slice(),
            Self::encode_integer(23).as_slice(),
        ].concat()));
        let mut req_body_content = Vec::new();
        req_body_content.extend(kdc_options);
        req_body_content.extend(cname);
        req_body_content.extend(realm);
        req_body_content.extend(sname);
        req_body_content.extend(till);
        req_body_content.extend(nonce);
        req_body_content.extend(etypes);
        let req_body = Self::encode_context_tag(4, &Self::encode_sequence(&req_body_content));
        let mut as_req_content = Vec::new();
        as_req_content.extend(pvno);
        as_req_content.extend(msg_type);
        as_req_content.extend(req_body);
        let as_req_seq = Self::encode_sequence(&as_req_content);
        let mut packet = vec![0x6a];
        packet.extend(Self::encode_length(as_req_seq.len()));
        packet.extend(as_req_seq);
        packet
    }
}
