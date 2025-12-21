//! LDAP protocol packet builder

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

pub struct LdapSearchRequest {
    message_id: u32,
    base_dn: String,
    scope: LdapScope,
    filter: String,
    attributes: Vec<String>,
}

impl LdapSearchRequest {
    pub fn new(base_dn: &str) -> Self {
        Self {
            message_id: 1,
            base_dn: base_dn.to_string(),
            scope: LdapScope::WholeSubtree,
            filter: "(objectClass=*)".to_string(),
            attributes: Vec::new(),
        }
    }

    pub fn message_id(mut self, id: u32) -> Self {
        self.message_id = id;
        self
    }

    pub fn scope(mut self, scope: LdapScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn filter(mut self, filter: &str) -> Self {
        self.filter = filter.to_string();
        self
    }

    pub fn attributes(mut self, attrs: Vec<&str>) -> Self {
        self.attributes = attrs.into_iter().map(|s| s.to_string()).collect();
        self
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

    fn encode_integer(value: u32) -> Vec<u8> {
        let mut result = vec![0x02];
        if value < 128 {
            result.push(1);
            result.push(value as u8);
        } else if value < 32768 {
            result.push(2);
            result.extend_from_slice(&(value as u16).to_be_bytes());
        } else {
            result.push(4);
            result.extend_from_slice(&value.to_be_bytes());
        }
        result
    }

    fn encode_string(s: &str) -> Vec<u8> {
        let mut result = vec![0x04];
        result.extend(Self::encode_length(s.len()));
        result.extend_from_slice(s.as_bytes());
        result
    }

    fn encode_filter(filter: &str) -> Vec<u8> {
        if filter == "(objectClass=*)" {
            return vec![0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's'];
        }
        let mut result = vec![0x87];
        let inner = filter.trim_start_matches('(').trim_end_matches(')');
        result.extend(Self::encode_length(inner.len()));
        result.extend_from_slice(inner.as_bytes());
        result
    }

    pub fn build(&self) -> Vec<u8> {
        let message_id = Self::encode_integer(self.message_id);
        let base_dn = Self::encode_string(&self.base_dn);
        let scope = vec![0x0a, 0x01, self.scope as u8];
        let deref = vec![0x0a, 0x01, 0x00];
        let size_limit = Self::encode_integer(0);
        let time_limit = Self::encode_integer(0);
        let types_only = vec![0x01, 0x01, 0x00];
        let filter = Self::encode_filter(&self.filter);
        let mut attrs = vec![0x30];
        let mut attrs_content = Vec::new();
        for attr in &self.attributes {
            attrs_content.extend(Self::encode_string(attr));
        }
        attrs.extend(Self::encode_length(attrs_content.len()));
        attrs.extend(attrs_content);
        let mut search_request_content: Vec<u8> = Vec::new();
        search_request_content.extend(&base_dn);
        search_request_content.extend(&scope);
        search_request_content.extend(&deref);
        search_request_content.extend(&size_limit);
        search_request_content.extend(&time_limit);
        search_request_content.extend(&types_only);
        search_request_content.extend(&filter);
        search_request_content.extend(&attrs);
        let mut search_request = vec![0x63];
        search_request.extend(Self::encode_length(search_request_content.len()));
        search_request.extend(search_request_content);
        let mut message_content: Vec<u8> = Vec::new();
        message_content.extend(&message_id);
        message_content.extend(&search_request);
        let mut packet = vec![0x30];
        packet.extend(Self::encode_length(message_content.len()));
        packet.extend(message_content);
        packet
    }

    pub fn rootdse_query() -> Self {
        Self::new("")
            .scope(LdapScope::BaseObject)
            .filter("(objectClass=*)")
            .attributes(vec!["namingContexts", "defaultNamingContext", "rootDomainNamingContext"])
    }
}
