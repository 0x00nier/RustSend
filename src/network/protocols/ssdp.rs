//! SSDP protocol packet builder

pub struct SsdpRequest {
    method: String,
    host: String,
    headers: Vec<(String, String)>,
}

impl SsdpRequest {
    pub fn m_search() -> Self {
        Self {
            method: "M-SEARCH".to_string(),
            host: "239.255.255.250:1900".to_string(),
            headers: vec![
                ("MAN".to_string(), "\"ssdp:discover\"".to_string()),
                ("MX".to_string(), "3".to_string()),
                ("ST".to_string(), "ssdp:all".to_string()),
            ],
        }
    }

    pub fn with_st(mut self, st: &str) -> Self {
        if let Some(pos) = self.headers.iter().position(|(k, _)| k == "ST") {
            self.headers[pos].1 = st.to_string();
        }
        self
    }

    pub fn search_target(self, st: &str) -> Self {
        self.with_st(st)
    }

    pub fn mx(mut self, mx: u32) -> Self {
        if let Some(pos) = self.headers.iter().position(|(k, _)| k == "MX") {
            self.headers[pos].1 = mx.to_string();
        }
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut request = format!("{} * HTTP/1.1\r\n", self.method);
        request.push_str(&format!("HOST: {}\r\n", self.host));
        for (key, value) in &self.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
        request.push_str("\r\n");
        request.into_bytes()
    }
}
