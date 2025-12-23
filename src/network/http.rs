//! HTTP parsing and stream viewing module
//!
//! Provides utilities for parsing HTTP requests/responses and
//! viewing HTTP streams in the TUI.

use crate::app::{HttpDirection, HttpStreamEntry};
use anyhow::{Context, Result};
use std::collections::HashMap;

/// HTTP request structure
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Add a header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the body
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.body = Some(data);
        self
    }

    /// Build the raw HTTP request bytes
    pub fn build(&self) -> Vec<u8> {
        let mut request = format!("{} {} {}\r\n", self.method, self.path, self.version);

        for (key, value) in &self.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        if let Some(body) = &self.body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }

        request.push_str("\r\n");

        let mut bytes = request.into_bytes();
        if let Some(body) = &self.body {
            bytes.extend_from_slice(body);
        }

        bytes
    }

    /// Create a GET request
    pub fn get(path: &str) -> Self {
        Self::new("GET", path).header("User-Agent", "NoirCast/0.1.0")
    }

    /// Create a POST request
    pub fn post(path: &str) -> Self {
        Self::new("POST", path).header("User-Agent", "NoirCast/0.1.0")
    }

    /// Create a HEAD request
    pub fn head(path: &str) -> Self {
        Self::new("HEAD", path).header("User-Agent", "NoirCast/0.1.0")
    }
}

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl HttpResponse {
    /// Parse an HTTP response from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);

        let status = response
            .parse(data)
            .context("Failed to parse HTTP response")?;

        let header_len = match status {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => data.len(),
        };

        let version = format!(
            "HTTP/1.{}",
            response.version.unwrap_or(1)
        );

        let status_code = response.code.unwrap_or(0);
        let status_text = response.reason.unwrap_or("").to_string();

        let mut header_map = HashMap::new();
        for header in response.headers.iter() {
            let name = header.name.to_string();
            let value = String::from_utf8_lossy(header.value).to_string();
            header_map.insert(name, value);
        }

        let body = if header_len < data.len() {
            Some(data[header_len..].to_vec())
        } else {
            None
        };

        Ok(Self {
            version,
            status_code,
            status_text,
            headers: header_map,
            body,
        })
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&String> {
        self.headers
            .get("Content-Type")
            .or_else(|| self.headers.get("content-type"))
    }

    /// Get content length
    pub fn content_length(&self) -> Option<usize> {
        self.headers
            .get("Content-Length")
            .or_else(|| self.headers.get("content-length"))
            .and_then(|v| v.parse().ok())
    }

    /// Check if response is successful (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if response is redirect (3xx)
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status_code)
    }

    /// Check if response is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Check if response is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    /// Format the response for display
    pub fn format_display(&self) -> String {
        let mut output = format!(
            "{} {} {}\n",
            self.version, self.status_code, self.status_text
        );

        for (key, value) in &self.headers {
            output.push_str(&format!("{}: {}\n", key, value));
        }

        if let Some(body) = &self.body {
            output.push_str("\n");
            // Try to display as text
            if let Ok(text) = std::str::from_utf8(body) {
                output.push_str(text);
            } else {
                output.push_str(&format!("[Binary data: {} bytes]", body.len()));
            }
        }

        output
    }
}

/// HTTP stream parser for tracking conversations
pub struct HttpStreamParser {
    entries: Vec<HttpStreamEntry>,
    pending_request: Option<HttpRequest>,
}

impl HttpStreamParser {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            pending_request: None,
        }
    }

    /// Parse raw data and identify HTTP request or response
    pub fn parse_data(&mut self, data: &[u8], timestamp: chrono::DateTime<chrono::Utc>) -> Option<HttpStreamEntry> {
        // Try to determine if this is a request or response
        if data.starts_with(b"HTTP/") {
            // This is a response
            if let Ok(response) = HttpResponse::parse(data) {
                let entry = HttpStreamEntry {
                    timestamp,
                    direction: HttpDirection::Response,
                    method: None,
                    url: None,
                    status_code: Some(response.status_code),
                    headers: response.headers.clone(),
                    body: response.body.as_ref().and_then(|b| String::from_utf8(b.clone()).ok()),
                    raw: data.to_vec(),
                };
                self.entries.push(entry.clone());
                return Some(entry);
            }
        } else if data.starts_with(b"GET ")
            || data.starts_with(b"POST ")
            || data.starts_with(b"PUT ")
            || data.starts_with(b"DELETE ")
            || data.starts_with(b"HEAD ")
            || data.starts_with(b"OPTIONS ")
            || data.starts_with(b"PATCH ")
        {
            // This is a request
            if let Ok((method, path, headers)) = Self::parse_request(data) {
                // Store as pending request for potential response matching
                let mut pending = HttpRequest::new(&method, &path);
                for (key, value) in &headers {
                    pending = pending.header(key, value);
                }
                if let Some(body) = Self::extract_body(data) {
                    pending.body = Some(body.into_bytes());
                }
                self.pending_request = Some(pending);

                let entry = HttpStreamEntry {
                    timestamp,
                    direction: HttpDirection::Request,
                    method: Some(method),
                    url: Some(path),
                    status_code: None,
                    headers,
                    body: Self::extract_body(data),
                    raw: data.to_vec(),
                };
                self.entries.push(entry.clone());
                return Some(entry);
            }
        }

        None
    }

    /// Get the pending request (most recent unmatched request)
    pub fn pending_request(&self) -> Option<&HttpRequest> {
        self.pending_request.as_ref()
    }

    /// Take and consume the pending request
    pub fn take_pending_request(&mut self) -> Option<HttpRequest> {
        self.pending_request.take()
    }

    /// Parse HTTP request manually
    fn parse_request(data: &[u8]) -> Result<(String, String, HashMap<String, String>)> {
        let text = std::str::from_utf8(data).context("Invalid UTF-8")?;
        let mut lines = text.lines();

        // Parse request line
        let request_line = lines.next().context("Empty request")?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid request line");
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok((method, path, headers))
    }

    /// Extract body from HTTP data
    fn extract_body(data: &[u8]) -> Option<String> {
        // Find the header/body separator
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let body_start = pos + 4;
            if body_start < data.len() {
                return String::from_utf8(data[body_start..].to_vec()).ok();
            }
        }
        None
    }

    /// Get all entries
    pub fn entries(&self) -> &[HttpStreamEntry] {
        &self.entries
    }

    /// Clear entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for HttpStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Format HTTP headers for display
pub fn format_headers(headers: &HashMap<String, String>) -> Vec<String> {
    headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect()
}

/// Get status code description
pub fn status_description(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// Common HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
}

impl HttpMethod {
    pub fn all() -> Vec<HttpMethod> {
        vec![
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Head,
            HttpMethod::Options,
            HttpMethod::Patch,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Connect => "CONNECT",
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// HTTP CONFIGURATION (curl-inspired features)
// =============================================================================

/// HTTP authentication methods
#[derive(Debug, Clone)]
pub enum HttpAuth {
    /// HTTP Basic authentication
    Basic { username: String, password: String },
    /// Bearer token authentication
    Bearer { token: String },
    /// HTTP Digest authentication (RFC 7616)
    Digest { username: String, password: String },
}

impl HttpAuth {
    /// Create Basic auth
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        HttpAuth::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Create Bearer token auth
    pub fn bearer(token: impl Into<String>) -> Self {
        HttpAuth::Bearer { token: token.into() }
    }

    /// Create Digest auth
    pub fn digest(username: impl Into<String>, password: impl Into<String>) -> Self {
        HttpAuth::Digest {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Get the Authorization header value for Basic auth
    pub fn basic_header_value(username: &str, password: &str) -> String {
        use std::io::Write;
        let credentials = format!("{}:{}", username, password);
        let mut encoded = String::new();
        {
            let mut encoder = base64_encoder(&mut encoded);
            encoder.write_all(credentials.as_bytes()).unwrap();
        }
        format!("Basic {}", encoded)
    }

    /// Get the Authorization header value
    pub fn to_header_value(&self) -> Option<String> {
        match self {
            HttpAuth::Basic { username, password } => {
                Some(Self::basic_header_value(username, password))
            }
            HttpAuth::Bearer { token } => {
                Some(format!("Bearer {}", token))
            }
            HttpAuth::Digest { .. } => {
                // Digest auth requires server challenge, can't be pre-computed
                None
            }
        }
    }
}

/// Simple base64 encoder for Basic auth
fn base64_encoder(output: &mut String) -> Base64Encoder<'_> {
    Base64Encoder { output }
}

struct Base64Encoder<'a> {
    output: &'a mut String,
}

impl<'a> std::io::Write for Base64Encoder<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in buf.chunks(3) {
            let mut val = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                val |= (byte as u32) << (16 - i * 8);
            }
            for i in 0..(chunk.len() + 1) {
                let idx = ((val >> (18 - i * 6)) & 0x3F) as usize;
                self.output.push(ALPHABET[idx] as char);
            }
            for _ in 0..(3 - chunk.len()) {
                self.output.push('=');
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// HTTP timeout configuration
#[derive(Debug, Clone)]
pub struct HttpTimeoutConfig {
    /// Connect timeout in milliseconds (default: 10000)
    pub connect_timeout_ms: u64,
    /// Maximum time for entire operation in milliseconds (default: 30000)
    pub max_time_ms: u64,
    /// DNS resolution timeout in milliseconds (default: 5000)
    pub dns_timeout_ms: u64,
}

impl Default for HttpTimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            max_time_ms: 30_000,
            dns_timeout_ms: 5_000,
        }
    }
}

/// HTTP retry configuration
#[derive(Debug, Clone)]
pub struct HttpRetryConfig {
    /// Maximum number of retries (default: 0)
    pub max_retries: u32,
    /// Delay between retries in milliseconds (default: 1000)
    pub retry_delay_ms: u64,
    /// Maximum total retry time in milliseconds (0 = unlimited)
    pub retry_max_time_ms: u64,
    /// Retry on timeout (default: true)
    pub retry_on_timeout: bool,
    /// Retry on connection refused (default: true)
    pub retry_on_connection_refused: bool,
    /// Use exponential backoff (default: true)
    pub exponential_backoff: bool,
}

impl Default for HttpRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 0,
            retry_delay_ms: 1_000,
            retry_max_time_ms: 0,
            retry_on_timeout: true,
            retry_on_connection_refused: true,
            exponential_backoff: true,
        }
    }
}

impl HttpRetryConfig {
    /// Calculate delay for the nth retry (0-indexed)
    pub fn delay_for_retry(&self, retry_num: u32) -> u64 {
        if self.exponential_backoff {
            // Exponential backoff: delay * 2^retry_num, capped at 60 seconds
            let multiplier = 2u64.pow(retry_num);
            (self.retry_delay_ms * multiplier).min(60_000)
        } else {
            self.retry_delay_ms
        }
    }
}

/// HTTP cookie
#[derive(Debug, Clone)]
pub struct HttpCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    pub secure: bool,
    pub http_only: bool,
}

impl HttpCookie {
    /// Create a simple cookie
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            expires: None,
            secure: false,
            http_only: false,
        }
    }

    /// Parse Set-Cookie header value
    pub fn parse(header_value: &str) -> Option<Self> {
        let mut parts = header_value.split(';');
        let name_value = parts.next()?.trim();
        let (name, value) = name_value.split_once('=')?;

        let mut cookie = Self::new(name.trim(), value.trim());

        for part in parts {
            let part = part.trim().to_lowercase();
            if part == "secure" {
                cookie.secure = true;
            } else if part == "httponly" {
                cookie.http_only = true;
            } else if let Some((attr, val)) = part.split_once('=') {
                match attr.trim() {
                    "domain" => cookie.domain = Some(val.trim().to_string()),
                    "path" => cookie.path = Some(val.trim().to_string()),
                    _ => {}
                }
            }
        }

        Some(cookie)
    }

    /// Format for Cookie header
    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// Cookie jar for managing multiple cookies
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: HashMap<String, HttpCookie>,
}

impl CookieJar {
    /// Create empty cookie jar
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a cookie
    pub fn set(&mut self, cookie: HttpCookie) {
        self.cookies.insert(cookie.name.clone(), cookie);
    }

    /// Get a cookie by name
    pub fn get(&self, name: &str) -> Option<&HttpCookie> {
        self.cookies.get(name)
    }

    /// Remove a cookie
    pub fn remove(&mut self, name: &str) -> Option<HttpCookie> {
        self.cookies.remove(name)
    }

    /// Clear all cookies
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Get Cookie header value for all cookies
    pub fn to_header_value(&self) -> String {
        self.cookies
            .values()
            .map(|c| c.to_header_value())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Update jar from Set-Cookie headers
    pub fn update_from_headers(&mut self, headers: &HashMap<String, String>) {
        // Check for Set-Cookie header (case insensitive)
        for (key, value) in headers {
            if key.eq_ignore_ascii_case("set-cookie") {
                if let Some(cookie) = HttpCookie::parse(value) {
                    self.set(cookie);
                }
            }
        }
    }

    /// Get cookie count
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Check if jar is empty
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

/// Full HTTP configuration (curl-inspired)
#[derive(Debug, Clone)]
pub struct HttpConfig {
    // Timeouts
    pub timeout: HttpTimeoutConfig,

    // Retry
    pub retry: HttpRetryConfig,

    // Authentication
    pub auth: Option<HttpAuth>,

    // Cookies
    pub cookies: CookieJar,

    // Redirects
    /// Follow HTTP redirects (default: false)
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow (default: 10)
    pub max_redirects: u8,

    // Headers
    /// User-Agent header value
    pub user_agent: String,
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
    /// Referer header
    pub referer: Option<String>,

    // Request modifications
    /// Force HTTP/1.0
    pub http10: bool,
    /// Disable Keep-Alive
    pub no_keepalive: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: HttpTimeoutConfig::default(),
            retry: HttpRetryConfig::default(),
            auth: None,
            cookies: CookieJar::new(),
            follow_redirects: false,
            max_redirects: 10,
            user_agent: "NoirCast/0.1.0".to_string(),
            custom_headers: HashMap::new(),
            referer: None,
            http10: false,
            no_keepalive: false,
        }
    }
}

impl HttpConfig {
    /// Create a new HTTP config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connect timeout
    pub fn connect_timeout(mut self, ms: u64) -> Self {
        self.timeout.connect_timeout_ms = ms;
        self
    }

    /// Set max operation time
    pub fn max_time(mut self, ms: u64) -> Self {
        self.timeout.max_time_ms = ms;
        self
    }

    /// Set retry count
    pub fn retries(mut self, count: u32) -> Self {
        self.retry.max_retries = count;
        self
    }

    /// Set Basic auth
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.auth = Some(HttpAuth::basic(username, password));
        self
    }

    /// Set Bearer token
    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.auth = Some(HttpAuth::bearer(token));
        self
    }

    /// Enable following redirects
    pub fn follow(mut self, enable: bool) -> Self {
        self.follow_redirects = enable;
        self
    }

    /// Set User-Agent
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.user_agent = ua.to_string();
        self
    }

    /// Add a custom header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.custom_headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set referer
    pub fn referer(mut self, url: &str) -> Self {
        self.referer = Some(url.to_string());
        self
    }

    /// Add a cookie
    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.set(HttpCookie::new(name, value));
        self
    }

    /// Apply config to an HttpRequest
    pub fn apply_to_request(&self, request: &mut HttpRequest) {
        // Set User-Agent
        request.headers.insert("User-Agent".to_string(), self.user_agent.clone());

        // Set auth header
        if let Some(ref auth) = self.auth {
            if let Some(header_value) = auth.to_header_value() {
                request.headers.insert("Authorization".to_string(), header_value);
            }
        }

        // Set cookies
        if !self.cookies.is_empty() {
            request.headers.insert("Cookie".to_string(), self.cookies.to_header_value());
        }

        // Set referer
        if let Some(ref referer) = self.referer {
            request.headers.insert("Referer".to_string(), referer.clone());
        }

        // Apply custom headers (last so they can override)
        for (key, value) in &self.custom_headers {
            request.headers.insert(key.clone(), value.clone());
        }

        // Connection header
        if self.no_keepalive {
            request.headers.insert("Connection".to_string(), "close".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_build() {
        let request = HttpRequest::get("/api/test")
            .header("Host", "example.com")
            .header("Accept", "*/*");

        let bytes = request.build();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("GET /api/test HTTP/1.1"));
        assert!(text.contains("Host: example.com"));
        assert!(text.contains("Accept: */*"));
    }

    #[test]
    fn test_http_response_parse() {
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";

        let response = HttpResponse::parse(response_data).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.status_text, "OK");
        assert!(response.is_success());
        assert_eq!(response.content_type(), Some(&"text/html".to_string()));
    }

    #[test]
    fn test_http_response_redirect() {
        let response = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status_code: 301,
            status_text: "Moved Permanently".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        assert!(response.is_redirect());
        assert!(!response.is_success());
    }

    #[test]
    fn test_status_description() {
        assert_eq!(status_description(200), "OK");
        assert_eq!(status_description(404), "Not Found");
        assert_eq!(status_description(500), "Internal Server Error");
    }

    #[test]
    fn test_http_stream_parser() {
        let mut parser = HttpStreamParser::new();

        let request_data = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let entry = parser.parse_data(request_data, chrono::Utc::now());

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.direction, HttpDirection::Request);
        assert_eq!(entry.method, Some("GET".to_string()));
    }
}
