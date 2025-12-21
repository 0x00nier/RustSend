//! Enhanced error types with context and categories
//!
//! Provides curl-inspired comprehensive error handling with detailed
//! context, categorization, and recovery suggestions.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Error categories for classification and retry logic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Network connectivity issues (transient, usually retriable)
    Network,
    /// DNS resolution failures
    Dns,
    /// Connection establishment failures
    Connection,
    /// Timeout errors (potentially retriable)
    Timeout,
    /// Protocol-level errors
    Protocol,
    /// Authentication/authorization errors
    Auth,
    /// Resource exhaustion (too many connections, memory, etc.)
    Resource,
    /// Input validation errors (not retriable)
    Validation,
    /// Internal errors (bugs, unexpected states)
    Internal,
    /// TLS/SSL errors
    Tls,
}

impl ErrorCategory {
    /// Whether errors in this category are generally retriable
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            ErrorCategory::Network
                | ErrorCategory::Timeout
                | ErrorCategory::Dns
                | ErrorCategory::Resource
        )
    }

    /// Suggested retry delay multiplier for this category
    pub fn retry_delay_multiplier(&self) -> f64 {
        match self {
            ErrorCategory::Timeout => 1.5,
            ErrorCategory::Resource => 2.0,
            ErrorCategory::Network => 1.0,
            ErrorCategory::Dns => 1.0,
            _ => 1.0,
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Network => write!(f, "Network"),
            ErrorCategory::Dns => write!(f, "DNS"),
            ErrorCategory::Connection => write!(f, "Connection"),
            ErrorCategory::Timeout => write!(f, "Timeout"),
            ErrorCategory::Protocol => write!(f, "Protocol"),
            ErrorCategory::Auth => write!(f, "Authentication"),
            ErrorCategory::Resource => write!(f, "Resource"),
            ErrorCategory::Validation => write!(f, "Validation"),
            ErrorCategory::Internal => write!(f, "Internal"),
            ErrorCategory::Tls => write!(f, "TLS/SSL"),
        }
    }
}

/// Comprehensive network error type with context
#[derive(Error, Debug)]
pub enum NetworkError {
    // DNS errors
    #[error("DNS resolution failed for '{host}': {reason}")]
    DnsResolution {
        host: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("DNS timeout for '{host}' after {elapsed:?}")]
    DnsTimeout {
        host: String,
        elapsed: Duration,
    },

    // Connection errors
    #[error("Connection refused by {addr}")]
    ConnectionRefused {
        addr: SocketAddr,
    },

    #[error("Connection timeout to {addr} after {elapsed:?}")]
    ConnectionTimeout {
        addr: SocketAddr,
        elapsed: Duration,
    },

    #[error("Connection reset by {addr}")]
    ConnectionReset {
        addr: SocketAddr,
    },

    #[error("Network unreachable: {addr}")]
    NetworkUnreachable {
        addr: SocketAddr,
        gateway: Option<String>,
    },

    #[error("Host unreachable: {addr}")]
    HostUnreachable {
        addr: SocketAddr,
    },

    // Timeout errors
    #[error("Operation timeout after {elapsed:?} (limit: {limit:?})")]
    OperationTimeout {
        operation: String,
        elapsed: Duration,
        limit: Duration,
    },

    #[error("Read timeout after {elapsed:?}")]
    ReadTimeout {
        elapsed: Duration,
    },

    #[error("Write timeout after {elapsed:?}")]
    WriteTimeout {
        elapsed: Duration,
    },

    // Protocol errors
    #[error("Protocol error: {message}")]
    ProtocolError {
        protocol: String,
        message: String,
    },

    #[error("Invalid response from {addr}: {reason}")]
    InvalidResponse {
        addr: SocketAddr,
        reason: String,
    },

    #[error("Unexpected protocol state: expected {expected}, got {actual}")]
    UnexpectedState {
        expected: String,
        actual: String,
    },

    // Resource errors
    #[error("Too many open connections ({current}/{max})")]
    TooManyConnections {
        current: usize,
        max: usize,
    },

    #[error("Buffer allocation failed: {reason}")]
    BufferAllocation {
        reason: String,
    },

    #[error("Socket creation failed: {reason}")]
    SocketCreation {
        reason: String,
    },

    // Validation errors
    #[error("Invalid target: {message}")]
    InvalidTarget {
        message: String,
    },

    #[error("Invalid port: {port}")]
    InvalidPort {
        port: String,
    },

    #[error("Invalid packet: {reason}")]
    InvalidPacket {
        reason: String,
    },

    // TLS errors
    #[error("TLS handshake failed with {addr}: {reason}")]
    TlsHandshake {
        addr: SocketAddr,
        reason: String,
    },

    #[error("Certificate error for {host}: {reason}")]
    CertificateError {
        host: String,
        reason: String,
    },

    // Generic
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl NetworkError {
    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            NetworkError::DnsResolution { .. } | NetworkError::DnsTimeout { .. } => {
                ErrorCategory::Dns
            }
            NetworkError::ConnectionRefused { .. }
            | NetworkError::ConnectionReset { .. }
            | NetworkError::NetworkUnreachable { .. }
            | NetworkError::HostUnreachable { .. } => ErrorCategory::Connection,
            NetworkError::ConnectionTimeout { .. }
            | NetworkError::OperationTimeout { .. }
            | NetworkError::ReadTimeout { .. }
            | NetworkError::WriteTimeout { .. } => ErrorCategory::Timeout,
            NetworkError::ProtocolError { .. }
            | NetworkError::InvalidResponse { .. }
            | NetworkError::UnexpectedState { .. } => ErrorCategory::Protocol,
            NetworkError::TooManyConnections { .. }
            | NetworkError::BufferAllocation { .. }
            | NetworkError::SocketCreation { .. } => ErrorCategory::Resource,
            NetworkError::InvalidTarget { .. }
            | NetworkError::InvalidPort { .. }
            | NetworkError::InvalidPacket { .. } => ErrorCategory::Validation,
            NetworkError::TlsHandshake { .. } | NetworkError::CertificateError { .. } => {
                ErrorCategory::Tls
            }
            NetworkError::Io(e) => match e.kind() {
                std::io::ErrorKind::TimedOut => ErrorCategory::Timeout,
                std::io::ErrorKind::ConnectionRefused => ErrorCategory::Connection,
                std::io::ErrorKind::ConnectionReset => ErrorCategory::Connection,
                std::io::ErrorKind::NotConnected => ErrorCategory::Connection,
                _ => ErrorCategory::Network,
            },
            NetworkError::Other(_) => ErrorCategory::Internal,
        }
    }

    /// Whether this error is retriable
    pub fn is_retriable(&self) -> bool {
        self.category().is_retriable()
    }

    /// Get a user-friendly suggestion for resolving this error
    pub fn suggestion(&self) -> String {
        match self {
            NetworkError::DnsResolution { host, .. } => {
                format!(
                    "Check if '{}' is spelled correctly and is a valid hostname. \
                    Try using an IP address instead.",
                    host
                )
            }
            NetworkError::DnsTimeout { .. } => {
                "DNS server may be slow or unreachable. Try increasing timeout or using a different DNS server.".to_string()
            }
            NetworkError::ConnectionRefused { addr } => {
                format!(
                    "No service is listening on {}. Verify the port is correct and the service is running.",
                    addr
                )
            }
            NetworkError::ConnectionTimeout { .. } => {
                "Connection is taking too long. The host may be behind a firewall, or try increasing the timeout.".to_string()
            }
            NetworkError::NetworkUnreachable { .. } => {
                "Check your network connection and routing table. The destination network may not be accessible.".to_string()
            }
            NetworkError::HostUnreachable { .. } => {
                "The specific host cannot be reached. It may be offline or blocking connections.".to_string()
            }
            NetworkError::TooManyConnections { max, .. } => {
                format!(
                    "Reduce batch size or wait for connections to complete. Current limit is {}.",
                    max
                )
            }
            NetworkError::InvalidTarget { message } => {
                format!("Fix the target specification: {}", message)
            }
            NetworkError::TlsHandshake { .. } => {
                "TLS negotiation failed. Check certificate validity and supported protocols.".to_string()
            }
            _ => "Check network connectivity and target availability.".to_string(),
        }
    }

    /// Get an error code for programmatic handling
    pub fn code(&self) -> i32 {
        match self {
            NetworkError::DnsResolution { .. } => 6,  // CURLE_COULDNT_RESOLVE_HOST
            NetworkError::DnsTimeout { .. } => 28,    // CURLE_OPERATION_TIMEDOUT
            NetworkError::ConnectionRefused { .. } => 7, // CURLE_COULDNT_CONNECT
            NetworkError::ConnectionTimeout { .. } => 28,
            NetworkError::ConnectionReset { .. } => 56, // CURLE_RECV_ERROR
            NetworkError::NetworkUnreachable { .. } => 7,
            NetworkError::HostUnreachable { .. } => 7,
            NetworkError::OperationTimeout { .. } => 28,
            NetworkError::ReadTimeout { .. } => 28,
            NetworkError::WriteTimeout { .. } => 55, // CURLE_SEND_ERROR
            NetworkError::ProtocolError { .. } => 8, // CURLE_WEIRD_SERVER_REPLY
            NetworkError::InvalidResponse { .. } => 8,
            NetworkError::UnexpectedState { .. } => 8,
            NetworkError::TooManyConnections { .. } => 89, // CURLE_NO_CONNECTION_AVAILABLE
            NetworkError::BufferAllocation { .. } => 27, // CURLE_OUT_OF_MEMORY
            NetworkError::SocketCreation { .. } => 45, // CURLE_INTERFACE_FAILED
            NetworkError::InvalidTarget { .. } => 3, // CURLE_URL_MALFORMAT
            NetworkError::InvalidPort { .. } => 3,
            NetworkError::InvalidPacket { .. } => 3,
            NetworkError::TlsHandshake { .. } => 35, // CURLE_SSL_CONNECT_ERROR
            NetworkError::CertificateError { .. } => 60, // CURLE_PEER_FAILED_VERIFICATION
            NetworkError::Io(_) => 1,
            NetworkError::Other(_) => 1,
        }
    }
}

/// Error context wrapper for adding metadata to errors
#[derive(Debug)]
pub struct ErrorContext {
    /// The underlying error
    pub error: NetworkError,
    /// Operation being performed
    pub operation: String,
    /// Target address or identifier
    pub target: String,
    /// When the error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// How long the operation took before failing
    pub duration: Duration,
    /// Retry attempt number (0 for first attempt)
    pub attempt: u32,
    /// Additional context
    pub metadata: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(error: NetworkError, operation: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            error,
            operation: operation.into(),
            target: target.into(),
            timestamp: chrono::Utc::now(),
            duration: Duration::ZERO,
            attempt: 0,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set the duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set the attempt number
    pub fn with_attempt(mut self, attempt: u32) -> Self {
        self.attempt = attempt;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        self.error.category()
    }

    /// Whether this error is retriable
    pub fn is_retriable(&self) -> bool {
        self.error.is_retriable()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} failed for {} after {:?}",
            self.timestamp.format("%H:%M:%S"),
            self.operation,
            self.target,
            self.duration
        )?;

        if self.attempt > 0 {
            write!(f, " (attempt {})", self.attempt + 1)?;
        }

        write!(f, "\nError: {}", self.error)?;
        write!(f, "\nSuggestion: {}", self.error.suggestion())?;

        if !self.metadata.is_empty() {
            write!(f, "\nMetadata:")?;
            for (k, v) in &self.metadata {
                write!(f, "\n  {}: {}", k, v)?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for ErrorContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Helper trait for adding context to errors
pub trait WithContext<T> {
    /// Add operation context to an error
    fn with_operation(self, operation: impl Into<String>) -> Result<T, ErrorContext>;

    /// Add target context to an error
    fn with_target(self, target: impl Into<String>) -> Result<T, ErrorContext>;
}

impl<T> WithContext<T> for Result<T, NetworkError> {
    fn with_operation(self, operation: impl Into<String>) -> Result<T, ErrorContext> {
        self.map_err(|e| ErrorContext::new(e, operation, "unknown"))
    }

    fn with_target(self, target: impl Into<String>) -> Result<T, ErrorContext> {
        self.map_err(|e| ErrorContext::new(e, "unknown operation", target))
    }
}

/// Convert std::io::Error to NetworkError with more context
pub fn from_io_error(e: std::io::Error, addr: Option<SocketAddr>) -> NetworkError {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => {
            if let Some(addr) = addr {
                NetworkError::ConnectionRefused { addr }
            } else {
                NetworkError::Io(e)
            }
        }
        std::io::ErrorKind::ConnectionReset => {
            if let Some(addr) = addr {
                NetworkError::ConnectionReset { addr }
            } else {
                NetworkError::Io(e)
            }
        }
        std::io::ErrorKind::TimedOut => {
            if let Some(addr) = addr {
                NetworkError::ConnectionTimeout {
                    addr,
                    elapsed: Duration::ZERO,
                }
            } else {
                NetworkError::Io(e)
            }
        }
        _ => NetworkError::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80))
    }

    #[test]
    fn test_error_category_retriable() {
        assert!(ErrorCategory::Network.is_retriable());
        assert!(ErrorCategory::Timeout.is_retriable());
        assert!(ErrorCategory::Dns.is_retriable());
        assert!(!ErrorCategory::Validation.is_retriable());
        assert!(!ErrorCategory::Auth.is_retriable());
    }

    #[test]
    fn test_network_error_category() {
        let err = NetworkError::DnsResolution {
            host: "test.com".to_string(),
            reason: "NXDOMAIN".to_string(),
            source: None,
        };
        assert_eq!(err.category(), ErrorCategory::Dns);

        let err = NetworkError::ConnectionRefused { addr: test_addr() };
        assert_eq!(err.category(), ErrorCategory::Connection);

        let err = NetworkError::ConnectionTimeout {
            addr: test_addr(),
            elapsed: Duration::from_secs(5),
        };
        assert_eq!(err.category(), ErrorCategory::Timeout);
    }

    #[test]
    fn test_network_error_retriable() {
        let err = NetworkError::ConnectionTimeout {
            addr: test_addr(),
            elapsed: Duration::from_secs(5),
        };
        assert!(err.is_retriable());

        let err = NetworkError::InvalidTarget {
            message: "bad target".to_string(),
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn test_error_code() {
        let err = NetworkError::DnsResolution {
            host: "test.com".to_string(),
            reason: "failed".to_string(),
            source: None,
        };
        assert_eq!(err.code(), 6);

        let err = NetworkError::ConnectionRefused { addr: test_addr() };
        assert_eq!(err.code(), 7);

        let err = NetworkError::ConnectionTimeout {
            addr: test_addr(),
            elapsed: Duration::from_secs(5),
        };
        assert_eq!(err.code(), 28);
    }

    #[test]
    fn test_error_suggestion() {
        let err = NetworkError::ConnectionRefused { addr: test_addr() };
        let suggestion = err.suggestion();
        assert!(suggestion.contains("service"));

        let err = NetworkError::DnsTimeout {
            host: "slow.dns".to_string(),
            elapsed: Duration::from_secs(10),
        };
        let suggestion = err.suggestion();
        assert!(suggestion.contains("DNS"));
    }

    #[test]
    fn test_error_context() {
        let err = NetworkError::ConnectionRefused { addr: test_addr() };
        let ctx = ErrorContext::new(err, "TCP connect", "192.168.1.1:80")
            .with_duration(Duration::from_millis(100))
            .with_attempt(2)
            .with_metadata("scan_type", "SYN");

        assert_eq!(ctx.category(), ErrorCategory::Connection);
        assert!(!ctx.is_retriable()); // Connection refused is not retriable
        assert_eq!(ctx.attempt, 2);
    }

    #[test]
    fn test_error_context_display() {
        let err = NetworkError::DnsResolution {
            host: "example.com".to_string(),
            reason: "NXDOMAIN".to_string(),
            source: None,
        };
        let ctx = ErrorContext::new(err, "DNS lookup", "example.com")
            .with_duration(Duration::from_millis(50));

        let display = format!("{}", ctx);
        assert!(display.contains("DNS lookup"));
        assert!(display.contains("example.com"));
        assert!(display.contains("NXDOMAIN"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = from_io_error(io_err, Some(test_addr()));

        matches!(err, NetworkError::ConnectionRefused { .. });
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", ErrorCategory::Network), "Network");
        assert_eq!(format!("{}", ErrorCategory::Dns), "DNS");
        assert_eq!(format!("{}", ErrorCategory::Timeout), "Timeout");
    }
}
