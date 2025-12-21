//! Network module for packet crafting and sending
//!
//! This module provides comprehensive networking capabilities inspired by curl's
//! architecture, including:
//! - Protocol-agnostic packet handling via `ProtocolHandler` trait
//! - Connection pooling with TTL and LRU eviction
//! - DNS caching for improved performance
//! - Enhanced error handling with context and categories
//! - Retry logic with exponential backoff and jitter

pub mod packet;
pub mod sender;
pub mod http;
pub mod protocols;
pub mod raw_socket;
pub mod batch_sender;

// Curl-inspired improvements
pub mod protocol_handler;
pub mod connection_pool;
pub mod dns_cache;
pub mod errors;
pub mod retry;

// Re-export commonly used types
pub use protocol_handler::{ProtocolHandler, ProtocolRegistry, ProtocolConfig, ProtocolFeatures, ProtocolMetadata};
pub use connection_pool::{ConnectionPool, ConnectionPoolConfig, ConnectionKey, PooledConnection, PoolStats};
pub use dns_cache::{DnsCache, DnsCacheConfig, DnsCacheEntry, global_dns_cache};
pub use errors::{NetworkError, ErrorCategory, ErrorContext};
pub use retry::{RetryPolicy, RetryState, BackoffStrategy, with_retry};
