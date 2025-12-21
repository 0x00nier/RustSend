//! Connection pooling with TTL and LRU eviction
//!
//! Inspired by curl's connection pool architecture, this module provides
//! connection reuse for TCP connections to improve performance.

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Configuration for connection pooling
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per host
    pub max_per_host: usize,
    /// Maximum total connections in pool
    pub max_total: usize,
    /// Time-to-live for idle connections
    pub idle_timeout: Duration,
    /// Maximum age of a connection (even if active)
    pub max_connection_age: Duration,
    /// How often to run cleanup
    pub cleanup_interval: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_per_host: 6,
            max_total: 100,
            idle_timeout: Duration::from_secs(60),
            max_connection_age: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// Key for identifying poolable connections
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    /// Remote address (IP and port)
    pub addr: SocketAddr,
    /// Whether this is a TLS connection
    pub is_tls: bool,
}

impl ConnectionKey {
    pub fn new(addr: SocketAddr, is_tls: bool) -> Self {
        Self { addr, is_tls }
    }

    pub fn from_addr(addr: SocketAddr) -> Self {
        Self { addr, is_tls: false }
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr.ip(), self.addr.port())
    }
}

/// A pooled connection with metadata
pub struct PooledConnection {
    /// The underlying TCP stream
    pub stream: TcpStream,
    /// When this connection was created
    pub created_at: Instant,
    /// When this connection was last used
    pub last_used: Instant,
    /// Number of times this connection has been reused
    pub reuse_count: u32,
    /// Connection key for returning to pool
    pub key: ConnectionKey,
}

impl PooledConnection {
    /// Create a new pooled connection
    pub fn new(stream: TcpStream, key: ConnectionKey) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
            reuse_count: 0,
            key,
        }
    }

    /// Check if this connection has exceeded its idle timeout
    pub fn is_idle_expired(&self, timeout: Duration) -> bool {
        self.last_used.elapsed() > timeout
    }

    /// Check if this connection has exceeded its maximum age
    pub fn is_age_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() > max_age
    }

    /// Check if the connection is still valid (not closed by peer)
    pub fn is_valid(&self) -> bool {
        // Use peek to check if connection is still alive
        // A closed connection will return an error or EOF
        match self.stream.try_read(&mut [0u8; 0]) {
            Ok(0) => false, // EOF - peer closed
            Ok(_) => true,  // Data available (shouldn't happen with empty buffer)
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // Still connected
            Err(_) => false, // Connection error
        }
    }

    /// Mark this connection as used (updates last_used timestamp)
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
        self.reuse_count += 1;
    }
}

/// Connection pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total connections created
    pub connections_created: AtomicU64,
    /// Total connections reused from pool
    pub connections_reused: AtomicU64,
    /// Total connections that expired (TTL)
    pub connections_expired: AtomicU64,
    /// Total connections evicted (LRU)
    pub connections_evicted: AtomicU64,
    /// Current connections in pool
    pub current_pooled: AtomicU64,
    /// Current active (checked out) connections
    pub current_active: AtomicU64,
}

impl PoolStats {
    /// Calculate the hit rate (reused / (reused + created))
    pub fn hit_rate(&self) -> f64 {
        let reused = self.connections_reused.load(Ordering::Relaxed);
        let created = self.connections_created.load(Ordering::Relaxed);
        let total = reused + created;
        if total == 0 {
            0.0
        } else {
            reused as f64 / total as f64
        }
    }
}

/// Connection pool for reusing TCP connections
pub struct ConnectionPool {
    /// Pool of idle connections organized by key
    connections: Mutex<HashMap<ConnectionKey, VecDeque<PooledConnection>>>,
    /// Pool configuration
    config: ConnectionPoolConfig,
    /// Pool statistics
    stats: Arc<PoolStats>,
}

impl ConnectionPool {
    /// Create a new connection pool with default configuration
    pub fn new() -> Self {
        Self::with_config(ConnectionPoolConfig::default())
    }

    /// Create a new connection pool with custom configuration
    pub fn with_config(config: ConnectionPoolConfig) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            config,
            stats: Arc::new(PoolStats::default()),
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Try to acquire a connection from the pool
    pub fn try_acquire(&self, key: &ConnectionKey) -> Option<PooledConnection> {
        let mut connections = self.connections.lock();

        if let Some(queue) = connections.get_mut(key) {
            while let Some(mut conn) = queue.pop_front() {
                // Check if connection is still valid
                if conn.is_idle_expired(self.config.idle_timeout) {
                    self.stats.connections_expired.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_pooled.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }

                if conn.is_age_expired(self.config.max_connection_age) {
                    self.stats.connections_expired.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_pooled.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }

                if !conn.is_valid() {
                    self.stats.connections_expired.fetch_sub(1, Ordering::Relaxed);
                    self.stats.current_pooled.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }

                // Valid connection found
                conn.touch();
                self.stats.connections_reused.fetch_add(1, Ordering::Relaxed);
                self.stats.current_pooled.fetch_sub(1, Ordering::Relaxed);
                self.stats.current_active.fetch_add(1, Ordering::Relaxed);
                return Some(conn);
            }

            // All connections expired, remove empty queue
            if queue.is_empty() {
                connections.remove(key);
            }
        }

        None
    }

    /// Release a connection back to the pool
    pub fn release(&self, mut conn: PooledConnection) {
        self.stats.current_active.fetch_sub(1, Ordering::Relaxed);

        // Check if connection is still worth keeping
        if conn.is_age_expired(self.config.max_connection_age) {
            self.stats.connections_expired.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if !conn.is_valid() {
            return;
        }

        conn.touch();
        let key = conn.key.clone();

        let mut connections = self.connections.lock();

        // Check pool limits
        let total_pooled: usize = connections.values().map(|q| q.len()).sum();
        if total_pooled >= self.config.max_total {
            // Pool is full, need to evict
            self.evict_one_lru(&mut connections);
        }

        let queue = connections.entry(key).or_insert_with(VecDeque::new);

        if queue.len() >= self.config.max_per_host {
            // Per-host limit reached, evict oldest for this host
            if queue.pop_front().is_some() {
                self.stats.connections_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }

        queue.push_back(conn);
        self.stats.current_pooled.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new connection creation
    pub fn record_creation(&self) {
        self.stats.connections_created.fetch_add(1, Ordering::Relaxed);
        self.stats.current_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Evict one connection using LRU policy (oldest last_used)
    fn evict_one_lru(&self, connections: &mut HashMap<ConnectionKey, VecDeque<PooledConnection>>) {
        let mut oldest_key: Option<ConnectionKey> = None;
        let mut oldest_time = Instant::now();

        for (key, queue) in connections.iter() {
            if let Some(conn) = queue.front() {
                if conn.last_used < oldest_time {
                    oldest_time = conn.last_used;
                    oldest_key = Some(key.clone());
                }
            }
        }

        if let Some(key) = oldest_key {
            if let Some(queue) = connections.get_mut(&key) {
                if queue.pop_front().is_some() {
                    self.stats.connections_evicted.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_pooled.fetch_sub(1, Ordering::Relaxed);
                }
                if queue.is_empty() {
                    connections.remove(&key);
                }
            }
        }
    }

    /// Clean up expired connections
    pub fn cleanup(&self) {
        let mut connections = self.connections.lock();
        let mut empty_keys = Vec::new();

        for (key, queue) in connections.iter_mut() {
            let before_len = queue.len();

            queue.retain(|conn| {
                !conn.is_idle_expired(self.config.idle_timeout)
                    && !conn.is_age_expired(self.config.max_connection_age)
            });

            let removed = before_len - queue.len();
            if removed > 0 {
                self.stats.connections_expired.fetch_add(removed as u64, Ordering::Relaxed);
                self.stats.current_pooled.fetch_sub(removed as u64, Ordering::Relaxed);
            }

            if queue.is_empty() {
                empty_keys.push(key.clone());
            }
        }

        for key in empty_keys {
            connections.remove(&key);
        }
    }

    /// Get the current pool size
    pub fn size(&self) -> usize {
        self.connections.lock().values().map(|q| q.len()).sum()
    }

    /// Clear the entire pool
    pub fn clear(&self) {
        let mut connections = self.connections.lock();
        let count: u64 = connections.values().map(|q| q.len() as u64).sum();
        connections.clear();
        self.stats.current_pooled.fetch_sub(count, Ordering::Relaxed);
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for pooled connections - automatically returns to pool on drop
pub struct ConnectionGuard<'a> {
    conn: Option<PooledConnection>,
    pool: &'a ConnectionPool,
}

impl<'a> ConnectionGuard<'a> {
    /// Create a new connection guard
    pub fn new(conn: PooledConnection, pool: &'a ConnectionPool) -> Self {
        Self {
            conn: Some(conn),
            pool,
        }
    }

    /// Get a reference to the underlying stream
    pub fn stream(&self) -> &TcpStream {
        &self.conn.as_ref().unwrap().stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.conn.as_mut().unwrap().stream
    }

    /// Don't return this connection to the pool (e.g., if an error occurred)
    pub fn discard(mut self) {
        self.conn.take();
    }
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.release(conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn make_key(port: u16) -> ConnectionKey {
        ConnectionKey::from_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
        )))
    }

    #[test]
    fn test_connection_pool_config_default() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_per_host, 6);
        assert_eq!(config.max_total, 100);
    }

    #[test]
    fn test_connection_key_display() {
        let key = make_key(8080);
        assert_eq!(format!("{}", key), "127.0.0.1:8080");
    }

    #[test]
    fn test_pool_stats_hit_rate() {
        let stats = PoolStats::default();
        assert_eq!(stats.hit_rate(), 0.0);

        stats.connections_reused.store(3, Ordering::Relaxed);
        stats.connections_created.store(7, Ordering::Relaxed);
        assert!((stats.hit_rate() - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_connection_pool_new() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_try_acquire_empty() {
        let pool = ConnectionPool::new();
        let key = make_key(80);
        assert!(pool.try_acquire(&key).is_none());
    }

    #[test]
    fn test_record_creation() {
        let pool = ConnectionPool::new();
        pool.record_creation();
        assert_eq!(pool.stats().connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pool.stats().current_active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_pool_clear() {
        let pool = ConnectionPool::new();
        // Pool starts empty, clear should be safe
        pool.clear();
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_pool_cleanup_empty() {
        let pool = ConnectionPool::new();
        // Cleanup on empty pool should work
        pool.cleanup();
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_connection_pool_config_custom() {
        let config = ConnectionPoolConfig {
            max_per_host: 10,
            max_total: 50,
            idle_timeout: Duration::from_secs(30),
            max_connection_age: Duration::from_secs(120),
            cleanup_interval: Duration::from_secs(15),
        };
        let pool = ConnectionPool::with_config(config);
        assert_eq!(pool.config.max_per_host, 10);
    }
}
