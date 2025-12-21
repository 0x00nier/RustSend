//! DNS caching layer
//!
//! Provides in-memory DNS caching with TTL support, inspired by curl's
//! DNS cache implementation for improved performance.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Configuration for DNS cache
#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    /// Maximum entries in the cache
    pub max_entries: usize,
    /// Default TTL for cached entries
    pub default_ttl: Duration,
    /// TTL for negative cache entries (failed lookups)
    pub negative_ttl: Duration,
    /// How often to run cleanup
    pub cleanup_interval: Duration,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            default_ttl: Duration::from_secs(300),      // 5 minutes
            negative_ttl: Duration::from_secs(60),      // 1 minute for failed lookups
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// A cached DNS entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// When this entry was created
    pub created_at: Instant,
    /// Time-to-live for this entry
    pub ttl: Duration,
    /// Number of times this entry was accessed
    pub hit_count: u64,
    /// Whether this is a negative cache entry (lookup failed)
    pub is_negative: bool,
    /// Error message for negative entries
    pub error: Option<String>,
}

impl DnsCacheEntry {
    /// Create a positive cache entry
    pub fn positive(addresses: Vec<IpAddr>, ttl: Duration) -> Self {
        Self {
            addresses,
            created_at: Instant::now(),
            ttl,
            hit_count: 0,
            is_negative: false,
            error: None,
        }
    }

    /// Create a negative cache entry (failed lookup)
    pub fn negative(error: String, ttl: Duration) -> Self {
        Self {
            addresses: Vec::new(),
            created_at: Instant::now(),
            ttl,
            hit_count: 0,
            is_negative: true,
            error: Some(error),
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    /// Remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.created_at.elapsed())
    }
}

/// DNS cache statistics
#[derive(Debug, Default)]
pub struct DnsCacheStats {
    /// Cache hits
    pub hits: AtomicU64,
    /// Cache misses
    pub misses: AtomicU64,
    /// Entries evicted (LRU or expired)
    pub evictions: AtomicU64,
    /// Negative cache hits
    pub negative_hits: AtomicU64,
    /// Current entries in cache
    pub current_entries: AtomicU64,
}

impl DnsCacheStats {
    /// Calculate hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

/// DNS cache for storing resolved hostnames
pub struct DnsCache {
    /// Cache entries
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
    /// Cache configuration
    config: DnsCacheConfig,
    /// Cache statistics
    stats: DnsCacheStats,
}

impl DnsCache {
    /// Create a new DNS cache with default configuration
    pub fn new() -> Self {
        Self::with_config(DnsCacheConfig::default())
    }

    /// Create a new DNS cache with custom configuration
    pub fn with_config(config: DnsCacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            stats: DnsCacheStats::default(),
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> &DnsCacheStats {
        &self.stats
    }

    /// Look up a hostname in the cache
    pub fn get(&self, hostname: &str) -> Option<DnsCacheEntry> {
        let key = hostname.to_lowercase();
        let mut entries = self.entries.write();

        if let Some(entry) = entries.get_mut(&key) {
            if entry.is_expired() {
                // Entry expired, remove it
                entries.remove(&key);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Update hit count
            entry.hit_count += 1;

            if entry.is_negative {
                self.stats.negative_hits.fetch_add(1, Ordering::Relaxed);
            }
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a successful lookup into the cache
    pub fn insert(&self, hostname: &str, addresses: Vec<IpAddr>) {
        self.insert_with_ttl(hostname, addresses, self.config.default_ttl);
    }

    /// Insert a successful lookup with custom TTL
    pub fn insert_with_ttl(&self, hostname: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        let key = hostname.to_lowercase();
        let entry = DnsCacheEntry::positive(addresses, ttl);

        let mut entries = self.entries.write();

        // Check if we need to evict entries
        if entries.len() >= self.config.max_entries && !entries.contains_key(&key) {
            self.evict_one_lru(&mut entries);
        }

        let is_new = !entries.contains_key(&key);
        entries.insert(key, entry);

        if is_new {
            self.stats.current_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Insert a failed lookup (negative caching)
    pub fn insert_negative(&self, hostname: &str, error: String) {
        let key = hostname.to_lowercase();
        let entry = DnsCacheEntry::negative(error, self.config.negative_ttl);

        let mut entries = self.entries.write();

        // Check if we need to evict entries
        if entries.len() >= self.config.max_entries && !entries.contains_key(&key) {
            self.evict_one_lru(&mut entries);
        }

        let is_new = !entries.contains_key(&key);
        entries.insert(key, entry);

        if is_new {
            self.stats.current_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove a specific entry from the cache
    pub fn remove(&self, hostname: &str) {
        let key = hostname.to_lowercase();
        let mut entries = self.entries.write();
        if entries.remove(&key).is_some() {
            self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Evict one entry using LRU policy (lowest hit count + oldest)
    fn evict_one_lru(&self, entries: &mut HashMap<String, DnsCacheEntry>) {
        let mut victim_key: Option<String> = None;
        let mut lowest_score = u64::MAX;

        for (key, entry) in entries.iter() {
            // Score based on hit count and age (lower is more evictable)
            let age_secs = entry.created_at.elapsed().as_secs();
            let score = entry.hit_count.saturating_mul(10).saturating_add(
                1000u64.saturating_sub(age_secs.min(1000))
            );

            if score < lowest_score {
                lowest_score = score;
                victim_key = Some(key.clone());
            }
        }

        if let Some(key) = victim_key {
            entries.remove(&key);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let mut entries = self.entries.write();
        let before_len = entries.len();

        entries.retain(|_, entry| !entry.is_expired());

        let removed = before_len - entries.len();
        if removed > 0 {
            self.stats.evictions.fetch_add(removed as u64, Ordering::Relaxed);
            self.stats.current_entries.fetch_sub(removed as u64, Ordering::Relaxed);
        }
    }

    /// Get the current cache size
    pub fn size(&self) -> usize {
        self.entries.read().len()
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        let count = entries.len() as u64;
        entries.clear();
        self.stats.current_entries.fetch_sub(count, Ordering::Relaxed);
    }

    /// Resolve a hostname, using cache if available
    pub async fn resolve_cached(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        // First try to parse as IP address directly
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Check cache first
        if let Some(entry) = self.get(hostname) {
            if entry.is_negative {
                return Err(entry.error.unwrap_or_else(|| "Cached DNS failure".to_string()));
            }
            return Ok(entry.addresses);
        }

        // Cache miss - perform actual lookup
        let result = Self::do_lookup(hostname).await;

        match &result {
            Ok(addresses) => {
                self.insert(hostname, addresses.clone());
            }
            Err(e) => {
                self.insert_negative(hostname, e.clone());
            }
        }

        result
    }

    /// Perform actual DNS lookup
    async fn do_lookup(hostname: &str) -> Result<Vec<IpAddr>, String> {
        use tokio::net::lookup_host;

        let addrs: Vec<std::net::SocketAddr> = lookup_host(format!("{}:0", hostname))
            .await
            .map_err(|e| format!("DNS lookup failed: {}", e))?
            .collect();

        if addrs.is_empty() {
            return Err("No addresses found".to_string());
        }

        Ok(addrs.into_iter().map(|a| a.ip()).collect())
    }

    /// Prefetch DNS entries for a list of hostnames
    pub async fn prefetch(&self, hostnames: &[&str]) {
        use futures::future::join_all;

        let futures: Vec<_> = hostnames
            .iter()
            .filter(|h| self.get(h).is_none()) // Only prefetch uncached
            .map(|h| self.resolve_cached(h))
            .collect();

        let _ = join_all(futures).await;
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global DNS cache singleton
static DNS_CACHE: std::sync::OnceLock<DnsCache> = std::sync::OnceLock::new();

/// Get the global DNS cache instance
pub fn global_dns_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(DnsCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_cache_config_default() {
        let config = DnsCacheConfig::default();
        assert_eq!(config.max_entries, 1000);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_dns_cache_entry_positive() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let entry = DnsCacheEntry::positive(addrs.clone(), Duration::from_secs(60));

        assert!(!entry.is_negative);
        assert!(!entry.is_expired());
        assert_eq!(entry.addresses, addrs);
    }

    #[test]
    fn test_dns_cache_entry_negative() {
        let entry = DnsCacheEntry::negative("Host not found".to_string(), Duration::from_secs(30));

        assert!(entry.is_negative);
        assert!(entry.error.is_some());
        assert!(entry.addresses.is_empty());
    }

    #[test]
    fn test_dns_cache_insert_get() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];

        cache.insert("example.com", addrs.clone());

        let entry = cache.get("example.com").unwrap();
        assert_eq!(entry.addresses, addrs);
        assert!(!entry.is_negative);
    }

    #[test]
    fn test_dns_cache_case_insensitive() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

        cache.insert("Example.COM", addrs.clone());

        // Should find with different case
        assert!(cache.get("example.com").is_some());
        assert!(cache.get("EXAMPLE.COM").is_some());
    }

    #[test]
    fn test_dns_cache_negative() {
        let cache = DnsCache::new();

        cache.insert_negative("nonexistent.invalid", "NXDOMAIN".to_string());

        let entry = cache.get("nonexistent.invalid").unwrap();
        assert!(entry.is_negative);
        assert_eq!(entry.error, Some("NXDOMAIN".to_string()));
    }

    #[test]
    fn test_dns_cache_stats_hit_rate() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];

        cache.insert("cloudflare.com", addrs);

        // First lookup - hit
        let _ = cache.get("cloudflare.com");
        // Second lookup - hit
        let _ = cache.get("cloudflare.com");
        // Miss
        let _ = cache.get("nonexistent.com");

        let stats = cache.stats();
        assert_eq!(stats.hits.load(Ordering::Relaxed), 2);
        assert_eq!(stats.misses.load(Ordering::Relaxed), 1);
        assert!((stats.hit_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_dns_cache_remove() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

        cache.insert("test.local", addrs);
        assert!(cache.get("test.local").is_some());

        cache.remove("test.local");
        assert!(cache.get("test.local").is_none());
    }

    #[test]
    fn test_dns_cache_clear() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

        cache.insert("host1.local", addrs.clone());
        cache.insert("host2.local", addrs);
        assert_eq!(cache.size(), 2);

        cache.clear();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_dns_cache_cleanup_not_expired() {
        let cache = DnsCache::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

        cache.insert("fresh.local", addrs);
        cache.cleanup();

        // Entry should still be there (not expired)
        assert!(cache.get("fresh.local").is_some());
    }

    #[test]
    fn test_remaining_ttl() {
        let entry = DnsCacheEntry::positive(
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            Duration::from_secs(300),
        );

        // Remaining TTL should be close to 300 seconds
        let remaining = entry.remaining_ttl();
        assert!(remaining.as_secs() >= 299);
    }

    #[tokio::test]
    async fn test_resolve_cached_ip() {
        let cache = DnsCache::new();

        // Direct IP should work without DNS lookup
        let result = cache.resolve_cached("127.0.0.1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        // Should not be cached (IP addresses bypass cache)
        assert_eq!(cache.size(), 0);
    }
}
