//! Retry policy with exponential backoff and jitter
//!
//! Provides curl-inspired retry logic with configurable backoff strategies
//! to prevent thundering herd problems and improve reliability.

use crate::network::errors::{ErrorCategory, NetworkError};
use rand::Rng;
use std::time::Duration;

/// Backoff strategy for retry delays
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed {
        delay: Duration,
    },
    /// Linear increase in delay
    Linear {
        initial: Duration,
        increment: Duration,
        max: Duration,
    },
    /// Exponential increase in delay (default and recommended)
    Exponential {
        initial: Duration,
        multiplier: f64,
        max: Duration,
    },
    /// Decorrelated jitter (AWS-style)
    DecorrelatedJitter {
        base: Duration,
        cap: Duration,
    },
    /// Full jitter (uniform random up to exponential cap)
    FullJitter {
        initial: Duration,
        multiplier: f64,
        max: Duration,
    },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        BackoffStrategy::Exponential {
            initial: Duration::from_millis(100),
            multiplier: 2.0,
            max: Duration::from_secs(30),
        }
    }
}

impl BackoffStrategy {
    /// Calculate the delay for a given attempt number
    pub fn delay(&self, attempt: u32, prev_delay: Option<Duration>) -> Duration {
        match self {
            BackoffStrategy::Fixed { delay } => *delay,

            BackoffStrategy::Linear {
                initial,
                increment,
                max,
            } => {
                let delay = *initial + (*increment * attempt);
                delay.min(*max)
            }

            BackoffStrategy::Exponential {
                initial,
                multiplier,
                max,
            } => {
                let delay_ms = initial.as_millis() as f64 * multiplier.powi(attempt as i32);
                let delay = Duration::from_millis(delay_ms as u64);
                delay.min(*max)
            }

            BackoffStrategy::DecorrelatedJitter { base, cap } => {
                // sleep = min(cap, random(base, sleep * 3))
                let prev = prev_delay.unwrap_or(*base);
                let mut rng = rand::thread_rng();
                let upper = (prev.as_millis() as f64 * 3.0) as u64;
                let lower = base.as_millis() as u64;
                let delay_ms = rng.gen_range(lower..=upper.max(lower));
                Duration::from_millis(delay_ms).min(*cap)
            }

            BackoffStrategy::FullJitter {
                initial,
                multiplier,
                max,
            } => {
                // Full jitter: random(0, min(cap, base * 2^attempt))
                let exponential_ms = initial.as_millis() as f64 * multiplier.powi(attempt as i32);
                let capped_ms = (exponential_ms as u64).min(max.as_millis() as u64);
                let mut rng = rand::thread_rng();
                let delay_ms = rng.gen_range(0..=capped_ms.max(1));
                Duration::from_millis(delay_ms)
            }
        }
    }

    /// Create a fixed backoff strategy
    pub fn fixed(delay: Duration) -> Self {
        BackoffStrategy::Fixed { delay }
    }

    /// Create an exponential backoff strategy
    pub fn exponential(initial: Duration, multiplier: f64, max: Duration) -> Self {
        BackoffStrategy::Exponential {
            initial,
            multiplier,
            max,
        }
    }

    /// Create a full jitter strategy (recommended for high-concurrency scenarios)
    pub fn full_jitter(initial: Duration, max: Duration) -> Self {
        BackoffStrategy::FullJitter {
            initial,
            multiplier: 2.0,
            max,
        }
    }
}

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_retries: u32,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Whether to add jitter to all strategies
    pub add_jitter: bool,
    /// Jitter factor (0.0 to 1.0) - portion of delay to randomize
    pub jitter_factor: f64,
    /// Which error categories are retriable
    pub retriable_categories: Vec<ErrorCategory>,
    /// Maximum total time to spend retrying
    pub max_retry_duration: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: BackoffStrategy::default(),
            add_jitter: true,
            jitter_factor: 0.3,
            retriable_categories: vec![
                ErrorCategory::Network,
                ErrorCategory::Timeout,
                ErrorCategory::Dns,
                ErrorCategory::Resource,
            ],
            max_retry_duration: Some(Duration::from_secs(60)),
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a policy with no retries
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create an aggressive retry policy for critical operations
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            backoff: BackoffStrategy::exponential(
                Duration::from_millis(50),
                2.0,
                Duration::from_secs(10),
            ),
            add_jitter: true,
            jitter_factor: 0.5,
            ..Default::default()
        }
    }

    /// Create a conservative retry policy (fewer, slower retries)
    pub fn conservative() -> Self {
        Self {
            max_retries: 2,
            backoff: BackoffStrategy::exponential(
                Duration::from_millis(500),
                2.0,
                Duration::from_secs(60),
            ),
            add_jitter: true,
            jitter_factor: 0.2,
            ..Default::default()
        }
    }

    /// Set maximum retries
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set backoff strategy
    pub fn with_backoff(mut self, backoff: BackoffStrategy) -> Self {
        self.backoff = backoff;
        self
    }

    /// Set jitter factor
    pub fn with_jitter(mut self, factor: f64) -> Self {
        self.add_jitter = true;
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// Disable jitter
    pub fn without_jitter(mut self) -> Self {
        self.add_jitter = false;
        self
    }

    /// Check if an error should be retried
    pub fn should_retry(&self, error: &NetworkError, attempt: u32) -> bool {
        if attempt >= self.max_retries {
            return false;
        }

        let category = error.category();
        self.retriable_categories.contains(&category)
    }

    /// Calculate the delay before the next retry
    pub fn next_delay(&self, attempt: u32, prev_delay: Option<Duration>) -> Duration {
        let base_delay = self.backoff.delay(attempt, prev_delay);

        if self.add_jitter && self.jitter_factor > 0.0 {
            Self::apply_jitter(base_delay, self.jitter_factor)
        } else {
            base_delay
        }
    }

    /// Apply jitter to a delay
    fn apply_jitter(delay: Duration, factor: f64) -> Duration {
        let mut rng = rand::thread_rng();
        let delay_ms = delay.as_millis() as f64;
        let jitter_range = delay_ms * factor;
        let jitter = rng.gen_range(-jitter_range..=jitter_range);
        let final_ms = (delay_ms + jitter).max(1.0) as u64;
        Duration::from_millis(final_ms)
    }
}

/// Retry state tracker for an operation
#[derive(Debug)]
pub struct RetryState {
    /// Current attempt number (0-based)
    pub attempt: u32,
    /// Total time spent so far
    pub total_time: Duration,
    /// Last delay used
    pub last_delay: Option<Duration>,
    /// History of errors encountered
    pub error_history: Vec<(u32, String)>,
    /// The retry policy
    policy: RetryPolicy,
}

impl RetryState {
    /// Create a new retry state with a policy
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            attempt: 0,
            total_time: Duration::ZERO,
            last_delay: None,
            error_history: Vec::new(),
            policy,
        }
    }

    /// Check if we should retry after an error
    pub fn should_retry(&self, error: &NetworkError) -> bool {
        // Check attempt limit
        if self.attempt >= self.policy.max_retries {
            return false;
        }

        // Check total time limit
        if let Some(max_duration) = self.policy.max_retry_duration {
            if self.total_time >= max_duration {
                return false;
            }
        }

        // Check if error is retriable
        self.policy.should_retry(error, self.attempt)
    }

    /// Get the delay for the next retry and advance state
    pub fn next_retry(&mut self, error: &NetworkError) -> Option<Duration> {
        if !self.should_retry(error) {
            return None;
        }

        let delay = self.policy.next_delay(self.attempt, self.last_delay);

        // Record error
        self.error_history
            .push((self.attempt, error.to_string()));

        // Advance state
        self.attempt += 1;
        self.total_time += delay;
        self.last_delay = Some(delay);

        Some(delay)
    }

    /// Reset state for a new operation
    pub fn reset(&mut self) {
        self.attempt = 0;
        self.total_time = Duration::ZERO;
        self.last_delay = None;
        self.error_history.clear();
    }

    /// Get the number of retries performed so far
    pub fn retries_performed(&self) -> u32 {
        self.attempt
    }

    /// Get the maximum retries allowed
    pub fn max_retries(&self) -> u32 {
        self.policy.max_retries
    }
}

/// Execute an async operation with retry logic
pub async fn with_retry<F, Fut, T>(
    policy: &RetryPolicy,
    mut operation: F,
) -> Result<T, NetworkError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, NetworkError>>,
{
    let mut state = RetryState::new(policy.clone());

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if let Some(delay) = state.next_retry(&error) {
                    tracing::debug!(
                        "Retry {} of {}: waiting {:?} after error: {}",
                        state.attempt,
                        policy.max_retries,
                        delay,
                        error
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    return Err(error);
                }
            }
        }
    }
}

/// Retry metrics
#[derive(Debug, Default)]
pub struct RetryMetrics {
    /// Total operations attempted
    pub total_operations: std::sync::atomic::AtomicU64,
    /// Operations that succeeded on first try
    pub first_try_success: std::sync::atomic::AtomicU64,
    /// Operations that succeeded after retry
    pub retry_success: std::sync::atomic::AtomicU64,
    /// Operations that failed after all retries
    pub retry_exhausted: std::sync::atomic::AtomicU64,
    /// Total retry attempts made
    pub total_retry_attempts: std::sync::atomic::AtomicU64,
    /// Total time spent waiting between retries
    pub total_retry_delay_ms: std::sync::atomic::AtomicU64,
}

impl RetryMetrics {
    /// Calculate retry success rate
    pub fn retry_success_rate(&self) -> f64 {
        let retry_success = self.retry_success.load(std::sync::atomic::Ordering::Relaxed);
        let retry_exhausted = self.retry_exhausted.load(std::sync::atomic::Ordering::Relaxed);
        let total = retry_success + retry_exhausted;
        if total == 0 {
            0.0
        } else {
            retry_success as f64 / total as f64
        }
    }

    /// Calculate average retries per failed first attempt
    pub fn avg_retries_per_failure(&self) -> f64 {
        let attempts = self.total_retry_attempts.load(std::sync::atomic::Ordering::Relaxed);
        let failures = self.retry_success.load(std::sync::atomic::Ordering::Relaxed)
            + self.retry_exhausted.load(std::sync::atomic::Ordering::Relaxed);
        if failures == 0 {
            0.0
        } else {
            attempts as f64 / failures as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_backoff() {
        let strategy = BackoffStrategy::fixed(Duration::from_millis(100));

        assert_eq!(strategy.delay(0, None), Duration::from_millis(100));
        assert_eq!(strategy.delay(5, None), Duration::from_millis(100));
    }

    #[test]
    fn test_exponential_backoff() {
        let strategy = BackoffStrategy::exponential(
            Duration::from_millis(100),
            2.0,
            Duration::from_secs(10),
        );

        assert_eq!(strategy.delay(0, None), Duration::from_millis(100));
        assert_eq!(strategy.delay(1, None), Duration::from_millis(200));
        assert_eq!(strategy.delay(2, None), Duration::from_millis(400));
        assert_eq!(strategy.delay(3, None), Duration::from_millis(800));
    }

    #[test]
    fn test_exponential_backoff_cap() {
        let strategy = BackoffStrategy::exponential(
            Duration::from_millis(100),
            2.0,
            Duration::from_millis(500),
        );

        // Should cap at 500ms
        assert_eq!(strategy.delay(10, None), Duration::from_millis(500));
    }

    #[test]
    fn test_linear_backoff() {
        let strategy = BackoffStrategy::Linear {
            initial: Duration::from_millis(100),
            increment: Duration::from_millis(50),
            max: Duration::from_millis(500),
        };

        assert_eq!(strategy.delay(0, None), Duration::from_millis(100));
        assert_eq!(strategy.delay(1, None), Duration::from_millis(150));
        assert_eq!(strategy.delay(2, None), Duration::from_millis(200));
    }

    #[test]
    fn test_full_jitter() {
        let strategy = BackoffStrategy::full_jitter(
            Duration::from_millis(100),
            Duration::from_secs(10),
        );

        // Full jitter should return values between 0 and the exponential cap
        for attempt in 0..5 {
            let delay = strategy.delay(attempt, None);
            assert!(delay <= Duration::from_secs(10));
        }
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert!(policy.add_jitter);
    }

    #[test]
    fn test_retry_policy_should_retry() {
        let policy = RetryPolicy::default();

        let timeout_err = NetworkError::OperationTimeout {
            operation: "test".to_string(),
            elapsed: Duration::from_secs(5),
            limit: Duration::from_secs(3),
        };
        assert!(policy.should_retry(&timeout_err, 0));
        assert!(policy.should_retry(&timeout_err, 2));
        assert!(!policy.should_retry(&timeout_err, 3)); // Exceeds max_retries

        let validation_err = NetworkError::InvalidTarget {
            message: "bad".to_string(),
        };
        assert!(!policy.should_retry(&validation_err, 0)); // Not retriable category
    }

    #[test]
    fn test_retry_state() {
        let policy = RetryPolicy::default().with_max_retries(2);
        let mut state = RetryState::new(policy);

        let error = NetworkError::OperationTimeout {
            operation: "test".to_string(),
            elapsed: Duration::from_secs(1),
            limit: Duration::from_secs(1),
        };

        // First retry
        assert!(state.next_retry(&error).is_some());
        assert_eq!(state.attempt, 1);

        // Second retry
        assert!(state.next_retry(&error).is_some());
        assert_eq!(state.attempt, 2);

        // No more retries
        assert!(state.next_retry(&error).is_none());
    }

    #[test]
    fn test_retry_policy_builders() {
        let aggressive = RetryPolicy::aggressive();
        assert_eq!(aggressive.max_retries, 5);

        let conservative = RetryPolicy::conservative();
        assert_eq!(conservative.max_retries, 2);

        let no_retry = RetryPolicy::no_retry();
        assert_eq!(no_retry.max_retries, 0);
    }

    #[test]
    fn test_retry_metrics() {
        let metrics = RetryMetrics::default();
        metrics.retry_success.store(3, std::sync::atomic::Ordering::Relaxed);
        metrics.retry_exhausted.store(1, std::sync::atomic::Ordering::Relaxed);

        assert!((metrics.retry_success_rate() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_policy_chaining() {
        let policy = RetryPolicy::new()
            .with_max_retries(5)
            .with_backoff(BackoffStrategy::fixed(Duration::from_millis(200)))
            .with_jitter(0.5)
            .without_jitter();

        assert_eq!(policy.max_retries, 5);
        assert!(!policy.add_jitter);
    }
}
