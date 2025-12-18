//! Circuit Breaker Pattern
//!
//! Implements the circuit breaker pattern for backend connections to:
//! - Prevent cascade failures
//! - Allow backends to recover
//! - Provide fast fail responses
//!
//! ## States
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Backend is failing, requests are rejected immediately
//! - **Half-Open**: Testing if backend has recovered
//!
//! ## Configuration
//!
//! ```toml
//! [circuit_breaker]
//! failure_threshold = 5          # Failures before opening
//! success_threshold = 3          # Successes to close from half-open
//! timeout_seconds = 30           # Time in open state before half-open
//! half_open_max_requests = 3     # Max requests in half-open state
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Backend is failing - requests are rejected
    Open,
    /// Testing recovery - limited requests allowed
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    
    /// Number of successes in half-open state to close the circuit
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    
    /// Time to wait in open state before transitioning to half-open
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    
    /// Maximum requests allowed in half-open state
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
    
    /// Minimum requests before calculating failure rate
    #[serde(default = "default_min_requests")]
    pub min_requests: u32,
    
    /// Failure rate threshold (0.0 - 1.0) for opening circuit
    #[serde(default = "default_failure_rate")]
    pub failure_rate_threshold: f64,
    
    /// Consider slow responses as failures
    #[serde(default)]
    pub slow_call_threshold: Option<Duration>,
    
    /// Rate of slow calls that triggers circuit open
    #[serde(default = "default_slow_rate")]
    pub slow_call_rate_threshold: f64,
}

fn default_failure_threshold() -> u32 { 5 }
fn default_success_threshold() -> u32 { 3 }
fn default_timeout() -> Duration { Duration::from_secs(30) }
fn default_half_open_max() -> u32 { 3 }
fn default_min_requests() -> u32 { 10 }
fn default_failure_rate() -> f64 { 0.5 }
fn default_slow_rate() -> f64 { 0.8 }

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout: default_timeout(),
            half_open_max_requests: default_half_open_max(),
            min_requests: default_min_requests(),
            failure_rate_threshold: default_failure_rate(),
            slow_call_threshold: None,
            slow_call_rate_threshold: default_slow_rate(),
        }
    }
}

/// Result of a circuit breaker call
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallResult {
    Success,
    Failure,
    Slow,
    Timeout,
}

/// Circuit breaker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStats {
    /// Current state
    pub state: CircuitState,
    /// Total calls
    pub total_calls: u64,
    /// Successful calls
    pub successful_calls: u64,
    /// Failed calls
    pub failed_calls: u64,
    /// Slow calls
    pub slow_calls: u64,
    /// Rejected calls (circuit open)
    pub rejected_calls: u64,
    /// Current failure rate
    pub failure_rate: f64,
    /// Current slow call rate
    pub slow_call_rate: f64,
    /// Time of last state change
    pub last_state_change: Option<chrono::DateTime<chrono::Utc>>,
    /// Time spent in current state
    pub time_in_state_ms: u64,
}

/// Internal circuit state
struct CircuitInternal {
    config: CircuitBreakerConfig,
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    half_open_requests: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    
    // Sliding window for rate calculation
    window_start: Instant,
    window_total: u32,
    window_failures: u32,
    window_slow: u32,
    
    // Statistics
    total_calls: AtomicU64,
    successful_calls: AtomicU64,
    failed_calls: AtomicU64,
    slow_calls: AtomicU64,
    rejected_calls: AtomicU64,
}

impl CircuitInternal {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            half_open_requests: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            window_start: Instant::now(),
            window_total: 0,
            window_failures: 0,
            window_slow: 0,
            total_calls: AtomicU64::new(0),
            successful_calls: AtomicU64::new(0),
            failed_calls: AtomicU64::new(0),
            slow_calls: AtomicU64::new(0),
            rejected_calls: AtomicU64::new(0),
        }
    }
    
    fn should_reset_window(&self) -> bool {
        self.window_start.elapsed() > Duration::from_secs(60)
    }
    
    fn reset_window(&mut self) {
        self.window_start = Instant::now();
        self.window_total = 0;
        self.window_failures = 0;
        self.window_slow = 0;
    }
    
    fn failure_rate(&self) -> f64 {
        if self.window_total == 0 {
            0.0
        } else {
            self.window_failures as f64 / self.window_total as f64
        }
    }
    
    fn slow_rate(&self) -> f64 {
        if self.window_total == 0 {
            0.0
        } else {
            self.window_slow as f64 / self.window_total as f64
        }
    }
}

/// A circuit breaker for a single backend
pub struct CircuitBreaker {
    /// Backend identifier
    pub id: String,
    /// Internal state
    internal: RwLock<CircuitInternal>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(id: &str, config: CircuitBreakerConfig) -> Self {
        Self {
            id: id.to_string(),
            internal: RwLock::new(CircuitInternal::new(config)),
        }
    }
    
    /// Check if request is allowed
    pub fn allow_request(&self) -> bool {
        let mut internal = self.internal.write();
        
        // Reset sliding window if needed
        if internal.should_reset_window() {
            internal.reset_window();
        }
        
        match internal.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has passed
                if internal.last_state_change.elapsed() >= internal.config.timeout {
                    self.transition_to(&mut internal, CircuitState::HalfOpen);
                    internal.half_open_requests = 1;
                    true
                } else {
                    internal.rejected_calls.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            CircuitState::HalfOpen => {
                if internal.half_open_requests < internal.config.half_open_max_requests {
                    internal.half_open_requests += 1;
                    true
                } else {
                    internal.rejected_calls.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }
    
    /// Record a call result
    pub fn record_result(&self, result: CallResult) {
        let mut internal = self.internal.write();
        
        internal.total_calls.fetch_add(1, Ordering::Relaxed);
        internal.window_total += 1;
        
        match result {
            CallResult::Success => {
                internal.successful_calls.fetch_add(1, Ordering::Relaxed);
                self.handle_success(&mut internal);
            }
            CallResult::Failure | CallResult::Timeout => {
                internal.failed_calls.fetch_add(1, Ordering::Relaxed);
                internal.window_failures += 1;
                self.handle_failure(&mut internal);
            }
            CallResult::Slow => {
                internal.slow_calls.fetch_add(1, Ordering::Relaxed);
                internal.window_slow += 1;
                // Slow calls can be treated as partial failures
                if internal.slow_rate() >= internal.config.slow_call_rate_threshold {
                    self.handle_failure(&mut internal);
                } else {
                    self.handle_success(&mut internal);
                }
            }
        }
    }
    
    /// Record success
    pub fn record_success(&self) {
        self.record_result(CallResult::Success);
    }
    
    /// Record failure
    pub fn record_failure(&self) {
        self.record_result(CallResult::Failure);
    }
    
    /// Record call with duration (for slow call detection)
    pub fn record_call(&self, success: bool, duration: Duration) {
        let internal = self.internal.read();
        let result = if !success {
            CallResult::Failure
        } else if let Some(threshold) = internal.config.slow_call_threshold {
            if duration > threshold {
                CallResult::Slow
            } else {
                CallResult::Success
            }
        } else {
            CallResult::Success
        };
        drop(internal);
        self.record_result(result);
    }
    
    /// Get current state
    pub fn state(&self) -> CircuitState {
        self.internal.read().state
    }
    
    /// Get statistics
    pub fn stats(&self) -> CircuitStats {
        let internal = self.internal.read();
        CircuitStats {
            state: internal.state,
            total_calls: internal.total_calls.load(Ordering::Relaxed),
            successful_calls: internal.successful_calls.load(Ordering::Relaxed),
            failed_calls: internal.failed_calls.load(Ordering::Relaxed),
            slow_calls: internal.slow_calls.load(Ordering::Relaxed),
            rejected_calls: internal.rejected_calls.load(Ordering::Relaxed),
            failure_rate: internal.failure_rate(),
            slow_call_rate: internal.slow_rate(),
            last_state_change: Some(chrono::Utc::now() - chrono::Duration::from_std(internal.last_state_change.elapsed()).unwrap_or_default()),
            time_in_state_ms: internal.last_state_change.elapsed().as_millis() as u64,
        }
    }
    
    /// Force circuit open (for manual intervention)
    pub fn force_open(&self) {
        let mut internal = self.internal.write();
        self.transition_to(&mut internal, CircuitState::Open);
    }
    
    /// Force circuit closed (for manual intervention)
    pub fn force_close(&self) {
        let mut internal = self.internal.write();
        self.transition_to(&mut internal, CircuitState::Closed);
    }
    
    /// Reset the circuit breaker
    pub fn reset(&self) {
        let mut internal = self.internal.write();
        internal.state = CircuitState::Closed;
        internal.failure_count = 0;
        internal.success_count = 0;
        internal.half_open_requests = 0;
        internal.last_failure_time = None;
        internal.last_state_change = Instant::now();
        internal.reset_window();
    }
    
    // Private helper methods
    
    fn handle_success(&self, internal: &mut CircuitInternal) {
        match internal.state {
            CircuitState::Closed => {
                // Reset failure count on success in closed state
                internal.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                internal.success_count += 1;
                if internal.success_count >= internal.config.success_threshold {
                    self.transition_to(internal, CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle it
            }
        }
    }
    
    fn handle_failure(&self, internal: &mut CircuitInternal) {
        internal.last_failure_time = Some(Instant::now());
        
        match internal.state {
            CircuitState::Closed => {
                internal.failure_count += 1;
                
                // Check if we should open based on count
                if internal.failure_count >= internal.config.failure_threshold {
                    self.transition_to(internal, CircuitState::Open);
                    return;
                }
                
                // Check if we should open based on rate
                if internal.window_total >= internal.config.min_requests {
                    if internal.failure_rate() >= internal.config.failure_rate_threshold {
                        self.transition_to(internal, CircuitState::Open);
                    }
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state reopens the circuit
                self.transition_to(internal, CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }
    
    fn transition_to(&self, internal: &mut CircuitInternal, new_state: CircuitState) {
        let old_state = internal.state;
        if old_state != new_state {
            info!(
                "Circuit breaker '{}' transitioning from {} to {}",
                self.id, old_state, new_state
            );
            
            internal.state = new_state;
            internal.last_state_change = Instant::now();
            internal.failure_count = 0;
            internal.success_count = 0;
            internal.half_open_requests = 0;
        }
    }
}

/// Circuit breaker registry for managing multiple backends
pub struct CircuitBreakerRegistry {
    /// Circuit breakers by backend ID
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    /// Default configuration
    default_config: CircuitBreakerConfig,
    /// Per-backend configurations
    configs: DashMap<String, CircuitBreakerConfig>,
}

impl CircuitBreakerRegistry {
    /// Create a new registry
    pub fn new(default_config: CircuitBreakerConfig) -> Arc<Self> {
        Arc::new(Self {
            breakers: DashMap::new(),
            default_config,
            configs: DashMap::new(),
        })
    }
    
    /// Get or create a circuit breaker for a backend
    pub fn get_or_create(&self, backend_id: &str) -> Arc<CircuitBreaker> {
        if let Some(breaker) = self.breakers.get(backend_id) {
            return breaker.clone();
        }
        
        let config = self.configs
            .get(backend_id)
            .map(|c| c.clone())
            .unwrap_or_else(|| self.default_config.clone());
        
        let breaker = Arc::new(CircuitBreaker::new(backend_id, config));
        self.breakers.insert(backend_id.to_string(), breaker.clone());
        
        breaker
    }
    
    /// Set configuration for a specific backend
    pub fn set_config(&self, backend_id: &str, config: CircuitBreakerConfig) {
        self.configs.insert(backend_id.to_string(), config);
        
        // If breaker exists, it will use old config until recreated
        // For immediate effect, remove and let it be recreated
        self.breakers.remove(backend_id);
    }
    
    /// Get all circuit breaker stats
    pub fn all_stats(&self) -> HashMap<String, CircuitStats> {
        self.breakers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().stats()))
            .collect()
    }
    
    /// Get circuit breakers in open state
    pub fn get_open_circuits(&self) -> Vec<String> {
        self.breakers
            .iter()
            .filter(|entry| entry.value().state() == CircuitState::Open)
            .map(|entry| entry.key().clone())
            .collect()
    }
    
    /// Reset all circuit breakers
    pub fn reset_all(&self) {
        for entry in self.breakers.iter() {
            entry.value().reset();
        }
    }
    
    /// Remove a circuit breaker
    pub fn remove(&self, backend_id: &str) {
        self.breakers.remove(backend_id);
        self.configs.remove(backend_id);
    }
    
    /// Cleanup unused circuit breakers (no recent activity)
    pub fn cleanup_inactive(&self, max_age: Duration) {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        for entry in self.breakers.iter() {
            let stats = entry.value().stats();
            if let Some(last_change) = stats.last_state_change {
                let age = chrono::Utc::now() - last_change;
                if age > chrono::Duration::from_std(max_age).unwrap_or_default() {
                    // Check if there's been any activity
                    if stats.total_calls == 0 {
                        to_remove.push(entry.key().clone());
                    }
                }
            }
        }
        
        for id in to_remove {
            self.breakers.remove(&id);
            debug!("Removed inactive circuit breaker: {}", id);
        }
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self {
            breakers: DashMap::new(),
            default_config: CircuitBreakerConfig::default(),
            configs: DashMap::new(),
        }
    }
}

/// RAII guard for circuit breaker calls
pub struct CircuitGuard {
    breaker: Arc<CircuitBreaker>,
    start: Instant,
    recorded: bool,
}

impl CircuitGuard {
    /// Create a new guard, returns None if circuit is open
    pub fn try_new(breaker: Arc<CircuitBreaker>) -> Option<Self> {
        if breaker.allow_request() {
            Some(Self {
                breaker,
                start: Instant::now(),
                recorded: false,
            })
        } else {
            None
        }
    }
    
    /// Mark call as successful
    pub fn success(mut self) {
        self.breaker.record_call(true, self.start.elapsed());
        self.recorded = true;
    }
    
    /// Mark call as failed
    pub fn failure(mut self) {
        self.breaker.record_call(false, self.start.elapsed());
        self.recorded = true;
    }
    
    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for CircuitGuard {
    fn drop(&mut self) {
        // If not explicitly recorded, treat as failure (e.g., panic)
        if !self.recorded {
            self.breaker.record_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }
    
    #[test]
    fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Record failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
    
    #[test]
    fn test_circuit_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
        
        let stats = cb.stats();
        assert_eq!(stats.rejected_calls, 1);
    }
    
    #[test]
    fn test_circuit_transitions_to_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));
        
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }
    
    #[test]
    fn test_circuit_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            timeout: Duration::from_millis(1),
            half_open_max_requests: 10,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        
        cb.allow_request(); // Transition to half-open
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
    
    #[test]
    fn test_half_open_fails_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        
        cb.allow_request(); // Transition to half-open
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
    
    #[test]
    fn test_registry() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig::default());
        
        let cb1 = registry.get_or_create("backend1");
        let cb2 = registry.get_or_create("backend2");
        let cb1_again = registry.get_or_create("backend1");
        
        assert_eq!(cb1.id, "backend1");
        assert_eq!(cb2.id, "backend2");
        assert!(Arc::ptr_eq(&cb1, &cb1_again));
    }
    
    #[test]
    fn test_force_open_close() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        
        cb.force_open();
        assert_eq!(cb.state(), CircuitState::Open);
        
        cb.force_close();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
    
    #[test]
    fn test_slow_call_detection() {
        let config = CircuitBreakerConfig {
            slow_call_threshold: Some(Duration::from_millis(10)),
            slow_call_rate_threshold: 0.5,
            min_requests: 2,
            failure_rate_threshold: 0.8,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Record slow calls
        cb.record_call(true, Duration::from_millis(20));
        cb.record_call(true, Duration::from_millis(20));
        
        let stats = cb.stats();
        assert_eq!(stats.slow_calls, 2);
    }
}
