//! Memory-efficient sliding-window rate limiter for Kite x402 payment endpoints.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SlidingWindowConfig {
    pub max_requests: usize,
    pub window_duration: Duration,
}

impl Default for SlidingWindowConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_duration: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
pub struct SlidingWindowLimiter {
    config: SlidingWindowConfig,
    state: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new(config: SlidingWindowConfig) -> Self {
        Self {
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_record(&self, key: &str) -> Result<usize, Duration> {
        let mut map = self.state.lock().unwrap();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.config.window_duration).unwrap_or(now);

        let timestamps = map.entry(key.to_string()).or_default();
        while let Some(&first) = timestamps.front() {
            if first < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() >= self.config.max_requests {
            let earliest = *timestamps.front().unwrap();
            let retry_after = earliest + self.config.window_duration - now;
            return Err(retry_after);
        }

        timestamps.push_back(now);
        Ok(self.config.max_requests - timestamps.len())
    }

    pub fn reset(&self, key: &str) {
        let mut map = self.state.lock().unwrap();
        map.remove(key);
    }
}
