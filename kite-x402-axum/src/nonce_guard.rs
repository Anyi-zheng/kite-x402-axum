//! Nonce replay protection guard for x402 payment signatures.
//!
//! Tracks recently observed payment nonces or signature digests in a thread-safe,
//! sliding-window bounded cache to reject duplicate submissions before calling
//! the remote facilitator.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use thiserror::Error;

use crate::types::PaymentPayload;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceReplayError {
    #[error("payment signature/nonce has already been used: {nonce}")]
    ReplayDetected { nonce: String },
}

#[derive(Debug)]
struct NonceEntry {
    nonce: String,
    seen_at: Instant,
}

#[derive(Debug)]
struct NonceStore {
    entries: HashMap<String, Instant>,
    queue: VecDeque<NonceEntry>,
}

/// Thread-safe in-memory cache for detecting and rejecting replayed payment nonces.
#[derive(Debug)]
pub struct PaymentNonceReplayGuard {
    max_capacity: usize,
    ttl: Duration,
    store: Mutex<NonceStore>,
}

impl Default for PaymentNonceReplayGuard {
    fn default() -> Self {
        Self::new(10_000, 3600)
    }
}

impl PaymentNonceReplayGuard {
    pub fn new(max_capacity: usize, ttl_seconds: u64) -> Self {
        Self {
            max_capacity: max_capacity.max(1),
            ttl: Duration::from_secs(ttl_seconds.max(1)),
            store: Mutex::new(NonceStore {
                entries: HashMap::with_capacity(max_capacity.min(1024)),
                queue: VecDeque::with_capacity(max_capacity.min(1024)),
            }),
        }
    }

    /// Extracts a unique replay key from the payment payload.
    ///
    /// Inspects `payload.authorization.nonce`, `payload.nonce`, or `payload.signature`,
    /// falling back to the canonical JSON serialization of the payload.
    pub fn extract_nonce_key(&self, payload: &PaymentPayload) -> String {
        if let Some(auth) = payload.payload.get("authorization") {
            if let Some(nonce) = auth.get("nonce") {
                if let Some(s) = nonce.as_str() {
                    return s.to_string();
                }
                return nonce.to_string();
            }
        }
        if let Some(nonce) = payload.payload.get("nonce") {
            if let Some(s) = nonce.as_str() {
                return s.to_string();
            }
            return nonce.to_string();
        }
        if let Some(sig) = payload.payload.get("signature") {
            if let Some(s) = sig.as_str() {
                return s.to_string();
            }
        }
        payload.payload.to_string()
    }

    /// Checks if a nonce was recently seen. If not seen, records it.
    ///
    /// Returns `Err(NonceReplayError::ReplayDetected)` if the nonce is still within TTL.
    pub fn check_and_record(&self, nonce: &str) -> Result<(), NonceReplayError> {
        let now = Instant::now();
        let mut store = self.store.lock().unwrap();

        // Evict expired entries from front of queue
        while let Some(front) = store.queue.front() {
            if now.duration_since(front.seen_at) > self.ttl {
                let expired = store.queue.pop_front().unwrap();
                if let Some(&ts) = store.entries.get(&expired.nonce) {
                    if ts == expired.seen_at {
                        store.entries.remove(&expired.nonce);
                    }
                }
            } else {
                break;
            }
        }

        // Check if nonce is currently active
        if let Some(&seen_at) = store.entries.get(nonce) {
            if now.duration_since(seen_at) <= self.ttl {
                return Err(NonceReplayError::ReplayDetected {
                    nonce: nonce.to_string(),
                });
            }
        }

        // If at capacity, pop oldest entry
        if store.entries.len() >= self.max_capacity {
            if let Some(oldest) = store.queue.pop_front() {
                store.entries.remove(&oldest.nonce);
            }
        }

        store.entries.insert(nonce.to_string(), now);
        store.queue.push_back(NonceEntry {
            nonce: nonce.to_string(),
            seen_at: now,
        });

        Ok(())
    }

    /// Number of nonces currently retained in memory.
    pub fn len(&self) -> usize {
        let store = self.store.lock().unwrap();
        store.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all recorded nonces.
    pub fn clear(&self) {
        let mut store = self.store.lock().unwrap();
        store.entries.clear();
        store.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::types::PaymentRequirements;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:2368".into(),
            amount: "1000".into(),
            asset: "0x0000000000000000000000000000000000000000".into(),
            pay_to: "0x1111111111111111111111111111111111111111".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    #[test]
    fn records_new_nonce_successfully() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert_eq!(guard.len(), 0);
        assert!(guard.check_and_record("nonce-1").is_ok());
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn rejects_replayed_nonce() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert!(guard.check_and_record("nonce-repeat").is_ok());
        let err = guard.check_and_record("nonce-repeat").unwrap_err();
        assert_eq!(
            err,
            NonceReplayError::ReplayDetected {
                nonce: "nonce-repeat".into()
            }
        );
    }

    #[test]
    fn isolates_distinct_nonces() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert!(guard.check_and_record("nonce-a").is_ok());
        assert!(guard.check_and_record("nonce-b").is_ok());
        assert!(guard.check_and_record("nonce-c").is_ok());
        assert_eq!(guard.len(), 3);
    }

    #[test]
    fn extracts_nonce_from_authorization_subfield() {
        let guard = PaymentNonceReplayGuard::default();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({
                "authorization": {
                    "nonce": "0xdeadbeef1234"
                }
            }),
            extensions: None,
        };
        assert_eq!(guard.extract_nonce_key(&payload), "0xdeadbeef1234");
    }

    #[test]
    fn extracts_nonce_from_top_level_payload() {
        let guard = PaymentNonceReplayGuard::default();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({
                "nonce": "0x5678"
            }),
            extensions: None,
        };
        assert_eq!(guard.extract_nonce_key(&payload), "0x5678");
    }

    #[test]
    fn respects_max_capacity_with_oldest_eviction() {
        let guard = PaymentNonceReplayGuard::new(2, 60);
        assert!(guard.check_and_record("nonce-1").is_ok());
        assert!(guard.check_and_record("nonce-2").is_ok());
        assert_eq!(guard.len(), 2);

        // Third entry evicts oldest ("nonce-1")
        assert!(guard.check_and_record("nonce-3").is_ok());
        assert_eq!(guard.len(), 2);

        // "nonce-1" can now be accepted again because it was evicted
        assert!(guard.check_and_record("nonce-1").is_ok());
        // but "nonce-3" should be rejected
        assert!(guard.check_and_record("nonce-3").is_err());
    }
}
