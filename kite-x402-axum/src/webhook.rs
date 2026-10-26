use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Webhook event trigger type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    PaymentPrompted,
    PaymentVerified,
    PaymentSettled,
    PaymentFailed,
}

/// A dispatched webhook event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_id: String,
    pub event_type: WebhookEventType,
    pub timestamp_ms: u64,
    pub payer: Option<String>,
    pub network: Option<String>,
    pub amount_atomic: Option<String>,
    pub tx_hash: Option<String>,
    pub request_path: Option<String>,
}

/// Delivery status of a webhook invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Abandoned,
}

/// Record of an external webhook delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryRecord {
    pub delivery_id: u64,
    pub target_url: String,
    pub payload: WebhookPayload,
    pub attempts: u32,
    pub max_retries: u32,
    pub status: DeliveryStatus,
    pub last_status_code: Option<u16>,
    pub last_error: Option<String>,
    pub last_attempt_ms: Option<u64>,
}

/// Configuration for webhook dispatcher.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub target_urls: Vec<String>,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_queue_size: usize,
    pub signing_secret: Option<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            target_urls: Vec::new(),
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_queue_size: 1000,
            signing_secret: None,
        }
    }
}

/// Thread-safe webhook queue and dispatcher.
#[derive(Debug, Clone)]
pub struct WebhookDispatcher {
    config: WebhookConfig,
    state: Arc<RwLock<WebhookState>>,
}

#[derive(Debug)]
struct WebhookState {
    next_delivery_id: u64,
    queue: VecDeque<WebhookDeliveryRecord>,
    history: VecDeque<WebhookDeliveryRecord>,
}

impl WebhookDispatcher {
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(WebhookState {
                next_delivery_id: 1,
                queue: VecDeque::new(),
                history: VecDeque::new(),
            })),
        }
    }

    /// Enqueues a payment lifecycle event for all registered webhook targets.
    pub fn enqueue_event(
        &self,
        event_type: WebhookEventType,
        payer: Option<String>,
        network: Option<String>,
        amount_atomic: Option<String>,
        tx_hash: Option<String>,
        request_path: Option<String>,
    ) -> Vec<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event_id = format!("evt_{}_{}", now, fastrand_hex(8));
        let payload = WebhookPayload {
            event_id,
            event_type,
            timestamp_ms: now,
            payer,
            network,
            amount_atomic,
            tx_hash,
            request_path,
        };

        let mut delivery_ids = Vec::new();
        let mut state = self.state.write().expect("lock poisoned");

        for target in &self.config.target_urls {
            let delivery_id = state.next_delivery_id;
            state.next_delivery_id += 1;

            let record = WebhookDeliveryRecord {
                delivery_id,
                target_url: target.clone(),
                payload: payload.clone(),
                attempts: 0,
                max_retries: self.config.max_retries,
                status: DeliveryStatus::Pending,
                last_status_code: None,
                last_error: None,
                last_attempt_ms: None,
            };

            if state.queue.len() >= self.config.max_queue_size {
                state.queue.pop_front();
            }
            state.queue.push_back(record);
            delivery_ids.push(delivery_id);
        }

        delivery_ids
    }

    /// Records the result of a delivery attempt.
    pub fn record_attempt_result(
        &self,
        delivery_id: u64,
        success: bool,
        status_code: Option<u16>,
        error_msg: Option<String>,
    ) -> Option<WebhookDeliveryRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut state = self.state.write().expect("lock poisoned");
        if let Some(pos) = state.queue.iter().position(|r| r.delivery_id == delivery_id) {
            let mut record = state.queue.remove(pos).unwrap();
            record.attempts += 1;
            record.last_attempt_ms = Some(now);
            record.last_status_code = status_code;
            record.last_error = error_msg;

            if success {
                record.status = DeliveryStatus::Delivered;
                if state.history.len() >= self.config.max_queue_size {
                    state.history.pop_front();
                }
                state.history.push_back(record.clone());
                Some(record)
            } else if record.attempts > record.max_retries {
                record.status = DeliveryStatus::Abandoned;
                if state.history.len() >= self.config.max_queue_size {
                    state.history.pop_front();
                }
                state.history.push_back(record.clone());
                Some(record)
            } else {
                record.status = DeliveryStatus::Failed;
                state.queue.push_back(record.clone());
                Some(record)
            }
        } else {
            None
        }
    }

    /// Number of pending deliveries in queue.
    pub fn pending_count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.queue.len()
    }

    /// Number of completed deliveries in history.
    pub fn history_count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.history.len()
    }
}

fn fastrand_hex(len: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    let val = hasher.finish();
    format!("{:016x}", val)[..len.min(16)].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_enqueue_and_delivery() {
        let config = WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_retries: 2,
            initial_backoff: Duration::from_millis(100),
            max_queue_size: 50,
            signing_secret: Some("secret-key".into()),
        };

        let dispatcher = WebhookDispatcher::new(config);
        let ids = dispatcher.enqueue_event(
            WebhookEventType::PaymentSettled,
            Some("0x1234".into()),
            Some("kite-mainnet".into()),
            Some("5000000".into()),
            Some("0xabc...".into()),
            Some("/v1/data".into()),
        );

        assert_eq!(ids.len(), 1);
        assert_eq!(dispatcher.pending_count(), 1);

        let delivery = dispatcher.record_attempt_result(ids[0], true, Some(200), None);
        assert!(delivery.is_some());
        assert_eq!(delivery.unwrap().status, DeliveryStatus::Delivered);
        assert_eq!(dispatcher.pending_count(), 0);
        assert_eq!(dispatcher.history_count(), 1);
    }

    #[test]
    fn test_webhook_retry_and_abandonment() {
        let config = WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_retries: 1,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config);
        let ids = dispatcher.enqueue_event(
            WebhookEventType::PaymentFailed,
            None,
            None,
            None,
            None,
            None,
        );

        // First attempt fails -> requeued
        let d1 = dispatcher.record_attempt_result(ids[0], false, Some(500), Some("Server error".into()));
        assert_eq!(d1.unwrap().status, DeliveryStatus::Failed);
        assert_eq!(dispatcher.pending_count(), 1);

        // Second attempt fails (exceeds max_retries = 1) -> Abandoned
        let d2 = dispatcher.record_attempt_result(ids[0], false, Some(500), Some("Server error".into()));
        assert_eq!(d2.unwrap().status, DeliveryStatus::Abandoned);
        assert_eq!(dispatcher.pending_count(), 0);
        assert_eq!(dispatcher.history_count(), 1);
    }
}
