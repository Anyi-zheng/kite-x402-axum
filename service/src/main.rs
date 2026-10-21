//! Runnable example wrapper service, equivalent to `main.go` /
//! `src/index.ts` in the other two templates: reads configuration from the
//! environment, exposes a free `/healthz`, and protects `/v1/*` with the
//! x402 payment gate before proxying to `UPSTREAM_URL`.
//!
//! See `.env.example` for every variable this reads, and the top-level
//! README in this directory for how to run it.

use std::{
    collections::HashMap,
    env,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use kite_x402_axum::{
    facilitator::{FacilitatorClient, RetryConfig},
    kite::{kite_chain_by_name, FACILITATOR_URL},
    middleware::{x402_payment, PaymentConfig},
    proxy::{proxy, same_origin_redirect_policy, UpstreamConfig},
    PaymentMetrics, PaymentMetricsSnapshot,
};
use serde_json::json;

mod cors;
use cors::{cors_middleware, CorsConfig};

#[tokio::main]
async fn main() {
    // Load .env file automatically if present (does not override existing env vars)
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting kite-x402 wrapper service");

    let port: u16 = env_or("PORT", "8402")
        .parse()
        .expect("PORT must be a number");

    let pay_to = env::var("PAY_TO").expect("PAY_TO is required (the wallet that receives payment)");
    let upstream_url = env::var("UPSTREAM_URL")
        .expect("UPSTREAM_URL is required (the API being wrapped)")
        .trim_end_matches('/')
        .to_string();
    let price_usd = env_or("PRICE_USD", "0.001");
    let network_name = env_or("KITE_NETWORK", "mainnet");
    let chain = kite_chain_by_name(&network_name)
        .unwrap_or_else(|e| panic!("invalid KITE_NETWORK={network_name:?}: {e}"));
    let facilitator_url = env_or("FACILITATOR_URL", FACILITATOR_URL);
    let description = env_or("SERVICE_DESCRIPTION", "Paid API access via Kite x402");
    let upstream_auth_header = env_or("UPSTREAM_AUTH_HEADER", "Authorization");
    let upstream_auth_value = env_or("UPSTREAM_AUTH_VALUE", "");
    let rate_limit_rps: f64 = env_or("RATE_LIMIT_RPS", "0")
        .parse()
        .expect("RATE_LIMIT_RPS must be a number");
    if rate_limit_rps < 0.0 {
        panic!("RATE_LIMIT_RPS must be non-negative");
    }
    let rate_limit_burst: f64 = env_or("RATE_LIMIT_BURST", &rate_limit_rps.to_string())
        .parse()
        .expect("RATE_LIMIT_BURST must be a number");
    if rate_limit_burst < 0.0 {
        panic!("RATE_LIMIT_BURST must be non-negative");
    }

    let rate_limiter: Arc<Option<TokenBucketRateLimiter>> = Arc::new(if rate_limit_rps > 0.0 {
        Some(TokenBucketRateLimiter::new(RateLimiterConfig {
            rps: rate_limit_rps,
            burst: rate_limit_burst.max(1.0),
        }))
    } else {
        None
    });

    let upstream_timeout_ms: u64 = env_or("UPSTREAM_TIMEOUT_MS", "10000")
        .parse()
        .expect("UPSTREAM_TIMEOUT_MS must be a number");
    if !(100..=300000).contains(&upstream_timeout_ms) {
        panic!("UPSTREAM_TIMEOUT_MS must be between 100 and 300000 ms");
    }
    let facilitator_timeout_ms: u64 = env_or("FACILITATOR_TIMEOUT_MS", "30000")
        .parse()
        .expect("FACILITATOR_TIMEOUT_MS must be a number");
    if !(100..=300000).contains(&facilitator_timeout_ms) {
        panic!("FACILITATOR_TIMEOUT_MS must be between 100 and 300000 ms");
    }
    let max_concurrent: usize = env_or("MAX_CONCURRENT_REQUESTS", "64")
        .parse()
        .expect("MAX_CONCURRENT_REQUESTS must be a number");
    if !(1..=10000).contains(&max_concurrent) {
        panic!("MAX_CONCURRENT_REQUESTS must be between 1 and 10000");
    }
    let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));

    let settle_retries: u32 = env_or("FACILITATOR_SETTLE_RETRIES", "2")
        .parse()
        .unwrap_or(2);
    let settle_backoff_ms: u64 = env_or("FACILITATOR_SETTLE_BACKOFF_MS", "150")
        .parse()
        .unwrap_or(150);

    let retry_cfg = RetryConfig::new(
        settle_retries,
        Duration::from_millis(settle_backoff_ms),
        Duration::from_secs(3),
    );

    let cors_origin = env_or("CORS_ORIGIN", "");
    let cors_cfg = Arc::new(CorsConfig::from_env(Some(&cors_origin)));

    tracing::info!(
        port = port,
        network = %network_name,
        chain_id = %chain.network,
        asset = %chain.asset_symbol,
        price_usd = %price_usd,
        pay_to = %pay_to,
        upstream_url = %upstream_url,
        facilitator_url = %facilitator_url,
        rate_limit_rps = rate_limit_rps,
        rate_limit_burst = rate_limit_burst,
        upstream_timeout_ms = upstream_timeout_ms,
        facilitator_timeout_ms = facilitator_timeout_ms,
        max_concurrent_requests = max_concurrent,
        cors_origin = %cors_origin,
        cors_enabled = cors_cfg.is_enabled(),
        auth_injected = !upstream_auth_value.is_empty(),
        "Configured kite-x402 wrapper"
    );

    // Never follow a redirect to another host: the injected upstream
    // credential would go with it. See `same_origin_redirect_policy`.
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(upstream_timeout_ms))
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("reqwest client");

    let clock_drift_secs = env::var("PAYMENT_CLOCK_DRIFT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let expiration_guard =
        clock_drift_secs.map(|drift| kite_x402_axum::ExpirationGuardConfig::new(drift, 5));

    let metrics = Arc::new(PaymentMetrics::new());
    let payment_cfg = Arc::new(PaymentConfig {
        pay_to,
        chain,
        price_usd,
        description,
        facilitator: FacilitatorClient::with_timeout(
            facilitator_url,
            Duration::from_millis(facilitator_timeout_ms),
        )
        .with_retry_config(retry_cfg),
        expiration_guard,
        metrics: Some(Arc::clone(&metrics)),
    });
    let upstream_cfg = Arc::new(UpstreamConfig {
        http: http_client,
        base_url: upstream_url,
        auth_header: upstream_auth_header,
        auth_value: upstream_auth_value,
    });

    // Everything under /v1 is metered: verify before the handler runs,
    // proxy to the upstream, settle only on a < 400 response.
    let paid = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(upstream_cfg)
        .layer(middleware::from_fn_with_state(
            payment_cfg.clone(),
            x402_payment,
        ))
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            concurrency_semaphore,
            concurrency_limiter,
        ));

    let service_metrics = Arc::new(ServiceMetrics::new());

    let metrics_router = Router::new()
        .route("/metrics/x402", axum::routing::get(metrics_x402_handler))
        .with_state(Arc::clone(&metrics));

    let diag_router = Router::new()
        .route("/livez", axum::routing::get(livez))
        .route("/metrics", axum::routing::get(metrics_endpoint))
        .with_state(Arc::clone(&service_metrics));

    let security_enabled = match env::var("SECURITY_HEADERS_ENABLED") {
        Ok(v) => v.trim() != "0" && !v.trim().eq_ignore_ascii_case("false"),
        Err(_) => true,
    };
    let security_csp = env_or("SECURITY_CSP", "default-src 'none'; frame-ancestors 'none'");
    let security_referrer_policy = env_or(
        "SECURITY_REFERRER_POLICY",
        "strict-origin-when-cross-origin",
    );

    let security_cfg = Arc::new(SecurityHeadersConfig {
        enabled: security_enabled,
        csp: security_csp,
        referrer_policy: security_referrer_policy,
    });

    tracing::info!(
        security_headers_enabled = security_enabled,
        "Configured security headers middleware"
    );

    let mut app = Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route(
            "/readyz",
            axum::routing::get(readyz).with_state(payment_cfg),
        )
        .merge(metrics_router)
        .merge(diag_router)
        .nest("/v1", paid)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            security_cfg,
            security_headers_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            service_metrics.clone(),
            http_request_logger,
        ));

    if cors_cfg.is_enabled() {
        app = app.layer(middleware::from_fn_with_state(cors_cfg, cors_middleware));
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("could not bind 0.0.0.0:{port}: {e}"));
    tracing::info!(
        port = port,
        network = %network_name,
        "kite-x402 wrapper listening on 0.0.0.0:{port} (network={network_name})"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");

    tracing::info!("Server shut down gracefully");
}

static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn is_valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'~' || b == b'-')
}

fn generate_request_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let count = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("req-{now:x}-{count:08x}")
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not_found",
            "message": "route not found"
        })),
    )
}

async fn metrics_x402_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<PaymentMetrics>>,
) -> Json<PaymentMetricsSnapshot> {
    tracing::debug!("Handling /metrics/x402 request");
    Json(metrics.snapshot())
}

#[derive(Debug)]
pub struct ServiceMetrics {
    start_time: Instant,
    total_requests: AtomicU64,
    paid_challenges: AtomicU64,
    successful_requests: AtomicU64,
    server_errors: AtomicU64,
    active_requests: AtomicI64,
}

impl Default for ServiceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            paid_challenges: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            active_requests: AtomicI64::new(0),
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "uptime_seconds": self.start_time.elapsed().as_secs(),
            "total_requests": self.total_requests.load(Ordering::SeqCst),
            "active_requests": self.active_requests.load(Ordering::SeqCst).max(0),
            "paid_challenges": self.paid_challenges.load(Ordering::SeqCst),
            "successful_requests": self.successful_requests.load(Ordering::SeqCst),
            "server_errors": self.server_errors.load(Ordering::SeqCst),
        })
    }
}

pub struct ActiveRequestGuard(Arc<ServiceMetrics>);

impl ActiveRequestGuard {
    pub fn new(metrics: Arc<ServiceMetrics>) -> Self {
        metrics.active_requests.fetch_add(1, Ordering::SeqCst);
        Self(metrics)
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn http_request_logger(
    State(metrics): State<Arc<ServiceMetrics>>,
    mut req: Request,
    next: Next,
) -> Response {
    let _guard = ActiveRequestGuard::new(metrics.clone());
    metrics.total_requests.fetch_add(1, Ordering::SeqCst);

    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map(|s| s.to_string())
        .unwrap_or_else(generate_request_id);

    if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", val);
    }

    // Custom headers can carry credentials too, so log names only.
    tracing::debug!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        header_names = ?req.headers().keys().collect::<Vec<_>>(),
        "--> Incoming HTTP request"
    );

    let mut response = next.run(req).await;

    if !response.headers().contains_key("x-request-id") {
        if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
            response.headers_mut().insert("x-request-id", val);
        }
    }

    let latency = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        metrics.server_errors.fetch_add(1, Ordering::SeqCst);
        tracing::error!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request failed (server error)"
        );
    } else if status == StatusCode::PAYMENT_REQUIRED {
        metrics.paid_challenges.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request requires payment (402 challenge issued)"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request client error"
        );
    } else {
        metrics.successful_requests.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request completed successfully"
        );
    }

    tracing::debug!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        latency = ?latency,
        response_header_names = ?response.headers().keys().collect::<Vec<_>>(),
        "<-- HTTP response details"
    );

    response
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityHeadersConfig {
    pub enabled: bool,
    pub csp: String,
    pub referrer_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            csp: "default-src 'none'; frame-ancestors 'none'".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
        }
    }
}

pub async fn security_headers_middleware(
    axum::extract::State(cfg): axum::extract::State<Arc<SecurityHeadersConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    if !cfg.enabled {
        return response;
    }

    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::X_XSS_PROTECTION,
        axum::http::HeaderValue::from_static("0"),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&cfg.referrer_policy) {
        headers.insert(axum::http::header::REFERRER_POLICY, val);
    }
    if let Ok(val) = axum::http::HeaderValue::from_str(&cfg.csp) {
        headers.insert(axum::http::header::CONTENT_SECURITY_POLICY, val);
    }

    response
}

#[derive(Clone, Debug)]
pub struct RateLimiterConfig {
    pub rps: f64,
    pub burst: f64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct TokenBucketRateLimiter {
    pub config: RateLimiterConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl TokenBucketRateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn acquire(&self, client_key: &str) -> Result<u64, u64> {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let bucket = buckets
            .entry(client_key.to_string())
            .or_insert_with(|| Bucket {
                tokens: self.config.burst,
                last_refill: now,
            });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.config.rps).min(self.config.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(bucket.tokens as u64)
        } else {
            let needed = 1.0 - bucket.tokens;
            let wait_secs = (needed / self.config.rps).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }
}

async fn rate_limit_middleware(
    State(limiter): State<Arc<Option<TokenBucketRateLimiter>>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(limiter) = limiter.as_ref() {
        let client_ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                req.headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "127.0.0.1".to_string());

        match limiter.acquire(&client_ip) {
            Ok(remaining) => {
                let mut response = next.run(req).await;
                if let Ok(limit_val) = limiter.config.rps.to_string().parse() {
                    response
                        .headers_mut()
                        .insert("x-ratelimit-limit", limit_val);
                }
                if let Ok(rem_val) = remaining.to_string().parse() {
                    response
                        .headers_mut()
                        .insert("x-ratelimit-remaining", rem_val);
                }
                response
            }
            Err(retry_after) => {
                tracing::warn!(client_ip = %client_ip, "Rate limit exceeded (429)");
                let mut res = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests, please slow down."
                    })),
                )
                    .into_response();
                if let Ok(retry_val) = retry_after.to_string().parse() {
                    res.headers_mut().insert("retry-after", retry_val);
                }
                if let Ok(limit_val) = limiter.config.rps.to_string().parse() {
                    res.headers_mut().insert("x-ratelimit-limit", limit_val);
                }
                if let Ok(rem_val) = "0".parse() {
                    res.headers_mut().insert("x-ratelimit-remaining", rem_val);
                }
                if let Ok(cc_val) = "no-store".parse() {
                    res.headers_mut().insert("cache-control", cc_val);
                }
                res
            }
        }
    } else {
        next.run(req).await
    }
}

async fn livez(State(metrics): State<Arc<ServiceMetrics>>) -> Json<serde_json::Value> {
    tracing::debug!("Handling /livez request");
    Json(json!({
        "status": "ok",
        "uptime_seconds": metrics.start_time.elapsed().as_secs(),
    }))
}

async fn metrics_endpoint(State(metrics): State<Arc<ServiceMetrics>>) -> Json<serde_json::Value> {
    tracing::debug!("Handling /metrics request");
    Json(metrics.snapshot())
}

async fn concurrency_limiter(
    axum::extract::State(semaphore): axum::extract::State<Arc<tokio::sync::Semaphore>>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(permit) = semaphore.try_acquire() else {
        tracing::warn!("Max concurrency capacity reached, rejecting request with 503");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (axum::http::header::RETRY_AFTER, "1"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            Json(json!({ "error": "service_busy" })),
        )
            .into_response();
    };

    let response = next.run(req).await;
    drop(permit);
    response
}

async fn healthz() -> Json<serde_json::Value> {
    tracing::debug!("Handling /healthz request");
    Json(json!({ "status": "ok" }))
}

async fn readyz(
    State(payment_cfg): State<Arc<PaymentConfig>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    tracing::debug!("Handling /readyz request");
    match payment_cfg.facilitator.probe().await {
        Ok(()) => Ok(Json(json!({
            "status": "ready",
            "facilitator": "ok",
            "network": payment_cfg.chain.network,
        }))),
        Err(err) => {
            tracing::warn!(error = %err, "Readiness probe failed: facilitator unreachable");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "facilitator": "unreachable",
                    "error": err.to_string(),
                })),
            ))
        }
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route("/healthz", get(healthz))
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logger_handles_404() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route("/healthz", get(healthz))
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/not_found")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // ---- env_or -------------------------------------------------------------
    // Each test uses its own variable name so parallel tests cannot interfere.

    #[test]
    fn env_or_returns_the_fallback_when_unset() {
        assert_eq!(env_or("KITE_TEST_ENV_OR_UNSET", "fallback"), "fallback");
    }

    #[test]
    fn env_or_returns_the_trimmed_value_when_set() {
        env::set_var("KITE_TEST_ENV_OR_SET", "  value \n");
        assert_eq!(env_or("KITE_TEST_ENV_OR_SET", "fallback"), "value");
    }

    #[test]
    fn env_or_treats_blank_values_as_unset() {
        for (i, blank) in ["", "   ", "\t\n"].into_iter().enumerate() {
            let key = format!("KITE_TEST_ENV_OR_BLANK_{i}");
            env::set_var(&key, blank);
            assert_eq!(env_or(&key, "fallback"), "fallback");
        }
    }

    #[test]
    fn env_or_does_not_trim_the_fallback() {
        assert_eq!(env_or("KITE_TEST_ENV_OR_UNSET_2", " padded "), " padded ");
    }

    // ---- http_request_logger --------------------------------------------------

    #[tokio::test]
    async fn logger_passes_every_status_class_through_unchanged() {
        for status in [200u16, 204, 302, 402, 404, 500, 503] {
            let metrics = Arc::new(ServiceMetrics::new());
            let app = Router::new()
                .route(
                    "/s",
                    get(move || async move { StatusCode::from_u16(status).unwrap() }),
                )
                .layer(middleware::from_fn_with_state(metrics, http_request_logger));
            let res = app
                .oneshot(Request::builder().uri("/s").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), status);
        }
    }

    #[tokio::test]
    async fn logger_does_not_alter_headers_or_body() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route("/h", get(|| async { ([("x-thing", "1")], "payload") }))
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));
        let res = app
            .oneshot(Request::builder().uri("/h").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.headers()["x-thing"], "1");
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"payload");
    }

    #[tokio::test]
    async fn healthz_body_is_status_ok_json() {
        let Json(v) = healthz().await;
        assert_eq!(v, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn livez_body_contains_ok_and_uptime() {
        let metrics = Arc::new(ServiceMetrics::new());
        let Json(v) = livez(State(metrics)).await;
        assert_eq!(v["status"], "ok");
        assert!(v["uptime_seconds"].as_u64().is_some());
    }

    #[tokio::test]
    async fn metrics_endpoint_tracks_and_reports_requests() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/metrics", get(metrics_endpoint))
            .with_state(metrics.clone())
            .layer(middleware::from_fn_with_state(
                metrics.clone(),
                http_request_logger,
            ));

        // Initial snapshot
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["total_requests"], 1);
        assert_eq!(body["active_requests"], 1);

        // Another request to /healthz
        let res2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        let Json(snapshot) = metrics_endpoint(State(metrics.clone())).await;
        assert_eq!(snapshot["total_requests"], 2);
        assert_eq!(snapshot["successful_requests"], 2);
        assert_eq!(metrics.active_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn parse_payment_clock_drift_secs() {
        env::set_var("PAYMENT_CLOCK_DRIFT_SECS", "45");
        let parsed = env::var("PAYMENT_CLOCK_DRIFT_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        assert_eq!(parsed, Some(45));
        env::remove_var("PAYMENT_CLOCK_DRIFT_SECS");
    }

    #[tokio::test]
    async fn security_headers_applied_by_default() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig::default());
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
        assert_eq!(res.headers()["x-frame-options"], "DENY");
        assert_eq!(res.headers()["x-xss-protection"], "0");
        assert_eq!(
            res.headers()["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            res.headers()["content-security-policy"],
            "default-src 'none'; frame-ancestors 'none'"
        );
    }

    #[tokio::test]
    async fn security_headers_disabled_when_flag_false() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig {
            enabled: false,
            ..Default::default()
        });
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.headers().contains_key("x-content-type-options"));
        assert!(!res.headers().contains_key("x-frame-options"));
        assert!(!res.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn security_headers_custom_csp_and_referrer() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig {
            enabled: true,
            csp: "default-src 'self'".to_string(),
            referrer_policy: "no-referrer".to_string(),
        });
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            res.headers()["content-security-policy"],
            "default-src 'self'"
        );
        assert_eq!(res.headers()["referrer-policy"], "no-referrer");
    }

    #[test]
    fn rate_limiter_allows_burst_and_depletes() {
        let limiter = TokenBucketRateLimiter::new(RateLimiterConfig {
            rps: 1.0,
            burst: 2.0,
        });

        // First two should succeed
        assert!(limiter.acquire("127.0.0.1").is_ok());
        assert!(limiter.acquire("127.0.0.1").is_ok());

        // Third should be rate limited
        let res = limiter.acquire("127.0.0.1");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), 1);

        // Different IP has separate bucket
        assert!(limiter.acquire("192.168.1.1").is_ok());
    }

    #[tokio::test]
    async fn rate_limit_middleware_returns_429_when_depleted() {
        let limiter = Arc::new(Some(TokenBucketRateLimiter::new(RateLimiterConfig {
            rps: 1.0,
            burst: 1.0,
        })));

        let app = Router::new()
            .route("/test", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ));

        // First request is allowed (200)
        let res1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("x-forwarded-for", "10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res1.status(), StatusCode::OK);
        assert_eq!(res1.headers()["x-ratelimit-remaining"], "0");

        // Second request triggers 429
        let res2 = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("x-forwarded-for", "10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res2.headers()["retry-after"], "1");
        assert_eq!(res2.headers()["cache-control"], "no-store");
    }
}
