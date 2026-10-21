//! Per-client token buckets and explicit trust for forwarding proxies.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct TrustedProxies(Vec<IpNetwork>);

#[derive(Clone, Debug)]
struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

impl TrustedProxies {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        let invalid =
            "RATE_LIMIT_TRUSTED_PROXIES must contain comma-separated IP addresses or CIDRs";
        if value.trim().is_empty() {
            return Ok(Self::default());
        }
        let mut networks = Vec::new();
        for value in value.split(',').map(str::trim) {
            let (address, prefix) = match value.split_once('/') {
                Some((address, prefix)) => {
                    (address, Some(prefix.parse::<u8>().map_err(|_| invalid)?))
                }
                None => (value, None),
            };
            let mut address = address.parse::<IpAddr>().map_err(|_| invalid)?;
            let bits = if address.is_ipv4() { 32 } else { 128 };
            let mut prefix = prefix.unwrap_or(bits);
            if prefix > bits {
                return Err(invalid);
            }
            if let IpAddr::V6(ip) = address {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    prefix = prefix.checked_sub(96).ok_or(invalid)?;
                    address = IpAddr::V4(ip);
                }
            }
            networks.push(IpNetwork { address, prefix });
        }
        Ok(Self(networks))
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.0.iter().any(|network| match (network.address, ip) {
            (IpAddr::V4(network_ip), IpAddr::V4(ip)) => {
                network.prefix == 0
                    || u32::from(network_ip) >> (32 - network.prefix)
                        == u32::from(ip) >> (32 - network.prefix)
            }
            (IpAddr::V6(network_ip), IpAddr::V6(ip)) => {
                network.prefix == 0
                    || u128::from(network_ip) >> (128 - network.prefix)
                        == u128::from(ip) >> (128 - network.prefix)
            }
            _ => false,
        })
    }
}

fn client_ip(headers: &HeaderMap, peer: IpAddr, proxies: &TrustedProxies) -> Result<IpAddr, ()> {
    let mut client = normalize_ip(peer);
    if !proxies.contains(client) {
        return Ok(client);
    }
    if headers.contains_key("x-forwarded-for") {
        let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
        for value in values.into_iter().rev() {
            if !proxies.contains(client) {
                break;
            }
            for hop in value.to_str().map_err(|_| ())?.split(',').rev() {
                // Everything left of the first untrusted hop is client-controlled.
                if !proxies.contains(client) {
                    return Ok(client);
                }
                client = normalize_ip(hop.trim().parse().map_err(|_| ())?);
            }
        }
    } else if let Some(value) = headers.get("x-real-ip") {
        if headers.get_all("x-real-ip").iter().count() != 1 {
            return Err(());
        }
        client = normalize_ip(
            value
                .to_str()
                .map_err(|_| ())?
                .trim()
                .parse()
                .map_err(|_| ())?,
        );
    }
    Ok(client)
}

#[derive(Clone, Debug)]
pub(crate) struct RateLimiterConfig {
    pub rps: f64,
    pub burst: f64,
    pub trusted_proxies: TrustedProxies,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub(crate) struct TokenBucketRateLimiter {
    pub config: RateLimiterConfig,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl TokenBucketRateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn acquire(&self, client_ip: IpAddr) -> Result<u64, u64> {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let bucket = buckets.entry(client_ip).or_insert_with(|| Bucket {
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

pub(crate) async fn rate_limit_middleware(
    State(limiter): State<Arc<Option<TokenBucketRateLimiter>>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(limiter) = limiter.as_ref() {
        let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("cache-control", "no-store")],
                Json(json!({ "error": "client_address_unavailable" })),
            )
                .into_response();
        };
        let client_ip = match client_ip(req.headers(), peer.ip(), &limiter.config.trusted_proxies) {
            Ok(ip) => ip,
            Err(()) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("cache-control", "no-store")],
                    Json(json!({ "error": "invalid_forwarded_ip" })),
                )
                    .into_response()
            }
        };

        match limiter.acquire(client_ip) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    fn config(burst: f64) -> RateLimiterConfig {
        RateLimiterConfig {
            rps: 1.0,
            burst,
            trusted_proxies: TrustedProxies::default(),
        }
    }

    fn resolve(peer: &str, proxies: &str, values: &[(&str, &str)]) -> Result<IpAddr, ()> {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        client_ip(
            &headers,
            peer.parse().unwrap(),
            &TrustedProxies::parse(proxies).unwrap(),
        )
    }

    #[test]
    fn networks_match_ipv4_ipv6_and_mapped_addresses() {
        for (network, inside, outside) in [
            ("10.2.3.4/8", "10.99.0.1", "11.0.0.1"),
            ("192.0.2.1", "192.0.2.1", "192.0.2.2"),
            ("2001:db8::/32", "2001:db8::1", "2001:db9::1"),
            ("::1", "::1", "::2"),
            ("0.0.0.0/0", "203.0.113.1", "::1"),
            ("::/0", "2001:db8::1", "192.0.2.1"),
            ("::ffff:192.0.2.0/120", "::ffff:192.0.2.2", "192.0.3.1"),
        ] {
            let proxies = TrustedProxies::parse(network).unwrap();
            assert!(
                proxies.contains(inside.parse().unwrap()),
                "{network}: {inside}"
            );
            assert!(
                !proxies.contains(outside.parse().unwrap()),
                "{network}: {outside}"
            );
        }
        for value in [
            "*",
            "host.example",
            "127.0.0.1/33",
            "::/129",
            "127.0.0.1,",
            ",",
            "127.0.0.1/x",
        ] {
            assert!(TrustedProxies::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn untrusted_peers_cannot_choose_their_bucket() {
        assert_eq!(
            resolve(
                "192.0.2.1",
                "10.0.0.0/8",
                &[("x-forwarded-for", "bad"), ("x-real-ip", "203.0.113.9")]
            ),
            Ok("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            resolve("::ffff:192.0.2.1", "", &[]),
            Ok("192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn trusted_chain_stops_at_first_untrusted_hop() {
        for forwarded in [
            "garbage, 203.0.113.9, 10.0.0.2",
            "192.0.2.100, 203.0.113.9, 10.0.0.2",
        ] {
            assert_eq!(
                resolve("10.0.0.1", "10.0.0.0/8", &[("x-forwarded-for", forwarded)]),
                Ok("203.0.113.9".parse().unwrap())
            );
        }
        assert_eq!(
            resolve(
                "2001:db8::1",
                "2001:db8::/32",
                &[("x-forwarded-for", "2001:db9::5, 2001:db8::2")]
            ),
            Ok("2001:db9::5".parse().unwrap())
        );
    }

    #[test]
    fn repeated_forwarded_headers_preserve_chain_order() {
        assert_eq!(
            resolve(
                "10.0.0.1",
                "10.0.0.0/8",
                &[
                    ("x-forwarded-for", "203.0.113.9"),
                    ("x-forwarded-for", "10.0.0.2")
                ]
            ),
            Ok("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn trusted_headers_are_validated_and_precedence_is_explicit() {
        for value in ["", "not-an-ip", "203.0.113.9,", "203.0.113.9:80"] {
            assert_eq!(
                resolve(
                    "10.0.0.1",
                    "10.0.0.0/8",
                    &[("x-forwarded-for", value), ("x-real-ip", "203.0.113.8")]
                ),
                Err(())
            );
        }
        assert_eq!(
            resolve("10.0.0.1", "10.0.0.0/8", &[("x-real-ip", "203.0.113.8")]),
            Ok("203.0.113.8".parse().unwrap())
        );
        assert_eq!(
            resolve(
                "10.0.0.1",
                "10.0.0.0/8",
                &[("x-real-ip", "203.0.113.8"), ("x-real-ip", "203.0.113.9")]
            ),
            Err(())
        );
        assert_eq!(
            resolve(
                "10.0.0.1",
                "10.0.0.0/8",
                &[
                    ("x-forwarded-for", "203.0.113.9"),
                    ("x-real-ip", "203.0.113.8")
                ]
            ),
            Ok("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn rate_limiter_allows_burst_and_keeps_clients_separate() {
        let limiter = TokenBucketRateLimiter::new(config(2.0));
        let ip = "192.0.2.1".parse().unwrap();
        assert!(limiter.acquire(ip).is_ok());
        assert!(limiter.acquire(ip).is_ok());
        assert_eq!(limiter.acquire(ip), Err(1));
        assert!(limiter.acquire("192.0.2.2".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn middleware_requires_peer_metadata_only_when_enabled() {
        for enabled in [false, true] {
            let limiter = Arc::new(enabled.then(|| TokenBucketRateLimiter::new(config(1.0))));
            let app = Router::new()
                .route("/test", get(|| async { StatusCode::OK }))
                .layer(middleware::from_fn_with_state(
                    limiter,
                    rate_limit_middleware,
                ));
            let response = app
                .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                }
            );
        }
    }

    #[tokio::test]
    async fn middleware_returns_429_for_the_same_transport_peer() {
        let limiter = Arc::new(Some(TokenBucketRateLimiter::new(config(1.0))));
        let app = Router::new()
            .route("/test", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ));
        for (forwarded, status) in [
            ("192.0.2.8", StatusCode::OK),
            ("192.0.2.9", StatusCode::TOO_MANY_REQUESTS),
        ] {
            let request = Request::builder()
                .uri("/test")
                .header("x-forwarded-for", forwarded)
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["x-ratelimit-remaining"], "0");
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(response.headers()["retry-after"], "1");
                assert_eq!(response.headers()["cache-control"], "no-store");
            }
        }
    }
}
