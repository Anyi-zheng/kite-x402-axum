//! 验证支付协议版本在本地校验，且两个支付头名称均保持相同语义。

mod common;

use axum::http::{header, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn unsupported_versions_are_rejected_before_any_downstream_call() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let requirements = probe_requirements(&app, "/v1/forecast").await;

    for header_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        for version in [0, 1, 3, u32::MAX] {
            let mut payload = payload_for(&requirements);
            payload.x402_version = version;
            let encoded = encode_payload(&payload);
            let response = send(
                &app,
                req_with("GET", "/v1/forecast", &[(header_name, &encoded)], vec![]),
            )
            .await;

            assert_eq!(
                response.status(),
                StatusCode::PAYMENT_REQUIRED,
                "{header_name}: x402Version {version}"
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(response.headers().get("PAYMENT-RESPONSE").is_none());
            let challenge = header_json(response.headers(), "PAYMENT-REQUIRED");
            assert_eq!(challenge["x402Version"], 2);
            assert_eq!(challenge["error"], "Invalid payment signature");
            assert_eq!(requirements_of(&response), requirements);
            assert_eq!(body_json(response).await, json!({}));
            assert_eq!(mocks.facilitator.verify_count(), 0);
            assert_eq!(mocks.upstream.count(), 0);
            assert_eq!(mocks.facilitator.settle_count(), 0);
            assert!(mocks.timeline().is_empty());
        }
    }
}

#[tokio::test]
async fn version_two_completes_payment_flow_with_either_header_name() {
    for header_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        let mocks = Mocks::start().await;
        let app = mocks.app();
        let requirements = probe_requirements(&app, "/v1/forecast").await;
        let encoded = payment_header(&requirements);
        let response = send(
            &app,
            req_with("GET", "/v1/forecast", &[(header_name, &encoded)], vec![]),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK, "{header_name}");
        let receipt = header_json(response.headers(), "PAYMENT-RESPONSE");
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["transaction"], TX_HASH);
        assert_eq!(body_json(response).await, json!({ "upstream": true }));
        assert_eq!(mocks.facilitator.verify_count(), 1);
        assert_eq!(mocks.upstream.count(), 1);
        assert_eq!(mocks.facilitator.settle_count(), 1);
        assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
    }
}
