//! Integration tests for 403 fail-closed (no route downgrade), 409 conflict, 422 validation,
//! 429 `Retry-After` & `X-RateLimit-*` dual-bucket pacing, and 2.45+ `Idempotency-Key` + timeout reconcile.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use n8n_api_client::{ApiClientConfig, ListQueryParams, N8nApiClient, Outcome, RateLimitConfig};
use n8n_capability::verify_fallback_allowed;
use n8n_mcp_server::ValidateParams;
use n8n_mcp_server::tools::execute_validate;
use n8n_policy::PolicyMode;
use n8n_types::{
    EnvironmentKind, N8nError, OperationStatus, PermissionDecision, RouteUsed, SecretValue,
};
use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{
    CANARY_API_KEY, build_loopback_api_client, build_test_app_state, loopback_ssrf_policy,
};

#[tokio::test]
async fn forbidden_403_fails_closed_with_zero_route_downgrade() {
    let server = MockServer::start().await;

    // Native MCP returns 403 Forbidden during validation -> MUST NOT fall back to offline or Public API!
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "Insufficient instance-level MCP permissions"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let state = build_test_app_state(
        "staging",
        &server.uri(),
        EnvironmentKind::Staging,
        PolicyMode::StagingSafe,
        true,
    );

    let env = execute_validate(
        &state,
        ValidateParams {
            instance: Some("staging".to_owned()),
            workflow: json!({ "name": "Demo", "nodes": [], "connections": {} }),
            use_native_mcp: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(env.status, OperationStatus::Blocked);
    assert_eq!(env.permission, PermissionDecision::Denied);
    assert_eq!(env.route_used, RouteUsed::NativeMcp);

    let e403 = N8nError::forbidden("staging", Some("workflow:update".to_owned()), "denied");
    assert!(verify_fallback_allowed(RouteUsed::NativeMcp, e403).is_err());
}

#[tokio::test]
async fn maps_409_conflict_and_422_validation_cleanly() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/wf_conflict/publish"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "Workflow version drift conflict"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/api/v1/workflows/wf_invalid"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": "Invalid node parameter schema"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);

    let err_409 = api
        .publish_workflow("wf_conflict", None)
        .await
        .expect_err("409 conflict");
    assert!(matches!(err_409, N8nError::Conflict409 { .. }));
    assert_eq!(err_409.to_operation_status(), OperationStatus::Conflict);

    let err_422 = api
        .update_workflow("wf_invalid", &json!({ "name": "" }))
        .await
        .expect_err("422 validation");
    assert!(matches!(err_422, N8nError::Validation422 { .. }));
}

#[tokio::test]
async fn obeys_429_retry_after_and_x_ratelimit_headers_across_buckets() {
    let server = MockServer::start().await;
    let call_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = call_counter.clone();

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0.25")
                    .insert_header("X-RateLimit-Limit", "10")
                    .insert_header("X-RateLimit-Remaining", "0")
                    .insert_header("X-RateLimit-Reset", "1")
                    .set_body_json(json!({ "message": "Too Many Requests" }))
            } else {
                ResponseTemplate::new(200)
                    .insert_header("X-RateLimit-Limit", "10")
                    .insert_header("X-RateLimit-Remaining", "9")
                    .insert_header("X-RateLimit-Reset", "60")
                    .set_body_json(json!({
                        "data": [{ "id": "wf_ok", "name": "Paced Workflow", "active": false }],
                        "nextCursor": null
                    }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let started = Instant::now();
    let res = api
        .list_workflows(&ListQueryParams::default())
        .await
        .expect("retries once after obeying Retry-After");
    let elapsed = started.elapsed();

    assert_eq!(res.data.len(), 1);
    assert!(
        elapsed >= Duration::from_millis(220),
        "must obey Retry-After=0.25s (elapsed={elapsed:?})"
    );
    let snap = api.rate_limit_snapshot();
    assert!(snap.server_headers_observed);
    assert_eq!(snap.global_read_remaining, Some(9));
    assert!(snap.total_pacing_sleeps_ms >= 220);
}

#[tokio::test]
async fn idempotent_post_reuses_exact_key_and_never_blindly_retries_mutating_timeout() {
    let server = MockServer::start().await;

    // 1. Timeout on mutating POST -> MUST NOT blindly retry (`expect(1)`) and MUST return UnknownNeedsReconcile!
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows"))
        .and(header_exists("idempotency-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(450))
                .set_body_json(json!({
                    "id": "wf_created_slow",
                    "name": "Slow Draft",
                    "active": false
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut cfg = ApiClientConfig::new("staging", server.uri(), SecretValue::new(CANARY_API_KEY));
    cfg.ssrf_policy = loopback_ssrf_policy();
    cfg.request_timeout = Duration::from_millis(120);
    cfg.rate_limit = RateLimitConfig {
        local_read_per_sec: 100,
        local_write_per_sec: 100,
        max_wait_ms: 2_000,
        max_429_retries: 2,
    };
    let fast_timeout_api = N8nApiClient::new(cfg).expect("client");

    let payload = json!({ "name": "Slow Draft", "nodes": [], "connections": {} });
    let outcome = fast_timeout_api
        .create_workflow("op_draft_create_99", &payload)
        .await
        .expect("timeout mapped to Outcome::UnknownNeedsReconcile");

    let captured_idem_key = match outcome {
        Outcome::UnknownNeedsReconcile {
            operation_id,
            idempotency_key: Some(key),
            ..
        } => {
            assert_eq!(operation_id, "op_draft_create_99");
            key
        }
        other => panic!("expected UnknownNeedsReconcile, got {other:?}"),
    };

    assert_eq!(
        fast_timeout_api
            .idempotency_store()
            .pending_uncertain_operations()
            .len(),
        1
    );

    // Same operation_id + identical canonical JSON produces the exact same Idempotency-Key!
    let reused_key = fast_timeout_api
        .idempotency_store()
        .resolve_key(
            &http::Method::POST,
            "/api/v1/workflows",
            "op_draft_create_99",
            Some(&json!({ "connections": {}, "nodes": [], "name": "Slow Draft" })),
        )
        .expect("resolve")
        .expect("some key");
    assert_eq!(reused_key, captured_idem_key);

    // Modified payload on same operation_id is refused!
    let mismatch = fast_timeout_api.idempotency_store().resolve_key(
        &http::Method::POST,
        "/api/v1/workflows",
        "op_draft_create_99",
        Some(&json!({ "name": "DIFFERENT_NAME", "nodes": [], "connections": {} })),
    );
    assert!(matches!(mismatch, Err(N8nError::Validation422 { .. })));
}
