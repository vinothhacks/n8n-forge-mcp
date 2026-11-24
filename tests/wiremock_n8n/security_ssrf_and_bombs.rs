//! Security integration tests verifying:
//! - SSRF private/metadata/loopback/cleartext blocking
//! - Cross-origin HTTP redirect blocking (zero auth header forwarding)
//! - 60 MiB compressed gzip response bomb rejection in bounded 16 MiB stream memory

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;
use n8n_api_client::{ApiClientConfig, ListQueryParams, N8nApiClient, SsrfPolicy};
use n8n_types::{N8nError, SecretValue};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{CANARY_API_KEY, build_loopback_api_client};

#[test]
fn ssrf_guard_rejects_metadata_private_rfc1918_and_cleartext_origins() {
    let blocked_urls = [
        "http://staging-n8n.example.internal",
        "https://169.254.169.254/latest/meta-data",
        "https://169.254.170.2/v2/credentials",
        "https://[::ffff:169.254.169.254]",
        "https://[fd00:ec2::254]",
        "https://metadata.google.internal",
        "https://10.0.0.15:5678",
        "https://172.16.10.20:5678",
        "https://192.168.1.50:5678",
        "https://100.100.100.200",
        "https://127.0.0.1:5678",
        "https://localhost:5678",
    ];

    for bad_url in blocked_urls {
        let mut cfg = ApiClientConfig::new("staging", bad_url, SecretValue::new(CANARY_API_KEY));
        cfg.ssrf_policy = SsrfPolicy::default(); // strict production default
        let err = match N8nApiClient::new(cfg) {
            Ok(_) => panic!("URL `{bad_url}` MUST be blocked by SSRF guard"),
            Err(e) => e,
        };
        assert!(
            matches!(err, N8nError::SsrfBlocked { .. }),
            "expected SsrfBlocked for `{bad_url}`, got {err:?}"
        );
    }
}

#[tokio::test]
async fn cross_origin_redirect_is_blocked_and_never_forwards_auth_headers() {
    let primary_n8n = MockServer::start().await;
    let evil_redirect_target = MockServer::start().await;

    // Any request reaching `evil_redirect_target` fails the test immediately (`expect(0)`)!
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&evil_redirect_target)
        .await;

    let redirect_location = format!("{}/capture-leaked-headers", evil_redirect_target.uri());
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", redirect_location.as_str()),
        )
        .expect(1)
        .mount(&primary_n8n)
        .await;

    let api = build_loopback_api_client(&primary_n8n.uri(), CANARY_API_KEY);
    let err = api
        .list_workflows(&ListQueryParams::default())
        .await
        .expect_err("302 redirect must be blocked");

    assert!(matches!(err, N8nError::SsrfBlocked { .. }));
}

#[tokio::test]
async fn rejects_60_mib_compressed_gzip_zip_bomb_cleanly_within_16_mib_budget() {
    let server = MockServer::start().await;

    // Generate a genuine 60 MiB payload compressed with gzip (~60 KB over the wire!)
    let compressed_bomb = {
        let mut encoder = GzEncoder::new(Vec::with_capacity(128 * 1024), Compression::fast());
        let zero_chunk = vec![b'0'; 1024 * 1024]; // 1 MiB chunk x 60 = 60 MiB
        for _ in 0..60 {
            encoder.write_all(&zero_chunk).expect("gzip write");
        }
        encoder.finish().expect("gzip finish")
    };
    assert!(
        compressed_bomb.len() < 512 * 1024,
        "60 MiB zero payload compresses under 512 KiB (actual={} bytes)",
        compressed_bomb.len()
    );

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header("Content-Encoding", "gzip")
                .set_body_bytes(compressed_bomb),
        )
        .expect(1)
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let err = api
        .list_workflows(&ListQueryParams::default())
        .await
        .expect_err("60 MiB zip bomb must be rejected by 16 MiB decompressed budget");

    match err {
        N8nError::PayloadTooLarge {
            limit_bytes,
            observed_bytes,
            phase,
        } => {
            assert_eq!(limit_bytes, 16 * 1024 * 1024);
            assert!(observed_bytes > limit_bytes);
            assert_eq!(phase, "decompressed");
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_60_mib_zstd_response_bomb_and_oversized_content_length() {
    let server = MockServer::start().await;

    let zero_payload = vec![b'A'; 60 * 1024 * 1024];
    let zstd_bomb = zstd::encode_all(zero_payload.as_slice(), 1).expect("zstd compress 60 MiB");
    assert!(zstd_bomb.len() < 64 * 1024);

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header("Content-Encoding", "zstd")
                .set_body_bytes(zstd_bomb),
        )
        .expect(1)
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let err = api
        .list_workflows(&ListQueryParams::default())
        .await
        .expect_err("60 MiB zstd bomb must be rejected");
    assert!(matches!(
        err,
        N8nError::PayloadTooLarge {
            ref phase,
            ..
        } if phase == "decompressed"
    ));
}
