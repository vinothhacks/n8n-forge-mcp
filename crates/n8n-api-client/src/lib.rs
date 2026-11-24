//! Hardened `n8n` Public API (`/api/v1`) client featuring:
//! - Strict HTTPS + URL normalization (`allow_loopback_http` dev/test opt-in only)
//! - DNS/IP SSRF guard & `redirect::Policy::none()` (zero cross-origin auth header forwarding)
//! - Bounded pre- and post-decompression streaming reader (16 MiB default, zip-bomb safe)
//! - n8n 2.47+ dual-bucket (`Retry-After`, `X-RateLimit-*`) + `governor` rate-limit engine
//! - n8n 2.45+ `IdempotencyStore` (`BLAKE3` canonical payload hash, 12h window) & timeout reconciliation

pub mod client;
pub mod idempotency;
pub mod models;
pub mod rate_limit;
pub mod ssrf;
pub mod streaming;

pub use client::{ApiClientConfig, N8nApiClient, RawRequest};
pub use idempotency::{IdempotencyRecord, IdempotencyStore, Outcome, canonical_json_bytes};
pub use models::*;
pub use rate_limit::{BucketSnapshot, MethodClass, RateLimitConfig, RateLimitEngine};
pub use ssrf::{
    OriginEndpoint, SsrfPolicy, normalize_and_validate_url, validate_ip_address,
    validate_path_segment,
};
pub use streaming::{DEFAULT_MAX_RESPONSE_BYTES, StreamBudget};
