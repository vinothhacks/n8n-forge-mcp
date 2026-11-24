//! Comprehensive `wiremock` integration, capability-matrix, rate-limit, idempotency,
//! SSRF/zip-bomb security, `rmcp` protocol, zero-secret verification, and `U01`–`U18` acceptance suite.

mod capabilities_matrix;
mod errors_rate_limit_idempotency;
mod helpers;
mod security_ssrf_and_bombs;
mod u01_u18_acceptance;
mod zero_secrets_and_mcp_protocol;
