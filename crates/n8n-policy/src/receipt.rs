//! Cryptographic one-use `ApprovalReceipt` (`BLAKE3` preimage digest + `HMAC-SHA256` signature)
//! bound to `(principal, instance, workflow_id, expected_version_hash, ops_hash, expires_at)`.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use n8n_types::{N8nError, N8nResult, RiskLevel};
use rand::RngExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const RECEIPT_TOKEN_PREFIX: &str = "n8n_rcpt_v1.";
/// Maximum lifetime allowed for any approval receipt (15 minutes).
pub const MAX_RECEIPT_TTL_SECS: i64 = 15 * 60;

/// Exact claims bound inside a cryptographic one-use `ApprovalReceipt` (V2 Section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalClaims {
    pub receipt_id: String,
    pub principal: String,
    pub instance: String,
    pub action: String,
    pub risk: RiskLevel,
    pub workflow_id: Option<String>,
    pub expected_version_hash: Option<String>,
    pub ops_hash: String,
    pub expires_at: DateTime<Utc>,
}

/// Wire envelope of a signed `ApprovalReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalReceipt {
    pub claims: ApprovalClaims,
    pub blake3_digest_hex: String,
    pub hmac_sha256_b64: String,
}

/// Expected context verified at commit time (TOCTOU guard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalExpectation {
    pub principal: String,
    pub instance: String,
    pub action: String,
    pub risk: RiskLevel,
    pub workflow_id: Option<String>,
    pub expected_version_hash: Option<String>,
    pub ops_hash: String,
}

/// Computes a deterministic `BLAKE3` hash over canonicalized operation parameters/mutations.
pub fn hash_ops(ops: &Value) -> N8nResult<String> {
    let serialized = serde_json::to_vec(ops)
        .map_err(|e| N8nError::protocol(format!("failed hashing operations: {e}")))?;
    let mut hasher = blake3::Hasher::new_derive_key("n8n-rs-mcp/v2/approval-ops-hash");
    hasher.update(&serialized);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Per-process cryptographic signer and single-use replay tracker for `ApprovalReceipt`s.
pub struct ReceiptSigner {
    hmac_key: Zeroizing<[u8; 32]>,
    consumed: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl ReceiptSigner {
    /// Initializes a `ReceiptSigner` with a fresh 256-bit CSPRNG HMAC key.
    #[must_use]
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);
        Self::from_key_bytes(key)
    }

    /// Initializes a `ReceiptSigner` from an explicit 32-byte key.
    #[must_use]
    pub fn from_key_bytes(key: [u8; 32]) -> Self {
        Self {
            hmac_key: Zeroizing::new(key),
            consumed: Mutex::new(HashMap::new()),
        }
    }

    /// Derives a 32-byte HMAC key from an operator secret via domain-separated `BLAKE3`.
    #[must_use]
    pub fn from_secret_seed(seed: &str) -> Self {
        let derived = blake3::derive_key("n8n-rs-mcp/v2/approval-hmac-key", seed.as_bytes());
        Self::from_key_bytes(derived)
    }

    /// Mints a short-lived, single-use `ApprovalReceipt` and its compact `n8n_rcpt_v1.<b64>` token.
    pub fn mint(
        &self,
        expectation: &ApprovalExpectation,
        ttl_secs: i64,
    ) -> N8nResult<(ApprovalReceipt, String)> {
        let clamped_ttl = ttl_secs.clamp(1, MAX_RECEIPT_TTL_SECS);
        let expires_at = Utc::now() + Duration::seconds(clamped_ttl);
        let claims = ApprovalClaims {
            receipt_id: format!("rcpt_{}", Uuid::now_v7().simple()),
            principal: expectation.principal.clone(),
            instance: expectation.instance.clone(),
            action: expectation.action.clone(),
            risk: expectation.risk,
            workflow_id: expectation.workflow_id.clone(),
            expected_version_hash: expectation.expected_version_hash.clone(),
            ops_hash: expectation.ops_hash.clone(),
            expires_at,
        };

        let digest = compute_claims_blake3(&claims);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.hmac_key.as_ref())
            .map_err(|_| N8nError::protocol("HMAC key init error"))?;
        mac.update(digest.as_bytes());
        let tag_bytes = mac.finalize().into_bytes();

        let receipt = ApprovalReceipt {
            claims,
            blake3_digest_hex: digest.to_hex().to_string(),
            hmac_sha256_b64: URL_SAFE_NO_PAD.encode(tag_bytes),
        };

        let json_bytes = serde_json::to_vec(&receipt)
            .map_err(|e| N8nError::protocol(format!("receipt encode error: {e}")))?;
        let compact_token = format!(
            "{RECEIPT_TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json_bytes)
        );
        Ok((receipt, compact_token))
    }

    /// Verifies signature, expiry, exact `(principal, instance, workflow_id, expected_version_hash, ops_hash)`
    /// binding, AND atomically consumes the receipt so any second replay is rejected!
    pub fn verify_and_consume(
        &self,
        token: &str,
        expected: &ApprovalExpectation,
        policy_mode_label: &str,
    ) -> N8nResult<ApprovalClaims> {
        let Some(encoded) = token.trim().strip_prefix(RECEIPT_TOKEN_PREFIX) else {
            return Err(N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "Invalid or missing ApprovalReceipt token (model-fabricated confirmation strings are rejected)",
                Some(
                    "Run preview first and supply a user-approved `n8n_rcpt_v1.*` receipt."
                        .to_owned(),
                ),
            ));
        };

        let decoded_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "Malformed ApprovalReceipt base64 payload",
                None,
            )
        })?;

        let receipt: ApprovalReceipt = serde_json::from_slice(&decoded_bytes).map_err(|_| {
            N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "Malformed ApprovalReceipt JSON structure",
                None,
            )
        })?;

        // 1. Recompute BLAKE3 claims preimage digest
        let recomputed_digest = compute_claims_blake3(&receipt.claims);
        if recomputed_digest.to_hex().as_str() != receipt.blake3_digest_hex {
            return Err(N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "ApprovalReceipt BLAKE3 claims digest mismatch (tampered payload)",
                None,
            ));
        }

        // 2. Constant-time HMAC-SHA256 tag verification
        let supplied_tag = URL_SAFE_NO_PAD
            .decode(&receipt.hmac_sha256_b64)
            .map_err(|_| {
                N8nError::policy_blocked(
                    &expected.action,
                    expected.risk,
                    policy_mode_label,
                    "Malformed ApprovalReceipt HMAC tag",
                    None,
                )
            })?;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.hmac_key.as_ref())
            .map_err(|_| N8nError::protocol("HMAC key init error"))?;
        mac.update(recomputed_digest.as_bytes());
        mac.verify_slice(&supplied_tag).map_err(|_| {
            N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "ApprovalReceipt cryptographic HMAC-SHA256 verification failed",
                None,
            )
        })?;

        // 3. Expiry check
        let now = Utc::now();
        if now > receipt.claims.expires_at {
            return Err(N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "ApprovalReceipt has expired; generate a fresh preview and confirmation",
                None,
            ));
        }

        // 4. Exact TOCTOU binding checks across all bound dimensions
        let c = &receipt.claims;
        if c.principal != expected.principal
            || c.instance != expected.instance
            || c.action != expected.action
            || c.risk < expected.risk
            || c.workflow_id != expected.workflow_id
            || c.expected_version_hash != expected.expected_version_hash
            || c.ops_hash != expected.ops_hash
        {
            return Err(N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "ApprovalReceipt binding mismatch: target instance, principal, workflow, version, or operations changed since preview",
                Some(
                    "Re-run preview on the current workflow version and confirm the updated plan."
                        .to_owned(),
                ),
            ));
        }

        // 5. Atomic single-use replay guard
        let mut consumed = self
            .consumed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        consumed.retain(|_, exp| *exp >= now);
        if consumed.contains_key(&c.receipt_id) {
            return Err(N8nError::policy_blocked(
                &expected.action,
                expected.risk,
                policy_mode_label,
                "ApprovalReceipt has already been consumed (strictly single-use)",
                Some(
                    "Generate a new preview and approval receipt for additional operations."
                        .to_owned(),
                ),
            ));
        }
        consumed.insert(c.receipt_id.clone(), c.expires_at);

        Ok(receipt.claims)
    }
}

fn compute_claims_blake3(claims: &ApprovalClaims) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key("n8n-rs-mcp/v2/approval-claims-preimage");
    update_len_prefixed(&mut hasher, claims.receipt_id.as_bytes());
    update_len_prefixed(&mut hasher, claims.principal.as_bytes());
    update_len_prefixed(&mut hasher, claims.instance.as_bytes());
    update_len_prefixed(&mut hasher, claims.action.as_bytes());
    update_len_prefixed(&mut hasher, claims.risk.label().as_bytes());
    update_len_prefixed(
        &mut hasher,
        claims.workflow_id.as_deref().unwrap_or("<none>").as_bytes(),
    );
    update_len_prefixed(
        &mut hasher,
        claims
            .expected_version_hash
            .as_deref()
            .unwrap_or("<none>")
            .as_bytes(),
    );
    update_len_prefixed(&mut hasher, claims.ops_hash.as_bytes());
    hasher.update(&claims.expires_at.timestamp_millis().to_le_bytes());
    hasher.finalize()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = bytes.len() as u64;
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
}
