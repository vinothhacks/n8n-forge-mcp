//! n8n 2.45+ `IdempotencyStore` attaching `Idempotency-Key` ONLY on supported `POST` endpoints,
//! hashing canonical request bytes (`BLAKE3`) within a 12-hour window, refusing payload drift,
//! and surfacing `Outcome::UnknownNeedsReconcile` on mutating transport timeouts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use http::Method;
use n8n_types::{N8nError, N8nResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

/// Documented n8n 2.45+ retention window for idempotent `POST` responses (12 hours).
pub const IDEMPOTENCY_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Default `POST` path templates supporting `Idempotency-Key` on n8n 2.45+.
const DEFAULT_SUPPORTED_POST_TEMPLATES: &[&str] = &[
    "/api/v1/workflows",
    "/api/v1/credentials",
    "/api/v1/data-tables",
    "/api/v1/data-tables/{id}/columns",
    "/api/v1/data-tables/{id}/rows",
    "/api/v1/projects",
    "/api/v1/projects/{projectId}/folders",
    "/api/v1/tags",
    "/api/v1/variables",
    "/api/v1/users",
    "/api/v1/workflows/{id}/test-runs",
    "/api/v1/community-packages",
    "/api/v1/promotions",
];

/// Mutating call outcome explicitly separating confirmed responses from uncertain timeout states
/// requiring read-after-write reconciliation before any retry (V2 Section 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome<T> {
    Confirmed {
        value: T,
    },
    UnknownNeedsReconcile {
        operation_id: String,
        idempotency_key: Option<String>,
        path_template: String,
        reason: String,
    },
}

/// Sanitized metadata stored per logical idempotent `POST` operation (never stores raw payload secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub operation_id: String,
    pub idempotency_key: String,
    pub path_template: String,
    pub payload_blake3_hex: String,
    pub created_at: Instant,
    pub uncertain_timeout: bool,
}

/// Thread-safe tracker enforcing n8n 2.45+ `Idempotency-Key` rules.
pub struct IdempotencyStore {
    instance: String,
    ttl: Duration,
    supported_post_templates: Mutex<HashSet<String>>,
    records: Mutex<HashMap<String, IdempotencyRecord>>,
}

impl IdempotencyStore {
    #[must_use]
    pub fn new(instance: impl Into<String>) -> Self {
        Self::with_ttl(instance, IDEMPOTENCY_TTL)
    }

    #[must_use]
    pub fn with_ttl(instance: impl Into<String>, ttl: Duration) -> Self {
        let defaults = DEFAULT_SUPPORTED_POST_TEMPLATES
            .iter()
            .map(|&s| s.to_owned())
            .collect();
        Self {
            instance: instance.into(),
            ttl,
            supported_post_templates: Mutex::new(defaults),
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Registers an additional `POST` path template advertised by `/api/v1/discover` as idempotent.
    pub fn register_supported_post_template(&self, path_template: impl Into<String>) {
        let mut set = self
            .supported_post_templates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set.insert(path_template.into());
    }

    /// Returns `true` ONLY when `method == POST` AND `path_template` is advertised/supported for idempotency.
    #[must_use]
    pub fn supports_endpoint(&self, method: &Method, path_template: &str) -> bool {
        if *method != Method::POST {
            return false;
        }
        let set = self
            .supported_post_templates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set.contains(path_template)
    }

    /// Resolves or mints an `Idempotency-Key` for a supported `POST` request.
    ///
    /// - Returns `Ok(None)` if `method != POST` or `path_template` does not support `Idempotency-Key`.
    /// - Within the 12-hour TTL window, retrying the same `operation_id` with identical canonical
    ///   request bytes returns the **exact same** `Idempotency-Key`.
    /// - Retrying the same `operation_id` with modified request bytes fails closed with `Validation422`!
    pub fn resolve_key(
        &self,
        method: &Method,
        path_template: &str,
        operation_id: &str,
        body: Option<&Value>,
    ) -> N8nResult<Option<String>> {
        if !self.supports_endpoint(method, path_template) {
            return Ok(None);
        }

        let canonical_bytes = canonical_json_bytes(body.unwrap_or(&Value::Null))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(method.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(path_template.as_bytes());
        hasher.update(b"|");
        hasher.update(&canonical_bytes);
        let payload_hash = hasher.finalize().to_hex().to_string();

        let now = Instant::now();
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        records.retain(|_, rec| now.saturating_duration_since(rec.created_at) < self.ttl);

        if let Some(existing) = records.get(operation_id) {
            if existing.path_template != path_template
                || existing.payload_blake3_hex != payload_hash
            {
                return Err(N8nError::validation(
                    &self.instance,
                    vec![format!(
                        "operation_id `{operation_id}` reused with different canonical payload or endpoint"
                    )],
                    "Idempotency-Key reuse refused: request payload bytes differ from original submission",
                ));
            }
            return Ok(Some(existing.idempotency_key.clone()));
        }

        let minted_key = format!("idem_{}", Uuid::now_v7().simple());
        records.insert(
            operation_id.to_owned(),
            IdempotencyRecord {
                operation_id: operation_id.to_owned(),
                idempotency_key: minted_key.clone(),
                path_template: path_template.to_owned(),
                payload_blake3_hex: payload_hash,
                created_at: now,
                uncertain_timeout: false,
            },
        );
        Ok(Some(minted_key))
    }

    /// Marks an operation as having experienced a transport timeout so reconciliation knows it is uncertain.
    pub fn mark_uncertain_timeout(&self, operation_id: &str) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rec) = records.get_mut(operation_id) {
            rec.uncertain_timeout = true;
        }
    }

    /// Lists operation IDs currently flagged as `uncertain_timeout` awaiting read-after-write reconciliation.
    #[must_use]
    pub fn pending_uncertain_operations(&self) -> Vec<IdempotencyRecord> {
        let now = Instant::now();
        let records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        records
            .values()
            .filter(|r| {
                r.uncertain_timeout && now.saturating_duration_since(r.created_at) < self.ttl
            })
            .cloned()
            .collect()
    }
}

/// Produces deterministic canonical UTF-8 JSON bytes with recursively sorted object keys.
pub fn canonical_json_bytes(value: &Value) -> N8nResult<Vec<u8>> {
    let sorted = sort_json_keys_recursive(value);
    serde_json::to_vec(&sorted)
        .map_err(|e| N8nError::protocol(format!("failed serializing canonical JSON: {e}")))
}

fn sort_json_keys_recursive(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys_recursive).collect()),
        Value::Object(map) => {
            let ordered: BTreeMap<&String, Value> = map
                .iter()
                .map(|(k, v)| (k, sort_json_keys_recursive(v)))
                .collect();
            let mut out = Map::with_capacity(ordered.len());
            for (k, v) in ordered {
                out.insert(k.clone(), v);
            }
            Value::Object(out)
        }
    }
}
