//! Memory-zeroizing secret wrapper (`SecretValue`) with redacted `Debug`, `Display`, and `Serialize`.

use std::fmt;

use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// Protected secret string backed by [`secrecy::SecretString`] (`Zeroize` on drop).
///
/// `Debug`, `Display`, and `Serialize` ALWAYS emit `"[REDACTED]"`, ensuring that accidental
/// logging, tracing, or struct serialization can never leak raw credentials.
#[derive(Clone)]
pub struct SecretValue {
    inner: SecretString,
}

impl SecretValue {
    /// Wraps a raw secret string in zeroizing memory.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self {
            inner: SecretString::from(raw.into()),
        }
    }

    /// Returns `true` if the underlying secret is empty or whitespace-only.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().trim().is_empty()
    }

    /// Explicitly exposes the raw secret strictly for outbound auth header construction.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Constant-purpose comparison of whether two non-empty secrets hold identical bytes
    /// (used e.g. to forbid reusing `X-N8N-API-KEY` as `N8N_MCP_ACCESS_TOKEN`).
    #[must_use]
    pub fn matches_secret(&self, other: &Self) -> bool {
        let a = blake3::hash(self.inner.expose_secret().as_bytes());
        let b = blake3::hash(other.inner.expose_secret().as_bytes());
        a == b && !self.is_empty()
    }

    /// Domain-separated `BLAKE3` digest of the secret (one-way, non-reversible, for principal ID derivation).
    #[must_use]
    pub fn domain_hash_hex(&self, domain_context: &str) -> String {
        let mut hasher = blake3::Hasher::new_derive_key(domain_context);
        hasher.update(self.inner.expose_secret().as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

impl Zeroize for SecretValue {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(\"[REDACTED]\")")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

impl JsonSchema for SecretValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("SecretValue")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }
}
