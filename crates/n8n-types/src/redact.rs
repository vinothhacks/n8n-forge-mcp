//! Recursive JSON & string secret redactor scrubbing JWTs, Bearer/Basic auth, `X-N8N-API-KEY`,
//! URL query secrets, database/broker DSNs, API key prefixes, and sensitive JSON object keys.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

const MAX_REDACT_DEPTH: usize = 64;

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
        .expect("valid static JWT regex")
});

static BEARER_OR_BASIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}")
        .expect("valid static Bearer/Basic regex")
});

static HEADER_API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(x-n8n-api-key|cf-access-client-secret|x-api-key|authorization)\s*([:=])\s*([^\s"',;\r\n]+)"#,
    )
    .expect("valid static header secret regex")
});

static DSN_CREDENTIALS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver|clickhouse|http(?:s)?)://[^:/@\s]+:)([^@\s]+)(@)",
    )
    .expect("valid static DSN regex")
});

static CONN_STRING_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(password|pwd|secret|api_?key|access_?token|client_?secret)\s*=\s*([^;&\s"'\r\n]+)"#,
    )
    .expect("valid static kv secret regex")
});

static QUERY_PARAM_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"([?&](?i:api_?key|access_?token|refresh_?token|token|secret|password|auth|sig|signature|x-n8n-api-key)=)([^&#\s"'\r\n]+)"#,
    )
    .expect("valid static query secret regex")
});

static KNOWN_TOKEN_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:n8n_api_[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b",
    )
    .expect("valid static token prefix regex")
});

/// Returns `true` if a JSON field key represents sensitive secret/credential material.
///
/// Note: Safe reference identifiers such as `credentialType`, `credentialId`, `credentials` (object map
/// of `{ id, name }` references in n8n nodes—handled recursively), `versionId`, `pageToken`, and
/// `maxTokens` are intentionally NOT treated as raw secrets so non-secret metadata stays intact.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();

    if matches!(
        normalized.as_str(),
        "pagetoken"
            | "nextpagetoken"
            | "maxtokens"
            | "maxtokensout"
            | "totaltokens"
            | "prompttokens"
            | "completiontokens"
            | "tokenbudget"
            | "tokencount"
            | "credentialid"
            | "credentialtype"
            | "credentialtypename"
            | "secretscount"
            | "secretsredacted"
            | "nosecretoutput"
    ) {
        return false;
    }

    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "clientsecret"
            | "webhooksecret"
            | "signingsecret"
            | "sharedsecret"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authtoken"
            | "bearertoken"
            | "mcptoken"
            | "mcpaccesstoken"
            | "n8nmcpaccesstoken"
            | "apikey"
            | "xapikey"
            | "n8napikey"
            | "xn8napikey"
            | "privatekey"
            | "secretkey"
            | "encryptionkey"
            | "hmackey"
            | "passphrase"
            | "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "cfaccessclientsecret"
            | "connectionstring"
            | "dsn"
    ) || normalized.ends_with("password")
        || normalized.ends_with("secret")
        || normalized.ends_with("apikey")
        || normalized.ends_with("privatekey")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("bearertoken")
}

/// Scrubs inline secrets (JWTs, Bearer/Basic headers, `X-N8N-API-KEY`, DSN passwords, query tokens,
/// and known API key prefixes) from any arbitrary string.
#[must_use]
pub fn redact_str(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let step1 = JWT_RE.replace_all(input, "[REDACTED:JWT]");
    let step2 = HEADER_API_KEY_RE.replace_all(&step1, "$1$2 [REDACTED:HEADER_SECRET]");
    let step3 = BEARER_OR_BASIC_RE.replace_all(&step2, "$1 [REDACTED:TOKEN]");
    let step4 = DSN_CREDENTIALS_RE.replace_all(&step3, "${1}[REDACTED:DSN_SECRET]${3}");
    let step5 = QUERY_PARAM_SECRET_RE.replace_all(&step4, "${1}[REDACTED:URL_SECRET]");
    let step6 = CONN_STRING_KV_RE.replace_all(&step5, "$1=[REDACTED:SECRET]");
    let step7 = KNOWN_TOKEN_PREFIX_RE.replace_all(&step6, "[REDACTED:TOKEN]");

    step7.into_owned()
}

/// Recursively scrubs sensitive keys and inline secret patterns across a JSON value tree.
#[must_use]
pub fn redact_json_value(value: &Value) -> Value {
    redact_json_depth(value, 0)
}

fn redact_json_depth(value: &Value, depth: usize) -> Value {
    if depth >= MAX_REDACT_DEPTH {
        return Value::String("[REDACTED:MAX_DEPTH]".to_owned());
    }

    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(s) => Value::String(redact_str(s)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_json_depth(item, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut sanitized = Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive_key(k) {
                    let replacement = match v {
                        Value::Null => Value::Null,
                        Value::Bool(b) => Value::Bool(*b),
                        _ => Value::String("[REDACTED]".to_owned()),
                    };
                    sanitized.insert(k.clone(), replacement);
                } else {
                    sanitized.insert(k.clone(), redact_json_depth(v, depth + 1));
                }
            }
            Value::Object(sanitized)
        }
    }
}
