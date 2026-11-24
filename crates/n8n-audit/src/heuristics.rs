//! Heuristic workflow hardening checks (`heuristics`) for V2 Section 10 security & reliability audits.
//!
//! Security invariant: Secret heuristic findings report ONLY `(node_id, node_name, field_path,
//! secret_kind)` and safe redacted summaries — **never** the matched secret value, substring, or
//! length. Zero active network probing or workflow execution occurs during heuristic scanning.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::LazyLock;

use n8n_graph::{PortKind, WorkflowIr, WorkflowNodeIr};
use n8n_types::{is_sensitive_key, redact_str};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::facts::AuditSeverity;

static ENV_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$env\b").expect("valid static $env regex"));

static JWT_DETECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
        .expect("valid static JWT detection regex")
});

static PEM_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
        .expect("valid static PEM key detection regex")
});

static API_KEY_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:n8n_api_[A-Za-z0-9_-]{8,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,})\b",
    )
    .expect("valid static API key prefix regex")
});

static BEARER_OR_BASIC_LIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
        .expect("valid static Bearer/Basic literal regex")
});

static DSN_WITH_PASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver|clickhouse|http(?:s)?)://[^:/@\s]+:[^@\s{]+@",
    )
    .expect("valid static DSN credential regex")
});

static QUERY_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[?&](?i:api_?key|access_?token|refresh_?token|token|secret|password|auth|sig|signature|x-n8n-api-key)=[^&#\s{]{4,}",
    )
    .expect("valid static query secret regex")
});

static CONN_KV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:password|pwd|secret|api_?key|access_?token|client_?secret)\s*=\s*[^;&\s$\{]{4,}",
    )
    .expect("valid static connection kv secret regex")
});

/// Classification of a suspected inline secret kind (without ever exposing the secret material).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Jwt,
    PemPrivateKey,
    ApiKeyPrefix,
    BearerOrBasicAuth,
    DatabaseOrBrokerDsn,
    UrlQuerySecret,
    ConnectionStringSecret,
    SensitiveParameterLiteral,
}

impl SecretKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::PemPrivateKey => "pem_private_key",
            Self::ApiKeyPrefix => "api_key_prefix",
            Self::BearerOrBasicAuth => "bearer_or_basic_auth",
            Self::DatabaseOrBrokerDsn => "database_or_broker_dsn",
            Self::UrlQuerySecret => "url_query_secret",
            Self::ConnectionStringSecret => "connection_string_secret",
            Self::SensitiveParameterLiteral => "sensitive_parameter_literal",
        }
    }
}

/// Heuristic hardening or security finding (`heuristics`) separated strictly from `observed_facts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditHeuristic {
    pub code: String,
    #[serde(default)]
    pub severity: AuditSeverity,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_kind: Option<SecretKind>,
    pub summary: String,
}

/// Backward-compatible alias preserved for Phase 1 consumers.
pub type HeuristicFinding = AuditHeuristic;

#[must_use]
pub fn references_process_env(text: &str) -> bool {
    ENV_REF_RE.is_match(text)
}

#[must_use]
pub fn is_cleartext_http_url(candidate: &str) -> bool {
    let trimmed = candidate.trim().trim_start_matches('=');
    Url::parse(trimmed).is_ok_and(|u| u.scheme() == "http")
}

/// Collects heuristic security & reliability findings across `ir` (pure static analysis, zero network I/O).
#[must_use]
pub fn collect_heuristics(ir: &WorkflowIr) -> Vec<AuditHeuristic> {
    let mut findings = Vec::new();
    let wf_id = ir.id.clone();

    // 1. Workflow-level missing `errorWorkflow` / `Error Trigger` resilience check.
    check_missing_error_workflow(ir, wf_id.as_deref(), &mut findings);

    // 2. Per-node parameter secret scanning + URL / SSRF / wildcard / egress checks.
    for node in &ir.nodes {
        if node.disabled {
            continue;
        }
        let safe_node_id = redact_str(&node.id);
        let safe_node_name = redact_str(&node.name);

        scan_parameters_for_secrets(
            &node.parameters,
            None,
            "/parameters",
            &safe_node_id,
            &safe_node_name,
            wf_id.as_deref(),
            &mut findings,
        );

        check_node_urls_and_ssrf(
            node,
            &safe_node_id,
            &safe_node_name,
            wf_id.as_deref(),
            &mut findings,
        );
    }

    // 3. Cross-node unvalidated external data egress from public triggers.
    check_unvalidated_external_egress(ir, wf_id.as_deref(), &mut findings);

    findings
}

fn check_missing_error_workflow(
    ir: &WorkflowIr,
    workflow_id: Option<&str>,
    findings: &mut Vec<AuditHeuristic>,
) {
    if ir.nodes.is_empty() {
        return;
    }

    let has_error_trigger_node = ir
        .nodes
        .iter()
        .any(|n| !n.disabled && n.node_type == "n8n-nodes-base.errorTrigger");
    if has_error_trigger_node {
        return;
    }

    let configured_error_wf = ir
        .settings
        .get("errorWorkflow")
        .and_then(|v| match v {
            Value::String(s) => Some(!s.trim().is_empty()),
            Value::Number(_) => Some(true),
            _ => None,
        })
        .unwrap_or(false);

    if !configured_error_wf {
        findings.push(AuditHeuristic {
            code: "missing_error_workflow_setting".to_owned(),
            severity: AuditSeverity::Low,
            confidence: "high".to_owned(),
            workflow_id: workflow_id.map(redact_str),
            node_id: None,
            node_name: None,
            field_path: Some("/settings/errorWorkflow".to_owned()),
            secret_kind: None,
            summary: "Workflow does not configure `settings.errorWorkflow` for centralized failure alerting."
                .to_owned(),
        });
    }
}

fn scan_parameters_for_secrets(
    value: &Value,
    current_key: Option<&str>,
    pointer: &str,
    safe_node_id: &str,
    safe_node_name: &str,
    workflow_id: Option<&str>,
    findings: &mut Vec<AuditHeuristic>,
) {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return;
            }
            if let Some((kind, confidence)) = classify_secret_heuristic(trimmed, current_key) {
                let safe_ptr = redact_str(pointer);
                findings.push(AuditHeuristic {
                    code: "potential_hardcoded_secret".to_owned(),
                    severity: AuditSeverity::High,
                    confidence: confidence.to_owned(),
                    workflow_id: workflow_id.map(redact_str),
                    node_id: Some(safe_node_id.to_owned()),
                    node_name: Some(safe_node_name.to_owned()),
                    field_path: Some(safe_ptr.clone()),
                    secret_kind: Some(kind),
                    summary: redact_str(&format!(
                        "Potential hardcoded `{}` detected at `{safe_ptr}` on node `{safe_node_name}` (value redacted; move secret into n8n encrypted credentials).",
                        kind.as_str()
                    )),
                });
            }
        }
        Value::Object(map) => {
            // Special check for header key/value pairs (`{ "name": "Authorization", "value": "..." }`).
            if let (Some(h_name), Some(h_val)) = (
                map.get("name").and_then(Value::as_str),
                map.get("value").and_then(Value::as_str),
            ) && is_sensitive_key(h_name)
                && !is_pure_dynamic_expression(h_val)
                && !h_val.trim().is_empty()
            {
                let val_ptr = redact_str(&format!("{pointer}/value"));
                let kind = classify_secret_heuristic(h_val.trim(), Some(h_name))
                    .map_or(SecretKind::SensitiveParameterLiteral, |(k, _)| k);
                findings.push(AuditHeuristic {
                    code: "potential_hardcoded_secret".to_owned(),
                    severity: AuditSeverity::High,
                    confidence: "high".to_owned(),
                    workflow_id: workflow_id.map(redact_str),
                    node_id: Some(safe_node_id.to_owned()),
                    node_name: Some(safe_node_name.to_owned()),
                    field_path: Some(val_ptr.clone()),
                    secret_kind: Some(kind),
                    summary: redact_str(&format!(
                        "Potential hardcoded `{}` in sensitive header/parameter `{}` at `{val_ptr}` on node `{safe_node_name}` (value redacted).",
                        kind.as_str(),
                        redact_str(h_name)
                    )),
                });
                return;
            }

            for (k, child) in map {
                let escaped = k.replace('~', "~0").replace('/', "~1");
                let child_ptr = format!("{pointer}/{escaped}");
                scan_parameters_for_secrets(
                    child,
                    Some(k.as_str()),
                    &child_ptr,
                    safe_node_id,
                    safe_node_name,
                    workflow_id,
                    findings,
                );
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                let child_ptr = format!("{pointer}/{idx}");
                scan_parameters_for_secrets(
                    child,
                    None,
                    &child_ptr,
                    safe_node_id,
                    safe_node_name,
                    workflow_id,
                    findings,
                );
            }
        }
        _ => {}
    }
}

fn is_pure_dynamic_expression(s: &str) -> bool {
    let trimmed = s.trim();
    if let Some(after_eq) = trimmed.strip_prefix('=') {
        let body = after_eq.trim();
        if body.starts_with("{{") && body.ends_with("}}") && !body[2..body.len() - 2].contains("{{")
        {
            return true;
        }
    }
    false
}

fn classify_secret_heuristic(
    text: &str,
    field_key: Option<&str>,
) -> Option<(SecretKind, &'static str)> {
    if PEM_KEY_RE.is_match(text) {
        return Some((SecretKind::PemPrivateKey, "high"));
    }
    if JWT_DETECT_RE.is_match(text) {
        return Some((SecretKind::Jwt, "high"));
    }
    if API_KEY_PREFIX_RE.is_match(text) {
        return Some((SecretKind::ApiKeyPrefix, "high"));
    }
    if DSN_WITH_PASS_RE.is_match(text) {
        return Some((SecretKind::DatabaseOrBrokerDsn, "high"));
    }
    if BEARER_OR_BASIC_LIT_RE.is_match(text) && !text.contains("{{") {
        return Some((SecretKind::BearerOrBasicAuth, "high"));
    }
    if QUERY_SECRET_RE.is_match(text) {
        return Some((SecretKind::UrlQuerySecret, "medium"));
    }
    if CONN_KV_SECRET_RE.is_match(text) {
        return Some((SecretKind::ConnectionStringSecret, "medium"));
    }

    if let Some(key) = field_key
        && is_sensitive_key(key)
        && !is_pure_dynamic_expression(text)
        && !matches!(
            text.to_ascii_lowercase().as_str(),
            "none"
                | "false"
                | "true"
                | "headerauth"
                | "basicauth"
                | "oautho2"
                | "predefinedcredentialtype"
                | "genericcredentialtype"
        )
        && text.len() >= 6
    {
        return Some((SecretKind::SensitiveParameterLiteral, "medium"));
    }

    None
}

fn check_node_urls_and_ssrf(
    node: &WorkflowNodeIr,
    safe_node_id: &str,
    safe_node_name: &str,
    workflow_id: Option<&str>,
    findings: &mut Vec<AuditHeuristic>,
) {
    // Check wildcard CORS `allowedOrigins: "*"` on triggers.
    if let Some(origins) = node
        .parameters
        .get("options")
        .and_then(|o| o.get("allowedOrigins"))
        .and_then(Value::as_str)
        && origins.trim() == "*"
    {
        findings.push(AuditHeuristic {
            code: "wildcard_cors_allowed_origins".to_owned(),
            severity: AuditSeverity::Low,
            confidence: "high".to_owned(),
            workflow_id: workflow_id.map(redact_str),
            node_id: Some(safe_node_id.to_owned()),
            node_name: Some(safe_node_name.to_owned()),
            field_path: Some("/parameters/options/allowedOrigins".to_owned()),
            secret_kind: None,
            summary: format!(
                "Node `{safe_node_name}` allows wildcard CORS origins (`allowedOrigins = \"*\"`)."
            ),
        });
    }

    if !matches!(
        node.node_type.as_str(),
        "n8n-nodes-base.httpRequest" | "n8n-nodes-base.graphql"
    ) {
        return;
    }

    let url_field = if node.parameters.get("url").is_some() {
        "url"
    } else if node.parameters.get("endpoint").is_some() {
        "endpoint"
    } else {
        return;
    };

    let Some(raw_url) = node.parameters.get(url_field).and_then(Value::as_str) else {
        return;
    };
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return;
    }
    let field_ptr = format!("/parameters/{url_field}");

    // Case 1: Pure or leading dynamic expression where scheme + host are unpinned (`={{ $json.url }}`).
    if let Some(expr_body) = trimmed.strip_prefix('=') {
        let expr_trimmed = expr_body.trim();
        if expr_trimmed.starts_with("{{") {
            findings.push(AuditHeuristic {
                code: "unconstrained_dynamic_ssrf_url".to_owned(),
                severity: AuditSeverity::High,
                confidence: "medium".to_owned(),
                workflow_id: workflow_id.map(redact_str),
                node_id: Some(safe_node_id.to_owned()),
                node_name: Some(safe_node_name.to_owned()),
                field_path: Some(field_ptr),
                secret_kind: None,
                summary: format!(
                    "Node `{safe_node_name}` constructs the entire target URL scheme/host from a dynamic expression, risking SSRF or arbitrary external data egress if fed untrusted input."
                ),
            });
            return;
        }
    }

    let candidate = trimmed.strip_prefix('=').unwrap_or(trimmed).trim();
    // Replace `{{ ... }}` path/query segments with a benign placeholder so host/scheme parsing succeeds.
    let parse_candidate = strip_mustache_for_url_parse(candidate);

    if candidate.contains('*') {
        findings.push(AuditHeuristic {
            code: "wildcard_external_url".to_owned(),
            severity: AuditSeverity::Medium,
            confidence: "medium".to_owned(),
            workflow_id: workflow_id.map(redact_str),
            node_id: Some(safe_node_id.to_owned()),
            node_name: Some(safe_node_name.to_owned()),
            field_path: Some(field_ptr.clone()),
            secret_kind: None,
            summary: format!(
                "Node `{safe_node_name}` contains a wildcard pattern in `{field_ptr}`."
            ),
        });
    }

    if let Ok(parsed) = Url::parse(&parse_candidate) {
        if parsed.scheme() == "http" {
            findings.push(AuditHeuristic {
                code: "cleartext_http_url".to_owned(),
                severity: AuditSeverity::Medium,
                confidence: "high".to_owned(),
                workflow_id: workflow_id.map(redact_str),
                node_id: Some(safe_node_id.to_owned()),
                node_name: Some(safe_node_name.to_owned()),
                field_path: Some(field_ptr.clone()),
                secret_kind: None,
                summary: format!(
                    "Node `{safe_node_name}` uses unencrypted `http://` transport in `{field_ptr}`."
                ),
            });
        }

        if let Some(host_raw) = parsed.host_str() {
            let host_clean = host_raw.trim_matches(['[', ']']).to_ascii_lowercase();
            if is_cloud_metadata_host(&host_clean) {
                findings.push(AuditHeuristic {
                    code: "ssrf_cloud_metadata_url".to_owned(),
                    severity: AuditSeverity::Critical,
                    confidence: "high".to_owned(),
                    workflow_id: workflow_id.map(redact_str),
                    node_id: Some(safe_node_id.to_owned()),
                    node_name: Some(safe_node_name.to_owned()),
                    field_path: Some(field_ptr),
                    secret_kind: None,
                    summary: format!(
                        "Node `{safe_node_name}` targets cloud instance metadata endpoint (`{host_clean}`), a high-risk SSRF credential theft vector."
                    ),
                });
            } else if is_loopback_or_private_or_raw_ip(&host_clean) {
                findings.push(AuditHeuristic {
                    code: "ssrf_private_or_raw_ip_url".to_owned(),
                    severity: AuditSeverity::High,
                    confidence: "high".to_owned(),
                    workflow_id: workflow_id.map(redact_str),
                    node_id: Some(safe_node_id.to_owned()),
                    node_name: Some(safe_node_name.to_owned()),
                    field_path: Some(field_ptr),
                    secret_kind: None,
                    summary: format!(
                        "Node `{safe_node_name}` targets a loopback, RFC1918 private network, or raw IP literal (`{host_clean}`) in `{url_field}`."
                    ),
                });
            }
        }
    }
}

fn strip_mustache_for_url_parse(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'}' && bytes[i + 1] == b'}') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            }
            out.push_str("expr_segment");
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn is_cloud_metadata_host(host: &str) -> bool {
    matches!(
        host,
        "169.254.169.254"
            | "100.100.100.200"
            | "metadata.google.internal"
            | "metadata"
            | "fd00:ec2::254"
            | "169.254.170.2"
    )
}

fn is_loopback_or_private_or_raw_ip(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".local")
    {
        return true;
    }

    // Any raw IPv4 or IPv6 literal (loopback, RFC1918, CGNAT, link-local, or public raw IP)
    // bypasses DNS/SNI hostname allowlisting and warrants review.
    host.parse::<IpAddr>().is_ok()
}

fn check_unvalidated_external_egress(
    ir: &WorkflowIr,
    workflow_id: Option<&str>,
    findings: &mut Vec<AuditHeuristic>,
) {
    let public_triggers: Vec<&WorkflowNodeIr> = ir
        .nodes
        .iter()
        .filter(|n| {
            !n.disabled
                && matches!(
                    n.node_type.as_str(),
                    "n8n-nodes-base.webhook"
                        | "n8n-nodes-base.formTrigger"
                        | "@n8n/n8n-nodes-langchain.chatTrigger"
                )
        })
        .collect();

    if public_triggers.is_empty() {
        return;
    }

    let node_by_name: std::collections::HashMap<&str, &WorkflowNodeIr> =
        ir.nodes.iter().map(|n| (n.name.as_str(), n)).collect();

    for trig in public_triggers {
        // BFS along main edges WITHOUT traversing through validation/filter/branch guard nodes.
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back(trig.name.as_str());
        visited.insert(trig.name.as_str());

        while let Some(curr) = queue.pop_front() {
            let Some(port_map) = ir.connections.get(curr) else {
                continue;
            };
            let Some(branches) = port_map.get(&PortKind::Main) else {
                continue;
            };

            for branch in branches {
                for edge in branch {
                    let next_name = edge.node.as_str();
                    if !visited.insert(next_name) {
                        continue;
                    }
                    let Some(target_node) = node_by_name.get(next_name).copied() else {
                        continue;
                    };
                    if target_node.disabled {
                        continue;
                    }
                    if is_validation_gate_node(&target_node.node_type) {
                        // Guard node validates/filters payload before downstream egress.
                        continue;
                    }
                    if is_external_egress_sink(target_node) {
                        let safe_trig = redact_str(&trig.name);
                        let safe_sink = redact_str(&target_node.name);
                        findings.push(AuditHeuristic {
                            code: "potential_unvalidated_external_egress".to_owned(),
                            severity: AuditSeverity::Medium,
                            confidence: "low".to_owned(),
                            workflow_id: workflow_id.map(redact_str),
                            node_id: Some(redact_str(&target_node.id)),
                            node_name: Some(safe_sink.clone()),
                            field_path: Some("/connections".to_owned()),
                            secret_kind: None,
                            summary: format!(
                                "Public trigger `{safe_trig}` flows directly to external sink `{safe_sink}` (`{}`) without an intermediate `IF`, `Filter`, `Switch`, or signature verification gate.",
                                target_node.node_type
                            ),
                        });
                        continue;
                    }
                    queue.push_back(next_name);
                }
            }
        }
    }
}

fn is_validation_gate_node(node_type: &str) -> bool {
    matches!(
        node_type,
        "n8n-nodes-base.if"
            | "n8n-nodes-base.filter"
            | "n8n-nodes-base.switch"
            | "n8n-nodes-base.crypto"
            | "n8n-nodes-base.jwt"
            | "n8n-nodes-base.Guardrails"
            | "@n8n/n8n-nodes-langchain.guardrails"
    )
}

fn is_external_egress_sink(node: &WorkflowNodeIr) -> bool {
    match node.node_type.as_str() {
        "n8n-nodes-base.httpRequest" => {
            let method = node
                .parameters
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET");
            let send_body = node
                .parameters
                .get("sendBody")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            send_body
                || matches!(
                    method.to_ascii_uppercase().as_str(),
                    "POST" | "PUT" | "PATCH" | "DELETE"
                )
        }
        "n8n-nodes-base.slack"
        | "n8n-nodes-base.emailSend"
        | "n8n-nodes-base.sendEmail"
        | "n8n-nodes-base.awsS3"
        | "n8n-nodes-base.ftp"
        | "n8n-nodes-base.discord"
        | "n8n-nodes-base.telegram"
        | "n8n-nodes-base.googleDrive"
        | "n8n-nodes-base.executeCommand" => true,
        _ => false,
    }
}
