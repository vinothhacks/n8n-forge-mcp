//! Deterministic observed factual findings (`observed_facts`) for V2 Section 10 workflow audits.
//!
//! Every finding in this module represents an objectively verifiable fact observed directly in the
//! workflow IR, topology graph, or authoritative node catalog — never probabilistic speculation.

use std::collections::HashSet;
use std::sync::LazyLock;

use n8n_catalog_db::{CatalogDb, NodeInfoMode, NodeInfoRequest, SchemaConfidence};
use n8n_graph::{CycleKind, WorkflowGraph, WorkflowIr, WorkflowNodeIr};
use n8n_types::redact_str;
use n8n_validator::{analyze_js_code_script, analyze_plain_or_template_expression};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

static PROCESS_ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:process\.env|Deno\.env|os\.environ)\b")
        .expect("valid static process.env regex")
});

/// Severity classification shared across factual and heuristic audit findings.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

/// Deterministic factual security or reliability observation in a workflow (`observed_facts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditFact {
    pub code: String,
    #[serde(default)]
    pub severity: AuditSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Backward-compatible alias preserved for Phase 1 consumers.
pub type ObservedFact = AuditFact;

/// Scans `ir` for deterministic observed security & reliability facts (zero network calls).
#[must_use]
pub fn collect_observed_facts(
    ir: &WorkflowIr,
    catalog: Option<&CatalogDb>,
    known_credential_ids: Option<&HashSet<String>>,
) -> Vec<AuditFact> {
    let mut facts = Vec::new();
    let wf_id = ir.id.clone();

    // 1. Topology-level invalid / unbounded failure loop cycles.
    let topology = WorkflowGraph::from_ir(ir).analyze();
    for cycle in &topology.cycles {
        if cycle.kind == CycleKind::UnboundedOrInvalidCycle {
            let path = cycle.nodes.join(" -> ");
            facts.push(AuditFact {
                code: "unbounded_or_invalid_cycle".to_owned(),
                severity: AuditSeverity::High,
                workflow_id: wf_id.clone(),
                node_id: None,
                node_name: cycle.nodes.first().cloned(),
                field_path: Some("/connections".to_owned()),
                description: redact_str(&format!(
                    "Unbounded or uncontrolled cycle detected ({path}): {}",
                    cycle.reason
                )),
                remediation: Some(
                    "Insert a `Loop Over Items` (`splitInBatches`) or bounded `IF`/`Switch` + `Wait` termination guard."
                        .to_owned(),
                ),
            });
        }
    }

    // 2. Per-node factual checks.
    for node in &ir.nodes {
        if node.disabled {
            continue;
        }

        check_public_trigger_without_auth(node, wf_id.as_deref(), &mut facts);
        check_high_risk_node_type(node, wf_id.as_deref(), &mut facts);
        check_external_io_resilience(node, wf_id.as_deref(), &mut facts);
        check_env_access(node, wf_id.as_deref(), &mut facts);
        check_credential_bindings_and_staleness(
            node,
            wf_id.as_deref(),
            catalog,
            known_credential_ids,
            &mut facts,
        );
    }

    facts
}

fn check_public_trigger_without_auth(
    node: &WorkflowNodeIr,
    workflow_id: Option<&str>,
    facts: &mut Vec<AuditFact>,
) {
    let has_bound_creds = node
        .credentials
        .as_ref()
        .is_some_and(|creds| !creds.is_empty());

    match node.node_type.as_str() {
        "n8n-nodes-base.webhook" => {
            let auth = node
                .parameters
                .get("authentication")
                .and_then(Value::as_str)
                .unwrap_or("none");
            if auth.eq_ignore_ascii_case("none") && !has_bound_creds {
                facts.push(AuditFact {
                    code: "public_webhook_without_auth".to_owned(),
                    severity: AuditSeverity::High,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/parameters/authentication".to_owned()),
                    description: format!(
                        "Public `Webhook` trigger `{}` has `authentication = \"none\"` and no bound authentication credentials.",
                        node.name
                    ),
                    remediation: Some(
                        "Configure headerAuth, basicAuth, jwtAuth, or HMAC signature verification before exposing webhook endpoints."
                            .to_owned(),
                    ),
                });
            }
        }
        "n8n-nodes-base.formTrigger" => {
            let auth = node
                .parameters
                .get("authentication")
                .and_then(Value::as_str)
                .unwrap_or("none");
            if auth.eq_ignore_ascii_case("none") && !has_bound_creds {
                facts.push(AuditFact {
                    code: "public_form_trigger_without_auth".to_owned(),
                    severity: AuditSeverity::Medium,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/parameters/authentication".to_owned()),
                    description: format!(
                        "Public `Form Trigger` `{}` has no authentication configured.",
                        node.name
                    ),
                    remediation: Some(
                        "Enable basicAuth on internal forms or enforce strict input validation and rate limiting."
                            .to_owned(),
                    ),
                });
            }
        }
        "@n8n/n8n-nodes-langchain.chatTrigger" => {
            let is_public = node
                .parameters
                .get("public")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let auth = node
                .parameters
                .get("authentication")
                .and_then(Value::as_str)
                .unwrap_or("none");
            if is_public && auth.eq_ignore_ascii_case("none") && !has_bound_creds {
                facts.push(AuditFact {
                    code: "public_chat_trigger_without_auth".to_owned(),
                    severity: AuditSeverity::High,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/parameters/authentication".to_owned()),
                    description: format!(
                        "Public `Chat Trigger` `{}` is publicly exposed (`public = true`) without authentication.",
                        node.name
                    ),
                    remediation: Some(
                        "Configure n8n user or basic authentication on public AI chat triggers to prevent unauthenticated LLM spend/abuse."
                            .to_owned(),
                    ),
                });
            }
        }
        _ => {}
    }
}

fn check_high_risk_node_type(
    node: &WorkflowNodeIr,
    workflow_id: Option<&str>,
    facts: &mut Vec<AuditFact>,
) {
    let classification = match node.node_type.as_str() {
        "n8n-nodes-base.executeCommand" => Some((
            "high_risk_node_type:executeCommand",
            AuditSeverity::Critical,
            "Executes arbitrary OS shell commands on the n8n host/worker container.",
            "Replace shell commands with native n8n nodes or an isolated external microservice.",
        )),
        "n8n-nodes-base.ssh" => Some((
            "high_risk_node_type:ssh",
            AuditSeverity::High,
            "Executes remote shell commands or file transfers over SSH.",
            "Restrict SSH credentials to least-privilege command forced-keys and audit host allowlists.",
        )),
        "n8n-nodes-base.readWriteFile"
        | "n8n-nodes-base.writeBinaryFile"
        | "n8n-nodes-base.readBinaryFiles"
        | "n8n-nodes-base.localFileTrigger" => Some((
            "high_risk_node_type:host_filesystem",
            AuditSeverity::High,
            "Reads or writes directly on the n8n host/container local filesystem.",
            "Prefer object storage nodes (S3/GCS/MinIO) and restrict `N8N_RESTRICT_FILE_ACCESS_TO`.",
        )),
        "n8n-nodes-base.ftp" => Some((
            "high_risk_node_type:ftp",
            AuditSeverity::Medium,
            "Transfers files via FTP/SFTP external protocol.",
            "Ensure SFTP (`sftp`) protocol is enforced rather than cleartext FTP.",
        )),
        "n8n-nodes-base.code" | "@n8n/n8n-nodes-langchain.toolCode" => Some((
            "high_risk_node_type:code",
            AuditSeverity::Medium,
            "Executes custom JavaScript/Python code inside the task runner.",
            "Prefer native n8n data nodes where possible and document `Why Code:` rationale.",
        )),
        _ => None,
    };

    if let Some((code, severity, summary, remediation)) = classification {
        facts.push(AuditFact {
            code: code.to_owned(),
            severity,
            workflow_id: workflow_id.map(ToOwned::to_owned),
            node_id: Some(node.id.clone()),
            node_name: Some(node.name.clone()),
            field_path: Some("/type".to_owned()),
            description: format!("Node `{}` (`{}`): {summary}", node.name, node.node_type),
            remediation: Some(remediation.to_owned()),
        });
    }
}

/// Returns `true` if a node type performs external network, database, or SaaS I/O that benefits
/// from explicit `retryOnFail` or `onError` configuration.
#[must_use]
pub fn is_external_io_node_type(node_type: &str) -> bool {
    if node_type.ends_with("Trigger")
        || node_type == "n8n-nodes-base.webhook"
        || node_type == "n8n-nodes-base.respondToWebhook"
    {
        return false;
    }

    matches!(
        node_type,
        "n8n-nodes-base.httpRequest"
            | "n8n-nodes-base.graphql"
            | "n8n-nodes-base.postgres"
            | "n8n-nodes-base.mySql"
            | "n8n-nodes-base.microsoftSql"
            | "n8n-nodes-base.mongoDb"
            | "n8n-nodes-base.redis"
            | "n8n-nodes-base.questDb"
            | "n8n-nodes-base.snowflake"
            | "n8n-nodes-base.googleBigQuery"
            | "n8n-nodes-base.awsS3"
            | "n8n-nodes-base.slack"
            | "n8n-nodes-base.github"
            | "n8n-nodes-base.gitlab"
            | "n8n-nodes-base.stripe"
            | "n8n-nodes-base.emailSend"
            | "n8n-nodes-base.sendEmail"
            | "n8n-nodes-base.amqp"
            | "n8n-nodes-base.kafka"
            | "n8n-nodes-base.rabbitMq"
            | "n8n-nodes-base.ftp"
            | "n8n-nodes-base.ssh"
            | "n8n-nodes-base.supabase"
            | "n8n-nodes-base.airtable"
            | "n8n-nodes-base.googleSheets"
    ) || node_type.starts_with("@n8n/n8n-nodes-langchain.lmChat")
}

fn check_external_io_resilience(
    node: &WorkflowNodeIr,
    workflow_id: Option<&str>,
    facts: &mut Vec<AuditFact>,
) {
    if !is_external_io_node_type(&node.node_type) {
        return;
    }

    let has_retry = node.retry_on_fail.unwrap_or(false);
    let has_error_policy = node.has_local_error_handling();
    if !has_retry && !has_error_policy {
        facts.push(AuditFact {
            code: "missing_retry_or_error_policy".to_owned(),
            severity: AuditSeverity::Low,
            workflow_id: workflow_id.map(ToOwned::to_owned),
            node_id: Some(node.id.clone()),
            node_name: Some(node.name.clone()),
            field_path: Some("/retryOnFail".to_owned()),
            description: format!(
                "External I/O node `{}` (`{}`) configures neither `retryOnFail` nor `onError`.",
                node.name, node.node_type
            ),
            remediation: Some(
                "Enable `retryOnFail: true` (for idempotent calls) or configure `onError: \"continueErrorOutput\"`."
                    .to_owned(),
            ),
        });
    }
}

fn check_env_access(node: &WorkflowNodeIr, workflow_id: Option<&str>, facts: &mut Vec<AuditFact>) {
    // Check Code node JS/Python bodies first.
    if node.node_type == "n8n-nodes-base.code"
        || node.node_type == "@n8n/n8n-nodes-langchain.toolCode"
    {
        for code_field in ["jsCode", "pythonCode", "code"] {
            if let Some(script) = node.parameters.get(code_field).and_then(Value::as_str) {
                let js_uses_env = if code_field != "pythonCode" {
                    analyze_js_code_script(script)
                        .builtin_vars
                        .iter()
                        .any(|v| v == "$env")
                } else {
                    false
                };
                if js_uses_env || script.contains("$env") || PROCESS_ENV_RE.is_match(script) {
                    facts.push(AuditFact {
                        code: "code_node_env_access".to_owned(),
                        severity: AuditSeverity::High,
                        workflow_id: workflow_id.map(ToOwned::to_owned),
                        node_id: Some(node.id.clone()),
                        node_name: Some(node.name.clone()),
                        field_path: Some(format!("/parameters/{code_field}")),
                        description: format!(
                            "Code node `{}` accesses host/worker environment variables (`$env` / `process.env`).",
                            node.name
                        ),
                        remediation: Some(
                            "Bind scoped n8n credentials or `$vars` instead of reading host `$env`, and keep `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`."
                                .to_owned(),
                        ),
                    });
                }
            }
        }
    }

    // Recursively check expressions across all node parameters.
    scan_parameter_env_access(&node.parameters, "/parameters", node, workflow_id, facts);
}

fn scan_parameter_env_access(
    value: &Value,
    pointer: &str,
    node: &WorkflowNodeIr,
    workflow_id: Option<&str>,
    facts: &mut Vec<AuditFact>,
) {
    match value {
        Value::String(s) => {
            if pointer.ends_with("/jsCode")
                || pointer.ends_with("/pythonCode")
                || pointer.ends_with("/code")
            {
                return;
            }
            if s.starts_with('=') && s.contains("{{") {
                let analysis = analyze_plain_or_template_expression(s);
                if analysis.builtin_vars.iter().any(|v| v == "$env") || PROCESS_ENV_RE.is_match(s) {
                    facts.push(AuditFact {
                        code: "expression_env_access".to_owned(),
                        severity: AuditSeverity::High,
                        workflow_id: workflow_id.map(ToOwned::to_owned),
                        node_id: Some(node.id.clone()),
                        node_name: Some(node.name.clone()),
                        field_path: Some(pointer.to_owned()),
                        description: format!(
                            "Parameter `{pointer}` on node `{}` reads `$env` at runtime.",
                            node.name
                        ),
                        remediation: Some(
                            "Replace `$env` expressions with bound n8n credentials or non-secret `$vars`."
                                .to_owned(),
                        ),
                    });
                }
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let escaped = k.replace('~', "~0").replace('/', "~1");
                scan_parameter_env_access(
                    child,
                    &format!("{pointer}/{escaped}"),
                    node,
                    workflow_id,
                    facts,
                );
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                scan_parameter_env_access(
                    child,
                    &format!("{pointer}/{idx}"),
                    node,
                    workflow_id,
                    facts,
                );
            }
        }
        _ => {}
    }
}

fn check_credential_bindings_and_staleness(
    node: &WorkflowNodeIr,
    workflow_id: Option<&str>,
    catalog: Option<&CatalogDb>,
    known_credential_ids: Option<&HashSet<String>>,
    facts: &mut Vec<AuditFact>,
) {
    // Check explicit credential reference bindings for empty or unknown IDs.
    if let Some(creds) = &node.credentials {
        for (cred_type, cred_ref) in creds {
            let raw_id = cred_ref.id.as_deref().unwrap_or("").trim();
            if raw_id.is_empty() {
                facts.push(AuditFact {
                    code: format!("unbound_credential_reference:{cred_type}"),
                    severity: AuditSeverity::Medium,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some(format!("/credentials/{cred_type}/id")),
                    description: format!(
                        "Node `{}` binds credential slot `{cred_type}` with an empty credential `id`.",
                        node.name
                    ),
                    remediation: Some(
                        "Bind a concrete non-secret credential reference `id` in n8n.".to_owned(),
                    ),
                });
            } else if let Some(known_ids) = known_credential_ids
                && !known_ids.contains(raw_id)
            {
                facts.push(AuditFact {
                    code: format!("stale_or_missing_credential_reference:{cred_type}"),
                    severity: AuditSeverity::Medium,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some(format!("/credentials/{cred_type}/id")),
                    description: format!(
                        "Node `{}` references credential id `{}` (`{cred_type}`) which was not found in the visible credential inventory.",
                        node.name,
                        redact_str(raw_id)
                    ),
                    remediation: Some(
                        "Verify whether the credential was deleted/rotated or resides in a project inaccessible to this principal."
                            .to_owned(),
                    ),
                });
            }
        }
    }

    let Some(db) = catalog else {
        return;
    };

    let node_ver_str = node.type_version_string();

    // Check stale `typeVersion` vs catalog latest version.
    if let Ok(ver_info) = db.get_node_info(&NodeInfoRequest {
        node_type: node.node_type.clone(),
        mode: NodeInfoMode::Versions,
        type_version: Some(node_ver_str.clone()),
        property_query: None,
    }) && ver_info.found_in_catalog
    {
        let latest_f64 = ver_info
            .versions
            .iter()
            .filter_map(|v| v.type_version.parse::<f64>().ok())
            .fold(None::<f64>, |acc, x| Some(acc.map_or(x, |a| a.max(x))));

        if let (Some(curr_v), Some(latest_v)) = (node.type_version_f64(), latest_f64)
            && curr_v + 1e-9 < latest_v
        {
            facts.push(AuditFact {
                code: "stale_node_type_version".to_owned(),
                severity: AuditSeverity::Info,
                workflow_id: workflow_id.map(ToOwned::to_owned),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/typeVersion".to_owned()),
                description: format!(
                    "Node `{}` (`{}`) uses `typeVersion = {node_ver_str}` behind catalog latest `{latest_v}`.",
                    node.name, node.node_type
                ),
                remediation: Some(
                    "Review breaking changes and upgrade node `typeVersion` during maintenance."
                        .to_owned(),
                ),
            });
        }
    }

    // Check catalog-required credentials missing on the node.
    if let Ok(inspection) =
        db.inspect_effective_node_fields(&node.node_type, Some(&node_ver_str), &node.parameters)
        && inspection.schema_confidence == SchemaConfidence::AuthoritativeCatalog
    {
        let required_creds: Vec<&str> = inspection
            .allowed_credentials
            .iter()
            .filter(|c| c.required)
            .map(|c| c.credential_type.as_str())
            .collect();

        if !required_creds.is_empty() {
            let bound_any = node.credentials.as_ref().is_some_and(|creds| {
                required_creds.iter().any(|req| {
                    creds
                        .get(*req)
                        .and_then(|cred_ref| cred_ref.id.as_deref())
                        .is_some_and(|id| !id.trim().is_empty())
                })
            });
            if !bound_any {
                let expected = required_creds.join(" | ");
                facts.push(AuditFact {
                    code: "missing_required_credential_binding".to_owned(),
                    severity: AuditSeverity::Medium,
                    workflow_id: workflow_id.map(ToOwned::to_owned),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/credentials".to_owned()),
                    description: format!(
                        "Node `{}` (`{}`) requires credential binding (`{expected}`), but none is attached.",
                        node.name, node.node_type
                    ),
                    remediation: Some(format!(
                        "Attach an approved `{expected}` credential reference to node `{}`.",
                        node.name
                    )),
                });
            }
        }
    }
}
