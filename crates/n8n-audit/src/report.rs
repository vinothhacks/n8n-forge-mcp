//! Combined three-tier audit report (`observed_facts`, `heuristics`, `permission_gaps`),
//! batch workflow scanner, and optional `/api/v1/audit` live report merger (V2 Section 10).

use std::collections::{HashMap, HashSet};

use n8n_api_client::N8nApiClient;
use n8n_catalog_db::CatalogDb;
use n8n_graph::WorkflowIr;
use n8n_types::{redact_json_value, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::facts::{AuditFact, AuditSeverity, ObservedFact, collect_observed_facts};
use crate::heuristics::{AuditHeuristic, HeuristicFinding, collect_heuristics};
use crate::permission_gaps::{
    PermissionGap, collect_permission_gaps, permission_gap_from_live_audit_error,
};

/// Three-tier audit report strictly separating deterministic facts, probabilistic heuristics,
/// and permission/schema visibility gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaticAuditReport {
    pub observed_facts: Vec<ObservedFact>,
    pub heuristics: Vec<HeuristicFinding>,
    pub permission_gaps: Vec<PermissionGap>,
}

impl StaticAuditReport {
    /// Returns `true` when neither observed facts nor heuristics were flagged.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.observed_facts.is_empty() && self.heuristics.is_empty()
    }

    /// Merges another `StaticAuditReport` into `self`.
    pub fn extend_from(&mut self, other: Self) {
        self.observed_facts.extend(other.observed_facts);
        self.heuristics.extend(other.heuristics);
        self.permission_gaps.extend(other.permission_gaps);
    }
}

/// Optional offline context supplied to [`audit_workflow`] and [`audit_workflows_batch`].
#[derive(Default)]
pub struct AuditContext<'a> {
    /// Authoritative offline node catalog (`data/catalog.sqlite.zst`) for `typeVersion` and credential checks.
    pub catalog: Option<&'a CatalogDb>,
    /// Subworkflows accessible in the current scope keyed by workflow `id`.
    pub accessible_subworkflows: HashMap<String, WorkflowIr>,
    /// Workflow IDs known to have returned HTTP `403`/`404` when read.
    pub inaccessible_workflow_ids: HashSet<String>,
    /// Optional inventory of visible credential IDs (`None` skips stale-ID inventory comparison).
    pub known_credential_ids: Option<HashSet<String>>,
    /// Whether the connected instance advertises `/api/v1/audit` (`Some(false)` records an honest gap).
    pub live_audit_advertised: Option<bool>,
}

/// Per-workflow entry in a [`BatchAuditReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowAuditEntry {
    pub workflow_id: Option<String>,
    pub workflow_name: String,
    pub report: StaticAuditReport,
}

/// Aggregated multi-workflow static audit report produced by [`audit_workflows_batch`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchAuditReport {
    pub workflows_scanned: usize,
    pub workflows: Vec<WorkflowAuditEntry>,
    pub combined: StaticAuditReport,
}

/// Performs a pure static security and reliability scan of a single workflow IR.
///
/// Guarantees:
/// - **Zero active network probing or workflow execution**
/// - **Strict 3-bucket separation** (`observed_facts`, `heuristics`, `permission_gaps`)
/// - **Zero secret echo** (all findings pass through `n8n_types::redact_str` and never include raw secret substrings)
#[must_use]
pub fn audit_workflow(ir: &WorkflowIr, ctx: &AuditContext<'_>) -> StaticAuditReport {
    let observed_facts = collect_observed_facts(ir, ctx.catalog, ctx.known_credential_ids.as_ref());
    let heuristics = collect_heuristics(ir);
    let permission_gaps = collect_permission_gaps(
        ir,
        ctx.catalog,
        &ctx.accessible_subworkflows,
        &ctx.inaccessible_workflow_ids,
        ctx.live_audit_advertised,
    );

    StaticAuditReport {
        observed_facts,
        heuristics,
        permission_gaps,
    }
}

/// Audits a batch of workflows offline, automatically cross-indexing every workflow in `workflows`
/// with an `id` as an accessible subworkflow target for sibling `executeWorkflow` nodes.
#[must_use]
pub fn audit_workflows_batch(
    workflows: &[WorkflowIr],
    base_ctx: &AuditContext<'_>,
) -> BatchAuditReport {
    let mut merged_subworkflows = base_ctx.accessible_subworkflows.clone();
    for wf in workflows {
        if let Some(id) = &wf.id {
            merged_subworkflows
                .entry(id.clone())
                .or_insert_with(|| wf.clone());
        }
    }

    let effective_ctx = AuditContext {
        catalog: base_ctx.catalog,
        accessible_subworkflows: merged_subworkflows,
        inaccessible_workflow_ids: base_ctx.inaccessible_workflow_ids.clone(),
        known_credential_ids: base_ctx.known_credential_ids.clone(),
        live_audit_advertised: base_ctx.live_audit_advertised,
    };

    let mut entries = Vec::with_capacity(workflows.len());
    let mut combined = StaticAuditReport::default();

    for wf in workflows {
        let report = audit_workflow(wf, &effective_ctx);
        combined.extend_from(report.clone());
        entries.push(WorkflowAuditEntry {
            workflow_id: wf.id.clone(),
            workflow_name: redact_str(&wf.name),
            report,
        });
    }

    BatchAuditReport {
        workflows_scanned: workflows.len(),
        workflows: entries,
        combined,
    }
}

/// Merges a redacted `/api/v1/audit` JSON response from n8n Public API into `report`.
pub fn merge_live_audit_payload(report: &mut StaticAuditReport, raw_payload: &Value) {
    let sanitized = redact_json_value(raw_payload);
    let Some(top_map) = sanitized.as_object() else {
        return;
    };

    for (risk_key, risk_entry) in top_map {
        let Some(risk_obj) = risk_entry.as_object() else {
            continue;
        };
        let category = risk_obj
            .get("risk")
            .and_then(Value::as_str)
            .unwrap_or(risk_key.as_str());
        let sections = risk_obj
            .get("sections")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for section in sections {
            let title = section
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("Live Audit Finding");
            let description = section
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            let recommendation = section
                .get("recommendation")
                .and_then(Value::as_str)
                .map(redact_str);
            let locations_len = section
                .get("location")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);

            let safe_title = redact_str(title);
            let safe_desc = redact_str(description);

            // Instance/filesystem/nodes/credentials reports from n8n's own database are observed server facts;
            // heuristic SQL/expression warnings reported by n8n are categorized carefully.
            if category.eq_ignore_ascii_case("database") {
                report.heuristics.push(AuditHeuristic {
                    code: format!("live_audit:{category}"),
                    severity: AuditSeverity::Medium,
                    confidence: "medium".to_owned(),
                    workflow_id: None,
                    node_id: None,
                    node_name: None,
                    field_path: None,
                    secret_kind: None,
                    summary: format!(
                        "[{category}] {safe_title}: {safe_desc} ({locations_len} location(s))"
                    ),
                });
            } else {
                report.observed_facts.push(AuditFact {
                    code: format!("live_audit:{category}"),
                    severity: AuditSeverity::Medium,
                    workflow_id: None,
                    node_id: None,
                    node_name: None,
                    field_path: None,
                    description: format!(
                        "[{category}] {safe_title}: {safe_desc} ({locations_len} location(s))"
                    ),
                    remediation: recommendation,
                });
            }
        }
    }
}

/// Runs [`audit_workflow`] and optionally queries `POST /api/v1/audit` on `client`, converting
/// `401` / `403` / `404` / `UnsupportedCapability` responses into honest `permission_gaps`
/// without failing the static audit.
pub async fn audit_workflow_with_live_api(
    ir: &WorkflowIr,
    ctx: &AuditContext<'_>,
    client: &N8nApiClient,
    categories: Option<&[String]>,
) -> StaticAuditReport {
    let mut report = audit_workflow(ir, ctx);
    match client.generate_audit(categories).await {
        Ok(live_json) => merge_live_audit_payload(&mut report, &live_json),
        Err(err) => {
            if let Some(gap) = permission_gap_from_live_audit_error(&err) {
                report.permission_gaps.push(gap);
            } else {
                report.permission_gaps.push(PermissionGap {
                    resource: "/api/v1/audit".to_owned(),
                    reason: redact_str(&format!(
                        "Live `/api/v1/audit` request could not complete: {err}"
                    )),
                    gap_kind: Some("live_audit_unavailable".to_owned()),
                    workflow_id: ir.id.clone(),
                    node_id: None,
                    node_name: None,
                    status_code: None,
                });
            }
        }
    }
    report
}
