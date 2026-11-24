//! Permission-limited and schema-limited visibility gaps (`permission_gaps`) reported honestly
//! during static and live API workflow audits (V2 Section 10).

use std::collections::{HashMap, HashSet};

use n8n_catalog_db::{CatalogDb, NodeInfoMode, NodeInfoRequest, SchemaConfidence};
use n8n_graph::{WorkflowIr, WorkflowNodeIr};
use n8n_types::{N8nError, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Honest visibility boundary where security properties cannot be proven offline or under the
/// current principal's permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGap {
    pub resource: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}

impl PermissionGap {
    #[must_use]
    pub fn new(resource: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            resource: redact_str(&resource.into()),
            reason: redact_str(&reason.into()),
            gap_kind: None,
            workflow_id: None,
            node_id: None,
            node_name: None,
            status_code: None,
        }
    }
}

/// Collects static visibility/permission gaps on `ir` without performing network calls.
#[must_use]
pub fn collect_permission_gaps(
    ir: &WorkflowIr,
    catalog: Option<&CatalogDb>,
    accessible_subworkflows: &HashMap<String, WorkflowIr>,
    inaccessible_workflow_ids: &HashSet<String>,
    live_audit_advertised: Option<bool>,
) -> Vec<PermissionGap> {
    let mut gaps = Vec::new();
    let wf_id = ir.id.clone();

    if live_audit_advertised == Some(false) {
        gaps.push(PermissionGap {
            resource: "/api/v1/audit".to_owned(),
            reason: "Connected n8n instance does not advertise or permit `/api/v1/audit`; server-side instance/database risk checks could not be queried.".to_owned(),
            gap_kind: Some("unadvertised_audit_endpoint".to_owned()),
            workflow_id: wf_id.clone(),
            node_id: None,
            node_name: None,
            status_code: None,
        });
    }

    for node in &ir.nodes {
        // 1. Hidden encrypted credential secret bodies.
        if let Some(creds) = &node.credentials {
            for (cred_type, cred_ref) in creds {
                if let Some(cred_id) = cred_ref
                    .id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    gaps.push(PermissionGap {
                        resource: format!("credential:{cred_type}:{}", redact_str(cred_id)),
                        reason: format!(
                            "Credential `{cred_type}` bound on node `{}` stores encrypted secret material server-side; token scope, rotation age, and secret entropy cannot be inspected via workflow JSON.",
                            node.name
                        ),
                        gap_kind: Some("hidden_credential_body".to_owned()),
                        workflow_id: wf_id.clone(),
                        node_id: Some(node.id.clone()),
                        node_name: Some(node.name.clone()),
                        status_code: None,
                    });
                }
            }
        }

        // 2. Unreadable / unprovided subworkflow targets (`executeWorkflow` / `toolWorkflow`).
        if matches!(
            node.node_type.as_str(),
            "n8n-nodes-base.executeWorkflow" | "@n8n/n8n-nodes-langchain.toolWorkflow"
        ) {
            match extract_target_subworkflow_id(node) {
                SubworkflowTargetRef::StaticId(target_id) => {
                    if inaccessible_workflow_ids.contains(&target_id)
                        || !accessible_subworkflows.contains_key(&target_id)
                    {
                        gaps.push(PermissionGap {
                            resource: format!("workflow:{target_id}"),
                            reason: format!(
                                "Node `{}` invokes subworkflow `{target_id}` whose graph is unreadable or not loaded in the current audit scope.",
                                node.name
                            ),
                            gap_kind: Some("unreadable_subworkflow".to_owned()),
                            workflow_id: wf_id.clone(),
                            node_id: Some(node.id.clone()),
                            node_name: Some(node.name.clone()),
                            status_code: if inaccessible_workflow_ids.contains(&target_id) {
                                Some(403)
                            } else {
                                None
                            },
                        });
                    }
                }
                SubworkflowTargetRef::DynamicExpression => {
                    gaps.push(PermissionGap {
                        resource: format!("workflow:dynamic_from_node:{}", node.name),
                        reason: format!(
                            "Node `{}` resolves its target subworkflow dynamically via runtime expression; nested subworkflow security posture cannot be statically audited.",
                            node.name
                        ),
                        gap_kind: Some("dynamic_subworkflow_reference".to_owned()),
                        workflow_id: wf_id.clone(),
                        node_id: Some(node.id.clone()),
                        node_name: Some(node.name.clone()),
                        status_code: None,
                    });
                }
                SubworkflowTargetRef::Missing => {}
            }
        }

        // 3. Community or unknown node partial schema visibility gap.
        let is_community_prefix =
            !node.node_type.starts_with("n8n-nodes-base.") && !node.node_type.starts_with("@n8n/");
        let partial_in_catalog = catalog.is_some_and(|db| {
            db.get_node_info(&NodeInfoRequest {
                node_type: node.node_type.clone(),
                mode: NodeInfoMode::Info,
                type_version: Some(node.type_version_string()),
                property_query: None,
            })
            .map(|info| info.schema_confidence == SchemaConfidence::UnknownOrCommunityPartial)
            .unwrap_or(true)
        });

        if is_community_prefix || partial_in_catalog {
            gaps.push(PermissionGap {
                resource: format!("node_schema:{}", node.node_type),
                reason: format!(
                    "Node `{}` uses community or unindexed type `{}`; parameter and credential rules have partial offline schema coverage.",
                    node.name, node.node_type
                ),
                gap_kind: Some("community_node_partial_schema".to_owned()),
                workflow_id: wf_id.clone(),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                status_code: None,
            });
        }
    }

    gaps
}

/// Converts a failed `/api/v1/audit` live API error into an honest `PermissionGap` when appropriate.
#[must_use]
pub fn permission_gap_from_live_audit_error(err: &N8nError) -> Option<PermissionGap> {
    match err {
        N8nError::Forbidden403 { message, .. } => Some(PermissionGap {
            resource: "/api/v1/audit".to_owned(),
            reason: redact_str(&format!(
                "Live `/api/v1/audit` endpoint returned HTTP 403 Forbidden (insufficient scope or role): {message}"
            )),
            gap_kind: Some("live_audit_forbidden_403".to_owned()),
            workflow_id: None,
            node_id: None,
            node_name: None,
            status_code: Some(403),
        }),
        N8nError::NotFoundOrConcealed404 { message, .. } => Some(PermissionGap {
            resource: "/api/v1/audit".to_owned(),
            reason: redact_str(&format!(
                "Live `/api/v1/audit` endpoint returned HTTP 404 Not Found or concealed on this n8n version/edition: {message}"
            )),
            gap_kind: Some("live_audit_not_found_404".to_owned()),
            workflow_id: None,
            node_id: None,
            node_name: None,
            status_code: Some(404),
        }),
        N8nError::UnsupportedCapability { reason, .. } => Some(PermissionGap {
            resource: "/api/v1/audit".to_owned(),
            reason: redact_str(&format!(
                "Live `/api/v1/audit` capability is not advertised by this n8n instance: {reason}"
            )),
            gap_kind: Some("live_audit_unsupported".to_owned()),
            workflow_id: None,
            node_id: None,
            node_name: None,
            status_code: None,
        }),
        N8nError::Unauthenticated401 { message, .. } => Some(PermissionGap {
            resource: "/api/v1/audit".to_owned(),
            reason: redact_str(&format!(
                "Live `/api/v1/audit` returned HTTP 401 Unauthenticated: {message}"
            )),
            gap_kind: Some("live_audit_unauthenticated_401".to_owned()),
            workflow_id: None,
            node_id: None,
            node_name: None,
            status_code: Some(401),
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubworkflowTargetRef {
    StaticId(String),
    DynamicExpression,
    Missing,
}

/// Extracts the referenced subworkflow ID from an `executeWorkflow` / `toolWorkflow` node.
#[must_use]
pub fn extract_target_subworkflow_id(node: &WorkflowNodeIr) -> SubworkflowTargetRef {
    let Some(raw) = node.parameters.get("workflowId") else {
        return SubworkflowTargetRef::Missing;
    };

    let candidate_str = match raw {
        Value::String(s) => Some(s.trim()),
        Value::Number(n) => return SubworkflowTargetRef::StaticId(n.to_string()),
        Value::Object(obj) => obj.get("value").and_then(Value::as_str).map(str::trim),
        _ => None,
    };

    match candidate_str {
        None | Some("") => SubworkflowTargetRef::Missing,
        Some(s) if s.starts_with('=') && s.contains("{{") => {
            SubworkflowTargetRef::DynamicExpression
        }
        Some(s) => SubworkflowTargetRef::StaticId(redact_str(s)),
    }
}
