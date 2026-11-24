use n8n_catalog_db::{NodeInfoMode, NodeInfoRequest};
use n8n_graph::canonical_blake3_json_hex;
use n8n_test_harness::summarize_execution_resource_redacted;
use n8n_types::{N8nError, N8nResult, redact_json_value};
use percent_encoding::percent_decode_str;
use rmcp::{
    ErrorData as McpError,
    model::{
        ListResourceTemplatesResult, ListResourcesResult, ReadResourceResponse, ReadResourceResult,
        Resource, ResourceContents, ResourceTemplate,
    },
};
use serde_json::{Value, json};

use crate::state::AppState;

/// Exact 4 read-only MCP Resource Templates exposed by V2.
#[must_use]
pub fn build_resource_templates() -> ListResourceTemplatesResult {
    let templates = vec![
        ResourceTemplate::new("n8n://{instance}/workflows/{id}", "workflow-sanitized")
            .with_title("Sanitized n8n Workflow")
            .with_description(
                "Read-only sanitized workflow graph, dual version identifiers (versionId + activeVersionId), and canonical hash.",
            )
            .with_mime_type("application/json"),
        ResourceTemplate::new(
            "n8n://{instance}/workflows/{id}/diff/{planId}",
            "workflow-plan-diff",
        )
        .with_title("Workflow Preview Plan Diff")
        .with_description(
            "Read-only bounded diff and side-effect summary for a pending or confirmed mutation planId.",
        )
        .with_mime_type("application/json"),
        ResourceTemplate::new(
            "n8n://{instance}/executions/{id}/summary",
            "execution-redacted-summary",
        )
        .with_title("Redacted Execution Summary")
        .with_description(
            "Read-only execution status, node timings, and redacted error summary with zero payload secret leakage.",
        )
        .with_mime_type("application/json"),
        ResourceTemplate::new(
            "n8n://catalog/node/{type}/{version}",
            "catalog-node-schema",
        )
        .with_title("Catalog Node Schema")
        .with_description(
            "Offline n8n catalog schema, operations, credential types, and version history for a node type.",
        )
        .with_mime_type("application/json"),
    ];
    ListResourceTemplatesResult::with_all_items(templates)
}

/// Return concrete dynamic resources for active preview diff plans.
#[must_use]
pub fn list_concrete_resources(state: &AppState) -> ListResourcesResult {
    let mut resources: Vec<Resource> = Vec::new();
    for plan in state.approval_manager.list_active_plans(50) {
        if let Some(wf_id) = &plan.workflow_id {
            let uri = format!(
                "n8n://{}/workflows/{wf_id}/diff/{}",
                plan.instance, plan.plan_id
            );
            let resource = Resource::new(uri, format!("Diff {}", plan.plan_id))
                .with_description(plan.summary.clone())
                .with_mime_type("application/json");
            resources.push(resource);
        }
    }
    ListResourcesResult::with_all_items(resources)
}

/// Resolve and read one of the 4 read-only `n8n://` resource URIs.
pub async fn read_n8n_resource(
    state: &AppState,
    uri: &str,
) -> Result<ReadResourceResponse, McpError> {
    let payload = resolve_resource_json(state, uri)
        .await
        .map_err(|err| McpError::invalid_params(err.to_string(), None))?;
    let sanitized = redact_json_value(&payload);
    let text = serde_json::to_string_pretty(&sanitized)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let content = ResourceContents::text(text, uri.to_owned()).with_mime_type("application/json");
    Ok(ReadResourceResponse::Complete(ReadResourceResult::new(
        vec![content],
    )))
}

async fn resolve_resource_json(state: &AppState, uri: &str) -> N8nResult<Value> {
    let rest = uri.strip_prefix("n8n://").ok_or_else(|| {
        N8nError::validation(
            &state.active_instance,
            vec![format!("invalid scheme in `{uri}`")],
            "Expected `n8n://` resource URI scheme",
        )
    })?;

    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["catalog", "node", raw_type, raw_version] => {
            let node_type = percent_decode_str(raw_type)
                .decode_utf8_lossy()
                .into_owned();
            let requested_version = percent_decode_str(raw_version)
                .decode_utf8_lossy()
                .into_owned();
            let version_opt = (!requested_version.is_empty() && requested_version != "latest")
                .then_some(requested_version.clone());
            let (info, versions) = state.with_catalog(|db| {
                let info = db.get_node_info(&NodeInfoRequest {
                    node_type: node_type.clone(),
                    mode: NodeInfoMode::Info,
                    type_version: version_opt,
                    property_query: None,
                })?;
                let versions = db.get_node_info(&NodeInfoRequest {
                    node_type: node_type.clone(),
                    mode: NodeInfoMode::Versions,
                    type_version: None,
                    property_query: None,
                })?;
                N8nResult::Ok((info, versions))
            })?;
            Ok(json!({
                "uri": uri,
                "requestedVersion": requested_version,
                "node": info,
                "versions": versions,
            }))
        }
        [instance, "workflows", wf_id] => {
            let decoded_instance = percent_decode_str(instance)
                .decode_utf8_lossy()
                .into_owned();
            let decoded_wf = percent_decode_str(wf_id).decode_utf8_lossy().into_owned();
            let rt = state.instance(Some(&decoded_instance))?;
            let Some(ref api) = rt.api_client else {
                return Err(N8nError::unauthenticated(
                    &rt.config.alias,
                    "N8N_API_KEY missing",
                ));
            };
            let wf = api.get_workflow(&decoded_wf, true).await?;
            let wf_val = serde_json::to_value(&wf)
                .map_err(|e| N8nError::protocol(format!("workflow serialize error: {e}")))?;
            let version_hash =
                canonical_blake3_json_hex(&wf_val, "n8n-rs-mcp/v2/workflow-version-hash");
            Ok(json!({
                "uri": uri,
                "instance": rt.config.alias,
                "workflowId": wf.id,
                "versionId": wf.version_id,
                "activeVersionId": wf.active_version_id,
                "canonicalVersionHash": version_hash,
                "workflow": redact_json_value(&wf_val),
            }))
        }
        [instance, "workflows", wf_id, "diff", plan_id] => {
            let decoded_instance = percent_decode_str(instance)
                .decode_utf8_lossy()
                .into_owned();
            let decoded_wf = percent_decode_str(wf_id).decode_utf8_lossy().into_owned();
            let decoded_plan = percent_decode_str(plan_id).decode_utf8_lossy().into_owned();

            if let Some(plan) = state.approval_manager.get_plan_for_resource(
                &decoded_instance,
                &decoded_wf,
                &decoded_plan,
            ) {
                return Ok(json!({
                    "uri": uri,
                    "planId": plan.plan_id,
                    "instance": plan.instance,
                    "workflowId": plan.workflow_id,
                    "action": plan.action,
                    "risk": plan.risk,
                    "confirmed": plan.confirmed,
                    "summary": plan.summary,
                    "expectedVersionHash": plan.expected_version_hash,
                    "opsHash": plan.ops_hash,
                    "diff": plan.diff,
                    "details": plan.diff_payload,
                    "sideEffects": plan.side_effects,
                    "expiresAt": plan.expires_at,
                }));
            }

            let batch_plan = {
                let jrnl = state.journal.lock().await;
                jrnl.get_batch_plan(&decoded_plan)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
            };
            if let Some(bp) = batch_plan {
                return Ok(json!({
                    "uri": uri,
                    "batchId": bp.batch_id,
                    "instance": bp.instance_id,
                    "workflowId": decoded_wf,
                    "haltedOnError": bp.halted_on_error,
                    "plan": bp,
                }));
            }

            Err(N8nError::not_found_or_concealed(
                &decoded_instance,
                format!("diff/{decoded_plan}"),
                format!("Diff plan `{decoded_plan}` was not found or has expired"),
            ))
        }
        [instance, "executions", exec_id, "summary"] => {
            let decoded_instance = percent_decode_str(instance)
                .decode_utf8_lossy()
                .into_owned();
            let decoded_exec = percent_decode_str(exec_id).decode_utf8_lossy().into_owned();
            let rt = state.instance(Some(&decoded_instance))?;
            let Some(ref api) = rt.api_client else {
                return Err(N8nError::unauthenticated(
                    &rt.config.alias,
                    "N8N_API_KEY missing",
                ));
            };
            let exec = api.get_execution(&decoded_exec, false).await?;
            let summary = summarize_execution_resource_redacted(
                &exec,
                &n8n_test_harness::ExecutionMinimizeOptions::summary_only(),
            )?;
            Ok(json!({
                "uri": uri,
                "instance": rt.config.alias,
                "summary": summary,
            }))
        }
        _ => Err(N8nError::not_found_or_concealed(
            &state.active_instance,
            uri.to_owned(),
            format!("Unrecognized n8n resource URI `{uri}`"),
        )),
    }
}
