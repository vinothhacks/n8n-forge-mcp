use chrono::Utc;
use n8n_api_client::ListQueryParams;
use n8n_capability::{LogicalOperation, verify_fallback_allowed};
use n8n_graph::{
    DEFAULT_DIFF_MAX_CHARS, GraphMutationError, GraphMutationOp, MutationPlan, WorkflowDiff,
    WorkflowGraph, WorkflowIr, apply_mutations,
};
use n8n_policy::{MAX_BATCH_WORKFLOWS, PolicyMode, enforce_batch_cap, hash_ops};
use n8n_state_vault::{
    BatchCheckpointStatus, CachePolicy, FindNodesQuery, GraphVariant, IndexWorkflowMetadata,
    JournalState, ParamPredicate, RESTORE_SIDE_EFFECTS_DISCLAIMER, ephemeral_scan_parameters,
};
use n8n_types::{
    BoundedDiffSummary, DetailLevel, N8nError, OperationStatus, PermissionDecision, RiskLevel,
    RouteUsed, ToolEnvelope, VerificationReport, redact_json_value,
};
use n8n_validator::{
    MutationApplyStatus, ValidatedMutationOp, ValidationOptions, apply_validated_mutation,
    validate_workflow,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::approval::PreviewPlanInit;
use crate::state::AppState;
use crate::tools::common::{
    AuthorizeSpec, authorize_operation, build_mutation_context_for_ir, ir_to_workflow_write_body,
    record_completed_mutation_journal, workflow_resource_to_ir,
};

/// Input schema for Tool #6: `n8n_find_nodes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindNodesParams {
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub active_only: bool,
    #[serde(default)]
    pub graph: Option<GraphVariant>,
    #[serde(default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub name_pattern: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub references_node: Option<String>,
    #[serde(default)]
    pub uses_variable: Option<String>,
    #[serde(default)]
    pub credential_type: Option<String>,
    #[serde(default)]
    pub stale_type_version: Option<bool>,
    #[serde(default)]
    pub missing_error_handler: Option<bool>,
    #[serde(default)]
    pub recent_failure_count: Option<u32>,
    #[serde(default)]
    pub refresh_index: bool,
    #[serde(default)]
    pub cache_policy: CachePolicy,
    #[serde(default)]
    pub revoke_project_id: Option<String>,
    #[serde(default)]
    pub ephemeral_path: Option<String>,
    #[serde(default)]
    pub ephemeral_predicate: Option<ParamPredicate>,
    #[serde(default)]
    pub page_token: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #7: `n8n_inspect_node_config`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InspectNodeConfigParams {
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub type_version: Option<String>,
    #[serde(default)]
    pub parameters: Option<Value>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #8: `n8n_mutate_nodes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MutateNodesParams {
    #[serde(default)]
    pub instance: Option<String>,
    pub workflow_id: String,
    #[serde(default = "default_preview_str")]
    pub mode: String,
    #[serde(default)]
    pub operations: Vec<GraphMutationOp>,
    #[serde(default)]
    pub validated_operations: Vec<ValidatedMutationOp>,
    #[serde(default)]
    pub expected_version_hash: Option<String>,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub prefer_native_mcp: Option<bool>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #9: `n8n_bulk_codemod`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkCodemodParams {
    #[serde(default = "default_preview_str")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub workflow_ids: Vec<String>,
    #[serde(default)]
    pub operations: Vec<GraphMutationOp>,
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

fn default_preview_str() -> String {
    "preview".to_owned()
}

/// Tool #6: `n8n_find_nodes`.
pub async fn execute_find_nodes(state: &AppState, params: FindNodesParams) -> ToolEnvelope<Value> {
    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: "find_nodes.search".to_owned(),
            logical_op: LogicalOperation::FindNodes,
            risk: RiskLevel::R0,
            workflow_id: params.workflow_id.clone(),
            project_id: params.project_id.clone(),
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload: json!({"workflowId": params.workflow_id, "nodeType": params.node_type}),
            explicit_apply_intent: false,
            approval_receipt: None,
            batch_workflow_count: None,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(env) => return env,
    };
    let alias = &auth.rt.config.alias;

    if let Some(ref revoke_proj) = params.revoke_project_id {
        let purged = match state.with_workflow_index_mut(|idx| {
            idx.revoke_principal_or_project(&auth.principal, Some(alias), Some(revoke_proj))
        }) {
            Ok(n) => n,
            Err(e) => return e.into_envelope(alias, "find_nodes.revoke", RouteUsed::Local),
        };
        return ToolEnvelope::new(
            OperationStatus::Success,
            alias,
            "find_nodes.revoke",
            auth.policy.permission,
            RouteUsed::Local,
        )
        .with_data(json!({ "revokedProjectId": revoke_proj, "purgedWorkflows": purged }));
    }

    let mut ephemeral_hits: Vec<Value> = Vec::new();
    let mut route_used = RouteUsed::Local;

    if params.refresh_index || params.ephemeral_path.is_some() {
        let Some(ref api) = auth.rt.api_client else {
            return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
                alias,
                "find_nodes.search",
                RouteUsed::PublicApi,
            );
        };
        route_used = RouteUsed::PublicApi;
        let fetched = if let Some(ref wf_id) = params.workflow_id {
            match api.get_workflow(wf_id, true).await {
                Ok(wf) => vec![wf],
                Err(e) => return e.into_envelope(alias, "find_nodes.search", RouteUsed::PublicApi),
            }
        } else {
            match api
                .list_workflows(&ListQueryParams {
                    limit: Some(100),
                    active: params.active_only.then_some(true),
                    exclude_pinned_data: Some(true),
                    ..ListQueryParams::default()
                })
                .await
            {
                Ok(p) => p.data,
                Err(e) => return e.into_envelope(alias, "find_nodes.search", RouteUsed::PublicApi),
            }
        };

        let proj = params
            .project_id
            .clone()
            .unwrap_or_else(|| "default".to_owned());
        let now = Utc::now();
        for wf in &fetched {
            let Ok((ir, _, _)) = workflow_resource_to_ir(wf) else {
                continue;
            };
            if params.refresh_index {
                let meta = IndexWorkflowMetadata {
                    principal_id: auth.principal.clone(),
                    instance_id: alias.clone(),
                    project_id: proj.clone(),
                    folder_id: params.folder_id.clone(),
                    graph: if wf.active {
                        GraphVariant::Published
                    } else {
                        GraphVariant::Draft
                    },
                    recent_failure_count: 0,
                    cache_policy: params.cache_policy,
                    ttl_secs: None,
                    latest_catalog_versions: None,
                };
                let _ = state.with_workflow_index_mut(|idx| idx.index_workflow_at(&ir, &meta, now));
            }
            if let (Some(path), Some(pred)) = (&params.ephemeral_path, &params.ephemeral_predicate)
            {
                match ephemeral_scan_parameters(&ir, path, pred) {
                    Ok(matches) => {
                        for m in matches {
                            ephemeral_hits.push(json!({
                                "workflowId": wf.id,
                                "nodeId": m.node_id,
                                "nodeName": m.node_name,
                                "matchedFieldPath": m.matched_field_path,
                            }));
                        }
                    }
                    Err(e) => {
                        return e.into_envelope(
                            alias,
                            "find_nodes.ephemeral_scan",
                            RouteUsed::Local,
                        );
                    }
                }
            }
        }
    }

    let mut q = FindNodesQuery::new(&auth.principal, alias);
    q.workflow_id = params.workflow_id;
    q.project_id = params.project_id;
    q.allowed_project_ids = auth
        .rt
        .config
        .allowed_project_ids
        .as_ref()
        .map(|s| s.iter().cloned().collect());
    q.folder_id = params.folder_id;
    q.active_only = params.active_only;
    q.graph = params.graph;
    q.node_type = params.node_type;
    q.name_pattern = params.name_pattern;
    q.disabled = params.disabled;
    q.references_node = params.references_node;
    q.uses_variable = params.uses_variable;
    q.credential_type = params.credential_type;
    q.stale_type_version = params.stale_type_version;
    q.missing_error_handler = params.missing_error_handler;
    q.recent_failure_count = params.recent_failure_count;
    q.page_token = params.page_token;
    q.max_results = params.limit.unwrap_or(50).clamp(1, 200);

    match state.with_workflow_index(|idx| idx.find_nodes_at(&q, Utc::now())) {
        Ok(page) => ToolEnvelope::new(
            OperationStatus::Success,
            alias,
            "find_nodes.search",
            auth.policy.permission,
            route_used,
        )
        .with_data(redact_json_value(&json!({
            "hits": page.hits,
            "count": page.hits.len(),
            "nextPageToken": page.next_page_token,
            "ephemeralMatches": ephemeral_hits,
        }))),
        Err(e) => e.into_envelope(alias, "find_nodes.search", route_used),
    }
}

/// Tool #7: `n8n_inspect_node_config`.
pub async fn execute_inspect_node_config(
    state: &AppState,
    params: InspectNodeConfigParams,
) -> ToolEnvelope<Value> {
    let inst_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    if let Some(ref wf_id) = params.workflow_id {
        let Some(ref target_node) = params.node_name else {
            return N8nError::validation(
                &inst_name,
                vec!["missing `nodeName`".to_owned()],
                "`nodeName` is required when `workflowId` is specified",
            )
            .into_envelope(
                &inst_name,
                "inspect_node_config.workflow",
                RouteUsed::Local,
            );
        };
        let auth = match authorize_operation(
            state,
            AuthorizeSpec {
                requested_instance: params.instance.as_deref(),
                action: "inspect_node_config.workflow".to_owned(),
                logical_op: LogicalOperation::InspectNodeConfig,
                risk: RiskLevel::R0,
                workflow_id: Some(wf_id.clone()),
                project_id: None,
                is_archived_workflow: false,
                expected_version_hash: None,
                ops_payload: json!({"workflowId": wf_id, "nodeName": target_node}),
                explicit_apply_intent: false,
                approval_receipt: None,
                batch_workflow_count: None,
            },
        )
        .await
        {
            Ok(a) => a,
            Err(env) => return env,
        };
        let alias = &auth.rt.config.alias;
        let Some(ref api) = auth.rt.api_client else {
            return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
                alias,
                "inspect_node_config.workflow",
                RouteUsed::PublicApi,
            );
        };
        let wf = match api.get_workflow(wf_id, false).await {
            Ok(w) => w,
            Err(e) => {
                return e.into_envelope(
                    alias,
                    "inspect_node_config.workflow",
                    RouteUsed::PublicApi,
                );
            }
        };
        let (ir, _, _) = match workflow_resource_to_ir(&wf) {
            Ok(t) => t,
            Err(e) => {
                return e.into_envelope(alias, "inspect_node_config.workflow", RouteUsed::Local);
            }
        };
        let Some(node) = ir
            .nodes
            .iter()
            .find(|n| n.name == *target_node || n.id == *target_node)
        else {
            return N8nError::not_found_or_concealed(
                alias,
                format!("workflow/{wf_id}/node/{target_node}"),
                format!("Node `{target_node}` not found in workflow `{wf_id}`"),
            )
            .into_envelope(alias, "inspect_node_config.workflow", RouteUsed::Local);
        };
        let ver_str = node
            .type_version
            .as_f64()
            .map(|v| v.to_string())
            .or_else(|| node.type_version.as_str().map(str::to_owned));
        let effective = match state.with_catalog(|db| {
            db.inspect_effective_node_fields(&node.node_type, ver_str.as_deref(), &node.parameters)
        }) {
            Ok(r) => r,
            Err(e) => {
                return e.into_envelope(alias, "inspect_node_config.workflow", RouteUsed::Local);
            }
        };
        let upstream_shape = WorkflowGraph::from_ir(&ir).infer_upstream_data_shape(&ir, &node.name);
        return ToolEnvelope::new(
            OperationStatus::Success,
            alias,
            "inspect_node_config.workflow",
            auth.policy.permission,
            RouteUsed::PublicApi,
        )
        .with_workflow_id(Some(wf_id.clone()))
        .with_data(redact_json_value(&json!({
            "nodeName": node.name,
            "nodeId": node.id,
            "effectiveFields": effective,
            "upstreamDataShape": upstream_shape,
        })));
    }

    let Some(ref nt) = params.node_type else {
        return N8nError::validation(
            &inst_name,
            vec!["missing `nodeType` or `workflowId`".to_owned()],
            "Provide either `(workflowId, nodeName)` or `nodeType`",
        )
        .into_envelope(&inst_name, "inspect_node_config.catalog", RouteUsed::Local);
    };
    let p_val = params.parameters.unwrap_or_else(|| json!({}));
    match state.with_catalog(|db| {
        db.inspect_effective_node_fields(nt, params.type_version.as_deref(), &p_val)
    }) {
        Ok(effective) => ToolEnvelope::new(
            OperationStatus::Success,
            inst_name,
            "inspect_node_config.catalog",
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_data(redact_json_value(&json!({ "effectiveFields": effective }))),
        Err(e) => e.into_envelope(inst_name, "inspect_node_config.catalog", RouteUsed::Local),
    }
}

/// Tool #8: `n8n_mutate_nodes`.
#[allow(clippy::too_many_lines)]
pub async fn execute_mutate_nodes(
    state: &AppState,
    params: MutateNodesParams,
) -> ToolEnvelope<Value> {
    let mode_norm = params.mode.trim().to_ascii_lowercase();
    let ops_payload = json!({
        "operations": params.operations,
        "validatedOperations": params.validated_operations,
    });

    if mode_norm != "apply" {
        let rt = match state.instance(params.instance.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                return e.into_envelope(
                    params.instance.as_deref().unwrap_or(&state.active_instance),
                    "mutate_nodes.preview",
                    RouteUsed::Local,
                );
            }
        };
        if rt.config.policy_mode == PolicyMode::ReadOnly {
            return N8nError::policy_blocked(
                "mutate_nodes.preview",
                RiskLevel::R2,
                "read-only",
                "Mutation preview blocked under `read-only` policy",
                None,
            )
            .into_envelope(&rt.config.alias, "mutate_nodes.preview", RouteUsed::Local);
        }
        let auth = match authorize_operation(
            state,
            AuthorizeSpec {
                requested_instance: params.instance.as_deref(),
                action: "mutate_nodes.preview".to_owned(),
                logical_op: LogicalOperation::WorkflowsRead,
                risk: RiskLevel::R0,
                workflow_id: Some(params.workflow_id.clone()),
                project_id: None,
                is_archived_workflow: false,
                expected_version_hash: None,
                ops_payload: ops_payload.clone(),
                explicit_apply_intent: false,
                approval_receipt: None,
                batch_workflow_count: None,
            },
        )
        .await
        {
            Ok(a) => a,
            Err(env) => return env,
        };
        let alias = &auth.rt.config.alias;
        let Some(ref api) = auth.rt.api_client else {
            return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
                alias,
                "mutate_nodes.preview",
                RouteUsed::PublicApi,
            );
        };
        let live = match api.get_workflow(&params.workflow_id, false).await {
            Ok(w) => w,
            Err(e) => {
                return e.into_envelope(alias, "mutate_nodes.preview", RouteUsed::PublicApi);
            }
        };
        let (base_ir, base_hash, _) = match workflow_resource_to_ir(&live) {
            Ok(t) => t,
            Err(e) => return e.into_envelope(alias, "mutate_nodes.preview", RouteUsed::Local),
        };
        if let Some(ref exp) = params.expected_version_hash
            && exp != &base_hash
        {
            return N8nError::Conflict409 {
                instance: alias.clone(),
                resource: Some(params.workflow_id),
                message: format!("Workflow drifted (`{base_hash}` != expected `{exp}`)"),
            }
            .into_envelope(alias, "mutate_nodes.preview", RouteUsed::PublicApi);
        }
        let (after_ir, mut_plan) = match compute_mutated_ir(
            state,
            alias,
            "mutate_nodes.preview",
            &base_ir,
            &params.operations,
            &params.validated_operations,
        ) {
            Ok(pair) => pair,
            Err(env) => return env,
        };
        let val_report = state.with_catalog(|db| {
            validate_workflow(&after_ir, Some(db), &ValidationOptions::default())
        });
        let preview_plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal: auth.principal,
            instance: alias.clone(),
            action: "mutate_nodes.apply".to_owned(),
            risk: RiskLevel::R2,
            workflow_id: Some(params.workflow_id.clone()),
            expected_version_hash: Some(base_hash),
            ops_hash: hash_ops(&ops_payload).unwrap_or_default(),
            summary: mut_plan.workflow_diff.diff_summary.summary.clone(),
            diff: Some(mut_plan.workflow_diff.diff_summary.clone()),
            diff_payload: serde_json::to_value(&mut_plan.workflow_diff).unwrap_or(Value::Null),
            side_effects: mut_plan.workflow_diff.risk_flags.clone(),
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            alias,
            "mutate_nodes.preview",
            PermissionDecision::NeedsApproval,
            RouteUsed::Local,
        )
        .with_workflow_id(Some(params.workflow_id))
        .with_versions(live.version_id, None, live.active_version_id)
        .with_diff(mut_plan.workflow_diff.diff_summary.clone())
        .with_next_actions([format!(
            "Confirm via `n8n_workflows(action=\"confirm_plan\", planId=\"{}\")` then call `n8n_mutate_nodes(mode=\"apply\")`.",
            preview_plan.plan_id
        )])
        .with_data(redact_json_value(&json!({
            "planId": preview_plan.plan_id,
            "expectedVersionHash": mut_plan.expected_version_hash,
            "resultingVersionHash": mut_plan.resulting_version_hash,
            "mutationPlan": mut_plan,
            "validationReport": val_report,
        })));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: "mutate_nodes.apply".to_owned(),
            logical_op: LogicalOperation::WorkflowsMutate,
            risk: RiskLevel::R2,
            workflow_id: Some(params.workflow_id.clone()),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: params.expected_version_hash.clone(),
            ops_payload,
            explicit_apply_intent: true,
            approval_receipt: params.approval_receipt.clone(),
            batch_workflow_count: None,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(env) => return env,
    };
    let alias = &auth.rt.config.alias;
    let Some(ref api) = auth.rt.api_client else {
        return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
            alias,
            "mutate_nodes.apply",
            RouteUsed::PublicApi,
        );
    };

    let _lock = state
        .policy_engine
        .lock_registry()
        .acquire_write_lock(alias, &params.workflow_id)
        .await;
    let live = match api.get_workflow(&params.workflow_id, false).await {
        Ok(w) => w,
        Err(e) => return e.into_envelope(alias, "mutate_nodes.apply", RouteUsed::PublicApi),
    };
    if live.is_archived {
        return N8nError::policy_blocked(
            "mutate_nodes.apply",
            RiskLevel::R2,
            auth.rt.config.policy_mode.as_str(),
            "Cannot mutate an archived workflow; unarchive first",
            None,
        )
        .into_envelope(alias, "mutate_nodes.apply", RouteUsed::Local);
    }
    let (base_ir, base_hash, _) = match workflow_resource_to_ir(&live) {
        Ok(t) => t,
        Err(e) => return e.into_envelope(alias, "mutate_nodes.apply", RouteUsed::Local),
    };
    if let Some(ref exp) = params.expected_version_hash
        && exp != &base_hash
    {
        return N8nError::Conflict409 {
            instance: alias.clone(),
            resource: Some(params.workflow_id),
            message: format!("TOCTOU conflict: live hash `{base_hash}` != expected `{exp}`"),
        }
        .into_envelope(alias, "mutate_nodes.apply", RouteUsed::PublicApi);
    }

    let (after_ir, mut_plan) = match compute_mutated_ir(
        state,
        alias,
        "mutate_nodes.apply",
        &base_ir,
        &params.operations,
        &params.validated_operations,
    ) {
        Ok(pair) => pair,
        Err(env) => return env,
    };

    let snap_hdr = state
        .with_snapshot_vault_mut(|v| {
            v.capture_snapshot_at(&auth.principal, alias, None, &base_ir, false, Utc::now())
        })
        .ok();

    let mut route_used = RouteUsed::PublicApi;
    let mut status = OperationStatus::Success;
    let mut warnings = Vec::new();
    let mut partial_inspection = None;

    let try_native = params
        .prefer_native_mcp
        .unwrap_or(auth.policy.route == RouteUsed::NativeMcp)
        && !mut_plan.requires_whole_array_or_api_fallback
        && params.validated_operations.is_empty();

    let mut wrote_via_native = false;
    if try_native && let Some(ref bridge) = auth.rt.mcp_bridge {
        let raw_ops: Vec<Value> = params
            .operations
            .iter()
            .filter_map(|op| serde_json::to_value(op).ok())
            .collect();
        let http_nodes: Vec<String> = after_ir
            .nodes
            .iter()
            .filter(|n| n.node_type.contains("httpRequest"))
            .map(|n| n.name.clone())
            .collect();
        match bridge
            .update_workflow_partial(&params.workflow_id, &raw_ops, &http_nodes)
            .await
        {
            Ok(insp) => {
                wrote_via_native = true;
                route_used = RouteUsed::NativeMcp;
                if !insp.skipped_operations.is_empty()
                    || !insp.removed_groups.is_empty()
                    || insp.derived_status == OperationStatus::Partial
                {
                    status = OperationStatus::Partial;
                }
                warnings.extend(insp.warnings.clone());
                partial_inspection = Some(insp);
            }
            Err(e) => {
                if let Err(fatal) = verify_fallback_allowed(RouteUsed::NativeMcp, e) {
                    return fatal.into_envelope(alias, "mutate_nodes.apply", RouteUsed::NativeMcp);
                }
            }
        }
    }

    if !wrote_via_native {
        let body = match ir_to_workflow_write_body(&after_ir, false) {
            Ok(b) => b,
            Err(e) => return e.into_envelope(alias, "mutate_nodes.apply", RouteUsed::Local),
        };
        if let Err(e) = api.update_workflow(&params.workflow_id, &body).await {
            return e.into_envelope(alias, "mutate_nodes.apply", RouteUsed::PublicApi);
        }
    }

    let verified = match api.get_workflow(&params.workflow_id, false).await {
        Ok(v) => v,
        Err(e) => return e.into_envelope(alias, "mutate_nodes.apply", route_used),
    };
    let after_hash = workflow_resource_to_ir(&verified).ok().map(|(_, h, _)| h);
    record_completed_mutation_journal(
        state,
        &auth.principal,
        alias,
        Some(&params.workflow_id),
        "mutate_nodes.apply",
        Some(&base_hash),
        after_hash.as_deref(),
        &auth.ops_hash,
        JournalState::Verified,
        json!({"snapshotId": snap_hdr.as_ref().map(|s| &s.snapshot_id), "route": route_used}),
    )
    .await;

    ToolEnvelope::new(
        status,
        alias,
        "mutate_nodes.apply",
        auth.policy.permission,
        route_used,
    )
    .with_workflow_id(Some(verified.id))
    .with_versions(
        live.version_id,
        verified.version_id,
        verified.active_version_id,
    )
    .with_changed(true)
    .with_warnings(warnings)
    .with_diff(mut_plan.workflow_diff.diff_summary)
    .with_verification(VerificationReport::verified([
        "Surgical node mutation committed and verified via GET read-back.".to_owned(),
    ]))
    .with_data(redact_json_value(&json!({
        "snapshotId": snap_hdr.map(|s| s.snapshot_id),
        "resultingVersionHash": after_hash,
        "nativeMcpInspection": partial_inspection,
    })))
}

/// Tool #9: `n8n_bulk_codemod`.
#[allow(clippy::too_many_lines)]
pub async fn execute_bulk_codemod(
    state: &AppState,
    params: BulkCodemodParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("bulk_codemod.{action_norm}");
    let inst_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    if matches!(action_norm.as_str(), "status" | "restore_plan") {
        let Some(ref bid) = params.batch_id else {
            return N8nError::validation(
                &inst_name,
                vec!["missing `batchId`".to_owned()],
                "`batchId` is required for `status` and `restore_plan`",
            )
            .into_envelope(&inst_name, full_action, RouteUsed::Local);
        };
        let rec = {
            let jrnl = state.journal.lock().await;
            jrnl.get_batch_plan(bid)
        };
        return match rec {
            Ok(Some(plan)) => {
                let restore_steps: Vec<Value> = if action_norm == "restore_plan" {
                    plan.checkpoints
                        .iter()
                        .filter_map(|cp| {
                            cp.snapshot_id.as_ref().map(|sid| {
                                json!({
                                    "workflowId": cp.workflow_id,
                                    "snapshotId": sid,
                                    "restoreCall": {
                                        "tool": "n8n_versions",
                                        "action": "restore",
                                        "workflowId": cp.workflow_id,
                                        "snapshotId": sid,
                                    }
                                })
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                ToolEnvelope::new(
                    OperationStatus::Success,
                    &plan.instance_id,
                    full_action,
                    PermissionDecision::Allowed,
                    RouteUsed::Local,
                )
                .with_warning(RESTORE_SIDE_EFFECTS_DISCLAIMER)
                .with_data(redact_json_value(&json!({
                    "batchPlan": plan,
                    "restoreSteps": restore_steps,
                    "disclaimer": RESTORE_SIDE_EFFECTS_DISCLAIMER,
                })))
            }
            Ok(None) => N8nError::not_found_or_concealed(
                &inst_name,
                format!("batch/{bid}"),
                format!("Batch `{bid}` not found"),
            )
            .into_envelope(&inst_name, full_action, RouteUsed::Local),
            Err(e) => e.into_envelope(&inst_name, full_action, RouteUsed::Local),
        };
    }

    let ops_payload = json!({
        "workflowIds": params.workflow_ids,
        "operations": params.operations,
        "batchId": params.batch_id,
    });

    if action_norm == "preview" {
        let Ok(rt) = state.instance(params.instance.as_deref()) else {
            return N8nError::config("unknown instance").into_envelope(
                inst_name,
                full_action,
                RouteUsed::Local,
            );
        };
        if rt.config.policy_mode == PolicyMode::ReadOnly {
            return N8nError::policy_blocked(
                &full_action,
                RiskLevel::R3,
                "read-only",
                "Bulk codemod preview blocked under `read-only` policy",
                None,
            )
            .into_envelope(&rt.config.alias, full_action, RouteUsed::Local);
        }
        if let Err(e) = enforce_batch_cap(
            params.workflow_ids.len(),
            rt.config.max_batch_workflows.min(MAX_BATCH_WORKFLOWS),
            rt.config.policy_mode.as_str(),
        ) {
            return e.into_envelope(&rt.config.alias, full_action, RouteUsed::Local);
        }
        let Some(ref api) = rt.api_client else {
            return N8nError::unauthenticated(&rt.config.alias, "N8N_API_KEY missing")
                .into_envelope(&rt.config.alias, full_action, RouteUsed::PublicApi);
        };
        let mut targets = Vec::with_capacity(params.workflow_ids.len());
        let mut previews = Vec::with_capacity(params.workflow_ids.len());
        for wf_id in &params.workflow_ids {
            let wf = match api.get_workflow(wf_id, false).await {
                Ok(w) => w,
                Err(e) => {
                    return e.into_envelope(&rt.config.alias, full_action, RouteUsed::PublicApi);
                }
            };
            let (base_ir, base_hash, _) = match workflow_resource_to_ir(&wf) {
                Ok(t) => t,
                Err(e) => return e.into_envelope(&rt.config.alias, full_action, RouteUsed::Local),
            };
            let (_, plan) = match compute_mutated_ir(
                state,
                &rt.config.alias,
                &full_action,
                &base_ir,
                &params.operations,
                &[],
            ) {
                Ok(p) => p,
                Err(env) => return env,
            };
            targets.push((wf_id.clone(), base_hash));
            previews.push(json!({
                "workflowId": wf_id,
                "summary": plan.workflow_diff.diff_summary,
            }));
        }
        let principal = state.principal_for(rt);
        let ops_hash = hash_ops(&ops_payload).unwrap_or_default();
        let summary = params
            .description
            .clone()
            .unwrap_or_else(|| format!("Bulk codemod across {} workflow(s)", targets.len()));
        let batch = {
            let mut jrnl = state.journal.lock().await;
            match jrnl.create_batch_plan(
                &principal,
                &rt.config.alias,
                &summary,
                &ops_hash,
                &targets,
                Some(MAX_BATCH_WORKFLOWS),
            ) {
                Ok(b) => b,
                Err(e) => return e.into_envelope(&rt.config.alias, full_action, RouteUsed::Local),
            }
        };
        let approval_plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal,
            instance: rt.config.alias.clone(),
            action: "bulk_codemod.apply".to_owned(),
            risk: RiskLevel::R3,
            workflow_id: None,
            expected_version_hash: None,
            ops_hash: hash_ops(&json!({
                "batchId": batch.batch_id,
                "operations": params.operations,
            }))
            .unwrap_or_default(),
            summary: summary.clone(),
            diff: Some(BoundedDiffSummary::redacted(
                summary,
                params.workflow_ids.clone(),
                false,
            )),
            diff_payload: json!({ "batchId": batch.batch_id, "previews": previews }),
            side_effects: vec![format!(
                "Mutates {} workflow draft(s) sequentially.",
                targets.len()
            )],
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            &rt.config.alias,
            full_action,
            PermissionDecision::NeedsApproval,
            RouteUsed::PublicApi,
        )
        .with_data(redact_json_value(&json!({
            "batchId": batch.batch_id,
            "planId": approval_plan.plan_id,
            "workflowPreviews": previews,
        })));
    }

    if !matches!(action_norm.as_str(), "apply" | "resume") {
        return N8nError::validation(
            &inst_name,
            vec![format!("unsupported action `{action_norm}`")],
            "Expected `preview`, `apply`, `status`, `resume`, or `restore_plan`",
        )
        .into_envelope(&inst_name, full_action, RouteUsed::Local);
    }

    let Some(ref bid) = params.batch_id else {
        return N8nError::validation(
            &inst_name,
            vec!["missing `batchId`".to_owned()],
            "`batchId` from `preview` is required for `apply` / `resume`",
        )
        .into_envelope(&inst_name, full_action, RouteUsed::Local);
    };
    let batch_record = {
        let jrnl = state.journal.lock().await;
        match jrnl.get_batch_plan(bid) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return N8nError::not_found_or_concealed(
                    &inst_name,
                    format!("batch/{bid}"),
                    "Batch plan not found",
                )
                .into_envelope(&inst_name, full_action, RouteUsed::Local);
            }
            Err(e) => return e.into_envelope(&inst_name, full_action, RouteUsed::Local),
        }
    };

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: "bulk_codemod.apply".to_owned(),
            logical_op: LogicalOperation::BulkCodemod,
            risk: RiskLevel::R3,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload: json!({
                "batchId": bid,
                "operations": params.operations,
            }),
            explicit_apply_intent: true,
            approval_receipt: params.approval_receipt,
            batch_workflow_count: Some(batch_record.target_workflow_ids.len()),
        },
    )
    .await
    {
        Ok(a) => a,
        Err(env) => return env,
    };
    let alias = &auth.rt.config.alias;
    let Some(ref api) = auth.rt.api_client else {
        return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
            alias,
            full_action,
            RouteUsed::PublicApi,
        );
    };

    // Strictly 1 concurrent write at a time, halting on first critical error!
    for cp in &batch_record.checkpoints {
        if cp.status == BatchCheckpointStatus::Verified {
            continue;
        }
        let _lock = state
            .policy_engine
            .lock_registry()
            .acquire_write_lock(alias, &cp.workflow_id)
            .await;
        {
            let mut jrnl = state.journal.lock().await;
            let _ = jrnl.update_batch_checkpoint(
                bid,
                &cp.workflow_id,
                BatchCheckpointStatus::InProgress,
                None,
                None,
                None,
            );
        }

        let step_res: Result<(Option<String>, String), (BatchCheckpointStatus, String)> = async {
            let live = api
                .get_workflow(&cp.workflow_id, false)
                .await
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            let (base_ir, live_hash, _) = workflow_resource_to_ir(&live)
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            if live_hash != cp.expected_version_hash {
                return Err((
                    BatchCheckpointStatus::Conflict,
                    format!(
                        "version drift `{live_hash}` != `{}`",
                        cp.expected_version_hash
                    ),
                ));
            }
            let snap_id = state
                .with_snapshot_vault_mut(|v| {
                    v.capture_snapshot_at(&auth.principal, alias, None, &base_ir, false, Utc::now())
                })
                .ok()
                .map(|s| s.snapshot_id);
            let ctx = state.with_catalog(|db| build_mutation_context_for_ir(&base_ir, db));
            let (after_ir, _) = apply_mutations(&base_ir, &params.operations, &ctx)
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            let body = ir_to_workflow_write_body(&after_ir, false)
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            api.update_workflow(&cp.workflow_id, &body)
                .await
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            let verified = api
                .get_workflow(&cp.workflow_id, false)
                .await
                .map_err(|e| (BatchCheckpointStatus::UnknownResult, e.to_string()))?;
            let (_, after_hash, _) = workflow_resource_to_ir(&verified)
                .map_err(|e| (BatchCheckpointStatus::Failed, e.to_string()))?;
            Ok((snap_id, after_hash))
        }
        .await;

        match step_res {
            Ok((snap_id, after_hash)) => {
                let mut jrnl = state.journal.lock().await;
                let _ = jrnl.update_batch_checkpoint(
                    bid,
                    &cp.workflow_id,
                    BatchCheckpointStatus::Verified,
                    snap_id.as_deref(),
                    Some(&after_hash),
                    None,
                );
            }
            Err((err_status, diag)) => {
                let updated = {
                    let mut jrnl = state.journal.lock().await;
                    jrnl.update_batch_checkpoint(
                        bid,
                        &cp.workflow_id,
                        err_status,
                        None,
                        None,
                        Some(&diag),
                    )
                    .ok()
                };
                return ToolEnvelope::new(
                    OperationStatus::Partial,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_warning(format!(
                    "Halted batch `{bid}` on `{}`: {diag}",
                    cp.workflow_id
                ))
                .with_data(redact_json_value(&json!({ "batchPlan": updated })));
            }
        }
    }

    let final_plan = {
        let jrnl = state.journal.lock().await;
        jrnl.get_batch_plan(bid).ok().flatten()
    };
    ToolEnvelope::new(
        OperationStatus::Success,
        alias,
        full_action,
        auth.policy.permission,
        RouteUsed::PublicApi,
    )
    .with_changed(true)
    .with_verification(VerificationReport::verified([format!(
        "Verified all {} workflow(s) in batch `{bid}`.",
        batch_record.target_workflow_ids.len()
    )]))
    .with_data(redact_json_value(&json!({ "batchPlan": final_plan })))
}

#[allow(clippy::result_large_err)]
fn compute_mutated_ir(
    state: &AppState,
    alias: &str,
    action: &str,
    base_ir: &WorkflowIr,
    ops: &[GraphMutationOp],
    validated_ops: &[ValidatedMutationOp],
) -> Result<(WorkflowIr, MutationPlan), ToolEnvelope<Value>> {
    if ops.is_empty() && validated_ops.is_empty() {
        return Err(N8nError::validation(
            alias,
            vec!["no mutation operations supplied".to_owned()],
            "Provide at least one operation in `operations` or `validatedOperations`",
        )
        .into_envelope(alias, action, RouteUsed::Local));
    }

    let mut current_ir = base_ir.clone();
    for vop in validated_ops {
        let outcome = state.with_catalog(|db| apply_validated_mutation(&current_ir, vop, Some(db)));
        match outcome.status {
            MutationApplyStatus::Applied => {
                current_ir = outcome.updated_workflow;
            }
            MutationApplyStatus::ManualReviewRequired => {
                return Err(ToolEnvelope::new(
                    OperationStatus::Blocked,
                    alias,
                    action,
                    PermissionDecision::Denied,
                    RouteUsed::Local,
                )
                .with_warning(
                    outcome
                        .message
                        .unwrap_or_else(|| "Dynamic expression requires manual review".to_owned()),
                )
                .with_data(redact_json_value(&json!({
                    "manualReviewRequired": true,
                    "blockingExpressions": outcome.blocking_expressions,
                }))));
            }
            MutationApplyStatus::Rejected => {
                return Err(N8nError::validation(
                    alias,
                    vec![outcome.error_code.unwrap_or_default()],
                    outcome
                        .message
                        .unwrap_or_else(|| "Mutation rejected".to_owned()),
                )
                .into_envelope(alias, action, RouteUsed::Local));
            }
        }
    }

    if ops.is_empty() {
        let diff = WorkflowDiff::compute(base_ir, &current_ir, DEFAULT_DIFF_MAX_CHARS);
        let plan = MutationPlan {
            plan_id: "validated_ops".to_owned(),
            expected_version_hash: base_ir.canonical_version_hash(),
            resulting_version_hash: current_ir.canonical_version_hash(),
            requires_whole_array_or_api_fallback: true,
            approval_required: true,
            operation_outcomes: Vec::new(),
            workflow_diff: diff,
            topology_after: WorkflowGraph::from_ir(&current_ir).analyze(),
        };
        return Ok((current_ir, plan));
    }

    let ctx = state.with_catalog(|db| build_mutation_context_for_ir(&current_ir, db));
    match apply_mutations(&current_ir, ops, &ctx) {
        Ok((after_ir, mut plan)) => {
            if !validated_ops.is_empty() {
                plan.expected_version_hash = base_ir.canonical_version_hash();
                plan.workflow_diff =
                    WorkflowDiff::compute(base_ir, &after_ir, DEFAULT_DIFF_MAX_CHARS);
                plan.requires_whole_array_or_api_fallback = true;
            }
            Ok((after_ir, plan))
        }
        Err(GraphMutationError::RenameManualReviewRequired { hazards, .. }) => {
            Err(ToolEnvelope::new(
                OperationStatus::Blocked,
                alias,
                action,
                PermissionDecision::Denied,
                RouteUsed::Local,
            )
            .with_warning(
                "Node rename blocked: dynamic expression reference(s) require manual review.",
            )
            .with_data(redact_json_value(&json!({
                "manualReviewRequired": true,
                "hazards": hazards,
            }))))
        }
        Err(err @ GraphMutationError::MigrationMissing { .. }) => Err(ToolEnvelope::new(
            OperationStatus::Blocked,
            alias,
            action,
            PermissionDecision::Denied,
            RouteUsed::Local,
        )
        .with_warning(err.to_string())
        .with_data(redact_json_value(&json!({
            "migrationMissing": true,
            "error": err,
        })))),
        Err(err) => Err(
            N8nError::validation(alias, vec![err.to_string()], err.to_string()).into_envelope(
                alias,
                action,
                RouteUsed::Local,
            ),
        ),
    }
}
