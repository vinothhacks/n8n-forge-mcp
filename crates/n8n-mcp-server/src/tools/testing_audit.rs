use std::collections::{HashMap, HashSet};

use chrono::Utc;
use n8n_api_client::{ListQueryParams, Outcome};
use n8n_audit::{
    AuditContext, audit_workflow, audit_workflows_batch, merge_live_audit_payload,
    permission_gap_from_live_audit_error,
};
use n8n_capability::LogicalOperation;
use n8n_catalog_db::{NodeInfoMode, NodeInfoRequest};
use n8n_graph::WorkflowIr;
use n8n_policy::{MAX_BATCH_WORKFLOWS, PolicyMode, enforce_batch_cap, hash_ops};
use n8n_state_vault::{FindNodesQuery, JournalState};
use n8n_test_harness::{
    DEFAULT_MAX_REPAIR_ATTEMPTS, ExecutionDetailLevel, ExecutionMinimizeOptions,
    MinimizedExecutionReport, RepairCandidateProposal, RepairConfidence, RepairLoopConfig,
    TestExecutionMode, TestOrchestrator, TestRunRequest, classify_workflow_side_effects,
    run_bounded_repair_loop, summarize_execution_resource_redacted,
};
use n8n_types::{
    DetailLevel, N8nError, OperationStatus, PermissionDecision, RiskLevel, RouteUsed, ToolEnvelope,
    VerificationReport, redact_json_value,
};
use n8n_validator::{ValidationOptions, validate_workflow};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::PreviewPlanInit;
use crate::state::AppState;
use crate::tools::common::{
    AuthorizeSpec, authorize_operation, record_completed_mutation_journal, workflow_resource_to_ir,
};

/// Input schema for Tool #12: `n8n_executions`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionsParams {
    #[serde(default = "default_list_str")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub execution_ids: Vec<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub exec_detail: ExecutionDetailLevel,
    #[serde(default)]
    pub reveal_data: bool,
    #[serde(default)]
    pub load_workflow: bool,
    #[serde(default)]
    pub tag_ids: Vec<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #13: `n8n_test_workflow`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestWorkflowParams {
    #[serde(default = "default_validate_only_str")]
    pub mode: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow: Option<Value>,
    #[serde(default)]
    pub subworkflow_ids: Vec<String>,
    #[serde(default)]
    pub pinned_nodes: Vec<String>,
    #[serde(default)]
    pub pin_data: Option<Value>,
    #[serde(default)]
    pub trigger_node: Option<String>,
    #[serde(default)]
    pub input_data: Option<Value>,
    #[serde(default)]
    pub staging_webhook_url: Option<String>,
    #[serde(default)]
    pub allowlisted_staging_webhooks: Vec<String>,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub repair_proposals: Vec<RepairCandidateProposal>,
    #[serde(default)]
    pub max_attempts: Option<u8>,
    #[serde(default)]
    pub session_override_approved: bool,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #14: `n8n_evaluations`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationsParams {
    #[serde(default = "default_list_runs_str")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    pub workflow_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #15: `n8n_explore_resources`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExploreResourcesParams {
    #[serde(default = "default_local_refs_str")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub type_version: Option<String>,
    #[serde(default)]
    pub property_name: Option<String>,
    #[serde(default)]
    pub parameters: Option<Value>,
    #[serde(default)]
    pub allow_external_network: bool,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #19: `n8n_audit`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditParams {
    #[serde(default = "default_workflow_str")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow_ids: Vec<String>,
    #[serde(default)]
    pub workflow: Option<Value>,
    #[serde(default)]
    pub include_live_audit: bool,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub detail: DetailLevel,
}

fn default_list_str() -> String {
    "list".to_owned()
}
fn default_validate_only_str() -> String {
    "validate_only".to_owned()
}
fn default_list_runs_str() -> String {
    "list_runs".to_owned()
}
fn default_local_refs_str() -> String {
    "local_references".to_owned()
}
fn default_workflow_str() -> String {
    "workflow".to_owned()
}

/// Tool #12: `n8n_executions`.
#[allow(clippy::too_many_lines)]
pub async fn execute_executions(state: &AppState, params: ExecutionsParams) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("executions.{action_norm}");
    let wants_expanded = params.exec_detail != ExecutionDetailLevel::Summary;
    if action_norm == "get" && wants_expanded && !params.reveal_data {
        let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
        return N8nError::policy_blocked(
            &full_action,
            RiskLevel::R3,
            "data-minimization",
            "Execution `node_io` / `full` inspection requires explicit `revealData: true`",
            Some("Use default `execDetail = \"summary\"` or pass `revealData: true`.".to_owned()),
        )
        .into_envelope(inst, full_action, RouteUsed::Local);
    }

    let (logical_op, risk) = match action_norm.as_str() {
        "list" | "tags_get" => (LogicalOperation::ExecutionsRead, RiskLevel::R0),
        "get" => (
            LogicalOperation::ExecutionsRead,
            if wants_expanded {
                RiskLevel::R2
            } else {
                RiskLevel::R0
            },
        ),
        "tags_update" => (LogicalOperation::ExecutionsControl, RiskLevel::R2),
        "retry" | "stop" => (LogicalOperation::ExecutionsControl, RiskLevel::R3),
        "stop_many" | "delete" => (LogicalOperation::ExecutionsControl, RiskLevel::R4),
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unsupported action `{other}`")],
                "Expected `list`, `get`, `retry`, `stop`, `stop_many`, `delete`, `tags_get`, or `tags_update`",
            )
            .into_envelope(inst, "executions.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "executionId": params.execution_id,
        "executionIds": params.execution_ids,
        "loadWorkflow": params.load_workflow,
        "tagIds": params.tag_ids,
    });

    if params.preview && risk.is_mutating() {
        let Ok(rt) = state.instance(params.instance.as_deref()) else {
            return N8nError::config("unknown instance").into_envelope(
                &state.active_instance,
                full_action,
                RouteUsed::Local,
            );
        };
        if rt.config.policy_mode == PolicyMode::ReadOnly {
            return N8nError::policy_blocked(
                &full_action,
                risk,
                "read-only",
                "Mutating execution control blocked in read-only mode",
                None,
            )
            .into_envelope(&rt.config.alias, full_action, RouteUsed::Local);
        }
        let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal: state.principal_for(rt),
            instance: rt.config.alias.clone(),
            action: full_action.clone(),
            risk,
            workflow_id: params.workflow_id.clone(),
            expected_version_hash: None,
            ops_hash: hash_ops(&ops_payload).unwrap_or_default(),
            summary: format!("Preview `{full_action}`"),
            diff: None,
            diff_payload: ops_payload,
            side_effects: vec![format!("Execution control ({})", risk.label())],
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            &rt.config.alias,
            full_action,
            PermissionDecision::NeedsApproval,
            RouteUsed::Local,
        )
        .with_data(json!({ "planId": plan.plan_id, "expiresAt": plan.expires_at }));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op,
            risk,
            workflow_id: params.workflow_id.clone(),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: risk == RiskLevel::R2,
            approval_receipt: params.approval_receipt.clone(),
            batch_workflow_count: (action_norm == "stop_many")
                .then_some(params.execution_ids.len()),
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

    match action_norm.as_str() {
        "list" => match api
            .list_executions(
                params.workflow_id.as_deref(),
                params.status.as_deref(),
                false,
                Some(params.limit.unwrap_or(20).clamp(1, 100)),
                params.cursor.as_deref(),
            )
            .await
        {
            Ok(page) => {
                let items: Vec<_> = page
                    .data
                    .iter()
                    .filter_map(|ex| {
                        summarize_execution_resource_redacted(
                            ex,
                            &ExecutionMinimizeOptions::summary_only(),
                        )
                        .ok()
                    })
                    .collect();
                ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_data(redact_json_value(&json!({
                    "items": items,
                    "count": items.len(),
                    "nextCursor": page.next_cursor,
                })))
            }
            Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
        },
        "get" => {
            let Some(ref eid) = params.execution_id else {
                return missing_param(alias, &full_action, "executionId");
            };
            let min_opts = if wants_expanded {
                ExecutionMinimizeOptions::with_authorized_reveal(params.exec_detail)
            } else {
                ExecutionMinimizeOptions::summary_only()
            };
            match api.get_execution(eid, wants_expanded).await {
                Ok(ex) => match summarize_execution_resource_redacted(&ex, &min_opts) {
                    Ok(rep) => ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(ex.workflow_id)
                    .with_data(redact_json_value(&json!({ "execution": rep }))),
                    Err(e) => e.into_envelope(alias, full_action, RouteUsed::Local),
                },
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "tags_get" => {
            let Some(ref eid) = params.execution_id else {
                return missing_param(alias, &full_action, "executionId");
            };
            match api.get_execution_tags(eid).await {
                Ok(tags) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_data(redact_json_value(&json!({ "tags": tags }))),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "tags_update" => {
            let Some(ref eid) = params.execution_id else {
                return missing_param(alias, &full_action, "executionId");
            };
            match api.update_execution_tags(eid, &params.tag_ids).await {
                Ok(tags) => {
                    record_completed_mutation_journal(
                        state,
                        &auth.principal,
                        alias,
                        params.workflow_id.as_deref(),
                        &full_action,
                        None,
                        None,
                        &auth.ops_hash,
                        JournalState::Verified,
                        json!({"executionId": eid}),
                    )
                    .await;
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_changed(true)
                    .with_data(redact_json_value(&json!({ "tags": tags })))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "retry" | "stop" | "delete" => {
            let Some(ref eid) = params.execution_id else {
                return missing_param(alias, &full_action, "executionId");
            };
            let res: Result<Value, N8nError> = match action_norm.as_str() {
                "retry" => api.retry_execution(eid, params.load_workflow).await,
                "stop" => api
                    .stop_execution(eid)
                    .await
                    .map(|r| json!({"id": r.id, "status": r.status})),
                _ => api
                    .delete_execution(eid)
                    .await
                    .map(|r| json!({"deletedId": r.id})),
            };
            match res {
                Ok(val) => {
                    record_completed_mutation_journal(
                        state,
                        &auth.principal,
                        alias,
                        params.workflow_id.as_deref(),
                        &full_action,
                        None,
                        None,
                        &auth.ops_hash,
                        JournalState::Verified,
                        json!({"executionId": eid}),
                    )
                    .await;
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_changed(true)
                    .with_data(redact_json_value(&val))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "stop_many" => {
            if let Err(e) = enforce_batch_cap(
                params.execution_ids.len(),
                MAX_BATCH_WORKFLOWS,
                auth.rt.config.policy_mode.as_str(),
            ) {
                return e.into_envelope(alias, full_action, RouteUsed::Local);
            }
            let mut stopped = Vec::new();
            for eid in &params.execution_ids {
                match api.stop_execution(eid).await {
                    Ok(r) => stopped.push(r.id),
                    Err(e) => {
                        return ToolEnvelope::new(
                            OperationStatus::Partial,
                            alias,
                            full_action,
                            auth.policy.permission,
                            RouteUsed::PublicApi,
                        )
                        .with_warning(format!("Halted `stop_many` at `{eid}`: {e}"))
                        .with_data(json!({ "stoppedIds": stopped }));
                    }
                }
            }
            ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_changed(!stopped.is_empty())
            .with_data(json!({ "stoppedIds": stopped }))
        }
        _ => unreachable!(),
    }
}

/// Tool #13: `n8n_test_workflow`.
#[allow(clippy::too_many_lines)]
pub async fn execute_test_workflow(
    state: &AppState,
    params: TestWorkflowParams,
) -> ToolEnvelope<Value> {
    let mode_norm = params.mode.trim().to_ascii_lowercase();
    let rt = match state.instance(params.instance.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            return e.into_envelope(
                params.instance.as_deref().unwrap_or(&state.active_instance),
                format!("test_workflow.{mode_norm}"),
                RouteUsed::Local,
            );
        }
    };
    let alias = &rt.config.alias;
    let principal = state.principal_for(rt);

    let ir = if let Some(ref wf_json) = params.workflow {
        match WorkflowIr::from_json_value(wf_json.clone()) {
            Ok(ir) => ir,
            Err(e) => {
                return N8nError::validation(alias, vec![e.to_string()], "Invalid workflow JSON")
                    .into_envelope(
                        alias,
                        format!("test_workflow.{mode_norm}"),
                        RouteUsed::Local,
                    );
            }
        }
    } else if let Some(ref wf_id) = params.workflow_id {
        let Some(ref api) = rt.api_client else {
            return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
                alias,
                format!("test_workflow.{mode_norm}"),
                RouteUsed::PublicApi,
            );
        };
        let wf = match api.get_workflow(wf_id, false).await {
            Ok(w) => w,
            Err(e) => {
                return e.into_envelope(
                    alias,
                    format!("test_workflow.{mode_norm}"),
                    RouteUsed::PublicApi,
                );
            }
        };
        match workflow_resource_to_ir(&wf) {
            Ok((ir, _, _)) => ir,
            Err(e) => {
                return e.into_envelope(
                    alias,
                    format!("test_workflow.{mode_norm}"),
                    RouteUsed::Local,
                );
            }
        }
    } else {
        return missing_param(alias, &format!("test_workflow.{mode_norm}"), "workflowId");
    };

    let mut subworkflows = HashMap::new();
    if let Some(ref api) = rt.api_client {
        for sub_id in &params.subworkflow_ids {
            if let Ok(swf) = api.get_workflow(sub_id, false).await
                && let Ok((sub_ir, _, _)) = workflow_resource_to_ir(&swf)
            {
                subworkflows.insert(sub_id.clone(), sub_ir);
            }
        }
    }

    let mut orchestrator = TestOrchestrator::new(rt.config.clone(), state.policy_engine.clone())
        .with_allowlisted_staging_webhooks(params.allowlisted_staging_webhooks.clone());
    if let Ok(caps) = state.resolve_instance_capabilities(rt, false).await {
        orchestrator = orchestrator.with_capabilities(caps);
    }
    if let Some(ref api) = rt.api_client {
        orchestrator = orchestrator.with_api_client(api.clone());
    }
    if let Some(ref bridge) = rt.mcp_bridge {
        orchestrator = orchestrator.with_mcp_bridge(bridge.clone());
    }

    if mode_norm == "diagnose_repair" {
        let cfg = match RepairLoopConfig::new(
            params.max_attempts.unwrap_or(DEFAULT_MAX_REPAIR_ATTEMPTS),
            params.session_override_approved,
        ) {
            Ok(c) => c,
            Err(e) => {
                return e.into_envelope(alias, "test_workflow.diagnose_repair", RouteUsed::Local);
            }
        };
        let initial_summary = if let (Some(eid), Some(api)) = (&params.execution_id, &rt.api_client)
        {
            match api.get_execution(eid, false).await {
                Ok(ex) => match summarize_execution_resource_redacted(
                    &ex,
                    &ExecutionMinimizeOptions::summary_only(),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return e.into_envelope(
                            alias,
                            "test_workflow.diagnose_repair",
                            RouteUsed::Local,
                        );
                    }
                },
                Err(e) => {
                    return e.into_envelope(
                        alias,
                        "test_workflow.diagnose_repair",
                        RouteUsed::PublicApi,
                    );
                }
            }
        } else {
            MinimizedExecutionReport {
                detail_level: ExecutionDetailLevel::Summary,
                execution_id: None,
                workflow_id: ir.id.clone(),
                status: "error".to_owned(),
                finished: true,
                is_terminal_success: false,
                duration_ms: None,
                failed_node: ir.nodes.first().map(|n| n.name.clone()),
                error_class: Some("ValidationOrSimulationCheck".to_owned()),
                error_message_redacted: Some("Initial diagnostic check".to_owned()),
                upstream_item_schemas: Default::default(),
                node_io: None,
                full_data: None,
                redacted: true,
                observed_payload_bytes: 0,
                notes: Vec::new(),
            }
        };

        let mut proposals_iter = params.repair_proposals.into_iter();
        let handle = tokio::runtime::Handle::current();
        let loop_res =
            tokio::task::spawn_blocking(move || {
                handle.block_on(run_bounded_repair_loop(
                    cfg,
                    ir,
                    initial_summary,
                    None,
                    move |_ctx, _wf| {
                        Ok(proposals_iter.next().unwrap_or(RepairCandidateProposal {
                            confidence: RepairConfidence::Low,
                            rationale: "No further candidate mutations supplied.".to_owned(),
                            mutations: Vec::new(),
                            verification_mode: TestExecutionMode::ValidateOnly,
                        }))
                    },
                    |ver_mode, candidate_ir| {
                        let orch = &orchestrator;
                        let pr = principal.clone();
                        async move {
                            let req = TestRunRequest::new(ver_mode, pr, candidate_ir);
                            let run_res = orch.run_test(&req, None).await?;
                            let summary = run_res.execution_summary.clone().unwrap_or(
                                MinimizedExecutionReport {
                                    detail_level: ExecutionDetailLevel::Summary,
                                    execution_id: None,
                                    workflow_id: run_res.workflow_id.clone(),
                                    status: format!("{:?}", run_res.status),
                                    finished: true,
                                    is_terminal_success: false,
                                    duration_ms: None,
                                    failed_node: None,
                                    error_class: None,
                                    error_message_redacted: None,
                                    upstream_item_schemas: Default::default(),
                                    node_io: None,
                                    full_data: None,
                                    redacted: true,
                                    observed_payload_bytes: 0,
                                    notes: Vec::new(),
                                },
                            );
                            Ok((run_res, summary))
                        }
                    },
                ))
            })
            .await
            .map_err(|e| N8nError::protocol(format!("repair task join error: {e}")))
            .and_then(|r| r);

        return match loop_res {
            Ok(outcome) => ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                "test_workflow.diagnose_repair",
                PermissionDecision::Allowed,
                RouteUsed::Local,
            )
            .with_data(redact_json_value(&json!({ "repairOutcome": outcome }))),
            Err(e) => e.into_envelope(alias, "test_workflow.diagnose_repair", RouteUsed::Local),
        };
    }

    let exec_mode = match mode_norm.as_str() {
        "validate_only" | "t0" => TestExecutionMode::ValidateOnly,
        "simulate" | "t1" => TestExecutionMode::Simulate,
        "manual" | "t2" => TestExecutionMode::Manual,
        "production" | "t3" => TestExecutionMode::Production,
        other => {
            return N8nError::validation(
                alias,
                vec![format!("unsupported test mode `{other}`")],
                "Expected `validate_only`, `simulate`, `manual`, `production`, or `diagnose_repair`",
            )
            .into_envelope(alias, "test_workflow.unknown", RouteUsed::Local);
        }
    };

    let pinned_set: HashSet<String> = params.pinned_nodes.into_iter().collect();
    let side_effects = classify_workflow_side_effects(
        &ir,
        &subworkflows,
        &pinned_set,
        params.trigger_node.as_deref(),
    );

    let mut req = TestRunRequest::new(exec_mode, principal.clone(), ir.clone());
    req.workflow_id = params.workflow_id.or_else(|| ir.id.clone());
    req.subworkflows = subworkflows;
    req.pinned_nodes = pinned_set;
    req.pin_data = params.pin_data;
    req.trigger_node = params.trigger_node;
    req.input_data = params.input_data;
    req.staging_webhook_url = params.staging_webhook_url;
    req.approval_receipt_token = params.approval_receipt;

    if params.preview
        && matches!(
            exec_mode,
            TestExecutionMode::Manual | TestExecutionMode::Production
        )
    {
        if rt.config.policy_mode == PolicyMode::ReadOnly {
            return N8nError::policy_blocked(
                exec_mode.receipt_action(),
                RiskLevel::R3,
                "read-only",
                "Execution preview blocked under `read-only` policy",
                None,
            )
            .into_envelope(alias, exec_mode.receipt_action(), RouteUsed::Local);
        }
        let ops_hash = req.compute_ops_hash().unwrap_or_default();
        let ver_hash = ir.canonical_version_hash();
        let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal,
            instance: alias.clone(),
            action: exec_mode.receipt_action().to_owned(),
            risk: RiskLevel::R3,
            workflow_id: req.workflow_id.clone(),
            expected_version_hash: Some(ver_hash),
            ops_hash,
            summary: format!(
                "Execute workflow in `{}` ({}) mode",
                exec_mode.as_str(),
                exec_mode.tier_code()
            ),
            diff: None,
            diff_payload: json!({ "sideEffects": side_effects }),
            side_effects: side_effects.blocking_reasons.clone(),
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            alias,
            exec_mode.receipt_action(),
            PermissionDecision::NeedsApproval,
            RouteUsed::Local,
        )
        .with_workflow_id(req.workflow_id)
        .with_data(redact_json_value(&json!({
            "planId": plan.plan_id,
            "tier": exec_mode.tier_code(),
            "sideEffectClassification": side_effects,
            "expiresAt": plan.expires_at,
        })));
    }

    let catalog_val = state.with_catalog(|db| {
        validate_workflow(&req.workflow, Some(db), &ValidationOptions::default())
    });
    let alias_owned = alias.clone();
    let handle = tokio::runtime::Handle::current();
    let mut env = match tokio::task::spawn_blocking(move || {
        handle.block_on(orchestrator.run_test_envelope(&req, None))
    })
    .await
    {
        Ok(env) => env,
        Err(e) => {
            return N8nError::protocol(format!("test runner join error: {e}")).into_envelope(
                alias_owned,
                exec_mode.receipt_action(),
                RouteUsed::Local,
            );
        }
    };
    if exec_mode == TestExecutionMode::ValidateOnly && !catalog_val.valid {
        env.status = OperationStatus::Error;
        if let Some(ref mut d) = env.data
            && let Some(obj) = d.as_object_mut()
        {
            obj.insert(
                "catalogValidation".to_owned(),
                redact_json_value(&serde_json::to_value(catalog_val).unwrap_or(Value::Null)),
            );
        }
    }
    env
}

/// Tool #14: `n8n_evaluations`.
pub async fn execute_evaluations(
    state: &AppState,
    params: EvaluationsParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("evaluations.{action_norm}");
    let risk = match action_norm.as_str() {
        "list_runs" | "get_run" | "get_cases" => RiskLevel::R0,
        "cancel_run" => RiskLevel::R2,
        "create_run" => RiskLevel::R3,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unsupported action `{other}`")],
                "Expected `list_runs`, `get_run`, `get_cases`, `create_run`, or `cancel_run`",
            )
            .into_envelope(inst, "evaluations.unknown", RouteUsed::Local);
        }
    };
    let ops_payload = json!({
        "action": action_norm,
        "workflowId": params.workflow_id,
        "runId": params.run_id,
        "body": params.body,
    });

    if params.preview && risk.is_mutating() {
        let Ok(rt) = state.instance(params.instance.as_deref()) else {
            return N8nError::config("unknown instance").into_envelope(
                &state.active_instance,
                full_action,
                RouteUsed::Local,
            );
        };
        let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal: state.principal_for(rt),
            instance: rt.config.alias.clone(),
            action: full_action.clone(),
            risk,
            workflow_id: Some(params.workflow_id.clone()),
            expected_version_hash: None,
            ops_hash: hash_ops(&ops_payload).unwrap_or_default(),
            summary: format!("Evaluation `{full_action}` on `{}`", params.workflow_id),
            diff: None,
            diff_payload: ops_payload,
            side_effects: vec!["Triggers evaluation test run across cases.".to_owned()],
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            &rt.config.alias,
            full_action,
            PermissionDecision::NeedsApproval,
            RouteUsed::Local,
        )
        .with_workflow_id(Some(params.workflow_id))
        .with_data(json!({ "planId": plan.plan_id, "expiresAt": plan.expires_at }));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::Evaluations,
            risk,
            workflow_id: Some(params.workflow_id.clone()),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: risk == RiskLevel::R2,
            approval_receipt: params.approval_receipt,
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
            full_action,
            RouteUsed::PublicApi,
        );
    };

    match action_norm.as_str() {
        "list_runs" => match api.list_test_runs(&params.workflow_id).await {
            Ok(v) => ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(params.workflow_id))
            .with_data(redact_json_value(&v)),
            Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
        },
        "get_run" | "get_cases" => {
            let Some(ref rid) = params.run_id else {
                return missing_param(alias, &full_action, "runId");
            };
            match api.get_test_run(&params.workflow_id, rid).await {
                Ok(v) => {
                    let projected = if action_norm == "get_cases" {
                        json!({
                            "runId": rid,
                            "cases": v.get("testCases").or_else(|| v.get("cases")).unwrap_or(&v),
                        })
                    } else {
                        v
                    };
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(Some(params.workflow_id))
                    .with_data(redact_json_value(&projected))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "create_run" => {
            let op_id = params
                .operation_id
                .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));
            let body = params.body.unwrap_or_else(|| json!({}));
            match api.start_test_run(&op_id, &params.workflow_id, &body).await {
                Ok(Outcome::Confirmed { value }) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_workflow_id(Some(params.workflow_id))
                .with_changed(true)
                .with_data(redact_json_value(&value)),
                Ok(Outcome::UnknownNeedsReconcile {
                    operation_id,
                    idempotency_key,
                    reason,
                    ..
                }) => ToolEnvelope::new(
                    OperationStatus::Partial,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_warning(reason)
                .with_verification(VerificationReport::inconclusive([
                    "Evaluation POST timed out; inspect `list_runs` before retrying.".to_owned(),
                ]))
                .with_data(json!({
                    "operationId": operation_id,
                    "idempotencyKey": idempotency_key,
                })),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "cancel_run" => {
            let Some(ref rid) = params.run_id else {
                return missing_param(alias, &full_action, "runId");
            };
            match api.cancel_test_run(&params.workflow_id, rid).await {
                Ok(v) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_workflow_id(Some(params.workflow_id))
                .with_changed(true)
                .with_data(redact_json_value(&v)),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        _ => unreachable!(),
    }
}

/// Tool #15: `n8n_explore_resources`.
pub async fn execute_explore_resources(
    state: &AppState,
    params: ExploreResourcesParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let inst_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    if action_norm == "local_references" {
        let catalog_part = if let Some(ref nt) = params.node_type {
            let p_val = params.parameters.clone().unwrap_or_else(|| json!({}));
            state
                .with_catalog(|db| {
                    let eff = db.inspect_effective_node_fields(
                        nt,
                        params.type_version.as_deref(),
                        &p_val,
                    )?;
                    let ops = db.get_node_info(&NodeInfoRequest {
                        node_type: nt.clone(),
                        mode: NodeInfoMode::Info,
                        type_version: params.type_version.clone(),
                        property_query: params.property_name.clone(),
                    })?;
                    Ok::<_, N8nError>(json!({
                        "effectiveFields": eff,
                        "operations": ops.operations,
                        "credentials": ops.credentials,
                    }))
                })
                .ok()
        } else {
            None
        };

        let index_hits = state
            .instance(params.instance.as_deref())
            .ok()
            .and_then(|rt| {
                let mut q = FindNodesQuery::new(state.principal_for(rt), &rt.config.alias);
                q.node_type.clone_from(&params.node_type);
                q.max_results = 25;
                state
                    .with_workflow_index(|idx| idx.find_nodes_at(&q, Utc::now()))
                    .ok()
            });

        return ToolEnvelope::new(
            OperationStatus::Success,
            inst_name,
            "explore_resources.local_references",
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_data(redact_json_value(&json!({
            "catalogOptions": catalog_part,
            "indexedUsage": index_hits,
        })));
    }

    if !matches!(action_norm.as_str(), "load_options" | "list_search") {
        return N8nError::validation(
            &inst_name,
            vec![format!("unsupported action `{action_norm}`")],
            "Expected `local_references`, `load_options`, or `list_search`",
        )
        .into_envelope(&inst_name, "explore_resources.unknown", RouteUsed::Local);
    }

    if !params.allow_external_network {
        return N8nError::policy_blocked(
            format!("explore_resources.{action_norm}"),
            RiskLevel::R1,
            "external-network-gate",
            "Dynamic `load_options` / `list_search` requires `allowExternalNetwork: true` because n8n queries external third-party APIs using bound credentials",
            Some("Use `action = \"local_references\"` offline or explicitly pass `allowExternalNetwork: true`.".to_owned()),
        )
        .into_envelope(
            inst_name,
            format!("explore_resources.{action_norm}"),
            RouteUsed::Local,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: format!("explore_resources.{action_norm}"),
            logical_op: LogicalOperation::ExploreResources,
            risk: RiskLevel::R1,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload: json!({"action": action_norm, "nodeType": params.node_type}),
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
    let Some(ref bridge) = auth.rt.mcp_bridge else {
        return N8nError::unsupported(
            alias,
            format!("explore_resources.{action_norm}"),
            "Dynamic resource locator inspection requires Instance-level Native MCP (`/mcp-server/http`)",
            Some("Use `action = \"local_references\"` for offline catalog schemas.".to_owned()),
        )
        .into_envelope(
            alias,
            format!("explore_resources.{action_norm}"),
            RouteUsed::Unsupported,
        );
    };

    match bridge.handshake_and_list_tools().await {
        Ok(neg) => N8nError::unsupported(
            alias,
            format!("explore_resources.{action_norm}"),
            format!(
                "Connected Native MCP server advertises {} tool(s) without `{action_norm}`",
                neg.advertised_tool_names.len()
            ),
            Some(
                "Use `action = \"local_references\"` to inspect static options and catalog fields."
                    .to_owned(),
            ),
        )
        .into_envelope(
            alias,
            format!("explore_resources.{action_norm}"),
            RouteUsed::Unsupported,
        ),
        Err(e) => e.into_envelope(
            alias,
            format!("explore_resources.{action_norm}"),
            RouteUsed::NativeMcp,
        ),
    }
}

/// Tool #19: `n8n_audit`.
pub async fn execute_audit(state: &AppState, params: AuditParams) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let inst_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    // Offline single-workflow JSON audit (no live API needed unless `include_live_audit`)
    if let Some(ref wf_val) = params.workflow
        && !params.include_live_audit
    {
        let ir = match WorkflowIr::from_json_value(wf_val.clone()) {
            Ok(ir) => ir,
            Err(e) => {
                return N8nError::validation(
                    &inst_name,
                    vec![e.to_string()],
                    "Invalid workflow JSON",
                )
                .into_envelope(&inst_name, "audit.workflow", RouteUsed::Local);
            }
        };
        let report = state.with_catalog(|db| {
            let ctx = AuditContext {
                catalog: Some(db),
                ..AuditContext::default()
            };
            audit_workflow(&ir, &ctx)
        });
        return ToolEnvelope::new(
            OperationStatus::Success,
            inst_name,
            "audit.workflow",
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_data(redact_json_value(&json!({ "audit": report })));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: format!("audit.{action_norm}"),
            logical_op: LogicalOperation::Audit,
            risk: RiskLevel::R0,
            workflow_id: params.workflow_id.clone(),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload: json!({"action": action_norm, "workflowId": params.workflow_id}),
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
            format!("audit.{action_norm}"),
            RouteUsed::PublicApi,
        );
    };
    let live_advertised = Some(
        auth.caps
            .has_rest_resource(&["audit"], &["/audit", "/api/v1/audit"]),
    );

    if action_norm == "batch" || (params.workflow_id.is_none() && params.workflow.is_none()) {
        let mut irs = Vec::new();
        let mut inaccessible = HashSet::new();
        if !params.workflow_ids.is_empty() {
            for id in &params.workflow_ids {
                match api.get_workflow(id, true).await {
                    Ok(wf) => {
                        if let Ok((ir, _, _)) = workflow_resource_to_ir(&wf) {
                            irs.push(ir);
                        }
                    }
                    Err(_) => {
                        inaccessible.insert(id.clone());
                    }
                }
            }
        } else {
            let page = match api
                .list_workflows(&ListQueryParams {
                    limit: Some(params.limit.unwrap_or(20).clamp(1, 100)),
                    exclude_pinned_data: Some(true),
                    ..ListQueryParams::default()
                })
                .await
            {
                Ok(p) => p,
                Err(e) => return e.into_envelope(alias, "audit.batch", RouteUsed::PublicApi),
            };
            for wf in &page.data {
                if let Ok((ir, _, _)) = workflow_resource_to_ir(wf) {
                    irs.push(ir);
                }
            }
        }
        let mut batch_report = state.with_catalog(|db| {
            let ctx = AuditContext {
                catalog: Some(db),
                inaccessible_workflow_ids: inaccessible,
                live_audit_advertised: live_advertised,
                ..AuditContext::default()
            };
            audit_workflows_batch(&irs, &ctx)
        });
        if params.include_live_audit {
            match api.generate_audit(params.categories.as_deref()).await {
                Ok(live) => merge_live_audit_payload(&mut batch_report.combined, &live),
                Err(e) => {
                    if let Some(gap) = permission_gap_from_live_audit_error(&e) {
                        batch_report.combined.permission_gaps.push(gap);
                    }
                }
            }
        }
        return ToolEnvelope::new(
            OperationStatus::Success,
            alias,
            "audit.batch",
            auth.policy.permission,
            RouteUsed::PublicApi,
        )
        .with_data(redact_json_value(&json!({ "batchAudit": batch_report })));
    }

    let ir = if let Some(ref wf_val) = params.workflow {
        match WorkflowIr::from_json_value(wf_val.clone()) {
            Ok(ir) => ir,
            Err(e) => {
                return N8nError::validation(alias, vec![e.to_string()], "Invalid workflow JSON")
                    .into_envelope(alias, "audit.workflow", RouteUsed::Local);
            }
        }
    } else if let Some(ref wf_id) = params.workflow_id {
        match api.get_workflow(wf_id, true).await {
            Ok(wf) => match workflow_resource_to_ir(&wf) {
                Ok((ir, _, _)) => ir,
                Err(e) => return e.into_envelope(alias, "audit.workflow", RouteUsed::Local),
            },
            Err(e) => return e.into_envelope(alias, "audit.workflow", RouteUsed::PublicApi),
        }
    } else {
        return missing_param(alias, "audit.workflow", "workflowId");
    };

    let mut report = state.with_catalog(|db| {
        let ctx = AuditContext {
            catalog: Some(db),
            live_audit_advertised: live_advertised,
            ..AuditContext::default()
        };
        audit_workflow(&ir, &ctx)
    });
    if params.include_live_audit {
        match api.generate_audit(params.categories.as_deref()).await {
            Ok(live) => merge_live_audit_payload(&mut report, &live),
            Err(e) => {
                if let Some(gap) = permission_gap_from_live_audit_error(&e) {
                    report.permission_gaps.push(gap);
                }
            }
        }
    }

    ToolEnvelope::new(
        OperationStatus::Success,
        alias,
        "audit.workflow",
        auth.policy.permission,
        RouteUsed::PublicApi,
    )
    .with_workflow_id(ir.id)
    .with_data(redact_json_value(&json!({ "audit": report })))
}

fn missing_param(alias: &str, full_action: &str, field: &str) -> ToolEnvelope<Value> {
    N8nError::validation(
        alias,
        vec![format!("missing `{field}`")],
        format!("`{field}` is required for `{full_action}`"),
    )
    .into_envelope(alias, full_action, RouteUsed::Local)
}
