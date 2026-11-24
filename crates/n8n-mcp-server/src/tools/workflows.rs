use std::collections::BTreeMap;

use chrono::Utc;
use n8n_api_client::{ListQueryParams, Outcome};
use n8n_capability::{LogicalOperation, verify_fallback_allowed};
use n8n_catalog_db::TemplateDetailMode;
use n8n_graph::{DEFAULT_DIFF_MAX_CHARS, NodeCredentialRef, WorkflowDiff, WorkflowIr};
use n8n_policy::{PolicyMode, hash_ops};
use n8n_state_vault::{JournalState, RESTORE_SIDE_EFFECTS_DISCLAIMER};
use n8n_types::{
    BoundedDiffSummary, DetailLevel, N8nError, N8nResult, OperationStatus, PermissionDecision,
    RiskLevel, RouteUsed, ToolEnvelope, VerificationReport, redact_json_value,
};
use n8n_validator::{ValidationOptions, validate_workflow};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::PreviewPlanInit;
use crate::state::AppState;
use crate::tools::common::{
    AuthorizeSpec, authorize_operation, compute_json_version_hash, format_workflow_view,
    ir_to_workflow_write_body, record_completed_mutation_journal, workflow_resource_to_ir,
};

/// Input schema for Tool #5: `n8n_workflows`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowsParams {
    pub action: String,
    pub instance: Option<String>,
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub active: Option<bool>,
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub workflow: Option<Value>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default)]
    pub destination_project_id: Option<String>,
    #[serde(default)]
    pub tag_ids: Vec<String>,
    #[serde(default)]
    pub publish_body: Option<Value>,
    #[serde(default)]
    pub expected_version_hash: Option<String>,
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub preview: bool,
}

/// Input schema for Tool #10: `n8n_versions`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionsParams {
    #[serde(default = "default_history_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    pub workflow_id: String,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub compare_version_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub expected_version_hash: Option<String>,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Non-secret credential reference `(id, name)` supplied to `n8n_deploy_template`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRefBinding {
    pub id: String,
    pub name: String,
}

/// Input schema for Tool #11: `n8n_deploy_template`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeployTemplateParams {
    #[serde(default)]
    pub instance: Option<String>,
    pub template_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub credential_bindings: BTreeMap<String, CredentialRefBinding>,
    #[serde(default = "default_preview_mode")]
    pub mode: String,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

fn default_history_action() -> String {
    "history".to_owned()
}

fn default_preview_mode() -> String {
    "preview".to_owned()
}

/// Tool #5: `n8n_workflows`.
#[allow(clippy::too_many_lines)]
pub async fn execute_workflows(state: &AppState, params: WorkflowsParams) -> ToolEnvelope<Value> {
    let raw_action = params.action.trim().to_ascii_lowercase();
    let action_norm = if raw_action == "update_meta" {
        "update_metadata".to_owned()
    } else {
        raw_action
    };

    if action_norm == "confirm_plan" {
        return handle_confirm_plan(state, &params);
    }

    let (logical_op, risk) = match action_norm.as_str() {
        "list" | "get" | "tags_get" | "dependencies" => {
            (LogicalOperation::WorkflowsRead, RiskLevel::R0)
        }
        "create" | "clone" => (LogicalOperation::WorkflowsCreate, RiskLevel::R2),
        "update_metadata" | "archive" | "unarchive" | "tags_update" => {
            (LogicalOperation::WorkflowsMutate, RiskLevel::R2)
        }
        "publish" | "unpublish" | "activate" | "deactivate" | "transfer" => {
            (LogicalOperation::WorkflowsPublish, RiskLevel::R3)
        }
        "delete" => (LogicalOperation::WorkflowsDelete, RiskLevel::R4),
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unsupported workflow action `{other}`")],
                format!("Unknown `n8n_workflows` action `{other}`"),
            )
            .into_envelope(inst, "workflows.unknown", RouteUsed::Local);
        }
    };

    let full_action = format!("workflows.{action_norm}");
    let ops_payload = json!({
        "action": action_norm,
        "workflowId": params.workflow_id,
        "name": params.name,
        "destinationProjectId": params.destination_project_id,
        "tagIds": params.tag_ids,
        "publishBody": params.publish_body,
    });

    if params.preview && risk.is_mutating() {
        return create_workflow_action_preview(state, &params, &full_action, risk, &ops_payload);
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op,
            risk,
            workflow_id: params.workflow_id.clone(),
            project_id: params.destination_project_id.clone(),
            is_archived_workflow: false,
            expected_version_hash: params.expected_version_hash.clone(),
            ops_payload,
            explicit_apply_intent: risk == RiskLevel::R2,
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
            full_action,
            RouteUsed::PublicApi,
        );
    };

    match action_norm.as_str() {
        "list" => match api
            .list_workflows(&ListQueryParams {
                limit: Some(params.limit.unwrap_or(20).clamp(1, 100)),
                cursor: params.cursor,
                active: params.active,
                exclude_pinned_data: Some(true),
                ..ListQueryParams::default()
            })
            .await
        {
            Ok(page) => {
                let items: Vec<Value> = page
                    .data
                    .iter()
                    .map(|wf| format_workflow_view(wf, params.detail))
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
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            match api
                .get_workflow(wf_id, params.detail != DetailLevel::Full)
                .await
            {
                Ok(wf) => {
                    let hash = workflow_resource_to_ir(&wf).ok().map(|(_, h, _)| h);
                    let mut view = format_workflow_view(&wf, params.detail);
                    if let (Some(obj), Some(h)) = (view.as_object_mut(), hash) {
                        obj.insert("canonicalVersionHash".to_owned(), Value::String(h));
                    }
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(Some(wf.id))
                    .with_versions(wf.version_id.clone(), wf.version_id, wf.active_version_id)
                    .with_data(view)
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "tags_get" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            match api.get_workflow_tags(wf_id).await {
                Ok(tags) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_workflow_id(Some(wf_id.clone()))
                .with_data(redact_json_value(&json!({ "tags": tags }))),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "dependencies" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            match api.get_workflow_dependencies(wf_id).await {
                Ok(deps) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::PublicApi,
                )
                .with_workflow_id(Some(wf_id.clone()))
                .with_data(redact_json_value(&deps)),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "create" | "clone" => {
            let draft_ir = if action_norm == "clone" {
                let Some(ref src_id) = params.workflow_id else {
                    return missing_wf_id(alias, &full_action);
                };
                let src = match api.get_workflow(src_id, false).await {
                    Ok(w) => w,
                    Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
                };
                let (mut ir, _, _) = match workflow_resource_to_ir(&src) {
                    Ok(t) => t,
                    Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
                };
                ir.name = params
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{} (Copy)", src.name));
                strip_ir_credential_secrets(&mut ir);
                ir
            } else {
                let Some(ref wf_json) = params.workflow else {
                    return N8nError::validation(
                        alias,
                        vec!["missing `workflow`".to_owned()],
                        "`workflow` JSON is required when `action == \"create\"`",
                    )
                    .into_envelope(alias, full_action, RouteUsed::Local);
                };
                let mut ir = match WorkflowIr::from_json_value(wf_json.clone()) {
                    Ok(ir) => ir,
                    Err(e) => {
                        return N8nError::validation(
                            alias,
                            vec![e.to_string()],
                            "Invalid workflow JSON",
                        )
                        .into_envelope(
                            alias,
                            full_action,
                            RouteUsed::Local,
                        );
                    }
                };
                if let Some(ref name) = params.name {
                    ir.name.clone_from(name);
                }
                strip_ir_credential_secrets(&mut ir);
                ir
            };
            create_and_verify_draft(
                state,
                &auth,
                api,
                &full_action,
                &draft_ir,
                params.operation_id.as_deref(),
                params.detail,
            )
            .await
        }
        "update_metadata" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, wf_id)
                .await;
            let current = match api.get_workflow(wf_id, false).await {
                Ok(w) => w,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            let (mut ir, base_hash, _) = match workflow_resource_to_ir(&current) {
                Ok(t) => t,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
            };
            if let Some(ref exp) = params.expected_version_hash
                && exp != &base_hash
            {
                return N8nError::Conflict409 {
                    instance: alias.clone(),
                    resource: Some(wf_id.clone()),
                    message: format!(
                        "Workflow `{wf_id}` drifted (`{base_hash}` != expected `{exp}`)"
                    ),
                }
                .into_envelope(alias, full_action, RouteUsed::PublicApi);
            }
            let _ = state.with_snapshot_vault_mut(|v| {
                v.capture_snapshot_at(&auth.principal, alias, None, &ir, false, Utc::now())
            });
            if let Some(ref name) = params.name {
                ir.name.clone_from(name);
            }
            if let Some(ref settings) = params.settings {
                ir.settings = settings.clone();
            }
            let body = match ir_to_workflow_write_body(&ir, false) {
                Ok(b) => b,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
            };
            let updated = match api.update_workflow(wf_id, &body).await {
                Ok(u) => u,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            let verified = api.get_workflow(wf_id, false).await.unwrap_or(updated);
            let after_hash = workflow_resource_to_ir(&verified).ok().map(|(_, h, _)| h);
            record_completed_mutation_journal(
                state,
                &auth.principal,
                alias,
                Some(wf_id),
                &full_action,
                Some(&base_hash),
                after_hash.as_deref(),
                &auth.ops_hash,
                JournalState::Verified,
                json!({"name": verified.name}),
            )
            .await;
            ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(verified.id.clone()))
            .with_versions(
                current.version_id,
                verified.version_id.clone(),
                verified.active_version_id.clone(),
            )
            .with_changed(true)
            .with_verification(VerificationReport::verified([
                "Workflow metadata verified via GET read-back.".to_owned(),
            ]))
            .with_data(format_workflow_view(&verified, params.detail))
        }
        "archive" | "unarchive" | "publish" | "unpublish" | "activate" | "deactivate" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, wf_id)
                .await;
            let before = api.get_workflow(wf_id, true).await.ok();
            let call_res = match action_norm.as_str() {
                "archive" => api.archive_workflow(wf_id).await,
                "unarchive" => api.unarchive_workflow(wf_id).await,
                "publish" => {
                    api.publish_workflow(wf_id, params.publish_body.as_ref())
                        .await
                }
                "unpublish" => api.unpublish_workflow(wf_id).await,
                "activate" => api.activate_workflow(wf_id).await,
                _ => api.deactivate_workflow(wf_id).await,
            };
            let mutated = match call_res {
                Ok(m) => m,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            let after = api.get_workflow(wf_id, true).await.unwrap_or(mutated);
            let (status, verification, warnings) = if action_norm == "publish" {
                if after.active_version_id.is_some() {
                    (
                        OperationStatus::Success,
                        VerificationReport::verified([format!(
                            "Verified live activeVersionId={:?} via GET read-back.",
                            after.active_version_id
                        )]),
                        Vec::new(),
                    )
                } else {
                    (
                        OperationStatus::Partial,
                        VerificationReport::inconclusive([
                            "Publish returned 200 but read-back `activeVersionId` is null."
                                .to_owned(),
                        ]),
                        vec!["activeVersionId was not populated after publish.".to_owned()],
                    )
                }
            } else {
                (
                    OperationStatus::Success,
                    VerificationReport::verified([format!(
                        "Lifecycle state verified (`active={}`, `isArchived={}`).",
                        after.active, after.is_archived
                    )]),
                    Vec::new(),
                )
            };
            record_completed_mutation_journal(
                state,
                &auth.principal,
                alias,
                Some(wf_id),
                &full_action,
                before.as_ref().and_then(|b| b.version_id.as_deref()),
                after.version_id.as_deref(),
                &auth.ops_hash,
                JournalState::Verified,
                json!({"active": after.active, "activeVersionId": after.active_version_id}),
            )
            .await;
            ToolEnvelope::new(
                status,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(after.id.clone()))
            .with_versions(
                before.and_then(|b| b.version_id),
                after.version_id.clone(),
                after.active_version_id.clone(),
            )
            .with_changed(true)
            .with_warnings(warnings)
            .with_verification(verification)
            .with_data(format_workflow_view(&after, params.detail))
        }
        "tags_update" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, wf_id)
                .await;
            match api.update_workflow_tags(wf_id, &params.tag_ids).await {
                Ok(tags) => {
                    record_completed_mutation_journal(
                        state,
                        &auth.principal,
                        alias,
                        Some(wf_id),
                        &full_action,
                        None,
                        None,
                        &auth.ops_hash,
                        JournalState::Verified,
                        json!({"tagCount": tags.len()}),
                    )
                    .await;
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(Some(wf_id.clone()))
                    .with_changed(true)
                    .with_data(redact_json_value(&json!({ "tags": tags })))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "transfer" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            let Some(ref dest) = params.destination_project_id else {
                return N8nError::validation(
                    alias,
                    vec!["missing `destinationProjectId`".to_owned()],
                    "`destinationProjectId` is required for `transfer`",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, wf_id)
                .await;
            match api.transfer_workflow(wf_id, dest).await {
                Ok(resp) => {
                    record_completed_mutation_journal(
                        state,
                        &auth.principal,
                        alias,
                        Some(wf_id),
                        &full_action,
                        None,
                        None,
                        &auth.ops_hash,
                        JournalState::Verified,
                        json!({"destinationProjectId": dest}),
                    )
                    .await;
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(Some(wf_id.clone()))
                    .with_changed(true)
                    .with_data(redact_json_value(&resp))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        "delete" => {
            let Some(ref wf_id) = params.workflow_id else {
                return missing_wf_id(alias, &full_action);
            };
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, wf_id)
                .await;
            if let Ok(existing) = api.get_workflow(wf_id, false).await
                && let Ok((ir, _, _)) = workflow_resource_to_ir(&existing)
            {
                let _ = state.with_snapshot_vault_mut(|v| {
                    v.capture_snapshot_at(&auth.principal, alias, None, &ir, false, Utc::now())
                });
            }
            match api.delete_workflow(wf_id).await {
                Ok(deleted) => {
                    record_completed_mutation_journal(
                        state,
                        &auth.principal,
                        alias,
                        Some(wf_id),
                        &full_action,
                        deleted.version_id.as_deref(),
                        None,
                        &auth.ops_hash,
                        JournalState::Verified,
                        json!({"deleted": true}),
                    )
                    .await;
                    ToolEnvelope::new(
                        OperationStatus::Success,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_workflow_id(Some(wf_id.clone()))
                    .with_changed(true)
                    .with_verification(VerificationReport::verified([
                        "Workflow deleted and pre-delete snapshot archived.".to_owned(),
                    ]))
                    .with_data(redact_json_value(&json!({ "deletedId": deleted.id })))
                }
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            }
        }
        _ => unreachable!(),
    }
}

/// Tool #10: `n8n_versions`.
#[allow(clippy::too_many_lines)]
pub async fn execute_versions(state: &AppState, params: VersionsParams) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("versions.{action_norm}");
    let (logical_op, risk) = match action_norm.as_str() {
        "history" | "get_version" | "snapshots" | "diff" => {
            (LogicalOperation::VersionsRead, RiskLevel::R0)
        }
        "restore" => (LogicalOperation::VersionsRestore, RiskLevel::R2),
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unsupported versions action `{other}`")],
                "Expected `history`, `get_version`, `snapshots`, `diff`, or `restore`",
            )
            .into_envelope(inst, "versions.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "workflowId": params.workflow_id,
        "versionId": params.version_id,
        "snapshotId": params.snapshot_id,
    });

    if action_norm == "restore" && params.preview {
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
                RiskLevel::R2,
                "read-only",
                "Restore preview blocked in read-only mode",
                None,
            )
            .into_envelope(&rt.config.alias, full_action, RouteUsed::Local);
        }
        let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal: state.principal_for(rt),
            instance: rt.config.alias.clone(),
            action: full_action.clone(),
            risk: RiskLevel::R2,
            workflow_id: Some(params.workflow_id.clone()),
            expected_version_hash: params.expected_version_hash,
            ops_hash: hash_ops(&ops_payload).unwrap_or_default(),
            summary: format!("Draft restore for workflow `{}`", params.workflow_id),
            diff: None,
            diff_payload: ops_payload,
            side_effects: vec![RESTORE_SIDE_EFFECTS_DISCLAIMER.to_owned()],
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
        .with_warning(RESTORE_SIDE_EFFECTS_DISCLAIMER)
        .with_data(redact_json_value(&json!({
            "planId": plan.plan_id,
            "disclaimer": RESTORE_SIDE_EFFECTS_DISCLAIMER,
            "expiresAt": plan.expires_at,
        })));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op,
            risk,
            workflow_id: Some(params.workflow_id.clone()),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: params.expected_version_hash.clone(),
            ops_payload,
            explicit_apply_intent: action_norm == "restore",
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
            full_action,
            RouteUsed::PublicApi,
        );
    };

    match action_norm.as_str() {
        "history" => match api
            .get_workflow_history(&params.workflow_id, params.limit, params.cursor.as_deref())
            .await
        {
            Ok(h) => ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(params.workflow_id))
            .with_data(redact_json_value(&h)),
            Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
        },
        "get_version" => {
            let Some(ref ver_id) = params.version_id else {
                return N8nError::validation(
                    alias,
                    vec!["missing `versionId`".to_owned()],
                    "`versionId` is required for `get_version`",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            match api.get_workflow_version(&params.workflow_id, ver_id).await {
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
            }
        }
        "snapshots" => {
            let res = state.with_snapshot_vault(|v| {
                v.list_snapshots(&auth.principal, alias, &params.workflow_id)
            });
            match res {
                Ok(snaps) => ToolEnvelope::new(
                    OperationStatus::Success,
                    alias,
                    full_action,
                    auth.policy.permission,
                    RouteUsed::Local,
                )
                .with_workflow_id(Some(params.workflow_id))
                .with_data(redact_json_value(&json!({ "snapshots": snaps }))),
                Err(e) => e.into_envelope(alias, full_action, RouteUsed::Local),
            }
        }
        "diff" => {
            let base_ir = match load_version_or_live_ir(
                state,
                &auth.principal,
                alias,
                api,
                &params.workflow_id,
                params.version_id.as_deref(),
                params.snapshot_id.as_deref(),
            )
            .await
            {
                Ok(ir) => ir,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            let target_ir = match load_version_or_live_ir(
                state,
                &auth.principal,
                alias,
                api,
                &params.workflow_id,
                params.compare_version_id.as_deref(),
                None,
            )
            .await
            {
                Ok(ir) => ir,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            let diff = WorkflowDiff::compute(&base_ir, &target_ir, DEFAULT_DIFF_MAX_CHARS);
            ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(params.workflow_id))
            .with_diff(diff.diff_summary.clone())
            .with_data(redact_json_value(&json!({ "workflowDiff": diff })))
        }
        "restore" => {
            let _lock = state
                .policy_engine
                .lock_registry()
                .acquire_write_lock(alias, &params.workflow_id)
                .await;
            let live_before = match api.get_workflow(&params.workflow_id, false).await {
                Ok(w) => w,
                Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
            };
            if let Ok((ir_before, _, _)) = workflow_resource_to_ir(&live_before) {
                let _ = state.with_snapshot_vault_mut(|v| {
                    v.capture_snapshot_at(
                        &auth.principal,
                        alias,
                        None,
                        &ir_before,
                        false,
                        Utc::now(),
                    )
                });
            }

            let mut route_used = RouteUsed::PublicApi;
            if let Some(ref snap_id) = params.snapshot_id {
                let restored = match state.with_snapshot_vault_mut(|v| {
                    v.restore_snapshot_at(&auth.principal, alias, snap_id, Utc::now())
                }) {
                    Ok(r) => r,
                    Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
                };
                let body = match ir_to_workflow_write_body(&restored.draft_workflow, true) {
                    Ok(b) => b,
                    Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
                };
                if let Err(e) = api.update_workflow(&params.workflow_id, &body).await {
                    return e.into_envelope(alias, full_action, RouteUsed::PublicApi);
                }
            } else if let Some(ref ver_id) = params.version_id {
                let mut used_native = false;
                if auth.policy.route == RouteUsed::NativeMcp
                    && let Some(ref bridge) = auth.rt.mcp_bridge
                {
                    match bridge
                        .restore_workflow_version(&params.workflow_id, ver_id)
                        .await
                    {
                        Ok(_) => {
                            used_native = true;
                            route_used = RouteUsed::NativeMcp;
                        }
                        Err(e) => {
                            if let Err(fatal) = verify_fallback_allowed(RouteUsed::NativeMcp, e) {
                                return fatal.into_envelope(
                                    alias,
                                    full_action,
                                    RouteUsed::NativeMcp,
                                );
                            }
                        }
                    }
                }
                if !used_native {
                    let ver_val = match api.get_workflow_version(&params.workflow_id, ver_id).await
                    {
                        Ok(v) => v,
                        Err(e) => return e.into_envelope(alias, full_action, RouteUsed::PublicApi),
                    };
                    let mut ir = match WorkflowIr::from_json_value(ver_val) {
                        Ok(ir) => ir,
                        Err(e) => {
                            return N8nError::protocol(e.to_string()).into_envelope(
                                alias,
                                full_action,
                                RouteUsed::Local,
                            );
                        }
                    };
                    strip_ir_credential_secrets(&mut ir);
                    let body = match ir_to_workflow_write_body(&ir, true) {
                        Ok(b) => b,
                        Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
                    };
                    if let Err(e) = api.update_workflow(&params.workflow_id, &body).await {
                        return e.into_envelope(alias, full_action, RouteUsed::PublicApi);
                    }
                }
            } else {
                return N8nError::validation(
                    alias,
                    vec!["missing `versionId` or `snapshotId`".to_owned()],
                    "Provide either `versionId` or `snapshotId` for `restore`",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            }

            let verified = match api.get_workflow(&params.workflow_id, false).await {
                Ok(v) => v,
                Err(e) => return e.into_envelope(alias, full_action, route_used),
            };
            record_completed_mutation_journal(
                state,
                &auth.principal,
                alias,
                Some(&params.workflow_id),
                &full_action,
                live_before.version_id.as_deref(),
                verified.version_id.as_deref(),
                &auth.ops_hash,
                JournalState::Verified,
                json!({"disclaimer": RESTORE_SIDE_EFFECTS_DISCLAIMER}),
            )
            .await;
            ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                route_used,
            )
            .with_workflow_id(Some(verified.id.clone()))
            .with_versions(
                live_before.version_id,
                verified.version_id.clone(),
                verified.active_version_id.clone(),
            )
            .with_changed(true)
            .with_warning(RESTORE_SIDE_EFFECTS_DISCLAIMER)
            .with_verification(VerificationReport::verified([
                "Restored draft state verified via GET read-back (not auto-published).".to_owned(),
            ]))
            .with_data(redact_json_value(&json!({
                "disclaimer": RESTORE_SIDE_EFFECTS_DISCLAIMER,
                "workflow": format_workflow_view(&verified, params.detail),
            })))
        }
        _ => unreachable!(),
    }
}

/// Tool #11: `n8n_deploy_template`.
pub async fn execute_deploy_template(
    state: &AppState,
    params: DeployTemplateParams,
) -> ToolEnvelope<Value> {
    let mode_norm = params.mode.trim().to_ascii_lowercase();
    let inst_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    let (mut ir, placeholders, val_report) = match state.with_catalog(|db| {
        let Some(entry) = db.get_template(&params.template_id, TemplateDetailMode::Full)? else {
            return Err(N8nError::not_found_or_concealed(
                &inst_name,
                format!("template/{}", params.template_id),
                format!("Template `{}` not found in catalog", params.template_id),
            ));
        };
        let wf_val = entry.workflow.unwrap_or_else(|| json!({}));
        let mut ir = WorkflowIr::from_json_value(wf_val)
            .map_err(|e| N8nError::protocol(format!("template IR parse failed: {e}")))?;
        ir.name = params.name.clone().unwrap_or(entry.name);
        strip_ir_credential_secrets(&mut ir);
        apply_template_credential_bindings(&inst_name, &mut ir, &params.credential_bindings)?;
        let report = validate_workflow(&ir, Some(db), &ValidationOptions::default());
        N8nResult::Ok((
            ir,
            entry.credential_placeholders.unwrap_or_default(),
            report,
        ))
    }) {
        Ok(res) => res,
        Err(e) => return e.into_envelope(inst_name, "deploy_template.prepare", RouteUsed::Local),
    };

    if !val_report.valid {
        return ToolEnvelope::new(
            OperationStatus::Error,
            inst_name,
            "deploy_template.validate",
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_data(redact_json_value(&json!({
            "valid": false,
            "validationReport": val_report,
        })));
    }

    let draft_body = match ir_to_workflow_write_body(&ir, true) {
        Ok(b) => b,
        Err(e) => return e.into_envelope(inst_name, "deploy_template.prepare", RouteUsed::Local),
    };
    let ops_payload = json!({
        "templateId": params.template_id,
        "name": ir.name,
        "bodyHash": compute_json_version_hash(&draft_body),
    });

    if mode_norm != "apply" {
        let Ok(rt) = state.instance(params.instance.as_deref()) else {
            return N8nError::config("unknown instance").into_envelope(
                inst_name,
                "deploy_template.preview",
                RouteUsed::Local,
            );
        };
        let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
            principal: state.principal_for(rt),
            instance: rt.config.alias.clone(),
            action: "deploy_template.apply".to_owned(),
            risk: RiskLevel::R2,
            workflow_id: None,
            expected_version_hash: None,
            ops_hash: hash_ops(&ops_payload).unwrap_or_default(),
            summary: format!("Deploy catalog template `{}` as inactive draft", ir.name),
            diff: Some(BoundedDiffSummary::redacted(
                format!("Create draft `{}` ({} nodes)", ir.name, ir.nodes.len()),
                ir.nodes.iter().map(|n| n.name.clone()).collect(),
                false,
            )),
            diff_payload: draft_body.clone(),
            side_effects: vec![
                "Creates an inactive workflow draft (zero live triggers).".to_owned(),
            ],
            ttl_secs: None,
        });
        return ToolEnvelope::new(
            OperationStatus::Preview,
            &rt.config.alias,
            "deploy_template.preview",
            PermissionDecision::NeedsApproval,
            RouteUsed::Local,
        )
        .with_data(redact_json_value(&json!({
            "planId": plan.plan_id,
            "validationReport": val_report,
            "credentialPlaceholders": placeholders,
            "draftWorkflow": draft_body,
        })));
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: "deploy_template.apply".to_owned(),
            logical_op: LogicalOperation::DeployTemplate,
            risk: RiskLevel::R2,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: true,
            approval_receipt: params.approval_receipt,
            batch_workflow_count: None,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(env) => return env,
    };
    let Some(ref api) = auth.rt.api_client else {
        return N8nError::unauthenticated(&auth.rt.config.alias, "N8N_API_KEY missing")
            .into_envelope(
                &auth.rt.config.alias,
                "deploy_template.apply",
                RouteUsed::PublicApi,
            );
    };
    strip_ir_credential_secrets(&mut ir);
    create_and_verify_draft(
        state,
        &auth,
        api,
        "deploy_template.apply",
        &ir,
        params.operation_id.as_deref(),
        params.detail,
    )
    .await
}

fn handle_confirm_plan(state: &AppState, params: &WorkflowsParams) -> ToolEnvelope<Value> {
    let rt = match state.instance(params.instance.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            return e.into_envelope(
                params.instance.as_deref().unwrap_or(&state.active_instance),
                "workflows.confirm_plan",
                RouteUsed::Local,
            );
        }
    };
    if rt.config.policy_mode == PolicyMode::ReadOnly {
        return N8nError::policy_blocked(
            "workflows.confirm_plan",
            RiskLevel::R2,
            "read-only",
            "`read-only` policy forbids minting mutation approval receipts",
            None,
        )
        .into_envelope(&rt.config.alias, "workflows.confirm_plan", RouteUsed::Local);
    }
    let Some(ref plan_id) = params.plan_id else {
        return N8nError::validation(
            &rt.config.alias,
            vec!["missing `planId`".to_owned()],
            "`planId` is required when `action == \"confirm_plan\"`",
        )
        .into_envelope(&rt.config.alias, "workflows.confirm_plan", RouteUsed::Local);
    };
    let principal = state.principal_for(rt);
    match state.approval_manager.confirm_plan_and_issue_receipt(
        state.policy_engine.receipt_signer(),
        &principal,
        &rt.config.alias,
        rt.config.policy_mode.as_str(),
        plan_id,
        params.ttl_secs.unwrap_or(300),
    ) {
        Ok((plan, receipt, token)) => ToolEnvelope::new(
            OperationStatus::Success,
            &rt.config.alias,
            "workflows.confirm_plan",
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_workflow_id(plan.workflow_id)
        .with_data(json!({
            "planId": plan.plan_id,
            "approvedAction": plan.action,
            "risk": plan.risk,
            "approvalReceipt": token,
            "expiresAt": receipt.claims.expires_at,
        })),
        Err(e) => e.into_envelope(&rt.config.alias, "workflows.confirm_plan", RouteUsed::Local),
    }
}

fn create_workflow_action_preview(
    state: &AppState,
    params: &WorkflowsParams,
    full_action: &str,
    risk: RiskLevel,
    ops_payload: &Value,
) -> ToolEnvelope<Value> {
    let rt = match state.instance(params.instance.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            return e.into_envelope(
                params.instance.as_deref().unwrap_or(&state.active_instance),
                full_action,
                RouteUsed::Local,
            );
        }
    };
    if rt.config.policy_mode == PolicyMode::ReadOnly {
        return N8nError::policy_blocked(
            full_action,
            risk,
            "read-only",
            "Preview of mutating operation blocked under `read-only` policy",
            None,
        )
        .into_envelope(&rt.config.alias, full_action, RouteUsed::Local);
    }
    let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
        principal: state.principal_for(rt),
        instance: rt.config.alias.clone(),
        action: full_action.to_owned(),
        risk,
        workflow_id: params.workflow_id.clone(),
        expected_version_hash: params.expected_version_hash.clone(),
        ops_hash: hash_ops(ops_payload).unwrap_or_default(),
        summary: format!(
            "Preview `{full_action}` on workflow {:?}",
            params.workflow_id
        ),
        diff: None,
        diff_payload: ops_payload.clone(),
        side_effects: vec![format!("Risk level: {}", risk.label())],
        ttl_secs: params.ttl_secs,
    });
    ToolEnvelope::new(
        OperationStatus::Preview,
        &rt.config.alias,
        full_action,
        PermissionDecision::NeedsApproval,
        RouteUsed::Local,
    )
    .with_workflow_id(params.workflow_id.clone())
    .with_next_actions([format!(
        "Call `n8n_workflows` with `action=\"confirm_plan\"` and `planId=\"{}\"` after operator approval.",
        plan.plan_id
    )])
    .with_data(redact_json_value(&json!({
        "planId": plan.plan_id,
        "risk": plan.risk,
        "expiresAt": plan.expires_at,
    })))
}

async fn create_and_verify_draft(
    state: &AppState,
    auth: &crate::tools::common::AuthorizedCall<'_>,
    api: &n8n_api_client::N8nApiClient,
    full_action: &str,
    draft_ir: &WorkflowIr,
    explicit_op_id: Option<&str>,
    detail: DetailLevel,
) -> ToolEnvelope<Value> {
    let alias = &auth.rt.config.alias;
    let body = match ir_to_workflow_write_body(draft_ir, true) {
        Ok(b) => b,
        Err(e) => return e.into_envelope(alias, full_action, RouteUsed::Local),
    };
    let op_id = explicit_op_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));
    match api.create_workflow(&op_id, &body).await {
        Ok(Outcome::Confirmed { value: created }) => {
            let verified = api
                .get_workflow(&created.id, false)
                .await
                .unwrap_or(created);
            let after_hash = workflow_resource_to_ir(&verified).ok().map(|(_, h, _)| h);
            record_completed_mutation_journal(
                state,
                &auth.principal,
                alias,
                Some(&verified.id),
                full_action,
                None,
                after_hash.as_deref(),
                &auth.ops_hash,
                JournalState::Verified,
                json!({"operationId": op_id}),
            )
            .await;
            ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_workflow_id(Some(verified.id.clone()))
            .with_versions(
                None,
                verified.version_id.clone(),
                verified.active_version_id.clone(),
            )
            .with_changed(true)
            .with_verification(VerificationReport::verified([
                "Created inactive draft and verified via GET read-back.".to_owned(),
            ]))
            .with_data(format_workflow_view(&verified, detail))
        }
        Ok(Outcome::UnknownNeedsReconcile {
            operation_id,
            idempotency_key,
            reason,
            ..
        }) => {
            record_completed_mutation_journal(
                state,
                &auth.principal,
                alias,
                None,
                full_action,
                None,
                None,
                &auth.ops_hash,
                JournalState::UnknownResult,
                json!({"operationId": operation_id, "idempotencyKey": idempotency_key}),
            )
            .await;
            ToolEnvelope::new(
                OperationStatus::Partial,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_warning(reason)
            .with_verification(VerificationReport::inconclusive([
                "POST timed out; reconcile before retrying with the same `operationId`.".to_owned(),
            ]))
            .with_data(json!({
                "operationId": operation_id,
                "idempotencyKey": idempotency_key,
            }))
        }
        Err(e) => e.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

async fn load_version_or_live_ir(
    state: &AppState,
    principal: &str,
    alias: &str,
    api: &n8n_api_client::N8nApiClient,
    workflow_id: &str,
    version_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> N8nResult<WorkflowIr> {
    if let Some(snap_id) = snapshot_id {
        let restored = state.with_snapshot_vault_mut(|v| {
            v.restore_snapshot_at(principal, alias, snap_id, Utc::now())
        })?;
        return Ok(restored.draft_workflow);
    }
    if let Some(ver_id) = version_id {
        let val = api.get_workflow_version(workflow_id, ver_id).await?;
        return WorkflowIr::from_json_value(val)
            .map_err(|e| N8nError::protocol(format!("version IR parse error: {e}")));
    }
    let live = api.get_workflow(workflow_id, false).await?;
    let (ir, _, _) = workflow_resource_to_ir(&live)?;
    Ok(ir)
}

fn strip_ir_credential_secrets(ir: &mut WorkflowIr) {
    for node in &mut ir.nodes {
        if let Some(ref mut creds) = node.credentials {
            for cred_ref in creds.values_mut() {
                cred_ref.extra.retain(|k, _| k != "data" && k != "secret");
            }
        }
    }
}

fn apply_template_credential_bindings(
    instance: &str,
    ir: &mut WorkflowIr,
    bindings: &BTreeMap<String, CredentialRefBinding>,
) -> N8nResult<()> {
    for (cred_type, binding) in bindings {
        let id_trim = binding.id.trim();
        if id_trim.is_empty()
            || id_trim.contains(' ')
            || id_trim.starts_with("eyJ")
            || id_trim.to_ascii_lowercase().starts_with("bearer ")
        {
            return Err(N8nError::validation(
                instance,
                vec![format!("invalid credential id for `{cred_type}`")],
                "Credential bindings must supply opaque credential IDs/names only, never secret tokens",
            ));
        }
        for node in &mut ir.nodes {
            if let Some(ref mut creds) = node.credentials
                && creds.contains_key(cred_type)
            {
                creds.insert(
                    cred_type.clone(),
                    NodeCredentialRef {
                        id: Some(id_trim.to_owned()),
                        name: binding.name.trim().to_owned(),
                        extra: Default::default(),
                    },
                );
            }
        }
    }
    Ok(())
}

fn missing_wf_id(alias: &str, full_action: &str) -> ToolEnvelope<Value> {
    N8nError::validation(
        alias,
        vec!["missing `workflowId`".to_owned()],
        format!("`workflowId` is required for `{full_action}`"),
    )
    .into_envelope(alias, full_action, RouteUsed::Local)
}
