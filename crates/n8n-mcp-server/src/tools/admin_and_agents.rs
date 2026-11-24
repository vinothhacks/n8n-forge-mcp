//! Tools #20 (`n8n_community_packages`), #21 (`n8n_git_and_packages`),
//! #22 (`n8n_admin_access`), #23 (`n8n_admin_settings`), and #24 (`n8n_agents`).

use http::Method;
use n8n_api_client::{Outcome, RawRequest, validate_path_segment};
use n8n_capability::{CapabilityState, LogicalOperation, select_operation_route};
use n8n_policy::hash_ops;
use n8n_state_vault::JournalState;
use n8n_types::{
    DetailLevel, N8nError, N8nResult, OperationStatus, PermissionDecision, RiskLevel, RouteUsed,
    ToolEnvelope, redact_json_value,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::PreviewPlanInit;
use crate::state::AppState;
use crate::tools::common::{
    AuthorizeSpec, authorize_operation, record_completed_mutation_journal,
    validate_pinned_community_package,
};

fn default_list_action() -> String {
    "list".to_owned()
}

fn default_sc_status_action() -> String {
    "source_control_status".to_owned()
}

fn default_list_users_action() -> String {
    "list_users".to_owned()
}

fn default_insights_action() -> String {
    "insights_summary".to_owned()
}

/// Input schema for Tool #20: `n8n_community_packages`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommunityPackagesParams {
    #[serde(default = "default_list_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #21: `n8n_git_and_packages`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitAndPackagesParams {
    #[serde(default = "default_sc_status_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #22: `n8n_admin_access`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminAccessParams {
    #[serde(default = "default_list_users_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub role_name: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #23: `n8n_admin_settings`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminSettingsParams {
    #[serde(default = "default_insights_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub destination_id: Option<String>,
    #[serde(default)]
    pub date_range: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

/// Input schema for Tool #24: `n8n_agents`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentsParams {
    #[serde(default = "default_list_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub approval_receipt: Option<String>,
    #[serde(default)]
    pub detail: DetailLevel,
}

fn admin_preview(
    state: &AppState,
    requested_instance: Option<&str>,
    full_action: &str,
    risk: RiskLevel,
    ops_payload: &Value,
) -> ToolEnvelope<Value> {
    let rt = match state.instance(requested_instance) {
        Ok(r) => r,
        Err(e) => {
            return e.into_envelope(
                requested_instance.unwrap_or(&state.active_instance),
                full_action,
                RouteUsed::Local,
            );
        }
    };
    let ops_hash = hash_ops(ops_payload).unwrap_or_default();
    let plan = state.approval_manager.create_preview_plan(PreviewPlanInit {
        principal: state.principal_for(rt),
        instance: rt.config.alias.clone(),
        action: full_action.to_owned(),
        risk,
        workflow_id: None,
        expected_version_hash: None,
        ops_hash,
        summary: format!("Preview high-risk admin action `{full_action}`"),
        diff: None,
        diff_payload: redact_json_value(ops_payload),
        side_effects: vec![format!("Admin action risk: {}", risk.label())],
        ttl_secs: None,
    });
    ToolEnvelope::new(
        OperationStatus::Preview,
        &rt.config.alias,
        full_action,
        PermissionDecision::NeedsApproval,
        RouteUsed::Local,
    )
    .with_next_actions([format!(
        "Call `n8n_workflows` with `action=\"confirm_plan\"` and `planId=\"{}\"` after explicit admin approval.",
        plan.plan_id
    )])
    .with_data(json!({
        "planId": plan.plan_id,
        "risk": plan.risk,
        "expiresAt": plan.expires_at,
    }))
}

fn check_community_package_allowlist(package_name: &str) -> N8nResult<()> {
    let allowlist_raw = std::env::var("N8N_ALLOWED_COMMUNITY_PACKAGES").unwrap_or_default();
    let allowed: Vec<String> = allowlist_raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed.is_empty()
        || !allowed
            .iter()
            .any(|p| p == &package_name.trim().to_ascii_lowercase())
    {
        return Err(N8nError::policy_blocked(
            "community_packages.allowlist",
            RiskLevel::R4,
            "package-allowlist",
            format!(
                "Community package `{}` is not listed in `N8N_ALLOWED_COMMUNITY_PACKAGES` supply-chain allowlist",
                package_name.trim()
            ),
            Some("Add the exact verified package name to N8N_ALLOWED_COMMUNITY_PACKAGES and enable R4 admin actions.".to_owned()),
        ));
    }
    Ok(())
}

/// Tool #20: `n8n_community_packages`.
pub async fn execute_community_packages(
    state: &AppState,
    params: CommunityPackagesParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("community_packages.{action_norm}");
    let risk = match action_norm.as_str() {
        "list" | "get" => RiskLevel::R0,
        "install" | "update" | "uninstall" => RiskLevel::R4,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown community_packages action `{other}`")],
                format!("Unsupported `n8n_community_packages` action `{other}`"),
            )
            .into_envelope(inst, "community_packages.unknown", RouteUsed::Local);
        }
    };

    let inst_hint = params.instance.as_deref().unwrap_or(&state.active_instance);
    if matches!(action_norm.as_str(), "install" | "update" | "uninstall") {
        let pkg = params.package_name.as_deref().unwrap_or("");
        let require_ver = action_norm != "uninstall";
        if let Err(e) = validate_pinned_community_package(
            inst_hint,
            pkg,
            params.version.as_deref(),
            require_ver,
        ) {
            return e.into_envelope(inst_hint, full_action, RouteUsed::Local);
        }
        if require_ver && let Err(e) = check_community_package_allowlist(pkg) {
            return e.into_envelope(inst_hint, full_action, RouteUsed::Local);
        }
    }

    let ops_payload = json!({
        "action": action_norm,
        "packageName": params.package_name,
        "version": params.version,
    });

    if params.preview && risk.is_mutating() {
        return admin_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::CommunityPackages,
            risk,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: false,
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
    let op_id = params
        .operation_id
        .clone()
        .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));

    let res: N8nResult<Value> = match action_norm.as_str() {
        "list" => api.list_community_packages().await,
        "get" => {
            let pkg = params.package_name.as_deref().unwrap_or("");
            api.list_community_packages().await.map(|all| {
                json!({
                    "packageName": pkg,
                    "inventory": all,
                })
            })
        }
        "install" => {
            let pkg = params.package_name.as_deref().unwrap_or("");
            let ver = params.version.as_deref().unwrap_or("");
            let body = json!({ "name": pkg, "version": ver });
            api.install_community_package(&op_id, &body)
                .await
                .map(|o| match o {
                    Outcome::Confirmed { value } => value,
                    Outcome::UnknownNeedsReconcile {
                        operation_id,
                        reason,
                        ..
                    } => {
                        json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                    }
                })
        }
        "update" => {
            let pkg = params.package_name.as_deref().unwrap_or("");
            let ver = params.version.as_deref().unwrap_or("");
            let body = json!({ "version": ver });
            api.update_community_package(pkg, &body).await
        }
        "uninstall" => {
            let pkg = params.package_name.as_deref().unwrap_or("");
            api.uninstall_community_package(pkg).await
        }
        _ => unreachable!(),
    };

    match res {
        Ok(payload) => {
            if risk.is_mutating() {
                record_completed_mutation_journal(
                    state,
                    &auth.principal,
                    alias,
                    None,
                    &full_action,
                    None,
                    None,
                    &auth.ops_hash,
                    JournalState::Verified,
                    json!({ "packageName": params.package_name, "version": params.version }),
                )
                .await;
            }
            let mut env = ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_data(redact_json_value(&payload));
            if risk.is_mutating() {
                env.changed = true;
            }
            env
        }
        Err(err) => err.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

/// Tool #21: `n8n_git_and_packages`.
pub async fn execute_git_and_packages(
    state: &AppState,
    params: GitAndPackagesParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("git_and_packages.{action_norm}");
    let risk = match action_norm.as_str() {
        "source_control_status"
        | "promotions_list"
        | "promotions_list_providers"
        | "promotions_list_environments"
        | "package_list" => RiskLevel::R0,
        "package_export" => RiskLevel::R3,
        "source_control_pull"
        | "source_control_push"
        | "promotions_create"
        | "promotions_promote"
        | "promotions_apply"
        | "package_import"
        | "package_import_selection" => RiskLevel::R4,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown git_and_packages action `{other}`")],
                format!("Unsupported `n8n_git_and_packages` action `{other}`"),
            )
            .into_envelope(inst, "git_and_packages.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "payload": redact_json_value(params.payload.as_ref().unwrap_or(&Value::Null)),
    });

    if params.preview && risk.is_mutating() {
        return admin_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::GitAndPackages,
            risk,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: false,
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
    let op_id = params
        .operation_id
        .clone()
        .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));
    let body = params.payload.clone().unwrap_or_else(|| json!({}));

    let res: N8nResult<Value> = match action_norm.as_str() {
        "source_control_status" => api.get_source_control_status().await,
        "source_control_pull" => api.pull_source_control(&body).await,
        "source_control_push" => api.push_source_control(&body).await,
        "promotions_list" | "promotions_list_providers" | "promotions_list_environments" => {
            api.list_promotions().await
        }
        "promotions_create" | "promotions_promote" | "promotions_apply" => {
            api.create_promotion(&op_id, &body).await.map(|o| match o {
                Outcome::Confirmed { value } => value,
                Outcome::UnknownNeedsReconcile {
                    operation_id,
                    reason,
                    ..
                } => {
                    json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                }
            })
        }
        "package_list" => api.list_n8n_packages().await,
        "package_export" => api.export_n8n_package(&body).await,
        "package_import" => api.import_n8n_package(&body).await,
        "package_import_selection" => api
            .send_raw(RawRequest {
                method: Method::POST,
                path_template: "/api/v1/n8n-packages/import-selection",
                sub_path: "n8n-packages/import-selection",
                query: &[],
                body: Some(&body),
                operation_id: None,
                accept_mime: "application/json",
            })
            .await
            .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
        _ => unreachable!(),
    };

    match res {
        Ok(payload) => {
            if risk.is_mutating() {
                record_completed_mutation_journal(
                    state,
                    &auth.principal,
                    alias,
                    None,
                    &full_action,
                    None,
                    None,
                    &auth.ops_hash,
                    JournalState::Verified,
                    json!({ "action": action_norm }),
                )
                .await;
            }
            let mut env = ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_data(redact_json_value(&payload));
            if risk.is_mutating() {
                env.changed = true;
            }
            env
        }
        Err(err) => err.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

/// Tool #22: `n8n_admin_access`.
#[allow(clippy::too_many_lines)]
pub async fn execute_admin_access(
    state: &AppState,
    params: AdminAccessParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("admin_access.{action_norm}");
    let risk = match action_norm.as_str() {
        "list_users"
        | "get_user"
        | "list_project_users"
        | "list_roles"
        | "list_role_mapping_rules"
        | "get_sso_oidc"
        | "get_sso_saml"
        | "get_ldap" => RiskLevel::R0,
        "create_users"
        | "delete_user"
        | "change_user_role"
        | "manage_project_user"
        | "role_mapping_rules"
        | "sso_oidc"
        | "sso_saml"
        | "ldap_settings"
        | "ldap_sync" => RiskLevel::R4,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown admin_access action `{other}`")],
                format!("Unsupported `n8n_admin_access` action `{other}`"),
            )
            .into_envelope(inst, "admin_access.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "userId": params.user_id,
        "projectId": params.project_id,
        "roleName": params.role_name,
        "ruleId": params.rule_id,
    });

    if params.preview && risk.is_mutating() {
        return admin_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::AdminAccess,
            risk,
            workflow_id: None,
            project_id: params.project_id.clone(),
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: false,
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
    let op_id = params
        .operation_id
        .clone()
        .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));
    let body = params.payload.clone().unwrap_or_else(|| json!({}));

    let res: N8nResult<Value> = match action_norm.as_str() {
        "list_users" => api
            .list_users(params.limit, params.cursor.as_deref())
            .await
            .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
        "get_user" => match params.user_id.as_deref() {
            Some(uid) => api
                .get_user(uid)
                .await
                .map(|u| serde_json::to_value(u).unwrap_or(Value::Null)),
            None => Err(N8nError::validation(
                alias,
                vec!["missing userId".into()],
                "userId required",
            )),
        },
        "list_project_users" => match params.project_id.as_deref() {
            Some(pid) => match validate_path_segment("project_id", pid) {
                Ok(p_clean) => api
                    .send_raw(RawRequest {
                        method: Method::GET,
                        path_template: "/api/v1/projects/{projectId}/users",
                        sub_path: &format!("projects/{p_clean}/users"),
                        query: &[],
                        body: None,
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            None => Err(N8nError::validation(
                alias,
                vec!["missing projectId".into()],
                "projectId required",
            )),
        },
        "list_roles" => api.list_roles().await,
        "list_role_mapping_rules" => api
            .send_raw(RawRequest {
                method: Method::GET,
                path_template: "/api/v1/role-mapping-rules",
                sub_path: "role-mapping-rules",
                query: &[],
                body: None,
                operation_id: None,
                accept_mime: "application/json",
            })
            .await
            .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
        "get_sso_oidc" => api.get_settings(Some("sso/oidc")).await,
        "get_sso_saml" => api.get_settings(Some("sso/saml")).await,
        "get_ldap" => api.get_settings(Some("ldap")).await,
        "create_users" => api.create_users(&op_id, &body).await.map(|o| match o {
            Outcome::Confirmed { value } => value,
            Outcome::UnknownNeedsReconcile {
                operation_id,
                reason,
                ..
            } => {
                json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
            }
        }),
        "delete_user" => match params.user_id.as_deref() {
            Some(uid) => api.delete_user(uid).await,
            None => Err(N8nError::validation(
                alias,
                vec!["missing userId".into()],
                "userId required",
            )),
        },
        "change_user_role" => match (params.user_id.as_deref(), params.role_name.as_deref()) {
            (Some(uid), Some(role)) => api.change_user_role(uid, role).await,
            _ => Err(N8nError::validation(
                alias,
                vec!["missing userId/roleName".into()],
                "userId and roleName required",
            )),
        },
        "manage_project_user" => match params.project_id.as_deref() {
            Some(pid) => match validate_path_segment("project_id", pid) {
                Ok(p_clean) => api
                    .send_raw(RawRequest {
                        method: Method::POST,
                        path_template: "/api/v1/projects/{projectId}/users",
                        sub_path: &format!("projects/{p_clean}/users"),
                        query: &[],
                        body: Some(&body),
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            None => Err(N8nError::validation(
                alias,
                vec!["missing projectId".into()],
                "projectId required",
            )),
        },
        "role_mapping_rules" => api
            .send_raw(RawRequest {
                method: Method::POST,
                path_template: "/api/v1/role-mapping-rules",
                sub_path: "role-mapping-rules",
                query: &[],
                body: Some(&body),
                operation_id: None,
                accept_mime: "application/json",
            })
            .await
            .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
        "sso_oidc" => api.update_settings("sso/oidc", &body).await,
        "sso_saml" => api.update_settings("sso/saml", &body).await,
        "ldap_settings" => api.update_settings("ldap", &body).await,
        "ldap_sync" => api
            .send_raw(RawRequest {
                method: Method::POST,
                path_template: "/api/v1/settings/ldap/sync",
                sub_path: "settings/ldap/sync",
                query: &[],
                body: Some(&body),
                operation_id: None,
                accept_mime: "application/json",
            })
            .await
            .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
        _ => unreachable!(),
    };

    match res {
        Ok(payload) => {
            if risk.is_mutating() {
                record_completed_mutation_journal(
                    state,
                    &auth.principal,
                    alias,
                    None,
                    &full_action,
                    None,
                    None,
                    &auth.ops_hash,
                    JournalState::Verified,
                    json!({ "action": action_norm }),
                )
                .await;
            }
            let mut env = ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_data(redact_json_value(&payload));
            if risk.is_mutating() {
                env.changed = true;
            }
            env
        }
        Err(err) => err.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

/// Tool #23: `n8n_admin_settings`.
pub async fn execute_admin_settings(
    state: &AppState,
    params: AdminSettingsParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("admin_settings.{action_norm}");
    let risk = match action_norm.as_str() {
        "insights_summary"
        | "get_rate_limits"
        | "get_security_policy"
        | "get_node_type_policy"
        | "list_node_type_policies"
        | "get_credential_type_policy"
        | "list_credential_type_policies"
        | "log_streaming_list"
        | "otel_get" => RiskLevel::R0,
        "put_rate_limits"
        | "put_security_policy"
        | "manage_node_type_policy"
        | "delete_node_type_policy"
        | "manage_credential_type_policy"
        | "delete_credential_type_policy"
        | "log_streaming_test"
        | "otel_put"
        | "otel_test" => RiskLevel::R4,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown admin_settings action `{other}`")],
                format!("Unsupported `n8n_admin_settings` action `{other}`"),
            )
            .into_envelope(inst, "admin_settings.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "policyId": params.policy_id,
        "destinationId": params.destination_id,
    });

    if params.preview && risk.is_mutating() {
        return admin_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::AdminSettings,
            risk,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
            ops_payload,
            explicit_apply_intent: false,
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
    let body = params.payload.clone().unwrap_or_else(|| json!({}));

    let res: N8nResult<Value> = match action_norm.as_str() {
        "insights_summary" => api.get_insights_summary(params.date_range.as_deref()).await,
        "get_rate_limits" => api.get_settings(Some("rate-limits")).await,
        "get_security_policy" => api.get_settings(Some("security-policy")).await,
        "get_node_type_policy" | "list_node_type_policies" => api.list_node_type_policies().await,
        "get_credential_type_policy" | "list_credential_type_policies" => {
            api.list_credential_type_policies().await
        }
        "log_streaming_list" => api.get_settings(Some("log-streaming/destinations")).await,
        "otel_get" => api.get_settings(Some("otel")).await,
        "put_rate_limits" => api.update_settings("rate-limits", &body).await,
        "put_security_policy" => api.update_settings("security-policy", &body).await,
        "manage_node_type_policy" => api.upsert_node_type_policy(&body).await,
        "delete_node_type_policy" => match params.policy_id.as_deref() {
            Some(pid) => api.delete_node_type_policy(pid).await,
            None => Err(N8nError::validation(
                alias,
                vec!["missing policyId".into()],
                "policyId required",
            )),
        },
        "manage_credential_type_policy" => api.upsert_credential_type_policy(&body).await,
        "delete_credential_type_policy" => match params.policy_id.as_deref() {
            Some(pid) => api.delete_credential_type_policy(pid).await,
            None => Err(N8nError::validation(
                alias,
                vec!["missing policyId".into()],
                "policyId required",
            )),
        },
        "log_streaming_test" => match params.destination_id.as_deref() {
            Some(did) => match validate_path_segment("destination_id", did) {
                Ok(d_clean) => api
                    .send_raw(RawRequest {
                        method: Method::POST,
                        path_template: "/api/v1/settings/log-streaming/destinations/{id}/test",
                        sub_path: &format!("settings/log-streaming/destinations/{d_clean}/test"),
                        query: &[],
                        body: Some(&body),
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            None => Err(N8nError::validation(
                alias,
                vec!["missing destinationId".into()],
                "destinationId required",
            )),
        },
        "otel_put" => api.update_settings("otel", &body).await,
        "otel_test" => api
            .send_raw(RawRequest {
                method: Method::POST,
                path_template: "/api/v1/settings/otel/test-trace",
                sub_path: "settings/otel/test-trace",
                query: &[],
                body: Some(&body),
                operation_id: None,
                accept_mime: "application/json",
            })
            .await
            .map(|(_, b)| serde_json::from_slice(&b).unwrap_or(Value::Null)),
        _ => unreachable!(),
    };

    match res {
        Ok(payload) => {
            if risk.is_mutating() {
                record_completed_mutation_journal(
                    state,
                    &auth.principal,
                    alias,
                    None,
                    &full_action,
                    None,
                    None,
                    &auth.ops_hash,
                    JournalState::Verified,
                    json!({ "action": action_norm }),
                )
                .await;
            }
            let mut env = ToolEnvelope::new(
                OperationStatus::Success,
                alias,
                full_action,
                auth.policy.permission,
                RouteUsed::PublicApi,
            )
            .with_data(redact_json_value(&payload));
            if risk.is_mutating() {
                env.changed = true;
            }
            env
        }
        Err(err) => err.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

/// Tool #24: `n8n_agents` (strictly gated on advertised `/agents` REST resource or Native MCP agent tool).
pub async fn execute_agents(state: &AppState, params: AgentsParams) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("agents.{action_norm}");
    let rt = match state.instance(params.instance.as_deref()) {
        Ok(r) => r,
        Err(err) => {
            return err.into_envelope(
                params.instance.as_deref().unwrap_or(&state.active_instance),
                full_action,
                RouteUsed::Local,
            );
        }
    };

    let caps = match state
        .resolve_instance_capabilities(rt, action_norm != "list" && action_norm != "get")
        .await
    {
        Ok(c) => c,
        Err(err) => {
            return err.into_envelope(&rt.config.alias, full_action, RouteUsed::PublicApi);
        }
    };

    let route_decision = select_operation_route(&caps, LogicalOperation::Agents);
    if route_decision.state != CapabilityState::Available {
        return N8nError::unsupported(
            &rt.config.alias,
            &full_action,
            format!(
                "Persisted Agents API is unavailable on `{}`: {} (Note: `agent:*` scopes alone do not establish endpoint availability unless `/agents` REST resources or Native MCP agent tools are advertised).",
                rt.config.alias, route_decision.reason
            ),
            route_decision.prerequisites.first().cloned(),
        )
        .into_envelope(&rt.config.alias, full_action, RouteUsed::Unsupported);
    }

    let risk = match action_norm.as_str() {
        "list" | "get" => RiskLevel::R0,
        "create" | "update" => RiskLevel::R2,
        "publish" | "unpublish" => RiskLevel::R3,
        "delete" => RiskLevel::R4,
        other => {
            return N8nError::validation(
                &rt.config.alias,
                vec![format!("unknown agents action `{other}`")],
                format!("Unsupported `n8n_agents` action `{other}`"),
            )
            .into_envelope(&rt.config.alias, "agents.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "agentId": params.agent_id,
    });
    if params.preview && risk.is_mutating() {
        return admin_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::Agents,
            risk,
            workflow_id: None,
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: None,
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

    let Some(ref api) = auth.rt.api_client else {
        return N8nError::unauthenticated(&auth.rt.config.alias, "N8N_API_KEY missing")
            .into_envelope(&auth.rt.config.alias, full_action, RouteUsed::PublicApi);
    };
    let sub_path = match (action_norm.as_str(), params.agent_id.as_deref()) {
        ("list", _) => "agents".to_owned(),
        ("get", Some(id)) => format!("agents/{}", id.trim()),
        _ => "agents".to_owned(),
    };
    let method = match action_norm.as_str() {
        "list" | "get" => Method::GET,
        "delete" => Method::DELETE,
        "update" => Method::PATCH,
        _ => Method::POST,
    };

    match api
        .send_raw(RawRequest {
            method,
            path_template: "/api/v1/agents",
            sub_path: &sub_path,
            query: &[],
            body: params.payload.as_ref(),
            operation_id: None,
            accept_mime: "application/json",
        })
        .await
    {
        Ok((_, bytes)) => {
            let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            ToolEnvelope::new(
                OperationStatus::Success,
                &auth.rt.config.alias,
                full_action,
                auth.policy.permission,
                auth.policy.route,
            )
            .with_data(redact_json_value(&val))
        }
        Err(err) => err.into_envelope(&auth.rt.config.alias, full_action, RouteUsed::PublicApi),
    }
}
