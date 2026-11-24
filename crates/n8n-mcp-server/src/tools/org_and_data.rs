//! Tools #16 (`n8n_credentials`), #17 (`n8n_datatables`), and #18 (`n8n_catalog_org`).

use http::Method;
use n8n_api_client::{Outcome, RawRequest, validate_path_segment};
use n8n_capability::LogicalOperation;
use n8n_policy::hash_ops;
use n8n_state_vault::JournalState;
use n8n_types::{
    DetailLevel, N8nError, N8nResult, OperationStatus, PermissionDecision, RiskLevel, RouteUsed,
    ToolEnvelope, VerificationReport, redact_json_value, redact_str,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::PreviewPlanInit;
use crate::state::AppState;
use crate::tools::common::{AuthorizeSpec, authorize_operation, record_completed_mutation_journal};

fn default_list_action() -> String {
    "list".to_owned()
}

fn default_projects_resource() -> String {
    "projects".to_owned()
}

/// Input schema for Tool #16: `n8n_credentials`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsParams {
    #[serde(default = "default_list_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default)]
    pub credential_type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub destination_project_id: Option<String>,
    /// Credential payload for `create`/`update`; secret `data` is NEVER echoed in previews, journals, or envelopes.
    #[serde(default)]
    pub credential_data: Option<Value>,
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

/// Input schema for Tool #17: `n8n_datatables`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataTablesParams {
    #[serde(default = "default_list_tables_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub table_id: Option<String>,
    #[serde(default)]
    pub column_id: Option<String>,
    #[serde(default)]
    pub row_id: Option<String>,
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

fn default_list_tables_action() -> String {
    "list_tables".to_owned()
}

/// Input schema for Tool #18: `n8n_catalog_org`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogOrgParams {
    #[serde(default = "default_projects_resource")]
    pub resource: String,
    #[serde(default = "default_list_action")]
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub tag_id: Option<String>,
    #[serde(default)]
    pub variable_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
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

fn make_preview(
    state: &AppState,
    requested_instance: Option<&str>,
    full_action: &str,
    risk: RiskLevel,
    ops_payload: &Value,
    summary: String,
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
        summary,
        diff: None,
        diff_payload: redact_json_value(ops_payload),
        side_effects: vec![format!("Risk level: {}", risk.label())],
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
        "Call `n8n_workflows` with `action=\"confirm_plan\"` and `planId=\"{}\"` after operator approval.",
        plan.plan_id
    )])
    .with_data(json!({
        "planId": plan.plan_id,
        "risk": plan.risk,
        "expiresAt": plan.expires_at,
    }))
}

fn strip_secret_data_metadata(val: Option<&Value>) -> Value {
    let Some(v) = val else {
        return Value::Null;
    };
    if let Some(obj) = v.as_object() {
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        json!({ "suppliedFieldNames": keys, "secretValuesRedacted": true })
    } else {
        json!({ "secretValuesRedacted": true })
    }
}

/// Tool #16: `n8n_credentials`.
#[allow(clippy::too_many_lines)]
pub async fn execute_credentials(
    state: &AppState,
    params: CredentialsParams,
) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("credentials.{action_norm}");

    if action_norm == "list_catalog_types" {
        let inst = params
            .instance
            .as_deref()
            .unwrap_or(&state.active_instance)
            .to_owned();
        return match state.with_catalog(|db| db.list_credential_types()) {
            Ok(types) => ToolEnvelope::new(
                OperationStatus::Success,
                inst,
                full_action,
                PermissionDecision::Allowed,
                RouteUsed::Local,
            )
            .with_data(json!({ "count": types.len(), "credentialTypes": types })),
            Err(e) => e.into_envelope(inst, full_action, RouteUsed::Local),
        };
    }

    if action_norm == "schema" {
        let inst = params
            .instance
            .as_deref()
            .unwrap_or(&state.active_instance)
            .to_owned();
        let Some(cred_type) = params
            .credential_type
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        else {
            return N8nError::validation(
                &inst,
                vec!["missing `credentialType`".to_owned()],
                "`credentialType` is required for `credentials.schema`",
            )
            .into_envelope(inst, full_action, RouteUsed::Local);
        };
        if let Ok(rt) = state.instance(params.instance.as_deref())
            && let Some(ref api) = rt.api_client
            && let Ok(live_schema) = api.get_credential_schema(cred_type).await
        {
            return ToolEnvelope::new(
                OperationStatus::Success,
                &rt.config.alias,
                full_action,
                PermissionDecision::Allowed,
                RouteUsed::PublicApi,
            )
            .with_data(json!({
                "credentialType": cred_type,
                "source": "public_api",
                "schema": redact_json_value(&live_schema),
            }));
        }
        return match state.with_catalog(|db| db.get_credential_type(cred_type)) {
            Ok(Some(schema)) => ToolEnvelope::new(
                OperationStatus::Success,
                inst,
                full_action,
                PermissionDecision::Allowed,
                RouteUsed::Local,
            )
            .with_data(json!({
                "credentialType": cred_type,
                "source": "offline_catalog",
                "schema": schema,
            })),
            Ok(None) => N8nError::not_found_or_concealed(
                &inst,
                format!("credentialType/{cred_type}"),
                format!("Credential schema `{cred_type}` not found in API or offline catalog"),
            )
            .into_envelope(inst, full_action, RouteUsed::Local),
            Err(e) => e.into_envelope(inst, full_action, RouteUsed::Local),
        };
    }

    let risk = match action_norm.as_str() {
        "list" | "dependencies" => RiskLevel::R0,
        "test" => RiskLevel::R2,
        "create" | "update" | "transfer" => RiskLevel::R3,
        "delete" => RiskLevel::R4,
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown credentials action `{other}`")],
                format!("Unsupported `n8n_credentials` action `{other}`"),
            )
            .into_envelope(inst, "credentials.unknown", RouteUsed::Local);
        }
    };

    // Never hash or persist raw secret values inside ops_payload!
    let ops_payload = json!({
        "action": action_norm,
        "credentialId": params.credential_id,
        "credentialType": params.credential_type,
        "name": params.name,
        "destinationProjectId": params.destination_project_id,
        "dataMeta": strip_secret_data_metadata(params.credential_data.as_ref()),
    });

    if params.preview && risk.is_mutating() {
        return make_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
            format!("Preview `{full_action}` (secret fields stripped)"),
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::Credentials,
            risk,
            workflow_id: None,
            project_id: params.destination_project_id.clone(),
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

    let alias = &auth.rt.config.alias;
    let Some(ref api) = auth.rt.api_client else {
        return N8nError::unauthenticated(alias, "N8N_API_KEY missing").into_envelope(
            alias,
            full_action,
            RouteUsed::PublicApi,
        );
    };

    let res: N8nResult<Value> = match action_norm.as_str() {
        "list" => api
            .list_credentials(params.limit, params.cursor.as_deref())
            .await
            .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
        "dependencies" => {
            let Some(cid) = params.credential_id.as_deref() else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialId".into()],
                    "credentialId required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            api.get_credential_dependencies(cid).await
        }
        "test" => {
            let Some(cid) = params.credential_id.as_deref() else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialId".into()],
                    "credentialId required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            api.test_credential(cid).await
        }
        "create" => {
            let Some(ctype) = params.credential_type.as_deref() else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialType".into()],
                    "credentialType required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            let Some(cname) = params.name.as_deref() else {
                return N8nError::validation(alias, vec!["missing name".into()], "name required")
                    .into_envelope(alias, full_action, RouteUsed::Local);
            };
            let body = json!({
                "name": cname,
                "type": ctype,
                "data": params.credential_data.clone().unwrap_or_else(|| json!({})),
            });
            let op_id = params
                .operation_id
                .clone()
                .unwrap_or_else(|| format!("op_{}", Uuid::new_v4().simple()));
            match api.create_credential(&op_id, &body).await {
                Ok(Outcome::Confirmed { value }) => Ok(json!({
                    "id": value.id,
                    "name": value.name,
                    "type": value.credential_type,
                    "createdAt": value.created_at,
                })),
                Ok(Outcome::UnknownNeedsReconcile {
                    operation_id,
                    reason,
                    ..
                }) => {
                    return ToolEnvelope::new(
                        OperationStatus::Partial,
                        alias,
                        full_action,
                        auth.policy.permission,
                        RouteUsed::PublicApi,
                    )
                    .with_verification(VerificationReport::inconclusive([reason]))
                    .with_data(json!({ "operationId": operation_id, "uncertainOutcome": true }));
                }
                Err(e) => Err(e),
            }
        }
        "update" => {
            let Some(cid) = params.credential_id.as_deref() else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialId".into()],
                    "credentialId required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            let mut body = serde_json::Map::new();
            if let Some(n) = &params.name {
                body.insert("name".to_owned(), json!(n));
            }
            if let Some(ct) = &params.credential_type {
                body.insert("type".to_owned(), json!(ct));
            }
            if let Some(d) = &params.credential_data {
                body.insert("data".to_owned(), d.clone());
            }
            api.update_credential(cid, &Value::Object(body))
                .await
                .map(|v| {
                    json!({
                        "id": v.id,
                        "name": v.name,
                        "type": v.credential_type,
                        "updatedAt": v.updated_at,
                    })
                })
        }
        "transfer" => {
            let (Some(cid), Some(dest)) = (
                params.credential_id.as_deref(),
                params.destination_project_id.as_deref(),
            ) else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialId or destinationProjectId".into()],
                    "credentialId and destinationProjectId are required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            api.transfer_credential(cid, dest).await
        }
        "delete" => {
            let Some(cid) = params.credential_id.as_deref() else {
                return N8nError::validation(
                    alias,
                    vec!["missing credentialId".into()],
                    "credentialId required",
                )
                .into_envelope(alias, full_action, RouteUsed::Local);
            };
            api.delete_credential(cid)
                .await
                .map(|v| json!({ "deletedId": v.id, "name": v.name }))
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
                    json!({ "credentialId": params.credential_id }),
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
                env = env.with_verification(VerificationReport::verified([
                    "Credential metadata operation succeeded (secret values never echoed)."
                        .to_owned(),
                ]));
            }
            env
        }
        Err(err) => err.into_envelope(alias, full_action, RouteUsed::PublicApi),
    }
}

/// Tool #17: `n8n_datatables`.
#[allow(clippy::too_many_lines)]
pub async fn execute_datatables(state: &AppState, params: DataTablesParams) -> ToolEnvelope<Value> {
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("datatables.{action_norm}");
    let risk = match action_norm.as_str() {
        "list_tables" | "get_table" | "dependencies" | "list_columns" | "list_rows" => {
            RiskLevel::R0
        }
        "create_table" | "update_table" | "create_column" | "update_column" | "insert_rows"
        | "upsert_row" | "upsert_rows" | "update_row" | "update_rows" => RiskLevel::R3,
        "delete_table" | "delete_column" | "delete_row" | "delete_rows" | "clear_rows" => {
            RiskLevel::R4
        }
        other => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unknown datatables action `{other}`")],
                format!("Unsupported `n8n_datatables` action `{other}`"),
            )
            .into_envelope(inst, "datatables.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "action": action_norm,
        "tableId": params.table_id,
        "columnId": params.column_id,
        "rowId": params.row_id,
        "payload": redact_json_value(params.payload.as_ref().unwrap_or(&Value::Null)),
    });

    if params.preview && risk.is_mutating() {
        return make_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
            format!("Preview `{full_action}` on table {:?}", params.table_id),
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::DataTables,
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
        "list_tables" => api
            .list_data_tables(params.limit, params.cursor.as_deref())
            .await
            .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
        "get_table" => match params.table_id.as_deref() {
            Some(tid) => api.get_data_table(tid).await.and_then(|t| {
                serde_json::to_value(t).map_err(|e| N8nError::protocol(e.to_string()))
            }),
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "dependencies" => match params.table_id.as_deref() {
            Some(tid) => api.get_data_table_dependencies(tid).await,
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "create_table" => api.create_data_table(&op_id, &body).await.map(|o| match o {
            Outcome::Confirmed { value } => serde_json::to_value(value).unwrap_or(Value::Null),
            Outcome::UnknownNeedsReconcile {
                operation_id,
                reason,
                ..
            } => {
                json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
            }
        }),
        "update_table" => match params.table_id.as_deref() {
            Some(tid) => api
                .update_data_table(tid, &body)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null)),
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "delete_table" => match params.table_id.as_deref() {
            Some(tid) => api.delete_data_table(tid).await,
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "list_columns" => match params.table_id.as_deref() {
            Some(tid) => api.list_data_table_columns(tid).await,
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "create_column" => match params.table_id.as_deref() {
            Some(tid) => api
                .create_data_table_column(&op_id, tid, &body)
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
                }),
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "update_column" => match (params.table_id.as_deref(), params.column_id.as_deref()) {
            (Some(tid), Some(cid)) => api.update_data_table_column(tid, cid, &body).await,
            _ => Err(N8nError::validation(alias, vec!["missing tableId/columnId".into()], "tableId and columnId required")),
        },
        "delete_column" => match (params.table_id.as_deref(), params.column_id.as_deref()) {
            (Some(tid), Some(cid)) => api.delete_data_table_column(tid, cid).await,
            _ => Err(N8nError::validation(alias, vec!["missing tableId/columnId".into()], "tableId and columnId required")),
        },
        "list_rows" => match params.table_id.as_deref() {
            Some(tid) => api.list_data_table_rows(tid, params.limit, params.cursor.as_deref()).await,
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "insert_rows" => match params.table_id.as_deref() {
            Some(tid) => api
                .insert_data_table_rows(&op_id, tid, &body)
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
                }),
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "upsert_row" | "upsert_rows" => match params.table_id.as_deref() {
            Some(tid) => api.upsert_data_table_rows(tid, &body).await,
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "update_row" | "update_rows" => match (params.table_id.as_deref(), params.row_id.as_deref()) {
            (Some(tid), Some(rid)) => api.update_data_table_row(tid, rid, &body).await,
            (Some(tid), None) => match validate_path_segment("table_id", tid) {
                Ok(tid_clean) => api
                    .send_raw(RawRequest {
                        method: Method::PATCH,
                        path_template: "/api/v1/data-tables/{id}/rows/update",
                        sub_path: &format!("data-tables/{tid_clean}/rows/update"),
                        query: &[],
                        body: Some(&body),
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            _ => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "delete_row" | "delete_rows" => match (params.table_id.as_deref(), params.row_id.as_deref()) {
            (Some(tid), Some(rid)) => api.delete_data_table_row(tid, rid).await,
            (Some(tid), None) => match validate_path_segment("table_id", tid) {
                Ok(tid_clean) => api
                    .send_raw(RawRequest {
                        method: Method::DELETE,
                        path_template: "/api/v1/data-tables/{id}/rows/delete",
                        sub_path: &format!("data-tables/{tid_clean}/rows/delete"),
                        query: &[],
                        body: Some(&body),
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            _ => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
        "clear_rows" => match params.table_id.as_deref() {
            Some(tid) => match validate_path_segment("table_id", tid) {
                Ok(tid_clean) => api
                    .send_raw(RawRequest {
                        method: Method::DELETE,
                        path_template: "/api/v1/data-tables/{id}/rows/clear",
                        sub_path: &format!("data-tables/{tid_clean}/rows/clear"),
                        query: &[],
                        body: None,
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
                Err(e) => Err(e),
            },
            None => Err(N8nError::validation(alias, vec!["missing tableId".into()], "tableId required")),
        },
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
                    json!({ "tableId": params.table_id }),
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

/// Tool #18: `n8n_catalog_org`.
#[allow(clippy::too_many_lines)]
pub async fn execute_catalog_org(
    state: &AppState,
    params: CatalogOrgParams,
) -> ToolEnvelope<Value> {
    let resource_norm = params.resource.trim().to_ascii_lowercase();
    let action_norm = params.action.trim().to_ascii_lowercase();
    let full_action = format!("catalog_org.{resource_norm}.{action_norm}");

    let risk = match (resource_norm.as_str(), action_norm.as_str()) {
        ("projects" | "folders" | "tags" | "variables", "list" | "get") => RiskLevel::R0,
        ("tags", "create" | "update") => RiskLevel::R2,
        ("projects" | "folders" | "variables", "create" | "update") => RiskLevel::R3,
        ("projects" | "folders" | "tags" | "variables", "delete") => RiskLevel::R4,
        _ => {
            let inst = params.instance.as_deref().unwrap_or(&state.active_instance);
            return N8nError::validation(
                inst,
                vec![format!("unsupported resource/action `{resource_norm}.{action_norm}`")],
                "Expected resource in {projects, folders, tags, variables} and action in {list, get, create, update, delete}",
            )
            .into_envelope(inst, "catalog_org.unknown", RouteUsed::Local);
        }
    };

    let ops_payload = json!({
        "resource": resource_norm,
        "action": action_norm,
        "projectId": params.project_id,
        "folderId": params.folder_id,
        "tagId": params.tag_id,
        "variableId": params.variable_id,
        "name": params.name,
        "key": params.key,
    });

    if params.preview && risk.is_mutating() {
        return make_preview(
            state,
            params.instance.as_deref(),
            &full_action,
            risk,
            &ops_payload,
            format!("Preview `{full_action}`"),
        );
    }

    let auth = match authorize_operation(
        state,
        AuthorizeSpec {
            requested_instance: params.instance.as_deref(),
            action: full_action.clone(),
            logical_op: LogicalOperation::CatalogOrg,
            risk,
            workflow_id: None,
            project_id: params.project_id.clone(),
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

    let res: N8nResult<Value> = match (resource_norm.as_str(), action_norm.as_str()) {
        ("projects", "list") => api
            .list_projects(params.limit, params.cursor.as_deref())
            .await
            .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
        ("projects", "get") => match params.project_id.as_deref() {
            Some(pid) => api
                .get_project(pid)
                .await
                .map(|p| serde_json::to_value(p).unwrap_or(Value::Null)),
            None => Err(N8nError::validation(alias, vec!["missing projectId".into()], "projectId required")),
        },
        ("projects", "create") => match params.name.as_deref() {
            Some(n) => api.create_project(&op_id, n).await.map(|o| match o {
                Outcome::Confirmed { value } => serde_json::to_value(value).unwrap_or(Value::Null),
                Outcome::UnknownNeedsReconcile {
                    operation_id,
                    reason,
                    ..
                } => {
                    json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                }
            }),
            None => Err(N8nError::validation(alias, vec!["missing name".into()], "name required")),
        },
        ("projects", "update") => match (params.project_id.as_deref(), params.name.as_deref()) {
            (Some(pid), Some(n)) => api
                .update_project(pid, n)
                .await
                .map(|p| serde_json::to_value(p).unwrap_or(Value::Null)),
            _ => Err(N8nError::validation(alias, vec!["missing projectId/name".into()], "projectId and name required")),
        },
        ("projects", "delete") => match params.project_id.as_deref() {
            Some(pid) => api.delete_project(pid).await,
            None => Err(N8nError::validation(alias, vec!["missing projectId".into()], "projectId required")),
        },
        ("folders", "list") => match params.project_id.as_deref() {
            Some(pid) => api
                .list_folders(pid, params.limit, params.cursor.as_deref())
                .await
                .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
            None => Err(N8nError::validation(alias, vec!["missing projectId".into()], "projectId required")),
        },
        ("folders", "get") => match (params.project_id.as_deref(), params.folder_id.as_deref()) {
            (Some(pid), Some(fid)) => match (
                validate_path_segment("project_id", pid),
                validate_path_segment("folder_id", fid),
            ) {
                (Ok(p_clean), Ok(f_clean)) => api
                    .send_raw(RawRequest {
                        method: Method::GET,
                        path_template: "/api/v1/projects/{projectId}/folders/{folderId}",
                        sub_path: &format!("projects/{p_clean}/folders/{f_clean}"),
                        query: &[],
                        body: None,
                        operation_id: None,
                        accept_mime: "application/json",
                    })
                    .await
                    .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
                (Err(e), _) | (_, Err(e)) => Err(e),
            },
            _ => Err(N8nError::validation(alias, vec!["missing projectId/folderId".into()], "projectId and folderId required")),
        },
        ("folders", "create") => match params.project_id.as_deref() {
            Some(pid) => {
                let body = params
                    .payload
                    .clone()
                    .unwrap_or_else(|| json!({ "name": params.name }));
                api.create_folder(&op_id, pid, &body).await.map(|o| match o {
                    Outcome::Confirmed { value } => serde_json::to_value(value).unwrap_or(Value::Null),
                    Outcome::UnknownNeedsReconcile {
                        operation_id,
                        reason,
                        ..
                    } => {
                        json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                    }
                })
            }
            None => Err(N8nError::validation(alias, vec!["missing projectId".into()], "projectId required")),
        },
        ("folders", "update") => match (params.project_id.as_deref(), params.folder_id.as_deref()) {
            (Some(pid), Some(fid)) => {
                let body = params
                    .payload
                    .clone()
                    .unwrap_or_else(|| json!({ "name": params.name }));
                api.update_folder(pid, fid, &body)
                    .await
                    .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
            }
            _ => Err(N8nError::validation(alias, vec!["missing projectId/folderId".into()], "projectId and folderId required")),
        },
        ("folders", "delete") => match (params.project_id.as_deref(), params.folder_id.as_deref()) {
            (Some(pid), Some(fid)) => api.delete_folder(pid, fid).await,
            _ => Err(N8nError::validation(alias, vec!["missing projectId/folderId".into()], "projectId and folderId required")),
        },
        ("tags", "list") => api
            .list_tags(params.limit, params.cursor.as_deref())
            .await
            .map(|p| json!({ "items": p.data, "nextCursor": p.next_cursor })),
        ("tags", "get") => match params.tag_id.as_deref() {
            Some(tid) => api
                .get_tag(tid)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null)),
            None => Err(N8nError::validation(alias, vec!["missing tagId".into()], "tagId required")),
        },
        ("tags", "create") => match params.name.as_deref() {
            Some(n) => api.create_tag(&op_id, n).await.map(|o| match o {
                Outcome::Confirmed { value } => serde_json::to_value(value).unwrap_or(Value::Null),
                Outcome::UnknownNeedsReconcile {
                    operation_id,
                    reason,
                    ..
                } => {
                    json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                }
            }),
            None => Err(N8nError::validation(alias, vec!["missing name".into()], "name required")),
        },
        ("tags", "update") => match (params.tag_id.as_deref(), params.name.as_deref()) {
            (Some(tid), Some(n)) => api
                .update_tag(tid, n)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null)),
            _ => Err(N8nError::validation(alias, vec!["missing tagId/name".into()], "tagId and name required")),
        },
        ("tags", "delete") => match params.tag_id.as_deref() {
            Some(tid) => api
                .delete_tag(tid)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null)),
            None => Err(N8nError::validation(alias, vec!["missing tagId".into()], "tagId required")),
        },
        ("variables", "list" | "get") => api
            .list_variables(params.limit, params.cursor.as_deref())
            .await
            .map(|p| {
                let redacted_items: Vec<Value> = p
                    .data
                    .into_iter()
                    .map(|v| {
                        json!({
                            "id": v.id,
                            "key": v.key,
                            "value": redact_str(&v.value),
                            "type": v.variable_type,
                        })
                    })
                    .collect();
                json!({ "items": redacted_items, "nextCursor": p.next_cursor })
            }),
        ("variables", "create") => {
            let body = params.payload.clone().unwrap_or_else(|| {
                json!({
                    "key": params.key,
                    "value": params.value.clone().unwrap_or_default(),
                })
            });
            api.create_variable(&op_id, &body).await.map(|o| match o {
                Outcome::Confirmed { value } => json!({
                    "id": value.id,
                    "key": value.key,
                    "value": redact_str(&value.value),
                }),
                Outcome::UnknownNeedsReconcile {
                    operation_id,
                    reason,
                    ..
                } => {
                    json!({ "operationId": operation_id, "uncertainOutcome": true, "message": reason })
                }
            })
        }
        ("variables", "update") => match params.variable_id.as_deref() {
            Some(vid) => {
                let body = params.payload.clone().unwrap_or_else(|| {
                    json!({
                        "key": params.key,
                        "value": params.value.clone().unwrap_or_default(),
                    })
                });
                api.update_variable(vid, &body).await.map(|v| {
                    json!({
                        "id": v.id,
                        "key": v.key,
                        "value": redact_str(&v.value),
                    })
                })
            }
            None => Err(N8nError::validation(alias, vec!["missing variableId".into()], "variableId required")),
        },
        ("variables", "delete") => match params.variable_id.as_deref() {
            Some(vid) => api.delete_variable(vid).await,
            None => Err(N8nError::validation(alias, vec!["missing variableId".into()], "variableId required")),
        },
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
                    json!({ "resource": resource_norm }),
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
