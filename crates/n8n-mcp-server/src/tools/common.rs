use std::collections::HashMap;
use std::sync::Arc;

use n8n_api_client::WorkflowResource;
use n8n_capability::{CapabilityProfile, LogicalOperation};
use n8n_catalog_db::{CatalogDb, NodeInfoMode, NodeInfoRequest};
use n8n_graph::{
    DynamicReferenceHazard, MutationContext, VersionMigrationRegistry, WorkflowIr,
    canonical_blake3_json_hex,
};
use n8n_policy::{PolicyCheckOutcome, PolicyCheckRequest, hash_ops};
use n8n_state_vault::{JournalState, JournalTransitionInput};
use n8n_types::{
    DetailLevel, N8nError, N8nResult, RiskLevel, RouteUsed, ToolEnvelope, UntrustedContent,
    redact_json_value,
};
use n8n_validator::rewrite_literal_node_references;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::state::{AppState, InstanceRuntime};

/// Resolved authorization bundle returned by [`authorize_operation`].
pub struct AuthorizedCall<'a> {
    pub rt: &'a InstanceRuntime,
    pub caps: CapabilityProfile,
    pub policy: PolicyCheckOutcome,
    pub principal: String,
    pub ops_hash: String,
}

/// Parameters for [`authorize_operation`].
pub struct AuthorizeSpec<'a> {
    pub requested_instance: Option<&'a str>,
    pub action: String,
    pub logical_op: LogicalOperation,
    pub risk: RiskLevel,
    pub workflow_id: Option<String>,
    pub project_id: Option<String>,
    pub is_archived_workflow: bool,
    pub expected_version_hash: Option<String>,
    pub ops_payload: Value,
    pub explicit_apply_intent: bool,
    pub approval_receipt: Option<String>,
    pub batch_workflow_count: Option<usize>,
}

/// Resolve instance runtime, refresh/read capabilities, and evaluate `PolicyEngine`.
#[allow(clippy::result_large_err)]
pub async fn authorize_operation<'a>(
    state: &'a AppState,
    spec: AuthorizeSpec<'a>,
) -> Result<AuthorizedCall<'a>, ToolEnvelope<Value>> {
    let rt = match state.instance(spec.requested_instance) {
        Ok(r) => r,
        Err(err) => {
            return Err(err.into_envelope(
                spec.requested_instance.unwrap_or(&state.active_instance),
                &spec.action,
                RouteUsed::Local,
            ));
        }
    };

    let caps = match state
        .resolve_instance_capabilities(rt, spec.risk.is_mutating())
        .await
    {
        Ok(c) => c,
        Err(err) => {
            return Err(err.into_envelope(&rt.config.alias, &spec.action, RouteUsed::PublicApi));
        }
    };

    let principal = state.principal_for(rt);
    let ops_hash = hash_ops(&spec.ops_payload).unwrap_or_default();
    let requested_alias = spec
        .requested_instance
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| rt.config.alias.clone(), str::to_owned);

    let check_req = PolicyCheckRequest {
        principal: principal.clone(),
        requested_instance: requested_alias,
        action: spec.action.clone(),
        logical_op: spec.logical_op,
        risk: spec.risk,
        workflow_id: spec.workflow_id,
        project_id: spec.project_id,
        is_archived_workflow: spec.is_archived_workflow,
        expected_version_hash: spec.expected_version_hash,
        ops_hash: ops_hash.clone(),
        explicit_apply_intent: spec.explicit_apply_intent,
        approval_receipt_token: spec.approval_receipt,
        batch_workflow_count: spec.batch_workflow_count,
    };

    let policy = match state.policy_engine.evaluate(&rt.config, &caps, &check_req) {
        Ok(ok) => ok,
        Err(err) => {
            return Err(err.into_envelope(&rt.config.alias, &spec.action, RouteUsed::Local));
        }
    };

    Ok(AuthorizedCall {
        rt,
        caps,
        policy,
        principal,
        ops_hash,
    })
}

/// Convert a typed `WorkflowResource` into `WorkflowIr` and compute its canonical BLAKE3 hash.
pub fn workflow_resource_to_ir(wf: &WorkflowResource) -> N8nResult<(WorkflowIr, String, Value)> {
    let raw = serde_json::to_value(wf)
        .map_err(|e| N8nError::protocol(format!("failed serializing WorkflowResource: {e}")))?;
    let ir = WorkflowIr::from_json_value(raw.clone())
        .map_err(|e| N8nError::protocol(format!("failed parsing WorkflowIr: {e}")))?;
    let version_hash = ir.canonical_version_hash();
    Ok((ir, version_hash, raw))
}

/// Build an n8n `POST /workflows` or `PUT /workflows/{id}` request body from `WorkflowIr`.
///
/// Enforces n8n Public API OpenAPI `additionalProperties: false` and `readOnly: true` constraints
/// across top-level workflow properties, `settings`, and `nodes[]` items.
pub fn ir_to_workflow_write_body(ir: &WorkflowIr, force_inactive: bool) -> N8nResult<Value> {
    const ALLOWED_TOP_LEVEL: &[&str] = &[
        "name",
        "nodes",
        "connections",
        "settings",
        "nodeGroups",
        "staticData",
        "pinData",
        "parentFolderId",
        "description",
    ];
    const ALLOWED_SETTINGS: &[&str] = &[
        "saveExecutionProgress",
        "saveManualExecutions",
        "saveDataErrorExecution",
        "saveDataSuccessExecution",
        "executionTimeout",
        "errorWorkflow",
        "timezone",
        "executionOrder",
        "binaryMode",
        "engineType",
        "callerPolicy",
        "callerIds",
        "timeSavedMode",
        "timeSavedPerExecution",
        "redactionPolicy",
        "redactCallerExecutions",
        "availableInMCP",
        "customTelemetryTags",
        "credentialResolverId",
    ];
    const ALLOWED_NODE_KEYS: &[&str] = &[
        "id",
        "name",
        "webhookId",
        "disabled",
        "notesInFlow",
        "notes",
        "type",
        "typeVersion",
        "executeOnce",
        "alwaysOutputData",
        "retryOnFail",
        "maxTries",
        "waitBetweenTries",
        "continueOnFail",
        "onError",
        "position",
        "parameters",
        "credentials",
        "customTelemetryTags",
        "extendsCredential",
    ];

    let mut val = ir
        .to_json_value()
        .map_err(|e| N8nError::protocol(format!("failed serializing WorkflowIr: {e}")))?;
    if let Some(obj) = val.as_object_mut() {
        obj.retain(|k, v| {
            ALLOWED_TOP_LEVEL.contains(&k.as_str())
                && !(matches!(
                    k.as_str(),
                    "nodeGroups" | "pinData" | "parentFolderId" | "description"
                ) && v.is_null())
        });

        if let Some(settings_obj) = obj.get_mut("settings").and_then(Value::as_object_mut) {
            settings_obj.retain(|k, v| ALLOWED_SETTINGS.contains(&k.as_str()) && !v.is_null());
        } else {
            obj.insert("settings".to_owned(), json!({ "executionOrder": "v1" }));
        }

        if let Some(nodes_arr) = obj.get_mut("nodes").and_then(Value::as_array_mut) {
            for node_val in nodes_arr {
                if let Some(node_obj) = node_val.as_object_mut() {
                    node_obj.retain(|k, v| ALLOWED_NODE_KEYS.contains(&k.as_str()) && !v.is_null());
                }
            }
        }

        let _ = force_inactive;
    }
    Ok(val)
}

/// Compute canonical hash of any JSON value.
#[must_use]
pub fn compute_json_version_hash(val: &Value) -> String {
    if let Ok(ir) = WorkflowIr::from_json_value(val.clone()) {
        ir.canonical_version_hash()
    } else {
        canonical_blake3_json_hex(val, "n8n-rs-mcp/v2/workflow-version-hash")
    }
}

/// Render a `WorkflowResource` according to `DetailLevel` with `UntrustedContent` node notes framing.
#[must_use]
pub fn format_workflow_view(wf: &WorkflowResource, detail: DetailLevel) -> Value {
    let sanitized_nodes: Vec<Value> = wf
        .nodes
        .iter()
        .map(|node| {
            let mut copy = redact_json_value(node);
            if let Some(obj) = copy.as_object_mut()
                && let Some(notes_str) = obj.get("notes").and_then(Value::as_str).map(str::to_owned)
            {
                let wrapped =
                    UntrustedContent::from_untrusted_text("workflow.node.notes", &notes_str);
                obj.insert(
                    "notes".to_owned(),
                    serde_json::to_value(wrapped).unwrap_or(Value::Null),
                );
            }
            if detail == DetailLevel::Minimal {
                json!({
                    "id": copy.get("id"),
                    "name": copy.get("name"),
                    "type": copy.get("type"),
                    "typeVersion": copy.get("typeVersion"),
                    "disabled": copy.get("disabled").unwrap_or(&Value::Bool(false)),
                })
            } else {
                copy
            }
        })
        .collect();

    match detail {
        DetailLevel::Minimal => json!({
            "id": wf.id,
            "name": wf.name,
            "active": wf.active,
            "isArchived": wf.is_archived,
            "versionId": wf.version_id,
            "activeVersionId": wf.active_version_id,
            "nodeCount": wf.nodes.len(),
        }),
        DetailLevel::Standard => json!({
            "id": wf.id,
            "name": wf.name,
            "active": wf.active,
            "isArchived": wf.is_archived,
            "versionId": wf.version_id,
            "activeVersionId": wf.active_version_id,
            "updatedAt": wf.updated_at,
            "tags": wf.tags,
            "nodes": sanitized_nodes,
            "connections": redact_json_value(&wf.connections),
        }),
        DetailLevel::Full => redact_json_value(&json!({
            "id": wf.id,
            "name": wf.name,
            "active": wf.active,
            "isArchived": wf.is_archived,
            "versionId": wf.version_id,
            "activeVersionId": wf.active_version_id,
            "createdAt": wf.created_at,
            "updatedAt": wf.updated_at,
            "tags": wf.tags,
            "settings": wf.settings,
            "nodes": sanitized_nodes,
            "connections": wf.connections,
        })),
    }
}

/// Build a `MutationContext` wiring `CatalogDb` credential rules and `oxc_parser` AST literal-vs-dynamic rename analysis.
pub fn build_mutation_context_for_ir(ir: &WorkflowIr, catalog: &CatalogDb) -> MutationContext {
    let mut allowed_creds: HashMap<String, Vec<String>> = HashMap::new();
    for node in &ir.nodes {
        if allowed_creds.contains_key(&node.node_type) {
            continue;
        }
        if let Ok(info) = catalog.get_node_info(&NodeInfoRequest {
            node_type: node.node_type.clone(),
            mode: NodeInfoMode::Info,
            type_version: None,
            property_query: None,
        }) && !info.credentials.is_empty()
        {
            allowed_creds.insert(
                node.node_type.clone(),
                info.credentials.into_iter().map(|c| c.name).collect(),
            );
        }
    }

    let hook = Arc::new(
        move |holder_node: &str,
              pointer: &str,
              expr_str: &str,
              old_name: &str,
              new_name: &str|
              -> Result<Option<String>, DynamicReferenceHazard> {
            match rewrite_literal_node_references(expr_str, old_name, new_name) {
                Ok(out) => {
                    if out.changed {
                        Ok(Some(out.rewritten))
                    } else {
                        Ok(None)
                    }
                }
                Err(err) => Err(DynamicReferenceHazard {
                    node_name: holder_node.to_owned(),
                    parameter_pointer: pointer.to_owned(),
                    expression_snippet: err.to_string(),
                }),
            }
        },
    );

    MutationContext {
        migration_registry: VersionMigrationRegistry::new(),
        allowed_credential_types: (!allowed_creds.is_empty()).then_some(allowed_creds),
        expression_rewrite_map: HashMap::new(),
        custom_rename_hook: Some(hook),
        diff_max_chars: None,
    }
}

/// Record a full state-machine journal trace for a synchronous/single-HTTP mutating call.
#[allow(clippy::too_many_arguments)]
pub async fn record_completed_mutation_journal(
    state: &AppState,
    principal: &str,
    instance: &str,
    workflow_id: Option<&str>,
    action: &str,
    base_hash: Option<&str>,
    result_hash: Option<&str>,
    ops_hash: &str,
    terminal_state: JournalState,
    details: Value,
) -> String {
    let op_id = format!("op_{}", Uuid::new_v4().simple());
    let steps = [
        JournalState::Planned,
        JournalState::Preparing,
        JournalState::Writing,
        JournalState::Verifying,
        terminal_state,
    ];
    for step in steps {
        state
            .append_journal_best_effort(JournalTransitionInput {
                operation_id: op_id.clone(),
                next_state: step,
                principal_id: principal.to_owned(),
                instance_id: instance.to_owned(),
                workflow_id: workflow_id.map(str::to_owned),
                action: action.to_owned(),
                base_version_hash: base_hash.map(str::to_owned),
                resulting_version_hash: (step == terminal_state)
                    .then(|| result_hash.map(str::to_owned))
                    .flatten(),
                ops_hash: Some(ops_hash.to_owned()),
                details: if step == terminal_state {
                    details.clone()
                } else {
                    json!({})
                },
            })
            .await;
    }
    op_id
}

/// Validate exact semver (`X.Y.Z`) and npm package name rules for `n8n_community_packages`.
pub fn validate_pinned_community_package(
    instance: &str,
    package_name: &str,
    version: Option<&str>,
    require_version: bool,
) -> N8nResult<()> {
    let trimmed = package_name.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.starts_with("git+")
        || trimmed.starts_with("file:")
        || trimmed.ends_with(".tgz")
        || trimmed.ends_with(".tar.gz")
        || !(trimmed.starts_with("n8n-nodes-") || trimmed.contains("/n8n-nodes-"))
    {
        return Err(N8nError::policy_blocked(
            "community_packages.validate",
            RiskLevel::R4,
            "package-allowlist",
            format!(
                "Community package `{trimmed}` rejected: must be a registry `n8n-nodes-*` package (git/tarball/URL sources are forbidden)"
            ),
            None,
        ));
    }

    if require_version {
        let ver = version.map(str::trim).unwrap_or("");
        if !is_exact_semver(ver) {
            return Err(N8nError::validation(
                instance,
                vec![format!("invalid version `{ver}`")],
                "Community package install/update requires an exact pinned `X.Y.Z` semver version (`latest`, `*`, `^`, `~` are forbidden)",
            ));
        }
    } else if let Some(ver) = version.map(str::trim).filter(|s| !s.is_empty())
        && !is_exact_semver(ver)
    {
        return Err(N8nError::validation(
            instance,
            vec![format!("invalid version `{ver}`")],
            "Version must be an exact `X.Y.Z` semver string",
        ));
    }

    Ok(())
}

fn is_exact_semver(ver: &str) -> bool {
    if ver.is_empty()
        || ver.eq_ignore_ascii_case("latest")
        || ver.contains('^')
        || ver.contains('~')
        || ver.contains('*')
        || ver.contains('>')
        || ver.contains('<')
        || ver.contains(' ')
    {
        return false;
    }
    let core = ver.split_once('-').map_or(ver, |(c, _)| c);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}
