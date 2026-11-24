use n8n_catalog_db::{
    NodeInfoMode, NodeInfoRequest, NodeSearchQuery, NodeSourceFilter, SearchMode,
    TemplateDetailMode, TemplateSearchMode, TemplateSearchQuery,
};
use n8n_graph::WorkflowIr;
use n8n_types::{
    DetailLevel, N8nError, OperationStatus, PermissionDecision, RouteUsed, ToolEnvelope,
    VerificationReport, redact_json_value,
};
use n8n_validator::{
    ValidationOptions, ValidationProfile, validate_node_json, validate_workflow,
    validate_workflow_skeleton,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::AppState;

/// Input schema for Tool #1: `n8n_capabilities`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesParams {
    /// Optional target instance alias (defaults to active configured instance).
    pub instance: Option<String>,
    /// Output verbosity (`minimal`, `standard`, `full`).
    #[serde(default)]
    pub detail: DetailLevel,
    /// Force a fresh discovery handshake bypassing the short-TTL cache.
    #[serde(default)]
    pub refresh: bool,
}

/// Input schema for Tool #2: `n8n_catalog_nodes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogNodesParams {
    /// Action (`search`, `info`, `docs`, `search_properties`, `versions`, `provenance`).
    #[serde(default = "default_search_action")]
    pub action: String,
    /// Search query string (for `search`) or node type identifier (for `info`/`docs`/`versions`).
    #[serde(default)]
    pub query: Option<String>,
    /// Explicit node type (e.g. `n8n-nodes-base.slack` or `slack`).
    #[serde(default)]
    pub node_type: Option<String>,
    /// Optional target `typeVersion` string (e.g. `"2.2"`).
    #[serde(default)]
    pub type_version: Option<String>,
    /// Optional property search substring (for `search_properties`).
    #[serde(default)]
    pub property_query: Option<String>,
    /// Lexical search mode (`OR`, `AND`, `FUZZY`).
    #[serde(default)]
    pub mode: SearchMode,
    /// Package source filter (`all`, `core`, `langchain`, `community`).
    #[serde(default)]
    pub source: NodeSourceFilter,
    /// Include resource/operation list on `search` hits.
    #[serde(default = "default_true")]
    pub include_operations: bool,
    /// Output verbosity (`minimal`, `standard`, `full`).
    #[serde(default)]
    pub detail: DetailLevel,
    /// Maximum results (`1..=100`, default `20`).
    #[serde(default = "default_limit_20")]
    pub limit: usize,
}

/// Input schema for Tool #3: `n8n_catalog_templates`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogTemplatesParams {
    /// Action (`search`, `get`, `list`).
    #[serde(default = "default_search_action")]
    pub action: String,
    /// Template ID (required when `action == "get"`).
    #[serde(default)]
    pub template_id: Option<String>,
    /// Search mode (`keyword`, `by_nodes`, `by_task`, `by_metadata`, `patterns`).
    #[serde(default)]
    pub mode: TemplateSearchMode,
    /// Keyword or pattern query.
    #[serde(default)]
    pub query: Option<String>,
    /// Filter by required node types (for `by_nodes`).
    #[serde(default)]
    pub node_types: Vec<String>,
    /// Require all `node_types` to match.
    #[serde(default)]
    pub match_all_nodes: bool,
    /// Task category filter (for `by_task`).
    #[serde(default)]
    pub task: Option<String>,
    /// Category filter.
    #[serde(default)]
    pub category: Option<String>,
    /// Complexity filter (`beginner`, `intermediate`, `advanced`).
    #[serde(default)]
    pub complexity: Option<String>,
    /// Maximum estimated setup minutes.
    #[serde(default)]
    pub max_setup_minutes: Option<u32>,
    /// Filter by required credential type.
    #[serde(default)]
    pub required_credential: Option<String>,
    /// Template projection mode (`nodes_only`, `structure`, `full`).
    #[serde(default)]
    pub template_detail: TemplateDetailMode,
    /// Envelope verbosity (`minimal`, `standard`, `full`).
    #[serde(default)]
    pub detail: DetailLevel,
    /// Maximum results (`1..=100`, default `20`).
    #[serde(default = "default_limit_20")]
    pub limit: usize,
}

/// Input schema for Tool #4: `n8n_validate`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateParams {
    /// Optional target instance alias.
    #[serde(default)]
    pub instance: Option<String>,
    /// Workflow JSON document to validate offline (and optionally via Native MCP).
    #[serde(default)]
    pub workflow: Value,
    /// Optional single node JSON object when validating an individual node (`action == "node"`).
    #[serde(default)]
    pub node: Option<Value>,
    /// Validation profile (`minimal`, `runtime`, `ai_friendly`, `strict`).
    #[serde(default)]
    pub profile: ValidationProfile,
    /// Check `$('Node')` cross-graph upstream reachability (default `true`).
    #[serde(default = "default_true")]
    pub check_expressions: bool,
    /// Whether to invoke Native MCP `validate_workflow` / `validate_node_config` when connected.
    #[serde(default)]
    pub use_native_mcp: bool,
}

fn default_search_action() -> String {
    "search".to_owned()
}

const fn default_true() -> bool {
    true
}

const fn default_limit_20() -> usize {
    20
}

/// Tool #1: `n8n_capabilities`.
pub async fn execute_capabilities(
    state: &AppState,
    params: CapabilitiesParams,
) -> ToolEnvelope<Value> {
    let rt = match state.instance(params.instance.as_deref()) {
        Ok(r) => r,
        Err(err) => {
            return err.into_envelope(
                params.instance.as_deref().unwrap_or(&state.active_instance),
                "capabilities.inspect",
                RouteUsed::Local,
            );
        }
    };

    let caps = match state
        .resolve_instance_capabilities(rt, params.refresh)
        .await
    {
        Ok(c) => c,
        Err(err) => {
            return err.into_envelope(
                &rt.config.alias,
                "capabilities.inspect",
                RouteUsed::PublicApi,
            );
        }
    };

    let rate_limits = rt
        .api_client
        .as_ref()
        .map(n8n_api_client::N8nApiClient::rate_limit_snapshot);

    let data = match params.detail {
        DetailLevel::Minimal => json!({
            "instance": caps.instance_alias,
            "environment": rt.config.environment,
            "policyMode": rt.config.policy_mode,
            "n8nVersion": caps.n8n_version,
            "protectedInstance": caps.protected_instance,
            "availableTools": caps.tools.iter()
                .filter(|t| t.state == n8n_capability::CapabilityState::Available)
                .map(|t| &t.tool_name)
                .collect::<Vec<_>>(),
        }),
        DetailLevel::Standard => json!({
            "instance": caps.instance_alias,
            "environment": rt.config.environment,
            "policyMode": rt.config.policy_mode,
            "discoverySource": caps.discovery_source,
            "n8nVersion": caps.n8n_version,
            "protectedInstance": caps.protected_instance,
            "scopesCount": caps.scopes.len(),
            "advertisedResources": caps.advertised_resources,
            "nativeMcp": caps.native_mcp,
            "rateLimits": rate_limits,
            "tools": caps.tools,
        }),
        DetailLevel::Full => json!({
            "environment": rt.config.environment,
            "policyMode": rt.config.policy_mode,
            "maxBatchWorkflows": rt.config.max_batch_workflows,
            "catalogPath": state.catalog_path_resolved.as_ref().map(|p| p.display().to_string()),
            "rateLimits": rate_limits,
            "profile": caps,
        }),
    };

    ToolEnvelope::new(
        OperationStatus::Success,
        &rt.config.alias,
        "capabilities.inspect",
        PermissionDecision::Allowed,
        RouteUsed::PublicApi,
    )
    .with_warnings(caps.warnings)
    .with_verification(VerificationReport::verified([
        "Capabilities verified against live instance handshake.".to_owned(),
    ]))
    .with_data(redact_json_value(&data))
}

/// Tool #2: `n8n_catalog_nodes`.
pub async fn execute_catalog_nodes(
    state: &AppState,
    params: CatalogNodesParams,
) -> ToolEnvelope<Value> {
    let instance_name = state.active_instance.clone();
    let action_norm = params.action.trim().to_ascii_lowercase();
    let limit = params.limit.clamp(1, 100);
    let mut warnings = Vec::new();
    if let Some(ref w) = state.catalog_warning {
        warnings.push(w.clone());
    }

    let result = state.with_catalog(|db| match action_norm.as_str() {
        "search" => {
            let q = params
                .query
                .clone()
                .or(params.node_type.clone())
                .unwrap_or_default();
            let resp = db.search_nodes(&NodeSearchQuery {
                query: q,
                mode: params.mode,
                source: params.source,
                include_operations: params.include_operations,
                detail: params.detail,
                limit,
            })?;
            serde_json::to_value(resp).map_err(|e| N8nError::protocol(e.to_string()))
        }
        "info" | "docs" | "search_properties" | "versions" => {
            let Some(nt) = params.node_type.clone().or(params.query.clone()) else {
                return Err(N8nError::validation(
                    &instance_name,
                    vec!["missing `nodeType`".to_owned()],
                    "`nodeType` is required for catalog node inspection",
                ));
            };
            let mode = match action_norm.as_str() {
                "docs" => NodeInfoMode::Docs,
                "search_properties" => NodeInfoMode::SearchProperties,
                "versions" => NodeInfoMode::Versions,
                _ => NodeInfoMode::Info,
            };
            let resp = db.get_node_info(&NodeInfoRequest {
                node_type: nt,
                mode,
                type_version: params.type_version.clone(),
                property_query: params.property_query.clone(),
            })?;
            serde_json::to_value(resp).map_err(|e| N8nError::protocol(e.to_string()))
        }
        "provenance" | "sync" => {
            let report = db.sync_catalog()?;
            serde_json::to_value(report).map_err(|e| N8nError::protocol(e.to_string()))
        }
        other => Err(N8nError::validation(
            &instance_name,
            vec![format!("unsupported action `{other}`")],
            "Expected `search`, `info`, `docs`, `search_properties`, `versions`, or `provenance`",
        )),
    });

    match result {
        Ok(data) => ToolEnvelope::new(
            OperationStatus::Success,
            instance_name,
            format!("catalog_nodes.{action_norm}"),
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_warnings(warnings)
        .with_data(redact_json_value(&data)),
        Err(err) => err.into_envelope(
            instance_name,
            format!("catalog_nodes.{action_norm}"),
            RouteUsed::Local,
        ),
    }
}

/// Tool #3: `n8n_catalog_templates`.
pub async fn execute_catalog_templates(
    state: &AppState,
    params: CatalogTemplatesParams,
) -> ToolEnvelope<Value> {
    let instance_name = state.active_instance.clone();
    let action_norm = params.action.trim().to_ascii_lowercase();
    let limit = params.limit.clamp(1, 100);
    let mut warnings = Vec::new();
    if let Some(ref w) = state.catalog_warning {
        warnings.push(w.clone());
    }

    let result = state.with_catalog(|db| match action_norm.as_str() {
        "get" => {
            let Some(ref tid) = params.template_id.or(params.query) else {
                return Err(N8nError::validation(
                    &instance_name,
                    vec!["missing `templateId`".to_owned()],
                    "`templateId` is required when `action == \"get\"`",
                ));
            };
            let entry = db.get_template(tid, params.template_detail)?;
            let Some(found) = entry else {
                return Err(N8nError::not_found_or_concealed(
                    &instance_name,
                    format!("template/{tid}"),
                    format!("Catalog template `{tid}` not found"),
                ));
            };
            serde_json::to_value(found).map_err(|e| N8nError::protocol(e.to_string()))
        }
        "list" => {
            let items: Vec<_> = db
                .list_template_summaries()?
                .into_iter()
                .take(limit)
                .collect();
            Ok(json!({
                "items": items,
                "count": items.len(),
            }))
        }
        "search" => {
            let resp = db.search_templates(&TemplateSearchQuery {
                mode: params.mode,
                query: params.query.clone(),
                node_types: params.node_types.clone(),
                match_all_nodes: params.match_all_nodes,
                task: params.task.clone(),
                category: params.category.clone(),
                complexity: params.complexity.clone(),
                max_setup_minutes: params.max_setup_minutes,
                min_setup_minutes: None,
                required_credential: params.required_credential.clone(),
                requires_no_credentials: None,
                detail: params.template_detail,
                limit,
            })?;
            serde_json::to_value(resp).map_err(|e| N8nError::protocol(e.to_string()))
        }
        other => Err(N8nError::validation(
            &instance_name,
            vec![format!("unsupported action `{other}`")],
            "Expected `search`, `get`, or `list`",
        )),
    });

    match result {
        Ok(data) => ToolEnvelope::new(
            OperationStatus::Success,
            instance_name,
            format!("catalog_templates.{action_norm}"),
            PermissionDecision::Allowed,
            RouteUsed::Local,
        )
        .with_warnings(warnings)
        .with_data(redact_json_value(&data)),
        Err(err) => err.into_envelope(
            instance_name,
            format!("catalog_templates.{action_norm}"),
            RouteUsed::Local,
        ),
    }
}

/// Tool #4: `n8n_validate` (full `n8n_validator::validate_workflow` + `validate_node_json` + `CatalogDb` + optional Native MCP).
pub async fn execute_validate(state: &AppState, params: ValidateParams) -> ToolEnvelope<Value> {
    let instance_name = params
        .instance
        .clone()
        .unwrap_or_else(|| state.active_instance.clone());

    // Single-node validation branch when `params.node` is supplied
    if let Some(ref node_val) = params.node {
        let node_res = state.with_catalog(|db| validate_node_json(node_val, db, params.profile));
        let report = match node_res {
            Ok(r) => r,
            Err(err) => {
                return err.into_envelope(instance_name, "validate.node", RouteUsed::Local);
            }
        };

        let mut route_used = RouteUsed::Local;
        let mut native_result = None;
        let mut warnings = vec![
            "Static schema/expression check only; does not prove live runtime execution."
                .to_owned(),
        ];

        if params.use_native_mcp
            && let Ok(rt) = state.instance(params.instance.as_deref())
            && let Some(ref bridge) = rt.mcp_bridge
        {
            let params_obj = node_val
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match bridge
                .validate_node_config(&report.node_type, &params_obj)
                .await
            {
                Ok(res) => {
                    route_used = RouteUsed::NativeMcp;
                    native_result = Some(res);
                }
                Err(err) => {
                    if !err.allows_route_fallback() {
                        return err.into_envelope(
                            instance_name,
                            "validate.node",
                            RouteUsed::NativeMcp,
                        );
                    }
                    warnings.push(format!(
                        "Native MCP node validation unavailable ({}); returning offline catalog validation only.",
                        err.error_code()
                    ));
                }
            }
        }

        let status = if report.valid {
            OperationStatus::Success
        } else {
            OperationStatus::Error
        };
        return ToolEnvelope::new(
            status,
            instance_name,
            "validate.node",
            PermissionDecision::Allowed,
            route_used,
        )
        .with_warnings(warnings)
        .with_data(redact_json_value(&json!({
            "valid": report.valid,
            "nodeReport": report,
            "nativeMcp": native_result,
        })));
    }

    // Full workflow validation
    let skeleton = validate_workflow_skeleton(&params.workflow);
    let full_report = if let Ok(ir) = WorkflowIr::from_json_value(params.workflow.clone()) {
        let opts = ValidationOptions {
            profile: params.profile,
            validate_nodes_with_catalog: true,
            check_expression_reachability: params.check_expressions,
        };
        Some(state.with_catalog(|db| validate_workflow(&ir, Some(db), &opts)))
    } else {
        None
    };

    let mut route_used = RouteUsed::Local;
    let mut native_result: Option<Value> = None;
    let mut warnings = vec![skeleton.limitation_note.clone()];

    if params.use_native_mcp
        && let Ok(rt) = state.instance(params.instance.as_deref())
        && let Some(ref bridge) = rt.mcp_bridge
    {
        match bridge.validate_workflow(&params.workflow).await {
            Ok(res) => {
                route_used = RouteUsed::NativeMcp;
                native_result = Some(res);
            }
            Err(err) => {
                if !err.allows_route_fallback() {
                    return err.into_envelope(
                        instance_name,
                        "validate.workflow",
                        RouteUsed::NativeMcp,
                    );
                }
                warnings.push(format!(
                    "Native MCP validation unavailable ({}); returning offline catalog + graph validation only.",
                    err.error_code()
                ));
            }
        }
    }

    let is_valid = skeleton.valid && full_report.as_ref().is_none_or(|r| r.valid);
    let status = if is_valid {
        OperationStatus::Success
    } else {
        OperationStatus::Error
    };

    ToolEnvelope::new(
        status,
        instance_name,
        "validate.workflow",
        PermissionDecision::Allowed,
        route_used,
    )
    .with_warnings(warnings)
    .with_data(redact_json_value(&json!({
        "valid": is_valid,
        "offline": skeleton,
        "workflowReport": full_report,
        "nativeMcp": native_result,
    })))
}
