//! Route selector (`NativeMcp | PublicApi | Local | Unsupported`) across all 24 V2 logical tools
//! and fail-closed route fallback guard (forbidding 401/403 route downgrade).

use n8n_types::{N8nError, N8nResult, RouteUsed};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::profile::{CapabilityProfile, CapabilityState, ToolCapabilityEntry};

/// Granular logical operations evaluated by the capability router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOperation {
    CapabilitiesInspect,
    CatalogNodesSearch,
    CatalogTemplatesSearch,
    ValidateOfflineOrNative,
    WorkflowsRead,
    WorkflowsCreate,
    WorkflowsMutate,
    WorkflowsPublish,
    WorkflowsDelete,
    FindNodes,
    InspectNodeConfig,
    BulkCodemod,
    VersionsRead,
    VersionsRestore,
    DeployTemplate,
    ExecutionsRead,
    ExecutionsControl,
    TestWorkflowSimulate,
    TestWorkflowManual,
    TestWorkflowProduction,
    Evaluations,
    ExploreResources,
    Credentials,
    DataTables,
    CatalogOrg,
    Audit,
    CommunityPackages,
    GitAndPackages,
    AdminAccess,
    AdminSettings,
    Agents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteDecision {
    pub route: RouteUsed,
    pub state: CapabilityState,
    pub reason: String,
    pub prerequisites: Vec<String>,
}

impl RouteDecision {
    fn available(route: RouteUsed, reason: impl Into<String>) -> Self {
        Self {
            route,
            state: CapabilityState::Available,
            reason: reason.into(),
            prerequisites: Vec::new(),
        }
    }

    fn unavailable(reason: impl Into<String>, prerequisites: Vec<String>) -> Self {
        Self {
            route: RouteUsed::Unsupported,
            state: CapabilityState::Unavailable,
            reason: reason.into(),
            prerequisites,
        }
    }
}

/// Fail-closed route guard: NEVER downgrade a failed `403 Forbidden` or `401 Unauthenticated`
/// on one route (`NativeMcp` or `PublicApi`) to an alternate route that achieves the same effect!
pub fn verify_fallback_allowed(attempted_route: RouteUsed, err: N8nError) -> N8nResult<()> {
    if !err.allows_route_fallback() {
        return Err(err);
    }
    let _ = attempted_route;
    Ok(())
}

/// Selects the authoritative route (`NativeMcp | PublicApi | Local | Unsupported`) for `op`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn select_operation_route(profile: &CapabilityProfile, op: LogicalOperation) -> RouteDecision {
    let mcp = profile.negotiated_mcp();
    let wf_rest = profile.has_rest_resource(
        &["workflow", "workflows"],
        &["/workflows", "/api/v1/workflows"],
    );

    match op {
        LogicalOperation::CapabilitiesInspect => {
            RouteDecision::available(RouteUsed::PublicApi, "Runtime discovery active.")
        }
        LogicalOperation::CatalogNodesSearch | LogicalOperation::CatalogTemplatesSearch => {
            RouteDecision::available(RouteUsed::Local, "Offline pinned catalog available.")
        }
        LogicalOperation::ValidateOfflineOrNative => {
            if mcp.is_some_and(|m| m.has_validate_workflow || m.has_validate_node_config) {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Offline Rust validator + Native MCP schema validation available.",
                )
            } else {
                RouteDecision::available(
                    RouteUsed::Local,
                    "Offline Rust validator available (Native MCP validation not configured).",
                )
            }
        }
        LogicalOperation::WorkflowsRead
        | LogicalOperation::FindNodes
        | LogicalOperation::InspectNodeConfig => {
            let can_read = wf_rest
                && (profile.has_scope("workflow:read") || profile.has_scope("workflow:list"));
            if can_read {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Authorized Public API workflow read/list available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `workflow:read`/`workflow:list` scope or `/workflows` resource.",
                    vec!["Grant `workflow:read` and `workflow:list` scopes.".to_owned()],
                )
            }
        }
        LogicalOperation::WorkflowsCreate | LogicalOperation::DeployTemplate => {
            if profile.protected_instance {
                return RouteDecision::unavailable(
                    "Instance is in protected read-only mode; workflow creation is disabled.",
                    vec!["Target a non-protected staging/development instance.".to_owned()],
                );
            }
            if mcp.is_some_and(|m| m.has_validate_workflow && m.has_create_workflow_from_code)
                && profile.has_scope("workflow:create")
            {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Native MCP `validate_workflow` + `create_workflow_from_code` available.",
                )
            } else if wf_rest && profile.has_scope("workflow:create") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Public API `POST /api/v1/workflows` available with local validation.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `workflow:create` scope or workflow creation endpoint.",
                    vec!["Grant `workflow:create` scope on staging API key.".to_owned()],
                )
            }
        }
        LogicalOperation::WorkflowsMutate | LogicalOperation::BulkCodemod => {
            if profile.protected_instance {
                return RouteDecision::unavailable(
                    "Instance is protected; workflow draft mutations are disabled.",
                    vec!["Target an editable staging/development instance.".to_owned()],
                );
            }
            if mcp.is_some_and(|m| m.has_update_workflow) && profile.has_scope("workflow:update") {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Native MCP partial `update_workflow` available.",
                )
            } else if wf_rest
                && profile.has_scope("workflow:update")
                && profile.has_scope("workflow:read")
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Public API guarded read-modify-write `PUT /api/v1/workflows/{id}` available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `workflow:update` (and `workflow:read`) scope or `/workflows` resource.",
                    vec!["Grant `workflow:read` and `workflow:update` scopes.".to_owned()],
                )
            }
        }
        LogicalOperation::WorkflowsPublish => {
            if profile.protected_instance {
                return RouteDecision::unavailable(
                    "Instance is protected; publish/unpublish is disabled.",
                    vec![],
                );
            }
            if wf_rest
                && (profile.has_scope("workflow:publish")
                    || profile.has_scope("workflow:activate")
                    || profile.has_scope("workflow:update"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Public API publish/unpublish endpoint available (requires confirmation).",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `workflow:publish`/`workflow:activate` scope or `/workflows` resource.",
                    vec!["Grant `workflow:publish` scope.".to_owned()],
                )
            }
        }
        LogicalOperation::WorkflowsDelete => {
            if profile.protected_instance {
                return RouteDecision::unavailable(
                    "Instance is protected; workflow deletion is disabled.",
                    vec![],
                );
            }
            if wf_rest && profile.has_scope("workflow:delete") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Public API `DELETE /api/v1/workflows/{id}` available (R4 approval required).",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `workflow:delete` scope.",
                    vec!["Grant `workflow:delete` scope if deletion is required.".to_owned()],
                )
            }
        }
        LogicalOperation::VersionsRead => {
            if wf_rest && profile.has_scope("workflow:read") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Workflow version history inspection available via Public API + local vault.",
                )
            } else {
                RouteDecision::unavailable("Missing `workflow:read` scope.", vec![])
            }
        }
        LogicalOperation::VersionsRestore => {
            if mcp.is_some_and(|m| m.has_restore_workflow_version)
                && profile.has_scope("workflow:update")
            {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Native MCP `restore_workflow_version` available.",
                )
            } else if wf_rest && profile.has_scope("workflow:update") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Local snapshot restore as draft via Public API `PUT /workflows/{id}`.",
                )
            } else {
                RouteDecision::unavailable(
                    "Version restore requires `workflow:update` or Native MCP `restore_workflow_version`.",
                    vec![],
                )
            }
        }
        LogicalOperation::ExecutionsRead => {
            let ex_rest = profile.has_rest_resource(
                &["execution", "executions"],
                &["/executions", "/api/v1/executions"],
            );
            if ex_rest
                && (profile.has_scope("execution:read") || profile.has_scope("execution:list"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Redacted execution inspection available via Public API.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `execution:read`/`execution:list` scope or `/executions` resource.",
                    vec!["Grant `execution:read` and `execution:list` scopes.".to_owned()],
                )
            }
        }
        LogicalOperation::ExecutionsControl => {
            let ex_rest = profile.has_rest_resource(
                &["execution", "executions"],
                &["/executions", "/api/v1/executions"],
            );
            if ex_rest
                && (profile.has_scope("execution:retry")
                    || profile.has_scope("execution:stop")
                    || profile.has_scope("execution:delete"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Execution retry/stop/delete available via Public API (approval gated).",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `execution:retry`/`execution:stop`/`execution:delete` scope.",
                    vec![],
                )
            }
        }
        LogicalOperation::TestWorkflowSimulate => {
            if mcp.is_some_and(|m| m.has_test_workflow) {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Native MCP `test_workflow` + pin data simulation available (subject to side-effect classifier).",
                )
            } else {
                RouteDecision::unavailable(
                    "Simulated pin-data execution requires Instance-level Native MCP (`test_workflow`).",
                    vec![
                        "Configure `N8N_MCP_BASE_URL` and isolated `N8N_MCP_ACCESS_TOKEN`."
                            .to_owned(),
                    ],
                )
            }
        }
        LogicalOperation::TestWorkflowManual | LogicalOperation::TestWorkflowProduction => {
            if mcp.is_some_and(|m| m.has_execute_workflow) {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Native MCP `execute_workflow` advertised (subject to local policy AND-gate and human approval).",
                )
            } else {
                RouteDecision::unavailable(
                    "Live workflow execution requires Native MCP `execute_workflow` or an allowlisted staging trigger.",
                    vec!["Configure Native MCP bridge (`/mcp-server/http`).".to_owned()],
                )
            }
        }
        LogicalOperation::Evaluations => {
            let eval_rest = profile.has_rest_resource(
                &["evaluation", "evaluations", "testrun", "test-runs"],
                &[
                    "/workflows/{id}/test-runs",
                    "/api/v1/workflows/{id}/test-runs",
                ],
            );
            if eval_rest
                && (profile.has_any_scope_with_prefix("evaluation:")
                    || profile.has_scope("workflow:read"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Workflow evaluation test-runs available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Evaluation `/test-runs` resource or scope not advertised on this instance.",
                    vec![],
                )
            }
        }
        LogicalOperation::ExploreResources => {
            if mcp.is_some_and(|m| !m.advertised_tool_names.is_empty()) {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Dynamic resource lookup via Native MCP available (consent-gated).",
                )
            } else {
                RouteDecision::unavailable(
                    "Dynamic `loadOptions`/`listSearch` requires Native MCP bridge.",
                    vec!["Configure Native MCP bridge (`/mcp-server/http`).".to_owned()],
                )
            }
        }
        LogicalOperation::Credentials => {
            let cred_rest = profile.has_rest_resource(
                &["credential", "credentials"],
                &["/credentials", "/api/v1/credentials"],
            );
            if cred_rest && profile.has_any_scope_with_prefix("credential:") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Credential schema and metadata operations available (no secret values exposed).",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `credential:*` scope or `/credentials` resource.",
                    vec![],
                )
            }
        }
        LogicalOperation::DataTables => {
            let dt_rest = profile.has_rest_resource(
                &["datatable", "datatables", "data-table", "data-tables"],
                &["/data-tables", "/api/v1/data-tables"],
            );
            if dt_rest && profile.has_any_scope_with_prefix("datatable:")
                || dt_rest && profile.has_any_scope_with_prefix("dataTable:")
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Data-table API operations available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing `datatable:*` scope or `/data-tables` resource.",
                    vec![],
                )
            }
        }
        LogicalOperation::CatalogOrg => {
            let org_rest = profile.has_rest_resource(
                &[
                    "project",
                    "projects",
                    "folder",
                    "folders",
                    "tag",
                    "tags",
                    "variable",
                    "variables",
                ],
                &[
                    "/projects",
                    "/tags",
                    "/variables",
                    "/api/v1/projects",
                    "/api/v1/tags",
                ],
            );
            if org_rest
                && (profile.has_any_scope_with_prefix("project:")
                    || profile.has_any_scope_with_prefix("folder:")
                    || profile.has_any_scope_with_prefix("tag:")
                    || profile.has_any_scope_with_prefix("variable:"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Projects/folders/tags/variables API available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Missing project/folder/tag/variable scopes or endpoints.",
                    vec![],
                )
            }
        }
        LogicalOperation::Audit => {
            let audit_rest = profile.has_rest_resource(&["audit"], &["/audit", "/api/v1/audit"]);
            if audit_rest
                && (profile.has_any_scope_with_prefix("audit:")
                    || profile.has_any_scope_with_prefix("securityAudit:"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Official `/api/v1/audit` + local static workflow security analyzer available.",
                )
            } else {
                RouteDecision::available(
                    RouteUsed::Local,
                    "Local static workflow hardening analyzer available (`/api/v1/audit` not authorized).",
                )
            }
        }
        LogicalOperation::CommunityPackages => {
            let pkg_rest = profile.has_rest_resource(
                &[
                    "communitypackage",
                    "communitypackages",
                    "community-packages",
                ],
                &["/community-packages", "/api/v1/community-packages"],
            );
            if pkg_rest && profile.has_any_scope_with_prefix("communityPackage:") {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Community packages endpoint available (admin allowlist + R4 approval required).",
                )
            } else {
                RouteDecision::unavailable(
                    "Community packages API or `communityPackage:*` scope not available.",
                    vec![],
                )
            }
        }
        LogicalOperation::GitAndPackages => {
            let git_rest = profile.has_rest_resource(
                &[
                    "sourcecontrol",
                    "source-control",
                    "promotion",
                    "promotions",
                    "n8npackage",
                    "n8n-packages",
                ],
                &[
                    "/source-control",
                    "/promotions",
                    "/n8n-packages",
                    "/api/v1/source-control",
                    "/api/v1/promotions",
                    "/api/v1/n8n-packages",
                ],
            );
            if git_rest
                && (profile.has_any_scope_with_prefix("sourceControl:")
                    || profile.has_any_scope_with_prefix("promotion:")
                    || profile.has_any_scope_with_prefix("n8nPackage:"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Source-control / promotions / `.n8np` packages endpoints available.",
                )
            } else {
                RouteDecision::unavailable(
                    "Source-control / promotions / `.n8np` endpoints or scopes not advertised.",
                    vec![],
                )
            }
        }
        LogicalOperation::AdminAccess => {
            let usr_rest = profile.has_rest_resource(
                &["user", "users", "role", "roles"],
                &["/users", "/roles", "/api/v1/users", "/api/v1/roles"],
            );
            if usr_rest
                && (profile.has_any_scope_with_prefix("user:")
                    || profile.has_any_scope_with_prefix("role:"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Admin user/role/project access endpoints available (R4 approval gated).",
                )
            } else {
                RouteDecision::unavailable(
                    "Admin user/role scopes or endpoints unavailable.",
                    vec![],
                )
            }
        }
        LogicalOperation::AdminSettings => {
            let set_rest = profile.has_rest_resource(
                &[
                    "settings",
                    "nodetypepolicy",
                    "credentialtypepolicy",
                    "insights",
                    "logstreaming",
                ],
                &[
                    "/settings",
                    "/node-type-policies",
                    "/credential-type-policies",
                    "/insights/summary",
                    "/api/v1/settings",
                ],
            );
            if set_rest
                && (profile.has_any_scope_with_prefix("settings:")
                    || profile.has_any_scope_with_prefix("nodeTypePolicy:")
                    || profile.has_any_scope_with_prefix("credentialTypePolicy:")
                    || profile.has_any_scope_with_prefix("eventBusDestination:")
                    || profile.has_any_scope_with_prefix("insights:"))
            {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Admin settings/policies/insights endpoints available (R4 approval gated).",
                )
            } else {
                RouteDecision::unavailable(
                    "Admin settings/policy scopes or endpoints unavailable.",
                    vec![],
                )
            }
        }
        LogicalOperation::Agents => {
            // CRITICAL V2 EDGE CASE: NEVER enable `n8n_agents` from `agent:*` scopes alone!
            let has_agent_rest =
                profile.has_rest_resource(&["agent", "agents"], &["/agents", "/api/v1/agents"]);
            let has_agent_mcp = mcp.is_some_and(|m| !m.advertised_agent_tools.is_empty());
            let has_agent_scope = profile.has_any_scope_with_prefix("agent:");

            if has_agent_mcp {
                RouteDecision::available(
                    RouteUsed::NativeMcp,
                    "Persisted Agents tools advertised by Native MCP.",
                )
            } else if has_agent_rest && has_agent_scope {
                RouteDecision::available(
                    RouteUsed::PublicApi,
                    "Persisted Agents REST resource and `agent:*` scopes advertised.",
                )
            } else if has_agent_scope && !has_agent_rest && !has_agent_mcp {
                RouteDecision::unavailable(
                    "Scopes include `agent:*`, but neither Public API `/agents` resources nor Native MCP agent tools are advertised on this instance.",
                    vec!["Requires an n8n release exposing persisted `/agents` REST or Native MCP tools.".to_owned()],
                )
            } else {
                RouteDecision::unavailable(
                    "Persisted n8n Agents are not advertised on this instance.",
                    vec![],
                )
            }
        }
    }
}

/// Builds the complete 24-tool capability matrix (V2 Section 4).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_24_tool_matrix(profile: &CapabilityProfile) -> Vec<ToolCapabilityEntry> {
    let entries: &[(&str, LogicalOperation, &[&str])] = &[
        (
            "n8n_capabilities",
            LogicalOperation::CapabilitiesInspect,
            &["inspect", "refresh"],
        ),
        (
            "n8n_catalog_nodes",
            LogicalOperation::CatalogNodesSearch,
            &["search", "inspect"],
        ),
        (
            "n8n_catalog_templates",
            LogicalOperation::CatalogTemplatesSearch,
            &["search", "get"],
        ),
        (
            "n8n_validate",
            LogicalOperation::ValidateOfflineOrNative,
            &["workflow", "node", "sdk_code"],
        ),
        (
            "n8n_workflows",
            LogicalOperation::WorkflowsRead,
            &[
                "list",
                "get",
                "create",
                "update_meta",
                "archive",
                "unarchive",
                "publish",
                "unpublish",
                "transfer",
                "delete",
            ],
        ),
        ("n8n_find_nodes", LogicalOperation::FindNodes, &["search"]),
        (
            "n8n_inspect_node_config",
            LogicalOperation::InspectNodeConfig,
            &["inspect"],
        ),
        (
            "n8n_mutate_nodes",
            LogicalOperation::WorkflowsMutate,
            &["preview", "apply"],
        ),
        (
            "n8n_bulk_codemod",
            LogicalOperation::BulkCodemod,
            &["preview", "apply", "status", "restore"],
        ),
        (
            "n8n_versions",
            LogicalOperation::VersionsRead,
            &["history", "diff", "snapshot", "restore"],
        ),
        (
            "n8n_deploy_template",
            LogicalOperation::DeployTemplate,
            &["preview", "deploy"],
        ),
        (
            "n8n_executions",
            LogicalOperation::ExecutionsRead,
            &["list", "get", "retry", "stop", "delete", "tags"],
        ),
        (
            "n8n_test_workflow",
            LogicalOperation::TestWorkflowSimulate,
            &["validate_only", "simulate", "manual", "production"],
        ),
        (
            "n8n_evaluations",
            LogicalOperation::Evaluations,
            &["list", "get", "run", "cancel"],
        ),
        (
            "n8n_explore_resources",
            LogicalOperation::ExploreResources,
            &["load_options", "list_search"],
        ),
        (
            "n8n_credentials",
            LogicalOperation::Credentials,
            &[
                "list", "schema", "test", "create", "update", "transfer", "delete",
            ],
        ),
        (
            "n8n_datatables",
            LogicalOperation::DataTables,
            &[
                "list", "get", "columns", "rows", "upsert", "create", "delete",
            ],
        ),
        (
            "n8n_catalog_org",
            LogicalOperation::CatalogOrg,
            &["projects", "folders", "tags", "variables"],
        ),
        (
            "n8n_audit",
            LogicalOperation::Audit,
            &["static_scan", "instance_audit"],
        ),
        (
            "n8n_community_packages",
            LogicalOperation::CommunityPackages,
            &["list", "install", "update", "uninstall"],
        ),
        (
            "n8n_git_and_packages",
            LogicalOperation::GitAndPackages,
            &["status", "pull", "push", "promotions", "export", "import"],
        ),
        (
            "n8n_admin_access",
            LogicalOperation::AdminAccess,
            &["users", "roles", "project_members"],
        ),
        (
            "n8n_admin_settings",
            LogicalOperation::AdminSettings,
            &[
                "settings",
                "node_policies",
                "credential_policies",
                "insights",
            ],
        ),
        ("n8n_agents", LogicalOperation::Agents, &["list", "get"]),
    ];

    entries
        .iter()
        .map(|(tool_name, primary_op, actions)| {
            let decision = select_operation_route(profile, *primary_op);
            let supported_actions = if *tool_name == "n8n_workflows" {
                compute_workflow_supported_actions(profile)
            } else if decision.state == CapabilityState::Available {
                actions.iter().map(|&s| s.to_owned()).collect()
            } else if *tool_name == "n8n_test_workflow" {
                // `validate_only` (T0) is always locally available even without Native MCP!
                vec!["validate_only".to_owned()]
            } else {
                Vec::new()
            };

            let (state, preferred_route) = if *tool_name == "n8n_test_workflow"
                && decision.state != CapabilityState::Available
            {
                (CapabilityState::Available, RouteUsed::Local)
            } else {
                (decision.state, decision.route)
            };

            ToolCapabilityEntry {
                tool_name: (*tool_name).to_owned(),
                state,
                preferred_route,
                reason: decision.reason,
                supported_actions,
                prerequisites: decision.prerequisites,
            }
        })
        .collect()
}

fn compute_workflow_supported_actions(profile: &CapabilityProfile) -> Vec<String> {
    let mut actions = Vec::new();
    if select_operation_route(profile, LogicalOperation::WorkflowsRead).state
        == CapabilityState::Available
    {
        actions.push("list".to_owned());
        actions.push("get".to_owned());
    }
    if select_operation_route(profile, LogicalOperation::WorkflowsCreate).state
        == CapabilityState::Available
    {
        actions.push("create".to_owned());
    }
    if select_operation_route(profile, LogicalOperation::WorkflowsMutate).state
        == CapabilityState::Available
    {
        actions.push("update_meta".to_owned());
        actions.push("archive".to_owned());
        actions.push("unarchive".to_owned());
        actions.push("transfer".to_owned());
    }
    if select_operation_route(profile, LogicalOperation::WorkflowsPublish).state
        == CapabilityState::Available
    {
        actions.push("publish".to_owned());
        actions.push("unpublish".to_owned());
    }
    if select_operation_route(profile, LogicalOperation::WorkflowsDelete).state
        == CapabilityState::Available
    {
        actions.push("delete".to_owned());
    }
    actions
}
