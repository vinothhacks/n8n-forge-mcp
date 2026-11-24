//! `rmcp 3.11.0` `ServerHandler` implementation exposing all 24 V2 tools, 4 `n8n://` resource templates,
//! and 5 guidance prompts over `stdio` (and via `invoke_tool_json` for the localhost HTTP gateway).

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResponse, Implementation,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router,
};
use serde_json::Value;

use crate::prompts::{build_guidance_prompts, render_guidance_prompt};
use crate::resources::{build_resource_templates, list_concrete_resources, read_n8n_resource};
use crate::state::AppState;
use crate::tools::{
    AdminAccessParams, AdminSettingsParams, AgentsParams, AuditParams, BulkCodemodParams,
    CapabilitiesParams, CatalogNodesParams, CatalogOrgParams, CatalogTemplatesParams,
    CommunityPackagesParams, CredentialsParams, DataTablesParams, DeployTemplateParams,
    EvaluationsParams, ExecutionsParams, ExploreResourcesParams, FindNodesParams,
    GitAndPackagesParams, InspectNodeConfigParams, MutateNodesParams, TestWorkflowParams,
    ValidateParams, VersionsParams, WorkflowsParams, execute_admin_access, execute_admin_settings,
    execute_agents, execute_audit, execute_bulk_codemod, execute_capabilities,
    execute_catalog_nodes, execute_catalog_org, execute_catalog_templates,
    execute_community_packages, execute_credentials, execute_datatables, execute_deploy_template,
    execute_evaluations, execute_executions, execute_explore_resources, execute_find_nodes,
    execute_git_and_packages, execute_inspect_node_config, execute_mutate_nodes,
    execute_test_workflow, execute_validate, execute_versions, execute_workflows,
};

fn serialize_envelope<T: serde::Serialize>(
    envelope: &n8n_types::ToolEnvelope<T>,
) -> Result<String, McpError> {
    envelope
        .to_redacted_json_string()
        .map_err(|e| McpError::internal_error(format!("envelope serialization error: {e}"), None))
}

/// `rmcp` MCP server handler backed by `AppState`.
#[derive(Clone)]
pub struct N8nMcpServer {
    state: AppState,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl N8nMcpServer {
    #[must_use]
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    #[must_use]
    pub const fn app_state(&self) -> &AppState {
        &self.state
    }

    #[must_use]
    pub fn list_registered_tools(&self) -> Vec<rmcp::model::Tool> {
        self.tool_router.list_all()
    }

    #[must_use]
    pub fn server_info(&self) -> ServerConfig {
        <Self as ServerHandler>::get_info(self)
    }

    /// Dispatch a tool invocation by name with JSON arguments (used by `http_gateway` and tests).
    #[allow(clippy::too_many_lines)]
    pub async fn invoke_tool_json(&self, name: &str, args: Value) -> Result<Value, McpError> {
        let parse_err = |e: serde_json::Error| McpError::invalid_params(e.to_string(), None);
        let env = match name {
            "n8n_capabilities" => {
                execute_capabilities(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_catalog_nodes" => {
                execute_catalog_nodes(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_catalog_templates" => {
                execute_catalog_templates(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_validate" => {
                execute_validate(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_workflows" => {
                execute_workflows(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_find_nodes" => {
                execute_find_nodes(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_inspect_node_config" => {
                execute_inspect_node_config(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_mutate_nodes" => {
                execute_mutate_nodes(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_bulk_codemod" => {
                execute_bulk_codemod(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_versions" => {
                execute_versions(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_deploy_template" => {
                execute_deploy_template(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_executions" => {
                execute_executions(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_test_workflow" => {
                execute_test_workflow(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_evaluations" => {
                execute_evaluations(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_explore_resources" => {
                execute_explore_resources(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_credentials" => {
                execute_credentials(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_datatables" => {
                execute_datatables(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_catalog_org" => {
                execute_catalog_org(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_audit" => {
                execute_audit(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_community_packages" => {
                execute_community_packages(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_git_and_packages" => {
                execute_git_and_packages(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_admin_access" => {
                execute_admin_access(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_admin_settings" => {
                execute_admin_settings(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            "n8n_agents" => {
                execute_agents(
                    &self.state,
                    serde_json::from_value(args).map_err(parse_err)?,
                )
                .await
            }
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown tool `{other}`"),
                    None,
                ));
            }
        };

        let text = serialize_envelope(&env)?;
        let result = CallToolResult::success(vec![ContentBlock::text(text)]);
        serde_json::to_value(result).map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    // 1. n8n_capabilities
    #[tool(
        name = "n8n_capabilities",
        description = "Inspect n8n instance capabilities, scopes, policy mode, Native MCP tools, and per-tool route availability (read-only, fail-closed)."
    )]
    async fn n8n_capabilities(
        &self,
        Parameters(params): Parameters<CapabilitiesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_capabilities(&self.state, params).await)
    }

    // 2. n8n_catalog_nodes
    #[tool(
        name = "n8n_catalog_nodes",
        description = "Search and inspect offline n8n node schemas, operations, AI tool capabilities, and version history using FTS5."
    )]
    async fn n8n_catalog_nodes(
        &self,
        Parameters(params): Parameters<CatalogNodesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_catalog_nodes(&self.state, params).await)
    }

    // 3. n8n_catalog_templates
    #[tool(
        name = "n8n_catalog_templates",
        description = "Search and retrieve sanitized offline n8n workflow templates by task, node type, or keyword."
    )]
    async fn n8n_catalog_templates(
        &self,
        Parameters(params): Parameters<CatalogTemplatesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_catalog_templates(&self.state, params).await)
    }

    // 4. n8n_validate
    #[tool(
        name = "n8n_validate",
        description = "Validate n8n workflow JSON structure, expressions, AI connections, and security heuristics offline (and optionally via Native MCP)."
    )]
    async fn n8n_validate(
        &self,
        Parameters(params): Parameters<ValidateParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_validate(&self.state, params).await)
    }

    // 5. n8n_workflows
    #[tool(
        name = "n8n_workflows",
        description = "List, inspect, create, update, publish, unpublish, archive, transfer, delete, or confirm_plan for n8n workflows with secret redaction and TOCTOU safety."
    )]
    async fn n8n_workflows(
        &self,
        Parameters(params): Parameters<WorkflowsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_workflows(&self.state, params).await)
    }

    // 6. n8n_find_nodes
    #[tool(
        name = "n8n_find_nodes",
        description = "Search nodes across authorized workflows by node type, credential type, expression reference, or ephemeral in-memory parameter substring."
    )]
    async fn n8n_find_nodes(
        &self,
        Parameters(params): Parameters<FindNodesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_find_nodes(&self.state, params).await)
    }

    // 7. n8n_inspect_node_config
    #[tool(
        name = "n8n_inspect_node_config",
        description = "Evaluate displayOptions against a live or inline node configuration to show visible, missing-required, and dead/hidden fields."
    )]
    async fn n8n_inspect_node_config(
        &self,
        Parameters(params): Parameters<InspectNodeConfigParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_inspect_node_config(&self.state, params).await)
    }

    // 8. n8n_mutate_nodes
    #[tool(
        name = "n8n_mutate_nodes",
        description = "Preview or apply surgical graph mutations (16 typed operations, literal-only AST node rename, branch insertion, retry/error hardening) with read-back verification."
    )]
    async fn n8n_mutate_nodes(
        &self,
        Parameters(params): Parameters<MutateNodesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_mutate_nodes(&self.state, params).await)
    }

    // 9. n8n_bulk_codemod
    #[tool(
        name = "n8n_bulk_codemod",
        description = "Preview or apply bounded cross-workflow codemods (hard max 20 workflows) with per-workflow snapshots and compensating rollback."
    )]
    async fn n8n_bulk_codemod(
        &self,
        Parameters(params): Parameters<BulkCodemodParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_bulk_codemod(&self.state, params).await)
    }

    // 10. n8n_versions
    #[tool(
        name = "n8n_versions",
        description = "List remote n8n workflow versions and local encrypted snapshots, compute redacted diffs, or restore a prior version as a draft."
    )]
    async fn n8n_versions(
        &self,
        Parameters(params): Parameters<VersionsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_versions(&self.state, params).await)
    }

    // 11. n8n_deploy_template
    #[tool(
        name = "n8n_deploy_template",
        description = "Instantiate an offline catalog template as an inactive draft workflow with credential reference bindings and auto-fix validation."
    )]
    async fn n8n_deploy_template(
        &self,
        Parameters(params): Parameters<DeployTemplateParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_deploy_template(&self.state, params).await)
    }

    // 12. n8n_executions
    #[tool(
        name = "n8n_executions",
        description = "List, summarize, inspect redacted node outputs, retry, stop, delete, or tag n8n workflow executions."
    )]
    async fn n8n_executions(
        &self,
        Parameters(params): Parameters<ExecutionsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_executions(&self.state, params).await)
    }

    // 13. n8n_test_workflow
    #[tool(
        name = "n8n_test_workflow",
        description = "Safely test workflows via T0 static dry-run, T1 pinned simulation (blocking dangerous side-effect nodes), T2 test-runs, T3 live triggers, or bounded 3-step repair_loop."
    )]
    async fn n8n_test_workflow(
        &self,
        Parameters(params): Parameters<TestWorkflowParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_test_workflow(&self.state, params).await)
    }

    // 14. n8n_evaluations
    #[tool(
        name = "n8n_evaluations",
        description = "Run, list, inspect, or delete n8n workflow evaluation test-runs (/api/v1/workflows/{id}/test-runs)."
    )]
    async fn n8n_evaluations(
        &self,
        Parameters(params): Parameters<EvaluationsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_evaluations(&self.state, params).await)
    }

    // 15. n8n_explore_resources
    #[tool(
        name = "n8n_explore_resources",
        description = "Inspect credential type schemas, credential workflow dependencies, and node dynamic resource-locator parameters."
    )]
    async fn n8n_explore_resources(
        &self,
        Parameters(params): Parameters<ExploreResourcesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_explore_resources(&self.state, params).await)
    }

    // 16. n8n_credentials
    #[tool(
        name = "n8n_credentials",
        description = "Manage n8n credential metadata, schemas, dependencies, connectivity tests, transfers, and receipt-gated lifecycle without ever echoing secret values."
    )]
    async fn n8n_credentials(
        &self,
        Parameters(params): Parameters<CredentialsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_credentials(&self.state, params).await)
    }

    // 17. n8n_datatables
    #[tool(
        name = "n8n_datatables",
        description = "Manage n8n Data Tables, columns, rows, upserts, and workflow dependencies with policy gating and output redaction."
    )]
    async fn n8n_datatables(
        &self,
        Parameters(params): Parameters<DataTablesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_datatables(&self.state, params).await)
    }

    // 18. n8n_catalog_org
    #[tool(
        name = "n8n_catalog_org",
        description = "Manage n8n organizational resources: projects, folders, tags, and redacted variables."
    )]
    async fn n8n_catalog_org(
        &self,
        Parameters(params): Parameters<CatalogOrgParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_catalog_org(&self.state, params).await)
    }

    // 19. n8n_audit
    #[tool(
        name = "n8n_audit",
        description = "Run deterministic 6-category static workflow security audits (separating observed facts, redacted heuristics, and permission gaps) plus optional /api/v1/audit merge."
    )]
    async fn n8n_audit(
        &self,
        Parameters(params): Parameters<AuditParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_audit(&self.state, params).await)
    }

    // 20. n8n_community_packages
    #[tool(
        name = "n8n_community_packages",
        description = "List or manage n8n community packages with exact-semver pinning, supply-chain allowlist enforcement, and R4 admin approval receipts."
    )]
    async fn n8n_community_packages(
        &self,
        Parameters(params): Parameters<CommunityPackagesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_community_packages(&self.state, params).await)
    }

    // 21. n8n_git_and_packages
    #[tool(
        name = "n8n_git_and_packages",
        description = "Inspect or manage n8n Enterprise Git Source Control, Environment Promotions, and Portable n8n Packages."
    )]
    async fn n8n_git_and_packages(
        &self,
        Parameters(params): Parameters<GitAndPackagesParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_git_and_packages(&self.state, params).await)
    }

    // 22. n8n_admin_access
    #[tool(
        name = "n8n_admin_access",
        description = "Inspect or administer n8n users, project memberships, roles, role-mapping rules, SSO (OIDC/SAML), and LDAP."
    )]
    async fn n8n_admin_access(
        &self,
        Parameters(params): Parameters<AdminAccessParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_admin_access(&self.state, params).await)
    }

    // 23. n8n_admin_settings
    #[tool(
        name = "n8n_admin_settings",
        description = "Inspect or administer n8n insights summaries, rate limits, security policies, node/credential type policies, log streaming, and OpenTelemetry."
    )]
    async fn n8n_admin_settings(
        &self,
        Parameters(params): Parameters<AdminSettingsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_admin_settings(&self.state, params).await)
    }

    // 24. n8n_agents
    #[tool(
        name = "n8n_agents",
        description = "Capability-gated interface for n8n persisted Agents; returns structured `unsupported` unless `/agents` REST endpoints or Native MCP agent tools are advertised."
    )]
    async fn n8n_agents(
        &self,
        Parameters(params): Parameters<AgentsParams>,
    ) -> Result<String, McpError> {
        serialize_envelope(&execute_agents(&self.state, params).await)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for N8nMcpServer {
    fn get_info(&self) -> ServerConfig {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_prompts()
            .build();
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("n8n-rs-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Governance-first Rust MCP server for n8n (V2). Always check `n8n_capabilities` first; prefer native nodes over Code; never bypass scopes, receipts, or policy gates.",
            )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(list_concrete_resources(&self.state))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(build_resource_templates())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        read_n8n_resource(&self.state, &request.uri).await
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(build_guidance_prompts())
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        render_guidance_prompt(&request)
    }
}

/// Runs the `N8nMcpServer` over MCP `stdio` transport until EOF / client disconnect.
pub async fn serve_stdio(state: AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = N8nMcpServer::new(state);
    let running = server.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
