//! V2 MCP tool implementations organized by domain (all 24 capability-gated tools).

pub mod admin_and_agents;
pub mod catalog_and_validate;
pub mod common;
pub mod graph_ops;
pub mod org_and_data;
pub mod testing_audit;
pub mod workflows;

pub use admin_and_agents::{
    AdminAccessParams, AdminSettingsParams, AgentsParams, CommunityPackagesParams,
    GitAndPackagesParams, execute_admin_access, execute_admin_settings, execute_agents,
    execute_community_packages, execute_git_and_packages,
};
pub use catalog_and_validate::{
    CapabilitiesParams, CatalogNodesParams, CatalogTemplatesParams, ValidateParams,
    execute_capabilities, execute_catalog_nodes, execute_catalog_templates, execute_validate,
};
pub use graph_ops::{
    BulkCodemodParams, FindNodesParams, InspectNodeConfigParams, MutateNodesParams,
    execute_bulk_codemod, execute_find_nodes, execute_inspect_node_config, execute_mutate_nodes,
};
pub use org_and_data::{
    CatalogOrgParams, CredentialsParams, DataTablesParams, execute_catalog_org,
    execute_credentials, execute_datatables,
};
pub use testing_audit::{
    AuditParams, EvaluationsParams, ExecutionsParams, ExploreResourcesParams, TestWorkflowParams,
    execute_audit, execute_evaluations, execute_executions, execute_explore_resources,
    execute_test_workflow,
};
pub use workflows::{
    CredentialRefBinding, DeployTemplateParams, VersionsParams, WorkflowsParams,
    execute_deploy_template, execute_versions, execute_workflows,
};
