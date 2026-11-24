//! `rmcp 3.11.0` MCP server front-end (`stdio` and optional authenticated loopback HTTP gateway)
//! exposing all 24 V2 tools, 4 resource templates, 5 prompts, and zero-secret `doctor` diagnostics.

pub mod approval;
pub mod doctor;
pub mod http_gateway;
pub mod prompts;
pub mod resources;
pub mod server;
pub mod state;
pub mod tools;

pub use approval::{ApprovalManager, PendingApprovalPlan, PreviewPlanInit};
pub use doctor::{DoctorCheckItem, DoctorReport, run_doctor};
pub use http_gateway::{HttpGatewayConfig, HttpGatewayHandle, MAX_HTTP_GATEWAY_BODY_BYTES};
pub use server::{N8nMcpServer, serve_stdio};
pub use state::{AppState, AppStateOptions, InstanceRuntime, resolve_and_open_catalog};
pub use tools::{
    AdminAccessParams, AdminSettingsParams, AgentsParams, AuditParams, BulkCodemodParams,
    CapabilitiesParams, CatalogNodesParams, CatalogOrgParams, CatalogTemplatesParams,
    CommunityPackagesParams, CredentialRefBinding, CredentialsParams, DataTablesParams,
    DeployTemplateParams, EvaluationsParams, ExecutionsParams, ExploreResourcesParams,
    FindNodesParams, GitAndPackagesParams, InspectNodeConfigParams, MutateNodesParams,
    TestWorkflowParams, ValidateParams, VersionsParams, WorkflowsParams,
};
