//! Shared loopback `wiremock` test builders and synthetic n8n fixtures.
//! Uses strictly loopback `wiremock` URIs and synthetic domains (`staging-n8n.example.internal`).

use std::collections::BTreeMap;
use std::time::Duration;

use n8n_api_client::{ApiClientConfig, N8nApiClient, RateLimitConfig, SsrfPolicy, StreamBudget};
use n8n_mcp_bridge::{McpBridgeConfig, NativeMcpBridge};
use n8n_mcp_server::AppState;
use n8n_policy::{InstancePolicyConfig, LoadedWorkspaceConfig, MAX_BATCH_WORKFLOWS, PolicyMode};
use n8n_types::{EnvironmentKind, SecretValue};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const CANARY_API_KEY: &str = "n8n_api_CANARY_TEST_KEY_998877665544";
pub const CANARY_MCP_TOKEN: &str = concat!(
    "ey",
    "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e",
    "yJzdWIiOiJDQU5BUllfTUNQX0JFQVJFUjEyMyJ9.CANARY_SIGNATURE_XYZ987"
);
pub const CANARY_CF_SECRET: &str = "cf_access_CANARY_CLIENT_SECRET_11223344";
pub const CANARY_DSN_PASS: &str = "Sup3rCanaryPgPass_445566!";

pub fn loopback_ssrf_policy() -> SsrfPolicy {
    SsrfPolicy {
        allow_loopback_http: true,
        trust_configured_private_host: false,
        trusted_private_ips: Vec::new(),
    }
}

pub fn build_loopback_api_client(server_uri: &str, api_key: &str) -> N8nApiClient {
    let mut cfg = ApiClientConfig::new("staging", server_uri, SecretValue::new(api_key));
    cfg.ssrf_policy = loopback_ssrf_policy();
    cfg.cf_access_client_id = Some("cf_client_id_demo.access".to_owned());
    cfg.cf_access_client_secret = Some(SecretValue::new(CANARY_CF_SECRET));
    cfg.rate_limit = RateLimitConfig {
        local_read_per_sec: 500,
        local_write_per_sec: 500,
        max_wait_ms: 5_000,
        max_429_retries: 2,
    };
    cfg.stream_budget = StreamBudget::default();
    N8nApiClient::new(cfg).expect("valid loopback api client")
}

pub fn build_loopback_mcp_bridge(server_uri: &str, mcp_token: &str) -> NativeMcpBridge {
    let endpoint = format!("{}/mcp-server/http", server_uri.trim_end_matches('/'));
    let mut cfg = McpBridgeConfig::new("staging", endpoint, SecretValue::new(mcp_token));
    cfg.ssrf_policy = loopback_ssrf_policy();
    NativeMcpBridge::new(cfg, Some(&SecretValue::new(CANARY_API_KEY)))
        .expect("valid loopback mcp bridge")
}

pub fn build_test_app_state(
    alias: &str,
    server_uri: &str,
    environment: EnvironmentKind,
    policy_mode: PolicyMode,
    with_mcp_bridge: bool,
) -> AppState {
    let mcp_base_url =
        with_mcp_bridge.then(|| format!("{}/mcp-server/http", server_uri.trim_end_matches('/')));
    let mcp_access_token = with_mcp_bridge.then(|| SecretValue::new(CANARY_MCP_TOKEN));

    let inst = InstancePolicyConfig {
        alias: alias.to_owned(),
        url: server_uri.to_owned(),
        environment,
        policy_mode,
        api_key: Some(SecretValue::new(CANARY_API_KEY)),
        mcp_base_url,
        mcp_access_token,
        cf_access_client_id: Some("cf_id_demo".to_owned()),
        cf_access_client_secret: Some(SecretValue::new(CANARY_CF_SECRET)),
        allow_loopback_http: true,
        trust_configured_private_host: false,
        enable_r4_admin_actions: false,
        max_batch_workflows: MAX_BATCH_WORKFLOWS,
        allowed_workflow_ids: None,
        allowed_project_ids: None,
    };

    let mut instances = BTreeMap::new();
    instances.insert(alias.to_owned(), inst);
    let ws = LoadedWorkspaceConfig {
        active_instance: alias.to_owned(),
        instances,
    };
    AppState::from_workspace_config(ws, Duration::from_secs(60)).expect("valid test AppState")
}

/// Synthetic n8n 2.48.7 Owner `/api/v1/discover?include=schemas` payload INCLUDING the verified
/// live edge case where `agent:*` scopes appear WITHOUT any `/agents` REST resource!
pub fn owner_discover_fixture() -> Value {
    json!({
        "version": "2.48.7",
        "scopes": [
            "workflow:create", "workflow:read", "workflow:update", "workflow:delete",
            "workflow:list", "workflow:publish", "workflow:activate",
            "execution:read", "execution:list", "execution:retry", "execution:stop", "execution:delete",
            "credential:create", "credential:update", "credential:delete", "credential:list",
            "datatable:read", "datatable:write", "datatable:list",
            "project:read", "project:create", "project:update", "project:delete",
            "folder:read", "folder:create", "tag:read", "tag:create", "variable:read", "variable:create",
            "evaluation:read", "evaluation:run",
            "audit:generate",
            "communityPackage:list", "communityPackage:install",
            "sourceControl:pull", "promotion:create", "n8nPackage:export",
            "user:read", "user:create", "role:list",
            "settings:read", "nodeTypePolicy:read", "credentialTypePolicy:read", "insights:read",
            "agent:read", "agent:list", "agent:create", "agent:update", "agent:delete"
        ],
        "resources": {
            "workflow": {
                "operations": [
                    { "operationId": "listWorkflows", "method": "GET", "path": "/api/v1/workflows" },
                    { "operationId": "createWorkflow", "method": "POST", "path": "/api/v1/workflows", "idempotent": true },
                    { "operationId": "publishWorkflow", "method": "POST", "path": "/api/v1/workflows/{id}/publish" }
                ]
            },
            "executions": { "operations": [{ "operationId": "listExecutions", "method": "GET", "path": "/api/v1/executions" }] },
            "evaluation": { "operations": [{ "operationId": "listTestRuns", "method": "GET", "path": "/api/v1/workflows/{id}/test-runs" }] },
            "credential": { "operations": [{ "operationId": "listCredentials", "method": "GET", "path": "/api/v1/credentials" }] },
            "datatable": { "operations": [{ "operationId": "listDataTables", "method": "GET", "path": "/api/v1/data-tables" }] },
            "projects": { "operations": [] },
            "folders": { "operations": [] },
            "tags": { "operations": [] },
            "variables": { "operations": [] },
            "audit": { "operations": [] },
            "community-packages": { "operations": [] },
            "source-control": { "operations": [] },
            "promotions": { "operations": [] },
            "n8npackage": { "operations": [] },
            "user": { "operations": [] },
            "roles": { "operations": [] },
            "settings": { "operations": [] },
            "nodetypepolicy": { "operations": [] },
            "credentialtypepolicy": { "operations": [] },
            "insights": { "operations": [] }
        },
        "protectedInstance": false
    })
}

pub async fn mount_native_mcp_server(server: &MockServer, tools: Value) {
    // Handles both `initialize` + `notifications/initialized` + `tools/list` on `/mcp-server/http`
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(move |req: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let rpc_method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let rpc_id = body.get("id").cloned().unwrap_or(Value::Null);
            match rpc_method {
                "initialize" => ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "sess_loopback_1")
                    .set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": "n8n-native-mcp", "version": "2.48.7" }
                        }
                    })),
                "notifications/initialized" => ResponseTemplate::new(202),
                "tools/list" => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": { "tools": tools }
                })),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{ "type": "text", "text": "{\"valid\":true}" }]
                    }
                })),
            }
        })
        .mount(server)
        .await;
}
