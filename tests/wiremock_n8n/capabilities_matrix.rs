//! Capability matrix contract tests verifying Owner, scoped Member, read-only, 401 expired key,
//! 404 read-only fallback probe, and the `agent:*` scope-without-endpoint rule.

use n8n_capability::{
    CapabilityResolverConfig, CapabilityState, DiscoverySource, LogicalOperation,
    resolve_capabilities, select_operation_route,
};
use n8n_mcp_bridge::PinDataToolName;
use n8n_mcp_server::CapabilitiesParams;
use n8n_mcp_server::WorkflowsParams;
use n8n_mcp_server::tools::{execute_capabilities, execute_workflows};
use n8n_policy::PolicyMode;
use n8n_types::{
    DetailLevel, EnvironmentKind, N8nError, OperationStatus, PermissionDecision, RouteUsed,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{
    CANARY_API_KEY, CANARY_MCP_TOKEN, build_loopback_api_client, build_loopback_mcp_bridge,
    build_test_app_state, mount_native_mcp_server, owner_discover_fixture,
};

#[tokio::test]
async fn owner_matrix_resolves_24_tools_and_marks_n8n_agents_unsupported_without_endpoint() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .and(query_param("include", "schemas"))
        .and(header("x-n8n-api-key", CANARY_API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(owner_discover_fixture()))
        .mount(&server)
        .await;

    let openapi_yml = r#"
openapi: "3.0.0"
info:
  title: n8n Public API
  version: "2.48.7"
paths:
  /workflows: {}
  /executions: {}
  /audit: {}
  /community-packages: {}
"#;
    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string(openapi_yml),
        )
        .mount(&server)
        .await;

    mount_native_mcp_server(
        &server,
        json!([
            { "name": "validate_workflow", "inputSchema": { "type": "object" } },
            { "name": "validate_node_config", "inputSchema": { "type": "object" } },
            { "name": "create_workflow_from_code", "inputSchema": { "type": "object" } },
            { "name": "update_workflow", "inputSchema": { "type": "object" } },
            { "name": "prepare_workflow_pin_data", "inputSchema": { "type": "object" } },
            { "name": "test_workflow", "inputSchema": { "type": "object" } },
            {
                "name": "execute_workflow",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workflowId": { "type": "string" },
                        "triggerNodeName": { "type": "string" }
                    }
                }
            },
            { "name": "restore_workflow_version", "inputSchema": { "type": "object" } }
        ]),
    )
    .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let bridge = build_loopback_mcp_bridge(&server.uri(), CANARY_MCP_TOKEN);
    let profile = resolve_capabilities(&api, Some(&bridge), CapabilityResolverConfig::default())
        .await
        .expect("owner capability handshake succeeds");

    assert_eq!(
        profile.discovery_source,
        DiscoverySource::DiscoverPlusOpenApi
    );
    assert_eq!(profile.n8n_version.as_deref(), Some("2.48.7"));
    assert_eq!(profile.tools.len(), 24);

    let mcp = profile.negotiated_mcp().expect("native mcp connected");
    assert_eq!(mcp.pin_data_tool, PinDataToolName::PrepareWorkflowPinData);
    assert!(mcp.supports_trigger_node_name);

    // Surgical edits & create prefer NativeMcp when advertised + authorized
    assert_eq!(
        select_operation_route(&profile, LogicalOperation::WorkflowsMutate).route,
        RouteUsed::NativeMcp
    );
    assert_eq!(
        select_operation_route(&profile, LogicalOperation::WorkflowsCreate).route,
        RouteUsed::NativeMcp
    );

    // CRITICAL V2 CHECK: `agent:*` scopes exist, but no `/agents` REST or Native MCP agent tools -> Unsupported!
    let agents_entry = profile
        .tools
        .iter()
        .find(|t| t.tool_name == "n8n_agents")
        .expect("n8n_agents present in 24-tool matrix");
    assert_eq!(agents_entry.state, CapabilityState::Unavailable);
    assert_eq!(agents_entry.preferred_route, RouteUsed::Unsupported);
    assert!(agents_entry.reason.contains("agent:*"));
}

#[tokio::test]
async fn scoped_member_and_readonly_matrices_hide_admin_and_destructive_routes() {
    let server = MockServer::start().await;

    // Scoped Member: workflow read/list/update + execution read ONLY
    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "2.48.7",
            "scopes": [
                "workflow:read",
                "workflow:list",
                "workflow:update",
                "execution:read"
            ],
            "resources": {
                "workflow": { "operations": [] },
                "executions": { "operations": [] },
                "user": { "operations": [] },
                "settings": { "operations": [] },
                "community-packages": { "operations": [] },
                "credential": { "operations": [] }
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let profile = resolve_capabilities(&api, None, CapabilityResolverConfig::default())
        .await
        .expect("member handshake");

    let wf_tool = profile
        .tools
        .iter()
        .find(|t| t.tool_name == "n8n_workflows")
        .expect("n8n_workflows");
    assert_eq!(wf_tool.state, CapabilityState::Available);
    assert!(wf_tool.supported_actions.contains(&"list".to_owned()));
    assert!(wf_tool.supported_actions.contains(&"get".to_owned()));
    assert!(
        wf_tool
            .supported_actions
            .contains(&"update_meta".to_owned())
    );
    assert!(!wf_tool.supported_actions.contains(&"delete".to_owned()));
    assert!(!wf_tool.supported_actions.contains(&"create".to_owned()));

    for denied_tool in [
        "n8n_admin_access",
        "n8n_admin_settings",
        "n8n_community_packages",
        "n8n_credentials",
    ] {
        let entry = profile
            .tools
            .iter()
            .find(|t| t.tool_name == denied_tool)
            .unwrap_or_else(|| panic!("missing {denied_tool}"));
        assert_eq!(
            entry.state,
            CapabilityState::Unavailable,
            "{denied_tool} must be unavailable for scoped Member"
        );
    }

    // Read-only policy profile blocks mutating actions even if scope has workflow:update!
    let ro_state = build_test_app_state(
        "prod",
        &server.uri(),
        EnvironmentKind::Production,
        PolicyMode::ReadOnly,
        false,
    );
    let blocked_env = execute_workflows(
        &ro_state,
        WorkflowsParams {
            action: "publish".to_owned(),
            instance: Some("prod".to_owned()),
            workflow_id: Some("wf_1".to_owned()),
            detail: DetailLevel::Minimal,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(blocked_env.status, OperationStatus::Blocked);
    assert_eq!(blocked_env.permission, PermissionDecision::Denied);
}

#[tokio::test]
async fn expired_401_key_fails_closed_without_probing_fallback_endpoints() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "API key expired"
        })))
        .expect(2)
        .mount(&server)
        .await;

    // Fallback endpoint MUST NOT be probed on 401!
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let err = resolve_capabilities(&api, None, CapabilityResolverConfig::default())
        .await
        .expect_err("401 must fail closed");
    assert!(matches!(err, N8nError::Unauthenticated401 { .. }));

    let state = build_test_app_state(
        "staging",
        &server.uri(),
        EnvironmentKind::Staging,
        PolicyMode::StagingSafe,
        false,
    );
    let env = execute_capabilities(
        &state,
        CapabilitiesParams {
            instance: None,
            detail: DetailLevel::Minimal,
            refresh: true,
        },
    )
    .await;
    assert_eq!(env.status, OperationStatus::Error);
    assert_eq!(env.permission, PermissionDecision::Denied);
}

#[tokio::test]
async fn legacy_404_discover_uses_strictly_readonly_fallback_probe_never_mutating() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{ "id": "wf_legacy_1", "name": "Legacy Flow", "active": true }],
            "nextCursor": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Assert zero mutating POST/PUT/PATCH/DELETE probes ever occur!
    for mutating in ["POST", "PUT", "PATCH", "DELETE"] {
        Mock::given(method(mutating))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
    }

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let profile = resolve_capabilities(&api, None, CapabilityResolverConfig::default())
        .await
        .expect("404 discover falls back to read-only GET workflows?limit=1");

    assert_eq!(
        profile.discovery_source,
        DiscoverySource::ReadOnlyFallbackProbe
    );
    assert_eq!(
        select_operation_route(&profile, LogicalOperation::WorkflowsRead).state,
        CapabilityState::Available
    );
    assert_eq!(
        select_operation_route(&profile, LogicalOperation::WorkflowsCreate).state,
        CapabilityState::Unavailable
    );
}

#[tokio::test]
async fn capability_cache_revalidates_before_mutation_and_purges_on_401() {
    use n8n_capability::CapabilityCache;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let server = MockServer::start().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = hits.clone();

    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(move |_req: &wiremock::Request| {
            let call_idx = hits_clone.fetch_add(1, Ordering::SeqCst);
            if call_idx < 2 {
                ResponseTemplate::new(200).set_body_json(owner_discover_fixture())
            } else {
                ResponseTemplate::new(401).set_body_json(json!({ "message": "Key revoked" }))
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let api = build_loopback_api_client(&server.uri(), CANARY_API_KEY);
    let cache = CapabilityCache::new(
        Duration::from_secs(300),
        CapabilityResolverConfig::default(),
    );

    // First read populates cache (hit #1)
    let _p1 = cache
        .resolve_for_read(&api, None, false)
        .await
        .expect("hit 1");
    // Second read uses TTL cache without hitting network (still 1 hit)
    let _p2 = cache
        .resolve_for_read(&api, None, false)
        .await
        .expect("cached");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Pre-mutation revalidation bypasses cache (hit #2)
    let _p3 = cache
        .revalidate_before_mutation(&api, None)
        .await
        .expect("revalidated hit 2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // Next revalidation hits revoked key (401 -> hit #3) and purges cached entry!
    let err = cache
        .revalidate_before_mutation(&api, None)
        .await
        .expect_err("revoked 401");
    assert!(matches!(err, N8nError::Unauthenticated401 { .. }));

    // Subsequent read cannot use stale cached grant; hits network again and fails closed!
    assert!(cache.resolve_for_read(&api, None, false).await.is_err());
}

#[tokio::test]
async fn native_mcp_bridge_enforces_trigger_node_name_and_sdk_prevalidation() {
    let server = MockServer::start().await;

    // Legacy <2.36 Native MCP without `triggerNodeName` property on `execute_workflow`
    mount_native_mcp_server(
        &server,
        json!([
            { "name": "validate_workflow", "inputSchema": { "type": "object" } },
            { "name": "create_workflow_from_code", "inputSchema": { "type": "object" } },
            {
                "name": "execute_workflow",
                "inputSchema": {
                    "type": "object",
                    "properties": { "workflowId": { "type": "string" } }
                }
            }
        ]),
    )
    .await;

    let bridge = build_loopback_mcp_bridge(&server.uri(), CANARY_MCP_TOKEN);

    // Ambiguous multiple triggers (`trigger_count = 2`) on <2.36 MUST fail safely instead of guessing!
    let trig_err = bridge
        .execute_workflow("wf_multi", "manual", None, 2, None)
        .await
        .expect_err("ambiguous triggers on <2.36 must fail closed");
    assert!(matches!(trig_err, N8nError::UnsupportedCapability { .. }));

    // `create_workflow_from_code` calls `validate_workflow` first and succeeds
    let created = bridge
        .create_workflow_from_code(
            "export default workflow('demo')",
            None,
            &["Fetch".to_owned()],
        )
        .await
        .expect("validated sdk create");
    assert_eq!(created.derived_status, OperationStatus::Success);
    assert_eq!(created.http_request_manual_binding_notes.len(), 1);
}
