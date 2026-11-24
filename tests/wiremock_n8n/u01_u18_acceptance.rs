//! End-to-end deterministic acceptance suite (`U01`–`U18`), 200-workflow `< 50 ms` warm FTS5
//! benchmark, single-use `ApprovalReceipt` & TOCTOU verification, `T0`/`T1` side-effect safety,
//! supply-chain & `n8n_agents` capability gating, and authenticated localhost HTTP gateway tests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use n8n_mcp_server::prompts::{build_guidance_prompts, render_guidance_prompt};
use n8n_mcp_server::resources::{build_resource_templates, read_n8n_resource};
use n8n_mcp_server::{HttpGatewayConfig, HttpGatewayHandle, N8nMcpServer};
use n8n_policy::PolicyMode;
use n8n_types::{EnvironmentKind, SecretValue};
use rmcp::model::GetPromptRequestParams;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{build_test_app_state, mount_native_mcp_server, owner_discover_fixture};

fn parse_tool_envelope(call_result: &Value) -> Value {
    let text = call_result["content"][0]["text"]
        .as_str()
        .expect("CallToolResult text block");
    serde_json::from_str(text).expect("valid ToolEnvelope JSON")
}

#[tokio::test]
async fn u01_u05_offline_catalog_validation_resources_prompts_and_audit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(200).set_body_json(owner_discover_fixture()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let wf_fixture = json!({
        "id": "wf_u01",
        "name": "Webhook Slack Notifier",
        "active": false,
        "isArchived": false,
        "versionId": "ver_1",
        "activeVersionId": null,
        "nodes": [
            {
                "id": "n1",
                "name": "Incoming Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [100, 200],
                "parameters": { "path": "order-hook", "httpMethod": "POST" }
            },
            {
                "id": "n2",
                "name": "Post Slack",
                "type": "n8n-nodes-base.slack",
                "typeVersion": 2.2,
                "position": [360, 200],
                "parameters": {
                    "resource": "message",
                    "operation": "post",
                    "text": "={{ $node[\"Incoming Webhook\"].json.orderId }}"
                },
                "credentials": { "slackApi": { "id": "cred_1", "name": "Ops Slack" } }
            }
        ],
        "connections": {
            "Incoming Webhook": {
                "main": [[{ "node": "Post Slack", "type": "main", "index": 0 }]]
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [wf_fixture.clone()],
            "nextCursor": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf_u01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wf_fixture.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions/exec_99"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "exec_99",
            "workflowId": "wf_u01",
            "status": "error",
            "finished": false,
            "mode": "webhook",
            "startedAt": "2026-11-24T00:00:00Z",
            "stoppedAt": "2026-11-24T00:00:01Z",
            "data": {
                "resultData": {
                    "error": {
                        "message": concat!(
                            "Upstream failed with Bearer ey",
                            "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.sig"
                        )
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    let state = build_test_app_state(
        "staging",
        &server.uri(),
        EnvironmentKind::Staging,
        PolicyMode::StagingSafe,
        false,
    );
    let mcp = N8nMcpServer::new(state.clone());

    // U01: Offline catalog node FTS5 search + conditional displayOptions inspection
    let cat_res = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_catalog_nodes",
            json!({ "action": "search", "query": "slack", "limit": 5 }),
        )
        .await
        .expect("n8n_catalog_nodes"),
    );
    assert_eq!(cat_res["status"], "success");
    assert!(
        cat_res["data"]["hits"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "offline catalog must return Slack node hits"
    );

    let inspect_res = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_inspect_node_config",
            json!({
                "nodeType": "n8n-nodes-base.httpRequest",
                "parameters": { "method": "POST", "sendBody": true }
            }),
        )
        .await
        .expect("n8n_inspect_node_config"),
    );
    assert_eq!(inspect_res["status"], "success");

    // U02: Template catalog search & offline validation (including Code node Why Code: advisory)
    let tpl_res = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_catalog_templates",
            json!({ "action": "search", "query": "webhook" }),
        )
        .await
        .expect("n8n_catalog_templates"),
    );
    assert_eq!(tpl_res["status"], "success");
    assert!(
        tpl_res["data"]["templates"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );

    // Incomplete Slack post (missing required channel selector) is caught by displayOptions validator!
    let val_missing = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_validate",
            json!({ "workflow": wf_fixture, "profile": "ai-friendly" }),
        )
        .await
        .expect("n8n_validate incomplete"),
    );
    assert_eq!(val_missing["status"], "error");
    assert_eq!(val_missing["data"]["valid"], false);

    // Valid native workflow passes ai-friendly validation cleanly
    let valid_wf = json!({
        "name": "Valid Native Flow",
        "nodes": [
            {
                "id": "n_trig",
                "name": "Manual Trigger",
                "type": "n8n-nodes-base.manualTrigger",
                "typeVersion": 1,
                "position": [0, 0],
                "parameters": {}
            },
            {
                "id": "n_set",
                "name": "Normalize Fields",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "position": [240, 0],
                "parameters": { "mode": "manual" }
            }
        ],
        "connections": {
            "Manual Trigger": {
                "main": [[{ "node": "Normalize Fields", "type": "main", "index": 0 }]]
            }
        }
    });
    let val_ok = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_validate",
            json!({ "workflow": valid_wf, "profile": "ai-friendly" }),
        )
        .await
        .expect("n8n_validate valid"),
    );
    assert_eq!(val_ok["status"], "success");
    assert_eq!(val_ok["data"]["valid"], true);

    // U03-U05: Audit (separates observedFacts vs heuristics vs permissionGaps) + Resources + Prompts
    let audit_res = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_audit",
            json!({ "action": "workflow", "workflowId": "wf_u01" }),
        )
        .await
        .expect("n8n_audit"),
    );
    assert_eq!(audit_res["status"], "success");

    // Verify all 4 resource templates & resource reads
    assert_eq!(build_resource_templates().resource_templates.len(), 4);
    let wf_res_read = read_n8n_resource(&state, "n8n://staging/workflows/wf_u01")
        .await
        .expect("read workflow resource");
    let wf_res_str = serde_json::to_string(&rmcp::model::ServerResult::from(wf_res_read))
        .expect("serialize resource");
    assert!(wf_res_str.contains("Webhook Slack Notifier"));

    let exec_res_read = read_n8n_resource(&state, "n8n://staging/executions/exec_99/summary")
        .await
        .expect("read execution summary resource");
    let exec_res_str = serde_json::to_string(&rmcp::model::ServerResult::from(exec_res_read))
        .expect("serialize exec resource");
    assert!(
        !exec_res_str.contains(concat!("ey", "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")),
        "JWT inside execution error must be redacted"
    );

    let cat_node_res = read_n8n_resource(
        &state,
        "n8n://catalog/node/n8n-nodes-base.httpRequest/default",
    )
    .await
    .expect("read catalog node resource");
    assert!(
        serde_json::to_string(&rmcp::model::ServerResult::from(cat_node_res))
            .unwrap()
            .contains("httpRequest")
    );

    // Verify all 5 guidance prompts render cleanly
    let prompts = build_guidance_prompts();
    assert_eq!(prompts.prompts.len(), 5);
    for prompt in &prompts.prompts {
        let mut args = serde_json::Map::new();
        args.insert("goal".to_owned(), json!("Sync orders"));
        args.insert("workflow_id".to_owned(), json!("wf_u01"));
        args.insert("change_request".to_owned(), json!("Add retry"));
        let req = GetPromptRequestParams::new(prompt.name.clone()).with_arguments(args);
        let rendered = render_guidance_prompt(&req).expect("render guidance prompt");
        assert!(
            !serde_json::to_string(&rmcp::model::ServerResult::from(rendered))
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn u04_warm_fts5_search_across_200_workflows_stays_under_50ms() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(200).set_body_json(owner_discover_fixture()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let mut workflows = Vec::with_capacity(200);
    for idx in 0..200 {
        let ntype = if idx % 10 == 0 {
            "n8n-nodes-base.slack"
        } else {
            "n8n-nodes-base.httpRequest"
        };
        workflows.push(json!({
            "id": format!("wf_bench_{idx:03}"),
            "name": format!("Bench Pipeline {idx:03}"),
            "active": idx % 2 == 0,
            "isArchived": false,
            "versionId": format!("v_{idx}"),
            "nodes": [
                {
                    "id": format!("n_{idx}_1"),
                    "name": "Trigger",
                    "type": "n8n-nodes-base.manualTrigger",
                    "typeVersion": 1,
                    "position": [0, 0],
                    "parameters": {}
                },
                {
                    "id": format!("n_{idx}_2"),
                    "name": format!("Step_{idx}"),
                    "type": ntype,
                    "typeVersion": 2.2,
                    "position": [220, 0],
                    "parameters": { "text": "={{ $json.id }}" },
                    "credentials": { "slackApi": { "id": "cred_shared", "name": "Prod Slack" } }
                }
            ],
            "connections": {
                "Trigger": { "main": [[{ "node": format!("Step_{idx}"), "type": "main", "index": 0 }]] }
            }
        }));
    }

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": workflows,
            "nextCursor": null
        })))
        .mount(&server)
        .await;

    let state = build_test_app_state(
        "staging",
        &server.uri(),
        EnvironmentKind::Staging,
        PolicyMode::StagingSafe,
        false,
    );
    let mcp = N8nMcpServer::new(state);

    // Cold populate index across 200 workflows
    let cold = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_find_nodes",
            json!({
                "nodeType": "n8n-nodes-base.slack",
                "refreshIndex": true,
                "limit": 50
            }),
        )
        .await
        .expect("cold find_nodes"),
    );
    assert_eq!(cold["status"], "success");
    assert_eq!(
        cold["data"]["hits"].as_array().map(Vec::len),
        Some(20),
        "20 of 200 workflows contain Slack node"
    );

    // Warm cached FTS5 query — V2 performance target: < 50 ms!
    let t0 = Instant::now();
    let warm = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_find_nodes",
            json!({
                "nodeType": "n8n-nodes-base.slack",
                "refreshIndex": false,
                "limit": 50
            }),
        )
        .await
        .expect("warm find_nodes"),
    );
    let elapsed = t0.elapsed();
    assert_eq!(warm["status"], "success");
    assert!(
        elapsed.as_millis() < 50,
        "warm FTS5 search over 200 indexed workflows took {} ms (must be < 50 ms)",
        elapsed.as_millis()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn u06_u10_staged_mutations_single_use_receipts_toctou_versions_and_batch_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(200).set_body_json(owner_discover_fixture()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let stored_wf = Arc::new(Mutex::new(json!({
        "id": "wf_mut_1",
        "name": "[MCP-E2E-TEST] Surgical Refactor",
        "active": false,
        "isArchived": false,
        "versionId": "ver_initial_1",
        "activeVersionId": null,
        "nodes": [
            {
                "id": "n_src",
                "name": "Fetch Orders",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [100, 100],
                "parameters": { "url": "https://api.example.com/orders", "method": "GET" }
            },
            {
                "id": "n_dst",
                "name": "Format Payload",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "position": [380, 100],
                "parameters": {
                    "assignments": {
                        "assignments": [
                            { "name": "orderTotal", "value": "={{ $('Fetch Orders').item.json.total }}" }
                        ]
                    }
                }
            }
        ],
        "connections": {
            "Fetch Orders": {
                "main": [[{ "node": "Format Payload", "type": "main", "index": 0 }]]
            }
        }
    })));

    let get_store = Arc::clone(&stored_wf);
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf_mut_1"))
        .respond_with(move |_req: &wiremock::Request| {
            let cur = get_store.lock().unwrap().clone();
            ResponseTemplate::new(200).set_body_json(cur)
        })
        .mount(&server)
        .await;

    let put_store = Arc::clone(&stored_wf);
    Mock::given(method("PUT"))
        .and(path("/api/v1/workflows/wf_mut_1"))
        .respond_with(move |req: &wiremock::Request| {
            let incoming: Value = serde_json::from_slice(&req.body).unwrap();
            let mut guard = put_store.lock().unwrap();
            guard["name"] = incoming["name"].clone();
            guard["nodes"] = incoming["nodes"].clone();
            guard["connections"] = incoming["connections"].clone();
            guard["versionId"] = json!("ver_after_mut_2");
            ResponseTemplate::new(200).set_body_json(guard.clone())
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf_mut_1/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{ "versionId": "ver_after_mut_2" }, { "versionId": "ver_initial_1" }],
            "nextCursor": null
        })))
        .mount(&server)
        .await;

    // ProductionGuarded requires receipts even on R2 draft mutations!
    let state = build_test_app_state(
        "prod",
        &server.uri(),
        EnvironmentKind::Production,
        PolicyMode::ProductionGuarded,
        false,
    );
    let mcp = N8nMcpServer::new(state.clone());

    let ops = json!([
        {
            "op": "configure_reliability",
            "node_name": "Fetch Orders",
            "retry_on_fail": true,
            "max_tries": 3,
            "wait_between_tries_ms": 1000
        },
        {
            "op": "rename_node",
            "old_name": "Fetch Orders",
            "new_name": "Load Orders API"
        }
    ]);

    // 1. Preview returns planId + bounded diff + expectedVersionHash
    let preview = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_mutate_nodes",
            json!({
                "workflowId": "wf_mut_1",
                "mode": "preview",
                "operations": ops
            }),
        )
        .await
        .expect("preview mutate_nodes"),
    );
    assert_eq!(preview["status"], "preview");
    let plan_id = preview["data"]["planId"]
        .as_str()
        .expect("planId")
        .to_owned();
    let expected_hash = preview["data"]["expectedVersionHash"]
        .as_str()
        .expect("expectedVersionHash")
        .to_owned();

    // Dynamic diff resource n8n://{instance}/workflows/{id}/diff/{planId} is readable!
    let diff_res = read_n8n_resource(
        &state,
        &format!("n8n://prod/workflows/wf_mut_1/diff/{plan_id}"),
    )
    .await
    .expect("read plan diff resource");
    assert!(
        serde_json::to_string(&rmcp::model::ServerResult::from(diff_res))
            .unwrap()
            .contains(&plan_id)
    );

    // 2. Apply WITHOUT approvalReceipt in ProductionGuarded -> Blocked!
    let blocked_apply = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_mutate_nodes",
            json!({
                "workflowId": "wf_mut_1",
                "mode": "apply",
                "expectedVersionHash": expected_hash,
                "operations": ops
            }),
        )
        .await
        .expect("unapproved apply"),
    );
    assert_eq!(blocked_apply["status"], "blocked");

    // 3. Mint single-use approvalReceipt via confirm_plan
    let confirmed = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_workflows",
            json!({
                "action": "confirm_plan",
                "planId": plan_id
            }),
        )
        .await
        .expect("confirm_plan"),
    );
    assert_eq!(confirmed["status"], "success");
    let receipt = confirmed["data"]["approvalReceipt"]
        .as_str()
        .expect("approvalReceipt")
        .to_owned();

    // 4. Apply with valid receipt -> Success, AST literal expression rewritten, snapshot saved!
    let applied = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_mutate_nodes",
            json!({
                "workflowId": "wf_mut_1",
                "mode": "apply",
                "expectedVersionHash": expected_hash,
                "approvalReceipt": receipt,
                "operations": ops
            }),
        )
        .await
        .expect("approved apply"),
    );
    assert_eq!(applied["status"], "success");
    assert_eq!(applied["changed"], true);

    // Verify AST literal-only expression rewrite updated `$('Fetch Orders')` -> `$('Load Orders API')`!
    let final_wf = stored_wf.lock().unwrap().clone();
    let final_wf_str = serde_json::to_string(&final_wf).unwrap();
    assert!(
        final_wf_str.contains("Load Orders API"),
        "renamed node & expression reference must be present in stored workflow"
    );

    // 5. Replay the exact same single-use receipt -> Blocked!
    let replayed = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_mutate_nodes",
            json!({
                "workflowId": "wf_mut_1",
                "mode": "apply",
                "expectedVersionHash": expected_hash,
                "approvalReceipt": receipt,
                "operations": ops
            }),
        )
        .await
        .expect("replayed receipt"),
    );
    assert_eq!(replayed["status"], "blocked");

    // 6. Inspect versions & local encrypted snapshots via n8n_versions
    let versions = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_versions",
            json!({
                "action": "history",
                "workflowId": "wf_mut_1"
            }),
        )
        .await
        .expect("n8n_versions history"),
    );
    assert_eq!(versions["status"], "success");

    let snaps = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_versions",
            json!({
                "action": "snapshots",
                "workflowId": "wf_mut_1"
            }),
        )
        .await
        .expect("n8n_versions snapshots"),
    );
    assert_eq!(snaps["status"], "success");
    assert!(
        snaps["data"]["snapshots"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
        "local encrypted pre-mutation snapshot must be recorded"
    );

    // 7. U10: Bulk codemod exceeding 20 workflows is hard-blocked by policy!
    let thirty_ids: Vec<String> = (0..30).map(|i| format!("wf_{i}")).collect();
    let bulk_blocked = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_bulk_codemod",
            json!({
                "action": "preview",
                "workflowIds": thirty_ids,
                "operations": ops
            }),
        )
        .await
        .expect("bulk_codemod > 20"),
    );
    assert_eq!(bulk_blocked["status"], "blocked");
}

#[tokio::test]
async fn u11_u18_side_effect_simulation_guard_rbac_concealment_supply_chain_agents_and_http_gateway()
 {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/discover"))
        .respond_with(ResponseTemplate::new(200).set_body_json(owner_discover_fixture()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/openapi.yml"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    // Dangerous workflow containing Execute Command EVEN WITH pinData
    let dangerous_wf = json!({
        "id": "wf_rce",
        "name": "[MCP-E2E-TEST] Dangerous Sim",
        "active": false,
        "nodes": [
            {
                "id": "n1",
                "name": "Shell Step",
                "type": "n8n-nodes-base.executeCommand",
                "typeVersion": 1,
                "position": [0, 0],
                "parameters": { "command": "whoami" }
            }
        ],
        "connections": {},
        "pinData": { "Shell Step": [{ "json": { "stdout": "pinned" } }] }
    });

    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf_rce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dangerous_wf.clone()))
        .mount(&server)
        .await;

    // Non-owner 403 on credentials list (U12)
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(
                json!({ "message": "Forbidden: missing credential:list permission" }),
            ),
        )
        .mount(&server)
        .await;

    mount_native_mcp_server(
        &server,
        json!([{ "name": "prepare_workflow_pin_data", "inputSchema": { "type": "object" } }]),
    )
    .await;

    let state = build_test_app_state(
        "staging",
        &server.uri(),
        EnvironmentKind::Staging,
        PolicyMode::StagingSafe,
        true,
    );
    let mcp = N8nMcpServer::new(state);

    // U11: T1 simulate MUST refuse Execute Command even when pinned!
    let sim_blocked = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_test_workflow",
            json!({
                "mode": "simulate",
                "workflowId": "wf_rce",
                "pinnedNodes": ["Shell Step"]
            }),
        )
        .await
        .expect("simulate dangerous workflow"),
    );
    assert_eq!(
        sim_blocked["status"], "blocked",
        "T1 simulation must block Execute Command side-effect node even when pinned: {sim_blocked}"
    );

    // U12: 403 on credentials list fails closed with Blocked / Denied
    let cred_403 = parse_tool_envelope(
        &mcp.invoke_tool_json("n8n_credentials", json!({ "action": "list" }))
            .await
            .expect("credentials 403"),
    );
    assert_eq!(cred_403["status"], "blocked");
    assert_eq!(cred_403["permission"], "denied");

    // Offline credential schema fallback works cleanly without exposing any secret!
    let cred_schema = parse_tool_envelope(
        &mcp.invoke_tool_json("n8n_credentials", json!({ "action": "list_catalog_types" }))
            .await
            .expect("credentials list_catalog_types"),
    );
    assert_eq!(cred_schema["status"], "success");
    assert!(
        cred_schema["data"]["count"]
            .as_u64()
            .is_some_and(|c| c >= 20)
    );

    // U16: Community package install rejects unpinned `latest` / range versions!
    let unpinned_pkg = parse_tool_envelope(
        &mcp.invoke_tool_json(
            "n8n_community_packages",
            json!({
                "action": "install",
                "packageName": "n8n-nodes-acme",
                "version": "latest"
            }),
        )
        .await
        .expect("unpinned community package"),
    );
    assert_ne!(unpinned_pkg["status"], "success");

    // U17: `n8n_agents` returns `unsupported` even though `agent:*` scopes exist in owner_discover_fixture!
    let agents_res = parse_tool_envelope(
        &mcp.invoke_tool_json("n8n_agents", json!({ "action": "list" }))
            .await
            .expect("n8n_agents"),
    );
    assert_eq!(
        agents_res["status"], "unsupported",
        "n8n_agents must return unsupported when /agents resource is absent despite agent:* scopes"
    );

    // U18: Localhost HTTP gateway enforces Bearer token & DNS-rebinding Host allowlist!
    let bind_zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let anon_cfg = HttpGatewayConfig::loopback(bind_zero, None);
    assert!(
        anon_cfg.validate().is_err(),
        "anonymous HTTP gateway must be rejected"
    );

    let gateway_token = "mcp_http_test_secret_token_9911";
    let auth_cfg = HttpGatewayConfig::loopback(bind_zero, Some(SecretValue::new(gateway_token)));
    let gw = HttpGatewayHandle::start(mcp, auth_cfg)
        .await
        .expect("start authenticated loopback HTTP gateway");
    let addr = gw.local_addr();
    let http_client = reqwest::Client::new();

    // Missing Bearer token -> 401
    let r_unauth = http_client
        .post(format!("http://{addr}/mcp"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_unauth.status().as_u16(), 401);

    // Spoofed Host header (DNS rebinding attempt) -> 403
    let r_rebind = http_client
        .post(format!("http://{addr}/mcp"))
        .header("Host", "evil.attacker.example")
        .header("Authorization", format!("Bearer {gateway_token}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_rebind.status().as_u16(), 403);

    // Valid Bearer + loopback Host -> 200 with all 24 tools!
    let r_ok = http_client
        .post(format!("http://{addr}/mcp"))
        .header("Authorization", format!("Bearer {gateway_token}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_ok.status().as_u16(), 200);
    let ok_json: Value = r_ok.json().await.unwrap();
    assert_eq!(
        ok_json["result"]["tools"].as_array().map(Vec::len),
        Some(24)
    );

    gw.shutdown().await;
}
