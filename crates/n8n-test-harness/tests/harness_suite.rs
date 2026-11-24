#![forbid(unsafe_code)]
//! Comprehensive Phase 4 acceptance & security test suite for `n8n-test-harness` (V2 Section 8 & 14).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use n8n_api_client::ssrf::SsrfPolicy;
use n8n_api_client::{ApiClientConfig, N8nApiClient};
use n8n_graph::{GraphMutationOp, WorkflowIr};
use n8n_mcp_bridge::{McpBridgeConfig, NativeMcpBridge, PinDataToolName};
use n8n_policy::{
    ApprovalExpectation, InstancePolicyConfig, MAX_BATCH_WORKFLOWS, PolicyEngine, PolicyMode,
    ReceiptSigner,
};
use n8n_state_vault::{CleanupLeaseState, JournalState, JournalTransitionInput, OperationJournal};
use n8n_test_harness::{
    ABSOLUTE_MAX_REPAIR_ATTEMPTS, DEFAULT_MAX_REPAIR_ATTEMPTS, DeterministicTestSafetyGate,
    ExecutionDetailLevel, ExecutionMinimizeOptions, LeaseCleanupOutcome,
    MAX_EXECUTION_PAYLOAD_BYTES, NodeSideEffectClass, RepairCandidateProposal, RepairConfidence,
    RepairHaltReason, RepairLoopConfig, RepairLoopStatus, RepairStage, SideEffectVerdict,
    StartupReconciler, TestExecutionMode, TestOrchestrator, TestOutcomeStatus, TestRunRequest,
    UncertainOperationOutcome, classify_workflow_side_effects, run_bounded_repair_loop,
    summarize_execution_redacted,
};
use n8n_types::{EnvironmentKind, N8nError, RiskLevel, RouteUsed, SecretValue};
use n8n_validator::ValidationStrength;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn loopback_ssrf_policy() -> SsrfPolicy {
    SsrfPolicy {
        allow_loopback_http: true,
        trust_configured_private_host: true,
        trusted_private_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

fn staging_instance_config(base_url: &str) -> InstancePolicyConfig {
    InstancePolicyConfig {
        alias: "staging".to_owned(),
        url: base_url.to_owned(),
        environment: EnvironmentKind::Staging,
        policy_mode: PolicyMode::StagingSafe,
        api_key: None,
        mcp_base_url: Some(format!("{base_url}/mcp-server/http")),
        mcp_access_token: None,
        cf_access_client_id: None,
        cf_access_client_secret: None,
        allow_loopback_http: true,
        trust_configured_private_host: true,
        enable_r4_admin_actions: false,
        max_batch_workflows: MAX_BATCH_WORKFLOWS,
        allowed_workflow_ids: None,
        allowed_project_ids: None,
    }
}

fn build_test_api_client(base_url: &str) -> N8nApiClient {
    let mut cfg = ApiClientConfig::new(
        "staging",
        base_url,
        SecretValue::new("test_public_api_key_isolated_01"),
    );
    cfg.ssrf_policy = loopback_ssrf_policy();
    N8nApiClient::new(cfg).expect("valid test N8nApiClient")
}

fn build_test_mcp_bridge(base_url: &str) -> NativeMcpBridge {
    let mut cfg = McpBridgeConfig::new(
        "staging",
        format!("{base_url}/mcp-server/http"),
        SecretValue::new("test_native_mcp_bearer_isolated_02"),
    );
    cfg.ssrf_policy = loopback_ssrf_policy();
    let api_key = SecretValue::new("test_public_api_key_isolated_01");
    NativeMcpBridge::new(cfg, Some(&api_key)).expect("valid isolated NativeMcpBridge")
}

/// JSON-RPC 2.0 `wiremock` responder simulating n8n's `/mcp-server/http` endpoint.
struct MockNativeMcpResponder {
    tools: Vec<Value>,
    pin_calls: Arc<AtomicUsize>,
    test_calls: Arc<AtomicUsize>,
    exec_calls: Arc<AtomicUsize>,
    fail_exec: bool,
    non_terminal_exec: bool,
}

impl Respond for MockNativeMcpResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let rpc_id = body.get("id").cloned().unwrap_or(Value::Null);
        let method_name = body.get("method").and_then(Value::as_str).unwrap_or("");

        match method_name {
            "initialize" => ResponseTemplate::new(200)
                .insert_header("mcp-session-id", "sess_mock_01")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "n8n-mcp-mock", "version": "2.48.7" }
                    }
                })),
            "notifications/initialized" => ResponseTemplate::new(202),
            "tools/list" => ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "tools": self.tools
                }
            })),
            "tools/call" => {
                let tool_name = body
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match tool_name {
                    "validate_workflow" => ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "structuredContent": {
                                "valid": true,
                                "checkedBy": "native_mcp"
                            }
                        }
                    })),
                    "prepare_workflow_pin_data" | "prepare_test_pin_data" => {
                        self.pin_calls.fetch_add(1, Ordering::SeqCst);
                        ResponseTemplate::new(200).set_body_json(json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": {
                                "structuredContent": {
                                    "prepared": true,
                                    "tool": tool_name
                                }
                            }
                        }))
                    }
                    "test_workflow" => {
                        self.test_calls.fetch_add(1, Ordering::SeqCst);
                        ResponseTemplate::new(200).set_body_json(json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": {
                                "structuredContent": {
                                    "executionId": "exec_sim_101",
                                    "workflowId": "wf_sim_1",
                                    "status": "success",
                                    "finished": true,
                                    "durationMs": 42,
                                    "data": {
                                        "resultData": {
                                            "runData": {
                                                "HTTP Fetch": [{
                                                    "data": {
                                                        "main": [[{
                                                            "json": {
                                                                "orderId": 9001,
                                                                "secretToken": "Bearer LIVE_SECRET_SHOULD_REDACT_999"
                                                            }
                                                        }]]
                                                    }
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        }))
                    }
                    "execute_workflow" => {
                        self.exec_calls.fetch_add(1, Ordering::SeqCst);
                        let payload = if self.non_terminal_exec {
                            json!({
                                "executionId": "exec_nonterm_77",
                                "status": "started",
                                "finished": false
                            })
                        } else if self.fail_exec {
                            json!({
                                "executionId": "exec_fail_55",
                                "status": "error",
                                "finished": true,
                                "data": {
                                    "resultData": {
                                        "error": {
                                            "name": "NodeApiError",
                                            "node": { "name": "Staging Slack" },
                                            "message": "Slack webhook failed with Authorization: Bearer SECRET_SLACK_TOK_12345"
                                        }
                                    }
                                }
                            })
                        } else {
                            json!({
                                "executionId": "exec_live_202",
                                "status": "success",
                                "finished": true,
                                "durationMs": 85
                            })
                        };
                        ResponseTemplate::new(200).set_body_json(json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": { "structuredContent": payload }
                        }))
                    }
                    _ => ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "error": { "code": -32601, "message": "tool not found" }
                    })),
                }
            }
            _ => ResponseTemplate::new(400),
        }
    }
}

// ============================================================================
// 1. Classifier & U13: Host/Filesystem I/O Blocked Even When HTTP/DB Are Pinned
// ============================================================================

#[tokio::test]
async fn t1_blocks_execute_command_read_write_files_and_host_code_even_when_http_and_db_pinned() {
    let server = MockServer::start().await;
    let pin_calls = Arc::new(AtomicUsize::new(0));
    let test_calls = Arc::new(AtomicUsize::new(0));
    let exec_calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(MockNativeMcpResponder {
            tools: vec![
                json!({ "name": "prepare_workflow_pin_data", "inputSchema": {} }),
                json!({ "name": "test_workflow", "inputSchema": {} }),
                json!({ "name": "execute_workflow", "inputSchema": { "properties": { "triggerNodeName": { "type": "string" } } } }),
            ],
            pin_calls: Arc::clone(&pin_calls),
            test_calls: Arc::clone(&test_calls),
            exec_calls: Arc::clone(&exec_calls),
            fail_exec: false,
            non_terminal_exec: false,
        })
        .mount(&server)
        .await;

    // Test every required credential-free / host I/O variant!
    let host_variants = [
        (
            "Run Shell",
            "n8n-nodes-base.executeCommand",
            json!({ "command": "whoami" }),
        ),
        (
            "Disk RW",
            "n8n-nodes-base.readWriteFile",
            json!({ "fileSelector": "/etc/hosts" }),
        ),
        (
            "Watch Disk",
            "n8n-nodes-base.localFileTrigger",
            json!({ "path": "/var/log" }),
        ),
        (
            "Legacy Write",
            "n8n-nodes-base.writeBinaryFile",
            json!({ "fileName": "out.bin" }),
        ),
        (
            "Legacy Read",
            "n8n-nodes-base.readBinaryFiles",
            json!({ "fileSelector": "*.txt" }),
        ),
        (
            "Remote SSH",
            "n8n-nodes-base.ssh",
            json!({ "command": "uptime" }),
        ),
        (
            "Remote FTP",
            "n8n-nodes-base.ftp",
            json!({ "path": "/upload" }),
        ),
        (
            "Host ChildProc Code",
            "n8n-nodes-base.code",
            json!({ "jsCode": "const cp = require('child_process'); return items;" }),
        ),
        (
            "Host Fs Code",
            "n8n-nodes-base.code",
            json!({ "jsCode": "import fs from 'fs'; return items;" }),
        ),
        (
            "Host Deno Code",
            "n8n-nodes-base.code",
            json!({ "jsCode": "const txt = await Deno.readTextFile('/tmp/a'); return items;" }),
        ),
        (
            "Host Bun Code",
            "n8n-nodes-base.code",
            json!({ "jsCode": "Bun.spawn(['ls']); return items;" }),
        ),
    ];

    let orchestrator = TestOrchestrator::new(
        staging_instance_config(&server.uri()),
        PolicyEngine::default(),
    )
    .with_mcp_bridge(build_test_mcp_bridge(&server.uri()));

    for (host_name, host_type, host_params) in host_variants {
        let is_trigger = host_type == "n8n-nodes-base.localFileTrigger";
        let wf = if is_trigger {
            WorkflowIr::from_json_value(json!({
                "id": "wf_u13",
                "name": "U13 Host Trigger Flow",
                "nodes": [
                    { "id": "1", "name": host_name, "type": host_type, "parameters": host_params },
                    { "id": "2", "name": "HTTP API", "type": "n8n-nodes-base.httpRequest", "parameters": { "url": "https://api.example.com" } },
                    { "id": "3", "name": "Postgres Write", "type": "n8n-nodes-base.postgres", "parameters": {} }
                ],
                "connections": {
                    host_name: { "main": [[{ "node": "HTTP API", "type": "main", "index": 0 }]] },
                    "HTTP API": { "main": [[{ "node": "Postgres Write", "type": "main", "index": 0 }]] }
                }
            }))
            .expect("valid ir")
        } else {
            WorkflowIr::from_json_value(json!({
                "id": "wf_u13",
                "name": "U13 Host Node Flow",
                "nodes": [
                    { "id": "1", "name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": { "path": "test" } },
                    { "id": "2", "name": "HTTP API", "type": "n8n-nodes-base.httpRequest", "parameters": { "url": "https://api.example.com" } },
                    { "id": "3", "name": "Postgres Write", "type": "n8n-nodes-base.postgres", "parameters": {} },
                    { "id": "4", "name": host_name, "type": host_type, "parameters": host_params }
                ],
                "connections": {
                    "Webhook": { "main": [[{ "node": "HTTP API", "type": "main", "index": 0 }]] },
                    "HTTP API": { "main": [[{ "node": "Postgres Write", "type": "main", "index": 0 }]] },
                    "Postgres Write": { "main": [[{ "node": host_name, "type": "main", "index": 0 }]] }
                }
            }))
            .expect("valid ir")
        };

        // Even when HTTP API, Postgres Write, AND the host node itself are all in `pinned_nodes`!
        let pinned = HashSet::from([
            "HTTP API".to_owned(),
            "Postgres Write".to_owned(),
            host_name.to_owned(),
        ]);

        let cls = classify_workflow_side_effects(&wf, &HashMap::new(), &pinned, None);
        assert_eq!(
            cls.verdict,
            SideEffectVerdict::BlockedHostOrFilesystemIo,
            "expected `{host_name}` (`{host_type}`) to block T1 even when pinned"
        );
        assert!(!cls.allows_t1_simulate());
        assert!(cls.host_io_nodes.contains(&host_name.to_owned()));
        assert!(cls.classified_nodes.iter().any(
            |n| n.node_name == host_name && n.class == NodeSideEffectClass::HostOrFilesystemIo
        ));

        let mut req = TestRunRequest::new(TestExecutionMode::Simulate, "principal_alice", wf);
        req.pinned_nodes = pinned;
        req.pin_data = Some(json!({
            "HTTP API": [{ "json": { "ok": true } }],
            "Postgres Write": [{ "json": { "rows": 1 } }],
            host_name: [{ "json": { "mocked": true } }]
        }));

        let res = orchestrator
            .run_test(&req, None)
            .await
            .expect("structured T1 block");
        assert_eq!(
            res.status,
            TestOutcomeStatus::BlockedOrUnsupportedSimulation
        );
        assert!(!res.escalated_to_live_mode);
        assert_eq!(res.attempts_made, 0);
    }

    // Zero remote simulation or execution calls were sent to n8n!
    assert_eq!(pin_calls.load(Ordering::SeqCst), 0);
    assert_eq!(test_calls.load(Ordering::SeqCst), 0);
    assert_eq!(exec_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn classifier_scopes_reachability_by_trigger_and_fails_closed_on_unknown_or_unsafe_subworkflows() {
    let parent = WorkflowIr::from_json_value(json!({
        "id": "wf_parent",
        "name": "Multi-Trigger & Subworkflow Parent",
        "nodes": [
            { "id": "1", "name": "Safe Webhook", "type": "n8n-nodes-base.webhook" },
            { "id": "2", "name": "Transform Set", "type": "n8n-nodes-base.set" },
            { "id": "3", "name": "Admin Cron", "type": "n8n-nodes-base.scheduleTrigger" },
            {
                "id": "4",
                "name": "Call Child",
                "type": "n8n-nodes-base.executeWorkflow",
                "parameters": { "workflowId": { "__rl": true, "value": "wf_child_1" } }
            }
        ],
        "connections": {
            "Safe Webhook": { "main": [[{ "node": "Transform Set", "type": "main", "index": 0 }]] },
            "Admin Cron": { "main": [[{ "node": "Call Child", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("parent ir");

    // 1. Selecting ONLY `Safe Webhook` excludes `Admin Cron -> Call Child`!
    let scoped_safe = classify_workflow_side_effects(
        &parent,
        &HashMap::new(),
        &HashSet::new(),
        Some("Safe Webhook"),
    );
    assert_eq!(scoped_safe.verdict, SideEffectVerdict::SafeForSimulate);
    assert!(scoped_safe.all_reachable_deterministic_local);
    assert_eq!(
        scoped_safe.reachable_nodes,
        vec!["Safe Webhook".to_owned(), "Transform Set".to_owned()]
    );

    // 2. All triggers (`None`) with missing `wf_child_1` -> `UnknownSubworkflowFailClosed`!
    let missing_sub =
        classify_workflow_side_effects(&parent, &HashMap::new(), &HashSet::new(), None);
    assert_eq!(
        missing_sub.verdict,
        SideEffectVerdict::UnknownSubworkflowFailClosed
    );
    assert!(!missing_sub.allows_t1_simulate());
    assert!(
        missing_sub
            .unknown_subworkflows
            .contains(&"wf_child_1".to_owned())
    );

    // 3. Providing `wf_child_1` containing `readWriteFile` -> recursively blocks as `BlockedHostOrFilesystemIo`!
    let unsafe_child = WorkflowIr::from_json_value(json!({
        "id": "wf_child_1",
        "name": "Unsafe Child",
        "nodes": [
            { "id": "c1", "name": "Sub Trigger", "type": "n8n-nodes-base.executeWorkflowTrigger" },
            { "id": "c2", "name": "Sub Write File", "type": "n8n-nodes-base.readWriteFile" }
        ],
        "connections": {
            "Sub Trigger": { "main": [[{ "node": "Sub Write File", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("unsafe child");

    let recursive_blocked = classify_workflow_side_effects(
        &parent,
        &HashMap::from([("wf_child_1".to_owned(), unsafe_child)]),
        &HashSet::new(),
        None,
    );
    assert_eq!(
        recursive_blocked.verdict,
        SideEffectVerdict::BlockedHostOrFilesystemIo
    );
    assert!(
        recursive_blocked
            .host_io_nodes
            .contains(&"wf_child_1::Sub Write File".to_owned())
    );

    // 4. Providing `wf_child_1` with pinned `Slack` -> `SafeForSimulate`!
    let pinned_child = WorkflowIr::from_json_value(json!({
        "id": "wf_child_1",
        "name": "Pinned Child",
        "nodes": [
            { "id": "c1", "name": "Sub Trigger", "type": "n8n-nodes-base.executeWorkflowTrigger" },
            { "id": "c2", "name": "Notify Slack", "type": "n8n-nodes-base.slack" }
        ],
        "connections": {
            "Sub Trigger": { "main": [[{ "node": "Notify Slack", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("pinned child");

    let recursive_safe = classify_workflow_side_effects(
        &parent,
        &HashMap::from([("wf_child_1".to_owned(), pinned_child)]),
        &HashSet::from(["wf_child_1::Notify Slack".to_owned()]),
        None,
    );
    assert_eq!(recursive_safe.verdict, SideEffectVerdict::SafeForSimulate);
}

// ============================================================================
// 2. T0, T1 (Native MCP & Offline Dry-Check), T2 (<2.36 Ambiguity, Webhook, Receipt), & T3 Routing
// ============================================================================

#[tokio::test]
async fn t0_and_t1_modes_negotiate_pin_tools_and_label_offline_dry_check_honestly() {
    let server = MockServer::start().await;
    let pin_calls = Arc::new(AtomicUsize::new(0));
    let test_calls = Arc::new(AtomicUsize::new(0));
    let exec_calls = Arc::new(AtomicUsize::new(0));

    // Mount legacy `< 2.34` tool surface (`prepare_test_pin_data` + `validate_workflow` + `test_workflow`).
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(MockNativeMcpResponder {
            tools: vec![
                json!({ "name": "validate_workflow", "inputSchema": {} }),
                json!({ "name": "prepare_test_pin_data", "inputSchema": {} }),
                json!({ "name": "test_workflow", "inputSchema": {} }),
            ],
            pin_calls: Arc::clone(&pin_calls),
            test_calls: Arc::clone(&test_calls),
            exec_calls: Arc::clone(&exec_calls),
            fail_exec: false,
            non_terminal_exec: false,
        })
        .mount(&server)
        .await;

    let wf_with_http = WorkflowIr::from_json_value(json!({
        "id": "wf_sim_1",
        "name": "Webhook to HTTP",
        "nodes": [
            { "id": "1", "name": "Intake", "type": "n8n-nodes-base.webhook", "parameters": { "path": "in" } },
            { "id": "2", "name": "HTTP Fetch", "type": "n8n-nodes-base.httpRequest", "parameters": { "url": "https://api.example.com" } },
            { "id": "3", "name": "Format", "type": "n8n-nodes-base.set", "parameters": {} }
        ],
        "connections": {
            "Intake": { "main": [[{ "node": "HTTP Fetch", "type": "main", "index": 0 }]] },
            "HTTP Fetch": { "main": [[{ "node": "Format", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("wf_with_http");

    let orch_with_bridge = TestOrchestrator::new(
        staging_instance_config(&server.uri()),
        PolicyEngine::default(),
    )
    .with_mcp_bridge(build_test_mcp_bridge(&server.uri()));

    // 1. T0 ValidateOnly returns `structural_syntax_only_not_runtime` + NativeMcpVerified!
    let t0_req = TestRunRequest::new(
        TestExecutionMode::ValidateOnly,
        "principal_alice",
        wf_with_http.clone(),
    );
    let t0_res = orch_with_bridge
        .run_test(&t0_req, None)
        .await
        .expect("T0 ok");
    assert_eq!(t0_res.status, TestOutcomeStatus::ValidationPassed);
    assert_eq!(t0_res.mode_guarantee, "structural_syntax_only_not_runtime");
    assert_eq!(t0_res.route_used, RouteUsed::NativeMcp);
    assert_eq!(
        t0_res.validation_report.as_ref().map(|r| r.strength),
        Some(ValidationStrength::NativeMcpVerified)
    );

    // 2. T1 Simulate WITHOUT pinning `HTTP Fetch` -> BlockedOrUnsupportedSimulation!
    let unpinned_t1 = TestRunRequest::new(
        TestExecutionMode::Simulate,
        "principal_alice",
        wf_with_http.clone(),
    );
    let blocked_res = orch_with_bridge
        .run_test(&unpinned_t1, None)
        .await
        .expect("T1 unpinned");
    assert_eq!(
        blocked_res.status,
        TestOutcomeStatus::BlockedOrUnsupportedSimulation
    );
    assert_eq!(test_calls.load(Ordering::SeqCst), 0);

    // 3. T1 Simulate WITH `HTTP Fetch` pinned -> negotiates `prepare_test_pin_data`, executes `test_workflow`,
    //    and redacts live secret from execution summary!
    let mut pinned_t1 = TestRunRequest::new(
        TestExecutionMode::Simulate,
        "principal_alice",
        wf_with_http.clone(),
    );
    pinned_t1.pin_data = Some(json!({
        "HTTP Fetch": [{ "json": { "orderId": 9001 } }]
    }));
    let sim_res = orch_with_bridge
        .run_test(&pinned_t1, None)
        .await
        .expect("T1 pinned");
    assert_eq!(sim_res.status, TestOutcomeStatus::SimulatedNativeMcp);
    assert_eq!(
        sim_res.pin_data_tool_used,
        Some(PinDataToolName::PrepareTestPinData)
    );
    assert_eq!(pin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(test_calls.load(Ordering::SeqCst), 1);
    assert_eq!(exec_calls.load(Ordering::SeqCst), 0);

    let serialized_sim = serde_json::to_string(&sim_res).expect("serialize sim_res");
    assert!(!serialized_sim.contains("LIVE_SECRET_SHOULD_REDACT_999"));
    assert_eq!(
        sim_res
            .execution_summary
            .as_ref()
            .and_then(|s| s.upstream_item_schemas.get("HTTP Fetch"))
            .and_then(|m| m.get("orderId"))
            .map(String::as_str),
        Some("number")
    );

    // 4. Bridge-less orchestrator:
    //    - Pure local transform graph -> `SimulatedOfflineDryCheck` labeled `"NOT real n8n execution"`!
    //    - Graph with pinned `HTTP Fetch` -> `BlockedOrUnsupportedSimulation` (NEVER escalates!).
    let orch_offline = TestOrchestrator::new(
        staging_instance_config("https://staging.example.internal"),
        PolicyEngine::default(),
    );

    let pure_local_wf = WorkflowIr::from_json_value(json!({
        "id": "wf_pure_local",
        "name": "Pure Transform",
        "nodes": [
            { "id": "1", "name": "Manual", "type": "n8n-nodes-base.manualTrigger" },
            { "id": "2", "name": "Edit", "type": "n8n-nodes-base.set", "parameters": {} },
            { "id": "3", "name": "Gate", "type": "n8n-nodes-base.if", "parameters": {} }
        ],
        "connections": {
            "Manual": { "main": [[{ "node": "Edit", "type": "main", "index": 0 }]] },
            "Edit": { "main": [[{ "node": "Gate", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("pure_local_wf");

    let dry_res = orch_offline
        .run_test(
            &TestRunRequest::new(TestExecutionMode::Simulate, "alice", pure_local_wf),
            None,
        )
        .await
        .expect("offline dry-check");
    assert_eq!(dry_res.status, TestOutcomeStatus::SimulatedOfflineDryCheck);
    assert!(dry_res.mode_guarantee.contains("NOT real n8n execution"));
    assert!(
        dry_res
            .warnings
            .iter()
            .any(|w| w.contains("NOT real n8n execution"))
    );

    let unsupported_without_bridge = orch_offline
        .run_test(&pinned_t1, None)
        .await
        .expect("unsupported without bridge");
    assert_eq!(
        unsupported_without_bridge.status,
        TestOutcomeStatus::BlockedOrUnsupportedSimulation
    );
    assert!(!unsupported_without_bridge.escalated_to_live_mode);

    // Also verify SafetyGate blocks `read-only` policy on T1.
    let mut ro_cfg = staging_instance_config("https://staging.example.internal");
    ro_cfg.policy_mode = PolicyMode::ReadOnly;
    let ro_decision = DeterministicTestSafetyGate::evaluate_t1(
        &ro_cfg,
        &wf_with_http,
        &HashMap::new(),
        &HashSet::from(["HTTP Fetch".to_owned()]),
        None,
    );
    assert!(!ro_decision.allowed_for_t1_simulate);
}

#[tokio::test]
async fn t2_and_t3_enforce_receipts_reject_ambiguous_triggers_pre_2_36_and_never_auto_retry() {
    let multi_trigger_wf = WorkflowIr::from_json_value(json!({
        "id": "wf_multi_trig",
        "name": "Multi Trigger Flow",
        "nodes": [
            { "id": "1", "name": "Webhook A", "type": "n8n-nodes-base.webhook", "parameters": { "path": "a" } },
            { "id": "2", "name": "Schedule B", "type": "n8n-nodes-base.scheduleTrigger", "parameters": {} },
            { "id": "3", "name": "Staging Slack", "type": "n8n-nodes-base.slack", "parameters": {} }
        ],
        "connections": {
            "Webhook A": { "main": [[{ "node": "Staging Slack", "type": "main", "index": 0 }]] },
            "Schedule B": { "main": [[{ "node": "Staging Slack", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("multi_trigger_wf");

    // 1. Legacy `< 2.36` Native MCP server WITHOUT `triggerNodeName` in `execute_workflow` schema!
    let legacy_server = MockServer::start().await;
    let legacy_exec_calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(MockNativeMcpResponder {
            tools: vec![json!({
                "name": "execute_workflow",
                "inputSchema": {
                    "type": "object",
                    "properties": { "workflowId": { "type": "string" } }
                }
            })],
            pin_calls: Arc::new(AtomicUsize::new(0)),
            test_calls: Arc::new(AtomicUsize::new(0)),
            exec_calls: Arc::clone(&legacy_exec_calls),
            fail_exec: false,
            non_terminal_exec: false,
        })
        .mount(&legacy_server)
        .await;

    let engine = PolicyEngine::new(ReceiptSigner::from_secret_seed("test_harness_seed_01"));
    let legacy_orch = TestOrchestrator::new(
        staging_instance_config(&legacy_server.uri()),
        engine.clone(),
    )
    .with_mcp_bridge(build_test_mcp_bridge(&legacy_server.uri()));

    // Missing receipt on T2 -> PolicyBlocked!
    let mut t2_req = TestRunRequest::new(
        TestExecutionMode::Manual,
        "principal_alice",
        multi_trigger_wf.clone(),
    );
    t2_req.trigger_node = Some("Webhook A".to_owned());
    assert!(matches!(
        legacy_orch.run_test(&t2_req, None).await,
        Err(N8nError::PolicyBlocked { .. })
    ));

    // Mint valid R3 receipt for `t2_req`.
    let ops_hash = t2_req.compute_ops_hash().expect("ops_hash");
    let (_rcpt, token) = engine
        .receipt_signer()
        .mint(
            &ApprovalExpectation {
                principal: "principal_alice".to_owned(),
                instance: "staging".to_owned(),
                action: TestExecutionMode::Manual.receipt_action().to_owned(),
                risk: RiskLevel::R3,
                workflow_id: Some("wf_multi_trig".to_owned()),
                expected_version_hash: Some(multi_trigger_wf.canonical_version_hash()),
                ops_hash,
            },
            300,
        )
        .expect("mint receipt");
    t2_req.approval_receipt_token = Some(token.clone());

    // Ambiguous trigger without `trigger_node` -> Validation422!
    let mut missing_trig_req = t2_req.clone();
    missing_trig_req.trigger_node = None;
    assert!(matches!(
        legacy_orch.run_test(&missing_trig_req, None).await,
        Err(N8nError::Validation422 { .. })
    ));

    // Multi-trigger with `trigger_node` on n8n < 2.36 -> UnsupportedCapability (and receipt NOT burned)!
    let pre_236_err = legacy_orch.run_test(&t2_req, None).await;
    assert!(matches!(
        pre_236_err,
        Err(N8nError::UnsupportedCapability { .. })
    ));
    assert_eq!(legacy_exec_calls.load(Ordering::SeqCst), 0);

    // 2. Modern `>= 2.36` server WITH `triggerNodeName`, configured to fail execution -> runs ONCE (0 auto-retry!),
    //    consumes single-use receipt so replay is blocked!
    let modern_server = MockServer::start().await;
    let modern_exec_calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(MockNativeMcpResponder {
            tools: vec![json!({
                "name": "execute_workflow",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workflowId": { "type": "string" },
                        "triggerNodeName": { "type": "string" }
                    }
                }
            })],
            pin_calls: Arc::new(AtomicUsize::new(0)),
            test_calls: Arc::new(AtomicUsize::new(0)),
            exec_calls: Arc::clone(&modern_exec_calls),
            fail_exec: true,
            non_terminal_exec: false,
        })
        .mount(&modern_server)
        .await;

    let modern_orch = TestOrchestrator::new(
        staging_instance_config(&modern_server.uri()),
        engine.clone(),
    )
    .with_mcp_bridge(build_test_mcp_bridge(&modern_server.uri()));

    let failed_t2 = modern_orch
        .run_test(&t2_req, None)
        .await
        .expect("T2 ran once and captured failure");
    assert_eq!(failed_t2.status, TestOutcomeStatus::ExecutionFailed);
    assert_eq!(failed_t2.attempts_made, 1);
    assert_eq!(modern_exec_calls.load(Ordering::SeqCst), 1);
    assert!(
        !serde_json::to_string(&failed_t2)
            .expect("json")
            .contains("SECRET_SLACK_TOK_12345")
    );

    // Replaying the exact same single-use receipt MUST be rejected!
    assert!(matches!(
        modern_orch.run_test(&t2_req, None).await,
        Err(N8nError::PolicyBlocked { .. })
    ));
    assert_eq!(modern_exec_calls.load(Ordering::SeqCst), 1);

    // 3. T2 Fallback via allowlisted staging test webhook URL (and blocking unallowlisted URLs).
    let wh_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webhook-test/orders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "accepted": true })))
        .expect(1)
        .mount(&wh_server)
        .await;

    let allowlisted_url = format!("{}/webhook-test/orders", wh_server.uri());
    let single_wh_wf = WorkflowIr::from_json_value(json!({
        "id": "wf_wh_only",
        "name": "Webhook Staging",
        "nodes": [
            { "id": "1", "name": "Order Hook", "type": "n8n-nodes-base.webhook", "parameters": { "path": "orders" } }
        ],
        "connections": {}
    }))
    .expect("single_wh_wf");

    let wh_orch = TestOrchestrator::new(staging_instance_config(&wh_server.uri()), engine.clone())
        .with_allowlisted_staging_webhooks([allowlisted_url.clone()]);

    let mut unallowlisted_req =
        TestRunRequest::new(TestExecutionMode::Manual, "alice", single_wh_wf.clone());
    unallowlisted_req.staging_webhook_url = Some(format!("{}/webhook-test/rogue", wh_server.uri()));
    unallowlisted_req.approval_receipt_token = Some("n8n_rcpt_v1.placeholder".to_owned());
    assert!(matches!(
        wh_orch.run_test(&unallowlisted_req, None).await,
        Err(N8nError::PolicyBlocked { .. })
    ));

    let mut wh_req = TestRunRequest::new(TestExecutionMode::Manual, "alice", single_wh_wf.clone());
    wh_req.staging_webhook_url = Some(allowlisted_url);
    wh_req.input_data = Some(json!({ "item": 1 }));
    let wh_ops_hash = wh_req.compute_ops_hash().expect("wh ops hash");
    let (_, wh_token) = engine
        .receipt_signer()
        .mint(
            &ApprovalExpectation {
                principal: "alice".to_owned(),
                instance: "staging".to_owned(),
                action: TestExecutionMode::Manual.receipt_action().to_owned(),
                risk: RiskLevel::R3,
                workflow_id: Some("wf_wh_only".to_owned()),
                expected_version_hash: Some(single_wh_wf.canonical_version_hash()),
                ops_hash: wh_ops_hash,
            },
            300,
        )
        .expect("mint wh token");
    wh_req.approval_receipt_token = Some(wh_token);

    let wh_res = wh_orch
        .run_test(&wh_req, None)
        .await
        .expect("webhook T2 ok");
    assert_eq!(wh_res.status, TestOutcomeStatus::ExecutionSucceeded);
    assert_eq!(wh_res.route_used, RouteUsed::PublicApi);

    // 4. T3 Production:
    //    - Denied under `StagingSafe` even with receipt!
    //    - Denied under `ProductionGuarded` without receipt (U09)!
    //    - Allowed under `ProductionGuarded` + R4 receipt, and `"started"` status maps to `ExecutionStartedNonTerminal`!
    let prod_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp-server/http"))
        .respond_with(MockNativeMcpResponder {
            tools: vec![json!({
                "name": "execute_workflow",
                "inputSchema": { "properties": { "triggerNodeName": { "type": "string" } } }
            })],
            pin_calls: Arc::new(AtomicUsize::new(0)),
            test_calls: Arc::new(AtomicUsize::new(0)),
            exec_calls: Arc::new(AtomicUsize::new(0)),
            fail_exec: false,
            non_terminal_exec: true,
        })
        .mount(&prod_server)
        .await;

    let t3_unconfirmed =
        TestRunRequest::new(TestExecutionMode::Production, "alice", single_wh_wf.clone());
    assert!(matches!(
        wh_orch.run_test(&t3_unconfirmed, None).await,
        Err(N8nError::PolicyBlocked { .. })
    ));

    let mut prod_cfg = staging_instance_config(&prod_server.uri());
    prod_cfg.alias = "prod".to_owned();
    prod_cfg.environment = EnvironmentKind::Production;
    prod_cfg.policy_mode = PolicyMode::ProductionGuarded;

    let mut prod_bridge_cfg = McpBridgeConfig::new(
        "prod",
        format!("{}/mcp-server/http", prod_server.uri()),
        SecretValue::new("prod_mcp_isolated_token_99"),
    );
    prod_bridge_cfg.ssrf_policy = loopback_ssrf_policy();
    let prod_bridge = NativeMcpBridge::new(prod_bridge_cfg, None).expect("prod bridge");

    let prod_orch = TestOrchestrator::new(prod_cfg, engine.clone()).with_mcp_bridge(prod_bridge);

    // U09: Unconfirmed T3 on `production-guarded` -> Blocked!
    let u09_env = prod_orch.run_test_envelope(&t3_unconfirmed, None).await;
    assert_eq!(u09_env.status, n8n_types::OperationStatus::Blocked);

    // Mint explicit R4 receipt -> succeeds, and `"started"` is honestly `ExecutionStartedNonTerminal`!
    let mut t3_approved = t3_unconfirmed.clone();
    let t3_ops_hash = t3_approved.compute_ops_hash().expect("t3 ops hash");
    let (_, t3_token) = engine
        .receipt_signer()
        .mint(
            &ApprovalExpectation {
                principal: "alice".to_owned(),
                instance: "prod".to_owned(),
                action: TestExecutionMode::Production.receipt_action().to_owned(),
                risk: RiskLevel::R4,
                workflow_id: Some("wf_wh_only".to_owned()),
                expected_version_hash: Some(single_wh_wf.canonical_version_hash()),
                ops_hash: t3_ops_hash,
            },
            300,
        )
        .expect("mint prod R4 receipt");
    t3_approved.approval_receipt_token = Some(t3_token);

    let t3_res = prod_orch.run_test(&t3_approved, None).await.expect("T3 ok");
    assert_eq!(
        t3_res.status,
        TestOutcomeStatus::ExecutionStartedNonTerminal
    );
}

// ============================================================================
// 3. Bounded Repair Loop (3 Default / 5 Max, Early Fingerprint/Confidence Halt, Zero Real Retry)
// ============================================================================

#[tokio::test]
async fn repair_loop_enforces_3_attempt_bound_early_fingerprint_halt_confidence_and_no_live_retry()
{
    // 1. Config bounds: 4 rejected without session override, 5 accepted with override, 6 rejected always!
    assert!(RepairLoopConfig::new(DEFAULT_MAX_REPAIR_ATTEMPTS, false).is_ok());
    assert!(matches!(
        RepairLoopConfig::new(4, false),
        Err(N8nError::PolicyBlocked { .. })
    ));
    assert!(RepairLoopConfig::new(ABSOLUTE_MAX_REPAIR_ATTEMPTS, true).is_ok());
    assert!(matches!(
        RepairLoopConfig::new(6, true),
        Err(N8nError::PolicyBlocked { .. })
    ));

    let base_wf = WorkflowIr::from_json_value(json!({
        "id": "wf_repair_1",
        "name": "Repair Demo",
        "nodes": [
            { "id": "1", "name": "Intake", "type": "n8n-nodes-base.manualTrigger" },
            {
                "id": "2",
                "name": "Map Order",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "parameters": {
                    "value": "={{ $json.wrongField }}"
                }
            }
        ],
        "connections": {
            "Intake": { "main": [[{ "node": "Map Order", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("base_wf");

    let make_failure = |msg: &str| {
        summarize_execution_redacted(
            &json!({
                "id": "exec_1",
                "status": "error",
                "finished": true,
                "data": {
                    "resultData": {
                        "error": {
                            "name": "ExpressionError",
                            "node": { "name": "Map Order" },
                            "message": msg
                        },
                        "runData": {
                            "Intake": [{
                                "data": { "main": [[{ "json": { "orderId": "ord_1" } }]] }
                            }]
                        }
                    }
                }
            }),
            &ExecutionMinimizeOptions::summary_only(),
        )
        .expect("summary")
    };

    // 2. Attempting `T2 Manual` inside repair loop MUST fail closed immediately!
    let live_retry_attempt = run_bounded_repair_loop(
        RepairLoopConfig::default(),
        base_wf.clone(),
        make_failure("undefined field"),
        None,
        |_ctx, _ir| {
            Ok(RepairCandidateProposal {
                confidence: RepairConfidence::High,
                rationale: "try live run".to_owned(),
                mutations: vec![GraphMutationOp::SetParams {
                    node_name: "Map Order".to_owned(),
                    pointer: "/value".to_owned(),
                    value: json!("={{ $json.orderId }}"),
                }],
                verification_mode: TestExecutionMode::Manual,
            })
        },
        |_mode, _ir| async move { unreachable!("live mode must be blocked before simulate_fn") },
    )
    .await;
    assert!(matches!(
        live_retry_attempt,
        Err(N8nError::PolicyBlocked { .. })
    ));

    // 3. Default 3-attempt bound when each attempt produces a distinct failure!
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_sim = Arc::clone(&counter);
    let orch = TestOrchestrator::new(
        staging_instance_config("https://staging.example.internal"),
        PolicyEngine::default(),
    );

    let bounded_3 = run_bounded_repair_loop(
        RepairLoopConfig::default(),
        base_wf.clone(),
        make_failure("distinct failure 0"),
        None,
        |ctx, _ir| {
            Ok(RepairCandidateProposal {
                confidence: RepairConfidence::High,
                rationale: format!("candidate patch #{}", ctx.attempt),
                mutations: vec![GraphMutationOp::SetParams {
                    node_name: "Map Order".to_owned(),
                    pointer: "/value".to_owned(),
                    value: json!(format!("={{{{ $json.try_{} }}}}", ctx.attempt)),
                }],
                verification_mode: TestExecutionMode::Simulate,
            })
        },
        move |mode, candidate_ir| {
            let _ = candidate_ir;
            let step = counter_sim.fetch_add(1, Ordering::SeqCst) + 1;
            let next_fail = make_failure(&format!("distinct failure {step}"));
            let res_stub = n8n_test_harness::TestRunResult {
                mode,
                tier: "T1".to_owned(),
                status: TestOutcomeStatus::ExecutionFailed,
                mode_guarantee: "sim".to_owned(),
                route_used: RouteUsed::NativeMcp,
                permission: n8n_types::PermissionDecision::Allowed,
                workflow_id: Some("wf_repair_1".to_owned()),
                selected_trigger: None,
                pin_data_tool_used: None,
                attempts_made: 1,
                escalated_to_live_mode: false,
                consumed_receipt_id: None,
                validation_report: None,
                native_validation_output: None,
                safety_gate: None,
                execution_summary: Some(next_fail.clone()),
                warnings: Vec::new(),
                next_actions: Vec::new(),
            };
            async move { Ok((res_stub, next_fail)) }
        },
    )
    .await
    .expect("bounded 3 completes");

    assert_eq!(bounded_3.state.status, RepairLoopStatus::Halted);
    assert_eq!(bounded_3.state.attempts_used, 3);
    assert_eq!(counter.load(Ordering::SeqCst), 3);
    assert_eq!(
        bounded_3.state.halt_reason,
        Some(RepairHaltReason::MaxAttemptsReached {
            attempts_used: 3,
            max_attempts: 3
        })
    );

    // 4. Repeated identical error fingerprint halts early after Attempt 1 (does NOT burn attempts 2 & 3)!
    let ident_out = run_bounded_repair_loop(
        RepairLoopConfig::default(),
        base_wf.clone(),
        make_failure("identical mapping error"),
        None,
        |_ctx, _ir| {
            Ok(RepairCandidateProposal {
                confidence: RepairConfidence::Medium,
                rationale: "no-op mapping tweak".to_owned(),
                mutations: vec![GraphMutationOp::SetParams {
                    node_name: "Map Order".to_owned(),
                    pointer: "/value".to_owned(),
                    value: json!("={{ $json.stillWrong }}"),
                }],
                verification_mode: TestExecutionMode::Simulate,
            })
        },
        move |mode, _ir| {
            let same_fail = make_failure("identical mapping error");
            let res_stub = n8n_test_harness::TestRunResult {
                mode,
                tier: "T1".to_owned(),
                status: TestOutcomeStatus::ExecutionFailed,
                mode_guarantee: "sim".to_owned(),
                route_used: RouteUsed::NativeMcp,
                permission: n8n_types::PermissionDecision::Allowed,
                workflow_id: Some("wf_repair_1".to_owned()),
                selected_trigger: None,
                pin_data_tool_used: None,
                attempts_made: 1,
                escalated_to_live_mode: false,
                consumed_receipt_id: None,
                validation_report: None,
                native_validation_output: None,
                safety_gate: None,
                execution_summary: Some(same_fail.clone()),
                warnings: Vec::new(),
                next_actions: Vec::new(),
            };
            async move { Ok((res_stub, same_fail)) }
        },
    )
    .await
    .expect("identical fp halt");
    assert_eq!(ident_out.state.attempts_used, 1);
    assert!(matches!(
        ident_out.state.halt_reason,
        Some(RepairHaltReason::RepeatedIdenticalErrorFingerprint { .. })
    ));

    // 5. Low confidence halts early before mutating/simulating, while High confidence resolves cleanly!
    let low_conf = run_bounded_repair_loop(
        RepairLoopConfig::default(),
        base_wf.clone(),
        make_failure("ambiguous upstream error"),
        None,
        |_ctx, _ir| {
            Ok(RepairCandidateProposal {
                confidence: RepairConfidence::Low,
                rationale: "insufficient schema evidence".to_owned(),
                mutations: vec![],
                verification_mode: TestExecutionMode::ValidateOnly,
            })
        },
        |_m, _ir| async move { unreachable!("low confidence halts before simulate") },
    )
    .await
    .expect("low confidence halt");
    assert!(matches!(
        low_conf.state.halt_reason,
        Some(RepairHaltReason::LowConfidence { .. })
    ));

    let resolved = run_bounded_repair_loop(
        RepairLoopConfig::default(),
        base_wf,
        make_failure("missing field wrongField"),
        None,
        |_ctx, _ir| {
            Ok(RepairCandidateProposal {
                confidence: RepairConfidence::High,
                rationale: "bind to Intake orderId schema field".to_owned(),
                mutations: vec![GraphMutationOp::SetParams {
                    node_name: "Map Order".to_owned(),
                    pointer: "/value".to_owned(),
                    value: json!("={{ $json.orderId }}"),
                }],
                verification_mode: TestExecutionMode::Simulate,
            })
        },
        |mode, patched_ir| {
            let orch_ref = &orch;
            async move {
                let res = orch_ref
                    .run_test(&TestRunRequest::new(mode, "alice", patched_ir), None)
                    .await?;
                let ok_summary = summarize_execution_redacted(
                    &json!({ "id": "exec_ok", "status": "success", "finished": true }),
                    &ExecutionMinimizeOptions::summary_only(),
                )?;
                Ok((res, ok_summary))
            }
        },
    )
    .await
    .expect("resolved repair loop");

    assert_eq!(resolved.state.status, RepairLoopStatus::Resolved);
    assert_eq!(
        resolved.state.attempts[0].stages_completed,
        vec![
            RepairStage::Diagnose,
            RepairStage::Inspect,
            RepairStage::PatchPreview,
            RepairStage::Validate,
            RepairStage::Simulate,
        ]
    );
    assert!(resolved.state.human_review_required_before_live_or_publish);
}

// ============================================================================
// 4. Execution Data Minimizer (`Summary` vs Gated `NodeIo` / `Full` + Redaction + 16 MiB Cap)
// ============================================================================

#[test]
fn execution_minimizer_strips_raw_values_in_summary_gates_node_io_and_enforces_16mib_cap() {
    let long_prefix = "x".repeat(500);
    let straddling_secret = concat!("sk", "-proj-STRADDLING_SECRET_KEY_1234567890ABCDEF");
    let raw_exec = json!({
        "id": "exec_900",
        "workflowId": "wf_billing",
        "status": "error",
        "finished": true,
        "startedAt": "2026-11-23T10:00:00.000Z",
        "stoppedAt": "2026-11-23T10:00:01.250Z",
        "data": {
            "resultData": {
                "error": {
                    "name": "NodeApiError",
                    "node": { "name": "Charge Stripe" },
                    "message": format!("{long_prefix} token={straddling_secret} trailing text")
                },
                "runData": {
                    "Order Intake": [{
                        "data": {
                            "main": [[{
                                "json": {
                                    "customerEmail": "sensitive.pii@customer.example",
                                    "amountCents": 19900,
                                    "vip": true,
                                    "apiKey": "SUPER_SECRET_INLINE_API_KEY_77777"
                                }
                            }]]
                        }
                    }]
                }
            }
        }
    });

    // 1. Default `Summary` outputs ONLY key->type schemas, NEVER raw payload values or straddling secrets!
    let summary =
        summarize_execution_redacted(&raw_exec, &ExecutionMinimizeOptions::summary_only())
            .expect("summary ok");
    assert_eq!(summary.duration_ms, Some(1250));
    assert_eq!(summary.failed_node.as_deref(), Some("Charge Stripe"));
    assert_eq!(summary.error_class.as_deref(), Some("NodeApiError"));
    assert!(summary.node_io.is_none());
    assert!(summary.full_data.is_none());
    assert_eq!(
        summary.upstream_item_schemas["Order Intake"]["customerEmail"],
        "string"
    );
    assert_eq!(
        summary.upstream_item_schemas["Order Intake"]["amountCents"],
        "number"
    );

    let summary_json = serde_json::to_string(&summary).expect("serialize summary");
    for forbidden in [
        "sensitive.pii@customer.example",
        "19900",
        "SUPER_SECRET_INLINE_API_KEY_77777",
        "STRADDLING_SECRET_KEY_1234567890ABCDEF",
    ] {
        assert!(
            !summary_json.contains(forbidden),
            "`Summary` leaked `{forbidden}`: {summary_json}"
        );
    }

    // 2. `NodeIo` and `Full` without `reveal_authorized = true` -> PolicyBlocked!
    let unauth_node_io = summarize_execution_redacted(
        &raw_exec,
        &ExecutionMinimizeOptions {
            detail_level: ExecutionDetailLevel::NodeIo,
            reveal_authorized: false,
            ..ExecutionMinimizeOptions::default()
        },
    );
    assert!(matches!(
        unauth_node_io,
        Err(N8nError::PolicyBlocked { .. })
    ));

    // 3. `NodeIo` blocked when `n8n_redact_execution_data == true` even if `reveal_authorized == true`!
    let n8n_redacted_block = summarize_execution_redacted(
        &raw_exec,
        &ExecutionMinimizeOptions {
            detail_level: ExecutionDetailLevel::Full,
            reveal_authorized: true,
            n8n_redact_execution_data: true,
            ..ExecutionMinimizeOptions::default()
        },
    );
    assert!(matches!(
        n8n_redacted_block,
        Err(N8nError::PolicyBlocked { .. })
    ));

    // 4. Authorized `NodeIo` & `Full` succeed AND recursively redact secrets via `n8n_types::redact_json_value`!
    let auth_io = summarize_execution_redacted(
        &raw_exec,
        &ExecutionMinimizeOptions::with_authorized_reveal(ExecutionDetailLevel::NodeIo),
    )
    .expect("authorized node_io");
    assert!(auth_io.node_io.is_some());
    let auth_io_str = serde_json::to_string(&auth_io).expect("json");
    assert!(!auth_io_str.contains("SUPER_SECRET_INLINE_API_KEY_77777"));

    // 5. Payload exceeding 16 MiB cap -> `PayloadTooLarge`!
    let oversized_string = "A".repeat(MAX_EXECUTION_PAYLOAD_BYTES + 4096);
    let huge_exec = json!({
        "id": "exec_huge",
        "status": "success",
        "finished": true,
        "data": { "blob": oversized_string }
    });
    let too_large = summarize_execution_redacted(
        &huge_exec,
        &ExecutionMinimizeOptions::with_authorized_reveal(ExecutionDetailLevel::Full),
    );
    assert!(matches!(too_large, Err(N8nError::PayloadTooLarge { .. })));
}

// ============================================================================
// 5. Crash-Recovery Cleanup Lease & Uncertain Operation Reconciliation (`wiremock`)
// ============================================================================

struct StatefulWorkflowApiMock {
    existing: Arc<std::sync::Mutex<HashMap<String, Value>>>,
    fail_delete_ids: HashSet<String>,
}

impl Respond for StatefulWorkflowApiMock {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let method_str = request.method.as_str();
        let path_str = request.url.path();
        let mut map = self
            .existing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if method_str == "POST" && path_str == "/api/v1/workflows" {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
            let wf_id = "wf_e2e_created_01".to_owned();
            let stored = json!({
                "id": wf_id,
                "name": body.get("name").and_then(Value::as_str).unwrap_or("[MCP-E2E-TEST] created"),
                "active": true,
                "isArchived": false,
                "versionId": "v1",
                "activeVersionId": "v1",
                "nodes": [],
                "connections": {},
                "settings": {}
            });
            map.insert(wf_id, stored.clone());
            return ResponseTemplate::new(200).set_body_json(stored);
        }

        if method_str == "GET" && path_str == "/api/v1/workflows" {
            let list: Vec<Value> = map.values().cloned().collect();
            return ResponseTemplate::new(200).set_body_json(json!({
                "data": list,
                "nextCursor": null
            }));
        }

        if let Some(rest) = path_str.strip_prefix("/api/v1/workflows/") {
            if let Some(wf_id) = rest.strip_suffix("/unpublish")
                && method_str == "POST"
            {
                if let Some(entry) = map.get_mut(wf_id) {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("active".to_owned(), json!(false));
                        obj.insert("activeVersionId".to_owned(), Value::Null);
                    }
                    return ResponseTemplate::new(200).set_body_json(entry.clone());
                }
                return ResponseTemplate::new(404).set_body_json(json!({ "message": "not found" }));
            }

            let wf_id = rest;
            if method_str == "GET" {
                return match map.get(wf_id) {
                    Some(w) => ResponseTemplate::new(200).set_body_json(w.clone()),
                    None => {
                        ResponseTemplate::new(404).set_body_json(json!({ "message": "not found" }))
                    }
                };
            }
            if method_str == "DELETE" {
                if self.fail_delete_ids.contains(wf_id) {
                    return ResponseTemplate::new(500)
                        .set_body_json(json!({ "message": "simulated storage lock failure" }));
                }
                return match map.remove(wf_id) {
                    Some(removed) => ResponseTemplate::new(200).set_body_json(removed),
                    None => {
                        ResponseTemplate::new(404).set_body_json(json!({ "message": "not found" }))
                    }
                };
            }
        }

        ResponseTemplate::new(404)
    }
}

#[tokio::test]
async fn reconciler_recovers_crashed_leases_verifies_404_marks_cleanup_required_and_resolves_unknown_ops()
 {
    let server = MockServer::start().await;
    let state_map = Arc::new(std::sync::Mutex::new(HashMap::from([
        // Pre-create crash orphan (no workflow_id recorded on lease yet, matched by exact `[MCP-E2E-TEST]` name)
        (
            "wf_orphan_precreate".to_owned(),
            json!({
                "id": "wf_orphan_precreate",
                "name": "[MCP-E2E-TEST] precreate-crash",
                "active": false,
                "isArchived": false,
                "versionId": "v_orphan",
                "activeVersionId": null,
                "nodes": [],
                "connections": {},
                "settings": {}
            }),
        ),
        // Lease whose DELETE will fail with HTTP 500 -> must become `CleanupRequired`!
        (
            "wf_stuck_500".to_owned(),
            json!({
                "id": "wf_stuck_500",
                "name": "[MCP-E2E-TEST] stuck-delete",
                "active": false,
                "isArchived": false,
                "versionId": "v_stuck",
                "activeVersionId": null,
                "nodes": [],
                "connections": {},
                "settings": {}
            }),
        ),
        // Normal user draft workflow whose POST timed out (`UnknownResult`) -> must be verified, NOT deleted!
        (
            "wf_user_timed_out".to_owned(),
            json!({
                "id": "wf_user_timed_out",
                "name": "Production Order Sync Draft",
                "active": false,
                "isArchived": false,
                "versionId": "v_user_1",
                "activeVersionId": null,
                "nodes": [],
                "connections": {},
                "settings": {}
            }),
        ),
    ])));

    Mock::given(path("/api/v1/workflows"))
        .respond_with(StatefulWorkflowApiMock {
            existing: Arc::clone(&state_map),
            fail_delete_ids: HashSet::new(),
        })
        .mount(&server)
        .await;

    Mock::given(wiremock::matchers::path_regex(r"^/api/v1/workflows/.+"))
        .respond_with(StatefulWorkflowApiMock {
            existing: Arc::clone(&state_map),
            fail_delete_ids: HashSet::from(["wf_stuck_500".to_owned()]),
        })
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let journal_db = tmp.path().join("journal.sqlite");
    let journal_jsonl = tmp.path().join("journal.jsonl");
    let mut journal =
        OperationJournal::open_files(&journal_db, Some(&journal_jsonl)).expect("open journal");

    let reconciler = StartupReconciler::new("staging");
    let api_client = build_test_api_client(&server.uri());

    // 1. Untagged workflow name without `[MCP-E2E-TEST]` MUST be rejected before lease write!
    assert!(matches!(
        reconciler.acquire_test_workflow_lease(
            &mut journal,
            "alice",
            "Real Billing Workflow",
            None
        ),
        Err(N8nError::PolicyBlocked { .. })
    ));

    // 2. Create leased workflow (`wf_e2e_created_01`, simulated as active on server so unpublish + delete + 404 run)
    //    and simulate process crash BEFORE `release_and_cleanup_lease`!
    let (lease_created, created_wf) = reconciler
        .create_leased_test_workflow(
            &mut journal,
            &api_client,
            "alice",
            &json!({
                "name": "[MCP-E2E-TEST] active-clone",
                "nodes": [],
                "connections": {}
            }),
            Some(60),
        )
        .await
        .expect("leased create");
    assert_eq!(created_wf.id, "wf_e2e_created_01");
    assert_eq!(
        lease_created.state,
        CleanupLeaseState::ActiveResourceCreated
    );

    // 3. Simulate pre-create crash lease (`AcquiredPreCreate` with `workflow_id == None`)!
    let lease_precreate = reconciler
        .acquire_test_workflow_lease(
            &mut journal,
            "alice",
            "[MCP-E2E-TEST] precreate-crash",
            Some(60),
        )
        .expect("precreate lease");
    assert_eq!(lease_precreate.state, CleanupLeaseState::AcquiredPreCreate);

    // 4. Simulate lease whose DELETE will return 500 -> must become `CleanupRequired`!
    let lease_stuck = reconciler
        .acquire_test_workflow_lease(
            &mut journal,
            "alice",
            "[MCP-E2E-TEST] stuck-delete",
            Some(60),
        )
        .expect("stuck lease");
    let _ = reconciler
        .bind_created_test_workflow(&mut journal, &lease_stuck.lease_id, "wf_stuck_500", None)
        .expect("bind stuck");

    // 5. Simulate `UnknownResult` journal operation for `wf_user_timed_out`!
    for st in [
        JournalState::Planned,
        JournalState::Preparing,
        JournalState::Writing,
        JournalState::UnknownResult,
    ] {
        journal
            .append_transition(JournalTransitionInput {
                operation_id: "op_timeout_user_1".to_owned(),
                next_state: st,
                principal_id: "alice".to_owned(),
                instance_id: "staging".to_owned(),
                workflow_id: Some("wf_user_timed_out".to_owned()),
                action: "workflows.create".to_owned(),
                base_version_hash: None,
                resulting_version_hash: None,
                ops_hash: None,
                details: json!({}),
            })
            .expect("append timeout");
    }

    drop(journal);

    // --- Simulate fresh process startup reading durable SQLite + JSONL journal ---
    let mut restarted_journal =
        OperationJournal::open_files(&journal_db, Some(&journal_jsonl)).expect("reopen journal");

    // Dry-run first: must NOT delete anything!
    let dry_report = reconciler
        .reconcile_startup(&mut restarted_journal, Some(&api_client), true)
        .await
        .expect("dry run");
    assert!(dry_report.summary.dry_run);
    assert_eq!(dry_report.summary.pending_leases_checked, 3);
    assert_eq!(dry_report.summary.uncertain_operations_found, 1);
    assert_eq!(dry_report.leases_cleaned, 0);

    // Live startup reconciliation!
    let live_report = reconciler
        .reconcile_startup(&mut restarted_journal, Some(&api_client), false)
        .await
        .expect("live reconcile");
    assert!(!live_report.summary.dry_run);
    assert_eq!(live_report.leases_cleaned, 2);
    assert_eq!(live_report.leases_marked_cleanup_required, 1);
    assert_eq!(live_report.uncertain_operations_resolved, 1);
    assert_eq!(live_report.uncertain_operations_remaining, 0);

    // Verify `wf_e2e_created_01` and `wf_orphan_precreate` were deleted & 404-verified,
    // `wf_stuck_500` is marked `CleanupRequired`, and `wf_user_timed_out` was preserved & marked `Verified`!
    assert!(
        live_report.lease_entries.iter().any(|e| matches!(
            e.outcome,
            LeaseCleanupOutcome::CleanedAndVerified404 { ref workflow_id } if workflow_id == "wf_e2e_created_01"
        ))
    );
    assert!(
        live_report.lease_entries.iter().any(|e| matches!(
            e.outcome,
            LeaseCleanupOutcome::CleanedAndVerified404 { ref workflow_id } if workflow_id == "wf_orphan_precreate"
        ))
    );
    assert!(live_report.lease_entries.iter().any(|e| {
        e.lease_id == lease_stuck.lease_id
            && e.final_lease_state == CleanupLeaseState::CleanupRequired
    }));
    assert!(matches!(
        live_report.operation_entries[0].outcome,
        UncertainOperationOutcome::ReconciledVerifiedPresent {
            ref workflow_id,
            ..
        } if workflow_id == "wf_user_timed_out"
    ));

    let remaining_remote = state_map.lock().expect("map lock");
    assert!(!remaining_remote.contains_key("wf_e2e_created_01"));
    assert!(!remaining_remote.contains_key("wf_orphan_precreate"));
    assert!(remaining_remote.contains_key("wf_stuck_500"));
    assert!(remaining_remote.contains_key("wf_user_timed_out"));
    drop(remaining_remote);

    // Verify BLAKE3 hash chain + JSONL mirror remain 100% tamper-free after reconciliation!
    assert!(restarted_journal.verify_hash_chain().is_ok());
}
