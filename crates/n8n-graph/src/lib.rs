#![forbid(unsafe_code)]
//! Production n8n Workflow Intermediate Representation (`WorkflowIr`), loop-aware `petgraph`
//! topology analyzer, 16 surgical graph mutation operations, and redacted RFC 6902 / semantic diff engine.

pub mod diff;
pub mod ir;
pub mod ops;
pub mod topology;

pub use diff::{
    ConnectionChangeKind, ConnectionDiffEntry, DEFAULT_DIFF_MAX_CHARS, JsonPatchOp,
    ModifiedNodeDiff, NodeDiffEntry, WorkflowDiff, compute_redacted_json_patch,
    compute_text_diff_summary, escape_json_pointer_token, query_workflow_json_path,
    unescape_json_pointer_token,
};
pub use ir::{
    ConnectionEdgeIr, NodeCredentialRef, NodeGroupIr, NodePortConnections, PortBranchList,
    PortKind, WorkflowIr, WorkflowNodeIr, canonical_blake3_json_hex,
};
pub use ops::{
    AppliedOpOutcome, DynamicReferenceHazard, ExpressionRenameCallback, GraphMutationError,
    GraphMutationOp, MutationContext, MutationPlan, RenameSafety, VersionMigrationRegistry,
    VersionMigrationTransform, WholeArrayFallback, apply_mutations, plan_mutations,
};
pub use topology::{
    CycleKind, DetectedCycle, GraphEdgeMeta, NodeOutputShape, PortAttachmentIssue, PortLineageHop,
    TopologyAnalysis, UpstreamDataShape, WorkflowGraph, WorkflowTopologySummary,
    is_ai_subnode_provider_type, is_any_trigger_type, is_canvas_annotation_type,
    is_error_trigger_type, is_loop_controller_type, is_primary_trigger_type,
};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{Value, json};

    use super::*;

    fn sample_ai_and_loop_workflow_json() -> Value {
        json!({
            "id": "wf_prod_01",
            "name": "RAG Order Triage Pipeline",
            "active": false,
            "isArchived": false,
            "versionId": "ver_draft_002",
            "activeVersionId": "ver_live_001",
            "nodes": [
                {
                    "id": "n_webhook",
                    "name": "Order Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "typeVersion": 2,
                    "position": [200, 300],
                    "parameters": {
                        "path": "orders/intake",
                        "httpMethod": "POST"
                    },
                    "webhookId": "wh_9988"
                },
                {
                    "id": "n_batches",
                    "name": "Loop Over Items",
                    "type": "n8n-nodes-base.splitInBatches",
                    "typeVersion": 3,
                    "position": [460, 300],
                    "parameters": {
                        "batchSize": 10
                    }
                },
                {
                    "id": "n_agent",
                    "name": "Triage Agent",
                    "type": "@n8n/n8n-nodes-langchain.agent",
                    "typeVersion": 1.7,
                    "position": [720, 420],
                    "parameters": {
                        "text": "={{ $('Order Webhook').item.json.body.summary }}"
                    }
                },
                {
                    "id": "n_lm",
                    "name": "OpenAI Chat",
                    "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                    "typeVersion": 1,
                    "position": [560, 640],
                    "parameters": {
                        "model": "gpt-4o-mini"
                    },
                    "credentials": {
                        "openAiApi": {
                            "id": "cred_oai_1",
                            "name": "Staging OpenAI"
                        }
                    }
                },
                {
                    "id": "n_mem",
                    "name": "Window Memory",
                    "type": "@n8n/n8n-nodes-langchain.memoryBufferWindow",
                    "typeVersion": 1.2,
                    "position": [680, 640],
                    "parameters": {}
                },
                {
                    "id": "n_parser",
                    "name": "Structured Parser",
                    "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
                    "typeVersion": 1,
                    "position": [800, 640],
                    "parameters": {}
                },
                {
                    "id": "n_tool",
                    "name": "Retriever Tool",
                    "type": "@n8n/n8n-nodes-langchain.toolVectorStore",
                    "typeVersion": 1,
                    "position": [940, 640],
                    "parameters": {}
                },
                {
                    "id": "n_retriever",
                    "name": "Vector Retriever",
                    "type": "@n8n/n8n-nodes-langchain.retrieverVectorStore",
                    "typeVersion": 1,
                    "position": [940, 820],
                    "parameters": {}
                },
                {
                    "id": "n_vstore",
                    "name": "PGVector Store",
                    "type": "@n8n/n8n-nodes-langchain.vectorStorePGVector",
                    "typeVersion": 1,
                    "position": [940, 1000],
                    "parameters": {}
                },
                {
                    "id": "n_embed",
                    "name": "OpenAI Embeddings",
                    "type": "@n8n/n8n-nodes-langchain.embeddingsOpenAi",
                    "typeVersion": 1,
                    "position": [760, 1180],
                    "parameters": {}
                },
                {
                    "id": "n_doc",
                    "name": "Default Data Loader",
                    "type": "@n8n/n8n-nodes-langchain.documentDefaultDataLoader",
                    "typeVersion": 1,
                    "position": [1100, 1180],
                    "parameters": {}
                },
                {
                    "id": "n_splitter",
                    "name": "Recursive Splitter",
                    "type": "@n8n/n8n-nodes-langchain.textSplitterRecursiveCharacterTextSplitter",
                    "typeVersion": 1,
                    "position": [1100, 1360],
                    "parameters": {}
                },
                {
                    "id": "n_done",
                    "name": "Finalize Batch",
                    "type": "n8n-nodes-base.set",
                    "typeVersion": 3.4,
                    "position": [760, 180],
                    "parameters": {
                        "assignments": {
                            "assignments": [
                                { "id": "a1", "name": "orderId", "type": "string", "value": "={{ $('Order Webhook').item.json.id }}" }
                            ]
                        }
                    }
                },
                {
                    "id": "n_err",
                    "name": "Error Alert",
                    "type": "n8n-nodes-base.slack",
                    "typeVersion": 2.2,
                    "position": [980, 420],
                    "parameters": {
                        "channel": "#ops"
                    }
                },
                {
                    "id": "n_sticky",
                    "name": "Canvas Note",
                    "type": "n8n-nodes-base.stickyNote",
                    "typeVersion": 1,
                    "position": [100, 100],
                    "parameters": {
                        "content": "## Architecture Note"
                    }
                }
            ],
            "connections": {
                "Order Webhook": {
                    "main": [
                        [
                            { "node": "Loop Over Items", "type": "main", "index": 0 }
                        ]
                    ]
                },
                "Loop Over Items": {
                    "main": [
                        [
                            { "node": "Finalize Batch", "type": "main", "index": 0 }
                        ],
                        [
                            { "node": "Triage Agent", "type": "main", "index": 0 }
                        ]
                    ]
                },
                "Triage Agent": {
                    "main": [
                        [
                            { "node": "Loop Over Items", "type": "main", "index": 0 }
                        ]
                    ],
                    "error": [
                        [
                            { "node": "Error Alert", "type": "error", "index": 0 }
                        ]
                    ]
                },
                "OpenAI Chat": {
                    "ai_languageModel": [
                        [
                            { "node": "Triage Agent", "type": "ai_languageModel", "index": 0 }
                        ]
                    ]
                },
                "Window Memory": {
                    "ai_memory": [
                        [
                            { "node": "Triage Agent", "type": "ai_memory", "index": 0 }
                        ]
                    ]
                },
                "Structured Parser": {
                    "ai_outputParser": [
                        [
                            { "node": "Triage Agent", "type": "ai_outputParser", "index": 0 }
                        ]
                    ]
                },
                "Retriever Tool": {
                    "ai_tool": [
                        [
                            { "node": "Triage Agent", "type": "ai_tool", "index": 0 }
                        ]
                    ]
                },
                "Vector Retriever": {
                    "ai_retriever": [
                        [
                            { "node": "Retriever Tool", "type": "ai_retriever", "index": 0 }
                        ]
                    ]
                },
                "PGVector Store": {
                    "ai_vectorStore": [
                        [
                            { "node": "Vector Retriever", "type": "ai_vectorStore", "index": 0 }
                        ]
                    ]
                },
                "OpenAI Embeddings": {
                    "ai_embedding": [
                        [
                            { "node": "PGVector Store", "type": "ai_embedding", "index": 0 }
                        ]
                    ]
                },
                "Default Data Loader": {
                    "ai_document": [
                        [
                            { "node": "PGVector Store", "type": "ai_document", "index": 0 }
                        ]
                    ]
                },
                "Recursive Splitter": {
                    "ai_textSplitter": [
                        [
                            { "node": "Default Data Loader", "type": "ai_textSplitter", "index": 0 }
                        ]
                    ]
                }
            },
            "pinData": {
                "Order Webhook": [
                    {
                        "json": {
                            "id": "ord_42",
                            "customerEmail": "buyer@example.com"
                        }
                    }
                ]
            },
            "nodeGroups": [
                {
                    "id": "grp_rag",
                    "name": "RAG Stack",
                    "nodeIds": ["n_agent", "n_lm", "n_mem", "n_parser"],
                    "color": "purple"
                }
            ],
            "settings": {
                "executionOrder": "v1",
                "saveManualExecutions": true
            },
            "tags": [
                { "id": "t_1", "name": "staging" }
            ],
            "meta": {
                "templateCredsSetupCompleted": true
            },
            "staticData": null,
            "customEnterpriseMetadata": {
                "ownerTeam": "fulfillment",
                "byteExact": [1, 2, 3]
            }
        })
    }

    #[test]
    fn lossless_roundtrip_and_canonical_blake3_hash() {
        let orig = sample_ai_and_loop_workflow_json();
        let ir = WorkflowIr::from_json_value(orig.clone()).expect("valid WorkflowIr");
        assert!(ir.has_unpublished_draft_changes());
        assert_eq!(ir.version_id.as_deref(), Some("ver_draft_002"));
        assert_eq!(ir.active_version_id.as_deref(), Some("ver_live_001"));

        let roundtripped = ir.to_json_value().expect("serializes back to Value");
        assert_eq!(
            roundtripped, orig,
            "WorkflowIr must roundtrip byte-for-byte"
        );

        // Reordering JSON object keys inside parameters/settings must yield the exact same canonical hash.
        let mut reordered = ir.clone();
        reordered.settings = json!({
            "saveManualExecutions": true,
            "executionOrder": "v1"
        });
        assert_eq!(
            ir.canonical_version_hash(),
            reordered.canonical_version_hash()
        );
    }

    #[test]
    fn topology_accepts_valid_loops_and_ai_subnode_trees_and_catches_invalid_graphs() {
        let ir = WorkflowIr::from_json_value(sample_ai_and_loop_workflow_json()).expect("valid ir");
        let graph = WorkflowGraph::from_ir(&ir);
        let analysis = graph.analyze();

        assert!(analysis.summary.has_cycles);
        assert!(
            !analysis.has_invalid_cycles,
            "splitInBatches loop must be classified as valid"
        );
        assert_eq!(analysis.cycles.len(), 1);
        assert_eq!(analysis.cycles[0].kind, CycleKind::ValidLoop);
        assert!(
            analysis.cycles[0]
                .controller_nodes
                .contains(&"Loop Over Items".to_owned())
        );
        assert!(
            analysis.disconnected_nodes.is_empty(),
            "all nodes including transitive AI sub-nodes must be reachable, got: {:?}",
            analysis.disconnected_nodes
        );
        assert!(
            analysis.port_issues.is_empty(),
            "unexpected port issues: {:?}",
            analysis.port_issues
        );
        assert!(!analysis.has_ambiguous_triggers);

        // Verify upstream data-shape inference extracts field types without raw values.
        let shape = graph.infer_upstream_data_shape(&ir, "Loop Over Items");
        let wh_shape = shape
            .direct_inputs
            .iter()
            .find(|s| s.source_node == "Order Webhook")
            .expect("webhook shape");
        assert_eq!(wh_shape.shape_origin, "pin_data_schema");
        assert_eq!(
            wh_shape.fields.get("customerEmail").map(String::as_str),
            Some("string")
        );

        // Now test ambiguous triggers, orphaned AI sub-node, missing LM, and unbounded cycle!
        let broken_ir = WorkflowIr::from_json_value(json!({
            "name": "Broken Topology",
            "nodes": [
                { "id": "1", "name": "Webhook A", "type": "n8n-nodes-base.webhook" },
                { "id": "2", "name": "Schedule B", "type": "n8n-nodes-base.scheduleTrigger" },
                { "id": "3", "name": "Set 1", "type": "n8n-nodes-base.set" },
                { "id": "4", "name": "Set 2", "type": "n8n-nodes-base.set" },
                { "id": "5", "name": "Orphaned Memory", "type": "@n8n/n8n-nodes-langchain.memoryBufferWindow" },
                { "id": "6", "name": "Headless Agent", "type": "@n8n/n8n-nodes-langchain.agent" }
            ],
            "connections": {
                "Webhook A": {
                    "main": [[{ "node": "Set 1", "type": "main", "index": 0 }]]
                },
                "Set 1": {
                    "main": [[{ "node": "Set 2", "type": "main", "index": 0 }]]
                },
                "Set 2": {
                    "main": [[
                        { "node": "Set 1", "type": "main", "index": 0 },
                        { "node": "Headless Agent", "type": "main", "index": 0 }
                    ]]
                }
            }
        }))
        .expect("valid broken ir");

        let broken_analysis = WorkflowGraph::from_ir(&broken_ir).analyze();
        assert!(broken_analysis.has_ambiguous_triggers);
        assert_eq!(broken_analysis.ambiguous_triggers.len(), 2);
        assert!(broken_analysis.has_invalid_cycles);
        assert!(
            broken_analysis
                .disconnected_nodes
                .contains(&"Orphaned Memory".to_owned())
        );
        assert!(broken_analysis.port_issues.iter().any(|p| matches!(
            p,
            PortAttachmentIssue::OrphanedAiSubNode { node_name, .. } if node_name == "Orphaned Memory"
        )));
        assert!(broken_analysis.port_issues.iter().any(|p| matches!(
            p,
            PortAttachmentIssue::MissingRequiredAiPort { node_name, required_port: PortKind::AiLanguageModel, .. }
            if node_name == "Headless Agent"
        )));
    }

    #[test]
    fn all_16_mutation_ops_and_safety_guards_work_end_to_end() {
        let base_ir =
            WorkflowIr::from_json_value(sample_ai_and_loop_workflow_json()).expect("valid ir");
        let ctx = MutationContext {
            allowed_credential_types: Some(HashMap::from([(
                "n8n-nodes-base.slack".to_owned(),
                vec!["slackApi".to_owned(), "slackOAuth2Api".to_owned()],
            )])),
            ..MutationContext::default()
        };

        // 1-5: SetParams (object + array fallback), UnsetParams, PatchTextField (exact + unified),
        // ConfigureReliability, BindCredential
        let ops_batch_1 = vec![
            GraphMutationOp::SetParams {
                node_name: "Order Webhook".to_owned(),
                pointer: "/options/responseCode".to_owned(),
                value: json!(202),
            },
            GraphMutationOp::SetParams {
                node_name: "Finalize Batch".to_owned(),
                pointer: "/assignments/assignments/0/value".to_owned(),
                value: json!("={{ $('Order Webhook').item.json.id + '-ok' }}"),
            },
            GraphMutationOp::UnsetParams {
                node_name: "Order Webhook".to_owned(),
                pointer: "/httpMethod".to_owned(),
            },
            GraphMutationOp::PatchTextField {
                node_name: "Canvas Note".to_owned(),
                pointer: "/content".to_owned(),
                before: "Architecture Note".to_owned(),
                after: "Updated Production Note".to_owned(),
                unified_hunk: None,
                replace_all: false,
            },
            GraphMutationOp::ConfigureReliability {
                node_name: "Error Alert".to_owned(),
                retry_on_fail: Some(true),
                max_tries: Some(3),
                wait_between_tries_ms: Some(1500),
                on_error: Some("continueRegularOutput".to_owned()),
                continue_on_fail: Some(true),
                execute_once: Some(false),
                always_output_data: Some(true),
            },
            GraphMutationOp::BindCredential {
                node_name: "Error Alert".to_owned(),
                credential_type: "slackApi".to_owned(),
                credential_id: "cred_slack_01".to_owned(),
                credential_name: "Ops Slack Bot".to_owned(),
            },
        ];

        let (ir_step1, plan1) =
            apply_mutations(&base_ir, &ops_batch_1, &ctx).expect("batch 1 succeeds");
        assert!(plan1.requires_whole_array_or_api_fallback);
        assert_eq!(
            plan1.operation_outcomes[1]
                .whole_array_fallback
                .as_ref()
                .map(|f| f.array_pointer.as_str()),
            Some("/assignments/assignments")
        );
        let err_node = ir_step1.node_by_name("Error Alert").expect("Error Alert");
        assert_eq!(err_node.retry_on_fail, Some(true));
        assert_eq!(err_node.max_tries, Some(3));
        assert_eq!(err_node.wait_between_tries, Some(1500));
        assert_eq!(err_node.always_output_data, Some(true));
        assert!(
            err_node
                .credentials
                .as_ref()
                .is_some_and(|c| c.contains_key("slackApi"))
        );

        // Non-RFC6901 dotted pointer must fail closed!
        let bad_ptr = apply_mutations(
            &ir_step1,
            &[GraphMutationOp::SetParams {
                node_name: "Order Webhook".to_owned(),
                pointer: "options.timeout".to_owned(),
                value: json!(1000),
            }],
            &ctx,
        );
        assert!(matches!(
            bad_ptr,
            Err(GraphMutationError::InvalidJsonPointer { .. })
        ));

        // Secret smuggled into BindCredential must fail closed!
        let bad_cred = apply_mutations(
            &ir_step1,
            &[GraphMutationOp::BindCredential {
                node_name: "Error Alert".to_owned(),
                credential_type: "slackApi".to_owned(),
                credential_id: "Bearer secret_live_token_123456".to_owned(),
                credential_name: "Leaked".to_owned(),
            }],
            &ctx,
        );
        assert!(matches!(
            bad_cred,
            Err(GraphMutationError::InvalidCredentialBinding { .. })
        ));

        // 6-14: AddNode, Connect, InsertNodeBetween (preserving branch 1 on Loop Over Items!),
        // RemoveNodeBridge, Rewire, Disconnect, RemoveNode, AutoLayout, SetNodeGroups
        let untouched_webhook_pos = ir_step1
            .node_by_name("Order Webhook")
            .expect("webhook")
            .position;

        let ops_batch_2 = vec![
            GraphMutationOp::AddNode {
                node: json!({
                    "id": "n_audit_log",
                    "name": "Audit Logger",
                    "type": "n8n-nodes-base.noOp",
                    "typeVersion": 1,
                    "parameters": {}
                }),
            },
            GraphMutationOp::Connect {
                from_node: "Finalize Batch".to_owned(),
                to_node: "Audit Logger".to_owned(),
                output_index: 0,
                input_index: 0,
                port_kind: PortKind::Main,
            },
            GraphMutationOp::InsertNodeBetween {
                upstream: "Loop Over Items".to_owned(),
                downstream: "Triage Agent".to_owned(),
                node: json!({
                    "id": "n_sanitize",
                    "name": "Sanitize Item",
                    "type": "n8n-nodes-base.set",
                    "typeVersion": 3.4,
                    "parameters": {}
                }),
                port_kind: Some(PortKind::Main),
                output_index: Some(1),
            },
            GraphMutationOp::AutoLayout {
                node_names: vec!["Sanitize Item".to_owned(), "Audit Logger".to_owned()],
            },
        ];

        let (ir_step2, _) =
            apply_mutations(&ir_step1, &ops_batch_2, &ctx).expect("batch 2 succeeds");
        // Untouched node coordinates MUST NOT move!
        assert_eq!(
            ir_step2
                .node_by_name("Order Webhook")
                .expect("webhook")
                .position,
            untouched_webhook_pos
        );
        // Branch 0 of Loop Over Items still targets Finalize Batch; branch 1 now targets Sanitize Item -> Triage Agent!
        let loop_branches = &ir_step2.connections["Loop Over Items"][&PortKind::Main];
        assert_eq!(loop_branches[0][0].node, "Finalize Batch");
        assert_eq!(loop_branches[1][0].node, "Sanitize Item");
        assert_eq!(
            ir_step2.connections["Sanitize Item"][&PortKind::Main][0][0].node,
            "Triage Agent"
        );

        // RemoveNodeBridge on `Sanitize Item` restores `Loop Over Items`[branch 1] -> `Triage Agent`!
        // Meanwhile RemoveNodeBridge on multi-branch `Loop Over Items` must be rejected!
        let bad_bridge = apply_mutations(
            &ir_step2,
            &[GraphMutationOp::RemoveNodeBridge {
                node_name: "Loop Over Items".to_owned(),
            }],
            &ctx,
        );
        assert!(matches!(
            bad_bridge,
            Err(GraphMutationError::BridgeArityMismatch { .. })
        ));

        let ops_batch_3 = vec![
            GraphMutationOp::RemoveNodeBridge {
                node_name: "Sanitize Item".to_owned(),
            },
            GraphMutationOp::AddNode {
                node: json!({
                    "id": "n_alt_sink",
                    "name": "Alt Sink",
                    "type": "n8n-nodes-base.noOp",
                    "typeVersion": 1,
                    "parameters": {}
                }),
            },
            GraphMutationOp::Rewire {
                from_node: "Finalize Batch".to_owned(),
                old_target: "Audit Logger".to_owned(),
                new_target: "Alt Sink".to_owned(),
                port_kind: Some(PortKind::Main),
                output_index: Some(0),
            },
            GraphMutationOp::Disconnect {
                from_node: "Finalize Batch".to_owned(),
                to_node: "Alt Sink".to_owned(),
                port_kind: Some(PortKind::Main),
                output_index: Some(0),
                input_index: Some(0),
            },
            GraphMutationOp::RemoveNode {
                node_name: "Audit Logger".to_owned(),
            },
            GraphMutationOp::RemoveNode {
                node_name: "Alt Sink".to_owned(),
            },
            GraphMutationOp::SetNodeGroups {
                groups: json!([
                    {
                        "id": "grp_core",
                        "name": "Core Intake",
                        "nodeIds": ["n_webhook", "n_batches"]
                    }
                ]),
            },
        ];

        let (ir_step3, _) =
            apply_mutations(&ir_step2, &ops_batch_3, &ctx).expect("batch 3 succeeds");
        assert_eq!(
            ir_step3.connections["Loop Over Items"][&PortKind::Main][1][0].node,
            "Triage Agent"
        );
        assert_eq!(ir_step3.node_groups.as_ref().map(Vec::len), Some(1));

        // Conflicting n8n 2.41+ group membership must fail closed!
        let bad_groups = apply_mutations(
            &ir_step3,
            &[GraphMutationOp::SetNodeGroups {
                groups: json!([
                    { "id": "g1", "name": "G1", "nodeIds": ["n_webhook"] },
                    { "id": "g2", "name": "G2", "nodeIds": ["n_webhook"] }
                ]),
            }],
            &ctx,
        );
        assert!(matches!(
            bad_groups,
            Err(GraphMutationError::InvalidNodeGroups { .. })
        ));
    }

    #[test]
    fn rename_node_rewrites_literals_and_blocks_dynamic_expressions() {
        let mut ir =
            WorkflowIr::from_json_value(sample_ai_and_loop_workflow_json()).expect("valid ir");
        // Add a plain prompt that happens to mention `$('Order Webhook')` WITHOUT leading `=` — must NOT be rewritten!
        ir.node_by_name_mut("Canvas Note")
            .expect("Canvas Note")
            .parameters = json!({
            "content": "Plain markdown mentioning $('Order Webhook') literally"
        });

        let ctx = MutationContext::default();
        let (renamed_ir, plan) = apply_mutations(
            &ir,
            &[GraphMutationOp::RenameNode {
                old_name: "Order Webhook".to_owned(),
                new_name: "Verified Intake Webhook".to_owned(),
            }],
            &ctx,
        )
        .expect("literal rename succeeds");

        assert!(renamed_ir.node_by_name("Verified Intake Webhook").is_some());
        assert!(
            renamed_ir
                .connections
                .contains_key("Verified Intake Webhook")
        );
        assert!(
            renamed_ir
                .pin_data
                .as_ref()
                .is_some_and(|p| p.contains_key("Verified Intake Webhook"))
        );
        assert_eq!(
            renamed_ir
                .node_by_name("Triage Agent")
                .expect("agent")
                .parameters["text"],
            json!("={{ $('Verified Intake Webhook').item.json.body.summary }}")
        );
        // Plain markdown note without `=` must stay untouched byte-for-byte!
        assert_eq!(
            renamed_ir
                .node_by_name("Canvas Note")
                .expect("note")
                .parameters["content"],
            json!("Plain markdown mentioning $('Order Webhook') literally")
        );
        assert!(matches!(
            plan.operation_outcomes[0].rename_safety,
            Some(RenameSafety::SafeLiteralRewrites { ref rewritten_locations }) if rewritten_locations.len() == 2
        ));

        // Now inject a dynamic expression `$('prefix_' + $json.step)` and verify rename refuses silent corruption!
        let mut dynamic_ir = renamed_ir.clone();
        dynamic_ir
            .node_by_name_mut("Triage Agent")
            .expect("agent")
            .parameters["dynamicExpr"] = json!("={{ $('prefix_' + $json.source).item.json.id }}");

        let blocked = apply_mutations(
            &dynamic_ir,
            &[GraphMutationOp::RenameNode {
                old_name: "Verified Intake Webhook".to_owned(),
                new_name: "Renamed Again".to_owned(),
            }],
            &ctx,
        );
        match blocked {
            Err(GraphMutationError::RenameManualReviewRequired { hazards, .. }) => {
                assert_eq!(hazards.len(), 1);
                assert_eq!(hazards[0].node_name, "Triage Agent");
                assert_eq!(hazards[0].parameter_pointer, "/dynamicExpr");
            }
            other => panic!("expected RenameManualReviewRequired, got {other:?}"),
        }
    }

    #[test]
    fn upgrade_node_version_requires_registered_migration_transform() {
        let ir = WorkflowIr::from_json_value(sample_ai_and_loop_workflow_json()).expect("valid ir");
        let empty_ctx = MutationContext::default();

        // Unregistered upgrade MUST fail closed with `MigrationMissing`!
        let missing = apply_mutations(
            &ir,
            &[GraphMutationOp::UpgradeNodeVersion {
                node_name: "Order Webhook".to_owned(),
                target_version: "2.1".to_owned(),
            }],
            &empty_ctx,
        );
        assert!(matches!(
            missing,
            Err(GraphMutationError::MigrationMissing {
                ref current_version,
                ref target_version,
                ..
            }) if current_version == "2" && target_version == "2.1"
        ));

        // Registering an explicit transform allows safe version migration!
        let mut reg_ctx = MutationContext::default();
        reg_ctx
            .migration_registry
            .register_fn("n8n-nodes-base.webhook", "2", "2.1", |node| {
                if let Some(obj) = node.parameters.as_object_mut() {
                    obj.insert(" migratedFromV2".trim().to_owned(), json!(true));
                }
                Ok(vec![
                    "Applied webhook 2 -> 2.1 parameter transform.".to_owned(),
                ])
            });

        let (upgraded_ir, _) = apply_mutations(
            &ir,
            &[GraphMutationOp::UpgradeNodeVersion {
                node_name: "Order Webhook".to_owned(),
                target_version: "2.1".to_owned(),
            }],
            &reg_ctx,
        )
        .expect("registered migration succeeds");

        let wh = upgraded_ir.node_by_name("Order Webhook").expect("wh");
        assert_eq!(wh.type_version, json!(2.1));
        assert_eq!(wh.parameters["migratedFromV2"], json!(true));
    }

    #[test]
    fn workflow_diff_and_rfc6902_patch_redact_sensitive_secrets() {
        let before =
            WorkflowIr::from_json_value(sample_ai_and_loop_workflow_json()).expect("valid ir");
        let raw_secret = concat!("sk", "-proj-SUPERSECRETLIVEKEY1234567890ABCDEF");
        let raw_dsn = concat!(
            "postgres://admin",
            ":UltraSecretDbPass99!@db.internal:5432/prod"
        );

        let (after, plan) = apply_mutations(
            &before,
            &[
                GraphMutationOp::SetParams {
                    node_name: "Error Alert".to_owned(),
                    pointer: "/apiKey".to_owned(),
                    value: json!(raw_secret),
                },
                GraphMutationOp::SetParams {
                    node_name: "Error Alert".to_owned(),
                    pointer: "/endpointNote".to_owned(),
                    value: json!(format!("Connects to {raw_dsn}")),
                },
            ],
            &MutationContext::default(),
        )
        .expect("mutations succeed");

        let serialized_diff = serde_json::to_string(&plan.workflow_diff).expect("diff serializes");
        assert!(
            !serialized_diff.contains(raw_secret),
            "raw API key leaked in WorkflowDiff: {serialized_diff}"
        );
        assert!(
            !serialized_diff.contains("UltraSecretDbPass99!"),
            "raw DSN password leaked in WorkflowDiff: {serialized_diff}"
        );
        assert!(
            plan.workflow_diff
                .risk_flags
                .contains(&"SIDE_EFFECT_NODE_ADDED_OR_MODIFIED".to_owned())
        );
        assert_eq!(
            after.node_by_name("Error Alert").expect("node").parameters["apiKey"],
            json!(raw_secret)
        );
    }

    #[test]
    fn polling_retry_loop_is_valid_while_ai_port_cycle_is_rejected() {
        let polling_ir = WorkflowIr::from_json_value(json!({
            "name": "Polling Retry Loop",
            "nodes": [
                { "id": "1", "name": "Manual Trigger", "type": "n8n-nodes-base.manualTrigger" },
                { "id": "2", "name": "Poll Job", "type": "n8n-nodes-base.httpRequest" },
                { "id": "3", "name": "Is Ready?", "type": "n8n-nodes-base.if" },
                { "id": "4", "name": "Backoff Wait", "type": "n8n-nodes-base.wait" },
                { "id": "5", "name": "Done", "type": "n8n-nodes-base.noOp" }
            ],
            "connections": {
                "Manual Trigger": { "main": [[{ "node": "Poll Job", "type": "main", "index": 0 }]] },
                "Poll Job": { "main": [[{ "node": "Is Ready?", "type": "main", "index": 0 }]] },
                "Is Ready?": {
                    "main": [
                        [{ "node": "Done", "type": "main", "index": 0 }],
                        [{ "node": "Backoff Wait", "type": "main", "index": 0 }]
                    ]
                },
                "Backoff Wait": { "main": [[{ "node": "Poll Job", "type": "main", "index": 0 }]] }
            }
        }))
        .expect("valid polling ir");

        let polling_graph = WorkflowGraph::from_ir(&polling_ir);
        let analysis = polling_graph.analyze();
        assert!(analysis.summary.has_cycles);
        assert!(!analysis.has_invalid_cycles);
        assert_eq!(analysis.cycles[0].kind, CycleKind::ValidLoop);
        assert!(!polling_graph.upstream_lineage("Done").is_empty());
        assert!(
            !polling_graph
                .downstream_lineage("Manual Trigger")
                .is_empty()
        );

        let ai_cycle_ir = WorkflowIr::from_json_value(json!({
            "name": "AI Cycle",
            "nodes": [
                { "id": "1", "name": "Agent A", "type": "@n8n/n8n-nodes-langchain.agent" },
                { "id": "2", "name": "Agent B", "type": "@n8n/n8n-nodes-langchain.agent" }
            ],
            "connections": {
                "Agent A": { "ai_tool": [[{ "node": "Agent B", "type": "ai_tool", "index": 0 }]] },
                "Agent B": { "ai_tool": [[{ "node": "Agent A", "type": "ai_tool", "index": 0 }]] }
            }
        }))
        .expect("ai cycle ir");

        let ai_analysis = WorkflowGraph::from_ir(&ai_cycle_ir).analyze();
        assert!(ai_analysis.has_invalid_cycles);
    }

    #[test]
    fn unified_hunk_patch_and_ambiguous_patch_guards() {
        let ir = WorkflowIr::from_json_value(json!({
            "name": "Code Patch",
            "nodes": [{
                "id": "c1",
                "name": "Transform",
                "type": "n8n-nodes-base.code",
                "parameters": {
                    "jsCode": "const x = 1;\nconst y = 2;\nconst dup = 'same';\nconst dup2 = 'same';\nreturn [{ json: { x, y } }];"
                }
            }],
            "connections": {}
        }))
        .expect("ir");

        // Ambiguous exact hunk with `replace_all: false` must fail closed!
        let ambig = apply_mutations(
            &ir,
            &[GraphMutationOp::PatchTextField {
                node_name: "Transform".to_owned(),
                pointer: "/jsCode".to_owned(),
                before: "'same'".to_owned(),
                after: "'updated'".to_owned(),
                unified_hunk: None,
                replace_all: false,
            }],
            &MutationContext::default(),
        );
        assert!(matches!(
            ambig,
            Err(GraphMutationError::TextPatchFailed { .. })
        ));

        // Unified hunk patch succeeds cleanly!
        let (patched, _) = apply_mutations(
            &ir,
            &[GraphMutationOp::PatchTextField {
                node_name: "Transform".to_owned(),
                pointer: "/jsCode".to_owned(),
                before: String::new(),
                after: String::new(),
                unified_hunk: Some(
                    "@@ -1,3 +1,3 @@\n const x = 1;\n-const y = 2;\n+const y = 42;\n const dup = 'same';"
                        .to_owned(),
                ),
                replace_all: false,
            }],
            &MutationContext::default(),
        )
        .expect("unified hunk succeeds");
        assert!(
            patched.node_by_name("Transform").expect("node").parameters["jsCode"]
                .as_str()
                .unwrap_or("")
                .contains("const y = 42;")
        );
    }

    #[test]
    fn rename_node_handles_jscode_comments_templates_and_custom_hooks() {
        let ir = WorkflowIr::from_json_value(json!({
            "name": "Code Refs",
            "nodes": [
                { "id": "1", "name": "Source Step", "type": "n8n-nodes-base.manualTrigger" },
                {
                    "id": "2",
                    "name": "Worker Code",
                    "type": "n8n-nodes-base.code",
                    "parameters": {
                        "jsCode": "// Comment with $(dynamicComment)\nconst literal = \"hello $(not_a_node)\";\nconst a = $('Source Step').first().json.id;\nconst b = $node[\"Source Step\"].json.val;\nconst c = $items('Source Step', 0, 1);\nconst msg = `id=${$('Source Step').item.json.id}`;\nreturn [{ json: { a, b, c, msg } }];"
                    }
                }
            ],
            "connections": {
                "Source Step": { "main": [[{ "node": "Worker Code", "type": "main", "index": 0 }]] }
            }
        }))
        .expect("ir");

        let (renamed, _) = apply_mutations(
            &ir,
            &[GraphMutationOp::RenameNode {
                old_name: "Source Step".to_owned(),
                new_name: "Clean Trigger".to_owned(),
            }],
            &MutationContext::default(),
        )
        .expect("jscode literal rename");

        let js = renamed
            .node_by_name("Worker Code")
            .expect("worker")
            .parameters["jsCode"]
            .as_str()
            .unwrap_or("");
        assert!(js.contains("// Comment with $(dynamicComment)"));
        assert!(js.contains("\"hello $(not_a_node)\""));
        assert!(js.contains("$('Clean Trigger').first()"));
        assert!(js.contains("$node[\"Clean Trigger\"].json.val"));
        assert!(js.contains("$items('Clean Trigger', 0, 1)"));
        assert!(js.contains("`id=${$('Clean Trigger').item.json.id}`"));
    }

    #[test]
    fn legacy_null_branches_and_remove_node_cleanup_invariants() {
        let ir = WorkflowIr::from_json_value(json!({
            "name": "Legacy Branches",
            "nodes": [
                { "id": "id_if", "name": "IF Gate", "type": "n8n-nodes-base.if" },
                { "id": "id_t", "name": "True Sink", "type": "n8n-nodes-base.noOp" },
                { "id": "id_f", "name": "False Sink", "type": "n8n-nodes-base.noOp" }
            ],
            "connections": {
                "IF Gate": {
                    "main": [
                        [{ "node": "True Sink", "type": "main", "index": 0 }],
                        [{ "node": "False Sink", "type": "main", "index": 0 }]
                    ]
                }
            },
            "pinData": {
                "True Sink": [{ "json": { "ok": true } }]
            },
            "nodeGroups": [
                { "id": "g_solo", "name": "Solo", "nodeIds": ["id_t"] },
                { "id": "g_pair", "name": "Pair", "nodeIds": ["id_if", "id_t"] }
            ]
        }))
        .expect("ir");

        let (cleaned, _) = apply_mutations(
            &ir,
            &[GraphMutationOp::RemoveNode {
                node_name: "True Sink".to_owned(),
            }],
            &MutationContext::default(),
        )
        .expect("remove True Sink");

        // Branch 0 must stay as empty `[]` so `False Sink` remains on branch 1!
        let branches = &cleaned.connections["IF Gate"][&PortKind::Main];
        assert!(branches[0].is_empty());
        assert_eq!(branches[1][0].node, "False Sink");
        assert!(
            cleaned
                .pin_data
                .as_ref()
                .is_none_or(|p| !p.contains_key("True Sink"))
        );
        let groups = cleaned.node_groups.as_ref().expect("groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, "g_pair");
        assert_eq!(groups[0].node_ids, vec!["id_if"]);

        // Also verify legacy `null` branch array slot deserializes cleanly!
        let legacy_null = WorkflowIr::from_json_value(json!({
            "name": "Null Slot",
            "nodes": [
                { "id": "1", "name": "IF", "type": "n8n-nodes-base.if" },
                { "id": "2", "name": "B", "type": "n8n-nodes-base.noOp" }
            ],
            "connections": {
                "IF": {
                    "main": [null, [{ "node": "B", "type": "main", "index": 0 }]]
                }
            }
        }))
        .expect("null branch slot parses cleanly");
        assert!(legacy_null.connections["IF"][&PortKind::Main][0].is_empty());
        assert_eq!(
            legacy_null.connections["IF"][&PortKind::Main][1][0].node,
            "B"
        );
    }

    #[test]
    fn all_nine_ai_port_wire_strings_and_rename_hooks_roundtrip() {
        use std::sync::Arc;

        let wire_ports = [
            (PortKind::Main, "main", false),
            (PortKind::Error, "error", false),
            (PortKind::AiLanguageModel, "ai_languageModel", true),
            (PortKind::AiTool, "ai_tool", true),
            (PortKind::AiMemory, "ai_memory", true),
            (PortKind::AiOutputParser, "ai_outputParser", true),
            (PortKind::AiRetriever, "ai_retriever", true),
            (PortKind::AiVectorStore, "ai_vectorStore", true),
            (PortKind::AiDocument, "ai_document", true),
            (PortKind::AiEmbedding, "ai_embedding", true),
            (PortKind::AiTextSplitter, "ai_textSplitter", true),
        ];

        for (kind, expected_wire, is_ai) in wire_ports {
            assert_eq!(kind.as_wire(), expected_wire);
            assert_eq!(PortKind::from_wire(expected_wire), kind);
            assert_eq!(kind.is_ai_subnode_port(), is_ai);
            let encoded = serde_json::to_value(&kind).expect("encode PortKind");
            assert_eq!(encoded, json!(expected_wire));
            let decoded: PortKind = serde_json::from_value(encoded).expect("decode PortKind");
            assert_eq!(decoded, kind);
        }

        // Exercise `expression_rewrite_map` + `custom_rename_hook` on RenameNode.
        let ir = WorkflowIr::from_json_value(json!({
            "name": "Hooked Rename",
            "nodes": [
                { "id": "1", "name": "OldStep", "type": "n8n-nodes-base.manualTrigger" },
                {
                    "id": "2",
                    "name": "Consumer",
                    "type": "n8n-nodes-base.set",
                    "parameters": {
                        "mappedField": "={{ $('prefix_' + $json.dynamic).item.json.id }}",
                        "hookedField": "={{ CUSTOM_REF('OldStep') }}"
                    }
                }
            ],
            "connections": {
                "OldStep": { "main": [[{ "node": "Consumer", "type": "main", "index": 0 }]] }
            }
        }))
        .expect("ir");

        let mut ctx = MutationContext::default();
        ctx.expression_rewrite_map.insert(
            ("Consumer".to_owned(), "/mappedField".to_owned()),
            "={{ $('NewStep').item.json.id }}".to_owned(),
        );
        ctx.custom_rename_hook = Some(Arc::new(|_holder, _ptr, expr, old_name, new_name| {
            let needle = format!("CUSTOM_REF('{old_name}')");
            if expr.contains(&needle) {
                Ok(Some(
                    expr.replace(&needle, &format!("CUSTOM_REF('{new_name}')")),
                ))
            } else {
                Ok(None)
            }
        }));

        let (renamed, _) = apply_mutations(
            &ir,
            &[GraphMutationOp::RenameNode {
                old_name: "OldStep".to_owned(),
                new_name: "NewStep".to_owned(),
            }],
            &ctx,
        )
        .expect("rewrite map + custom hook succeed");

        let consumer = renamed.node_by_name("Consumer").expect("Consumer");
        assert_eq!(
            consumer.parameters["mappedField"],
            json!("={{ $('NewStep').item.json.id }}")
        );
        assert_eq!(
            consumer.parameters["hookedField"],
            json!("={{ CUSTOM_REF('NewStep') }}")
        );
    }
}
