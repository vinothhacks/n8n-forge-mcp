//! Full Equivalence Gate + Validator Test Suite for `n8n-validator`.
//!
//! Loads `../../tests/equivalence/cases.jsonl` and `../../data/catalog.sqlite.zst` and verifies
//! 100% pass across:
//! - `expression_refs` (71 cases)
//! - `node_validation` (75 cases)
//! - `graph_topology` (65 cases)
//! - `workflow_diff` (60 cases)
//!
//! Plus `display_options` (85 cases via `CatalogDb`) = 356/356 total equivalence cases, alongside
//! targeted AST, cross-graph reachability, and byte-accurate literal rewrite tests.

use std::fs;
use std::path::PathBuf;

use n8n_catalog_db::{CatalogDb, DisplayEvalContext, evaluate_display_options};
use n8n_graph::{RenameSafety, WorkflowIr};
use n8n_validator::{
    ExpressionError, ExpressionRenameMode, MutationApplyStatus, ReferenceKind, ValidatedMutationOp,
    ValidationOptions, ValidationProfile, ValidationStrength, analyze_plain_or_template_expression,
    analyze_template_expression, apply_validated_mutation, evaluate_parameter_expression,
    extract_expression_blocks, rewrite_literal_node_references, validate_node_json,
    validate_workflow, validate_workflow_skeleton, validate_workflow_topology_json,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct RawEquivalenceCase {
    id: String,
    category: String,
    description: String,
    input: Value,
    expected: Value,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn load_all_cases() -> Vec<RawEquivalenceCase> {
    let path = workspace_root()
        .join("tests")
        .join("equivalence")
        .join("cases.jsonl");
    let raw = fs::read_to_string(&path).expect("read tests/equivalence/cases.jsonl");
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<RawEquivalenceCase>(line).expect("parse JSONL case"))
        .collect()
}

fn open_bundled_catalog() -> CatalogDb {
    let root = workspace_root();
    let zst_path = root.join("data").join("catalog.sqlite.zst");
    let manifest_path = root.join("data").join("catalog.manifest.json");
    CatalogDb::open_from_zst_path(&zst_path, Some(&manifest_path))
        .expect("open bundled catalog.sqlite.zst")
}

#[test]
fn equivalence_gate_all_356_cases_pass() {
    let cases = load_all_cases();
    let catalog = open_bundled_catalog();

    let mut count_display_options = 0usize;
    let mut count_expression_refs = 0usize;
    let mut count_node_validation = 0usize;
    let mut count_graph_topology = 0usize;
    let mut count_workflow_diff = 0usize;

    for case in &cases {
        match case.category.as_str() {
            "display_options" => {
                count_display_options += 1;
                let empty_map = serde_json::Map::new();
                let params = case.input["parameters"].as_object().unwrap_or(&empty_map);
                let defaults = case.input["propertyDefaults"]
                    .as_object()
                    .unwrap_or(&empty_map);
                let node_ctx = case.input["nodeContext"].as_object().unwrap_or(&empty_map);
                let disp_opt = case.input.get("displayOptions");
                let parent_disp_opt = case.input.get("parentDisplayOptions");

                let ctx = DisplayEvalContext::new(params, defaults, node_ctx);
                let actual_visible = evaluate_display_options(disp_opt, parent_disp_opt, &ctx);
                let expected_visible = case.expected["visible"].as_bool().expect("visible");

                assert_eq!(
                    actual_visible, expected_visible,
                    "display_options visible mismatch on {} ({})",
                    case.id, case.description
                );
            }
            "expression_refs" => {
                count_expression_refs += 1;
                let value = case.input["value"].as_str().expect("input.value");
                let rename_pair = case
                    .input
                    .get("renameRequest")
                    .and_then(Value::as_object)
                    .map(|obj| {
                        (
                            obj["from"].as_str().expect("from"),
                            obj["to"].as_str().expect("to"),
                        )
                    });

                let eval = evaluate_parameter_expression(value, rename_pair);

                let exp_is_expr = case.expected["isExpression"]
                    .as_bool()
                    .expect("isExpression");
                let exp_valid = case.expected["validSyntax"].as_bool().expect("validSyntax");
                let exp_blocks: Vec<String> = case.expected["expressionBlocks"]
                    .as_array()
                    .expect("expressionBlocks")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                let exp_refs: Vec<String> = case.expected["referencedNodes"]
                    .as_array()
                    .expect("referencedNodes")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                let exp_code_warn = case.expected["codeLikeExpressionWarning"]
                    .as_bool()
                    .expect("codeLikeExpressionWarning");
                let exp_rename_mode = case.expected["renameMode"].as_str().expect("renameMode");
                let exp_rewritten = case.expected["rewrittenValue"].as_str();

                assert_eq!(
                    eval.analysis.is_expression, exp_is_expr,
                    "{} ({}) isExpression",
                    case.id, case.description
                );
                assert_eq!(
                    eval.analysis.valid_syntax, exp_valid,
                    "{} ({}) validSyntax (diagnostics: {:?})",
                    case.id, case.description, eval.analysis.diagnostics
                );
                assert_eq!(
                    eval.analysis.expression_blocks, exp_blocks,
                    "{} ({}) expressionBlocks",
                    case.id, case.description
                );
                assert_eq!(
                    eval.analysis.referenced_nodes, exp_refs,
                    "{} ({}) referencedNodes",
                    case.id, case.description
                );
                assert_eq!(
                    eval.analysis.code_like_expression_warning, exp_code_warn,
                    "{} ({}) codeLikeExpressionWarning",
                    case.id, case.description
                );

                let actual_mode = match eval.rename_mode {
                    ExpressionRenameMode::NotApplicable => "not_applicable",
                    ExpressionRenameMode::SafeLiteral => "safe_literal",
                    ExpressionRenameMode::ManualReviewRequired => "manual_review_required",
                };
                assert_eq!(
                    actual_mode, exp_rename_mode,
                    "{} ({}) renameMode",
                    case.id, case.description
                );
                assert_eq!(
                    eval.rewritten_value.as_deref(),
                    exp_rewritten,
                    "{} ({}) rewrittenValue",
                    case.id,
                    case.description
                );
            }
            "node_validation" => {
                count_node_validation += 1;
                let node_val = &case.input["node"];
                let report = validate_node_json(node_val, &catalog, ValidationProfile::AiFriendly)
                    .unwrap_or_else(|e| panic!("{} ({}): {e}", case.id, case.description));

                let exp_valid = case.expected["valid"].as_bool().expect("valid");
                let exp_conf = case.expected["validationConfidence"]
                    .as_str()
                    .expect("validationConfidence");
                let exp_errors: Vec<String> = case.expected["errorCodes"]
                    .as_array()
                    .expect("errorCodes")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                let exp_warnings: Vec<String> = case.expected["warningCodes"]
                    .as_array()
                    .expect("warningCodes")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();

                assert_eq!(
                    report.valid, exp_valid,
                    "{} ({}) valid; actual errors={:?}, warnings={:?}",
                    case.id, case.description, report.error_codes, report.warning_codes
                );
                assert_eq!(
                    report.validation_confidence, exp_conf,
                    "{} ({}) validationConfidence",
                    case.id, case.description
                );
                assert_eq!(
                    report.error_codes, exp_errors,
                    "{} ({}) errorCodes",
                    case.id, case.description
                );
                assert_eq!(
                    report.warning_codes, exp_warnings,
                    "{} ({}) warningCodes",
                    case.id, case.description
                );
            }
            "graph_topology" => {
                count_graph_topology += 1;
                let wf_val = &case.input["workflow"];
                let report = validate_workflow_topology_json(wf_val, Some(&catalog));

                let exp_valid = case.expected["valid"].as_bool().expect("valid");
                let exp_node_count =
                    case.expected["nodeCount"].as_u64().expect("nodeCount") as usize;
                let exp_has_cycles = case.expected["hasCycles"].as_bool().expect("hasCycles");
                let exp_controlled = case.expected["isControlledLoop"]
                    .as_bool()
                    .expect("isControlledLoop");
                let exp_errors: Vec<String> = case.expected["errorCodes"]
                    .as_array()
                    .expect("errorCodes")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                let exp_warnings: Vec<String> = case.expected["warningCodes"]
                    .as_array()
                    .expect("warningCodes")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();

                assert_eq!(
                    report.valid, exp_valid,
                    "{} ({}) valid; errors={:?}, warnings={:?}",
                    case.id, case.description, report.error_codes, report.warning_codes
                );
                assert_eq!(
                    report.node_count, exp_node_count,
                    "{} ({}) nodeCount",
                    case.id, case.description
                );
                assert_eq!(
                    report.has_cycles, exp_has_cycles,
                    "{} ({}) hasCycles",
                    case.id, case.description
                );
                assert_eq!(
                    report.is_controlled_loop, exp_controlled,
                    "{} ({}) isControlledLoop",
                    case.id, case.description
                );
                assert_eq!(
                    report.error_codes, exp_errors,
                    "{} ({}) errorCodes",
                    case.id, case.description
                );
                assert_eq!(
                    report.warning_codes, exp_warnings,
                    "{} ({}) warningCodes",
                    case.id, case.description
                );
            }
            "workflow_diff" => {
                count_workflow_diff += 1;
                let wf_ir = WorkflowIr::from_json_value(case.input["workflow"].clone())
                    .unwrap_or_else(|e| panic!("{} wf parse: {e}", case.id));
                let mutation: ValidatedMutationOp =
                    serde_json::from_value(case.input["mutation"].clone())
                        .unwrap_or_else(|e| panic!("{} mutation parse: {e}", case.id));

                let outcome = apply_validated_mutation(&wf_ir, &mutation, Some(&catalog));

                let exp_status = case.expected["status"].as_str().expect("status");
                let actual_status = match outcome.status {
                    MutationApplyStatus::Applied => "applied",
                    MutationApplyStatus::Rejected => "rejected",
                    MutationApplyStatus::ManualReviewRequired => "manual_review_required",
                };
                assert_eq!(
                    actual_status, exp_status,
                    "{} ({}) status (err={:?}, msg={:?})",
                    case.id, case.description, outcome.error_code, outcome.message
                );

                let exp_changed = case.expected["changed"].as_bool().expect("changed");
                assert_eq!(
                    outcome.changed, exp_changed,
                    "{} ({}) changed",
                    case.id, case.description
                );

                if let Some(exp_err) = case.expected.get("errorCode").and_then(Value::as_str) {
                    assert_eq!(
                        outcome.error_code.as_deref(),
                        Some(exp_err),
                        "{} ({}) errorCode",
                        case.id,
                        case.description
                    );
                }
                if let Some(exp_resolved) = case.expected.get("resolvedValue") {
                    assert_eq!(
                        outcome.resolved_value.as_ref(),
                        Some(exp_resolved),
                        "{} ({}) resolvedValue",
                        case.id,
                        case.description
                    );
                }
                if let Some(exp_removed) = case.expected.get("removed").and_then(Value::as_bool) {
                    assert_eq!(
                        outcome.removed,
                        Some(exp_removed),
                        "{} ({}) removed",
                        case.id,
                        case.description
                    );
                }
                if let Some(exp_pos) = case.expected.get("position").and_then(Value::as_array) {
                    let expected_xy = [
                        exp_pos[0].as_f64().expect("x"),
                        exp_pos[1].as_f64().expect("y"),
                    ];
                    assert_eq!(
                        outcome.position,
                        Some(expected_xy),
                        "{} ({}) position",
                        case.id,
                        case.description
                    );
                }
                if let Some(exp_dis) = case.expected.get("disabled").and_then(Value::as_bool) {
                    assert_eq!(
                        outcome.disabled,
                        Some(exp_dis),
                        "{} ({}) disabled",
                        case.id,
                        case.description
                    );
                }
                if let Some(exp_conn_renamed) = case
                    .expected
                    .get("connectionKeysRenamed")
                    .and_then(Value::as_array)
                {
                    let expected_keys: Vec<String> = exp_conn_renamed
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect();
                    assert_eq!(
                        outcome.connection_keys_renamed, expected_keys,
                        "{} ({}) connectionKeysRenamed",
                        case.id, case.description
                    );
                }
                if let Some(exp_rewritten) = case
                    .expected
                    .get("rewrittenExpressions")
                    .and_then(Value::as_array)
                {
                    assert_eq!(
                        outcome.rewritten_expressions.len(),
                        exp_rewritten.len(),
                        "{} ({}) rewrittenExpressions len",
                        case.id,
                        case.description
                    );
                    for (actual_entry, exp_entry) in
                        outcome.rewritten_expressions.iter().zip(exp_rewritten)
                    {
                        assert_eq!(actual_entry.node, exp_entry["node"].as_str().unwrap());
                        assert_eq!(actual_entry.pointer, exp_entry["pointer"].as_str().unwrap());
                        assert_eq!(actual_entry.after, exp_entry["after"].as_str().unwrap());
                    }
                }
                if let Some(exp_count) = case.expected.get("rewrittenCount").and_then(Value::as_u64)
                {
                    assert_eq!(
                        outcome.rewritten_count, exp_count as usize,
                        "{} ({}) rewrittenCount",
                        case.id, case.description
                    );
                }
                if let Some(exp_blocking) = case
                    .expected
                    .get("blockingExpressions")
                    .and_then(Value::as_array)
                {
                    assert_eq!(
                        outcome.blocking_expressions.len(),
                        exp_blocking.len(),
                        "{} ({}) blockingExpressions len",
                        case.id,
                        case.description
                    );
                    for (actual_b, exp_b) in outcome.blocking_expressions.iter().zip(exp_blocking) {
                        assert_eq!(actual_b.node, exp_b["node"].as_str().unwrap());
                        assert_eq!(actual_b.pointer, exp_b["pointer"].as_str().unwrap());
                    }
                }
                if let Some(exp_added_edges) =
                    case.expected.get("addedEdges").and_then(Value::as_array)
                {
                    let expected: Vec<String> = exp_added_edges
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect();
                    assert_eq!(
                        outcome.added_edges, expected,
                        "{} ({}) addedEdges",
                        case.id, case.description
                    );
                }
                if let Some(exp_removed_edges) =
                    case.expected.get("removedEdges").and_then(Value::as_array)
                {
                    let expected: Vec<String> = exp_removed_edges
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect();
                    assert_eq!(
                        outcome.removed_edges, expected,
                        "{} ({}) removedEdges",
                        case.id, case.description
                    );
                }
            }
            other => panic!("Unexpected equivalence category `{other}` on {}", case.id),
        }
    }

    assert_eq!(count_display_options, 85, "display_options case count");
    assert_eq!(count_expression_refs, 71, "expression_refs case count");
    assert_eq!(count_node_validation, 75, "node_validation case count");
    assert_eq!(count_graph_topology, 65, "graph_topology case count");
    assert_eq!(count_workflow_diff, 60, "workflow_diff case count");
    assert_eq!(
        count_display_options
            + count_expression_refs
            + count_node_validation
            + count_graph_topology
            + count_workflow_diff,
        356,
        "total equivalence cases must equal 356"
    );
}

#[test]
fn ast_extracts_all_builtin_vars_and_preserves_bytes_on_plain_and_template_rewrites() {
    let plain = "$('Fetch Order').item.json.total + $json.tax + $env.REGION + $vars.CURRENCY + $now.toISO() + $today + $itemIndex + $runIndex + $execution.id + $workflow.name + $input.first().json.x + $binary.data";
    let analysis = analyze_plain_or_template_expression(plain);
    assert!(analysis.valid_syntax);
    assert_eq!(analysis.referenced_nodes, vec!["Fetch Order"]);
    assert!(matches!(
        analysis.rename_safety,
        RenameSafety::SafeLiteralRewrites { .. }
    ));
    for expected_builtin in [
        "$json",
        "$env",
        "$vars",
        "$now",
        "$today",
        "$itemIndex",
        "$runIndex",
        "$execution",
        "$workflow",
        "$input",
        "$binary",
    ] {
        assert!(
            analysis.builtin_vars.iter().any(|b| b == expected_builtin),
            "missing builtin {expected_builtin}"
        );
    }

    let template = "Order /* keep comment 'Fetch Order' */ {{ $('Fetch Order').item.json.id }} / {{ $node[\"Fetch Order\"].json.code }}!";
    let prefixed = format!("={template}");
    let rewritten =
        rewrite_literal_node_references(&prefixed, "Fetch Order", "Load Order V2").unwrap();
    assert!(rewritten.changed);
    assert_eq!(rewritten.replaced_count, 2);
    assert_eq!(
        rewritten.rewritten,
        "=Order /* keep comment 'Fetch Order' */ {{ $('Load Order V2').item.json.id }} / {{ $node[\"Load Order V2\"].json.code }}!"
    );

    // Dynamic reference must fail closed with DynamicReferenceManualReview.
    let dyn_expr = "={{ $('Prefix_' + $json.env).item.json.id }}";
    let dyn_analysis = analyze_template_expression(dyn_expr);
    assert!(matches!(
        dyn_analysis.rename_safety,
        RenameSafety::ManualReviewRequired { .. }
    ));
    assert!(matches!(
        &dyn_analysis.references[0].kind,
        ReferenceKind::DynamicNodeRef { .. }
    ));
    let err = rewrite_literal_node_references(dyn_expr, "Prefix_prod", "New").unwrap_err();
    assert!(matches!(
        err,
        ExpressionError::DynamicReferenceManualReview { .. }
    ));
}

#[test]
fn full_validate_workflow_catches_unreachable_and_missing_expression_targets() {
    let catalog = open_bundled_catalog();
    let wf_json = json!({
        "name": "Cross-Graph Reachability Check",
        "nodes": [
            {
                "id": "1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [0, 0],
                "parameters": {
                    "httpMethod": "POST",
                    "path": "ingest"
                }
            },
            {
                "id": "2",
                "name": "Step A",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "position": [220, 0],
                "parameters": {
                    "mode": "manual",
                    "badDownstreamRef": "={{ $('Step B').item.json.later }}",
                    "ghostRef": "={{ $('Does Not Exist').item.json.x }}"
                }
            },
            {
                "id": "3",
                "name": "Step B",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "position": [440, 0],
                "parameters": {
                    "mode": "manual",
                    "goodUpstreamRef": "={{ $('Webhook').item.json.body.id }}"
                }
            }
        ],
        "connections": {
            "Webhook": {
                "main": [[{ "node": "Step A", "type": "main", "index": 0 }]]
            },
            "Step A": {
                "main": [[{ "node": "Step B", "type": "main", "index": 0 }]]
            }
        }
    });

    let ir = WorkflowIr::from_json_value(wf_json.clone()).expect("valid IR");
    let report = validate_workflow(&ir, Some(&catalog), &ValidationOptions::default());

    assert!(!report.valid);
    assert_eq!(report.strength, ValidationStrength::OfflineAuthoritative);
    assert!(
        report
            .error_codes
            .contains(&"unreachable_referenced_node:Step A->Step B".to_owned()),
        "errors: {:?}",
        report.error_codes
    );
    assert!(
        report
            .error_codes
            .contains(&"unknown_referenced_node:Step A->Does Not Exist".to_owned()),
        "errors: {:?}",
        report.error_codes
    );
    assert!(
        !report
            .error_codes
            .iter()
            .any(|c| c.contains("Step B->Webhook")),
        "Step B -> Webhook is valid upstream!"
    );

    // Skeleton compatibility smoke check.
    let skel = validate_workflow_skeleton(&wf_json);
    assert!(skel.valid);
    assert_eq!(
        extract_expression_blocks("={{ $('Webhook').item.json.id }}/{{ $now }}"),
        vec!["$('Webhook').item.json.id", "$now"]
    );
}
