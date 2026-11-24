//! Full workflow validator combining `n8n_graph::WorkflowGraph` topology checks,
//! `CatalogDb` per-node schema validation, AI sub-node port rules, and cross-graph
//! expression reference reachability.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use n8n_catalog_db::{CatalogDb, NodeInfoMode, NodeInfoRequest, SchemaConfidence};
use n8n_graph::{
    PortKind, WorkflowGraph, WorkflowIr, WorkflowNodeIr, escape_json_pointer_token,
    is_any_trigger_type, is_canvas_annotation_type,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ast::{ReferenceKind, analyze_js_code_script};
use crate::expressions::{analyze_template_expression, extract_expression_blocks};
use crate::node_config::{
    NodeValidationReport, ValidationProfile, ValidationSeverity, validate_node_config,
};

/// Strength/fidelity classification of workflow validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStrength {
    SkeletonOffline,
    CatalogOffline,
    OfflineAuthoritative,
    OfflinePartialSchema,
    NativeMcpVerified,
}

/// Issue emitted by lightweight skeleton validation (preserved for `n8n-mcp-server` compatibility).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SkeletonValidationIssue {
    pub severity: String,
    pub code: String,
    pub node_name: Option<String>,
    pub message: String,
}

/// Report emitted by `validate_workflow_skeleton` (preserved for `n8n-mcp-server` compatibility).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SkeletonValidationReport {
    pub valid: bool,
    pub strength: ValidationStrength,
    pub node_count: usize,
    pub connection_source_count: usize,
    pub issues: Vec<SkeletonValidationIssue>,
    #[serde(default)]
    pub limitation_note: String,
}

/// Options controlling full workflow validation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidationOptions {
    pub profile: ValidationProfile,
    pub validate_nodes_with_catalog: bool,
    pub check_expression_reachability: bool,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            profile: ValidationProfile::AiFriendly,
            validate_nodes_with_catalog: true,
            check_expression_reachability: true,
        }
    }
}

/// Unified workflow-level validation finding across topology, node schema, and expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowValidationIssue {
    pub severity: ValidationSeverity,
    pub category: String,
    pub code: String,
    pub node_id: Option<String>,
    pub node_name: Option<String>,
    pub field_path: Option<String>,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Dedicated graph topology validation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopologyValidationReport {
    pub valid: bool,
    pub node_count: usize,
    pub has_cycles: bool,
    pub is_controlled_loop: bool,
    pub error_codes: Vec<String>,
    pub warning_codes: Vec<String>,
    pub issues: Vec<WorkflowValidationIssue>,
}

/// Comprehensive workflow validation report produced by `validate_workflow`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowValidationReport {
    pub valid: bool,
    pub strength: ValidationStrength,
    pub profile: ValidationProfile,
    pub node_count: usize,
    pub has_cycles: bool,
    pub is_controlled_loop: bool,
    pub error_codes: Vec<String>,
    pub warning_codes: Vec<String>,
    pub topology: TopologyValidationReport,
    pub node_reports: BTreeMap<String, NodeValidationReport>,
    pub issues: Vec<WorkflowValidationIssue>,
}

/// Validates basic structural invariants of an n8n workflow JSON object without requiring `CatalogDb`.
#[must_use]
pub fn validate_workflow_skeleton(workflow: &Value) -> SkeletonValidationReport {
    let Some(obj) = workflow.as_object() else {
        return SkeletonValidationReport {
            valid: false,
            strength: ValidationStrength::SkeletonOffline,
            node_count: 0,
            connection_source_count: 0,
            issues: vec![SkeletonValidationIssue {
                severity: "error".to_owned(),
                code: "invalid_workflow_root".to_owned(),
                node_name: None,
                message: "Workflow payload must be a JSON object.".to_owned(),
            }],
            limitation_note:
                "Offline structural/syntax check only; does not guarantee runtime correctness."
                    .to_owned(),
        };
    };

    let mut issues = Vec::new();
    let mut node_names = HashSet::new();
    let mut node_ids = HashSet::new();

    let nodes = obj.get("nodes").and_then(Value::as_array);
    let node_count = nodes.map_or(0, Vec::len);
    if nodes.is_none() {
        issues.push(SkeletonValidationIssue {
            severity: "error".to_owned(),
            code: "missing_nodes_array".to_owned(),
            node_name: None,
            message: "Workflow JSON is missing `nodes` array.".to_owned(),
        });
    }

    if let Some(node_list) = nodes {
        for node in node_list {
            let name = node.get("name").and_then(Value::as_str).unwrap_or("");
            let id = node.get("id").and_then(Value::as_str).unwrap_or("");
            let node_type = node.get("type").and_then(Value::as_str).unwrap_or("");

            if name.trim().is_empty() {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "empty_node_name".to_owned(),
                    node_name: None,
                    message: "Node is missing a non-empty `name`.".to_owned(),
                });
            } else if !node_names.insert(name.to_owned()) {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "duplicate_node_name".to_owned(),
                    node_name: Some(name.to_owned()),
                    message: format!("Duplicate node name `{name}`."),
                });
            }

            if !id.is_empty() && !node_ids.insert(id.to_owned()) {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "duplicate_node_id".to_owned(),
                    node_name: Some(name.to_owned()),
                    message: format!("Duplicate node id `{id}`."),
                });
            }

            if node_type.trim().is_empty() {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "missing_node_type".to_owned(),
                    node_name: (!name.is_empty()).then(|| name.to_owned()),
                    message: "Node is missing `type`.".to_owned(),
                });
            }

            if node_type == "n8n-nodes-base.code" {
                let notes = node.get("notes").and_then(Value::as_str).unwrap_or("");
                if !notes.trim_start().starts_with("Why Code:") {
                    issues.push(SkeletonValidationIssue {
                        severity: "warning".to_owned(),
                        code: "code_node_missing_rationale".to_owned(),
                        node_name: Some(name.to_owned()),
                        message: "Code node should start `notes` with `Why Code:` explaining why a native node cannot satisfy the task.".to_owned(),
                    });
                }
            }

            if let Some(params) = node.get("parameters") {
                scan_skeleton_expressions(params, name, &mut issues);
            }
        }
    }

    let connections = obj.get("connections").and_then(Value::as_object);
    let connection_source_count = connections.map_or(0, serde_json::Map::len);
    if connections.is_none() {
        issues.push(SkeletonValidationIssue {
            severity: "error".to_owned(),
            code: "missing_connections_object".to_owned(),
            node_name: None,
            message: "Workflow JSON is missing `connections` object.".to_owned(),
        });
    } else if let Some(conn_map) = connections {
        for (src_name, outputs) in conn_map {
            if !node_names.contains(src_name) {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "unknown_connection_source".to_owned(),
                    node_name: Some(src_name.clone()),
                    message: format!("Connection source `{src_name}` does not exist in `nodes`."),
                });
            }
            if let Some(port_obj) = outputs.as_object() {
                for branches in port_obj.values() {
                    if let Some(branch_arr) = branches.as_array() {
                        for branch in branch_arr {
                            if let Some(targets) = branch.as_array() {
                                for target in targets {
                                    if let Some(dst_name) =
                                        target.get("node").and_then(Value::as_str)
                                        && !node_names.contains(dst_name)
                                    {
                                        issues.push(SkeletonValidationIssue {
                                            severity: "error".to_owned(),
                                            code: "unknown_connection_target".to_owned(),
                                            node_name: Some(src_name.clone()),
                                            message: format!(
                                                "Connection from `{src_name}` references missing target node `{dst_name}`."
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let has_errors = issues.iter().any(|i| i.severity == "error");
    SkeletonValidationReport {
        valid: !has_errors,
        strength: ValidationStrength::SkeletonOffline,
        node_count,
        connection_source_count,
        issues,
        limitation_note:
            "Offline structural/syntax check only; does not guarantee runtime correctness."
                .to_owned(),
    }
}

fn scan_skeleton_expressions(
    val: &Value,
    node_name: &str,
    issues: &mut Vec<SkeletonValidationIssue>,
) {
    match val {
        Value::String(s) => {
            if s.starts_with('=') && s.contains("{{") && extract_expression_blocks(s).is_empty() {
                issues.push(SkeletonValidationIssue {
                    severity: "error".to_owned(),
                    code: "unclosed_expression_braces".to_owned(),
                    node_name: Some(node_name.to_owned()),
                    message: "Expression starts with `=` and `{{` but has unclosed or empty `}}`."
                        .to_owned(),
                });
            }
        }
        Value::Array(arr) => {
            for item in arr {
                scan_skeleton_expressions(item, node_name, issues);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                scan_skeleton_expressions(item, node_name, issues);
            }
        }
        _ => {}
    }
}

/// Validates topology invariants directly from raw workflow JSON (catching pre-IR JSON errors
/// such as negative connection input indices before running `WorkflowGraph` topology checks).
#[must_use]
pub fn validate_workflow_topology_json(
    workflow: &Value,
    catalog: Option<&CatalogDb>,
) -> TopologyValidationReport {
    let Some(obj) = workflow.as_object() else {
        return TopologyValidationReport {
            valid: false,
            node_count: 0,
            has_cycles: false,
            is_controlled_loop: false,
            error_codes: vec!["invalid_workflow_root".to_owned()],
            warning_codes: Vec::new(),
            issues: vec![WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: "invalid_workflow_root".to_owned(),
                node_id: None,
                node_name: None,
                field_path: None,
                message: "Workflow JSON must be an object.".to_owned(),
                suggestion: None,
            }],
        };
    };

    // Detect negative target input indices (`"index": -1`) before deserializing `usize` in `WorkflowIr`.
    let mut pre_ir_issues = Vec::new();
    let mut normalized = workflow.clone();
    if let Some(conns) = normalized
        .get_mut("connections")
        .and_then(Value::as_object_mut)
    {
        for (src, ports) in conns.iter_mut() {
            if let Some(port_obj) = ports.as_object_mut() {
                for branches in port_obj.values_mut() {
                    if let Some(branch_arr) = branches.as_array_mut() {
                        for branch in branch_arr.iter_mut() {
                            if let Some(edges) = branch.as_array_mut() {
                                for edge in edges.iter_mut() {
                                    if let Some(idx_i64) = edge.get("index").and_then(Value::as_i64)
                                        && idx_i64 < 0
                                    {
                                        pre_ir_issues.push(WorkflowValidationIssue {
                                            severity: ValidationSeverity::Error,
                                            category: "topology".to_owned(),
                                            code: "invalid_input_index".to_owned(),
                                            node_id: None,
                                            node_name: Some(src.clone()),
                                            field_path: Some("/connections".to_owned()),
                                            message: format!(
                                                "Connection from `{src}` uses negative target input index `{idx_i64}`."
                                            ),
                                            suggestion: Some(
                                                "Target input index must be a non-negative integer.".to_owned(),
                                            ),
                                        });
                                        if let Some(edge_map) = edge.as_object_mut() {
                                            edge_map.insert("index".to_owned(), Value::from(0));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let node_count_fallback = obj
        .get("nodes")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    let Ok(ir) = WorkflowIr::from_json_value(normalized) else {
        let mut error_codes: Vec<String> = pre_ir_issues.iter().map(|i| i.code.clone()).collect();
        if error_codes.is_empty() {
            error_codes.push("invalid_workflow_schema".to_owned());
        }
        return TopologyValidationReport {
            valid: false,
            node_count: node_count_fallback,
            has_cycles: false,
            is_controlled_loop: false,
            error_codes,
            warning_codes: Vec::new(),
            issues: pre_ir_issues,
        };
    };

    let mut report = validate_workflow_topology(&ir, catalog);
    if !pre_ir_issues.is_empty() {
        for pre in pre_ir_issues {
            if !report.error_codes.contains(&pre.code) {
                report.error_codes.insert(0, pre.code.clone());
            }
            report.issues.insert(0, pre);
        }
        report.valid = false;
        report.warning_codes.clear();
        report
            .issues
            .retain(|i| i.severity == ValidationSeverity::Error);
    }
    report
}

/// Validates workflow graph topology, cycles, port bounds, AI sub-node ports, and reachability.
#[must_use]
pub fn validate_workflow_topology(
    ir: &WorkflowIr,
    catalog: Option<&CatalogDb>,
) -> TopologyValidationReport {
    let node_count = ir.nodes.len();
    let mut issues = Vec::new();

    if ir.nodes.is_empty() {
        issues.push(WorkflowValidationIssue {
            severity: ValidationSeverity::Error,
            category: "topology".to_owned(),
            code: "empty_workflow".to_owned(),
            node_id: None,
            node_name: None,
            field_path: Some("/nodes".to_owned()),
            message: "Workflow contains zero nodes.".to_owned(),
            suggestion: Some("Add a trigger node and at least one processing step.".to_owned()),
        });
        return finalize_topology_report(node_count, false, false, issues);
    }

    // 1. Duplicate node names & IDs.
    let mut seen_names = HashSet::with_capacity(ir.nodes.len());
    let mut seen_ids = HashSet::with_capacity(ir.nodes.len());
    let mut node_map: HashMap<&str, &WorkflowNodeIr> = HashMap::with_capacity(ir.nodes.len());

    for node in &ir.nodes {
        if node.name.trim().is_empty() {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: "empty_node_name".to_owned(),
                node_id: Some(node.id.clone()),
                node_name: None,
                field_path: Some("/nodes".to_owned()),
                message: "Node has an empty `name`.".to_owned(),
                suggestion: None,
            });
        } else if !seen_names.insert(node.name.as_str()) {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("duplicate_node_name:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/nodes".to_owned()),
                message: format!("Duplicate node name `{}`.", node.name),
                suggestion: Some("Every node in `nodes[]` must have a unique `name`.".to_owned()),
            });
        } else {
            node_map.insert(node.name.as_str(), node);
            if !node.id.is_empty() && !seen_ids.insert(node.id.as_str()) {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: "topology".to_owned(),
                    code: format!("duplicate_node_id:{}", node.id),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/nodes".to_owned()),
                    message: format!("Duplicate node id `{}`.", node.id),
                    suggestion: Some("Every node in `nodes[]` must have a unique `id`.".to_owned()),
                });
            }
        }
    }

    // 2. Dangling connection sources & targets.
    for (src_name, port_map) in &ir.connections {
        if !node_map.contains_key(src_name.as_str()) {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("dangling_connection_source:{src_name}"),
                node_id: None,
                node_name: Some(src_name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!("Connection source `{src_name}` does not exist in `nodes[]`."),
                suggestion: None,
            });
            continue;
        }
        for branches in port_map.values() {
            for branch in branches {
                for edge in branch {
                    if !node_map.contains_key(edge.node.as_str()) {
                        issues.push(WorkflowValidationIssue {
                            severity: ValidationSeverity::Error,
                            category: "topology".to_owned(),
                            code: format!("dangling_connection_target:{}", edge.node),
                            node_id: None,
                            node_name: Some(src_name.clone()),
                            field_path: Some("/connections".to_owned()),
                            message: format!(
                                "Connection from `{src_name}` targets nonexistent node `{}`.",
                                edge.node
                            ),
                            suggestion: None,
                        });
                    }
                }
            }
        }
    }

    // 3. Cycle & controlled-loop classification via `WorkflowGraph`.
    let graph = WorkflowGraph::from_ir(ir);
    let topo = graph.analyze();
    let has_cycles = !topo.cycles.is_empty();
    let mut has_uncontrolled_cycle = false;

    for cycle in &topo.cycles {
        if !is_strictly_controlled_loop(ir, &node_map, &cycle.nodes) {
            has_uncontrolled_cycle = true;
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: "uncontrolled_cycle".to_owned(),
                node_id: None,
                node_name: cycle.nodes.first().cloned(),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "Uncontrolled execution cycle detected across nodes: {}.",
                    cycle.nodes.join(" -> ")
                ),
                suggestion: Some(
                    "Terminate loops via `Loop Over Items` (`splitInBatches` loop branch 1) or a `Wait` + `IF` exit branch."
                        .to_owned(),
                ),
            });
        }
    }
    let is_controlled_loop = has_cycles && !has_uncontrolled_cycle;

    // 4. Port arity, trigger input, and AI sub-node port checks.
    let mut reversed_ai_nodes: HashSet<String> = HashSet::new();
    let mut incoming_ai_ports: HashMap<String, Vec<String>> = HashMap::new();
    let mut incoming_main_indices: HashMap<String, BTreeSet<usize>> = HashMap::new();
    let mut outgoing_edge_counts: HashMap<String, usize> = HashMap::new();
    let mut incoming_edge_counts: HashMap<String, usize> = HashMap::new();

    for (src_name, port_map) in &ir.connections {
        let Some(&src_node) = node_map.get(src_name.as_str()) else {
            continue;
        };

        for (port_kind, branches) in port_map {
            let port_key = port_kind.as_wire();
            let has_any_edge_in_port = branches.iter().any(|b| !b.is_empty());
            if has_any_edge_in_port && node_has_zero_outputs(&src_node.node_type) {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: "topology".to_owned(),
                    code: format!("node_has_no_outputs:{src_name}"),
                    node_id: Some(src_node.id.clone()),
                    node_name: Some(src_name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!(
                        "Terminal node `{src_name}` (`{}`) has 0 outputs and cannot wire downstream.",
                        src_node.node_type
                    ),
                    suggestion: None,
                });
                continue;
            }

            if port_key == "main" && expected_ai_provider_output_port(&src_node.node_type).is_none()
            {
                let max_out = max_main_output_branches(src_node, catalog);
                for (branch_idx, branch_edges) in branches.iter().enumerate() {
                    if !branch_edges.is_empty() && branch_idx >= max_out {
                        issues.push(WorkflowValidationIssue {
                            severity: ValidationSeverity::Error,
                            category: "topology".to_owned(),
                            code: format!("output_branch_out_of_bounds:{src_name}:{branch_idx}"),
                            node_id: Some(src_node.id.clone()),
                            node_name: Some(src_name.clone()),
                            field_path: Some("/connections".to_owned()),
                            message: format!(
                                "Node `{src_name}` (`{}`) emits on `main` branch {branch_idx}, exceeding max outputs ({max_out}).",
                                src_node.node_type
                            ),
                            suggestion: None,
                        });
                    }
                }
            }

            for branch_edges in branches {
                for edge in branch_edges {
                    let Some(&dst_node) = node_map.get(edge.node.as_str()) else {
                        continue;
                    };
                    *outgoing_edge_counts.entry(src_name.clone()).or_insert(0) += 1;
                    *incoming_edge_counts.entry(edge.node.clone()).or_insert(0) += 1;

                    let edge_port = edge.port_type.as_wire();
                    // Check reversed AI edge (e.g. `Agent --ai_languageModel--> OpenAI`).
                    if edge_port.starts_with("ai_")
                        && expected_ai_provider_output_port(&src_node.node_type).is_none()
                        && !src_node.node_type.contains("vectorStore")
                        && expected_ai_provider_output_port(&dst_node.node_type).is_some()
                    {
                        reversed_ai_nodes.insert(src_name.clone());
                        reversed_ai_nodes.insert(edge.node.clone());
                        issues.push(WorkflowValidationIssue {
                            severity: ValidationSeverity::Error,
                            category: "topology".to_owned(),
                            code: format!("ai_port_direction_reversed:{src_name}->{}", edge.node),
                            node_id: Some(src_node.id.clone()),
                            node_name: Some(src_name.clone()),
                            field_path: Some("/connections".to_owned()),
                            message: format!(
                                "AI connection `{src_name} -> {}` on `{edge_port}` is reversed; sub-node must connect INTO host node.",
                                edge.node
                            ),
                            suggestion: Some(format!(
                                "Connect `{}` -> `{src_name}` on `{edge_port}`.",
                                edge.node
                            )),
                        });
                        continue;
                    }

                    // Check AI sub-node provider output port match.
                    if let Some(expected_out) =
                        expected_ai_provider_output_port(&src_node.node_type)
                        && edge_port != expected_out
                    {
                        issues.push(WorkflowValidationIssue {
                            severity: ValidationSeverity::Error,
                            category: "topology".to_owned(),
                            code: format!(
                                "ai_port_mismatch:{src_name}->{}:{edge_port}",
                                edge.node
                            ),
                            node_id: Some(src_node.id.clone()),
                            node_name: Some(src_name.clone()),
                            field_path: Some("/connections".to_owned()),
                            message: format!(
                                "AI sub-node `{src_name}` outputs `{expected_out}`, not `{edge_port}`."
                            ),
                            suggestion: Some(format!("Wire `{src_name}` via `{expected_out}`.")),
                        });
                        incoming_ai_ports
                            .entry(edge.node.clone())
                            .or_default()
                            .push(edge_port.to_owned());
                        continue;
                    }

                    if edge_port.starts_with("ai_") {
                        let accepted = accepted_ai_ports_for_target(&dst_node.node_type);
                        if !accepted.contains(&edge_port) {
                            issues.push(WorkflowValidationIssue {
                                severity: ValidationSeverity::Error,
                                category: "topology".to_owned(),
                                code: format!("unsupported_target_port:{}:{edge_port}", edge.node),
                                node_id: Some(dst_node.id.clone()),
                                node_name: Some(edge.node.clone()),
                                field_path: Some("/connections".to_owned()),
                                message: format!(
                                    "Target node `{}` (`{}`) does not accept AI port `{edge_port}`.",
                                    edge.node, dst_node.node_type
                                ),
                                suggestion: None,
                            });
                        }
                        incoming_ai_ports
                            .entry(edge.node.clone())
                            .or_default()
                            .push(edge_port.to_owned());
                    } else if edge_port == "main" {
                        incoming_main_indices
                            .entry(edge.node.clone())
                            .or_default()
                            .insert(edge.index);

                        if is_any_trigger_type(&dst_node.node_type) {
                            if !has_uncontrolled_cycle {
                                issues.push(WorkflowValidationIssue {
                                    severity: ValidationSeverity::Error,
                                    category: "topology".to_owned(),
                                    code: format!("trigger_cannot_receive_main_input:{}", edge.node),
                                    node_id: Some(dst_node.id.clone()),
                                    node_name: Some(edge.node.clone()),
                                    field_path: Some("/connections".to_owned()),
                                    message: format!(
                                        "Trigger node `{}` cannot receive incoming `main` connections.",
                                        edge.node
                                    ),
                                    suggestion: None,
                                });
                            }
                        } else {
                            let max_in = max_main_input_ports(dst_node, catalog);
                            if edge.index >= max_in {
                                issues.push(WorkflowValidationIssue {
                                    severity: ValidationSeverity::Error,
                                    category: "topology".to_owned(),
                                    code: format!(
                                        "input_index_out_of_bounds:{}:{}",
                                        edge.node, edge.index
                                    ),
                                    node_id: Some(dst_node.id.clone()),
                                    node_name: Some(edge.node.clone()),
                                    field_path: Some("/connections".to_owned()),
                                    message: format!(
                                        "Target node `{}` (`{}`) received `main` input index {}, exceeding max inputs ({max_in}).",
                                        edge.node, dst_node.node_type, edge.index
                                    ),
                                    suggestion: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. Required AI sub-node ports & orphan AI sub-node checks.
    for node in &ir.nodes {
        if node.disabled || reversed_ai_nodes.contains(&node.name) {
            continue;
        }
        let ai_in = incoming_ai_ports
            .get(&node.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        if requires_ai_language_model(&node.node_type)
            && !ai_in.iter().any(|p| p == "ai_languageModel")
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("missing_ai_language_model:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "AI node `{}` (`{}`) requires an `ai_languageModel` sub-node connection.",
                    node.name, node.node_type
                ),
                suggestion: Some("Connect a Chat Model node via `ai_languageModel`.".to_owned()),
            });
        }

        let memory_count = ai_in.iter().filter(|p| p.as_str() == "ai_memory").count();
        if memory_count > 1 {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("multiple_ai_memory_inputs:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "AI node `{}` has {memory_count} `ai_memory` connections; at most 1 memory sub-node is supported.",
                    node.name
                ),
                suggestion: None,
            });
        }

        if node.node_type == "@n8n/n8n-nodes-langchain.outputParserAutofixing"
            && !ai_in.iter().any(|p| p == "ai_outputParser")
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("missing_ai_output_parser:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "Auto-fixing Output Parser `{}` requires a child `ai_outputParser` connection.",
                    node.name
                ),
                suggestion: None,
            });
        }

        if node
            .node_type
            .starts_with("@n8n/n8n-nodes-langchain.vectorStore")
            && !ai_in.iter().any(|p| p == "ai_embedding")
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("missing_ai_embedding:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "Vector Store node `{}` requires an `ai_embedding` sub-node connection.",
                    node.name
                ),
                suggestion: None,
            });
        }

        if expected_ai_provider_output_port(&node.node_type).is_some()
            && outgoing_edge_counts.get(&node.name).copied().unwrap_or(0) == 0
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "topology".to_owned(),
                code: format!("orphan_ai_subnode:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "AI sub-node `{}` (`{}`) is not connected to any AI host node.",
                    node.name, node.node_type
                ),
                suggestion: None,
            });
        }
    }

    // 6. Soft reachability & structural lints (only emitted when hard structural errors are clean).
    let has_hard_errors = issues
        .iter()
        .any(|i| i.severity == ValidationSeverity::Error);
    if !has_hard_errors {
        emit_soft_topology_warnings(
            ir,
            &topo.disconnected_nodes,
            &incoming_main_indices,
            &outgoing_edge_counts,
            &incoming_edge_counts,
            &mut issues,
        );
    }

    finalize_topology_report(node_count, has_cycles, is_controlled_loop, issues)
}

fn emit_soft_topology_warnings(
    ir: &WorkflowIr,
    disconnected_set: &[String],
    incoming_main_indices: &HashMap<String, BTreeSet<usize>>,
    outgoing_edge_counts: &HashMap<String, usize>,
    incoming_edge_counts: &HashMap<String, usize>,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    let enabled_triggers: Vec<&WorkflowNodeIr> = ir
        .nodes
        .iter()
        .filter(|n| !n.disabled && is_any_trigger_type(&n.node_type))
        .collect();

    let non_annotation_nodes: Vec<&WorkflowNodeIr> = ir
        .nodes
        .iter()
        .filter(|n| !n.disabled && !is_canvas_annotation_type(&n.node_type))
        .collect();

    if enabled_triggers.is_empty() && !non_annotation_nodes.is_empty() {
        issues.push(WorkflowValidationIssue {
            severity: ValidationSeverity::Warning,
            category: "topology".to_owned(),
            code: "missing_trigger_node".to_owned(),
            node_id: None,
            node_name: None,
            field_path: Some("/nodes".to_owned()),
            message: "Workflow has no enabled trigger node (`Webhook`, `Schedule`, `Manual Trigger`, etc.).".to_owned(),
            suggestion: None,
        });
    } else {
        for trig in &enabled_triggers {
            if outgoing_edge_counts.get(&trig.name).copied().unwrap_or(0) == 0 {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "topology".to_owned(),
                    code: format!("disconnected_trigger:{}", trig.name),
                    node_id: Some(trig.id.clone()),
                    node_name: Some(trig.name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!(
                        "Trigger node `{}` has zero outgoing connections.",
                        trig.name
                    ),
                    suggestion: None,
                });
            }
        }

        let disconnected_lookup: HashSet<&str> =
            disconnected_set.iter().map(String::as_str).collect();
        for node in &ir.nodes {
            if !node.disabled
                && !is_any_trigger_type(&node.node_type)
                && !is_canvas_annotation_type(&node.node_type)
                && disconnected_lookup.contains(node.name.as_str())
            {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "topology".to_owned(),
                    code: format!("unreachable_node:{}", node.name),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!("Node `{}` is unreachable from any trigger.", node.name),
                    suggestion: None,
                });
            }
        }
    }

    let ancestors = compute_all_upstream_ancestors(ir);

    // Webhook <-> Respond to Webhook pairing lints.
    for node in &ir.nodes {
        if node.disabled {
            continue;
        }
        if node.node_type == "n8n-nodes-base.webhook"
            && outgoing_edge_counts.get(&node.name).copied().unwrap_or(0) > 0
        {
            let explicit_response_node =
                node.parameters.get("responseMode").and_then(Value::as_str) == Some("responseNode");
            let skeleton_two_node_webhook = node
                .parameters
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
                && ir.nodes.len() == 2;

            if explicit_response_node || skeleton_two_node_webhook {
                let has_downstream_respond = ir.nodes.iter().any(|other| {
                    other.node_type == "n8n-nodes-base.respondToWebhook"
                        && ancestors
                            .get(&other.name)
                            .is_some_and(|set| set.contains(&node.name))
                });
                if !has_downstream_respond {
                    issues.push(WorkflowValidationIssue {
                        severity: ValidationSeverity::Warning,
                        category: "topology".to_owned(),
                        code: "webhook_response_node_maybe_missing".to_owned(),
                        node_id: Some(node.id.clone()),
                        node_name: Some(node.name.clone()),
                        field_path: Some("/parameters/responseMode".to_owned()),
                        message: format!(
                            "Webhook `{}` has no downstream `Respond to Webhook` node.",
                            node.name
                        ),
                        suggestion: None,
                    });
                }
            }
        }

        if node.node_type == "n8n-nodes-base.respondToWebhook" {
            let has_upstream_webhook = ancestors.get(&node.name).is_some_and(|set| {
                set.iter().any(|anc_name| {
                    ir.node_by_name(anc_name).is_some_and(|anc| {
                        matches!(
                            anc.node_type.as_str(),
                            "n8n-nodes-base.webhook"
                                | "n8n-nodes-base.formTrigger"
                                | "@n8n/n8n-nodes-langchain.chatTrigger"
                        )
                    })
                })
            });
            if !has_upstream_webhook {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "topology".to_owned(),
                    code: "respond_to_webhook_without_webhook_trigger".to_owned(),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!(
                        "`Respond to Webhook` node `{}` has no upstream Webhook trigger.",
                        node.name
                    ),
                    suggestion: None,
                });
            }
        }

        if node.node_type == "n8n-nodes-base.merge" {
            let connected_inputs = incoming_main_indices
                .get(&node.name)
                .map_or(0, BTreeSet::len);
            if connected_inputs > 0 && connected_inputs < 2 {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "topology".to_owned(),
                    code: format!("merge_missing_second_input:{}", node.name),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!(
                        "Merge node `{}` only has 1 input stream connected.",
                        node.name
                    ),
                    suggestion: None,
                });
            }
        }

        if matches!(
            node.node_type.as_str(),
            "n8n-nodes-base.if" | "n8n-nodes-base.switch"
        ) && incoming_edge_counts.get(&node.name).copied().unwrap_or(0) > 0
            && outgoing_edge_counts.get(&node.name).copied().unwrap_or(0) == 0
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Warning,
                category: "topology".to_owned(),
                code: format!("dead_end_branch_node:{}", node.name),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/connections".to_owned()),
                message: format!(
                    "Branching node `{}` has no connected outgoing branches.",
                    node.name
                ),
                suggestion: None,
            });
        }

        if node.node_type == "n8n-nodes-base.splitInBatches" {
            let loop_body_empty = ir
                .connections
                .get(&node.name)
                .and_then(|pm| pm.get(&PortKind::Main))
                .and_then(|branches| branches.get(1))
                .is_none_or(Vec::is_empty);
            if loop_body_empty {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "topology".to_owned(),
                    code: format!("empty_loop_body:{}", node.name),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some("/connections".to_owned()),
                    message: format!(
                        "`Loop Over Items` node `{}` has an empty `loop` body branch (output 1).",
                        node.name
                    ),
                    suggestion: None,
                });
            }
        }
    }
}

fn finalize_topology_report(
    node_count: usize,
    has_cycles: bool,
    is_controlled_loop: bool,
    issues: Vec<WorkflowValidationIssue>,
) -> TopologyValidationReport {
    let mut error_codes = Vec::new();
    let mut warning_codes = Vec::new();
    for issue in &issues {
        match issue.severity {
            ValidationSeverity::Error => {
                if !error_codes.contains(&issue.code) {
                    error_codes.push(issue.code.clone());
                }
            }
            ValidationSeverity::Warning | ValidationSeverity::Suggestion => {
                if !warning_codes.contains(&issue.code) {
                    warning_codes.push(issue.code.clone());
                }
            }
        }
    }

    TopologyValidationReport {
        valid: error_codes.is_empty(),
        node_count,
        has_cycles,
        is_controlled_loop,
        error_codes,
        warning_codes,
        issues,
    }
}

fn is_strictly_controlled_loop(
    ir: &WorkflowIr,
    node_map: &HashMap<&str, &WorkflowNodeIr>,
    cycle_nodes: &[String],
) -> bool {
    if cycle_nodes.len() < 2 {
        return false;
    }
    let cycle_set: HashSet<&str> = cycle_nodes.iter().map(String::as_str).collect();

    let mut has_split_in_batches_body_loop = false;
    let mut has_conditional_exit = false;
    let mut has_wait_node = false;

    for name in cycle_nodes {
        let Some(&node) = node_map.get(name.as_str()) else {
            return false;
        };
        if is_any_trigger_type(&node.node_type) {
            return false;
        }
        if node.node_type == "n8n-nodes-base.wait" {
            has_wait_node = true;
        }
        if node.node_type == "n8n-nodes-base.splitInBatches"
            && let Some(branches) = ir
                .connections
                .get(name)
                .and_then(|pm| pm.get(&PortKind::Main))
        {
            let done_reenters = branches
                .first()
                .is_some_and(|edges| edges.iter().any(|e| cycle_set.contains(e.node.as_str())));
            let loop_enters = branches
                .get(1)
                .is_some_and(|edges| edges.iter().any(|e| cycle_set.contains(e.node.as_str())));
            if loop_enters && !done_reenters {
                has_split_in_batches_body_loop = true;
            }
        }
        if matches!(
            node.node_type.as_str(),
            "n8n-nodes-base.if" | "n8n-nodes-base.switch"
        ) && let Some(branches) = ir
            .connections
            .get(name)
            .and_then(|pm| pm.get(&PortKind::Main))
        {
            let leaves_cycle = branches
                .iter()
                .flatten()
                .any(|e| !cycle_set.contains(e.node.as_str()));
            if leaves_cycle {
                has_conditional_exit = true;
            }
        }
    }

    has_split_in_batches_body_loop
        || (has_conditional_exit && has_wait_node)
        || has_conditional_exit
}

fn node_has_zero_outputs(node_type: &str) -> bool {
    node_type == "n8n-nodes-base.stopAndError"
}

fn max_main_output_branches(node: &WorkflowNodeIr, catalog: Option<&CatalogDb>) -> usize {
    let error_branch_extra = usize::from(node.on_error.as_deref() == Some("continueErrorOutput"));
    let base = match node.node_type.as_str() {
        "n8n-nodes-base.switch" => 16,
        "n8n-nodes-base.compareDatasets" => 4,
        "n8n-nodes-base.if" | "n8n-nodes-base.splitInBatches" => 2,
        "n8n-nodes-base.stopAndError" => 0,
        _ => catalog
            .and_then(|db| {
                db.get_node_info(&NodeInfoRequest {
                    node_type: node.node_type.clone(),
                    mode: NodeInfoMode::Info,
                    type_version: Some(node.type_version_string()),
                    property_query: None,
                })
                .ok()
            })
            .filter(|info| info.found_in_catalog && !info.outputs.is_empty())
            .map_or(1, |info| {
                let main_count = info.outputs.iter().filter(|o| o.as_str() == "main").count();
                main_count.max(1)
            }),
    };
    base + error_branch_extra
}

fn max_main_input_ports(node: &WorkflowNodeIr, catalog: Option<&CatalogDb>) -> usize {
    match node.node_type.as_str() {
        "n8n-nodes-base.merge" => 16,
        "n8n-nodes-base.compareDatasets" => 2,
        _ => catalog
            .and_then(|db| {
                db.get_node_info(&NodeInfoRequest {
                    node_type: node.node_type.clone(),
                    mode: NodeInfoMode::Info,
                    type_version: Some(node.type_version_string()),
                    property_query: None,
                })
                .ok()
            })
            .filter(|info| info.found_in_catalog && !info.inputs.is_empty())
            .map_or(1, |info| {
                let main_count = info.inputs.iter().filter(|i| i.as_str() == "main").count();
                main_count.max(1)
            }),
    }
}

fn expected_ai_provider_output_port(node_type: &str) -> Option<&'static str> {
    if node_type.starts_with("@n8n/n8n-nodes-langchain.lmChat")
        || node_type.starts_with("@n8n/n8n-nodes-langchain.lm")
    {
        Some("ai_languageModel")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.memory") {
        Some("ai_memory")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.tool")
        || (node_type.starts_with("n8n-nodes-base.") && node_type.ends_with("Tool"))
    {
        Some("ai_tool")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.outputParser") {
        Some("ai_outputParser")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.embeddings") {
        Some("ai_embedding")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.document") {
        Some("ai_document")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.textSplitter") {
        Some("ai_textSplitter")
    } else if node_type.starts_with("@n8n/n8n-nodes-langchain.reranker") {
        Some("ai_reranker")
    } else {
        None
    }
}

fn accepted_ai_ports_for_target(node_type: &str) -> &'static [&'static str] {
    match node_type {
        "@n8n/n8n-nodes-langchain.agent" => &[
            "ai_languageModel",
            "ai_memory",
            "ai_tool",
            "ai_outputParser",
        ],
        "@n8n/n8n-nodes-langchain.chainLlm" => {
            &["ai_languageModel", "ai_memory", "ai_outputParser"]
        }
        "@n8n/n8n-nodes-langchain.chainSummarization" => &["ai_languageModel", "ai_document"],
        "@n8n/n8n-nodes-langchain.chainRetrievalQa" => {
            &["ai_languageModel", "ai_retriever", "ai_memory"]
        }
        "@n8n/n8n-nodes-langchain.informationExtractor"
        | "@n8n/n8n-nodes-langchain.sentimentAnalysis"
        | "@n8n/n8n-nodes-langchain.textClassifier" => &["ai_languageModel"],
        "@n8n/n8n-nodes-langchain.outputParserAutofixing" => {
            &["ai_languageModel", "ai_outputParser"]
        }
        _ if node_type.starts_with("@n8n/n8n-nodes-langchain.vectorStore") => {
            &["ai_embedding", "ai_document", "ai_reranker"]
        }
        _ if node_type.starts_with("@n8n/n8n-nodes-langchain.document") => &["ai_textSplitter"],
        "@n8n/n8n-nodes-langchain.retrieverVectorStore" => &["ai_vectorStore"],
        _ => &[],
    }
}

fn requires_ai_language_model(node_type: &str) -> bool {
    matches!(
        node_type,
        "@n8n/n8n-nodes-langchain.agent"
            | "@n8n/n8n-nodes-langchain.chainLlm"
            | "@n8n/n8n-nodes-langchain.chainSummarization"
            | "@n8n/n8n-nodes-langchain.chainRetrievalQa"
            | "@n8n/n8n-nodes-langchain.informationExtractor"
            | "@n8n/n8n-nodes-langchain.sentimentAnalysis"
            | "@n8n/n8n-nodes-langchain.textClassifier"
    )
}

/// Computes all upstream ancestors for every node in `ir` across all port types.
#[must_use]
pub fn compute_all_upstream_ancestors(ir: &WorkflowIr) -> HashMap<String, HashSet<String>> {
    let mut reverse_adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for (src, pm) in &ir.connections {
        for branches in pm.values() {
            for branch in branches {
                for edge in branch {
                    reverse_adj
                        .entry(edge.node.as_str())
                        .or_default()
                        .push(src.as_str());
                }
            }
        }
    }

    let mut result = HashMap::with_capacity(ir.nodes.len());
    for node in &ir.nodes {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(parents) = reverse_adj.get(node.name.as_str()) {
            for &p in parents {
                if visited.insert(p.to_owned()) {
                    queue.push_back(p);
                }
            }
        }
        while let Some(cur) = queue.pop_front() {
            if let Some(parents) = reverse_adj.get(cur) {
                for &p in parents {
                    if visited.insert(p.to_owned()) {
                        queue.push_back(p);
                    }
                }
            }
        }
        result.insert(node.name.clone(), visited);
    }
    result
}

/// Full production workflow validator combining `WorkflowGraph` topology checks, per-node
/// `CatalogDb` validation, and cross-graph `$('Node')` expression reference reachability.
#[must_use]
pub fn validate_workflow(
    ir: &WorkflowIr,
    catalog: Option<&CatalogDb>,
    options: &ValidationOptions,
) -> WorkflowValidationReport {
    let topology = validate_workflow_topology(ir, catalog);
    let mut issues = topology.issues.clone();
    let mut node_reports = BTreeMap::new();
    let mut any_partial_schema = false;

    if let Some(db) = catalog.filter(|_| options.validate_nodes_with_catalog) {
        for node in &ir.nodes {
            if is_canvas_annotation_type(&node.node_type) {
                continue;
            }
            if let Ok(report) = validate_node_config(node, db, options.profile) {
                if report.schema_confidence == SchemaConfidence::UnknownOrCommunityPartial {
                    any_partial_schema = true;
                }
                for node_issue in &report.issues {
                    issues.push(WorkflowValidationIssue {
                        severity: node_issue.severity,
                        category: "node_config".to_owned(),
                        code: node_issue.code.clone(),
                        node_id: Some(node_issue.node_id.clone()),
                        node_name: Some(node_issue.node_name.clone()),
                        field_path: node_issue.field_path.clone(),
                        message: node_issue.message.clone(),
                        suggestion: node_issue.suggestion.clone(),
                    });
                }
                node_reports.insert(node.name.clone(), report);
            }
        }
    } else {
        // Without CatalogDb, still run offline Code rationale + JS/expression syntax checks.
        for node in &ir.nodes {
            validate_node_without_catalog(node, options.profile, &mut issues);
        }
    }

    // Cross-graph expression reference reachability (`$('Target')`, `$node["Target"]`, `$items("Target")`).
    if options.check_expression_reachability {
        let ancestors = compute_all_upstream_ancestors(ir);
        for node in &ir.nodes {
            validate_cross_graph_expressions(node, ir, &ancestors, options.profile, &mut issues);
        }
    }

    let strength = match catalog {
        Some(_) if options.validate_nodes_with_catalog => {
            if any_partial_schema {
                ValidationStrength::OfflinePartialSchema
            } else {
                ValidationStrength::OfflineAuthoritative
            }
        }
        _ => ValidationStrength::SkeletonOffline,
    };

    let mut error_codes = Vec::new();
    let mut warning_codes = Vec::new();
    for issue in &issues {
        match issue.severity {
            ValidationSeverity::Error => {
                if !error_codes.contains(&issue.code) {
                    error_codes.push(issue.code.clone());
                }
            }
            ValidationSeverity::Warning | ValidationSeverity::Suggestion => {
                if !warning_codes.contains(&issue.code) {
                    warning_codes.push(issue.code.clone());
                }
            }
        }
    }

    WorkflowValidationReport {
        valid: error_codes.is_empty(),
        strength,
        profile: options.profile,
        node_count: ir.nodes.len(),
        has_cycles: topology.has_cycles,
        is_controlled_loop: topology.is_controlled_loop,
        error_codes,
        warning_codes,
        topology,
        node_reports,
        issues,
    }
}

fn validate_node_without_catalog(
    node: &WorkflowNodeIr,
    profile: ValidationProfile,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    if matches!(
        node.node_type.as_str(),
        "n8n-nodes-base.code" | "@n8n/n8n-nodes-langchain.toolCode"
    ) {
        if profile != ValidationProfile::Minimal
            && !crate::node_config::code_node_has_why_rationale(node.notes.as_deref())
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Warning,
                category: "node_config".to_owned(),
                code: "native_first_code_rationale_missing".to_owned(),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/notes".to_owned()),
                message: format!(
                    "Code node `{}` lacks a `Why Code:` rationale in `notes`.",
                    node.name
                ),
                suggestion: None,
            });
        }
        let lang = node
            .parameters
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("javaScript");
        if matches!(lang, "javaScript" | "javascript")
            && let Some(js) = node.parameters.get("jsCode").and_then(Value::as_str)
            && !js.trim().is_empty()
            && !analyze_js_code_script(js).valid_syntax
        {
            issues.push(WorkflowValidationIssue {
                severity: ValidationSeverity::Error,
                category: "node_config".to_owned(),
                code: "invalid_code_syntax".to_owned(),
                node_id: Some(node.id.clone()),
                node_name: Some(node.name.clone()),
                field_path: Some("/parameters/jsCode".to_owned()),
                message: format!("JavaScript syntax error in Code node `{}`.", node.name),
                suggestion: None,
            });
        }
    }

    scan_offline_param_syntax(node, &node.parameters, "/parameters", profile, issues);
}

fn scan_offline_param_syntax(
    node: &WorkflowNodeIr,
    val: &Value,
    pointer: &str,
    profile: ValidationProfile,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    match val {
        Value::String(s) if s.starts_with('=') => {
            let analysis = analyze_template_expression(s);
            if !analysis.valid_syntax {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Error,
                    category: "expression".to_owned(),
                    code: format!("invalid_expression_syntax:{pointer}"),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some(pointer.to_owned()),
                    message: format!(
                        "Invalid expression syntax at `{pointer}` on node `{}`.",
                        node.name
                    ),
                    suggestion: None,
                });
            } else if analysis.code_like_expression_warning && profile != ValidationProfile::Minimal
            {
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "expression".to_owned(),
                    code: "code_like_expression".to_owned(),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some(pointer.to_owned()),
                    message: format!(
                        "Complex multi-statement/function expression at `{pointer}` on node `{}`.",
                        node.name
                    ),
                    suggestion: analysis.native_first_suggestion,
                });
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let next_ptr = format!("{pointer}/{}", escape_json_pointer_token(k));
                scan_offline_param_syntax(node, child, &next_ptr, profile, issues);
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let next_ptr = format!("{pointer}/{i}");
                scan_offline_param_syntax(node, child, &next_ptr, profile, issues);
            }
        }
        _ => {}
    }
}

fn validate_cross_graph_expressions(
    node: &WorkflowNodeIr,
    ir: &WorkflowIr,
    ancestors: &HashMap<String, HashSet<String>>,
    profile: ValidationProfile,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    let node_ancestors = ancestors.get(&node.name);

    check_value_reachability(
        node,
        &node.parameters,
        "/parameters",
        ir,
        node_ancestors,
        profile,
        issues,
    );

    if matches!(
        node.node_type.as_str(),
        "n8n-nodes-base.code" | "@n8n/n8n-nodes-langchain.toolCode"
    ) {
        let lang = node
            .parameters
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("javaScript");
        if matches!(lang, "javaScript" | "javascript")
            && let Some(js) = node.parameters.get("jsCode").and_then(Value::as_str)
        {
            let ast = analyze_js_code_script(js);
            if ast.valid_syntax {
                for r in &ast.references {
                    match &r.kind {
                        ReferenceKind::LiteralNode(target) => {
                            check_single_target_reachability(
                                node,
                                target,
                                "/parameters/jsCode",
                                ir,
                                node_ancestors,
                                issues,
                            );
                        }
                        ReferenceKind::DynamicNodeRef { snippet, .. } => {
                            if profile != ValidationProfile::Minimal {
                                issues.push(WorkflowValidationIssue {
                                    severity: ValidationSeverity::Warning,
                                    category: "expression".to_owned(),
                                    code: format!("dynamic_node_reference:{}", node.name),
                                    node_id: Some(node.id.clone()),
                                    node_name: Some(node.name.clone()),
                                    field_path: Some("/parameters/jsCode".to_owned()),
                                    message: format!(
                                        "Dynamic node reference `{snippet}` in `{}` requires manual review on node renames.",
                                        node.name
                                    ),
                                    suggestion: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

fn check_value_reachability(
    node: &WorkflowNodeIr,
    val: &Value,
    pointer: &str,
    ir: &WorkflowIr,
    node_ancestors: Option<&HashSet<String>>,
    profile: ValidationProfile,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    match val {
        Value::String(s) if s.starts_with('=') => {
            let analysis = analyze_template_expression(s);
            if !analysis.valid_syntax {
                return;
            }
            for target in &analysis.referenced_nodes {
                check_single_target_reachability(node, target, pointer, ir, node_ancestors, issues);
            }
            if !analysis.dynamic_references.is_empty() && profile != ValidationProfile::Minimal {
                let snippet = &analysis.dynamic_references[0].snippet;
                issues.push(WorkflowValidationIssue {
                    severity: ValidationSeverity::Warning,
                    category: "expression".to_owned(),
                    code: format!("dynamic_node_reference:{}", node.name),
                    node_id: Some(node.id.clone()),
                    node_name: Some(node.name.clone()),
                    field_path: Some(pointer.to_owned()),
                    message: format!(
                        "Dynamic node reference `{snippet}` at `{pointer}` on `{}` requires manual review during renames.",
                        node.name
                    ),
                    suggestion: None,
                });
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let next_ptr = format!("{pointer}/{}", escape_json_pointer_token(k));
                check_value_reachability(
                    node,
                    child,
                    &next_ptr,
                    ir,
                    node_ancestors,
                    profile,
                    issues,
                );
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let next_ptr = format!("{pointer}/{i}");
                check_value_reachability(
                    node,
                    child,
                    &next_ptr,
                    ir,
                    node_ancestors,
                    profile,
                    issues,
                );
            }
        }
        _ => {}
    }
}

fn check_single_target_reachability(
    node: &WorkflowNodeIr,
    target: &str,
    pointer: &str,
    ir: &WorkflowIr,
    node_ancestors: Option<&HashSet<String>>,
    issues: &mut Vec<WorkflowValidationIssue>,
) {
    let is_ancestor = node_ancestors.is_some_and(|set| set.contains(target));
    if target == node.name && !is_ancestor {
        issues.push(WorkflowValidationIssue {
            severity: ValidationSeverity::Error,
            category: "expression".to_owned(),
            code: format!("self_referencing_expression:{}", node.name),
            node_id: Some(node.id.clone()),
            node_name: Some(node.name.clone()),
            field_path: Some(pointer.to_owned()),
            message: format!(
                "Expression at `{pointer}` on node `{}` references itself without an upstream loop.",
                node.name
            ),
            suggestion: None,
        });
    } else if ir.node_by_name(target).is_none() {
        issues.push(WorkflowValidationIssue {
            severity: ValidationSeverity::Error,
            category: "expression".to_owned(),
            code: format!("unknown_referenced_node:{}->{target}", node.name),
            node_id: Some(node.id.clone()),
            node_name: Some(node.name.clone()),
            field_path: Some(pointer.to_owned()),
            message: format!(
                "Expression at `{pointer}` on node `{}` references nonexistent node `{target}`.",
                node.name
            ),
            suggestion: None,
        });
    } else if !is_ancestor {
        issues.push(WorkflowValidationIssue {
            severity: ValidationSeverity::Error,
            category: "expression".to_owned(),
            code: format!("unreachable_referenced_node:{}->{target}", node.name),
            node_id: Some(node.id.clone()),
            node_name: Some(node.name.clone()),
            field_path: Some(pointer.to_owned()),
            message: format!(
                "Expression at `{pointer}` on node `{}` references `{target}`, which is not upstream/reachable from `{}`.",
                node.name, node.name
            ),
            suggestion: Some(format!(
                "Ensure `{target}` executes upstream of `{}` before referencing its output.",
                node.name
            )),
        });
    }
}
