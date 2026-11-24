//! AST-verified workflow graph & RFC 6901 JSON Pointer mutation engine with diff verification.
//!
//! Combines `n8n_graph::WorkflowIr` + `WorkflowDiff` with `oxc_parser` AST literal rewriting,
//! whole-array replacement guards, protected node-field enforcement, secret-material rejection,
//! and dangling expression-reference checks.

use n8n_catalog_db::{CatalogDb, NodeInfoMode, NodeInfoRequest, json_values_equal};
use n8n_graph::{
    ConnectionChangeKind, ConnectionEdgeIr, NodeCredentialRef, PortKind, WorkflowDiff, WorkflowIr,
    WorkflowNodeIr, escape_json_pointer_token, unescape_json_pointer_token,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ast::{ReferenceKind, analyze_js_code_script};
use crate::expressions::{analyze_template_expression, rewrite_literal_node_references};

const PROTECTED_NODE_FIELDS: &[&str] = &[
    "id",
    "type",
    "position",
    "name",
    "credentials",
    "typeVersion",
];

/// High-level workflow patch operation validated before application.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ValidatedMutationOp {
    SetParam {
        node: String,
        pointer: String,
        value: Value,
        #[serde(default, alias = "allowWholeArrayReplace")]
        allow_whole_array_replace: bool,
    },
    UnsetParam {
        node: String,
        pointer: String,
        #[serde(default, alias = "allowWholeArrayReplace")]
        allow_whole_array_replace: bool,
    },
    MoveNode {
        node: String,
        position: [f64; 2],
    },
    RenameNode {
        from: String,
        to: String,
    },
    InsertBetween {
        after: String,
        before: String,
        #[serde(default)]
        branch: usize,
        node: WorkflowNodeIr,
    },
    RemoveNode {
        node: String,
        #[serde(default)]
        bridge: bool,
    },
    SetEnabled {
        node: String,
        enabled: bool,
    },
    ConnectNodes {
        from: String,
        to: String,
        #[serde(default = "default_main_port")]
        port: String,
        #[serde(default)]
        branch: usize,
        #[serde(default)]
        index: usize,
    },
    AddNodeAndConnect {
        after: String,
        #[serde(default)]
        branch: usize,
        node: WorkflowNodeIr,
    },
    DisconnectNodes {
        from: String,
        to: String,
        #[serde(default = "default_main_port")]
        port: String,
        #[serde(default)]
        branch: usize,
    },
    BindCredential {
        node: String,
        #[serde(alias = "credentialType")]
        credential_type: String,
        #[serde(alias = "credentialId")]
        credential_id: String,
        #[serde(default, alias = "credentialName")]
        credential_name: Option<String>,
        #[serde(default)]
        data: Option<Value>,
    },
    UpgradeNodeVersion {
        node: String,
        #[serde(alias = "targetVersion")]
        target_version: Value,
    },
}

fn default_main_port() -> String {
    "main".to_owned()
}

/// Disposition of a validated mutation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MutationApplyStatus {
    Applied,
    Rejected,
    ManualReviewRequired,
}

/// Expression parameter rewritten during `rename_node`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewrittenExpressionEntry {
    pub node: String,
    pub pointer: String,
    pub before: String,
    pub after: String,
}

/// Dynamic expression location blocking automatic `rename_node`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlockingExpressionLocation {
    pub node: String,
    pub pointer: String,
}

/// Full outcome of validating and applying a single `ValidatedMutationOp`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedMutationOutcome {
    pub status: MutationApplyStatus,
    pub changed: bool,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub resolved_value: Option<Value>,
    pub removed: Option<bool>,
    pub position: Option<[f64; 2]>,
    pub disabled: Option<bool>,
    pub connection_keys_renamed: Vec<String>,
    pub rewritten_expressions: Vec<RewrittenExpressionEntry>,
    pub rewritten_count: usize,
    pub blocking_expressions: Vec<BlockingExpressionLocation>,
    pub added_edges: Vec<String>,
    pub removed_edges: Vec<String>,
    pub diff: Option<WorkflowDiff>,
    pub updated_workflow: WorkflowIr,
}

impl ValidatedMutationOutcome {
    fn rejected(
        before: &WorkflowIr,
        error_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: MutationApplyStatus::Rejected,
            changed: false,
            error_code: Some(error_code.into()),
            message: Some(message.into()),
            resolved_value: None,
            removed: None,
            position: None,
            disabled: None,
            connection_keys_renamed: Vec::new(),
            rewritten_expressions: Vec::new(),
            rewritten_count: 0,
            blocking_expressions: Vec::new(),
            added_edges: Vec::new(),
            removed_edges: Vec::new(),
            diff: None,
            updated_workflow: before.clone(),
        }
    }
}

/// Validates and applies `op` against `before`, returning the updated `WorkflowIr` and
/// structured `WorkflowDiff` when `status == Applied`.
#[must_use]
pub fn apply_validated_mutation(
    before: &WorkflowIr,
    op: &ValidatedMutationOp,
    catalog: Option<&CatalogDb>,
) -> ValidatedMutationOutcome {
    match op {
        ValidatedMutationOp::SetParam {
            node,
            pointer,
            value,
            allow_whole_array_replace,
        } => apply_set_param(before, node, pointer, value, *allow_whole_array_replace),
        ValidatedMutationOp::UnsetParam {
            node,
            pointer,
            allow_whole_array_replace,
        } => apply_unset_param(before, node, pointer, *allow_whole_array_replace),
        ValidatedMutationOp::MoveNode { node, position } => {
            apply_move_node(before, node, *position)
        }
        ValidatedMutationOp::RenameNode { from, to } => apply_rename_node(before, from, to),
        ValidatedMutationOp::InsertBetween {
            after,
            before: target_before,
            branch,
            node,
        } => apply_insert_between(before, after, target_before, *branch, node),
        ValidatedMutationOp::RemoveNode { node, bridge } => {
            apply_remove_node(before, node, *bridge)
        }
        ValidatedMutationOp::SetEnabled { node, enabled } => {
            apply_set_enabled(before, node, *enabled)
        }
        ValidatedMutationOp::ConnectNodes {
            from,
            to,
            port,
            branch,
            index,
        } => apply_connect_nodes(before, from, to, port, *branch, *index),
        ValidatedMutationOp::AddNodeAndConnect {
            after,
            branch,
            node,
        } => apply_add_node_and_connect(before, after, *branch, node),
        ValidatedMutationOp::DisconnectNodes {
            from,
            to,
            port,
            branch,
        } => apply_disconnect_nodes(before, from, to, port, *branch),
        ValidatedMutationOp::BindCredential {
            node,
            credential_type,
            credential_id,
            credential_name,
            data,
        } => apply_bind_credential(
            before,
            node,
            credential_type,
            credential_id,
            credential_name.as_deref(),
            data.as_ref(),
        ),
        ValidatedMutationOp::UpgradeNodeVersion {
            node,
            target_version,
        } => apply_upgrade_node_version(before, node, target_version, catalog),
    }
}

fn finalize_applied(
    before: &WorkflowIr,
    after: WorkflowIr,
) -> (bool, Vec<String>, Vec<String>, WorkflowDiff) {
    let diff = WorkflowDiff::compute(before, &after, 4096);
    let mut added_edges = Vec::new();
    let mut removed_edges = Vec::new();
    for conn in &diff.connection_changes {
        let label = format!("{}->{}", conn.from_node, conn.to_node);
        match conn.change {
            ConnectionChangeKind::Added => added_edges.push(label),
            ConnectionChangeKind::Removed => removed_edges.push(label),
        }
    }
    let changed = diff.expected_version_hash != diff.after_version_hash;
    (changed, added_edges, removed_edges, diff)
}

fn parse_pointer_tokens(pointer: &str) -> Result<Vec<String>, &'static str> {
    if !pointer.starts_with('/') || pointer.len() < 2 {
        return Err("invalid_json_pointer");
    }
    Ok(pointer[1..]
        .split('/')
        .map(unescape_json_pointer_token)
        .collect())
}

fn apply_set_param(
    before: &WorkflowIr,
    node_name: &str,
    pointer: &str,
    value: &Value,
    allow_whole_array_replace: bool,
) -> ValidatedMutationOutcome {
    let Ok(tokens) = parse_pointer_tokens(pointer) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "invalid_json_pointer",
            format!("Invalid RFC 6901 JSON Pointer `{pointer}`: must start with `/`."),
        );
    };

    let root = &tokens[0];
    if PROTECTED_NODE_FIELDS.contains(&root.as_str()) {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("protected_node_field:/{root}"),
            format!("Direct set_param on protected node field `/{root}` is forbidden."),
        );
    }

    let mut after = before.clone();
    let Some(node_ir) = after.node_by_name_mut(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found in workflow."),
        );
    };

    let Ok(mut node_json) = serde_json::to_value(&*node_ir) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "serialization_error",
            "Failed to serialize target node.",
        );
    };

    let resolved = match set_json_pointer_guarded(
        &mut node_json,
        &tokens,
        pointer,
        value.clone(),
        allow_whole_array_replace,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return ValidatedMutationOutcome::rejected(before, code, msg),
    };

    let Ok(updated_node) = serde_json::from_value::<WorkflowNodeIr>(node_json) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "invalid_node_field_value",
            format!("Updated value at `{pointer}` violated node schema types."),
        );
    };
    *node_ir = updated_node;

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: Some(resolved),
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn set_json_pointer_guarded(
    root: &mut Value,
    tokens: &[String],
    full_pointer: &str,
    new_val: Value,
    allow_whole_array_replace: bool,
) -> Result<Value, (String, String)> {
    let mut current = root;
    for token in &tokens[..tokens.len() - 1] {
        match current {
            Value::Object(map) => {
                if !map.contains_key(token) {
                    map.insert(token.clone(), Value::Object(Map::new()));
                }
                current = map.get_mut(token).ok_or_else(|| {
                    (
                        "invalid_json_pointer".to_owned(),
                        format!("Cannot traverse `{token}`"),
                    )
                })?;
            }
            Value::Array(arr) => {
                let idx = token.parse::<usize>().map_err(|_| {
                    (
                        "invalid_json_pointer".to_owned(),
                        format!("Non-numeric array index `{token}` in `{full_pointer}`"),
                    )
                })?;
                if idx >= arr.len() {
                    return Err((
                        format!("array_index_out_of_bounds:{idx}"),
                        format!("Array index {idx} out of bounds (len {})", arr.len()),
                    ));
                }
                current = &mut arr[idx];
            }
            _ => {
                return Err((
                    "invalid_json_pointer".to_owned(),
                    format!("Cannot traverse scalar at `{token}` in `{full_pointer}`"),
                ));
            }
        }
    }

    let last = &tokens[tokens.len() - 1];
    match current {
        Value::Object(map) => {
            if let Some(existing) = map.get(last)
                && existing.is_array()
            {
                if !allow_whole_array_replace {
                    return Err((
                        format!("whole_array_replace_blocked:{full_pointer}"),
                        format!(
                            "Whole-array replacement at `{full_pointer}` requires `allowWholeArrayReplace: true`."
                        ),
                    ));
                }
                if !new_val.is_array() {
                    return Err((
                        format!("array_type_mismatch:{full_pointer}"),
                        format!("Replacing array at `{full_pointer}` requires an array value."),
                    ));
                }
            }
            map.insert(last.clone(), new_val.clone());
            Ok(new_val)
        }
        Value::Array(arr) => {
            if last == "-" {
                arr.push(new_val.clone());
                return Ok(new_val);
            }
            let idx = last.parse::<usize>().map_err(|_| {
                (
                    "invalid_json_pointer".to_owned(),
                    format!("Invalid array index `{last}` in `{full_pointer}`"),
                )
            })?;
            if idx >= arr.len() {
                return Err((
                    format!("array_index_out_of_bounds:{idx}"),
                    format!("Array index {idx} out of bounds (len {})", arr.len()),
                ));
            }
            if arr[idx].is_array() && !allow_whole_array_replace {
                return Err((
                    format!("whole_array_replace_blocked:{full_pointer}"),
                    format!("Whole-array replacement at `{full_pointer}` blocked."),
                ));
            }
            arr[idx] = new_val.clone();
            Ok(new_val)
        }
        _ => Err((
            "invalid_json_pointer".to_owned(),
            format!("Parent of `{last}` in `{full_pointer}` is neither object nor array"),
        )),
    }
}

fn apply_unset_param(
    before: &WorkflowIr,
    node_name: &str,
    pointer: &str,
    allow_whole_array_replace: bool,
) -> ValidatedMutationOutcome {
    let Ok(tokens) = parse_pointer_tokens(pointer) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "invalid_json_pointer",
            format!("Invalid RFC 6901 JSON Pointer `{pointer}`."),
        );
    };

    let root = &tokens[0];
    if PROTECTED_NODE_FIELDS.contains(&root.as_str()) {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("protected_node_field:/{root}"),
            format!("Cannot unset protected node field `/{root}`."),
        );
    }

    let mut after = before.clone();
    let Some(node_ir) = after.node_by_name_mut(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found in workflow."),
        );
    };

    let Ok(mut node_json) = serde_json::to_value(&*node_ir) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "serialization_error",
            "Failed to serialize target node.",
        );
    };

    let removed = match unset_json_pointer_guarded(
        &mut node_json,
        &tokens,
        pointer,
        allow_whole_array_replace,
    ) {
        Ok(r) => r,
        Err((code, msg)) => return ValidatedMutationOutcome::rejected(before, code, msg),
    };

    let Ok(updated_node) = serde_json::from_value::<WorkflowNodeIr>(node_json) else {
        return ValidatedMutationOutcome::rejected(
            before,
            "invalid_node_field_value",
            format!("Unsetting `{pointer}` produced an invalid node structure."),
        );
    };
    *node_ir = updated_node;

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed: changed || removed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: Some(removed),
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn unset_json_pointer_guarded(
    root: &mut Value,
    tokens: &[String],
    full_pointer: &str,
    allow_whole_array_replace: bool,
) -> Result<bool, (String, String)> {
    let mut current = root;
    for token in &tokens[..tokens.len() - 1] {
        match current {
            Value::Object(map) => {
                let Some(next) = map.get_mut(token) else {
                    return Ok(false);
                };
                current = next;
            }
            Value::Array(arr) => {
                let idx = token.parse::<usize>().map_err(|_| {
                    (
                        "invalid_json_pointer".to_owned(),
                        format!("Non-numeric array index `{token}` in `{full_pointer}`"),
                    )
                })?;
                if idx >= arr.len() {
                    return Err((
                        format!("array_index_out_of_bounds:{idx}"),
                        format!("Array index {idx} out of bounds"),
                    ));
                }
                current = &mut arr[idx];
            }
            _ => return Ok(false),
        }
    }

    let last = &tokens[tokens.len() - 1];
    match current {
        Value::Object(map) => {
            if let Some(existing) = map.get(last)
                && let Some(arr) = existing.as_array()
                && !arr.is_empty()
                && !allow_whole_array_replace
            {
                return Err((
                    format!("whole_array_replace_blocked:{full_pointer}"),
                    format!(
                        "Unsetting non-empty array `{full_pointer}` requires `allowWholeArrayReplace: true`."
                    ),
                ));
            }
            Ok(map.remove(last).is_some())
        }
        Value::Array(arr) => {
            let idx = last.parse::<usize>().map_err(|_| {
                (
                    "invalid_json_pointer".to_owned(),
                    format!("Invalid array index `{last}` in `{full_pointer}`"),
                )
            })?;
            if idx >= arr.len() {
                return Err((
                    format!("array_index_out_of_bounds:{idx}"),
                    format!("Array index {idx} out of bounds"),
                ));
            }
            arr.remove(idx);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn apply_move_node(
    before: &WorkflowIr,
    node_name: &str,
    position: [f64; 2],
) -> ValidatedMutationOutcome {
    let mut after = before.clone();
    let Some(node_ir) = after.node_by_name_mut(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found."),
        );
    };
    node_ir.position = position;

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: Some(position),
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_rename_node(before: &WorkflowIr, from: &str, to: &str) -> ValidatedMutationOutcome {
    if before.node_by_name(from).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{from}"),
            format!("Node `{from}` not found."),
        );
    }
    if to.trim().is_empty() {
        return ValidatedMutationOutcome::rejected(
            before,
            "empty_node_name",
            "Target node name cannot be empty or whitespace.",
        );
    }
    if from == to {
        let diff = WorkflowDiff::compute(before, before, 4096);
        return ValidatedMutationOutcome {
            status: MutationApplyStatus::Applied,
            changed: false,
            error_code: None,
            message: None,
            resolved_value: None,
            removed: None,
            position: None,
            disabled: None,
            connection_keys_renamed: Vec::new(),
            rewritten_expressions: Vec::new(),
            rewritten_count: 0,
            blocking_expressions: Vec::new(),
            added_edges: Vec::new(),
            removed_edges: Vec::new(),
            diff: Some(diff),
            updated_workflow: before.clone(),
        };
    }
    if before.node_by_name(to).is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("duplicate_node_name:{to}"),
            format!("A node named `{to}` already exists in this workflow."),
        );
    }

    // Pre-scan all parameters across the workflow for dynamic node references via AST.
    let mut blocking_expressions = Vec::new();
    for node in &before.nodes {
        collect_dynamic_hazards_in_value(
            &node.name,
            &node.parameters,
            "/parameters",
            &mut blocking_expressions,
        );
        if matches!(
            node.node_type.as_str(),
            "n8n-nodes-base.code" | "@n8n/n8n-nodes-langchain.toolCode"
        ) && let Some(js_code) = node.parameters.get("jsCode").and_then(Value::as_str)
        {
            let script_ast = analyze_js_code_script(js_code);
            if script_ast
                .references
                .iter()
                .any(|r| matches!(r.kind, ReferenceKind::DynamicNodeRef { .. }))
            {
                blocking_expressions.push(BlockingExpressionLocation {
                    node: node.name.clone(),
                    pointer: "/parameters/jsCode".to_owned(),
                });
            }
        }
    }

    if !blocking_expressions.is_empty() {
        return ValidatedMutationOutcome {
            status: MutationApplyStatus::ManualReviewRequired,
            changed: false,
            error_code: None,
            message: Some(format!(
                "Cannot automatically rename `{from}` -> `{to}`: {} dynamic node reference(s) require manual review.",
                blocking_expressions.len()
            )),
            resolved_value: None,
            removed: None,
            position: None,
            disabled: None,
            connection_keys_renamed: Vec::new(),
            rewritten_expressions: Vec::new(),
            rewritten_count: 0,
            blocking_expressions,
            added_edges: Vec::new(),
            removed_edges: Vec::new(),
            diff: None,
            updated_workflow: before.clone(),
        };
    }

    let mut after = before.clone();
    let mut rewritten_expressions = Vec::new();

    // Rewrite AST-verified literal node references across all nodes.
    for node in &mut after.nodes {
        let current_node_label = if node.name == from {
            to.to_owned()
        } else {
            node.name.clone()
        };
        rewrite_value_literals_recursive(
            &current_node_label,
            &mut node.parameters,
            "/parameters",
            from,
            to,
            &mut rewritten_expressions,
        );
    }

    if let Some(target_node) = after.node_by_name_mut(from) {
        target_node.name = to.to_owned();
    }

    let mut connection_keys_renamed = Vec::new();
    let mut updated_connections = indexmap::IndexMap::with_capacity(after.connections.len());
    for (src_key, mut port_map) in after.connections {
        let next_src = if src_key == from {
            connection_keys_renamed.push(format!("{from}->{to}"));
            to.to_owned()
        } else {
            src_key
        };
        for branches in port_map.values_mut() {
            for branch in branches {
                for edge in branch {
                    if edge.node == from {
                        edge.node = to.to_owned();
                    }
                }
            }
        }
        updated_connections.insert(next_src, port_map);
    }
    after.connections = updated_connections;

    if let Some(pin_map) = &mut after.pin_data {
        let mut next_pins = indexmap::IndexMap::with_capacity(pin_map.len());
        for (k, v) in pin_map.drain(..) {
            let next_k = if k == from { to.to_owned() } else { k };
            next_pins.insert(next_k, v);
        }
        *pin_map = next_pins;
    }

    let rewritten_count = rewritten_expressions.len();
    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed,
        rewritten_expressions,
        rewritten_count,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn collect_dynamic_hazards_in_value(
    node_name: &str,
    val: &Value,
    pointer: &str,
    out: &mut Vec<BlockingExpressionLocation>,
) {
    match val {
        Value::String(s) if s.starts_with('=') => {
            let analysis = analyze_template_expression(s);
            if !analysis.dynamic_references.is_empty() {
                out.push(BlockingExpressionLocation {
                    node: node_name.to_owned(),
                    pointer: pointer.to_owned(),
                });
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let escaped = escape_json_pointer_token(k);
                let next_ptr = format!("{pointer}/{escaped}");
                collect_dynamic_hazards_in_value(node_name, child, &next_ptr, out);
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                let next_ptr = format!("{pointer}/{idx}");
                collect_dynamic_hazards_in_value(node_name, child, &next_ptr, out);
            }
        }
        _ => {}
    }
}

fn rewrite_value_literals_recursive(
    node_name: &str,
    val: &mut Value,
    pointer: &str,
    from: &str,
    to: &str,
    rewritten: &mut Vec<RewrittenExpressionEntry>,
) {
    match val {
        Value::String(s) if s.starts_with('=') => {
            if let Ok(outcome) = rewrite_literal_node_references(s, from, to)
                && outcome.changed
            {
                let before_str = s.clone();
                *s = outcome.rewritten.clone();
                rewritten.push(RewrittenExpressionEntry {
                    node: node_name.to_owned(),
                    pointer: pointer.to_owned(),
                    before: before_str,
                    after: outcome.rewritten,
                });
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let escaped = escape_json_pointer_token(k);
                let next_ptr = format!("{pointer}/{escaped}");
                rewrite_value_literals_recursive(node_name, child, &next_ptr, from, to, rewritten);
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter_mut().enumerate() {
                let next_ptr = format!("{pointer}/{idx}");
                rewrite_value_literals_recursive(node_name, child, &next_ptr, from, to, rewritten);
            }
        }
        _ => {}
    }
}

fn apply_insert_between(
    before: &WorkflowIr,
    after_node: &str,
    before_node: &str,
    branch: usize,
    new_node: &WorkflowNodeIr,
) -> ValidatedMutationOutcome {
    if before.node_by_name(after_node).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{after_node}"),
            format!("Node `{after_node}` not found."),
        );
    }
    if before.node_by_name(before_node).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{before_node}"),
            format!("Node `{before_node}` not found."),
        );
    }
    if before.node_by_name(&new_node.name).is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("duplicate_node_name:{}", new_node.name),
            format!("Node `{}` already exists.", new_node.name),
        );
    }
    if before.node_by_id(&new_node.id).is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("duplicate_node_id:{}", new_node.id),
            format!("Node id `{}` already exists.", new_node.id),
        );
    }

    let mut after = before.clone();
    let existing_target_idx = after
        .connections
        .get_mut(after_node)
        .and_then(|pm| pm.get_mut(&PortKind::Main))
        .and_then(|branches| branches.get_mut(branch))
        .and_then(|edges| {
            let pos = edges.iter().position(|e| e.node == before_node)?;
            let removed = edges.remove(pos);
            Some((edges, removed.index))
        });

    let Some((src_edges, original_input_idx)) = existing_target_idx else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("edge_not_found:{after_node}->{before_node}"),
            format!(
                "Direct edge `{after_node} -> {before_node}` on branch {branch} does not exist."
            ),
        );
    };

    src_edges.push(ConnectionEdgeIr::new(
        new_node.name.clone(),
        PortKind::Main,
        0,
    ));

    after
        .connections
        .entry(new_node.name.clone())
        .or_default()
        .entry(PortKind::Main)
        .or_default()
        .push(vec![ConnectionEdgeIr::new(
            before_node.to_owned(),
            PortKind::Main,
            original_input_idx,
        )]);

    after.nodes.push(new_node.clone());

    let (changed, _sorted_added, removed_edges, diff) = finalize_applied(before, after.clone());
    let added_edges = vec![
        format!("{after_node}->{}", new_node.name),
        format!("{}->{before_node}", new_node.name),
    ];
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_remove_node(
    before: &WorkflowIr,
    node_name: &str,
    bridge: bool,
) -> ValidatedMutationOutcome {
    if before.node_by_name(node_name).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found."),
        );
    }

    // Guard against leaving dangling `$('Removed')` expression references on remaining nodes.
    for other in &before.nodes {
        if other.name == node_name {
            continue;
        }
        if value_references_target_node(&other.parameters, node_name) {
            return ValidatedMutationOutcome::rejected(
                before,
                format!("dangling_expression_reference:{}->{node_name}", other.name),
                format!(
                    "Cannot remove `{node_name}`: downstream node `{}` still references it in an expression.",
                    other.name
                ),
            );
        }
    }

    let mut after = before.clone();
    let outgoing_main_zero: Vec<ConnectionEdgeIr> = if bridge {
        after
            .connections
            .get(node_name)
            .and_then(|pm| pm.get(&PortKind::Main))
            .and_then(|b| b.first())
            .map_or_else(Vec::new, Clone::clone)
    } else {
        Vec::new()
    };

    after.nodes.retain(|n| n.name != node_name);
    after.connections.shift_remove(node_name);

    for port_map in after.connections.values_mut() {
        for (port_key, branches) in port_map.iter_mut() {
            for branch_edges in branches {
                if bridge && *port_key == PortKind::Main {
                    let mut next_edges = Vec::new();
                    for edge in branch_edges.drain(..) {
                        if edge.node == node_name {
                            for bridged in &outgoing_main_zero {
                                if !next_edges.iter().any(|e: &ConnectionEdgeIr| {
                                    e.node == bridged.node && e.index == bridged.index
                                }) {
                                    next_edges.push(bridged.clone());
                                }
                            }
                        } else {
                            next_edges.push(edge);
                        }
                    }
                    *branch_edges = next_edges;
                } else {
                    branch_edges.retain(|e| e.node != node_name);
                }
            }
        }
    }
    after.connections.retain(|_, pm| {
        pm.values()
            .any(|branches| branches.iter().any(|b| !b.is_empty()))
    });

    if let Some(pins) = &mut after.pin_data {
        pins.shift_remove(node_name);
    }

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn value_references_target_node(val: &Value, target: &str) -> bool {
    match val {
        Value::String(s) if s.starts_with('=') => {
            let analysis = analyze_template_expression(s);
            analysis.referenced_nodes.iter().any(|n| n == target)
        }
        Value::Object(map) => map
            .values()
            .any(|v| value_references_target_node(v, target)),
        Value::Array(items) => items
            .iter()
            .any(|v| value_references_target_node(v, target)),
        _ => false,
    }
}

fn apply_set_enabled(
    before: &WorkflowIr,
    node_name: &str,
    enabled: bool,
) -> ValidatedMutationOutcome {
    let mut after = before.clone();
    let Some(node_ir) = after.node_by_name_mut(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found."),
        );
    };
    let next_disabled = !enabled;
    node_ir.disabled = next_disabled;

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: Some(next_disabled),
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_connect_nodes(
    before: &WorkflowIr,
    from: &str,
    to: &str,
    port: &str,
    branch: usize,
    index: usize,
) -> ValidatedMutationOutcome {
    if before.node_by_name(from).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{from}"),
            format!("Source node `{from}` not found."),
        );
    }
    if before.node_by_name(to).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{to}"),
            format!("Target node `{to}` not found."),
        );
    }

    let mut after = before.clone();
    let port_kind = PortKind::from_wire(port);

    let branches = after
        .connections
        .entry(from.to_owned())
        .or_default()
        .entry(port_kind.clone())
        .or_default();
    while branches.len() <= branch {
        branches.push(Vec::new());
    }
    let edge = ConnectionEdgeIr::new(to.to_owned(), port_kind, index);
    if !branches[branch]
        .iter()
        .any(|e| e.node == edge.node && e.index == edge.index && e.port_type == edge.port_type)
    {
        branches[branch].push(edge);
    }

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_add_node_and_connect(
    before: &WorkflowIr,
    after_node: &str,
    branch: usize,
    new_node: &WorkflowNodeIr,
) -> ValidatedMutationOutcome {
    if before.node_by_name(after_node).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{after_node}"),
            format!("Source node `{after_node}` not found."),
        );
    }
    if before.node_by_name(&new_node.name).is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("duplicate_node_name:{}", new_node.name),
            format!("Node `{}` already exists.", new_node.name),
        );
    }
    if before.node_by_id(&new_node.id).is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("duplicate_node_id:{}", new_node.id),
            format!("Node id `{}` already exists.", new_node.id),
        );
    }

    let mut after = before.clone();
    after.nodes.push(new_node.clone());
    let branches = after
        .connections
        .entry(after_node.to_owned())
        .or_default()
        .entry(PortKind::Main)
        .or_default();
    while branches.len() <= branch {
        branches.push(Vec::new());
    }
    branches[branch].push(ConnectionEdgeIr::new(
        new_node.name.clone(),
        PortKind::Main,
        0,
    ));

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_disconnect_nodes(
    before: &WorkflowIr,
    from: &str,
    to: &str,
    port: &str,
    branch: usize,
) -> ValidatedMutationOutcome {
    if before.node_by_name(from).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{from}"),
            format!("Source node `{from}` not found."),
        );
    }
    if before.node_by_name(to).is_none() {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{to}"),
            format!("Target node `{to}` not found."),
        );
    }

    let mut after = before.clone();
    let port_kind = PortKind::from_wire(port);
    if let Some(pm) = after.connections.get_mut(from)
        && let Some(branches) = pm.get_mut(&port_kind)
        && let Some(edges) = branches.get_mut(branch)
    {
        edges.retain(|e| e.node != to);
    }
    after.connections.retain(|_, pm| {
        pm.values()
            .any(|branches| branches.iter().any(|b| !b.is_empty()))
    });

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_bind_credential(
    before: &WorkflowIr,
    node_name: &str,
    credential_type: &str,
    credential_id: &str,
    credential_name: Option<&str>,
    secret_data: Option<&Value>,
) -> ValidatedMutationOutcome {
    if secret_data.is_some() {
        return ValidatedMutationOutcome::rejected(
            before,
            "secret_material_forbidden_in_workflow_mutation",
            "Credential secret payloads are strictly forbidden inside workflow graph mutations; bind by `credentialId` + `credentialName` metadata only.",
        );
    }

    let mut after = before.clone();
    let Some(node_ir) = after.node_by_name_mut(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found."),
        );
    };

    node_ir
        .credentials
        .get_or_insert_with(indexmap::IndexMap::new)
        .insert(
            credential_type.to_owned(),
            NodeCredentialRef::new(credential_id, credential_name.unwrap_or_default()),
        );

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: None,
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}

fn apply_upgrade_node_version(
    before: &WorkflowIr,
    node_name: &str,
    target_version: &Value,
    catalog: Option<&CatalogDb>,
) -> ValidatedMutationOutcome {
    let Some(existing_node) = before.node_by_name(node_name) else {
        return ValidatedMutationOutcome::rejected(
            before,
            format!("node_not_found:{node_name}"),
            format!("Node `{node_name}` not found."),
        );
    };

    if json_values_equal(&existing_node.type_version, target_version) {
        let diff = WorkflowDiff::compute(before, before, 4096);
        return ValidatedMutationOutcome {
            status: MutationApplyStatus::Applied,
            changed: false,
            error_code: None,
            message: None,
            resolved_value: Some(target_version.clone()),
            removed: None,
            position: None,
            disabled: None,
            connection_keys_renamed: Vec::new(),
            rewritten_expressions: Vec::new(),
            rewritten_count: 0,
            blocking_expressions: Vec::new(),
            added_edges: Vec::new(),
            removed_edges: Vec::new(),
            diff: Some(diff),
            updated_workflow: before.clone(),
        };
    }

    let current_str = existing_node.type_version_string();
    let target_str = match target_version {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };

    let version_supported = catalog
        .and_then(|db| {
            db.get_node_info(&NodeInfoRequest {
                node_type: existing_node.node_type.clone(),
                mode: NodeInfoMode::Versions,
                type_version: Some(target_str.clone()),
                property_query: None,
            })
            .ok()
        })
        .is_some_and(|info| info.found_in_catalog && info.version_in_catalog);

    if !version_supported {
        return ValidatedMutationOutcome::rejected(
            before,
            format!(
                "migration_missing:{}:{current_str}->{target_str}",
                existing_node.node_type
            ),
            format!(
                "No deterministic parameter migration registered for `{}` `{current_str} -> {target_str}`.",
                existing_node.node_type
            ),
        );
    }

    let mut after = before.clone();
    if let Some(node_ir) = after.node_by_name_mut(node_name) {
        node_ir.type_version = target_version.clone();
    }

    let (changed, added_edges, removed_edges, diff) = finalize_applied(before, after.clone());
    ValidatedMutationOutcome {
        status: MutationApplyStatus::Applied,
        changed,
        error_code: None,
        message: None,
        resolved_value: Some(target_version.clone()),
        removed: None,
        position: None,
        disabled: None,
        connection_keys_renamed: Vec::new(),
        rewritten_expressions: Vec::new(),
        rewritten_count: 0,
        blocking_expressions: Vec::new(),
        added_edges,
        removed_edges,
        diff: Some(diff),
        updated_workflow: after,
    }
}
