//! Semantic [`WorkflowDiff`], RFC 6902 [`JsonPatchOp`] generator, and `similar` bounded redacted
//! unified diff summaries (V2 Section 7).

use std::collections::{BTreeSet, HashMap};

use n8n_types::{BoundedDiffSummary, N8nError, N8nResult, redact_json_value, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_path::JsonPath;
use similar::TextDiff;

use crate::ir::{PortKind, WorkflowIr, WorkflowNodeIr};
use crate::topology::is_any_trigger_type;

/// Default character limit for unified diff text previews.
pub const DEFAULT_DIFF_MAX_CHARS: usize = 8_192;

/// Maximum JSONPath expression length accepted from untrusted callers.
const MAX_JSONPATH_EXPR_BYTES: usize = 2_048;

/// RFC 6902 JSON Patch operation emitted inside [`WorkflowDiff`] (all values pre-redacted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum JsonPatchOp {
    Add { path: String, value: Value },
    Remove { path: String },
    Replace { path: String, value: Value },
}

/// Summary of an added or removed workflow node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeDiffEntry {
    pub id: String,
    pub name: String,
    pub node_type: String,
}

/// Semantic summary of a modified workflow node (matched by stable `id` across renames).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModifiedNodeDiff {
    pub id: String,
    pub before_name: String,
    pub after_name: String,
    pub node_type: String,
    pub changed_fields: Vec<String>,
    pub parameter_patch: Vec<JsonPatchOp>,
}

/// Whether a connection edge was added or removed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionChangeKind {
    Added,
    Removed,
}

/// Directed connection edge change between two workflow versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDiffEntry {
    pub change: ConnectionChangeKind,
    pub from_node: String,
    pub to_node: String,
    pub port_kind: PortKind,
    pub output_index: usize,
    pub input_index: usize,
}

/// Complete redacted semantic diff between two [`WorkflowIr`] states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowDiff {
    pub expected_version_hash: String,
    pub after_version_hash: String,
    pub diff_summary: BoundedDiffSummary,
    pub json_patch: Vec<JsonPatchOp>,
    pub added_nodes: Vec<NodeDiffEntry>,
    pub removed_nodes: Vec<NodeDiffEntry>,
    pub modified_nodes: Vec<ModifiedNodeDiff>,
    pub connection_changes: Vec<ConnectionDiffEntry>,
    pub risk_flags: Vec<String>,
}

impl WorkflowDiff {
    /// Computes a full semantic, RFC 6902 JSON Patch, and bounded unified diff with recursive secret redaction.
    #[must_use]
    pub fn compute(before: &WorkflowIr, after: &WorkflowIr, max_summary_chars: usize) -> Self {
        let expected_version_hash = before.canonical_version_hash();
        let after_version_hash = after.canonical_version_hash();

        let before_raw = before.to_json_value().unwrap_or(Value::Null);
        let after_raw = after.to_json_value().unwrap_or(Value::Null);

        let before_redacted = redact_json_value(&before_raw);
        let after_redacted = redact_json_value(&after_raw);

        let json_patch = compute_redacted_json_patch(&before_redacted, &after_redacted);

        let (added_nodes, removed_nodes, modified_nodes, node_risk_flags) =
            diff_nodes(before, after);
        let connection_changes = diff_connections(before, after);

        let mut risk_set: BTreeSet<String> = node_risk_flags.into_iter().collect();
        if before.active || after.active {
            risk_set.insert("ACTIVE_WORKFLOW_TARGET".to_owned());
        }
        if before.active != after.active {
            risk_set.insert("ACTIVE_STATE_CHANGED".to_owned());
        }
        if !removed_nodes.is_empty() {
            risk_set.insert("NODE_REMOVED".to_owned());
        }
        if before.settings != after.settings {
            risk_set.insert("WORKFLOW_SETTINGS_CHANGED".to_owned());
        }
        if connection_changes
            .iter()
            .any(|c| c.change == ConnectionChangeKind::Removed && c.port_kind == PortKind::Error)
        {
            risk_set.insert("ERROR_HANDLING_REDUCED".to_owned());
        }

        let mut changed_node_names = BTreeSet::new();
        for n in &added_nodes {
            changed_node_names.insert(n.name.clone());
        }
        for n in &removed_nodes {
            changed_node_names.insert(n.name.clone());
        }
        for n in &modified_nodes {
            changed_node_names.insert(n.after_name.clone());
        }

        let before_pretty = serde_json::to_string_pretty(&before_redacted).unwrap_or_default();
        let after_pretty = serde_json::to_string_pretty(&after_redacted).unwrap_or_default();
        let mut diff_summary =
            compute_text_diff_summary(&before_pretty, &after_pretty, max_summary_chars);
        diff_summary.changed_nodes = changed_node_names
            .into_iter()
            .map(|n| redact_str(&n))
            .collect();

        Self {
            expected_version_hash,
            after_version_hash,
            diff_summary,
            json_patch,
            added_nodes,
            removed_nodes,
            modified_nodes,
            connection_changes,
            risk_flags: risk_set.into_iter().collect(),
        }
    }
}

/// Computes a bounded unified diff summary between two serialized workflow representations,
/// scrubbing secrets both before diffing and on the final clipped output.
#[must_use]
pub fn compute_text_diff_summary(
    before: &str,
    after: &str,
    max_chars: usize,
) -> BoundedDiffSummary {
    let safe_before = redact_str(before);
    let safe_after = redact_str(after);
    let diff = TextDiff::from_lines(&safe_before, &safe_after);
    let unified = diff.unified_diff().header("before", "after").to_string();
    let char_count = unified.chars().count();
    let truncated = char_count > max_chars;
    let clipped = if truncated {
        unified.chars().take(max_chars).collect::<String>()
    } else {
        unified
    };
    BoundedDiffSummary::redacted(clipped, Vec::new(), truncated)
}

/// Generates redacted RFC 6902 JSON Patch operations transforming `before` into `after`.
#[must_use]
pub fn compute_redacted_json_patch(before: &Value, after: &Value) -> Vec<JsonPatchOp> {
    let safe_before = redact_json_value(before);
    let safe_after = redact_json_value(after);
    let mut ops = Vec::new();
    diff_json_recursive(&safe_before, &safe_after, "", &mut ops);
    ops
}

/// Escapes a single RFC 6901 JSON Pointer reference token (`~` -> `~0`, `/` -> `~1`).
#[must_use]
pub fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Unescapes a single RFC 6901 JSON Pointer reference token (`~1` -> `/`, `~0` -> `~`).
#[must_use]
pub fn unescape_json_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn diff_json_recursive(before: &Value, after: &Value, path: &str, out: &mut Vec<JsonPatchOp>) {
    if before == after {
        return;
    }

    match (before, after) {
        (Value::Object(b_map), Value::Object(a_map)) => {
            for (k, b_val) in b_map {
                let child_path = format!("{path}/{}", escape_json_pointer_token(k));
                match a_map.get(k) {
                    Some(a_val) => diff_json_recursive(b_val, a_val, &child_path, out),
                    None => out.push(JsonPatchOp::Remove { path: child_path }),
                }
            }
            for (k, a_val) in a_map {
                if !b_map.contains_key(k) {
                    let child_path = format!("{path}/{}", escape_json_pointer_token(k));
                    out.push(JsonPatchOp::Add {
                        path: child_path,
                        value: a_val.clone(),
                    });
                }
            }
        }
        (Value::Array(b_arr), Value::Array(a_arr)) => {
            let shared_len = b_arr.len().min(a_arr.len());
            for idx in 0..shared_len {
                let child_path = format!("{path}/{idx}");
                diff_json_recursive(&b_arr[idx], &a_arr[idx], &child_path, out);
            }
            if a_arr.len() > b_arr.len() {
                for (idx, item) in a_arr.iter().enumerate().skip(shared_len) {
                    out.push(JsonPatchOp::Add {
                        path: format!("{path}/{idx}"),
                        value: item.clone(),
                    });
                }
            } else if b_arr.len() > a_arr.len() {
                // Emit removals in reverse index order per RFC 6902 sequential array application rules!
                for idx in (shared_len..b_arr.len()).rev() {
                    out.push(JsonPatchOp::Remove {
                        path: format!("{path}/{idx}"),
                    });
                }
            }
        }
        _ => {
            out.push(JsonPatchOp::Replace {
                path: path.to_owned(),
                value: after.clone(),
            });
        }
    }
}

fn node_identity_key(node: &WorkflowNodeIr) -> String {
    if node.id.is_empty() {
        format!("name:{}", node.name)
    } else {
        format!("id:{}", node.id)
    }
}

fn is_side_effect_node_type(node_type: &str) -> bool {
    let short = node_type
        .rsplit('.')
        .next()
        .unwrap_or(node_type)
        .to_ascii_lowercase();
    matches!(
        short.as_str(),
        "executecommand"
            | "readwritefile"
            | "writebinaryfile"
            | "httprequest"
            | "postgres"
            | "mysql"
            | "mongodb"
            | "redis"
            | "slack"
            | "microsoftteams"
            | "discord"
            | "emailsend"
            | "gmail"
            | "stripe"
            | "ssh"
            | "ftp"
            | "s3"
            | "executeworkflow"
    )
}

fn is_code_node_type(node_type: &str) -> bool {
    let short = node_type
        .rsplit('.')
        .next()
        .unwrap_or(node_type)
        .to_ascii_lowercase();
    matches!(short.as_str(), "code" | "function" | "functionitem")
}

fn diff_nodes(
    before: &WorkflowIr,
    after: &WorkflowIr,
) -> (
    Vec<NodeDiffEntry>,
    Vec<NodeDiffEntry>,
    Vec<ModifiedNodeDiff>,
    Vec<String>,
) {
    let mut before_by_key: HashMap<String, &WorkflowNodeIr> =
        HashMap::with_capacity(before.nodes.len());
    for n in &before.nodes {
        before_by_key.insert(node_identity_key(n), n);
    }

    let mut after_by_key: HashMap<String, &WorkflowNodeIr> =
        HashMap::with_capacity(after.nodes.len());
    for n in &after.nodes {
        after_by_key.insert(node_identity_key(n), n);
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut risks = Vec::new();

    for a_node in &after.nodes {
        let key = node_identity_key(a_node);
        if let Some(&b_node) = before_by_key.get(&key) {
            if b_node != a_node {
                let mut changed_fields = Vec::new();
                if b_node.name != a_node.name {
                    changed_fields.push("name".to_owned());
                }
                if b_node.node_type != a_node.node_type {
                    changed_fields.push("type".to_owned());
                }
                if b_node.type_version != a_node.type_version {
                    changed_fields.push("typeVersion".to_owned());
                }
                if b_node.position != a_node.position {
                    changed_fields.push("position".to_owned());
                }
                if b_node.disabled != a_node.disabled {
                    changed_fields.push("disabled".to_owned());
                }
                if b_node.credentials != a_node.credentials {
                    changed_fields.push("credentials".to_owned());
                    risks.push("CREDENTIAL_BINDING_CHANGED".to_owned());
                }
                if b_node.retry_on_fail != a_node.retry_on_fail
                    || b_node.max_tries != a_node.max_tries
                    || b_node.wait_between_tries != a_node.wait_between_tries
                    || b_node.on_error != a_node.on_error
                    || b_node.continue_on_fail != a_node.continue_on_fail
                    || b_node.execute_once != a_node.execute_once
                    || b_node.always_output_data != a_node.always_output_data
                {
                    changed_fields.push("reliability".to_owned());
                    if b_node.has_local_error_handling() && !a_node.has_local_error_handling() {
                        risks.push("ERROR_HANDLING_REDUCED".to_owned());
                    }
                }
                if b_node.notes != a_node.notes || b_node.notes_in_flow != a_node.notes_in_flow {
                    changed_fields.push("notes".to_owned());
                }
                if b_node.webhook_id != a_node.webhook_id {
                    changed_fields.push("webhookId".to_owned());
                }
                if b_node.extra != a_node.extra {
                    changed_fields.push("extra".to_owned());
                }

                let parameter_patch = if b_node.parameters != a_node.parameters {
                    changed_fields.push("parameters".to_owned());
                    compute_redacted_json_patch(&b_node.parameters, &a_node.parameters)
                } else {
                    Vec::new()
                };

                if is_any_trigger_type(&a_node.node_type) || is_any_trigger_type(&b_node.node_type)
                {
                    risks.push("TRIGGER_MODIFIED".to_owned());
                }
                if (is_side_effect_node_type(&a_node.node_type)
                    || is_side_effect_node_type(&b_node.node_type))
                    && (b_node.parameters != a_node.parameters
                        || b_node.credentials != a_node.credentials
                        || b_node.disabled != a_node.disabled)
                {
                    risks.push("SIDE_EFFECT_NODE_ADDED_OR_MODIFIED".to_owned());
                }
                if is_code_node_type(&a_node.node_type) && b_node.parameters != a_node.parameters {
                    risks.push("CODE_NODE_ADDED_OR_MODIFIED".to_owned());
                }

                modified.push(ModifiedNodeDiff {
                    id: a_node.id.clone(),
                    before_name: redact_str(&b_node.name),
                    after_name: redact_str(&a_node.name),
                    node_type: a_node.node_type.clone(),
                    changed_fields,
                    parameter_patch,
                });
            }
        } else {
            if is_any_trigger_type(&a_node.node_type) {
                risks.push("TRIGGER_MODIFIED".to_owned());
            }
            if is_side_effect_node_type(&a_node.node_type) {
                risks.push("SIDE_EFFECT_NODE_ADDED_OR_MODIFIED".to_owned());
            }
            if is_code_node_type(&a_node.node_type) {
                risks.push("CODE_NODE_ADDED_OR_MODIFIED".to_owned());
            }
            if a_node.credentials.as_ref().is_some_and(|c| !c.is_empty()) {
                risks.push("CREDENTIAL_BINDING_CHANGED".to_owned());
            }
            added.push(NodeDiffEntry {
                id: a_node.id.clone(),
                name: redact_str(&a_node.name),
                node_type: a_node.node_type.clone(),
            });
        }
    }

    for b_node in &before.nodes {
        let key = node_identity_key(b_node);
        if !after_by_key.contains_key(&key) {
            if is_any_trigger_type(&b_node.node_type) {
                risks.push("TRIGGER_MODIFIED".to_owned());
            }
            removed.push(NodeDiffEntry {
                id: b_node.id.clone(),
                name: redact_str(&b_node.name),
                node_type: b_node.node_type.clone(),
            });
        }
    }

    (added, removed, modified, risks)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalEdgeKey {
    from_node: String,
    port_wire: String,
    output_index: usize,
    to_node: String,
    input_index: usize,
}

fn collect_edge_set(ir: &WorkflowIr) -> BTreeSet<CanonicalEdgeKey> {
    let mut set = BTreeSet::new();
    for (src, port_map) in &ir.connections {
        for (port_kind, branches) in port_map {
            for (out_idx, branch) in branches.iter().enumerate() {
                for edge in branch {
                    set.insert(CanonicalEdgeKey {
                        from_node: src.clone(),
                        port_wire: port_kind.as_wire().to_owned(),
                        output_index: out_idx,
                        to_node: edge.node.clone(),
                        input_index: edge.index,
                    });
                }
            }
        }
    }
    set
}

fn diff_connections(before: &WorkflowIr, after: &WorkflowIr) -> Vec<ConnectionDiffEntry> {
    let before_edges = collect_edge_set(before);
    let after_edges = collect_edge_set(after);
    let mut changes = Vec::new();

    for removed_edge in before_edges.difference(&after_edges) {
        changes.push(ConnectionDiffEntry {
            change: ConnectionChangeKind::Removed,
            from_node: redact_str(&removed_edge.from_node),
            to_node: redact_str(&removed_edge.to_node),
            port_kind: PortKind::from_wire(&removed_edge.port_wire),
            output_index: removed_edge.output_index,
            input_index: removed_edge.input_index,
        });
    }
    for added_edge in after_edges.difference(&before_edges) {
        changes.push(ConnectionDiffEntry {
            change: ConnectionChangeKind::Added,
            from_node: redact_str(&added_edge.from_node),
            to_node: redact_str(&added_edge.to_node),
            port_kind: PortKind::from_wire(&added_edge.port_wire),
            output_index: added_edge.output_index,
            input_index: added_edge.input_index,
        });
    }
    changes
}

/// Evaluates a bounded JSONPath query against a workflow JSON value.
pub fn query_workflow_json_path<'a>(doc: &'a Value, expr: &str) -> N8nResult<Vec<&'a Value>> {
    if expr.len() > MAX_JSONPATH_EXPR_BYTES {
        return Err(N8nError::validation(
            "local",
            vec!["JSONPath expression exceeds maximum length".to_owned()],
            "JSONPath expression too long",
        ));
    }
    let compiled = JsonPath::parse(expr)
        .map_err(|e| N8nError::validation("local", vec![], format!("invalid JSONPath: {e}")))?;
    Ok(compiled.query(doc).all())
}
