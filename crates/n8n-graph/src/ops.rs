//! All 16 V2 Section 7 workflow graph mutation operations, strict invariants, RFC 6901 JSON Pointer
//! array-index fallback detection, unified/exact text patching, safe literal vs dynamic node rename
//! rewriting, selective `AutoLayout`, n8n 2.41+ `nodeGroups` validation, and explicit
//! `VersionMigrationTransform` gating.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use indexmap::IndexMap;
use n8n_types::{redact_json_value, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::diff::{
    DEFAULT_DIFF_MAX_CHARS, WorkflowDiff, escape_json_pointer_token, unescape_json_pointer_token,
};
use crate::ir::{
    ConnectionEdgeIr, NodeCredentialRef, NodeGroupIr, PortKind, WorkflowIr, WorkflowNodeIr,
};
use crate::topology::{
    TopologyAnalysis, WorkflowGraph, is_ai_subnode_provider_type, is_canvas_annotation_type,
};

/// Maximum size in bytes accepted for `PatchTextField` inputs/targets (1 MiB).
pub const MAX_TEXT_PATCH_BYTES: usize = 1_048_576;

/// 16 surgical workflow graph mutation operations (V2 Section 7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GraphMutationOp {
    SetParams {
        node_name: String,
        pointer: String,
        value: Value,
    },
    UnsetParams {
        node_name: String,
        pointer: String,
    },
    PatchTextField {
        node_name: String,
        pointer: String,
        #[serde(default)]
        before: String,
        #[serde(default)]
        after: String,
        /// Optional unified diff hunk (`@@ ... @@` or context/`-`/`+` lines) when applying unified patches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unified_hunk: Option<String>,
        /// When `true`, replaces all exact occurrences of `before`; when `false` (default), refuses ambiguous multi-matches.
        #[serde(default)]
        replace_all: bool,
    },
    ConfigureReliability {
        node_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_on_fail: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_tries: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_between_tries_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        on_error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continue_on_fail: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execute_once: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        always_output_data: Option<bool>,
    },
    BindCredential {
        node_name: String,
        credential_type: String,
        credential_id: String,
        credential_name: String,
    },
    AddNode {
        node: Value,
    },
    RemoveNode {
        node_name: String,
    },
    RenameNode {
        old_name: String,
        new_name: String,
    },
    InsertNodeBetween {
        upstream: String,
        downstream: String,
        node: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port_kind: Option<PortKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_index: Option<usize>,
    },
    RemoveNodeBridge {
        node_name: String,
    },
    Connect {
        from_node: String,
        to_node: String,
        output_index: usize,
        input_index: usize,
        #[serde(default)]
        port_kind: PortKind,
    },
    Disconnect {
        from_node: String,
        to_node: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port_kind: Option<PortKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_index: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_index: Option<usize>,
    },
    Rewire {
        from_node: String,
        old_target: String,
        new_target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port_kind: Option<PortKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_index: Option<usize>,
    },
    AutoLayout {
        node_names: Vec<String>,
    },
    SetNodeGroups {
        groups: Value,
    },
    UpgradeNodeVersion {
        node_name: String,
        target_version: String,
    },
}

/// Hazard descriptor when an expression uses dynamic/computed node references that cannot be safely rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DynamicReferenceHazard {
    pub node_name: String,
    pub parameter_pointer: String,
    pub expression_snippet: String,
}

/// Safety classification emitted for `RenameNode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RenameSafety {
    SafeLiteralRewrites {
        rewritten_locations: Vec<String>,
    },
    ManualReviewRequired {
        hazards: Vec<DynamicReferenceHazard>,
    },
}

/// Whole-array replacement fallback metadata when `SetParams` or `UnsetParams` touches an array index
/// (since native MCP `setNodeParameter` does not support array indices).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WholeArrayFallback {
    pub node_name: String,
    pub array_pointer: String,
    pub updated_array_redacted: Value,
}

/// Per-operation outcome recorded in a [`MutationPlan`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppliedOpOutcome {
    pub op_index: usize,
    pub op_kind: String,
    pub requires_whole_array_or_api_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whole_array_fallback: Option<WholeArrayFallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename_safety: Option<RenameSafety>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Complete dry-run / commit plan produced by [`plan_mutations`] and [`apply_mutations`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MutationPlan {
    pub plan_id: String,
    pub expected_version_hash: String,
    pub resulting_version_hash: String,
    pub requires_whole_array_or_api_fallback: bool,
    pub approval_required: bool,
    pub operation_outcomes: Vec<AppliedOpOutcome>,
    pub workflow_diff: WorkflowDiff,
    pub topology_after: TopologyAnalysis,
}

/// Structured fail-closed error hierarchy for workflow graph mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum GraphMutationError {
    #[error("node `{node_name}` not found in workflow")]
    NodeNotFound { node_name: String },

    #[error("duplicate node name `{node_name}` violates unique name invariant")]
    DuplicateNodeName { node_name: String },

    #[error("duplicate node id `{node_id}` violates unique ID invariant")]
    DuplicateNodeId { node_id: String },

    #[error("invalid node payload: {reason}")]
    InvalidNodeDefinition { reason: String },

    #[error("invalid RFC 6901 JSON Pointer `{pointer}`: {reason}")]
    InvalidJsonPointer { pointer: String, reason: String },

    #[error("JSON Pointer `{pointer}` on node `{node_name}` could not be resolved: {reason}")]
    PointerTargetNotFound {
        node_name: String,
        pointer: String,
        reason: String,
    },

    #[error("text patch failed on `{node_name}` `{pointer}`: {reason}")]
    TextPatchFailed {
        node_name: String,
        pointer: String,
        reason: String,
    },

    #[error("invalid reliability configuration on `{node_name}`: {reason}")]
    InvalidReliabilityConfig { node_name: String, reason: String },

    #[error("invalid credential binding on `{node_name}`: {reason}")]
    InvalidCredentialBinding { node_name: String, reason: String },

    #[error(
        "rename `{old_name}` -> `{new_name}` refused (`manual_review_required`): {} dynamic expression reference(s) detected",
        hazards.len()
    )]
    RenameManualReviewRequired {
        old_name: String,
        new_name: String,
        hazards: Vec<DynamicReferenceHazard>,
    },

    #[error("connection edge `{from_node}` -> `{to_node}` not found")]
    EdgeNotFound { from_node: String, to_node: String },

    #[error("cannot bridge-remove `{node_name}`: {reason}")]
    BridgeArityMismatch { node_name: String, reason: String },

    #[error("auto_layout requires at least one explicit target node name")]
    EmptyAutoLayoutSelection,

    #[error("invalid nodeGroups configuration: {reason}")]
    InvalidNodeGroups { reason: String },

    #[error(
        "migration_missing: no registered VersionMigrationTransform for `{node_type}` from `{current_version}` to `{target_version}` on node `{node_name}`"
    )]
    MigrationMissing {
        node_name: String,
        node_type: String,
        current_version: String,
        target_version: String,
    },

    #[error("version migration failed on `{node_name}`: {reason}")]
    MigrationFailed { node_name: String, reason: String },
}

/// Explicit registered migration transform required by `UpgradeNodeVersion`.
pub trait VersionMigrationTransform: Send + Sync {
    fn node_type(&self) -> &str;
    fn source_version(&self) -> &str;
    fn target_version(&self) -> &str;
    fn migrate(&self, node: &mut WorkflowNodeIr) -> Result<Vec<String>, String>;
}

type MigrationClosureFn =
    Box<dyn Fn(&mut WorkflowNodeIr) -> Result<Vec<String>, String> + Send + Sync>;

struct ClosureMigration {
    node_type: String,
    source_version: String,
    target_version: String,
    func: MigrationClosureFn,
}

impl VersionMigrationTransform for ClosureMigration {
    fn node_type(&self) -> &str {
        &self.node_type
    }

    fn source_version(&self) -> &str {
        &self.source_version
    }

    fn target_version(&self) -> &str {
        &self.target_version
    }

    fn migrate(&self, node: &mut WorkflowNodeIr) -> Result<Vec<String>, String> {
        (self.func)(node)
    }
}

/// Registry of verified [`VersionMigrationTransform`]s keyed by `(node_type, from_version, to_version)`.
#[derive(Clone, Default)]
pub struct VersionMigrationRegistry {
    transforms: HashMap<(String, String, String), Arc<dyn VersionMigrationTransform>>,
}

impl fmt::Debug for VersionMigrationRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionMigrationRegistry")
            .field("registered_count", &self.transforms.len())
            .finish()
    }
}

impl VersionMigrationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<T: VersionMigrationTransform + 'static>(&mut self, transform: T) {
        let key = (
            transform.node_type().to_owned(),
            transform.source_version().to_owned(),
            transform.target_version().to_owned(),
        );
        self.transforms.insert(key, Arc::new(transform));
    }

    pub fn register_fn<F>(
        &mut self,
        node_type: impl Into<String>,
        from_version: impl Into<String>,
        to_version: impl Into<String>,
        func: F,
    ) where
        F: Fn(&mut WorkflowNodeIr) -> Result<Vec<String>, String> + Send + Sync + 'static,
    {
        self.register(ClosureMigration {
            node_type: node_type.into(),
            source_version: from_version.into(),
            target_version: to_version.into(),
            func: Box::new(func),
        });
    }

    #[must_use]
    pub fn get(
        &self,
        node_type: &str,
        from_version: &str,
        to_version: &str,
    ) -> Option<&Arc<dyn VersionMigrationTransform>> {
        self.transforms.get(&(
            node_type.to_owned(),
            from_version.to_owned(),
            to_version.to_owned(),
        ))
    }
}

/// Optional external AST expression rename hook (for callers like `n8n-validator` supplying custom AST logic).
pub type ExpressionRenameCallback = dyn Fn(&str, &str, &str, &str, &str) -> Result<Option<String>, DynamicReferenceHazard>
    + Send
    + Sync;

/// Execution context for [`plan_mutations`] and [`apply_mutations`].
#[derive(Clone, Default)]
pub struct MutationContext {
    pub migration_registry: VersionMigrationRegistry,
    /// Optional map of `node_type -> allowed credential_type names` for stricter schema-backed credential checks.
    pub allowed_credential_types: Option<HashMap<String, Vec<String>>>,
    /// Optional explicit expression rewrite overrides keyed by `(node_name, parameter_pointer) -> new_expression`.
    pub expression_rewrite_map: HashMap<(String, String), String>,
    /// Optional custom expression rename callback `(holder_node_name, pointer, expr_str, old_name, new_name)`.
    pub custom_rename_hook: Option<Arc<ExpressionRenameCallback>>,
    /// Maximum characters in unified diff summary (defaults to `DEFAULT_DIFF_MAX_CHARS`).
    pub diff_max_chars: Option<usize>,
}

impl fmt::Debug for MutationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutationContext")
            .field("migration_registry", &self.migration_registry)
            .field(
                "has_allowed_credential_types",
                &self.allowed_credential_types.is_some(),
            )
            .field(
                "expression_rewrite_map_len",
                &self.expression_rewrite_map.len(),
            )
            .field("has_custom_rename_hook", &self.custom_rename_hook.is_some())
            .finish()
    }
}

/// Validates and plans a batch of [`GraphMutationOp`]s on a clone of `before` without mutating `before` in-place.
pub fn plan_mutations(
    before: &WorkflowIr,
    ops: &[GraphMutationOp],
    ctx: &MutationContext,
) -> Result<MutationPlan, GraphMutationError> {
    let (_, plan) = apply_mutations(before, ops, ctx)?;
    Ok(plan)
}

/// Applies all [`GraphMutationOp`]s atomically to a cloned [`WorkflowIr`], returning the mutated IR and [`MutationPlan`].
pub fn apply_mutations(
    before: &WorkflowIr,
    ops: &[GraphMutationOp],
    ctx: &MutationContext,
) -> Result<(WorkflowIr, MutationPlan), GraphMutationError> {
    let expected_version_hash = before.canonical_version_hash();
    let mut working = before.clone();
    let mut outcomes = Vec::with_capacity(ops.len());

    for (op_index, op) in ops.iter().enumerate() {
        let outcome = apply_single_op(&mut working, op_index, op, ctx)?;
        outcomes.push(outcome);
    }

    let resulting_version_hash = working.canonical_version_hash();
    let requires_whole_array_or_api_fallback = outcomes
        .iter()
        .any(|o| o.requires_whole_array_or_api_fallback);
    let max_chars = ctx.diff_max_chars.unwrap_or(DEFAULT_DIFF_MAX_CHARS);
    let workflow_diff = WorkflowDiff::compute(before, &working, max_chars);
    let topology_after = WorkflowGraph::from_ir(&working).analyze();
    let approval_required =
        working.active || !workflow_diff.risk_flags.is_empty() || !ops.is_empty();

    let plan = MutationPlan {
        plan_id: format!("plan_{}", Uuid::now_v7().simple()),
        expected_version_hash,
        resulting_version_hash,
        requires_whole_array_or_api_fallback,
        approval_required,
        operation_outcomes: outcomes,
        workflow_diff,
        topology_after,
    };

    Ok((working, plan))
}

#[allow(clippy::too_many_lines)]
fn apply_single_op(
    wf: &mut WorkflowIr,
    op_index: usize,
    op: &GraphMutationOp,
    ctx: &MutationContext,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    match op {
        GraphMutationOp::SetParams {
            node_name,
            pointer,
            value,
        } => apply_set_params(wf, op_index, node_name, pointer, value),

        GraphMutationOp::UnsetParams { node_name, pointer } => {
            apply_unset_params(wf, op_index, node_name, pointer)
        }

        GraphMutationOp::PatchTextField {
            node_name,
            pointer,
            before,
            after,
            unified_hunk,
            replace_all,
        } => apply_patch_text_field(
            wf,
            op_index,
            node_name,
            pointer,
            before,
            after,
            unified_hunk.as_deref(),
            *replace_all,
        ),

        GraphMutationOp::ConfigureReliability {
            node_name,
            retry_on_fail,
            max_tries,
            wait_between_tries_ms,
            on_error,
            continue_on_fail,
            execute_once,
            always_output_data,
        } => apply_configure_reliability(
            wf,
            op_index,
            node_name,
            *retry_on_fail,
            *max_tries,
            *wait_between_tries_ms,
            on_error.as_deref(),
            *continue_on_fail,
            *execute_once,
            *always_output_data,
        ),

        GraphMutationOp::BindCredential {
            node_name,
            credential_type,
            credential_id,
            credential_name,
        } => apply_bind_credential(
            wf,
            op_index,
            node_name,
            credential_type,
            credential_id,
            credential_name,
            ctx,
        ),

        GraphMutationOp::AddNode { node } => apply_add_node(wf, op_index, node),

        GraphMutationOp::RemoveNode { node_name } => apply_remove_node(wf, op_index, node_name),

        GraphMutationOp::RenameNode { old_name, new_name } => {
            apply_rename_node(wf, op_index, old_name, new_name, ctx)
        }

        GraphMutationOp::InsertNodeBetween {
            upstream,
            downstream,
            node,
            port_kind,
            output_index,
        } => apply_insert_node_between(
            wf,
            op_index,
            upstream,
            downstream,
            node,
            port_kind.as_ref(),
            *output_index,
        ),

        GraphMutationOp::RemoveNodeBridge { node_name } => {
            apply_remove_node_bridge(wf, op_index, node_name)
        }

        GraphMutationOp::Connect {
            from_node,
            to_node,
            output_index,
            input_index,
            port_kind,
        } => apply_connect(
            wf,
            op_index,
            from_node,
            to_node,
            *output_index,
            *input_index,
            port_kind,
        ),

        GraphMutationOp::Disconnect {
            from_node,
            to_node,
            port_kind,
            output_index,
            input_index,
        } => apply_disconnect(
            wf,
            op_index,
            from_node,
            to_node,
            port_kind.as_ref(),
            *output_index,
            *input_index,
        ),

        GraphMutationOp::Rewire {
            from_node,
            old_target,
            new_target,
            port_kind,
            output_index,
        } => apply_rewire(
            wf,
            op_index,
            from_node,
            old_target,
            new_target,
            port_kind.as_ref(),
            *output_index,
        ),

        GraphMutationOp::AutoLayout { node_names } => apply_auto_layout(wf, op_index, node_names),

        GraphMutationOp::SetNodeGroups { groups } => apply_set_node_groups(wf, op_index, groups),

        GraphMutationOp::UpgradeNodeVersion {
            node_name,
            target_version,
        } => apply_upgrade_node_version(wf, op_index, node_name, target_version, ctx),
    }
}

fn parse_rfc6901_tokens(pointer: &str) -> Result<Vec<String>, GraphMutationError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') {
        return Err(GraphMutationError::InvalidJsonPointer {
            pointer: redact_str(pointer),
            reason: "RFC 6901 JSON Pointer must be empty (`\"\"`) or start with `'/'` (dotted/JSONPath syntax is not server-native)".to_owned(),
        });
    }
    // Validate `~` escapes: only `~0` and `~1` are valid in RFC 6901.
    let bytes = pointer.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'~' {
            if i + 1 >= bytes.len() || (bytes[i + 1] != b'0' && bytes[i + 1] != b'1') {
                return Err(GraphMutationError::InvalidJsonPointer {
                    pointer: redact_str(pointer),
                    reason: "invalid `~` escape in RFC 6901 pointer (expected `~0` or `~1`)"
                        .to_owned(),
                });
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(pointer[1..]
        .split('/')
        .map(unescape_json_pointer_token)
        .collect())
}

fn is_array_index_token(token: &str) -> bool {
    token == "-" || (!token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()))
}

fn format_pointer_from_tokens(tokens: &[String]) -> String {
    if tokens.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for t in tokens {
        out.push('/');
        out.push_str(&escape_json_pointer_token(t));
    }
    out
}

fn apply_set_params(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    pointer: &str,
    value: &Value,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let tokens = parse_rfc6901_tokens(pointer)?;
    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    if tokens.is_empty() {
        if !value.is_object() {
            return Err(GraphMutationError::InvalidJsonPointer {
                pointer: String::new(),
                reason: "replacing root `parameters` requires a JSON object".to_owned(),
            });
        }
        node.parameters = value.clone();
        return Ok(AppliedOpOutcome {
            op_index,
            op_kind: "set_params".to_owned(),
            requires_whole_array_or_api_fallback: false,
            whole_array_fallback: None,
            rename_safety: None,
            notes: Vec::new(),
        });
    }

    if !node.parameters.is_object() {
        node.parameters = Value::Object(Map::new());
    }

    let syntactic_array_token = tokens.iter().any(|t| is_array_index_token(t));
    let mut first_array_depth: Option<usize> = None;

    let mut current = &mut node.parameters;
    for (depth, token) in tokens[..tokens.len() - 1].iter().enumerate() {
        match current {
            Value::Object(map) => {
                if !map.contains_key(token) {
                    map.insert(token.clone(), Value::Object(Map::new()));
                }
                current = map.get_mut(token).ok_or_else(|| {
                    GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: "failed descending object map".to_owned(),
                    }
                })?;
            }
            Value::Array(arr) => {
                if first_array_depth.is_none() {
                    first_array_depth = Some(depth);
                }
                let idx = token.parse::<usize>().map_err(|_| {
                    GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("non-numeric array index `{}`", redact_str(token)),
                    }
                })?;
                if idx >= arr.len() {
                    return Err(GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("array index {idx} out of bounds (len={})", arr.len()),
                    });
                }
                current = &mut arr[idx];
            }
            _ => {
                return Err(GraphMutationError::PointerTargetNotFound {
                    node_name: redact_str(node_name),
                    pointer: redact_str(pointer),
                    reason: "intermediate target is a scalar value, not an object or array"
                        .to_owned(),
                });
            }
        }
    }

    let last_token = &tokens[tokens.len() - 1];
    match current {
        Value::Object(map) => {
            map.insert(last_token.clone(), value.clone());
        }
        Value::Array(arr) => {
            if first_array_depth.is_none() {
                first_array_depth = Some(tokens.len() - 1);
            }
            if last_token == "-" {
                arr.push(value.clone());
            } else {
                let idx = last_token.parse::<usize>().map_err(|_| {
                    GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("invalid array index `{}`", redact_str(last_token)),
                    }
                })?;
                if idx > arr.len() {
                    return Err(GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("array index {idx} out of bounds (len={})", arr.len()),
                    });
                }
                if idx == arr.len() {
                    arr.push(value.clone());
                } else {
                    arr[idx] = value.clone();
                }
            }
        }
        _ => {
            return Err(GraphMutationError::PointerTargetNotFound {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason: "parent target is a scalar value".to_owned(),
            });
        }
    }

    let requires_fallback = syntactic_array_token || first_array_depth.is_some();
    let mut notes = Vec::new();
    let whole_array_fallback = if requires_fallback {
        let arr_depth = first_array_depth.unwrap_or_else(|| {
            tokens
                .iter()
                .position(|t| is_array_index_token(t))
                .unwrap_or(0)
        });
        let arr_ptr = format_pointer_from_tokens(&tokens[..arr_depth]);
        let updated_arr = node
            .parameters
            .pointer(&arr_ptr)
            .map_or(Value::Null, redact_json_value);
        notes.push(format!(
            "Pointer `{}` addresses an array index; native MCP `setNodeParameter` requires whole-array replacement at `{}` or Public API fallback.",
            redact_str(pointer),
            redact_str(&arr_ptr)
        ));
        Some(WholeArrayFallback {
            node_name: redact_str(node_name),
            array_pointer: arr_ptr,
            updated_array_redacted: updated_arr,
        })
    } else {
        None
    };

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "set_params".to_owned(),
        requires_whole_array_or_api_fallback: requires_fallback,
        whole_array_fallback,
        rename_safety: None,
        notes,
    })
}

fn apply_unset_params(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    pointer: &str,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let tokens = parse_rfc6901_tokens(pointer)?;
    if tokens.is_empty() {
        return Err(GraphMutationError::InvalidJsonPointer {
            pointer: String::new(),
            reason: "cannot unset root `parameters` object (`\"\"`); specify a child pointer"
                .to_owned(),
        });
    }

    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    let syntactic_array_token = tokens.iter().any(|t| is_array_index_token(t));
    let mut first_array_depth: Option<usize> = None;

    let mut current = &mut node.parameters;
    for (depth, token) in tokens[..tokens.len() - 1].iter().enumerate() {
        match current {
            Value::Object(map) => {
                current = map.get_mut(token).ok_or_else(|| {
                    GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("missing intermediate key `{}`", redact_str(token)),
                    }
                })?;
            }
            Value::Array(arr) => {
                if first_array_depth.is_none() {
                    first_array_depth = Some(depth);
                }
                let idx = token.parse::<usize>().map_err(|_| {
                    GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("invalid array index `{}`", redact_str(token)),
                    }
                })?;
                if idx >= arr.len() {
                    return Err(GraphMutationError::PointerTargetNotFound {
                        node_name: redact_str(node_name),
                        pointer: redact_str(pointer),
                        reason: format!("array index {idx} out of bounds"),
                    });
                }
                current = &mut arr[idx];
            }
            _ => {
                return Err(GraphMutationError::PointerTargetNotFound {
                    node_name: redact_str(node_name),
                    pointer: redact_str(pointer),
                    reason: "intermediate target is a scalar".to_owned(),
                });
            }
        }
    }

    let last_token = &tokens[tokens.len() - 1];
    match current {
        Value::Object(map) => {
            if map.remove(last_token).is_none() {
                return Err(GraphMutationError::PointerTargetNotFound {
                    node_name: redact_str(node_name),
                    pointer: redact_str(pointer),
                    reason: format!("key `{}` does not exist", redact_str(last_token)),
                });
            }
        }
        Value::Array(arr) => {
            if first_array_depth.is_none() {
                first_array_depth = Some(tokens.len() - 1);
            }
            let idx = last_token.parse::<usize>().map_err(|_| {
                GraphMutationError::PointerTargetNotFound {
                    node_name: redact_str(node_name),
                    pointer: redact_str(pointer),
                    reason: format!("invalid array index `{}`", redact_str(last_token)),
                }
            })?;
            if idx >= arr.len() {
                return Err(GraphMutationError::PointerTargetNotFound {
                    node_name: redact_str(node_name),
                    pointer: redact_str(pointer),
                    reason: format!("array index {idx} out of bounds"),
                });
            }
            arr.remove(idx);
        }
        _ => {
            return Err(GraphMutationError::PointerTargetNotFound {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason: "parent target is not a container".to_owned(),
            });
        }
    }

    let requires_fallback = syntactic_array_token || first_array_depth.is_some();
    let whole_array_fallback = if requires_fallback {
        let arr_depth = first_array_depth.unwrap_or(0);
        let arr_ptr = format_pointer_from_tokens(&tokens[..arr_depth]);
        let updated_arr = node
            .parameters
            .pointer(&arr_ptr)
            .map_or(Value::Null, redact_json_value);
        Some(WholeArrayFallback {
            node_name: redact_str(node_name),
            array_pointer: arr_ptr,
            updated_array_redacted: updated_arr,
        })
    } else {
        None
    };

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "unset_params".to_owned(),
        requires_whole_array_or_api_fallback: requires_fallback,
        whole_array_fallback,
        rename_safety: None,
        notes: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_patch_text_field(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    pointer: &str,
    before: &str,
    after: &str,
    unified_hunk: Option<&str>,
    replace_all: bool,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let tokens = parse_rfc6901_tokens(pointer)?;
    if tokens.is_empty() {
        return Err(GraphMutationError::InvalidJsonPointer {
            pointer: String::new(),
            reason: "PatchTextField requires a pointer to a string parameter".to_owned(),
        });
    }
    if before.len() > MAX_TEXT_PATCH_BYTES
        || after.len() > MAX_TEXT_PATCH_BYTES
        || unified_hunk.is_some_and(|h| h.len() > MAX_TEXT_PATCH_BYTES)
    {
        return Err(GraphMutationError::TextPatchFailed {
            node_name: redact_str(node_name),
            pointer: redact_str(pointer),
            reason: format!("patch payload exceeds {MAX_TEXT_PATCH_BYTES} byte safety bound"),
        });
    }

    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    let syntactic_array_token = tokens.iter().any(|t| is_array_index_token(t));
    let target_val = node.parameters.pointer_mut(pointer).ok_or_else(|| {
        GraphMutationError::PointerTargetNotFound {
            node_name: redact_str(node_name),
            pointer: redact_str(pointer),
            reason: "target field does not exist".to_owned(),
        }
    })?;

    let Some(current_text) = target_val.as_str() else {
        return Err(GraphMutationError::TextPatchFailed {
            node_name: redact_str(node_name),
            pointer: redact_str(pointer),
            reason: "target field is not a string".to_owned(),
        });
    };

    if current_text.len() > MAX_TEXT_PATCH_BYTES {
        return Err(GraphMutationError::TextPatchFailed {
            node_name: redact_str(node_name),
            pointer: redact_str(pointer),
            reason: "existing text field exceeds bounded patch limit".to_owned(),
        });
    }

    let updated_text = if let Some(hunk) = unified_hunk {
        apply_unified_hunk_str(current_text, hunk).map_err(|reason| {
            GraphMutationError::TextPatchFailed {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason,
            }
        })?
    } else {
        if before.is_empty() {
            return Err(GraphMutationError::TextPatchFailed {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason: "`before` hunk cannot be empty".to_owned(),
            });
        }
        let match_count = current_text.matches(before).count();
        if match_count == 0 {
            return Err(GraphMutationError::TextPatchFailed {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason: "`before` hunk not found in target string".to_owned(),
            });
        }
        if match_count > 1 && !replace_all {
            return Err(GraphMutationError::TextPatchFailed {
                node_name: redact_str(node_name),
                pointer: redact_str(pointer),
                reason: format!(
                    "ambiguous `before` hunk matched {match_count} occurrences; provide more context or set `replace_all: true`"
                ),
            });
        }
        if replace_all {
            current_text.replace(before, after)
        } else {
            current_text.replacen(before, after, 1)
        }
    };

    *target_val = Value::String(updated_text);

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "patch_text_field".to_owned(),
        requires_whole_array_or_api_fallback: syntactic_array_token,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_unified_hunk_str(source: &str, hunk: &str) -> Result<String, String> {
    let mut old_lines = Vec::new();
    let mut new_lines = Vec::new();

    for raw_line in hunk.lines() {
        if raw_line.starts_with("@@") || raw_line.starts_with("---") || raw_line.starts_with("+++")
        {
            continue;
        }
        if let Some(rest) = raw_line.strip_prefix('-') {
            old_lines.push(rest);
        } else if let Some(rest) = raw_line.strip_prefix('+') {
            new_lines.push(rest);
        } else if let Some(rest) = raw_line.strip_prefix(' ') {
            old_lines.push(rest);
            new_lines.push(rest);
        } else {
            old_lines.push(raw_line);
            new_lines.push(raw_line);
        }
    }

    if old_lines.is_empty() {
        return Err("unified hunk contains no context or removed lines".to_owned());
    }

    let needle = old_lines.join("\n");
    let replacement = new_lines.join("\n");
    let count = source.matches(&needle).count();
    if count == 0 {
        return Err("unified hunk context/removed lines did not match target text".to_owned());
    }
    if count > 1 {
        return Err("unified hunk matched multiple locations; add surrounding context".to_owned());
    }
    Ok(source.replacen(&needle, &replacement, 1))
}

#[allow(clippy::too_many_arguments)]
fn apply_configure_reliability(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    retry_on_fail: Option<bool>,
    max_tries: Option<u32>,
    wait_between_tries_ms: Option<u64>,
    on_error: Option<&str>,
    continue_on_fail: Option<bool>,
    execute_once: Option<bool>,
    always_output_data: Option<bool>,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if retry_on_fail.is_none()
        && max_tries.is_none()
        && wait_between_tries_ms.is_none()
        && on_error.is_none()
        && continue_on_fail.is_none()
        && execute_once.is_none()
        && always_output_data.is_none()
    {
        return Err(GraphMutationError::InvalidReliabilityConfig {
            node_name: redact_str(node_name),
            reason: "at least one reliability option must be specified".to_owned(),
        });
    }

    if let Some(tries) = max_tries
        && !(1..=10).contains(&tries)
    {
        return Err(GraphMutationError::InvalidReliabilityConfig {
            node_name: redact_str(node_name),
            reason: format!("`maxTries` must be in 1..=10 (got {tries})"),
        });
    }

    if let Some(wait_ms) = wait_between_tries_ms
        && wait_ms > 3_600_000
    {
        return Err(GraphMutationError::InvalidReliabilityConfig {
            node_name: redact_str(node_name),
            reason: "`waitBetweenTries` cannot exceed 3_600_000 ms".to_owned(),
        });
    }

    if let Some(mode) = on_error
        && !matches!(
            mode,
            "stopWorkflow" | "continueRegularOutput" | "continueErrorOutput"
        )
    {
        return Err(GraphMutationError::InvalidReliabilityConfig {
            node_name: redact_str(node_name),
            reason: format!(
                "unsupported `onError` value `{}` (expected `stopWorkflow`, `continueRegularOutput`, or `continueErrorOutput`)",
                redact_str(mode)
            ),
        });
    }

    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    if let Some(v) = retry_on_fail {
        node.retry_on_fail = Some(v);
    }
    if let Some(v) = max_tries {
        node.max_tries = Some(v);
    }
    if let Some(v) = wait_between_tries_ms {
        node.wait_between_tries = Some(v);
    }
    if let Some(v) = on_error {
        node.on_error = Some(v.to_owned());
    }
    if let Some(v) = continue_on_fail {
        node.continue_on_fail = Some(v);
    }
    if let Some(v) = execute_once {
        node.execute_once = Some(v);
    }
    if let Some(v) = always_output_data {
        node.always_output_data = Some(v);
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "configure_reliability".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn contains_secret_like_material(raw: &str) -> bool {
    redact_str(raw) != raw
}

fn apply_bind_credential(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    credential_type: &str,
    credential_id: &str,
    credential_name: &str,
    ctx: &MutationContext,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if credential_type.trim().is_empty()
        || credential_id.trim().is_empty()
        || credential_name.trim().is_empty()
    {
        return Err(GraphMutationError::InvalidCredentialBinding {
            node_name: redact_str(node_name),
            reason:
                "`credential_type`, `credential_id`, and `credential_name` must all be non-empty"
                    .to_owned(),
        });
    }

    if contains_secret_like_material(credential_type)
        || contains_secret_like_material(credential_id)
        || contains_secret_like_material(credential_name)
    {
        return Err(GraphMutationError::InvalidCredentialBinding {
            node_name: redact_str(node_name),
            reason: "credential binding accepts non-secret reference ID and display name only; raw secret material is forbidden".to_owned(),
        });
    }

    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    if let Some(ref allowed_map) = ctx.allowed_credential_types
        && let Some(allowed_list) = allowed_map.get(&node.node_type)
        && !allowed_list.iter().any(|c| c == credential_type)
    {
        return Err(GraphMutationError::InvalidCredentialBinding {
            node_name: redact_str(node_name),
            reason: format!(
                "credential type `{}` is not compatible with node type `{}`",
                redact_str(credential_type),
                redact_str(&node.node_type)
            ),
        });
    }

    let mut notes = Vec::new();
    if node
        .node_type
        .rsplit('.')
        .next()
        .is_some_and(|s| s.eq_ignore_ascii_case("httpRequest"))
    {
        notes.push(
            "Explicit credential reference bound to HTTP Request node (verify `authentication` parameter matches)."
                .to_owned(),
        );
    }

    let creds = node.credentials.get_or_insert_with(IndexMap::new);
    creds.insert(
        credential_type.to_owned(),
        NodeCredentialRef::new(credential_id, credential_name),
    );

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "bind_credential".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes,
    })
}

fn parse_and_prepare_new_node(
    wf: &WorkflowIr,
    raw_node: &Value,
    fallback_position: Option<[f64; 2]>,
) -> Result<WorkflowNodeIr, GraphMutationError> {
    let Some(obj) = raw_node.as_object() else {
        return Err(GraphMutationError::InvalidNodeDefinition {
            reason: "node payload must be a JSON object".to_owned(),
        });
    };

    let has_explicit_position = obj.contains_key("position");
    let mut parsed: WorkflowNodeIr = serde_json::from_value(raw_node.clone()).map_err(|e| {
        GraphMutationError::InvalidNodeDefinition {
            reason: redact_str(&e.to_string()),
        }
    })?;

    if parsed.name.trim().is_empty() {
        return Err(GraphMutationError::InvalidNodeDefinition {
            reason: "node `name` must not be empty".to_owned(),
        });
    }
    if parsed.node_type.trim().is_empty() {
        return Err(GraphMutationError::InvalidNodeDefinition {
            reason: "node `type` must not be empty".to_owned(),
        });
    }
    if parsed.id.trim().is_empty() {
        parsed.id = Uuid::new_v4().to_string();
    }

    if wf.nodes.iter().any(|n| n.name == parsed.name) {
        return Err(GraphMutationError::DuplicateNodeName {
            node_name: redact_str(&parsed.name),
        });
    }
    if wf.nodes.iter().any(|n| n.id == parsed.id) {
        return Err(GraphMutationError::DuplicateNodeId {
            node_id: redact_str(&parsed.id),
        });
    }

    // Ensure no raw credential secrets (`data` or secret tokens) are smuggled inside `node.credentials`.
    if let Some(ref creds) = parsed.credentials {
        for (cred_type, cred_ref) in creds {
            if cred_ref.extra.contains_key("data")
                || cred_ref
                    .extra
                    .keys()
                    .any(|k| n8n_types::is_sensitive_key(k))
                || contains_secret_like_material(&cred_ref.name)
                || cred_ref
                    .id
                    .as_deref()
                    .is_some_and(contains_secret_like_material)
            {
                return Err(GraphMutationError::InvalidCredentialBinding {
                    node_name: redact_str(&parsed.name),
                    reason: format!(
                        "credential `{}` on new node contains forbidden secret payload; pass reference `id` and `name` only",
                        redact_str(cred_type)
                    ),
                });
            }
        }
    }

    if !has_explicit_position {
        parsed.position = fallback_position.unwrap_or_else(|| next_default_canvas_position(wf));
    }

    Ok(parsed)
}

fn next_default_canvas_position(wf: &WorkflowIr) -> [f64; 2] {
    if wf.nodes.is_empty() {
        return [240.0, 300.0];
    }
    let max_x = wf
        .nodes
        .iter()
        .map(|n| n.position[0])
        .fold(240.0_f64, f64::max);
    let base_y = wf.nodes.first().map_or(300.0, |n| n.position[1]);
    [max_x + 240.0, base_y]
}

fn apply_add_node(
    wf: &mut WorkflowIr,
    op_index: usize,
    raw_node: &Value,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let node = parse_and_prepare_new_node(wf, raw_node, None)?;
    wf.nodes.push(node);
    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "add_node".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn remove_node_clean_references(wf: &mut WorkflowIr, node_name: &str, removed_id: &str) {
    // 1. Remove outgoing connections key.
    wf.connections.shift_remove(node_name);

    // 2. Remove incoming edges targeting `node_name` across all ports, preserving branch index positions!
    let mut empty_sources = Vec::new();
    for (src_key, port_map) in &mut wf.connections {
        let mut empty_ports = Vec::new();
        for (port_kind, branches) in port_map.iter_mut() {
            for branch in branches.iter_mut() {
                branch.retain(|edge| edge.node != node_name);
            }
            if branches.iter().all(Vec::is_empty) {
                empty_ports.push(port_kind.clone());
            }
        }
        for p in empty_ports {
            port_map.shift_remove(&p);
        }
        if port_map.is_empty() {
            empty_sources.push(src_key.clone());
        }
    }
    for src in empty_sources {
        wf.connections.shift_remove(&src);
    }

    // 3. Clean up `pinData`.
    if let Some(ref mut pin_map) = wf.pin_data {
        pin_map.shift_remove(node_name);
    }

    // 4. Clean up `nodeGroups` (referencing `node.id`).
    if let Some(ref mut groups) = wf.node_groups
        && !removed_id.is_empty()
    {
        groups.retain_mut(|grp| {
            let had_member = grp.node_ids.iter().any(|id| id == removed_id);
            grp.node_ids.retain(|id| id != removed_id);
            !(had_member && grp.node_ids.is_empty())
        });
    }
}

fn apply_remove_node(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let Some(pos) = wf.nodes.iter().position(|n| n.name == node_name) else {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        });
    };
    let removed = wf.nodes.remove(pos);
    remove_node_clean_references(wf, node_name, &removed.id);

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "remove_node".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_rename_node(
    wf: &mut WorkflowIr,
    op_index: usize,
    old_name: &str,
    new_name: &str,
    ctx: &MutationContext,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if new_name.trim().is_empty() {
        return Err(GraphMutationError::InvalidNodeDefinition {
            reason: "`new_name` must not be empty".to_owned(),
        });
    }

    let Some(target_idx) = wf.nodes.iter().position(|n| n.name == old_name) else {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(old_name),
        });
    };

    if old_name == new_name {
        return Ok(AppliedOpOutcome {
            op_index,
            op_kind: "rename_node".to_owned(),
            requires_whole_array_or_api_fallback: false,
            whole_array_fallback: None,
            rename_safety: Some(RenameSafety::SafeLiteralRewrites {
                rewritten_locations: Vec::new(),
            }),
            notes: vec!["Node already has requested name; no-op.".to_owned()],
        });
    }

    if wf.nodes.iter().any(|n| n.name == new_name) {
        return Err(GraphMutationError::DuplicateNodeName {
            node_name: redact_str(new_name),
        });
    }

    // 1. Scan & stage expression rewrites across ALL nodes BEFORE mutating anything, so any dynamic
    //    reference hazard fails closed without partial corruption!
    let mut staged_param_updates: Vec<(usize, Value)> = Vec::new();
    let mut rewritten_locations: Vec<String> = Vec::new();
    let mut hazards: Vec<DynamicReferenceHazard> = Vec::new();

    for (idx, node) in wf.nodes.iter().enumerate() {
        let holder_name = if idx == target_idx {
            new_name
        } else {
            node.name.as_str()
        };
        let is_code_node = matches!(
            node.node_type
                .rsplit('.')
                .next()
                .unwrap_or(&node.node_type)
                .to_ascii_lowercase()
                .as_str(),
            "code" | "function" | "functionitem"
        );
        let mut cloned_params = node.parameters.clone();
        let mut node_modified = false;

        rewrite_params_recursive(
            &node.name,
            holder_name,
            is_code_node,
            "",
            &mut cloned_params,
            old_name,
            new_name,
            ctx,
            &mut node_modified,
            &mut rewritten_locations,
            &mut hazards,
        );

        if node_modified {
            staged_param_updates.push((idx, cloned_params));
        }
    }

    if !hazards.is_empty() {
        return Err(GraphMutationError::RenameManualReviewRequired {
            old_name: redact_str(old_name),
            new_name: redact_str(new_name),
            hazards,
        });
    }

    // 2. Apply staged expression updates.
    for (idx, updated_params) in staged_param_updates {
        wf.nodes[idx].parameters = updated_params;
    }

    // 3. Rename `node.name`.
    wf.nodes[target_idx].name = new_name.to_owned();

    // 4. Rename `connections` source key (preserving `IndexMap` entry order!) and target `edge.node`s.
    let mut rebuilt_connections = IndexMap::with_capacity(wf.connections.len());
    for (src_key, mut port_map) in std::mem::take(&mut wf.connections) {
        for branches in port_map.values_mut() {
            for branch in branches {
                for edge in branch {
                    if edge.node == old_name {
                        edge.node = new_name.to_owned();
                    }
                }
            }
        }
        let updated_key = if src_key == old_name {
            new_name.to_owned()
        } else {
            src_key
        };
        rebuilt_connections.insert(updated_key, port_map);
    }
    wf.connections = rebuilt_connections;

    // 5. Rename `pinData` key (preserving `IndexMap` entry order!).
    if let Some(pin_map) = wf.pin_data.take() {
        let mut rebuilt_pins = IndexMap::with_capacity(pin_map.len());
        for (k, v) in pin_map {
            let next_k = if k == old_name {
                new_name.to_owned()
            } else {
                k
            };
            rebuilt_pins.insert(next_k, v);
        }
        wf.pin_data = Some(rebuilt_pins);
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "rename_node".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: Some(RenameSafety::SafeLiteralRewrites {
            rewritten_locations,
        }),
        notes: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn rewrite_params_recursive(
    orig_holder_name: &str,
    display_holder_name: &str,
    is_code_node: bool,
    pointer: &str,
    val: &mut Value,
    old_name: &str,
    new_name: &str,
    ctx: &MutationContext,
    node_modified: &mut bool,
    rewritten_locations: &mut Vec<String>,
    hazards: &mut Vec<DynamicReferenceHazard>,
) {
    match val {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let child_ptr = format!("{pointer}/{}", escape_json_pointer_token(k));
                rewrite_params_recursive(
                    orig_holder_name,
                    display_holder_name,
                    is_code_node,
                    &child_ptr,
                    v,
                    old_name,
                    new_name,
                    ctx,
                    node_modified,
                    rewritten_locations,
                    hazards,
                );
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let child_ptr = format!("{pointer}/{i}");
                rewrite_params_recursive(
                    orig_holder_name,
                    display_holder_name,
                    is_code_node,
                    &child_ptr,
                    item,
                    old_name,
                    new_name,
                    ctx,
                    node_modified,
                    rewritten_locations,
                    hazards,
                );
            }
        }
        Value::String(s) => {
            // 1. Check explicit caller-supplied rewrite map first.
            if let Some(explicit) = ctx
                .expression_rewrite_map
                .get(&(orig_holder_name.to_owned(), pointer.to_owned()))
            {
                if s != explicit {
                    *s = explicit.clone();
                    *node_modified = true;
                    rewritten_locations.push(format!(
                        "{}:{}",
                        redact_str(display_holder_name),
                        redact_str(pointer)
                    ));
                }
                return;
            }

            let is_code_script_field =
                is_code_node && matches!(pointer, "/jsCode" | "/pythonCode" | "/functionCode");
            let is_n8n_expr = s.starts_with('=');

            // Preserve plain non-expression strings (prompts, SQL, URLs) byte-for-byte!
            if !is_n8n_expr && !is_code_script_field {
                return;
            }

            // 2. Check optional custom AST callback if supplied.
            if let Some(ref hook) = ctx.custom_rename_hook {
                match hook(orig_holder_name, pointer, s, old_name, new_name) {
                    Ok(Some(updated)) => {
                        *s = updated;
                        *node_modified = true;
                        rewritten_locations.push(format!(
                            "{}:{}",
                            redact_str(display_holder_name),
                            redact_str(pointer)
                        ));
                        return;
                    }
                    Ok(None) => return,
                    Err(hazard) => {
                        hazards.push(hazard);
                        return;
                    }
                }
            }

            // 3. Built-in JS/n8n expression reference analyzer & span-exact rewriter.
            let scan_res = if is_n8n_expr {
                rewrite_n8n_template_string(s, old_name, new_name)
            } else {
                rewrite_js_code_segment(s, old_name, new_name)
            };

            match scan_res {
                Ok(Some(updated)) => {
                    *s = updated;
                    *node_modified = true;
                    rewritten_locations.push(format!(
                        "{}:{}",
                        redact_str(display_holder_name),
                        redact_str(pointer)
                    ));
                }
                Ok(None) => {}
                Err(snippet) => {
                    hazards.push(DynamicReferenceHazard {
                        node_name: redact_str(orig_holder_name),
                        parameter_pointer: redact_str(pointer),
                        expression_snippet: redact_str(&snippet),
                    });
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Scans an `={{ ... }}` template parameter, rewriting ONLY inside `{{ ... }}` blocks and preserving
/// all outside literal template text byte-for-byte.
fn rewrite_n8n_template_string(
    input: &str,
    old_name: &str,
    new_name: &str,
) -> Result<Option<String>, String> {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;
    let bytes = input.as_bytes();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if let Some(rel_open) = input[cursor..].find("{{") {
            let open_pos = cursor + rel_open;
            out.push_str(&input[cursor..open_pos]);
            let body_start = open_pos + 2;
            if let Some(close_pos) = find_matching_double_brace_end(input, body_start) {
                let body = &input[body_start..close_pos];
                out.push_str("{{");
                match rewrite_js_code_segment(body, old_name, new_name)? {
                    Some(rewritten_body) => {
                        out.push_str(&rewritten_body);
                        changed = true;
                    }
                    None => out.push_str(body),
                }
                out.push_str("}}");
                cursor = close_pos + 2;
            } else {
                out.push_str(&input[open_pos..]);
                cursor = bytes.len();
            }
        } else {
            out.push_str(&input[cursor..]);
            break;
        }
    }

    Ok(changed.then_some(out))
}

fn find_matching_double_brace_end(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut brace_depth = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_js_quoted_literal(s, i);
            }
            b'{' => {
                brace_depth += 1;
                i += 1;
            }
            b'}' => {
                if brace_depth == 0 {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                        return Some(i);
                    }
                } else {
                    brace_depth -= 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_js_quoted_literal(s: &str, quote_start: usize) -> usize {
    let bytes = s.as_bytes();
    let quote = bytes[quote_start];
    let mut i = quote_start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    bytes.len()
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Scans a JS/Python expression or script body for `$('Node')`, `$node['Node']`, and `$items('Node', ...)`.
/// Returns `Err(snippet)` if ANY dynamic/computed selector is encountered.
#[allow(clippy::too_many_lines)]
fn rewrite_js_code_segment(
    code: &str,
    old_name: &str,
    new_name: &str,
) -> Result<Option<String>, String> {
    let bytes = code.as_bytes();
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        // Skip single-line comments `//...`
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Skip block comments `/*...*/`
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Skip string literals `'...'` and `"..."`
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            i = skip_js_quoted_literal(code, i);
            continue;
        }
        // Handle template literals `` `...${ expr }...` `` recursively!
        if bytes[i] == b'`' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'`' {
                    i += 1;
                    break;
                } else if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    let expr_start = i + 2;
                    let expr_end = find_matching_single_brace(code, expr_start);
                    let inner = &code[expr_start..expr_end];
                    if let Some(rewritten_inner) =
                        rewrite_js_code_segment(inner, old_name, new_name)?
                    {
                        replacements.push((expr_start, expr_end, rewritten_inner));
                    }
                    i = (expr_end + 1).min(bytes.len());
                } else {
                    i += 1;
                }
            }
            continue;
        }

        // Detect standalone `$` token
        if bytes[i] == b'$' && (i == 0 || !is_ident_continue(bytes[i - 1])) {
            let after_dollar = skip_ascii_ws(code, i + 1);
            // Case A: `$( ... )`
            if after_dollar < bytes.len() && bytes[after_dollar] == b'(' {
                let close_paren = find_matching_delim(code, after_dollar + 1, b'(', b')')
                    .ok_or_else(|| code[i..].chars().take(64).collect::<String>())?;
                let arg_slice = &code[after_dollar + 1..close_paren];
                match inspect_single_string_selector(arg_slice) {
                    SelectorKind::StaticLiteral {
                        quote,
                        unescaped,
                        rel_start,
                        rel_end,
                    } => {
                        if unescaped == old_name {
                            let abs_start = after_dollar + 1 + rel_start;
                            let abs_end = after_dollar + 1 + rel_end;
                            replacements.push((
                                abs_start,
                                abs_end,
                                format_escaped_js_string(quote, new_name),
                            ));
                        }
                    }
                    SelectorKind::Dynamic => {
                        return Err(code[i..=close_paren].to_owned());
                    }
                }
                i = close_paren + 1;
                continue;
            }

            // Case B: `$node[ ... ]`
            if code[i..].starts_with("$node")
                && (i + 5 >= bytes.len() || !is_ident_continue(bytes[i + 5]))
            {
                let after_kw = skip_ascii_ws(code, i + 5);
                if after_kw < bytes.len() && bytes[after_kw] == b'[' {
                    let close_bracket = find_matching_delim(code, after_kw + 1, b'[', b']')
                        .ok_or_else(|| code[i..].chars().take(64).collect::<String>())?;
                    let arg_slice = &code[after_kw + 1..close_bracket];
                    match inspect_single_string_selector(arg_slice) {
                        SelectorKind::StaticLiteral {
                            quote,
                            unescaped,
                            rel_start,
                            rel_end,
                        } => {
                            if unescaped == old_name {
                                let abs_start = after_kw + 1 + rel_start;
                                let abs_end = after_kw + 1 + rel_end;
                                replacements.push((
                                    abs_start,
                                    abs_end,
                                    format_escaped_js_string(quote, new_name),
                                ));
                            }
                        }
                        SelectorKind::Dynamic => {
                            return Err(code[i..=close_bracket].to_owned());
                        }
                    }
                    i = close_bracket + 1;
                    continue;
                }
            }

            // Case C: `$items( first_arg , ... )`
            if code[i..].starts_with("$items")
                && (i + 6 >= bytes.len() || !is_ident_continue(bytes[i + 6]))
            {
                let after_kw = skip_ascii_ws(code, i + 6);
                if after_kw < bytes.len() && bytes[after_kw] == b'(' {
                    let close_paren = find_matching_delim(code, after_kw + 1, b'(', b')')
                        .ok_or_else(|| code[i..].chars().take(64).collect::<String>())?;
                    let args_slice = &code[after_kw + 1..close_paren];
                    if !args_slice.trim().is_empty() {
                        let first_arg_end =
                            find_top_level_comma(args_slice).unwrap_or(args_slice.len());
                        let first_arg = &args_slice[..first_arg_end];
                        match inspect_single_string_selector(first_arg) {
                            SelectorKind::StaticLiteral {
                                quote,
                                unescaped,
                                rel_start,
                                rel_end,
                            } => {
                                if unescaped == old_name {
                                    let abs_start = after_kw + 1 + rel_start;
                                    let abs_end = after_kw + 1 + rel_end;
                                    replacements.push((
                                        abs_start,
                                        abs_end,
                                        format_escaped_js_string(quote, new_name),
                                    ));
                                }
                            }
                            SelectorKind::Dynamic => {
                                return Err(code[i..=close_paren].to_owned());
                            }
                        }
                    }
                    i = close_paren + 1;
                    continue;
                }
            }
        }

        i += 1;
    }

    if replacements.is_empty() {
        return Ok(None);
    }

    let mut rebuilt = String::with_capacity(code.len() + 16);
    let mut last_idx = 0;
    for (start, end, rep) in replacements {
        rebuilt.push_str(&code[last_idx..start]);
        rebuilt.push_str(&rep);
        last_idx = end;
    }
    rebuilt.push_str(&code[last_idx..]);
    Ok(Some(rebuilt))
}

enum SelectorKind {
    StaticLiteral {
        quote: char,
        unescaped: String,
        rel_start: usize,
        rel_end: usize,
    },
    Dynamic,
}

fn inspect_single_string_selector(arg: &str) -> SelectorKind {
    let bytes = arg.as_bytes();
    let start = skip_ascii_ws(arg, 0);
    if start >= bytes.len() {
        return SelectorKind::Dynamic;
    }
    let quote_byte = bytes[start];
    if quote_byte != b'\'' && quote_byte != b'"' && quote_byte != b'`' {
        return SelectorKind::Dynamic;
    }

    let mut i = start + 1;
    let mut unescaped = String::new();
    let mut closed_at = None;

    while i < bytes.len() {
        // Template interpolation `${...}` makes a backtick selector dynamic!
        if quote_byte == b'`' && bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            return SelectorKind::Dynamic;
        }
        if bytes[i] == b'\\' {
            if i + 1 >= bytes.len() {
                return SelectorKind::Dynamic;
            }
            let esc = bytes[i + 1];
            match esc {
                b'n' => unescaped.push('\n'),
                b'r' => unescaped.push('\r'),
                b't' => unescaped.push('\t'),
                b'\\' => unescaped.push('\\'),
                b'\'' => unescaped.push('\''),
                b'"' => unescaped.push('"'),
                b'`' => unescaped.push('`'),
                other => unescaped.push(char::from(other)),
            }
            i += 2;
        } else if bytes[i] == quote_byte {
            closed_at = Some(i + 1);
            break;
        } else {
            let Some(ch) = arg[i..].chars().next() else {
                return SelectorKind::Dynamic;
            };
            unescaped.push(ch);
            i += ch.len_utf8();
        }
    }

    let Some(end_pos) = closed_at else {
        return SelectorKind::Dynamic;
    };

    // If anything other than whitespace follows the closing quote (e.g. `'prefix' + x`), it is dynamic!
    let trailing = skip_ascii_ws(arg, end_pos);
    if trailing != bytes.len() {
        return SelectorKind::Dynamic;
    }

    SelectorKind::StaticLiteral {
        quote: char::from(quote_byte),
        unescaped,
        rel_start: start,
        rel_end: end_pos,
    }
}

fn format_escaped_js_string(quote: char, content: &str) -> String {
    let mut out = String::with_capacity(content.len() + 2);
    out.push(quote);
    for ch in content.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '$' if quote == '`' => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn skip_ascii_ws(s: &str, mut idx: usize) -> usize {
    let bytes = s.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

fn find_matching_single_brace(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => i = skip_js_quoted_literal(s, i),
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

fn find_matching_delim(s: &str, start: usize, open_b: u8, close_b: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut depth = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\'' || b == b'"' || b == b'`' {
            i = skip_js_quoted_literal(s, i);
        } else if b == open_b {
            depth += 1;
            i += 1;
        } else if b == close_b {
            if depth == 0 {
                return Some(i);
            }
            depth -= 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    None
}

fn find_top_level_comma(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => i = skip_js_quoted_literal(s, i),
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' if depth == 0 => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn apply_insert_node_between(
    wf: &mut WorkflowIr,
    op_index: usize,
    upstream: &str,
    downstream: &str,
    raw_node: &Value,
    port_filter: Option<&PortKind>,
    output_index_filter: Option<usize>,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let up_pos = wf
        .node_by_name(upstream)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(upstream),
        })?
        .position;
    let down_pos = wf
        .node_by_name(downstream)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(downstream),
        })?
        .position;

    let midpoint = [
        f64::midpoint(up_pos[0], down_pos[0]),
        f64::midpoint(up_pos[1], down_pos[1]),
    ];
    let new_node = parse_and_prepare_new_node(wf, raw_node, Some(midpoint))?;
    let new_node_name = new_node.name.clone();

    let Some(up_ports) = wf.connections.get_mut(upstream) else {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(upstream),
            to_node: redact_str(downstream),
        });
    };

    let mut spliced_targets: Vec<(PortKind, ConnectionEdgeIr)> = Vec::new();
    for (port_kind, branches) in up_ports.iter_mut() {
        if port_filter.is_some_and(|pf| pf != port_kind) {
            continue;
        }
        for (branch_idx, branch) in branches.iter_mut().enumerate() {
            if output_index_filter.is_some_and(|of| of != branch_idx) {
                continue;
            }
            for edge in branch.iter_mut() {
                if edge.node == downstream {
                    let downstream_copy = edge.clone();
                    edge.node = new_node_name.clone();
                    edge.index = 0;
                    spliced_targets.push((port_kind.clone(), downstream_copy));
                }
            }
        }
    }

    if spliced_targets.is_empty() {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(upstream),
            to_node: redact_str(downstream),
        });
    }

    let new_node_ports = wf.connections.entry(new_node_name).or_default();
    for (port_kind, dst_edge) in spliced_targets {
        let branches = new_node_ports.entry(port_kind).or_default();
        if branches.is_empty() {
            branches.push(Vec::new());
        }
        if !branches[0].iter().any(|e| {
            e.node == dst_edge.node
                && e.port_type == dst_edge.port_type
                && e.index == dst_edge.index
        }) {
            branches[0].push(dst_edge);
        }
    }

    wf.nodes.push(new_node);

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "insert_node_between".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_remove_node_bridge(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let Some(node_pos) = wf.nodes.iter().position(|n| n.name == node_name) else {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        });
    };

    // Gather incoming edges `(src_node, port_kind, src_branch_idx, m_input_idx)`
    let mut incoming: Vec<(String, PortKind, usize, usize)> = Vec::new();
    for (src, port_map) in &wf.connections {
        for (port_kind, branches) in port_map {
            for (b_idx, branch) in branches.iter().enumerate() {
                for edge in branch {
                    if edge.node == node_name {
                        if src == node_name {
                            return Err(GraphMutationError::BridgeArityMismatch {
                                node_name: redact_str(node_name),
                                reason: "cannot bridge-remove a node with a self-loop".to_owned(),
                            });
                        }
                        incoming.push((src.clone(), port_kind.clone(), b_idx, edge.index));
                    }
                }
            }
        }
    }

    // Gather active outgoing branches `(port_kind, m_branch_idx, edges)`
    let mut active_outgoing: Vec<(PortKind, usize, Vec<ConnectionEdgeIr>)> = Vec::new();
    if let Some(out_map) = wf.connections.get(node_name) {
        for (port_kind, branches) in out_map {
            for (b_idx, branch) in branches.iter().enumerate() {
                if !branch.is_empty() {
                    active_outgoing.push((port_kind.clone(), b_idx, branch.clone()));
                }
            }
        }
    }

    if incoming.is_empty() || active_outgoing.is_empty() {
        return Err(GraphMutationError::BridgeArityMismatch {
            node_name: redact_str(node_name),
            reason: "RemoveNodeBridge requires at least one incoming edge and one active outgoing branch (use `remove_node` for terminal/isolated nodes)".to_owned(),
        });
    }

    if active_outgoing.len() > 1 {
        return Err(GraphMutationError::BridgeArityMismatch {
            node_name: redact_str(node_name),
            reason: format!(
                "node has {} active output branches; bridging across multi-branch routing is ambiguous",
                active_outgoing.len()
            ),
        });
    }

    let distinct_in_indices: HashSet<usize> = incoming.iter().map(|x| x.3).collect();
    if distinct_in_indices.len() > 1 {
        return Err(GraphMutationError::BridgeArityMismatch {
            node_name: redact_str(node_name),
            reason: "node receives multiple distinct input indices (e.g. Merge inputs); bridging would alter multi-input arity".to_owned(),
        });
    }

    let (out_port, _, downstream_targets) = &active_outgoing[0];
    if incoming
        .iter()
        .any(|(_, in_port, _, _)| in_port != out_port)
    {
        return Err(GraphMutationError::BridgeArityMismatch {
            node_name: redact_str(node_name),
            reason: "incoming port type does not match outgoing port type".to_owned(),
        });
    }

    // Bridge every incoming `(A, port, a_branch_idx)` directly to `downstream_targets` in place!
    for (src, port_kind, branch_idx, _) in &incoming {
        if let Some(port_map) = wf.connections.get_mut(src)
            && let Some(branches) = port_map.get_mut(port_kind)
            && let Some(branch) = branches.get_mut(*branch_idx)
        {
            let mut next_branch = Vec::with_capacity(branch.len() + downstream_targets.len());
            for existing in branch.drain(..) {
                if existing.node == node_name {
                    for target in downstream_targets {
                        if !next_branch.iter().any(|e: &ConnectionEdgeIr| {
                            e.node == target.node
                                && e.port_type == target.port_type
                                && e.index == target.index
                        }) {
                            next_branch.push(target.clone());
                        }
                    }
                } else if !next_branch.iter().any(|e| {
                    e.node == existing.node
                        && e.port_type == existing.port_type
                        && e.index == existing.index
                }) {
                    next_branch.push(existing);
                }
            }
            *branch = next_branch;
        }
    }

    let removed = wf.nodes.remove(node_pos);
    remove_node_clean_references(wf, node_name, &removed.id);

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "remove_node_bridge".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_connect(
    wf: &mut WorkflowIr,
    op_index: usize,
    from_node: &str,
    to_node: &str,
    output_index: usize,
    input_index: usize,
    port_kind: &PortKind,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if wf.node_by_name(from_node).is_none() {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(from_node),
        });
    }
    if wf.node_by_name(to_node).is_none() {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(to_node),
        });
    }

    let port_map = wf.connections.entry(from_node.to_owned()).or_default();
    let branches = port_map.entry(port_kind.clone()).or_default();
    while branches.len() <= output_index {
        branches.push(Vec::new());
    }

    let branch = &mut branches[output_index];
    if !branch
        .iter()
        .any(|e| e.node == to_node && e.port_type == *port_kind && e.index == input_index)
    {
        branch.push(ConnectionEdgeIr::new(
            to_node,
            port_kind.clone(),
            input_index,
        ));
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "connect".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_disconnect(
    wf: &mut WorkflowIr,
    op_index: usize,
    from_node: &str,
    to_node: &str,
    port_filter: Option<&PortKind>,
    output_index_filter: Option<usize>,
    input_index_filter: Option<usize>,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if wf.node_by_name(from_node).is_none() {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(from_node),
        });
    }

    let Some(port_map) = wf.connections.get_mut(from_node) else {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(from_node),
            to_node: redact_str(to_node),
        });
    };

    let mut removed_count = 0usize;
    let mut empty_ports = Vec::new();

    for (port_kind, branches) in port_map.iter_mut() {
        if port_filter.is_some_and(|pf| pf != port_kind) {
            continue;
        }
        for (b_idx, branch) in branches.iter_mut().enumerate() {
            if output_index_filter.is_some_and(|of| of != b_idx) {
                continue;
            }
            let before_len = branch.len();
            branch.retain(|edge| {
                !(edge.node == to_node && input_index_filter.is_none_or(|in_f| in_f == edge.index))
            });
            removed_count += before_len - branch.len();
        }
        if branches.iter().all(Vec::is_empty) {
            empty_ports.push(port_kind.clone());
        }
    }

    if removed_count == 0 {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(from_node),
            to_node: redact_str(to_node),
        });
    }

    for p in empty_ports {
        port_map.shift_remove(&p);
    }
    if port_map.is_empty() {
        wf.connections.shift_remove(from_node);
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "disconnect".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

fn apply_rewire(
    wf: &mut WorkflowIr,
    op_index: usize,
    from_node: &str,
    old_target: &str,
    new_target: &str,
    port_filter: Option<&PortKind>,
    output_index_filter: Option<usize>,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if wf.node_by_name(from_node).is_none() {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(from_node),
        });
    }
    if wf.node_by_name(new_target).is_none() {
        return Err(GraphMutationError::NodeNotFound {
            node_name: redact_str(new_target),
        });
    }

    let Some(port_map) = wf.connections.get_mut(from_node) else {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(from_node),
            to_node: redact_str(old_target),
        });
    };

    let mut rewired_count = 0usize;
    for (port_kind, branches) in port_map.iter_mut() {
        if port_filter.is_some_and(|pf| pf != port_kind) {
            continue;
        }
        for (b_idx, branch) in branches.iter_mut().enumerate() {
            if output_index_filter.is_some_and(|of| of != b_idx) {
                continue;
            }
            let mut deduped = Vec::with_capacity(branch.len());
            for mut edge in branch.drain(..) {
                if edge.node == old_target {
                    edge.node = new_target.to_owned();
                    rewired_count += 1;
                }
                if !deduped.iter().any(|existing: &ConnectionEdgeIr| {
                    existing.node == edge.node
                        && existing.port_type == edge.port_type
                        && existing.index == edge.index
                }) {
                    deduped.push(edge);
                }
            }
            *branch = deduped;
        }
    }

    if rewired_count == 0 {
        return Err(GraphMutationError::EdgeNotFound {
            from_node: redact_str(from_node),
            to_node: redact_str(old_target),
        });
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "rewire".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: Vec::new(),
    })
}

/// Selective `AutoLayout`: ONLY repositions nodes explicitly named in `node_names`; untouched canvas
/// nodes retain their exact coordinates bit-for-bit!
fn apply_auto_layout(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_names: &[String],
) -> Result<AppliedOpOutcome, GraphMutationError> {
    if node_names.is_empty() {
        return Err(GraphMutationError::EmptyAutoLayoutSelection);
    }

    let mut selected_set = HashSet::with_capacity(node_names.len());
    for name in node_names {
        if wf.node_by_name(name).is_none() {
            return Err(GraphMutationError::NodeNotFound {
                node_name: redact_str(name),
            });
        }
        selected_set.insert(name.clone());
    }

    // Track occupied positions of untouched canvas nodes so newly laid-out nodes avoid collisions.
    let mut occupied: Vec<[f64; 2]> = wf
        .nodes
        .iter()
        .filter(|n| !selected_set.contains(&n.name) && !is_canvas_annotation_type(&n.node_type))
        .map(|n| n.position)
        .collect();

    // Map incoming execution edges and outgoing AI host attachments.
    let mut incoming_exec: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    let mut outgoing_ai_host: BTreeMap<String, String> = BTreeMap::new();

    for (src, port_map) in &wf.connections {
        for (port_kind, branches) in port_map {
            for (b_idx, branch) in branches.iter().enumerate() {
                for edge in branch {
                    if port_kind.is_ai_subnode_port() {
                        outgoing_ai_host
                            .entry(src.clone())
                            .or_insert_with(|| edge.node.clone());
                    } else {
                        incoming_exec
                            .entry(edge.node.clone())
                            .or_default()
                            .push((src.clone(), b_idx));
                    }
                }
            }
        }
    }

    let mut placed_positions: HashMap<String, [f64; 2]> = wf
        .nodes
        .iter()
        .filter(|n| !selected_set.contains(&n.name))
        .map(|n| (n.name.clone(), n.position))
        .collect();

    for (order_idx, name) in node_names.iter().enumerate() {
        let Some(node_ref) = wf.node_by_name(name) else {
            continue;
        };
        let candidate = if is_ai_subnode_provider_type(&node_ref.node_type)
            && let Some(host_name) = outgoing_ai_host.get(name)
            && let Some(&host_pos) = placed_positions.get(host_name)
        {
            #[allow(clippy::cast_precision_loss)]
            [
                host_pos[0] + (order_idx as f64) * 180.0,
                host_pos[1] + 200.0,
            ]
        } else if let Some(preds) = incoming_exec.get(name)
            && let Some((pred_name, branch_idx)) =
                preds.iter().find(|(p, _)| placed_positions.contains_key(p))
            && let Some(&pred_pos) = placed_positions.get(pred_name)
        {
            #[allow(clippy::cast_precision_loss)]
            [
                pred_pos[0] + 260.0,
                pred_pos[1] + (*branch_idx as f64) * 160.0,
            ]
        } else {
            #[allow(clippy::cast_precision_loss)]
            [240.0 + (order_idx as f64) * 260.0, 300.0]
        };

        let resolved = resolve_canvas_collision(candidate, &occupied);
        occupied.push(resolved);
        placed_positions.insert(name.clone(), resolved);
    }

    for node in &mut wf.nodes {
        if selected_set.contains(&node.name)
            && let Some(&pos) = placed_positions.get(&node.name)
        {
            node.position = pos;
        }
    }

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "auto_layout".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: vec![format!(
            "Repositioned {} explicitly requested node(s); all other canvas nodes left untouched.",
            selected_set.len()
        )],
    })
}

fn resolve_canvas_collision(mut candidate: [f64; 2], occupied: &[[f64; 2]]) -> [f64; 2] {
    for _ in 0..64 {
        let collides = occupied
            .iter()
            .any(|p| (p[0] - candidate[0]).abs() < 120.0 && (p[1] - candidate[1]).abs() < 100.0);
        if !collides {
            return candidate;
        }
        candidate[1] += 140.0;
    }
    candidate
}

fn apply_set_node_groups(
    wf: &mut WorkflowIr,
    op_index: usize,
    raw_groups: &Value,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let mut parsed_groups: Vec<NodeGroupIr> =
        serde_json::from_value(raw_groups.clone()).map_err(|e| {
            GraphMutationError::InvalidNodeGroups {
                reason: redact_str(&e.to_string()),
            }
        })?;

    let known_node_ids: HashSet<&str> = wf
        .nodes
        .iter()
        .filter(|n| !n.id.is_empty())
        .map(|n| n.id.as_str())
        .collect();
    let mut seen_group_ids = HashSet::with_capacity(parsed_groups.len());
    let mut assigned_node_to_group: HashMap<String, String> = HashMap::new();

    for grp in &mut parsed_groups {
        if grp.id.trim().is_empty() {
            return Err(GraphMutationError::InvalidNodeGroups {
                reason: "nodeGroup `id` must not be empty".to_owned(),
            });
        }
        if !seen_group_ids.insert(grp.id.clone()) {
            return Err(GraphMutationError::InvalidNodeGroups {
                reason: format!("duplicate nodeGroup id `{}`", redact_str(&grp.id)),
            });
        }

        let mut deduped_members = Vec::with_capacity(grp.node_ids.len());
        for member_id in &grp.node_ids {
            if !known_node_ids.contains(member_id.as_str()) {
                return Err(GraphMutationError::InvalidNodeGroups {
                    reason: format!(
                        "nodeGroup `{}` references unknown node ID `{}`",
                        redact_str(&grp.id),
                        redact_str(member_id)
                    ),
                });
            }
            if let Some(prev_grp) = assigned_node_to_group.get(member_id) {
                if prev_grp != &grp.id {
                    return Err(GraphMutationError::InvalidNodeGroups {
                        reason: format!(
                            "n8n 2.41+ group conflict: node ID `{}` cannot belong to both `{}` and `{}`",
                            redact_str(member_id),
                            redact_str(prev_grp),
                            redact_str(&grp.id)
                        ),
                    });
                }
            } else {
                assigned_node_to_group.insert(member_id.clone(), grp.id.clone());
                deduped_members.push(member_id.clone());
            }
        }
        grp.node_ids = deduped_members;
    }

    wf.node_groups = Some(parsed_groups);

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "set_node_groups".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes: vec![
            "Validated n8n 2.41+ node group member IDs; check `skippedOperations`/`removedGroups` if routed via Native MCP.".to_owned(),
        ],
    })
}

fn apply_upgrade_node_version(
    wf: &mut WorkflowIr,
    op_index: usize,
    node_name: &str,
    target_version: &str,
    ctx: &MutationContext,
) -> Result<AppliedOpOutcome, GraphMutationError> {
    let target_trimmed = target_version.trim();
    if target_trimmed.is_empty() {
        return Err(GraphMutationError::MigrationFailed {
            node_name: redact_str(node_name),
            reason: "`target_version` cannot be empty".to_owned(),
        });
    }

    let node = wf
        .node_by_name_mut(node_name)
        .ok_or_else(|| GraphMutationError::NodeNotFound {
            node_name: redact_str(node_name),
        })?;

    let current_version = node.type_version_string();
    if current_version == target_trimmed {
        return Ok(AppliedOpOutcome {
            op_index,
            op_kind: "upgrade_node_version".to_owned(),
            requires_whole_array_or_api_fallback: false,
            whole_array_fallback: None,
            rename_safety: None,
            notes: vec![format!("Node already at typeVersion {target_trimmed}.")],
        });
    }

    let Some(transform) =
        ctx.migration_registry
            .get(&node.node_type, &current_version, target_trimmed)
    else {
        return Err(GraphMutationError::MigrationMissing {
            node_name: redact_str(node_name),
            node_type: redact_str(&node.node_type),
            current_version: redact_str(&current_version),
            target_version: redact_str(target_trimmed),
        });
    };

    let mut candidate = node.clone();
    let notes = transform.migrate(&mut candidate).map_err(|reason| {
        GraphMutationError::MigrationFailed {
            node_name: redact_str(node_name),
            reason: redact_str(&reason),
        }
    })?;

    candidate.type_version = parse_version_json_value(target_trimmed);
    *node = candidate;

    Ok(AppliedOpOutcome {
        op_index,
        op_kind: "upgrade_node_version".to_owned(),
        requires_whole_array_or_api_fallback: false,
        whole_array_fallback: None,
        rename_safety: None,
        notes,
    })
}

fn parse_version_json_value(raw: &str) -> Value {
    if let Ok(int_v) = raw.parse::<u64>() {
        Value::Number(Number::from(int_v))
    } else if let Ok(float_v) = raw.parse::<f64>()
        && let Some(num) = Number::from_f64(float_v)
    {
        Value::Number(num)
    } else {
        Value::String(raw.to_owned())
    }
}
