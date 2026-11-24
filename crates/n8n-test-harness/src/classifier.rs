//! Deterministic workflow side-effect classifier for V2 Section 8 (`T1 Simulate` safety gate).
//!
//! Key security invariants:
//! - Resolves reachable nodes from a selected `trigger_node` (or all enabled triggers, plus
//!   transitively attached `ai_*` sub-node providers and enabled error triggers).
//! - Classifies credential-free host/filesystem/shell/runtime I/O nodes (`executeCommand`,
//!   `readWriteFile`, `localFileTrigger`, `writeBinaryFile`, `readBinaryFiles`, `ssh`, `ftp`, and
//!   `code` nodes referencing `child_process`, `fs`, `Deno`, `Bun`, or Python `subprocess`/`shutil`)
//!   as [`NodeSideEffectClass::HostOrFilesystemIo`].
//! - **CRITICAL V2 SECTION 8 RULE:** Never assume pin data blocks credential-free host/filesystem
//!   I/O nodes! `T1 Simulate` ALWAYS blocks [`NodeSideEffectClass::HostOrFilesystemIo`] even when
//!   credentialed/HTTP/DB nodes (or the host node itself) are listed in `pinned_nodes`.
//! - Recursively inspects `executeWorkflow` / `toolWorkflow` subworkflows; if any referenced
//!   subworkflow is absent from `subworkflows`, uses a dynamic expression, or forms a cycle,
//!   marks [`SideEffectVerdict::UnknownSubworkflowFailClosed`] and blocks `T1 Simulate`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::LazyLock;

use n8n_graph::{
    PortKind, WorkflowIr, WorkflowNodeIr, is_any_trigger_type, is_canvas_annotation_type,
    is_error_trigger_type,
};
use n8n_types::redact_str;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum recursive `executeWorkflow` nesting depth inspected before failing closed.
pub const MAX_SUBWORKFLOW_RECURSION_DEPTH: usize = 16;

static CODE_HOST_IO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:\b(?:child_process|Deno|Bun|worker_threads|subprocess|shutil)\b|\bnode:(?:child_process|fs|net|dgram|tls|worker_threads)\b|\bfs\b|\bprocess\.(?:binding|dlopen)\b|\bos\.(?:system|popen|spawn[a-z]*|exec[a-z]*|remove|unlink|rmdir)\b)",
    )
    .expect("valid static code host I/O regex")
});

static CODE_NETWORK_IO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\baxios\b|\b\$http\b|\bhttp\.request\b|\bhttps\.request\b|\burllib\b|\brequests\.(?:get|post|put| patch|delete|request)\b)",
    )
    .expect("valid static code network I/O regex")
});

/// Side-effect risk class assigned to a reachable workflow node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeSideEffectClass {
    /// Purely deterministic local transform, control-flow, or trigger node.
    DeterministicLocalTransform,
    /// External network, SaaS, LLM, message queue, or database I/O node.
    /// Permitted in `T1 Simulate` ONLY when mocked via `pinned_nodes` (or isolated sandbox stub).
    ExternalCredentialedOrNetworkIo,
    /// Credential-free or host-level command/filesystem/binary/SSH/FTP/runtime-exec I/O node.
    /// ALWAYS blocked in `T1 Simulate` even when `pinned_nodes` pins HTTP/DB or host nodes!
    HostOrFilesystemIo,
    /// Subworkflow call (`executeWorkflow` / `toolWorkflow`) requiring recursive subworkflow inspection.
    SubworkflowInvocation,
    /// Unrecognized community/custom node type — treated fail-closed in `T1 Simulate`.
    UnknownOrCustomNode,
}

/// Overall `T1 Simulate` safety verdict produced by [`classify_workflow_side_effects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectVerdict {
    /// Safe to run in `T1 Simulate` (all external I/O nodes are pinned, zero host I/O, zero unknown subworkflows).
    SafeForSimulate,
    /// Blocked fail-closed because a reachable `executeWorkflow` subworkflow is missing, dynamic, or cyclic.
    UnknownSubworkflowFailClosed,
    /// Blocked because a reachable node performs host/command/filesystem I/O (`HostOrFilesystemIo`).
    BlockedHostOrFilesystemIo,
    /// Blocked because a reachable external/network/DB/custom node is unpinned or trigger resolution failed.
    BlockedUnpinnedExternalOrUnknownIo,
}

/// Per-node side-effect classification record (including nested subworkflow provenance when applicable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedNodeEffect {
    /// Qualified display path (`NodeName` for root workflow, `sub_id::NodeName` for nested subworkflows).
    pub qualified_name: String,
    pub workflow_id: Option<String>,
    pub node_id: String,
    pub node_name: String,
    pub node_type: String,
    pub class: NodeSideEffectClass,
    pub is_pinned: bool,
    pub blocks_t1_simulate: bool,
    pub reason: String,
}

/// Complete side-effect classification report across a workflow and its reachable subworkflows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SideEffectClassification {
    pub verdict: SideEffectVerdict,
    pub selected_trigger: Option<String>,
    pub trigger_found: bool,
    pub reachable_nodes: Vec<String>,
    pub classified_nodes: Vec<ClassifiedNodeEffect>,
    pub host_io_nodes: Vec<String>,
    pub unpinned_external_nodes: Vec<String>,
    pub pinned_external_nodes: Vec<String>,
    pub unknown_subworkflows: Vec<String>,
    pub unknown_custom_nodes: Vec<String>,
    pub inspected_subworkflow_ids: Vec<String>,
    /// `true` iff `verdict == SafeForSimulate` AND every reachable node is a pure local transform
    /// (no pinned external nodes, no code nodes requiring live JS/Python task runners, no subworkflows).
    pub all_reachable_deterministic_local: bool,
    pub blocking_reasons: Vec<String>,
}

impl SideEffectClassification {
    /// Returns `true` ONLY when `verdict == SideEffectVerdict::SafeForSimulate`.
    #[must_use]
    pub const fn allows_t1_simulate(&self) -> bool {
        matches!(self.verdict, SideEffectVerdict::SafeForSimulate)
    }

    /// Returns `true` if any reachable node performs host/filesystem I/O.
    #[must_use]
    pub fn has_host_or_filesystem_io(&self) -> bool {
        !self.host_io_nodes.is_empty()
    }
}

/// Returns `true` if a node type can execute host commands, read/write local files, or open SSH/FTP sessions.
#[must_use]
pub fn is_high_risk_local_io_node(node_type: &str) -> bool {
    matches!(
        node_type,
        "n8n-nodes-base.executeCommand"
            | "n8n-nodes-base.readWriteFile"
            | "n8n-nodes-base.localFileTrigger"
            | "n8n-nodes-base.writeBinaryFile"
            | "n8n-nodes-base.readBinaryFiles"
            | "n8n-nodes-base.readBinaryFile"
            | "n8n-nodes-base.ssh"
            | "n8n-nodes-base.ftp"
    )
}

/// Classifies a single [`WorkflowNodeIr`] into its [`NodeSideEffectClass`] + human-readable reason.
#[must_use]
pub fn classify_single_node(node: &WorkflowNodeIr) -> (NodeSideEffectClass, String) {
    let nt = node.node_type.as_str();

    if is_high_risk_local_io_node(nt) {
        return (
            NodeSideEffectClass::HostOrFilesystemIo,
            format!(
                "Node `{}` (`{nt}`) performs host command, local filesystem, or SSH/FTP I/O that pinning cannot neutralize.",
                redact_str(&node.name)
            ),
        );
    }

    if matches!(
        nt,
        "n8n-nodes-base.executeWorkflow" | "@n8n/n8n-nodes-langchain.toolWorkflow"
    ) {
        return (
            NodeSideEffectClass::SubworkflowInvocation,
            format!(
                "Node `{}` (`{nt}`) invokes a nested subworkflow whose reachable graph must be inspected.",
                redact_str(&node.name)
            ),
        );
    }

    if matches!(
        nt,
        "n8n-nodes-base.code"
            | "n8n-nodes-base.function"
            | "n8n-nodes-base.functionItem"
            | "@n8n/n8n-nodes-langchain.toolCode"
    ) {
        let mut code_blobs = Vec::new();
        collect_code_strings(&node.parameters, &mut code_blobs);
        for snippet in &code_blobs {
            if let Some(m) = CODE_HOST_IO_RE.find(snippet) {
                return (
                    NodeSideEffectClass::HostOrFilesystemIo,
                    format!(
                        "Code node `{}` (`{nt}`) references host/filesystem API `{}`.",
                        redact_str(&node.name),
                        redact_str(m.as_str())
                    ),
                );
            }
        }
        for snippet in &code_blobs {
            if let Some(m) = CODE_NETWORK_IO_RE.find(snippet) {
                return (
                    NodeSideEffectClass::ExternalCredentialedOrNetworkIo,
                    format!(
                        "Code node `{}` (`{nt}`) performs outbound network call via `{}`.",
                        redact_str(&node.name),
                        redact_str(m.as_str())
                    ),
                );
            }
        }
        return (
            NodeSideEffectClass::DeterministicLocalTransform,
            format!(
                "Code node `{}` (`{nt}`) contains pure in-memory transformation logic.",
                redact_str(&node.name)
            ),
        );
    }

    if is_known_external_network_or_db_node(nt) {
        return (
            NodeSideEffectClass::ExternalCredentialedOrNetworkIo,
            format!(
                "Node `{}` (`{nt}`) performs external network, database, data-table, queue, or SaaS I/O.",
                redact_str(&node.name)
            ),
        );
    }

    if is_pure_deterministic_local_node(nt) {
        return (
            NodeSideEffectClass::DeterministicLocalTransform,
            format!(
                "Node `{}` (`{nt}`) is a deterministic local trigger/transform/control-flow node.",
                redact_str(&node.name)
            ),
        );
    }

    // Any remaining node with bound credentials (other than pure incoming auth triggers handled above)
    // is an external credentialed integration.
    if node
        .credentials
        .as_ref()
        .is_some_and(|creds| !creds.is_empty())
    {
        return (
            NodeSideEffectClass::ExternalCredentialedOrNetworkIo,
            format!(
                "Node `{}` (`{nt}`) binds external credentials and may perform external side effects.",
                redact_str(&node.name)
            ),
        );
    }

    (
        NodeSideEffectClass::UnknownOrCustomNode,
        format!(
            "Unrecognized or community node `{}` (`{nt}`) cannot be proven side-effect-free offline.",
            redact_str(&node.name)
        ),
    )
}

/// Classifies all reachable side effects across `ir` and any referenced `subworkflows` from `trigger_node`
/// (or all enabled triggers when `trigger_node` is `None`).
#[must_use]
pub fn classify_workflow_side_effects(
    ir: &WorkflowIr,
    subworkflows: &HashMap<String, WorkflowIr>,
    pinned_nodes: &HashSet<String>,
    trigger_node: Option<&str>,
) -> SideEffectClassification {
    let mut state = ClassificationAccumulator::default();
    let mut active_stack = HashSet::new();
    if let Some(ref root_id) = ir.id {
        active_stack.insert(root_id.clone());
    }

    inspect_workflow_recursive(
        ir,
        subworkflows,
        pinned_nodes,
        trigger_node,
        None,
        0,
        &mut active_stack,
        &mut state,
    );

    let verdict = if !state.host_io_nodes.is_empty() {
        SideEffectVerdict::BlockedHostOrFilesystemIo
    } else if !state.unknown_subworkflows.is_empty() {
        SideEffectVerdict::UnknownSubworkflowFailClosed
    } else if !state.trigger_found
        || !state.unpinned_external_nodes.is_empty()
        || !state.unknown_custom_nodes.is_empty()
    {
        SideEffectVerdict::BlockedUnpinnedExternalOrUnknownIo
    } else {
        SideEffectVerdict::SafeForSimulate
    };

    let all_reachable_deterministic_local = verdict == SideEffectVerdict::SafeForSimulate
        && state.pinned_external_nodes.is_empty()
        && state.inspected_subworkflow_ids.is_empty()
        && !state.has_code_runner_node
        && !state.reachable_nodes.is_empty();

    SideEffectClassification {
        verdict,
        selected_trigger: trigger_node.map(redact_str),
        trigger_found: state.trigger_found,
        reachable_nodes: state.reachable_nodes,
        classified_nodes: state.classified_nodes,
        host_io_nodes: state.host_io_nodes.into_iter().collect(),
        unpinned_external_nodes: state.unpinned_external_nodes.into_iter().collect(),
        pinned_external_nodes: state.pinned_external_nodes.into_iter().collect(),
        unknown_subworkflows: state.unknown_subworkflows.into_iter().collect(),
        unknown_custom_nodes: state.unknown_custom_nodes.into_iter().collect(),
        inspected_subworkflow_ids: state.inspected_subworkflow_ids.into_iter().collect(),
        all_reachable_deterministic_local,
        blocking_reasons: state.blocking_reasons,
    }
}

#[derive(Default)]
struct ClassificationAccumulator {
    trigger_found: bool,
    reachable_nodes: Vec<String>,
    classified_nodes: Vec<ClassifiedNodeEffect>,
    host_io_nodes: BTreeSet<String>,
    unpinned_external_nodes: BTreeSet<String>,
    pinned_external_nodes: BTreeSet<String>,
    unknown_subworkflows: BTreeSet<String>,
    unknown_custom_nodes: BTreeSet<String>,
    inspected_subworkflow_ids: BTreeSet<String>,
    has_code_runner_node: bool,
    blocking_reasons: Vec<String>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn inspect_workflow_recursive(
    ir: &WorkflowIr,
    subworkflows: &HashMap<String, WorkflowIr>,
    pinned_nodes: &HashSet<String>,
    trigger_node: Option<&str>,
    prefix: Option<&str>,
    depth: usize,
    active_stack: &mut HashSet<String>,
    acc: &mut ClassificationAccumulator,
) {
    if depth > MAX_SUBWORKFLOW_RECURSION_DEPTH {
        let marker = prefix.unwrap_or("<root>").to_owned();
        acc.unknown_subworkflows.insert(marker.clone());
        acc.blocking_reasons.push(format!(
            "Subworkflow recursion depth exceeded maximum ({MAX_SUBWORKFLOW_RECURSION_DEPTH}) at `{marker}`."
        ));
        return;
    }

    let (reachable, trig_ok) = resolve_reachable_nodes(ir, trigger_node);
    if depth == 0 {
        acc.trigger_found = trig_ok;
        if !trig_ok {
            acc.blocking_reasons.push(format!(
                "Selected trigger `{}` was not found or is disabled in workflow.",
                redact_str(trigger_node.unwrap_or("<unknown>"))
            ));
            return;
        }
    }

    for node in reachable {
        let qualified = match prefix {
            Some(p) => format!("{p}::{}", redact_str(&node.name)),
            None => redact_str(&node.name),
        };
        if depth == 0 {
            acc.reachable_nodes.push(node.name.clone());
        }

        if matches!(
            node.node_type.as_str(),
            "n8n-nodes-base.code"
                | "n8n-nodes-base.function"
                | "n8n-nodes-base.functionItem"
                | "@n8n/n8n-nodes-langchain.toolCode"
                | "@n8n/n8n-nodes-langchain.agent"
        ) || node.node_type.starts_with("@n8n/n8n-nodes-langchain.chain")
        {
            acc.has_code_runner_node = true;
        }

        let is_pinned = pinned_nodes.contains(&node.name) || pinned_nodes.contains(&qualified);
        let (class, reason) = classify_single_node(node);

        let blocks_t1 = match class {
            NodeSideEffectClass::DeterministicLocalTransform => false,
            NodeSideEffectClass::HostOrFilesystemIo => {
                // CRITICAL V2 SECTION 8 INVARIANT:
                // Never assume pinning blocks credential-free host/filesystem/command I/O nodes!
                acc.host_io_nodes.insert(qualified.clone());
                acc.blocking_reasons.push(format!(
                    "Host/filesystem I/O node `{qualified}` (`{}`) is blocked in `T1 Simulate` even if other or same nodes are pinned.",
                    redact_str(&node.node_type)
                ));
                true
            }
            NodeSideEffectClass::ExternalCredentialedOrNetworkIo => {
                if is_pinned {
                    acc.pinned_external_nodes.insert(qualified.clone());
                    false
                } else {
                    acc.unpinned_external_nodes.insert(qualified.clone());
                    acc.blocking_reasons.push(format!(
                        "External/network/DB node `{qualified}` (`{}`) is reachable and not mocked in `pinned_nodes`.",
                        redact_str(&node.node_type)
                    ));
                    true
                }
            }
            NodeSideEffectClass::UnknownOrCustomNode => {
                acc.unknown_custom_nodes.insert(qualified.clone());
                acc.blocking_reasons.push(format!(
                    "Unknown/community node `{qualified}` (`{}`) cannot be verified side-effect-free for `T1 Simulate`.",
                    redact_str(&node.node_type)
                ));
                true
            }
            NodeSideEffectClass::SubworkflowInvocation => {
                match extract_subworkflow_reference(node) {
                    SubworkflowRefKind::StaticId(sub_id) => {
                        if active_stack.contains(&sub_id) {
                            acc.unknown_subworkflows.insert(sub_id.clone());
                            acc.blocking_reasons.push(format!(
                                "Cyclic subworkflow reference `{sub_id}` from `{qualified}` blocked fail-closed."
                            ));
                            true
                        } else if let Some(sub_ir) = subworkflows.get(&sub_id) {
                            acc.inspected_subworkflow_ids.insert(sub_id.clone());
                            active_stack.insert(sub_id.clone());
                            let sub_prefix = match prefix {
                                Some(p) => format!("{p}::{sub_id}"),
                                None => sub_id.clone(),
                            };
                            let host_before = acc.host_io_nodes.len();
                            let unpinned_before = acc.unpinned_external_nodes.len();
                            let unknown_sub_before = acc.unknown_subworkflows.len();
                            let unknown_cust_before = acc.unknown_custom_nodes.len();

                            inspect_workflow_recursive(
                                sub_ir,
                                subworkflows,
                                pinned_nodes,
                                None,
                                Some(&sub_prefix),
                                depth + 1,
                                active_stack,
                                acc,
                            );
                            active_stack.remove(&sub_id);

                            acc.host_io_nodes.len() > host_before
                                || acc.unpinned_external_nodes.len() > unpinned_before
                                || acc.unknown_subworkflows.len() > unknown_sub_before
                                || acc.unknown_custom_nodes.len() > unknown_cust_before
                        } else {
                            acc.unknown_subworkflows.insert(sub_id.clone());
                            acc.blocking_reasons.push(format!(
                                "Subworkflow `{sub_id}` referenced by `{qualified}` is absent from `subworkflows` (fail-closed)."
                            ));
                            true
                        }
                    }
                    SubworkflowRefKind::DynamicExpression(expr_preview) => {
                        let tag = format!("{qualified}:<dynamic:{expr_preview}>");
                        acc.unknown_subworkflows.insert(tag);
                        acc.blocking_reasons.push(format!(
                            "Subworkflow node `{qualified}` uses a dynamic `workflowId` expression and cannot be statically verified (fail-closed)."
                        ));
                        true
                    }
                    SubworkflowRefKind::Missing => {
                        let tag = format!("{qualified}:<missing_workflow_id>");
                        acc.unknown_subworkflows.insert(tag);
                        acc.blocking_reasons.push(format!(
                            "Subworkflow node `{qualified}` has no static `workflowId` configured (fail-closed)."
                        ));
                        true
                    }
                }
            }
        };

        acc.classified_nodes.push(ClassifiedNodeEffect {
            qualified_name: qualified,
            workflow_id: ir.id.clone(),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            node_type: node.node_type.clone(),
            class,
            is_pinned,
            blocks_t1_simulate: blocks_t1,
            reason,
        });
    }
}

/// Resolves enabled non-annotation nodes reachable from `trigger_node` (or all enabled triggers),
/// including transitively attached incoming `ai_*` provider sub-nodes.
fn resolve_reachable_nodes<'a>(
    ir: &'a WorkflowIr,
    trigger_node: Option<&str>,
) -> (Vec<&'a WorkflowNodeIr>, bool) {
    let mut enabled_by_name: HashMap<&str, &'a WorkflowNodeIr> = HashMap::new();
    for node in &ir.nodes {
        if !node.disabled && !is_canvas_annotation_type(&node.node_type) {
            enabled_by_name.insert(node.name.as_str(), node);
        }
    }

    // Build forward (`main`/`error`/custom) and reverse `ai_*` provider adjacency maps.
    let mut forward_adj: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut incoming_ai_providers: HashMap<&str, Vec<&str>> = HashMap::new();

    for (src_name, port_map) in &ir.connections {
        if !enabled_by_name.contains_key(src_name.as_str()) {
            continue;
        }
        for (port_kind, branches) in port_map {
            for branch in branches {
                for edge in branch {
                    let Some(&dst_node) = enabled_by_name.get(edge.node.as_str()) else {
                        continue;
                    };
                    if port_kind.is_ai_subnode_port() || edge.port_type.is_ai_subnode_port() {
                        incoming_ai_providers
                            .entry(dst_node.name.as_str())
                            .or_default()
                            .push(src_name.as_str());
                    } else {
                        forward_adj
                            .entry(src_name.as_str())
                            .or_default()
                            .push(dst_node.name.as_str());
                    }
                }
            }
        }
    }

    let mut seeds: Vec<&str> = Vec::new();
    if let Some(trig) = trigger_node {
        let Some(&node) = enabled_by_name.get(trig) else {
            return (Vec::new(), false);
        };
        seeds.push(node.name.as_str());
    } else {
        for node in &ir.nodes {
            if !node.disabled
                && !is_canvas_annotation_type(&node.node_type)
                && (is_any_trigger_type(&node.node_type)
                    || is_error_trigger_type(&node.node_type)
                    || is_subworkflow_or_legacy_trigger(&node.node_type))
            {
                seeds.push(node.name.as_str());
            }
        }
        // If a subworkflow or draft fragment has no explicit trigger node, inspect all enabled
        // non-annotation nodes conservatively so side effects can never hide behind missing triggers.
        if seeds.is_empty() {
            for node in &ir.nodes {
                if !node.disabled && !is_canvas_annotation_type(&node.node_type) {
                    seeds.push(node.name.as_str());
                }
            }
        }
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for s in seeds {
        if visited.insert(s) {
            queue.push_back(s);
        }
    }

    while let Some(curr) = queue.pop_front() {
        if let Some(nexts) = forward_adj.get(curr) {
            for &nxt in nexts {
                if visited.insert(nxt) {
                    queue.push_back(nxt);
                }
            }
        }
        // Any reachable consumer node also activates its attached `ai_*` provider tree!
        if let Some(providers) = incoming_ai_providers.get(curr) {
            for &prov in providers {
                if visited.insert(prov) {
                    queue.push_back(prov);
                }
            }
        }
    }

    // Preserve deterministic declaration order from `ir.nodes`.
    let mut ordered = Vec::with_capacity(visited.len());
    for node in &ir.nodes {
        if visited.contains(node.name.as_str()) {
            ordered.push(node);
        }
    }

    (ordered, true)
}

enum SubworkflowRefKind {
    StaticId(String),
    DynamicExpression(String),
    Missing,
}

fn extract_subworkflow_reference(node: &WorkflowNodeIr) -> SubworkflowRefKind {
    let Some(raw) = node.parameters.get("workflowId") else {
        return SubworkflowRefKind::Missing;
    };

    let candidate = match raw {
        Value::String(s) => Some(s.trim()),
        Value::Number(n) => return SubworkflowRefKind::StaticId(n.to_string()),
        Value::Object(obj) => obj
            .get("value")
            .or_else(|| obj.get("id"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.trim()),
                _ => None,
            }),
        _ => None,
    };

    match candidate {
        None | Some("") => SubworkflowRefKind::Missing,
        Some(s)
            if (s.starts_with('=') && s.contains("{{"))
                || s.contains("$json")
                || s.contains("$(") =>
        {
            let preview: String = s.chars().take(48).collect();
            SubworkflowRefKind::DynamicExpression(redact_str(&preview))
        }
        Some(s) => SubworkflowRefKind::StaticId(redact_str(s)),
    }
}

fn collect_code_strings(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                collect_code_strings(item, out);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_code_strings(item, out);
            }
        }
        _ => {}
    }
}

fn is_subworkflow_or_legacy_trigger(node_type: &str) -> bool {
    matches!(
        node_type,
        "n8n-nodes-base.executeWorkflowTrigger"
            | "n8n-nodes-base.start"
            | "n8n-nodes-base.manualTrigger"
    )
}

fn is_known_external_network_or_db_node(node_type: &str) -> bool {
    matches!(
        node_type,
        "n8n-nodes-base.httpRequest"
            | "@n8n/n8n-nodes-langchain.toolHttpRequest"
            | "n8n-nodes-base.graphql"
            | "n8n-nodes-base.postgres"
            | "n8n-nodes-base.mySql"
            | "n8n-nodes-base.mysql"
            | "n8n-nodes-base.microsoftSql"
            | "n8n-nodes-base.mongoDb"
            | "n8n-nodes-base.redis"
            | "n8n-nodes-base.questDb"
            | "n8n-nodes-base.snowflake"
            | "n8n-nodes-base.googleBigQuery"
            | "n8n-nodes-base.supabase"
            | "n8n-nodes-base.crateDb"
            | "n8n-nodes-base.timescaleDb"
            | "n8n-nodes-base.awsDynamoDb"
            | "n8n-nodes-base.dataTable"
            | "n8n-nodes-base.n8nDataTable"
            | "n8n-nodes-base.airtable"
            | "n8n-nodes-base.googleSheets"
            | "n8n-nodes-base.nocodb"
            | "n8n-nodes-base.baserow"
            | "n8n-nodes-base.slack"
            | "n8n-nodes-base.microsoftTeams"
            | "n8n-nodes-base.gmail"
            | "n8n-nodes-base.emailSend"
            | "n8n-nodes-base.sendEmail"
            | "n8n-nodes-base.discord"
            | "n8n-nodes-base.telegram"
            | "n8n-nodes-base.twilio"
            | "n8n-nodes-base.stripe"
            | "n8n-nodes-base.github"
            | "n8n-nodes-base.gitlab"
            | "n8n-nodes-base.jira"
            | "n8n-nodes-base.linear"
            | "n8n-nodes-base.notion"
            | "n8n-nodes-base.hubspot"
            | "n8n-nodes-base.salesforce"
            | "n8n-nodes-base.awsS3"
            | "n8n-nodes-base.googleCloudStorage"
            | "n8n-nodes-base.amqp"
            | "n8n-nodes-base.kafka"
            | "n8n-nodes-base.rabbitMq"
            | "n8n-nodes-base.mqtt"
            | "n8n-nodes-base.n8n"
    ) || node_type.starts_with("@n8n/n8n-nodes-langchain.lm")
        || node_type.starts_with("@n8n/n8n-nodes-langchain.embeddings")
        || node_type.starts_with("@n8n/n8n-nodes-langchain.openAi")
        || (node_type.starts_with("@n8n/n8n-nodes-langchain.vectorStore")
            && node_type != "@n8n/n8n-nodes-langchain.vectorStoreInMemory")
}

fn is_pure_deterministic_local_node(node_type: &str) -> bool {
    if node_type == "n8n-nodes-base.localFileTrigger" {
        return false;
    }

    matches!(
        node_type,
        "n8n-nodes-base.manualTrigger"
            | "n8n-nodes-base.webhook"
            | "n8n-nodes-base.scheduleTrigger"
            | "n8n-nodes-base.cron"
            | "n8n-nodes-base.interval"
            | "n8n-nodes-base.formTrigger"
            | "n8n-nodes-base.executeWorkflowTrigger"
            | "n8n-nodes-base.errorTrigger"
            | "n8n-nodes-base.start"
            | "@n8n/n8n-nodes-langchain.chatTrigger"
            | "n8n-nodes-base.set"
            | "n8n-nodes-base.if"
            | "n8n-nodes-base.switch"
            | "n8n-nodes-base.merge"
            | "n8n-nodes-base.splitInBatches"
            | "n8n-nodes-base.splitOut"
            | "n8n-nodes-base.itemLists"
            | "n8n-nodes-base.aggregate"
            | "n8n-nodes-base.summarize"
            | "n8n-nodes-base.filter"
            | "n8n-nodes-base.removeDuplicates"
            | "n8n-nodes-base.sort"
            | "n8n-nodes-base.limit"
            | "n8n-nodes-base.dateTime"
            | "n8n-nodes-base.compareDatasets"
            | "n8n-nodes-base.renameKeys"
            | "n8n-nodes-base.crypto"
            | "n8n-nodes-base.xml"
            | "n8n-nodes-base.html"
            | "n8n-nodes-base.markdown"
            | "n8n-nodes-base.compression"
            | "n8n-nodes-base.spreadsheetFile"
            | "n8n-nodes-base.extractFromFile"
            | "n8n-nodes-base.convertToFile"
            | "n8n-nodes-base.moveBinaryData"
            | "n8n-nodes-base.noOp"
            | "n8n-nodes-base.wait"
            | "n8n-nodes-base.stopAndError"
            | "n8n-nodes-base.respondToWebhook"
            | "@n8n/n8n-nodes-langchain.memoryBufferWindow"
            | "@n8n/n8n-nodes-langchain.outputParserStructured"
            | "@n8n/n8n-nodes-langchain.outputParserItemList"
            | "@n8n/n8n-nodes-langchain.outputParserAutofixing"
            | "@n8n/n8n-nodes-langchain.documentDefaultDataLoader"
            | "@n8n/n8n-nodes-langchain.retrieverVectorStore"
            | "@n8n/n8n-nodes-langchain.toolVectorStore"
            | "@n8n/n8n-nodes-langchain.vectorStoreInMemory"
            | "@n8n/n8n-nodes-langchain.agent"
    ) || node_type.starts_with("@n8n/n8n-nodes-langchain.textSplitter")
        || node_type.starts_with("@n8n/n8n-nodes-langchain.chain")
}

// Keep PortKind referenced explicitly for clarity around AI sub-node ports.
const _: fn(&PortKind) -> bool = PortKind::is_ai_subnode_port;
