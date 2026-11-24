//! `petgraph`-backed n8n workflow graph topology engine supporting legitimate loops
//! (`splitInBatches` / `Loop Over Items` / polling retry loops), trigger reachability,
//! disconnected-node & ambiguous multi-trigger detection, AI sub-node port validation,
//! and safe upstream/downstream port & data-shape lineage.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use petgraph::Direction;
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::{PortKind, WorkflowIr, WorkflowNodeIr};

/// Compact topology summary preserved for Phase 1/2 callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTopologySummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub has_cycles: bool,
}

impl WorkflowTopologySummary {
    #[must_use]
    pub fn analyze(ir: &WorkflowIr) -> Self {
        let graph = WorkflowGraph::from_ir(ir);
        graph.summary()
    }
}

/// Edge metadata stored inside [`WorkflowGraph`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdgeMeta {
    pub source_port: PortKind,
    pub target_port: PortKind,
    pub output_index: usize,
    pub input_index: usize,
}

/// Classification of a directed cycle in an n8n workflow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CycleKind {
    /// Legitimate iterative loop (`splitInBatches` / `Loop Over Items` or conditional retry/polling loop).
    ValidLoop,
    /// Unconditional cycle with no exit gate, or cycle across `ai_*` sub-node ports.
    UnboundedOrInvalidCycle,
}

/// Details of a strongly connected cycle detected in the workflow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetectedCycle {
    pub kind: CycleKind,
    pub nodes: Vec<String>,
    pub controller_nodes: Vec<String>,
    pub reason: String,
}

/// Structural or AI sub-node port attachment issue detected during topology analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum PortAttachmentIssue {
    DanglingSourceNode {
        source_node: String,
    },
    DanglingTargetNode {
        source_node: String,
        target_node: String,
        port: PortKind,
    },
    MismatchedEdgePortType {
        source_node: String,
        target_node: String,
        declared_port: PortKind,
        edge_port: PortKind,
    },
    OrphanedAiSubNode {
        node_name: String,
        node_type: String,
    },
    InvalidMainOutputFromAiSubNode {
        node_name: String,
        node_type: String,
        target_node: String,
    },
    InvalidAiAttachmentTarget {
        source_node: String,
        target_node: String,
        target_node_type: String,
        port: PortKind,
    },
    DuplicateSingletonAiAttachment {
        target_node: String,
        port: PortKind,
        input_index: usize,
        providers: Vec<String>,
    },
    MissingRequiredAiPort {
        node_name: String,
        node_type: String,
        required_port: PortKind,
    },
}

/// Single hop in upstream or downstream lineage traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PortLineageHop {
    pub from_node: String,
    pub to_node: String,
    pub port_kind: PortKind,
    pub output_index: usize,
    pub input_index: usize,
    pub distance: usize,
}

/// Sanitized data-shape descriptor for an upstream node output (field names and JSON types only, never raw secret values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeOutputShape {
    pub source_node: String,
    pub node_type: String,
    pub port_kind: PortKind,
    pub output_index: usize,
    pub shape_origin: String,
    pub fields: BTreeMap<String, String>,
}

/// Aggregated upstream data-shape lineage feeding into a target node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamDataShape {
    pub target_node: String,
    pub direct_inputs: Vec<NodeOutputShape>,
    pub attached_ai_providers: Vec<PortLineageHop>,
    pub reachable_upstream_nodes: Vec<String>,
}

/// Full topology report for an n8n workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopologyAnalysis {
    pub summary: WorkflowTopologySummary,
    pub primary_triggers: Vec<String>,
    pub error_triggers: Vec<String>,
    pub disabled_triggers: Vec<String>,
    pub has_ambiguous_triggers: bool,
    pub ambiguous_triggers: Vec<String>,
    pub reachable_nodes: Vec<String>,
    pub disconnected_nodes: Vec<String>,
    pub cycles: Vec<DetectedCycle>,
    pub has_invalid_cycles: bool,
    pub port_issues: Vec<PortAttachmentIssue>,
}

/// `petgraph`-backed workflow topology model.
#[derive(Debug, Clone)]
pub struct WorkflowGraph {
    graph: DiGraph<WorkflowNodeIr, GraphEdgeMeta>,
    by_name: HashMap<String, NodeIndex>,
    structural_issues: Vec<PortAttachmentIssue>,
}

impl WorkflowGraph {
    /// Builds a [`WorkflowGraph`] from a [`WorkflowIr`].
    #[must_use]
    pub fn from_ir(ir: &WorkflowIr) -> Self {
        let mut graph = DiGraph::with_capacity(ir.nodes.len(), ir.connections.len() * 2);
        let mut by_name = HashMap::with_capacity(ir.nodes.len());
        let mut structural_issues = Vec::new();

        for node in &ir.nodes {
            let idx = graph.add_node(node.clone());
            by_name.entry(node.name.clone()).or_insert(idx);
        }

        for (src_name, port_map) in &ir.connections {
            let Some(&src_idx) = by_name.get(src_name) else {
                structural_issues.push(PortAttachmentIssue::DanglingSourceNode {
                    source_node: src_name.clone(),
                });
                continue;
            };
            for (declared_port, branches) in port_map {
                for (output_index, branch_edges) in branches.iter().enumerate() {
                    for edge in branch_edges {
                        if edge.port_type != *declared_port {
                            structural_issues.push(PortAttachmentIssue::MismatchedEdgePortType {
                                source_node: src_name.clone(),
                                target_node: edge.node.clone(),
                                declared_port: declared_port.clone(),
                                edge_port: edge.port_type.clone(),
                            });
                        }
                        if let Some(&dst_idx) = by_name.get(&edge.node) {
                            graph.add_edge(
                                src_idx,
                                dst_idx,
                                GraphEdgeMeta {
                                    source_port: declared_port.clone(),
                                    target_port: edge.port_type.clone(),
                                    output_index,
                                    input_index: edge.index,
                                },
                            );
                        } else {
                            structural_issues.push(PortAttachmentIssue::DanglingTargetNode {
                                source_node: src_name.clone(),
                                target_node: edge.node.clone(),
                                port: declared_port.clone(),
                            });
                        }
                    }
                }
            }
        }

        Self {
            graph,
            by_name,
            structural_issues,
        }
    }

    /// Returns the compact [`WorkflowTopologySummary`].
    #[must_use]
    pub fn summary(&self) -> WorkflowTopologySummary {
        WorkflowTopologySummary {
            node_count: self.graph.node_count(),
            edge_count: self.graph.edge_count(),
            has_cycles: petgraph::algo::is_cyclic_directed(&self.graph),
        }
    }

    /// Runs comprehensive topology, loop, reachability, multi-trigger, and AI port validation.
    #[must_use]
    pub fn analyze(&self) -> TopologyAnalysis {
        let mut primary_triggers = Vec::new();
        let mut error_triggers = Vec::new();
        let mut disabled_triggers = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            if is_error_trigger_type(&node.node_type) {
                if node.disabled {
                    disabled_triggers.push(node.name.clone());
                } else {
                    error_triggers.push(node.name.clone());
                }
            } else if is_primary_trigger_type(&node.node_type) {
                if node.disabled {
                    disabled_triggers.push(node.name.clone());
                } else {
                    primary_triggers.push(node.name.clone());
                }
            }
        }

        let has_ambiguous_triggers = primary_triggers.len() > 1;
        let ambiguous_triggers = if has_ambiguous_triggers {
            primary_triggers.clone()
        } else {
            Vec::new()
        };

        let reachable_set = self.compute_reachable_indices(&primary_triggers, &error_triggers);
        let mut reachable_nodes = Vec::new();
        let mut disconnected_nodes = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            if is_canvas_annotation_type(&node.node_type) {
                continue;
            }
            if reachable_set.contains(&idx) {
                reachable_nodes.push(node.name.clone());
            } else {
                disconnected_nodes.push(node.name.clone());
            }
        }

        let cycles = self.detect_cycles();
        let has_invalid_cycles = cycles
            .iter()
            .any(|c| c.kind == CycleKind::UnboundedOrInvalidCycle);

        let mut port_issues = self.structural_issues.clone();
        port_issues.extend(self.validate_ai_ports());

        TopologyAnalysis {
            summary: self.summary(),
            primary_triggers,
            error_triggers,
            disabled_triggers,
            has_ambiguous_triggers,
            ambiguous_triggers,
            reachable_nodes,
            disconnected_nodes,
            cycles,
            has_invalid_cycles,
            port_issues,
        }
    }

    /// Returns deterministically ordered nodes reachable from enabled triggers (including attached AI sub-nodes).
    #[must_use]
    pub fn reachable_from_triggers(&self) -> Vec<String> {
        self.analyze().reachable_nodes
    }

    /// Returns non-annotation nodes not reachable from any enabled trigger.
    #[must_use]
    pub fn disconnected_nodes(&self) -> Vec<String> {
        self.analyze().disconnected_nodes
    }

    /// Computes upstream port lineage (`predecessor -> ... -> node_name`) in BFS hop order, safe in the presence of loops.
    #[must_use]
    pub fn upstream_lineage(&self, node_name: &str) -> Vec<PortLineageHop> {
        let Some(&target_idx) = self.by_name.get(node_name) else {
            return Vec::new();
        };
        let mut hops = Vec::new();
        let mut visited_nodes = HashSet::new();
        visited_nodes.insert(target_idx);
        let mut queue = VecDeque::new();
        queue.push_back((target_idx, 0usize));

        while let Some((curr_idx, dist)) = queue.pop_front() {
            for edge in self.graph.edges_directed(curr_idx, Direction::Incoming) {
                let src_idx = edge.source();
                let meta = edge.weight();
                hops.push(PortLineageHop {
                    from_node: self.graph[src_idx].name.clone(),
                    to_node: self.graph[curr_idx].name.clone(),
                    port_kind: meta.source_port.clone(),
                    output_index: meta.output_index,
                    input_index: meta.input_index,
                    distance: dist + 1,
                });
                if visited_nodes.insert(src_idx) {
                    queue.push_back((src_idx, dist + 1));
                }
            }
        }
        hops
    }

    /// Computes downstream port lineage (`node_name -> ... -> consumer`) in BFS hop order, safe in the presence of loops.
    #[must_use]
    pub fn downstream_lineage(&self, node_name: &str) -> Vec<PortLineageHop> {
        let Some(&start_idx) = self.by_name.get(node_name) else {
            return Vec::new();
        };
        let mut hops = Vec::new();
        let mut visited_nodes = HashSet::new();
        visited_nodes.insert(start_idx);
        let mut queue = VecDeque::new();
        queue.push_back((start_idx, 0usize));

        while let Some((curr_idx, dist)) = queue.pop_front() {
            for edge in self.graph.edges_directed(curr_idx, Direction::Outgoing) {
                let dst_idx = edge.target();
                let meta = edge.weight();
                hops.push(PortLineageHop {
                    from_node: self.graph[curr_idx].name.clone(),
                    to_node: self.graph[dst_idx].name.clone(),
                    port_kind: meta.source_port.clone(),
                    output_index: meta.output_index,
                    input_index: meta.input_index,
                    distance: dist + 1,
                });
                if visited_nodes.insert(dst_idx) {
                    queue.push_back((dst_idx, dist + 1));
                }
            }
        }
        hops
    }

    /// Infers sanitized upstream output data shapes feeding into `node_name` without exposing raw parameter/pinned values.
    #[must_use]
    pub fn infer_upstream_data_shape(&self, ir: &WorkflowIr, node_name: &str) -> UpstreamDataShape {
        let lineage = self.upstream_lineage(node_name);
        let mut direct_inputs = Vec::new();
        let mut attached_ai_providers = Vec::new();
        let mut reachable_upstream_set = BTreeSet::new();

        for hop in &lineage {
            reachable_upstream_set.insert(hop.from_node.clone());
            if hop.distance == 1 {
                if hop.port_kind.is_ai_subnode_port() {
                    attached_ai_providers.push(hop.clone());
                } else if let Some(src_node) = ir.node_by_name(&hop.from_node) {
                    direct_inputs.push(infer_single_node_output_shape(
                        ir,
                        src_node,
                        &hop.port_kind,
                        hop.output_index,
                    ));
                }
            }
        }

        UpstreamDataShape {
            target_node: node_name.to_owned(),
            direct_inputs,
            attached_ai_providers,
            reachable_upstream_nodes: reachable_upstream_set.into_iter().collect(),
        }
    }

    fn compute_reachable_indices(
        &self,
        primary_triggers: &[String],
        error_triggers: &[String],
    ) -> HashSet<NodeIndex> {
        let mut reachable = HashSet::new();
        let mut exec_queue = VecDeque::new();

        for name in primary_triggers.iter().chain(error_triggers.iter()) {
            if let Some(&idx) = self.by_name.get(name)
                && reachable.insert(idx)
            {
                exec_queue.push_back(idx);
            }
        }

        // 1. Forward traversal along execution (`main` / `error` / non-`ai_*`) edges.
        while let Some(curr) = exec_queue.pop_front() {
            for edge in self.graph.edges_directed(curr, Direction::Outgoing) {
                if !edge.weight().source_port.is_ai_subnode_port() {
                    let dst = edge.target();
                    if reachable.insert(dst) {
                        exec_queue.push_back(dst);
                    }
                }
            }
        }

        // 2. Transitive backward pull of AI sub-node providers (`Provider --[ai_*]--> ReachableHost`).
        let mut ai_queue: VecDeque<NodeIndex> = reachable.iter().copied().collect();
        while let Some(host_idx) = ai_queue.pop_front() {
            for edge in self.graph.edges_directed(host_idx, Direction::Incoming) {
                if edge.weight().source_port.is_ai_subnode_port() {
                    let provider_idx = edge.source();
                    if reachable.insert(provider_idx) {
                        ai_queue.push_back(provider_idx);
                    }
                }
            }
        }

        reachable
    }

    fn detect_cycles(&self) -> Vec<DetectedCycle> {
        let sccs = tarjan_scc(&self.graph);
        let mut detected = Vec::new();

        for scc in sccs {
            let is_cycle = if scc.len() > 1 {
                true
            } else if let Some(&single) = scc.first() {
                self.graph
                    .edges_directed(single, Direction::Outgoing)
                    .any(|e| e.target() == single)
            } else {
                false
            };

            if !is_cycle {
                continue;
            }

            let scc_set: HashSet<NodeIndex> = scc.iter().copied().collect();
            let mut node_names: Vec<String> = scc
                .iter()
                .map(|&idx| self.graph[idx].name.clone())
                .collect();
            node_names.sort();

            let has_ai_edge_in_cycle = scc.iter().any(|&idx| {
                self.graph
                    .edges_directed(idx, Direction::Outgoing)
                    .any(|e| {
                        scc_set.contains(&e.target()) && e.weight().source_port.is_ai_subnode_port()
                    })
            });

            if has_ai_edge_in_cycle {
                detected.push(DetectedCycle {
                    kind: CycleKind::UnboundedOrInvalidCycle,
                    nodes: node_names,
                    controller_nodes: Vec::new(),
                    reason: "Cycle traverses AI sub-node attachment ports (`ai_*`), which must form a DAG.".to_owned(),
                });
                continue;
            }

            // Single-node unconditional self-loop is never a valid n8n loop unless splitInBatches with exit.
            if scc.len() == 1 {
                detected.push(DetectedCycle {
                    kind: CycleKind::UnboundedOrInvalidCycle,
                    nodes: node_names,
                    controller_nodes: Vec::new(),
                    reason: "Direct single-node self-loop has no iterative batch or conditional exit gate.".to_owned(),
                });
                continue;
            }

            let mut controllers: Vec<String> = scc
                .iter()
                .filter_map(|&idx| {
                    let n = &self.graph[idx];
                    is_loop_controller_type(&n.node_type).then(|| n.name.clone())
                })
                .collect();
            controllers.sort();

            if !controllers.is_empty() {
                detected.push(DetectedCycle {
                    kind: CycleKind::ValidLoop,
                    nodes: node_names,
                    reason: format!(
                        "Controlled workflow loop gated by `{}`.",
                        controllers.join(", ")
                    ),
                    controller_nodes: controllers,
                });
            } else {
                detected.push(DetectedCycle {
                    kind: CycleKind::UnboundedOrInvalidCycle,
                    nodes: node_names,
                    controller_nodes: Vec::new(),
                    reason: "Directed cycle contains no `splitInBatches`, `if`, `switch`, or `filter` exit controller.".to_owned(),
                });
            }
        }

        detected
    }

    fn validate_ai_ports(&self) -> Vec<PortAttachmentIssue> {
        let mut issues = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            if node.disabled {
                continue;
            }

            // Check AI-only sub-node providers.
            if is_ai_subnode_provider_type(&node.node_type) {
                let mut has_ai_outgoing = false;
                for edge in self.graph.edges_directed(idx, Direction::Outgoing) {
                    let meta = edge.weight();
                    let dst_node = &self.graph[edge.target()];
                    if meta.source_port.is_ai_subnode_port() {
                        has_ai_outgoing = true;
                        if !can_accept_ai_port(&dst_node.node_type) {
                            issues.push(PortAttachmentIssue::InvalidAiAttachmentTarget {
                                source_node: node.name.clone(),
                                target_node: dst_node.name.clone(),
                                target_node_type: dst_node.node_type.clone(),
                                port: meta.source_port.clone(),
                            });
                        }
                    } else if meta.source_port == PortKind::Main {
                        issues.push(PortAttachmentIssue::InvalidMainOutputFromAiSubNode {
                            node_name: node.name.clone(),
                            node_type: node.node_type.clone(),
                            target_node: dst_node.name.clone(),
                        });
                    }
                }
                if !has_ai_outgoing {
                    issues.push(PortAttachmentIssue::OrphanedAiSubNode {
                        node_name: node.name.clone(),
                        node_type: node.node_type.clone(),
                    });
                }
            }

            // Check any `ai_*` incoming edges on this node for invalid target or singleton slot collisions.
            let mut incoming_by_slot: BTreeMap<(String, usize), Vec<(PortKind, String)>> =
                BTreeMap::new();
            for edge in self.graph.edges_directed(idx, Direction::Incoming) {
                let src_node = &self.graph[edge.source()];
                if src_node.disabled {
                    continue;
                }
                let meta = edge.weight();
                if meta.source_port.is_ai_subnode_port() {
                    if !can_accept_ai_port(&node.node_type) {
                        let candidate = PortAttachmentIssue::InvalidAiAttachmentTarget {
                            source_node: src_node.name.clone(),
                            target_node: node.name.clone(),
                            target_node_type: node.node_type.clone(),
                            port: meta.source_port.clone(),
                        };
                        if !issues.contains(&candidate) {
                            issues.push(candidate);
                        }
                    }
                    incoming_by_slot
                        .entry((meta.source_port.as_wire().to_owned(), meta.input_index))
                        .or_default()
                        .push((meta.source_port.clone(), src_node.name.clone()));
                }
            }

            for ((_, input_index), mut entries) in incoming_by_slot {
                if entries.len() > 1
                    && let Some((port, _)) = entries.first()
                    && port.is_singleton_ai_slot()
                {
                    let port_clone = port.clone();
                    entries.sort_by(|a, b| a.1.cmp(&b.1));
                    let providers = entries.into_iter().map(|(_, p)| p).collect();
                    issues.push(PortAttachmentIssue::DuplicateSingletonAiAttachment {
                        target_node: node.name.clone(),
                        port: port_clone,
                        input_index,
                        providers,
                    });
                }
            }

            // Check AI host nodes that require `ai_languageModel`.
            if requires_ai_language_model(&node.node_type) {
                let has_lm = self
                    .graph
                    .edges_directed(idx, Direction::Incoming)
                    .any(|e| {
                        !self.graph[e.source()].disabled
                            && e.weight().source_port == PortKind::AiLanguageModel
                    });
                if !has_lm {
                    issues.push(PortAttachmentIssue::MissingRequiredAiPort {
                        node_name: node.name.clone(),
                        node_type: node.node_type.clone(),
                        required_port: PortKind::AiLanguageModel,
                    });
                }
            }
        }

        issues
    }
}

fn short_type_name(node_type: &str) -> &str {
    node_type.rsplit('.').next().unwrap_or(node_type)
}

/// Returns `true` if `node_type` is `errorTrigger`.
#[must_use]
pub fn is_error_trigger_type(node_type: &str) -> bool {
    short_type_name(node_type).eq_ignore_ascii_case("errorTrigger")
}

/// Returns `true` if `node_type` is a primary workflow trigger (excluding `errorTrigger`).
#[must_use]
pub fn is_primary_trigger_type(node_type: &str) -> bool {
    if is_error_trigger_type(node_type) {
        return false;
    }
    let short = short_type_name(node_type);
    let lower = short.to_ascii_lowercase();
    lower.ends_with("trigger")
        || matches!(
            lower.as_str(),
            "webhook" | "start" | "cron" | "interval" | "emailreadimap" | "activemq"
        )
}

/// Returns `true` if `node_type` is any trigger (`primary` or `errorTrigger`).
#[must_use]
pub fn is_any_trigger_type(node_type: &str) -> bool {
    is_error_trigger_type(node_type) || is_primary_trigger_type(node_type)
}

/// Returns `true` if `node_type` is a non-executable canvas annotation (`stickyNote`).
#[must_use]
pub fn is_canvas_annotation_type(node_type: &str) -> bool {
    short_type_name(node_type).eq_ignore_ascii_case("stickyNote")
}

/// Returns `true` if `node_type` is a legitimate loop or conditional branch exit controller.
#[must_use]
pub fn is_loop_controller_type(node_type: &str) -> bool {
    let lower = short_type_name(node_type).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "splitinbatches" | "if" | "switch" | "filter"
    )
}

/// Returns `true` if `node_type` is an AI sub-node provider (`lmChat*`, `embeddings*`, `memory*`, etc.).
#[must_use]
pub fn is_ai_subnode_provider_type(node_type: &str) -> bool {
    let lower = short_type_name(node_type).to_ascii_lowercase();
    lower.starts_with("lmchat")
        || lower.starts_with("lm") && node_type.contains("langchain")
        || lower.starts_with("embeddings")
        || lower.starts_with("memory")
        || lower.starts_with("outputparser")
        || lower.starts_with("textsplitter")
        || lower.starts_with("document") && node_type.contains("langchain")
        || lower.starts_with("retriever")
        || lower.starts_with("tool") && node_type.contains("langchain")
}

fn can_accept_ai_port(node_type: &str) -> bool {
    if is_canvas_annotation_type(node_type) {
        return false;
    }
    if is_any_trigger_type(node_type) {
        let lower = short_type_name(node_type).to_ascii_lowercase();
        return lower == "mcptrigger" || lower == "chattrigger";
    }
    node_type.contains("langchain")
        || short_type_name(node_type)
            .to_ascii_lowercase()
            .contains("agent")
}

fn requires_ai_language_model(node_type: &str) -> bool {
    if !node_type.contains("langchain") {
        return false;
    }
    let lower = short_type_name(node_type).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "agent"
            | "chainllm"
            | "chainretrievalqa"
            | "chainsummarization"
            | "informationextractor"
            | "sentimentanalysis"
            | "textclassifier"
    )
}

fn infer_single_node_output_shape(
    ir: &WorkflowIr,
    node: &WorkflowNodeIr,
    port_kind: &PortKind,
    output_index: usize,
) -> NodeOutputShape {
    // 1. Check `pinData` first (extracting ONLY key names + JSON value type tags, never raw values).
    if let Some(pin_map) = &ir.pin_data
        && let Some(pinned) = pin_map.get(&node.name)
    {
        let mut fields = BTreeMap::new();
        let sample_obj = pinned
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("json").or(Some(item)))
            .and_then(Value::as_object)
            .or_else(|| pinned.as_object());
        if let Some(obj) = sample_obj {
            for (k, v) in obj {
                fields.insert(k.clone(), json_value_type_tag(v).to_owned());
            }
            return NodeOutputShape {
                source_node: node.name.clone(),
                node_type: node.node_type.clone(),
                port_kind: port_kind.clone(),
                output_index,
                shape_origin: "pin_data_schema".to_owned(),
                fields,
            };
        }
    }

    // 2. Check Edit Fields / Set v3+ (`parameters.assignments.assignments`).
    let short = short_type_name(&node.node_type).to_ascii_lowercase();
    if short == "set" {
        let mut fields = BTreeMap::new();
        if let Some(assignments) = node
            .parameters
            .pointer("/assignments/assignments")
            .and_then(Value::as_array)
        {
            for item in assignments {
                if let Some(name) = item.get("name").and_then(Value::as_str)
                    && !name.is_empty()
                {
                    let ty = item
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("any")
                        .to_owned();
                    fields.insert(name.to_owned(), ty);
                }
            }
        }
        if !fields.is_empty() {
            return NodeOutputShape {
                source_node: node.name.clone(),
                node_type: node.node_type.clone(),
                port_kind: port_kind.clone(),
                output_index,
                shape_origin: "set_node_assignments".to_owned(),
                fields,
            };
        }
    }

    // 3. Well-known built-in node output envelopes.
    let (origin, fields) = match short.as_str() {
        "webhook" => (
            "builtin_webhook_envelope",
            BTreeMap::from([
                ("headers".to_owned(), "object".to_owned()),
                ("params".to_owned(), "object".to_owned()),
                ("query".to_owned(), "object".to_owned()),
                ("body".to_owned(), "any".to_owned()),
            ]),
        ),
        "httprequest" => (
            "builtin_http_response",
            BTreeMap::from([
                ("statusCode".to_owned(), "number".to_owned()),
                ("headers".to_owned(), "object".to_owned()),
                ("body".to_owned(), "any".to_owned()),
            ]),
        ),
        _ => ("dynamic_or_passthrough", BTreeMap::new()),
    };

    NodeOutputShape {
        source_node: node.name.clone(),
        node_type: node.node_type.clone(),
        port_kind: port_kind.clone(),
        output_index,
        shape_origin: origin.to_owned(),
        fields,
    }
}

const fn json_value_type_tag(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
