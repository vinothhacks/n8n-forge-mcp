//! FTS5 + BM25 + native-first node search, `get_node_info` (`info`, `docs`, `search_properties`,
//! `versions`), and `inspect_effective_node_fields`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use indexmap::IndexMap;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use n8n_types::{DetailLevel, N8nError, N8nResult, redact_json_value, redact_str};

use crate::display_options::{
    DisplayEvalContext, EffectiveNestedFields, build_node_context, compute_effective_nested_fields,
    evaluate_display_options,
};
use crate::schema::{
    CatalogDb, NodeCatalogEntry, NodeCredentialRule, NodeOperationRecord, NodePropertyRecord,
    NodeVersionRecord, SchemaConfidence, is_authoritative_package,
};

/// Canonical V2 Section 7 native data transformation & flow-control nodes prioritized ahead of
/// `HTTP Request` and `Code`.
pub const NATIVE_DATA_NODE_TYPES: &[&str] = &[
    "n8n-nodes-base.set",
    "n8n-nodes-base.filter",
    "n8n-nodes-base.if",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.merge",
    "n8n-nodes-base.aggregate",
    "n8n-nodes-base.summarize",
    "n8n-nodes-base.removeDuplicates",
    "n8n-nodes-base.sort",
    "n8n-nodes-base.limit",
    "n8n-nodes-base.splitOut",
    "n8n-nodes-base.dateTime",
    "n8n-nodes-base.compareDatasets",
];

const V2_CODE_GUIDANCE_HINT: &str = "Native-first policy: Prefer native data nodes (Edit Fields/Set, Filter, IF, Switch, Merge, Aggregate, Summarize, Remove Duplicates, Sort, Limit, Split Out, Date & Time, Compare Datasets) or short expressions before using Code. Use a Code node only for stateful/recursive logic, unsupported parsers, or replacing 4+ glue nodes, and start its notes with 'Why Code: <reason>'.";

const V2_HTTP_GUIDANCE_HINT: &str = "Native-first policy: Check for a dedicated native service node (e.g., Slack, Postgres, Google Sheets, GitHub, Jira, HubSpot, Microsoft Teams) before using generic HTTP Request, and always bind credentials by reference rather than raw headers.";

/// Lexical query matching mode for [`CatalogDb::search_nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum SearchMode {
    #[default]
    #[serde(alias = "or", alias = "Or")]
    Or,
    #[serde(alias = "and", alias = "And")]
    And,
    #[serde(alias = "fuzzy", alias = "Fuzzy", alias = "prefix", alias = "PREFIX")]
    Fuzzy,
}

/// Package source filter for [`CatalogDb::search_nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NodeSourceFilter {
    #[default]
    All,
    Core,
    Langchain,
    Community,
}

impl NodeSourceFilter {
    #[must_use]
    pub fn matches_package(self, package_name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Core => package_name == "n8n-nodes-base",
            Self::Langchain => package_name == "@n8n/n8n-nodes-langchain",
            Self::Community => {
                !matches!(package_name, "n8n-nodes-base" | "@n8n/n8n-nodes-langchain")
            }
        }
    }
}

/// Search parameters for [`CatalogDb::search_nodes`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSearchQuery {
    pub query: String,
    #[serde(default)]
    pub mode: SearchMode,
    #[serde(default)]
    pub source: NodeSourceFilter,
    #[serde(default = "default_true")]
    pub include_operations: bool,
    #[serde(default)]
    pub detail: DetailLevel,
    #[serde(default = "default_search_limit")]
    pub limit: usize,
}

impl Default for NodeSearchQuery {
    fn default() -> Self {
        Self {
            query: String::new(),
            mode: SearchMode::Or,
            source: NodeSourceFilter::All,
            include_operations: true,
            detail: DetailLevel::Standard,
            limit: 20,
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_search_limit() -> usize {
    20
}

/// Ranked node search hit projected according to `detail = minimal | standard | full`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSearchHit {
    pub node_type: String,
    pub short_type: String,
    pub display_name: String,
    pub category: String,
    pub default_version: String,
    pub native_priority: u8,
    pub is_trigger: bool,
    pub relevance_score: f64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_effect_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_webhook: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_ai_tool: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_tool_variant: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<NodeOperationRecord>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_variant_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<NodeVersionRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<NodePropertyRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
}

/// Response returned by [`CatalogDb::search_nodes`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSearchResponse {
    pub query: String,
    pub mode: SearchMode,
    pub source: NodeSourceFilter,
    pub detail: DetailLevel,
    pub total_returned: usize,
    pub hits: Vec<NodeSearchHit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guidance_hints: Vec<String>,
}

/// Inspection sub-mode for [`CatalogDb::get_node_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeInfoMode {
    #[default]
    Info,
    Docs,
    SearchProperties,
    Versions,
}

/// Request payload for [`CatalogDb::get_node_info`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoRequest {
    pub node_type: String,
    #[serde(default)]
    pub mode: NodeInfoMode,
    #[serde(default)]
    pub type_version: Option<String>,
    #[serde(default)]
    pub property_query: Option<String>,
}

/// Matched top-level or nested property returned by `NodeInfoMode::SearchProperties`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PropertySearchMatch {
    pub path: String,
    pub name: String,
    pub display_name: String,
    pub prop_type: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_options: Option<Value>,
}

/// Structured documentation generated for `NodeInfoMode::Docs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeDocsSection {
    pub overview: String,
    pub usage_guidance: String,
    pub ports_summary: String,
    pub credentials_summary: Vec<String>,
    pub operations_summary: Vec<String>,
    pub key_properties: Vec<String>,
    pub markdown: String,
}

/// Response returned by [`CatalogDb::get_node_info`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoResponse {
    pub node_type: String,
    pub found_in_catalog: bool,
    pub version_in_catalog: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_version: Option<String>,
    pub schema_confidence: SchemaConfidence,
    pub mode: NodeInfoMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<NodeCatalogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<NodeCredentialRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<NodeOperationRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<NodePropertyRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<NodeVersionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<NodeDocsSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub property_matches: Vec<PropertySearchMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guidance_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Effective property state under a node's resolved `typeVersion` and `current_params`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveProperty {
    pub name: String,
    pub display_name: String,
    pub prop_type: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_value: Option<Value>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested: Option<EffectiveNestedFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_format: Option<Value>,
}

/// Effective credential rule enriched from `credential_types` (field names only, zero secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveCredentialRule {
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_fields: Vec<String>,
    pub required: bool,
    pub visible: bool,
}

/// Result of [`CatalogDb::inspect_effective_node_fields`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveNodeInspection {
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_type_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_type_version: Option<String>,
    pub schema_confidence: SchemaConfidence,
    pub visible_required_properties: Vec<EffectiveProperty>,
    pub visible_optional_properties: Vec<EffectiveProperty>,
    pub hidden_properties: Vec<String>,
    pub missing_required_properties: Vec<String>,
    pub defaults: BTreeMap<String, Value>,
    pub effective_values: BTreeMap<String, Value>,
    pub allowed_credentials: Vec<EffectiveCredentialRule>,
    pub all_declared_credentials: Vec<EffectiveCredentialRule>,
    pub unknown_parameter_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inactive_parameter_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guidance_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Returns `true` if `node_type` is one of the 13 V2 native data/flow nodes.
#[must_use]
pub fn is_native_data_node(node_type: &str) -> bool {
    NATIVE_DATA_NODE_TYPES.contains(&node_type)
}

/// Deterministic native-first sorter preserving existing public signature.
///
/// Ordering:
/// 1. `native_priority` ascending (`1` service/trigger -> `2` native data -> `3` HTTP/AI -> `4` Code -> `5` OS/community)
/// 2. Canonical V2 native data nodes (`Set`, `Filter`, `IF`, `Switch`, `Merge`, etc.) ahead of other priority-2 nodes
/// 3. `native_score` descending
/// 4. `node_type` ascending
#[must_use]
pub fn rank_native_first(mut entries: Vec<NodeCatalogEntry>) -> Vec<NodeCatalogEntry> {
    entries.sort_by(|a, b| {
        effective_priority_rank(&a.node_type, a.native_priority)
            .cmp(&effective_priority_rank(&b.node_type, b.native_priority))
            .then_with(|| b.native_score.cmp(&a.native_score))
            .then_with(|| a.node_type.cmp(&b.node_type))
    });
    entries
}

fn effective_priority_rank(node_type: &str, native_priority: u8) -> (u8, u8) {
    let sub_rank =
        if node_type == "n8n-nodes-base.code" || node_type == "@n8n/n8n-nodes-langchain.toolCode" {
            2
        } else if node_type == "n8n-nodes-base.httpRequest"
            || (native_priority == 2 && !is_native_data_node(node_type))
        {
            1
        } else {
            0
        };
    (native_priority, sub_rank)
}

/// Computes V2 native-first guidance hints when `Code` or `HTTP Request` is queried or matched.
#[must_use]
pub fn native_first_guidance_for_query(
    raw_query: &str,
    matched_node_types: &[&str],
) -> Vec<String> {
    let q_lower = raw_query.to_ascii_lowercase();
    let tokens = tokenize_search_terms(raw_query);

    let code_queried = tokens.iter().any(|t| {
        matches!(
            t.as_str(),
            "code" | "javascript" | "jscode" | "python" | "pythoncode" | "script" | "function"
        )
    }) || q_lower.contains("n8n-nodes-base.code")
        || matched_node_types
            .iter()
            .any(|nt| *nt == "n8n-nodes-base.code" || *nt == "@n8n/n8n-nodes-langchain.toolCode");

    let http_queried = tokens.iter().any(|t| {
        matches!(
            t.as_str(),
            "http" | "httprequest" | "rest" | "fetch" | "curl" | "axios"
        )
    }) || q_lower.contains("n8n-nodes-base.httprequest")
        || matched_node_types.contains(&"n8n-nodes-base.httpRequest");

    let mut hints = Vec::new();
    if code_queried {
        hints.push(V2_CODE_GUIDANCE_HINT.to_owned());
    }
    if http_queried {
        hints.push(V2_HTTP_GUIDANCE_HINT.to_owned());
    }
    hints
}

#[derive(Debug, Clone)]
struct RawNodeRow {
    entry: NodeCatalogEntry,
    development_style: String,
    is_versioned: bool,
    is_tool_variant: bool,
    tool_variant_of: Option<String>,
    inputs: Vec<String>,
    outputs: Vec<String>,
    output_names: Option<Vec<String>>,
    credentials: Vec<NodeCredentialRule>,
    schema_hash: String,
}

impl CatalogDb {
    /// Searches the offline node catalog using SQLite FTS5 (`bm25()`) combined with V2 native-first
    /// priority ranking (`native service -> native data -> HTTP Request -> Code`).
    pub fn search_nodes(&self, req: &NodeSearchQuery) -> N8nResult<NodeSearchResponse> {
        let clamped_limit = req.limit.clamp(1, 100);
        let trimmed_query = req.query.trim();
        let tokens = tokenize_search_terms(trimmed_query);

        let mut scored_candidates: IndexMap<String, (RawNodeRow, f64)> = IndexMap::new();

        if trimmed_query.is_empty() {
            for row in self.load_all_raw_nodes(req.source)? {
                let score = compute_combined_relevance("", &[], &row.entry, 0.0);
                scored_candidates.insert(row.entry.node_type.clone(), (row, score));
            }
        } else if !tokens.is_empty() {
            if let Some(fts_expr) =
                build_node_fts_expression(&tokens, req.mode, req.include_operations)
            {
                let fts_hits = self.query_node_fts(&fts_expr, req.source, clamped_limit * 4)?;
                for (row, raw_bm25) in fts_hits {
                    let lexical_boost = (-raw_bm25).max(0.0);
                    let score = compute_combined_relevance(
                        trimmed_query,
                        &tokens,
                        &row.entry,
                        lexical_boost,
                    );
                    scored_candidates.insert(row.entry.node_type.clone(), (row, score));
                }
            }

            if req.mode == SearchMode::Fuzzy && scored_candidates.len() < clamped_limit {
                for row in self.load_all_raw_nodes(req.source)? {
                    if scored_candidates.contains_key(&row.entry.node_type) {
                        continue;
                    }
                    if let Some(fuzzy_lex) = fuzzy_match_node(&tokens, &row.entry) {
                        let score = compute_combined_relevance(
                            trimmed_query,
                            &tokens,
                            &row.entry,
                            fuzzy_lex,
                        );
                        scored_candidates.insert(row.entry.node_type.clone(), (row, score));
                    }
                }
            }
        }

        let mut ranked: Vec<(RawNodeRow, f64)> = scored_candidates.into_values().collect();
        ranked.sort_by(|(a_row, a_score), (b_row, b_score)| {
            b_score
                .partial_cmp(a_score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| {
                    effective_priority_rank(&a_row.entry.node_type, a_row.entry.native_priority)
                        .cmp(&effective_priority_rank(
                            &b_row.entry.node_type,
                            b_row.entry.native_priority,
                        ))
                })
                .then_with(|| b_row.entry.native_score.cmp(&a_row.entry.native_score))
                .then_with(|| a_row.entry.node_type.cmp(&b_row.entry.node_type))
        });
        ranked.truncate(clamped_limit);

        let matched_types_owned: Vec<String> = ranked
            .iter()
            .map(|(r, _)| r.entry.node_type.clone())
            .collect();
        let matched_refs: Vec<&str> = matched_types_owned.iter().map(String::as_str).collect();
        let guidance_hints = native_first_guidance_for_query(trimmed_query, &matched_refs);

        let mut hits = Vec::with_capacity(ranked.len());
        for (raw, score) in ranked {
            hits.push(self.project_search_hit(raw, score, req.detail, req.include_operations)?);
        }

        Ok(NodeSearchResponse {
            query: redact_str(trimmed_query),
            mode: req.mode,
            source: req.source,
            detail: req.detail,
            total_returned: hits.len(),
            hits,
            guidance_hints,
        })
    }

    /// Retrieves detailed node schema, generated documentation, property search hits, or version
    /// history for a node (`info`, `docs`, `search_properties`, `versions`).
    pub fn get_node_info(&self, req: &NodeInfoRequest) -> N8nResult<NodeInfoResponse> {
        let requested_name = req.node_type.trim();
        let Some(raw) = self.load_single_raw_node(requested_name)? else {
            return Ok(NodeInfoResponse {
                node_type: redact_str(requested_name),
                found_in_catalog: false,
                version_in_catalog: false,
                resolved_version: req.type_version.as_ref().map(|v| redact_str(v)),
                schema_confidence: SchemaConfidence::UnknownOrCommunityPartial,
                mode: req.mode,
                entry: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
                output_names: None,
                credentials: Vec::new(),
                operations: Vec::new(),
                properties: Vec::new(),
                versions: Vec::new(),
                docs: None,
                property_matches: Vec::new(),
                guidance_hints: native_first_guidance_for_query(requested_name, &[]),
                warnings: vec![format!(
                    "Node type `{}` is not present in the offline catalog; treating schema confidence as partial (`UnknownOrCommunityPartial`).",
                    redact_str(requested_name)
                )],
            });
        };

        let canonical_type = raw.entry.node_type.clone();
        let all_versions = self.load_node_versions(&canonical_type)?;
        let operations = self.load_node_operations(&canonical_type)?;

        let mut warnings = Vec::new();
        let (resolved_ver, version_in_catalog) = match req
            .type_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => (raw.entry.default_version.clone(), true),
            Some(requested_ver) => {
                if let Some((matched_ver, _)) =
                    self.resolve_catalog_version(&canonical_type, requested_ver)?
                {
                    (matched_ver, true)
                } else {
                    let known_list = all_versions
                        .iter()
                        .map(|v| v.type_version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    warnings.push(format!(
                        "Requested typeVersion `{}` for `{canonical_type}` is not in the offline catalog (known: [{known_list}]); falling back to defaultVersion `{}` with partial confidence.",
                        redact_str(requested_ver),
                        raw.entry.default_version
                    ));
                    (raw.entry.default_version.clone(), false)
                }
            }
        };

        let schema_confidence =
            if is_authoritative_package(&raw.entry.package_name) && version_in_catalog {
                SchemaConfidence::AuthoritativeCatalog
            } else {
                SchemaConfidence::UnknownOrCommunityPartial
            };

        let properties = self.load_node_properties_with_fallback(
            &canonical_type,
            &resolved_ver,
            &raw.entry.default_version,
        )?;
        let guidance_hints =
            native_first_guidance_for_query(&canonical_type, &[canonical_type.as_str()]);

        let mut docs = None;
        let mut property_matches = Vec::new();

        match req.mode {
            NodeInfoMode::Info => {}
            NodeInfoMode::Docs => {
                docs =
                    Some(self.build_node_docs(&raw, &operations, &properties, &guidance_hints)?);
            }
            NodeInfoMode::SearchProperties => {
                let needle = req
                    .property_query
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                property_matches = search_node_properties(&properties, &needle);
            }
            NodeInfoMode::Versions => {}
        }

        let include_full_props = matches!(req.mode, NodeInfoMode::Info | NodeInfoMode::Docs);
        let include_ops = matches!(req.mode, NodeInfoMode::Info | NodeInfoMode::Docs);

        Ok(NodeInfoResponse {
            node_type: canonical_type,
            found_in_catalog: true,
            version_in_catalog,
            resolved_version: Some(resolved_ver),
            schema_confidence,
            mode: req.mode,
            entry: Some(raw.entry),
            inputs: raw.inputs,
            outputs: raw.outputs,
            output_names: raw.output_names,
            credentials: raw.credentials,
            operations: if include_ops { operations } else { Vec::new() },
            properties: if include_full_props {
                properties
            } else {
                Vec::new()
            },
            versions: all_versions,
            docs,
            property_matches,
            guidance_hints,
            warnings,
        })
    }

    /// Evaluates conditional `displayOptions`, schema defaults, nested `options`/`collection`/`fixedCollection`
    /// fields, allowed/required credential types, and unknown-parameter warnings for `(node_type, type_version)`
    /// under `current_params`.
    pub fn inspect_effective_node_fields(
        &self,
        node_type: &str,
        type_version: Option<&str>,
        current_params: &Value,
    ) -> N8nResult<EffectiveNodeInspection> {
        let requested_name = node_type.trim();
        let requested_ver_clean = type_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(redact_str);

        let empty_map = Map::new();
        let raw_params_map = current_params.as_object().unwrap_or(&empty_map);
        let sanitized_params_val = redact_json_value(current_params);
        let sanitized_params_map = sanitized_params_val.as_object().unwrap_or(&empty_map);

        let Some(raw) = self.load_single_raw_node(requested_name)? else {
            return Ok(EffectiveNodeInspection {
                node_type: redact_str(requested_name),
                requested_type_version: requested_ver_clean,
                resolved_type_version: None,
                schema_confidence: SchemaConfidence::UnknownOrCommunityPartial,
                visible_required_properties: Vec::new(),
                visible_optional_properties: Vec::new(),
                hidden_properties: Vec::new(),
                missing_required_properties: Vec::new(),
                defaults: BTreeMap::new(),
                effective_values: sanitized_params_map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                allowed_credentials: Vec::new(),
                all_declared_credentials: Vec::new(),
                unknown_parameter_warnings: Vec::new(),
                inactive_parameter_warnings: Vec::new(),
                guidance_hints: native_first_guidance_for_query(requested_name, &[]),
                warnings: vec![format!(
                    "Node type `{}` is unknown or from a community package not in the offline catalog (`SchemaConfidence::UnknownOrCommunityPartial`). Observed parameters are echoed safely without claiming full schema validation.",
                    redact_str(requested_name)
                )],
            });
        };

        let canonical_type = raw.entry.node_type.clone();
        let mut warnings = Vec::new();

        let (resolved_ver, effective_ver_for_ctx, version_in_catalog) = match type_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => (
                raw.entry.default_version.clone(),
                raw.entry.default_version.clone(),
                true,
            ),
            Some(req_v) => {
                if let Some((matched_v, _)) =
                    self.resolve_catalog_version(&canonical_type, req_v)?
                {
                    (matched_v.clone(), matched_v, true)
                } else {
                    warnings.push(format!(
                        "Requested typeVersion `{}` for `{canonical_type}` is unseen in the offline catalog; schema confidence downgraded to `UnknownOrCommunityPartial`.",
                        redact_str(req_v)
                    ));
                    (raw.entry.default_version.clone(), req_v.to_owned(), false)
                }
            }
        };

        let schema_confidence =
            if is_authoritative_package(&raw.entry.package_name) && version_in_catalog {
                SchemaConfidence::AuthoritativeCatalog
            } else {
                SchemaConfidence::UnknownOrCommunityPartial
            };

        let properties = self.load_node_properties_with_fallback(
            &canonical_type,
            &resolved_ver,
            &raw.entry.default_version,
        )?;

        let node_ctx = build_node_context(
            Some(&effective_ver_for_ctx),
            Some(raw.is_tool_variant || raw.entry.is_ai_tool),
        );

        // Fixed-point default resolution so multi-row conditional properties (e.g. Slack `operation`
        // per `resource`) resolve the active visible default rather than overwriting unconditionally.
        let resolved_defaults =
            resolve_conditional_property_defaults(&properties, raw_params_map, &node_ctx);
        let eval_ctx = DisplayEvalContext::new(raw_params_map, &resolved_defaults, &node_ctx);

        let mut declared_names = BTreeSet::new();
        let mut visible_names = BTreeSet::new();
        let mut visible_required_properties = Vec::new();
        let mut visible_optional_properties = Vec::new();
        let mut missing_required_properties = Vec::new();
        let mut visible_defaults = BTreeMap::new();
        let mut effective_values = BTreeMap::new();

        for prop in &properties {
            declared_names.insert(prop.name.clone());
            let is_vis = evaluate_display_options(prop.display_options.as_ref(), None, &eval_ctx);
            if !is_vis {
                continue;
            }
            // Deduplicate multi-row conditional properties (keep first visible definition).
            if !visible_names.insert(prop.name.clone()) {
                continue;
            }

            if let Some(ref def_v) = prop.default_value {
                visible_defaults.insert(prop.name.clone(), redact_json_value(def_v));
            }

            let raw_effective_opt = raw_params_map
                .get(&prop.name)
                .or(prop.default_value.as_ref());
            let current_sanitized = sanitized_params_map.get(&prop.name).cloned();

            if let Some(eff_v) = raw_effective_opt {
                effective_values.insert(prop.name.clone(), redact_json_value(eff_v));
            }

            if prop.required && is_missing_required_value(raw_effective_opt) {
                missing_required_properties.push(prop.name.clone());
            }

            let nested = compute_effective_nested_fields(
                &prop.prop_type,
                prop.options.as_ref(),
                prop.display_options.as_ref(),
                &eval_ctx,
                raw_params_map.get(&prop.name),
            );
            let nested_opt = if nested.is_empty() {
                None
            } else {
                Some(nested)
            };

            let eff_prop = EffectiveProperty {
                name: prop.name.clone(),
                display_name: prop.display_name.clone(),
                prop_type: prop.prop_type.clone(),
                required: prop.required,
                default_value: prop.default_value.as_ref().map(redact_json_value),
                current_value: current_sanitized,
                description: prop.description.clone(),
                nested: nested_opt,
                expected_format: prop.expected_format.clone(),
            };

            if prop.required {
                visible_required_properties.push(eff_prop);
            } else {
                visible_optional_properties.push(eff_prop);
            }
        }

        let hidden_properties: Vec<String> = declared_names
            .iter()
            .filter(|name| !visible_names.contains(*name))
            .cloned()
            .collect();

        let mut all_declared_credentials = Vec::with_capacity(raw.credentials.len());
        let mut allowed_credentials = Vec::new();
        for cred_rule in &raw.credentials {
            let cred_vis =
                evaluate_display_options(cred_rule.display_options.as_ref(), None, &eval_ctx);
            let cred_meta = self.get_credential_type(&cred_rule.name)?;
            let enriched = EffectiveCredentialRule {
                credential_type: cred_rule.name.clone(),
                display_name: cred_meta.as_ref().map(|m| m.display_name.clone()),
                auth_kind: cred_meta.as_ref().map(|m| m.auth_kind.clone()),
                documentation_url: cred_meta.as_ref().and_then(|m| m.documentation_url.clone()),
                required_fields: cred_meta.map(|m| m.required_fields).unwrap_or_default(),
                required: cred_rule.required,
                visible: cred_vis,
            };
            if cred_vis {
                allowed_credentials.push(enriched.clone());
            }
            all_declared_credentials.push(enriched);
        }

        let mut unknown_parameter_warnings = Vec::new();
        let mut inactive_parameter_warnings = Vec::new();

        for param_key in raw_params_map.keys() {
            if param_key.starts_with('@') {
                continue;
            }
            let safe_key = redact_str(param_key);
            if !declared_names.contains(param_key) {
                if schema_confidence.is_authoritative() {
                    unknown_parameter_warnings.push(format!(
                        "Unknown parameter `{safe_key}` is not declared in authoritative catalog schema for `{canonical_type}@{resolved_ver}`."
                    ));
                }
            } else if !visible_names.contains(param_key) {
                inactive_parameter_warnings.push(format!(
                    "Parameter `{safe_key}` is present in current_params but hidden by `displayOptions` under the active configuration."
                ));
            }
        }

        let guidance_hints =
            native_first_guidance_for_query(&canonical_type, &[canonical_type.as_str()]);

        Ok(EffectiveNodeInspection {
            node_type: canonical_type,
            requested_type_version: requested_ver_clean,
            resolved_type_version: Some(resolved_ver),
            schema_confidence,
            visible_required_properties,
            visible_optional_properties,
            hidden_properties,
            missing_required_properties,
            defaults: visible_defaults,
            effective_values,
            allowed_credentials,
            all_declared_credentials,
            unknown_parameter_warnings,
            inactive_parameter_warnings,
            guidance_hints,
            warnings,
        })
    }

    fn query_node_fts(
        &self,
        fts_expr: &str,
        source: NodeSourceFilter,
        limit: usize,
    ) -> N8nResult<Vec<(RawNodeRow, f64)>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT
                    nt.node_type, nt.short_type, nt.package_name, nt.display_name,
                    nt.description, nt.category, nt.development_style, nt.default_version,
                    nt.is_versioned, nt.is_trigger, nt.is_webhook, nt.is_ai_tool,
                    nt.is_tool_variant, nt.has_tool_variant, nt.tool_variant_of,
                    nt.native_priority, nt.native_score, nt.side_effect_class,
                    nt.inputs_json, nt.outputs_json, nt.output_names_json,
                    nt.credentials_json, nt.schema_hash,
                    bm25(node_fts, 8.0, 10.0, 10.0, 3.0, 2.0, 3.0, 6.0) AS bm25_rank
                 FROM node_fts
                 JOIN node_types nt ON nt.node_type = node_fts.node_type
                 WHERE node_fts MATCH ?1
                 ORDER BY bm25_rank ASC
                 LIMIT ?2;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing node_fts query: {e}")))?;

        let limit_i64 = i64::try_from(limit).unwrap_or(100);
        let rows = stmt
            .query_map(rusqlite::params![fts_expr, limit_i64], |row| {
                let raw = map_raw_node_row(row)?;
                let bm25_val: f64 = row.get(23)?;
                Ok((raw, bm25_val))
            })
            .map_err(|e| N8nError::protocol(format!("failed executing node_fts query: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            let (node_row, bm25_val) =
                r.map_err(|e| N8nError::protocol(format!("invalid node_fts row: {e}")))?;
            if source.matches_package(&node_row.entry.package_name) {
                out.push((node_row, bm25_val));
            }
        }
        Ok(out)
    }

    fn load_all_raw_nodes(&self, source: NodeSourceFilter) -> N8nResult<Vec<RawNodeRow>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT
                    node_type, short_type, package_name, display_name,
                    description, category, development_style, default_version,
                    is_versioned, is_trigger, is_webhook, is_ai_tool,
                    is_tool_variant, has_tool_variant, tool_variant_of,
                    native_priority, native_score, side_effect_class,
                    inputs_json, outputs_json, output_names_json,
                    credentials_json, schema_hash
                 FROM node_types
                 ORDER BY native_priority ASC, native_score DESC, node_type ASC;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing node_types scan: {e}")))?;

        let rows = stmt
            .query_map([], map_raw_node_row)
            .map_err(|e| N8nError::protocol(format!("failed scanning node_types: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            let row = r.map_err(|e| N8nError::protocol(format!("invalid node_types row: {e}")))?;
            if source.matches_package(&row.entry.package_name) {
                out.push(row);
            }
        }
        Ok(out)
    }

    fn load_single_raw_node(&self, node_type_or_short: &str) -> N8nResult<Option<RawNodeRow>> {
        if node_type_or_short.is_empty() {
            return Ok(None);
        }
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT
                    node_type, short_type, package_name, display_name,
                    description, category, development_style, default_version,
                    is_versioned, is_trigger, is_webhook, is_ai_tool,
                    is_tool_variant, has_tool_variant, tool_variant_of,
                    native_priority, native_score, side_effect_class,
                    inputs_json, outputs_json, output_names_json,
                    credentials_json, schema_hash
                 FROM node_types
                 WHERE node_type = ?1 OR short_type = ?1
                 LIMIT 1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing single node query: {e}")))?;

        stmt.query_row(rusqlite::params![node_type_or_short], map_raw_node_row)
            .optional()
            .map_err(|e| N8nError::protocol(format!("failed querying single node: {e}")))
    }

    fn load_node_versions(&self, node_type: &str) -> N8nResult<Vec<NodeVersionRecord>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT type_version, numeric_version, is_default, is_deprecated, breaking_notes, schema_hash
                 FROM node_versions
                 WHERE node_type = ?1
                 ORDER BY numeric_version ASC, type_version ASC;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing node_versions query: {e}")))?;

        let rows = stmt
            .query_map(rusqlite::params![node_type], |row| {
                Ok(NodeVersionRecord {
                    type_version: row.get(0)?,
                    numeric_version: row.get(1)?,
                    is_default: row.get::<_, i64>(2)? != 0,
                    is_deprecated: row.get::<_, i64>(3)? != 0,
                    breaking_notes: row.get(4)?,
                    schema_hash: row.get(5)?,
                })
            })
            .map_err(|e| N8nError::protocol(format!("failed reading node_versions: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| N8nError::protocol(format!("invalid node_versions row: {e}")))?);
        }
        Ok(out)
    }

    fn load_node_operations(&self, node_type: &str) -> N8nResult<Vec<NodeOperationRecord>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT resource, operation, display_name, description, action_label
                 FROM node_operations
                 WHERE node_type = ?1
                 ORDER BY id ASC;",
            )
            .map_err(|e| {
                N8nError::protocol(format!("failed preparing node_operations query: {e}"))
            })?;

        let rows = stmt
            .query_map(rusqlite::params![node_type], |row| {
                Ok(NodeOperationRecord {
                    resource: row.get(0)?,
                    operation: row.get(1)?,
                    display_name: row.get(2)?,
                    description: row.get(3)?,
                    action_label: row.get(4)?,
                })
            })
            .map_err(|e| N8nError::protocol(format!("failed reading node_operations: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(
                r.map_err(|e| N8nError::protocol(format!("invalid node_operations row: {e}")))?,
            );
        }
        Ok(out)
    }

    fn load_node_properties_with_fallback(
        &self,
        node_type: &str,
        resolved_version: &str,
        default_version: &str,
    ) -> N8nResult<Vec<NodePropertyRecord>> {
        let exact = self.load_node_properties_exact(node_type, resolved_version)?;
        if !exact.is_empty() || resolved_version == default_version {
            return Ok(exact);
        }
        self.load_node_properties_exact(node_type, default_version)
    }

    fn load_node_properties_exact(
        &self,
        node_type: &str,
        type_version: &str,
    ) -> N8nResult<Vec<NodePropertyRecord>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT prop_index, type_version, name, display_name, prop_type,
                        required, default_json, description, options_json,
                        display_options_json, expected_format_json
                 FROM node_properties
                 WHERE node_type = ?1 AND type_version = ?2
                 ORDER BY prop_index ASC;",
            )
            .map_err(|e| {
                N8nError::protocol(format!("failed preparing node_properties query: {e}"))
            })?;

        let rows = stmt
            .query_map(rusqlite::params![node_type, type_version], |row| {
                let idx_i64: i64 = row.get(0)?;
                let default_raw: Option<String> = row.get(6)?;
                let options_raw: Option<String> = row.get(8)?;
                let disp_raw: Option<String> = row.get(9)?;
                let fmt_raw: Option<String> = row.get(10)?;

                Ok(NodePropertyRecord {
                    prop_index: usize::try_from(idx_i64.max(0)).unwrap_or(0),
                    type_version: row.get(1)?,
                    name: row.get(2)?,
                    display_name: row.get(3)?,
                    prop_type: row.get(4)?,
                    required: row.get::<_, i64>(5)? != 0,
                    default_value: default_raw
                        .as_deref()
                        .and_then(|s| serde_json::from_str(s).ok()),
                    description: row.get(7)?,
                    options: options_raw
                        .as_deref()
                        .and_then(|s| serde_json::from_str(s).ok()),
                    display_options: disp_raw
                        .as_deref()
                        .and_then(|s| serde_json::from_str(s).ok()),
                    expected_format: fmt_raw
                        .as_deref()
                        .and_then(|s| serde_json::from_str(s).ok()),
                })
            })
            .map_err(|e| N8nError::protocol(format!("failed reading node_properties: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(
                r.map_err(|e| N8nError::protocol(format!("invalid node_properties row: {e}")))?,
            );
        }
        Ok(out)
    }

    fn project_search_hit(
        &self,
        raw: RawNodeRow,
        score: f64,
        detail: DetailLevel,
        include_operations: bool,
    ) -> N8nResult<NodeSearchHit> {
        let rounded_score = (score * 1000.0).round() / 1000.0;

        match detail {
            DetailLevel::Minimal => Ok(NodeSearchHit {
                node_type: raw.entry.node_type,
                short_type: raw.entry.short_type,
                display_name: raw.entry.display_name,
                category: raw.entry.category,
                default_version: raw.entry.default_version,
                native_priority: raw.entry.native_priority,
                is_trigger: raw.entry.is_trigger,
                relevance_score: rounded_score,
                package_name: None,
                description: None,
                native_score: None,
                side_effect_class: None,
                is_webhook: None,
                is_ai_tool: None,
                has_tool_variant: None,
                inputs: None,
                outputs: None,
                credential_types: None,
                operations: None,
                output_names: None,
                tool_variant_of: None,
                development_style: None,
                versions: None,
                properties: None,
                schema_hash: None,
            }),
            DetailLevel::Standard => {
                let ops = if include_operations {
                    Some(self.load_node_operations(&raw.entry.node_type)?)
                } else {
                    None
                };
                let cred_names: Vec<String> = raw.credentials.into_iter().map(|c| c.name).collect();
                Ok(NodeSearchHit {
                    node_type: raw.entry.node_type,
                    short_type: raw.entry.short_type,
                    display_name: raw.entry.display_name,
                    category: raw.entry.category,
                    default_version: raw.entry.default_version,
                    native_priority: raw.entry.native_priority,
                    is_trigger: raw.entry.is_trigger,
                    relevance_score: rounded_score,
                    package_name: Some(raw.entry.package_name),
                    description: Some(raw.entry.description),
                    native_score: Some(raw.entry.native_score),
                    side_effect_class: Some(raw.entry.side_effect_class),
                    is_webhook: Some(raw.entry.is_webhook),
                    is_ai_tool: Some(raw.entry.is_ai_tool),
                    has_tool_variant: Some(raw.entry.has_tool_variant),
                    inputs: Some(raw.inputs),
                    outputs: Some(raw.outputs),
                    credential_types: Some(cred_names),
                    operations: ops,
                    output_names: None,
                    tool_variant_of: None,
                    development_style: None,
                    versions: None,
                    properties: None,
                    schema_hash: None,
                })
            }
            DetailLevel::Full => {
                let ops = self.load_node_operations(&raw.entry.node_type)?;
                let versions = self.load_node_versions(&raw.entry.node_type)?;
                let properties = self
                    .load_node_properties_exact(&raw.entry.node_type, &raw.entry.default_version)?;
                let cred_names: Vec<String> = raw.credentials.into_iter().map(|c| c.name).collect();
                let _ = raw.is_versioned;
                Ok(NodeSearchHit {
                    node_type: raw.entry.node_type,
                    short_type: raw.entry.short_type,
                    display_name: raw.entry.display_name,
                    category: raw.entry.category,
                    default_version: raw.entry.default_version,
                    native_priority: raw.entry.native_priority,
                    is_trigger: raw.entry.is_trigger,
                    relevance_score: rounded_score,
                    package_name: Some(raw.entry.package_name),
                    description: Some(raw.entry.description),
                    native_score: Some(raw.entry.native_score),
                    side_effect_class: Some(raw.entry.side_effect_class),
                    is_webhook: Some(raw.entry.is_webhook),
                    is_ai_tool: Some(raw.entry.is_ai_tool),
                    has_tool_variant: Some(raw.entry.has_tool_variant),
                    inputs: Some(raw.inputs),
                    outputs: Some(raw.outputs),
                    credential_types: Some(cred_names),
                    operations: Some(ops),
                    output_names: raw.output_names,
                    tool_variant_of: raw.tool_variant_of,
                    development_style: Some(raw.development_style),
                    versions: Some(versions),
                    properties: Some(properties),
                    schema_hash: Some(raw.schema_hash),
                })
            }
        }
    }

    fn build_node_docs(
        &self,
        raw: &RawNodeRow,
        operations: &[NodeOperationRecord],
        properties: &[NodePropertyRecord],
        guidance_hints: &[String],
    ) -> N8nResult<NodeDocsSection> {
        let overview = format!(
            "{} (`{}`) — {} [Category: {}, Default Version: {}, Priority Tier: {}]",
            raw.entry.display_name,
            raw.entry.node_type,
            raw.entry.description,
            raw.entry.category,
            raw.entry.default_version,
            raw.entry.native_priority
        );

        let usage_guidance = if !guidance_hints.is_empty() {
            guidance_hints.join(" ")
        } else if raw.entry.native_priority == 1 {
            "Preferred native integration/trigger node (Tier 1). Bind credentials by reference ID/name."
                .to_owned()
        } else if is_native_data_node(&raw.entry.node_type) {
            "Preferred native data/flow transformation node (Tier 2). Use instead of custom Code nodes whenever possible."
                .to_owned()
        } else {
            format!(
                "Side-effect classification: `{}`.",
                raw.entry.side_effect_class
            )
        };

        let in_ports = if raw.inputs.is_empty() {
            "none (trigger / sub-node)".to_owned()
        } else {
            raw.inputs.join(", ")
        };
        let out_ports = if raw.outputs.is_empty() {
            "none (terminal)".to_owned()
        } else {
            raw.outputs.join(", ")
        };
        let ports_summary = format!("Inputs: [{in_ports}] -> Outputs: [{out_ports}]");

        let mut credentials_summary = Vec::with_capacity(raw.credentials.len());
        for cred in &raw.credentials {
            if let Some(meta) = self.get_credential_type(&cred.name)? {
                let doc_suffix = meta
                    .documentation_url
                    .as_deref()
                    .map_or_else(String::new, |u| format!(" ({u})"));
                credentials_summary.push(format!(
                    "`{}` ({}, auth={}) — fields: [{}]{doc_suffix}",
                    meta.credential_type,
                    meta.display_name,
                    meta.auth_kind,
                    meta.required_fields.join(", ")
                ));
            } else {
                credentials_summary.push(format!("`{}` (required={})", cred.name, cred.required));
            }
        }

        let operations_summary: Vec<String> = operations
            .iter()
            .map(|op| format!("{}.{}: {}", op.resource, op.operation, op.display_name))
            .collect();

        let mut seen_props = BTreeSet::new();
        let mut key_properties = Vec::new();
        for prop in properties {
            if !seen_props.insert(prop.name.clone()) {
                continue;
            }
            let req_tag = if prop.required {
                "required"
            } else {
                "optional"
            };
            key_properties.push(format!(
                "`{}` ({}, {req_tag}): {}",
                prop.name, prop.prop_type, prop.description
            ));
        }

        let mut markdown = String::new();
        let _ = writeln!(
            markdown,
            "# {} (`{}`)\n\n{}\n\n- **Ports:** {}\n- **Guidance:** {}",
            raw.entry.display_name,
            raw.entry.node_type,
            raw.entry.description,
            ports_summary,
            usage_guidance
        );
        if !credentials_summary.is_empty() {
            let _ = writeln!(markdown, "\n## Credentials");
            for c in &credentials_summary {
                let _ = writeln!(markdown, "- {c}");
            }
        }
        if !operations_summary.is_empty() {
            let _ = writeln!(markdown, "\n## Operations");
            for o in &operations_summary {
                let _ = writeln!(markdown, "- {o}");
            }
        }
        if !key_properties.is_empty() {
            let _ = writeln!(markdown, "\n## Properties");
            for p in &key_properties {
                let _ = writeln!(markdown, "- {p}");
            }
        }

        Ok(NodeDocsSection {
            overview,
            usage_guidance,
            ports_summary,
            credentials_summary,
            operations_summary,
            key_properties,
            markdown,
        })
    }
}

fn map_raw_node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawNodeRow> {
    let inputs_str: String = row.get(18)?;
    let outputs_str: String = row.get(19)?;
    let output_names_str: Option<String> = row.get(20)?;
    let creds_str: String = row.get(21)?;

    let priority_i64: i64 = row.get(15)?;
    let score_i64: i64 = row.get(16)?;

    Ok(RawNodeRow {
        entry: NodeCatalogEntry {
            node_type: row.get(0)?,
            short_type: row.get(1)?,
            package_name: row.get(2)?,
            display_name: row.get(3)?,
            description: row.get(4)?,
            category: row.get(5)?,
            default_version: row.get(7)?,
            is_trigger: row.get::<_, i64>(9)? != 0,
            is_webhook: row.get::<_, i64>(10)? != 0,
            is_ai_tool: row.get::<_, i64>(11)? != 0,
            has_tool_variant: row.get::<_, i64>(13)? != 0,
            native_priority: u8::try_from(priority_i64.clamp(1, 255)).unwrap_or(5),
            native_score: u8::try_from(score_i64.clamp(0, 100)).unwrap_or(50),
            side_effect_class: row.get(17)?,
        },
        development_style: row.get(6)?,
        is_versioned: row.get::<_, i64>(8)? != 0,
        is_tool_variant: row.get::<_, i64>(12)? != 0,
        tool_variant_of: row.get(14)?,
        inputs: serde_json::from_str(&inputs_str).unwrap_or_default(),
        outputs: serde_json::from_str(&outputs_str).unwrap_or_default(),
        output_names: output_names_str
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok()),
        credentials: serde_json::from_str(&creds_str).unwrap_or_default(),
        schema_hash: row.get(22)?,
    })
}

pub(crate) fn tokenize_search_terms(raw_query: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();

    for ch in raw_query.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            for lower in ch.to_lowercase() {
                current.push(lower);
            }
        } else if !current.is_empty() {
            push_clean_token(&mut out, &mut current);
        }
    }
    if !current.is_empty() {
        push_clean_token(&mut out, &mut current);
    }

    out
}

fn push_clean_token(out: &mut Vec<String>, current: &mut String) {
    let candidate = std::mem::take(current);
    // Skip redundant FTS5 structural noise tokens if user pasted package prefixes or operators.
    if !candidate.is_empty() && !out.contains(&candidate) {
        out.push(candidate);
    }
}

fn build_node_fts_expression(
    tokens: &[String],
    mode: SearchMode,
    include_operations: bool,
) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }

    let term_exprs: Vec<String> = tokens
        .iter()
        .map(|tok| match mode {
            SearchMode::Fuzzy => format!("{tok}*"),
            SearchMode::Or | SearchMode::And => format!("\"{tok}\""),
        })
        .collect();

    let joined = match mode {
        SearchMode::And => term_exprs.join(" AND "),
        SearchMode::Or | SearchMode::Fuzzy => term_exprs.join(" OR "),
    };

    if include_operations {
        Some(joined)
    } else {
        Some(format!(
            "{{node_type short_type display_name category description keywords}} : ({joined})"
        ))
    }
}

fn compute_combined_relevance(
    raw_query: &str,
    tokens: &[String],
    entry: &NodeCatalogEntry,
    lexical_bm25: f64,
) -> f64 {
    let priority_boost = match entry.native_priority {
        1 => 30.0,
        2 if is_native_data_node(&entry.node_type) => 24.0,
        2 => 20.0,
        3 => 12.0,
        4 => 4.0,
        _ => 0.0,
    };
    let score_boost = f64::from(entry.native_score) * 0.15;

    let q_lower = raw_query.trim().to_ascii_lowercase();
    let short_lower = entry.short_type.to_ascii_lowercase();
    let disp_lower = entry.display_name.to_ascii_lowercase();
    let full_lower = entry.node_type.to_ascii_lowercase();

    let mut exact_boost = 0.0;
    if !q_lower.is_empty() {
        if q_lower == full_lower || q_lower == short_lower || q_lower == disp_lower {
            exact_boost += 60.0;
        } else if disp_lower.contains(&q_lower) || short_lower.starts_with(&q_lower) {
            exact_boost += 22.0;
        }
    }

    for tok in tokens {
        if tok == &short_lower {
            exact_boost += 25.0;
        } else if disp_lower
            .split(|c: char| !c.is_alphanumeric())
            .any(|w| w == tok)
        {
            exact_boost += 12.0;
        }
    }

    lexical_bm25 * 2.5 + priority_boost + score_boost + exact_boost
}

fn fuzzy_match_node(tokens: &[String], entry: &NodeCatalogEntry) -> Option<f64> {
    let candidates = [
        entry.short_type.to_ascii_lowercase(),
        entry.display_name.to_ascii_lowercase(),
        entry.category.to_ascii_lowercase(),
    ];

    let mut best = 0.0_f64;
    for tok in tokens {
        if tok.len() < 3 {
            continue;
        }
        for cand in &candidates {
            if cand.contains(tok) {
                best = best.max(6.0);
                continue;
            }
            for word in cand.split(|c: char| !c.is_alphanumeric()) {
                if word.is_empty() {
                    continue;
                }
                let dist = bounded_edit_distance(tok, word, 2);
                if dist <= 1 {
                    best = best.max(5.0);
                } else if dist == 2 && tok.len() >= 5 {
                    best = best.max(3.0);
                }
            }
        }
    }

    if best > 0.0 { Some(best) } else { None }
}

fn bounded_edit_distance(a: &str, b: &str, max_dist: usize) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    if a_chars.len().abs_diff(b_chars.len()) > max_dist {
        return max_dist + 1;
    }

    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0; b_chars.len() + 1];

    for (i, &ca) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
            row_min = row_min.min(curr[j + 1]);
        }
        if row_min > max_dist {
            return max_dist + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_chars.len()]
}

fn resolve_conditional_property_defaults(
    properties: &[NodePropertyRecord],
    params: &Map<String, Value>,
    node_ctx: &Map<String, Value>,
) -> Map<String, Value> {
    let mut defaults = Map::new();

    // Pass 1: unconditional schema defaults.
    for prop in properties {
        if prop.display_options.is_none()
            && let Some(ref def_val) = prop.default_value
            && !defaults.contains_key(&prop.name)
        {
            defaults.insert(prop.name.clone(), def_val.clone());
        }
    }

    // Pass 2: fixed-point resolution of visible conditional property defaults (up to 4 hops).
    for _ in 0..4 {
        let mut changed = false;
        let snapshot = defaults.clone();
        let ctx = DisplayEvalContext::new(params, &snapshot, node_ctx);

        for prop in properties {
            if prop.display_options.is_some()
                && !defaults.contains_key(&prop.name)
                && let Some(ref def_val) = prop.default_value
                && evaluate_display_options(prop.display_options.as_ref(), None, &ctx)
            {
                defaults.insert(prop.name.clone(), def_val.clone());
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    defaults
}

fn is_missing_required_value(effective: Option<&Value>) -> bool {
    match effective {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(_) => false,
    }
}

fn search_node_properties(
    properties: &[NodePropertyRecord],
    needle_lower: &str,
) -> Vec<PropertySearchMatch> {
    let mut matches = Vec::new();
    let mut seen_paths = BTreeSet::new();

    for prop in properties {
        let top_hit = needle_lower.is_empty()
            || prop.name.to_ascii_lowercase().contains(needle_lower)
            || prop
                .display_name
                .to_ascii_lowercase()
                .contains(needle_lower)
            || prop.description.to_ascii_lowercase().contains(needle_lower)
            || prop.prop_type.to_ascii_lowercase().contains(needle_lower);

        if top_hit && seen_paths.insert(prop.name.clone()) {
            matches.push(PropertySearchMatch {
                path: prop.name.clone(),
                name: prop.name.clone(),
                display_name: prop.display_name.clone(),
                prop_type: prop.prop_type.clone(),
                required: prop.required,
                default_value: prop.default_value.clone(),
                description: prop.description.clone(),
                display_options: prop.display_options.clone(),
            });
        }

        // Also inspect nested `collection` or `fixedCollection` child fields.
        if let Some(options_arr) = prop.options.as_ref().and_then(Value::as_array) {
            if prop.prop_type == "collection" {
                for child in options_arr {
                    collect_nested_property_match(
                        &prop.name,
                        child,
                        needle_lower,
                        &mut seen_paths,
                        &mut matches,
                    );
                }
            } else if prop.prop_type == "fixedCollection" {
                for grp in options_arr {
                    if let Some(gobj) = grp.as_object()
                        && let Some(gname) = gobj.get("name").and_then(Value::as_str)
                        && let Some(vals) = gobj.get("values").and_then(Value::as_array)
                    {
                        let prefix = format!("{}.{gname}", prop.name);
                        for child in vals {
                            collect_nested_property_match(
                                &prefix,
                                child,
                                needle_lower,
                                &mut seen_paths,
                                &mut matches,
                            );
                        }
                    }
                }
            }
        }
    }

    matches
}

fn collect_nested_property_match(
    prefix: &str,
    child_val: &Value,
    needle_lower: &str,
    seen_paths: &mut BTreeSet<String>,
    out: &mut Vec<PropertySearchMatch>,
) {
    let Some(obj) = child_val.as_object() else {
        return;
    };
    let Some(cname) = obj.get("name").and_then(Value::as_str) else {
        return;
    };
    let cdisp = obj
        .get("displayName")
        .or_else(|| obj.get("display_name"))
        .and_then(Value::as_str)
        .unwrap_or(cname);
    let ctype = obj.get("type").and_then(Value::as_str).unwrap_or("string");
    let cdesc = obj.get("description").and_then(Value::as_str).unwrap_or("");

    let hit = needle_lower.is_empty()
        || cname.to_ascii_lowercase().contains(needle_lower)
        || cdisp.to_ascii_lowercase().contains(needle_lower)
        || cdesc.to_ascii_lowercase().contains(needle_lower)
        || ctype.to_ascii_lowercase().contains(needle_lower);

    let full_path = format!("{prefix}.{cname}");
    if hit && seen_paths.insert(full_path.clone()) {
        out.push(PropertySearchMatch {
            path: full_path,
            name: cname.to_owned(),
            display_name: cdisp.to_owned(),
            prop_type: ctype.to_owned(),
            required: obj
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            default_value: obj.get("default").cloned(),
            description: cdesc.to_owned(),
            display_options: obj.get("displayOptions").cloned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::*;

    fn open_real_catalog() -> CatalogDb {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        CatalogDb::open_default_workspace_bundle(&root).expect("load real catalog bundle")
    }

    #[test]
    fn search_nodes_supports_or_and_fuzzy_source_filters_and_native_first_hints() {
        let db = open_real_catalog();

        // 1. Native-first ranking: searching "slack message" puts Slack ahead of HTTP/Code.
        let slack_res = db
            .search_nodes(&NodeSearchQuery {
                query: "slack message".to_owned(),
                mode: SearchMode::Or,
                source: NodeSourceFilter::All,
                include_operations: true,
                detail: DetailLevel::Standard,
                limit: 5,
            })
            .expect("search slack");
        assert!(!slack_res.hits.is_empty());
        assert_eq!(slack_res.hits[0].node_type, "n8n-nodes-base.slack");
        assert!(slack_res.hits[0].operations.is_some());

        // 2. AND mode narrows strictly to nodes matching all terms.
        let and_res = db
            .search_nodes(&NodeSearchQuery {
                query: "qdrant vector".to_owned(),
                mode: SearchMode::And,
                source: NodeSourceFilter::Langchain,
                include_operations: false,
                detail: DetailLevel::Minimal,
                limit: 5,
            })
            .expect("search qdrant AND");
        assert_eq!(and_res.total_returned, 1);
        assert_eq!(
            and_res.hits[0].node_type,
            "@n8n/n8n-nodes-langchain.vectorStoreQdrant"
        );
        assert!(and_res.hits[0].description.is_none()); // Minimal omits description

        // 3. FUZZY mode handles prefix and typo ("postgrse").
        let fuzzy_res = db
            .search_nodes(&NodeSearchQuery {
                query: "postgrse".to_owned(),
                mode: SearchMode::Fuzzy,
                source: NodeSourceFilter::Core,
                include_operations: false,
                detail: DetailLevel::Minimal,
                limit: 5,
            })
            .expect("fuzzy search");
        assert!(
            fuzzy_res
                .hits
                .iter()
                .any(|h| h.node_type == "n8n-nodes-base.postgres")
        );

        // 4. Querying Code or HTTP Request emits V2 native-first guidance hints.
        let code_res = db
            .search_nodes(&NodeSearchQuery {
                query: "code javascript".to_owned(),
                mode: SearchMode::Or,
                source: NodeSourceFilter::All,
                include_operations: false,
                detail: DetailLevel::Full,
                limit: 5,
            })
            .expect("code search");
        assert!(
            code_res
                .guidance_hints
                .iter()
                .any(|h| h.contains("Why Code:"))
        );

        let http_res = db
            .search_nodes(&NodeSearchQuery {
                query: "httpRequest rest".to_owned(),
                mode: SearchMode::Or,
                source: NodeSourceFilter::Core,
                include_operations: false,
                detail: DetailLevel::Standard,
                limit: 5,
            })
            .expect("http search");
        assert!(
            http_res
                .guidance_hints
                .iter()
                .any(|h| h.contains("dedicated native service node"))
        );

        // 5. Native priority order helper puts Service (1) -> Native Data (2) -> HTTP (3) -> Code (4).
        let mixed = vec![
            NodeCatalogEntry {
                node_type: "n8n-nodes-base.code".to_owned(),
                display_name: "Code".to_owned(),
                default_version: "2".to_owned(),
                native_priority: 4,
                native_score: 40,
                ..serde_json::from_value(json!({
                    "nodeType": "n8n-nodes-base.code",
                    "displayName": "Code",
                    "defaultVersion": "2",
                    "nativePriority": 4
                }))
                .expect("entry")
            },
            NodeCatalogEntry {
                node_type: "n8n-nodes-base.httpRequest".to_owned(),
                display_name: "HTTP Request".to_owned(),
                default_version: "4.2".to_owned(),
                native_priority: 3,
                native_score: 80,
                ..serde_json::from_value(json!({
                    "nodeType": "n8n-nodes-base.httpRequest",
                    "displayName": "HTTP Request",
                    "defaultVersion": "4.2",
                    "nativePriority": 3
                }))
                .expect("entry")
            },
            NodeCatalogEntry {
                node_type: "n8n-nodes-base.set".to_owned(),
                display_name: "Edit Fields (Set)".to_owned(),
                default_version: "3.4".to_owned(),
                native_priority: 2,
                native_score: 96,
                ..serde_json::from_value(json!({
                    "nodeType": "n8n-nodes-base.set",
                    "displayName": "Edit Fields (Set)",
                    "defaultVersion": "3.4",
                    "nativePriority": 2
                }))
                .expect("entry")
            },
            NodeCatalogEntry {
                node_type: "n8n-nodes-base.slack".to_owned(),
                display_name: "Slack".to_owned(),
                default_version: "2.3".to_owned(),
                native_priority: 1,
                native_score: 98,
                ..serde_json::from_value(json!({
                    "nodeType": "n8n-nodes-base.slack",
                    "displayName": "Slack",
                    "defaultVersion": "2.3",
                    "nativePriority": 1
                }))
                .expect("entry")
            },
        ];
        let ranked = rank_native_first(mixed);
        let ordered_types: Vec<&str> = ranked.iter().map(|e| e.node_type.as_str()).collect();
        assert_eq!(
            ordered_types,
            vec![
                "n8n-nodes-base.slack",
                "n8n-nodes-base.set",
                "n8n-nodes-base.httpRequest",
                "n8n-nodes-base.code"
            ]
        );
    }

    #[test]
    fn get_node_info_covers_info_docs_search_properties_and_versions() {
        let db = open_real_catalog();

        let docs_resp = db
            .get_node_info(&NodeInfoRequest {
                node_type: "n8n-nodes-base.postgres".to_owned(),
                mode: NodeInfoMode::Docs,
                type_version: None,
                property_query: None,
            })
            .expect("docs mode");
        assert!(docs_resp.found_in_catalog);
        assert_eq!(
            docs_resp.schema_confidence,
            SchemaConfidence::AuthoritativeCatalog
        );
        let docs = docs_resp.docs.expect("docs populated");
        assert!(docs.markdown.contains("Postgres"));
        assert!(!docs.credentials_summary.is_empty());

        let prop_resp = db
            .get_node_info(&NodeInfoRequest {
                node_type: "httpRequest".to_owned(),
                mode: NodeInfoMode::SearchProperties,
                type_version: Some("4.2".to_owned()),
                property_query: Some("body".to_owned()),
            })
            .expect("search_properties mode");
        assert!(
            prop_resp
                .property_matches
                .iter()
                .any(|m| m.name == "jsonBody")
        );

        let ver_resp = db
            .get_node_info(&NodeInfoRequest {
                node_type: "n8n-nodes-base.httpRequest".to_owned(),
                mode: NodeInfoMode::Versions,
                type_version: None,
                property_query: None,
            })
            .expect("versions mode");
        assert!(ver_resp.versions.len() >= 4);
        assert!(
            ver_resp
                .versions
                .iter()
                .any(|v| v.is_default && v.type_version == "4.2")
        );
    }

    #[test]
    fn inspect_effective_node_fields_resolves_visibility_credentials_and_unknown_warnings() {
        let db = open_real_catalog();

        // 1. HTTP Request GET vs POST JSON body visibility + unknown parameter warning.
        let get_inspect = db
            .inspect_effective_node_fields(
                "n8n-nodes-base.httpRequest",
                Some("4.2"),
                &json!({
                    "method": "GET",
                    "url": "https://api.example.com/items",
                    "bogusParam": 123,
                    "jsonBody": "{}"
                }),
            )
            .expect("inspect GET");
        assert_eq!(
            get_inspect.schema_confidence,
            SchemaConfidence::AuthoritativeCatalog
        );
        assert!(
            get_inspect
                .visible_required_properties
                .iter()
                .any(|p| p.name == "url")
        );
        assert!(
            get_inspect
                .hidden_properties
                .contains(&"jsonBody".to_owned())
        );
        assert_eq!(get_inspect.unknown_parameter_warnings.len(), 1);
        assert!(get_inspect.unknown_parameter_warnings[0].contains("bogusParam"));
        assert_eq!(get_inspect.inactive_parameter_warnings.len(), 1);
        assert!(get_inspect.inactive_parameter_warnings[0].contains("jsonBody"));

        // 2. Slack multi-row conditional `operation` default resolution + OAuth2 credential visibility.
        let slack_inspect = db
            .inspect_effective_node_fields(
                "n8n-nodes-base.slack",
                Some("2.3"),
                &json!({
                    "authentication": "oAuth2"
                }),
            )
            .expect("inspect Slack");
        assert_eq!(
            slack_inspect.defaults.get("resource"),
            Some(&json!("message"))
        );
        assert_eq!(
            slack_inspect.defaults.get("operation"),
            Some(&json!("post"))
        );
        assert!(
            slack_inspect
                .visible_required_properties
                .iter()
                .any(|p| p.name == "channelId")
        );
        assert_eq!(slack_inspect.allowed_credentials.len(), 1);
        assert_eq!(
            slack_inspect.allowed_credentials[0].credential_type,
            "slackOAuth2Api"
        );

        // 3. Community node never falsely emits authoritative unknown_parameter_warnings.
        let comm_inspect = db
            .inspect_effective_node_fields(
                "n8n-nodes-custom-erp.syncOrder",
                Some("1"),
                &json!({ "customField": "abc" }),
            )
            .expect("inspect community");
        assert_eq!(
            comm_inspect.schema_confidence,
            SchemaConfidence::UnknownOrCommunityPartial
        );
        assert!(comm_inspect.unknown_parameter_warnings.is_empty());
        assert!(!comm_inspect.warnings.is_empty());
    }

    #[test]
    fn resists_fts5_syntax_edge_cases_and_covers_all_13_native_data_nodes() {
        let db = open_real_catalog();

        // Adversarial / punctuation-heavy FTS5 query strings never error.
        for tricky in [
            "",
            "   ",
            "\"unclosed quote ((( OR AND NOT * : ---",
            "@n8n/n8n-nodes-langchain.agent",
            "n8n-nodes-base.httpRequest",
        ] {
            let res = db
                .search_nodes(&NodeSearchQuery {
                    query: tricky.to_owned(),
                    mode: SearchMode::Or,
                    ..NodeSearchQuery::default()
                })
                .expect("fts query must not fail on special punctuation");
            assert!(res.total_returned <= 20);
        }

        // Every one of the 13 V2 native data nodes exists in the authoritative catalog as Priority 2.
        assert_eq!(NATIVE_DATA_NODE_TYPES.len(), 13);
        for &nd_type in NATIVE_DATA_NODE_TYPES {
            let info = db
                .get_node_info(&NodeInfoRequest {
                    node_type: nd_type.to_owned(),
                    mode: NodeInfoMode::Info,
                    type_version: None,
                    property_query: None,
                })
                .expect("get native data node");
            assert!(info.found_in_catalog, "missing native data node {nd_type}");
            assert_eq!(
                info.schema_confidence,
                SchemaConfidence::AuthoritativeCatalog
            );
            assert_eq!(info.entry.expect("entry").native_priority, 2);
        }
    }
}
