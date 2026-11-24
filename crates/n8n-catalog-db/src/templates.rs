//! Curated workflow template search (`keyword`, `by_nodes`, `by_task`, `by_metadata`, `patterns`)
//! and sanitized deployable template projection (`nodes_only`, `structure`, `full`) with
//! credential-reference placeholders and zero secrets.

use std::collections::BTreeSet;

use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use n8n_types::{N8nError, N8nResult, is_sensitive_key, redact_str};

use crate::schema::CatalogDb;
use crate::search::tokenize_search_terms;

/// Compact template summary preserved for backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSummary {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// Search mode for [`CatalogDb::search_templates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSearchMode {
    #[default]
    Keyword,
    ByNodes,
    ByTask,
    ByMetadata,
    Patterns,
}

/// Output detail projection for [`CatalogDb::search_templates`] and [`CatalogDb::get_template`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateDetailMode {
    NodesOnly,
    #[default]
    Structure,
    Full,
}

/// Search query for [`CatalogDb::search_templates`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSearchQuery {
    #[serde(default)]
    pub mode: TemplateSearchMode,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub node_types: Vec<String>,
    #[serde(default)]
    pub match_all_nodes: bool,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub complexity: Option<String>,
    #[serde(default)]
    pub max_setup_minutes: Option<u32>,
    #[serde(default)]
    pub min_setup_minutes: Option<u32>,
    #[serde(default)]
    pub required_credential: Option<String>,
    #[serde(default)]
    pub requires_no_credentials: Option<bool>,
    #[serde(default)]
    pub detail: TemplateDetailMode,
    #[serde(default = "default_template_limit")]
    pub limit: usize,
}

impl Default for TemplateSearchQuery {
    fn default() -> Self {
        Self {
            mode: TemplateSearchMode::Keyword,
            query: None,
            node_types: Vec::new(),
            match_all_nodes: false,
            task: None,
            category: None,
            complexity: None,
            max_setup_minutes: None,
            min_setup_minutes: None,
            required_credential: None,
            requires_no_credentials: None,
            detail: TemplateDetailMode::Structure,
            limit: 20,
        }
    }
}

const fn default_template_limit() -> usize {
    20
}

/// Sanitized structural summary of a node inside a template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateNodeStub {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub type_version: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<Vec<i64>>,
}

/// Non-secret credential binding placeholder attached to `structure` and `full` templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPlaceholder {
    pub credential_type: String,
    pub placeholder_id: String,
    pub placeholder_name: String,
    pub bound_nodes: Vec<String>,
}

/// Projected template entry returned by [`CatalogDb::search_templates`] and [`CatalogDb::get_template`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateCatalogEntry {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub complexity: String,
    pub estimated_setup_minutes: u32,
    pub pattern_archetype: String,
    pub nodes_used: Vec<String>,
    pub required_credentials: Vec<String>,
    pub source_attribution: String,
    pub nodes: Vec<TemplateNodeStub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_placeholders: Option<Vec<CredentialPlaceholder>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<Value>,
}

/// Search response returned by [`CatalogDb::search_templates`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSearchResponse {
    pub mode: TemplateSearchMode,
    pub detail: TemplateDetailMode,
    pub total_returned: usize,
    pub templates: Vec<TemplateCatalogEntry>,
}

#[derive(Debug, Clone)]
struct RawTemplateRow {
    id: i64,
    slug: String,
    name: String,
    description: String,
    category: String,
    complexity: String,
    estimated_setup_minutes: u32,
    nodes_used: Vec<String>,
    required_credentials: Vec<String>,
    workflow_json: Value,
    source_attribution: String,
}

impl CatalogDb {
    /// Lists lightweight [`TemplateSummary`] items across all catalogued templates.
    pub fn list_template_summaries(&self) -> N8nResult<Vec<TemplateSummary>> {
        let mut stmt = self
            .connection()
            .prepare_cached("SELECT id, name, description FROM templates ORDER BY id ASC;")
            .map_err(|e| {
                N8nError::protocol(format!("failed preparing template summary list: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                let id_num: i64 = row.get(0)?;
                Ok(TemplateSummary {
                    id: id_num.to_string(),
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            })
            .map_err(|e| N8nError::protocol(format!("failed reading template summaries: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| N8nError::protocol(format!("invalid template summary: {e}")))?);
        }
        Ok(out)
    }

    /// Fetches a single curated template by numeric ID (`"1"`) or slug (`"rag-qdrant-knowledge-assistant"`).
    pub fn get_template(
        &self,
        id_or_slug: &str,
        detail: TemplateDetailMode,
    ) -> N8nResult<Option<TemplateCatalogEntry>> {
        let trimmed = id_or_slug.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let raw_opt = if let Ok(numeric_id) = trimmed.parse::<i64>() {
            self.load_template_by_id(numeric_id)?
        } else {
            self.load_template_by_slug(trimmed)?
        };

        match raw_opt {
            Some(raw) => Ok(Some(self.project_template(raw, detail)?)),
            None => Ok(None),
        }
    }

    /// Searches curated templates across `keyword`, `by_nodes`, `by_task`, `by_metadata`, and `patterns`.
    pub fn search_templates(&self, req: &TemplateSearchQuery) -> N8nResult<TemplateSearchResponse> {
        let clamped_limit = req.limit.clamp(1, 100);

        let matched_rows: Vec<RawTemplateRow> = match req.mode {
            TemplateSearchMode::Keyword => {
                let q = req.query.as_deref().unwrap_or("").trim();
                if q.is_empty() {
                    self.load_all_templates(clamped_limit)?
                } else {
                    self.query_template_fts_keywords(q, clamped_limit)?
                }
            }
            TemplateSearchMode::ByNodes => {
                self.search_templates_by_nodes(&req.node_types, req.match_all_nodes, clamped_limit)?
            }
            TemplateSearchMode::ByTask => {
                let task_str = req
                    .task
                    .as_deref()
                    .or(req.query.as_deref())
                    .unwrap_or("")
                    .trim();
                self.search_templates_by_task(task_str, clamped_limit)?
            }
            TemplateSearchMode::ByMetadata => {
                self.search_templates_by_metadata(req, clamped_limit)?
            }
            TemplateSearchMode::Patterns => self.search_template_patterns(req, clamped_limit)?,
        };

        let mut templates = Vec::with_capacity(matched_rows.len());
        for raw in matched_rows {
            templates.push(self.project_template(raw, req.detail)?);
        }

        Ok(TemplateSearchResponse {
            mode: req.mode,
            detail: req.detail,
            total_returned: templates.len(),
            templates,
        })
    }

    fn load_template_by_id(&self, id: i64) -> N8nResult<Option<RawTemplateRow>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT id, slug, name, description, category, complexity,
                        estimated_setup_minutes, nodes_used_json, required_credentials_json,
                        workflow_json, source_attribution
                 FROM templates
                 WHERE id = ?1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing template id lookup: {e}")))?;

        stmt.query_row(rusqlite::params![id], map_raw_template_row)
            .optional()
            .map_err(|e| N8nError::protocol(format!("failed querying template by id: {e}")))
    }

    fn load_template_by_slug(&self, slug: &str) -> N8nResult<Option<RawTemplateRow>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT id, slug, name, description, category, complexity,
                        estimated_setup_minutes, nodes_used_json, required_credentials_json,
                        workflow_json, source_attribution
                 FROM templates
                 WHERE slug = ?1;",
            )
            .map_err(|e| {
                N8nError::protocol(format!("failed preparing template slug lookup: {e}"))
            })?;

        stmt.query_row(rusqlite::params![slug], map_raw_template_row)
            .optional()
            .map_err(|e| N8nError::protocol(format!("failed querying template by slug: {e}")))
    }

    fn load_all_templates(&self, limit: usize) -> N8nResult<Vec<RawTemplateRow>> {
        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT id, slug, name, description, category, complexity,
                        estimated_setup_minutes, nodes_used_json, required_credentials_json,
                        workflow_json, source_attribution
                 FROM templates
                 ORDER BY id ASC
                 LIMIT ?1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing all templates scan: {e}")))?;

        let limit_i64 = i64::try_from(limit).unwrap_or(100);
        let rows = stmt
            .query_map(rusqlite::params![limit_i64], map_raw_template_row)
            .map_err(|e| N8nError::protocol(format!("failed scanning templates: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| N8nError::protocol(format!("invalid template row: {e}")))?);
        }
        Ok(out)
    }

    fn query_template_fts_keywords(
        &self,
        raw_query: &str,
        limit: usize,
    ) -> N8nResult<Vec<RawTemplateRow>> {
        let tokens = tokenize_search_terms(raw_query);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let expr = tokens
            .iter()
            .map(|t| format!("(\"{t}\" OR {t}*)"))
            .collect::<Vec<_>>()
            .join(" OR ");

        let mut stmt = self
            .connection()
            .prepare_cached(
                "SELECT t.id, t.slug, t.name, t.description, t.category, t.complexity,
                        t.estimated_setup_minutes, t.nodes_used_json, t.required_credentials_json,
                        t.workflow_json, t.source_attribution,
                        bm25(template_fts, 6.0, 8.0, 3.0, 4.0, 5.0) AS rank_score
                 FROM template_fts
                 JOIN templates t ON t.slug = template_fts.slug
                 WHERE template_fts MATCH ?1
                 ORDER BY rank_score ASC, t.id ASC
                 LIMIT ?2;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing template_fts query: {e}")))?;

        let limit_i64 = i64::try_from(limit).unwrap_or(100);
        let rows = stmt
            .query_map(rusqlite::params![expr, limit_i64], map_raw_template_row)
            .map_err(|e| N8nError::protocol(format!("failed executing template_fts query: {e}")))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| N8nError::protocol(format!("invalid template_fts row: {e}")))?);
        }
        Ok(out)
    }

    fn search_templates_by_nodes(
        &self,
        requested_nodes: &[String],
        match_all: bool,
        limit: usize,
    ) -> N8nResult<Vec<RawTemplateRow>> {
        if requested_nodes.is_empty() {
            return Ok(Vec::new());
        }

        let mut canonical_targets = Vec::with_capacity(requested_nodes.len());
        for raw_nt in requested_nodes {
            let clean = raw_nt.trim();
            if clean.is_empty() {
                continue;
            }
            if let Some((canon, _, _)) = self.lookup_node_identity(clean)? {
                canonical_targets.push(canon.to_ascii_lowercase());
            } else {
                canonical_targets.push(clean.to_ascii_lowercase());
            }
        }
        if canonical_targets.is_empty() {
            return Ok(Vec::new());
        }

        let all = self.load_all_templates(200)?;
        let mut scored: Vec<(usize, RawTemplateRow)> = Vec::new();

        for row in all {
            let used_lower: Vec<String> = row
                .nodes_used
                .iter()
                .map(|u| u.to_ascii_lowercase())
                .collect();

            let matched_count = canonical_targets
                .iter()
                .filter(|target| {
                    used_lower.iter().any(|u| {
                        u == *target
                            || u.rsplit('.')
                                .next()
                                .is_some_and(|short| short == target.as_str())
                    })
                })
                .count();

            if (match_all && matched_count == canonical_targets.len())
                || (!match_all && matched_count > 0)
            {
                scored.push((matched_count, row));
            }
        }

        scored.sort_by(|(a_cnt, a_row), (b_cnt, b_row)| {
            b_cnt.cmp(a_cnt).then_with(|| a_row.id.cmp(&b_row.id))
        });
        scored.truncate(limit);
        Ok(scored.into_iter().map(|(_, r)| r).collect())
    }

    fn search_templates_by_task(&self, task: &str, limit: usize) -> N8nResult<Vec<RawTemplateRow>> {
        if task.is_empty() {
            return self.load_all_templates(limit);
        }

        let norm: String = task
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();

        let expanded = match norm.trim_matches('_') {
            "webhook" | "webhooks" | "webhook_processing" | "http_webhook" => {
                "webhook hmac respond signature ingest"
            }
            "rag" | "vector" | "knowledge_base" | "embeddings" => {
                "rag qdrant pgvector embeddings vector document"
            }
            "ai" | "ai_agent" | "agent" | "conversational" | "chatbot" => {
                "agent chat memory tool llm langchain"
            }
            "triage" | "classification" | "ai_classification" | "structured_output" => {
                "classify structured parser triage switch gemini"
            }
            "database_sync" | "data_sync" | "sync" | "reconciliation" | "etl" => {
                "postgres sheets compare delta sync xml merge"
            }
            "error" | "error_handling" | "incident" | "reliability" | "alerting" => {
                "error incident jira slack alert"
            }
            "scheduled" | "cron" | "polling" | "digest" => "schedule polling dedupe digest",
            "crm" | "lead" | "sales" | "enrichment" => "hubspot crm lead gmail airtable batch loop",
            "subworkflow" | "modular" | "datatable" => {
                "subworkflow datatable reusable executeWorkflowTrigger"
            }
            "idempotency" | "bot" | "telegram" | "redis" => "redis idempotency lock telegram",
            "privacy" | "local_ai" | "local_llm" | "ollama" => "ollama privacy local log",
            "devops" | "github" | "release" => "github release notion discord markdown",
            _ => task,
        };

        self.query_template_fts_keywords(expanded, limit)
    }

    fn search_templates_by_metadata(
        &self,
        req: &TemplateSearchQuery,
        limit: usize,
    ) -> N8nResult<Vec<RawTemplateRow>> {
        let base_pool = if let Some(q) = req
            .query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            self.query_template_fts_keywords(q, 200)?
        } else {
            self.load_all_templates(200)?
        };

        let cat_filter = req
            .category
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let comp_filter = req
            .complexity
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let cred_filter = req
            .required_credential
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        let mut filtered = Vec::new();
        for row in base_pool {
            if let Some(ref cat) = cat_filter
                && !row.category.to_ascii_lowercase().contains(cat)
            {
                continue;
            }
            if let Some(ref comp) = comp_filter
                && row.complexity.to_ascii_lowercase() != *comp
            {
                continue;
            }
            if let Some(max_min) = req.max_setup_minutes
                && row.estimated_setup_minutes > max_min
            {
                continue;
            }
            if let Some(min_min) = req.min_setup_minutes
                && row.estimated_setup_minutes < min_min
            {
                continue;
            }
            if let Some(ref cred) = cred_filter
                && !row
                    .required_credentials
                    .iter()
                    .any(|c| c.to_ascii_lowercase() == *cred)
            {
                continue;
            }
            if let Some(no_creds) = req.requires_no_credentials
                && row.required_credentials.is_empty() != no_creds
            {
                continue;
            }
            filtered.push(row);
            if filtered.len() >= limit {
                break;
            }
        }

        Ok(filtered)
    }

    fn search_template_patterns(
        &self,
        req: &TemplateSearchQuery,
        limit: usize,
    ) -> N8nResult<Vec<RawTemplateRow>> {
        let pool = self.search_templates_by_metadata(req, 200)?;
        let q_opt = req
            .query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        let mut out = Vec::new();
        for row in pool {
            if let Some(ref q) = q_opt {
                let arch = derive_pattern_archetype(&row.slug, &row.category).to_ascii_lowercase();
                let slug_l = row.slug.to_ascii_lowercase();
                let cat_l = row.category.to_ascii_lowercase();
                let name_l = row.name.to_ascii_lowercase();
                if !arch.contains(q)
                    && !slug_l.contains(q)
                    && !cat_l.contains(q)
                    && !name_l.contains(q)
                {
                    continue;
                }
            }
            out.push(row);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    fn project_template(
        &self,
        raw: RawTemplateRow,
        detail: TemplateDetailMode,
    ) -> N8nResult<TemplateCatalogEntry> {
        let archetype = derive_pattern_archetype(&raw.slug, &raw.category);
        let (sanitized_wf, placeholders, node_stubs) = self.sanitize_and_bind_template_workflow(
            &raw.workflow_json,
            &raw.required_credentials,
            detail,
        )?;

        let connections = match detail {
            TemplateDetailMode::NodesOnly => None,
            TemplateDetailMode::Structure | TemplateDetailMode::Full => {
                sanitized_wf.get("connections").cloned()
            }
        };

        let credential_placeholders = match detail {
            TemplateDetailMode::NodesOnly => None,
            TemplateDetailMode::Structure | TemplateDetailMode::Full => Some(placeholders),
        };

        let workflow = match detail {
            TemplateDetailMode::Full => Some(sanitized_wf),
            TemplateDetailMode::NodesOnly | TemplateDetailMode::Structure => None,
        };

        Ok(TemplateCatalogEntry {
            id: raw.id,
            slug: raw.slug,
            name: raw.name,
            description: raw.description,
            category: raw.category,
            complexity: raw.complexity,
            estimated_setup_minutes: raw.estimated_setup_minutes,
            pattern_archetype: archetype,
            nodes_used: raw.nodes_used,
            required_credentials: raw.required_credentials,
            source_attribution: raw.source_attribution,
            nodes: node_stubs,
            connections,
            credential_placeholders,
            workflow,
        })
    }

    fn sanitize_and_bind_template_workflow(
        &self,
        raw_workflow: &Value,
        required_credentials: &[String],
        detail: TemplateDetailMode,
    ) -> N8nResult<(Value, Vec<CredentialPlaceholder>, Vec<TemplateNodeStub>)> {
        let req_cred_set: BTreeSet<&str> =
            required_credentials.iter().map(String::as_str).collect();
        let mut wf_obj = raw_workflow.as_object().cloned().unwrap_or_default();

        let mut bound_by_cred: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for c in required_credentials {
            bound_by_cred.entry(c.clone()).or_default();
        }

        let mut stubs = Vec::new();
        let mut sanitized_nodes = Vec::new();

        if let Some(nodes_arr) = wf_obj.get("nodes").and_then(Value::as_array) {
            for node_val in nodes_arr {
                let Some(mut node_obj) = node_val.as_object().cloned() else {
                    continue;
                };
                let id = node_obj
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let name = node_obj
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let node_type = node_obj
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let type_version = node_obj
                    .get("typeVersion")
                    .cloned()
                    .unwrap_or_else(|| json!(1));
                let position = if detail == TemplateDetailMode::NodesOnly {
                    None
                } else {
                    node_obj
                        .get("position")
                        .and_then(Value::as_array)
                        .map(|arr| arr.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
                };

                stubs.push(TemplateNodeStub {
                    id,
                    name: name.clone(),
                    node_type: node_type.clone(),
                    type_version: type_version.clone(),
                    position,
                });

                // Sanitize parameters recursively so zero raw secrets can ever exit `templates.rs`.
                if let Some(params_val) = node_obj.get("parameters") {
                    let clean_params = sanitize_template_json_value(params_val, 0);
                    node_obj.insert("parameters".to_owned(), clean_params);
                }

                // Inject deterministic credential-reference placeholders (ID + label only, zero secrets).
                let matching_creds = self.resolve_node_template_credentials(
                    &node_type,
                    &type_version,
                    node_obj.get("parameters"),
                    &req_cred_set,
                )?;

                if !matching_creds.is_empty() {
                    let mut cred_map = node_obj
                        .get("credentials")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();

                    for cred_type in matching_creds {
                        bound_by_cred
                            .entry(cred_type.clone())
                            .or_default()
                            .push(name.clone());

                        let placeholder_id = format!("{{{{CREDENTIAL_ID:{cred_type}}}}}");
                        let placeholder_name = format!(
                            "Placeholder: {cred_type} (bind credential reference before activation)"
                        );
                        cred_map.insert(
                            cred_type,
                            json!({
                                "id": placeholder_id,
                                "name": placeholder_name,
                            }),
                        );
                    }
                    node_obj.insert("credentials".to_owned(), Value::Object(cred_map));
                } else if let Some(existing_creds) =
                    node_obj.get("credentials").and_then(Value::as_object)
                {
                    let mut scrubbed_creds = Map::new();
                    for (ctype, _val) in existing_creds {
                        let safe_ctype = redact_str(ctype);
                        scrubbed_creds.insert(
                            safe_ctype.clone(),
                            json!({
                                "id": format!("{{{{CREDENTIAL_ID:{safe_ctype}}}}}"),
                                "name": format!("Placeholder: {safe_ctype} (bind credential reference before activation)"),
                            }),
                        );
                    }
                    node_obj.insert("credentials".to_owned(), Value::Object(scrubbed_creds));
                }

                sanitized_nodes.push(Value::Object(node_obj));
            }
        }

        wf_obj.insert("nodes".to_owned(), Value::Array(sanitized_nodes));
        if let Some(conns) = wf_obj.get("connections") {
            wf_obj.insert(
                "connections".to_owned(),
                sanitize_template_json_value(conns, 0),
            );
        }

        let mut placeholders = Vec::with_capacity(bound_by_cred.len());
        for (cred_type, bound_nodes) in bound_by_cred {
            let display_label = self
                .get_credential_type(&cred_type)?
                .map_or_else(|| cred_type.clone(), |c| c.display_name);
            placeholders.push(CredentialPlaceholder {
                placeholder_id: format!("{{{{CREDENTIAL_ID:{cred_type}}}}}"),
                placeholder_name: format!(
                    "Placeholder: {display_label} (bind credential reference before activation)"
                ),
                credential_type: cred_type,
                bound_nodes,
            });
        }

        Ok((Value::Object(wf_obj), placeholders, stubs))
    }

    fn resolve_node_template_credentials(
        &self,
        node_type: &str,
        type_version: &Value,
        params_opt: Option<&Value>,
        template_req_creds: &BTreeSet<&str>,
    ) -> N8nResult<Vec<String>> {
        if template_req_creds.is_empty() || node_type.is_empty() {
            return Ok(Vec::new());
        }

        let ver_str = match type_version {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        };
        let ver_opt = if ver_str.is_empty() {
            None
        } else {
            Some(ver_str.as_str())
        };
        let fallback_params = json!({});
        let params_ref = params_opt.unwrap_or(&fallback_params);

        let inspection = self.inspect_effective_node_fields(node_type, ver_opt, params_ref)?;
        if inspection.all_declared_credentials.is_empty() {
            return Ok(Vec::new());
        }

        let mut matched: Vec<String> = inspection
            .allowed_credentials
            .iter()
            .filter(|c| template_req_creds.contains(c.credential_type.as_str()))
            .map(|c| c.credential_type.clone())
            .collect();

        if matched.is_empty() && inspection.all_declared_credentials.len() == 1 {
            let single = &inspection.all_declared_credentials[0].credential_type;
            if template_req_creds.contains(single.as_str()) {
                matched.push(single.clone());
            }
        }

        Ok(matched)
    }
}

fn map_raw_template_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTemplateRow> {
    let mins_i64: i64 = row.get(6)?;
    let nodes_used_str: String = row.get(7)?;
    let creds_str: String = row.get(8)?;
    let wf_str: String = row.get(9)?;

    Ok(RawTemplateRow {
        id: row.get(0)?,
        slug: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        category: row.get(4)?,
        complexity: row.get(5)?,
        estimated_setup_minutes: u32::try_from(mins_i64.max(0)).unwrap_or(15),
        nodes_used: serde_json::from_str(&nodes_used_str).unwrap_or_default(),
        required_credentials: serde_json::from_str(&creds_str).unwrap_or_default(),
        workflow_json: serde_json::from_str(&wf_str).unwrap_or_else(|_| json!({})),
        source_attribution: row.get(10)?,
    })
}

fn derive_pattern_archetype(slug: &str, category: &str) -> String {
    if slug.contains("hmac") {
        "webhook_hmac_verified_upsert".to_owned()
    } else if slug.contains("webhook") && slug.contains("ack") {
        "webhook_validation_sync_reply".to_owned()
    } else if slug.contains("rag") || slug.contains("pgvector") {
        "rag_vector_store_agent".to_owned()
    } else if slug.contains("agent") {
        "conversational_tool_agent".to_owned()
    } else if slug.contains("triage") || slug.contains("switch") {
        "structured_llm_switch_router".to_owned()
    } else if slug.contains("loop") || slug.contains("batch") {
        "rate_limited_batch_loop".to_owned()
    } else if slug.contains("error") {
        "centralized_error_incident_fanout".to_owned()
    } else if slug.contains("delta") || slug.contains("sync") {
        "dataset_delta_reconciliation".to_owned()
    } else if slug.contains("subworkflow") {
        "modular_subworkflow_service".to_owned()
    } else if slug.contains("idempotency") || slug.contains("redis") {
        "distributed_idempotency_guard".to_owned()
    } else if slug.contains("ollama") {
        "local_privacy_llm_pipeline".to_owned()
    } else {
        category
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_owned()
    }
}

fn sanitize_template_json_value(value: &Value, depth: usize) -> Value {
    if depth >= 64 {
        return Value::String("[REDACTED:MAX_DEPTH]".to_owned());
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(s) => Value::String(redact_str(s)),
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| sanitize_template_json_value(v, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive_key(k) {
                    let safe_val = match v {
                        Value::Null => Value::Null,
                        Value::Bool(b) => Value::Bool(*b),
                        Value::String(s)
                            if (s.starts_with("={{ $vars.") || s.starts_with("={{ $json."))
                                && redact_str(s) == *s =>
                        {
                            // Preserve safe non-secret `$vars` / `$json` expression placeholders.
                            Value::String(s.clone())
                        }
                        _ => Value::String(
                            "{{PLACEHOLDER:CONFIGURE_SECRET_VIA_N8N_CREDENTIALS}}".to_owned(),
                        ),
                    };
                    out.insert(k.clone(), safe_val);
                } else {
                    out.insert(k.clone(), sanitize_template_json_value(v, depth + 1));
                }
            }
            Value::Object(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn open_real_catalog() -> CatalogDb {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        CatalogDb::open_default_workspace_bundle(&root).expect("load real catalog bundle")
    }

    #[test]
    fn searches_templates_across_all_five_modes_and_three_detail_projections() {
        let db = open_real_catalog();

        let summaries = db.list_template_summaries().expect("summaries");
        assert_eq!(summaries.len(), 16);

        // 1. Keyword search (`nodes_only`)
        let kw = db
            .search_templates(&TemplateSearchQuery {
                mode: TemplateSearchMode::Keyword,
                query: Some("qdrant rag".to_owned()),
                detail: TemplateDetailMode::NodesOnly,
                ..TemplateSearchQuery::default()
            })
            .expect("keyword search");
        assert!(!kw.templates.is_empty());
        assert_eq!(kw.templates[0].slug, "rag-qdrant-knowledge-assistant");
        assert!(kw.templates[0].connections.is_none());
        assert!(kw.templates[0].workflow.is_none());
        assert!(kw.templates[0].nodes[0].position.is_none());

        // 2. ByNodes search (`structure`)
        let by_nodes = db
            .search_templates(&TemplateSearchQuery {
                mode: TemplateSearchMode::ByNodes,
                node_types: vec![
                    "n8n-nodes-base.compareDatasets".to_owned(),
                    "googleSheets".to_owned(),
                ],
                match_all_nodes: true,
                detail: TemplateDetailMode::Structure,
                ..TemplateSearchQuery::default()
            })
            .expect("by_nodes search");
        assert_eq!(by_nodes.total_returned, 1);
        assert_eq!(
            by_nodes.templates[0].slug,
            "database-to-google-sheets-delta-sync"
        );
        assert!(by_nodes.templates[0].connections.is_some());
        assert!(by_nodes.templates[0].credential_placeholders.is_some());
        assert!(by_nodes.templates[0].workflow.is_none());

        // 3. ByTask search (`full` with credential placeholders & zero secrets)
        let by_task = db
            .search_templates(&TemplateSearchQuery {
                mode: TemplateSearchMode::ByTask,
                task: Some("error_handling".to_owned()),
                detail: TemplateDetailMode::Full,
                ..TemplateSearchQuery::default()
            })
            .expect("by_task search");
        assert!(
            by_task
                .templates
                .iter()
                .any(|t| t.slug == "centralized-error-incident-router")
        );

        // 4. ByMetadata search
        let by_meta = db
            .search_templates(&TemplateSearchQuery {
                mode: TemplateSearchMode::ByMetadata,
                complexity: Some("beginner".to_owned()),
                requires_no_credentials: Some(true),
                detail: TemplateDetailMode::Structure,
                ..TemplateSearchQuery::default()
            })
            .expect("by_metadata search");
        assert_eq!(by_meta.total_returned, 1);
        assert_eq!(
            by_meta.templates[0].slug,
            "subworkflow-modular-datatable-audit-service"
        );

        // 5. Patterns mode
        let patterns = db
            .search_templates(&TemplateSearchQuery {
                mode: TemplateSearchMode::Patterns,
                query: Some("rate_limited_batch_loop".to_owned()),
                detail: TemplateDetailMode::NodesOnly,
                ..TemplateSearchQuery::default()
            })
            .expect("patterns search");
        assert_eq!(patterns.total_returned, 1);
        assert_eq!(
            patterns.templates[0].slug,
            "batch-rate-limited-crm-enrichment-loop"
        );
    }

    #[test]
    fn full_template_projection_injects_credential_placeholders_and_contains_zero_secrets() {
        let db = open_real_catalog();

        let tmpl = db
            .get_template(
                "scheduled-api-dedupe-slack-digest",
                TemplateDetailMode::Full,
            )
            .expect("get_template")
            .expect("template exists");

        let placeholders = tmpl
            .credential_placeholders
            .expect("credential_placeholders present");
        assert_eq!(placeholders.len(), 2);
        assert!(
            placeholders
                .iter()
                .any(|p| p.credential_type == "httpHeaderAuth"
                    && p.placeholder_id == "{{CREDENTIAL_ID:httpHeaderAuth}}"
                    && p.bound_nodes.contains(&"Fetch Feed".to_owned()))
        );
        assert!(placeholders.iter().any(|p| p.credential_type == "slackApi"
            && p.placeholder_id == "{{CREDENTIAL_ID:slackApi}}"
            && p.bound_nodes.contains(&"Post Slack Digest".to_owned())));

        let wf = tmpl.workflow.expect("full workflow JSON present");
        let serialized = serde_json::to_string(&wf).expect("serialize workflow");
        assert!(serialized.contains("{{CREDENTIAL_ID:httpHeaderAuth}}"));
        assert!(serialized.contains("{{CREDENTIAL_ID:slackApi}}"));
        assert!(!serialized.contains("sk-"));
        assert!(!serialized.contains("n8n_api_"));
        assert!(!serialized.contains("eyJ"));
    }

    #[test]
    fn scrubs_synthetic_secrets_injected_into_custom_in_memory_template() {
        let db = CatalogDb::open_in_memory().expect("open in-memory");
        let dirty_wf = json!({
            "name": "Dirty Fixture",
            "nodes": [
                {
                    "id": "n1",
                    "name": "Call API",
                    "type": "n8n-nodes-base.httpRequest",
                    "typeVersion": 4.2,
                    "position": [100, 200],
                    "parameters": {
                        "url": "https://api.example.com/data?api_key=super_secret_12345",
                        "apiKey": concat!("sk", "-live-1234567890abcdefghijklmnop"),
                        "secret": "={{ $vars.SAFE_VAR_REF }}"
                    },
                    "credentials": {
                        "httpHeaderAuth": {
                            "id": "real_secret_id",
                            "name": "Bearer secret_token_value_123456"
                        }
                    }
                }
            ],
            "connections": {}
        });

        db.connection()
            .execute(
                "INSERT INTO templates (
                    id, slug, name, description, category, complexity,
                    estimated_setup_minutes, nodes_used_json, required_credentials_json,
                    workflow_json, source_attribution
                ) VALUES (99, 'dirty-test', 'Dirty Test', 'Desc', 'Testing', 'beginner', 5, '[\"n8n-nodes-base.httpRequest\"]', '[]', ?1, 'unit-test');",
                rusqlite::params![dirty_wf.to_string()],
            )
            .expect("insert custom template");

        let projected = db
            .get_template("99", TemplateDetailMode::Full)
            .expect("get_template")
            .expect("present");
        let dumped = serde_json::to_string(&projected).expect("serialize");

        assert!(!dumped.contains("super_secret_12345"));
        assert!(!dumped.contains(concat!("sk", "-live-1234567890abcdefghijklmnop")));
        assert!(!dumped.contains("secret_token_value_123456"));
        assert!(dumped.contains("{{PLACEHOLDER:CONFIGURE_SECRET_VIA_N8N_CREDENTIALS}}"));
        assert!(dumped.contains("={{ $vars.SAFE_VAR_REF }}"));
        assert!(dumped.contains("{{CREDENTIAL_ID:httpHeaderAuth}}"));
    }
}
