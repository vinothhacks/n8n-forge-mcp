//! `rusqlite` (WAL + FTS5) sanitized live workflow & node metadata index partitioned by
//! `(principal_id, instance_id, project_id, workflow_id, version_hash)` with zero plaintext
//! parameter JSON persisted by default, partition revocation, and ephemeral in-memory parameter scanning.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use chrono::{DateTime, Duration, Utc};
use n8n_graph::{
    PortKind, WorkflowIr, WorkflowNodeIr, is_any_trigger_type, is_canvas_annotation_type,
};
use n8n_types::{N8nError, N8nResult, redact_str};
use regex::{Regex, RegexBuilder};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_json_path::JsonPath;

use crate::acl::protect_state_file;

/// Default TTL for cached sanitized workflow metadata (15 minutes).
pub const DEFAULT_INDEX_TTL_SECS: i64 = 15 * 60;

/// Maximum compiled regex size for ephemeral in-memory parameter scans (256 KiB).
const MAX_EPHEMERAL_REGEX_SIZE: usize = 256 * 1024;

static LITERAL_DOLLAR_NODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\$\(\s*|\$node\[\s*|\$items\(\s*)(?:'([^'\\]+)'|"([^"\\]+)"|`([^`$\\]+)`)\s*(?:\)|\]|,)"#,
    )
    .expect("valid static node ref regex")
});

static VARIABLE_REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\$(?:vars|env)(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*\])"#,
    )
    .expect("valid static variable ref regex")
});

/// Persistence policy governing what workflow metadata may be written to the local index (V2 Section 7 & 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    /// Default: persists ONLY sanitized structural/node/reference/health metadata; ZERO plaintext parameter JSON.
    #[default]
    MetadataOnly,
    /// Strict sensitivity mode (`no_persistent_payload`): writes nothing to SQLite and purges any prior cached partition.
    NoPersistentPayload,
}

/// Distinguishes editable draft vs live published workflow graphs (`graph=draft|published`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GraphVariant {
    #[default]
    Draft,
    Published,
}

impl GraphVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Self {
        if raw.eq_ignore_ascii_case("published") {
            Self::Published
        } else {
            Self::Draft
        }
    }
}

/// Multi-tenant & version-bound partition descriptor for indexing a workflow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexWorkflowMetadata {
    pub principal_id: String,
    pub instance_id: String,
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub graph: GraphVariant,
    #[serde(default)]
    pub recent_failure_count: u32,
    #[serde(default)]
    pub cache_policy: CachePolicy,
    /// Optional TTL in seconds (defaults to [`DEFAULT_INDEX_TTL_SECS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
    /// Optional catalog map of `node_type -> latest_type_version` used to compute `stale_type_version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_catalog_versions: Option<HashMap<String, f64>>,
}

/// Summary returned after indexing (or skipping under `NoPersistentPayload`) a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedPartitionReceipt {
    pub persisted: bool,
    pub workflow_id: String,
    pub version_hash: String,
    pub indexed_node_count: usize,
    pub cache_policy: CachePolicy,
}

/// Query contract for Tool #6 `n8n_find_nodes` implementing all V2 Section 7 search operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindNodesQuery {
    pub principal_id: String,
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Optional live allowlist of project IDs the caller is currently authorized to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_project_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub active_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphVariant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses_variable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_type_version: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_error_handler: Option<bool>,
    /// Matches workflows/nodes with `recent_failure_count >= n` (or `== 0` when `Some(0)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_failure_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

const fn default_max_results() -> usize {
    50
}

impl FindNodesQuery {
    #[must_use]
    pub fn new(principal_id: impl Into<String>, instance_id: impl Into<String>) -> Self {
        Self {
            principal_id: principal_id.into(),
            instance_id: instance_id.into(),
            workflow_id: None,
            project_id: None,
            allowed_project_ids: None,
            folder_id: None,
            active_only: false,
            graph: None,
            node_type: None,
            name_pattern: None,
            disabled: None,
            references_node: None,
            uses_variable: None,
            credential_type: None,
            stale_type_version: None,
            missing_error_handler: None,
            recent_failure_count: None,
            page_token: None,
            max_results: default_max_results(),
        }
    }
}

/// Sanitized node search hit (guaranteed free of parameter JSON or secret material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedNodeHit {
    pub project_id: String,
    pub folder_id: Option<String>,
    pub workflow_id: String,
    pub workflow_name: String,
    pub graph: GraphVariant,
    pub active: bool,
    pub version_hash: String,
    pub node_id: String,
    pub node_name: String,
    pub node_type: String,
    pub type_version: String,
    pub disabled: bool,
    pub retry_on_fail: bool,
    pub missing_error_handler: bool,
    pub stale_type_version: bool,
    pub recent_failure_count: u32,
    pub referenced_nodes: Vec<String>,
    pub used_variables: Vec<String>,
    pub credential_types: Vec<String>,
}

/// Paginated response returned by [`SanitizedWorkflowIndex::find_nodes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindNodesPage {
    pub hits: Vec<IndexedNodeHit>,
    pub next_page_token: Option<String>,
}

/// Safe predicate evaluated in-memory by [`ephemeral_scan_parameters`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParamPredicate {
    Exists,
    Equals {
        expected: Value,
    },
    ContainsSubstring {
        substring: String,
        #[serde(default)]
        case_insensitive: bool,
    },
    MatchesRegex {
        pattern: String,
    },
}

/// Sanitized result of [`ephemeral_scan_parameters`]: ONLY `(node_id, node_name, matched_field_path)` —
/// raw parameter values are NEVER persisted or echoed!
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralParamMatch {
    pub node_id: String,
    pub node_name: String,
    pub matched_field_path: String,
}

impl EphemeralParamMatch {
    #[must_use]
    pub fn as_tuple(&self) -> (&str, &str, &str) {
        (&self.node_id, &self.node_name, &self.matched_field_path)
    }
}

/// `rusqlite` WAL + FTS5 sanitized live workflow & node index.
pub struct SanitizedWorkflowIndex {
    conn: Connection,
}

impl SanitizedWorkflowIndex {
    /// Opens an in-memory SQLite FTS5 index with full schema & cascade triggers initialized.
    pub fn open_in_memory() -> N8nResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| N8nError::config(format!("failed opening sanitized index: {e}")))?;
        let index = Self { conn };
        index.init_schema()?;
        Ok(index)
    }

    /// Opens a persistent SQLite WAL + FTS5 index file and enforces current-user-only OS ACLs (`0600` / `icacls`).
    pub fn open_file(db_path: &Path) -> N8nResult<Self> {
        if let Some(parent) = db_path.parent() {
            crate::acl::protect_state_dir(parent)?;
        }
        let conn = Connection::open(db_path)
            .map_err(|e| N8nError::config(format!("failed opening state index file: {e}")))?;
        let _ = protect_state_file(db_path)?;
        let index = Self { conn };
        index.init_schema()?;
        Ok(index)
    }

    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    fn init_schema(&self) -> N8nResult<()> {
        self.conn
            .execute_batch(
                r"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;
                PRAGMA secure_delete = ON;

                CREATE TABLE IF NOT EXISTS indexed_workflows (
                    partition_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    principal_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    folder_id TEXT,
                    workflow_id TEXT NOT NULL,
                    graph_variant TEXT NOT NULL,
                    version_hash TEXT NOT NULL,
                    workflow_name TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    is_archived INTEGER NOT NULL,
                    version_id TEXT,
                    active_version_id TEXT,
                    topology_json TEXT NOT NULL,
                    recent_failure_count INTEGER NOT NULL DEFAULT 0,
                    indexed_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    UNIQUE(principal_id, instance_id, project_id, workflow_id, graph_variant)
                );

                CREATE INDEX IF NOT EXISTS idx_wf_lookup
                    ON indexed_workflows(principal_id, instance_id, project_id, workflow_id);

                CREATE TABLE IF NOT EXISTS indexed_nodes (
                    node_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    partition_row_id INTEGER NOT NULL REFERENCES indexed_workflows(partition_row_id) ON DELETE CASCADE,
                    node_id TEXT NOT NULL,
                    node_name TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    type_version_str TEXT NOT NULL,
                    type_version_num REAL,
                    disabled INTEGER NOT NULL,
                    retry_on_fail INTEGER NOT NULL,
                    has_error_handler INTEGER NOT NULL,
                    missing_error_handler INTEGER NOT NULL,
                    stale_type_version INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_nodes_partition
                    ON indexed_nodes(partition_row_id);
                CREATE INDEX IF NOT EXISTS idx_nodes_type
                    ON indexed_nodes(node_type);

                CREATE TABLE IF NOT EXISTS indexed_node_references (
                    node_row_id INTEGER NOT NULL REFERENCES indexed_nodes(node_row_id) ON DELETE CASCADE,
                    ref_node_name TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_node_refs_target
                    ON indexed_node_references(ref_node_name, node_row_id);

                CREATE TABLE IF NOT EXISTS indexed_node_variables (
                    node_row_id INTEGER NOT NULL REFERENCES indexed_nodes(node_row_id) ON DELETE CASCADE,
                    variable_name TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_node_vars_name
                    ON indexed_node_variables(variable_name, node_row_id);

                CREATE TABLE IF NOT EXISTS indexed_node_credentials (
                    node_row_id INTEGER NOT NULL REFERENCES indexed_nodes(node_row_id) ON DELETE CASCADE,
                    credential_type TEXT NOT NULL,
                    credential_ref_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_node_creds_type
                    ON indexed_node_credentials(credential_type, node_row_id);

                CREATE VIRTUAL TABLE IF NOT EXISTS indexed_nodes_fts USING fts5(
                    node_name,
                    node_type,
                    workflow_name,
                    tokenize = 'unicode61'
                );

                CREATE TRIGGER IF NOT EXISTS trg_indexed_nodes_ad
                AFTER DELETE ON indexed_nodes
                BEGIN
                    DELETE FROM indexed_nodes_fts WHERE rowid = old.node_row_id;
                END;
                ",
            )
            .map_err(|e| N8nError::config(format!("failed initializing sanitized FTS5 index schema: {e}")))
    }

    /// Indexes a [`WorkflowIr`] under the specified partition metadata.
    /// Never persists raw `parameters` JSON; under [`CachePolicy::NoPersistentPayload`], clears any cached entry and writes nothing.
    pub fn index_workflow(
        &mut self,
        ir: &WorkflowIr,
        meta: &IndexWorkflowMetadata,
    ) -> N8nResult<IndexedPartitionReceipt> {
        self.index_workflow_at(ir, meta, Utc::now())
    }

    pub fn index_workflow_at(
        &mut self,
        ir: &WorkflowIr,
        meta: &IndexWorkflowMetadata,
        now: DateTime<Utc>,
    ) -> N8nResult<IndexedPartitionReceipt> {
        let wf_id = ir
            .id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                N8nError::validation(
                    &meta.instance_id,
                    vec!["workflow `id` is required for live index partitioning".to_owned()],
                    "cannot index workflow without `id`",
                )
            })?
            .to_owned();

        let version_hash = ir.canonical_version_hash();

        if meta.cache_policy == CachePolicy::NoPersistentPayload {
            self.conn
                .execute(
                    "DELETE FROM indexed_workflows
                     WHERE principal_id = ?1 AND instance_id = ?2 AND project_id = ?3 AND workflow_id = ?4 AND graph_variant = ?5",
                    params![
                        meta.principal_id,
                        meta.instance_id,
                        meta.project_id,
                        wf_id,
                        meta.graph.as_str()
                    ],
                )
                .map_err(|e| N8nError::protocol(format!("failed clearing NoPersistentPayload partition: {e}")))?;

            return Ok(IndexedPartitionReceipt {
                persisted: false,
                workflow_id: wf_id,
                version_hash,
                indexed_node_count: 0,
                cache_policy: CachePolicy::NoPersistentPayload,
            });
        }

        let ttl_secs = meta.ttl_secs.unwrap_or(DEFAULT_INDEX_TTL_SECS).max(1);
        let indexed_at_ms = now.timestamp_millis();
        let expires_at_ms = (now + Duration::seconds(ttl_secs)).timestamp_millis();
        let safe_wf_name = redact_str(&ir.name);
        let safe_topology = build_safe_topology_json(ir);
        let topology_str =
            serde_json::to_string(&safe_topology).unwrap_or_else(|_| "{}".to_owned());

        let workflow_has_global_error_handler = ir
            .settings
            .get("errorWorkflow")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
            || ir
                .nodes
                .iter()
                .any(|n| !n.disabled && n8n_graph::is_error_trigger_type(&n.node_type));

        let tx = self
            .conn
            .transaction()
            .map_err(|e| N8nError::protocol(format!("index transaction begin error: {e}")))?;

        tx.execute(
            "DELETE FROM indexed_workflows
             WHERE principal_id = ?1 AND instance_id = ?2 AND project_id = ?3 AND workflow_id = ?4 AND graph_variant = ?5",
            params![
                meta.principal_id,
                meta.instance_id,
                meta.project_id,
                wf_id,
                meta.graph.as_str()
            ],
        )
        .map_err(|e| N8nError::protocol(format!("index replace cleanup error: {e}")))?;

        tx.execute(
            "INSERT INTO indexed_workflows (
                principal_id, instance_id, project_id, folder_id, workflow_id, graph_variant,
                version_hash, workflow_name, active, is_archived, version_id, active_version_id,
                topology_json, recent_failure_count, indexed_at_ms, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                meta.principal_id,
                meta.instance_id,
                meta.project_id,
                meta.folder_id,
                wf_id,
                meta.graph.as_str(),
                version_hash,
                safe_wf_name,
                i32::from(ir.active),
                i32::from(ir.is_archived.unwrap_or(false)),
                ir.version_id,
                ir.active_version_id,
                topology_str,
                meta.recent_failure_count,
                indexed_at_ms,
                expires_at_ms,
            ],
        )
        .map_err(|e| N8nError::protocol(format!("index workflow insert error: {e}")))?;

        let partition_row_id = tx.last_insert_rowid();

        for node in &ir.nodes {
            let safe_node_name = redact_str(&node.name);
            let safe_node_id = redact_str(&node.id);
            let ver_str = node.type_version_string();
            let ver_num = node.type_version_f64();

            let has_outgoing_error_edge = ir
                .connections
                .get(&node.name)
                .and_then(|pm| pm.get(&PortKind::Error))
                .is_some_and(|branches| branches.iter().any(|b| !b.is_empty()));

            let has_error_handler = node.has_local_error_handling()
                || has_outgoing_error_edge
                || workflow_has_global_error_handler;
            let missing_error_handler =
                is_fallible_external_node(&node.node_type) && !has_error_handler;

            let stale_type_version = match (&meta.latest_catalog_versions, ver_num) {
                (Some(latest_map), Some(cur_v)) => latest_map
                    .get(&node.node_type)
                    .is_some_and(|&latest_v| cur_v + f64::EPSILON < latest_v),
                _ => false,
            };

            tx.execute(
                "INSERT INTO indexed_nodes (
                    partition_row_id, node_id, node_name, node_type, type_version_str,
                    type_version_num, disabled, retry_on_fail, has_error_handler,
                    missing_error_handler, stale_type_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    partition_row_id,
                    safe_node_id,
                    safe_node_name,
                    node.node_type,
                    ver_str,
                    ver_num,
                    i32::from(node.disabled),
                    i32::from(node.retry_on_fail.unwrap_or(false)),
                    i32::from(has_error_handler),
                    i32::from(missing_error_handler),
                    i32::from(stale_type_version),
                ],
            )
            .map_err(|e| N8nError::protocol(format!("index node insert error: {e}")))?;

            let node_row_id = tx.last_insert_rowid();

            tx.execute(
                "INSERT INTO indexed_nodes_fts(rowid, node_name, node_type, workflow_name)
                 VALUES (?1, ?2, ?3, ?4)",
                params![node_row_id, safe_node_name, node.node_type, safe_wf_name],
            )
            .map_err(|e| N8nError::protocol(format!("FTS5 insert error: {e}")))?;

            let (ref_nodes, used_vars) = extract_safe_expression_refs(node);
            for ref_node in ref_nodes {
                tx.execute(
                    "INSERT INTO indexed_node_references(node_row_id, ref_node_name) VALUES (?1, ?2)",
                    params![node_row_id, redact_str(&ref_node)],
                )
                .map_err(|e| N8nError::protocol(format!("node reference insert error: {e}")))?;
            }

            for var_name in used_vars {
                tx.execute(
                    "INSERT INTO indexed_node_variables(node_row_id, variable_name) VALUES (?1, ?2)",
                    params![node_row_id, redact_str(&var_name)],
                )
                .map_err(|e| N8nError::protocol(format!("node variable insert error: {e}")))?;
            }

            if let Some(ref creds) = node.credentials {
                for (cred_type, cred_ref) in creds {
                    let ref_hash = hash_credential_reference(
                        cred_type,
                        cred_ref.id.as_deref().unwrap_or(""),
                        &cred_ref.name,
                    );
                    tx.execute(
                        "INSERT INTO indexed_node_credentials(node_row_id, credential_type, credential_ref_hash)
                         VALUES (?1, ?2, ?3)",
                        params![node_row_id, redact_str(cred_type), ref_hash],
                    )
                    .map_err(|e| N8nError::protocol(format!("node credential ref insert error: {e}")))?;
                }
            }
        }

        tx.commit()
            .map_err(|e| N8nError::protocol(format!("index transaction commit error: {e}")))?;

        Ok(IndexedPartitionReceipt {
            persisted: true,
            workflow_id: wf_id,
            version_hash,
            indexed_node_count: ir.nodes.len(),
            cache_policy: CachePolicy::MetadataOnly,
        })
    }

    /// Executes a multi-operator sanitized node search strictly isolated to `(principal_id, instance_id)`.
    pub fn find_nodes(&self, query: &FindNodesQuery) -> N8nResult<FindNodesPage> {
        self.find_nodes_at(query, Utc::now())
    }

    #[allow(clippy::too_many_lines)]
    pub fn find_nodes_at(
        &self,
        query: &FindNodesQuery,
        now: DateTime<Utc>,
    ) -> N8nResult<FindNodesPage> {
        if let Some(ref allowed) = query.allowed_project_ids
            && allowed.is_empty()
        {
            return Ok(FindNodesPage {
                hits: Vec::new(),
                next_page_token: None,
            });
        }

        let clamped_limit = query.max_results.clamp(1, 200);
        let cursor_row_id = parse_page_cursor(query.page_token.as_deref())?;

        let mut sql = String::from(
            "SELECT
                n.node_row_id,
                w.project_id,
                w.folder_id,
                w.workflow_id,
                w.workflow_name,
                w.graph_variant,
                w.active,
                w.version_hash,
                n.node_id,
                n.node_name,
                n.node_type,
                n.type_version_str,
                n.disabled,
                n.retry_on_fail,
                n.missing_error_handler,
                n.stale_type_version,
                w.recent_failure_count
             FROM indexed_nodes n
             INNER JOIN indexed_workflows w ON w.partition_row_id = n.partition_row_id
             WHERE w.principal_id = ?
               AND w.instance_id = ?
               AND w.expires_at_ms >= ?",
        );

        let mut bind_values: Vec<SqlValue> = vec![
            SqlValue::Text(query.principal_id.clone()),
            SqlValue::Text(query.instance_id.clone()),
            SqlValue::Integer(now.timestamp_millis()),
        ];

        if let Some(cursor_id) = cursor_row_id {
            sql.push_str(" AND n.node_row_id > ?");
            bind_values.push(SqlValue::Integer(cursor_id));
        }

        if let Some(ref wf_id) = query.workflow_id {
            sql.push_str(" AND w.workflow_id = ?");
            bind_values.push(SqlValue::Text(wf_id.clone()));
        }

        if let Some(ref proj_id) = query.project_id {
            sql.push_str(" AND w.project_id = ?");
            bind_values.push(SqlValue::Text(proj_id.clone()));
        }

        if let Some(ref allowed_projs) = query.allowed_project_ids {
            let placeholders = std::iter::repeat_n("?", allowed_projs.len())
                .collect::<Vec<_>>()
                .join(", ");
            sql.push_str(&format!(" AND w.project_id IN ({placeholders})"));
            for p in allowed_projs {
                bind_values.push(SqlValue::Text(p.clone()));
            }
        }

        if let Some(ref folder) = query.folder_id {
            sql.push_str(" AND w.folder_id = ?");
            bind_values.push(SqlValue::Text(folder.clone()));
        }

        if query.active_only {
            sql.push_str(" AND w.active = 1");
        }

        if let Some(g) = query.graph {
            sql.push_str(" AND w.graph_variant = ?");
            bind_values.push(SqlValue::Text(g.as_str().to_owned()));
        }

        if let Some(ref nt) = query.node_type {
            let lower_nt = nt.to_ascii_lowercase();
            sql.push_str(" AND (LOWER(n.node_type) = ? OR LOWER(n.node_type) LIKE ? ESCAPE '\\')");
            bind_values.push(SqlValue::Text(lower_nt.clone()));
            bind_values.push(SqlValue::Text(format!("%.{}", escape_sql_like(&lower_nt))));
        }

        if let Some(ref pat) = query.name_pattern {
            let trimmed = pat.trim();
            if !trimmed.is_empty() {
                if trimmed.contains('%') || trimmed.contains('*') {
                    let like_pat = trimmed.replace('*', "%").to_ascii_lowercase();
                    sql.push_str(" AND LOWER(n.node_name) LIKE ?");
                    bind_values.push(SqlValue::Text(like_pat));
                } else if let Some(fts_expr) = build_fts5_prefix_query(trimmed) {
                    let sub_like = format!("%{}%", escape_sql_like(&trimmed.to_ascii_lowercase()));
                    sql.push_str(
                        " AND (n.node_row_id IN (SELECT rowid FROM indexed_nodes_fts WHERE indexed_nodes_fts MATCH ?) OR LOWER(n.node_name) LIKE ? ESCAPE '\\')",
                    );
                    bind_values.push(SqlValue::Text(fts_expr));
                    bind_values.push(SqlValue::Text(sub_like));
                } else {
                    let sub_like = format!("%{}%", escape_sql_like(&trimmed.to_ascii_lowercase()));
                    sql.push_str(" AND LOWER(n.node_name) LIKE ? ESCAPE '\\'");
                    bind_values.push(SqlValue::Text(sub_like));
                }
            }
        }

        if let Some(dis) = query.disabled {
            sql.push_str(" AND n.disabled = ?");
            bind_values.push(SqlValue::Integer(i64::from(dis)));
        }

        if let Some(ref ref_node) = query.references_node {
            sql.push_str(
                " AND EXISTS (SELECT 1 FROM indexed_node_references r WHERE r.node_row_id = n.node_row_id AND r.ref_node_name = ?)",
            );
            bind_values.push(SqlValue::Text(ref_node.clone()));
        }

        if let Some(ref var_name) = query.uses_variable {
            sql.push_str(
                " AND EXISTS (SELECT 1 FROM indexed_node_variables v WHERE v.node_row_id = n.node_row_id AND v.variable_name = ?)",
            );
            bind_values.push(SqlValue::Text(var_name.clone()));
        }

        if let Some(ref cred_type) = query.credential_type {
            sql.push_str(
                " AND EXISTS (SELECT 1 FROM indexed_node_credentials c WHERE c.node_row_id = n.node_row_id AND c.credential_type = ?)",
            );
            bind_values.push(SqlValue::Text(cred_type.clone()));
        }

        if let Some(stale) = query.stale_type_version {
            sql.push_str(" AND n.stale_type_version = ?");
            bind_values.push(SqlValue::Integer(i64::from(stale)));
        }

        if let Some(missing_eh) = query.missing_error_handler {
            sql.push_str(" AND n.missing_error_handler = ?");
            bind_values.push(SqlValue::Integer(i64::from(missing_eh)));
        }

        if let Some(fail_cnt) = query.recent_failure_count {
            if fail_cnt == 0 {
                sql.push_str(" AND w.recent_failure_count = 0");
            } else {
                sql.push_str(" AND w.recent_failure_count >= ?");
                bind_values.push(SqlValue::Integer(i64::from(fail_cnt)));
            }
        }

        let fetch_limit = clamped_limit + 1;
        sql.push_str(" ORDER BY n.node_row_id ASC LIMIT ?");
        #[allow(clippy::cast_possible_wrap)]
        bind_values.push(SqlValue::Integer(fetch_limit as i64));

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| N8nError::protocol(format!("index query prepare error: {e}")))?;

        let mut raw_rows = Vec::new();
        let mut rows = stmt
            .query(params_from_iter(bind_values))
            .map_err(|e| N8nError::protocol(format!("index query execution error: {e}")))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| N8nError::protocol(format!("index row step error: {e}")))?
        {
            let node_row_id: i64 = row.get(0).map_err(|e| N8nError::protocol(e.to_string()))?;
            let hit = IndexedNodeHit {
                project_id: row.get(1).map_err(|e| N8nError::protocol(e.to_string()))?,
                folder_id: row.get(2).map_err(|e| N8nError::protocol(e.to_string()))?,
                workflow_id: row.get(3).map_err(|e| N8nError::protocol(e.to_string()))?,
                workflow_name: row.get(4).map_err(|e| N8nError::protocol(e.to_string()))?,
                graph: GraphVariant::from_db_str(
                    &row.get::<_, String>(5)
                        .map_err(|e| N8nError::protocol(e.to_string()))?,
                ),
                active: row
                    .get::<_, i64>(6)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    != 0,
                version_hash: row.get(7).map_err(|e| N8nError::protocol(e.to_string()))?,
                node_id: row.get(8).map_err(|e| N8nError::protocol(e.to_string()))?,
                node_name: row.get(9).map_err(|e| N8nError::protocol(e.to_string()))?,
                node_type: row.get(10).map_err(|e| N8nError::protocol(e.to_string()))?,
                type_version: row.get(11).map_err(|e| N8nError::protocol(e.to_string()))?,
                disabled: row
                    .get::<_, i64>(12)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    != 0,
                retry_on_fail: row
                    .get::<_, i64>(13)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    != 0,
                missing_error_handler: row
                    .get::<_, i64>(14)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    != 0,
                stale_type_version: row
                    .get::<_, i64>(15)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    != 0,
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                recent_failure_count: row
                    .get::<_, i64>(16)
                    .map_err(|e| N8nError::protocol(e.to_string()))?
                    .max(0) as u32,
                referenced_nodes: Vec::new(),
                used_variables: Vec::new(),
                credential_types: Vec::new(),
            };
            raw_rows.push((node_row_id, hit));
        }
        drop(rows);
        drop(stmt);

        let has_more = raw_rows.len() > clamped_limit;
        if has_more {
            raw_rows.truncate(clamped_limit);
        }

        let next_page_token = if has_more {
            raw_rows.last().map(|(row_id, _)| format!("cur_{row_id}"))
        } else {
            None
        };

        let mut hits = Vec::with_capacity(raw_rows.len());
        for (node_row_id, mut hit) in raw_rows {
            hit.referenced_nodes = self.load_child_strings(
                "SELECT ref_node_name FROM indexed_node_references WHERE node_row_id = ?1 ORDER BY ref_node_name ASC",
                node_row_id,
            )?;
            hit.used_variables = self.load_child_strings(
                "SELECT variable_name FROM indexed_node_variables WHERE node_row_id = ?1 ORDER BY variable_name ASC",
                node_row_id,
            )?;
            hit.credential_types = self.load_child_strings(
                "SELECT DISTINCT credential_type FROM indexed_node_credentials WHERE node_row_id = ?1 ORDER BY credential_type ASC",
                node_row_id,
            )?;
            hits.push(hit);
        }

        Ok(FindNodesPage {
            hits,
            next_page_token,
        })
    }

    fn load_child_strings(&self, sql: &str, node_row_id: i64) -> N8nResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| N8nError::protocol(e.to_string()))?;
        let iter = stmt
            .query_map(params![node_row_id], |r| r.get::<_, String>(0))
            .map_err(|e| N8nError::protocol(e.to_string()))?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item.map_err(|e| N8nError::protocol(e.to_string()))?);
        }
        Ok(out)
    }

    /// Immediately purges cached workflow/node/FTS5 entries when a principal or project loses access (V2 Section 7 & U17).
    pub fn revoke_principal_or_project(
        &self,
        principal_id: &str,
        instance_id: Option<&str>,
        project_id: Option<&str>,
    ) -> N8nResult<usize> {
        let deleted = match (instance_id, project_id) {
            (Some(inst), Some(proj)) => self.conn.execute(
                "DELETE FROM indexed_workflows WHERE principal_id = ?1 AND instance_id = ?2 AND project_id = ?3",
                params![principal_id, inst, proj],
            ),
            (Some(inst), None) => self.conn.execute(
                "DELETE FROM indexed_workflows WHERE principal_id = ?1 AND instance_id = ?2",
                params![principal_id, inst],
            ),
            (None, Some(proj)) => self.conn.execute(
                "DELETE FROM indexed_workflows WHERE principal_id = ?1 AND project_id = ?2",
                params![principal_id, proj],
            ),
            (None, None) => self.conn.execute(
                "DELETE FROM indexed_workflows WHERE principal_id = ?1",
                params![principal_id],
            ),
        }
        .map_err(|e| N8nError::protocol(format!("failed purging revoked index partition: {e}")))?;

        Ok(deleted)
    }

    /// Purges all index partitions whose TTL has expired as of `now`.
    pub fn purge_expired(&self, now: DateTime<Utc>) -> N8nResult<usize> {
        self.conn
            .execute(
                "DELETE FROM indexed_workflows WHERE expires_at_ms < ?1",
                params![now.timestamp_millis()],
            )
            .map_err(|e| {
                N8nError::protocol(format!("failed purging expired index partitions: {e}"))
            })
    }

    /// Returns current total row count inside the `indexed_nodes_fts` virtual table (for diagnostics/tests).
    pub fn fts_row_count(&self) -> N8nResult<usize> {
        let cnt: Option<i64> = self
            .conn
            .query_row("SELECT COUNT(*) FROM indexed_nodes_fts", [], |r| r.get(0))
            .optional()
            .map_err(|e| N8nError::protocol(e.to_string()))?;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        Ok(cnt.unwrap_or(0).max(0) as usize)
    }
}

/// Scans an in-memory [`WorkflowIr`] for a parameter path + [`ParamPredicate`] (RFC 6901 JSON Pointer `/a/b`
/// OR `serde_json_path` JSONPath `$.a.b`), returning ONLY `(node_id, node_name, matched_field_path)`
/// without persisting or echoing raw values!
pub fn ephemeral_scan_parameters(
    ir: &WorkflowIr,
    param_path: &str,
    predicate: &ParamPredicate,
) -> N8nResult<Vec<EphemeralParamMatch>> {
    let trimmed_path = param_path.trim();
    if trimmed_path.is_empty() {
        return Err(N8nError::validation(
            "local",
            vec!["`param_path` must not be empty".to_owned()],
            "ephemeral_scan_parameters requires a non-empty RFC 6901 pointer or JSONPath",
        ));
    }

    let compiled_regex = if let ParamPredicate::MatchesRegex { pattern } = predicate {
        Some(
            RegexBuilder::new(pattern)
                .size_limit(MAX_EPHEMERAL_REGEX_SIZE)
                .build()
                .map_err(|e| {
                    N8nError::validation(
                        "local",
                        vec![],
                        format!("invalid or oversized parameter scan regex: {e}"),
                    )
                })?,
        )
    } else {
        None
    };

    let compiled_jsonpath = if trimmed_path.starts_with('$') {
        Some(JsonPath::parse(trimmed_path).map_err(|e| {
            N8nError::validation(
                "local",
                vec![],
                format!("invalid JSONPath `{trimmed_path}`: {e}"),
            )
        })?)
    } else if !trimmed_path.starts_with('/') {
        return Err(N8nError::validation(
            "local",
            vec![],
            "param_path must start with `'/'` (RFC 6901 JSON Pointer) or `'$'` (JSONPath)",
        ));
    } else {
        None
    };

    let mut matches = Vec::new();

    for node in &ir.nodes {
        if let Some(ref jp) = compiled_jsonpath {
            for located in jp.query_located(&node.parameters).all() {
                if evaluate_param_predicate(located.node(), predicate, compiled_regex.as_ref()) {
                    matches.push(EphemeralParamMatch {
                        node_id: redact_str(&node.id),
                        node_name: redact_str(&node.name),
                        matched_field_path: redact_str(&located.location().to_string()),
                    });
                }
            }
        } else if let Some(val) = node.parameters.pointer(trimmed_path)
            && evaluate_param_predicate(val, predicate, compiled_regex.as_ref())
        {
            matches.push(EphemeralParamMatch {
                node_id: redact_str(&node.id),
                node_name: redact_str(&node.name),
                matched_field_path: redact_str(trimmed_path),
            });
        }
    }

    Ok(matches)
}

fn evaluate_param_predicate(
    value: &Value,
    predicate: &ParamPredicate,
    compiled_re: Option<&Regex>,
) -> bool {
    match predicate {
        ParamPredicate::Exists => !value.is_null(),
        ParamPredicate::Equals { expected } => value == expected,
        ParamPredicate::ContainsSubstring {
            substring,
            case_insensitive,
        } => {
            let Some(s) = value.as_str() else {
                return false;
            };
            if *case_insensitive {
                s.to_ascii_lowercase()
                    .contains(&substring.to_ascii_lowercase())
            } else {
                s.contains(substring.as_str())
            }
        }
        ParamPredicate::MatchesRegex { .. } => {
            let Some(s) = value.as_str() else {
                return false;
            };
            compiled_re.is_some_and(|re| re.is_match(s))
        }
    }
}

fn parse_page_cursor(token: Option<&str>) -> N8nResult<Option<i64>> {
    let Some(raw) = token.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some(num_str) = raw.strip_prefix("cur_") else {
        return Err(N8nError::validation(
            "local",
            vec!["malformed `pageToken`".to_owned()],
            "invalid pagination cursor format",
        ));
    };
    let id = num_str.parse::<i64>().map_err(|_| {
        N8nError::validation(
            "local",
            vec!["non-numeric `pageToken`".to_owned()],
            "invalid pagination cursor",
        )
    })?;
    Ok(Some(id))
}

fn escape_sql_like(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn build_fts5_prefix_query(pattern: &str) -> Option<String> {
    let tokens: Vec<String> = pattern
        .split(|c: char| !c.is_alphanumeric())
        .filter(|tok| !tok.is_empty())
        .map(|tok| format!("\"{}\"*", tok.to_lowercase()))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" AND "))
    }
}

fn is_fallible_external_node(node_type: &str) -> bool {
    if is_any_trigger_type(node_type) || is_canvas_annotation_type(node_type) {
        return false;
    }
    let short = node_type
        .rsplit('.')
        .next()
        .unwrap_or(node_type)
        .to_ascii_lowercase();
    !matches!(
        short.as_str(),
        "noop"
            | "set"
            | "if"
            | "switch"
            | "merge"
            | "filter"
            | "sort"
            | "limit"
            | "splitout"
            | "splitinbatches"
            | "aggregate"
            | "summarize"
            | "removeduplicates"
            | "datetime"
            | "comparedatasets"
            | "wait"
            | "stopanderror"
    )
}

fn build_safe_topology_json(ir: &WorkflowIr) -> Value {
    let mut edges = Vec::new();
    for (src, port_map) in &ir.connections {
        for (port_kind, branches) in port_map {
            for (out_idx, branch) in branches.iter().enumerate() {
                for edge in branch {
                    edges.push(json!({
                        "from": redact_str(src),
                        "to": redact_str(&edge.node),
                        "port": port_kind.as_wire(),
                        "out": out_idx,
                        "in": edge.index,
                    }));
                }
            }
        }
    }
    json!({
        "nodeCount": ir.nodes.len(),
        "edges": edges,
    })
}

fn extract_safe_expression_refs(node: &WorkflowNodeIr) -> (Vec<String>, Vec<String>) {
    let mut ref_nodes = BTreeSet::new();
    let mut used_vars = BTreeSet::new();
    let is_code = matches!(
        node.node_type
            .rsplit('.')
            .next()
            .unwrap_or(&node.node_type)
            .to_ascii_lowercase()
            .as_str(),
        "code" | "function" | "functionitem"
    );
    collect_refs_from_value(&node.parameters, is_code, &mut ref_nodes, &mut used_vars);
    (
        ref_nodes.into_iter().collect(),
        used_vars.into_iter().collect(),
    )
}

fn collect_refs_from_value(
    val: &Value,
    is_code_node: bool,
    ref_nodes: &mut BTreeSet<String>,
    used_vars: &mut BTreeSet<String>,
) {
    match val {
        Value::Object(map) => {
            for v in map.values() {
                collect_refs_from_value(v, is_code_node, ref_nodes, used_vars);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_refs_from_value(item, is_code_node, ref_nodes, used_vars);
            }
        }
        Value::String(s) => {
            if !s.starts_with('=') && !is_code_node {
                return;
            }
            for cap in LITERAL_DOLLAR_NODE_RE.captures_iter(s) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
                    ref_nodes.insert(m.as_str().to_owned());
                }
            }
            for cap in VARIABLE_REF_RE.captures_iter(s) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
                    used_vars.insert(m.as_str().to_owned());
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn hash_credential_reference(cred_type: &str, cred_id: &str, cred_name: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("n8n-rs-mcp/v2/index-credential-ref");
    hasher.update(cred_type.as_bytes());
    hasher.update(b"|");
    hasher.update(cred_id.as_bytes());
    hasher.update(b"|");
    hasher.update(cred_name.as_bytes());
    hasher.finalize().to_hex().to_string()
}
