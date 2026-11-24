//! Offline versioned node & template catalog SQLite schema, bounded `zstd` bundle loader,
//! `BLAKE3` content verification, `sync_catalog` integrity validator, and `SchemaConfidence`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, backup::Backup};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use n8n_types::{N8nError, N8nResult};

/// Default workspace-relative path to the compressed offline catalog bundle.
pub const DEFAULT_CATALOG_ZST_REL_PATH: &str = "data/catalog.sqlite.zst";

/// Default workspace-relative path to the offline catalog manifest.
pub const DEFAULT_CATALOG_MANIFEST_REL_PATH: &str = "data/catalog.manifest.json";

/// Default maximum compressed `.sqlite.zst` archive size (`16 MiB`).
pub const DEFAULT_MAX_COMPRESSED_CATALOG_BYTES: u64 = 16 * 1024 * 1024;

/// Default maximum decompressed SQLite image size (`64 MiB`).
pub const DEFAULT_MAX_DECOMPRESSED_CATALOG_BYTES: u64 = 64 * 1024 * 1024;

/// SQLite 3 file header magic bytes (`16` bytes).
const SQLITE3_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Required tables and FTS5 virtual tables in a valid catalog image.
pub const REQUIRED_CATALOG_TABLES: &[&str] = &[
    "catalog_metadata",
    "node_types",
    "node_versions",
    "node_properties",
    "node_operations",
    "credential_types",
    "node_fts",
    "templates",
    "template_fts",
];

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(1);

const EMPTY_CATALOG_DDL: &str = r"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS catalog_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_types (
    node_type TEXT PRIMARY KEY,
    short_type TEXT NOT NULL UNIQUE,
    package_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    development_style TEXT NOT NULL,
    default_version TEXT NOT NULL,
    is_versioned INTEGER NOT NULL,
    is_trigger INTEGER NOT NULL,
    is_webhook INTEGER NOT NULL,
    is_ai_tool INTEGER NOT NULL,
    is_tool_variant INTEGER NOT NULL,
    has_tool_variant INTEGER NOT NULL,
    tool_variant_of TEXT,
    native_priority INTEGER NOT NULL,
    native_score INTEGER NOT NULL,
    side_effect_class TEXT NOT NULL,
    inputs_json TEXT NOT NULL,
    outputs_json TEXT NOT NULL,
    output_names_json TEXT,
    credentials_json TEXT NOT NULL,
    schema_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_versions (
    node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
    type_version TEXT NOT NULL,
    numeric_version REAL NOT NULL,
    is_default INTEGER NOT NULL,
    is_deprecated INTEGER NOT NULL DEFAULT 0,
    breaking_notes TEXT,
    schema_hash TEXT NOT NULL,
    PRIMARY KEY (node_type, type_version)
);

CREATE TABLE IF NOT EXISTS node_properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
    type_version TEXT NOT NULL,
    prop_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    prop_type TEXT NOT NULL,
    required INTEGER NOT NULL,
    default_json TEXT,
    description TEXT NOT NULL,
    options_json TEXT,
    display_options_json TEXT,
    expected_format_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_node_properties_lookup
    ON node_properties(node_type, type_version, prop_index);

CREATE TABLE IF NOT EXISTS node_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    operation TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    action_label TEXT,
    UNIQUE(node_type, resource, operation)
);

CREATE TABLE IF NOT EXISTS credential_types (
    credential_type TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    documentation_url TEXT,
    auth_kind TEXT NOT NULL,
    is_generic INTEGER NOT NULL,
    required_fields_json TEXT NOT NULL,
    supported_nodes_json TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS node_fts USING fts5(
    node_type,
    short_type,
    display_name,
    category,
    description,
    operations_text,
    keywords,
    tokenize='porter unicode61'
);

CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    complexity TEXT NOT NULL,
    estimated_setup_minutes INTEGER NOT NULL,
    nodes_used_json TEXT NOT NULL,
    required_credentials_json TEXT NOT NULL,
    workflow_json TEXT NOT NULL,
    source_attribution TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS template_fts USING fts5(
    slug,
    name,
    description,
    category,
    nodes_text,
    tokenize='porter unicode61'
);
";

/// Distinguishes authoritative core/LangChain schemas from partial community or unseen-version nodes.
///
/// Per V2 Section 7, callers MUST NEVER claim full schema validation coverage when confidence is
/// [`SchemaConfidence::UnknownOrCommunityPartial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SchemaConfidence {
    /// Known core (`n8n-nodes-base.*`) or LangChain (`@n8n/n8n-nodes-langchain.*`) node type
    /// and known `typeVersion` verified in the offline catalog.
    AuthoritativeCatalog,
    /// Unknown node type, community/custom package node, or unseen `typeVersion` not present
    /// in the offline catalog.
    UnknownOrCommunityPartial,
}

impl SchemaConfidence {
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::AuthoritativeCatalog)
    }

    /// Short compatibility label (`"authoritative"` or `"partial"`) matching equivalence fixtures.
    #[must_use]
    pub const fn as_validation_label(self) -> &'static str {
        match self {
            Self::AuthoritativeCatalog => "authoritative",
            Self::UnknownOrCommunityPartial => "partial",
        }
    }
}

/// Bounded streaming limits and optional expected digests when loading a catalog bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogLoadOptions {
    pub max_compressed_bytes: u64,
    pub max_decompressed_bytes: u64,
    #[serde(default)]
    pub expected_decompressed_blake3: Option<String>,
    #[serde(default)]
    pub expected_compressed_blake3: Option<String>,
}

impl Default for CatalogLoadOptions {
    fn default() -> Self {
        Self {
            max_compressed_bytes: DEFAULT_MAX_COMPRESSED_CATALOG_BYTES,
            max_decompressed_bytes: DEFAULT_MAX_DECOMPRESSED_CATALOG_BYTES,
            expected_decompressed_blake3: None,
            expected_compressed_blake3: None,
        }
    }
}

/// Digest section in `data/catalog.manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogManifestDigests {
    pub decompressed_sqlite_blake3: String,
    #[serde(default)]
    pub decompressed_sqlite_sha256: Option<String>,
    #[serde(default)]
    pub compressed_zst_blake3: Option<String>,
    #[serde(default)]
    pub compressed_zst_sha256: Option<String>,
}

/// Byte-size section in `data/catalog.manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogManifestSizes {
    pub decompressed_sqlite_bytes: u64,
    pub compressed_zst_bytes: u64,
}

/// Parsed representation of `data/catalog.manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogManifest {
    pub schema_version: u32,
    pub bundle_version: String,
    pub source_version: String,
    #[serde(default)]
    pub source_license: Option<String>,
    #[serde(default)]
    pub source_repository: Option<String>,
    pub target_n8n_baseline: String,
    pub extracted_at: String,
    pub bundle_file: String,
    pub blake3_hex: String,
    #[serde(default)]
    pub digests: Option<CatalogManifestDigests>,
    #[serde(default)]
    pub sizes: Option<CatalogManifestSizes>,
    pub node_count: usize,
    pub template_count: usize,
    #[serde(default)]
    pub native_priority_scale: BTreeMap<String, String>,
    #[serde(default)]
    pub tables: BTreeMap<String, usize>,
}

impl CatalogManifest {
    /// Reads and parses `catalog.manifest.json` from disk.
    pub fn from_path(path: &Path) -> N8nResult<Self> {
        let raw = fs::read_to_string(path).map_err(|e| {
            N8nError::config(format!(
                "failed reading catalog manifest `{}`: {e}",
                path.display()
            ))
        })?;
        Self::from_json_str(&raw)
    }

    /// Parses `catalog.manifest.json` from a JSON string.
    pub fn from_json_str(raw: &str) -> N8nResult<Self> {
        serde_json::from_str(raw)
            .map_err(|e| N8nError::config(format!("invalid catalog manifest JSON: {e}")))
    }
}

/// Verified catalog provenance and table row counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogProvenance {
    pub bundle_version: String,
    pub blake3_hex: String,
    pub node_count: usize,
    pub template_count: usize,
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub source_version: String,
    #[serde(default)]
    pub target_n8n_baseline: String,
    #[serde(default)]
    pub extracted_at: String,
    #[serde(default)]
    pub table_row_counts: BTreeMap<String, usize>,
}

/// Full integrity report produced by [`sync_catalog`] and [`CatalogDb::sync_catalog`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSyncReport {
    pub quick_check: String,
    pub verified_tables: Vec<String>,
    pub fts_indexes_verified: bool,
    pub manifest_matched: Option<bool>,
    pub provenance: CatalogProvenance,
}

/// Node summary entry stored in `node_types`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCatalogEntry {
    pub node_type: String,
    pub display_name: String,
    pub default_version: String,
    pub native_priority: u8,
    #[serde(default)]
    pub short_type: String,
    #[serde(default)]
    pub package_name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub native_score: u8,
    #[serde(default)]
    pub is_trigger: bool,
    #[serde(default)]
    pub is_webhook: bool,
    #[serde(default)]
    pub is_ai_tool: bool,
    #[serde(default)]
    pub has_tool_variant: bool,
    #[serde(default)]
    pub side_effect_class: String,
}

/// Version row stored in `node_versions`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeVersionRecord {
    pub type_version: String,
    pub numeric_version: f64,
    pub is_default: bool,
    pub is_deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaking_notes: Option<String>,
    pub schema_hash: String,
}

/// Property definition row stored in `node_properties`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodePropertyRecord {
    pub prop_index: usize,
    pub type_version: String,
    pub name: String,
    pub display_name: String,
    pub prop_type: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_format: Option<Value>,
}

/// Resource/operation pair stored in `node_operations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeOperationRecord {
    pub resource: String,
    pub operation: String,
    pub display_name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_label: Option<String>,
}

/// Credential binding rule declared on a `node_types.credentials_json` entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredentialRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_options: Option<Value>,
}

const fn default_true() -> bool {
    true
}

/// Credential type metadata stored in `credential_types` (field names only, zero secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialTypeSchema {
    pub credential_type: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    pub auth_kind: String,
    pub is_generic: bool,
    pub required_fields: Vec<String>,
    pub supported_nodes: Vec<String>,
}

/// Offline n8n node & template catalog backed by SQLite + FTS5.
pub struct CatalogDb {
    conn: Connection,
    bundle_path: Option<PathBuf>,
    provenance: CatalogProvenance,
}

impl CatalogDb {
    /// Opens an in-memory SQLite catalog initialized with the full empty DDL schema.
    pub fn open_in_memory() -> N8nResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| N8nError::config(format!("failed opening in-memory catalog db: {e}")))?;
        conn.execute_batch(EMPTY_CATALOG_DDL).map_err(|e| {
            N8nError::config(format!("failed initializing in-memory catalog schema: {e}"))
        })?;
        let default_meta = [
            ("schema_version", "1"),
            ("bundle_version", "in-memory-empty"),
            ("source_version", "in-memory"),
            ("target_n8n_baseline", "2.48.7"),
            ("extracted_at", "1970-01-01T00:00:00Z"),
            ("node_count", "0"),
            ("template_count", "0"),
        ];
        for (k, v) in default_meta {
            conn.execute(
                "INSERT OR IGNORE INTO catalog_metadata(key, value) VALUES (?1, ?2);",
                rusqlite::params![k, v],
            )
            .map_err(|e| N8nError::config(format!("failed seeding catalog_metadata: {e}")))?;
        }
        let empty_hash = blake3::hash(b"").to_hex().to_string();
        let provenance = read_catalog_provenance(&conn, &empty_hash)?;
        Ok(Self {
            conn,
            bundle_path: None,
            provenance,
        })
    }

    /// Loads `CatalogDb` from the workspace default `data/catalog.sqlite.zst` and `data/catalog.manifest.json`.
    pub fn open_default_workspace_bundle(workspace_root: &Path) -> N8nResult<Self> {
        let zst_path = workspace_root.join(DEFAULT_CATALOG_ZST_REL_PATH);
        let manifest_path = workspace_root.join(DEFAULT_CATALOG_MANIFEST_REL_PATH);
        let manifest_opt = if manifest_path.exists() {
            Some(manifest_path.as_path())
        } else {
            None
        };
        Self::open_from_zst_path(&zst_path, manifest_opt)
    }

    /// Loads `CatalogDb` from a compressed `.sqlite.zst` bundle path with optional `catalog.manifest.json`.
    pub fn open_from_zst_path(zst_path: &Path, manifest_path: Option<&Path>) -> N8nResult<Self> {
        let manifest = match manifest_path {
            Some(mp) => Some(CatalogManifest::from_path(mp)?),
            None => None,
        };
        Self::open_from_zst_path_with_options(
            zst_path,
            manifest.as_ref(),
            &CatalogLoadOptions::default(),
        )
    }

    /// Loads `CatalogDb` from a compressed `.sqlite.zst` bundle path with explicit bounds and manifest.
    pub fn open_from_zst_path_with_options(
        zst_path: &Path,
        manifest: Option<&CatalogManifest>,
        options: &CatalogLoadOptions,
    ) -> N8nResult<Self> {
        let file_meta = fs::metadata(zst_path).map_err(|e| {
            N8nError::config(format!(
                "failed stating catalog bundle `{}`: {e}",
                zst_path.display()
            ))
        })?;
        if file_meta.len() > options.max_compressed_bytes {
            return Err(N8nError::payload_too_large(
                options.max_compressed_bytes,
                file_meta.len(),
                "catalog_zst_compressed",
            ));
        }
        let compressed = fs::read(zst_path).map_err(|e| {
            N8nError::config(format!(
                "failed reading catalog bundle `{}`: {e}",
                zst_path.display()
            ))
        })?;
        let mut db = Self::open_from_zst_bytes_with_options(&compressed, manifest, options)?;
        db.bundle_path = Some(zst_path.to_path_buf());
        Ok(db)
    }

    /// Loads `CatalogDb` from compressed `.sqlite.zst` bytes and optional `CatalogManifest`.
    pub fn open_from_zst_bytes(
        zst_bytes: &[u8],
        manifest: Option<&CatalogManifest>,
    ) -> N8nResult<Self> {
        Self::open_from_zst_bytes_with_options(zst_bytes, manifest, &CatalogLoadOptions::default())
    }

    /// Loads `CatalogDb` from compressed `.sqlite.zst` bytes with bounded streaming `zstd`
    /// decompression, `BLAKE3` verification, and read-only in-memory SQLite hydration.
    pub fn open_from_zst_bytes_with_options(
        zst_bytes: &[u8],
        manifest: Option<&CatalogManifest>,
        options: &CatalogLoadOptions,
    ) -> N8nResult<Self> {
        let (sqlite_bytes, decompressed_blake3) =
            decompress_and_verify_zst(zst_bytes, manifest, options)?;
        let conn = materialize_readonly_memory_sqlite(&sqlite_bytes, &decompressed_blake3)?;
        let report = validate_catalog_connection(&conn, &decompressed_blake3, manifest)?;
        Ok(Self {
            conn,
            bundle_path: None,
            provenance: report.provenance,
        })
    }

    /// Opens an uncompressed `.sqlite` catalog file in read-only mode for custom testing or inspection.
    pub fn open_uncompressed_sqlite(sqlite_path: &Path) -> N8nResult<Self> {
        let meta = fs::metadata(sqlite_path).map_err(|e| {
            N8nError::config(format!(
                "failed stating uncompressed catalog `{}`: {e}",
                sqlite_path.display()
            ))
        })?;
        if meta.len() > DEFAULT_MAX_DECOMPRESSED_CATALOG_BYTES {
            return Err(N8nError::payload_too_large(
                DEFAULT_MAX_DECOMPRESSED_CATALOG_BYTES,
                meta.len(),
                "catalog_sqlite_uncompressed",
            ));
        }
        let raw_bytes = fs::read(sqlite_path).map_err(|e| {
            N8nError::config(format!(
                "failed reading uncompressed catalog `{}`: {e}",
                sqlite_path.display()
            ))
        })?;
        if raw_bytes.len() < SQLITE3_HEADER_MAGIC.len()
            || &raw_bytes[..SQLITE3_HEADER_MAGIC.len()] != SQLITE3_HEADER_MAGIC
        {
            return Err(N8nError::config(format!(
                "file `{}` does not have a valid SQLite 3 header",
                sqlite_path.display()
            )));
        }
        let digest = blake3::hash(&raw_bytes).to_hex().to_string();
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(sqlite_path, flags).map_err(|e| {
            N8nError::config(format!(
                "failed opening read-only SQLite catalog `{}`: {e}",
                sqlite_path.display()
            ))
        })?;
        conn.pragma_update(None, "query_only", true).map_err(|e| {
            N8nError::config(format!("failed enabling query_only on catalog db: {e}"))
        })?;
        let report = validate_catalog_connection(&conn, &digest, None)?;
        Ok(Self {
            conn,
            bundle_path: Some(sqlite_path.to_path_buf()),
            provenance: report.provenance,
        })
    }

    /// Inspects a `.sqlite.zst` bundle file using bounded streaming decompression and computes its
    /// decompressed `BLAKE3` content hash.
    pub fn verify_bundle_hash(path: &Path) -> N8nResult<String> {
        let options = CatalogLoadOptions::default();
        let meta = fs::metadata(path)
            .map_err(|e| N8nError::config(format!("failed reading catalog bundle: {e}")))?;
        if meta.len() > options.max_compressed_bytes {
            return Err(N8nError::payload_too_large(
                options.max_compressed_bytes,
                meta.len(),
                "catalog_zst_compressed",
            ));
        }
        let compressed = fs::read(path)
            .map_err(|e| N8nError::config(format!("failed reading catalog bundle: {e}")))?;
        let (_bytes, digest) = decompress_and_verify_zst(&compressed, None, &options)?;
        Ok(digest)
    }

    /// Runs `PRAGMA quick_check`, required table/FTS5 verification, and provenance reconciliation.
    pub fn sync_catalog(&self) -> N8nResult<CatalogSyncReport> {
        validate_catalog_connection(&self.conn, &self.provenance.blake3_hex, None)
    }

    /// Runs `sync_catalog` verification and additionally cross-checks against a `CatalogManifest`.
    pub fn sync_catalog_with_manifest(
        &self,
        manifest: &CatalogManifest,
    ) -> N8nResult<CatalogSyncReport> {
        validate_catalog_connection(&self.conn, &self.provenance.blake3_hex, Some(manifest))
    }

    /// Classifies whether `(node_type, type_version)` is covered by an authoritative catalog schema
    /// or must be treated with partial confidence (unknown/community node or unseen `typeVersion`).
    pub fn classify_schema_confidence(
        &self,
        node_type: &str,
        type_version: Option<&str>,
    ) -> N8nResult<SchemaConfidence> {
        let Some((canonical_type, package_name, default_version)) =
            self.lookup_node_identity(node_type)?
        else {
            return Ok(SchemaConfidence::UnknownOrCommunityPartial);
        };

        if !is_authoritative_package(&package_name) {
            return Ok(SchemaConfidence::UnknownOrCommunityPartial);
        }

        let target_ver = type_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_version.as_str());

        if self.has_node_version(&canonical_type, target_ver)? {
            Ok(SchemaConfidence::AuthoritativeCatalog)
        } else {
            Ok(SchemaConfidence::UnknownOrCommunityPartial)
        }
    }

    /// Looks up a credential schema by `credential_type` (e.g. `"postgres"`, `"slackApi"`).
    pub fn get_credential_type(
        &self,
        credential_type: &str,
    ) -> N8nResult<Option<CredentialTypeSchema>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT credential_type, display_name, documentation_url, auth_kind,
                        is_generic, required_fields_json, supported_nodes_json
                 FROM credential_types
                 WHERE credential_type = ?1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing credential lookup: {e}")))?;

        stmt.query_row(rusqlite::params![credential_type], |row| {
            let req_json: String = row.get(5)?;
            let sup_json: String = row.get(6)?;
            let required_fields: Vec<String> = serde_json::from_str(&req_json).unwrap_or_default();
            let supported_nodes: Vec<String> = serde_json::from_str(&sup_json).unwrap_or_default();
            Ok(CredentialTypeSchema {
                credential_type: row.get(0)?,
                display_name: row.get(1)?,
                documentation_url: row.get(2)?,
                auth_kind: row.get(3)?,
                is_generic: row.get::<_, i64>(4)? != 0,
                required_fields,
                supported_nodes,
            })
        })
        .optional()
        .map_err(|e| N8nError::protocol(format!("failed querying credential_types: {e}")))
    }

    /// Lists all credential schemas in the catalog ordered by `credential_type`.
    pub fn list_credential_types(&self) -> N8nResult<Vec<CredentialTypeSchema>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT credential_type, display_name, documentation_url, auth_kind,
                        is_generic, required_fields_json, supported_nodes_json
                 FROM credential_types
                 ORDER BY credential_type ASC;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing credential list: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let req_json: String = row.get(5)?;
                let sup_json: String = row.get(6)?;
                Ok(CredentialTypeSchema {
                    credential_type: row.get(0)?,
                    display_name: row.get(1)?,
                    documentation_url: row.get(2)?,
                    auth_kind: row.get(3)?,
                    is_generic: row.get::<_, i64>(4)? != 0,
                    required_fields: serde_json::from_str(&req_json).unwrap_or_default(),
                    supported_nodes: serde_json::from_str(&sup_json).unwrap_or_default(),
                })
            })
            .map_err(|e| N8nError::protocol(format!("failed reading credential_types: {e}")))?;

        let mut out = Vec::new();
        for item in rows {
            out.push(
                item.map_err(|e| N8nError::protocol(format!("invalid credential_types row: {e}")))?,
            );
        }
        Ok(out)
    }

    #[must_use]
    pub const fn provenance(&self) -> &CatalogProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn bundle_path(&self) -> Option<&Path> {
        self.bundle_path.as_deref()
    }

    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn lookup_node_identity(
        &self,
        node_type_or_short: &str,
    ) -> N8nResult<Option<(String, String, String)>> {
        let trimmed = node_type_or_short.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT node_type, package_name, default_version
                 FROM node_types
                 WHERE node_type = ?1 OR short_type = ?1
                 LIMIT 1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing node lookup: {e}")))?;

        stmt.query_row(rusqlite::params![trimmed], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()
        .map_err(|e| N8nError::protocol(format!("failed querying node identity: {e}")))
    }

    pub(crate) fn has_node_version(&self, node_type: &str, version_str: &str) -> N8nResult<bool> {
        Ok(self
            .resolve_catalog_version(node_type, version_str)?
            .is_some())
    }

    pub(crate) fn resolve_catalog_version(
        &self,
        node_type: &str,
        version_str: &str,
    ) -> N8nResult<Option<(String, f64)>> {
        let mut exact_stmt = self
            .conn
            .prepare_cached(
                "SELECT type_version, numeric_version
                 FROM node_versions
                 WHERE node_type = ?1 AND type_version = ?2
                 LIMIT 1;",
            )
            .map_err(|e| N8nError::protocol(format!("failed preparing version lookup: {e}")))?;

        if let Some(hit) = exact_stmt
            .query_row(rusqlite::params![node_type, version_str], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
            })
            .optional()
            .map_err(|e| N8nError::protocol(format!("failed querying node_versions: {e}")))?
        {
            return Ok(Some(hit));
        }

        if let Ok(parsed_num) = version_str.parse::<f64>()
            && parsed_num.is_finite()
        {
            let mut num_stmt = self
                .conn
                .prepare_cached(
                    "SELECT type_version, numeric_version
                     FROM node_versions
                     WHERE node_type = ?1 AND ABS(numeric_version - ?2) < 1e-6
                     LIMIT 1;",
                )
                .map_err(|e| {
                    N8nError::protocol(format!("failed preparing numeric version lookup: {e}"))
                })?;

            return num_stmt
                .query_row(rusqlite::params![node_type, parsed_num], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
                })
                .optional()
                .map_err(|e| {
                    N8nError::protocol(format!("failed querying numeric node_versions: {e}"))
                });
        }

        Ok(None)
    }
}

/// Validates a compressed `.sqlite.zst` bundle (and optional `catalog.manifest.json`) end-to-end:
/// bounded streaming decompression, `BLAKE3` verification, `PRAGMA quick_check`, required tables,
/// FTS5 index probes, and row-count provenance reconciliation.
pub fn sync_catalog(
    bundle_path: &Path,
    manifest_path: Option<&Path>,
) -> N8nResult<CatalogSyncReport> {
    let manifest = match manifest_path {
        Some(mp) => Some(CatalogManifest::from_path(mp)?),
        None => None,
    };
    let db = CatalogDb::open_from_zst_path_with_options(
        bundle_path,
        manifest.as_ref(),
        &CatalogLoadOptions::default(),
    )?;
    match manifest {
        Some(ref m) => db.sync_catalog_with_manifest(m),
        None => db.sync_catalog(),
    }
}

pub(crate) fn is_authoritative_package(package_name: &str) -> bool {
    matches!(package_name, "n8n-nodes-base" | "@n8n/n8n-nodes-langchain")
}

fn decompress_and_verify_zst(
    zst_bytes: &[u8],
    manifest: Option<&CatalogManifest>,
    options: &CatalogLoadOptions,
) -> N8nResult<(Vec<u8>, String)> {
    let compressed_len = zst_bytes.len() as u64;
    if compressed_len > options.max_compressed_bytes {
        return Err(N8nError::payload_too_large(
            options.max_compressed_bytes,
            compressed_len,
            "catalog_zst_compressed",
        ));
    }

    if let Some(m) = manifest
        && let Some(ref sizes) = m.sizes
        && sizes.compressed_zst_bytes != compressed_len
    {
        return Err(N8nError::config(format!(
            "compressed catalog byte size mismatch: manifest expects {}, got {}",
            sizes.compressed_zst_bytes, compressed_len
        )));
    }

    let expected_zst_blake3 = options.expected_compressed_blake3.as_deref().or_else(|| {
        manifest
            .and_then(|m| m.digests.as_ref())
            .and_then(|d| d.compressed_zst_blake3.as_deref())
    });
    if let Some(expected_comp_hex) = expected_zst_blake3 {
        let actual_comp_hex = blake3::hash(zst_bytes).to_hex().to_string();
        if !actual_comp_hex.eq_ignore_ascii_case(expected_comp_hex) {
            return Err(N8nError::config(format!(
                "compressed catalog BLAKE3 digest mismatch: expected {expected_comp_hex}, got {actual_comp_hex}"
            )));
        }
    }

    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(zst_bytes))
        .map_err(|e| N8nError::config(format!("invalid zstd catalog header: {e}")))?;

    let initial_cap = manifest
        .and_then(|m| m.sizes.as_ref())
        .and_then(|s| usize::try_from(s.decompressed_sqlite_bytes).ok())
        .map_or(64 * 1024, |n| n.min(4 * 1024 * 1024));

    let mut out = Vec::with_capacity(initial_cap);
    let mut hasher = blake3::Hasher::new();
    let mut chunk = [0_u8; 16 * 1024];
    let mut observed_bytes: u64 = 0;

    loop {
        let n = decoder
            .read(&mut chunk)
            .map_err(|e| N8nError::config(format!("invalid zstd catalog stream: {e}")))?;
        if n == 0 {
            break;
        }
        observed_bytes = observed_bytes.saturating_add(n as u64);
        if observed_bytes > options.max_decompressed_bytes {
            return Err(N8nError::payload_too_large(
                options.max_decompressed_bytes,
                observed_bytes,
                "catalog_zst_decompressed",
            ));
        }
        hasher.update(&chunk[..n]);
        out.extend_from_slice(&chunk[..n]);
    }

    if out.len() < SQLITE3_HEADER_MAGIC.len()
        || &out[..SQLITE3_HEADER_MAGIC.len()] != SQLITE3_HEADER_MAGIC
    {
        return Err(N8nError::config(
            "decompressed catalog image does not start with SQLite 3 header",
        ));
    }

    let actual_blake3 = hasher.finalize().to_hex().to_string();

    if let Some(m) = manifest
        && let Some(ref sizes) = m.sizes
        && sizes.decompressed_sqlite_bytes != observed_bytes
    {
        return Err(N8nError::config(format!(
            "decompressed catalog byte size mismatch: manifest expects {}, got {}",
            sizes.decompressed_sqlite_bytes, observed_bytes
        )));
    }

    let expected_sqlite_blake3 = options
        .expected_decompressed_blake3
        .as_deref()
        .or_else(|| manifest.map(|m| m.blake3_hex.as_str()));
    if let Some(expected_hex) = expected_sqlite_blake3
        && !actual_blake3.eq_ignore_ascii_case(expected_hex)
    {
        return Err(N8nError::config(format!(
            "decompressed catalog BLAKE3 digest mismatch: expected {expected_hex}, got {actual_blake3}"
        )));
    }

    if let Some(m) = manifest
        && let Some(ref digests) = m.digests
        && !actual_blake3.eq_ignore_ascii_case(&digests.decompressed_sqlite_blake3)
    {
        return Err(N8nError::config(format!(
            "decompressed catalog BLAKE3 mismatch against manifest.digests: expected {}, got {actual_blake3}",
            digests.decompressed_sqlite_blake3
        )));
    }

    Ok((out, actual_blake3))
}

fn materialize_readonly_memory_sqlite(
    sqlite_bytes: &[u8],
    digest_hex: &str,
) -> N8nResult<Connection> {
    let seq = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let prefix = &digest_hex[..digest_hex.len().min(12)];
    let temp_name = format!("n8n-forge-catalog-{prefix}-{pid}-{seq}.sqlite");
    let temp_path = std::env::temp_dir().join(temp_name);

    struct EphemeralFileGuard(PathBuf);
    impl Drop for EphemeralFileGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    let _guard = EphemeralFileGuard(temp_path.clone());
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| {
                N8nError::config(format!(
                    "failed creating ephemeral catalog staging file: {e}"
                ))
            })?;
        file.write_all(sqlite_bytes).map_err(|e| {
            N8nError::config(format!(
                "failed writing ephemeral catalog staging file: {e}"
            ))
        })?;
        file.flush().map_err(|e| {
            N8nError::config(format!(
                "failed flushing ephemeral catalog staging file: {e}"
            ))
        })?;
    }

    let src_flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let src_conn = Connection::open_with_flags(&temp_path, src_flags)
        .map_err(|e| N8nError::config(format!("failed opening staged catalog image: {e}")))?;

    let mut mem_conn = Connection::open_in_memory()
        .map_err(|e| N8nError::config(format!("failed opening in-memory catalog target: {e}")))?;

    {
        let backup = Backup::new(&src_conn, &mut mem_conn)
            .map_err(|e| N8nError::config(format!("failed initializing SQLite backup: {e}")))?;
        backup
            .run_to_completion(2048, Duration::ZERO, None)
            .map_err(|e| {
                N8nError::config(format!("failed loading SQLite image into memory: {e}"))
            })?;
    }
    drop(src_conn);

    mem_conn
        .pragma_update(None, "query_only", true)
        .map_err(|e| N8nError::config(format!("failed setting catalog query_only pragma: {e}")))?;

    Ok(mem_conn)
}

fn validate_catalog_connection(
    conn: &Connection,
    blake3_hex: &str,
    manifest: Option<&CatalogManifest>,
) -> N8nResult<CatalogSyncReport> {
    // 1. Verify PRAGMA quick_check returns exclusively "ok".
    let mut qc_stmt = conn
        .prepare("PRAGMA quick_check;")
        .map_err(|e| N8nError::config(format!("failed preparing PRAGMA quick_check: {e}")))?;
    let qc_rows = qc_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| N8nError::config(format!("failed running PRAGMA quick_check: {e}")))?;
    let mut qc_messages = Vec::new();
    for r in qc_rows {
        let msg = r.map_err(|e| N8nError::config(format!("invalid quick_check row: {e}")))?;
        qc_messages.push(msg);
    }
    if qc_messages.is_empty() || qc_messages.iter().any(|m| !m.eq_ignore_ascii_case("ok")) {
        return Err(N8nError::config(format!(
            "SQLite PRAGMA quick_check failed: {}",
            qc_messages.join("; ")
        )));
    }

    // 2. Verify all 9 required tables / FTS5 virtual tables exist in sqlite_master.
    let mut verified_tables = Vec::with_capacity(REQUIRED_CATALOG_TABLES.len());
    for &table_name in REQUIRED_CATALOG_TABLES {
        let exists: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1;",
                rusqlite::params![table_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                N8nError::config(format!(
                    "failed checking sqlite_master for `{table_name}`: {e}"
                ))
            })?;
        if exists.is_none() {
            return Err(N8nError::config(format!(
                "catalog SQLite image missing required table `{table_name}`"
            )));
        }
        verified_tables.push(table_name.to_owned());
    }

    // 3. Probe both FTS5 virtual tables with a benign MATCH query to confirm FTS5 index health.
    let _: Option<String> = conn
        .query_row(
            "SELECT node_type FROM node_fts WHERE node_fts MATCH '\"webhook\"' LIMIT 1;",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| N8nError::config(format!("node_fts FTS5 probe failed: {e}")))?;

    let _: Option<String> = conn
        .query_row(
            "SELECT slug FROM template_fts WHERE template_fts MATCH '\"webhook\"' LIMIT 1;",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| N8nError::config(format!("template_fts FTS5 probe failed: {e}")))?;

    // 4. Read provenance metadata and verify table row counts.
    let provenance = read_catalog_provenance(conn, blake3_hex)?;

    let node_types_rows = provenance
        .table_row_counts
        .get("node_types")
        .copied()
        .unwrap_or(0);
    let node_fts_rows = provenance
        .table_row_counts
        .get("node_fts")
        .copied()
        .unwrap_or(0);
    if provenance.node_count != node_types_rows || node_types_rows != node_fts_rows {
        return Err(N8nError::config(format!(
            "catalog node count mismatch: metadata={}, node_types={}, node_fts={}",
            provenance.node_count, node_types_rows, node_fts_rows
        )));
    }

    let tmpl_rows = provenance
        .table_row_counts
        .get("templates")
        .copied()
        .unwrap_or(0);
    let tmpl_fts_rows = provenance
        .table_row_counts
        .get("template_fts")
        .copied()
        .unwrap_or(0);
    if provenance.template_count != tmpl_rows || tmpl_rows != tmpl_fts_rows {
        return Err(N8nError::config(format!(
            "catalog template count mismatch: metadata={}, templates={}, template_fts={}",
            provenance.template_count, tmpl_rows, tmpl_fts_rows
        )));
    }

    let manifest_matched = if let Some(m) = manifest {
        if m.bundle_version != provenance.bundle_version
            || m.source_version != provenance.source_version
            || m.extracted_at != provenance.extracted_at
            || m.node_count != provenance.node_count
            || m.template_count != provenance.template_count
            || !m.blake3_hex.eq_ignore_ascii_case(&provenance.blake3_hex)
        {
            return Err(N8nError::config(
                "catalog provenance metadata does not match catalog.manifest.json",
            ));
        }
        for (tbl, &expected_cnt) in &m.tables {
            let actual_cnt = provenance
                .table_row_counts
                .get(tbl)
                .copied()
                .ok_or_else(|| {
                    N8nError::config(format!(
                        "manifest table `{tbl}` missing from verified catalog counts"
                    ))
                })?;
            if actual_cnt != expected_cnt {
                return Err(N8nError::config(format!(
                    "catalog table `{tbl}` row count mismatch: manifest={expected_cnt}, sqlite={actual_cnt}"
                )));
            }
        }
        Some(true)
    } else {
        None
    };

    Ok(CatalogSyncReport {
        quick_check: "ok".to_owned(),
        verified_tables,
        fts_indexes_verified: true,
        manifest_matched,
        provenance,
    })
}

fn read_catalog_provenance(conn: &Connection, blake3_hex: &str) -> N8nResult<CatalogProvenance> {
    let mut meta_map = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT key, value FROM catalog_metadata;")
            .map_err(|e| N8nError::config(format!("failed reading catalog_metadata: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| N8nError::config(format!("failed querying catalog_metadata: {e}")))?;
        for r in rows {
            let (k, v) = r.map_err(|e| N8nError::config(format!("invalid metadata row: {e}")))?;
            meta_map.insert(k, v);
        }
    }

    let mut table_row_counts = BTreeMap::new();
    for &tbl in REQUIRED_CATALOG_TABLES {
        // `tbl` comes strictly from the static `REQUIRED_CATALOG_TABLES` slice above.
        let sql = format!("SELECT COUNT(*) FROM {tbl};");
        let count_i64: i64 = conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|e| N8nError::config(format!("failed counting rows in `{tbl}`: {e}")))?;
        let count = usize::try_from(count_i64.max(0)).unwrap_or(0);
        table_row_counts.insert(tbl.to_owned(), count);
    }

    let schema_version = meta_map
        .get("schema_version")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);
    let bundle_version = meta_map
        .get("bundle_version")
        .cloned()
        .ok_or_else(|| N8nError::config("catalog_metadata missing `bundle_version`"))?;
    let source_version = meta_map
        .get("source_version")
        .cloned()
        .ok_or_else(|| N8nError::config("catalog_metadata missing `source_version`"))?;
    let target_n8n_baseline = meta_map
        .get("target_n8n_baseline")
        .cloned()
        .unwrap_or_else(|| "2.48.7".to_owned());
    let extracted_at = meta_map
        .get("extracted_at")
        .cloned()
        .ok_or_else(|| N8nError::config("catalog_metadata missing `extracted_at`"))?;

    let node_count = match meta_map.get("node_count") {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|e| N8nError::config(format!("invalid `node_count` metadata: {e}")))?,
        None => table_row_counts.get("node_types").copied().unwrap_or(0),
    };
    let template_count = match meta_map.get("template_count") {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|e| N8nError::config(format!("invalid `template_count` metadata: {e}")))?,
        None => table_row_counts.get("templates").copied().unwrap_or(0),
    };

    Ok(CatalogProvenance {
        bundle_version,
        blake3_hex: blake3_hex.to_owned(),
        node_count,
        template_count,
        schema_version,
        source_version,
        target_n8n_baseline,
        extracted_at,
        table_row_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root exists")
    }

    #[test]
    fn loads_real_zst_bundle_and_reconciles_manifest_provenance() {
        let root = workspace_root();
        let zst_path = root.join(DEFAULT_CATALOG_ZST_REL_PATH);
        let manifest_path = root.join(DEFAULT_CATALOG_MANIFEST_REL_PATH);

        let manifest = CatalogManifest::from_path(&manifest_path).expect("valid manifest");
        let report = sync_catalog(&zst_path, Some(&manifest_path)).expect("sync_catalog passes");

        assert_eq!(report.quick_check, "ok");
        assert!(report.fts_indexes_verified);
        assert_eq!(report.manifest_matched, Some(true));
        assert_eq!(report.verified_tables.len(), REQUIRED_CATALOG_TABLES.len());
        assert_eq!(report.provenance.bundle_version, manifest.bundle_version);
        assert_eq!(report.provenance.source_version, "n8n-mcp@2.103.2");
        assert_eq!(report.provenance.extracted_at, "2026-11-23T00:00:00Z");
        assert_eq!(report.provenance.blake3_hex, manifest.blake3_hex);
        assert_eq!(report.provenance.node_count, 72);
        assert_eq!(report.provenance.template_count, 16);

        let hash_only = CatalogDb::verify_bundle_hash(&zst_path).expect("hash check");
        assert_eq!(hash_only, manifest.blake3_hex);
    }

    #[test]
    fn enforces_decompressed_byte_budget_and_blake3_mismatch_defense() {
        let root = workspace_root();
        let zst_bytes = fs::read(root.join(DEFAULT_CATALOG_ZST_REL_PATH)).expect("read zst");

        let tiny_limit = CatalogLoadOptions {
            max_compressed_bytes: DEFAULT_MAX_COMPRESSED_CATALOG_BYTES,
            max_decompressed_bytes: 4096,
            expected_decompressed_blake3: None,
            expected_compressed_blake3: None,
        };
        let err = match CatalogDb::open_from_zst_bytes_with_options(&zst_bytes, None, &tiny_limit) {
            Ok(_) => panic!("must abort oversized decompressed stream"),
            Err(err) => err,
        };
        assert_eq!(err.error_code(), "PAYLOAD_TOO_LARGE");

        let wrong_digest = CatalogLoadOptions {
            expected_decompressed_blake3: Some("0".repeat(64)),
            ..CatalogLoadOptions::default()
        };
        let digest_err =
            match CatalogDb::open_from_zst_bytes_with_options(&zst_bytes, None, &wrong_digest) {
                Ok(_) => panic!("must reject wrong BLAKE3 digest"),
                Err(err) => err,
            };
        assert_eq!(digest_err.error_code(), "CONFIG_ERROR");
    }

    #[test]
    fn opens_uncompressed_sqlite_for_custom_testing_and_classifies_confidence() {
        let root = workspace_root();
        let zst_bytes = fs::read(root.join(DEFAULT_CATALOG_ZST_REL_PATH)).expect("read zst");
        let (sqlite_bytes, _) =
            decompress_and_verify_zst(&zst_bytes, None, &CatalogLoadOptions::default())
                .expect("decompress");

        let tmp = tempfile::tempdir().expect("tempdir");
        let sqlite_file = tmp.path().join("custom_test_catalog.sqlite");
        fs::write(&sqlite_file, &sqlite_bytes).expect("write uncompressed sqlite");

        let db = CatalogDb::open_uncompressed_sqlite(&sqlite_file).expect("open uncompressed");
        assert_eq!(db.bundle_path(), Some(sqlite_file.as_path()));
        assert_eq!(db.provenance().node_count, 72);

        // Authoritative core & LangChain nodes at known versions
        assert_eq!(
            db.classify_schema_confidence("n8n-nodes-base.postgres", Some("2.5"))
                .expect("classify"),
            SchemaConfidence::AuthoritativeCatalog
        );
        assert_eq!(
            db.classify_schema_confidence("@n8n/n8n-nodes-langchain.agent", Some("1.8"))
                .expect("classify"),
            SchemaConfidence::AuthoritativeCatalog
        );

        // Unseen typeVersion on a known core node -> UnknownOrCommunityPartial!
        assert_eq!(
            db.classify_schema_confidence("n8n-nodes-base.postgres", Some("99.9"))
                .expect("classify"),
            SchemaConfidence::UnknownOrCommunityPartial
        );

        // Unknown / community node types -> UnknownOrCommunityPartial!
        assert_eq!(
            db.classify_schema_confidence("n8n-nodes-acme-crm.acmeContact", Some("1"))
                .expect("classify"),
            SchemaConfidence::UnknownOrCommunityPartial
        );
        assert_eq!(
            db.classify_schema_confidence("@community/n8n-nodes-firecrawl.firecrawl", None)
                .expect("classify"),
            SchemaConfidence::UnknownOrCommunityPartial
        );
    }

    #[test]
    fn in_memory_empty_catalog_passes_sync_catalog_and_credential_listing() {
        let empty = CatalogDb::open_in_memory().expect("open_in_memory");
        let sync = empty.sync_catalog().expect("sync empty catalog");
        assert_eq!(sync.quick_check, "ok");
        assert!(sync.fts_indexes_verified);
        assert_eq!(sync.provenance.node_count, 0);
        assert_eq!(sync.provenance.template_count, 0);
        assert!(empty.list_credential_types().expect("creds").is_empty());

        let root = workspace_root();
        let real = CatalogDb::open_default_workspace_bundle(&root).expect("real catalog");
        let creds = real.list_credential_types().expect("list real creds");
        assert_eq!(creds.len(), 30);
    }
}
