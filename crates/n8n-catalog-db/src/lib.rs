//! Offline versioned node & template catalog (`data/catalog.sqlite.zst`), bounded `zstd` +
//! `BLAKE3` provenance verifier, n8n `displayOptions` conditional evaluator, FTS5 native-first
//! node search, effective node field inspector, and curated workflow templates.

pub mod display_options;
pub mod schema;
pub mod search;
pub mod templates;

// Preserve all Phase 1 public re-exports required by downstream crates (`n8n-validator`,
// `n8n-mcp-server`, `n8n-mcp-cli`), plus full Wave 2 production catalog types.
pub use display_options::{
    AllowedOptionValue, DisplayEvalContext, EffectiveChildProperty, EffectiveFixedCollectionGroup,
    EffectiveNestedFields, build_node_context, compute_effective_nested_fields,
    evaluate_display_options, is_property_visible, json_values_equal,
};
pub use schema::{
    CatalogDb, CatalogLoadOptions, CatalogManifest, CatalogManifestDigests, CatalogManifestSizes,
    CatalogProvenance, CatalogSyncReport, CredentialTypeSchema, DEFAULT_CATALOG_MANIFEST_REL_PATH,
    DEFAULT_CATALOG_ZST_REL_PATH, DEFAULT_MAX_COMPRESSED_CATALOG_BYTES,
    DEFAULT_MAX_DECOMPRESSED_CATALOG_BYTES, NodeCatalogEntry, NodeCredentialRule,
    NodeOperationRecord, NodePropertyRecord, NodeVersionRecord, REQUIRED_CATALOG_TABLES,
    SchemaConfidence, sync_catalog,
};
pub use search::{
    EffectiveCredentialRule, EffectiveNodeInspection, EffectiveProperty, NATIVE_DATA_NODE_TYPES,
    NodeDocsSection, NodeInfoMode, NodeInfoRequest, NodeInfoResponse, NodeSearchHit,
    NodeSearchQuery, NodeSearchResponse, NodeSourceFilter, PropertySearchMatch, SearchMode,
    is_native_data_node, native_first_guidance_for_query, rank_native_first,
};
pub use templates::{
    CredentialPlaceholder, TemplateCatalogEntry, TemplateDetailMode, TemplateNodeStub,
    TemplateSearchMode, TemplateSearchQuery, TemplateSearchResponse, TemplateSummary,
};
