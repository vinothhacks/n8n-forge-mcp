//! Typed Public API DTOs for `/api/v1/discover`, workflows, executions, evaluations, credentials,
//! data-tables, projects, folders, users, tags, variables, packages, source-control, and policies.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Cursor-paginated list envelope returned by n8n `/api/v1/*` list endpoints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", bound(deserialize = "T: Deserialize<'de>"))]
pub struct PaginatedList<T> {
    #[serde(default)]
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Standard query parameters for cursor-paginated endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListQueryParams {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub active: Option<bool>,
    pub tags: Option<String>,
    pub name: Option<String>,
    pub project_id: Option<String>,
    pub exclude_pinned_data: Option<bool>,
}

/// Response from `GET /api/v1/discover?include=schemas`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverPayload {
    pub version: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resources: Value,
    #[serde(default)]
    pub features: BTreeMap<String, Value>,
    #[serde(default)]
    pub rate_limits: Option<Value>,
    #[serde(default)]
    pub protected_instance: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Workflow representation separating `versionId` (draft) from `activeVersionId` (live published).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowResource {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub is_archived: bool,
    pub version_id: Option<String>,
    pub active_version_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default)]
    pub nodes: Vec<Value>,
    #[serde(default)]
    pub connections: Value,
    #[serde(default)]
    pub settings: Value,
    #[serde(default)]
    pub tags: Vec<TagResource>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TagResource {
    pub id: String,
    pub name: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResource {
    pub id: String,
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub finished: bool,
    pub mode: Option<String>,
    pub status: Option<String>,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub retry_of: Option<String>,
    pub retry_success_id: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
}

/// Credential metadata record (never exposes raw secret `data` values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataTableResource {
    pub id: String,
    pub name: String,
    pub project_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectResource {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub project_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FolderResource {
    pub id: String,
    pub name: String,
    pub parent_folder_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserResource {
    pub id: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<String>,
    #[serde(default)]
    pub is_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VariableResource {
    pub id: String,
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub variable_type: Option<String>,
}
