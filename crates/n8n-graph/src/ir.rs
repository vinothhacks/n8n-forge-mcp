//! Lossless n8n Workflow Intermediate Representation (`WorkflowIr`) supporting draft `versionId` vs
//! live `activeVersionId`, `main`/`error`/AI sub-node ports, `pinData`, `nodeGroups`, unknown-field
//! byte-for-byte preservation, and deterministic `BLAKE3` canonical version hashing.

use std::collections::BTreeMap;
use std::fmt;

use indexmap::IndexMap;
use n8n_types::{N8nError, N8nResult};
use schemars::JsonSchema;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Number, Value};

/// Per-port branch table: outer `Vec` is `output_index` (branch index), inner `Vec` lists outgoing edges.
pub type PortBranchList = Vec<Vec<ConnectionEdgeIr>>;

/// Map of port type (`main`, `error`, `ai_*`) to outgoing branch arrays for a single source node.
pub type NodePortConnections = IndexMap<PortKind, PortBranchList>;

/// Connection port classification across standard execution, error outputs, and LangChain/AI sub-nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum PortKind {
    #[default]
    Main,
    Error,
    AiLanguageModel,
    AiTool,
    AiMemory,
    AiOutputParser,
    AiRetriever,
    AiVectorStore,
    AiDocument,
    AiEmbedding,
    AiTextSplitter,
    Custom(String),
}

impl PortKind {
    /// Parses an n8n wire port string into a typed [`PortKind`].
    #[must_use]
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "main" => Self::Main,
            "error" => Self::Error,
            "ai_languageModel" => Self::AiLanguageModel,
            "ai_tool" => Self::AiTool,
            "ai_memory" => Self::AiMemory,
            "ai_outputParser" => Self::AiOutputParser,
            "ai_retriever" => Self::AiRetriever,
            "ai_vectorStore" => Self::AiVectorStore,
            "ai_document" => Self::AiDocument,
            "ai_embedding" => Self::AiEmbedding,
            "ai_textSplitter" => Self::AiTextSplitter,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Returns the exact n8n wire representation for this port.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Main => "main",
            Self::Error => "error",
            Self::AiLanguageModel => "ai_languageModel",
            Self::AiTool => "ai_tool",
            Self::AiMemory => "ai_memory",
            Self::AiOutputParser => "ai_outputParser",
            Self::AiRetriever => "ai_retriever",
            Self::AiVectorStore => "ai_vectorStore",
            Self::AiDocument => "ai_document",
            Self::AiEmbedding => "ai_embedding",
            Self::AiTextSplitter => "ai_textSplitter",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns `true` when this port is an AI sub-node attachment port (`ai_*`).
    #[must_use]
    pub fn is_ai_subnode_port(&self) -> bool {
        match self {
            Self::AiLanguageModel
            | Self::AiTool
            | Self::AiMemory
            | Self::AiOutputParser
            | Self::AiRetriever
            | Self::AiVectorStore
            | Self::AiDocument
            | Self::AiEmbedding
            | Self::AiTextSplitter => true,
            Self::Main | Self::Error => false,
            Self::Custom(s) => s.starts_with("ai_"),
        }
    }

    /// Returns `true` when multiple simultaneous provider attachments on index `0` are normally invalid.
    #[must_use]
    pub const fn is_singleton_ai_slot(&self) -> bool {
        matches!(
            self,
            Self::AiLanguageModel
                | Self::AiMemory
                | Self::AiOutputParser
                | Self::AiEmbedding
                | Self::AiTextSplitter
        )
    }
}

impl fmt::Display for PortKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

impl Serialize for PortKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for PortKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_wire(&s))
    }
}

impl JsonSchema for PortKind {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("PortKind")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }
}

/// Directed target edge inside `connections[sourceNode][portType][outputIndex]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionEdgeIr {
    pub node: String,
    #[serde(rename = "type", default)]
    pub port_type: PortKind,
    #[serde(default)]
    pub index: usize,
    #[serde(flatten, default)]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub extra: IndexMap<String, Value>,
}

impl ConnectionEdgeIr {
    #[must_use]
    pub fn new(node: impl Into<String>, port_type: PortKind, index: usize) -> Self {
        Self {
            node: node.into(),
            port_type,
            index,
            extra: IndexMap::new(),
        }
    }
}

/// Non-secret credential reference bound on a workflow node (`{ id, name }`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredentialRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(flatten, default)]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub extra: IndexMap<String, Value>,
}

impl NodeCredentialRef {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            name: name.into(),
            extra: IndexMap::new(),
        }
    }
}

/// n8n 2.41+ canvas node group referencing member `node.id` values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeGroupIr {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub node_ids: Vec<String>,
    #[serde(flatten, default)]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub extra: IndexMap<String, Value>,
}

const fn is_false(b: &bool) -> bool {
    !*b
}

fn default_type_version() -> Value {
    Value::Number(Number::from(1))
}

fn default_empty_object() -> Value {
    Value::Object(Map::new())
}

fn serialize_position<S: Serializer>(pos: &[f64; 2], serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(2))?;
    for &coord in pos {
        if coord.is_finite()
            && coord.fract() == 0.0
            && coord >= (i64::MIN as f64)
            && coord <= (i64::MAX as f64)
        {
            #[allow(clippy::cast_possible_truncation)]
            seq.serialize_element(&(coord as i64))?;
        } else {
            seq.serialize_element(&coord)?;
        }
    }
    seq.end()
}

/// Lossless representation of a single n8n workflow node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowNodeIr {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default = "default_type_version")]
    pub type_version: Value,
    #[serde(default, serialize_with = "serialize_position")]
    pub position: [f64; 2],
    #[serde(default = "default_empty_object")]
    pub parameters: Value,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<BTreeMap<String, NodeCredentialRef>>")]
    pub credentials: Option<IndexMap<String, NodeCredentialRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_on_fail: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_between_tries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continue_on_fail: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_once: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_output_data: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_in_flow: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_id: Option<String>,
    #[serde(flatten, default)]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub extra: IndexMap<String, Value>,
}

impl WorkflowNodeIr {
    /// Formats `type_version` as a clean string (`"1"`, `"4.2"`, etc.).
    #[must_use]
    pub fn type_version_string(&self) -> String {
        match &self.type_version {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }

    /// Parses `type_version` as `f64` when numeric.
    #[must_use]
    pub fn type_version_f64(&self) -> Option<f64> {
        match &self.type_version {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    /// Returns `true` if this node has explicit node-level retry or continue-on-error semantics configured.
    #[must_use]
    pub fn has_local_error_handling(&self) -> bool {
        self.retry_on_fail.unwrap_or(false)
            || self.continue_on_fail.unwrap_or(false)
            || matches!(
                self.on_error.as_deref(),
                Some("continueRegularOutput" | "continueErrorOutput")
            )
    }
}

fn deserialize_connections<'de, D>(
    deserializer: D,
) -> Result<IndexMap<String, NodePortConnections>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ConnectionsVisitor;

    impl<'de> Visitor<'de> for ConnectionsVisitor {
        type Value = IndexMap<String, NodePortConnections>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an n8n workflow connections object")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut out = IndexMap::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((src_node, ports_val)) = map.next_entry::<String, PortMapHelper>()? {
                out.insert(src_node, ports_val.0);
            }
            Ok(out)
        }
    }

    struct PortMapHelper(NodePortConnections);

    impl<'de> Deserialize<'de> for PortMapHelper {
        fn deserialize<D2: Deserializer<'de>>(d: D2) -> Result<Self, D2::Error> {
            struct PortMapVisitor;
            impl<'de> Visitor<'de> for PortMapVisitor {
                type Value = PortMapHelper;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a map of port types to branch arrays")
                }

                fn visit_map<M2>(self, mut map: M2) -> Result<Self::Value, M2::Error>
                where
                    M2: MapAccess<'de>,
                {
                    let mut ports = IndexMap::with_capacity(map.size_hint().unwrap_or(0));
                    while let Some((port_kind, branches)) =
                        map.next_entry::<PortKind, NullableBranchVec>()?
                    {
                        ports.insert(port_kind, branches.0);
                    }
                    Ok(PortMapHelper(ports))
                }
            }
            d.deserialize_map(PortMapVisitor)
        }
    }

    struct NullableBranchVec(PortBranchList);

    impl<'de> Deserialize<'de> for NullableBranchVec {
        fn deserialize<D3: Deserializer<'de>>(d: D3) -> Result<Self, D3::Error> {
            struct BranchSeqVisitor;
            impl<'de> Visitor<'de> for BranchSeqVisitor {
                type Value = NullableBranchVec;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an array of connection branch arrays")
                }

                fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                where
                    S: SeqAccess<'de>,
                {
                    let mut branches = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(slot) = seq.next_element::<Option<Vec<ConnectionEdgeIr>>>()? {
                        branches.push(slot.unwrap_or_default());
                    }
                    Ok(NullableBranchVec(branches))
                }

                fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(NullableBranchVec(Vec::new()))
                }

                fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(NullableBranchVec(Vec::new()))
                }
            }
            d.deserialize_seq(BranchSeqVisitor)
        }
    }

    deserializer.deserialize_map(ConnectionsVisitor)
}

/// Lossless Intermediate Representation of an n8n workflow JSON document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowIr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_archived: Option<bool>,
    /// Current editable draft version identifier (`versionId`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// Currently published live version identifier (`activeVersionId`), distinct from draft `version_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_version_id: Option<String>,
    #[serde(default)]
    pub nodes: Vec<WorkflowNodeIr>,
    #[serde(default, deserialize_with = "deserialize_connections")]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub connections: IndexMap<String, NodePortConnections>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<BTreeMap<String, Value>>")]
    pub pin_data: Option<IndexMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_groups: Option<Vec<NodeGroupIr>>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub settings: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    /// Preserves all unknown/instance-specific top-level fields (`staticData`, `shared`, `createdAt`, etc.) byte-for-byte.
    #[serde(flatten, default)]
    #[schemars(with = "BTreeMap<String, Value>")]
    pub extra: IndexMap<String, Value>,
}

impl WorkflowIr {
    /// Parses a `WorkflowIr` from an untrusted JSON string without panicking.
    pub fn from_json_str(raw: &str) -> N8nResult<Self> {
        serde_json::from_str(raw).map_err(|e| {
            N8nError::validation("local", vec![], format!("invalid workflow JSON: {e}"))
        })
    }

    /// Parses a `WorkflowIr` from a `serde_json::Value`.
    pub fn from_json_value(val: Value) -> N8nResult<Self> {
        serde_json::from_value(val).map_err(|e| {
            N8nError::validation("local", vec![], format!("invalid workflow JSON: {e}"))
        })
    }

    /// Serializes this `WorkflowIr` back into a `serde_json::Value` preserving field order and `extra`.
    pub fn to_json_value(&self) -> N8nResult<Value> {
        serde_json::to_value(self)
            .map_err(|e| N8nError::protocol(format!("failed serializing WorkflowIr: {e}")))
    }

    /// Serializes this `WorkflowIr` to compact JSON.
    pub fn to_json_string(&self) -> N8nResult<String> {
        serde_json::to_string(self)
            .map_err(|e| N8nError::protocol(format!("failed serializing WorkflowIr: {e}")))
    }

    /// Serializes this `WorkflowIr` to pretty-printed JSON.
    pub fn to_json_string_pretty(&self) -> N8nResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| N8nError::protocol(format!("failed serializing WorkflowIr: {e}")))
    }

    /// Looks up a node by exact display `name`.
    #[must_use]
    pub fn node_by_name(&self, name: &str) -> Option<&WorkflowNodeIr> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Looks up a mutable node by exact display `name`.
    pub fn node_by_name_mut(&mut self, name: &str) -> Option<&mut WorkflowNodeIr> {
        self.nodes.iter_mut().find(|n| n.name == name)
    }

    /// Looks up a node by stable `id`.
    #[must_use]
    pub fn node_by_id(&self, id: &str) -> Option<&WorkflowNodeIr> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Returns `true` when the draft `version_id` differs from the live `active_version_id`.
    #[must_use]
    pub fn has_unpublished_draft_changes(&self) -> bool {
        match (&self.version_id, &self.active_version_id) {
            (Some(draft), Some(live)) => draft != live,
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// Computes a deterministic 64-character hex `BLAKE3` digest over the canonicalized workflow JSON
    /// (recursively sorting object keys so semantically identical JSON maps produce identical hashes).
    #[must_use]
    pub fn canonical_version_hash(&self) -> String {
        let value = serde_json::to_value(self).unwrap_or(Value::Null);
        canonical_blake3_json_hex(&value, "n8n-rs-mcp/v2/workflow-canonical-version-hash")
    }
}

/// Computes a domain-separated `BLAKE3` hex digest over a canonicalized `serde_json::Value`.
#[must_use]
pub fn canonical_blake3_json_hex(value: &Value, domain_context: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(domain_context);
    hash_canonical_value(&mut hasher, value);
    hasher.finalize().to_hex().to_string()
}

fn hash_canonical_value(hasher: &mut blake3::Hasher, value: &Value) {
    match value {
        Value::Null => {
            hasher.update(b"N");
        }
        Value::Bool(true) => {
            hasher.update(b"T");
        }
        Value::Bool(false) => {
            hasher.update(b"F");
        }
        Value::Number(n) => {
            hasher.update(b"#");
            if let Some(i) = n.as_i64() {
                hasher.update(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                hasher.update(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                let norm = if f == 0.0 { 0.0 } else { f };
                if norm.is_finite()
                    && norm.fract() == 0.0
                    && norm >= (i64::MIN as f64)
                    && norm <= (i64::MAX as f64)
                {
                    #[allow(clippy::cast_possible_truncation)]
                    hasher.update((norm as i64).to_string().as_bytes());
                } else {
                    hasher.update(norm.to_string().as_bytes());
                }
            }
            hasher.update(b";");
        }
        Value::String(s) => {
            hasher.update(b"S");
            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());
        }
        Value::Array(items) => {
            hasher.update(b"[");
            hasher.update(&(items.len() as u64).to_le_bytes());
            for item in items {
                hash_canonical_value(hasher, item);
            }
            hasher.update(b"]");
        }
        Value::Object(map) => {
            hasher.update(b"{");
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            hasher.update(&(keys.len() as u64).to_le_bytes());
            for k in keys {
                hasher.update(&(k.len() as u64).to_le_bytes());
                hasher.update(k.as_bytes());
                if let Some(v) = map.get(k) {
                    hash_canonical_value(hasher, v);
                }
            }
            hasher.update(b"}");
        }
    }
}
