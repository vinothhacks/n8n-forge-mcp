//! Dynamic `tools/list` feature negotiation and partial `update_workflow` response inspector.

use std::collections::BTreeSet;

use n8n_types::{OperationStatus, redact_json_value, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Negotiated pin-data preparation tool name (renamed in n8n 2.34.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PinDataToolName {
    /// n8n >= 2.34.0 (`prepare_workflow_pin_data`)
    PrepareWorkflowPinData,
    /// n8n < 2.34.0 (`prepare_test_pin_data`)
    PrepareTestPinData,
    /// Neither tool advertised on this instance
    Unavailable,
}

impl PinDataToolName {
    #[must_use]
    pub const fn wire_name(self) -> Option<&'static str> {
        match self {
            Self::PrepareWorkflowPinData => Some("prepare_workflow_pin_data"),
            Self::PrepareTestPinData => Some("prepare_test_pin_data"),
            Self::Unavailable => None,
        }
    }
}

/// Sanitized descriptor of a single advertised tool from Native MCP `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDescriptor {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Value,
}

/// Negotiated Native MCP capability surface derived strictly from live `tools/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NegotiatedMcpTools {
    pub server_protocol_version: Option<String>,
    pub advertised_tool_names: BTreeSet<String>,
    pub pin_data_tool: PinDataToolName,
    pub has_validate_node_config: bool,
    pub has_validate_workflow: bool,
    pub has_create_workflow_from_code: bool,
    pub has_update_workflow: bool,
    pub has_test_workflow: bool,
    pub has_execute_workflow: bool,
    pub supports_trigger_node_name: bool,
    pub has_restore_workflow_version: bool,
    pub advertised_agent_tools: Vec<String>,
    /// Heuristic signal for n8n >= 2.47 protected instance mode: `execute_workflow` is present
    /// while mutating builder tools (`create_workflow_from_code`, `update_workflow`) are withheld.
    pub protected_instance_suspected: bool,
}

impl Default for NegotiatedMcpTools {
    fn default() -> Self {
        Self {
            server_protocol_version: None,
            advertised_tool_names: BTreeSet::new(),
            pin_data_tool: PinDataToolName::Unavailable,
            has_validate_node_config: false,
            has_validate_workflow: false,
            has_create_workflow_from_code: false,
            has_update_workflow: false,
            has_test_workflow: false,
            has_execute_workflow: false,
            supports_trigger_node_name: false,
            has_restore_workflow_version: false,
            advertised_agent_tools: Vec::new(),
            protected_instance_suspected: false,
        }
    }
}

/// Negotiates native MCP tool names and schema flags from raw `tools/list` descriptors.
#[must_use]
pub fn negotiate_tools(
    protocol_version: Option<String>,
    tools: &[McpToolDescriptor],
) -> NegotiatedMcpTools {
    let mut names = BTreeSet::new();
    let mut supports_trigger_node_name = false;
    let mut agent_tools = Vec::new();

    for tool in tools {
        names.insert(tool.name.clone());
        if tool.name == "execute_workflow" {
            supports_trigger_node_name = tool
                .input_schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|props| props.contains_key("triggerNodeName"));
        }
        let lower = tool.name.to_ascii_lowercase();
        if lower == "list_agents"
            || lower == "get_agent"
            || lower == "create_agent"
            || lower == "update_agent"
            || lower == "delete_agent"
            || lower.starts_with("agent_")
        {
            agent_tools.push(tool.name.clone());
        }
    }
    agent_tools.sort();

    let pin_data_tool = if names.contains("prepare_workflow_pin_data") {
        PinDataToolName::PrepareWorkflowPinData
    } else if names.contains("prepare_test_pin_data") {
        PinDataToolName::PrepareTestPinData
    } else {
        PinDataToolName::Unavailable
    };

    let has_validate_node_config = names.contains("validate_node_config");
    let has_validate_workflow = names.contains("validate_workflow");
    let has_create_workflow_from_code = names.contains("create_workflow_from_code");
    let has_update_workflow = names.contains("update_workflow");
    let has_test_workflow = names.contains("test_workflow");
    let has_execute_workflow = names.contains("execute_workflow");
    let has_restore_workflow_version = names.contains("restore_workflow_version");

    let protected_instance_suspected =
        has_execute_workflow && !has_create_workflow_from_code && !has_update_workflow;

    NegotiatedMcpTools {
        server_protocol_version: protocol_version,
        advertised_tool_names: names,
        pin_data_tool,
        has_validate_node_config,
        has_validate_workflow,
        has_create_workflow_from_code,
        has_update_workflow,
        has_test_workflow,
        has_execute_workflow,
        supports_trigger_node_name,
        has_restore_workflow_version,
        advertised_agent_tools: agent_tools,
        protected_instance_suspected,
    }
}

/// Sanitized credential reference auto-assigned by native MCP workflow builder tools (no secret values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoAssignedCredentialRef {
    pub node_name: String,
    pub credential_type: String,
    pub credential_id: Option<String>,
    pub credential_label: Option<String>,
}

/// Structured inspection report for native MCP partial `update_workflow` responses (n8n 2.20+ / 2.41+).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PartialUpdateInspection {
    pub derived_status: OperationStatus,
    pub skipped_operations: Vec<Value>,
    pub removed_groups: Vec<Value>,
    pub auto_assigned_credentials: Vec<AutoAssignedCredentialRef>,
    pub http_request_manual_binding_notes: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub sanitized_payload: Value,
}

/// Inspects a native MCP `update_workflow` or `create_workflow_from_code` payload so skipped
/// node-group operations, removed groups, and HTTP Request credential skips are surfaced honestly.
#[must_use]
pub fn inspect_partial_update_result(
    raw_result: &Value,
    touched_http_request_nodes: &[String],
) -> PartialUpdateInspection {
    let sanitized = redact_json_value(raw_result);

    let skipped_operations = sanitized
        .get("skippedOperations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let removed_groups = sanitized
        .get("removedGroups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut auto_assigned_credentials = Vec::new();
    if let Some(arr) = sanitized
        .get("autoAssignedCredentials")
        .and_then(Value::as_array)
    {
        for item in arr {
            let node_name = item
                .get("nodeName")
                .or_else(|| item.get("node"))
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
                .to_owned();
            let credential_type = item
                .get("credentialType")
                .or_else(|| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
                .to_owned();
            let credential_id = item
                .get("credentialId")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .map(redact_str);
            let credential_label = item
                .get("credentialName")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .map(redact_str);
            auto_assigned_credentials.push(AutoAssignedCredentialRef {
                node_name: redact_str(&node_name),
                credential_type: redact_str(&credential_type),
                credential_id,
                credential_label,
            });
        }
    }

    let mut warnings: Vec<String> = sanitized
        .get("warnings")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(redact_str)
                .collect()
        })
        .unwrap_or_default();

    let errors: Vec<String> = sanitized
        .get("errors")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(redact_str)
                .collect()
        })
        .unwrap_or_default();

    let mut http_request_manual_binding_notes = Vec::new();
    let mentions_http_skip = warnings.iter().any(|w| {
        let lower = w.to_ascii_lowercase();
        lower.contains("http request") || lower.contains("httprequest")
    });

    if mentions_http_skip || !touched_http_request_nodes.is_empty() {
        for node_name in touched_http_request_nodes {
            let already_assigned = auto_assigned_credentials
                .iter()
                .any(|c| c.node_name == *node_name);
            if !already_assigned {
                let note = format!(
                    "Native MCP skips automatic credential assignment on HTTP Request node `{}`; bind an approved credential reference explicitly via `bind_credential`.",
                    redact_str(node_name)
                );
                http_request_manual_binding_notes.push(note);
            }
        }
        if touched_http_request_nodes.is_empty() && mentions_http_skip {
            http_request_manual_binding_notes.push(
                "Native MCP reported skipped credential assignment on an HTTP Request node; bind an approved credential reference explicitly via `bind_credential`."
                    .to_owned(),
            );
        }
    }

    if !skipped_operations.is_empty() {
        warnings.push(format!(
            "{} operation(s) were skipped by n8n Native MCP (verify nodeGroups and graph state).",
            skipped_operations.len()
        ));
    }
    if !removed_groups.is_empty() {
        warnings.push(format!(
            "{} node group(s) were removed during partial update.",
            removed_groups.len()
        ));
    }

    let derived_status = if !errors.is_empty() {
        OperationStatus::Error
    } else if !skipped_operations.is_empty() || !removed_groups.is_empty() {
        OperationStatus::Partial
    } else {
        OperationStatus::Success
    };

    PartialUpdateInspection {
        derived_status,
        skipped_operations,
        removed_groups,
        auto_assigned_credentials,
        http_request_manual_binding_notes,
        warnings,
        errors,
        sanitized_payload: sanitized,
    }
}
