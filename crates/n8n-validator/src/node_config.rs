//! Schema-driven per-node configuration validator backed by `n8n_catalog_db::CatalogDb`.

use n8n_catalog_db::{
    CatalogDb, EffectiveNodeInspection, EffectiveProperty, NodeInfoMode, NodeInfoRequest,
    SchemaConfidence, json_values_equal,
};
use n8n_graph::WorkflowNodeIr;
use n8n_types::N8nResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ast::analyze_js_code_script;
use crate::expressions::{CODE_LIKE_EXPRESSION_GUIDANCE, analyze_template_expression};
use crate::workflow::ValidationStrength;

/// Validation strictness profile modeled after V2 Section 7.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProfile {
    /// Checks only basic structural, version, and JS/expression syntax validity.
    Minimal,
    /// Enforces runtime-critical `displayOptions` required properties, enum bounds, credentials,
    /// JS syntax, and V2 `Why Code:` rationale.
    Runtime,
    /// Default agent profile: `Runtime` plus native-first guidance and inline expression lints.
    #[default]
    #[serde(alias = "ai-friendly", alias = "aiFriendly")]
    AiFriendly,
    /// Promotes unknown/inactive parameter warnings and strict `typeVersion` catalog bounds.
    Strict,
}

/// Severity of a node-level validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Error,
    Warning,
    Suggestion,
}

/// Structured issue reported for a single node configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeValidationIssue {
    pub severity: ValidationSeverity,
    pub code: String,
    pub node_id: String,
    pub node_name: String,
    pub field_path: Option<String>,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Validation report for a single workflow node against `CatalogDb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeValidationReport {
    pub valid: bool,
    pub node_id: String,
    pub node_name: String,
    pub node_type: String,
    pub resolved_type_version: Option<String>,
    pub schema_confidence: SchemaConfidence,
    /// `"authoritative"` or `"partial"` compatibility label.
    pub validation_confidence: String,
    pub strength: ValidationStrength,
    pub profile: ValidationProfile,
    pub error_codes: Vec<String>,
    pub warning_codes: Vec<String>,
    pub issues: Vec<NodeValidationIssue>,
    pub guidance_hints: Vec<String>,
}

/// Checks whether a `Code` node's `notes` field satisfies the V2 `Why Code:` governance rule.
#[must_use]
pub fn code_node_has_why_rationale(notes: Option<&str>) -> bool {
    notes
        .map(str::trim_start)
        .is_some_and(|trimmed| trimmed.starts_with("Why Code:"))
}

/// Validates a raw node JSON value against `CatalogDb`.
///
/// # Errors
/// Returns `N8nError` if `node_json` cannot be parsed as a `WorkflowNodeIr` or catalog query fails.
pub fn validate_node_json(
    node_json: &Value,
    catalog: &CatalogDb,
    profile: ValidationProfile,
) -> N8nResult<NodeValidationReport> {
    let node: WorkflowNodeIr = serde_json::from_value(node_json.clone()).map_err(|err| {
        n8n_types::N8nError::validation("local", None, format!("Invalid node JSON payload: {err}"))
    })?;
    validate_node_config(&node, catalog, profile)
}

/// Validates a single `WorkflowNodeIr` against `CatalogDb` using `inspect_effective_node_fields`.
///
/// # Errors
/// Returns `N8nError` only if an underlying SQLite query against `CatalogDb` fails.
pub fn validate_node_config(
    node: &WorkflowNodeIr,
    catalog: &CatalogDb,
    profile: ValidationProfile,
) -> N8nResult<NodeValidationReport> {
    let requested_version = node.type_version_string();
    let info = catalog.get_node_info(&NodeInfoRequest {
        node_type: node.node_type.clone(),
        mode: NodeInfoMode::Info,
        type_version: Some(requested_version.clone()),
        property_query: None,
    })?;
    let inspection = catalog.inspect_effective_node_fields(
        &node.node_type,
        Some(requested_version.as_str()),
        &node.parameters,
    )?;

    let strength = match inspection.schema_confidence {
        SchemaConfidence::AuthoritativeCatalog => ValidationStrength::OfflineAuthoritative,
        SchemaConfidence::UnknownOrCommunityPartial => ValidationStrength::OfflinePartialSchema,
    };
    let validation_confidence = inspection
        .schema_confidence
        .as_validation_label()
        .to_owned();

    let mut issues = Vec::new();

    if !info.found_in_catalog {
        issues.push(NodeValidationIssue {
            severity: ValidationSeverity::Warning,
            code: "unknown_node_type_partial_validation".to_owned(),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            field_path: Some("/type".to_owned()),
            message: format!(
                "Node type `{}` is not in the bundled authoritative catalog; community/custom node validated with partial schema confidence.",
                node.node_type
            ),
            suggestion: Some(
                "Verify runtime schema via live instance MCP bridge when available.".to_owned(),
            ),
        });
    } else if !info.version_in_catalog {
        validate_version_bounds(node, &info.versions, profile, &mut issues);
    }

    if info.found_in_catalog && info.version_in_catalog && profile != ValidationProfile::Minimal {
        validate_visible_enum_options(node, &inspection, &mut issues);
        validate_missing_required_properties(node, &inspection, &mut issues);
        validate_credentials(node, catalog, &inspection, &mut issues)?;

        if profile == ValidationProfile::Strict {
            for unknown in &inspection.unknown_parameter_warnings {
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "unknown_parameter".to_owned(),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some("/parameters".to_owned()),
                    message: unknown.clone(),
                    suggestion: None,
                });
            }
            for inactive in &inspection.inactive_parameter_warnings {
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "inactive_parameter".to_owned(),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some("/parameters".to_owned()),
                    message: inactive.clone(),
                    suggestion: None,
                });
            }
        }
    }

    // Code node governance & JS AST syntax check.
    if is_code_node_type(&node.node_type) {
        validate_code_node(node, &inspection, profile, &mut issues);
    }

    // Parameter inline expression syntax & complexity checks.
    validate_parameter_expressions(node, &node.parameters, "/parameters", profile, &mut issues);

    let mut error_codes = Vec::new();
    let mut warning_codes = Vec::new();
    for issue in &issues {
        match issue.severity {
            ValidationSeverity::Error => {
                if !error_codes.contains(&issue.code) {
                    error_codes.push(issue.code.clone());
                }
            }
            ValidationSeverity::Warning | ValidationSeverity::Suggestion => {
                if !warning_codes.contains(&issue.code) {
                    warning_codes.push(issue.code.clone());
                }
            }
        }
    }

    Ok(NodeValidationReport {
        valid: error_codes.is_empty(),
        node_id: node.id.clone(),
        node_name: node.name.clone(),
        node_type: node.node_type.clone(),
        resolved_type_version: inspection.resolved_type_version,
        schema_confidence: inspection.schema_confidence,
        validation_confidence,
        strength,
        profile,
        error_codes,
        warning_codes,
        issues,
        guidance_hints: inspection.guidance_hints,
    })
}

fn is_code_node_type(node_type: &str) -> bool {
    matches!(
        node_type,
        "n8n-nodes-base.code" | "@n8n/n8n-nodes-langchain.toolCode"
    )
}

fn validate_version_bounds(
    node: &WorkflowNodeIr,
    versions: &[n8n_catalog_db::NodeVersionRecord],
    profile: ValidationProfile,
    issues: &mut Vec<NodeValidationIssue>,
) {
    let requested_num = node.type_version_f64();
    let numeric_versions: Vec<f64> = versions
        .iter()
        .filter_map(|v| v.type_version.parse::<f64>().ok())
        .collect();

    if let (Some(req), Some(min_v), Some(max_v)) = (
        requested_num,
        numeric_versions.iter().copied().reduce(f64::min),
        numeric_versions.iter().copied().reduce(f64::max),
    ) && req <= 0.0
    {
        issues.push(NodeValidationIssue {
            severity: ValidationSeverity::Error,
            code: "invalid_type_version".to_owned(),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            field_path: Some("/typeVersion".to_owned()),
            message: format!(
                "Node `{}` specifies non-positive typeVersion `{req}` (catalog range {min_v}..={max_v}).",
                node.name
            ),
            suggestion: Some(format!("Use catalog version `{max_v}`.")),
        });
        return;
    }

    let severity = if profile == ValidationProfile::Strict {
        ValidationSeverity::Error
    } else {
        ValidationSeverity::Warning
    };
    issues.push(NodeValidationIssue {
        severity,
        code: "unseen_type_version_partial_validation".to_owned(),
        node_id: node.id.clone(),
        node_name: node.name.clone(),
        field_path: Some("/typeVersion".to_owned()),
        message: format!(
            "Node `{}` uses typeVersion `{}` not present in the bundled catalog; falling back to closest schema with partial confidence.",
            node.name,
            node.type_version_string()
        ),
        suggestion: None,
    });
}

fn validate_visible_enum_options(
    node: &WorkflowNodeIr,
    inspection: &EffectiveNodeInspection,
    issues: &mut Vec<NodeValidationIssue>,
) {
    let all_visible = inspection
        .visible_required_properties
        .iter()
        .chain(inspection.visible_optional_properties.iter());

    for prop in all_visible {
        check_property_enum_value(node, prop, issues);
    }
}

fn check_property_enum_value(
    node: &WorkflowNodeIr,
    prop: &EffectiveProperty,
    issues: &mut Vec<NodeValidationIssue>,
) {
    let Some(current) = &prop.current_value else {
        return;
    };
    let Some(nested) = &prop.nested else {
        return;
    };
    if nested.enum_options.is_empty() {
        return;
    }

    // Expressions starting with `=` are computed at runtime and bypass static enum comparison.
    if current.as_str().is_some_and(|s| s.starts_with('=')) {
        return;
    }

    match prop.prop_type.as_str() {
        "options" => {
            let valid = nested
                .enum_options
                .iter()
                .any(|allowed| json_values_equal(&allowed.value, current));
            if !valid {
                let allowed_preview: Vec<String> = nested
                    .enum_options
                    .iter()
                    .take(8)
                    .map(|o| o.value.to_string())
                    .collect();
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: format!("invalid_option_value:{}", prop.name),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some(format!("/parameters/{}", prop.name)),
                    message: format!(
                        "Parameter `{}` on node `{}` has invalid option value `{current}` (allowed: {}).",
                        prop.name,
                        node.name,
                        allowed_preview.join(", ")
                    ),
                    suggestion: None,
                });
            }
        }
        "multiOptions" => match current {
            Value::Array(items) => {
                let all_valid = items.iter().all(|item| {
                    item.as_str().is_some_and(|s| s.starts_with('='))
                        || nested
                            .enum_options
                            .iter()
                            .any(|allowed| json_values_equal(&allowed.value, item))
                });
                if !all_valid {
                    issues.push(NodeValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: format!("invalid_option_value:{}", prop.name),
                        node_id: node.id.clone(),
                        node_name: node.name.clone(),
                        field_path: Some(format!("/parameters/{}", prop.name)),
                        message: format!(
                            "Parameter `{}` on node `{}` contains an invalid multiOptions entry.",
                            prop.name, node.name
                        ),
                        suggestion: None,
                    });
                }
            }
            _ => {
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: format!("invalid_option_value:{}", prop.name),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some(format!("/parameters/{}", prop.name)),
                    message: format!(
                        "Parameter `{}` on node `{}` expects an array of option values.",
                        prop.name, node.name
                    ),
                    suggestion: None,
                });
            }
        },
        _ => {}
    }
}

fn validate_missing_required_properties(
    node: &WorkflowNodeIr,
    inspection: &EffectiveNodeInspection,
    issues: &mut Vec<NodeValidationIssue>,
) {
    for prop_name in &inspection.missing_required_properties {
        issues.push(NodeValidationIssue {
            severity: ValidationSeverity::Error,
            code: format!("missing_required_property:{prop_name}"),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            field_path: Some(format!("/parameters/{prop_name}")),
            message: format!(
                "Required parameter `{prop_name}` is missing or empty on node `{}` (`{}`).",
                node.name, node.node_type
            ),
            suggestion: None,
        });
    }
}

fn validate_credentials(
    node: &WorkflowNodeIr,
    catalog: &CatalogDb,
    inspection: &EffectiveNodeInspection,
    issues: &mut Vec<NodeValidationIssue>,
) -> N8nResult<()> {
    let mut allowed_names: Vec<String> = inspection
        .allowed_credentials
        .iter()
        .map(|c| c.credential_type.clone())
        .collect();
    let mut required_names: Vec<String> = inspection
        .allowed_credentials
        .iter()
        .filter(|c| c.required)
        .map(|c| c.credential_type.clone())
        .collect();

    // Handle HTTP Request `authentication = "genericCredentialType"` + `genericAuthType`.
    if let Some(auth_mode) = inspection
        .effective_values
        .get("authentication")
        .and_then(Value::as_str)
        && auth_mode == "genericCredentialType"
        && let Some(generic_type) = inspection
            .effective_values
            .get("genericAuthType")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !s.starts_with('='))
    {
        let is_known_generic = catalog
            .get_credential_type(generic_type)?
            .is_some_and(|schema| {
                schema.is_generic || schema.supported_nodes.iter().any(|n| n == &node.node_type)
            });
        if is_known_generic || !allowed_names.iter().any(|n| n == generic_type) {
            if !allowed_names.iter().any(|n| n == generic_type) {
                allowed_names.push(generic_type.to_owned());
            }
            if !required_names.iter().any(|n| n == generic_type) {
                required_names.push(generic_type.to_owned());
            }
        }
    }

    let bound_keys: Vec<String> = node
        .credentials
        .as_ref()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();

    // 1. Flag bound credentials that are incompatible with this node's active / declared schema.
    for cred_key in &bound_keys {
        let in_active = allowed_names.iter().any(|a| a == cred_key);
        let in_declared = inspection
            .all_declared_credentials
            .iter()
            .any(|c| &c.credential_type == cred_key);

        let compatible = if !allowed_names.is_empty() {
            in_active
        } else {
            in_declared
        };

        if !compatible {
            issues.push(NodeValidationIssue {
                severity: ValidationSeverity::Error,
                code: format!("incompatible_credential_type:{cred_key}"),
                node_id: node.id.clone(),
                node_name: node.name.clone(),
                field_path: Some(format!("/credentials/{cred_key}")),
                message: format!(
                    "Credential type `{cred_key}` is incompatible with node `{}` (`{}`).",
                    node.name, node.node_type
                ),
                suggestion: (!allowed_names.is_empty())
                    .then(|| format!("Allowed credential types: {}", allowed_names.join(", "))),
            });
        }
    }

    // 2. Ensure at least one required active credential is bound when required_names is non-empty.
    if !required_names.is_empty() {
        let satisfied = required_names
            .iter()
            .any(|req| bound_keys.iter().any(|bound| bound == req));
        if !satisfied {
            let primary_missing = &required_names[0];
            issues.push(NodeValidationIssue {
                severity: ValidationSeverity::Error,
                code: format!("missing_required_credential:{primary_missing}"),
                node_id: node.id.clone(),
                node_name: node.name.clone(),
                field_path: Some("/credentials".to_owned()),
                message: format!(
                    "Node `{}` (`{}`) requires credential `{primary_missing}`.",
                    node.name, node.node_type
                ),
                suggestion: Some(format!(
                    "Bind a `{primary_missing}` credential reference (`id` + `name`)."
                )),
            });
        }
    }

    Ok(())
}

fn validate_code_node(
    node: &WorkflowNodeIr,
    inspection: &EffectiveNodeInspection,
    profile: ValidationProfile,
    issues: &mut Vec<NodeValidationIssue>,
) {
    if profile != ValidationProfile::Minimal && !code_node_has_why_rationale(node.notes.as_deref())
    {
        issues.push(NodeValidationIssue {
            severity: ValidationSeverity::Warning,
            code: "native_first_code_rationale_missing".to_owned(),
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            field_path: Some("/notes".to_owned()),
            message: format!(
                "Code node `{}` lacks a `Why Code:` rationale in `notes`.",
                node.name
            ),
            suggestion: Some(
                "Prefer native nodes (Edit Fields, Filter, IF, Switch, Merge, Aggregate, Summarize, Date & Time) when possible; otherwise start `notes` with `Why Code: <reason>`."
                    .to_owned(),
            ),
        });
    }

    let effective_lang = inspection
        .effective_values
        .get("language")
        .and_then(Value::as_str)
        .or_else(|| node.parameters.get("language").and_then(Value::as_str))
        .unwrap_or("javaScript");

    if matches!(effective_lang, "javaScript" | "javascript")
        && let Some(js_code) = node
            .parameters
            .get("jsCode")
            .or_else(|| node.parameters.get("code"))
            .and_then(Value::as_str)
        && !js_code.trim().is_empty()
    {
        let ast = analyze_js_code_script(js_code);
        if !ast.valid_syntax {
            let detail = ast
                .diagnostics
                .first()
                .map_or("JavaScript syntax error", |d| d.message.as_str());
            issues.push(NodeValidationIssue {
                severity: ValidationSeverity::Error,
                code: "invalid_code_syntax".to_owned(),
                node_id: node.id.clone(),
                node_name: node.name.clone(),
                field_path: Some("/parameters/jsCode".to_owned()),
                message: format!(
                    "JavaScript syntax error in Code node `{}`: {detail}",
                    node.name
                ),
                suggestion: None,
            });
        }
    }
}

fn validate_parameter_expressions(
    node: &WorkflowNodeIr,
    value: &Value,
    pointer: &str,
    profile: ValidationProfile,
    issues: &mut Vec<NodeValidationIssue>,
) {
    match value {
        Value::String(s) if s.starts_with('=') => {
            let analysis = analyze_template_expression(s);
            if !analysis.valid_syntax {
                let msg = analysis
                    .diagnostics
                    .first()
                    .map_or("Invalid n8n expression syntax", |d| d.message.as_str());
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: format!("invalid_expression_syntax:{pointer}"),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some(pointer.to_owned()),
                    message: format!(
                        "Invalid expression at `{pointer}` on node `{}`: {msg}",
                        node.name
                    ),
                    suggestion: None,
                });
            } else if analysis.code_like_expression_warning && profile != ValidationProfile::Minimal
            {
                issues.push(NodeValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "code_like_expression".to_owned(),
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    field_path: Some(pointer.to_owned()),
                    message: format!(
                        "Inline expression at `{pointer}` on node `{}` contains multi-statement or function-body code.",
                        node.name
                    ),
                    suggestion: Some(CODE_LIKE_EXPRESSION_GUIDANCE.to_owned()),
                });
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let escaped = n8n_graph::escape_json_pointer_token(k);
                let next_ptr = format!("{pointer}/{escaped}");
                validate_parameter_expressions(node, child, &next_ptr, profile, issues);
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                let next_ptr = format!("{pointer}/{idx}");
                validate_parameter_expressions(node, child, &next_ptr, profile, issues);
            }
        }
        _ => {}
    }
}
