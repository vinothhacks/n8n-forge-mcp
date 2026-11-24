//! Bounded `diagnose -> inspect -> validate -> patch preview -> simulate` repair loop coordinator
//! and recursive secret-redacting execution data minimizer (V2 Section 8).
//!
//! Security & reliability invariants:
//! - Default `max_attempts = 3`, hard ceiling `5` ONLY with explicit per-session override.
//! - **Zero automatic retry** of real `T2 Manual` or `T3 Production` runs.
//! - Halts early on repeated identical error fingerprints (`BLAKE3`) or `Low` repair confidence.
//! - Execution data minimization defaults to [`ExecutionDetailLevel::Summary`], returning status,
//!   duration, failed node, error class, truncated redacted error message, and upstream item
//!   field/type schemas **without raw payload values**.
//! - [`ExecutionDetailLevel::NodeIo`] and [`ExecutionDetailLevel::Full`] require explicit reveal
//!   authorization, respect n8n `redactExecutionData`, enforce a strict 16 MiB cap, and apply
//!   recursive `n8n_types::redact_json_value` scrubbing before returning.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::LazyLock;

use chrono::DateTime;
use n8n_api_client::ExecutionResource;
use n8n_catalog_db::CatalogDb;
use n8n_graph::{
    GraphMutationOp, MutationContext, UpstreamDataShape, WorkflowGraph, WorkflowIr, apply_mutations,
};
use n8n_types::{
    BoundedDiffSummary, N8nError, N8nResult, RiskLevel, redact_json_value, redact_str,
};
use n8n_validator::{ValidationOptions, WorkflowValidationReport, validate_workflow};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::modes::{TestExecutionMode, TestOutcomeStatus, TestRunResult};

/// Pre-scrubs compound `Authorization: Bearer <token>` / `Authorization: Basic <token>` strings
/// (including cases where an upstream client already turned the scheme word into
/// `[REDACTED:HEADER_SECRET]`) before delegating to `n8n_types::redact_str`.
static AUTH_SCHEME_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(authorization|proxy-authorization)\s*([:=])\s*(?:\[redacted:header_secret\]|bearer|basic|token|digest|apikey)\s+([^\s"',;\r\n]+)"#,
    )
    .expect("valid static auth-scheme header regex")
});

fn scrub_execution_str(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let pre = AUTH_SCHEME_HEADER_RE.replace_all(input, "$1$2 [REDACTED:HEADER_SECRET]");
    redact_str(&pre)
}

fn pre_scrub_auth_headers_in_json(value: &Value, depth: usize) -> Value {
    if depth >= 64 {
        return Value::String("[REDACTED:MAX_DEPTH]".to_owned());
    }
    match value {
        Value::String(s) => Value::String(
            AUTH_SCHEME_HEADER_RE
                .replace_all(s, "$1$2 [REDACTED:HEADER_SECRET]")
                .into_owned(),
        ),
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| pre_scrub_auth_headers_in_json(v, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), pre_scrub_auth_headers_in_json(v, depth + 1));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn scrub_execution_json(value: &Value) -> Value {
    let pre = pre_scrub_auth_headers_in_json(value, 0);
    redact_json_value(&pre)
}

/// Default maximum automatic repair iterations in a single debugging loop.
pub const DEFAULT_MAX_REPAIR_ATTEMPTS: u8 = 3;

/// Absolute hard ceiling on automatic repair iterations even with explicit session override.
pub const ABSOLUTE_MAX_REPAIR_ATTEMPTS: u8 = 5;

/// Hard decompressed/materialized byte ceiling (16 MiB) for execution payload inspection.
pub const MAX_EXECUTION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum character count included in a summarized redacted execution error message.
pub const MAX_SUMMARY_ERROR_CHARS: usize = 512;

/// Maximum items per node included when `NodeIo` reveal is explicitly authorized.
pub const DEFAULT_MAX_NODE_IO_ITEMS: usize = 25;

// ============================================================================
// 1. Execution Data Minimizer (`Summary | NodeIo | Full`)
// ============================================================================

/// Verbosity tier for execution diagnostics (`Summary` by default; `NodeIo`/`Full` gated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDetailLevel {
    /// Safe default: status, duration, failed node, error class, truncated redacted message,
    /// and upstream item key/type schema shapes without raw payload values.
    #[default]
    Summary,
    /// Restricted: redacted per-node input/output item samples (requires explicit reveal authorization).
    NodeIo,
    /// Restricted: full execution `data` payload recursively scrubbed via `redact_json_value`
    /// and capped at 16 MiB (requires explicit reveal authorization).
    Full,
}

/// Policy and budget controls passed to [`summarize_execution_redacted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionMinimizeOptions {
    pub detail_level: ExecutionDetailLevel,
    /// Must be `true` to unlock `NodeIo` or `Full` payloads; never auto-enabled.
    pub reveal_authorized: bool,
    /// Mirrors n8n's instance/workflow `redactExecutionData` policy; when `true`, `NodeIo`/`Full` are denied.
    pub n8n_redact_execution_data: bool,
    /// Maximum allowed execution JSON size in bytes (clamped to <= `MAX_EXECUTION_PAYLOAD_BYTES` = 16 MiB).
    pub max_payload_bytes: usize,
    /// Maximum items retained per node in `NodeIo` mode.
    pub max_items_per_node: usize,
}

impl Default for ExecutionMinimizeOptions {
    fn default() -> Self {
        Self {
            detail_level: ExecutionDetailLevel::Summary,
            reveal_authorized: false,
            n8n_redact_execution_data: false,
            max_payload_bytes: MAX_EXECUTION_PAYLOAD_BYTES,
            max_items_per_node: DEFAULT_MAX_NODE_IO_ITEMS,
        }
    }
}

impl ExecutionMinimizeOptions {
    /// Convenience constructor for safe default `Summary` mode.
    #[must_use]
    pub fn summary_only() -> Self {
        Self::default()
    }

    /// Convenience constructor for explicitly authorized `NodeIo` or `Full` reveal.
    #[must_use]
    pub fn with_authorized_reveal(detail_level: ExecutionDetailLevel) -> Self {
        Self {
            detail_level,
            reveal_authorized: true,
            ..Self::default()
        }
    }
}

/// Redacted, size-bounded execution diagnostic summary produced by [`summarize_execution_redacted`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MinimizedExecutionReport {
    pub detail_level: ExecutionDetailLevel,
    pub execution_id: Option<String>,
    pub workflow_id: Option<String>,
    pub status: String,
    pub finished: bool,
    /// `true` ONLY when terminal status is `"success"` with no error (`"started"`/`"running"` is NEVER success!).
    pub is_terminal_success: bool,
    pub duration_ms: Option<u64>,
    pub failed_node: Option<String>,
    pub error_class: Option<String>,
    pub error_message_redacted: Option<String>,
    /// Map of `nodeName -> { fieldName -> jsonTypeName }` containing zero raw payload values!
    pub upstream_item_schemas: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_io: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_data: Option<Value>,
    pub redacted: bool,
    pub observed_payload_bytes: usize,
    pub notes: Vec<String>,
}

/// Summarizes a typed [`ExecutionResource`] through [`summarize_execution_redacted`].
pub fn summarize_execution_resource_redacted(
    execution: &ExecutionResource,
    options: &ExecutionMinimizeOptions,
) -> N8nResult<MinimizedExecutionReport> {
    let raw = serde_json::to_value(execution)
        .map_err(|e| N8nError::protocol(format!("failed serializing ExecutionResource: {e}")))?;
    summarize_execution_redacted(&raw, options)
}

/// Minimizes and recursively redacts raw n8n execution JSON according to V2 Section 8 rules.
#[allow(clippy::too_many_lines)]
pub fn summarize_execution_redacted(
    raw_execution: &Value,
    options: &ExecutionMinimizeOptions,
) -> N8nResult<MinimizedExecutionReport> {
    let effective_byte_cap = options
        .max_payload_bytes
        .clamp(1024, MAX_EXECUTION_PAYLOAD_BYTES);

    // 1. Gate `NodeIo` and `Full` behind explicit reveal authorization & n8n `redactExecutionData` policy!
    let payload_flagged_redacted = raw_execution
        .get("redactExecutionData")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || raw_execution
            .pointer("/data/redactExecutionData")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    if options.detail_level != ExecutionDetailLevel::Summary {
        if options.n8n_redact_execution_data || payload_flagged_redacted {
            return Err(N8nError::policy_blocked(
                "executions.reveal",
                RiskLevel::R3,
                "redact_execution_data",
                "n8n `redactExecutionData` policy is active for this execution; `node_io` and `full` payload reveal are prohibited",
                Some("Use `detail_level = \"summary\"` to inspect redacted schema shapes and error metadata.".to_owned()),
            ));
        }
        if !options.reveal_authorized {
            return Err(N8nError::policy_blocked(
                "executions.reveal",
                RiskLevel::R3,
                "execution_data_minimization",
                format!(
                    "Execution detail level `{:?}` is restricted and requires explicit user reveal authorization",
                    options.detail_level
                ),
                Some("Request explicit user approval before revealing `node_io` or `full` execution payloads.".to_owned()),
            ));
        }
    }

    // 2. Enforce strict 16 MiB cap before materializing/cloning large structures!
    let observed_bytes = estimate_json_bytes_bounded(raw_execution, effective_byte_cap + 1);
    if observed_bytes > effective_byte_cap {
        return Err(N8nError::payload_too_large(
            effective_byte_cap as u64,
            observed_bytes as u64,
            "execution_minimizer_16mib_cap",
        ));
    }

    let execution_id = raw_execution
        .get("id")
        .or_else(|| raw_execution.get("executionId"))
        .and_then(|v| match v {
            Value::String(s) => Some(scrub_execution_str(s)),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });

    let workflow_id = raw_execution.get("workflowId").and_then(|v| match v {
        Value::String(s) => Some(scrub_execution_str(s)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    });

    let error_obj = locate_error_object(raw_execution);
    let has_error = error_obj.is_some();

    let raw_status = raw_execution
        .get("status")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase());

    let explicit_finished = raw_execution.get("finished").and_then(Value::as_bool);

    let status = match raw_status.as_deref() {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            if has_error {
                "error".to_owned()
            } else if explicit_finished == Some(true) {
                "success".to_owned()
            } else if explicit_finished == Some(false) {
                "running".to_owned()
            } else {
                "unknown".to_owned()
            }
        }
    };

    let is_non_terminal_status = matches!(
        status.as_str(),
        "started" | "running" | "waiting" | "new" | "queued"
    );
    let finished = match explicit_finished {
        Some(f) => f && !is_non_terminal_status,
        None => !is_non_terminal_status && status != "unknown",
    };
    let is_terminal_success = finished && status == "success" && !has_error;

    let duration_ms = extract_duration_ms(raw_execution);
    let failed_node = extract_failed_node(raw_execution, error_obj, has_error || status == "error");
    let error_class = extract_error_class(error_obj, raw_execution);
    let (error_message_redacted, error_truncated) =
        extract_truncated_redacted_error(error_obj, raw_execution);

    let run_data_opt = locate_run_data(raw_execution);
    let upstream_item_schemas = extract_upstream_item_schemas(run_data_opt);

    let mut notes = Vec::new();
    if is_non_terminal_status {
        notes.push(format!(
            "Execution status `{status}` is non-terminal; `started`/`running` is NOT treated as `success`."
        ));
    }
    if error_truncated {
        notes.push(format!(
            "Error message truncated to {MAX_SUMMARY_ERROR_CHARS} characters after secret redaction."
        ));
    }

    let (node_io, full_data) = match options.detail_level {
        ExecutionDetailLevel::Summary => (None, None),
        ExecutionDetailLevel::NodeIo => {
            let io_val = extract_redacted_node_io(
                run_data_opt,
                options.max_items_per_node.clamp(1, 200),
                &mut notes,
            );
            (Some(io_val), None)
        }
        ExecutionDetailLevel::Full => {
            let target = raw_execution.get("data").unwrap_or(raw_execution);
            let scrubbed = scrub_execution_json(target);
            (None, Some(scrubbed))
        }
    };

    Ok(MinimizedExecutionReport {
        detail_level: options.detail_level,
        execution_id,
        workflow_id,
        status,
        finished,
        is_terminal_success,
        duration_ms,
        failed_node,
        error_class,
        error_message_redacted,
        upstream_item_schemas,
        node_io,
        full_data,
        redacted: true,
        observed_payload_bytes: observed_bytes,
        notes,
    })
}

fn estimate_json_bytes_bounded(value: &Value, ceiling: usize) -> usize {
    fn walk(v: &Value, acc: &mut usize, ceiling: usize) {
        if *acc >= ceiling {
            return;
        }
        match v {
            Value::Null => *acc = acc.saturating_add(4),
            Value::Bool(b) => *acc = acc.saturating_add(if *b { 4 } else { 5 }),
            Value::Number(n) => *acc = acc.saturating_add(n.to_string().len()),
            Value::String(s) => *acc = acc.saturating_add(s.len().saturating_add(2)),
            Value::Array(arr) => {
                *acc = acc.saturating_add(2);
                for item in arr {
                    walk(item, acc, ceiling);
                    if *acc >= ceiling {
                        return;
                    }
                    *acc = acc.saturating_add(1);
                }
            }
            Value::Object(map) => {
                *acc = acc.saturating_add(2);
                for (k, val) in map {
                    *acc = acc.saturating_add(k.len().saturating_add(4));
                    walk(val, acc, ceiling);
                    if *acc >= ceiling {
                        return;
                    }
                }
            }
        }
    }

    let mut total = 0_usize;
    walk(value, &mut total, ceiling);
    total
}

fn locate_error_object(raw: &Value) -> Option<&Value> {
    raw.pointer("/data/resultData/error")
        .filter(|v| !v.is_null())
        .or_else(|| raw.pointer("/resultData/error").filter(|v| !v.is_null()))
        .or_else(|| raw.get("error").filter(|v| !v.is_null()))
}

fn locate_run_data(raw: &Value) -> Option<&Map<String, Value>> {
    raw.pointer("/data/resultData/runData")
        .and_then(Value::as_object)
        .or_else(|| {
            raw.pointer("/resultData/runData")
                .and_then(Value::as_object)
        })
        .or_else(|| raw.get("runData").and_then(Value::as_object))
}

fn extract_duration_ms(raw: &Value) -> Option<u64> {
    if let Some(ms) = raw
        .get("durationMs")
        .or_else(|| raw.get("executionTime"))
        .and_then(Value::as_u64)
    {
        return Some(ms);
    }

    let started = raw.get("startedAt").and_then(Value::as_str)?;
    let stopped = raw.get("stoppedAt").and_then(Value::as_str)?;
    let start_dt = DateTime::parse_from_rfc3339(started).ok()?;
    let stop_dt = DateTime::parse_from_rfc3339(stopped).ok()?;
    let delta = stop_dt.signed_duration_since(start_dt).num_milliseconds();
    u64::try_from(delta.max(0)).ok()
}

fn extract_failed_node(raw: &Value, error_obj: Option<&Value>, is_failed: bool) -> Option<String> {
    if let Some(err) = error_obj {
        if let Some(name) = err.pointer("/node/name").and_then(Value::as_str) {
            return Some(scrub_execution_str(name));
        }
        if let Some(name) = err.get("node").and_then(Value::as_str) {
            return Some(scrub_execution_str(name));
        }
        if let Some(name) = err.get("nodeName").and_then(Value::as_str) {
            return Some(scrub_execution_str(name));
        }
    }

    if let Some(explicit) = raw.get("failedNode").and_then(Value::as_str) {
        return Some(scrub_execution_str(explicit));
    }

    if is_failed
        && let Some(last) = raw
            .pointer("/data/resultData/lastNodeExecuted")
            .or_else(|| raw.pointer("/resultData/lastNodeExecuted"))
            .and_then(Value::as_str)
    {
        return Some(scrub_execution_str(last));
    }

    None
}

fn extract_error_class(error_obj: Option<&Value>, raw: &Value) -> Option<String> {
    if let Some(err) = error_obj
        && let Some(cls) = err
            .get("name")
            .or_else(|| err.get("errorClass"))
            .or_else(|| err.get("code"))
            .or_else(|| err.get("httpCode"))
            .and_then(|v| match v {
                Value::String(s) if !s.trim().is_empty() => Some(scrub_execution_str(s.trim())),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
    {
        return Some(cls);
    }
    raw.get("errorClass")
        .and_then(Value::as_str)
        .map(scrub_execution_str)
}

fn extract_truncated_redacted_error(
    error_obj: Option<&Value>,
    raw: &Value,
) -> (Option<String>, bool) {
    let raw_msg = error_obj
        .and_then(|err| match err {
            Value::String(s) => Some(s.as_str()),
            Value::Object(_) => err
                .get("message")
                .or_else(|| err.get("description"))
                .and_then(Value::as_str),
            _ => None,
        })
        .or_else(|| raw.get("errorMessage").and_then(Value::as_str));

    let Some(msg) = raw_msg else {
        return (None, false);
    };

    // Redact over a wider window first so secrets straddling `MAX_SUMMARY_ERROR_CHARS` cannot leak half-tokens!
    let pre_window: String = msg.chars().take(MAX_SUMMARY_ERROR_CHARS * 8).collect();
    let scrubbed = scrub_execution_str(&pre_window);
    let char_count = scrubbed.chars().count();
    if char_count > MAX_SUMMARY_ERROR_CHARS {
        let truncated: String = scrubbed.chars().take(MAX_SUMMARY_ERROR_CHARS).collect();
        // Run `scrub_execution_str` a second time for defense-in-depth.
        (
            Some(format!("{}...[truncated]", scrub_execution_str(&truncated))),
            true,
        )
    } else {
        (
            Some(scrubbed),
            msg.chars().count() > pre_window.chars().count(),
        )
    }
}

/// Extracts ONLY `{ fieldName -> jsonType }` schemas per node from `runData` — NEVER raw values!
fn extract_upstream_item_schemas(
    run_data: Option<&Map<String, Value>>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut schemas = BTreeMap::new();
    let Some(rd) = run_data else {
        return schemas;
    };

    for (node_name, runs_val) in rd {
        let mut field_types = BTreeMap::new();
        let Some(runs_arr) = runs_val.as_array() else {
            continue;
        };

        for task_run in runs_arr.iter().take(5) {
            if let Some(main_branches) = task_run.pointer("/data/main").and_then(Value::as_array) {
                for branch in main_branches {
                    if let Some(items) = branch.as_array() {
                        for item in items.iter().take(25) {
                            let payload_obj = item
                                .get("json")
                                .and_then(Value::as_object)
                                .or_else(|| item.as_object());
                            if let Some(obj) = payload_obj {
                                for (k, v) in obj {
                                    let safe_key = scrub_execution_str(k);
                                    field_types
                                        .entry(safe_key)
                                        .or_insert_with(|| json_value_type_name(v).to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }

        schemas.insert(scrub_execution_str(node_name), field_types);
    }

    schemas
}

fn extract_redacted_node_io(
    run_data: Option<&Map<String, Value>>,
    max_items_per_node: usize,
    notes: &mut Vec<String>,
) -> Value {
    let Some(rd) = run_data else {
        return json!({});
    };

    let mut out = Map::new();
    for (node_name, runs_val) in rd {
        let mut collected_items = Vec::new();
        let mut truncated_for_node = false;

        if let Some(runs_arr) = runs_val.as_array() {
            for task_run in runs_arr {
                if let Some(main_branches) =
                    task_run.pointer("/data/main").and_then(Value::as_array)
                {
                    for branch in main_branches {
                        if let Some(items) = branch.as_array() {
                            for item in items {
                                if collected_items.len() >= max_items_per_node {
                                    truncated_for_node = true;
                                    break;
                                }
                                let json_part = item.get("json").unwrap_or(item);
                                collected_items.push(scrub_execution_json(json_part));
                            }
                        }
                    }
                }
            }
        }

        if truncated_for_node {
            notes.push(format!(
                "Node `{}` output items capped at {max_items_per_node} items in `node_io` view.",
                redact_str(node_name)
            ));
        }

        out.insert(
            redact_str(node_name),
            json!({
                "items": collected_items,
                "truncated": truncated_for_node,
            }),
        );
    }

    Value::Object(out)
}

const fn json_value_type_name(val: &Value) -> &'static str {
    match val {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ============================================================================
// 2. Bounded Diagnose -> Inspect -> Validate -> Patch Preview -> Simulate Loop
// ============================================================================

/// Confidence score declared for a proposed repair candidate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RepairConfidence {
    Low,
    Medium,
    High,
}

/// Ordered stages inside each bounded repair iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepairStage {
    Diagnose,
    Inspect,
    Validate,
    PatchPreview,
    Simulate,
}

/// Configuration for [`RepairLoopState`] and [`run_bounded_repair_loop`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairLoopConfig {
    pub max_attempts: u8,
    pub session_override_approved: bool,
    pub min_confidence: RepairConfidence,
    pub halt_on_identical_error_fingerprint: bool,
}

impl Default for RepairLoopConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_REPAIR_ATTEMPTS,
            session_override_approved: false,
            min_confidence: RepairConfidence::Medium,
            halt_on_identical_error_fingerprint: true,
        }
    }
}

impl RepairLoopConfig {
    /// Builds and validates a [`RepairLoopConfig`]:
    /// - `1..=3` allowed by default
    /// - `4..=5` requires `session_override_approved == true`
    /// - `0` or `> 5` rejected fail-closed!
    pub fn new(requested_max_attempts: u8, session_override_approved: bool) -> N8nResult<Self> {
        let cfg = Self {
            max_attempts: requested_max_attempts,
            session_override_approved,
            ..Self::default()
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> N8nResult<()> {
        if self.max_attempts == 0 {
            return Err(N8nError::validation(
                "local",
                vec!["`max_attempts` must be >= 1".to_owned()],
                "invalid repair loop configuration",
            ));
        }
        if self.max_attempts > ABSOLUTE_MAX_REPAIR_ATTEMPTS {
            return Err(N8nError::policy_blocked(
                "repair_loop.configure",
                RiskLevel::R2,
                "repair_loop_hard_ceiling",
                format!(
                    "Requested `max_attempts = {}` exceeds absolute hard ceiling ({ABSOLUTE_MAX_REPAIR_ATTEMPTS})",
                    self.max_attempts
                ),
                Some(format!(
                    "Use `max_attempts <= {DEFAULT_MAX_REPAIR_ATTEMPTS}` (or `<= {ABSOLUTE_MAX_REPAIR_ATTEMPTS}` with explicit session override)."
                )),
            ));
        }
        if self.max_attempts > DEFAULT_MAX_REPAIR_ATTEMPTS && !self.session_override_approved {
            return Err(N8nError::policy_blocked(
                "repair_loop.configure",
                RiskLevel::R2,
                "repair_loop_default_cap",
                format!(
                    "Requested `max_attempts = {}` exceeds default cap ({DEFAULT_MAX_REPAIR_ATTEMPTS}) without explicit per-session override",
                    self.max_attempts
                ),
                Some("Enable `session_override_approved = true` for up to 5 attempts.".to_owned()),
            ));
        }
        Ok(())
    }
}

/// Terminal or intermediate status of [`RepairLoopState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepairLoopStatus {
    InProgress,
    Resolved,
    Halted,
}

/// Reason why the bounded repair loop stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepairHaltReason {
    /// Candidate patch validated cleanly and passed safe `T0`/`T1` verification.
    Resolved { attempts_used: u8 },
    /// Configured `max_attempts` budget exhausted (`3` default, `5` max).
    MaxAttemptsReached { attempts_used: u8, max_attempts: u8 },
    /// Two attempts yielded the exact same failure fingerprint — stopped early instead of looping blindly.
    RepeatedIdenticalErrorFingerprint { fingerprint: String },
    /// Candidate repair confidence fell below `min_confidence` (or zero mutations proposed).
    LowConfidence {
        observed: RepairConfidence,
        minimum_required: RepairConfidence,
        diagnostic_note: String,
    },
    /// Attempted to run/retry `T2 Manual` or `T3 Production` inside the automated repair loop!
    RealExecutionRetryForbidden { attempted_mode: TestExecutionMode },
    /// Candidate patch failed offline structural/schema/expression validation.
    ValidationFailedAfterPatch { error_codes: Vec<String> },
    /// Safe simulation (`T1`) was blocked by the side-effect safety gate or unsupported without Native MCP.
    SimulationBlockedOrUnsupported { reason: String },
}

/// Proposed surgical graph fix produced during an iteration of [`run_bounded_repair_loop`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairCandidateProposal {
    pub confidence: RepairConfidence,
    pub rationale: String,
    pub mutations: Vec<GraphMutationOp>,
    /// Safe test mode to verify the candidate (`ValidateOnly` or `Simulate` ONLY; `Manual`/`Production` rejected!).
    pub verification_mode: TestExecutionMode,
}

/// Sanitized inspection context provided to the repair proposer for the failing node.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairInspectionContext {
    pub attempt: u8,
    pub execution_summary: MinimizedExecutionReport,
    pub error_fingerprint: String,
    pub upstream_data_shape: Option<UpstreamDataShape>,
    pub current_validation: WorkflowValidationReport,
}

/// Audit record of a single bounded repair iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairAttemptRecord {
    pub attempt: u8,
    pub stages_completed: Vec<RepairStage>,
    pub error_fingerprint: String,
    pub failed_node: Option<String>,
    pub error_class: Option<String>,
    pub confidence: Option<RepairConfidence>,
    pub rationale: Option<String>,
    pub patch_preview: Option<BoundedDiffSummary>,
    pub validation_passed: Option<bool>,
    pub simulation_mode: Option<TestExecutionMode>,
    pub simulation_status: Option<TestOutcomeStatus>,
}

/// Stateful coordinator enforcing V2 Section 8 repair loop bounds, error-fingerprint deduplication,
/// confidence thresholds, and the zero-real-retry rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairLoopState {
    pub config: RepairLoopConfig,
    pub status: RepairLoopStatus,
    pub attempts_used: u8,
    pub seen_error_fingerprints: Vec<String>,
    pub attempts: Vec<RepairAttemptRecord>,
    pub halt_reason: Option<RepairHaltReason>,
    pub human_review_required_before_live_or_publish: bool,
}

impl RepairLoopState {
    /// Initializes a validated [`RepairLoopState`].
    pub fn new(config: RepairLoopConfig) -> N8nResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            status: RepairLoopStatus::InProgress,
            attempts_used: 0,
            seen_error_fingerprints: Vec::new(),
            attempts: Vec::new(),
            halt_reason: None,
            human_review_required_before_live_or_publish: true,
        })
    }

    /// Computes a deterministic `BLAKE3` fingerprint over `(failed_node, error_class, redacted_error_message, upstream_schema)`.
    #[must_use]
    pub fn compute_error_fingerprint(summary: &MinimizedExecutionReport) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("n8n-rs-mcp/v2/repair-error-fingerprint");
        update_lp(
            &mut hasher,
            summary.failed_node.as_deref().unwrap_or("<none>"),
        );
        update_lp(
            &mut hasher,
            summary.error_class.as_deref().unwrap_or("<none>"),
        );
        update_lp(
            &mut hasher,
            summary
                .error_message_redacted
                .as_deref()
                .unwrap_or("<none>"),
        );
        if let Ok(schema_bytes) = serde_json::to_vec(&summary.upstream_item_schemas) {
            hasher.update(&(schema_bytes.len() as u64).to_le_bytes());
            hasher.update(&schema_bytes);
        }
        format!("errfp_{}", &hasher.finalize().to_hex()[..32])
    }

    /// Enforces that `mode` is NEVER `Manual` (`T2`) or `Production` (`T3`) inside an automated repair loop.
    pub fn ensure_safe_verification_mode(&mut self, mode: TestExecutionMode) -> N8nResult<()> {
        if matches!(
            mode,
            TestExecutionMode::Manual | TestExecutionMode::Production
        ) {
            let reason = RepairHaltReason::RealExecutionRetryForbidden {
                attempted_mode: mode,
            };
            self.status = RepairLoopStatus::Halted;
            self.halt_reason = Some(reason);
            return Err(N8nError::policy_blocked(
                "repair_loop.simulate",
                RiskLevel::R3,
                "no_auto_retry_real_execution",
                format!(
                    "Automatic repair loop strictly forbids running or retrying live `{}` executions (side effects may duplicate messages/writes/payments)",
                    mode.as_str()
                ),
                Some("Use `validate_only` (T0) or `simulate` (T1) during repair, then request human review before T2/T3.".to_owned()),
            ));
        }
        Ok(())
    }

    /// Checks attempt budget and repeated error fingerprint before starting a repair iteration.
    /// Returns `Ok(Some(attempt_number))` when the iteration may proceed, or `Ok(None)` when halted cleanly.
    pub fn check_can_begin_attempt(
        &mut self,
        summary: &MinimizedExecutionReport,
    ) -> N8nResult<Option<(u8, String)>> {
        if self.status != RepairLoopStatus::InProgress {
            return Ok(None);
        }

        let fp = Self::compute_error_fingerprint(summary);
        if self.config.halt_on_identical_error_fingerprint
            && self.seen_error_fingerprints.iter().any(|prev| prev == &fp)
        {
            self.status = RepairLoopStatus::Halted;
            self.halt_reason =
                Some(RepairHaltReason::RepeatedIdenticalErrorFingerprint { fingerprint: fp });
            return Ok(None);
        }

        if self.attempts_used >= self.config.max_attempts {
            self.status = RepairLoopStatus::Halted;
            self.halt_reason = Some(RepairHaltReason::MaxAttemptsReached {
                attempts_used: self.attempts_used,
                max_attempts: self.config.max_attempts,
            });
            return Ok(None);
        }

        self.attempts_used += 1;
        self.seen_error_fingerprints.push(fp.clone());
        Ok(Some((self.attempts_used, fp)))
    }
}

/// Final outcome returned by [`run_bounded_repair_loop`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepairLoopOutcome {
    pub state: RepairLoopState,
    pub working_workflow: WorkflowIr,
    pub last_execution_summary: MinimizedExecutionReport,
    pub last_validation_report: Option<WorkflowValidationReport>,
}

/// Executes the bounded V2 Section 8 `diagnose -> inspect -> validate -> patch preview -> simulate`
/// coordinator over `initial_workflow`.
///
/// - `propose_fn`: receives [`RepairInspectionContext`] and `&WorkflowIr`, returning a [`RepairCandidateProposal`].
/// - `simulate_fn`: executes **only** `T0 ValidateOnly` or `T1 Simulate` on the candidate `WorkflowIr`
///   and returns `(TestRunResult, MinimizedExecutionReport)`.
#[allow(clippy::too_many_lines)]
pub async fn run_bounded_repair_loop<P, S, Fut>(
    config: RepairLoopConfig,
    initial_workflow: WorkflowIr,
    initial_failure: MinimizedExecutionReport,
    catalog: Option<&CatalogDb>,
    mut propose_fn: P,
    mut simulate_fn: S,
) -> N8nResult<RepairLoopOutcome>
where
    P: FnMut(&RepairInspectionContext, &WorkflowIr) -> N8nResult<RepairCandidateProposal>,
    S: FnMut(TestExecutionMode, WorkflowIr) -> Fut,
    Fut: Future<Output = N8nResult<(TestRunResult, MinimizedExecutionReport)>>,
{
    let mut state = RepairLoopState::new(config)?;
    let mut current_ir = initial_workflow;
    let mut current_failure = initial_failure;
    let mut last_validation: Option<WorkflowValidationReport> = None;

    // Stage 1: Diagnose & check iteration / fingerprint bounds on each iteration.
    while let Some((attempt_no, fp)) = state.check_can_begin_attempt(&current_failure)? {
        let mut stages = vec![RepairStage::Diagnose];

        // Stage 2: Inspect current workflow graph, upstream schema shape, and baseline validation.
        let graph = WorkflowGraph::from_ir(&current_ir);
        let upstream_shape = current_failure
            .failed_node
            .as_deref()
            .map(|node_name| graph.infer_upstream_data_shape(&current_ir, node_name));
        let baseline_validation =
            validate_workflow(&current_ir, catalog, &ValidationOptions::default());
        stages.push(RepairStage::Inspect);

        let inspect_ctx = RepairInspectionContext {
            attempt: attempt_no,
            execution_summary: current_failure.clone(),
            error_fingerprint: fp.clone(),
            upstream_data_shape: upstream_shape,
            current_validation: baseline_validation,
        };

        let proposal = propose_fn(&inspect_ctx, &current_ir)?;

        // Never allow auto-retrying real `T2 Manual` or `T3 Production` runs!
        if let Err(err) = state.ensure_safe_verification_mode(proposal.verification_mode) {
            state.attempts.push(RepairAttemptRecord {
                attempt: attempt_no,
                stages_completed: stages,
                error_fingerprint: fp,
                failed_node: current_failure.failed_node.clone(),
                error_class: current_failure.error_class.clone(),
                confidence: Some(proposal.confidence),
                rationale: Some(redact_str(&proposal.rationale)),
                patch_preview: None,
                validation_passed: None,
                simulation_mode: Some(proposal.verification_mode),
                simulation_status: None,
            });
            return Err(err);
        }

        // Halt early on low confidence or empty patch instead of guessing!
        if proposal.confidence < state.config.min_confidence || proposal.mutations.is_empty() {
            let reason = RepairHaltReason::LowConfidence {
                observed: proposal.confidence,
                minimum_required: state.config.min_confidence,
                diagnostic_note: redact_str(&proposal.rationale),
            };
            state.status = RepairLoopStatus::Halted;
            state.halt_reason = Some(reason);
            state.attempts.push(RepairAttemptRecord {
                attempt: attempt_no,
                stages_completed: stages,
                error_fingerprint: fp,
                failed_node: current_failure.failed_node.clone(),
                error_class: current_failure.error_class.clone(),
                confidence: Some(proposal.confidence),
                rationale: Some(redact_str(&proposal.rationale)),
                patch_preview: None,
                validation_passed: None,
                simulation_mode: None,
                simulation_status: None,
            });
            break;
        }

        // Stage 3 & 4: Patch Preview + Offline Structural/AST Validation.
        let (candidate_ir, mutation_plan) = apply_mutations(
            &current_ir,
            &proposal.mutations,
            &MutationContext::default(),
        )
        .map_err(|e| {
            N8nError::validation(
                "local",
                vec![redact_str(&e.to_string())],
                "repair candidate mutation failed",
            )
        })?;

        let preview_summary = mutation_plan.workflow_diff.diff_summary.clone();
        stages.push(RepairStage::PatchPreview);

        let post_patch_validation =
            validate_workflow(&candidate_ir, catalog, &ValidationOptions::default());
        let valid = post_patch_validation.valid;
        let error_codes = post_patch_validation.error_codes.clone();
        last_validation = Some(post_patch_validation);
        stages.push(RepairStage::Validate);

        if !valid {
            state.status = RepairLoopStatus::Halted;
            state.halt_reason = Some(RepairHaltReason::ValidationFailedAfterPatch { error_codes });
            state.attempts.push(RepairAttemptRecord {
                attempt: attempt_no,
                stages_completed: stages,
                error_fingerprint: fp,
                failed_node: current_failure.failed_node.clone(),
                error_class: current_failure.error_class.clone(),
                confidence: Some(proposal.confidence),
                rationale: Some(redact_str(&proposal.rationale)),
                patch_preview: Some(preview_summary),
                validation_passed: Some(false),
                simulation_mode: None,
                simulation_status: None,
            });
            break;
        }

        // Stage 5: Safe Simulation (`T0` or `T1`).
        let (sim_result, next_exec_summary) =
            simulate_fn(proposal.verification_mode, candidate_ir.clone()).await?;
        stages.push(RepairStage::Simulate);

        current_ir = candidate_ir;

        let sim_status = sim_result.status;
        state.attempts.push(RepairAttemptRecord {
            attempt: attempt_no,
            stages_completed: stages,
            error_fingerprint: fp,
            failed_node: current_failure.failed_node.clone(),
            error_class: current_failure.error_class.clone(),
            confidence: Some(proposal.confidence),
            rationale: Some(redact_str(&proposal.rationale)),
            patch_preview: Some(preview_summary),
            validation_passed: Some(true),
            simulation_mode: Some(proposal.verification_mode),
            simulation_status: Some(sim_status),
        });

        current_failure = next_exec_summary;

        match sim_status {
            TestOutcomeStatus::ValidationPassed
            | TestOutcomeStatus::SimulatedNativeMcp
            | TestOutcomeStatus::SimulatedOfflineDryCheck => {
                state.status = RepairLoopStatus::Resolved;
                state.halt_reason = Some(RepairHaltReason::Resolved {
                    attempts_used: attempt_no,
                });
                break;
            }
            TestOutcomeStatus::BlockedOrUnsupportedSimulation
            | TestOutcomeStatus::RequiresApprovalOrPolicyBlocked => {
                state.status = RepairLoopStatus::Halted;
                state.halt_reason = Some(RepairHaltReason::SimulationBlockedOrUnsupported {
                    reason: sim_result
                        .warnings
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "simulation blocked by safety gate".to_owned()),
                });
                break;
            }
            TestOutcomeStatus::ValidationFailed
            | TestOutcomeStatus::ExecutionFailed
            | TestOutcomeStatus::ExecutionStartedNonTerminal
            | TestOutcomeStatus::ExecutionSucceeded => {
                if state.attempts_used >= state.config.max_attempts {
                    state.status = RepairLoopStatus::Halted;
                    state.halt_reason = Some(RepairHaltReason::MaxAttemptsReached {
                        attempts_used: state.attempts_used,
                        max_attempts: state.config.max_attempts,
                    });
                    break;
                }
            }
        }
    }

    Ok(RepairLoopOutcome {
        state,
        working_workflow: current_ir,
        last_execution_summary: current_failure,
        last_validation_report: last_validation,
    })
}

fn update_lp(hasher: &mut blake3::Hasher, s: &str) {
    let bytes = s.as_bytes();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
