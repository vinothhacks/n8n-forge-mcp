//! V2 Section 8 Test Execution Spectrum (`T0 ValidateOnly` .. `T3 Production`),
//! `DeterministicTestSafetyGate`, and `TestOrchestrator`.
//!
//! Core guarantees:
//! - `T0 ValidateOnly`: Offline `n8n_validator::validate_workflow` + optional `NativeMcpBridge::validate_workflow`,
//!   returning `mode_guarantee = "structural_syntax_only_not_runtime"`.
//! - `T1 Simulate`: Enforces [`DeterministicTestSafetyGate`] (`classify_workflow_side_effects` + `PolicyMode`).
//!   Blocks `HostOrFilesystemIo` (`executeCommand`, `readWriteFile`, etc.) even when HTTP/DB nodes are pinned,
//!   blocks unknown `executeWorkflow` subworkflows fail-closed, negotiates `prepare_workflow_pin_data` vs
//!   `prepare_test_pin_data`, falls back to an offline dry-check explicitly labeled `"NOT real n8n execution"`
//!   ONLY for purely deterministic local transform graphs, and **NEVER escalates silently to `T2` or `T3`**.
//! - `T2 Manual`: Requires non-read-only staging/dev policy + verified single-use `ApprovalReceipt` (`R3`),
//!   prefers `NativeMcpBridge::execute_workflow("manual")` with `triggerNodeName` negotiation (rejecting
//!   ambiguous multi-trigger workflows on n8n < 2.36) or an explicitly allowlisted staging test webhook URL,
//!   and **never auto-retries on failure**.
//! - `T3 Production`: Default denied unless `PolicyMode::ProductionGuarded` + explicit `R3`/`R4` `ApprovalReceipt`.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use http::header::CONTENT_TYPE;
use n8n_api_client::N8nApiClient;
use n8n_api_client::ssrf::{SsrfPolicy, normalize_and_validate_url, resolve_and_validate_origin};
use n8n_api_client::streaming::{StreamBudget, read_bounded_response};
use n8n_capability::CapabilityProfile;
use n8n_catalog_db::CatalogDb;
use n8n_graph::{WorkflowGraph, WorkflowIr, is_primary_trigger_type};
use n8n_mcp_bridge::{NativeMcpBridge, NegotiatedMcpTools, PinDataToolName};
use n8n_policy::{
    ApprovalClaims, ApprovalExpectation, InstancePolicyConfig, PolicyEngine, PolicyMode, hash_ops,
};
use n8n_types::{
    EnvironmentKind, N8nError, N8nResult, OperationStatus, PermissionDecision, RiskLevel,
    RouteUsed, ToolEnvelope, VerificationReport, redact_json_value, redact_str,
};
use n8n_validator::{
    ValidationOptions, ValidationSeverity, ValidationStrength, WorkflowValidationIssue,
    WorkflowValidationReport, validate_workflow,
};
use reqwest::redirect;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::classifier::{
    SideEffectClassification, SideEffectVerdict, classify_workflow_side_effects,
};
use crate::repair_loop::{
    ExecutionMinimizeOptions, MinimizedExecutionReport, summarize_execution_redacted,
};

/// Controlled V2 Section 8 test execution tiers (`T0..T3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestExecutionMode {
    /// `T0`: Structural, schema, expression AST, and topology validation only; not runtime correctness.
    ValidateOnly,
    /// `T1`: Synthetic fixture + side-effect safety gate via Native MCP `test_workflow` or pure-local dry-check.
    Simulate,
    /// `T2`: Approved staging execution (`execute_workflow(manual)` or allowlisted staging test webhook).
    Manual,
    /// `T3`: Guarded live production execution (default denied; requires `ProductionGuarded` + `R3`/`R4` receipt).
    Production,
}

impl TestExecutionMode {
    /// Short V2 tier label (`"T0"`, `"T1"`, `"T2"`, `"T3"`).
    #[must_use]
    pub const fn tier_code(self) -> &'static str {
        match self {
            Self::ValidateOnly => "T0",
            Self::Simulate => "T1",
            Self::Manual => "T2",
            Self::Production => "T3",
        }
    }

    /// Canonical wire action name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidateOnly => "validate_only",
            Self::Simulate => "simulate",
            Self::Manual => "manual",
            Self::Production => "production",
        }
    }

    /// Canonical approval action identifier bound in `ApprovalReceipt` claims.
    #[must_use]
    pub const fn receipt_action(self) -> &'static str {
        match self {
            Self::ValidateOnly => "test_workflow.validate_only",
            Self::Simulate => "test_workflow.simulate",
            Self::Manual => "test_workflow.manual",
            Self::Production => "test_workflow.production",
        }
    }

    /// Baseline risk classification for this test tier.
    #[must_use]
    pub const fn baseline_risk(self) -> RiskLevel {
        match self {
            Self::ValidateOnly | Self::Simulate => RiskLevel::R1,
            Self::Manual | Self::Production => RiskLevel::R3,
        }
    }
}

/// Structured outcome status of a [`TestOrchestrator::run_test`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcomeStatus {
    /// `T0` structural/syntax/schema validation succeeded.
    ValidationPassed,
    /// `T0` or offline dry-check detected structural/syntax/schema validation errors.
    ValidationFailed,
    /// `T1` simulated run succeeded via Native MCP `test_workflow` with safety gate + pin data.
    SimulatedNativeMcp,
    /// `T1` bounded offline structural/expression dry-check succeeded (`NOT real n8n execution`).
    SimulatedOfflineDryCheck,
    /// `T1` blocked by [`DeterministicTestSafetyGate`] or unsupported without Native MCP (never escalated!).
    BlockedOrUnsupportedSimulation,
    /// Blocked by policy or missing/invalid `ApprovalReceipt`.
    RequiresApprovalOrPolicyBlocked,
    /// Execution returned `"started"`/`"running"`/`"waiting"` (never falsely reported as `success`!).
    ExecutionStartedNonTerminal,
    /// Live `T2`/`T3` execution completed terminally with `status == "success"`.
    ExecutionSucceeded,
    /// Simulated or live execution failed at runtime on a node.
    ExecutionFailed,
}

impl TestOutcomeStatus {
    #[must_use]
    pub const fn to_operation_status(self) -> OperationStatus {
        match self {
            Self::ValidationPassed | Self::SimulatedNativeMcp | Self::ExecutionSucceeded => {
                OperationStatus::Success
            }
            Self::SimulatedOfflineDryCheck | Self::ExecutionStartedNonTerminal => {
                OperationStatus::Partial
            }
            Self::BlockedOrUnsupportedSimulation | Self::RequiresApprovalOrPolicyBlocked => {
                OperationStatus::Blocked
            }
            Self::ValidationFailed | Self::ExecutionFailed => OperationStatus::Error,
        }
    }
}

/// Pre-execution evaluation produced by [`DeterministicTestSafetyGate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SafetyGateDecision {
    pub allowed_for_t1_simulate: bool,
    pub policy_mode: PolicyMode,
    pub environment: EnvironmentKind,
    pub classification: SideEffectClassification,
    pub blocking_reasons: Vec<String>,
    pub remediation_steps: Vec<String>,
}

/// Deterministic pre-flight safety gate combining [`classify_workflow_side_effects`] and [`InstancePolicyConfig`].
pub struct DeterministicTestSafetyGate;

impl DeterministicTestSafetyGate {
    /// Evaluates whether `workflow` can safely run in `T1 Simulate` on `instance_cfg`.
    #[must_use]
    pub fn evaluate_t1(
        instance_cfg: &InstancePolicyConfig,
        workflow: &WorkflowIr,
        subworkflows: &HashMap<String, WorkflowIr>,
        pinned_nodes: &HashSet<String>,
        trigger_node: Option<&str>,
    ) -> SafetyGateDecision {
        let classification =
            classify_workflow_side_effects(workflow, subworkflows, pinned_nodes, trigger_node);

        let mut blocking_reasons = Vec::new();
        let mut remediation_steps = Vec::new();

        if instance_cfg.policy_mode == PolicyMode::ReadOnly {
            blocking_reasons.push(
                "Instance policy `read-only` forbids `T1 Simulate` execution; use `T0 validate_only` instead."
                    .to_owned(),
            );
            remediation_steps.push(
                "Run `mode = \"validate_only\"` (T0) or switch to an isolated `staging-safe` instance."
                    .to_owned(),
            );
        }

        if instance_cfg.environment == EnvironmentKind::Production {
            blocking_reasons.push(
                "`T1 Simulate` is restricted to non-production staging/development instances so pin-data runs never touch production workers or credentials."
                    .to_owned(),
            );
            remediation_steps.push(
                "Target an isolated `staging` or `development` n8n instance for `simulate`."
                    .to_owned(),
            );
        }

        if !classification.allows_t1_simulate() {
            blocking_reasons.extend(classification.blocking_reasons.iter().cloned());
            match classification.verdict {
                SideEffectVerdict::BlockedHostOrFilesystemIo => {
                    remediation_steps.push(
                        "Pinning HTTP/DB nodes CANNOT block credential-free host/filesystem nodes (`executeCommand`, `readWriteFile`, `writeBinaryFile`, `ssh`, `ftp`, or host `code`). Remove/replace those nodes or run inside an explicitly isolated disposable container with human approval."
                            .to_owned(),
                    );
                }
                SideEffectVerdict::UnknownSubworkflowFailClosed => {
                    remediation_steps.push(
                        "Load and pass all referenced `executeWorkflow` subworkflow graphs in `subworkflows` so nested side effects can be statically verified."
                            .to_owned(),
                    );
                }
                SideEffectVerdict::BlockedUnpinnedExternalOrUnknownIo => {
                    if !classification.unpinned_external_nodes.is_empty() {
                        remediation_steps.push(format!(
                            "Provide mock pin data (`pinned_nodes` / `pin_data`) for reachable external I/O nodes: {}.",
                            classification.unpinned_external_nodes.join(", ")
                        ));
                    }
                    if !classification.unknown_custom_nodes.is_empty() {
                        remediation_steps.push(format!(
                            "Community/custom nodes ({}) cannot be proven side-effect-free for `T1 Simulate`; use an approved `T2 Manual` staging run if needed.",
                            classification.unknown_custom_nodes.join(", ")
                        ));
                    }
                }
                SideEffectVerdict::SafeForSimulate => {}
            }
        }

        let allowed_for_t1_simulate =
            blocking_reasons.is_empty() && classification.allows_t1_simulate();

        SafetyGateDecision {
            allowed_for_t1_simulate,
            policy_mode: instance_cfg.policy_mode,
            environment: instance_cfg.environment,
            classification,
            blocking_reasons,
            remediation_steps,
        }
    }
}

/// Input specification for [`TestOrchestrator::run_test`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestRunRequest {
    pub mode: TestExecutionMode,
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    pub workflow: WorkflowIr,
    #[serde(default)]
    pub subworkflows: HashMap<String, WorkflowIr>,
    #[serde(default)]
    pub pinned_nodes: HashSet<String>,
    /// Optional mock pin data map (`{ "Node Name": [{ "json": { ... } }] }`) for `T1 Simulate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_data: Option<Value>,
    /// Optional trigger node name (required when a workflow has multiple primary triggers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_node: Option<String>,
    /// Optional synthetic/test input payload passed to the trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_data: Option<Value>,
    /// Optional staging test webhook URL for `T2 Manual` when Native MCP `execute_workflow` is unavailable.
    /// Must match an entry in `TestOrchestrator`'s explicit staging webhook allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_webhook_url: Option<String>,
    /// Optional single-use cryptographic `ApprovalReceipt` token (`n8n_rcpt_v1.*`) required for `T2` and `T3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_receipt_token: Option<String>,
    /// Optional explicit `ops_hash` override when minting/verifying receipts; computed deterministically if `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ops_hash: Option<String>,
    /// Optional `expected_version_hash` bound into the `ApprovalReceipt`; defaults to `workflow.canonical_version_hash()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version_hash: Option<String>,
    /// When `true` in `T0 ValidateOnly`, also invokes `NativeMcpBridge::validate_workflow` if advertised.
    #[serde(default = "default_true")]
    pub prefer_native_validation: bool,
    /// When `true` in `T3 Production`, requires `RiskLevel::R4` (rather than `R3`/`R4`).
    #[serde(default)]
    pub require_r4_receipt: bool,
    #[serde(default)]
    pub validation_options: ValidationOptions,
    #[serde(default)]
    pub minimize_options: ExecutionMinimizeOptions,
}

const fn default_true() -> bool {
    true
}

impl TestRunRequest {
    /// Creates a minimal [`TestRunRequest`] for `mode`, `principal`, and `workflow`.
    #[must_use]
    pub fn new(
        mode: TestExecutionMode,
        principal: impl Into<String>,
        workflow: WorkflowIr,
    ) -> Self {
        let wf_id = workflow.id.clone();
        Self {
            mode,
            principal: principal.into(),
            workflow_id: wf_id,
            workflow,
            subworkflows: HashMap::new(),
            pinned_nodes: HashSet::new(),
            pin_data: None,
            trigger_node: None,
            input_data: None,
            staging_webhook_url: None,
            approval_receipt_token: None,
            expected_ops_hash: None,
            expected_version_hash: None,
            prefer_native_validation: true,
            require_r4_receipt: false,
            validation_options: ValidationOptions::default(),
            minimize_options: ExecutionMinimizeOptions::default(),
        }
    }

    /// Resolves effective `workflow_id` from request or `WorkflowIr`.
    #[must_use]
    pub fn resolved_workflow_id(&self) -> Option<String> {
        self.workflow_id
            .clone()
            .or_else(|| self.workflow.id.clone())
    }

    /// Computes the deterministic `BLAKE3` operations digest bound to `T2`/`T3` approval receipts.
    pub fn compute_ops_hash(&self) -> N8nResult<String> {
        if let Some(ref explicit) = self.expected_ops_hash {
            return Ok(explicit.clone());
        }
        hash_ops(&json!({
            "mode": self.mode.as_str(),
            "workflowId": self.resolved_workflow_id(),
            "triggerNode": self.trigger_node,
            "stagingWebhookUrl": self.staging_webhook_url,
            "inputData": self.input_data,
        }))
    }

    /// Collects all pinned node names across `pinned_nodes`, `pin_data` object keys, and `workflow.pin_data`.
    #[must_use]
    pub fn effective_pinned_nodes(&self) -> HashSet<String> {
        let mut set = self.pinned_nodes.clone();
        if let Some(Value::Object(map)) = &self.pin_data {
            for k in map.keys() {
                set.insert(k.clone());
            }
        }
        if let Some(ref wf_pins) = self.workflow.pin_data {
            for k in wf_pins.keys() {
                set.insert(k.clone());
            }
        }
        set
    }
}

/// Structured result returned by [`TestOrchestrator::run_test`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestRunResult {
    pub mode: TestExecutionMode,
    pub tier: String,
    pub status: TestOutcomeStatus,
    pub mode_guarantee: String,
    pub route_used: RouteUsed,
    pub permission: PermissionDecision,
    pub workflow_id: Option<String>,
    pub selected_trigger: Option<String>,
    pub pin_data_tool_used: Option<PinDataToolName>,
    pub attempts_made: u8,
    pub escalated_to_live_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_report: Option<WorkflowValidationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_validation_output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_gate: Option<SafetyGateDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_summary: Option<MinimizedExecutionReport>,
    pub warnings: Vec<String>,
    pub next_actions: Vec<String>,
}

/// Orchestrates `T0 ValidateOnly`, `T1 Simulate`, `T2 Manual`, and `T3 Production` workflow tests.
pub struct TestOrchestrator {
    instance_cfg: InstancePolicyConfig,
    capabilities: Option<CapabilityProfile>,
    policy_engine: PolicyEngine,
    api_client: Option<N8nApiClient>,
    mcp_bridge: Option<NativeMcpBridge>,
    allowlisted_staging_webhooks: HashSet<String>,
    webhook_ssrf_policy: SsrfPolicy,
    webhook_stream_budget: StreamBudget,
}

impl TestOrchestrator {
    /// Creates a new [`TestOrchestrator`] bound to `instance_cfg` and `policy_engine`.
    #[must_use]
    pub fn new(instance_cfg: InstancePolicyConfig, policy_engine: PolicyEngine) -> Self {
        let ssrf = SsrfPolicy {
            allow_loopback_http: instance_cfg.allow_loopback_http,
            trust_configured_private_host: instance_cfg.trust_configured_private_host,
            trusted_private_ips: Vec::new(),
        };
        Self {
            instance_cfg,
            capabilities: None,
            policy_engine,
            api_client: None,
            mcp_bridge: None,
            allowlisted_staging_webhooks: HashSet::new(),
            webhook_ssrf_policy: ssrf,
            webhook_stream_budget: StreamBudget::default(),
        }
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilityProfile) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    #[must_use]
    pub fn with_api_client(mut self, api_client: N8nApiClient) -> Self {
        self.api_client = Some(api_client);
        self
    }

    #[must_use]
    pub fn with_mcp_bridge(mut self, mcp_bridge: NativeMcpBridge) -> Self {
        self.mcp_bridge = Some(mcp_bridge);
        self
    }

    #[must_use]
    pub fn with_allowlisted_staging_webhooks(
        mut self,
        urls: impl IntoIterator<Item = String>,
    ) -> Self {
        self.allowlisted_staging_webhooks = urls.into_iter().collect();
        self
    }

    #[must_use]
    pub const fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    #[must_use]
    pub const fn instance_config(&self) -> &InstancePolicyConfig {
        &self.instance_cfg
    }

    /// Executes `req` according to the strict V2 Section 8 test mode routing and safety gates.
    pub async fn run_test(
        &self,
        req: &TestRunRequest,
        catalog: Option<&CatalogDb>,
    ) -> N8nResult<TestRunResult> {
        match req.mode {
            TestExecutionMode::ValidateOnly => self.run_t0_validate_only(req, catalog).await,
            TestExecutionMode::Simulate => self.run_t1_simulate(req, catalog).await,
            TestExecutionMode::Manual => self.run_t2_manual(req).await,
            TestExecutionMode::Production => self.run_t3_production(req).await,
        }
    }

    /// Executes `req` and wraps the outcome (or fail-closed error) into a redacted [`ToolEnvelope`].
    pub async fn run_test_envelope(
        &self,
        req: &TestRunRequest,
        catalog: Option<&CatalogDb>,
    ) -> ToolEnvelope<Value> {
        let action = req.mode.receipt_action().to_owned();
        match self.run_test(req, catalog).await {
            Ok(res) => {
                let op_status = res.status.to_operation_status();
                let perm = res.permission;
                let route = res.route_used;
                let wf_id = res.workflow_id.clone();
                let warnings = res.warnings.clone();
                let next_actions = res.next_actions.clone();
                let data_val = serde_json::to_value(&res)
                    .map(|v| redact_json_value(&v))
                    .unwrap_or(Value::Null);

                ToolEnvelope::new(
                    op_status,
                    self.instance_cfg.alias.clone(),
                    action,
                    perm,
                    route,
                )
                .with_workflow_id(wf_id)
                .with_warnings(warnings)
                .with_next_actions(next_actions)
                .with_verification(VerificationReport::verified([format!(
                    "mode_guarantee={}",
                    res.mode_guarantee
                )]))
                .with_data(data_val)
            }
            Err(err) => err.into_envelope(
                self.instance_cfg.alias.clone(),
                action,
                RouteUsed::Unsupported,
            ),
        }
    }

    // ------------------------------------------------------------------------
    // T0: ValidateOnly
    // ------------------------------------------------------------------------

    async fn run_t0_validate_only(
        &self,
        req: &TestRunRequest,
        catalog: Option<&CatalogDb>,
    ) -> N8nResult<TestRunResult> {
        let mut report = validate_workflow(&req.workflow, catalog, &req.validation_options);
        let mut route_used = RouteUsed::Local;
        let mut native_validation_output = None;
        let mut warnings = Vec::new();

        if req.prefer_native_validation
            && let Some(ref bridge) = self.mcp_bridge
        {
            let neg = ensure_bridge_negotiated(bridge).await?;
            if neg.has_validate_workflow {
                let wf_json = req.workflow.to_json_value()?;
                match bridge
                    .validate_workflow(&json!({ "workflow": wf_json }))
                    .await
                {
                    Ok(native_out) => {
                        route_used = RouteUsed::NativeMcp;
                        if native_out.get("valid").and_then(Value::as_bool) == Some(false) {
                            report.valid = false;
                            let msg = native_out
                                .get("message")
                                .and_then(Value::as_str)
                                .map(redact_str)
                                .unwrap_or_else(|| {
                                    "Native MCP `validate_workflow` reported schema errors."
                                        .to_owned()
                                });
                            report
                                .error_codes
                                .push("native_mcp_validation_failed".to_owned());
                            report.issues.push(WorkflowValidationIssue {
                                severity: ValidationSeverity::Error,
                                category: "native_mcp".to_owned(),
                                code: "native_mcp_validation_failed".to_owned(),
                                node_id: None,
                                node_name: None,
                                field_path: None,
                                message: msg,
                                suggestion: Some(
                                    "Inspect `nativeValidationOutput` for instance-specific node schema mismatches."
                                        .to_owned(),
                                ),
                            });
                        }
                        report.strength = ValidationStrength::NativeMcpVerified;
                        native_validation_output = Some(redact_json_value(&native_out));
                    }
                    Err(err) if !err.allows_route_fallback() => {
                        // Fail-closed on 401/403/SSRF!
                        return Err(err);
                    }
                    Err(err) => {
                        warnings.push(format!(
                            "Native MCP `validate_workflow` unavailable ({}); completed offline validation only.",
                            redact_str(&err.to_string())
                        ));
                    }
                }
            }
        }

        let status = if report.valid {
            TestOutcomeStatus::ValidationPassed
        } else {
            TestOutcomeStatus::ValidationFailed
        };

        let next_actions = if report.valid {
            vec![
                "Structural validation passed (not a runtime guarantee); run `simulate` (T1) on staging if runtime flow checks are needed."
                    .to_owned(),
            ]
        } else {
            vec![
                "Fix the reported workflow validation errors and re-run `validate_only` (T0)."
                    .to_owned(),
            ]
        };

        Ok(TestRunResult {
            mode: TestExecutionMode::ValidateOnly,
            tier: TestExecutionMode::ValidateOnly.tier_code().to_owned(),
            status,
            mode_guarantee: "structural_syntax_only_not_runtime".to_owned(),
            route_used,
            permission: PermissionDecision::Allowed,
            workflow_id: req.resolved_workflow_id(),
            selected_trigger: req.trigger_node.clone(),
            pin_data_tool_used: None,
            attempts_made: 0,
            escalated_to_live_mode: false,
            consumed_receipt_id: None,
            validation_report: Some(report),
            native_validation_output,
            safety_gate: None,
            execution_summary: None,
            warnings,
            next_actions,
        })
    }

    // ------------------------------------------------------------------------
    // T1: Simulate (NEVER escalates silently to T2/T3!)
    // ------------------------------------------------------------------------

    #[allow(clippy::too_many_lines)]
    async fn run_t1_simulate(
        &self,
        req: &TestRunRequest,
        catalog: Option<&CatalogDb>,
    ) -> N8nResult<TestRunResult> {
        let effective_pins = req.effective_pinned_nodes();
        let gate = DeterministicTestSafetyGate::evaluate_t1(
            &self.instance_cfg,
            &req.workflow,
            &req.subworkflows,
            &effective_pins,
            req.trigger_node.as_deref(),
        );

        // 1. If the deterministic safety gate rejects T1, NEVER escalate to T2/T3!
        if !gate.allowed_for_t1_simulate {
            let perm = if self.instance_cfg.policy_mode == PolicyMode::ReadOnly {
                PermissionDecision::Denied
            } else {
                PermissionDecision::NeedsApproval
            };
            let warnings = gate.blocking_reasons.clone();
            let next_actions = gate.remediation_steps.clone();
            return Ok(TestRunResult {
                mode: TestExecutionMode::Simulate,
                tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                status: TestOutcomeStatus::BlockedOrUnsupportedSimulation,
                mode_guarantee: "simulation_blocked_by_safety_gate_no_execution_performed"
                    .to_owned(),
                route_used: RouteUsed::Unsupported,
                permission: perm,
                workflow_id: req.resolved_workflow_id(),
                selected_trigger: req.trigger_node.clone(),
                pin_data_tool_used: None,
                attempts_made: 0,
                escalated_to_live_mode: false,
                consumed_receipt_id: None,
                validation_report: None,
                native_validation_output: None,
                safety_gate: Some(gate),
                execution_summary: None,
                warnings,
                next_actions,
            });
        }

        // 2. Safety gate passed! Prefer Native MCP `test_workflow` when advertised.
        if let Some(ref bridge) = self.mcp_bridge {
            let neg = ensure_bridge_negotiated(bridge).await?;
            if neg.has_test_workflow {
                let Some(wf_id) = req.resolved_workflow_id() else {
                    return Ok(TestRunResult {
                        mode: TestExecutionMode::Simulate,
                        tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                        status: TestOutcomeStatus::BlockedOrUnsupportedSimulation,
                        mode_guarantee:
                            "simulation_requires_saved_staging_draft_workflow_id_no_execution"
                                .to_owned(),
                        route_used: RouteUsed::Unsupported,
                        permission: PermissionDecision::Allowed,
                        workflow_id: None,
                        selected_trigger: req.trigger_node.clone(),
                        pin_data_tool_used: None,
                        attempts_made: 0,
                        escalated_to_live_mode: false,
                        consumed_receipt_id: None,
                        validation_report: None,
                        native_validation_output: None,
                        safety_gate: Some(gate),
                        execution_summary: None,
                        warnings: vec![
                            "Native MCP `test_workflow` requires a saved staging draft `workflowId`."
                                .to_owned(),
                        ],
                        next_actions: vec![
                            "Save the workflow as an inactive staging draft first, then run `simulate`."
                                .to_owned(),
                        ],
                    });
                };

                let pin_payload = resolve_pin_payload(req);
                let mut pin_tool_used = None;

                if let Some(ref pd) = pin_payload {
                    if neg.pin_data_tool == PinDataToolName::Unavailable {
                        return Ok(TestRunResult {
                            mode: TestExecutionMode::Simulate,
                            tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                            status: TestOutcomeStatus::BlockedOrUnsupportedSimulation,
                            mode_guarantee:
                                "simulation_blocked_pin_data_tool_unavailable_no_execution"
                                    .to_owned(),
                            route_used: RouteUsed::Unsupported,
                            permission: PermissionDecision::Unknown,
                            workflow_id: Some(wf_id),
                            selected_trigger: req.trigger_node.clone(),
                            pin_data_tool_used: Some(PinDataToolName::Unavailable),
                            attempts_made: 0,
                            escalated_to_live_mode: false,
                            consumed_receipt_id: None,
                            validation_report: None,
                            native_validation_output: None,
                            safety_gate: Some(gate),
                            execution_summary: None,
                            warnings: vec![
                                "Pin data is required for safe simulation, but neither `prepare_workflow_pin_data` nor `prepare_test_pin_data` is advertised by Native MCP."
                                    .to_owned(),
                            ],
                            next_actions: vec![
                                "Upgrade n8n >= 2.15 or pre-populate draft `pinData` on an isolated staging instance."
                                    .to_owned(),
                            ],
                        });
                    }
                    let _ = bridge.prepare_pin_data(&wf_id, pd).await?;
                    pin_tool_used = Some(neg.pin_data_tool);
                } else if !gate.classification.pinned_external_nodes.is_empty()
                    && req.workflow.pin_data.is_none()
                {
                    return Ok(TestRunResult {
                        mode: TestExecutionMode::Simulate,
                        tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                        status: TestOutcomeStatus::BlockedOrUnsupportedSimulation,
                        mode_guarantee: "simulation_blocked_missing_pin_payload_no_execution"
                            .to_owned(),
                        route_used: RouteUsed::Unsupported,
                        permission: PermissionDecision::Allowed,
                        workflow_id: Some(wf_id),
                        selected_trigger: req.trigger_node.clone(),
                        pin_data_tool_used: None,
                        attempts_made: 0,
                        escalated_to_live_mode: false,
                        consumed_receipt_id: None,
                        validation_report: None,
                        native_validation_output: None,
                        safety_gate: Some(gate),
                        execution_summary: None,
                        warnings: vec![
                            "Nodes were listed in `pinned_nodes`, but no `pin_data` mock payload was supplied and workflow `pinData` is empty."
                                .to_owned(),
                        ],
                        next_actions: vec![
                            "Supply mock JSON items in `pin_data` for every pinned external node."
                                .to_owned(),
                        ],
                    });
                }

                let raw_test_res = bridge
                    .test_workflow(&wf_id, req.input_data.as_ref())
                    .await?;
                let exec_summary =
                    summarize_execution_redacted(&raw_test_res, &req.minimize_options)?;

                let status = if exec_summary.is_terminal_success {
                    TestOutcomeStatus::SimulatedNativeMcp
                } else if !exec_summary.finished {
                    TestOutcomeStatus::ExecutionStartedNonTerminal
                } else {
                    TestOutcomeStatus::ExecutionFailed
                };

                let mut warnings = exec_summary.notes.clone();
                if status == TestOutcomeStatus::ExecutionFailed
                    && let Some(ref err_txt) = exec_summary.error_message_redacted
                {
                    warnings.push(format!("Simulated execution failed: {err_txt}"));
                }

                return Ok(TestRunResult {
                    mode: TestExecutionMode::Simulate,
                    tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                    status,
                    mode_guarantee:
                        "simulated_pin_data_side_effect_gated_may_not_replicate_external_services"
                            .to_owned(),
                    route_used: RouteUsed::NativeMcp,
                    permission: PermissionDecision::Allowed,
                    workflow_id: Some(wf_id),
                    selected_trigger: req.trigger_node.clone(),
                    pin_data_tool_used: pin_tool_used,
                    attempts_made: 1,
                    escalated_to_live_mode: false,
                    consumed_receipt_id: None,
                    validation_report: None,
                    native_validation_output: None,
                    safety_gate: Some(gate),
                    execution_summary: Some(exec_summary),
                    warnings,
                    next_actions: vec![
                        "Review simulated output schema; request human approval before running `manual` (T2) or publishing."
                            .to_owned(),
                    ],
                });
            }
        }

        // 3. No Native MCP `test_workflow`: ONLY perform bounded offline dry-check if ALL reachable
        //    nodes are purely deterministic local transform nodes!
        if gate.classification.all_reachable_deterministic_local {
            let validation = validate_workflow(&req.workflow, catalog, &req.validation_options);
            let status = if validation.valid {
                TestOutcomeStatus::SimulatedOfflineDryCheck
            } else {
                TestOutcomeStatus::ValidationFailed
            };

            return Ok(TestRunResult {
                mode: TestExecutionMode::Simulate,
                tier: TestExecutionMode::Simulate.tier_code().to_owned(),
                status,
                mode_guarantee: "offline_deterministic_dry_check: NOT real n8n execution"
                    .to_owned(),
                route_used: RouteUsed::Local,
                permission: PermissionDecision::Allowed,
                workflow_id: req.resolved_workflow_id(),
                selected_trigger: req.trigger_node.clone(),
                pin_data_tool_used: None,
                attempts_made: 1,
                escalated_to_live_mode: false,
                consumed_receipt_id: None,
                validation_report: Some(validation),
                native_validation_output: None,
                safety_gate: Some(gate),
                execution_summary: None,
                warnings: vec![
                    "Native MCP `test_workflow` is unavailable; performed bounded offline structural/expression dry-check — NOT real n8n execution."
                        .to_owned(),
                ],
                next_actions: vec![
                    "Enable n8n Instance-level MCP (`test_workflow`) on staging for full task-runner pin-data simulation."
                        .to_owned(),
                ],
            });
        }

        // 4. Otherwise return `BlockedOrUnsupportedSimulation` — NEVER escalate to T2/T3!
        Ok(TestRunResult {
            mode: TestExecutionMode::Simulate,
            tier: TestExecutionMode::Simulate.tier_code().to_owned(),
            status: TestOutcomeStatus::BlockedOrUnsupportedSimulation,
            mode_guarantee: "unsupported_simulation_without_native_mcp_never_escalated".to_owned(),
            route_used: RouteUsed::Unsupported,
            permission: PermissionDecision::Unknown,
            workflow_id: req.resolved_workflow_id(),
            selected_trigger: req.trigger_node.clone(),
            pin_data_tool_used: None,
            attempts_made: 0,
            escalated_to_live_mode: false,
            consumed_receipt_id: None,
            validation_report: None,
            native_validation_output: None,
            safety_gate: Some(gate),
            execution_summary: None,
            warnings: vec![
                "Workflow includes pinned external or runtime-evaluated Code/AI nodes that require Native MCP `test_workflow`; refusing to escalate to live `T2`/`T3` execution."
                    .to_owned(),
            ],
            next_actions: vec![
                "Configure `N8N_MCP_BASE_URL` + isolated `N8N_MCP_ACCESS_TOKEN` on an isolated staging n8n >= 2.15 instance."
                    .to_owned(),
            ],
        })
    }

    // ------------------------------------------------------------------------
    // T2: Manual (staging live run, single-use receipt, zero auto-retry!)
    // ------------------------------------------------------------------------

    #[allow(clippy::too_many_lines)]
    async fn run_t2_manual(&self, req: &TestRunRequest) -> N8nResult<TestRunResult> {
        let mode_label = self.instance_cfg.policy_mode.as_str();

        // 1. Enforce non-read-only staging/development policy!
        if self.instance_cfg.policy_mode == PolicyMode::ReadOnly {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Manual.receipt_action(),
                RiskLevel::R3,
                mode_label,
                "Policy `read-only` strictly forbids `T2 Manual` workflow execution",
                None,
            ));
        }
        if self.instance_cfg.environment == EnvironmentKind::Production
            || self.instance_cfg.policy_mode == PolicyMode::ProductionGuarded
        {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Manual.receipt_action(),
                RiskLevel::R3,
                mode_label,
                "`T2 Manual` requires a non-production staging/development instance; production targets require `T3 Production` under `production-guarded`",
                Some("Switch to a `staging` instance or request an explicit `T3 Production` receipt.".to_owned()),
            ));
        }

        self.enforce_common_workflow_guards(req, RiskLevel::R3)?;

        // 2. Require presence of single-use ApprovalReceipt before probing routes.
        let Some(ref receipt_token) = req.approval_receipt_token else {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Manual.receipt_action(),
                RiskLevel::R3,
                mode_label,
                "`T2 Manual` produces real staging side effects and requires a single-use cryptographic ApprovalReceipt",
                Some("Preview target version, trigger, credentials, and input first, then supply an `n8n_rcpt_v1.*` receipt.".to_owned()),
            ));
        };

        // 3. Inspect trigger topology & resolve route BEFORE consuming the single-use receipt.
        let (trigger_count, resolved_trigger) =
            validate_trigger_selection(&req.workflow, req.trigger_node.as_deref())?;

        enum ManualRoutePlan<'a> {
            NativeBridge {
                bridge: &'a NativeMcpBridge,
                wf_id: String,
            },
            AllowlistedWebhook {
                url: url::Url,
            },
        }

        let plan = if let Some(ref bridge) = self.mcp_bridge {
            let neg = ensure_bridge_negotiated(bridge).await?;
            if neg.has_execute_workflow {
                if (trigger_count > 1 || req.trigger_node.is_some())
                    && !neg.supports_trigger_node_name
                {
                    return Err(N8nError::unsupported(
                        &self.instance_cfg.alias,
                        "execute_workflow.triggerNodeName",
                        "Ambiguous workflow trigger selection: `triggerNodeName` is not supported on n8n < 2.36.0; refusing to guess trigger",
                        Some("Upgrade n8n >= 2.36.0 or test a single-trigger workflow.".to_owned()),
                    ));
                }
                let wf_id = req.resolved_workflow_id().ok_or_else(|| {
                    N8nError::validation(
                        &self.instance_cfg.alias,
                        vec!["missing `workflow_id`".to_owned()],
                        "`T2 Manual` via Native MCP requires a saved workflow ID",
                    )
                })?;
                ManualRoutePlan::NativeBridge { bridge, wf_id }
            } else if let Some(ref wh_raw) = req.staging_webhook_url {
                let validated_url = self
                    .validate_allowlisted_staging_webhook(
                        wh_raw,
                        &req.workflow,
                        resolved_trigger.as_deref(),
                    )
                    .await?;
                ManualRoutePlan::AllowlistedWebhook { url: validated_url }
            } else {
                return Err(N8nError::unsupported(
                    &self.instance_cfg.alias,
                    TestExecutionMode::Manual.receipt_action(),
                    "Native MCP does not advertise `execute_workflow` and no allowlisted `staging_webhook_url` was supplied",
                    Some("Enable Native MCP `execute_workflow` or configure an explicit allowlisted staging webhook URL.".to_owned()),
                ));
            }
        } else if let Some(ref wh_raw) = req.staging_webhook_url {
            let validated_url = self
                .validate_allowlisted_staging_webhook(
                    wh_raw,
                    &req.workflow,
                    resolved_trigger.as_deref(),
                )
                .await?;
            ManualRoutePlan::AllowlistedWebhook { url: validated_url }
        } else {
            return Err(N8nError::unsupported(
                &self.instance_cfg.alias,
                TestExecutionMode::Manual.receipt_action(),
                "Public-API-only mode cannot arbitrarily execute Schedule/Manual workflows without Native MCP `execute_workflow` or an allowlisted staging test webhook URL",
                Some("Configure Native MCP bridge (`/mcp-server/http`) or supply an allowlisted staging test webhook URL.".to_owned()),
            ));
        };

        // 4. Verify & atomically consume the single-use `R3` ApprovalReceipt!
        let claims = self.verify_and_consume_receipt(
            req,
            receipt_token,
            TestExecutionMode::Manual.receipt_action(),
            RiskLevel::R3,
        )?;

        // 5. Execute ONCE (`attempts_made = 1` — NEVER auto-retry live staging runs!).
        let (route_used, raw_exec_json) = match plan {
            ManualRoutePlan::NativeBridge { bridge, wf_id } => {
                let out = bridge
                    .execute_workflow(
                        &wf_id,
                        "manual",
                        req.trigger_node.as_deref(),
                        trigger_count,
                        req.input_data.as_ref(),
                    )
                    .await?;
                (RouteUsed::NativeMcp, out)
            }
            ManualRoutePlan::AllowlistedWebhook { url } => {
                let out = self
                    .invoke_allowlisted_webhook_once(&url, req.input_data.as_ref())
                    .await?;
                (RouteUsed::PublicApi, out)
            }
        };

        let exec_summary = summarize_execution_redacted(&raw_exec_json, &req.minimize_options)?;
        let status = map_live_execution_status(&exec_summary);
        let classify = classify_workflow_side_effects(
            &req.workflow,
            &req.subworkflows,
            &HashSet::new(),
            resolved_trigger.as_deref(),
        );

        let mut warnings = exec_summary.notes.clone();
        if status == TestOutcomeStatus::ExecutionFailed {
            warnings.push(
                "Staging manual execution failed; automatic retry was NOT performed because partial runs may have already emitted side effects."
                    .to_owned(),
            );
        }

        Ok(TestRunResult {
            mode: TestExecutionMode::Manual,
            tier: TestExecutionMode::Manual.tier_code().to_owned(),
            status,
            mode_guarantee: "staging_end_to_end_real_staging_side_effects_no_auto_retry".to_owned(),
            route_used,
            permission: PermissionDecision::Allowed,
            workflow_id: req.resolved_workflow_id(),
            selected_trigger: resolved_trigger,
            pin_data_tool_used: None,
            attempts_made: 1,
            escalated_to_live_mode: false,
            consumed_receipt_id: Some(claims.receipt_id),
            validation_report: None,
            native_validation_output: None,
            safety_gate: Some(SafetyGateDecision {
                allowed_for_t1_simulate: classify.allows_t1_simulate(),
                policy_mode: self.instance_cfg.policy_mode,
                environment: self.instance_cfg.environment,
                classification: classify,
                blocking_reasons: Vec::new(),
                remediation_steps: Vec::new(),
            }),
            execution_summary: Some(exec_summary),
            warnings,
            next_actions: vec![
                "Inspect redacted execution summary; do not re-execute blindly if external side effects occurred."
                    .to_owned(),
            ],
        })
    }

    // ------------------------------------------------------------------------
    // T3: Production (default denied unless ProductionGuarded + R3/R4 receipt!)
    // ------------------------------------------------------------------------

    async fn run_t3_production(&self, req: &TestRunRequest) -> N8nResult<TestRunResult> {
        let mode_label = self.instance_cfg.policy_mode.as_str();

        // 1. Default DENIED unless `PolicyMode::ProductionGuarded`!
        if self.instance_cfg.policy_mode != PolicyMode::ProductionGuarded {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Production.receipt_action(),
                RiskLevel::R4,
                mode_label,
                format!(
                    "`T3 Production` execution is denied by default under policy `{mode_label}`; requires `production-guarded`"
                ),
                Some("Configure `policy = \"production-guarded\"` and obtain an explicit `R3`/`R4` human ApprovalReceipt.".to_owned()),
            ));
        }

        let classify = classify_workflow_side_effects(
            &req.workflow,
            &req.subworkflows,
            &HashSet::new(),
            req.trigger_node.as_deref(),
        );

        let required_risk = if req.require_r4_receipt || classify.has_host_or_filesystem_io() {
            if !self.instance_cfg.enable_r4_admin_actions {
                return Err(N8nError::policy_blocked(
                    TestExecutionMode::Production.receipt_action(),
                    RiskLevel::R4,
                    mode_label,
                    "Production execution involving `R4` host/destructive capabilities requires `enable_r4_admin_actions = true`",
                    Some(
                        "Enable `enable_r4_admin_actions` and supply an `R4` ApprovalReceipt."
                            .to_owned(),
                    ),
                ));
            }
            RiskLevel::R4
        } else {
            // `ReceiptSigner::verify_and_consume` accepts BOTH `R3` and `R4` receipts when `expected.risk == R3`!
            RiskLevel::R3
        };

        self.enforce_common_workflow_guards(req, required_risk)?;

        let Some(ref receipt_token) = req.approval_receipt_token else {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Production.receipt_action(),
                required_risk,
                mode_label,
                "`T3 Production` requires a verified single-use `R3`/`R4` ApprovalReceipt",
                Some("Present exact workflow version, trigger, input, and live side-effect impact to the user to mint an `n8n_rcpt_v1.*` receipt.".to_owned()),
            ));
        };

        let Some(ref bridge) = self.mcp_bridge else {
            return Err(N8nError::unsupported(
                &self.instance_cfg.alias,
                TestExecutionMode::Production.receipt_action(),
                "`T3 Production` requires Native MCP `execute_workflow(production)`",
                Some("Configure Native MCP bridge (`/mcp-server/http`) on the `production-guarded` instance.".to_owned()),
            ));
        };

        let neg = ensure_bridge_negotiated(bridge).await?;
        if !neg.has_execute_workflow {
            return Err(N8nError::unsupported(
                &self.instance_cfg.alias,
                TestExecutionMode::Production.receipt_action(),
                "`execute_workflow` is not advertised by Native MCP on this instance",
                None,
            ));
        }

        let (trigger_count, resolved_trigger) =
            validate_trigger_selection(&req.workflow, req.trigger_node.as_deref())?;
        if (trigger_count > 1 || req.trigger_node.is_some()) && !neg.supports_trigger_node_name {
            return Err(N8nError::unsupported(
                &self.instance_cfg.alias,
                "execute_workflow.triggerNodeName",
                "Ambiguous workflow trigger selection: `triggerNodeName` is not supported on n8n < 2.36.0; refusing to guess production trigger",
                Some("Upgrade n8n >= 2.36.0.".to_owned()),
            ));
        }

        let wf_id = req.resolved_workflow_id().ok_or_else(|| {
            N8nError::validation(
                &self.instance_cfg.alias,
                vec!["missing `workflow_id`".to_owned()],
                "`T3 Production` requires an explicit `workflow_id`",
            )
        })?;

        let claims = self.verify_and_consume_receipt(
            req,
            receipt_token,
            TestExecutionMode::Production.receipt_action(),
            required_risk,
        )?;

        let raw_exec = bridge
            .execute_workflow(
                &wf_id,
                "production",
                req.trigger_node.as_deref(),
                trigger_count,
                req.input_data.as_ref(),
            )
            .await?;

        let exec_summary = summarize_execution_redacted(&raw_exec, &req.minimize_options)?;
        let status = map_live_execution_status(&exec_summary);
        let warnings = exec_summary.notes.clone();

        Ok(TestRunResult {
            mode: TestExecutionMode::Production,
            tier: TestExecutionMode::Production.tier_code().to_owned(),
            status,
            mode_guarantee: "live_production_execution_potentially_irreversible_no_auto_retry"
                .to_owned(),
            route_used: RouteUsed::NativeMcp,
            permission: PermissionDecision::Allowed,
            workflow_id: Some(wf_id),
            selected_trigger: resolved_trigger,
            pin_data_tool_used: None,
            attempts_made: 1,
            escalated_to_live_mode: false,
            consumed_receipt_id: Some(claims.receipt_id),
            validation_report: None,
            native_validation_output: None,
            safety_gate: None,
            execution_summary: Some(exec_summary),
            warnings,
            next_actions: vec![
                "Monitor execution status via `n8n_executions`; never auto-retry failed production executions."
                    .to_owned(),
            ],
        })
    }

    fn enforce_common_workflow_guards(
        &self,
        req: &TestRunRequest,
        risk: RiskLevel,
    ) -> N8nResult<()> {
        let mode_label = self.instance_cfg.policy_mode.as_str();
        if req.workflow.is_archived.unwrap_or(false) {
            return Err(N8nError::policy_blocked(
                req.mode.receipt_action(),
                risk,
                mode_label,
                "Archived workflows cannot be executed; unarchive first",
                None,
            ));
        }
        if let (Some(allowlist), Some(wf_id)) = (
            &self.instance_cfg.allowed_workflow_ids,
            req.resolved_workflow_id(),
        ) && !allowlist.contains(&wf_id)
        {
            return Err(N8nError::policy_blocked(
                req.mode.receipt_action(),
                risk,
                mode_label,
                format!("Workflow `{wf_id}` is outside `allowed_workflow_ids` policy"),
                None,
            ));
        }
        let _ = &self.capabilities;
        let _ = &self.api_client;
        Ok(())
    }

    fn verify_and_consume_receipt(
        &self,
        req: &TestRunRequest,
        token: &str,
        action: &str,
        minimum_risk: RiskLevel,
    ) -> N8nResult<ApprovalClaims> {
        let ops_hash = req.compute_ops_hash()?;
        let expected_version_hash = req
            .expected_version_hash
            .clone()
            .or_else(|| Some(req.workflow.canonical_version_hash()));
        let expectation = ApprovalExpectation {
            principal: req.principal.clone(),
            instance: self.instance_cfg.alias.clone(),
            action: action.to_owned(),
            risk: minimum_risk,
            workflow_id: req.resolved_workflow_id(),
            expected_version_hash,
            ops_hash,
        };
        self.policy_engine.receipt_signer().verify_and_consume(
            token,
            &expectation,
            self.instance_cfg.policy_mode.as_str(),
        )
    }

    async fn validate_allowlisted_staging_webhook(
        &self,
        raw_url: &str,
        workflow: &WorkflowIr,
        resolved_trigger: Option<&str>,
    ) -> N8nResult<url::Url> {
        let trimmed = raw_url.trim();
        if !self.allowlisted_staging_webhooks.contains(trimmed) {
            return Err(N8nError::policy_blocked(
                TestExecutionMode::Manual.receipt_action(),
                RiskLevel::R3,
                self.instance_cfg.policy_mode.as_str(),
                format!(
                    "Staging test webhook URL `{}` is not in the explicit staging webhook allowlist",
                    redact_str(trimmed)
                ),
                Some("Add the exact staging test webhook URL to the allowlist or use Native MCP `execute_workflow(manual)`.".to_owned()),
            ));
        }

        // Verify trigger semantics: never silently substitute a webhook call for a Schedule/Manual trigger!
        if let Some(trig_name) = resolved_trigger
            && let Some(trig_node) = workflow.node_by_name(trig_name)
            && !matches!(
                trig_node.node_type.as_str(),
                "n8n-nodes-base.webhook"
                    | "n8n-nodes-base.formTrigger"
                    | "@n8n/n8n-nodes-langchain.chatTrigger"
            )
        {
            return Err(N8nError::unsupported(
                &self.instance_cfg.alias,
                TestExecutionMode::Manual.receipt_action(),
                format!(
                    "Cannot invoke non-HTTP trigger `{}` (`{}`) via staging webhook URL without silently altering trigger semantics",
                    redact_str(trig_name),
                    redact_str(&trig_node.node_type)
                ),
                Some("Enable Native MCP `execute_workflow(manual)` to test Schedule/Manual triggers accurately.".to_owned()),
            ));
        }

        let origin = normalize_and_validate_url(trimmed, &self.webhook_ssrf_policy)?;
        let _addrs = resolve_and_validate_origin(&origin, &self.webhook_ssrf_policy).await?;
        Ok(origin.base_url)
    }

    async fn invoke_allowlisted_webhook_once(
        &self,
        webhook_url: &url::Url,
        input_data: Option<&Value>,
    ) -> N8nResult<Value> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| N8nError::config(format!("webhook HTTP client build error: {e}")))?;

        let payload = input_data.cloned().unwrap_or_else(|| json!({}));
        let resp = client
            .post(webhook_url.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                N8nError::transport(
                    &self.instance_cfg.alias,
                    e.status().map(|s| s.as_u16()),
                    format!(
                        "Staging webhook invocation error: {}",
                        redact_str(&e.to_string())
                    ),
                )
            })?;

        if resp.status().is_redirection() {
            return Err(N8nError::ssrf_blocked(
                webhook_url.as_str(),
                "Staging test webhook returned HTTP redirect (blocked)",
            ));
        }

        let http_status = resp.status();
        let body_bytes =
            read_bounded_response(&self.instance_cfg.alias, resp, self.webhook_stream_budget)
                .await?;

        if !http_status.is_success() {
            let text = String::from_utf8_lossy(&body_bytes);
            let bounded: String = text.chars().take(512).collect();
            return Ok(json!({
                "status": "error",
                "finished": true,
                "error": {
                    "name": format!("WebhookHttp{}", http_status.as_u16()),
                    "message": redact_str(&bounded),
                }
            }));
        }

        if let Ok(parsed) = serde_json::from_slice::<Value>(&body_bytes)
            && parsed.is_object()
        {
            if parsed.get("status").is_some()
                || parsed.get("executionId").is_some()
                || parsed.get("id").is_some()
            {
                return Ok(parsed);
            }
            return Ok(json!({
                "status": "success",
                "finished": true,
                "data": {
                    "resultData": {
                        "runData": {
                            "WebhookResponse": [{
                                "data": {
                                    "main": [[{ "json": parsed }]]
                                }
                            }]
                        }
                    }
                }
            }));
        }

        Ok(json!({
            "status": "success",
            "finished": true,
        }))
    }
}

async fn ensure_bridge_negotiated(bridge: &NativeMcpBridge) -> N8nResult<NegotiatedMcpTools> {
    if let Some(cached) = bridge.cached_negotiated_tools().await {
        return Ok(cached);
    }
    bridge.handshake_and_list_tools().await
}

fn resolve_pin_payload(req: &TestRunRequest) -> Option<Value> {
    if let Some(ref pd) = req.pin_data
        && pd.as_object().is_some_and(|m| !m.is_empty())
    {
        return Some(pd.clone());
    }
    if let Some(ref wf_pd) = req.workflow.pin_data
        && !wf_pd.is_empty()
    {
        return serde_json::to_value(wf_pd).ok();
    }
    None
}

fn validate_trigger_selection(
    workflow: &WorkflowIr,
    requested_trigger: Option<&str>,
) -> N8nResult<(usize, Option<String>)> {
    let topology = WorkflowGraph::from_ir(workflow).analyze();
    let trigger_count = topology.primary_triggers.len();

    if let Some(trig) = requested_trigger {
        let Some(node) = workflow.node_by_name(trig) else {
            return Err(N8nError::validation(
                "local",
                vec![format!(
                    "trigger node `{}` does not exist",
                    redact_str(trig)
                )],
                "invalid `trigger_node` selection",
            ));
        };
        if node.disabled || !is_primary_trigger_type(&node.node_type) {
            return Err(N8nError::validation(
                "local",
                vec![format!(
                    "node `{}` (`{}`) is disabled or not a primary workflow trigger",
                    redact_str(trig),
                    redact_str(&node.node_type)
                )],
                "invalid `trigger_node` selection",
            ));
        }
        return Ok((trigger_count, Some(trig.to_owned())));
    }

    if trigger_count > 1 {
        return Err(N8nError::validation(
            "local",
            vec![format!(
                "workflow has {trigger_count} enabled primary triggers ({}); specify `trigger_node` explicitly",
                topology.primary_triggers.join(", ")
            )],
            "ambiguous multi-trigger workflow selection",
        ));
    }

    Ok((trigger_count, topology.primary_triggers.first().cloned()))
}

const fn map_live_execution_status(summary: &MinimizedExecutionReport) -> TestOutcomeStatus {
    if summary.is_terminal_success {
        TestOutcomeStatus::ExecutionSucceeded
    } else if !summary.finished {
        TestOutcomeStatus::ExecutionStartedNonTerminal
    } else {
        TestOutcomeStatus::ExecutionFailed
    }
}
