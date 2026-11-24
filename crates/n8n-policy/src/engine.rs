//! Server-enforced AND-gate policy evaluator (`PolicyEngine`) combining `PolicyMode`,
//! `RiskLevel` (`R0..R4`), protected-instance overrides, allowlists, and `ApprovalReceipt`s.

use std::sync::Arc;

use n8n_capability::{
    CapabilityProfile, CapabilityState, LogicalOperation, select_operation_route,
};
use n8n_types::{EnvironmentKind, N8nError, N8nResult, PermissionDecision, RiskLevel, RouteUsed};

use crate::config::{InstancePolicyConfig, PolicyMode};
use crate::locks::{WorkflowLockRegistry, enforce_batch_cap};
use crate::receipt::{ApprovalClaims, ApprovalExpectation, ReceiptSigner};

/// Input describing a concrete operation under evaluation by `PolicyEngine`.
#[derive(Debug, Clone)]
pub struct PolicyCheckRequest {
    pub principal: String,
    pub requested_instance: String,
    pub action: String,
    pub logical_op: LogicalOperation,
    pub risk: RiskLevel,
    pub workflow_id: Option<String>,
    pub project_id: Option<String>,
    pub is_archived_workflow: bool,
    pub expected_version_hash: Option<String>,
    pub ops_hash: String,
    /// True when the caller already ran preview and explicitly submitted `apply` for an `R2` staging draft edit.
    pub explicit_apply_intent: bool,
    pub approval_receipt_token: Option<String>,
    pub batch_workflow_count: Option<usize>,
}

/// Verified outcome of a passing `PolicyEngine` evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheckOutcome {
    pub permission: PermissionDecision,
    pub route: RouteUsed,
    pub consumed_receipt: Option<ApprovalClaims>,
}

/// Server-enforced policy engine holding the `ReceiptSigner` and `WorkflowLockRegistry`.
#[derive(Clone)]
pub struct PolicyEngine {
    signer: Arc<ReceiptSigner>,
    locks: WorkflowLockRegistry,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(ReceiptSigner::new_random())
    }
}

impl PolicyEngine {
    #[must_use]
    pub fn new(signer: ReceiptSigner) -> Self {
        Self {
            signer: Arc::new(signer),
            locks: WorkflowLockRegistry::new(),
        }
    }

    #[must_use]
    pub fn receipt_signer(&self) -> &ReceiptSigner {
        &self.signer
    }

    #[must_use]
    pub fn lock_registry(&self) -> &WorkflowLockRegistry {
        &self.locks
    }

    /// Evaluates the strict AND-gate across instance binding, batch caps, allowlists,
    /// archived/protected flags, `PolicyMode` (`R0..R4`), live capability routes, and `ApprovalReceipt`s.
    ///
    /// **Any deny wins.**
    pub fn evaluate(
        &self,
        instance_cfg: &InstancePolicyConfig,
        capabilities: &CapabilityProfile,
        req: &PolicyCheckRequest,
    ) -> N8nResult<PolicyCheckOutcome> {
        let mode_label = instance_cfg.policy_mode.as_str();

        // 1. Instance alias pinning: never allow mutating or crossing into another instance!
        if req.requested_instance != instance_cfg.alias {
            return Err(N8nError::policy_blocked(
                &req.action,
                req.risk,
                mode_label,
                format!(
                    "Target instance `{}` does not match bound instance `{}`",
                    req.requested_instance, instance_cfg.alias
                ),
                None,
            ));
        }

        instance_cfg.validate()?;

        // 2. Batch cap check (<= 20 workflows)
        if let Some(count) = req.batch_workflow_count {
            enforce_batch_cap(count, instance_cfg.max_batch_workflows, mode_label)?;
        }

        // 3. Workflow & project allowlists
        if let (Some(allow_wfs), Some(wf_id)) =
            (&instance_cfg.allowed_workflow_ids, &req.workflow_id)
            && !allow_wfs.contains(wf_id)
        {
            return Err(N8nError::policy_blocked(
                &req.action,
                req.risk,
                mode_label,
                format!("Workflow `{wf_id}` is outside the configured workflow allowlist"),
                None,
            ));
        }
        if let (Some(allow_projs), Some(proj_id)) =
            (&instance_cfg.allowed_project_ids, &req.project_id)
            && !allow_projs.contains(proj_id)
        {
            return Err(N8nError::policy_blocked(
                &req.action,
                req.risk,
                mode_label,
                format!("Project `{proj_id}` is outside the configured project allowlist"),
                None,
            ));
        }

        // 4. Archived workflow protection
        if req.is_archived_workflow
            && req.risk >= RiskLevel::R2
            && !matches!(
                req.action.as_str(),
                "workflows.unarchive" | "workflows.delete"
            )
        {
            return Err(N8nError::policy_blocked(
                &req.action,
                req.risk,
                mode_label,
                "Target workflow is archived; unarchive before mutating or publishing",
                None,
            ));
        }

        // 5. CRITICAL AND-GATE RULE: `read-only` blocks ALL effect-producing calls (`R2..R4`) AND
        // explicitly blocks `execute_workflow(production|manual)` and `test_workflow(simulate)` even
        // when n8n 2.47+ protected-instance Native MCP permits `execute_workflow(production)`!
        let is_any_live_or_sim_exec = matches!(
            req.logical_op,
            LogicalOperation::TestWorkflowSimulate
                | LogicalOperation::TestWorkflowManual
                | LogicalOperation::TestWorkflowProduction
        );

        if instance_cfg.policy_mode == PolicyMode::ReadOnly
            && (req.risk >= RiskLevel::R2 || is_any_live_or_sim_exec)
        {
            return Err(N8nError::policy_blocked(
                &req.action,
                req.risk,
                mode_label,
                "Policy `read-only` strictly forbids all writes and workflow executions (including `execute_workflow(production)` on protected instances)",
                None,
            ));
        }

        // 6. Capability & route check (fail-closed)
        let route_decision = select_operation_route(capabilities, req.logical_op);
        if route_decision.state != CapabilityState::Available {
            return Err(N8nError::unsupported(
                &instance_cfg.alias,
                &req.action,
                route_decision.reason,
                route_decision.prerequisites.into_iter().next(),
            ));
        }

        // 7. PolicyMode x Environment x RiskLevel (`R0..R4`) matrix
        let needs_cryptographic_receipt = match instance_cfg.policy_mode {
            PolicyMode::ReadOnly => false, // R0/R1 only reached here
            PolicyMode::StagingSafe => {
                if instance_cfg.environment == EnvironmentKind::Production
                    && req.risk >= RiskLevel::R2
                {
                    return Err(N8nError::policy_blocked(
                        &req.action,
                        req.risk,
                        mode_label,
                        "`staging-safe` policy forbids mutating or executing on a `production` instance",
                        Some("Use `read-only` or explicitly enable `production-guarded` with per-action confirmation.".to_owned()),
                    ));
                }
                match req.risk {
                    RiskLevel::R0 | RiskLevel::R1 => false,
                    RiskLevel::R2 => {
                        if req.approval_receipt_token.is_some() {
                            true
                        } else if req.explicit_apply_intent {
                            false
                        } else {
                            return Err(N8nError::policy_blocked(
                                &req.action,
                                req.risk,
                                mode_label,
                                "Staging draft write (`R2`) requires preview first followed by explicit apply intent or ApprovalReceipt",
                                Some(
                                    "Run preview first to inspect the diff before applying."
                                        .to_owned(),
                                ),
                            ));
                        }
                    }
                    RiskLevel::R3 => true,
                    RiskLevel::R4 => {
                        if !instance_cfg.enable_r4_admin_actions {
                            return Err(N8nError::policy_blocked(
                                &req.action,
                                req.risk,
                                mode_label,
                                "Destructive/admin operation (`R4`) is disabled by default under `staging-safe`",
                                Some("Enable `enable_r4_admin_actions = true` in policy TOML and provide an ApprovalReceipt.".to_owned()),
                            ));
                        }
                        true
                    }
                }
            }
            PolicyMode::ProductionGuarded => match req.risk {
                RiskLevel::R0 | RiskLevel::R1 => false,
                RiskLevel::R2 | RiskLevel::R3 => true,
                RiskLevel::R4 => {
                    if !instance_cfg.enable_r4_admin_actions {
                        return Err(N8nError::policy_blocked(
                            &req.action,
                            req.risk,
                            mode_label,
                            "Destructive/admin operation (`R4`) is disabled under default `production-guarded` policy",
                            Some("Explicitly enable `enable_r4_admin_actions` and supply a human ApprovalReceipt.".to_owned()),
                        ));
                    }
                    true
                }
            },
            PolicyMode::FullDev => match req.risk {
                RiskLevel::R0 | RiskLevel::R1 | RiskLevel::R2 => false,
                RiskLevel::R3 => true,
                RiskLevel::R4 => {
                    if !instance_cfg.enable_r4_admin_actions {
                        return Err(N8nError::policy_blocked(
                            &req.action,
                            req.risk,
                            mode_label,
                            "Admin/destructive (`R4`) action requires `enable_r4_admin_actions` even in `full-dev`",
                            None,
                        ));
                    }
                    true
                }
            },
        };

        let consumed_receipt = if needs_cryptographic_receipt {
            let Some(ref token) = req.approval_receipt_token else {
                return Err(N8nError::policy_blocked(
                    &req.action,
                    req.risk,
                    mode_label,
                    format!(
                        "Operation `{}` ({}) requires a cryptographic single-use ApprovalReceipt",
                        req.action,
                        req.risk.label()
                    ),
                    Some("Run preview first, present the diff and side-effect summary to the user, and obtain an `n8n_rcpt_v1.*` confirmation receipt.".to_owned()),
                ));
            };
            let expectation = ApprovalExpectation {
                principal: req.principal.clone(),
                instance: instance_cfg.alias.clone(),
                action: req.action.clone(),
                risk: req.risk,
                workflow_id: req.workflow_id.clone(),
                expected_version_hash: req.expected_version_hash.clone(),
                ops_hash: req.ops_hash.clone(),
            };
            Some(
                self.signer
                    .verify_and_consume(token, &expectation, mode_label)?,
            )
        } else {
            None
        };

        Ok(PolicyCheckOutcome {
            permission: PermissionDecision::Allowed,
            route: route_decision.route,
            consumed_receipt,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Utc;
    use n8n_capability::{CapabilityProfile, DiscoverySource, LogicalOperation, NativeMcpStatus};
    use n8n_mcp_bridge::{NegotiatedMcpTools, PinDataToolName};
    use n8n_types::{EnvironmentKind, N8nError, PermissionDecision, RiskLevel, RouteUsed};
    use serde_json::json;

    use crate::{
        ApprovalExpectation, InstancePolicyConfig, MAX_BATCH_WORKFLOWS, PolicyCheckRequest,
        PolicyEngine, PolicyMode, ReceiptSigner, WorkflowLockRegistry, enforce_batch_cap, hash_ops,
        load_workspace_config,
    };

    fn sample_capabilities(protected_with_exec: bool) -> CapabilityProfile {
        let mut scopes = BTreeSet::new();
        scopes.insert("workflow:read".to_owned());
        scopes.insert("workflow:list".to_owned());
        scopes.insert("workflow:create".to_owned());
        scopes.insert("workflow:update".to_owned());
        scopes.insert("workflow:publish".to_owned());
        let mut resources = BTreeSet::new();
        resources.insert("workflow".to_owned());

        let mcp_tools = NegotiatedMcpTools {
            has_execute_workflow: true,
            has_test_workflow: true,
            pin_data_tool: PinDataToolName::PrepareWorkflowPinData,
            protected_instance_suspected: protected_with_exec,
            ..Default::default()
        };

        CapabilityProfile {
            instance_alias: "prod".to_owned(),
            principal_fingerprint: "p_123".to_owned(),
            resolved_at: Utc::now(),
            discovery_source: DiscoverySource::DiscoverEndpoint,
            n8n_version: Some("2.48.7".to_owned()),
            scopes_advertised: true,
            scopes,
            advertised_resources: resources,
            advertised_operations: BTreeSet::new(),
            openapi_paths: BTreeSet::new(),
            protected_instance: protected_with_exec,
            rate_limits_configured: false,
            native_mcp: NativeMcpStatus::Connected {
                tools: Box::new(mcp_tools),
            },
            tools: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn read_only_and_gate_blocks_execute_workflow_production_on_protected_instance() {
        let engine = PolicyEngine::default();
        let cfg = InstancePolicyConfig {
            alias: "prod".to_owned(),
            url: "https://n8n.example.internal".to_owned(),
            environment: EnvironmentKind::Production,
            policy_mode: PolicyMode::ReadOnly,
            api_key: None,
            mcp_base_url: None,
            mcp_access_token: None,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            allow_loopback_http: false,
            trust_configured_private_host: false,
            enable_r4_admin_actions: false,
            max_batch_workflows: MAX_BATCH_WORKFLOWS,
            allowed_workflow_ids: None,
            allowed_project_ids: None,
        };
        let caps = sample_capabilities(true);

        let req = PolicyCheckRequest {
            principal: "p_123".to_owned(),
            requested_instance: "prod".to_owned(),
            action: "test_workflow.production".to_owned(),
            logical_op: LogicalOperation::TestWorkflowProduction,
            risk: RiskLevel::R3,
            workflow_id: Some("wf_1".to_owned()),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: Some("v1".to_owned()),
            ops_hash: "h1".to_owned(),
            explicit_apply_intent: true,
            approval_receipt_token: None,
            batch_workflow_count: None,
        };

        let res = engine.evaluate(&cfg, &caps, &req);
        assert!(matches!(res, Err(N8nError::PolicyBlocked { .. })));
    }

    #[test]
    fn cryptographic_receipt_is_single_use_and_rejects_tampering_or_target_drift() {
        let signer = ReceiptSigner::from_secret_seed("unit_test_seed_key");
        let engine = PolicyEngine::new(signer);
        let ops_digest = hash_ops(&json!([{ "op": "publish" }])).expect("hash ops");

        let exp = ApprovalExpectation {
            principal: "p_123".to_owned(),
            instance: "prod".to_owned(),
            action: "workflows.publish".to_owned(),
            risk: RiskLevel::R3,
            workflow_id: Some("wf_abc".to_owned()),
            expected_version_hash: Some("ver_draft_9".to_owned()),
            ops_hash: ops_digest.clone(),
        };

        let (_receipt, token) = engine.receipt_signer().mint(&exp, 300).expect("mint");

        let cfg = InstancePolicyConfig {
            alias: "prod".to_owned(),
            url: "https://n8n.example.internal".to_owned(),
            environment: EnvironmentKind::Production,
            policy_mode: PolicyMode::ProductionGuarded,
            api_key: None,
            mcp_base_url: None,
            mcp_access_token: None,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            allow_loopback_http: false,
            trust_configured_private_host: false,
            enable_r4_admin_actions: false,
            max_batch_workflows: MAX_BATCH_WORKFLOWS,
            allowed_workflow_ids: None,
            allowed_project_ids: None,
        };
        let caps = sample_capabilities(false);

        // Model-fabricated token rejected
        let fake_req = PolicyCheckRequest {
            principal: "p_123".to_owned(),
            requested_instance: "prod".to_owned(),
            action: "workflows.publish".to_owned(),
            logical_op: LogicalOperation::WorkflowsPublish,
            risk: RiskLevel::R3,
            workflow_id: Some("wf_abc".to_owned()),
            project_id: None,
            is_archived_workflow: false,
            expected_version_hash: Some("ver_draft_9".to_owned()),
            ops_hash: ops_digest.clone(),
            explicit_apply_intent: true,
            approval_receipt_token: Some("apply=true".to_owned()),
            batch_workflow_count: None,
        };
        assert!(matches!(
            engine.evaluate(&cfg, &caps, &fake_req),
            Err(N8nError::PolicyBlocked { .. })
        ));

        // Workflow version drift (TOCTOU) rejected WITHOUT consuming valid receipt for wrong target
        let drift_req = PolicyCheckRequest {
            expected_version_hash: Some("ver_draft_10_modified_by_ui".to_owned()),
            approval_receipt_token: Some(token.clone()),
            ..fake_req.clone()
        };
        assert!(matches!(
            engine.evaluate(&cfg, &caps, &drift_req),
            Err(N8nError::PolicyBlocked { .. })
        ));

        // First valid commit succeeds!
        let valid_req = PolicyCheckRequest {
            approval_receipt_token: Some(token.clone()),
            ..fake_req
        };
        let ok = engine
            .evaluate(&cfg, &caps, &valid_req)
            .expect("first use succeeds");
        assert_eq!(ok.permission, PermissionDecision::Allowed);
        assert_eq!(ok.route, RouteUsed::PublicApi);

        // Second replay of the exact same receipt is rejected!
        let replay = engine.evaluate(&cfg, &caps, &valid_req);
        assert!(matches!(replay, Err(N8nError::PolicyBlocked { .. })));
    }

    #[tokio::test]
    async fn batch_cap_blocks_30_workflows_and_lock_registry_serializes_same_workflow() {
        // U10: 30 workflows blocked by default batch cap = 20
        assert!(matches!(
            enforce_batch_cap(30, MAX_BATCH_WORKFLOWS, "staging-safe"),
            Err(N8nError::PolicyBlocked { .. })
        ));
        assert!(enforce_batch_cap(20, MAX_BATCH_WORKFLOWS, "staging-safe").is_ok());

        let registry = WorkflowLockRegistry::new();
        let guard1 = registry.acquire_write_lock("staging", "wf_1").await;
        assert!(registry.try_acquire_write_lock("staging", "wf_1").is_none());
        // Different workflow is not blocked!
        assert!(registry.try_acquire_write_lock("staging", "wf_2").is_some());
        drop(guard1);
        assert!(registry.try_acquire_write_lock("staging", "wf_1").is_some());
    }

    #[test]
    fn config_loader_blocks_full_dev_on_production() {
        let res = load_workspace_config(None, None, None, Some(PolicyMode::FullDev), |k| match k {
            "N8N_ENVIRONMENT" => Some("production".to_owned()),
            "N8N_API_URL" => Some("https://n8n.example.internal".to_owned()),
            _ => None,
        });
        assert!(matches!(res, Err(N8nError::Config { .. })));
    }

    #[test]
    fn config_loader_reads_instances_and_policy_toml_files_without_plaintext_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let instances_path = dir.path().join("instances.toml");
        let policy_path = dir.path().join("policy.staging.toml");

        std::fs::write(
            &instances_path,
            r#"
[instances.staging]
url = "https://staging-n8n.example.internal"
environment = "staging"
policy = "staging-safe"
api_key_env = "N8N_STAGING_API_KEY"
mcp_base_url = "https://staging-n8n.example.internal/mcp-server/http"
mcp_token_env = "N8N_STAGING_MCP_TOKEN"

[instances.prod]
url = "https://n8n.example.internal"
environment = "production"
policy = "read-only"
api_key_env = "N8N_PROD_API_KEY"
"#,
        )
        .expect("write instances.toml");

        std::fs::write(
            &policy_path,
            r#"
max_batch_workflows = 15
enable_r4_admin_actions = false
allowed_workflow_ids = ["wf_allowed_1", "wf_allowed_2"]
"#,
        )
        .expect("write policy.toml");

        let loaded = load_workspace_config(
            Some(&instances_path),
            Some(&policy_path),
            Some("staging"),
            None,
            |k| match k {
                "N8N_STAGING_API_KEY" => Some("staging_secret_api_key".to_owned()),
                "N8N_STAGING_MCP_TOKEN" => Some("staging_isolated_mcp_token".to_owned()),
                _ => None,
            },
        )
        .expect("load workspace config");

        let staging = loaded.active().expect("active staging");
        assert_eq!(staging.alias, "staging");
        assert_eq!(staging.policy_mode, PolicyMode::StagingSafe);
        assert_eq!(staging.max_batch_workflows, 15);
        assert!(staging.api_key.is_some());
        assert!(staging.mcp_access_token.is_some());

        let prod = loaded.get_instance(Some("prod")).expect("prod profile");
        assert_eq!(prod.policy_mode, PolicyMode::ReadOnly);
    }
}
