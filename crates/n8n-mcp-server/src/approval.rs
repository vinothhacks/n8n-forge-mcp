use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use n8n_policy::{ApprovalExpectation, ApprovalReceipt, ReceiptSigner, hash_ops};
use n8n_types::{BoundedDiffSummary, N8nError, N8nResult, RiskLevel, redact_json_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const MAX_ACTIVE_PLANS: usize = 512;
const DEFAULT_PLAN_TTL_SECS: i64 = 900;

/// Stored preview plan awaiting explicit operator confirmation before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApprovalPlan {
    pub plan_id: String,
    pub principal: String,
    pub instance: String,
    pub action: String,
    pub risk: RiskLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version_hash: Option<String>,
    pub ops_hash: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<BoundedDiffSummary>,
    #[serde(default)]
    pub diff_payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub confirmed: bool,
}

/// Parameters to register a new preview plan in [`ApprovalManager`].
#[derive(Debug, Clone)]
pub struct PreviewPlanInit {
    pub principal: String,
    pub instance: String,
    pub action: String,
    pub risk: RiskLevel,
    pub workflow_id: Option<String>,
    pub expected_version_hash: Option<String>,
    pub ops_hash: String,
    pub summary: String,
    pub diff: Option<BoundedDiffSummary>,
    pub diff_payload: Value,
    pub side_effects: Vec<String>,
    pub ttl_secs: Option<i64>,
}

/// Manages preview plans and mints single-use cryptographic `ApprovalReceipt`s bound to
/// `(principal, instance, action, risk, workflow_id, expected_version_hash, ops_hash, expires_at)`.
#[derive(Clone, Default)]
pub struct ApprovalManager {
    plans: Arc<Mutex<BTreeMap<String, PendingApprovalPlan>>>,
}

impl std::fmt::Debug for ApprovalManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        f.debug_struct("ApprovalManager")
            .field("active_plans", &count)
            .finish()
    }
}

impl ApprovalManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministically hash an operations/payload JSON value for receipt binding.
    pub fn compute_ops_hash(payload: &Value) -> N8nResult<String> {
        hash_ops(payload)
    }

    /// Store a bounded, secret-redacted preview plan and return its record.
    pub fn create_preview_plan(&self, init: PreviewPlanInit) -> PendingApprovalPlan {
        let now = Utc::now();
        let ttl = init
            .ttl_secs
            .unwrap_or(DEFAULT_PLAN_TTL_SECS)
            .clamp(30, 900);
        let plan_id = format!("plan_{}", Uuid::new_v4().simple());
        let sanitized_payload = redact_json_value(&init.diff_payload);
        let plan = PendingApprovalPlan {
            plan_id: plan_id.clone(),
            principal: init.principal,
            instance: init.instance,
            action: init.action,
            risk: init.risk,
            workflow_id: init.workflow_id,
            expected_version_hash: init.expected_version_hash,
            ops_hash: init.ops_hash,
            summary: init.summary,
            diff: init.diff,
            diff_payload: sanitized_payload,
            side_effects: init.side_effects,
            created_at: now,
            expires_at: now + Duration::seconds(ttl),
            confirmed: false,
        };

        let mut guard = self
            .plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, existing| existing.expires_at > now);
        if guard.len() >= MAX_ACTIVE_PLANS
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, p)| p.created_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest_key);
        }
        guard.insert(plan_id, plan.clone());
        plan
    }

    /// Retrieve a non-expired preview plan by `plan_id`.
    #[must_use]
    pub fn get_plan(&self, plan_id: &str) -> Option<PendingApprovalPlan> {
        let now = Utc::now();
        let mut guard = self
            .plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, existing| existing.expires_at > now);
        guard.get(plan_id).cloned()
    }

    /// Retrieve a non-expired plan scoped to `(instance, workflow_id, plan_id)` for MCP resources.
    #[must_use]
    pub fn get_plan_for_resource(
        &self,
        instance: &str,
        workflow_id: &str,
        plan_id: &str,
    ) -> Option<PendingApprovalPlan> {
        self.get_plan(plan_id).filter(|p| {
            p.instance == instance
                && p.workflow_id
                    .as_deref()
                    .is_none_or(|wf_id| wf_id == workflow_id)
        })
    }

    /// List active non-expired plans that have a `workflow_id` (for `resources/list`).
    #[must_use]
    pub fn list_active_plans(&self, limit: usize) -> Vec<PendingApprovalPlan> {
        let now = Utc::now();
        let mut guard = self
            .plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, existing| existing.expires_at > now);
        guard.values().take(limit.clamp(1, 100)).cloned().collect()
    }

    /// Confirm an existing preview plan and mint a single-use cryptographic `ApprovalReceipt`.
    pub fn confirm_plan_and_issue_receipt(
        &self,
        signer: &ReceiptSigner,
        principal: &str,
        instance: &str,
        policy_mode: &str,
        plan_id: &str,
        ttl_secs: i64,
    ) -> N8nResult<(PendingApprovalPlan, ApprovalReceipt, String)> {
        let now = Utc::now();
        let plan = {
            let mut guard = self
                .plans
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.retain(|_, existing| existing.expires_at > now);
            let Some(plan) = guard.get_mut(plan_id) else {
                return Err(N8nError::policy_blocked(
                    "workflows.confirm_plan",
                    RiskLevel::R2,
                    policy_mode,
                    format!(
                        "Preview plan `{plan_id}` was not found or has expired; generate a fresh preview first"
                    ),
                    Some("Run preview first to obtain a valid `planId`.".to_owned()),
                ));
            };
            if plan.principal != principal {
                return Err(N8nError::policy_blocked(
                    &plan.action,
                    plan.risk,
                    policy_mode,
                    "Preview plan principal mismatch",
                    None,
                ));
            }
            if plan.instance != instance {
                return Err(N8nError::policy_blocked(
                    &plan.action,
                    plan.risk,
                    policy_mode,
                    format!(
                        "Preview plan `{plan_id}` belongs to instance `{}`, not `{instance}`",
                        plan.instance
                    ),
                    None,
                ));
            }
            plan.confirmed = true;
            plan.clone()
        };

        let expectation = ApprovalExpectation {
            principal: principal.to_owned(),
            instance: instance.to_owned(),
            action: plan.action.clone(),
            risk: plan.risk,
            workflow_id: plan.workflow_id.clone(),
            expected_version_hash: plan.expected_version_hash.clone(),
            ops_hash: plan.ops_hash.clone(),
        };
        let (receipt, signed_token) = signer.mint(&expectation, ttl_secs.clamp(30, 900))?;
        Ok((plan, receipt, signed_token))
    }

    /// Mint a direct bound single-use `ApprovalReceipt` after explicit operator confirmation.
    pub fn issue_approval_receipt(
        &self,
        signer: &ReceiptSigner,
        expectation: &ApprovalExpectation,
        ttl_secs: i64,
    ) -> N8nResult<(ApprovalReceipt, String)> {
        signer.mint(expectation, ttl_secs.clamp(30, 900))
    }
}
