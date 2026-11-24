//! Crash-safe `StartupReconciler` integrating `n8n_state_vault::OperationJournal`
//! (`CleanupLeaseRecord` and `UnknownResult` operations) with `N8nApiClient` (V2 Section 8 & 9).
//!
//! Safety invariants:
//! - **Write-ahead lease acquisition:** [`StartupReconciler::acquire_test_workflow_lease`] writes a
//!   durable `CleanupLeaseRecord` to SQLite WAL **before** creating any temporary `[MCP-E2E-TEST]`
//!   workflow over the network.
//! - **Verified cleanup:** [`StartupReconciler::release_and_cleanup_lease`] unpublishes/deactivates
//!   if active, deletes the workflow, verifies HTTP `404` on read-back `GET /api/v1/workflows/{id}`,
//!   and closes the lease (`CleanedVerified`), or marks `CleanupRequired` if any step fails.
//! - **Prefix safety rail:** Refuses to delete any remote workflow whose name does NOT start with
//!   `[MCP-E2E-TEST]`.
//! - **Zero reliance on `Drop`:** `StartupReconciler` intentionally implements NO `Drop` trait;
//!   process crashes and power loss are recovered deterministically via [`StartupReconciler::reconcile_startup`].

use n8n_api_client::{ListQueryParams, N8nApiClient, Outcome, WorkflowResource};
use n8n_graph::WorkflowIr;
use n8n_state_vault::{
    CleanupLeaseRecord, CleanupLeaseState, JournalRecord, JournalState, JournalTransitionInput,
    OperationJournal,
};
use n8n_types::{N8nError, N8nResult, RiskLevel, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// Mandatory name prefix required on all ephemeral/isolated test workflows managed by cleanup leases.
pub const E2E_TEST_WORKFLOW_PREFIX: &str = "[MCP-E2E-TEST]";

/// Default cleanup lease TTL (15 minutes).
pub const DEFAULT_TEST_LEASE_TTL_SECS: i64 = 15 * 60;

/// Compact reconciliation summary preserved with exact field compatibility for `n8n-mcp-cli`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileSummary {
    pub instance: String,
    pub dry_run: bool,
    pub pending_leases_checked: usize,
    pub uncertain_operations_found: usize,
    pub notes: Vec<String>,
}

/// Outcome of reconciling or releasing a single [`CleanupLeaseRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LeaseCleanupOutcome {
    /// Workflow was unpublished/deactivated (if active), deleted, and confirmed absent via `404` read-back.
    CleanedAndVerified404 { workflow_id: String },
    /// Workflow was already absent (`404` on initial `GET`) or never created prior to pre-create crash.
    AlreadyAbsentVerified404 { workflow_id: Option<String> },
    /// Dry-run inspection only; no remote mutation executed.
    DryRunWouldClean { workflow_id: Option<String> },
    /// Cleanup failed or prefix safety check failed; lease marked `cleanup_required` for operator alert!
    CleanupRequired {
        workflow_id: Option<String>,
        reason: String,
    },
}

/// Per-lease audit entry inside [`StartupReconcileReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeaseReconcileEntry {
    pub lease_id: String,
    pub workflow_name_tag: String,
    pub outcome: LeaseCleanupOutcome,
    pub final_lease_state: CleanupLeaseState,
}

/// Outcome of reconciling a single `Writing` / `Verifying` / `UnknownResult` journal operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum UncertainOperationOutcome {
    /// Read-back confirmed the target workflow exists; journal transitioned to `Verified`.
    ReconciledVerifiedPresent {
        workflow_id: String,
        version_hash: String,
    },
    /// Orphaned `[MCP-E2E-TEST]` workflow from an interrupted test operation was deleted + `404` verified.
    CleanedOrphanedTestWorkflow { workflow_id: String },
    /// Read-back returned `404` for a timed-out create (or confirmed a delete); journal resolved cleanly.
    ReconciledAbsent404 { resolved_state: JournalState },
    /// Dry-run inspection only; journal not mutated.
    DryRunInspected,
    /// Remote verification could not conclusively resolve state (e.g. 5xx or offline); kept `UnknownResult`.
    RemainsUncertain { reason: String },
}

/// Per-operation audit entry inside [`StartupReconcileReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UncertainOperationReconcileEntry {
    pub operation_id: String,
    pub action: String,
    pub workflow_id: Option<String>,
    pub outcome: UncertainOperationOutcome,
}

/// Full startup reconciliation report embedding [`ReconcileSummary`] plus per-lease and per-operation outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartupReconcileReport {
    pub summary: ReconcileSummary,
    pub leases_cleaned: usize,
    pub leases_marked_cleanup_required: usize,
    pub uncertain_operations_resolved: usize,
    pub uncertain_operations_remaining: usize,
    pub lease_entries: Vec<LeaseReconcileEntry>,
    pub operation_entries: Vec<UncertainOperationReconcileEntry>,
}

/// Crash-safe test workflow lease manager and startup journal reconciler.
///
/// Explicitly implements **NO `Drop` handler** — cleanup relies on durable write-ahead SQLite
/// leases and verified HTTP read-backs, never best-effort destructors.
#[derive(Debug, Clone)]
pub struct StartupReconciler {
    instance_alias: String,
}

impl StartupReconciler {
    #[must_use]
    pub fn new(instance_alias: impl Into<String>) -> Self {
        Self {
            instance_alias: instance_alias.into(),
        }
    }

    #[must_use]
    pub fn instance_alias(&self) -> &str {
        &self.instance_alias
    }

    /// Writes a durable `CleanupLeaseRecord` (`AcquiredPreCreate`) to `journal` **BEFORE** creating
    /// any temporary `[MCP-E2E-TEST]` workflow on n8n.
    pub fn acquire_test_workflow_lease(
        &self,
        journal: &mut OperationJournal,
        principal_id: &str,
        workflow_name: &str,
        ttl_secs: Option<i64>,
    ) -> N8nResult<CleanupLeaseRecord> {
        ensure_test_workflow_prefix(&self.instance_alias, workflow_name)?;
        let effective_ttl = ttl_secs.unwrap_or(DEFAULT_TEST_LEASE_TTL_SECS).max(1);
        journal.acquire_cleanup_lease(
            principal_id,
            &self.instance_alias,
            "ephemeral_test_workflow",
            workflow_name.trim(),
            effective_ttl,
        )
    }

    /// Binds a newly created `[MCP-E2E-TEST]` `workflow_id` onto an acquired lease (`ActiveResourceCreated`).
    pub fn bind_created_test_workflow(
        &self,
        journal: &mut OperationJournal,
        lease_id: &str,
        workflow_id: &str,
        note: Option<&str>,
    ) -> N8nResult<CleanupLeaseRecord> {
        journal.bind_cleanup_lease_workflow(lease_id, workflow_id, note)
    }

    /// Acquires a durable pre-create lease, creates an inactive (`active = false`) `[MCP-E2E-TEST]`
    /// draft workflow via `api_client`, and binds the resulting `workflow_id` (or records `UnknownResult`
    /// on timeout so `reconcile_startup` cleans up any orphaned resource).
    pub async fn create_leased_test_workflow(
        &self,
        journal: &mut OperationJournal,
        api_client: &N8nApiClient,
        principal_id: &str,
        workflow_body: &Value,
        ttl_secs: Option<i64>,
    ) -> N8nResult<(CleanupLeaseRecord, WorkflowResource)> {
        let wf_name = workflow_body
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("");
        ensure_test_workflow_prefix(&self.instance_alias, wf_name)?;

        // 1. Durable write-ahead cleanup lease BEFORE network POST!
        let lease = self.acquire_test_workflow_lease(journal, principal_id, wf_name, ttl_secs)?;

        let mut safe_draft = workflow_body.clone();
        if let Some(obj) = safe_draft.as_object_mut() {
            obj.insert("active".to_owned(), Value::Bool(false));
        }

        let op_id = format!("op_testwf_{}", Uuid::now_v7().simple());
        for st in [
            JournalState::Planned,
            JournalState::Preparing,
            JournalState::Writing,
        ] {
            let _ = journal.append_transition(JournalTransitionInput {
                operation_id: op_id.clone(),
                next_state: st,
                principal_id: principal_id.to_owned(),
                instance_id: self.instance_alias.clone(),
                workflow_id: None,
                action: "test_workflow.ephemeral_create".to_owned(),
                base_version_hash: None,
                resulting_version_hash: None,
                ops_hash: None,
                details: json!({
                    "leaseId": lease.lease_id,
                    "workflowName": wf_name.trim(),
                }),
            })?;
        }

        match api_client.create_workflow(&op_id, &safe_draft).await? {
            Outcome::Confirmed { value } => {
                let bound_lease = journal.bind_cleanup_lease_workflow(
                    &lease.lease_id,
                    &value.id,
                    Some("created inactive [MCP-E2E-TEST] draft"),
                )?;
                let _ = journal.append_transition(JournalTransitionInput {
                    operation_id: op_id.clone(),
                    next_state: JournalState::Verifying,
                    principal_id: principal_id.to_owned(),
                    instance_id: self.instance_alias.clone(),
                    workflow_id: Some(value.id.clone()),
                    action: "test_workflow.ephemeral_create".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: value.version_id.clone(),
                    ops_hash: None,
                    details: json!({ "leaseId": bound_lease.lease_id }),
                })?;
                let _ = journal.append_transition(JournalTransitionInput {
                    operation_id: op_id,
                    next_state: JournalState::Verified,
                    principal_id: principal_id.to_owned(),
                    instance_id: self.instance_alias.clone(),
                    workflow_id: Some(value.id.clone()),
                    action: "test_workflow.ephemeral_create".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: value.version_id.clone(),
                    ops_hash: None,
                    details: json!({ "leaseId": bound_lease.lease_id }),
                })?;
                Ok((bound_lease, value))
            }
            Outcome::UnknownNeedsReconcile { reason, .. } => {
                let _ = journal.append_transition(JournalTransitionInput {
                    operation_id: op_id.clone(),
                    next_state: JournalState::UnknownResult,
                    principal_id: principal_id.to_owned(),
                    instance_id: self.instance_alias.clone(),
                    workflow_id: None,
                    action: "test_workflow.ephemeral_create".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: None,
                    ops_hash: None,
                    details: json!({
                        "leaseId": lease.lease_id,
                        "workflowName": wf_name.trim(),
                        "reason": redact_str(&reason),
                    }),
                });
                Err(N8nError::timeout_unknown(
                    &self.instance_alias,
                    "POST",
                    "/api/v1/workflows",
                    true,
                    reason,
                ))
            }
        }
    }

    /// Releases a cleanup lease by unpublishing/deactivating (if active), deleting the temporary
    /// `[MCP-E2E-TEST]` workflow, verifying HTTP `404` on read-back, and closing the lease in `journal`.
    ///
    /// On any deletion or read-back verification error, transitions the lease to
    /// `CleanupLeaseState::CleanupRequired` instead of hiding the failure!
    pub async fn release_and_cleanup_lease(
        &self,
        journal: &mut OperationJournal,
        api_client: &N8nApiClient,
        lease_id: &str,
    ) -> N8nResult<LeaseReconcileEntry> {
        let lease = journal.get_cleanup_lease(lease_id)?.ok_or_else(|| {
            N8nError::not_found_or_concealed(
                &self.instance_alias,
                lease_id,
                "cleanup lease not found in OperationJournal",
            )
        })?;

        if !lease
            .workflow_name_tag
            .starts_with(E2E_TEST_WORKFLOW_PREFIX)
        {
            let reason = format!(
                "Refusing cleanup for lease `{}`: workflow tag `{}` lacks mandatory `{E2E_TEST_WORKFLOW_PREFIX}` prefix",
                lease.lease_id,
                redact_str(&lease.workflow_name_tag)
            );
            let updated = journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
            return Ok(LeaseReconcileEntry {
                lease_id: lease.lease_id,
                workflow_name_tag: lease.workflow_name_tag,
                outcome: LeaseCleanupOutcome::CleanupRequired {
                    workflow_id: lease.workflow_id,
                    reason,
                },
                final_lease_state: updated.state,
            });
        }

        // Resolve remote workflow(s): either directly by bound `workflow_id` or by exact `workflow_name_tag`
        // if the previous process crashed between `acquire_cleanup_lease` and `bind_cleanup_lease_workflow`.
        if let Some(ref wf_id) = lease.workflow_id {
            return self
                .cleanup_known_workflow_for_lease(journal, api_client, &lease, wf_id)
                .await;
        }

        // Pre-create crash window (`workflow_id == None`): search remote workflows matching exact `workflow_name_tag`.
        let list_res = api_client
            .list_workflows(&ListQueryParams {
                name: Some(lease.workflow_name_tag.clone()),
                limit: Some(50),
                exclude_pinned_data: Some(true),
                ..ListQueryParams::default()
            })
            .await;

        let candidates = match list_res {
            Ok(page) => page
                .data
                .into_iter()
                .filter(|w| {
                    w.name == lease.workflow_name_tag
                        && w.name.starts_with(E2E_TEST_WORKFLOW_PREFIX)
                })
                .collect::<Vec<_>>(),
            Err(err) => {
                let reason = format!(
                    "Failed listing workflows to reconcile pre-create lease `{}`: {}",
                    lease.lease_id,
                    redact_str(&err.to_string())
                );
                let updated =
                    journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
                return Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id,
                    workflow_name_tag: lease.workflow_name_tag,
                    outcome: LeaseCleanupOutcome::CleanupRequired {
                        workflow_id: None,
                        reason,
                    },
                    final_lease_state: updated.state,
                });
            }
        };

        let Some(first_match) = candidates.first() else {
            let updated = journal.complete_cleanup_lease(
                &lease.lease_id,
                true,
                Some("no remote [MCP-E2E-TEST] workflow created prior to crash; verified absent"),
            )?;
            return Ok(LeaseReconcileEntry {
                lease_id: lease.lease_id,
                workflow_name_tag: lease.workflow_name_tag,
                outcome: LeaseCleanupOutcome::AlreadyAbsentVerified404 { workflow_id: None },
                final_lease_state: updated.state,
            });
        };

        let discovered_id = first_match.id.clone();
        let _ = journal.bind_cleanup_lease_workflow(
            &lease.lease_id,
            &discovered_id,
            Some("bound orphaned [MCP-E2E-TEST] workflow during startup reconciliation"),
        )?;
        self.cleanup_known_workflow_for_lease(journal, api_client, &lease, &discovered_id)
            .await
    }

    /// Scans open/expired `CleanupLeaseRecord` entries and `Writing`/`Verifying`/`UnknownResult`
    /// journal entries on startup, cleaning up authorized `[MCP-E2E-TEST]` workflows (verifying `404`
    /// read-back) or marking `cleanup_required` on error.
    #[allow(clippy::too_many_lines)]
    pub async fn reconcile_startup(
        &self,
        journal: &mut OperationJournal,
        api_client: Option<&N8nApiClient>,
        dry_run: bool,
    ) -> N8nResult<StartupReconcileReport> {
        let pending_leases = journal.list_pending_cleanup_leases(Some(&self.instance_alias))?;
        let uncertain_ops = journal.list_uncertain_operations(Some(&self.instance_alias))?;
        let in_mem_uncertain = api_client.map_or(0, |c| {
            c.idempotency_store().pending_uncertain_operations().len()
        });

        let mut notes = Vec::new();
        let mut lease_entries = Vec::with_capacity(pending_leases.len());
        let mut operation_entries = Vec::with_capacity(uncertain_ops.len());
        let mut leases_cleaned = 0_usize;
        let mut leases_marked_cleanup_required = 0_usize;
        let mut uncertain_operations_resolved = 0_usize;
        let mut uncertain_operations_remaining = 0_usize;

        if in_mem_uncertain > 0 {
            notes.push(format!(
                "Observed {in_mem_uncertain} in-memory idempotency timeout record(s) alongside durable journal."
            ));
        }

        if dry_run || api_client.is_none() {
            if api_client.is_none() && !dry_run {
                notes.push(
                    "No `N8nApiClient` configured; performed offline inspection without remote cleanup."
                        .to_owned(),
                );
            }
            for lease in &pending_leases {
                lease_entries.push(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::DryRunWouldClean {
                        workflow_id: lease.workflow_id.clone(),
                    },
                    final_lease_state: lease.state,
                });
            }
            for op in &uncertain_ops {
                uncertain_operations_remaining += 1;
                operation_entries.push(UncertainOperationReconcileEntry {
                    operation_id: op.operation_id.clone(),
                    action: op.action.clone(),
                    workflow_id: op.workflow_id.clone(),
                    outcome: UncertainOperationOutcome::DryRunInspected,
                });
            }

            let summary = ReconcileSummary {
                instance: self.instance_alias.clone(),
                dry_run: true,
                pending_leases_checked: pending_leases.len(),
                uncertain_operations_found: uncertain_ops.len() + in_mem_uncertain,
                notes,
            };
            return Ok(StartupReconcileReport {
                summary,
                leases_cleaned,
                leases_marked_cleanup_required,
                uncertain_operations_resolved,
                uncertain_operations_remaining,
                lease_entries,
                operation_entries,
            });
        }

        let Some(client) = api_client else {
            unreachable!("checked api_client.is_none() above");
        };

        // 1. Reconcile all pending / expired / previously failed cleanup leases.
        for lease in &pending_leases {
            let entry = self
                .release_and_cleanup_lease(journal, client, &lease.lease_id)
                .await?;
            match entry.final_lease_state {
                CleanupLeaseState::CleanedVerified => {
                    leases_cleaned += 1;
                }
                CleanupLeaseState::CleanupRequired
                | CleanupLeaseState::AcquiredPreCreate
                | CleanupLeaseState::ActiveResourceCreated => {
                    leases_marked_cleanup_required += 1;
                    notes.push(format!(
                        "ALERT: Lease `{}` (`{}`) requires operator cleanup!",
                        entry.lease_id, entry.workflow_name_tag
                    ));
                }
            }
            lease_entries.push(entry);
        }

        // 2. Reconcile `Writing` / `Verifying` / `UnknownResult` journal operations.
        for op in &uncertain_ops {
            let op_entry = self
                .reconcile_single_uncertain_op(journal, client, op)
                .await?;
            match op_entry.outcome {
                UncertainOperationOutcome::ReconciledVerifiedPresent { .. }
                | UncertainOperationOutcome::CleanedOrphanedTestWorkflow { .. }
                | UncertainOperationOutcome::ReconciledAbsent404 { .. } => {
                    uncertain_operations_resolved += 1;
                }
                UncertainOperationOutcome::DryRunInspected
                | UncertainOperationOutcome::RemainsUncertain { .. } => {
                    uncertain_operations_remaining += 1;
                }
            }
            operation_entries.push(op_entry);
        }

        notes.push(format!(
            "Reconciled {} pending lease(s) ({} cleaned, {} cleanup_required) and {} uncertain operation(s) ({} resolved, {} remaining).",
            pending_leases.len(),
            leases_cleaned,
            leases_marked_cleanup_required,
            uncertain_ops.len(),
            uncertain_operations_resolved,
            uncertain_operations_remaining
        ));

        let summary = ReconcileSummary {
            instance: self.instance_alias.clone(),
            dry_run: false,
            pending_leases_checked: pending_leases.len(),
            uncertain_operations_found: uncertain_ops.len() + in_mem_uncertain,
            notes,
        };

        Ok(StartupReconcileReport {
            summary,
            leases_cleaned,
            leases_marked_cleanup_required,
            uncertain_operations_resolved,
            uncertain_operations_remaining,
            lease_entries,
            operation_entries,
        })
    }

    async fn cleanup_known_workflow_for_lease(
        &self,
        journal: &mut OperationJournal,
        api_client: &N8nApiClient,
        lease: &CleanupLeaseRecord,
        wf_id: &str,
    ) -> N8nResult<LeaseReconcileEntry> {
        let initial_get = api_client.get_workflow(wf_id, true).await;
        let wf = match initial_get {
            Ok(w) => w,
            Err(N8nError::NotFoundOrConcealed404 { .. }) => {
                let updated = journal.complete_cleanup_lease(
                    &lease.lease_id,
                    true,
                    Some("workflow already absent (404 read-back verified)"),
                )?;
                return Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::AlreadyAbsentVerified404 {
                        workflow_id: Some(wf_id.to_owned()),
                    },
                    final_lease_state: updated.state,
                });
            }
            Err(err) => {
                let reason = format!(
                    "Initial GET failed for leased workflow `{wf_id}`: {}",
                    redact_str(&err.to_string())
                );
                let updated =
                    journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
                return Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::CleanupRequired {
                        workflow_id: Some(wf_id.to_owned()),
                        reason,
                    },
                    final_lease_state: updated.state,
                });
            }
        };

        // Prefix safety guard: NEVER delete a workflow unless its remote name ALSO begins with `[MCP-E2E-TEST]`!
        if !wf.name.starts_with(E2E_TEST_WORKFLOW_PREFIX) {
            let reason = format!(
                "Safety rail blocked deletion of workflow `{wf_id}`: remote name `{}` does not start with `{E2E_TEST_WORKFLOW_PREFIX}`",
                redact_str(&wf.name)
            );
            let updated = journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
            return Ok(LeaseReconcileEntry {
                lease_id: lease.lease_id.clone(),
                workflow_name_tag: lease.workflow_name_tag.clone(),
                outcome: LeaseCleanupOutcome::CleanupRequired {
                    workflow_id: Some(wf_id.to_owned()),
                    reason,
                },
                final_lease_state: updated.state,
            });
        }

        // 1. Unpublish / deactivate first if active or `activeVersionId` is set!
        if (wf.active || wf.active_version_id.is_some())
            && let Err(unpub_err) = unpublish_or_deactivate(api_client, wf_id).await
        {
            let reason = format!(
                "Failed unpublishing/deactivating active test workflow `{wf_id}` before delete: {}",
                redact_str(&unpub_err.to_string())
            );
            let updated = journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
            return Ok(LeaseReconcileEntry {
                lease_id: lease.lease_id.clone(),
                workflow_name_tag: lease.workflow_name_tag.clone(),
                outcome: LeaseCleanupOutcome::CleanupRequired {
                    workflow_id: Some(wf_id.to_owned()),
                    reason,
                },
                final_lease_state: updated.state,
            });
        }

        // 2. Delete temporary `[MCP-E2E-TEST]` workflow.
        if let Err(del_err) = api_client.delete_workflow(wf_id).await
            && !matches!(del_err, N8nError::NotFoundOrConcealed404 { .. })
        {
            let reason = format!(
                "DELETE failed for test workflow `{wf_id}`: {}",
                redact_str(&del_err.to_string())
            );
            let updated = journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
            return Ok(LeaseReconcileEntry {
                lease_id: lease.lease_id.clone(),
                workflow_name_tag: lease.workflow_name_tag.clone(),
                outcome: LeaseCleanupOutcome::CleanupRequired {
                    workflow_id: Some(wf_id.to_owned()),
                    reason,
                },
                final_lease_state: updated.state,
            });
        }

        // 3. Mandatory `404` read-back verification!
        match api_client.get_workflow(wf_id, true).await {
            Err(N8nError::NotFoundOrConcealed404 { .. }) => {
                let updated = journal.complete_cleanup_lease(
                    &lease.lease_id,
                    true,
                    Some("deleted [MCP-E2E-TEST] workflow and verified HTTP 404 on read-back"),
                )?;
                Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::CleanedAndVerified404 {
                        workflow_id: wf_id.to_owned(),
                    },
                    final_lease_state: updated.state,
                })
            }
            Ok(_) => {
                let reason = format!(
                    "Post-DELETE read-back for `{wf_id}` still returned 200 OK instead of 404 Not Found"
                );
                let updated =
                    journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
                Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::CleanupRequired {
                        workflow_id: Some(wf_id.to_owned()),
                        reason,
                    },
                    final_lease_state: updated.state,
                })
            }
            Err(other_err) => {
                let reason = format!(
                    "Post-DELETE 404 read-back check inconclusive for `{wf_id}`: {}",
                    redact_str(&other_err.to_string())
                );
                let updated =
                    journal.complete_cleanup_lease(&lease.lease_id, false, Some(&reason))?;
                Ok(LeaseReconcileEntry {
                    lease_id: lease.lease_id.clone(),
                    workflow_name_tag: lease.workflow_name_tag.clone(),
                    outcome: LeaseCleanupOutcome::CleanupRequired {
                        workflow_id: Some(wf_id.to_owned()),
                        reason,
                    },
                    final_lease_state: updated.state,
                })
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn reconcile_single_uncertain_op(
        &self,
        journal: &mut OperationJournal,
        api_client: &N8nApiClient,
        op: &JournalRecord,
    ) -> N8nResult<UncertainOperationReconcileEntry> {
        let current_state =
            JournalState::from_str_opt(&op.state).unwrap_or(JournalState::UnknownResult);

        // If `workflow_id` is absent, check if `details.workflowName` identifies an `[MCP-E2E-TEST]` workflow.
        let resolved_wf_id = if let Some(ref id) = op.workflow_id {
            Some(id.clone())
        } else if let Some(wf_name) = op.details.get("workflowName").and_then(Value::as_str) {
            match api_client
                .list_workflows(&ListQueryParams {
                    name: Some(wf_name.to_owned()),
                    limit: Some(20),
                    exclude_pinned_data: Some(true),
                    ..ListQueryParams::default()
                })
                .await
            {
                Ok(page) => page
                    .data
                    .into_iter()
                    .find(|w| w.name == wf_name)
                    .map(|w| w.id),
                Err(err) => {
                    return Ok(UncertainOperationReconcileEntry {
                        operation_id: op.operation_id.clone(),
                        action: op.action.clone(),
                        workflow_id: None,
                        outcome: UncertainOperationOutcome::RemainsUncertain {
                            reason: redact_str(&err.to_string()),
                        },
                    });
                }
            }
        } else {
            None
        };

        let Some(wf_id) = resolved_wf_id else {
            // For an interrupted `create` where no remote workflow matches `workflowName`, mark `Failed` cleanly.
            if op.details.get("workflowName").is_some() {
                transition_uncertain_to_terminal(
                    journal,
                    op,
                    current_state,
                    JournalState::Failed,
                    None,
                    None,
                    json!({ "reconciled": true, "remoteFound": false }),
                )?;
                return Ok(UncertainOperationReconcileEntry {
                    operation_id: op.operation_id.clone(),
                    action: op.action.clone(),
                    workflow_id: None,
                    outcome: UncertainOperationOutcome::ReconciledAbsent404 {
                        resolved_state: JournalState::Failed,
                    },
                });
            }

            return Ok(UncertainOperationReconcileEntry {
                operation_id: op.operation_id.clone(),
                action: op.action.clone(),
                workflow_id: None,
                outcome: UncertainOperationOutcome::RemainsUncertain {
                    reason: "No `workflowId` or `workflowName` recorded on uncertain operation."
                        .to_owned(),
                },
            });
        };

        match api_client.get_workflow(&wf_id, true).await {
            Ok(wf) => {
                // If this uncertain operation was an ephemeral `[MCP-E2E-TEST]` workflow creation, clean it up!
                let is_ephemeral_test_op = wf.name.starts_with(E2E_TEST_WORKFLOW_PREFIX)
                    && (op.action.contains("ephemeral") || op.action.contains("test_workflow"));

                if is_ephemeral_test_op {
                    if wf.active || wf.active_version_id.is_some() {
                        let _ = unpublish_or_deactivate(api_client, &wf_id).await;
                    }
                    if api_client.delete_workflow(&wf_id).await.is_ok()
                        && matches!(
                            api_client.get_workflow(&wf_id, true).await,
                            Err(N8nError::NotFoundOrConcealed404 { .. })
                        )
                    {
                        transition_uncertain_to_terminal(
                            journal,
                            op,
                            current_state,
                            JournalState::Failed,
                            Some(&wf_id),
                            None,
                            json!({
                                "reconciled": true,
                                "cleanedOrphanedTestWorkflow": true,
                            }),
                        )?;
                        return Ok(UncertainOperationReconcileEntry {
                            operation_id: op.operation_id.clone(),
                            action: op.action.clone(),
                            workflow_id: Some(wf_id.clone()),
                            outcome: UncertainOperationOutcome::CleanedOrphanedTestWorkflow {
                                workflow_id: wf_id,
                            },
                        });
                    }
                }

                let version_hash = serde_json::to_value(&wf)
                    .ok()
                    .and_then(|v| WorkflowIr::from_json_value(v).ok())
                    .map(|ir| ir.canonical_version_hash())
                    .or_else(|| wf.version_id.clone())
                    .unwrap_or_else(|| "verified_present".to_owned());

                transition_uncertain_to_terminal(
                    journal,
                    op,
                    current_state,
                    JournalState::Verified,
                    Some(&wf_id),
                    Some(&version_hash),
                    json!({
                        "reconciled": true,
                        "verifiedPresent": true,
                    }),
                )?;

                Ok(UncertainOperationReconcileEntry {
                    operation_id: op.operation_id.clone(),
                    action: op.action.clone(),
                    workflow_id: Some(wf_id.clone()),
                    outcome: UncertainOperationOutcome::ReconciledVerifiedPresent {
                        workflow_id: wf_id,
                        version_hash,
                    },
                })
            }
            Err(N8nError::NotFoundOrConcealed404 { .. }) => {
                let resolved_state = if op.action == "workflows.delete" {
                    JournalState::Verified
                } else {
                    JournalState::Failed
                };
                transition_uncertain_to_terminal(
                    journal,
                    op,
                    current_state,
                    resolved_state,
                    Some(&wf_id),
                    None,
                    json!({
                        "reconciled": true,
                        "readBack404": true,
                    }),
                )?;
                Ok(UncertainOperationReconcileEntry {
                    operation_id: op.operation_id.clone(),
                    action: op.action.clone(),
                    workflow_id: Some(wf_id),
                    outcome: UncertainOperationOutcome::ReconciledAbsent404 { resolved_state },
                })
            }
            Err(err) => Ok(UncertainOperationReconcileEntry {
                operation_id: op.operation_id.clone(),
                action: op.action.clone(),
                workflow_id: Some(wf_id),
                outcome: UncertainOperationOutcome::RemainsUncertain {
                    reason: redact_str(&err.to_string()),
                },
            }),
        }
    }
}

fn ensure_test_workflow_prefix(instance_alias: &str, workflow_name: &str) -> N8nResult<()> {
    let trimmed = workflow_name.trim();
    if !trimmed.starts_with(E2E_TEST_WORKFLOW_PREFIX) {
        return Err(N8nError::policy_blocked(
            "test_harness.acquire_lease",
            RiskLevel::R2,
            "test_workflow_prefix_guard",
            format!(
                "Temporary test workflows managed by cleanup leases MUST start with `{E2E_TEST_WORKFLOW_PREFIX}` (got `{}` on `{instance_alias}`)",
                redact_str(trimmed)
            ),
            Some(format!(
                "Prefix temporary test workflow names with `{E2E_TEST_WORKFLOW_PREFIX}`."
            )),
        ));
    }
    Ok(())
}

async fn unpublish_or_deactivate(api_client: &N8nApiClient, workflow_id: &str) -> N8nResult<()> {
    match api_client.unpublish_workflow(workflow_id).await {
        Ok(_) => Ok(()),
        Err(err) if !err.allows_route_fallback() => Err(err),
        Err(_) => {
            // Fallback for older n8n versions exposing `/deactivate` instead of `/unpublish`.
            let _ = api_client.deactivate_workflow(workflow_id).await?;
            Ok(())
        }
    }
}

fn transition_uncertain_to_terminal(
    journal: &mut OperationJournal,
    op: &JournalRecord,
    current_state: JournalState,
    terminal_state: JournalState,
    workflow_id: Option<&str>,
    resulting_version_hash: Option<&str>,
    details: Value,
) -> N8nResult<()> {
    // Respect V2 Section 9 state machine: `Writing` must step through `Verifying` before `Verified`!
    if current_state == JournalState::Writing && terminal_state == JournalState::Verified {
        let _ = journal.append_transition(JournalTransitionInput {
            operation_id: op.operation_id.clone(),
            next_state: JournalState::Verifying,
            principal_id: op.principal_id.clone(),
            instance_id: op.instance_id.clone(),
            workflow_id: workflow_id
                .map(str::to_owned)
                .or_else(|| op.workflow_id.clone()),
            action: op.action.clone(),
            base_version_hash: op.base_version_hash.clone(),
            resulting_version_hash: None,
            ops_hash: op.ops_hash.clone(),
            details: json!({ "step": "startup_reconcile_verifying" }),
        })?;
    }

    let _ = journal.append_transition(JournalTransitionInput {
        operation_id: op.operation_id.clone(),
        next_state: terminal_state,
        principal_id: op.principal_id.clone(),
        instance_id: op.instance_id.clone(),
        workflow_id: workflow_id
            .map(str::to_owned)
            .or_else(|| op.workflow_id.clone()),
        action: op.action.clone(),
        base_version_hash: op.base_version_hash.clone(),
        resulting_version_hash: resulting_version_hash.map(str::to_owned),
        ops_hash: op.ops_hash.clone(),
        details,
    })?;
    Ok(())
}
