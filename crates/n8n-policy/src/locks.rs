//! Per-workflow `tokio::sync::Mutex` lock registry and batch/concurrency hard caps (`V2 Section 5`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use n8n_types::{N8nError, N8nResult, RiskLevel};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Default and hard maximum number of workflows permitted in a single bulk batch (`U10`).
pub const MAX_BATCH_WORKFLOWS: usize = 20;

/// Strict per-workflow write concurrency ceiling (`1` concurrent write per `(instance, workflow_id)`).
pub const MAX_WORKFLOW_WRITE_CONCURRENCY: usize = 1;

/// Owned RAII guard representing exclusive write serialization within this Rust process
/// for a specific `(instance, workflow_id)` pair.
pub struct WorkflowWriteGuard {
    _guard: OwnedMutexGuard<()>,
    pub instance: String,
    pub workflow_id: String,
}

type WorkflowMutex = Arc<AsyncMutex<()>>;
type WorkflowLockMap = HashMap<(String, String), WorkflowMutex>;

/// Process-wide per-`(instance, workflow_id)` async write lock table.
#[derive(Default, Clone)]
pub struct WorkflowLockRegistry {
    locks: Arc<Mutex<WorkflowLockMap>>,
}

impl WorkflowLockRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn get_or_insert_mutex(&self, instance: &str, workflow_id: &str) -> Arc<AsyncMutex<()>> {
        let mut table = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table
            .entry((instance.to_owned(), workflow_id.to_owned()))
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Acquires the exclusive `tokio::sync::Mutex` write lock for `(instance, workflow_id)`.
    pub async fn acquire_write_lock(
        &self,
        instance: &str,
        workflow_id: &str,
    ) -> WorkflowWriteGuard {
        let mutex = self.get_or_insert_mutex(instance, workflow_id);
        let guard = mutex.lock_owned().await;
        WorkflowWriteGuard {
            _guard: guard,
            instance: instance.to_owned(),
            workflow_id: workflow_id.to_owned(),
        }
    }

    /// Attempts non-blocking acquisition of the per-workflow write lock.
    pub fn try_acquire_write_lock(
        &self,
        instance: &str,
        workflow_id: &str,
    ) -> Option<WorkflowWriteGuard> {
        let mutex = self.get_or_insert_mutex(instance, workflow_id);
        mutex.try_lock_owned().ok().map(|guard| WorkflowWriteGuard {
            _guard: guard,
            instance: instance.to_owned(),
            workflow_id: workflow_id.to_owned(),
        })
    }
}

/// Enforces the batch size cap (`<= 20` workflows per batch).
pub fn enforce_batch_cap(
    requested_workflow_count: usize,
    configured_cap: usize,
    policy_mode_label: &str,
) -> N8nResult<()> {
    let effective_cap = configured_cap.min(MAX_BATCH_WORKFLOWS);
    if requested_workflow_count == 0 {
        return Err(N8nError::validation(
            "local",
            vec!["batch selector matched 0 workflows".to_owned()],
            "Batch operation requires at least 1 target workflow",
        ));
    }
    if requested_workflow_count > effective_cap {
        return Err(N8nError::policy_blocked(
            "bulk_codemod",
            RiskLevel::R3,
            policy_mode_label,
            format!(
                "Batch targets {requested_workflow_count} workflows, exceeding the maximum batch cap of {effective_cap} workflows (concurrency = {MAX_WORKFLOW_WRITE_CONCURRENCY})"
            ),
            Some(format!(
                "Narrow selector to at most {effective_cap} workflows per batch and preview before confirming."
            )),
        ));
    }
    Ok(())
}
