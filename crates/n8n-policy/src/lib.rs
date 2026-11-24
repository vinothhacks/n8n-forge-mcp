//! Server-enforced authorization and production policy engine (`n8n-policy`):
//! - Config loader (`env` + optional `instances.toml` + `policy.*.toml`)
//! - `PolicyMode` (`ReadOnly`, `StagingSafe`, `ProductionGuarded`, `FullDev`) & `R0..R4` AND-gate
//! - Cryptographic single-use `ApprovalReceipt` (`BLAKE3` + `HMAC-SHA256`)
//! - Per-workflow `tokio::sync::Mutex` write lock registry & batch cap (20 workflows / concurrency 1)

pub mod config;
pub mod engine;
pub mod locks;
pub mod receipt;

pub use config::{
    InstancePolicyConfig, LoadedWorkspaceConfig, PolicyFileOverrides, PolicyMode,
    load_workspace_config,
};
pub use engine::{PolicyCheckOutcome, PolicyCheckRequest, PolicyEngine};
pub use locks::{
    MAX_BATCH_WORKFLOWS, MAX_WORKFLOW_WRITE_CONCURRENCY, WorkflowLockRegistry, WorkflowWriteGuard,
    enforce_batch_cap,
};
pub use receipt::{ApprovalClaims, ApprovalExpectation, ApprovalReceipt, ReceiptSigner, hash_ops};
