#![forbid(unsafe_code)]
//! Safe execution spectrum (`T0..T3`), deterministic side-effect node classifier,
//! bounded 3-attempt repair loop + execution data minimizer, and crash-safe startup cleanup reconciler.

pub mod classifier;
pub mod modes;
pub mod reconciler;
pub mod repair_loop;

pub use classifier::{
    ClassifiedNodeEffect, MAX_SUBWORKFLOW_RECURSION_DEPTH, NodeSideEffectClass,
    SideEffectClassification, SideEffectVerdict, classify_single_node,
    classify_workflow_side_effects, is_high_risk_local_io_node,
};
pub use modes::{
    DeterministicTestSafetyGate, SafetyGateDecision, TestExecutionMode, TestOrchestrator,
    TestOutcomeStatus, TestRunRequest, TestRunResult,
};
pub use reconciler::{
    DEFAULT_TEST_LEASE_TTL_SECS, E2E_TEST_WORKFLOW_PREFIX, LeaseCleanupOutcome,
    LeaseReconcileEntry, ReconcileSummary, StartupReconcileReport, StartupReconciler,
    UncertainOperationOutcome, UncertainOperationReconcileEntry,
};
pub use repair_loop::{
    ABSOLUTE_MAX_REPAIR_ATTEMPTS, DEFAULT_MAX_NODE_IO_ITEMS, DEFAULT_MAX_REPAIR_ATTEMPTS,
    ExecutionDetailLevel, ExecutionMinimizeOptions, MAX_EXECUTION_PAYLOAD_BYTES,
    MAX_SUMMARY_ERROR_CHARS, MinimizedExecutionReport, RepairAttemptRecord,
    RepairCandidateProposal, RepairConfidence, RepairHaltReason, RepairInspectionContext,
    RepairLoopConfig, RepairLoopOutcome, RepairLoopState, RepairLoopStatus, RepairStage,
    run_bounded_repair_loop, summarize_execution_redacted, summarize_execution_resource_redacted,
};
