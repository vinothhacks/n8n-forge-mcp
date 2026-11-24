//! Static workflow security & reliability scanner (`n8n-audit`) separating `observed_facts`,
//! `heuristics`, and `permission_gaps` per V2 Section 10.
//!
//! Security guarantees:
//! - `#![forbid(unsafe_code)]`
//! - Zero active network probing or workflow execution during static audits
//! - Zero raw secret echo (`n8n_types::redact_str` + location-only `(node_id, node_name, field_path, secret_kind)` reporting)

#![forbid(unsafe_code)]

pub mod facts;
pub mod heuristics;
pub mod permission_gaps;
pub mod report;

pub use facts::{
    AuditFact, AuditSeverity, ObservedFact, collect_observed_facts, is_external_io_node_type,
};
pub use heuristics::{
    AuditHeuristic, HeuristicFinding, SecretKind, collect_heuristics, is_cleartext_http_url,
    references_process_env,
};
pub use permission_gaps::{
    PermissionGap, SubworkflowTargetRef, collect_permission_gaps, extract_target_subworkflow_id,
    permission_gap_from_live_audit_error,
};
pub use report::{
    AuditContext, BatchAuditReport, StaticAuditReport, WorkflowAuditEntry, audit_workflow,
    audit_workflow_with_live_api, audit_workflows_batch, merge_live_audit_payload,
};
