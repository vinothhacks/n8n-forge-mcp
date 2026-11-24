#![forbid(unsafe_code)]
//! Offline structural, schema, expression AST, and cross-graph workflow validator for `n8n-rs-mcp`.

pub mod ast;
pub mod expressions;
pub mod mutation;
pub mod node_config;
pub mod workflow;

pub use ast::{
    AccessorForm, ExtractedNodeReference, JsAstAnalysis, JsSyntaxDiagnostic, N8N_RUNTIME_BUILTINS,
    QuoteStyle, ReferenceKind, TextSpan, analyze_inline_js_block, analyze_js_code_script,
};
pub use expressions::{
    CODE_LIKE_EXPRESSION_GUIDANCE, DynamicNodeReference, ExpressionAnalysis, ExpressionError,
    ExpressionRenameMode, ExpressionRewriteOutcome, ParameterRenameEvaluation,
    analyze_plain_or_template_expression, analyze_template_expression,
    evaluate_parameter_expression, extract_expression_blocks, rewrite_literal_node_references,
};
pub use mutation::{
    BlockingExpressionLocation, MutationApplyStatus, RewrittenExpressionEntry, ValidatedMutationOp,
    ValidatedMutationOutcome, apply_validated_mutation,
};
pub use node_config::{
    NodeValidationIssue, NodeValidationReport, ValidationProfile, ValidationSeverity,
    code_node_has_why_rationale, validate_node_config, validate_node_json,
};
pub use workflow::{
    SkeletonValidationIssue, SkeletonValidationReport, TopologyValidationReport, ValidationOptions,
    ValidationStrength, WorkflowValidationIssue, WorkflowValidationReport,
    compute_all_upstream_ancestors, validate_workflow, validate_workflow_skeleton,
    validate_workflow_topology, validate_workflow_topology_json,
};
