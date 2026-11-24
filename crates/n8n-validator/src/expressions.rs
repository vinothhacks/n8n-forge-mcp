//! n8n expression template scanner, `oxc_parser` AST reference extractor, and byte-accurate
//! literal node-reference rewriter.

use n8n_graph::{DynamicReferenceHazard, RenameSafety};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ast::{
    ExtractedNodeReference, JsAstAnalysis, JsSyntaxDiagnostic, ReferenceKind, TextSpan,
    analyze_inline_js_block,
};

/// V2 native-first guidance message emitted when an inline expression contains multi-statement
/// or function-body imperative logic.
pub const CODE_LIKE_EXPRESSION_GUIDANCE: &str = "Inline expression contains multi-statement or function-body logic; prefer native nodes (Edit Fields, Filter, IF, Switch) or move imperative code into a `Code` node with notes starting with `Why Code: <reason>`.";

/// Dynamic node selector flagged for manual review during node rename operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DynamicNodeReference {
    pub span: TextSpan,
    pub snippet: String,
}

/// Rename safety mode reported for parameter expression inspection and equivalence checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExpressionRenameMode {
    NotApplicable,
    SafeLiteral,
    ManualReviewRequired,
}

/// Complete analysis of an n8n parameter value or standalone expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExpressionAnalysis {
    pub is_expression: bool,
    pub valid_syntax: bool,
    pub expression_blocks: Vec<String>,
    pub referenced_nodes: Vec<String>,
    pub references: Vec<ExtractedNodeReference>,
    pub dynamic_references: Vec<DynamicNodeReference>,
    pub builtin_vars: Vec<String>,
    pub code_like_expression_warning: bool,
    pub native_first_suggestion: Option<String>,
    pub rename_safety: RenameSafety,
    pub diagnostics: Vec<JsSyntaxDiagnostic>,
}

/// Outcome of rewriting AST-verified literal node references inside an expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExpressionRewriteOutcome {
    pub original: String,
    pub rewritten: String,
    pub changed: bool,
    pub replaced_count: usize,
    pub rename_safety: RenameSafety,
}

/// Outcome of evaluating an optional node-rename request on a parameter string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParameterRenameEvaluation {
    pub analysis: ExpressionAnalysis,
    pub rename_mode: ExpressionRenameMode,
    pub rewritten_value: Option<String>,
}

/// Errors returned when parsing or rewriting n8n expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpressionError {
    #[error("unbalanced `{{{{ ... }}}}` expression braces at byte {offset}: {message}")]
    UnbalancedTemplateBraces { offset: usize, message: String },
    #[error("JavaScript syntax error in expression at {span:?}: {message}")]
    SyntaxError { message: String, span: TextSpan },
    #[error(
        "cannot safely rewrite `{old_name}` -> `{new_name}`: dynamic node reference `{snippet}` requires manual review"
    )]
    DynamicReferenceManualReview {
        old_name: String,
        new_name: String,
        snippet: String,
        dynamic_references: Vec<DynamicNodeReference>,
    },
}

#[derive(Debug, Clone, Copy)]
struct TemplateBlockSpan {
    /// Start byte index of inner expression content (immediately after `{{`) in outer `param`.
    inner_start: usize,
    /// End byte index of inner expression content (immediately before `}}`) in outer `param`.
    inner_end: usize,
}

/// Scans an n8n `=...` template string into `{{ ... }}` inner expression byte spans.
fn scan_template_blocks(param: &str) -> Result<Vec<TemplateBlockSpan>, ExpressionError> {
    let Some(rest) = param.strip_prefix('=') else {
        return Ok(Vec::new());
    };
    let rest_offset = 1usize;
    let bytes = rest.as_bytes();
    let mut blocks = Vec::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        if cursor + 1 < bytes.len() && bytes[cursor] == b'{' && bytes[cursor + 1] == b'{' {
            let inner_start_rel = cursor + 2;
            if let Some(inner_end_rel) = find_matching_double_brace_end(rest, inner_start_rel) {
                blocks.push(TemplateBlockSpan {
                    inner_start: rest_offset + inner_start_rel,
                    inner_end: rest_offset + inner_end_rel,
                });
                cursor = inner_end_rel + 2;
            } else {
                return Err(ExpressionError::UnbalancedTemplateBraces {
                    offset: rest_offset + cursor,
                    message: "Unclosed `{{` delimiter in n8n template expression".to_owned(),
                });
            }
        } else if cursor + 1 < bytes.len() && bytes[cursor] == b'}' && bytes[cursor + 1] == b'}' {
            return Err(ExpressionError::UnbalancedTemplateBraces {
                offset: rest_offset + cursor,
                message: "Unmatched closing `}}` delimiter outside `{{ ... }}` block".to_owned(),
            });
        } else {
            cursor += 1;
        }
    }

    Ok(blocks)
}

/// Extracts `{{ ... }}` trimmed expression blocks from an n8n parameter string.
///
/// Only strings prefixed with `=` are treated as n8n expressions; plain strings
/// containing literal mustache braces remain inert text.
#[must_use]
pub fn extract_expression_blocks(param: &str) -> Vec<&str> {
    let Ok(blocks) = scan_template_blocks(param) else {
        return Vec::new();
    };
    blocks
        .into_iter()
        .filter_map(|b| param.get(b.inner_start..b.inner_end).map(str::trim))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Finds the byte offset of the closing `}}` matching an opening `{{`, accounting for
/// nested JS object/block braces, string literals (`'...'`, `"..."`), template literals
/// (`` `...${...}...` ``), and line/block comments.
fn find_matching_double_brace_end(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut brace_depth = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(bytes.len());
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'`' => {
                i = skip_template_literal(bytes, i + 1);
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'{' => {
                brace_depth += 1;
                i += 1;
            }
            b'}' => {
                if brace_depth == 0 {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                        return Some(i);
                    }
                    // Unmatched single `}` inside expression block; keep scanning so `oxc_parser`
                    // reports the exact JS syntax diagnostic once `}}` is reached.
                    i += 1;
                } else {
                    brace_depth -= 1;
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    // Fallback: if the author had an unclosed `{` inside JS (e.g. `={{ function broken( { }}`),
    // locate a trailing `}}` so `oxc_parser` still produces a rich syntax error diagnostic.
    s[start..].rfind("}}").map(|rel| start + rel)
}

fn skip_template_literal(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == b'`' {
            return i + 1;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            i += 2;
            let mut interp_depth = 1usize;
            while i < bytes.len() && interp_depth > 0 {
                match bytes[i] {
                    b'\'' | b'"' => {
                        let q = bytes[i];
                        i += 1;
                        while i < bytes.len() {
                            if bytes[i] == b'\\' {
                                i = (i + 2).min(bytes.len());
                                continue;
                            }
                            if bytes[i] == q {
                                i += 1;
                                break;
                            }
                            i += 1;
                        }
                    }
                    b'`' => {
                        i = skip_template_literal(bytes, i + 1);
                    }
                    b'{' => {
                        interp_depth += 1;
                        i += 1;
                    }
                    b'}' => {
                        interp_depth -= 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }
        i += 1;
    }
    i
}

fn safe_rename_status() -> RenameSafety {
    RenameSafety::SafeLiteralRewrites {
        rewritten_locations: Vec::new(),
    }
}

fn build_rename_safety(dynamic_references: &[DynamicNodeReference]) -> RenameSafety {
    if dynamic_references.is_empty() {
        safe_rename_status()
    } else {
        RenameSafety::ManualReviewRequired {
            hazards: dynamic_references
                .iter()
                .map(|d| DynamicReferenceHazard {
                    node_name: String::new(),
                    parameter_pointer: format!("{}..{}", d.span.start, d.span.end),
                    expression_snippet: d.snippet.clone(),
                })
                .collect(),
        }
    }
}

/// Analyzes an n8n parameter string (`=...` with zero or more `{{ ... }}` segments, or literal).
#[must_use]
pub fn analyze_template_expression(param: &str) -> ExpressionAnalysis {
    if !param.starts_with('=') {
        return ExpressionAnalysis {
            is_expression: false,
            valid_syntax: true,
            expression_blocks: Vec::new(),
            referenced_nodes: Vec::new(),
            references: Vec::new(),
            dynamic_references: Vec::new(),
            builtin_vars: Vec::new(),
            code_like_expression_warning: false,
            native_first_suggestion: None,
            rename_safety: safe_rename_status(),
            diagnostics: Vec::new(),
        };
    }

    let blocks = match scan_template_blocks(param) {
        Ok(b) => b,
        Err(ExpressionError::UnbalancedTemplateBraces { offset, message }) => {
            return ExpressionAnalysis {
                is_expression: true,
                valid_syntax: false,
                expression_blocks: Vec::new(),
                referenced_nodes: Vec::new(),
                references: Vec::new(),
                dynamic_references: Vec::new(),
                builtin_vars: Vec::new(),
                code_like_expression_warning: false,
                native_first_suggestion: None,
                rename_safety: safe_rename_status(),
                diagnostics: vec![JsSyntaxDiagnostic {
                    message,
                    span: TextSpan::new(offset, param.len()),
                }],
            };
        }
        Err(_) => unreachable!("scan_template_blocks only returns UnbalancedTemplateBraces"),
    };

    if blocks.is_empty() {
        // Leading `=` without `{{ ... }}` (e.g. `"=plain-value"`).
        return ExpressionAnalysis {
            is_expression: true,
            valid_syntax: true,
            expression_blocks: Vec::new(),
            referenced_nodes: Vec::new(),
            references: Vec::new(),
            dynamic_references: Vec::new(),
            builtin_vars: Vec::new(),
            code_like_expression_warning: false,
            native_first_suggestion: None,
            rename_safety: safe_rename_status(),
            diagnostics: Vec::new(),
        };
    }

    let mut trimmed_blocks = Vec::with_capacity(blocks.len());
    let mut all_references = Vec::new();
    let mut referenced_nodes = Vec::new();
    let mut dynamic_references = Vec::new();
    let mut builtin_vars = Vec::new();
    let mut diagnostics = Vec::new();
    let mut valid_syntax = true;
    let mut code_like_warning = false;

    for block in &blocks {
        let raw_slice = param.get(block.inner_start..block.inner_end).unwrap_or("");
        let ast_res = analyze_inline_js_block(raw_slice, block.inner_start);
        if !ast_res.valid_syntax {
            valid_syntax = false;
            diagnostics.extend(ast_res.diagnostics);
        } else {
            trimmed_blocks.push(raw_slice.trim().to_owned());
            merge_ast_into(
                ast_res,
                &mut all_references,
                &mut referenced_nodes,
                &mut dynamic_references,
                &mut builtin_vars,
                &mut code_like_warning,
            );
        }
    }

    if !valid_syntax {
        return ExpressionAnalysis {
            is_expression: true,
            valid_syntax: false,
            expression_blocks: Vec::new(),
            referenced_nodes: Vec::new(),
            references: Vec::new(),
            dynamic_references: Vec::new(),
            builtin_vars: Vec::new(),
            code_like_expression_warning: false,
            native_first_suggestion: None,
            rename_safety: safe_rename_status(),
            diagnostics,
        };
    }

    let rename_safety = build_rename_safety(&dynamic_references);

    let native_first_suggestion =
        code_like_warning.then(|| CODE_LIKE_EXPRESSION_GUIDANCE.to_owned());

    ExpressionAnalysis {
        is_expression: true,
        valid_syntax: true,
        expression_blocks: trimmed_blocks,
        referenced_nodes,
        references: all_references,
        dynamic_references,
        builtin_vars,
        code_like_expression_warning: code_like_warning,
        native_first_suggestion,
        rename_safety,
        diagnostics,
    }
}

/// Analyzes either an `=...` template expression OR a plain standalone JS expression.
#[must_use]
pub fn analyze_plain_or_template_expression(expr: &str) -> ExpressionAnalysis {
    if expr.starts_with('=') {
        return analyze_template_expression(expr);
    }

    let ast_res = analyze_inline_js_block(expr, 0);
    if !ast_res.valid_syntax {
        return ExpressionAnalysis {
            is_expression: true,
            valid_syntax: false,
            expression_blocks: Vec::new(),
            referenced_nodes: Vec::new(),
            references: Vec::new(),
            dynamic_references: Vec::new(),
            builtin_vars: Vec::new(),
            code_like_expression_warning: false,
            native_first_suggestion: None,
            rename_safety: safe_rename_status(),
            diagnostics: ast_res.diagnostics,
        };
    }

    let mut all_references = Vec::new();
    let mut referenced_nodes = Vec::new();
    let mut dynamic_references = Vec::new();
    let mut builtin_vars = Vec::new();
    let mut code_like_warning = false;
    merge_ast_into(
        ast_res,
        &mut all_references,
        &mut referenced_nodes,
        &mut dynamic_references,
        &mut builtin_vars,
        &mut code_like_warning,
    );

    let rename_safety = build_rename_safety(&dynamic_references);

    ExpressionAnalysis {
        is_expression: true,
        valid_syntax: true,
        expression_blocks: vec![expr.trim().to_owned()],
        referenced_nodes,
        references: all_references,
        dynamic_references,
        builtin_vars,
        code_like_expression_warning: code_like_warning,
        native_first_suggestion: code_like_warning
            .then(|| CODE_LIKE_EXPRESSION_GUIDANCE.to_owned()),
        rename_safety,
        diagnostics: Vec::new(),
    }
}

fn merge_ast_into(
    ast_res: JsAstAnalysis,
    all_references: &mut Vec<ExtractedNodeReference>,
    referenced_nodes: &mut Vec<String>,
    dynamic_references: &mut Vec<DynamicNodeReference>,
    builtin_vars: &mut Vec<String>,
    code_like_warning: &mut bool,
) {
    if ast_res.is_multi_statement_or_function_body {
        *code_like_warning = true;
    }
    for builtin in ast_res.builtin_vars {
        if !builtin_vars.iter().any(|v| v == &builtin) {
            builtin_vars.push(builtin);
        }
    }
    for r in ast_res.references {
        match &r.kind {
            ReferenceKind::LiteralNode(name) => {
                if !referenced_nodes.iter().any(|existing| existing == name) {
                    referenced_nodes.push(name.clone());
                }
            }
            ReferenceKind::DynamicNodeRef { span, snippet } => {
                dynamic_references.push(DynamicNodeReference {
                    span: *span,
                    snippet: snippet.clone(),
                });
            }
        }
        all_references.push(r);
    }
}

/// Rewrites ONLY AST-verified string literal node references (`$('Old')`, `$node["Old"]`,
/// `$items('Old', ...)`) from `old_name` to `new_name`, preserving all surrounding template
/// and JavaScript text byte-for-byte.
///
/// Refuses to rewrite when any dynamic/computed node reference is present in the expression,
/// returning `Err(ExpressionError::DynamicReferenceManualReview { .. })`.
///
/// # Errors
/// Returns `ExpressionError` if the expression has unbalanced `{{ ... }}` delimiters, invalid
/// JS syntax, or dynamic node references requiring manual human review.
pub fn rewrite_literal_node_references(
    expr: &str,
    old_name: &str,
    new_name: &str,
) -> Result<ExpressionRewriteOutcome, ExpressionError> {
    if expr.starts_with('=') {
        let blocks = scan_template_blocks(expr)?;
        if blocks.is_empty() {
            return Ok(ExpressionRewriteOutcome {
                original: expr.to_owned(),
                rewritten: expr.to_owned(),
                changed: false,
                replaced_count: 0,
                rename_safety: safe_rename_status(),
            });
        }
    }

    let analysis = analyze_plain_or_template_expression(expr);
    if !analysis.valid_syntax {
        let first = analysis
            .diagnostics
            .into_iter()
            .next()
            .unwrap_or(JsSyntaxDiagnostic {
                message: "Invalid JavaScript expression syntax".to_owned(),
                span: TextSpan::new(0, expr.len()),
            });
        return Err(ExpressionError::SyntaxError {
            message: first.message,
            span: first.span,
        });
    }

    if !analysis.dynamic_references.is_empty() {
        let snippet = analysis.dynamic_references[0].snippet.clone();
        return Err(ExpressionError::DynamicReferenceManualReview {
            old_name: old_name.to_owned(),
            new_name: new_name.to_owned(),
            snippet,
            dynamic_references: analysis.dynamic_references,
        });
    }

    apply_literal_replacements(expr, &analysis.references, old_name, new_name)
}

fn apply_literal_replacements(
    source: &str,
    references: &[ExtractedNodeReference],
    old_name: &str,
    new_name: &str,
) -> Result<ExpressionRewriteOutcome, ExpressionError> {
    let mut edits: Vec<(TextSpan, String)> = Vec::new();
    for reference in references {
        if let ReferenceKind::LiteralNode(name) = &reference.kind
            && name == old_name
            && let (Some(span), Some(quote_style)) = (reference.literal_span, reference.quote_style)
        {
            let formatted = quote_style.format_escaped(new_name);
            edits.push((span, formatted));
        }
    }

    if edits.is_empty() || old_name == new_name {
        return Ok(ExpressionRewriteOutcome {
            original: source.to_owned(),
            rewritten: source.to_owned(),
            changed: false,
            replaced_count: 0,
            rename_safety: safe_rename_status(),
        });
    }

    // Sort spans ascending and splice byte-accurately while preserving surrounding text.
    edits.sort_by_key(|(span, _)| span.start);
    let mut out = String::with_capacity(source.len() + edits.len() * 8);
    let mut cursor = 0usize;
    let mut replaced_count = 0usize;
    let mut rewritten_locations = Vec::with_capacity(edits.len());

    for (span, replacement) in edits {
        if span.start < cursor || span.end > source.len() {
            return Err(ExpressionError::SyntaxError {
                message: "Overlapping or out-of-bounds literal span during rewrite".to_owned(),
                span,
            });
        }
        rewritten_locations.push(format!("{}..{}", span.start, span.end));
        out.push_str(&source[cursor..span.start]);
        out.push_str(&replacement);
        cursor = span.end;
        replaced_count += 1;
    }
    out.push_str(&source[cursor..]);

    let changed = out != source;
    Ok(ExpressionRewriteOutcome {
        original: source.to_owned(),
        rewritten: out,
        changed,
        replaced_count,
        rename_safety: RenameSafety::SafeLiteralRewrites {
            rewritten_locations,
        },
    })
}

/// Evaluates an n8n parameter string and optional `(from, to)` rename request in a single pass.
#[must_use]
pub fn evaluate_parameter_expression(
    param: &str,
    rename_request: Option<(&str, &str)>,
) -> ParameterRenameEvaluation {
    let analysis = analyze_template_expression(param);

    let Some((old_name, new_name)) = rename_request else {
        return ParameterRenameEvaluation {
            analysis,
            rename_mode: ExpressionRenameMode::NotApplicable,
            rewritten_value: None,
        };
    };

    if !analysis.is_expression || !analysis.valid_syntax || analysis.expression_blocks.is_empty() {
        return ParameterRenameEvaluation {
            analysis,
            rename_mode: ExpressionRenameMode::NotApplicable,
            rewritten_value: None,
        };
    }

    if !analysis.dynamic_references.is_empty() {
        return ParameterRenameEvaluation {
            analysis,
            rename_mode: ExpressionRenameMode::ManualReviewRequired,
            rewritten_value: None,
        };
    }

    match apply_literal_replacements(param, &analysis.references, old_name, new_name) {
        Ok(outcome) => ParameterRenameEvaluation {
            analysis,
            rename_mode: ExpressionRenameMode::SafeLiteral,
            rewritten_value: Some(outcome.rewritten),
        },
        Err(_) => ParameterRenameEvaluation {
            analysis,
            rename_mode: ExpressionRenameMode::ManualReviewRequired,
            rewritten_value: None,
        },
    }
}
