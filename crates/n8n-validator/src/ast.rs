//! Real JavaScript AST analyzer powered by `oxc_parser` (`oxc_allocator`, `oxc_ast`, `oxc_span`).
//!
//! Extracts upstream node references (`$('Node')`, `$node['Node']`, `$items('Node', ...)`),
//! distinguishes static literal node names from dynamic/computed selectors, tracks built-in
//! n8n runtime identifiers (`$json`, `$input`, `$env`, ...), detects multi-statement /
//! function-body inline expressions, and records exact byte spans for safe literal rewrites.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionBody, ArrowFunctionExpression, AssignmentTarget,
    AssignmentTargetMaybeDefault, AssignmentTargetProperty, BindingPattern, BindingProperty,
    CallExpression, ChainElement, ComputedMemberExpression, Declaration, Expression,
    ForStatementInit, ForStatementLeft, Function, JSXAttributeItem, JSXAttributeValue, JSXChild,
    JSXExpression, MemberExpression, MethodDefinition, ObjectPropertyKind, Program,
    PropertyDefinition, PropertyKey, SimpleAssignmentTarget, Statement, TemplateLiteral,
    VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Canonical built-in n8n runtime identifiers tracked during AST traversal.
pub const N8N_RUNTIME_BUILTINS: &[&str] = &[
    "$json",
    "$input",
    "$binary",
    "$env",
    "$vars",
    "$execution",
    "$workflow",
    "$now",
    "$today",
    "$itemIndex",
    "$runIndex",
];

/// Inclusive start, exclusive end UTF-8 byte offsets within the analyzed source string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct TextSpan {
    pub start: usize,
    pub end: usize,
}

impl TextSpan {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn offset_by(self, delta: usize) -> Self {
        Self {
            start: self.start + delta,
            end: self.end + delta,
        }
    }
}

/// Syntax family used to reference another node in an n8n expression or script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessorForm {
    /// `$('Node Name')`
    DollarSelector,
    /// `$node["Node Name"]` or `$node['Node Name']`
    DollarNodeBracket,
    /// `$items('Node Name', ...)`
    DollarItemsCall,
}

/// Quote delimiter surrounding an AST-proven string literal node reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStyle {
    Single,
    Double,
    Backtick,
}

impl QuoteStyle {
    /// Formats `node_name` inside the original quote delimiter with exact JS escaping.
    #[must_use]
    pub fn format_escaped(self, node_name: &str) -> String {
        let mut out = String::with_capacity(node_name.len() + 4);
        let quote_ch = match self {
            Self::Single => '\'',
            Self::Double => '"',
            Self::Backtick => '`',
        };
        out.push(quote_ch);
        for ch in node_name.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{2028}' => out.push_str("\\u2028"),
                '\u{2029}' => out.push_str("\\u2029"),
                '\'' if self == Self::Single => out.push_str("\\'"),
                '"' if self == Self::Double => out.push_str("\\\""),
                '`' if self == Self::Backtick => out.push_str("\\`"),
                '$' if self == Self::Backtick => out.push_str("\\$"),
                other => out.push(other),
            }
        }
        out.push(quote_ch);
        out
    }
}

/// Classification of an extracted node reference in JS AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReferenceKind {
    /// Static string literal argument proven by JS AST (`$('Node')`, `$node["Node"]`, `$items("Node")`).
    LiteralNode(String),
    /// Dynamic/computed node selector (`$('prefix_' + x)`, `$node[varName]`, `` $(`A_${x}`) ``).
    DynamicNodeRef { span: TextSpan, snippet: String },
}

/// Rich record of a node reference discovered during AST traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedNodeReference {
    pub accessor: AccessorForm,
    pub kind: ReferenceKind,
    /// Span of the entire call/member access (e.g. `$('Fetch Users')`), relative to analyzed text.
    pub expression_span: TextSpan,
    /// Exact span of the string literal (including quotes) when `kind` is `LiteralNode`.
    pub literal_span: Option<TextSpan>,
    /// Original quote style when `kind` is `LiteralNode`.
    pub quote_style: Option<QuoteStyle>,
}

/// JavaScript syntax error reported by `oxc_parser` with exact byte span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JsSyntaxDiagnostic {
    pub message: String,
    pub span: TextSpan,
}

/// Complete AST inspection result for a single JS expression block or `Code` script.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JsAstAnalysis {
    pub valid_syntax: bool,
    pub diagnostics: Vec<JsSyntaxDiagnostic>,
    pub references: Vec<ExtractedNodeReference>,
    pub builtin_vars: Vec<String>,
    pub is_multi_statement_or_function_body: bool,
}

/// Parses a single n8n `{{ ... }}` inline expression body with `oxc_parser`.
///
/// `base_offset` is added to all returned spans so callers get byte offsets into the outer
/// parameter string.
#[must_use]
pub fn analyze_inline_js_block(raw_block: &str, base_offset: usize) -> JsAstAnalysis {
    let trimmed = raw_block.trim();
    if trimmed.is_empty() {
        return JsAstAnalysis {
            valid_syntax: false,
            diagnostics: vec![JsSyntaxDiagnostic {
                message: "Empty n8n expression block `{{ }}`".to_owned(),
                span: TextSpan::new(base_offset, base_offset + raw_block.len()),
            }],
            ..JsAstAnalysis::default()
        };
    }

    // Attempt 1: Single JavaScript expression wrapped in `const __n8n_expr__ = (\n<raw_block>\n);`
    const EXPR_PREFIX: &str = "const __n8n_expr__ = (\n";
    const EXPR_SUFFIX: &str = "\n);";
    let mut wrapped_expr =
        String::with_capacity(EXPR_PREFIX.len() + raw_block.len() + EXPR_SUFFIX.len());
    wrapped_expr.push_str(EXPR_PREFIX);
    wrapped_expr.push_str(raw_block);
    wrapped_expr.push_str(EXPR_SUFFIX);

    let allocator = Allocator::default();
    let parsed_expr = Parser::new(&allocator, &wrapped_expr, SourceType::mjs()).parse();
    if parsed_expr.diagnostics.is_empty() {
        if has_disallowed_inline_class(&parsed_expr.program) {
            return JsAstAnalysis {
                valid_syntax: false,
                diagnostics: vec![JsSyntaxDiagnostic {
                    message: "Class declarations/expressions are not valid inline n8n expressions"
                        .to_owned(),
                    span: TextSpan::new(base_offset, base_offset + raw_block.len()),
                }],
                ..JsAstAnalysis::default()
            };
        }

        let mut collector = AstCollector::new(raw_block, EXPR_PREFIX.len(), base_offset);
        collector.visit_program(&parsed_expr.program);
        return JsAstAnalysis {
            valid_syntax: true,
            diagnostics: Vec::new(),
            references: collector.references,
            builtin_vars: collector.builtin_vars,
            is_multi_statement_or_function_body: collector.has_complex_inline_code,
        };
    }

    // Attempt 2: Function-body / multi-statement inline expression (`let x = ...; return x;`, `if (...) ...`).
    const FN_PREFIX: &str = "function __n8n_inline__() {\n";
    const FN_SUFFIX: &str = "\n}";
    let mut wrapped_fn = String::with_capacity(FN_PREFIX.len() + raw_block.len() + FN_SUFFIX.len());
    wrapped_fn.push_str(FN_PREFIX);
    wrapped_fn.push_str(raw_block);
    wrapped_fn.push_str(FN_SUFFIX);

    let fn_allocator = Allocator::default();
    let parsed_fn = Parser::new(&fn_allocator, &wrapped_fn, SourceType::mjs()).parse();
    if parsed_fn.diagnostics.is_empty() && is_allowed_inline_statement_body(&parsed_fn.program) {
        let mut collector = AstCollector::new(raw_block, FN_PREFIX.len(), base_offset);
        collector.visit_program(&parsed_fn.program);
        return JsAstAnalysis {
            valid_syntax: true,
            diagnostics: Vec::new(),
            references: collector.references,
            builtin_vars: collector.builtin_vars,
            is_multi_statement_or_function_body: true,
        };
    }

    let diagnostics = parsed_expr
        .diagnostics
        .into_iter()
        .map(|diag| {
            let span = diag.labels.first().map_or_else(
                || TextSpan::new(base_offset, base_offset + raw_block.len()),
                |labeled| {
                    map_wrapped_span(
                        labeled.offset() as usize,
                        (labeled.offset() + labeled.len()) as usize,
                        EXPR_PREFIX.len(),
                        raw_block.len(),
                        base_offset,
                    )
                },
            );
            JsSyntaxDiagnostic {
                message: diag.message.to_string(),
                span,
            }
        })
        .collect();

    JsAstAnalysis {
        valid_syntax: false,
        diagnostics,
        ..JsAstAnalysis::default()
    }
}

/// Parses full `Code` node JavaScript (`jsCode`) inside n8n's async function execution wrapper.
#[must_use]
pub fn analyze_js_code_script(js_code: &str) -> JsAstAnalysis {
    const SCRIPT_PREFIX: &str = "async function __n8n_code__() {\n";
    const SCRIPT_SUFFIX: &str = "\n}";
    let mut wrapped =
        String::with_capacity(SCRIPT_PREFIX.len() + js_code.len() + SCRIPT_SUFFIX.len());
    wrapped.push_str(SCRIPT_PREFIX);
    wrapped.push_str(js_code);
    wrapped.push_str(SCRIPT_SUFFIX);

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &wrapped, SourceType::mjs()).parse();
    if !parsed.diagnostics.is_empty() {
        let diagnostics = parsed
            .diagnostics
            .into_iter()
            .map(|diag| {
                let span = diag.labels.first().map_or_else(
                    || TextSpan::new(0, js_code.len()),
                    |labeled| {
                        map_wrapped_span(
                            labeled.offset() as usize,
                            (labeled.offset() + labeled.len()) as usize,
                            SCRIPT_PREFIX.len(),
                            js_code.len(),
                            0,
                        )
                    },
                );
                JsSyntaxDiagnostic {
                    message: diag.message.to_string(),
                    span,
                }
            })
            .collect();
        return JsAstAnalysis {
            valid_syntax: false,
            diagnostics,
            ..JsAstAnalysis::default()
        };
    }

    let mut collector = AstCollector::new(js_code, SCRIPT_PREFIX.len(), 0);
    if let Some(Statement::FunctionDeclaration(func)) = parsed.program.body.first()
        && let Some(body) = &func.body
    {
        for stmt in &body.statements {
            collector.visit_statement(stmt);
        }
    }

    JsAstAnalysis {
        valid_syntax: true,
        diagnostics: Vec::new(),
        references: collector.references,
        builtin_vars: collector.builtin_vars,
        is_multi_statement_or_function_body: collector.has_complex_inline_code,
    }
}

fn map_wrapped_span(
    raw_start: usize,
    raw_end: usize,
    prefix_len: usize,
    inner_len: usize,
    base_offset: usize,
) -> TextSpan {
    let clamped_start = raw_start.saturating_sub(prefix_len).min(inner_len);
    let clamped_end = raw_end
        .saturating_sub(prefix_len)
        .min(inner_len)
        .max(clamped_start);
    TextSpan::new(base_offset + clamped_start, base_offset + clamped_end)
}

fn has_disallowed_inline_class(program: &Program<'_>) -> bool {
    for stmt in &program.body {
        if let Statement::VariableDeclaration(decl) = stmt {
            for declarator in &decl.declarations {
                if let Some(init) = &declarator.init {
                    let unwrapped = init.without_parentheses();
                    if matches!(unwrapped, Expression::ClassExpression(_)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_allowed_inline_statement_body(program: &Program<'_>) -> bool {
    let Some(Statement::FunctionDeclaration(func)) = program.body.first() else {
        return false;
    };
    let Some(body) = &func.body else {
        return false;
    };
    let non_empty: Vec<&Statement<'_>> = body
        .statements
        .iter()
        .filter(|s| !matches!(s, Statement::EmptyStatement(_)))
        .collect();
    if non_empty.is_empty() {
        return false;
    }
    for stmt in &non_empty {
        if matches!(stmt, Statement::ClassDeclaration(_)) {
            return false;
        }
    }
    if non_empty.len() == 1 {
        return matches!(
            non_empty[0],
            Statement::IfStatement(_)
                | Statement::ForStatement(_)
                | Statement::ForInStatement(_)
                | Statement::ForOfStatement(_)
                | Statement::WhileStatement(_)
                | Statement::DoWhileStatement(_)
                | Statement::SwitchStatement(_)
                | Statement::TryStatement(_)
                | Statement::ReturnStatement(_)
                | Statement::VariableDeclaration(_)
        );
    }
    true
}

struct AstCollector<'src> {
    raw_source: &'src str,
    wrapper_prefix_len: usize,
    base_offset: usize,
    references: Vec<ExtractedNodeReference>,
    builtin_vars: Vec<String>,
    has_complex_inline_code: bool,
}

impl<'src> AstCollector<'src> {
    const fn new(raw_source: &'src str, wrapper_prefix_len: usize, base_offset: usize) -> Self {
        Self {
            raw_source,
            wrapper_prefix_len,
            base_offset,
            references: Vec::new(),
            builtin_vars: Vec::new(),
            has_complex_inline_code: false,
        }
    }

    fn to_outer_span(&self, span: Span) -> TextSpan {
        map_wrapped_span(
            span.start as usize,
            span.end as usize,
            self.wrapper_prefix_len,
            self.raw_source.len(),
            self.base_offset,
        )
    }

    fn slice_inner(&self, span: Span) -> String {
        let local_start = (span.start as usize)
            .saturating_sub(self.wrapper_prefix_len)
            .min(self.raw_source.len());
        let local_end = (span.end as usize)
            .saturating_sub(self.wrapper_prefix_len)
            .min(self.raw_source.len())
            .max(local_start);
        self.raw_source
            .get(local_start..local_end)
            .unwrap_or("")
            .to_owned()
    }

    fn detect_quote_style(&self, span: Span) -> QuoteStyle {
        let slice = self.slice_inner(span);
        if slice.starts_with('"') {
            QuoteStyle::Double
        } else if slice.starts_with('`') {
            QuoteStyle::Backtick
        } else {
            QuoteStyle::Single
        }
    }

    fn record_builtin(&mut self, name: &str) {
        if N8N_RUNTIME_BUILTINS.contains(&name) && !self.builtin_vars.iter().any(|v| v == name) {
            self.builtin_vars.push(name.to_owned());
        }
    }

    fn visit_program(&mut self, program: &Program<'_>) {
        for stmt in &program.body {
            match stmt {
                Statement::VariableDeclaration(decl)
                    if decl.declarations.len() == 1
                        && matches!(
                            &decl.declarations[0].id,
                            BindingPattern::BindingIdentifier(id)
                                if id.name == "__n8n_expr__"
                        ) =>
                {
                    if let Some(init) = &decl.declarations[0].init {
                        self.visit_expression(init);
                    }
                }
                Statement::FunctionDeclaration(func)
                    if func
                        .id
                        .as_ref()
                        .is_some_and(|id| id.name == "__n8n_inline__") =>
                {
                    self.has_complex_inline_code = true;
                    if let Some(body) = &func.body {
                        for inner_stmt in &body.statements {
                            self.visit_statement(inner_stmt);
                        }
                    }
                }
                other => self.visit_statement(other),
            }
        }
    }

    fn visit_statement(&mut self, stmt: &Statement<'_>) {
        match stmt {
            Statement::BlockStatement(block) => {
                for inner in &block.body {
                    self.visit_statement(inner);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.visit_expression(&expr_stmt.expression);
            }
            Statement::ReturnStatement(ret) => {
                self.has_complex_inline_code = true;
                if let Some(arg) = &ret.argument {
                    self.visit_expression(arg);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.has_complex_inline_code = true;
                self.visit_expression(&if_stmt.test);
                self.visit_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.visit_statement(alt);
                }
            }
            Statement::SwitchStatement(sw) => {
                self.has_complex_inline_code = true;
                self.visit_expression(&sw.discriminant);
                for case in &sw.cases {
                    if let Some(test) = &case.test {
                        self.visit_expression(test);
                    }
                    for cons in &case.consequent {
                        self.visit_statement(cons);
                    }
                }
            }
            Statement::ForStatement(for_stmt) => {
                self.has_complex_inline_code = true;
                if let Some(init) = &for_stmt.init {
                    match init {
                        ForStatementInit::VariableDeclaration(v) => {
                            for d in &v.declarations {
                                self.visit_variable_declarator(d);
                            }
                        }
                        _ => {
                            if let Some(expr) = init.as_expression() {
                                self.visit_expression(expr);
                            }
                        }
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.visit_expression(test);
                }
                if let Some(update) = &for_stmt.update {
                    self.visit_expression(update);
                }
                self.visit_statement(&for_stmt.body);
            }
            Statement::ForInStatement(for_in) => {
                self.has_complex_inline_code = true;
                self.visit_for_left(&for_in.left);
                self.visit_expression(&for_in.right);
                self.visit_statement(&for_in.body);
            }
            Statement::ForOfStatement(for_of) => {
                self.has_complex_inline_code = true;
                self.visit_for_left(&for_of.left);
                self.visit_expression(&for_of.right);
                self.visit_statement(&for_of.body);
            }
            Statement::WhileStatement(wh) => {
                self.has_complex_inline_code = true;
                self.visit_expression(&wh.test);
                self.visit_statement(&wh.body);
            }
            Statement::DoWhileStatement(do_wh) => {
                self.has_complex_inline_code = true;
                self.visit_statement(&do_wh.body);
                self.visit_expression(&do_wh.test);
            }
            Statement::TryStatement(try_stmt) => {
                self.has_complex_inline_code = true;
                for s in &try_stmt.block.body {
                    self.visit_statement(s);
                }
                if let Some(handler) = &try_stmt.handler {
                    if let Some(param) = &handler.param {
                        self.visit_binding_pattern(&param.pattern);
                    }
                    for s in &handler.body.body {
                        self.visit_statement(s);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for s in &finalizer.body {
                        self.visit_statement(s);
                    }
                }
            }
            Statement::ThrowStatement(thr) => {
                self.has_complex_inline_code = true;
                self.visit_expression(&thr.argument);
            }
            Statement::LabeledStatement(lbl) => {
                self.visit_statement(&lbl.body);
            }
            Statement::WithStatement(with_stmt) => {
                self.visit_expression(&with_stmt.object);
                self.visit_statement(&with_stmt.body);
            }
            Statement::VariableDeclaration(decl) => {
                self.has_complex_inline_code = true;
                for d in &decl.declarations {
                    self.visit_variable_declarator(d);
                }
            }
            Statement::FunctionDeclaration(func) => {
                self.has_complex_inline_code = true;
                self.visit_function(func);
            }
            Statement::ClassDeclaration(cls) => {
                self.has_complex_inline_code = true;
                for elem in &cls.body.body {
                    match elem {
                        oxc_ast::ast::ClassElement::MethodDefinition(m) => {
                            self.visit_method_definition(m);
                        }
                        oxc_ast::ast::ClassElement::PropertyDefinition(p) => {
                            self.visit_property_definition(p);
                        }
                        oxc_ast::ast::ClassElement::StaticBlock(sb) => {
                            for s in &sb.body {
                                self.visit_statement(s);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                if let Some(decl) = stmt.as_declaration() {
                    self.visit_declaration(decl);
                }
            }
        }
    }

    fn visit_declaration(&mut self, decl: &Declaration<'_>) {
        match decl {
            Declaration::VariableDeclaration(v) => {
                self.has_complex_inline_code = true;
                for d in &v.declarations {
                    self.visit_variable_declarator(d);
                }
            }
            Declaration::FunctionDeclaration(f) => {
                self.has_complex_inline_code = true;
                self.visit_function(f);
            }
            _ => {}
        }
    }

    fn visit_for_left(&mut self, left: &ForStatementLeft<'_>) {
        match left {
            ForStatementLeft::VariableDeclaration(v) => {
                for d in &v.declarations {
                    self.visit_variable_declarator(d);
                }
            }
            _ => {
                if let Some(target) = left.as_assignment_target() {
                    self.visit_assignment_target(target);
                }
            }
        }
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'_>) {
        self.visit_binding_pattern(&decl.id);
        if let Some(init) = &decl.init {
            self.visit_expression(init);
        }
    }

    fn visit_binding_pattern(&mut self, pat: &BindingPattern<'_>) {
        match pat {
            BindingPattern::BindingIdentifier(_) => {}
            BindingPattern::ObjectPattern(obj) => {
                for prop in &obj.properties {
                    self.visit_binding_property(prop);
                }
                if let Some(rest) = &obj.rest {
                    self.visit_binding_pattern(&rest.argument);
                }
            }
            BindingPattern::ArrayPattern(arr) => {
                for elem in arr.elements.iter().flatten() {
                    self.visit_binding_pattern(elem);
                }
                if let Some(rest) = &arr.rest {
                    self.visit_binding_pattern(&rest.argument);
                }
            }
            BindingPattern::AssignmentPattern(assign) => {
                self.visit_binding_pattern(&assign.left);
                self.visit_expression(&assign.right);
            }
        }
    }

    fn visit_binding_property(&mut self, prop: &BindingProperty<'_>) {
        self.visit_property_key(&prop.key);
        self.visit_binding_pattern(&prop.value);
    }

    fn visit_function(&mut self, func: &Function<'_>) {
        for param in &func.params.items {
            self.visit_binding_pattern(&param.pattern);
        }
        if let Some(rest) = &func.params.rest {
            self.visit_binding_pattern(&rest.rest.argument);
        }
        if let Some(body) = &func.body {
            for stmt in &body.statements {
                self.visit_statement(stmt);
            }
        }
    }

    fn visit_arrow_function(&mut self, arrow: &ArrowFunctionExpression<'_>) {
        for param in &arrow.params.items {
            self.visit_binding_pattern(&param.pattern);
        }
        if let Some(rest) = &arrow.params.rest {
            self.visit_binding_pattern(&rest.rest.argument);
        }
        match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                self.has_complex_inline_code = true;
                for stmt in &body.statements {
                    self.visit_statement(stmt);
                }
            }
            other => {
                if let Some(expr) = other.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'_>) {
        self.visit_property_key(&method.key);
        self.visit_function(&method.value);
    }

    fn visit_property_definition(&mut self, prop: &PropertyDefinition<'_>) {
        self.visit_property_key(&prop.key);
        if let Some(val) = &prop.value {
            self.visit_expression(val);
        }
    }

    fn visit_property_key(&mut self, key: &PropertyKey<'_>) {
        if let Some(expr) = key.as_expression() {
            self.visit_expression(expr);
        }
    }

    fn inspect_call_node_reference(&mut self, call: &CallExpression<'_>) {
        let callee = call.callee.without_parentheses();
        let Expression::Identifier(ident) = callee else {
            return;
        };

        let accessor = match ident.name.as_str() {
            "$" => AccessorForm::DollarSelector,
            "$items" => {
                if call.arguments.is_empty() {
                    return;
                }
                AccessorForm::DollarItemsCall
            }
            _ => return,
        };

        let expr_span = self.to_outer_span(call.span);
        if call.arguments.is_empty()
            || (accessor == AccessorForm::DollarSelector && call.arguments.len() != 1)
        {
            self.references.push(ExtractedNodeReference {
                accessor,
                kind: ReferenceKind::DynamicNodeRef {
                    span: expr_span,
                    snippet: self.slice_inner(call.span),
                },
                expression_span: expr_span,
                literal_span: None,
                quote_style: None,
            });
            return;
        }

        let first_arg = &call.arguments[0];
        if let Some((node_name, lit_span, quote_style)) = self.extract_static_arg_literal(first_arg)
        {
            self.references.push(ExtractedNodeReference {
                accessor,
                kind: ReferenceKind::LiteralNode(node_name),
                expression_span: expr_span,
                literal_span: Some(lit_span),
                quote_style: Some(quote_style),
            });
        } else {
            let arg_span = self.to_outer_span(first_arg.span());
            self.references.push(ExtractedNodeReference {
                accessor,
                kind: ReferenceKind::DynamicNodeRef {
                    span: arg_span,
                    snippet: self.slice_inner(first_arg.span()),
                },
                expression_span: expr_span,
                literal_span: None,
                quote_style: None,
            });
        }
    }

    fn inspect_computed_member_node_reference(&mut self, comp: &ComputedMemberExpression<'_>) {
        let obj = comp.object.without_parentheses();
        let Expression::Identifier(ident) = obj else {
            return;
        };
        if ident.name.as_str() != "$node" {
            return;
        }

        let expr_span = self.to_outer_span(comp.span);
        if let Some((node_name, lit_span, quote_style)) =
            self.extract_static_expr_literal(&comp.expression)
        {
            self.references.push(ExtractedNodeReference {
                accessor: AccessorForm::DollarNodeBracket,
                kind: ReferenceKind::LiteralNode(node_name),
                expression_span: expr_span,
                literal_span: Some(lit_span),
                quote_style: Some(quote_style),
            });
        } else {
            let idx_span = self.to_outer_span(comp.expression.span());
            self.references.push(ExtractedNodeReference {
                accessor: AccessorForm::DollarNodeBracket,
                kind: ReferenceKind::DynamicNodeRef {
                    span: idx_span,
                    snippet: self.slice_inner(comp.expression.span()),
                },
                expression_span: expr_span,
                literal_span: None,
                quote_style: None,
            });
        }
    }

    fn extract_static_arg_literal(
        &self,
        arg: &Argument<'_>,
    ) -> Option<(String, TextSpan, QuoteStyle)> {
        let expr = arg.as_expression()?;
        self.extract_static_expr_literal(expr)
    }

    fn extract_static_expr_literal(
        &self,
        expr: &Expression<'_>,
    ) -> Option<(String, TextSpan, QuoteStyle)> {
        match expr.without_parentheses() {
            Expression::StringLiteral(lit) => {
                let decoded = lit.value.as_str().map_or_else(
                    || String::from_utf16_lossy(&lit.value.encode_utf16().collect::<Vec<_>>()),
                    ToOwned::to_owned,
                );
                Some((
                    decoded,
                    self.to_outer_span(lit.span),
                    self.detect_quote_style(lit.span),
                ))
            }
            Expression::TemplateLiteral(tpl)
                if tpl.expressions.is_empty() && tpl.quasis.len() == 1 =>
            {
                let value = tpl.quasis[0].value.cooked.as_ref().map_or_else(
                    || tpl.quasis[0].value.raw.as_str().to_owned(),
                    |cooked| {
                        cooked.as_str().map_or_else(
                            || String::from_utf16_lossy(&cooked.encode_utf16().collect::<Vec<_>>()),
                            ToOwned::to_owned,
                        )
                    },
                );
                Some((value, self.to_outer_span(tpl.span), QuoteStyle::Backtick))
            }
            _ => None,
        }
    }

    fn visit_expression(&mut self, expr: &Expression<'_>) {
        match expr {
            Expression::Identifier(ident) => {
                self.record_builtin(ident.name.as_str());
            }
            Expression::ParenthesizedExpression(paren) => {
                self.visit_expression(&paren.expression);
            }
            Expression::CallExpression(call) => {
                self.inspect_call_node_reference(call);
                self.visit_expression(&call.callee);
                for arg in &call.arguments {
                    self.visit_argument(arg);
                }
            }
            Expression::NewExpression(new_expr) => {
                self.visit_expression(&new_expr.callee);
                for arg in &new_expr.arguments {
                    self.visit_argument(arg);
                }
            }
            Expression::ComputedMemberExpression(comp) => {
                self.inspect_computed_member_node_reference(comp);
                self.visit_expression(&comp.object);
                self.visit_expression(&comp.expression);
            }
            Expression::StaticMemberExpression(stat) => {
                self.visit_expression(&stat.object);
            }
            Expression::PrivateFieldExpression(priv_f) => {
                self.visit_expression(&priv_f.object);
            }
            Expression::ChainExpression(chain) => {
                self.visit_chain_element(&chain.expression);
            }
            Expression::TemplateLiteral(tpl) => {
                self.visit_template_literal(tpl);
            }
            Expression::TaggedTemplateExpression(tagged) => {
                self.visit_expression(&tagged.tag);
                self.visit_template_literal(&tagged.quasi);
            }
            Expression::BinaryExpression(bin) => {
                self.visit_expression(&bin.left);
                self.visit_expression(&bin.right);
            }
            Expression::LogicalExpression(log) => {
                self.visit_expression(&log.left);
                self.visit_expression(&log.right);
            }
            Expression::UnaryExpression(un) => {
                self.visit_expression(&un.argument);
            }
            Expression::UpdateExpression(upd) => {
                self.visit_simple_assignment_target(&upd.argument);
            }
            Expression::ConditionalExpression(cond) => {
                self.visit_expression(&cond.test);
                self.visit_expression(&cond.consequent);
                self.visit_expression(&cond.alternate);
            }
            Expression::AssignmentExpression(assign) => {
                self.visit_assignment_target(&assign.left);
                self.visit_expression(&assign.right);
            }
            Expression::SequenceExpression(seq) => {
                for item in &seq.expressions {
                    self.visit_expression(item);
                }
            }
            Expression::ArrayExpression(arr) => {
                for elem in &arr.elements {
                    match elem {
                        ArrayExpressionElement::SpreadElement(sp) => {
                            self.visit_expression(&sp.argument);
                        }
                        ArrayExpressionElement::Elision(_) => {}
                        _ => {
                            if let Some(e) = elem.as_expression() {
                                self.visit_expression(e);
                            }
                        }
                    }
                }
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.visit_property_key(&p.key);
                            self.visit_expression(&p.value);
                        }
                        ObjectPropertyKind::SpreadProperty(sp) => {
                            self.visit_expression(&sp.argument);
                        }
                    }
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                self.visit_arrow_function(arrow);
            }
            Expression::FunctionExpression(func) => {
                self.has_complex_inline_code = true;
                self.visit_function(func);
            }
            Expression::AwaitExpression(aw) => {
                self.visit_expression(&aw.argument);
            }
            Expression::YieldExpression(yld) => {
                if let Some(arg) = &yld.argument {
                    self.visit_expression(arg);
                }
            }
            Expression::ImportExpression(imp) => {
                self.visit_expression(&imp.source);
                if let Some(opts) = &imp.options {
                    self.visit_expression(opts);
                }
            }
            Expression::JSXElement(el) => {
                for attr in &el.opening_element.attributes {
                    if let JSXAttributeItem::Attribute(a) = attr {
                        if let Some(JSXAttributeValue::ExpressionContainer(c)) = &a.value {
                            self.visit_jsx_expression(&c.expression);
                        }
                    } else if let JSXAttributeItem::SpreadAttribute(sp) = attr {
                        self.visit_expression(&sp.argument);
                    }
                }
                for child in &el.children {
                    self.visit_jsx_child(child);
                }
            }
            Expression::JSXFragment(frag) => {
                for child in &frag.children {
                    self.visit_jsx_child(child);
                }
            }
            _ => {}
        }
    }

    fn visit_jsx_child(&mut self, child: &JSXChild<'_>) {
        match child {
            JSXChild::ExpressionContainer(c) => self.visit_jsx_expression(&c.expression),
            JSXChild::Element(el) => {
                for inner in &el.children {
                    self.visit_jsx_child(inner);
                }
            }
            JSXChild::Fragment(f) => {
                for inner in &f.children {
                    self.visit_jsx_child(inner);
                }
            }
            JSXChild::Spread(sp) => self.visit_expression(&sp.expression),
            JSXChild::Text(_) => {}
        }
    }

    fn visit_jsx_expression(&mut self, jsx_expr: &JSXExpression<'_>) {
        if let Some(expr) = jsx_expr.as_expression() {
            self.visit_expression(expr);
        }
    }

    fn visit_argument(&mut self, arg: &Argument<'_>) {
        match arg {
            Argument::SpreadElement(sp) => self.visit_expression(&sp.argument),
            _ => {
                if let Some(expr) = arg.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_template_literal(&mut self, tpl: &TemplateLiteral<'_>) {
        for expr in &tpl.expressions {
            self.visit_expression(expr);
        }
    }

    fn visit_chain_element(&mut self, elem: &ChainElement<'_>) {
        match elem {
            ChainElement::CallExpression(call) => {
                self.inspect_call_node_reference(call);
                self.visit_expression(&call.callee);
                for arg in &call.arguments {
                    self.visit_argument(arg);
                }
            }
            ChainElement::ComputedMemberExpression(comp) => {
                self.inspect_computed_member_node_reference(comp);
                self.visit_expression(&comp.object);
                self.visit_expression(&comp.expression);
            }
            ChainElement::StaticMemberExpression(stat) => {
                self.visit_expression(&stat.object);
            }
            ChainElement::PrivateFieldExpression(priv_f) => {
                self.visit_expression(&priv_f.object);
            }
            _ => {}
        }
    }

    fn visit_assignment_target(&mut self, target: &AssignmentTarget<'_>) {
        match target {
            AssignmentTarget::ArrayAssignmentTarget(arr) => {
                for elem in arr.elements.iter().flatten() {
                    self.visit_assignment_target_maybe_default(elem);
                }
                if let Some(rest) = &arr.rest {
                    self.visit_assignment_target(&rest.target);
                }
            }
            AssignmentTarget::ObjectAssignmentTarget(obj) => {
                for prop in &obj.properties {
                    match prop {
                        AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(id) => {
                            if let Some(init) = &id.init {
                                self.visit_expression(init);
                            }
                        }
                        AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
                            self.visit_property_key(&p.name);
                            self.visit_assignment_target_maybe_default(&p.binding);
                        }
                    }
                }
                if let Some(rest) = &obj.rest {
                    self.visit_assignment_target(&rest.target);
                }
            }
            _ => {
                if let Some(simple) = target.as_simple_assignment_target() {
                    self.visit_simple_assignment_target(simple);
                }
            }
        }
    }

    fn visit_assignment_target_maybe_default(
        &mut self,
        maybe_def: &AssignmentTargetMaybeDefault<'_>,
    ) {
        match maybe_def {
            AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(with_def) => {
                self.visit_assignment_target(&with_def.binding);
                self.visit_expression(&with_def.init);
            }
            _ => {
                if let Some(target) = maybe_def.as_assignment_target() {
                    self.visit_assignment_target(target);
                }
            }
        }
    }

    fn visit_simple_assignment_target(&mut self, simple: &SimpleAssignmentTarget<'_>) {
        if let Some(member) = simple.as_member_expression() {
            self.visit_member_expression(member);
        }
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'_>) {
        match member {
            MemberExpression::ComputedMemberExpression(comp) => {
                self.inspect_computed_member_node_reference(comp);
                self.visit_expression(&comp.object);
                self.visit_expression(&comp.expression);
            }
            MemberExpression::StaticMemberExpression(stat) => {
                self.visit_expression(&stat.object);
            }
            MemberExpression::PrivateFieldExpression(priv_f) => {
                self.visit_expression(&priv_f.object);
            }
        }
    }
}
