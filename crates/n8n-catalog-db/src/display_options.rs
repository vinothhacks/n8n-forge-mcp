//! Full n8n `displayOptions` (`show` / `hide` / `_cnd` / `@version` / `@tool` / defaults)
//! conditional visibility evaluator and nested `options` / `collection` / `fixedCollection`
//! effective property resolver.

use regex::RegexBuilder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

/// Maximum regex pattern length accepted from node schema `_cnd.regex` rules.
const MAX_DISPLAY_REGEX_PATTERN_BYTES: usize = 512;

/// Maximum parameter string length evaluated against `_cnd.regex`.
const MAX_DISPLAY_REGEX_INPUT_BYTES: usize = 65_536;

/// Compiled DFA/NFA size cap (`256 KiB`) preventing pathological schema regexes.
const DISPLAY_REGEX_DFA_LIMIT: usize = 256 * 1024;

/// Evaluation context combining explicit node parameters, schema property defaults,
/// and runtime node context keys (`@version`, `@tool`).
#[derive(Debug, Clone, Copy)]
pub struct DisplayEvalContext<'a> {
    pub parameters: &'a Map<String, Value>,
    pub property_defaults: &'a Map<String, Value>,
    pub node_context: &'a Map<String, Value>,
}

impl<'a> DisplayEvalContext<'a> {
    #[must_use]
    pub fn new(
        parameters: &'a Map<String, Value>,
        property_defaults: &'a Map<String, Value>,
        node_context: &'a Map<String, Value>,
    ) -> Self {
        Self {
            parameters,
            property_defaults,
            node_context,
        }
    }

    /// Resolves a key following n8n precedence (`node_context` > `parameters` > `property_defaults`).
    #[must_use]
    pub fn resolve_key(&self, key: &str) -> (bool, Option<&'a Value>) {
        if let Some(v) = self.node_context.get(key) {
            return (true, Some(v));
        }
        if let Some(v) = self.parameters.get(key) {
            return (true, Some(v));
        }
        if let Some(v) = self.property_defaults.get(key) {
            return (true, Some(v));
        }
        (false, None)
    }
}

/// Enum option entry inside an `options` or `multiOptions` property.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowedOptionValue {
    pub name: String,
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Effective child field inside a `collection` or `fixedCollection` group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveChildProperty {
    pub name: String,
    pub display_name: String,
    pub prop_type: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    pub description: String,
    pub visible: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_options: Vec<AllowedOptionValue>,
}

/// Effective group inside a `fixedCollection` property (`options[].values[]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveFixedCollectionGroup {
    pub name: String,
    pub display_name: String,
    pub visible: bool,
    pub fields: Vec<EffectiveChildProperty>,
}

/// Effective nested options/sub-fields resolved for `options`, `multiOptions`, `collection`,
/// or `fixedCollection` properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveNestedFields {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_options: Vec<AllowedOptionValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_fields: Vec<EffectiveChildProperty>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_collection_groups: Vec<EffectiveFixedCollectionGroup>,
}

impl EffectiveNestedFields {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enum_options.is_empty()
            && self.collection_fields.is_empty()
            && self.fixed_collection_groups.is_empty()
    }
}

/// Builds a `nodeContext` map (`@version`, `@tool`) from an optional `type_version` string and tool flag.
#[must_use]
pub fn build_node_context(type_version: Option<&str>, is_tool: Option<bool>) -> Map<String, Value> {
    let mut ctx = Map::new();
    if let Some(ver_raw) = type_version.map(str::trim).filter(|s| !s.is_empty()) {
        ctx.insert("@version".to_owned(), version_str_to_json_value(ver_raw));
    }
    if let Some(tool_flag) = is_tool {
        ctx.insert("@tool".to_owned(), Value::Bool(tool_flag));
    }
    ctx
}

fn version_str_to_json_value(ver_raw: &str) -> Value {
    if let Ok(int_val) = ver_raw.parse::<i64>() {
        return Value::Number(Number::from(int_val));
    }
    if let Ok(float_val) = ver_raw.parse::<f64>()
        && let Some(num) = Number::from_f64(float_val)
    {
        return Value::Number(num);
    }
    Value::String(ver_raw.to_owned())
}

/// Evaluates whether a field with optional `displayOptions` is visible under `current_params`
/// (with empty schema defaults and empty `nodeContext`).
#[must_use]
pub fn is_property_visible(display_options: Option<&Value>, current_params: &Value) -> bool {
    let empty_map = Map::new();
    let params_map = current_params.as_object().unwrap_or(&empty_map);
    let ctx = DisplayEvalContext::new(params_map, &empty_map, &empty_map);
    evaluate_display_options(display_options, None, &ctx)
}

/// Evaluates n8n `displayOptions` (and optional `parent_display_options` for nested collection
/// or `fixedCollection` children) against [`DisplayEvalContext`].
///
/// Semantics:
/// - `None`, `null`, or `{}` is unconditionally visible (`true`).
/// - `show`: cross-property **AND**, within-property array **OR** (including `_cnd` predicates).
/// - `hide`: cross-property **OR**, within-property array **OR**; any matching `hide` rule hides
///   the property even when `show` matches.
#[must_use]
pub fn evaluate_display_options(
    display_options: Option<&Value>,
    parent_display_options: Option<&Value>,
    ctx: &DisplayEvalContext<'_>,
) -> bool {
    if let Some(parent_disp) = parent_display_options
        && !evaluate_single_display_options(Some(parent_disp), ctx)
    {
        return false;
    }
    evaluate_single_display_options(display_options, ctx)
}

fn evaluate_single_display_options(
    display_options: Option<&Value>,
    ctx: &DisplayEvalContext<'_>,
) -> bool {
    let Some(disp_val) = display_options else {
        return true;
    };
    if disp_val.is_null() {
        return true;
    }
    let Some(disp_obj) = disp_val.as_object() else {
        return true;
    };
    if disp_obj.is_empty() {
        return true;
    }

    if let Some(show_val) = disp_obj.get("show")
        && let Some(show_map) = show_val.as_object()
    {
        for (prop_key, allowed_spec) in show_map {
            let (key_present, actual) = ctx.resolve_key(prop_key);
            let matched = match allowed_spec {
                Value::Array(items) => items
                    .iter()
                    .any(|rule| match_rule_item(rule, actual, key_present)),
                single => match_rule_item(single, actual, key_present),
            };
            if !matched {
                return false;
            }
        }
    }

    if let Some(hide_val) = disp_obj.get("hide")
        && let Some(hide_map) = hide_val.as_object()
    {
        for (prop_key, hidden_spec) in hide_map {
            let (key_present, actual) = ctx.resolve_key(prop_key);
            let triggered = match hidden_spec {
                Value::Array(items) => items
                    .iter()
                    .any(|rule| match_rule_item(rule, actual, key_present)),
                single => match_rule_item(single, actual, key_present),
            };
            if triggered {
                return false;
            }
        }
    }

    true
}

fn match_rule_item(rule_item: &Value, actual: Option<&Value>, key_present: bool) -> bool {
    if let Some(rule_obj) = rule_item.as_object()
        && let Some(cnd_val) = rule_obj.get("_cnd")
    {
        let Some(cnd_obj) = cnd_val.as_object() else {
            return false;
        };
        return eval_cnd(cnd_obj, actual, key_present);
    }

    let actual_norm = actual.unwrap_or(&Value::Null);
    if !key_present && rule_item.is_null() {
        return true;
    }
    if !key_present {
        return false;
    }
    json_values_equal(actual_norm, rule_item)
}

fn eval_cnd(cnd: &Map<String, Value>, actual: Option<&Value>, key_present: bool) -> bool {
    if cnd.is_empty() {
        return false;
    }

    if let Some(exists_val) = cnd.get("exists") {
        let want = value_as_truthy_bool(exists_val);
        let exists_now = key_present
            && match actual {
                None | Some(Value::Null) => false,
                Some(Value::String(s)) => !s.is_empty(),
                Some(_) => true,
            };
        if exists_now != want {
            return false;
        }
        if cnd.len() == 1 {
            return true;
        }
    }

    if !key_present {
        return false;
    }

    let actual_val = actual.unwrap_or(&Value::Null);

    for (op, expected) in cnd {
        if op == "exists" {
            continue;
        }
        let op_ok = match op.as_str() {
            "eq" => json_values_equal(actual_val, expected),
            "not" => !json_values_equal(actual_val, expected),
            "gt" => numeric_pair(actual_val, expected).is_some_and(|(a, b)| a > b),
            "gte" => numeric_pair(actual_val, expected).is_some_and(|(a, b)| a >= b),
            "lt" => numeric_pair(actual_val, expected).is_some_and(|(a, b)| a < b),
            "lte" => numeric_pair(actual_val, expected).is_some_and(|(a, b)| a <= b),
            "between" => eval_between(actual_val, expected),
            "startsWith" => match (actual_val.as_str(), expected.as_str()) {
                (Some(s), Some(prefix)) => s.starts_with(prefix),
                _ => false,
            },
            "endsWith" => match (actual_val.as_str(), expected.as_str()) {
                (Some(s), Some(suffix)) => s.ends_with(suffix),
                _ => false,
            },
            "includes" => match actual_val {
                Value::String(s) => expected.as_str().is_some_and(|sub| s.contains(sub)),
                Value::Array(items) => items.iter().any(|item| json_values_equal(item, expected)),
                _ => false,
            },
            "regex" => match (actual_val.as_str(), expected.as_str()) {
                (Some(text), Some(pat)) => eval_bounded_regex(pat, text),
                _ => false,
            },
            _ => false,
        };
        if !op_ok {
            return false;
        }
    }

    true
}

fn value_as_truthy_bool(val: &Value) -> bool {
    match val {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn as_strict_number(val: &Value) -> Option<f64> {
    match val {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn numeric_pair(actual: &Value, expected: &Value) -> Option<(f64, f64)> {
    Some((as_strict_number(actual)?, as_strict_number(expected)?))
}

fn eval_between(actual: &Value, expected: &Value) -> bool {
    let Some(actual_num) = as_strict_number(actual) else {
        return false;
    };
    if let Some(obj) = expected.as_object() {
        let Some(from_num) = obj.get("from").and_then(as_strict_number) else {
            return false;
        };
        let Some(to_num) = obj.get("to").and_then(as_strict_number) else {
            return false;
        };
        return from_num <= actual_num && actual_num <= to_num;
    }
    if let Some(arr) = expected.as_array()
        && arr.len() == 2
        && let (Some(from_num), Some(to_num)) =
            (as_strict_number(&arr[0]), as_strict_number(&arr[1]))
    {
        return from_num <= actual_num && actual_num <= to_num;
    }
    false
}

fn eval_bounded_regex(raw_pattern: &str, text: &str) -> bool {
    if raw_pattern.is_empty()
        || raw_pattern.len() > MAX_DISPLAY_REGEX_PATTERN_BYTES
        || text.len() > MAX_DISPLAY_REGEX_INPUT_BYTES
    {
        return false;
    }

    let (pattern, case_insensitive, multi_line, dot_matches_new_line) =
        parse_optional_js_regex_literal(raw_pattern);

    let Ok(re) = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(multi_line)
        .dot_matches_new_line(dot_matches_new_line)
        .size_limit(DISPLAY_REGEX_DFA_LIMIT)
        .dfa_size_limit(DISPLAY_REGEX_DFA_LIMIT)
        .build()
    else {
        return false;
    };

    re.is_match(text)
}

fn parse_optional_js_regex_literal(raw: &str) -> (&str, bool, bool, bool) {
    if let Some(rest) = raw.strip_prefix('/')
        && let Some(last_slash) = rest.rfind('/')
    {
        let body = &rest[..last_slash];
        let flags = &rest[last_slash + 1..];
        if !body.is_empty()
            && flags
                .chars()
                .all(|c| matches!(c, 'i' | 'm' | 's' | 'u' | 'g' | 'y'))
        {
            return (
                body,
                flags.contains('i'),
                flags.contains('m'),
                flags.contains('s'),
            );
        }
    }
    (raw, false, false, false)
}

/// Compares two JSON values using n8n / JavaScript scalar equality semantics (`2 == 2.0` is `true`,
/// while `true != 1` and `"2" != 2`).
#[must_use]
pub fn json_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            if let (Some(ai), Some(bi)) = (a.as_i64(), b.as_i64()) {
                return ai == bi;
            }
            if let (Some(au), Some(bu)) = (a.as_u64(), b.as_u64()) {
                return au == bu;
            }
            match (a.as_f64(), b.as_f64()) {
                (Some(af), Some(bf)) => (af - bf).abs() <= 1e-9,
                _ => false,
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(ai, bi)| json_values_equal(ai, bi))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, av)| b.get(k).is_some_and(|bv| json_values_equal(av, bv)))
        }
        _ => false,
    }
}

/// Computes effective enum choices, `collection` child properties, and `fixedCollection` groups
/// for a property under the given parent `displayOptions` and evaluation context.
#[must_use]
pub fn compute_effective_nested_fields(
    prop_type: &str,
    options_json: Option<&Value>,
    parent_display_options: Option<&Value>,
    top_ctx: &DisplayEvalContext<'_>,
    nested_param_value: Option<&Value>,
) -> EffectiveNestedFields {
    let mut out = EffectiveNestedFields::default();
    let Some(options_arr) = options_json.and_then(Value::as_array) else {
        return out;
    };

    if !evaluate_single_display_options(parent_display_options, top_ctx) {
        return out;
    }

    match prop_type {
        "options" | "multiOptions" => {
            out.enum_options = extract_enum_options(options_arr, top_ctx);
        }
        "collection" => {
            let mut merged_defaults = top_ctx.property_defaults.clone();
            for item in options_arr {
                if let Some(obj) = item.as_object()
                    && let Some(name) = obj.get("name").and_then(Value::as_str)
                    && let Some(def_val) = obj.get("default")
                {
                    let item_disp = obj.get("displayOptions");
                    if item_disp.is_none() {
                        merged_defaults.insert(name.to_owned(), def_val.clone());
                    }
                }
            }

            let mut merged_params = top_ctx.parameters.clone();
            if let Some(nested_obj) = nested_param_value.and_then(Value::as_object) {
                for (k, v) in nested_obj {
                    merged_params.insert(k.clone(), v.clone());
                }
            }

            let child_ctx =
                DisplayEvalContext::new(&merged_params, &merged_defaults, top_ctx.node_context);
            for item in options_arr {
                if let Some(child) = parse_child_property(item, parent_display_options, &child_ctx)
                {
                    out.collection_fields.push(child);
                }
            }
        }
        "fixedCollection" => {
            for group_val in options_arr {
                let Some(group_obj) = group_val.as_object() else {
                    continue;
                };
                let Some(group_name) = group_obj.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let group_display_name = group_obj
                    .get("displayName")
                    .or_else(|| group_obj.get("display_name"))
                    .and_then(Value::as_str)
                    .unwrap_or(group_name)
                    .to_owned();
                let group_disp = group_obj.get("displayOptions");
                let group_visible =
                    evaluate_display_options(group_disp, parent_display_options, top_ctx);

                let group_instance_obj = nested_param_value
                    .and_then(Value::as_object)
                    .and_then(|m| m.get(group_name))
                    .and_then(|gv| match gv {
                        Value::Object(o) => Some(o),
                        Value::Array(arr) => arr.first().and_then(Value::as_object),
                        _ => None,
                    });

                let values_arr = group_obj
                    .get("values")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();

                let mut merged_defaults = top_ctx.property_defaults.clone();
                for field_val in &values_arr {
                    if let Some(fobj) = field_val.as_object()
                        && let Some(fname) = fobj.get("name").and_then(Value::as_str)
                        && let Some(def_val) = fobj.get("default")
                        && fobj.get("displayOptions").is_none()
                    {
                        merged_defaults.insert(fname.to_owned(), def_val.clone());
                    }
                }

                let mut merged_params = top_ctx.parameters.clone();
                if let Some(inst) = group_instance_obj {
                    for (k, v) in inst {
                        merged_params.insert(k.clone(), v.clone());
                    }
                }

                let child_ctx =
                    DisplayEvalContext::new(&merged_params, &merged_defaults, top_ctx.node_context);
                let mut fields = Vec::with_capacity(values_arr.len());
                for field_val in &values_arr {
                    if let Some(mut child) =
                        parse_child_property(field_val, parent_display_options, &child_ctx)
                    {
                        if !group_visible {
                            child.visible = false;
                        }
                        fields.push(child);
                    }
                }

                out.fixed_collection_groups
                    .push(EffectiveFixedCollectionGroup {
                        name: group_name.to_owned(),
                        display_name: group_display_name,
                        visible: group_visible,
                        fields,
                    });
            }
        }
        _ => {}
    }

    out
}

fn extract_enum_options(
    options_arr: &[Value],
    ctx: &DisplayEvalContext<'_>,
) -> Vec<AllowedOptionValue> {
    let mut out = Vec::with_capacity(options_arr.len());
    for opt in options_arr {
        let Some(obj) = opt.as_object() else {
            continue;
        };
        let Some(val) = obj.get("value") else {
            continue;
        };
        if !evaluate_single_display_options(obj.get("displayOptions"), ctx) {
            continue;
        }
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| val.to_string(), str::to_owned);
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let action = obj
            .get("action")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        out.push(AllowedOptionValue {
            name,
            value: val.clone(),
            description,
            action,
        });
    }
    out
}

fn parse_child_property(
    raw: &Value,
    parent_display_options: Option<&Value>,
    ctx: &DisplayEvalContext<'_>,
) -> Option<EffectiveChildProperty> {
    let obj = raw.as_object()?;
    let name = obj.get("name").and_then(Value::as_str)?.to_owned();
    let display_name = obj
        .get("displayName")
        .or_else(|| obj.get("display_name"))
        .and_then(Value::as_str)
        .unwrap_or(&name)
        .to_owned();
    let prop_type = obj
        .get("type")
        .or_else(|| obj.get("prop_type"))
        .and_then(Value::as_str)
        .unwrap_or("string")
        .to_owned();
    let required = obj
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let default_value = obj.get("default").cloned();
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    let visible = evaluate_display_options(obj.get("displayOptions"), parent_display_options, ctx);
    let enum_options = if matches!(prop_type.as_str(), "options" | "multiOptions") {
        obj.get("options")
            .and_then(Value::as_array)
            .map(|arr| extract_enum_options(arr, ctx))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Some(EffectiveChildProperty {
        name,
        display_name,
        prop_type,
        required,
        default_value,
        description,
        visible,
        enum_options,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EquivalenceRecord {
        id: String,
        category: String,
        description: String,
        input: Value,
        expected: Value,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DisplayCaseInput {
        display_options: Option<Value>,
        parent_display_options: Option<Value>,
        #[serde(default)]
        parameters: Map<String, Value>,
        #[serde(default)]
        property_defaults: Map<String, Value>,
        #[serde(default)]
        node_context: Map<String, Value>,
    }

    #[derive(Debug, Deserialize)]
    struct DisplayCaseExpected {
        visible: bool,
    }

    #[test]
    fn passes_100_percent_of_display_options_equivalence_corpus() {
        let cases_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/equivalence/cases.jsonl");
        let content = fs::read_to_string(&cases_path)
            .expect("tests/equivalence/cases.jsonl must be readable");

        let mut evaluated_count = 0usize;
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: EquivalenceRecord = serde_json::from_str(trimmed)
                .unwrap_or_else(|e| panic!("invalid JSONL on line {}: {e}", line_idx + 1));
            if rec.category != "display_options" {
                continue;
            }

            let inp: DisplayCaseInput = serde_json::from_value(rec.input)
                .unwrap_or_else(|e| panic!("invalid display_options input in {}: {e}", rec.id));
            let exp: DisplayCaseExpected = serde_json::from_value(rec.expected)
                .unwrap_or_else(|e| panic!("invalid display_options expected in {}: {e}", rec.id));

            let ctx =
                DisplayEvalContext::new(&inp.parameters, &inp.property_defaults, &inp.node_context);
            let actual = evaluate_display_options(
                inp.display_options.as_ref(),
                inp.parent_display_options.as_ref(),
                &ctx,
            );

            assert_eq!(
                actual, exp.visible,
                "equivalence mismatch on case {} ({}): got visible={actual}, expected visible={}",
                rec.id, rec.description, exp.visible
            );
            evaluated_count += 1;
        }

        assert!(
            evaluated_count >= 85,
            "expected at least 85 display_options equivalence cases, evaluated {evaluated_count}"
        );
    }

    #[test]
    fn resolves_nested_collection_and_fixed_collection_visibility() {
        let parent_disp = json!({ "show": { "sendQuery": [true] } });
        let fixed_options = json!([
            {
                "name": "parameters",
                "displayName": "Parameter",
                "values": [
                    {
                        "name": "name",
                        "displayName": "Name",
                        "type": "string",
                        "required": true,
                        "default": ""
                    },
                    {
                        "name": "expressionValue",
                        "displayName": "Expression Value",
                        "type": "string",
                        "displayOptions": { "show": { "mode": ["expression"] } }
                    }
                ]
            }
        ]);

        let top_params: Map<String, Value> = serde_json::from_value(json!({
            "sendQuery": true
        }))
        .expect("map");
        let defaults = Map::new();
        let node_ctx = build_node_context(Some("4.2"), Some(false));
        let ctx = DisplayEvalContext::new(&top_params, &defaults, &node_ctx);

        let nested_val = json!({
            "parameters": [
                { "name": "page", "mode": "expression" }
            ]
        });
        let resolved = compute_effective_nested_fields(
            "fixedCollection",
            Some(&fixed_options),
            Some(&parent_disp),
            &ctx,
            Some(&nested_val),
        );

        assert_eq!(resolved.fixed_collection_groups.len(), 1);
        let grp = &resolved.fixed_collection_groups[0];
        assert!(grp.visible);
        assert_eq!(grp.fields.len(), 2);
        assert!(grp.fields[0].visible);
        assert!(grp.fields[1].visible);

        // When parent `sendQuery` is false, nested fields are suppressed.
        let hidden_params: Map<String, Value> =
            serde_json::from_value(json!({ "sendQuery": false })).expect("map");
        let hidden_ctx = DisplayEvalContext::new(&hidden_params, &defaults, &node_ctx);
        let hidden_resolved = compute_effective_nested_fields(
            "fixedCollection",
            Some(&fixed_options),
            Some(&parent_disp),
            &hidden_ctx,
            Some(&nested_val),
        );
        assert!(hidden_resolved.is_empty());
    }

    #[test]
    fn handles_js_regex_literals_array_includes_and_numeric_equality() {
        assert!(json_values_equal(&json!(2), &json!(2.0)));
        assert!(!json_values_equal(&json!(true), &json!(1)));
        assert!(!json_values_equal(&json!("2"), &json!(2)));

        let disp = json!({
            "show": {
                "header": [{ "_cnd": { "regex": "/^x-custom-[0-9]+$/i" } }],
                "tags": [{ "_cnd": { "includes": "critical" } }]
            }
        });
        let params = json!({
            "header": "X-CUSTOM-42",
            "tags": ["ops", "critical"]
        });
        assert!(is_property_visible(Some(&disp), &params));

        // Oversized regex pattern fails closed without panicking.
        let huge_re = format!("^{}$", "a".repeat(MAX_DISPLAY_REGEX_PATTERN_BYTES + 10));
        let bad_disp = json!({
            "show": { "s": [{ "_cnd": { "regex": huge_re } }] }
        });
        assert!(!is_property_visible(
            Some(&bad_disp),
            &json!({ "s": "aaaa" })
        ));
    }
}
