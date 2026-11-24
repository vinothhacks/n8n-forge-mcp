#!/usr/bin/env python3
"""
Deterministic Equivalence Corpus Generator for n8n-rs-mcp (n8n-forge-mcp).

Generates `tests/equivalence/cases.jsonl` (360 structured JSONL test cases) covering:
  1. `display_options`  (show/hide, multi-value arrays, `_cnd` operators, defaults, nested collections)
  2. `expression_refs`  (n8n `={{ ... }}` extraction, Unicode names, literal rename vs dynamic guard, syntax/code-like checks)
  3. `node_validation`  (required fields, conditional requireds, enum options, credential types, community `partial`, `Why Code:`)
  4. `graph_topology`   (linear, IF/Switch/Merge, Loop Over Items back-edges, dangling targets, AI `ai_*` port rules, orphans)
  5. `workflow_diff`    (JSON Pointer set/unset, whole-array replacement guard, safe node rename + ref rewrite, insert between A & B)

Provenance: Clean-room black-box specification verified against MIT-licensed `czlonkowski/n8n-mcp@2.103.2`
and n8n `2.48.7` public workflow schemas. Zero secrets or live tokens.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_catalog import blake3_hex, canonical_json
from catalog_seed import NODE_DEFS


# ---------------------------------------------------------------------------
# Reference Evaluator for `displayOptions` (used to verify every generated case)
# ---------------------------------------------------------------------------

def _eval_cnd(cnd: dict[str, Any], actual: Any, key_present: bool) -> bool:
    if "exists" in cnd:
        want = bool(cnd["exists"])
        exists_now = key_present and actual is not None and actual != ""
        return exists_now is want
    if not key_present and actual is None:
        return False
    if "eq" in cnd:
        return actual == cnd["eq"]
    if "not" in cnd:
        return actual != cnd["not"]
    if "gt" in cnd:
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual > cnd["gt"]
    if "gte" in cnd:
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual >= cnd["gte"]
    if "lt" in cnd:
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual < cnd["lt"]
    if "lte" in cnd:
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual <= cnd["lte"]
    if "between" in cnd:
        b = cnd["between"]
        return (
            isinstance(actual, (int, float))
            and not isinstance(actual, bool)
            and b["from"] <= actual <= b["to"]
        )
    if "startsWith" in cnd:
        return isinstance(actual, str) and actual.startswith(cnd["startsWith"])
    if "endsWith" in cnd:
        return isinstance(actual, str) and actual.endswith(cnd["endsWith"])
    if "includes" in cnd:
        return isinstance(actual, (str, list)) and cnd["includes"] in actual
    if "regex" in cnd:
        return isinstance(actual, str) and re.search(cnd["regex"], actual) is not None
    return False


def _match_rule_item(rule_item: Any, actual: Any, key_present: bool) -> bool:
    if isinstance(rule_item, dict) and "_cnd" in rule_item:
        return _eval_cnd(rule_item["_cnd"], actual, key_present)
    return actual == rule_item


def eval_display_options(
    display_options: dict[str, Any] | None,
    params: dict[str, Any],
    defaults: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> bool:
    if not display_options:
        return True
    merged: dict[str, Any] = {}
    if defaults:
        merged.update(defaults)
    merged.update(params)
    if context:
        merged.update(context)

    show_map = display_options.get("show")
    if show_map:
        for key, allowed_values in show_map.items():
            key_present = key in merged
            actual = merged.get(key)
            vals = allowed_values if isinstance(allowed_values, list) else [allowed_values]
            if not any(_match_rule_item(v, actual, key_present) for v in vals):
                return False

    hide_map = display_options.get("hide")
    if hide_map:
        for key, hidden_values in hide_map.items():
            key_present = key in merged
            actual = merged.get(key)
            vals = hidden_values if isinstance(hidden_values, list) else [hidden_values]
            if any(_match_rule_item(v, actual, key_present) for v in vals):
                return False

    return True


# ---------------------------------------------------------------------------
# Category 1: `display_options` (80 cases)
# ---------------------------------------------------------------------------

def build_display_options_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    idx = 0

    def add(
        sub: str,
        desc: str,
        disp: dict[str, Any] | None,
        params: dict[str, Any],
        defaults: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        parent_disp: dict[str, Any] | None = None,
        expected_override: bool | None = None,
    ) -> None:
        nonlocal idx
        idx += 1
        vis = eval_display_options(disp, params, defaults, context)
        if parent_disp is not None:
            vis = vis and eval_display_options(parent_disp, params, defaults, context)
        if expected_override is not None and vis != expected_override:
            raise AssertionError(f"display_options anchor mismatch on {desc}: {vis} != {expected_override}")
        cases.append({
            "id": f"disp-{idx:04d}",
            "category": "display_options",
            "subcategory": sub,
            "compatibilityClass": "exact_parity",
            "description": desc,
            "input": {
                "displayOptions": disp,
                "parentDisplayOptions": parent_disp,
                "parameters": params,
                "propertyDefaults": defaults or {},
                "nodeContext": context or {},
            },
            "expected": {
                "visible": vis,
            },
        })

    # 1a. Unconditional / empty displayOptions
    add("unconditional", "Null displayOptions is always visible", None, {}, expected_override=True)
    add("unconditional", "Empty object displayOptions is visible", {}, {"method": "GET"}, expected_override=True)

    # 1b. Single & multi-value `show` arrays
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]:
        want = method in ("POST", "PUT", "PATCH", "DELETE")
        add(
            "show_multi_value",
            f"HTTP sendBody visibility when method={method}",
            {"show": {"method": ["POST", "PUT", "PATCH", "DELETE"]}},
            {"method": method},
            expected_override=want,
        )

    # 1c. Multi-key `show` AND semantics (HTTP Request jsonBody)
    json_body_disp = {
        "show": {
            "sendBody": [True],
            "contentType": ["json"],
            "specifyBody": ["json"],
            "method": ["POST", "PUT", "PATCH", "DELETE"],
        }
    }
    combos = [
        ({"method": "POST", "sendBody": True, "contentType": "json", "specifyBody": "json"}, True),
        ({"method": "PUT", "sendBody": True, "contentType": "json", "specifyBody": "json"}, True),
        ({"method": "GET", "sendBody": True, "contentType": "json", "specifyBody": "json"}, False),
        ({"method": "POST", "sendBody": False, "contentType": "json", "specifyBody": "json"}, False),
        ({"method": "POST", "sendBody": True, "contentType": "form-urlencoded", "specifyBody": "json"}, False),
        ({"method": "POST", "sendBody": True, "contentType": "json", "specifyBody": "keypair"}, False),
        ({}, False),
    ]
    for c_idx, (p, want) in enumerate(combos, 1):
        add("show_multi_key_and", f"HTTP jsonBody 4-key AND gate combo #{c_idx}", json_body_disp, p, expected_override=want)

    # 1d. `hide` and `show` + `hide` precedence
    add("hide_rule", "Webhook responseCode hidden when responseMode=responseNode", {"hide": {"responseMode": ["responseNode"]}}, {"responseMode": "responseNode"}, expected_override=False)
    add("hide_rule", "Webhook responseCode visible when responseMode=onReceived", {"hide": {"responseMode": ["responseNode"]}}, {"responseMode": "onReceived"}, expected_override=True)
    add("show_and_hide", "Show resource=message AND hide operation=delete when op=post", {"show": {"resource": ["message"]}, "hide": {"operation": ["delete"]}}, {"resource": "message", "operation": "post"}, expected_override=True)
    add("show_and_hide", "Hide overrides matching show when operation=delete", {"show": {"resource": ["message"]}, "hide": {"operation": ["delete"]}}, {"resource": "message", "operation": "delete"}, expected_override=False)
    add("show_and_hide", "Show mismatch fails even when hide is not triggered", {"show": {"resource": ["message"]}, "hide": {"operation": ["delete"]}}, {"resource": "channel", "operation": "create"}, expected_override=False)

    # 1e. Missing parameter fallback to schema defaults
    add("defaults_fallback", "Default method=GET hides sendBody when method omitted", {"show": {"method": ["POST"]}}, {}, defaults={"method": "GET"}, expected_override=False)
    add("defaults_fallback", "Default operation=select shows returnAll when operation omitted", {"show": {"operation": ["select"]}}, {}, defaults={"operation": "select"}, expected_override=True)
    add("defaults_fallback", "Explicit parameter overrides schema default", {"show": {"operation": ["select"]}}, {"operation": "executeQuery"}, defaults={"operation": "select"}, expected_override=False)
    add("defaults_fallback", "Boolean false default satisfies show=[false]", {"show": {"returnAll": [False]}}, {}, defaults={"returnAll": False}, expected_override=True)
    add("defaults_fallback", "Missing key with no default does not match show=[false]", {"show": {"returnAll": [False]}}, {}, defaults={}, expected_override=False)

    # 1f. `@version` and `@tool` node context keys
    for ver in [1, 2, 2.1, 2.2, 3]:
        add("version_gate", f"Version-gated field (@version in [2.1, 2.2, 3]) at v={ver}", {"show": {"@version": [2.1, 2.2, 3]}}, {}, context={"@version": ver}, expected_override=(ver in (2.1, 2.2, 3)))
    add("tool_context", "Tool-only description shown when @tool=true", {"show": {"@tool": [True]}}, {}, context={"@tool": True}, expected_override=True)
    add("tool_context", "Tool-only description hidden when @tool=false", {"show": {"@tool": [True]}}, {}, context={"@tool": False}, expected_override=False)

    # 1g. `_cnd` operators (eq, not, gt, gte, lt, lte, between, startsWith, endsWith, includes, regex, exists)
    cnd_specs: list[tuple[str, dict[str, Any], dict[str, Any], bool]] = [
        ("cnd eq match", {"show": {"@version": [{"_cnd": {"eq": 2.5}}]}}, {"@version": 2.5}, True),
        ("cnd eq mismatch", {"show": {"@version": [{"_cnd": {"eq": 2.5}}]}}, {"@version": 2.4}, False),
        ("cnd not match", {"show": {"mode": [{"_cnd": {"not": "manual"}}]}}, {"mode": "raw"}, True),
        ("cnd not mismatch", {"show": {"mode": [{"_cnd": {"not": "manual"}}]}}, {"mode": "manual"}, False),
        ("cnd gte match", {"show": {"@version": [{"_cnd": {"gte": 2.2}}]}}, {"@version": 2.5}, True),
        ("cnd gte boundary", {"show": {"@version": [{"_cnd": {"gte": 2.2}}]}}, {"@version": 2.2}, True),
        ("cnd gte below", {"show": {"@version": [{"_cnd": {"gte": 2.2}}]}}, {"@version": 2.0}, False),
        ("cnd gt match", {"show": {"batchSize": [{"_cnd": {"gt": 10}}]}}, {"batchSize": 25}, True),
        ("cnd gt boundary false", {"show": {"batchSize": [{"_cnd": {"gt": 10}}]}}, {"batchSize": 10}, False),
        ("cnd lt match", {"show": {"retries": [{"_cnd": {"lt": 3}}]}}, {"retries": 2}, True),
        ("cnd lte boundary", {"show": {"retries": [{"_cnd": {"lte": 3}}]}}, {"retries": 3}, True),
        ("cnd lte above", {"show": {"retries": [{"_cnd": {"lte": 3}}]}}, {"retries": 5}, False),
        ("cnd between inside", {"show": {"port": [{"_cnd": {"between": {"from": 1024, "to": 65535}}}]}}, {"port": 5432}, True),
        ("cnd between outside", {"show": {"port": [{"_cnd": {"between": {"from": 1024, "to": 65535}}}]}}, {"port": 80}, False),
        ("cnd startsWith https", {"show": {"url": [{"_cnd": {"startsWith": "https://"}}]}}, {"url": "https://n8n.example.com/hook"}, True),
        ("cnd startsWith http false", {"show": {"url": [{"_cnd": {"startsWith": "https://"}}]}}, {"url": "http://localhost:5678"}, False),
        ("cnd endsWith .json", {"show": {"fileName": [{"_cnd": {"endsWith": ".json"}}]}}, {"fileName": "export.json"}, True),
        ("cnd endsWith .csv false", {"show": {"fileName": [{"_cnd": {"endsWith": ".json"}}]}}, {"fileName": "export.csv"}, False),
        ("cnd includes substring", {"show": {"model": [{"_cnd": {"includes": "gpt-4"}}]}}, {"model": "gpt-4o-mini"}, True),
        ("cnd includes miss", {"show": {"model": [{"_cnd": {"includes": "gpt-4"}}]}}, {"model": "claude-sonnet-4"}, False),
        ("cnd regex match", {"show": {"table": [{"_cnd": {"regex": "^audit_[a-z0-9_]+$"}}]}}, {"table": "audit_events_2026"}, True),
        ("cnd regex mismatch", {"show": {"table": [{"_cnd": {"regex": "^audit_[a-z0-9_]+$"}}]}}, {"table": "public_users"}, False),
        ("cnd exists true present", {"show": {"webhookSecret": [{"_cnd": {"exists": True}}]}}, {"webhookSecret": "configured"}, True),
        ("cnd exists true empty string", {"show": {"webhookSecret": [{"_cnd": {"exists": True}}]}}, {"webhookSecret": ""}, False),
        ("cnd exists true missing", {"show": {"webhookSecret": [{"_cnd": {"exists": True}}]}}, {}, False),
        ("cnd exists false missing", {"show": {"webhookSecret": [{"_cnd": {"exists": False}}]}}, {}, True),
        ("hide with cnd lt 2", {"hide": {"@version": [{"_cnd": {"lt": 2}}]}}, {"@version": 1.5}, False),
        ("hide with cnd lt 2 at v2", {"hide": {"@version": [{"_cnd": {"lt": 2}}]}}, {"@version": 2.0}, True),
    ]
    for desc, disp, params, want in cnd_specs:
        add("cnd_operator", f"_cnd evaluation: {desc}", disp, params, expected_override=want)

    # 1h. Nested `fixedCollection` / `collection` parent + child visibility
    parent_q = {"show": {"sendQuery": [True]}}
    child_expr = {"show": {"parameterMode": ["expression"]}}
    add("nested_fixed_collection", "Child in fixedCollection visible when both parent and child match", child_expr, {"sendQuery": True, "parameterMode": "expression"}, parent_disp=parent_q, expected_override=True)
    add("nested_fixed_collection", "Child in fixedCollection hidden when parent sendQuery=false", child_expr, {"sendQuery": False, "parameterMode": "expression"}, parent_disp=parent_q, expected_override=False)
    add("nested_fixed_collection", "Child in fixedCollection hidden when child mode mismatches", child_expr, {"sendQuery": True, "parameterMode": "fixed"}, parent_disp=parent_q, expected_override=False)

    # 1i. Real catalog node property rules sampled deterministically from `NODE_DEFS`
    sampled = 0
    for node in NODE_DEFS:
        if sampled >= 22:
            break
        defaults = {p["name"]: p["default"] for p in node.get("properties", []) if "default" in p}
        for prop in node.get("properties", []):
            if "displayOptions" in prop:
                add(
                    "catalog_schema_property",
                    f"{node['node_type']}.{prop['name']} visibility under default parameters",
                    prop["displayOptions"],
                    {},
                    defaults=defaults,
                )
                sampled += 1
                if sampled >= 22:
                    break

    return cases


# ---------------------------------------------------------------------------
# Category 2: `expression_refs` (80 cases)
# ---------------------------------------------------------------------------

def build_expression_refs_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    idx = 0

    def add(
        sub: str,
        desc: str,
        raw_value: str,
        *,
        is_expr: bool,
        valid_syntax: bool,
        blocks: list[str],
        refs: list[str],
        rename_mode: str = "not_applicable",
        rename_from: str | None = None,
        rename_to: str | None = None,
        rewritten: str | None = None,
        code_like: bool = False,
        compat: str = "exact_parity",
    ) -> None:
        nonlocal idx
        idx += 1
        cases.append({
            "id": f"expr-{idx:04d}",
            "category": "expression_refs",
            "subcategory": sub,
            "compatibilityClass": compat,
            "description": desc,
            "input": {
                "value": raw_value,
                "renameRequest": {"from": rename_from, "to": rename_to} if rename_from else None,
            },
            "expected": {
                "isExpression": is_expr,
                "validSyntax": valid_syntax,
                "expressionBlocks": blocks,
                "referencedNodes": refs,
                "renameMode": rename_mode,
                "rewrittenValue": rewritten,
                "codeLikeExpressionWarning": code_like,
            },
        })

    # 2a. Plain strings vs `={{ ... }}` prefix rules
    add("prefix_detection", "Plain string without leading '=' is literal", "https://api.example.com/v1/users", is_expr=False, valid_syntax=True, blocks=[], refs=[])
    add("prefix_detection", "Mustache braces without leading '=' remain literal text in n8n", "Hello {{ $json.name }}", is_expr=False, valid_syntax=True, blocks=[], refs=[])
    add("prefix_detection", "Leading '=' without '{{' is static formula prefix literal", "=plain-value", is_expr=True, valid_syntax=True, blocks=[], refs=[])
    add("prefix_detection", "Simple $json property access", "={{ $json.foo }}", is_expr=True, valid_syntax=True, blocks=["$json.foo"], refs=[])
    add("prefix_detection", "Nested $json bracket and optional chaining", "={{ $json.user?.profile['email'] ?? 'unknown' }}", is_expr=True, valid_syntax=True, blocks=["$json.user?.profile['email'] ?? 'unknown'"], refs=[])
    add("prefix_detection", "$input.first().json access", "={{ $input.first().json.orderId }}", is_expr=True, valid_syntax=True, blocks=["$input.first().json.orderId"], refs=[])
    add("prefix_detection", "$now Luxon ISO helper", "={{ $now.minus({ hours: 24 }).toISO() }}", is_expr=True, valid_syntax=True, blocks=["$now.minus({ hours: 24 }).toISO()"], refs=[])
    add("prefix_detection", "Built-in n8n string/array expression helpers", "={{ $json.email.extractDomain().toLowerCase() }}", is_expr=True, valid_syntax=True, blocks=["$json.email.extractDomain().toLowerCase()"], refs=[])

    # 2b. Explicit node references & Unicode / punctuation names (safe literal rename)
    literal_ref_specs = [
        ("Single-quoted $() item ref", "={{ $('Inbound Webhook').item.json.body.id }}", ["$('Inbound Webhook').item.json.body.id"], ["Inbound Webhook"], "Inbound Webhook", "Verified Webhook", "={{ $('Verified Webhook').item.json.body.id }}"),
        ("Double-quoted $() first() ref", '={{ $("Fetch Customer").first().json.email }}', ['$("Fetch Customer").first().json.email'], ["Fetch Customer"], "Fetch Customer", "Load Customer", '={{ $("Load Customer").first().json.email }}'),
        ("Legacy $node bracket Unicode rocket", '={{ $node["Unicode Node 🚀"].json.status }}', ['$node["Unicode Node 🚀"].json.status'], ["Unicode Node 🚀"], "Unicode Node 🚀", "Launch Node 🛰️", '={{ $node["Launch Node 🛰️"].json.status }}'),
        ("Unicode CJK & accented node name", "={{ $('Données 日本語').item.json.total }}", ["$('Données 日本語').item.json.total"], ["Données 日本語"], "Données 日本語", "Données Normalisées", "={{ $('Données Normalisées').item.json.total }}"),
        ("Escaped apostrophe inside single-quoted node name", "={{ $('Owner\\'s Approval').item.json.approved }}", ["$('Owner\\'s Approval').item.json.approved"], ["Owner's Approval"], "Owner's Approval", "Manager's Signoff", "={{ $('Manager\\'s Signoff').item.json.approved }}"),
        ("$items() legacy helper literal node ref", '={{ $items("Read Postgres", 0, 0)[0].json.id }}', ['$items("Read Postgres", 0, 0)[0].json.id'], ["Read Postgres"], "Read Postgres", "Query Customers", '={{ $items("Query Customers", 0, 0)[0].json.id }}'),
        ("Node name with dots, slashes, and colons", "={{ $('HTTP: GET /v1/orders.list').last().json.items }}", ["$('HTTP: GET /v1/orders.list').last().json.items"], ["HTTP: GET /v1/orders.list"], "HTTP: GET /v1/orders.list", "HTTP: List Orders", "={{ $('HTTP: List Orders').last().json.items }}"),
        ("isExecuted check on upstream node", "={{ $('Optional Enrichment').isExecuted ? $('Optional Enrichment').item.json.tier : 'standard' }}", ["$('Optional Enrichment').isExecuted ? $('Optional Enrichment').item.json.tier : 'standard'"], ["Optional Enrichment"], "Optional Enrichment", "CRM Enrichment", "={{ $('CRM Enrichment').isExecuted ? $('CRM Enrichment').item.json.tier : 'standard' }}"),
        ("Unrelated node rename leaves expression untouched", "={{ $('Node Alpha').item.json.x }}", ["$('Node Alpha').item.json.x"], ["Node Alpha"], "Node Beta", "Node Gamma", "={{ $('Node Alpha').item.json.x }}"),
        ("String literal mentioning node name outside $() is NOT rewritten", "={{ $('Source Node').item.json.label + ' from Source Node' }}", ["$('Source Node').item.json.label + ' from Source Node'"], ["Source Node"], "Source Node", "Renamed Source", "={{ $('Renamed Source').item.json.label + ' from Source Node' }}"),
    ]
    for desc, raw, blks, rfs, r_from, r_to, rw in literal_ref_specs:
        add("safe_literal_rename", desc, raw, is_expr=True, valid_syntax=True, blocks=blks, refs=rfs, rename_mode="safe_literal", rename_from=r_from, rename_to=r_to, rewritten=rw)

    # 2c. Multi-expression template strings
    multi_specs = [
        (
            "Two expressions in Slack alert template",
            "=Order {{ $('Create Order').item.json.id }} for {{ $('Lookup User').item.json.email }}",
            ["$('Create Order').item.json.id", "$('Lookup User').item.json.email"],
            ["Create Order", "Lookup User"],
            "Lookup User", "Fetch Account",
            "=Order {{ $('Create Order').item.json.id }} for {{ $('Fetch Account').item.json.email }}",
        ),
        (
            "Three expressions mixing $json and two upstream nodes",
            "=https://api.example.com/{{ $('Tenant Config').first().json.region }}/users/{{ $json.userId }}?trace={{ $('Inbound Webhook').item.json.headers['x-request-id'] }}",
            ["$('Tenant Config').first().json.region", "$json.userId", "$('Inbound Webhook').item.json.headers['x-request-id']"],
            ["Tenant Config", "Inbound Webhook"],
            "Tenant Config", "Load Region Config",
            "=https://api.example.com/{{ $('Load Region Config').first().json.region }}/users/{{ $json.userId }}?trace={{ $('Inbound Webhook').item.json.headers['x-request-id'] }}",
        ),
        (
            "Object literal with nested braces inside {{ }}",
            "={{ JSON.stringify({ id: $('Read Row').item.json.id, meta: { ok: true } }) }}",
            ["JSON.stringify({ id: $('Read Row').item.json.id, meta: { ok: true } })"],
            ["Read Row"],
            "Read Row", "Select Row",
            "={{ JSON.stringify({ id: $('Select Row').item.json.id, meta: { ok: true } }) }}",
        ),
    ]
    for desc, raw, blks, rfs, r_from, r_to, rw in multi_specs:
        add("multi_expression_template", desc, raw, is_expr=True, valid_syntax=True, blocks=blks, refs=rfs, rename_mode="safe_literal", rename_from=r_from, rename_to=r_to, rewritten=rw)

    # 2d. Dynamic / computed references -> MUST emit `manual_review_required` on rename
    dynamic_specs = [
        ("Binary concatenation in $()", "={{ $('prefix_' + $json.env).item.json.url }}", ["$('prefix_' + $json.env).item.json.url"]),
        ("Template literal with interpolation in $()", "={{ $(`Branch_${$json.tier}`).first().json.limit }}", ["$(`Branch_${$json.tier}`).first().json.limit"]),
        ("Ternary selector inside $()", "={{ $($json.isProd ? 'Prod DB' : 'Staging DB').item.json.host }}", ["$($json.isProd ? 'Prod DB' : 'Staging DB').item.json.host"]),
        ("Computed bracket index on $node", "={{ $node[$json.sourceNode].json.payload }}", ["$node[$json.sourceNode].json.payload"]),
        ("Computed concatenation on $node[]", "={{ $node['Step ' + $itemIndex].json.result }}", ["$node['Step ' + $itemIndex].json.result"]),
        ("Dynamic first arg in $items()", "={{ $items($json.targetName, 0, 0) }}", ["$items($json.targetName, 0, 0)"]),
        ("Mixed static and dynamic node references", "={{ $('Static Node').item.json.a + $('Dyn_' + $json.k).item.json.b }}", ["$('Static Node').item.json.a + $('Dyn_' + $json.k).item.json.b"]),
    ]
    for desc, raw, blks in dynamic_specs:
        add(
            "dynamic_ref_guard", desc, raw,
            is_expr=True, valid_syntax=True, blocks=blks,
            refs=["Static Node"] if "Static Node" in raw else [],
            rename_mode="manual_review_required",
            rename_from="Prod DB", rename_to="Primary DB", rewritten=None,
            compat="intentional_hardening",
        )

    # 2e. Syntax errors in expressions (15 cases)
    invalid_exprs = [
        ("Empty expression block", "={{ }}"),
        ("Whitespace-only expression block", "={{    }}"),
        ("Unclosed opening mustache braces", "={{ $json.foo"),
        ("Unmatched closing mustache braces", "=$json.foo }}"),
        ("Trailing binary operator", "={{ $json.price * }}"),
        ("Unbalanced opening parenthesis", "={{ ($json.a + $json.b }}"),
        ("Unbalanced closing bracket", "={{ $json.items[0]] }}"),
        ("Unterminated single-quoted string", "={{ $('Broken Node).item.json.id }}"),
        ("Unterminated template literal", "={{ `hello ${$json.name}` + `unclosed }}"),
        ("Double dot property syntax error", "={{ $json..foo }}"),
        ("Invalid keyword token in expression", "={{ class Foo {} }}"),
        ("Broken ternary missing colon", "={{ $json.active ? 'yes' }}"),
        ("Second template block syntax error", "=Valid {{ $json.id }} and broken {{ $json. + }}"),
        ("Invalid regex literal flags", "={{ /abc/xyz.test($json.s) }}"),
        ("Dangling arrow function without body", "={{ $json.items.map(x => ) }}"),
    ]
    for desc, raw in invalid_exprs:
        add("syntax_error", desc, raw, is_expr=True, valid_syntax=False, blocks=[], refs=[])

    # 2f. Multiline / multi-statement code-like expressions (warn to use Code node) (12 cases)
    code_like_specs = [
        ("IIFE with const declarations", "={{ (() => { const a = $json.x; const b = a * 2; return b + 1; })() }}"),
        ("Multi-statement body with semicolons", "={{ let sum = 0; for (const x of $json.arr) { sum += x; } return sum; }}"),
        ("Multiline map/reduce pipeline > 3 statements", "={{\n  const valid = $json.items.filter(i => i.ok);\n  const mapped = valid.map(i => i.amount);\n  return mapped.reduce((a, b) => a + b, 0);\n}}"),
        ("Try/catch block inside expression", "={{ (() => { try { return JSON.parse($json.raw); } catch (e) { return null; } })() }}"),
        ("While loop inside expression", "={{ (() => { let n = 5; while (n > 0) { n--; } return n; })() }}"),
        ("Switch statement inside expression", "={{ (() => { switch ($json.kind) { case 'a': return 1; default: return 0; } })() }}"),
        ("Function declaration inside expression", "={{ (function compute(v) { if (v <= 1) return 1; return v * compute(v - 1); })(5) }}"),
        ("Object mutation across statements", "={{ const out = {}; out.id = $json.id; out.ts = Date.now(); return out; }}"),
        ("RegExp exec loop in expression", "={{ (() => { const re = /\\d+/g; const m = []; let r; while ((r = re.exec($json.s))) m.push(r[0]); return m; })() }}"),
        ("Nested conditionals and assignments", "={{ let tier = 'free'; if ($json.spend > 1000) { tier = 'ent'; } else if ($json.spend > 100) { tier = 'pro'; } return tier; }}"),
        ("Array sort + dedupe imperative block", "={{ const seen = new Set(); const res = []; for (const x of $json.list) { if (!seen.has(x)) { seen.add(x); res.push(x); } } return res; }}"),
        ("HMAC-like manual byte loop in expression", "={{ (() => { const bytes = [1,2,3,4]; let acc = 0; for (let i = 0; i < bytes.length; i++) acc ^= bytes[i]; return acc; })() }}"),
    ]
    for desc, raw in code_like_specs:
        add("code_like_expression", desc, raw, is_expr=True, valid_syntax=True, blocks=[raw[3:-2].strip()], refs=[], code_like=True, compat="intentional_hardening")

    # 2g. Parameterized bulk variations across real catalog node names (fill to 80 cases)
    sample_names = [
        "Webhook Trigger", "Read Postgres", "Upsert HubSpot", "Support AI Agent",
        "Diff Records", "Post Slack Digest", "Check Redis Lock", "Parse XML Feed",
        "Classify Ticket", "Qdrant Knowledge Base", "Fetch Unread Emails",
        "Stamp Timestamp", "Upsert Audit Row", "Throttle Pause", "Summarize Run", "Render HTML Notes",
    ]
    for n_name in sample_names:
        raw = f"={{{{ $('{n_name}').item.json.id }}}}"
        rw = f"={{{{ $('{n_name} V2').item.json.id }}}}"
        add(
            "catalog_node_ref_rename",
            f"Safe rename rewrite for upstream node '{n_name}'",
            raw,
            is_expr=True, valid_syntax=True,
            blocks=[f"$('{n_name}').item.json.id"],
            refs=[n_name],
            rename_mode="safe_literal",
            rename_from=n_name, rename_to=f"{n_name} V2", rewritten=rw,
        )

    return cases


# ---------------------------------------------------------------------------
# Category 3: `node_validation` (75 cases)
# ---------------------------------------------------------------------------

def build_node_validation_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    idx = 0

    def add(
        sub: str,
        desc: str,
        node_json: dict[str, Any],
        *,
        valid: bool,
        confidence: str = "authoritative",
        error_codes: list[str] | None = None,
        warning_codes: list[str] | None = None,
        compat: str = "exact_parity",
    ) -> None:
        nonlocal idx
        idx += 1
        cases.append({
            "id": f"nval-{idx:04d}",
            "category": "node_validation",
            "subcategory": sub,
            "compatibilityClass": compat,
            "description": desc,
            "input": {"node": node_json},
            "expected": {
                "valid": valid,
                "validationConfidence": confidence,
                "errorCodes": error_codes or [],
                "warningCodes": warning_codes or [],
            },
        })

    # 3a. Valid core & AI nodes (18 cases)
    valid_nodes = [
        ("Valid GET HTTP Request", {"id": "1", "name": "Fetch Users", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "GET", "url": "https://api.example.com/users"}}),
        ("Valid POST HTTP Request with JSON body", {"id": "2", "name": "Create User", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "POST", "url": "https://api.example.com/users", "sendBody": True, "contentType": "json", "specifyBody": "json", "jsonBody": '{"name":"Alice"}'}}),
        ("Valid Webhook with Header Auth", {"id": "3", "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "parameters": {"httpMethod": "POST", "path": "orders/new", "authentication": "headerAuth"}, "credentials": {"httpHeaderAuth": {"id": "cred_1", "name": "Webhook Header"}}}),
        ("Valid Postgres select", {"id": "4", "name": "Select Orders", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "select", "schema": "public", "table": "orders", "returnAll": False, "limit": 25}, "credentials": {"postgres": {"id": "cred_pg", "name": "Prod PG"}}}),
        ("Valid Postgres executeQuery (table hidden)", {"id": "5", "name": "Run SQL", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "executeQuery", "query": "SELECT count(*) FROM orders"}, "credentials": {"postgres": {"id": "cred_pg", "name": "Prod PG"}}}),
        ("Valid Slack message post", {"id": "6", "name": "Notify Slack", "type": "n8n-nodes-base.slack", "typeVersion": 2.3, "parameters": {"authentication": "accessToken", "resource": "message", "operation": "post", "channelId": "C01234", "text": "Deployment complete"}, "credentials": {"slackApi": {"id": "cred_sl", "name": "Slack Bot"}}}),
        ("Valid Edit Fields (Set) manual mode", {"id": "7", "name": "Normalize", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "parameters": {"mode": "manual", "assignments": {"assignments": [{"name": "ok", "type": "boolean", "value": True}]}}}),
        ("Valid Edit Fields (Set) raw JSON mode", {"id": "8", "name": "Raw JSON", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "parameters": {"mode": "raw", "jsonOutput": '{"hello":"world"}'}}),
        ("Valid IF v2.2 node", {"id": "9", "name": "Check Status", "type": "n8n-nodes-base.if", "typeVersion": 2.2, "parameters": {"conditions": {"combinator": "and", "conditions": []}}}),
        ("Valid Switch rules mode", {"id": "10", "name": "Route Tier", "type": "n8n-nodes-base.switch", "typeVersion": 3.2, "parameters": {"mode": "rules", "rules": {"values": []}}}),
        ("Valid Merge combine by fields", {"id": "11", "name": "Join Streams", "type": "n8n-nodes-base.merge", "typeVersion": 3.1, "parameters": {"mode": "combine", "combineBy": "combineByFields", "fieldsToMatchString": "userId"}}),
        ("Valid Redis set with TTL", {"id": "12", "name": "Set Cache", "type": "n8n-nodes-base.redis", "typeVersion": 1, "parameters": {"operation": "set", "key": "session:1", "value": "ok", "expire": True, "ttl": 120}, "credentials": {"redis": {"id": "cred_rd", "name": "Redis"}}}),
        ("Valid Data Table upsert", {"id": "13", "name": "Upsert State", "type": "n8n-nodes-base.dataTable", "typeVersion": 1, "parameters": {"operation": "upsert", "dataTableId": "tbl_runs"}}),
        ("Valid AI Agent auto prompt", {"id": "14", "name": "Ops Agent", "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 1.8, "parameters": {"promptType": "auto"}}),
        ("Valid OpenAI Chat Model", {"id": "15", "name": "GPT-4o Mini", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1.2, "parameters": {"model": "gpt-4o-mini"}, "credentials": {"openAiApi": {"id": "cred_oa", "name": "OpenAI"}}}),
        ("Valid Qdrant retrieve-as-tool", {"id": "16", "name": "KB Search", "type": "@n8n/n8n-nodes-langchain.vectorStoreQdrant", "typeVersion": 1.1, "parameters": {"mode": "retrieve-as-tool", "qdrantCollection": "docs", "toolName": "search_docs", "toolDescription": "Searches docs."}, "credentials": {"qdrantApi": {"id": "cred_qd", "name": "Qdrant"}}}),
        ("Valid Crypto HMAC SHA256", {"id": "17", "name": "Verify Sig", "type": "n8n-nodes-base.crypto", "typeVersion": 1, "parameters": {"action": "hmac", "type": "SHA256", "value": "={{ $json.raw }}", "secret": "={{ $vars.PURPOSE }}", "dataPropertyName": "sig"}}),
        ("Valid Code node with 'Why Code:' rationale", {"id": "18", "name": "Custom Parser", "type": "n8n-nodes-base.code", "typeVersion": 2, "notes": "Why Code: Stateful binary frame CRC16 parser not supported by native nodes.", "parameters": {"mode": "runOnceForAllItems", "language": "javaScript", "jsCode": "return $input.all();"}}),
    ]
    for desc, nj in valid_nodes:
        add("valid_known_node", desc, nj, valid=True)

    # 3b. Missing top-level & conditional required properties (20 cases)
    missing_req = [
        ("HTTP Request missing required url", {"id": "1", "name": "HTTP", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "GET"}}, ["missing_required_property:url"]),
        ("HTTP Request empty url", {"id": "2", "name": "HTTP", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "GET", "url": ""}}, ["missing_required_property:url"]),
        ("Webhook missing required path", {"id": "3", "name": "Hook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "parameters": {"httpMethod": "POST"}}, ["missing_required_property:path"]),
        ("Postgres select missing required table", {"id": "4", "name": "PG", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "select"}, "credentials": {"postgres": {"id": "c1", "name": "PG"}}}, ["missing_required_property:table"]),
        ("Postgres executeQuery missing required query", {"id": "5", "name": "PG", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "executeQuery"}, "credentials": {"postgres": {"id": "c1", "name": "PG"}}}, ["missing_required_property:query"]),
        ("Slack message:post missing channelId and text", {"id": "6", "name": "Slack", "type": "n8n-nodes-base.slack", "typeVersion": 2.3, "parameters": {"resource": "message", "operation": "post"}, "credentials": {"slackApi": {"id": "c2", "name": "Slack"}}}, ["missing_required_property:channelId", "missing_required_property:text"]),
        ("Gmail message:send missing sendTo/subject/message", {"id": "7", "name": "Gmail", "type": "n8n-nodes-base.gmail", "typeVersion": 2.1, "parameters": {"resource": "message", "operation": "send"}, "credentials": {"gmailOAuth2": {"id": "c3", "name": "Gmail"}}}, ["missing_required_property:sendTo", "missing_required_property:subject", "missing_required_property:message"]),
        ("Jira issue:create missing project and summary", {"id": "8", "name": "Jira", "type": "n8n-nodes-base.jira", "typeVersion": 1, "parameters": {"resource": "issue", "operation": "create"}, "credentials": {"jiraSoftwareCloudApi": {"id": "c4", "name": "Jira"}}}, ["missing_required_property:project", "missing_required_property:summary"]),
        ("Merge combineByFields missing fieldsToMatchString", {"id": "9", "name": "Merge", "type": "n8n-nodes-base.merge", "typeVersion": 3.1, "parameters": {"mode": "combine", "combineBy": "combineByFields"}}, ["missing_required_property:fieldsToMatchString"]),
        ("Respond to Webhook redirect missing redirectURL", {"id": "10", "name": "Reply", "type": "n8n-nodes-base.respondToWebhook", "typeVersion": 1.1, "parameters": {"respondWith": "redirect"}}, ["missing_required_property:redirectURL"]),
        ("Execute Workflow database source missing workflowId", {"id": "11", "name": "Call Sub", "type": "n8n-nodes-base.executeWorkflow", "typeVersion": 1.2, "parameters": {"source": "database"}}, ["missing_required_property:workflowId"]),
        ("Execute Command missing command", {"id": "12", "name": "Exec", "type": "n8n-nodes-base.executeCommand", "typeVersion": 1, "parameters": {}}, ["missing_required_property:command"]),
        ("Read/Write Files write mode missing fileName", {"id": "13", "name": "Write Disk", "type": "n8n-nodes-base.readWriteFile", "typeVersion": 1, "parameters": {"operation": "write"}}, ["missing_required_property:fileName"]),
        ("Split Out missing fieldToSplitOut", {"id": "14", "name": "Split", "type": "n8n-nodes-base.splitOut", "typeVersion": 1, "parameters": {}}, ["missing_required_property:fieldToSplitOut"]),
        ("Remove Duplicates selectedFields missing fieldsToCompare", {"id": "15", "name": "Dedupe", "type": "n8n-nodes-base.removeDuplicates", "typeVersion": 2, "parameters": {"operation": "removeDuplicateInputItems", "compare": "selectedFields"}}, ["missing_required_property:fieldsToCompare"]),
        ("Crypto hmac missing value and secret", {"id": "16", "name": "HMAC", "type": "n8n-nodes-base.crypto", "typeVersion": 1, "parameters": {"action": "hmac"}}, ["missing_required_property:value", "missing_required_property:secret"]),
        ("AI Agent define mode missing text", {"id": "17", "name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 1.8, "parameters": {"promptType": "define", "text": ""}}, ["missing_required_property:text"]),
        ("Simple Memory customKey missing sessionKey", {"id": "18", "name": "Memory", "type": "@n8n/n8n-nodes-langchain.memoryBufferWindow", "typeVersion": 1.3, "parameters": {"sessionIdType": "customKey"}}, ["missing_required_property:sessionKey"]),
        ("Qdrant retrieve-as-tool missing qdrantCollection", {"id": "19", "name": "Qdrant", "type": "@n8n/n8n-nodes-langchain.vectorStoreQdrant", "typeVersion": 1.1, "parameters": {"mode": "retrieve-as-tool"}, "credentials": {"qdrantApi": {"id": "cq", "name": "Q"}}}, ["missing_required_property:qdrantCollection"]),
        ("Data Table missing dataTableId", {"id": "20", "name": "DT", "type": "n8n-nodes-base.dataTable", "typeVersion": 1, "parameters": {"operation": "get"}}, ["missing_required_property:dataTableId"]),
    ]
    for desc, nj, errs in missing_req:
        add("missing_required_property", desc, nj, valid=False, error_codes=errs)

    # 3c. Invalid enum `options` values (12 cases)
    bad_enums = [
        ("HTTP Request invalid method TRACE", {"id": "1", "name": "HTTP", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "TRACE", "url": "https://example.com"}}, ["invalid_option_value:method"]),
        ("Webhook invalid authentication mode oauth99", {"id": "2", "name": "Hook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "parameters": {"httpMethod": "POST", "path": "test", "authentication": "oauth99"}}, ["invalid_option_value:authentication"]),
        ("Slack invalid resource workspaceAdmin", {"id": "3", "name": "Slack", "type": "n8n-nodes-base.slack", "typeVersion": 2.3, "parameters": {"resource": "workspaceAdmin", "operation": "post"}, "credentials": {"slackApi": {"id": "c", "name": "S"}}}, ["invalid_option_value:resource"]),
        ("Slack message invalid operation archiveChannel", {"id": "4", "name": "Slack", "type": "n8n-nodes-base.slack", "typeVersion": 2.3, "parameters": {"resource": "message", "operation": "archiveChannel"}, "credentials": {"slackApi": {"id": "c", "name": "S"}}}, ["invalid_option_value:operation"]),
        ("Postgres invalid operation dropDatabase", {"id": "5", "name": "PG", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "dropDatabase", "table": "t"}, "credentials": {"postgres": {"id": "c", "name": "PG"}}}, ["invalid_option_value:operation"]),
        ("Merge invalid mode crossJoinMagic", {"id": "6", "name": "Merge", "type": "n8n-nodes-base.merge", "typeVersion": 3.1, "parameters": {"mode": "crossJoinMagic"}}, ["invalid_option_value:mode"]),
        ("Edit Fields invalid mode yaml", {"id": "7", "name": "Set", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "parameters": {"mode": "yaml"}}, ["invalid_option_value:mode"]),
        ("Limit invalid keep middleItems", {"id": "8", "name": "Limit", "type": "n8n-nodes-base.limit", "typeVersion": 1, "parameters": {"maxItems": 5, "keep": "middleItems"}}, ["invalid_option_value:keep"]),
        ("Compression invalid outputFormat rar", {"id": "9", "name": "Zip", "type": "n8n-nodes-base.compression", "typeVersion": 1.1, "parameters": {"operation": "compress", "binaryPropertyName": "data", "outputFormat": "rar"}}, ["invalid_option_value:outputFormat"]),
        ("Code invalid language ruby", {"id": "10", "name": "Code", "type": "n8n-nodes-base.code", "typeVersion": 2, "notes": "Why Code: test", "parameters": {"language": "ruby"}}, ["invalid_option_value:language"]),
        ("Wait invalid resume onSignal", {"id": "11", "name": "Wait", "type": "n8n-nodes-base.wait", "typeVersion": 1.1, "parameters": {"resume": "onSignal"}}, ["invalid_option_value:resume"]),
        ("Qdrant invalid mode dropCollection", {"id": "12", "name": "Qdrant", "type": "@n8n/n8n-nodes-langchain.vectorStoreQdrant", "typeVersion": 1.1, "parameters": {"mode": "dropCollection", "qdrantCollection": "kb"}, "credentials": {"qdrantApi": {"id": "c", "name": "Q"}}}, ["invalid_option_value:mode"]),
    ]
    for desc, nj, errs in bad_enums:
        add("invalid_enum_option", desc, nj, valid=False, error_codes=errs)

    # 3d. Credential-type compatibility & missing required credentials (10 cases)
    cred_cases = [
        ("Postgres missing required postgres credential", {"id": "1", "name": "PG", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "select", "table": "users"}}, False, ["missing_required_credential:postgres"]),
        ("Postgres bound to incompatible slackApi credential", {"id": "2", "name": "PG", "type": "n8n-nodes-base.postgres", "typeVersion": 2.5, "parameters": {"operation": "select", "table": "users"}, "credentials": {"slackApi": {"id": "c1", "name": "Wrong"}}}, False, ["incompatible_credential_type:slackApi", "missing_required_credential:postgres"]),
        ("Webhook basicAuth missing httpBasicAuth credential", {"id": "3", "name": "Hook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "parameters": {"httpMethod": "POST", "path": "secure", "authentication": "basicAuth"}}, False, ["missing_required_credential:httpBasicAuth"]),
        ("Webhook authentication=none requires no credential", {"id": "4", "name": "Public Hook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "parameters": {"httpMethod": "POST", "path": "public", "authentication": "none"}}, True, []),
        ("OpenAI Chat Model missing openAiApi credential", {"id": "5", "name": "LLM", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1.2, "parameters": {"model": "gpt-4o-mini"}}, False, ["missing_required_credential:openAiApi"]),
        ("OpenAI Chat Model given anthropicApi credential", {"id": "6", "name": "LLM", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1.2, "parameters": {"model": "gpt-4o-mini"}, "credentials": {"anthropicApi": {"id": "ca", "name": "Claude"}}}, False, ["incompatible_credential_type:anthropicApi", "missing_required_credential:openAiApi"]),
        ("HTTP Request genericCredentialType=httpBearerAuth with matching credential", {"id": "7", "name": "API", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "parameters": {"method": "GET", "url": "https://api.example.com", "authentication": "genericCredentialType", "genericAuthType": "httpBearerAuth"}, "credentials": {"httpBearerAuth": {"id": "cb", "name": "Bearer"}}}, True, []),
        ("Slack oAuth2 mode satisfied by slackOAuth2Api", {"id": "8", "name": "Slack", "type": "n8n-nodes-base.slack", "typeVersion": 2.3, "parameters": {"authentication": "oAuth2", "resource": "message", "operation": "post", "channelId": "C1", "text": "hi"}, "credentials": {"slackOAuth2Api": {"id": "co", "name": "Slack OAuth"}}}, True, []),
        ("GitHub missing githubApi credential", {"id": "9", "name": "GH", "type": "n8n-nodes-base.github", "typeVersion": 1.1, "parameters": {"resource": "issue", "operation": "get", "owner": "org", "repository": "repo"}}, False, ["missing_required_credential:githubApi"]),
        ("PGVector satisfied by postgres credential", {"id": "10", "name": "PGV", "type": "@n8n/n8n-nodes-langchain.vectorStorePGVector", "typeVersion": 1.1, "parameters": {"mode": "load", "tableName": "vecs"}, "credentials": {"postgres": {"id": "cp", "name": "PG"}}}, True, []),
    ]
    for desc, nj, ok, errs in cred_cases:
        add("credential_compatibility", desc, nj, valid=ok, error_codes=errs)

    # 3e. Unknown community / custom nodes -> `partial` confidence (never crash or claim authoritative) (7 cases)
    comm_nodes = [
        ("Community package CRM node yields partial confidence", "n8n-nodes-acme-crm.acmeContact"),
        ("Scoped community scraper node yields partial confidence", "@community/n8n-nodes-firecrawl.firecrawl"),
        ("Internal private custom node yields partial confidence", "CUSTOM.internalLedgerSync"),
        ("Community WhatsApp bridge node yields partial confidence", "n8n-nodes-evolution-api.evolutionApi"),
        ("Community PDF generator node yields partial confidence", "n8n-nodes-pdfmake.pdfMake"),
        ("Community ClickHouse node yields partial confidence", "n8n-nodes-clickhouse.clickHouse"),
        ("Community Meilisearch node yields partial confidence", "n8n-nodes-meilisearch.meilisearch"),
    ]
    for desc, ctype in comm_nodes:
        add(
            "community_partial_confidence", desc,
            {"id": "c1", "name": "Community Step", "type": ctype, "typeVersion": 1, "parameters": {"action": "sync"}},
            valid=True, confidence="partial", warning_codes=["unknown_node_type_partial_validation"],
            compat="intentional_hardening",
        )

    # 3f. `Code` node `Why Code:` native-first governance checks (8 cases)
    code_rationale_cases = [
        ("Code node with explicit 'Why Code:' prefix passes cleanly", "Why Code: Recursive tree flattening with cycle tracking.", True, []),
        ("Code node with leading whitespace before 'Why Code:' passes", "  Why Code: Custom binary protobuf framing.", True, []),
        ("Code node with no notes emits native-first warning", None, True, ["native_first_code_rationale_missing"]),
        ("Code node with empty notes emits native-first warning", "", True, ["native_first_code_rationale_missing"]),
        ("Code node with generic note lacking 'Why Code:' emits warning", "Transforms the array items", True, ["native_first_code_rationale_missing"]),
        ("Code node replacing simple field mapping emits warning", "Map firstName and lastName", True, ["native_first_code_rationale_missing"]),
        ("Code node with Python language and 'Why Code:' passes", "Why Code: Statistical quantile calculation in Python.", True, []),
        ("Code node with syntax error in jsCode fails validation", "Why Code: Custom parser", False, []),
    ]
    for c_i, (desc, notes_val, ok, warns) in enumerate(code_rationale_cases, 1):
        nj: dict[str, Any] = {
            "id": f"code_{c_i}",
            "name": "Code Step",
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "parameters": {
                "mode": "runOnceForAllItems",
                "language": "python" if "Python" in desc else "javaScript",
                "jsCode": "function broken( {" if not ok else "return $input.all();",
                "pythonCode": "return _input.all()",
            },
        }
        if notes_val is not None:
            nj["notes"] = notes_val
        add(
            "why_code_governance", desc, nj,
            valid=ok,
            error_codes=["invalid_code_syntax"] if not ok else [],
            warning_codes=warns,
            compat="intentional_hardening",
        )

    return cases


# ---------------------------------------------------------------------------
# Category 4: `graph_topology` (65 cases)
# ---------------------------------------------------------------------------

def build_graph_topology_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    idx = 0

    def add(
        sub: str,
        desc: str,
        nodes: list[dict[str, Any]],
        connections: dict[str, Any],
        *,
        valid: bool,
        has_cycles: bool = False,
        controlled_loop: bool = False,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        compat: str = "exact_parity",
    ) -> None:
        nonlocal idx
        idx += 1
        cases.append({
            "id": f"topo-{idx:04d}",
            "category": "graph_topology",
            "subcategory": sub,
            "compatibilityClass": compat,
            "description": desc,
            "input": {
                "workflow": {
                    "name": f"Topology Case {idx}",
                    "nodes": nodes,
                    "connections": connections,
                }
            },
            "expected": {
                "valid": valid,
                "nodeCount": len(nodes),
                "hasCycles": has_cycles,
                "isControlledLoop": controlled_loop,
                "errorCodes": errors or [],
                "warningCodes": warnings or [],
            },
        })

    def nd(name: str, ntype: str, ver: float = 1.0) -> dict[str, Any]:
        return {"id": name.lower().replace(" ", "_"), "name": name, "type": ntype, "typeVersion": ver, "position": [200, 200], "parameters": {}}

    def edge(dst: str, port: str = "main", index: int = 0) -> dict[str, Any]:
        return {"node": dst, "type": port, "index": index}

    # 4a. Valid linear & branching workflows (15 cases)
    for length in range(2, 8):
        chain_nodes = [nd("Trigger", "n8n-nodes-base.manualTrigger")] + [nd(f"Step {i}", "n8n-nodes-base.set", 3.4) for i in range(1, length)]
        conns: dict[str, Any] = {}
        for i in range(len(chain_nodes) - 1):
            conns[chain_nodes[i]["name"]] = {"main": [[edge(chain_nodes[i + 1]["name"])]]}
        add("valid_linear", f"Valid {length}-node linear pipeline", chain_nodes, conns, valid=True)

    add(
        "valid_branching", "Valid IF true/false branching into Merge",
        [nd("Webhook", "n8n-nodes-base.webhook", 2), nd("IF", "n8n-nodes-base.if", 2.2), nd("True Set", "n8n-nodes-base.set", 3.4), nd("False Set", "n8n-nodes-base.set", 3.4), nd("Merge", "n8n-nodes-base.merge", 3.1)],
        {
            "Webhook": {"main": [[edge("IF")]]},
            "IF": {"main": [[edge("True Set")], [edge("False Set")]]},
            "True Set": {"main": [[edge("Merge", "main", 0)]]},
            "False Set": {"main": [[edge("Merge", "main", 1)]]},
        },
        valid=True,
    )
    for num_branches in [2, 3, 4]:
        sw_nodes = [nd("Trigger", "n8n-nodes-base.manualTrigger"), nd("Switch", "n8n-nodes-base.switch", 3.2)] + [nd(f"B{b}", "n8n-nodes-base.slack", 2.3) for b in range(num_branches)]
        add(
            "valid_branching", f"Valid Switch {num_branches}-way fan-out",
            sw_nodes,
            {"Trigger": {"main": [[edge("Switch")]]}, "Switch": {"main": [[edge(f"B{b}")] for b in range(num_branches)]}},
            valid=True,
        )
    for fanout in [2, 3, 4]:
        fo_nodes = [nd("Schedule", "n8n-nodes-base.scheduleTrigger", 1.2)] + [nd(f"Target {k}", "n8n-nodes-base.httpRequest", 4.2) for k in range(fanout)]
        add(
            "valid_branching", f"Valid parallel fan-out from Schedule to {fanout} targets",
            fo_nodes,
            {"Schedule": {"main": [[edge(f"Target {k}") for k in range(fanout)]]}},
            valid=True,
        )
    add(
        "valid_branching", "Valid Compare Datasets 4-output reconciliation graph",
        [nd("Start", "n8n-nodes-base.manualTrigger"), nd("A", "n8n-nodes-base.postgres", 2.5), nd("B", "n8n-nodes-base.googleSheets", 4.5), nd("Compare", "n8n-nodes-base.compareDatasets", 2.3), nd("Insert", "n8n-nodes-base.googleSheets", 4.5), nd("Update", "n8n-nodes-base.googleSheets", 4.5)],
        {
            "Start": {"main": [[edge("A"), edge("B")]]},
            "A": {"main": [[edge("Compare", "main", 0)]]},
            "B": {"main": [[edge("Compare", "main", 1)]]},
            "Compare": {"main": [[edge("Insert")], [], [edge("Update")], []]},
        },
        valid=True,
    )
    add(
        "valid_branching", "Valid Error Trigger standalone incident handler",
        [nd("Error Trigger", "n8n-nodes-base.errorTrigger", 1), nd("Notify Slack", "n8n-nodes-base.slack", 2.3)],
        {"Error Trigger": {"main": [[edge("Notify Slack")]]}},
        valid=True,
    )

    # 4b. Loop Over Items (`splitInBatches`) valid cycles vs invalid uncontrolled cycles (12 cases)
    for loop_len in [1, 2, 3, 4]:
        body = [nd(f"Body {k}", "n8n-nodes-base.set", 3.4) for k in range(1, loop_len + 1)]
        l_nodes = [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Loop", "n8n-nodes-base.splitInBatches", 3), nd("Done", "n8n-nodes-base.summarize", 1.1)] + body
        l_conns: dict[str, Any] = {
            "Start": {"main": [[edge("Loop")]]},
            "Loop": {"main": [[edge("Done")], [edge(body[0]["name"])]]},
        }
        for k in range(len(body) - 1):
            l_conns[body[k]["name"]] = {"main": [[edge(body[k + 1]["name"])]]}
        l_conns[body[-1]["name"]] = {"main": [[edge("Loop")]]}
        add("valid_loop_cycle", f"Valid Loop Over Items back-edge with {loop_len} body node(s)", l_nodes, l_conns, valid=True, has_cycles=True, controlled_loop=True)

    add(
        "valid_loop_cycle", "Valid polling retry loop controlled by Wait + IF",
        [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Poll Status", "n8n-nodes-base.httpRequest", 4.2), nd("Is Ready", "n8n-nodes-base.if", 2.2), nd("Wait 5s", "n8n-nodes-base.wait", 1.1), nd("Finish", "n8n-nodes-base.set", 3.4)],
        {
            "Start": {"main": [[edge("Poll Status")]]},
            "Poll Status": {"main": [[edge("Is Ready")]]},
            "Is Ready": {"main": [[edge("Finish")], [edge("Wait 5s")]]},
            "Wait 5s": {"main": [[edge("Poll Status")]]},
        },
        valid=True, has_cycles=True, controlled_loop=True,
    )

    uncontrolled_specs = [
        ("Self-loop on Set node", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set A", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Set A")]]}, "Set A": {"main": [[edge("Set A")]]}}),
        ("Direct 2-node Set <-> HTTP infinite cycle", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set A", "n8n-nodes-base.set", 3.4), nd("HTTP B", "n8n-nodes-base.httpRequest", 4.2)], {"Start": {"main": [[edge("Set A")]]}, "Set A": {"main": [[edge("HTTP B")]]}, "HTTP B": {"main": [[edge("Set A")]]}}),
        ("3-node cycle without Loop Over Items or Wait", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("A", "n8n-nodes-base.set", 3.4), nd("B", "n8n-nodes-base.filter", 2.2), nd("C", "n8n-nodes-base.sort", 1)], {"Start": {"main": [[edge("A")]]}, "A": {"main": [[edge("B")]]}, "B": {"main": [[edge("C")]]}, "C": {"main": [[edge("A")]]}}),
        ("Cycle feeding back into Webhook trigger", [nd("Webhook", "n8n-nodes-base.webhook", 2), nd("Set", "n8n-nodes-base.set", 3.4)], {"Webhook": {"main": [[edge("Set")]]}, "Set": {"main": [[edge("Webhook")]]}}),
        ("Loop Over Items done branch cycling back into Loop", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Loop", "n8n-nodes-base.splitInBatches", 3)], {"Start": {"main": [[edge("Loop")]]}, "Loop": {"main": [[edge("Loop")], []]}}),
        ("Disconnected 2-node cycle island", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("X", "n8n-nodes-base.set", 3.4), nd("Y", "n8n-nodes-base.set", 3.4)], {"X": {"main": [[edge("Y")]]}, "Y": {"main": [[edge("X")]]}}),
        ("Merge self-feedback cycle", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Merge", "n8n-nodes-base.merge", 3.1)], {"Start": {"main": [[edge("Merge", "main", 0)]]}, "Merge": {"main": [[edge("Merge", "main", 1)]]}}),
    ]
    for desc, u_nodes, u_conns in uncontrolled_specs:
        add("uncontrolled_cycle", desc, u_nodes, u_conns, valid=False, has_cycles=True, controlled_loop=False, errors=["uncontrolled_cycle"])

    # 4c. Invalid dangling references & out-of-range ports (12 cases)
    dangling_specs = [
        ("Target node does not exist in nodes[]", [nd("Start", "n8n-nodes-base.manualTrigger")], {"Start": {"main": [[edge("Ghost Node")]]}}, ["dangling_connection_target:Ghost Node"]),
        ("Source node key in connections does not exist in nodes[]", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set", "n8n-nodes-base.set", 3.4)], {"Removed Node": {"main": [[edge("Set")]]}}, ["dangling_connection_source:Removed Node"]),
        ("Case-mismatch target node name ('set' vs 'Set')", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("set")]]}}, ["dangling_connection_target:set"]),
        ("Stale connection left behind after node rename", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Load User", "n8n-nodes-base.postgres", 2.5)], {"Start": {"main": [[edge("Fetch User")]]}}, ["dangling_connection_target:Fetch User"]),
        ("Duplicate node names in nodes[]", [nd("Dup", "n8n-nodes-base.manualTrigger"), nd("Dup", "n8n-nodes-base.set", 3.4)], {}, ["duplicate_node_name:Dup"]),
        ("Duplicate node IDs in nodes[]", [{"id": "same", "name": "A", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": [0, 0], "parameters": {}}, {"id": "same", "name": "B", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [200, 0], "parameters": {}}], {"A": {"main": [[edge("B")]]}}, ["duplicate_node_id:same"]),
        ("Negative target input index", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Set", "main", -1)]]}}, ["invalid_input_index"]),
        ("Single-input Set receiving main index 2", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Set", "main", 2)]]}}, ["input_index_out_of_bounds:Set:2"]),
        ("Single-output Set emitting main branch 1", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Set", "n8n-nodes-base.set", 3.4), nd("B", "n8n-nodes-base.noOp", 1)], {"Start": {"main": [[edge("Set")]]}, "Set": {"main": [[], [edge("B")]]}}, ["output_branch_out_of_bounds:Set:1"]),
        ("Stop and Error node (0 outputs) wired to downstream node", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Stop", "n8n-nodes-base.stopAndError", 1), nd("After", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Stop")]]}, "Stop": {"main": [[edge("After")]]}}, ["node_has_no_outputs:Stop"]),
        ("Trigger node receiving incoming main edge", [nd("A", "n8n-nodes-base.manualTrigger"), nd("Hook", "n8n-nodes-base.webhook", 2)], {"A": {"main": [[edge("Hook")]]}}, ["trigger_cannot_receive_main_input:Hook"]),
        ("Empty workflow with zero nodes", [], {}, ["empty_workflow"]),
    ]
    for desc, d_nodes, d_conns, errs in dangling_specs:
        add("dangling_or_bounds", desc, d_nodes, d_conns, valid=False, errors=errs)

    # 4d. AI LangChain sub-node port topology (`ai_languageModel`, `ai_tool`, `ai_memory`, `ai_outputParser`, `ai_embedding`, `ai_document`) (16 cases)
    add(
        "ai_subnode_ports", "Valid full AI Agent cluster with Model, Memory, Calculator, Qdrant + Embeddings, and Structured Output Parser",
        [
            nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1),
            nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8),
            nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2),
            nd("Memory", "@n8n/n8n-nodes-langchain.memoryBufferWindow", 1.3),
            nd("Calc", "@n8n/n8n-nodes-langchain.toolCalculator", 1),
            nd("Qdrant", "@n8n/n8n-nodes-langchain.vectorStoreQdrant", 1.1),
            nd("Embed", "@n8n/n8n-nodes-langchain.embeddingsOpenAi", 1.1),
            nd("Parser", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2),
        ],
        {
            "Chat": {"main": [[edge("Agent")]]},
            "OpenAI": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]},
            "Memory": {"ai_memory": [[edge("Agent", "ai_memory", 0)]]},
            "Calc": {"ai_tool": [[edge("Agent", "ai_tool", 0)]]},
            "Qdrant": {"ai_tool": [[edge("Agent", "ai_tool", 0)]]},
            "Embed": {"ai_embedding": [[edge("Qdrant", "ai_embedding", 0)]]},
            "Parser": {"ai_outputParser": [[edge("Agent", "ai_outputParser", 0)]]},
        },
        valid=True,
    )
    add(
        "ai_subnode_ports", "Valid Basic LLM Chain with Auto-fixing + Structured Output Parser",
        [
            nd("Start", "n8n-nodes-base.manualTrigger", 1),
            nd("Chain", "@n8n/n8n-nodes-langchain.chainLlm", 1.5),
            nd("Claude", "@n8n/n8n-nodes-langchain.lmChatAnthropic", 1.3),
            nd("Autofix", "@n8n/n8n-nodes-langchain.outputParserAutofixing", 1),
            nd("Schema", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2),
        ],
        {
            "Start": {"main": [[edge("Chain")]]},
            "Claude": {"ai_languageModel": [[edge("Chain", "ai_languageModel", 0), edge("Autofix", "ai_languageModel", 0)]]},
            "Schema": {"ai_outputParser": [[edge("Autofix", "ai_outputParser", 0)]]},
            "Autofix": {"ai_outputParser": [[edge("Chain", "ai_outputParser", 0)]]},
        },
        valid=True,
    )

    ai_bad_specs = [
        ("AI Agent missing required ai_languageModel connection", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8)], {"Chat": {"main": [[edge("Agent")]]}}, ["missing_ai_language_model:Agent"]),
        ("Basic LLM Chain missing required ai_languageModel connection", [nd("Start", "n8n-nodes-base.manualTrigger", 1), nd("Chain", "@n8n/n8n-nodes-langchain.chainLlm", 1.5)], {"Start": {"main": [[edge("Chain")]]}}, ["missing_ai_language_model:Chain"]),
        ("OpenAI Chat Model wired into ai_tool instead of ai_languageModel", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2)], {"Chat": {"main": [[edge("Agent")]]}, "OpenAI": {"ai_tool": [[edge("Agent", "ai_tool", 0)]]}}, ["ai_port_mismatch:OpenAI->Agent:ai_tool", "missing_ai_language_model:Agent"]),
        ("Calculator Tool wired into ai_languageModel port", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("Calc", "@n8n/n8n-nodes-langchain.toolCalculator", 1)], {"Chat": {"main": [[edge("Agent")]]}, "Calc": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}}, ["ai_port_mismatch:Calc->Agent:ai_languageModel"]),
        ("Simple Memory wired into main port of Set node", [nd("Start", "n8n-nodes-base.manualTrigger", 1), nd("Mem", "@n8n/n8n-nodes-langchain.memoryBufferWindow", 1.3), nd("Set", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Set")]]}, "Mem": {"main": [[edge("Set")]]}}, ["ai_port_mismatch:Mem->Set:main"]),
        ("Structured Output Parser wired into ai_memory port", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Parser", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2)], {"Chat": {"main": [[edge("Agent")]]}, "OpenAI": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}, "Parser": {"ai_memory": [[edge("Agent", "ai_memory", 0)]]}}, ["ai_port_mismatch:Parser->Agent:ai_memory"]),
        ("Embeddings OpenAI wired directly into AI Agent ai_tool", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Embed", "@n8n/n8n-nodes-langchain.embeddingsOpenAi", 1.1)], {"Chat": {"main": [[edge("Agent")]]}, "OpenAI": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}, "Embed": {"ai_tool": [[edge("Agent", "ai_tool", 0)]]}}, ["ai_port_mismatch:Embed->Agent:ai_tool"]),
        ("Basic LLM Chain given ai_tool connection (unsupported on chainLlm)", [nd("Start", "n8n-nodes-base.manualTrigger", 1), nd("Chain", "@n8n/n8n-nodes-langchain.chainLlm", 1.5), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Calc", "@n8n/n8n-nodes-langchain.toolCalculator", 1)], {"Start": {"main": [[edge("Chain")]]}, "OpenAI": {"ai_languageModel": [[edge("Chain", "ai_languageModel", 0)]]}, "Calc": {"ai_tool": [[edge("Chain", "ai_tool", 0)]]}}, ["unsupported_target_port:Chain:ai_tool"]),
        ("Reversed AI edge direction (Agent -> OpenAI Chat Model)", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2)], {"Chat": {"main": [[edge("Agent")]]}, "Agent": {"ai_languageModel": [[edge("OpenAI", "ai_languageModel", 0)]]}}, ["ai_port_direction_reversed:Agent->OpenAI"]),
        ("Multiple Simple Memory nodes wired into single AI Agent", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Mem1", "@n8n/n8n-nodes-langchain.memoryBufferWindow", 1.3), nd("Mem2", "@n8n/n8n-nodes-langchain.memoryBufferWindow", 1.3)], {"Chat": {"main": [[edge("Agent")]]}, "OpenAI": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}, "Mem1": {"ai_memory": [[edge("Agent", "ai_memory", 0)]]}, "Mem2": {"ai_memory": [[edge("Agent", "ai_memory", 0)]]}}, ["multiple_ai_memory_inputs:Agent"]),
        ("Auto-fixing Output Parser missing wrapped child ai_outputParser", [nd("Start", "n8n-nodes-base.manualTrigger", 1), nd("Chain", "@n8n/n8n-nodes-langchain.chainLlm", 1.5), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Autofix", "@n8n/n8n-nodes-langchain.outputParserAutofixing", 1)], {"Start": {"main": [[edge("Chain")]]}, "OpenAI": {"ai_languageModel": [[edge("Chain", "ai_languageModel", 0), edge("Autofix", "ai_languageModel", 0)]]}, "Autofix": {"ai_outputParser": [[edge("Chain", "ai_outputParser", 0)]]}}, ["missing_ai_output_parser:Autofix"]),
        ("Default Data Loader wired into ai_languageModel port", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("Loader", "@n8n/n8n-nodes-langchain.documentDefaultDataLoader", 1)], {"Chat": {"main": [[edge("Agent")]]}, "Loader": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}}, ["ai_port_mismatch:Loader->Agent:ai_languageModel"]),
        ("Orphan OpenAI Chat Model sub-node connected to nothing", [nd("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1), nd("Agent", "@n8n/n8n-nodes-langchain.agent", 1.8), nd("OpenAI", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2), nd("Unused Gemini", "@n8n/n8n-nodes-langchain.lmChatGoogleGemini", 1)], {"Chat": {"main": [[edge("Agent")]]}, "OpenAI": {"ai_languageModel": [[edge("Agent", "ai_languageModel", 0)]]}}, ["orphan_ai_subnode:Unused Gemini"]),
        ("Vector Store insert mode missing ai_embedding provider", [nd("Start", "n8n-nodes-base.manualTrigger", 1), nd("Qdrant", "@n8n/n8n-nodes-langchain.vectorStoreQdrant", 1.1)], {"Start": {"main": [[edge("Qdrant")]]}}, ["missing_ai_embedding:Qdrant"]),
    ]
    for desc, a_nodes, a_conns, errs in ai_bad_specs:
        add("ai_subnode_ports", desc, a_nodes, a_conns, valid=False, errors=errs)

    # 4e. Disconnected triggers & orphan island warnings (10 cases)
    warn_specs = [
        ("Workflow with no trigger node emits missing_trigger_node warning", [nd("Set 1", "n8n-nodes-base.set", 3.4), nd("Set 2", "n8n-nodes-base.set", 3.4)], {"Set 1": {"main": [[edge("Set 2")]]}}, ["missing_trigger_node"]),
        ("Trigger with zero outgoing connections emits disconnected_trigger warning", [nd("Webhook", "n8n-nodes-base.webhook", 2)], {}, ["disconnected_trigger:Webhook"]),
        ("Unreachable orphan Set node alongside valid pipeline", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Active Set", "n8n-nodes-base.set", 3.4), nd("Orphan Set", "n8n-nodes-base.set", 3.4)], {"Start": {"main": [[edge("Active Set")]]}}, ["unreachable_node:Orphan Set"]),
        ("Orphan 2-node island unreachable from any trigger", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Main", "n8n-nodes-base.set", 3.4), nd("Island A", "n8n-nodes-base.httpRequest", 4.2), nd("Island B", "n8n-nodes-base.slack", 2.3)], {"Start": {"main": [[edge("Main")]]}, "Island A": {"main": [[edge("Island B")]]}}, ["unreachable_node:Island A", "unreachable_node:Island B"]),
        ("Webhook responseNode mode without Respond to Webhook downstream", [nd("Webhook", "n8n-nodes-base.webhook", 2), nd("Set", "n8n-nodes-base.set", 3.4)], {"Webhook": {"main": [[edge("Set")]]}}, ["webhook_response_node_maybe_missing"]),
        ("Respond to Webhook without upstream Webhook trigger", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Reply", "n8n-nodes-base.respondToWebhook", 1.1)], {"Start": {"main": [[edge("Reply")]]}}, ["respond_to_webhook_without_webhook_trigger"]),
        ("Two disconnected triggers in same workflow", [nd("Schedule", "n8n-nodes-base.scheduleTrigger", 1.2), nd("Step A", "n8n-nodes-base.set", 3.4), nd("Unused Manual", "n8n-nodes-base.manualTrigger", 1)], {"Schedule": {"main": [[edge("Step A")]]}}, ["disconnected_trigger:Unused Manual"]),
        ("Merge node with only input 0 connected emits single_input_merge warning", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Merge", "n8n-nodes-base.merge", 3.1)], {"Start": {"main": [[edge("Merge", "main", 0)]]}}, ["merge_missing_second_input:Merge"]),
        ("IF node with both true and false branches empty", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("IF", "n8n-nodes-base.if", 2.2)], {"Start": {"main": [[edge("IF")]]}, "IF": {"main": [[], []]}}, ["dead_end_branch_node:IF"]),
        ("Loop Over Items with empty loop body branch", [nd("Start", "n8n-nodes-base.manualTrigger"), nd("Loop", "n8n-nodes-base.splitInBatches", 3), nd("Done", "n8n-nodes-base.noOp", 1)], {"Start": {"main": [[edge("Loop")]]}, "Loop": {"main": [[edge("Done")], []]}}, ["empty_loop_body:Loop"]),
    ]
    for desc, w_nodes, w_conns, warns in warn_specs:
        add("topology_warnings", desc, w_nodes, w_conns, valid=True, warnings=warns)

    return cases


# ---------------------------------------------------------------------------
# Category 5: `workflow_diff` (60 cases)
# ---------------------------------------------------------------------------

def build_workflow_diff_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    idx = 0

    base_workflow = {
        "name": "Order Processing Pipeline",
        "nodes": [
            {"id": "n1", "name": "Inbound Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "position": [200, 300], "parameters": {"httpMethod": "POST", "path": "orders", "responseCode": 200}},
            {"id": "n2", "name": "Fetch Customer", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "position": [450, 300], "parameters": {"method": "GET", "url": "https://api.example.com/customers", "options": {"timeout": 5000}, "headers": {"x/api~key": "header_ref"}, "tags": ["tier1", "sync"]}},
            {"id": "n3", "name": "Format Order", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [700, 300], "parameters": {"mode": "manual", "customerEmail": "={{ $('Fetch Customer').item.json.email }}", "webhookPath": "={{ $node[\"Inbound Webhook\"].json.headers.host }}"}},
        ],
        "connections": {
            "Inbound Webhook": {"main": [[{"node": "Fetch Customer", "type": "main", "index": 0}]]},
            "Fetch Customer": {"main": [[{"node": "Format Order", "type": "main", "index": 0}]]},
        },
    }

    def add(
        sub: str,
        desc: str,
        op: dict[str, Any],
        expected: dict[str, Any],
        workflow_override: dict[str, Any] | None = None,
        compat: str = "exact_parity",
    ) -> None:
        nonlocal idx
        idx += 1
        cases.append({
            "id": f"diff-{idx:04d}",
            "category": "workflow_diff",
            "subcategory": sub,
            "compatibilityClass": compat,
            "description": desc,
            "input": {
                "workflow": workflow_override or base_workflow,
                "mutation": op,
            },
            "expected": expected,
        })

    # 5a. JSON Pointer set/unset operations (18 cases)
    ptr_specs = [
        ("Set scalar URL via JSON Pointer", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/url", "value": "https://api.example.com/v2/customers"}, {"status": "applied", "changed": True, "resolvedValue": "https://api.example.com/v2/customers"}),
        ("Set nested number /parameters/options/timeout", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/options/timeout", "value": 15000}, {"status": "applied", "changed": True, "resolvedValue": 15000}),
        ("Set RFC6901 escaped pointer ~1 and ~0 (/parameters/headers/x~1api~0key)", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/headers/x~1api~0key", "value": "rotated_ref"}, {"status": "applied", "changed": True, "resolvedValue": "rotated_ref"}),
        ("Idempotent set_param to identical value marks changed=false", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/method", "value": "GET"}, {"status": "applied", "changed": False, "resolvedValue": "GET"}),
        ("Set single array element by index /parameters/tags/1", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags/1", "value": "priority"}, {"status": "applied", "changed": True, "resolvedValue": "priority"}),
        ("Append array element via '-' token /parameters/tags/-", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags/-", "value": "audited"}, {"status": "applied", "changed": True, "resolvedValue": "audited"}),
        ("Create new nested object key /parameters/options/retryOnFail", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/options/retryOnFail", "value": True}, {"status": "applied", "changed": True, "resolvedValue": True}),
        ("Set node-level retryOnFail flag /retryOnFail", {"op": "set_param", "node": "Fetch Customer", "pointer": "/retryOnFail", "value": True}, {"status": "applied", "changed": True, "resolvedValue": True}),
        ("Set node-level maxTries /maxTries", {"op": "set_param", "node": "Fetch Customer", "pointer": "/maxTries", "value": 3}, {"status": "applied", "changed": True, "resolvedValue": 3}),
        ("Set node-level notes rationale /notes", {"op": "set_param", "node": "Format Order", "pointer": "/notes", "value": "Normalizes customer email"}, {"status": "applied", "changed": True, "resolvedValue": "Normalizes customer email"}),
        ("Unset existing optional parameter /parameters/responseCode", {"op": "unset_param", "node": "Inbound Webhook", "pointer": "/parameters/responseCode"}, {"status": "applied", "changed": True, "removed": True}),
        ("Unset nonexistent optional key is idempotent no-op", {"op": "unset_param", "node": "Inbound Webhook", "pointer": "/parameters/nonExistentKey"}, {"status": "applied", "changed": False, "removed": False}),
        ("Reject JSON Pointer missing leading slash", {"op": "set_param", "node": "Fetch Customer", "pointer": "parameters/url", "value": "https://x"}, {"status": "rejected", "changed": False, "errorCode": "invalid_json_pointer"}),
        ("Reject mutation targeting protected /id field", {"op": "set_param", "node": "Fetch Customer", "pointer": "/id", "value": "hijack"}, {"status": "rejected", "changed": False, "errorCode": "protected_node_field:/id"}),
        ("Reject mutation targeting protected /type field", {"op": "set_param", "node": "Fetch Customer", "pointer": "/type", "value": "n8n-nodes-base.executeCommand"}, {"status": "rejected", "changed": False, "errorCode": "protected_node_field:/type"}),
        ("Reject set_param on nonexistent node", {"op": "set_param", "node": "Missing Node", "pointer": "/parameters/url", "value": "https://x"}, {"status": "rejected", "changed": False, "errorCode": "node_not_found:Missing Node"}),
        ("Reject out-of-bounds array index /parameters/tags/99", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags/99", "value": "x"}, {"status": "rejected", "changed": False, "errorCode": "array_index_out_of_bounds:99"}),
        ("Unset nested timeout key /parameters/options/timeout", {"op": "unset_param", "node": "Fetch Customer", "pointer": "/parameters/options/timeout"}, {"status": "applied", "changed": True, "removed": True}),
    ]
    for desc, op, exp in ptr_specs:
        add("json_pointer_set_unset", desc, op, exp, compat="intentional_hardening" if "protected_node_field" in str(exp) else "exact_parity")

    # 5b. Whole-array replacement guard (12 cases)
    arr_specs = [
        ("Block whole-array replacement on /parameters/tags when allowWholeArrayReplace=false", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": ["replaced"], "allowWholeArrayReplace": False}, {"status": "rejected", "changed": False, "errorCode": "whole_array_replace_blocked:/parameters/tags"}),
        ("Block whole-array replacement when allowWholeArrayReplace omitted", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": []}, {"status": "rejected", "changed": False, "errorCode": "whole_array_replace_blocked:/parameters/tags"}),
        ("Allow whole-array replacement when allowWholeArrayReplace=true", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": ["v2", "verified"], "allowWholeArrayReplace": True}, {"status": "applied", "changed": True, "resolvedValue": ["v2", "verified"]}),
        ("Block clearing array to null without guard", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": None}, {"status": "rejected", "changed": False, "errorCode": "whole_array_replace_blocked:/parameters/tags"}),
        ("Block replacing array with object type mismatch", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": {"0": "a"}, "allowWholeArrayReplace": True}, {"status": "rejected", "changed": False, "errorCode": "array_type_mismatch:/parameters/tags"}),
        ("Block unset_param on non-empty array without allowWholeArrayReplace", {"op": "unset_param", "node": "Fetch Customer", "pointer": "/parameters/tags"}, {"status": "rejected", "changed": False, "errorCode": "whole_array_replace_blocked:/parameters/tags"}),
        ("Allow unset_param on array when allowWholeArrayReplace=true", {"op": "unset_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "allowWholeArrayReplace": True}, {"status": "applied", "changed": True, "removed": True}),
        ("Setting newly created array property succeeds without guard", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/newList", "value": ["a", "b"]}, {"status": "applied", "changed": True, "resolvedValue": ["a", "b"]}),
        ("Position 2-tuple /position update allowed via move_node op", {"op": "move_node", "node": "Fetch Customer", "position": [520, 340]}, {"status": "applied", "changed": True, "position": [520, 340]}),
        ("Direct /position array overwrite via set_param blocked without guard", {"op": "set_param", "node": "Fetch Customer", "pointer": "/position", "value": [0, 0]}, {"status": "rejected", "changed": False, "errorCode": "protected_node_field:/position"}),
        ("Single element removal /parameters/tags/0 allowed without whole-array flag", {"op": "unset_param", "node": "Fetch Customer", "pointer": "/parameters/tags/0"}, {"status": "applied", "changed": True, "removed": True}),
        ("Idempotent identical array value with allowWholeArrayReplace=true reports changed=false", {"op": "set_param", "node": "Fetch Customer", "pointer": "/parameters/tags", "value": ["tier1", "sync"], "allowWholeArrayReplace": True}, {"status": "applied", "changed": False, "resolvedValue": ["tier1", "sync"]}),
    ]
    for desc, op, exp in arr_specs:
        add("whole_array_guard", desc, op, exp, compat="intentional_hardening")

    # 5c. Node rename with downstream literal reference updates & dynamic guard (15 cases)
    rename_specs = [
        (
            "Rename 'Fetch Customer' -> 'Load Customer' updates nodes, connections, and downstream $() ref",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Load Customer"},
            {"status": "applied", "changed": True, "rewrittenExpressions": [{"node": "Format Order", "pointer": "/parameters/customerEmail", "after": "={{ $('Load Customer').item.json.email }}"}], "connectionKeysRenamed": ["Fetch Customer->Load Customer"]},
            None,
        ),
        (
            "Rename 'Inbound Webhook' -> 'Order Webhook' updates $node[\"...\"] legacy ref",
            {"op": "rename_node", "from": "Inbound Webhook", "to": "Order Webhook"},
            {"status": "applied", "changed": True, "rewrittenExpressions": [{"node": "Format Order", "pointer": "/parameters/webhookPath", "after": "={{ $node[\"Order Webhook\"].json.headers.host }}"}], "connectionKeysRenamed": ["Inbound Webhook->Order Webhook"]},
            None,
        ),
        (
            "Rename to Unicode name 'Client 🚀' escapes cleanly",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Client 🚀"},
            {"status": "applied", "changed": True, "rewrittenExpressions": [{"node": "Format Order", "pointer": "/parameters/customerEmail", "after": "={{ $('Client 🚀').item.json.email }}"}]},
            None,
        ),
        (
            "Rename to name containing single quote escapes apostrophe in $()",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Customer's Profile"},
            {"status": "applied", "changed": True, "rewrittenExpressions": [{"node": "Format Order", "pointer": "/parameters/customerEmail", "after": "={{ $('Customer\\'s Profile').item.json.email }}"}]},
            None,
        ),
        (
            "Rename leaf node 'Format Order' -> 'Shape Response' (zero expression rewrites needed)",
            {"op": "rename_node", "from": "Format Order", "to": "Shape Response"},
            {"status": "applied", "changed": True, "rewrittenExpressions": []},
            None,
        ),
        (
            "Reject rename colliding with existing node name 'Format Order'",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Format Order"},
            {"status": "rejected", "changed": False, "errorCode": "duplicate_node_name:Format Order"},
            None,
        ),
        (
            "Reject rename to empty whitespace string",
            {"op": "rename_node", "from": "Fetch Customer", "to": "   "},
            {"status": "rejected", "changed": False, "errorCode": "empty_node_name"},
            None,
        ),
        (
            "Reject rename of nonexistent node",
            {"op": "rename_node", "from": "Ghost Step", "to": "New Step"},
            {"status": "rejected", "changed": False, "errorCode": "node_not_found:Ghost Step"},
            None,
        ),
        (
            "Idempotent rename to same name reports changed=false",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Fetch Customer"},
            {"status": "applied", "changed": False, "rewrittenExpressions": []},
            None,
        ),
        (
            "Block rename with manual_review_required when downstream has dynamic $('Fetch ' + $json.x)",
            {"op": "rename_node", "from": "Fetch Customer", "to": "Load Customer"},
            {"status": "manual_review_required", "changed": False, "blockingExpressions": [{"node": "Dyn Consumer", "pointer": "/parameters/val"}]},
            {
                "name": "Dynamic Ref Workflow",
                "nodes": [
                    {"id": "1", "name": "Fetch Customer", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "position": [200, 200], "parameters": {"method": "GET", "url": "https://example.com"}},
                    {"id": "2", "name": "Dyn Consumer", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [440, 200], "parameters": {"val": "={{ $('Fetch ' + $json.kind).item.json.id }}"}},
                ],
                "connections": {"Fetch Customer": {"main": [[{"node": "Dyn Consumer", "type": "main", "index": 0}]]}},
            },
        ),
    ]
    for desc, op, exp, wf_ov in rename_specs:
        add("node_rename", desc, op, exp, workflow_override=wf_ov, compat="intentional_hardening" if exp["status"] == "manual_review_required" else "exact_parity")

    for extra_i in range(1, 6):
        add(
            "node_rename",
            f"Multi-consumer rename fanout rewrite #{extra_i} ({extra_i + 1} downstream expressions)",
            {"op": "rename_node", "from": "Source", "to": f"Renamed Source {extra_i}"},
            {"status": "applied", "changed": True, "rewrittenCount": extra_i + 1},
            workflow_override={
                "name": f"Fanout Rename {extra_i}",
                "nodes": [{"id": "s", "name": "Source", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": [0, 0], "parameters": {}}]
                + [{"id": f"c{k}", "name": f"Consumer {k}", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [240 * k, 0], "parameters": {"v": "={{ $('Source').item.json.id }}"}} for k in range(1, extra_i + 2)],
                "connections": {"Source": {"main": [[{"node": f"Consumer {k}", "type": "main", "index": 0} for k in range(1, extra_i + 2)]]}},
            },
        )

    # 5d. Structural graph mutations: insert between A & B, bridge delete, rewire, enable/disable (15 cases)
    struct_specs = [
        ("Insert Filter node between 'Inbound Webhook' and 'Fetch Customer'", {"op": "insert_between", "after": "Inbound Webhook", "before": "Fetch Customer", "branch": 0, "node": {"id": "n_flt", "name": "Filter Valid", "type": "n8n-nodes-base.filter", "typeVersion": 2.2, "position": [325, 300], "parameters": {}}}, {"status": "applied", "changed": True, "addedEdges": ["Inbound Webhook->Filter Valid", "Filter Valid->Fetch Customer"], "removedEdges": ["Inbound Webhook->Fetch Customer"]}),
        ("Insert Dedupe node between 'Fetch Customer' and 'Format Order'", {"op": "insert_between", "after": "Fetch Customer", "before": "Format Order", "branch": 0, "node": {"id": "n_dd", "name": "Dedupe", "type": "n8n-nodes-base.removeDuplicates", "typeVersion": 2, "position": [575, 300], "parameters": {}}}, {"status": "applied", "changed": True, "addedEdges": ["Fetch Customer->Dedupe", "Dedupe->Format Order"], "removedEdges": ["Fetch Customer->Format Order"]}),
        ("Reject insert_between when direct edge A -> B does not exist", {"op": "insert_between", "after": "Inbound Webhook", "before": "Format Order", "branch": 0, "node": {"id": "n_x", "name": "Mid", "type": "n8n-nodes-base.noOp", "typeVersion": 1, "position": [400, 300], "parameters": {}}}, {"status": "rejected", "changed": False, "errorCode": "edge_not_found:Inbound Webhook->Format Order"}),
        ("Reject insert_between when new node name collides", {"op": "insert_between", "after": "Inbound Webhook", "before": "Fetch Customer", "branch": 0, "node": {"id": "n_dup", "name": "Format Order", "type": "n8n-nodes-base.noOp", "typeVersion": 1, "position": [325, 300], "parameters": {}}}, {"status": "rejected", "changed": False, "errorCode": "duplicate_node_name:Format Order"}),
        ("Remove middle node with bridge=true rewires Inbound Webhook -> Format Order (blocked if expression refs remain)", {"op": "remove_node", "node": "Fetch Customer", "bridge": True}, {"status": "rejected", "changed": False, "errorCode": "dangling_expression_reference:Format Order->Fetch Customer"}),
        ("Remove leaf node 'Format Order' cleanly removes incoming edge", {"op": "remove_node", "node": "Format Order", "bridge": False}, {"status": "applied", "changed": True, "removedEdges": ["Fetch Customer->Format Order"]}),
        ("Disable node 'Fetch Customer' sets disabled=true", {"op": "set_enabled", "node": "Fetch Customer", "enabled": False}, {"status": "applied", "changed": True, "disabled": True}),
        ("Re-enable node already enabled is idempotent changed=false", {"op": "set_enabled", "node": "Fetch Customer", "enabled": True}, {"status": "applied", "changed": False, "disabled": False}),
        ("Add AI sub-node wire ai_languageModel OpenAI -> Agent", {"op": "connect_nodes", "from": "OpenAI", "to": "Agent", "port": "ai_languageModel", "branch": 0, "index": 0}, {"status": "rejected", "changed": False, "errorCode": "node_not_found:OpenAI"}),
        ("Connect 'Format Order' -> new 'Respond 200' leaf node", {"op": "add_node_and_connect", "after": "Format Order", "branch": 0, "node": {"id": "n_resp", "name": "Respond 200", "type": "n8n-nodes-base.respondToWebhook", "typeVersion": 1.1, "position": [940, 300], "parameters": {"respondWith": "firstIncomingItem"}}}, {"status": "applied", "changed": True, "addedEdges": ["Format Order->Respond 200"]}),
        ("Disconnect edge 'Fetch Customer' -> 'Format Order'", {"op": "disconnect_nodes", "from": "Fetch Customer", "to": "Format Order", "port": "main", "branch": 0}, {"status": "applied", "changed": True, "removedEdges": ["Fetch Customer->Format Order"]}),
        ("Disconnect nonexistent edge is idempotent changed=false", {"op": "disconnect_nodes", "from": "Inbound Webhook", "to": "Format Order", "port": "main", "branch": 0}, {"status": "applied", "changed": False, "removedEdges": []}),
        ("Bind credential metadata by id/name without secret payload", {"op": "bind_credential", "node": "Fetch Customer", "credentialType": "httpBearerAuth", "credentialId": "cred_bearer_01", "credentialName": "Customer API Bearer"}, {"status": "applied", "changed": True}),
        ("Reject bind_credential containing raw secret data fields", {"op": "bind_credential", "node": "Fetch Customer", "credentialType": "httpBearerAuth", "credentialId": "cred_01", "data": {"token": "placeholder_forbidden"}}, {"status": "rejected", "changed": False, "errorCode": "secret_material_forbidden_in_workflow_mutation"}),
        ("Upgrade node version without registered migration returns migration_missing", {"op": "upgrade_node_version", "node": "Inbound Webhook", "targetVersion": 99}, {"status": "rejected", "changed": False, "errorCode": "migration_missing:n8n-nodes-base.webhook:2->99"}),
    ]
    for desc, op, exp in struct_specs:
        add("structural_graph_diff", desc, op, exp, compat="intentional_hardening" if "errorCode" in exp and ("dangling_expression" in exp["errorCode"] or "secret_material" in exp["errorCode"] or "migration_missing" in exp["errorCode"]) else "exact_parity")

    return cases


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    out_dir = repo_root / "tests" / "equivalence"
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "cases.jsonl"

    all_cases: list[dict[str, Any]] = []
    all_cases.extend(build_display_options_cases())
    all_cases.extend(build_expression_refs_cases())
    all_cases.extend(build_node_validation_cases())
    all_cases.extend(build_graph_topology_cases())
    all_cases.extend(build_workflow_diff_cases())

    seen_ids: set[str] = set()
    lines: list[str] = []
    cat_counts: Counter[str] = Counter()
    compat_counts: Counter[str] = Counter()

    for rec in all_cases:
        cid = rec["id"]
        if cid in seen_ids:
            raise RuntimeError(f"Duplicate equivalence case ID: {cid}")
        seen_ids.add(cid)
        cat_counts[rec["category"]] += 1
        compat_counts[rec["compatibilityClass"]] += 1
        lines.append(canonical_json(rec))

    payload = ("\n".join(lines) + "\n").encode("utf-8")
    jsonl_path.write_bytes(payload)

    # Verify JSONL parseability & >= 300 threshold
    parsed_back = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(parsed_back) != len(all_cases) or len(parsed_back) < 300:
        raise RuntimeError(f"Equivalence JSONL verification failed: count={len(parsed_back)}")

    summary = {
        "status": "ok",
        "output": str(jsonl_path.relative_to(repo_root)),
        "totalCases": len(parsed_back),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "blake3": blake3_hex(payload),
        "byCategory": dict(cat_counts),
        "byCompatibilityClass": dict(compat_counts),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
