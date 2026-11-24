# User Guide: `n8n-rs-mcp` (`n8n-forge-mcp`)

`n8n-rs-mcp` is a Rust-native Model Context Protocol (MCP) server and operator CLI that lets AI coding agents (**Cursor**, **Claude Code**, **Codex**, **OpenCode**, and any MCP `2026-07-28`-compatible client) directly inspect, validate, create, edit, test, debug, and govern real **n8n** workflows—while enforcing server-side policy gates, secret redaction, diff previews, and single-use cryptographic approvals.

---

## 1. Core Concepts Before Connecting

1. **Real n8n Control Plane, Not an Offline Mock:** Connected operations talk to your real n8n instance through its documented **Public REST API** (`/api/v1`) and, when separately enabled, n8n's **Instance-Level Native MCP** (`/mcp-server/http`).
2. **Draft (`versionId`) vs Published (`activeVersionId`):** Creating or editing a workflow updates its **draft** (`versionId`). Live production triggers continue running `activeVersionId` until an authorized `publish` action completes and read-back verification confirms activation.
3. **Fail-Closed Policy Profiles:** Every instance alias is bound to a server-enforced policy (`read-only`, `staging-safe`, `production-guarded`, or `full-dev`). An AI agent cannot elevate its own policy or override target URLs through tool arguments.
4. **Zero Plaintext Secrets in Chat or Config:** Supply `N8N_API_KEY` and (optional) `N8N_MCP_ACCESS_TOKEN` through environment variables or OS credential helpers—never hardcode tokens in `mcp.json` or Git repositories.

---

## 2. Client Setup (`stdio` Default & Optional Localhost HTTPS)

### Prerequisite: Verify Your Environment First

Before launching an AI coding client, run the non-mutating `doctor` check in your terminal to confirm TLS, authentication scopes, state-vault permissions, and offline catalog integrity:

```sh
export N8N_API_URL="https://staging-n8n.example.internal"
export N8N_ENVIRONMENT="staging"
export N8N_API_KEY="${YOUR_INJECTED_STAGING_API_KEY}"

# Optional: separate token from n8n Settings -> Instance-level MCP (never reuse N8N_API_KEY)
export N8N_MCP_BASE_URL="https://staging-n8n.example.internal/mcp-server/http"
export N8N_MCP_ACCESS_TOKEN="${YOUR_INJECTED_STAGING_MCP_TOKEN}"

n8n-rs-mcp sync-catalog --from pinned-bundle
n8n-rs-mcp doctor --instance staging --no-secret-output
```

---

### 2.1 Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

Register `n8n-forge` using `stdio` transport. Reference environment variables from your OS shell or secret launcher rather than committing literal keys:

```json
{
  "mcpServers": {
    "n8n-forge": {
      "command": "n8n-rs-mcp",
      "args": [
        "mcp",
        "--instances-config",
        "/path/to/instances.toml",
        "--instance",
        "staging",
        "--policy",
        "staging-safe"
      ],
      "env": {
        "N8N_STAGING_API_KEY": "${env:N8N_STAGING_API_KEY}",
        "N8N_STAGING_MCP_TOKEN": "${env:N8N_STAGING_MCP_TOKEN}",
        "RUST_LOG": "warn,n8n_rs_mcp=info"
      }
    }
  }
}
```

### 2.2 Claude Code (`.mcp.json` or `claude mcp add`)

Add Separate Staging (`staging-safe`) and Production (`read-only`) server entries in `.mcp.json` (or via `claude mcp add`):

```json
{
  "mcpServers": {
    "n8n-forge-staging": {
      "type": "stdio",
      "command": "n8n-rs-mcp",
      "args": ["mcp", "--instance", "staging", "--policy", "staging-safe"],
      "env": {
        "N8N_API_URL": "https://staging-n8n.example.internal",
        "N8N_ENVIRONMENT": "staging"
      }
    },
    "n8n-forge-prod-ro": {
      "type": "stdio",
      "command": "n8n-rs-mcp",
      "args": ["mcp", "--instance", "prod", "--policy", "read-only"],
      "env": {
        "N8N_API_URL": "https://n8n.example.internal",
        "N8N_ENVIRONMENT": "production"
      }
    }
  }
}
```

CLI registration shortcut:

```sh
claude mcp add --transport stdio n8n-forge-staging \
  -e N8N_API_URL=https://staging-n8n.example.internal \
  -e N8N_ENVIRONMENT=staging \
  -- n8n-rs-mcp mcp --instance staging --policy staging-safe
```

### 2.3 Codex (`~/.codex/config.toml`)

Add an `[mcp_servers.n8n_forge]` block to `~/.codex/config.toml` and forward only the required environment variable names via `env_vars`:

```toml
[mcp_servers.n8n_forge]
command = "n8n-rs-mcp"
args = ["mcp", "--instance", "staging", "--policy", "staging-safe"]
env = { N8N_API_URL = "https://staging-n8n.example.internal", N8N_ENVIRONMENT = "staging" }
env_vars = ["N8N_API_KEY", "N8N_MCP_BASE_URL", "N8N_MCP_ACCESS_TOKEN"]
startup_timeout_sec = 15
tool_timeout_sec = 60
```

### 2.4 OpenCode (`opencode.json`)

Configure a `local` (`stdio`) MCP server entry in your project or user `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "n8n-forge": {
      "type": "local",
      "command": [
        "n8n-rs-mcp",
        "mcp",
        "--instance",
        "staging",
        "--policy",
        "staging-safe"
      ],
      "enabled": true,
      "environment": {
        "N8N_API_URL": "https://staging-n8n.example.internal",
        "N8N_ENVIRONMENT": "staging",
        "N8N_API_KEY": "{env:N8N_API_KEY}",
        "N8N_MCP_BASE_URL": "https://staging-n8n.example.internal/mcp-server/http",
        "N8N_MCP_ACCESS_TOKEN": "{env:N8N_MCP_ACCESS_TOKEN}"
      }
    }
  }
}
```

### 2.5 Optional Authenticated Localhost HTTPS Mode (Streamable HTTP)

`stdio` (one local process per operator) is the recommended default. When a client requires Streamable HTTP:

- The gateway binds strictly to loopback (`https://127.0.0.1:8443/mcp` or `https://[::1]:8443/mcp`) by default; anonymous `0.0.0.0` listeners are prohibited.
- Requires valid TLS termination, per-client bearer/JWT/mTLS authentication, and strict `Origin` and `Host` header validation.
- Each authenticated client identity (`principal_id`) is mapped to its own n8n credential profile, rate-limit budget, FTS5 index partition, audit stream, and snapshot encryption scope—never share a single global Owner API key across untrusted users.

Example Streamable HTTP client config (Claude Code / OpenCode remote transport):

```json
{
  "mcpServers": {
    "n8n-forge-https": {
      "type": "http",
      "url": "https://127.0.0.1:8443/mcp",
      "headers": {
        "Authorization": "Bearer ${env:N8N_FORGE_GATEWAY_CLIENT_TOKEN}"
      }
    }
  }
}
```

---

## 3. CLI Command Reference

All logs are written to `stderr` so `stdio` JSON-RPC framing on `stdout` stays uncorrupted. Global flags `--instances-config <PATH>` and `--policy-config <PATH>` apply to any subcommand.

| Subcommand | Example Invocation | Purpose |
| --- | --- | --- |
| `mcp` | `n8n-rs-mcp mcp --instance staging --policy staging-safe` | Starts the MCP server over `stdio` for the selected instance alias and policy profile (`read-only`, `staging-safe`, `production-guarded`, `full-dev`). |
| `doctor` | `n8n-rs-mcp doctor --instance staging --no-secret-output --format table` | Runs non-mutating checks: URL/SSRF guard, DNS/TLS, `/api/v1/discover` reachability, API key scopes, optional Native MCP `tools/list`, OS state-vault ACLs, and catalog integrity. Exits non-zero if unhealthy. Never echoes secrets. |
| `capabilities` | `n8n-rs-mcp capabilities --instance staging --format json` | Executes the live fail-closed capability handshake and prints per-tool states (`available`, `unavailable`, `unknown`, `blocked_by_policy`) and selected routes (`native_mcp`, `public_api`, `local`, `unsupported`). |
| `sync-catalog` | `n8n-rs-mcp sync-catalog --from pinned-bundle` | Verifies the `BLAKE3` cryptographic digest and SQLite `FTS5` integrity of `data/catalog.sqlite.zst` (or a custom bundle path). |
| `reconcile` | `n8n-rs-mcp reconcile --instance staging --dry-run` | Inspects the `BLAKE3` operation journal, `2.45+` idempotency store, and durable test cleanup leases to reconcile post-timeout `WRITE_RESULT_UNCERTAIN` states or abandoned test artifacts (`--dry-run=false` applies authorized cleanup). |

---

## 4. Standard Tool Response Envelope (`ToolEnvelope<T>`)

Every MCP tool returns a redacted, JSON-Schema-typed `ToolEnvelope<T>`:

```json
{
  "status": "success",
  "instance": "staging",
  "operationId": "op_01935a8c9f107b328a1d4e6f00112233",
  "workflowId": "wf_948102",
  "action": "mutate_nodes.apply",
  "permission": "allowed",
  "routeUsed": "native_mcp",
  "versionBefore": "9a1c44b2-0100-4c9e-8b1d-112233445566",
  "versionAfter": "fe72b190-0200-4c9e-8b1d-778899aabbcc",
  "activeVersionId": "9a1c44b2-0100-4c9e-8b1d-112233445566",
  "changed": true,
  "warnings": [
    "Draft version updated; active published version remains 9a1c44b2-0100-4c9e-8b1d-112233445566 until explicitly published."
  ],
  "data": {},
  "diff": {
    "summary": "1 node updated (Postgres Insert: retryOnFail=true, maxTries=3)"
  },
  "verification": {
    "state": "verified",
    "details": ["Read-back versionId and node configuration verified."]
  },
  "nextActions": [
    "Run n8n_test_workflow with mode='simulate' to verify flow behavior."
  ],
  "auditId": "aud_7f3c91d04b2e881a"
}
```

- **`status` values:** `success`, `preview`, `blocked`, `unsupported`, `conflict`, `partial`, `error`.
- **`permission` values:** `allowed`, `needs_approval`, `denied`, `unknown`.
- **`verification.state` values:** `verified`, `inconclusive`, `not_run`. HTTP `200` alone never produces `success` if Native MCP reports `skippedOperations` (`partial`) or if post-write verification times out (`WRITE_RESULT_UNCERTAIN`).
- **Detail control:** List/read tools accept `detail = "minimal" | "standard" | "full"` plus cursor pagination (`cursor`, `limit`).

---

## 5. Complete Reference: All 24 MCP Tools

> **Important:** Seeing a tool in `tools/list` does **not** grant permission to invoke it. `n8n-policy` evaluates profile rules, API scopes, project access, instance protection, and cryptographic `ApprovalReceipt` tokens on every call.

### 5.1 Discovery, Offline Catalog & Validation (`#1` – `#4`)

| # | Tool Name | Risk | Preferred Route | Operations & Key Arguments |
| --- | --- | --- | --- | --- |
| 1 | `n8n_capabilities` | `R0` | Discovery (`/discover` + Native MCP) | `instance?`, `detail?`, `refresh?`. Returns active policy mode, n8n version, scopes, rate-limit headers, Native MCP tools, and per-tool availability. Call first in every session. |
| 2 | `n8n_catalog_nodes` | `R0` | `local` + optional native schema | `action`: `search \| get \| operations`. FTS5 node search with **native-first ranking** (service node -> native Set/IF/Switch/Filter -> HTTP Request -> Code node), conditional `displayOptions` filtering, and credential type requirements. |
| 3 | `n8n_catalog_templates` | `R0` | `local` | `action`: `search \| get`. Searches curated workflow patterns (`webhook`, `rag`, `slack`, `error-handler`, etc.) and returns topology summaries or deployable draft JSON. |
| 4 | `n8n_validate` | `R1` | `local` + `native_mcp` (`validate_node_config` / `validate_workflow`) | Validates node configs, `={{ ... }}` expressions (`oxc_parser` AST), JavaScript `Code` nodes (`Why Code:` rationale check), AI `ai_*` sub-node ports, and loop-aware topology. Reports `validationStrength` (`server_native`, `offline_schema`, or `partial` for unknown community nodes). |

### 5.2 Workflow Inspection, Search & Graph Authoring (`#5` – `#11`)

| # | Tool Name | Risk | Preferred Route | Operations & Key Arguments |
| --- | --- | --- | --- | --- |
| 5 | `n8n_workflows` | `R0`–`R4` | `native_mcp` / `public_api` | `action`: `list \| get` (`R0`), `create \| clone \| update_meta` (`R2` draft), `archive \| unarchive \| publish \| unpublish \| activate \| deactivate \| transfer` (`R3` + `ApprovalReceipt`), `delete` (`R4` + `ApprovalReceipt`). Always reports both draft `versionId` and live `activeVersionId`. |
| 6 | `n8n_find_nodes` | `R0` | `local` sanitized index | Cross-workflow search over `(principal, instance, project, workflow)` partitions using `node_type`, `name_pattern`, `disabled`, `references_node`, `uses_variable`, `credential_type`, `stale_type_version`, `missing_error_handler`, and ephemeral in-memory `param_path` predicates (never persists or echoes secret parameter values). |
| 7 | `n8n_inspect_node_config` | `R0` | `local` graph + catalog | Returns effective visible parameters for `(workflow_id, node_name_or_id)` after evaluating `typeVersion` defaults, `displayOptions.show/hide`, `options`, `fixedCollection`, and sanitized upstream data shapes. |
| 8 | `n8n_mutate_nodes` | `R1` (`preview`) / `R2` (`apply`) | `native_mcp` partial `update_workflow` -> `public_api` fallback | `mode`: `preview \| apply`. Supports all 16 graph ops: `set_params` (JSON Pointer; whole-array replacement guard), `unset_params`, `patch_text_field`, `configure_reliability`, `bind_credential`, `add_node`, `remove_node`, `rename_node` (AST-safe literal rewrite; refuses dynamic `$('prefix' + x)`), `insert_node_between`, `remove_node_bridge`, `connect`, `disconnect`, `rewire`, `auto_layout`, `set_node_groups`, `upgrade_node_version`. |
| 9 | `n8n_bulk_codemod` | `R1` (`preview`) / `R4` (`apply`) | Sequential per-workflow lock + checkpoint | `action`: `preview \| apply \| status \| resume \| restore_plan`. Max **20 workflows** per batch (`10` in `production-guarded`), concurrency `1`, halts immediately on first critical error, records per-target checkpoints, and offers best-effort draft restore. |
| 10 | `n8n_versions` | `R0` / `R2` / `R3` | `native_mcp` + `local` AEAD vault | `action`: `history \| diff \| release_notes` (`R0`), `snapshot` (`R2`), `restore` (`R3` + `ApprovalReceipt`). Restores workflow draft configuration only—never reverses external side effects. |
| 11 | `n8n_deploy_template` | `R2` | `native_mcp` builder / `public_api` | Instantiates a validated catalog template as an **inactive draft** inside the chosen `project_id` / `parent_folder_id` and binds existing authorized credential references by ID/label. |

### 5.3 Safe Testing, Execution Diagnostics & Evaluations (`#12` – `#14`)

| # | Tool Name | Risk | Preferred Route | Operations & Key Arguments |
| --- | --- | --- | --- | --- |
| 12 | `n8n_executions` | `R0` / `R3` / `R4` | `public_api` + `native_mcp` | `action`: `list \| get \| summarize_failure` (`R0`, defaults to redacted `summary`), `retry \| stop \| tags` (`R3` + `ApprovalReceipt`; warns that `retry` may duplicate side effects), `delete` (`R4` + `ApprovalReceipt`). `node_io`/`full` payloads require restricted reveal authorization. |
| 13 | `n8n_test_workflow` | `R1`–`R4` | Tiered `T0`–`T3` harness | `mode`: `validate_only` (`T0`, `R1`), `simulate` (`T1`, `R2` via Native MCP `prepare_workflow_pin_data` + `test_workflow`, **only** when the side-effect classifier verifies zero `executeCommand`, host file-write, unpinned HTTP, or unknown subworkflow nodes), `manual` (`T2`, `R3` + `ApprovalReceipt` on staging), `production` (`T3`, `R4` + `ApprovalReceipt`, off by default). Bounded repair loop capped at 3 attempts (5 max override). |
| 14 | `n8n_evaluations` | `R0` / `R3` | `public_api` (`/workflows/{id}/test-runs`, `>= 2.30`) | `action`: `list_runs \| get_run \| list_cases` (`R0`), `run \| cancel` (`R3` + `ApprovalReceipt`). Returns `unsupported` on instances without Evaluations. |

### 5.4 Resources, Credentials, Data Tables, Organization & Audit (`#15` – `#19`)

| # | Tool Name | Risk | Preferred Route | Operations & Key Arguments |
| --- | --- | --- | --- | --- |
| 15 | `n8n_explore_resources` | `R0` / `R3` | `native_mcp` (`loadOptions` / `listSearch`) | Queries dynamic dropdown options or resource IDs using existing credential references. Requires consent/approval (`R3`) when live external network reads occur. |
| 16 | `n8n_credentials` | `R0` / `R3` / `R4` | `public_api` | `action`: `schema \| list_meta \| dependencies \| test` (`R0`), `transfer` (`R3` + `ApprovalReceipt`), `create \| update \| delete` (`R4` + `ApprovalReceipt` via protected input channel). Never exports, reverse-reads, or echoes credential secret values. |
| 17 | `n8n_datatables` | `R0` / `R3` / `R4` | `public_api` / `native_mcp` | `action`: `list_tables \| get_schema \| query_rows \| dependencies` (`R0`), `insert_rows \| update_rows \| upsert_rows` (`R3` + `ApprovalReceipt`), `create_table \| delete_rows \| delete_table` (`R4` + `ApprovalReceipt`). |
| 18 | `n8n_catalog_org` | `R0` / `R2`–`R4` | `public_api` | Manages authorized `projects`, `folders` (`>= 2.19`/`2.32`), `tags`, and `variables` (`list/get` `R0`; mutations policy- and scope-gated; variable values redacted where sensitive). |
| 19 | `n8n_audit` | `R0` | `local` static scanner + optional `/api/v1/audit` | Produces a structured hardening report strictly separating **`observed_facts`** (unauthenticated webhooks, missing `retryOnFail`, `$env` usage), **`heuristics`** (masked secret candidates, SSRF patterns), and **`permission_gaps`**. Performs zero active exploitation. |

### 5.5 Community Packages, Git/Promotion, Enterprise Admin & Persisted Agents (`#20` – `#24`)

| # | Tool Name | Risk | Preferred Route | Operations & Key Arguments |
| --- | --- | --- | --- | --- |
| 20 | `n8n_community_packages` | `R0` / `R4` | `public_api` (`/community-packages`) | `action`: `list \| inspect` (`R0`), `install \| update \| uninstall` (`R4` + `ApprovalReceipt` + exact package/semver allowlist in `policy.*.toml`). Rejects unsigned or unallowlisted packages. |
| 21 | `n8n_git_and_packages` | `R0` / `R4` | `public_api` (`/source-control/*`, `/promotions/*`, `/n8n-packages/*`) | `action`: `status` (`R0`), `pull \| push \| promote \| export_package \| import_package` (`R4` + `ApprovalReceipt` when advertised by license/instance). |
| 22 | `n8n_admin_access` | `R0` / `R4` | `public_api` (`/users`, `/projects`, `/roles`) | Admin-only inspection and `R4`-gated management of users, project memberships, and RBAC/SSO configurations advertised by the instance. |
| 23 | `n8n_admin_settings` | `R0` / `R4` | `public_api` (`/settings/*`, `nodetypepolicy`, `credentialtypepolicy`, `logstreaming`) | Inspects or updates (`R4` + `ApprovalReceipt`) rate-limit policies, node/credential type allowlists, and log-streaming observability settings. |
| 24 | `n8n_agents` | `R0`–`R4` | Capability-gated (`native_mcp` / `/agents`) | Manages n8n persisted Agents (`>= 2.34.0`) **only** when executable `/agents` REST endpoints or Native MCP agent tools are advertised. If `discover.scopes` lists `agent:*` without endpoints, returns honest `unsupported` (`AGENT_ENDPOINTS_NOT_EXPOSED`). |

---

## 6. MCP Resource Templates (`n8n://`)

Clients supporting MCP resources can read bounded, redacted snapshots directly via four URI templates:

| Resource URI Template | Access | Returned Payload |
| --- | --- | --- |
| `n8n://{instance}/workflows/{id}` | `R0` Read-only | Sanitized workflow graph IR (`versionId`, `activeVersionId`, nodes, connections, `nodeGroups`, untrusted-tagged notes, and masked sensitive parameters). |
| `n8n://{instance}/workflows/{id}/diff/{planId}` | `R0` Read-only | Bounded semantic and JSON Pointer diff, risk flags, `expected_version_hash`, and approval instructions for a staged preview `planId`. |
| `n8n://{instance}/executions/{id}/summary` | `R0` Read-only | Minimized failure/execution summary (status, duration, failing node, sanitized error class, truncated redacted message, upstream item schema). |
| `n8n://catalog/node/{type}/{version}` | `R0` Read-only | Offline catalog schema for `(type, version)` (e.g., `n8n://catalog/node/n8n-nodes-base.httpRequest/4.2`), including operations, properties, `displayOptions`, and credential types. |

---

## 7. MCP Prompt Templates

`n8n-rs-mcp` exposes five structured workflow prompts. **Prompts are guidance templates only—never authorization bypasses.** Every tool call triggered while following a prompt still passes through `n8n-policy` and requires human `ApprovalReceipt` confirmation for `R3`/`R4` actions.

| Prompt Name | Arguments | Guided Agent Workflow |
| --- | --- | --- |
| `/build-workflow` | `instance`, `goal`, `project_id?` | Runs `n8n_capabilities` -> `n8n_catalog_nodes` (native-first node selection) -> `n8n_validate` -> `n8n_workflows(action="create")` inactive draft -> `n8n_test_workflow(mode="simulate")`. |
| `/debug-workflow` | `instance`, `workflow_id`, `execution_id?` | Fetches `n8n_executions(action="summarize_failure")` -> `n8n_inspect_node_config` -> `n8n_validate` -> `n8n_mutate_nodes(mode="preview")` minimal fix -> bounded simulated re-test. |
| `/refactor-nodes` | `instance`, `workflow_id`, `goal` | Audits expressions and stale `typeVersion`s via `n8n_find_nodes` -> generates AST-safe rename/reliability/wiring preview via `n8n_mutate_nodes(mode="preview")`, flagging dynamic expressions for manual review. |
| `/security-hardening` | `instance`, `workflow_id?` | Runs `n8n_audit` -> reviews `observed_facts`, `heuristics`, and `permission_gaps` -> proposes webhook auth, `retryOnFail`, timeout, and credential-binding remediations as draft previews. |
| `/promote-staging-to-prod` | `staging_instance`, `prod_instance`, `workflow_id` | Verifies staging validation and `T1`/`T2` test evidence -> compares staging draft against `prod_instance` -> prepares a gated promotion/publish plan requiring explicit human `R3`/`R4` approval. |

---

## 8. End-to-End Safe Authoring & Publication Walkthrough

1. **Discover capabilities:** Ask the agent to check `n8n_capabilities` on `staging` to confirm write scopes and whether Native MCP (`update_workflow`, `test_workflow`) is active.
2. **Choose native nodes & validate offline:** The agent queries `n8n_catalog_nodes` and validates the proposed workflow JSON with `n8n_validate` (`Why Code:` required if any `Code` node is used).
3. **Create an inactive staging draft:** `n8n_workflows` (`action="create"`) persists the draft and returns the real `workflowId`, `versionAfter`, and n8n editor URL.
4. **Simulate safely (`T1`):** `n8n_test_workflow` (`mode="simulate"`) verifies the side-effect classifier passes, runs pinned test data, and summarizes any mapping error without raw secret exposure.
5. **Preview -> Approve -> Apply surgical edits:** `n8n_mutate_nodes` (`mode="preview"`) returns `plan_id` and a semantic diff. Applying checks `expected_version_hash`, writes an encrypted `ChaCha20-Poly1305` pre-write snapshot, applies the patch, and verifies the saved graph on read-back.
6. **Guarded publish (`R3`):** Only after you review the diff and supply confirmation does `n8n_workflows` (`action="publish"`) issue a single-use `ApprovalReceipt`, publish the workflow, and verify that `activeVersionId` matches the reviewed draft version.

---

## 9. Product Limits & Truthful Operational Constraints (V2 Section 16)

Operators and AI agents must rely on these exact operational boundaries:

1. **"Creates/edits in real n8n"** means the workflow is persisted through an authorized n8n interface (`/api/v1` or `/mcp-server/http`) and verified by reading it back. Before connection and authorization, the server cannot change anything in your n8n instance.
2. **"Tests"** means either offline/static validation (`T0`), a policy-safe simulated test (`T1`), or an explicitly approved execution (`T2`/`T3`). Every test response reports which mode ran. **Static validation alone is not an end-to-end runtime test.**
3. **"Safe simulated testing"** is conditional: n8n pin data bypasses pinned credentialed/HTTP nodes, **not** credential-free filesystem or `Execute Command` nodes. `n8n-rs-mcp` denies or requires sandboxing for risky side-effecting nodes in `simulate` mode.
4. **"Publish"** is consequential (`R3`/`R4`) and requires exact target and version authorization. Saving a workflow draft (`versionId`) does **not** automatically change the live version (`activeVersionId`) serving production traffic.
5. **"Rollback" / "Restore"** restores workflow configuration/draft state only. It **cannot** undo sent emails, Slack/Teams notifications, third-party API requests, payments, or database writes performed during past executions.
6. **"Refactoring safe"** covers AST-parseable literal node references (`$('Node Name')`) and tested graph shapes; dynamic/computed JavaScript references (`$('prefix' + name)`) and unknown custom community node schemas are flagged `manual_review_required` rather than silently rewritten.
7. **"No leakage"** cannot be mathematically guaranteed end-to-end. `n8n-rs-mcp` redacts secrets in MCP responses, logs, indexes, and snapshots, **but** cloud LLM providers, TLS inspection proxies, and n8n integrations transmit data according to their own configurations.
8. **"Auto-adaptive"** is a capability-discovery, route-selection, and clear-error mechanism. It never bypasses missing n8n API-key scopes, project roles, instance protection, or Enterprise feature licenses.
