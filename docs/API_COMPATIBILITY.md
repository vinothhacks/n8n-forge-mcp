# n8n Version & API Compatibility Matrix

**Target Baseline:** n8n `2.48.7` stable (released `2026-11-20`)  
**Rust MCP SDK Baseline:** `rmcp` `3.11.0` (MCP protocol `2026-07-28` with backward negotiation over `stdio` and Streamable HTTP)  
**Legacy Compatibility Floor:** n8n `2.3.6` (degraded read/draft-only Public API fallback; advanced routes explicitly `unsupported`)

`n8n-rs-mcp` (`n8n-forge-mcp`) treats runtime capability negotiation as **authoritative and fail-closed**. Documentation version numbers inform expectations and test fixtures, while actual routing decisions are derived per instance from `GET /api/v1/discover?include=schemas`, `GET /api/v1/openapi.yml`, and—when separately configured—the instance-level Native MCP `tools/list` response at `<origin>/mcp-server/http`.

---

## 1. Version Feature Matrix (n8n `2.3.6` -> `2.48.7`)

| Feature / Capability | Introduced / Changed | Authoritative Signal | `n8n-rs-mcp` Implementation Behavior |
| --- | --- | --- | --- |
| **Baseline full feature matrix** | **2.48.7** | `/api/v1/discover?include=schemas` + `/mcp-server/http` | Full 15+ Public API resource groups, 69 granular scopes, Native MCP builder/test/version tools, rate-limit header pacing, and `POST` idempotency. |
| **Public API dual-bucket rate limits** | **2.47.0** | `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` | Off by default in n8n, configurable by admin across global key-level read/write and per-endpoint read/write windows. `n8n-api-client` paces from server headers when present and applies a conservative local `governor` token bucket otherwise. |
| **Native MCP protected instance mode** | **2.47.0** | Native MCP tool error / capability state | n8n 2.47+ protected mode blocks mutating Native MCP builder tools while still permitting `execute_workflow` on published production workflows. **`n8n-rs-mcp`'s `read-only` policy is stricter and unconditionally blocks all `execute_workflow` calls.** |
| **Public API idempotent `POST`** | **2.45.0** | Endpoint schema / discover metadata | Sends `Idempotency-Key` **only** on `POST` endpoints that advertise idempotency support. Persists `(idempotency_key, canonical_body_blake3, timestamp)` for safe retry within n8n's **12-hour** response retention window. Ignored on `GET`/`PUT`/`PATCH`/`DELETE`. |
| **Canvas `nodeGroups` skip reporting** | **2.41.0** *(groups: 2.28, descriptions: 2.32)* | `update_workflow` `skippedOperations` & `removedGroups` | Native partial `update_workflow` is batch-atomic per workflow **except** for skipped node-group operations in 2.41+. `n8n-mcp-bridge` inspects `skippedOperations` and `removedGroups`, verifies saved groups on read-back, and emits `status: "partial"` rather than false `success` if any group op was skipped. |
| **Explicit trigger selection (`triggerNodeName`)** | **2.36.0** | `execute_workflow` / `test_workflow` input schema | Passes `triggerNodeName` when targeting multi-trigger workflows on `>= 2.36.0`. On older instances (`< 2.36.0`), if a workflow contains more than one enabled trigger node, execution fails closed with `AMBIGUOUS_TRIGGER` instead of guessing. |
| **Pin-data preparation rename (`prepare_workflow_pin_data`)** | **2.34.0** | Native MCP `tools/list` | Renamed from `prepare_test_pin_data` in 2.34.0. `n8n-mcp-bridge` negotiates the exact tool name advertised in `tools/list` at session initialization. |
| **Persisted Agents module** | **2.34.0** | `discover.resources` **OR** Native MCP `AGENT_TOOL_NAMES` | Requires both n8n `>= 2.34.0` and the Agents module enabled. See **Section 3 (`agent:*` Scopes Rule)** below—scopes alone never mark Agents supported. |
| **Modern `/publish` & `/unpublish` REST routes** | **2.33.0** | `discover` operationIds / `Deprecation` header on `/activate` | Prefers `POST /api/v1/workflows/{id}/publish` and `/unpublish` when advertised (`>= 2.33.0`), falling back to `/activate` and `/deactivate` on older servers while honoring `Deprecation` headers. Always verifies `activeVersionId` vs draft `versionId` after write. |
| **Evaluations & workflow folder placement** | **2.30.0 / 2.32.0** *(folders CRUD: 2.19)* | `/workflows/{id}/test-runs`, `/projects/{id}/folders` | `list_runs` / `get_run` / `list_cases` from 2.30+; `run` / `cancel` and `parentFolderId` / `moveToFolder` from 2.32+. Unadvertised routes return `status: "unsupported"`. |
| **Workflow version restore (`restore_workflow_version`)** | **2.29.0** | Native MCP `tools/list` + `/workflows/{id}/versions/{versionId}` | Uses Native MCP `restore_workflow_version` when advertised; otherwise falls back to restoring an authorized local `ChaCha20-Poly1305` snapshot **strictly as an inactive draft** with explicit user approval. |
| **Server-side node config validation (`validate_node_config`)** | **2.25.1** | Native MCP `tools/list` | Uses Native MCP `validate_node_config` when available (`validationStrength: "server_native"`), falling back to offline `catalog.sqlite.zst` + `displayOptions` validation (`validationStrength: "offline_schema"`). |
| **Partial `update_workflow` batch operations** | **2.20.0** | Native MCP `tools/list` | Preferred route for `n8n_mutate_nodes`. JSON Pointer `setNodeParameter` does **not** address individual array elements—array edits use whole-array replacement with preview or guarded Public API write. Inspects `autoAssignedCredentials` without auto-binding `httpRequest` credentials. |
| **Instance-level Native MCP endpoint** | **2.18.4** | `<origin>/mcp-server/http` `initialize` + `tools/list` | Requires explicit enablement in **Settings -> Instance-level MCP** and a dedicated `N8N_MCP_ACCESS_TOKEN` (100 req/window/token server limit). Never substitutes `X-N8N-API-KEY`. |
| **Pin-data workflow testing (`test_workflow`)** | **2.15.0** | Native MCP `tools/list` | Bypasses credentialed/HTTP nodes via pinned fixtures, **but executes credential-free nodes normally**. `n8n-test-harness` runs a deterministic side-effect classifier before allowing `T1 (simulate)` to block `executeCommand`, host file writes, and unpinned network/subworkflow calls. |
| **Universal Public API key scopes** | **2.14.0** | `discover.scopes` | Available across plans from 2.14.0; pre-2.14 non-Enterprise keys lack granular scope filtering. `n8n-capability` enforces least privilege and checks per-resource access rather than inferring project visibility from scope strings or role labels. |
| **Native MCP workflow builder (`validate_workflow`, `create_workflow_from_code`, `update_workflow`)** | **2.12.0 / 2.13.0** | Native MCP `tools/list` | Always runs `validate_workflow` prior to `create_workflow_from_code`. Negotiated dynamically from `tools/list` rather than hard-coded semver comparisons. |
| **Legacy Public API floor** | **2.3.6** | Read-only fallback probe (`GET /api/v1/workflows?limit=1`) | Treated strictly as a legacy compatibility target when `/api/v1/discover` returns `404`. Enables authorized Public API workflow/execution reads and guarded full-graph draft writes while marking `/discover`-only, Native MCP, Evaluations, Data Tables, Folders, and Agents `unsupported`. |

---

## 2. Authoritative Capability Handshake (ADR-001)

### Context
n8n deployments span self-hosted Community, self-hosted Enterprise, and n8n Cloud across versions `2.3.6` through `2.48.7+`. A single instance exposes up to two supported programmatic control planes:
1. **Public REST API** (`<origin>/api/v1`), authenticated with `X-N8N-API-KEY`.
2. **Instance-Level Native MCP** (`<origin>/mcp-server/http`), authenticated with `Authorization: Bearer <N8N_MCP_ACCESS_TOKEN>`.

### Decision
`n8n-capability` executes a deterministic, fail-closed 7-step handshake per configured instance alias:

1. **Endpoint & TLS Validation:** Normalize the configured instance URL, strip embedded credentials/fragments, enforce HTTPS (permitting `http://127.0.0.1` / `http://localhost` **only** when `profile = "full-dev"` and `allow_insecure_loopback = true`), and pin DNS-resolved IPs against the SSRF policy.
2. **Discovery Probe:** Request `GET /api/v1/discover?include=schemas` (and `GET /api/v1/openapi.yml` when schema cross-checking is requested). Extract advertised `resources`, `operations` (`operationId` + request schema), and `scopes`.
3. **Legacy Read-Only Fallback (on `404`/`405`/`410` from `/discover`):** Issue only non-mutating probes (`GET /healthz` and `GET /api/v1/workflows?limit=1`). **Never probe stateful `POST`/`PUT`/`PATCH`/`DELETE` endpoints to test capability.**
4. **Optional Native MCP Handshake:** When `N8N_MCP_ACCESS_TOKEN` is configured, connect `rmcp` Streamable HTTP client to `<origin>/mcp-server/http`, complete `initialize`, and record the exact `tools/list` names and JSON Schemas. Missing Native MCP credentials degrade gracefully to `PublicApi` or `Local` routes without error.
5. **Route Derivation:** Map each of the 24 logical MCP tools and sub-actions to `RouteUsed ∈ { NativeMcp, PublicApi, Local, Unsupported }`:
   - Prefer `NativeMcp` when authenticated and it provides safer surgical semantics (e.g., partial `update_workflow`, `validate_node_config`, `prepare_workflow_pin_data` + `test_workflow`, `restore_workflow_version`).
   - Otherwise select `PublicApi` when the exact resource and `operationId` are advertised (or verified in the legacy `2.3.6` core workflow/execution set).
   - Otherwise select `Local` only for purely offline catalog, AST, or static audit operations (`n8n_catalog_nodes`, `n8n_catalog_templates`, offline `n8n_validate`, static `n8n_audit`).
   - Otherwise mark `Unsupported` with explicit unmet prerequisites.
6. **Zero Private-API Fallback:** **Never** fall back to undocumented `/rest/*` editor endpoints, browser session cookies, internal database connections, or privilege-escalation workarounds. Never downgrade an HTTP `403 Forbidden` on one transport to an alternate transport to bypass access controls.
7. **Short-TTL Caching & Pre-Mutation Revalidation:** Capability snapshots are cached with a 10-minute positive TTL (30-second failure TTL) partitioned by `(principal_id, instance_alias)` and revalidated before consequential writes.

---

## 3. Verified `agent:*` Scopes Without Endpoints Rule

Live empirical verification against n8n `2.48.x` (`GET /api/v1/discover?include=schemas`) confirmed an essential edge case:

- `discover.scopes` can advertise `agent:*` scope identifiers (such as `agent:read`, `agent:list`, `agent:create`, `agent:update`, `agent:delete`) in the global scope catalog **even when**:
  1. `discover.resources` and `/api/v1/openapi.yml` expose **no** `/agents` REST paths, **and**
  2. Instance-level Native MCP (`/mcp-server/http`) is either disabled or its `tools/list` exposes **none** of the official agent tools (`search_agents`, `get_agent`, `create_agent`, `mutate_agent`, `validate_agent`, `call_agent`, `publish_agent`, `unpublish_agent`, `revert_agent`, `list_agent_versions`, `delete_agent`, `discover_agent_assets`, `verify_agent_mcp_server`, `update_agent_integration`, `get_agent_builder_reference`).

**Mandatory Rule:**
> `n8n-capability` **MUST NEVER** infer feature availability from `discover.scopes` alone. If `agent:*` scopes are present but neither `/agents` Public API operations nor Native MCP agent tools are advertised, `n8n_agents` (and its capability matrix entry) **MUST** return `status: "unsupported"` with diagnostic code `AGENT_ENDPOINTS_NOT_EXPOSED` explaining that persisted Agents require n8n `>= 2.34.0` with the Agents module enabled and Native MCP `/mcp-server/http` access configured.

This rule applies generally to every enterprise or module-gated surface (`/audit`, `/community-packages`, `/promotions/*`, `/source-control/*`, `/data-tables/*`, `/workflows/{id}/test-runs`, `/variables`, `/projects`, `/roles`, `/settings/*`): **an operation is routable if and only if an executable REST resource operation or Native MCP tool is actually advertised.**

---

## 4. Draft vs Published Graph Semantics (`versionId` vs `activeVersionId`)

In n8n `2.x` (especially `2.29+` workflow history and `2.33+` publish/unpublish lifecycle):

- Saving a workflow via `POST /api/v1/workflows`, `PUT /api/v1/workflows/{id}`, or Native MCP `update_workflow` updates `versionId` (the editable **draft** graph).
- Live production webhook/schedule/poll triggers execute `activeVersionId` (the **published** version). Editing a draft does **not** automatically alter live production traffic on instances with decoupled draft/publish semantics.
- Every `ToolEnvelope<T>` emitted by `n8n_workflows`, `n8n_mutate_nodes`, `n8n_versions`, and `n8n_test_workflow` explicitly reports:
  - `versionBefore`: Draft `versionId` observed prior to mutation.
  - `versionAfter`: Draft `versionId` verified via read-back after mutation.
  - `activeVersionId`: Currently published live version ID (or `null` when unpublished/inactive).
- `n8n_workflows.publish` and `n8n_workflows.unpublish` **never** declare `status: "success"` solely on HTTP `200 OK`; they perform read-back verification to confirm `activeVersionId` transitioned to the expected version (or `null` on unpublish), reporting `partial` or `inconclusive` if workflow review gates or delayed trigger registration defer activation.

---

## 5. HTTP & Transport Error Classification Contract

| Upstream Signal | Mapped `OperationStatus` / Code | Retryable? | Required Client & Router Handling |
| --- | --- | --- | --- |
| `401 Unauthorized` | `Error` (`AUTH_INVALID_OR_EXPIRED`) | No | Report invalid/expired `N8N_API_KEY` or `N8N_MCP_ACCESS_TOKEN` without echoing token bytes. Never prompt for an Owner key automatically. |
| `403 Forbidden` | `Blocked` (`PERMISSION_OR_LICENSE_DENIED`) | No | Distinguish insufficient scope, project membership, protected instance, or unlicensed enterprise feature. **Never retry via an alternate route.** |
| `404 Not Found` | `Unsupported` or `Error` (`RESOURCE_ABSENT_OR_CONCEALED`) | No* | Note that n8n returns `404` both for non-existent routes and for workflows/projects concealed from the caller's scope. Do **not** claim `404` proves an older n8n version without `/discover` or version corroboration. (*Only `/publish` -> `/activate` route negotiation retries `404`.) |
| `409 Conflict` | `Conflict` (`UPSTREAM_CONFLICT`) | No | Surface conflict details; require fresh read + new preview plan. |
| `422 Unprocessable Entity` / `400 Bad Request` | `Error` (`VALIDATION_REJECTED`) | No | Map field-level schema/settings/nodeGroup rejection reasons without leaking sensitive parameter payloads. |
| `429 Too Many Requests` | Throttled -> `Error` (`RATE_LIMITED`) if budget exceeded | Yes (safe ops) | Honor `Retry-After` and `X-RateLimit-Reset` across global and endpoint buckets (`2.47+`), or Native MCP 100-req/window limit. Only auto-retry idempotent reads or `2.45+` idempotent `POST`s with identical key + canonical body. |
| Transport timeout / connection reset **after** write | `Partial` / `Error` (`WRITE_RESULT_UNCERTAIN`) | **Reconcile first** | **Never** blindly re-issue a mutating `POST`/`PUT`/`DELETE` with a new request. Execute read-after-write reconciliation (`GET` workflow/list or replay exact `Idempotency-Key` within 12h window). |
