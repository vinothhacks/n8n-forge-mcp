# Authorization, Risk Tiers & Approval Model

**Component:** `n8n-policy`  
**Core Principle:** Server-enforced **AND-gate** authorization with TOCTOU-checked, single-use cryptographic `ApprovalReceipt` tokens for consequential operations.

---

## 1. Server-Enforced AND-Gate Invariant

Every tool invocation in `n8n-rs-mcp` passes through `n8n-policy` **before** any transport or local state mutation executes. Tool visibility in `tools/list`, prompt templates, or MCP `readOnlyHint` annotations **never** grant execution rights.

An operation proceeds if and only if **all** five gates evaluate to `Allow`:

```text
Authorized = ProfilePolicy(profile, risk_level, action)
          && InstanceScopeGate(advertised_scopes, required_scope)
          && ResourceAccessGate(principal_id, instance_alias, project_id, workflow_id)
          && InstanceProtectionGate(n8n_protected_mode, workflow_archived_state)
          && ApprovalGate(risk_level, cryptographic_receipt, current_state_hash)
```

**Any single `Deny` wins.** When n8n returns `403 Forbidden`, `n8n-policy` never falls back to an alternative transport or wider credential.

---

## 2. Operation Risk Classification (`R0` – `R4`)

| Risk Tier | Classification | Representative Operations | Preview Required? | Cryptographic `ApprovalReceipt` Required? |
| --- | --- | --- | --- | --- |
| **`R0`** | **Read-Only Metadata** | `n8n_capabilities`, `n8n_catalog_nodes`, `n8n_catalog_templates`, `n8n_workflows.list/get`, `n8n_find_nodes`, `n8n_inspect_node_config`, `n8n_executions.list/get(summary)`, `n8n_versions.history/diff`, `n8n_audit(static)` | No | No |
| **`R1`** | **Safe Local Prepare** | `n8n_validate` (offline / `validate_node_config`), `n8n_mutate_nodes(mode="preview")`, `n8n_test_workflow(mode="validate_only")`, `n8n_bulk_codemod(mode="preview")` | N/A (is preview) | No (bounded CPU/memory budgets enforced) |
| **`R2`** | **Staging Draft Write & Isolated Simulation** | `n8n_workflows.create` (inactive draft), `n8n_mutate_nodes(mode="apply")` on inactive draft, `n8n_deploy_template` (inactive draft), `n8n_versions.snapshot`, `n8n_test_workflow(mode="simulate")` *(only after side-effect classifier passes)* | **Yes** (`plan_id` + diff) | Required in `production-guarded`; explicit `plan_id` + version hash match in `staging-safe` |
| **`R3`** | **Consequential / Real External Effects** | `n8n_test_workflow(mode="manual")` (staging live credentials), `n8n_workflows.publish/unpublish/activate/deactivate/transfer/archive`, `n8n_versions.restore`, `n8n_executions.retry/stop`, `n8n_datatables` row insert/update/upsert/delete, `n8n_evaluations.run`, `n8n_explore_resources` (external credentialed lookup) | **Yes** (target + side-effect scope) | **Yes — single-use bound `ApprovalReceipt` mandatory** |
| **`R4`** | **Destructive, Bulk, Credential & Admin** | `n8n_test_workflow(mode="production")`, `n8n_workflows.delete`, `n8n_executions.delete`, `n8n_bulk_codemod(mode="apply")` (max 20 workflows), `n8n_credentials.create/update/delete`, `n8n_community_packages.install/update/uninstall`, `n8n_git_and_packages.push/pull/promote/import`, `n8n_admin_access.*`, `n8n_admin_settings.*`, production `publish` | **Yes** (elevated impact & blast-radius summary) | **Yes — elevated single-use `ApprovalReceipt` + explicit policy enablement** |

---

## 3. Built-In Policy Profiles

Operators bind each configured n8n instance alias (`staging`, `prod`, `local-dev`) to an immutable server-side profile in `config/policy.*.toml` or CLI `--policy`. **An AI agent cannot switch profiles, edit allowlists, or elevate risk ceilings via MCP calls.**

| Capability / Gate | `read-only` | `staging-safe` | `production-guarded` | `full-dev` |
| --- | --- | --- | --- | --- |
| Intended target | Default production | Shared staging / QA | Explicitly enabled prod ops | Local disposable Docker n8n |
| `R0` Read & `R1` Preview/Validate | Allowed | Allowed | Allowed | Allowed |
| `R2` Inactive Draft Writes | **Blocked** | Allowed after preview + version check | Allowed **only** with `ApprovalReceipt` | Allowed after preview + version check |
| `T1` (`simulate`) Pin-Data Test | **Blocked** | Allowed if side-effect gate passes | **Blocked** (run in staging instead) | Allowed if side-effect gate passes |
| `R3` Real Effects (`manual` run, `publish`, `restore`, `datatables` write) | **Blocked** | Requires bound `ApprovalReceipt` | Requires bound `ApprovalReceipt` | Requires bound `ApprovalReceipt` (or explicit dev test allowlist) |
| `T3` (`production`) Live Execution | **Blocked** *(even if n8n 2.47+ protected mode permits it)* | **Blocked** | Disabled by default; requires explicit opt-in + `R4` receipt | Allowed on disposable loopback with `R4` receipt |
| `R4` Delete / Bulk / Credentials / Packages / Git / Admin | **Blocked** | **Blocked** unless specific sub-capability enabled + `R4` receipt | **Blocked** by default; granular opt-in + `R4` receipt | Allowed with `R4` receipt + package allowlist |
| Max workflows per `n8n_bulk_codemod` batch | `0` | `20` | `10` (if explicitly enabled) | `20` |
| Plaintext `http://` loopback allowed | No | No | No | Optional (`allow_insecure_loopback = true`) |

---

## 4. Cryptographic Approval & Commit Protocol (ADR-004)

A model setting `"apply": true` or `"confirmed": "yes"` in tool JSON **never** satisfies an `R3`/`R4` (or `production-guarded` `R2`) approval requirement. `n8n-policy` enforces a 7-step stateful commit protocol:

```text
[1. Preview] -> [2. Issue/Bind Receipt] -> [3. Acquire Workflow Lock]
     -> [4. TOCTOU Recheck] -> [5. Snapshot + Journal] -> [6. Commit] -> [7. Read-Back Verify]
```

### Step 1: Deterministic Preview & Plan Generation
1. Resolve `(principal_id, instance_alias, workflow_id)` and verify read/write scopes.
2. Fetch current workflow state (`versionId` draft and `activeVersionId` published).
3. Compute canonical state and mutation digests:
   - `expected_version_hash = BLAKE3(canonical_json(current_draft_workflow))`
   - `ops_hash = BLAKE3(canonical_json(normalized_operations))`
4. Run offline graph/schema/AST validation and side-effect classification.
5. Persist `PLANNED -> PREVIEWED` record with unique `plan_id`, redacted semantic diff, JSON Pointer patch summary, risk tier, and residual-risk warnings. Return `status: "preview"`, `permission: "needs_approval"`.

### Step 2: Cryptographic Single-Use `ApprovalReceipt`
When the human operator approves the exact `plan_id` (via host approval callback, CLI confirmation command, or out-of-band signed token), `n8n-policy` constructs and verifies `ApprovalReceipt`:

```text
mac_input = "n8n-rs-mcp.receipt.v1"
         || principal_id
         || instance_alias
         || workflow_id_or_target_set_hash
         || expected_version_hash
         || ops_hash
         || risk_level
         || issued_at_unix_be64
         || expires_at_unix_be64
         || random_nonce_128

receipt_tag = HMAC-SHA256(per_process_or_os_vault_approval_secret, mac_input)
```

**Receipt Validation Rules:**
- **Constant-time MAC verification** (`subtle::ConstantTimeEq`): Rejects forged, truncated, or model-hallucinated tokens immediately.
- **Strict Parameter Binding:** Changing **any** parameter after preview—target `instance_alias`, `workflow_id`, a single node field in `operations`, or bulk selector—changes `ops_hash` or target binding and invalidates the receipt (`APPROVAL_SCOPE_MISMATCH`). There is **no** `confirm_all` wildcard.
- **Short TTL:** Default expiry is `300 seconds` (`5 minutes`) from issuance.
- **Atomic Single-Use Consumption:** `random_nonce_128` is atomically marked `CONSUMED` in `n8n-state-vault` prior to network I/O. Replay of an already-used receipt is rejected (`APPROVAL_RECEIPT_REPLAYED`).
- **Missing Client Approval UI:** If the connected MCP client cannot surface an interactive user confirmation flow, the server returns `status: "preview"` with exact CLI/out-of-band approval instructions and **never auto-approves**.

### Step 3: Per-Workflow Local Concurrency Lock
Acquire an in-process `tokio::sync::MutexGuard` keyed by `(instance_alias, workflow_id)` (enforcing at most **1 concurrent write per workflow** through this server). Bulk codemods acquire locks sequentially per target workflow and cap batches at `20` workflows.

### Step 4: Just-In-Time TOCTOU Recheck
While holding the `(instance_alias, workflow_id)` lock:
1. Re-verify policy and active capability/permission state.
2. Re-fetch the live workflow from n8n and recompute `live_version_hash` and `live_version_id`.
3. If `live_version_hash != expected_version_hash` or `live_version_id != plan.version_before`, **abort before writing** with `status: "conflict"`, error code `CONCURRENT_EDIT_DETECTED`, and return a fresh diff prompt.

### Step 5: Pre-Write AEAD Snapshot & Hash-Chained Journal
1. Store a redacted, `zstd`-compressed, `ChaCha20-Poly1305`-encrypted snapshot of the pre-write draft (bound via AAD to `(principal_id, instance_alias, project_id, workflow_id, expected_version_hash, timestamp)`).
2. Append `WRITING` entry to the `BLAKE3` hash-chained operation journal (recording `Idempotency-Key` + canonical request digest when targeting a `2.45+` idempotent `POST` endpoint).

### Step 6: Guarded Execution / Write
- Route to the safest supported interface: prefer Native MCP atomic partial `update_workflow` (`>= 2.20.0`), else validated Public API `PUT /api/v1/workflows/{id}` / `POST /api/v1/workflows`.
- Inspect structured response fields (`skippedOperations`, `removedGroups`, `autoAssignedCredentials`, warnings).

### Step 7: Read-Back Verification & Final Receipt
1. Fetch the saved workflow back from n8n.
2. Verify:
   - `versionId` advanced as expected (`versionAfter`).
   - Saved nodes, connections, and `nodeGroups` match the intended post-mutation graph.
   - For `publish` / `unpublish`, verify `activeVersionId` actually matches the target draft version (or `null` on unpublish).
3. Record final journal state:
   - `VERIFIED` -> `status: "success"`
   - `PARTIAL` (e.g., `2.41+` skipped canvas group or deferred review gate) -> `status: "partial"`
   - Network timeout / stream drop after commit -> `UNKNOWN_RESULT` (`WRITE_RESULT_UNCERTAIN`), triggering read-after-write reconciliation before any retry is permitted.
4. Release per-workflow lock.

---

## 5. Honest Concurrency & Rollback Disclosure (ADR-005)

### Best-Effort Public API Concurrency Limit
n8n's documented Public API (`PUT /api/v1/workflows/{id}`) and Native MCP (`update_workflow`) do **not** currently enforce a universal server-side conditional write header (`If-Match` / `expectedVersionId` compare-and-swap) across independent clients.

Consequently:
- `n8n-rs-mcp` **guarantees** serialization across concurrent tool calls passing through the same `n8n-rs-mcp` process (via the per-workflow lock) and catches edits made **before** Step 4 (via the TOCTOU pre-write fetch).
- `n8n-rs-mcp` **cannot guarantee** zero lost updates if a human clicks *Save* in the n8n web editor or an external script sends `PUT` during the millisecond network window between Step 4 (`GET`) and Step 6 (`PUT`).
- `n8n-rs-mcp` **never fabricates** an HTTP `409` status code when n8n did not return one; local drift detections use internal status `Conflict` with code `CONCURRENT_EDIT_DETECTED`, and post-write mismatches emit `WRITE_RESULT_UNCERTAIN` / `POST_WRITE_DRIFT_DETECTED`.
- For high-impact production modifications under `production-guarded`, operators should use an exclusive maintenance window or source-control promotion workflow.

### Rollback & Batch Non-Atomicity Disclosure
- **Single-Workflow Restore:** `n8n_versions.restore` (via Native MCP `restore_workflow_version` on `>= 2.29` or local AEAD snapshot draft write) restores **workflow graph configuration only**. Every restore response includes a mandatory warning stating that external side effects (webhook deliveries, sent emails/Slack/Teams messages, payments, database writes) **are not reversed**.
- **Multi-Workflow Codemods (`n8n_bulk_codemod`):** n8n has no cross-workflow distributed transaction. Batches are capped at `20` workflows, checkpointed per workflow, **halt immediately on the first critical failure**, report exact per-workflow states (`verified`, `failed`, `skipped`, `unknown_result`), and offer an optional, separately approved **best-effort restore plan** for already-modified workflows.
