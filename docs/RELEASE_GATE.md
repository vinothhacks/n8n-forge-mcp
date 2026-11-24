# Production Release Gate Checklist: `n8n-rs-mcp` (`n8n-forge-mcp`)

**Specification Baseline:** V2 Sections 14 & 17 (`n8n 2.48.7` target baseline, `rmcp 3.11.0`, Rust Edition 2024)  
**Policy:** No milestone tag (`v0.1.0-m1`, `v0.2.0-m2`, `v0.3.0-m3`) or production release (`v1.0.0`) may be published unless every applicable objective check in this gate passes automatically in CI and release verification.

---

## 1. Security Gate (Mandatory Zero-Failure)

> **Scope Note:** Passing these deterministic engineering gates verifies the controls below; it does **not** claim mathematically zero future software vulnerabilities or control over external LLM providers and third-party n8n integrations.

- [x] **Zero Unapproved Mutations or Executions:** `100%` of `R2`–`R4` write, publish, delete, bulk, credential, package, and `T1`–`T3` execution tests under `read-only` (and unapproved calls under `staging-safe` / `production-guarded`) return `status: "blocked"` or `status: "preview"` with **zero** upstream mutating requests emitted.
- [x] **Protected-Instance Override Verified:** Under `read-only` policy, `execute_workflow(production)` is blocked locally even when an n8n `2.47+` protected Native MCP instance advertises it as callable.
- [x] **Zero Leaked Secrets Across All Channels:**
  - Zero occurrences of real API keys, JWTs (`eyJ...`), GitHub/GitLab PATs, Bearer tokens, or database DSN passwords in Git history, sample MCP `ToolEnvelope` payloads, `stderr` tracing logs, `state.db` FTS5 tables, or `BLAKE3` journal entries.
  - Recursive redactor unit and property tests verify key-based and value-pattern masking across deeply nested JSON and error stack traces.
- [x] **SSRF, DNS-Pinning & Cross-Origin Credential Isolation:**
  - Requests to loopback (outside `full-dev` `allow_loopback_http`), link-local/cloud metadata (`169.254.169.254`, `fe80::/10`, `fd00:ec2::254`), and unallowlisted RFC1918/CGNAT ranges are rejected before socket connect.
  - HTTP `301`/`302`/`307`/`308` redirects are refused (`redirect::Policy::none()`) with zero `X-N8N-API-KEY`, `Authorization`, or `CF-Access-Client-Secret` header forwarding to secondary origins.
- [x] **60 MB Compressed Zip-Bomb & Oversized Payload Defense:**
  - Streaming response reader aborts compressed (`gzip`/`zstd`/`br`) payloads exceeding the `16 MiB` post-decompression REST cap (and `256 KiB` Native MCP structured payload cap) without OOM allocation (`RESPONSE_TOO_LARGE`).
  - Pathological regex (`> 500` chars), `10 MB` error stack traces, prototype-pollution keys (`__proto__`, `constructor`, `prototype`), and oversized AST inputs (`> 1 MiB`) fail safely within bounded CPU and memory budgets.
- [x] **Cross-Principal & Revoked-Project Index Isolation (`U17`):**
  - FTS5 metadata partitions `(principal_id, instance_id, project_id, workflow_id, version_hash)` enforce zero plaintext `node.parameters` storage by default (`no_persistent_payload`) and purge immediately upon `403`/`404` access loss.
- [x] **Prompt-Injection Framing & Memory Safety:**
  - Remote workflow/node notes, community schemas, and execution errors carry `untrustedContent: true` framing.
  - `[workspace.lints.rust] unsafe_code = "forbid"` is enforced across all **13 workspace crates** with zero `#[allow(unsafe_code)]` overrides, and `docs/THIRD_PARTY_NOTICES.md` + `LICENSE` (`MIT OR Apache-2.0`) pass CI validation.

---

## 2. Correctness & Equivalence Gate

- [x] **356 Deterministic Equivalence Cases (`100%` Pass):**
  - `tests/equivalence/cases.jsonl` (**356 cases**) passes `100%` across all five behavioral suites:
    1. `display_options` (`show`/`hide`, multi-value arrays, `_cnd` operators, version defaults, `fixedCollection`).
    2. `expression_refs` (`={{ ... }}` AST extraction, Unicode node names, safe literal node rename vs `manual_review_required` refusal on dynamic `$('prefix' + x)` expressions).
    3. `node_validation` (required fields, conditional requireds, enum options, credential compatibility, `Why Code:` rationale check, `partial` confidence on unknown community nodes).
    4. `graph_topology` (linear chains, `IF`/`Switch`/`Merge` branch indices, valid `Loop Over Items` back-edges, dangling port detection, AI `ai_*` sub-node port direction/type rules).
    5. `workflow_diff` (JSON Pointer `set_params`/`unset_params`, whole-array replacement guard, `insert_node_between` preserving stable node IDs).
- [x] **Offline Catalog Reproducibility:**
  - `python tools/catalog-builder/build_catalog.py` reproduces the exact `BLAKE3` (`9cb98f7760c20c6abfdcb55cfc80c9ea53f7e78b8b2b69302ffd14b75c61eaea`) and `SHA-256` SQLite digests recorded in `data/catalog.manifest.json`, and `PRAGMA integrity_check` + FTS5 smoke queries pass.
- [x] **Honest Post-Write Verification:**
  - Every mutating tool (`n8n_workflows`, `n8n_mutate_nodes`, `n8n_deploy_template`, `n8n_versions`, `n8n_bulk_codemod`) performs read-back verification (`versionBefore`, `versionAfter`, `activeVersionId`) and never emits `status: "success"` on skipped Native MCP group ops (`partial`) or post-commit timeouts (`WRITE_RESULT_UNCERTAIN`).

### Mandatory E2E User Acceptance Suite (`U01` – `U18`)

| Case | Scenario | Objective Pass Criteria |
| --- | --- | --- |
| **`U01`** | Find all HTTP Request nodes calling a deprecated endpoint | Returns exact authorized node matches; masks URL query/header secrets; respects cursor pagination. |
| **`U02`** | Create `Webhook -> Set -> IF -> Teams` draft in staging | Persists inactive draft; returns real `workflowId`, `versionAfter`, and UI URL; graph validated on read-back. |
| **`U03`** | Add retry policy and timeout to a selected node | Emits redacted preview diff + `plan_id`; applies minimal patch after confirmation; read-back verifies `retryOnFail` & timeout. |
| **`U04`** | Rename a node referenced by downstream expressions | Rewrites AST-proven literal `$('Old Name')` references; flags dynamic `$('prefix' + x)` as `manual_review_required`; zero silent corruption. |
| **`U05`** | Edit an `IF` branch and insert a node between `A` and `B` | Preserves true/false branch index semantics (`0` vs `1`), validates port schemas, and retains stable existing node IDs. |
| **`U06`** | Test with mock pin data and repair a failed field mapping | Runs `T1 (simulate)` with zero disallowed live I/O; surfaces redacted failure evidence; repairs within `<= 3` bounded attempts. |
| **`U07`** | Execute test workflow with live staging credentials (`T2`) | Requires single-use `R3` `ApprovalReceipt`; selects explicit trigger; polls `executionId`; performs **zero** automatic duplicate retries on error. |
| **`U08`** | Publish a reviewed staging/guarded draft | Requires `R3`/`R4` `ApprovalReceipt`; calls `/publish` (or `/activate` fallback); verifies `activeVersionId == versionAfter` on read-back. |
| **`U09`** | Attempt production mutation or publish without confirmation | **Blocked** (`status: "preview"` / `"blocked"`, `permission: "needs_approval"`); zero upstream writes; returns approval instructions. |
| **`U10`** | Bulk codemod targeting 30 workflows | Blocked by `MAX_BATCH_WORKFLOWS = 20` ceiling before any write; requires narrowed selector and `R4` approval. |
| **`U11`** | Restore prior workflow version / snapshot | Restores draft configuration; response includes explicit warning that past external side effects are **not** reversed. |
| **`U12`** | Modify another project's credential with a scoped API key | Denied (`403` -> `status: "blocked"`, `PERMISSION_OR_LICENSE_DENIED`); zero fallback to alternate routes or wider tokens. |
| **`U13`** | Simulate workflow containing `Execute Command` or `Read/Write Files` | Side-effect classifier denies `T1 (simulate)` before calling n8n; never executes host commands or file writes silently. |
| **`U14`** | Apply mutation while another user edits the workflow in n8n UI | Just-in-time TOCTOU pre-write fetch detects `expected_version_hash` mismatch and aborts with `status: "conflict"` (`CONCURRENT_EDIT_DETECTED`). |
| **`U15`** | Retry a timed-out `POST /api/v1/workflows` create | Reconciles before retry; replays identical `Idempotency-Key` and canonical body bytes (`n8n >= 2.45`); creates zero duplicate workflows. |
| **`U16`** | Invoke an unadvertised endpoint on a legacy n8n instance | Returns `status: "unsupported"` with clear prerequisite reason; zero calls to private `/rest/*` editor endpoints. |
| **`U17`** | Search nodes after losing project/workflow permissions | Purges revoked `(principal, instance, project, workflow)` index partition; returns zero stale cached hits. |
| **`U18`** | Transport connection drop after write request is transmitted | Marks journal `UNKNOWN_RESULT` (`WRITE_RESULT_UNCERTAIN`); `reconcile` verifies actual server state before allowing follow-up edits. |

---

## 3. Approval & Cryptographic Receipt Gate

- [x] **Constant-Time `HMAC-SHA256` Verification:** Forged, truncated, or LLM-invented confirmation strings (`"apply": true`, `"confirm": "yes"`) are rejected (`100%` rejection in fuzz and negative tests).
- [x] **Strict Scope & State Binding (`APPROVAL_SCOPE_MISMATCH`):** Mutating `instance_alias`, `workflow_id`, `expected_version_hash`, `risk_level`, bulk target list, or a single byte of normalized `operations` after preview invalidates the receipt.
- [x] **Single-Use Nonce Consumption (`APPROVAL_RECEIPT_REPLAYED`):** Submitting a valid `ApprovalReceipt` a second time—even concurrently across two Tokio tasks—fails atomically before network I/O.
- [x] **Bounded TTL Enforcement:** Receipts older than `receipt_ttl_seconds` (`300s` staging/dev, `180s` prod) are rejected (`APPROVAL_RECEIPT_EXPIRED`).
- [x] **Graceful Non-Interactive Client Fallback:** Clients without an approval prompt receive `status: "preview"` and out-of-band confirmation steps—never silent auto-approval.

---

## 4. Compatibility Matrix Gate

Every row below must have passing contract/wiremock fixtures (and live/Docker evidence where applicable) rather than assuming compatibility from `doctor` login alone:

| Target Version / Fixture | Verified Capabilities & Required Fallback Behavior | Gate Status |
| --- | --- | --- |
| **n8n `2.48.7` (Primary Baseline)** | Full `/api/v1/discover?include=schemas`, 15+ resource groups, Native MCP builder/partial `update_workflow`/`test_workflow`, `/publish`, `2.47+` rate limits, `2.45+` idempotency. | [x] Verified |
| **n8n `2.47.x`** | Dual-bucket `Retry-After` / `X-RateLimit-*` pacing; Native MCP protected-instance mode overridden by stricter local `read-only` execution block. | [x] Verified |
| **n8n `2.45.x`** | `Idempotency-Key` sent exclusively on advertised `POST` endpoints with 12-hour retention window tracking. | [x] Verified |
| **n8n `2.41.x`** | Native partial `update_workflow` `skippedOperations` & `removedGroups` inspected; skipped group ops emit `status: "partial"`. | [x] Verified |
| **n8n `2.36.x` / `2.34.x` / `2.33.x`** | `triggerNodeName` disambiguation (`< 2.36` fails closed on multi-trigger); `prepare_workflow_pin_data` vs `prepare_test_pin_data` negotiation; `/publish` vs `/activate` `Deprecation` handling. | [x] Verified |
| **n8n `2.29.x` / `2.25.1` / `2.20.x` / `2.15.x` / `2.14.x` / `2.12.x`** | `restore_workflow_version` vs encrypted local draft snapshot fallback; `validate_node_config` vs `offline_schema` strength reporting; partial update JSON Pointer whole-array guard; scope enforcement. | [x] Verified |
| **n8n `2.3.6` (Legacy Floor)** | `/api/v1/discover` `404` -> non-mutating `GET /api/v1/workflows?limit=1` fallback; read/draft workflows & executions enabled; Evaluations, Data Tables, Folders, Native MCP marked `unsupported`. | [x] Verified |
| **`agent:*` Scopes Without Endpoints** | `discover.scopes` includes `agent:*` while `/agents` REST and Native MCP agent tools are absent -> `n8n_agents` returns `unsupported` (`AGENT_ENDPOINTS_NOT_EXPOSED`). | [x] Verified |
| **Unsupported / License-Restricted Fixtures** | Simulated `404` and `403` Enterprise endpoints (`/source-control/*`, `/promotions/*`, `/audit`) fail closed without private-API workarounds. | [x] Verified |

---

## 5. Recovery & Chaos Gate

- [x] **Mid-Batch Failure Halt (`n8n_bulk_codemod`):** Simulated failure on workflow `k` of `N` (`N <= 20`) immediately stops writes to `k+1..N`, records exact per-workflow states (`verified`, `failed`, `skipped`, `unknown_result`), and generates an approval-gated best-effort draft restore plan.
- [x] **Durable Cleanup Lease Reconciliation:** Simulated crash after creating an ephemeral `[MCP-E2E-TEST]` workflow leaves a durable lease in `state.db`; subsequent `n8n-rs-mcp reconcile --instance staging --dry-run=false` removes the orphan workflow and verifies `404` on read-back (or surfaces `cleanup_required` if unauthorized).
- [x] **`BLAKE3` Journal Tamper Detection:** Modifying or deleting any historical row in `state.db`'s operation journal is detected by `doctor` / `reconcile` (`AUDIT_JOURNAL_INTEGRITY_ERROR`).
- [x] **AEAD Snapshot Integrity & Keyless Degradation:** Tampering with `.snap` ciphertext or swapping AAD metadata (`principal_id` / `workflow_id`) fails `ChaCha20-Poly1305` decryption; missing OS keyring degrades cleanly to memory-only `Zeroize` snapshots without plaintext disk writes.

---

## 6. Performance, Soak & Portability Gate

> **Measurement Honesty Rule:** Numbers below are engineering targets measured on fixed reference hardware with `data/catalog.sqlite.zst` and the 200-workflow synthetic corpus—not unconditional platform-independent guarantees. Record actual measured values in each release note.

| Metric | Objective Engineering Target | Measured `v1.0.0` Baseline (`x86_64-pc-windows-msvc`) |
| --- | --- | --- |
| **Stripped Release Binary Size** | **`< 25 MiB`** (`26,214,400` bytes) on primary 64-bit targets (`lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`) | **`17.13 MiB`** (`17,964,032` bytes) |
| **Idle Resident Set Size (RSS)** | **`< 25 MiB`** after `stdio` `initialize` + `tools/list` + catalog metadata open | **`17.24 MiB`** working set after warm `stdio` `initialize` + `tools/list` |
| **Warm Cached FTS5 Search Latency** | **`< 50 ms` P95** across `n8n_catalog_nodes` and `n8n_find_nodes` over **200 synthetic workflows** | **`< 2 ms`** (`U04` 200-workflow FTS5 search benchmark) |
| **Cold Process Startup (`doctor` / `initialize`)** | **Low hundreds of ms (`P50` / `P95` recorded)**; no false `< 15 ms` claim | **`~95–180 ms`** cold spawn + zstd catalog verify |
| **Rate-Limited Stability & Retry Pacing** | Dual-bucket `Retry-After` / `X-RateLimit-*` pacing with zero unbounded memory growth or SQLite lock deadlocks | Verified in `wiremock_n8n::errors_rate_limit_idempotency` & `n8n-state-vault` concurrency tests |

### Multi-Platform Release Artifacts & Supply-Chain Provenance
- [x] Release archives configured and built automatically in `.github/workflows/release.yml` for all **5 targets**:
  - `x86_64-pc-windows-msvc` (`.zip`)
  - `x86_64-unknown-linux-gnu` (`.tar.gz`)
  - `aarch64-unknown-linux-gnu` (`.tar.gz`)
  - `x86_64-apple-darwin` (`.tar.gz`)
  - `aarch64-apple-darwin` (`.tar.gz`)
- [x] Every archive bundles `n8n-rs-mcp` (`.exe`), `data/catalog.sqlite.zst`, `data/catalog.manifest.json`, `config/*.toml`, `examples/*`, `README.md`, `LICENSE`, and `docs/THIRD_PARTY_NOTICES.md`.
- [x] `SHA256SUMS.txt`, CycloneDX SBOM (`.cdx.json`), SPDX SBOM (`.spdx.json`), locked `cargo metadata` snapshot, and GitHub SLSA build provenance attestations (`actions/attest-build-provenance`) are configured in `.github/workflows/release.yml`.

---

## 7. Definition of Done Sign-Off (`v1.0.0` Production Readiness)

The release manager may sign off `v1.0.0` only when every statement below is empirically verified:

1. [x] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` (**96/96 workspace tests + 356/356 equivalence cases**) pass cleanly, with multi-OS matrix wired in `.github/workflows/ci.yml`.
2. [x] An authorized agent created an isolated `[MCP-E2E-TEST]` inactive draft workflow on a real staging n8n 2.x instance, mutated it via `n8n_mutate_nodes` (`preview -> confirm_plan -> apply`), verified read-back state, captured an encrypted snapshot, verified policy blocks, deleted the ephemeral draft with `404` read-back verification, and confirmed zero leftover test artifacts via `reconcile --dry-run=false`.
3. [x] `read-only` production and cross-project boundary checks deny every mutation and execution path without fallback.
4. [x] All documentation artifacts (`README.md`, `docs/USER_GUIDE.md`, `docs/OPERATIONS.md`, `docs/RELEASE_GATE.md`, `docs/API_COMPATIBILITY.md`, `docs/THREAT_MODEL.md`, `docs/APPROVAL_MODEL.md`, `docs/THIRD_PARTY_NOTICES.md`) and `LICENSE` contain zero real secrets or internal hostnames.
