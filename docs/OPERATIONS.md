# Operations & Security Runbook: `n8n-rs-mcp` (`n8n-forge-mcp`)

This runbook covers production deployment, multi-instance policy governance, secret injection and rotation, OS-protected state vault layout, `ChaCha20-Poly1305` snapshot encryption, `BLAKE3` audit journal verification, rate-limit/idempotency tuning, crash recovery (`reconcile`), and safe-cardinality observability (V2 Section 15).

---

## 1. Multi-Instance `instances.toml` & Policy Profiles

`n8n-rs-mcp` binds every named instance alias to an explicit environment classification (`development`, `staging`, `production`) and an immutable server-side policy mode (`read-only`, `staging-safe`, `production-guarded`, `full-dev`).

- **Server-Side Immutability:** Tool calls only reference configured `alias` names (e.g., `"staging"`, `"prod"`). An agent cannot pass raw URLs or switch profiles. Startup validates that `full-dev` is assigned only to a `development` instance.
- **Zero Secrets in Config Files:** Store `instances.toml` with mode `0600` (Unix) or per-user DACL (Windows), referencing **environment variable names** (`api_key_env`, `mcp_token_env`)—never literal credentials.

### Reference Multi-Instance `instances.toml` (All 4 Profiles)

```toml
# ~/.config/n8n-rs-mcp/instances.toml (Unix 0600)
# %APPDATA%\n8n-rs-mcp\instances.toml (Windows private user DACL)
schema_version = 1
default_instance = "staging"

[catalog]
bundle_path = "./data/catalog.sqlite.zst"
manifest_path = "./data/catalog.manifest.json"
verify_blake3_on_startup = true

# 1. Local disposable Docker n8n (`full-dev`)
[instances.local-dev]
url = "http://127.0.0.1:5678"
environment = "development"
policy = "full-dev"
allow_loopback_http = true
api_key_env = "N8N_LOCAL_DEV_API_KEY"
mcp_base_url = "http://127.0.0.1:5678/mcp-server/http"
mcp_token_env = "N8N_LOCAL_DEV_MCP_TOKEN"

# 2. Shared QA / Staging n8n (`staging-safe`)
[instances.staging]
url = "https://staging-n8n.example.internal"
environment = "staging"
policy = "staging-safe"
api_key_env = "N8N_STAGING_API_KEY"
mcp_base_url = "https://staging-n8n.example.internal/mcp-server/http"
mcp_token_env = "N8N_STAGING_MCP_TOKEN"
# Set `trust_configured_private_host = true` ONLY if DNS resolves to an approved internal RFC1918 IP:
trust_configured_private_host = false
# Optional Cloudflare Access service token env var names (pinned strictly to `url` origin):
cf_access_client_id_env = "CF_STAGING_ACCESS_CLIENT_ID"
cf_access_client_secret_env = "CF_STAGING_ACCESS_CLIENT_SECRET"

# 3. Default Production Inspection (`read-only`)
[instances.prod]
url = "https://n8n.example.internal"
environment = "production"
policy = "read-only"
api_key_env = "N8N_PROD_READONLY_API_KEY"
# Native MCP bridge intentionally omitted in default production read-only profile.

# 4. Break-Glass / Maintenance Window Production (`production-guarded`)
[instances.prod-maint]
url = "https://n8n.example.internal"
environment = "production"
policy = "production-guarded"
api_key_env = "N8N_PROD_MAINT_API_KEY"
mcp_base_url = "https://n8n.example.internal/mcp-server/http"
mcp_token_env = "N8N_PROD_MAINT_MCP_TOKEN"
enable_r4_admin_actions = false
allowed_project_ids = ["proj_core_billing"]
allowed_workflow_ids = ["wf_invoice_sync_v2"]
```

### Policy Profile Enforcement Summary

| Control | `read-only` | `staging-safe` | `production-guarded` | `full-dev` |
| --- | --- | --- | --- | --- |
| Allowed `environment` | Any (`production` default) | `staging`, `development` | `production`, `staging` | **`development` only** |
| `R0` Read & `R1` Offline Validate/Preview | Allowed | Allowed | Allowed | Allowed |
| `R2` Draft Writes (`create`, `mutate_nodes.apply`) | **Blocked** | Preview + version hash match | **Single-use `ApprovalReceipt`** | Preview + version hash match |
| `T1` (`simulate`) Pin-Data Testing | **Blocked** | Side-effect classifier gated | **Blocked** (test in staging) | Side-effect classifier gated |
| `R3` Live Effects (`manual` test, `publish`, `restore`) | **Blocked** | **Single-use `ApprovalReceipt`** | **Single-use `ApprovalReceipt`** | **Single-use `ApprovalReceipt`** |
| `T3` (`production`) Execution | **Blocked** *(overrides n8n 2.47+ protected mode)* | **Blocked** | Opt-in + **`R4` `ApprovalReceipt`** | Loopback + **`R4` `ApprovalReceipt`** |
| `R4` Bulk / Delete / Creds / Packages / Admin | **Blocked** | **Blocked** unless explicitly enabled | **Blocked** unless granularly enabled + `R4` receipt | Allowed with `R4` receipt + package allowlist |
| `max_batch_workflows` ceiling | `0` | `20` | `10` (if enabled) | `20` |

Repository policy templates live under `config/policy.prod-read-only.toml`, `config/policy.staging.toml`, and `config/policy.dev.toml`, and can be passed explicitly via `--policy-config <PATH>`.

---

## 2. Secret Injection, Origin Pinning & Key Rotation

### Secret Separation Invariants
1. **Distinct Credentials per Control Plane:** `N8N_API_KEY` (`X-N8N-API-KEY` on `/api/v1`) and `N8N_MCP_ACCESS_TOKEN` (`Authorization: Bearer` on `/mcp-server/http`) are separate credentials with independent scopes and rate limits. Startup validation **rejects** configurations where `N8N_MCP_ACCESS_TOKEN == N8N_API_KEY`.
2. **Origin-Pinned Header Injection:**
   - `X-N8N-API-KEY` is sent **only** to the exact `(scheme, host, port)` origin of `url`.
   - `Authorization: Bearer <N8N_MCP_ACCESS_TOKEN>` is sent **only** to the exact origin of `mcp_base_url`.
   - `CF-Access-Client-Id` and `CF-Access-Client-Secret` are sent **only** to the configured Cloudflare-protected origin.
   - HTTP `3xx` redirects are disabled (`redirect::Policy::none()`), preventing cross-origin credential forwarding.
3. **Least-Privilege API Key Scopes (n8n `>= 2.14.0`):**
   - For `prod` (`read-only`), provision an n8n API key limited to `workflow:read`, `workflow:list`, `execution:read`, `execution:list`, `project:read`, `tag:list`, and `credential:list` (if metadata checks are needed). Never issue a global Owner key for read-only inspection.

### Zero-Downtime Key Rotation Procedure
1. **Create replacement credential in n8n:** Generate a new scoped API key (or rotate the Instance-Level MCP access token under **Settings -> Instance-level MCP**) with an overlap window.
2. **Update secret store / launcher:** Write the new secret into your OS secret manager (`secret-tool`, macOS `security`, Windows Credential Manager, Vault, or CI secret store) mapped to `N8N_<ALIAS>_API_KEY` / `N8N_<ALIAS>_MCP_TOKEN`.
3. **Verify before cutover:** Run `n8n-rs-mcp doctor --instance <alias> --no-secret-output` in a test shell with the new environment variable to verify HTTP `200` on `/api/v1/discover` and expected scope coverage.
4. **Restart `n8n-rs-mcp` process:** Restart the client's `stdio` MCP server (or reload the localhost HTTPS gateway) so in-memory `SecretString` buffers zeroize old key material and load the new token.
5. **Revoke old credential in n8n:** Delete the superseded API key / token in n8n and confirm revocation with a negative test if required by compliance.

---

## 3. OS-Protected State Vault Layout & Permissions (`n8n-state-vault`)

`n8n-state-vault` stores the sanitized FTS5 metadata index, capability cache, `BLAKE3` operation journal, and AEAD-encrypted draft snapshots inside an OS-specific per-user directory—never in a shared `/tmp` or repository working tree.

### Default Vault Paths & Mandatory ACLs

| Platform | Default Vault Root | Directory Permission | File Permission (`state.db*`, `snapshots/*`) |
| --- | --- | --- | --- |
| **Windows** | `%LOCALAPPDATA%\n8n-rs-mcp\vault\` | `icacls` `/inheritance:r /grant:r "<CurrentUserSID>:(OI)(CI)(F)"` | Inherited single-SID full control; zero `Users` / `Everyone` ACEs |
| **Linux** | `${XDG_DATA_HOME:-~/.local/share}/n8n-rs-mcp/vault/` | `0700` (`drwx------`) | `0600` (`-rw-------`) |
| **macOS** | `~/Library/Application Support/n8n-rs-mcp/vault/` | `0700` (`drwx------`) | `0600` (`-rw-------`) |

### Directory Structure

```text
vault/
|-- state.db               # SQLite (WAL mode): sanitized FTS5 node index, capability TTL cache,
|                          # consumed ApprovalReceipt nonces, cleanup leases, BLAKE3 audit journal
|-- state.db-wal           # Write-ahead log (enforced 0600 / private user DACL)
|-- state.db-shm           # Shared-memory WAL index (enforced 0600 / private user DACL)
`-- snapshots/
    `-- <principal_hash>/<instance_alias>/<workflow_id>/<version_hash>_<unix_ts>.snap
                           # zstd-compressed + ChaCha20-Poly1305 AEAD ciphertext + 96-bit nonce
```

### Sanitized Index & Partition Isolation Rules
- **`cache_policy = "no_persistent_payload"` (Default):** `state.db` indexes only structural metadata (`node_id`, `node_name`, `node_type`, `type_version`, `referenced_nodes`, `credential_type_ref_hash`, `health_flags`). Plaintext `node.parameters` JSON is **never** written to SQLite by default.
- **Partition Key:** Every indexed row is keyed by `(principal_id, instance_id, project_id, workflow_id, version_hash)`.
- **Immediate Revocation Purge:** If n8n returns `403 Forbidden` or `404 Not Found` for a previously indexed project or workflow, `n8n-state-vault` immediately deletes that `(principal_id, instance_id, project_id, workflow_id)` partition so revoked workflows never leak through cached `n8n_find_nodes` queries.
- **Startup ACL Check:** Both `mcp` startup and `doctor` verify directory/file ownership and ACLs. If group/world permission bits (Unix) or multi-user ACEs (Windows) are present and `require_private_os_acl = true`, startup fails closed with remediation commands (`chmod 0700` / `icacls`).

---

## 4. `ChaCha20-Poly1305` Snapshot Key Management

Before executing any `R2`–`R4` workflow graph mutation (when `capture_encrypted_snapshot_before_write = true`), `n8n-state-vault` captures a pre-write draft snapshot:

1. **Redaction & Compression:** Credential secrets and unapproved sensitive literals are stripped, and the canonical draft JSON is compressed with `zstd`.
2. **AEAD Construction:** Encrypted with `ChaCha20-Poly1305` using a 256-bit key and a fresh 96-bit CSPRNG nonce (`rand`).
3. **AAD Context Binding:** Additional Authenticated Data binds:
   ```text
   aad = "n8n-rs-mcp.snapshot.v1"
      || principal_id || instance_id || project_id || workflow_id || expected_version_hash || created_at_unix_be64
   ```
   Moving or renaming a `.snap` file across principals, instances, or workflows causes AEAD tag verification to fail immediately.
4. **Master Key Custody & Headless Fallback:**
   - **Desktop / Workstation:** Master key `k_master` (32 bytes, keyed by `key_id`) is stored in **Windows Credential Manager (DPAPI)**, **macOS Keychain**, or **Linux Secret Service**.
   - **Headless / Container Fallback:** If no OS keyring is reachable and no explicit KMS/key-fd secret is injected, `n8n-state-vault` **never falls back to a hardcoded key or plaintext disk file**—it automatically switches to bounded **ephemeral in-memory snapshots** (`Zeroize` on process exit) and surfaces a clear warning in `doctor` and tool responses.
5. **Snapshot Key Rotation & Retention:**
   - Each `.snap` header records `key_id` (non-secret UUID). During key rotation, generate a new 256-bit active key in the OS keyring (`key_id_new`); existing snapshots within the retention window (`snapshot_retention_days`, default `30` days in staging/prod, `14` days in dev) either re-wrap under `key_id_new` or age out cleanly.
   - Expired snapshots are unlinked on startup housekeeping and explicit purge calls, removing both SQLite metadata rows and `.snap` ciphertexts.

---

## 5. `BLAKE3` Hash-Chained Audit Journal Verification

Every mutating or effect-producing operation transitions through a deterministic journal state machine in `state.db`:

```text
PLANNED -> PREVIEWED -> USER_APPROVED -> PREPARING -> WRITING -> VERIFYING -> VERIFIED
                                                                          \-> PARTIAL
                                                                          \-> CONFLICT
                                                                          \-> UNKNOWN_RESULT
                                                                          \-> FAILED
```

### Cryptographic Chain Formula
Each appended journal row `i` computes a tamper-evident digest over canonical redacted JSON:

```text
entry_hash[0] = BLAKE3("n8n-rs-mcp.journal.genesis.v1" || instance_id || canonical_redacted_record[0])
entry_hash[i] = BLAKE3(entry_hash[i - 1] || canonical_redacted_record[i])
```

- **Zero Secrets in Journal:** `canonical_redacted_record` contains `audit_id`, `operation_id`, `principal_id` (opaque hash), `instance_alias`, `workflow_id`, `action`, `risk_level`, `plan_id`, `receipt_nonce_hash`, `version_before`, `version_after`, `active_version_id`, `ops_hash`, `status`, and `timestamp`—never raw parameter values or auth headers.
- **Integrity Verification:** `n8n-rs-mcp doctor` and `n8n-rs-mcp reconcile` walk the journal chain from genesis (or the latest signed rotation anchor) to verify `entry_hash[i]` continuity. Any deleted, reordered, or edited SQLite row breaks the `BLAKE3` chain and raises `AUDIT_JOURNAL_INTEGRITY_ERROR`.
- **Journal Rotation:** Before archiving old journal segments, record the terminal `entry_hash[N]` as the signed `rotation_anchor_hash` of the next segment so audit continuity spans rotations.

---

## 6. Rate-Limit & Idempotency Tuning

### Dual-Bucket Rate Limiting (`n8n >= 2.47.0` + Local Governor)
- **Server-Driven Pacing (Authoritative):** When n8n `2.47+` rate limiting is enabled by the instance administrator, `n8n-api-client` tracks both the **global API-key read/write bucket** and **per-endpoint read/write bucket** via `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`.
- **Conservative Local Token Bucket (`governor`):** When upstream rate-limit headers are absent (default n8n config), `n8n-api-client` enforces a local burst/sustained request budget per `(principal_id, instance_alias)` so a runaway agent loop cannot saturate the n8n Node.js event loop or database pool.
- **Native MCP Bridge Pacing:** Respects n8n's instance-level `/mcp-server/http` per-token window limit (`100 requests / window / token`).
- **Safe Retry Rule on `429`:** `429 Too Many Requests` honors `Retry-After` with jitter **only** for read-only requests (`GET`) and verified `2.45+` idempotent `POST` requests replaying the exact `Idempotency-Key`. Non-idempotent mutations surface `RATE_LIMITED` (`status: "error"`) rather than risking duplicate writes.

### Idempotent `POST` Tracking (`n8n >= 2.45.0`)
- Sent **only** on `POST` endpoints whose `/api/v1/discover` schema advertises `Idempotency-Key` support (ignored by n8n on `GET`, `PUT`, `PATCH`, `DELETE`).
- Before transmitting a supported `POST`, `n8n-api-client` persists `(operation_id, idempotency_key, canonical_body_blake3, created_at_unix)` in the journal/idempotency store.
- **12-Hour Window & Exact-Bytes Rule:** n8n retains successful idempotent `POST` responses for **at most 12 hours** and rejects key reuse with altered request bodies. If a network timeout occurs during `POST /api/v1/workflows`, `n8n-rs-mcp` **never** generates a new `Idempotency-Key`—it reconciles first and only replays the identical `(idempotency_key, canonical_body)` within the 12-hour window.

---

## 7. Crash-Recovery & Reconciliation Runbook (`reconcile`)

Network drops, client cancellations, or power loss after a mutating HTTP/MCP request is sent create an **unknown outcome** (`UNKNOWN_RESULT` / `WRITE_RESULT_UNCERTAIN`). Never blindly re-run failed writes before reconciling.

### Step-by-Step Recovery Procedure

1. **Inspect pending uncertain states (non-mutating):**
   ```sh
   n8n-rs-mcp reconcile --instance staging --dry-run
   ```
   Review three queues in the JSON output:
   - `uncertain_operations_found`: Operations stuck in `WRITING` or `UNKNOWN_RESULT`.
   - `pending_leases_checked`: Durable `n8n-test-harness` cleanup leases written prior to ephemeral staging test resources.
   - Incomplete `n8n_bulk_codemod` batch checkpoints.

2. **Reconcile `WRITE_RESULT_UNCERTAIN` workflows:**
   - For `update` / `mutate_nodes`: `reconcile` fetches `GET /api/v1/workflows/{id}`, compares `versionId` and canonical graph `BLAKE3` against `version_before` and expected post-mutation state, and transitions the journal entry to `VERIFIED` (write landed), `ROLLED_BACK_OR_UNCHANGED` (write never landed), or `POST_WRITE_DRIFT_DETECTED` (concurrent edit occurred).
   - For `create`: `reconcile` checks the `2.45+` idempotency record or searches recent workflows in the target project matching the planned name/digest before declaring whether creation succeeded.

3. **Execute authorized test-resource cleanup:**
   ```sh
   n8n-rs-mcp reconcile --instance staging --dry-run=false
   ```
   - Unpublishes and deletes any abandoned `[MCP-E2E-TEST]` or temporary test workflows recorded in durable cleanup leases, verifying `404` / absence on read-back.
   - If permissions were revoked or n8n is unreachable, marks the lease `cleanup_required` and emits a structured operator alert—never silently dropping failed cleanups.

4. **Rebuild corrupted local index (Zero n8n Data Loss):**
   - Because n8n itself is the source of truth for workflows and executions, if `state.db`'s FTS5 cache ever needs a clean rebuild, archive `state.db` + `snapshots/` for audit retention, restart `n8n-rs-mcp`, and run `n8n-rs-mcp doctor --instance <alias> --no-secret-output` to initialize a fresh ACL-protected `state.db`.

---

## 8. Safe-Cardinality Metrics & Redacted Logging (V2 Section 15)

### Safe-Cardinality Metrics Contract
All telemetry counters, histograms, and gauges enforce **strictly bounded label cardinality** (never using `workflow_id`, `execution_id`, `user_email`, or `url` as metric labels):

| Metric Name | Type | Allowed Bounded Labels | Operational Purpose |
| --- | --- | --- | --- |
| `n8n_mcp_tool_requests_total` | Counter | `tool`, `action`, `status`, `risk_level`, `route_used` | Request volume, route distribution, and failure classes across all 24 tools |
| `n8n_mcp_tool_duration_seconds` | Histogram | `tool`, `route_used` | End-to-end tool latency (`P50`, `P95`, `P99`) |
| `n8n_upstream_http_requests_total` | Counter | `instance`, `plane` (`public_api\|native_mcp`), `method`, `status_class` (`2xx\|401\|403\|404\|409\|422\|429\|5xx\|timeout`) | Upstream n8n health, auth errors, and rate-limit pressure |
| `n8n_upstream_rate_limit_waits_total` | Counter | `instance`, `bucket` (`global_read\|global_write\|endpoint\|local_governor\|native_mcp`) | Throttling backoff tracking (`2.47+` headers & local governor) |
| `n8n_policy_decisions_total` | Counter | `instance`, `profile`, `risk_level`, `decision` (`allowed\|needs_approval\|denied\|replay_rejected\|scope_mismatch`) | Authorization gate auditing and approval-bypass detection |
| `n8n_uncertain_writes_open` | Gauge | `instance` | Count of unresolved `WRITE_RESULT_UNCERTAIN` journal entries needing `reconcile` |
| `n8n_cleanup_leases_backlog` | Gauge | `instance`, `state` (`active\|cleanup_required`) | Abandoned test-harness resources awaiting cleanup |
| `n8n_catalog_and_index_search_seconds` | Histogram | `index` (`catalog_fts5\|live_workflow_fts5`), `cache` (`hit\|miss`) | Verifies `<50 ms` warm cached FTS5 search SLA |
| `n8n_state_vault_bytes` | Gauge | `component` (`state_db\|wal\|snapshots`) | Disk footprint monitoring for SQLite state and encrypted snapshots |
| `n8n_capability_mismatches_total` | Counter | `instance`, `reason` (`scopes_without_endpoint\|legacy_fallback\|skipped_group`) | Tracks n8n version/module drift (e.g., `agent:*` scopes without endpoints) |

### Structured Redacted Log Schema (`stderr`)
Configure verbosity via `RUST_LOG=warn,n8n_rs_mcp=info` (JSON output supported via tracing configuration). Every log event adheres to strict field inclusion/exclusion rules:

- **Permitted Log Fields:** `timestamp`, `level`, `operation_id`, `audit_id`, `principal_hash` (opaque salted hash), `instance` (alias only), `tool`, `action`, `risk_level`, `http_method`, `path_template` (e.g., `/api/v1/workflows/{id}`, **never** query strings or secret webhook paths), `status`, `duration_ms`, `version_before`, `version_after`, `active_version_id`, `error_code` (sanitized enum).
- **Strictly Prohibited in Logs:** `X-N8N-API-KEY`, `N8N_MCP_ACCESS_TOKEN`, `CF-Access-Client-Secret`, `ApprovalReceipt` HMAC tags, raw `node.parameters`, execution `runData` / webhook bodies, `$env` values, credential payloads, and unredacted upstream stack traces.
