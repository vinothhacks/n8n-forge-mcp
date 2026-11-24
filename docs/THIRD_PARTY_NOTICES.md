# Third-Party Notices & License Attribution

`n8n-forge-mcp` (`n8n-rs-mcp`) is an independent, clean-room Rust implementation of an MCP control, validation, testing, and governance server for n8n. This document records third-party open-source attributions, offline catalog metadata provenance, Rust dependency licenses, and trademark/interoperability disclosures.

---

## 1. Offline Catalog & Validation Reference Provenance (`czlonkowski/n8n-mcp`)

Portions of the offline public node/template catalog schema design, `displayOptions` conditional visibility rules, expression bracket validation edge cases, and black-box equivalence test expectations in `tools/catalog-builder/` and `tests/equivalence/cases.jsonl` were informed by and verified against the MIT-licensed `n8n-mcp` project (`v2.103.2`):

- **Project:** `n8n-mcp` (`https://github.com/czlonkowski/n8n-mcp`)
- **Version Referenced:** `2.103.2`
- **Author:** Romuald Czlonkowski (`www.aiadvisors.pl/en`)
- **License:** MIT License

### Verbatim MIT License Notice (`czlonkowski/n8n-mcp`)

```text
MIT License

Copyright (c) 2024 Romuald Czlonkowski @ www.aiadvisors.pl/en

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. n8n Public API & Interoperability Notice

- **Trademark & Non-Affiliation:** `n8n` is a trademark of **n8n GmbH**. `n8n-forge-mcp` (`n8n-rs-mcp`) is an independent open-source software project and is **not** affiliated with, sponsored by, or officially endorsed by n8n GmbH.
- **Clean-Room Public Interface Integration:**
  - Runtime communication with n8n occurs **exclusively** over n8n's documented Public REST API (`/api/v1`, `/api/v1/discover`, `/api/v1/openapi.yml`) and n8n's documented Instance-Level MCP protocol (`/mcp-server/http`).
  - **Zero** proprietary n8n Sustainable Use License (SUL) backend execution engine code and **zero** n8n Enterprise Edition (`.ee.ts`) source files were translated, copied, linked, or embedded into this repository or its compiled Rust artifacts.
  - Node type identifiers (e.g., `n8n-nodes-base.webhook`, `@n8n/n8n-nodes-langchain.agent`), parameter names, and OpenAPI path contracts in `data/catalog.sqlite.zst` and `tests/contract/openapi_v1_paths.json` represent factual interoperability descriptors required to construct valid workflow JSON documents for n8n instances.

---

## 3. Rust Workspace Crate Dependencies

All runtime and test dependencies of the `n8n-rs-mcp` Cargo workspace use permissive OSI-approved licenses (`MIT`, `Apache-2.0`, `ISC`, `CC0-1.0`, `BSD-3-Clause`). Exact version pins are recorded in `Cargo.lock` and verified in CI.

| Crate | Upstream Repository | License(s) | Role in `n8n-rs-mcp` |
| --- | --- | --- | --- |
| `rmcp`, `rmcp-macros` | `https://github.com/modelcontextprotocol/rust-sdk` | `MIT OR Apache-2.0` | Official Rust MCP server (`stdio`) and Streamable HTTP bridge client (`3.11.0`) |
| `tokio`, `tokio-util`, `futures` | `https://github.com/tokio-rs/tokio` | `MIT` / `MIT OR Apache-2.0` | Async runtime, bounded concurrency, per-workflow `Mutex` locks, cancellation |
| `reqwest` | `https://github.com/seanmonstar/reqwest` | `MIT OR Apache-2.0` | Bounded HTTPS REST client with `rustls` and disabled cross-origin redirects |
| `rustls` | `https://github.com/rustls/rustls` | `Apache-2.0 OR ISC OR MIT` | Memory-safe TLS implementation |
| `serde`, `serde_json`, `schemars` | `https://github.com/serde-rs/serde`, `https://github.com/GREsau/schemars` | `MIT OR Apache-2.0` | Typed DTO serialization and compact MCP tool JSON Schema generation |
| `rusqlite` | `https://github.com/rusqlite/rusqlite` | `MIT` (bundled SQLite: Public Domain) | Offline catalog reader (`FTS5`) and per-user sanitized state vault / journal |
| `zstd` | `https://github.com/gyscos/zstd-rs` | `MIT` (`libzstd`: `BSD-3-Clause OR GPL-2.0` — BSD-3-Clause selected) | Decompression of `data/catalog.sqlite.zst` and snapshot compression |
| `blake3` | `https://github.com/BLAKE3-team/BLAKE3` | `CC0-1.0 OR Apache-2.0` | Content-addressed workflow/operation digests, catalog manifest checks, journal hash chain |
| `chacha20poly1305`, `hmac`, `sha2`, `subtle` | `https://github.com/RustCrypto` | `Apache-2.0 OR MIT` / `BSD-3-Clause` | AEAD snapshot encryption (`ChaCha20-Poly1305`) and constant-time `ApprovalReceipt` MAC verification |
| `secrecy`, `zeroize` | `https://github.com/iqlusioninc/crates` | `Apache-2.0 OR MIT` | Redacted secret wrappers and best-effort memory zeroization on drop |
| `oxc_parser`, `oxc_allocator`, `oxc_ast`, `oxc_span` | `https://github.com/oxc-project/oxc` | `MIT` | Fast AST parsing for JavaScript `Code` nodes and `={{ ... }}` n8n expressions |
| `petgraph` | `https://github.com/petgraph/petgraph` | `MIT OR Apache-2.0` | Loop-aware workflow graph topology, port validation, and trigger reachability |
| `serde_json_path`, `jmespath` | `https://github.com/hiltontj/serde_json_path`, `https://github.com/jmespath/jmespath.rs` | `MIT` / `Apache-2.0` | Bounded metadata predicate evaluation and `$jmespath()` expression checks |
| `regex`, `similar` | `https://github.com/rust-lang/regex`, `https://github.com/mitsuhiko/similar` | `MIT OR Apache-2.0` / `Apache-2.0` | Linear-time bounded text patching/redaction and semantic workflow diffs |
| `governor` | `https://github.com/boinkor-net/governor` | `MIT` | Local rate-limit token bucket complementing n8n `2.47+` `X-RateLimit-*` headers |
| `clap`, `tracing`, `thiserror`, `uuid`, `chrono`, `url`, `ipnet` | Respective crates.io maintainers | `MIT OR Apache-2.0` | CLI subcommands, structured redacted telemetry, typed errors, URL/CIDR SSRF checks |
| `wiremock`, `proptest`, `tempfile` *(dev-only)* | Respective crates.io maintainers | `MIT OR Apache-2.0` | Deterministic HTTP contract, chaos, property, and security test suites |

---

## 4. Development-Time Verification Tooling (Not Distributed)

During development and equivalence verification, the following MCP tools may be invoked by contributors on local development machines. **None of these tools are linked into, bundled with, or required at runtime by `n8n-rs-mcp`:**

- `rust-anything` (`https://github.com/erkamyaman/rust-anything`) — Development-time equivalence harness (`cases.jsonl` replay/diff gating).
- `rea-mcp` / `rea-rust` (`https://github.com/Reuben-Chauhan/rea-mcp`, `https://github.com/nanashili/rea-rust`) — Development-time static artifact and SQLite schema inspection.
