#!/usr/bin/env python3
"""
Reproducible Offline Node & Template Catalog Builder for n8n-rs-mcp (n8n-forge-mcp).

Builds `data/catalog.sqlite.zst` and `data/catalog.manifest.json` using Python 3 `sqlite3` (FTS5),
a verified pure-Python BLAKE3 + SHA-256 content hasher, and zstd compression (via Python `zstandard`
when available or Node.js >= 22.15 built-in `zlib.zstdCompressSync` / `zstd` CLI).

Provenance & Attribution:
  - Node type metadata, versions, conditional `displayOptions`, operations, and curated workflow
    patterns verified against MIT-licensed `czlonkowski/n8n-mcp@2.103.2` and n8n `2.48.7` schemas.
  - Zero secrets or live instance tokens are read or emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog_seed import CREDENTIAL_TYPES, NODE_DEFS, TEMPLATES

SCHEMA_VERSION = 1
BUNDLE_VERSION = "2026.11.23-v1"
SOURCE_VERSION = "n8n-mcp@2.103.2"
TARGET_N8N_BASELINE = "2.48.7"
FIXED_EXTRACTION_TIMESTAMP = "2026-11-23T00:00:00Z"


# ---------------------------------------------------------------------------
# Pure-Python Official BLAKE3 (256-bit) Implementation (CC0-1.0 spec)
# Matches `blake3::hash(&bytes).to_hex()` in Rust byte-for-byte for all sizes.
# ---------------------------------------------------------------------------

_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

_CHUNK_START = 1 << 0
_CHUNK_END = 1 << 1
_PARENT = 1 << 2
_ROOT = 1 << 3
_BLOCK_LEN = 64
_CHUNK_LEN = 1024


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _round(state: list[int], m: tuple[int, ...]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    cv: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        _IV[0],
        _IV[1],
        _IV[2],
        _IV[3],
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len,
        flags,
    ]
    m = block_words
    for r in range(7):
        _round(state, m)
        if r < 6:
            m = tuple(m[i] for i in _MSG_PERMUTATION)
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def _block_words_from_bytes(block: bytes) -> tuple[int, ...]:
    padded = block if len(block) == _BLOCK_LEN else block.ljust(_BLOCK_LEN, b"\x00")
    return struct.unpack("<16I", padded)


def _chunk_output(chunk_bytes: bytes, chunk_counter: int, key: tuple[int, ...], flags: int) -> tuple[tuple[int, ...], tuple[int, ...], int, int, int]:
    cv = key
    if not chunk_bytes:
        return (cv, _block_words_from_bytes(b""), chunk_counter, 0, flags | _CHUNK_START | _CHUNK_END)

    num_blocks = (len(chunk_bytes) + _BLOCK_LEN - 1) // _BLOCK_LEN
    for b_idx in range(num_blocks - 1):
        block = chunk_bytes[b_idx * _BLOCK_LEN : (b_idx + 1) * _BLOCK_LEN]
        b_flags = flags | (_CHUNK_START if b_idx == 0 else 0)
        out = _compress(cv, _block_words_from_bytes(block), chunk_counter, _BLOCK_LEN, b_flags)
        cv = tuple(out[:8])

    last_block = chunk_bytes[(num_blocks - 1) * _BLOCK_LEN :]
    last_flags = flags | (_CHUNK_START if num_blocks == 1 else 0) | _CHUNK_END
    return (cv, _block_words_from_bytes(last_block), chunk_counter, len(last_block), last_flags)


def _output_cv(output: tuple[tuple[int, ...], tuple[int, ...], int, int, int]) -> tuple[int, ...]:
    cv, block_words, counter, block_len, flags = output
    return tuple(_compress(cv, block_words, counter, block_len, flags)[:8])


def _output_root_hex(output: tuple[tuple[int, ...], tuple[int, ...], int, int, int]) -> str:
    cv, block_words, counter, block_len, flags = output
    words = _compress(cv, block_words, counter, block_len, flags | _ROOT)[:8]
    return struct.pack("<8I", *words).hex()


def _parent_output(left_cv: tuple[int, ...], right_cv: tuple[int, ...], key: tuple[int, ...], flags: int) -> tuple[tuple[int, ...], tuple[int, ...], int, int, int]:
    return (key, left_cv + right_cv, 0, _BLOCK_LEN, flags | _PARENT)


def blake3_hex(data: bytes) -> str:
    try:
        import blake3 as _native_blake3  # type: ignore[import-not-found]

        return str(_native_blake3.blake3(data).hexdigest())
    except ImportError:
        pass

    if not data:
        return _output_root_hex(_chunk_output(b"", 0, _IV, 0))

    cv_stack: list[tuple[int, ...]] = []
    num_chunks = (len(data) + _CHUNK_LEN - 1) // _CHUNK_LEN

    for chunk_idx in range(num_chunks - 1):
        chunk = data[chunk_idx * _CHUNK_LEN : (chunk_idx + 1) * _CHUNK_LEN]
        new_cv = _output_cv(_chunk_output(chunk, chunk_idx, _IV, 0))
        total_chunks = chunk_idx + 1
        while (total_chunks & 1) == 0:
            new_cv = _output_cv(_parent_output(cv_stack.pop(), new_cv, _IV, 0))
            total_chunks >>= 1
        cv_stack.append(new_cv)

    last_chunk = data[(num_chunks - 1) * _CHUNK_LEN :]
    output = _chunk_output(last_chunk, num_chunks - 1, _IV, 0)
    while cv_stack:
        right_cv = _output_cv(output)
        output = _parent_output(cv_stack.pop(), right_cv, _IV, 0)
    return _output_root_hex(output)


def verify_blake3_self_test() -> None:
    # Official BLAKE3 test vectors (input[i] = i % 251)
    def pattern(n: int) -> bytes:
        return bytes(i % 251 for i in range(n))

    expected = {
        0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    }
    for length, digest in expected.items():
        actual = blake3_hex(pattern(length))
        if actual != digest:
            raise RuntimeError(f"BLAKE3 self-test mismatch at len={length}: {actual} != {digest}")


def compress_zstd(raw_bytes: bytes, level: int = 19) -> bytes:
    try:
        import zstandard as zstd  # type: ignore[import-not-found]

        cctx = zstd.ZstdCompressor(level=level)
        return bytes(cctx.compress(raw_bytes))
    except ImportError:
        pass

    zstd_bin = shutil.which("zstd")
    if zstd_bin:
        proc = subprocess.run(
            [zstd_bin, f"-{level}", "--stdout"],
            input=raw_bytes,
            capture_output=True,
            check=True,
        )
        return proc.stdout

    node_bin = shutil.which("node")
    if node_bin:
        js = (
            "const fs = require('fs'), zlib = require('zlib');"
            "const input = fs.readFileSync(process.argv[1]);"
            "const params = { [zlib.constants.ZSTD_c_compressionLevel]: Number(process.argv[3]) };"
            "const out = zlib.zstdCompressSync(input, { params });"
            "const verify = zlib.zstdDecompressSync(out);"
            "if (!verify.equals(input)) { process.exit(2); }"
            "fs.writeFileSync(process.argv[2], out);"
        )
        with tempfile.TemporaryDirectory() as tmp:
            in_file = Path(tmp) / "catalog.sqlite"
            out_file = Path(tmp) / "catalog.sqlite.zst"
            in_file.write_bytes(raw_bytes)
            subprocess.run([node_bin, "-e", js, str(in_file), str(out_file), str(level)], check=True)
            return out_file.read_bytes()

    raise RuntimeError("No zstd compressor found (install Python 'zstandard', 'zstd' CLI, or Node.js >= 22.15).")


def decompress_zstd(zst_bytes: bytes) -> bytes:
    try:
        import zstandard as zstd  # type: ignore[import-not-found]

        dctx = zstd.ZstdDecompressor()
        return bytes(dctx.decompress(zst_bytes))
    except ImportError:
        pass

    zstd_bin = shutil.which("zstd")
    if zstd_bin:
        proc = subprocess.run(
            [zstd_bin, "-d", "--stdout"],
            input=zst_bytes,
            capture_output=True,
            check=True,
        )
        return proc.stdout

    node_bin = shutil.which("node")
    if node_bin:
        js = (
            "const fs = require('fs'), zlib = require('zlib');"
            "const input = fs.readFileSync(process.argv[1]);"
            "const out = zlib.zstdDecompressSync(input);"
            "fs.writeFileSync(process.argv[2], out);"
        )
        with tempfile.TemporaryDirectory() as tmp:
            in_file = Path(tmp) / "catalog.sqlite.zst"
            out_file = Path(tmp) / "catalog.sqlite"
            in_file.write_bytes(zst_bytes)
            subprocess.run([node_bin, "-e", js, str(in_file), str(out_file)], check=True)
            return out_file.read_bytes()

    raise RuntimeError("No zstd decompressor found.")


def verify_roundtrip_archive(zst_path: Path, expected_blake3: str, expected_sha256: str) -> dict[str, Any]:
    archived = zst_path.read_bytes()
    decompressed = decompress_zstd(archived)
    actual_blake3 = blake3_hex(decompressed)
    actual_sha256 = hashlib.sha256(decompressed).hexdigest()
    if actual_blake3 != expected_blake3:
        raise RuntimeError(f"Decompressed BLAKE3 mismatch: {actual_blake3} != {expected_blake3}")
    if actual_sha256 != expected_sha256:
        raise RuntimeError(f"Decompressed SHA-256 mismatch: {actual_sha256} != {expected_sha256}")

    with tempfile.TemporaryDirectory() as tmp:
        verify_db = Path(tmp) / "verify.sqlite"
        verify_db.write_bytes(decompressed)
        conn = sqlite3.connect(str(verify_db))
        try:
            cur = conn.cursor()
            integrity = cur.execute("PRAGMA integrity_check;").fetchone()[0]
            if integrity != "ok":
                raise RuntimeError(f"SQLite PRAGMA integrity_check failed: {integrity}")
            fts_webhook = cur.execute(
                "SELECT node_type FROM node_fts WHERE node_fts MATCH 'webhook' ORDER BY rank LIMIT 5;"
            ).fetchall()
            fts_agent = cur.execute(
                "SELECT node_type FROM node_fts WHERE node_fts MATCH 'agent OR openai' ORDER BY rank LIMIT 5;"
            ).fetchall()
            fts_tmpl = cur.execute(
                "SELECT slug FROM template_fts WHERE template_fts MATCH 'webhook OR rag OR slack' ORDER BY rank LIMIT 5;"
            ).fetchall()
            if not fts_webhook or not fts_agent or not fts_tmpl:
                raise RuntimeError("FTS5 MATCH verification returned empty results")
            return {
                "integrityCheck": integrity,
                "ftsWebhookHits": [r[0] for r in fts_webhook],
                "ftsAiHits": [r[0] for r in fts_agent],
                "ftsTemplateHits": [r[0] for r in fts_tmpl],
            }
        finally:
            conn.close()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


DDL_STATEMENTS = [
    "PRAGMA page_size = 4096;",
    "PRAGMA encoding = 'UTF-8';",
    "PRAGMA foreign_keys = ON;",
    """
    CREATE TABLE catalog_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE node_types (
        node_type TEXT PRIMARY KEY,
        short_type TEXT NOT NULL UNIQUE,
        package_name TEXT NOT NULL,
        display_name TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        development_style TEXT NOT NULL,
        default_version TEXT NOT NULL,
        is_versioned INTEGER NOT NULL,
        is_trigger INTEGER NOT NULL,
        is_webhook INTEGER NOT NULL,
        is_ai_tool INTEGER NOT NULL,
        is_tool_variant INTEGER NOT NULL,
        has_tool_variant INTEGER NOT NULL,
        tool_variant_of TEXT,
        native_priority INTEGER NOT NULL,
        native_score INTEGER NOT NULL,
        side_effect_class TEXT NOT NULL,
        inputs_json TEXT NOT NULL,
        outputs_json TEXT NOT NULL,
        output_names_json TEXT,
        credentials_json TEXT NOT NULL,
        schema_hash TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE node_versions (
        node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
        type_version TEXT NOT NULL,
        numeric_version REAL NOT NULL,
        is_default INTEGER NOT NULL,
        is_deprecated INTEGER NOT NULL DEFAULT 0,
        breaking_notes TEXT,
        schema_hash TEXT NOT NULL,
        PRIMARY KEY (node_type, type_version)
    );
    """,
    """
    CREATE TABLE node_properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
        type_version TEXT NOT NULL,
        prop_index INTEGER NOT NULL,
        name TEXT NOT NULL,
        display_name TEXT NOT NULL,
        prop_type TEXT NOT NULL,
        required INTEGER NOT NULL,
        default_json TEXT,
        description TEXT NOT NULL,
        options_json TEXT,
        display_options_json TEXT,
        expected_format_json TEXT
    );
    """,
    """
    CREATE INDEX idx_node_properties_lookup
        ON node_properties(node_type, type_version, prop_index);
    """,
    """
    CREATE TABLE node_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_type TEXT NOT NULL REFERENCES node_types(node_type) ON DELETE CASCADE,
        resource TEXT NOT NULL,
        operation TEXT NOT NULL,
        display_name TEXT NOT NULL,
        description TEXT NOT NULL,
        action_label TEXT,
        UNIQUE(node_type, resource, operation)
    );
    """,
    """
    CREATE TABLE credential_types (
        credential_type TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        documentation_url TEXT,
        auth_kind TEXT NOT NULL,
        is_generic INTEGER NOT NULL,
        required_fields_json TEXT NOT NULL,
        supported_nodes_json TEXT NOT NULL
    );
    """,
    """
    CREATE VIRTUAL TABLE node_fts USING fts5(
        node_type,
        short_type,
        display_name,
        category,
        description,
        operations_text,
        keywords,
        tokenize='porter unicode61'
    );
    """,
    """
    CREATE TABLE templates (
        id INTEGER PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        complexity TEXT NOT NULL,
        estimated_setup_minutes INTEGER NOT NULL,
        nodes_used_json TEXT NOT NULL,
        required_credentials_json TEXT NOT NULL,
        workflow_json TEXT NOT NULL,
        source_attribution TEXT NOT NULL
    );
    """,
    """
    CREATE VIRTUAL TABLE template_fts USING fts5(
        slug,
        name,
        description,
        category,
        nodes_text,
        tokenize='porter unicode61'
    );
    """,
]


def build_sqlite_bytes() -> tuple[bytes, dict[str, int]]:
    with tempfile.TemporaryDirectory() as tmp:
        db_file = Path(tmp) / "catalog.sqlite"
        conn = sqlite3.connect(str(db_file))
        try:
            cur = conn.cursor()
            for stmt in DDL_STATEMENTS:
                cur.execute(stmt)

            sorted_nodes = sorted(NODE_DEFS, key=lambda n: n["node_type"])
            sorted_creds = sorted(CREDENTIAL_TYPES, key=lambda c: c["credential_type"])
            sorted_templates = sorted(TEMPLATES, key=lambda t: t["id"])

            meta_rows = [
                ("schema_version", str(SCHEMA_VERSION)),
                ("bundle_version", BUNDLE_VERSION),
                ("source_version", SOURCE_VERSION),
                ("target_n8n_baseline", TARGET_N8N_BASELINE),
                ("extracted_at", FIXED_EXTRACTION_TIMESTAMP),
                ("node_count", str(len(sorted_nodes))),
                ("template_count", str(len(sorted_templates))),
            ]
            cur.executemany("INSERT INTO catalog_metadata(key, value) VALUES (?, ?);", meta_rows)

            version_rows_count = 0
            prop_rows_count = 0
            op_rows_count = 0

            for node in sorted_nodes:
                node_hash = blake3_hex(canonical_json(node).encode("utf-8"))
                cur.execute(
                    """
                    INSERT INTO node_types (
                        node_type, short_type, package_name, display_name, description,
                        category, development_style, default_version, is_versioned,
                        is_trigger, is_webhook, is_ai_tool, is_tool_variant, has_tool_variant,
                        tool_variant_of, native_priority, native_score, side_effect_class,
                        inputs_json, outputs_json, output_names_json, credentials_json, schema_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        node["node_type"],
                        node["short_type"],
                        node["package_name"],
                        node["display_name"],
                        node["description"],
                        node["category"],
                        node.get("development_style", "programmatic"),
                        node["default_version"],
                        1 if node.get("is_versioned", True) else 0,
                        1 if node.get("is_trigger", False) else 0,
                        1 if node.get("is_webhook", False) else 0,
                        1 if node.get("is_ai_tool", False) else 0,
                        1 if node.get("is_tool_variant", False) else 0,
                        1 if node.get("has_tool_variant", False) else 0,
                        node.get("tool_variant_of"),
                        int(node["native_priority"]),
                        int(node["native_score"]),
                        node["side_effect_class"],
                        canonical_json(node["inputs"]),
                        canonical_json(node["outputs"]),
                        canonical_json(node["output_names"]) if node.get("output_names") else None,
                        canonical_json(node.get("credentials", [])),
                        node_hash,
                    ),
                )

                for ver in node["versions"]:
                    ver_str = str(ver["version"])
                    ver_hash = blake3_hex(f"{node['node_type']}@{ver_str}:{node_hash}".encode("utf-8"))
                    cur.execute(
                        """
                        INSERT INTO node_versions (
                            node_type, type_version, numeric_version, is_default,
                            is_deprecated, breaking_notes, schema_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            node["node_type"],
                            ver_str,
                            float(ver["version"]),
                            1 if ver_str == node["default_version"] else 0,
                            1 if ver.get("deprecated", False) else 0,
                            ver.get("breaking_notes"),
                            ver_hash,
                        ),
                    )
                    version_rows_count += 1

                for idx, prop in enumerate(node.get("properties", [])):
                    cur.execute(
                        """
                        INSERT INTO node_properties (
                            node_type, type_version, prop_index, name, display_name,
                            prop_type, required, default_json, description,
                            options_json, display_options_json, expected_format_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            node["node_type"],
                            prop.get("type_version", node["default_version"]),
                            idx,
                            prop["name"],
                            prop["display_name"],
                            prop["type"],
                            1 if prop.get("required", False) else 0,
                            canonical_json(prop["default"]) if "default" in prop else None,
                            prop.get("description", ""),
                            canonical_json(prop["options"]) if "options" in prop else None,
                            canonical_json(prop["displayOptions"]) if "displayOptions" in prop else None,
                            canonical_json(prop["expectedFormat"]) if "expectedFormat" in prop else None,
                        ),
                    )
                    prop_rows_count += 1

                ops_text_parts: list[str] = []
                for op in node.get("operations", []):
                    cur.execute(
                        """
                        INSERT INTO node_operations (
                            node_type, resource, operation, display_name, description, action_label
                        ) VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (
                            node["node_type"],
                            op["resource"],
                            op["operation"],
                            op["display_name"],
                            op.get("description", ""),
                            op.get("action_label"),
                        ),
                    )
                    ops_text_parts.append(f"{op['resource']} {op['operation']} {op['display_name']}")
                    op_rows_count += 1

                cur.execute(
                    """
                    INSERT INTO node_fts (
                        node_type, short_type, display_name, category, description, operations_text, keywords
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        node["node_type"],
                        node["short_type"],
                        node["display_name"],
                        node["category"],
                        node["description"],
                        " | ".join(ops_text_parts),
                        " ".join(node.get("keywords", [])),
                    ),
                )

            for cred in sorted_creds:
                cur.execute(
                    """
                    INSERT INTO credential_types (
                        credential_type, display_name, documentation_url, auth_kind,
                        is_generic, required_fields_json, supported_nodes_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        cred["credential_type"],
                        cred["display_name"],
                        cred.get("documentation_url"),
                        cred["auth_kind"],
                        1 if cred.get("is_generic", False) else 0,
                        canonical_json(cred["required_fields"]),
                        canonical_json(cred["supported_nodes"]),
                    ),
                )

            for tmpl in sorted_templates:
                cur.execute(
                    """
                    INSERT INTO templates (
                        id, slug, name, description, category, complexity,
                        estimated_setup_minutes, nodes_used_json, required_credentials_json,
                        workflow_json, source_attribution
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        int(tmpl["id"]),
                        tmpl["slug"],
                        tmpl["name"],
                        tmpl["description"],
                        tmpl["category"],
                        tmpl["complexity"],
                        int(tmpl["estimated_setup_minutes"]),
                        canonical_json(tmpl["nodes_used"]),
                        canonical_json(tmpl["required_credentials"]),
                        canonical_json(tmpl["workflow"]),
                        tmpl["source_attribution"],
                    ),
                )
                cur.execute(
                    """
                    INSERT INTO template_fts (
                        slug, name, description, category, nodes_text
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        tmpl["slug"],
                        tmpl["name"],
                        tmpl["description"],
                        tmpl["category"],
                        " ".join(tmpl["nodes_used"]),
                    ),
                )

            # Optimize FTS5 indexes and compact deterministically into a clean single-file image.
            cur.execute("INSERT INTO node_fts(node_fts) VALUES ('optimize');")
            cur.execute("INSERT INTO template_fts(template_fts) VALUES ('optimize');")
            conn.commit()
            cur.execute("VACUUM;")
            conn.commit()

            counts = {
                "catalog_metadata": len(meta_rows),
                "node_types": len(sorted_nodes),
                "node_versions": version_rows_count,
                "node_properties": prop_rows_count,
                "node_operations": op_rows_count,
                "credential_types": len(sorted_creds),
                "node_fts": cur.execute("SELECT COUNT(*) FROM node_fts;").fetchone()[0],
                "templates": len(sorted_templates),
                "template_fts": cur.execute("SELECT COUNT(*) FROM template_fts;").fetchone()[0],
            }
        finally:
            conn.close()

        return db_file.read_bytes(), counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reproducible data/catalog.sqlite.zst and manifest.")
    parser.add_argument(
        "--out-dir",
        default="data",
        help="Output directory relative to workspace root (default: data)",
    )
    args = parser.parse_args()

    verify_blake3_self_test()

    repo_root = Path(__file__).resolve().parents[2]
    out_dir = (repo_root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sqlite_bytes, table_counts = build_sqlite_bytes()
    zst_bytes = compress_zstd(sqlite_bytes, level=19)

    sqlite_blake3 = blake3_hex(sqlite_bytes)
    sqlite_sha256 = hashlib.sha256(sqlite_bytes).hexdigest()
    zst_blake3 = blake3_hex(zst_bytes)
    zst_sha256 = hashlib.sha256(zst_bytes).hexdigest()

    bundle_path = out_dir / "catalog.sqlite.zst"
    manifest_path = out_dir / "catalog.manifest.json"

    bundle_path.write_bytes(zst_bytes)
    verification = verify_roundtrip_archive(bundle_path, sqlite_blake3, sqlite_sha256)

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "bundleVersion": BUNDLE_VERSION,
        "sourceVersion": SOURCE_VERSION,
        "sourceLicense": "MIT",
        "sourceRepository": "https://github.com/czlonkowski/n8n-mcp",
        "targetN8nBaseline": TARGET_N8N_BASELINE,
        "extractedAt": FIXED_EXTRACTION_TIMESTAMP,
        "bundleFile": "catalog.sqlite.zst",
        "blake3Hex": sqlite_blake3,
        "digests": {
            "decompressedSqliteBlake3": sqlite_blake3,
            "decompressedSqliteSha256": sqlite_sha256,
            "compressedZstBlake3": zst_blake3,
            "compressedZstSha256": zst_sha256,
        },
        "sizes": {
            "decompressedSqliteBytes": len(sqlite_bytes),
            "compressedZstBytes": len(zst_bytes),
        },
        "nodeCount": table_counts["node_types"],
        "templateCount": table_counts["templates"],
        "nativePriorityScale": {
            "1": "Native service integration or trigger node (highest priority)",
            "2": "Native data transformation / flow control node (Set, Filter, IF, Switch, Merge, etc.)",
            "3": "Generic HTTP Request or LangChain/AI cluster node",
            "4": "Code node (use only with 'Why Code:' rationale when native nodes cannot express logic)",
            "5": "Community or fallback node",
        },
        "tables": table_counts,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _display_path(target: Path) -> str:
        try:
            return os.path.relpath(target, repo_root)
        except ValueError:
            return str(target)

    print(
        json.dumps(
            {
                "status": "ok",
                "bundle": _display_path(bundle_path),
                "manifest": _display_path(manifest_path),
                "sqliteBytes": len(sqlite_bytes),
                "zstBytes": len(zst_bytes),
                "blake3Hex": sqlite_blake3,
                "compressedZstBlake3": zst_blake3,
                "compressedZstSha256": zst_sha256,
                "tables": table_counts,
                "verification": verification,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
