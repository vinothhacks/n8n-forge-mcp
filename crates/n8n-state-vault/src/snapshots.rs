//! Pre-write workflow draft snapshots using `XChaCha20-Poly1305` / `ChaCha20-Poly1305` AEAD,
//! `zstd` compression, `BLAKE3` integrity verification, secret stripping & default redaction,
//! per-principal key derivation, memory-only transient fallback, bounded retention, and TTL purge.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use n8n_graph::{NodeCredentialRef, WorkflowIr};
use n8n_types::{N8nError, N8nResult, redact_json_value, redact_str};
use rand::RngExt;
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::acl::{protect_state_dir, protect_state_file};

/// Mandatory V2 Section 9 & 16 disclaimer attached to every restored snapshot draft.
pub const RESTORE_SIDE_EFFECTS_DISCLAIMER: &str = "Restoring a workflow snapshot recovers draft configuration only. External side effects (sent webhooks, database writes, emails, messages, payments, credential changes, and execution history) are NOT reversed.";

/// Maximum decompressed snapshot JSON size (16 MiB) preventing decompression bombs.
const MAX_SNAPSHOT_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

/// Size of `XChaCha20-Poly1305` random nonce prepended to `.snap` blobs.
const XNONCE_LEN: usize = 24;

/// Storage backing used for a captured snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStorageMode {
    #[default]
    PersistentEncrypted,
    MemoryTransient,
}

impl SnapshotStorageMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PersistentEncrypted => "persistent_encrypted",
            Self::MemoryTransient => "memory_transient",
        }
    }

    fn from_db_str(s: &str) -> Self {
        if s == "memory_transient" {
            Self::MemoryTransient
        } else {
            Self::PersistentEncrypted
        }
    }
}

/// Snapshot metadata header persisted in SQLite (or memory) while encrypted payload lives in `snapshots/` (or memory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotHeader {
    pub snapshot_id: String,
    pub principal_id: String,
    pub instance: String,
    pub workflow_id: String,
    pub version_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default = "epoch_utc")]
    #[schemars(with = "String")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub plaintext_blake3_hex: String,
    #[serde(default)]
    pub ciphertext_blake3_hex: String,
    #[serde(default)]
    pub encrypted_sensitive_retention: bool,
    #[serde(default)]
    pub storage_mode: SnapshotStorageMode,
}

fn epoch_utc() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(Utc::now)
}

/// Result of verifying and restoring a workflow draft snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestoredSnapshot {
    pub header: SnapshotHeader,
    pub draft_workflow: WorkflowIr,
    pub integrity_verified: bool,
    pub disclaimer: String,
}

///Retention and TTL configuration for [`SnapshotVault`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRetentionPolicy {
    pub max_per_workflow: usize,
    pub max_total: usize,
    pub default_ttl_secs: i64,
}

impl Default for SnapshotRetentionPolicy {
    fn default() -> Self {
        Self {
            max_per_workflow: 10,
            max_total: 200,
            default_ttl_secs: 7 * 24 * 3600,
        }
    }
}

/// Key management source for snapshot AEAD encryption (V2 Section 9 & 10).
#[derive(Clone)]
pub enum SnapshotKeyProvider {
    /// Explicit caller-supplied 32-byte key (e.g. from OS keyring / DPAPI).
    ExplicitKey(Zeroizing<[u8; 32]>),
    /// Reads key material from an environment variable; falls back to memory-only transient mode if unset!
    FromEnvOrMemoryFallback { env_var: String },
    /// Loads (or generates) a 32-byte CSPRNG key in an OS ACL-protected file (`0600` / `icacls`) separate from `state.db`.
    ProtectedKeyFile { path: PathBuf },
    /// Memory-only transient key & storage (nothing written to disk; lost on process exit).
    MemoryOnlyTransient,
}

#[derive(Clone)]
struct ResolvedKeyMaterial {
    master_key: Zeroizing<[u8; 32]>,
    storage_mode: SnapshotStorageMode,
}

impl SnapshotKeyProvider {
    fn resolve(&self) -> N8nResult<ResolvedKeyMaterial> {
        match self {
            Self::ExplicitKey(k) => Ok(ResolvedKeyMaterial {
                master_key: k.clone(),
                storage_mode: SnapshotStorageMode::PersistentEncrypted,
            }),
            Self::FromEnvOrMemoryFallback { env_var } => {
                if let Ok(raw) = std::env::var(env_var) {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        let key = decode_or_derive_32byte_key(trimmed);
                        return Ok(ResolvedKeyMaterial {
                            master_key: key,
                            storage_mode: SnapshotStorageMode::PersistentEncrypted,
                        });
                    }
                }
                let mut ephemeral = Zeroizing::new([0u8; 32]);
                rand::rng().fill(ephemeral.as_mut());
                Ok(ResolvedKeyMaterial {
                    master_key: ephemeral,
                    storage_mode: SnapshotStorageMode::MemoryTransient,
                })
            }
            Self::ProtectedKeyFile { path } => {
                if path.exists() {
                    let raw = fs::read(path).map_err(|e| {
                        N8nError::config(format!(
                            "failed reading snapshot key file: {}",
                            redact_str(&e.to_string())
                        ))
                    })?;
                    let text = String::from_utf8_lossy(&raw);
                    let key = if raw.len() == 32 {
                        let mut arr = Zeroizing::new([0u8; 32]);
                        arr.copy_from_slice(&raw);
                        arr
                    } else {
                        decode_or_derive_32byte_key(text.trim())
                    };
                    let _ = protect_state_file(path)?;
                    Ok(ResolvedKeyMaterial {
                        master_key: key,
                        storage_mode: SnapshotStorageMode::PersistentEncrypted,
                    })
                } else {
                    if let Some(parent) = path.parent() {
                        protect_state_dir(parent)?;
                    }
                    let mut fresh = Zeroizing::new([0u8; 32]);
                    rand::rng().fill(fresh.as_mut());
                    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(fresh.as_ref()));
                    fs::write(path, encoded.as_bytes()).map_err(|e| {
                        N8nError::config(format!(
                            "failed writing protected snapshot key file: {}",
                            redact_str(&e.to_string())
                        ))
                    })?;
                    let _ = protect_state_file(path)?;
                    Ok(ResolvedKeyMaterial {
                        master_key: fresh,
                        storage_mode: SnapshotStorageMode::PersistentEncrypted,
                    })
                }
            }
            Self::MemoryOnlyTransient => {
                let mut ephemeral = Zeroizing::new([0u8; 32]);
                rand::rng().fill(ephemeral.as_mut());
                Ok(ResolvedKeyMaterial {
                    master_key: ephemeral,
                    storage_mode: SnapshotStorageMode::MemoryTransient,
                })
            }
        }
    }
}

fn decode_or_derive_32byte_key(raw: &str) -> Zeroizing<[u8; 32]> {
    if raw.len() == 64
        && let Some(hex_bytes) = decode_hex_32(raw)
    {
        return Zeroizing::new(hex_bytes);
    }
    if let Ok(decoded) = URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| BASE64_STD.decode(raw))
        && decoded.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Zeroizing::new(out);
    }
    Zeroizing::new(blake3::derive_key(
        "n8n-rs-mcp/v2/snapshot-master-key-kdf",
        raw.as_bytes(),
    ))
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte_str = hex.get(i * 2..i * 2 + 2)?;
        *slot = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(out)
}

/// Encrypts compressed workflow bytes with `ChaCha20-Poly1305` using a caller-provided 32-byte key and 12-byte nonce.
pub fn seal_snapshot_bytes(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> N8nResult<Vec<u8>> {
    let compressed = zstd::encode_all(plaintext, 3)
        .map_err(|e| N8nError::protocol(format!("snapshot zstd compression failed: {e}")))?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key_bytes));
    cipher
        .encrypt(&Nonce::from(*nonce_bytes), compressed.as_slice())
        .map_err(|_| N8nError::protocol("snapshot AEAD encryption failed"))
}

/// Decrypts and bounded-decompresses workflow bytes sealed with [`seal_snapshot_bytes`].
pub fn open_snapshot_bytes(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> N8nResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key_bytes));
    let compressed = cipher
        .decrypt(&Nonce::from(*nonce_bytes), ciphertext)
        .map_err(|_| {
            N8nError::protocol(
                "snapshot AEAD authentication failed (tampered key, nonce, or ciphertext)",
            )
        })?;
    bounded_zstd_decompress(&compressed)
}

fn bounded_zstd_decompress(compressed: &[u8]) -> N8nResult<Vec<u8>> {
    let decoder = zstd::Decoder::new(compressed)
        .map_err(|e| N8nError::protocol(format!("snapshot zstd init failed: {e}")))?;
    let mut limited = decoder.take(MAX_SNAPSHOT_DECOMPRESSED_BYTES + 1);
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| N8nError::protocol(format!("snapshot zstd decompression failed: {e}")))?;
    if out.len() as u64 > MAX_SNAPSHOT_DECOMPRESSED_BYTES {
        return Err(N8nError::payload_too_large(
            MAX_SNAPSHOT_DECOMPRESSED_BYTES,
            out.len() as u64,
            "snapshot_decompress",
        ));
    }
    Ok(out)
}

/// Authenticated snapshot vault managing SQLite metadata + separate AEAD `.snap` files (or transient memory fallback).
pub struct SnapshotVault {
    conn: Connection,
    snapshots_dir: Option<PathBuf>,
    key_material: ResolvedKeyMaterial,
    retention: SnapshotRetentionPolicy,
    memory_blobs: HashMap<String, Vec<u8>>,
}

impl SnapshotVault {
    /// Opens an in-memory transient `SnapshotVault` (useful for tests or keyless sessions).
    pub fn open_in_memory(
        key_provider: &SnapshotKeyProvider,
        retention: SnapshotRetentionPolicy,
    ) -> N8nResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| N8nError::config(format!("failed opening in-memory snapshot DB: {e}")))?;
        let resolved = key_provider.resolve()?;
        let vault = Self {
            conn,
            snapshots_dir: None,
            key_material: ResolvedKeyMaterial {
                master_key: resolved.master_key,
                storage_mode: SnapshotStorageMode::MemoryTransient,
            },
            retention,
            memory_blobs: HashMap::new(),
        };
        vault.init_schema()?;
        Ok(vault)
    }

    /// Opens a persistent `SnapshotVault` at `vault_root` (`state.db` + `snapshots/` directory),
    /// automatically downgrading to memory-only transient blobs if `key_provider` resolves to transient mode!
    pub fn open_at_dir(
        vault_root: &Path,
        key_provider: &SnapshotKeyProvider,
        retention: SnapshotRetentionPolicy,
    ) -> N8nResult<Self> {
        protect_state_dir(vault_root)?;
        let resolved = key_provider.resolve()?;

        let (conn, snapshots_dir) =
            if resolved.storage_mode == SnapshotStorageMode::PersistentEncrypted {
                let db_path = vault_root.join("state.db");
                let c = Connection::open(&db_path).map_err(|e| {
                    N8nError::config(format!("failed opening state.db for snapshots: {e}"))
                })?;
                let _ = protect_state_file(&db_path)?;
                let snap_dir = vault_root.join("snapshots");
                protect_state_dir(&snap_dir)?;
                (c, Some(snap_dir))
            } else {
                let c = Connection::open_in_memory().map_err(|e| {
                    N8nError::config(format!("failed opening transient snapshot DB: {e}"))
                })?;
                (c, None)
            };

        let vault = Self {
            conn,
            snapshots_dir,
            key_material: resolved,
            retention,
            memory_blobs: HashMap::new(),
        };
        vault.init_schema()?;
        Ok(vault)
    }

    /// Returns the active [`SnapshotStorageMode`] (`PersistentEncrypted` vs `MemoryTransient`).
    #[must_use]
    pub const fn storage_mode(&self) -> SnapshotStorageMode {
        self.key_material.storage_mode
    }

    fn init_schema(&self) -> N8nResult<()> {
        self.conn
            .execute_batch(
                r"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA secure_delete = ON;

                CREATE TABLE IF NOT EXISTS snapshot_headers (
                    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id TEXT NOT NULL UNIQUE,
                    principal_id TEXT NOT NULL,
                    instance TEXT NOT NULL,
                    project_id TEXT,
                    workflow_id TEXT NOT NULL,
                    version_hash TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER,
                    plaintext_blake3_hex TEXT NOT NULL,
                    ciphertext_blake3_hex TEXT NOT NULL,
                    encrypted_sensitive_retention INTEGER NOT NULL,
                    storage_mode TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_snapshots_wf
                    ON snapshot_headers(principal_id, instance, workflow_id, created_at_ms DESC);
                ",
            )
            .map_err(|e| {
                N8nError::config(format!("failed initializing snapshot_headers table: {e}"))
            })
    }

    /// Captures an AEAD-encrypted (`XChaCha20-Poly1305` + `zstd` + `BLAKE3`) pre-write snapshot of `workflow`.
    /// Strips raw credential secret fields unconditionally and redacts sensitive parameters unless
    /// `encrypted_sensitive_retention == true`.
    pub fn capture_snapshot(
        &mut self,
        principal_id: &str,
        instance: &str,
        project_id: Option<&str>,
        workflow: &WorkflowIr,
        encrypted_sensitive_retention: bool,
    ) -> N8nResult<SnapshotHeader> {
        self.capture_snapshot_at(
            principal_id,
            instance,
            project_id,
            workflow,
            encrypted_sensitive_retention,
            Utc::now(),
        )
    }

    pub fn capture_snapshot_at(
        &mut self,
        principal_id: &str,
        instance: &str,
        project_id: Option<&str>,
        workflow: &WorkflowIr,
        encrypted_sensitive_retention: bool,
        now: DateTime<Utc>,
    ) -> N8nResult<SnapshotHeader> {
        let wf_id = workflow
            .id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                N8nError::validation(
                    instance,
                    vec!["workflow `id` is required to capture snapshot".to_owned()],
                    "cannot snapshot workflow without `id`",
                )
            })?
            .to_owned();

        let sanitized_wf = sanitize_workflow_for_snapshot(workflow, encrypted_sensitive_retention);
        let version_hash = sanitized_wf.canonical_version_hash();
        let plaintext_bytes = serde_json::to_vec(&sanitized_wf)
            .map_err(|e| N8nError::protocol(format!("snapshot serialize error: {e}")))?;

        let plaintext_blake3_hex = blake3::hash(&plaintext_bytes).to_hex().to_string();
        let snapshot_id = format!("snap_{}", Uuid::now_v7().simple());

        let aad = build_snapshot_aad(
            &snapshot_id,
            principal_id,
            instance,
            project_id,
            &wf_id,
            &version_hash,
        );
        let subkey = derive_principal_subkey(&self.key_material.master_key, principal_id, instance);

        let compressed = zstd::encode_all(plaintext_bytes.as_slice(), 3)
            .map_err(|e| N8nError::protocol(format!("snapshot zstd compression failed: {e}")))?;

        let mut xnonce_bytes = [0u8; XNONCE_LEN];
        rand::rng().fill(&mut xnonce_bytes);
        let cipher = XChaCha20Poly1305::new(&Key::from(*subkey));
        let ct = cipher
            .encrypt(
                &XNonce::from(xnonce_bytes),
                Payload {
                    msg: compressed.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| N8nError::protocol("snapshot XChaCha20-Poly1305 encryption failed"))?;

        let mut blob = Vec::with_capacity(XNONCE_LEN + ct.len());
        blob.extend_from_slice(&xnonce_bytes);
        blob.extend_from_slice(&ct);
        let ciphertext_blake3_hex = blake3::hash(&blob).to_hex().to_string();

        if let Some(ref dir) = self.snapshots_dir {
            let file_path = dir.join(format!("{snapshot_id}.snap"));
            fs::write(&file_path, &blob).map_err(|e| {
                N8nError::protocol(format!(
                    "failed writing encrypted snapshot blob: {}",
                    redact_str(&e.to_string())
                ))
            })?;
            let _ = protect_state_file(&file_path)?;
        } else {
            self.memory_blobs.insert(snapshot_id.clone(), blob);
        }

        let expires_at = (self.retention.default_ttl_secs > 0)
            .then(|| now + Duration::seconds(self.retention.default_ttl_secs));

        let header = SnapshotHeader {
            snapshot_id,
            principal_id: principal_id.to_owned(),
            instance: instance.to_owned(),
            workflow_id: wf_id.clone(),
            version_hash,
            project_id: project_id.map(str::to_owned),
            created_at: now,
            expires_at,
            plaintext_blake3_hex,
            ciphertext_blake3_hex,
            encrypted_sensitive_retention,
            storage_mode: self.key_material.storage_mode,
        };

        self.conn
            .execute(
                "INSERT INTO snapshot_headers (
                    snapshot_id, principal_id, instance, project_id, workflow_id, version_hash,
                    created_at_ms, expires_at_ms, plaintext_blake3_hex, ciphertext_blake3_hex,
                    encrypted_sensitive_retention, storage_mode
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    header.snapshot_id,
                    header.principal_id,
                    header.instance,
                    header.project_id,
                    header.workflow_id,
                    header.version_hash,
                    header.created_at.timestamp_millis(),
                    header.expires_at.map(|t| t.timestamp_millis()),
                    header.plaintext_blake3_hex,
                    header.ciphertext_blake3_hex,
                    i32::from(header.encrypted_sensitive_retention),
                    header.storage_mode.as_str(),
                ],
            )
            .map_err(|e| N8nError::protocol(format!("failed inserting snapshot header: {e}")))?;

        self.enforce_retention(principal_id, instance, &wf_id)?;
        Ok(header)
    }

    /// Restores and cryptographically verifies a snapshot draft for `(principal_id, instance, snapshot_id)`.
    pub fn restore_snapshot(
        &self,
        principal_id: &str,
        instance: &str,
        snapshot_id: &str,
    ) -> N8nResult<RestoredSnapshot> {
        self.restore_snapshot_at(principal_id, instance, snapshot_id, Utc::now())
    }

    pub fn restore_snapshot_at(
        &self,
        principal_id: &str,
        instance: &str,
        snapshot_id: &str,
        now: DateTime<Utc>,
    ) -> N8nResult<RestoredSnapshot> {
        let header = self.load_header(snapshot_id)?.ok_or_else(|| {
            N8nError::not_found_or_concealed(instance, snapshot_id, "snapshot not found")
        })?;

        if header.principal_id != principal_id || header.instance != instance {
            return Err(N8nError::forbidden(
                instance,
                Some("snapshot:restore".to_owned()),
                "snapshot belongs to a different principal or instance",
            ));
        }

        if let Some(exp) = header.expires_at
            && now > exp
        {
            return Err(N8nError::validation(
                instance,
                vec!["snapshot TTL has expired".to_owned()],
                "cannot restore expired snapshot",
            ));
        }

        let blob = if let Some(ref dir) = self.snapshots_dir {
            let file_path = dir.join(format!("{}.snap", header.snapshot_id));
            fs::read(&file_path).map_err(|e| {
                N8nError::protocol(format!(
                    "failed reading snapshot blob: {}",
                    redact_str(&e.to_string())
                ))
            })?
        } else {
            self.memory_blobs
                .get(&header.snapshot_id)
                .cloned()
                .ok_or_else(|| {
                    N8nError::not_found_or_concealed(
                        instance,
                        snapshot_id,
                        "transient memory snapshot blob missing",
                    )
                })?
        };

        if blob.len() <= XNONCE_LEN {
            return Err(N8nError::protocol(
                "snapshot blob truncated (missing XChaCha20-Poly1305 nonce/tag)",
            ));
        }

        // 1. Verify ciphertext BLAKE3 hash prior to AEAD decryption.
        let observed_ct_hash = blake3::hash(&blob).to_hex().to_string();
        if observed_ct_hash != header.ciphertext_blake3_hex {
            return Err(N8nError::protocol(
                "snapshot ciphertext BLAKE3 integrity check failed (tampered blob)",
            ));
        }

        // 2. Decrypt with per-principal subkey + AAD binding all header identity fields.
        let mut xnonce_bytes = [0u8; XNONCE_LEN];
        xnonce_bytes.copy_from_slice(&blob[..XNONCE_LEN]);
        let ciphertext = &blob[XNONCE_LEN..];

        let aad = build_snapshot_aad(
            &header.snapshot_id,
            &header.principal_id,
            &header.instance,
            header.project_id.as_deref(),
            &header.workflow_id,
            &header.version_hash,
        );
        let subkey = derive_principal_subkey(&self.key_material.master_key, principal_id, instance);
        let cipher = XChaCha20Poly1305::new(&Key::from(*subkey));
        let compressed = cipher
            .decrypt(
                &XNonce::from(xnonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| {
                N8nError::protocol(
                    "snapshot XChaCha20-Poly1305 AEAD verification failed (tampered ciphertext or header metadata)",
                )
            })?;

        // 3. Bounded zstd decompression + plaintext BLAKE3 verification.
        let plaintext_bytes = bounded_zstd_decompress(&compressed)?;
        let observed_pt_hash = blake3::hash(&plaintext_bytes).to_hex().to_string();
        if observed_pt_hash != header.plaintext_blake3_hex {
            return Err(N8nError::protocol(
                "snapshot plaintext BLAKE3 digest mismatch",
            ));
        }

        let mut draft_workflow: WorkflowIr =
            serde_json::from_slice(&plaintext_bytes).map_err(|e| {
                N8nError::protocol(format!("failed deserializing restored snapshot IR: {e}"))
            })?;

        // Force restored workflow into inactive draft posture (never silently overwrite live active state!).
        draft_workflow.active = false;
        draft_workflow.active_version_id = None;

        Ok(RestoredSnapshot {
            header,
            draft_workflow,
            integrity_verified: true,
            disclaimer: RESTORE_SIDE_EFFECTS_DISCLAIMER.to_owned(),
        })
    }

    /// Lists snapshot headers for `(principal_id, instance, workflow_id)` newest first.
    pub fn list_snapshots(
        &self,
        principal_id: &str,
        instance: &str,
        workflow_id: &str,
    ) -> N8nResult<Vec<SnapshotHeader>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT snapshot_id, principal_id, instance, project_id, workflow_id, version_hash,
                        created_at_ms, expires_at_ms, plaintext_blake3_hex, ciphertext_blake3_hex,
                        encrypted_sensitive_retention, storage_mode
                 FROM snapshot_headers
                 WHERE principal_id = ?1 AND instance = ?2 AND workflow_id = ?3
                 ORDER BY created_at_ms DESC, row_id DESC",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let iter = stmt
            .query_map(params![principal_id, instance, workflow_id], map_header_row)
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let mut out = Vec::new();
        for item in iter {
            out.push(item.map_err(|e| N8nError::protocol(e.to_string()))?);
        }
        Ok(out)
    }

    /// Purges all expired snapshots as of `now`, removing both SQLite headers and `.snap` blobs.
    pub fn purge_expired(&mut self, now: DateTime<Utc>) -> N8nResult<usize> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT snapshot_id FROM snapshot_headers WHERE expires_at_ms IS NOT NULL AND expires_at_ms < ?1",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let ids: Vec<String> = stmt
            .query_map(params![now.timestamp_millis()], |r| r.get::<_, String>(0))
            .map_err(|e| N8nError::protocol(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| N8nError::protocol(e.to_string()))?;
        drop(stmt);

        for id in &ids {
            self.delete_snapshot_by_id(id)?;
        }
        Ok(ids.len())
    }

    fn enforce_retention(
        &mut self,
        principal_id: &str,
        instance: &str,
        workflow_id: &str,
    ) -> N8nResult<()> {
        if self.retention.max_per_workflow > 0 {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT snapshot_id FROM snapshot_headers
                     WHERE principal_id = ?1 AND instance = ?2 AND workflow_id = ?3
                     ORDER BY created_at_ms DESC, row_id DESC",
                )
                .map_err(|e| N8nError::protocol(e.to_string()))?;
            let wf_ids: Vec<String> = stmt
                .query_map(params![principal_id, instance, workflow_id], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(|e| N8nError::protocol(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| N8nError::protocol(e.to_string()))?;
            drop(stmt);

            for stale_id in wf_ids.into_iter().skip(self.retention.max_per_workflow) {
                self.delete_snapshot_by_id(&stale_id)?;
            }
        }

        if self.retention.max_total > 0 {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT snapshot_id FROM snapshot_headers
                     ORDER BY created_at_ms DESC, row_id DESC",
                )
                .map_err(|e| N8nError::protocol(e.to_string()))?;
            let all_ids: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| N8nError::protocol(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| N8nError::protocol(e.to_string()))?;
            drop(stmt);

            for stale_id in all_ids.into_iter().skip(self.retention.max_total) {
                self.delete_snapshot_by_id(&stale_id)?;
            }
        }

        Ok(())
    }

    fn delete_snapshot_by_id(&mut self, snapshot_id: &str) -> N8nResult<()> {
        self.conn
            .execute(
                "DELETE FROM snapshot_headers WHERE snapshot_id = ?1",
                params![snapshot_id],
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;
        self.memory_blobs.remove(snapshot_id);
        if let Some(ref dir) = self.snapshots_dir {
            let file_path = dir.join(format!("{snapshot_id}.snap"));
            if file_path.exists() {
                let _ = fs::remove_file(file_path);
            }
        }
        Ok(())
    }

    fn load_header(&self, snapshot_id: &str) -> N8nResult<Option<SnapshotHeader>> {
        self.conn
            .query_row(
                "SELECT snapshot_id, principal_id, instance, project_id, workflow_id, version_hash,
                        created_at_ms, expires_at_ms, plaintext_blake3_hex, ciphertext_blake3_hex,
                        encrypted_sensitive_retention, storage_mode
                 FROM snapshot_headers WHERE snapshot_id = ?1",
                params![snapshot_id],
                map_header_row,
            )
            .optional()
            .map_err(|e| N8nError::protocol(e.to_string()))
    }
}

fn map_header_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SnapshotHeader> {
    let created_ms: i64 = row.get(6)?;
    let expires_ms: Option<i64> = row.get(7)?;
    let created_at = DateTime::<Utc>::from_timestamp_millis(created_ms).unwrap_or_else(epoch_utc);
    let expires_at = expires_ms.and_then(DateTime::<Utc>::from_timestamp_millis);
    let storage_str: String = row.get(11)?;

    Ok(SnapshotHeader {
        snapshot_id: row.get(0)?,
        principal_id: row.get(1)?,
        instance: row.get(2)?,
        project_id: row.get(3)?,
        workflow_id: row.get(4)?,
        version_hash: row.get(5)?,
        created_at,
        expires_at,
        plaintext_blake3_hex: row.get(8)?,
        ciphertext_blake3_hex: row.get(9)?,
        encrypted_sensitive_retention: row.get::<_, i64>(10)? != 0,
        storage_mode: SnapshotStorageMode::from_db_str(&storage_str),
    })
}

fn derive_principal_subkey(
    master_key: &[u8; 32],
    principal_id: &str,
    instance: &str,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(master_key);
    hasher.update(b"n8n-rs-mcp/v2/snapshot-principal-subkey|");
    hasher.update(&(principal_id.len() as u64).to_le_bytes());
    hasher.update(principal_id.as_bytes());
    hasher.update(b"|");
    hasher.update(&(instance.len() as u64).to_le_bytes());
    hasher.update(instance.as_bytes());
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn build_snapshot_aad(
    snapshot_id: &str,
    principal_id: &str,
    instance: &str,
    project_id: Option<&str>,
    workflow_id: &str,
    version_hash: &str,
) -> Vec<u8> {
    format!(
        "v2|{snapshot_id}|{principal_id}|{instance}|{}|{workflow_id}|{version_hash}",
        project_id.unwrap_or("<none>")
    )
    .into_bytes()
}

fn sanitize_workflow_for_snapshot(
    workflow: &WorkflowIr,
    encrypted_sensitive_retention: bool,
) -> WorkflowIr {
    let mut cleaned = workflow.clone();

    for node in &mut cleaned.nodes {
        // Unconditionally strip any extra/secret fields inside `node.credentials`, keeping ONLY `id` and `name`.
        if let Some(ref mut cred_map) = node.credentials {
            let mut safe_creds = IndexMap::with_capacity(cred_map.len());
            for (cred_type, cred_ref) in cred_map.iter() {
                safe_creds.insert(
                    redact_str(cred_type),
                    NodeCredentialRef {
                        id: cred_ref.id.as_deref().map(redact_str),
                        name: redact_str(&cred_ref.name),
                        extra: IndexMap::new(),
                    },
                );
            }
            *cred_map = safe_creds;
        }

        if !encrypted_sensitive_retention {
            node.parameters = redact_json_value(&node.parameters);
            let mut safe_node_extra = IndexMap::with_capacity(node.extra.len());
            for (k, v) in &node.extra {
                if n8n_types::is_sensitive_key(k) {
                    safe_node_extra.insert(
                        k.clone(),
                        serde_json::Value::String("[REDACTED]".to_owned()),
                    );
                } else {
                    safe_node_extra.insert(k.clone(), redact_json_value(v));
                }
            }
            node.extra = safe_node_extra;
        }
    }

    if !encrypted_sensitive_retention {
        if let Some(ref mut pins) = cleaned.pin_data {
            for val in pins.values_mut() {
                *val = redact_json_value(val);
            }
        }
        cleaned.settings = redact_json_value(&cleaned.settings);
        if let Some(ref mut meta) = cleaned.meta {
            *meta = redact_json_value(meta);
        }
        let mut safe_wf_extra = IndexMap::with_capacity(cleaned.extra.len());
        for (k, v) in &cleaned.extra {
            if n8n_types::is_sensitive_key(k) {
                safe_wf_extra.insert(
                    k.clone(),
                    serde_json::Value::String("[REDACTED]".to_owned()),
                );
            } else {
                safe_wf_extra.insert(k.clone(), redact_json_value(v));
            }
        }
        cleaned.extra = safe_wf_extra;
    }

    cleaned
}
