//! Append-only `BLAKE3` hash-chained SQLite + JSONL operation & audit journal implementing the
//! V2 Section 9 state machine (`Planned -> Previewed -> UserApproved -> Preparing -> Writing ->
//! Verifying -> Verified | Partial | Conflict | UnknownResult | Failed`), tamper verification,
//! durable batch codemod checkpoints, durable test cleanup leases, and recursive secret redaction.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use n8n_graph::canonical_blake3_json_hex;
use n8n_types::{N8nError, N8nResult, redact_json_value, redact_str};
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::acl::{protect_state_dir, protect_state_file};

/// Genesis `prev_hash_hex` anchoring sequence #1 of the hash chain.
pub const GENESIS_PREV_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Default maximum workflows allowed in a single bulk codemod batch (V2 Section 5).
pub const DEFAULT_MAX_BATCH_WORKFLOWS: usize = 20;

/// Exact V2 Section 9 per-workflow operation lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Planned,
    Previewed,
    UserApproved,
    Preparing,
    Writing,
    Verifying,
    Verified,
    Partial,
    Conflict,
    UnknownResult,
    Failed,
}

impl JournalState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Previewed => "previewed",
            Self::UserApproved => "user_approved",
            Self::Preparing => "preparing",
            Self::Writing => "writing",
            Self::Verifying => "verifying",
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Conflict => "conflict",
            Self::UnknownResult => "unknown_result",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn from_str_opt(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "planned" => Some(Self::Planned),
            "previewed" => Some(Self::Previewed),
            "user_approved" | "userapproved" => Some(Self::UserApproved),
            "preparing" => Some(Self::Preparing),
            "writing" => Some(Self::Writing),
            "verifying" => Some(Self::Verifying),
            "verified" => Some(Self::Verified),
            "partial" => Some(Self::Partial),
            "conflict" => Some(Self::Conflict),
            "unknown_result" | "unknownresult" => Some(Self::UnknownResult),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Enforces legal transitions along the V2 Section 9 operation state machine.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Planned => matches!(
                next,
                Self::Previewed | Self::Preparing | Self::Conflict | Self::Failed
            ),
            Self::Previewed => matches!(
                next,
                Self::UserApproved | Self::Preparing | Self::Conflict | Self::Failed
            ),
            Self::UserApproved => {
                matches!(next, Self::Preparing | Self::Conflict | Self::Failed)
            }
            Self::Preparing => matches!(next, Self::Writing | Self::Conflict | Self::Failed),
            Self::Writing => matches!(
                next,
                Self::Verifying
                    | Self::UnknownResult
                    | Self::Partial
                    | Self::Conflict
                    | Self::Failed
            ),
            Self::Verifying | Self::UnknownResult => matches!(
                next,
                Self::Verifying
                    | Self::Verified
                    | Self::Partial
                    | Self::Conflict
                    | Self::UnknownResult
                    | Self::Failed
            ),
            Self::Verified | Self::Partial | Self::Conflict | Self::Failed => false,
        }
    }

    /// Valid starting states for a newly created operation record.
    #[must_use]
    pub const fn is_valid_initial_state(self) -> bool {
        matches!(self, Self::Planned | Self::Previewed)
    }

    /// Returns `true` when crash/timeout reconciliation should inspect this operation on startup.
    #[must_use]
    pub const fn needs_startup_reconciliation(self) -> bool {
        matches!(self, Self::Writing | Self::Verifying | Self::UnknownResult)
    }
}

/// Append-only `BLAKE3` hash-chained journal record persisted to SQLite + optional JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JournalRecord {
    pub sequence: u64,
    pub prev_hash_hex: String,
    pub entry_hash_hex: String,
    pub operation_id: String,
    pub state: String,
    #[schemars(with = "String")]
    pub recorded_at: DateTime<Utc>,
    #[serde(default)]
    pub principal_id: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_version_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_version_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops_hash: Option<String>,
    #[serde(default)]
    pub details: Value,
}

impl JournalRecord {
    /// Compact chain hash helper preserved for Phase 1 compatibility.
    #[must_use]
    pub fn compute_chain_hash(prev_hash_hex: &str, operation_id: &str, state: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev_hash_hex.as_bytes());
        hasher.update(b"|");
        hasher.update(operation_id.as_bytes());
        hasher.update(b"|");
        hasher.update(state.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Computes the full domain-separated `BLAKE3` tamper-evident hash covering all record fields and canonicalized `details`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn compute_full_entry_hash(
        sequence: u64,
        prev_hash_hex: &str,
        operation_id: &str,
        state: &str,
        recorded_at_ms: i64,
        principal_id: &str,
        instance_id: &str,
        workflow_id: Option<&str>,
        action: &str,
        base_version_hash: Option<&str>,
        resulting_version_hash: Option<&str>,
        ops_hash: Option<&str>,
        redacted_details: &Value,
    ) -> String {
        let details_digest =
            canonical_blake3_json_hex(redacted_details, "n8n-rs-mcp/v2/journal-details-hash");
        let mut hasher = blake3::Hasher::new_derive_key("n8n-rs-mcp/v2/journal-entry-chain");
        hasher.update(&sequence.to_le_bytes());
        update_lp(&mut hasher, prev_hash_hex.as_bytes());
        update_lp(&mut hasher, operation_id.as_bytes());
        update_lp(&mut hasher, state.as_bytes());
        hasher.update(&recorded_at_ms.to_le_bytes());
        update_lp(&mut hasher, principal_id.as_bytes());
        update_lp(&mut hasher, instance_id.as_bytes());
        update_lp(&mut hasher, workflow_id.unwrap_or("<none>").as_bytes());
        update_lp(&mut hasher, action.as_bytes());
        update_lp(
            &mut hasher,
            base_version_hash.unwrap_or("<none>").as_bytes(),
        );
        update_lp(
            &mut hasher,
            resulting_version_hash.unwrap_or("<none>").as_bytes(),
        );
        update_lp(&mut hasher, ops_hash.unwrap_or("<none>").as_bytes());
        update_lp(&mut hasher, details_digest.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

fn update_lp(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Input arguments for appending a state transition to [`OperationJournal`].
#[derive(Debug, Clone)]
pub struct JournalTransitionInput {
    pub operation_id: String,
    pub next_state: JournalState,
    pub principal_id: String,
    pub instance_id: String,
    pub workflow_id: Option<String>,
    pub action: String,
    pub base_version_hash: Option<String>,
    pub resulting_version_hash: Option<String>,
    pub ops_hash: Option<String>,
    pub details: Value,
}

/// Tamper or corruption error returned by [`OperationJournal::verify_hash_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalTamperError {
    #[error("journal storage read failed: {message}")]
    StorageFailure { message: String },

    #[error("journal sequence gap at expected={expected_sequence}, actual={actual_sequence}")]
    SequenceGap {
        expected_sequence: u64,
        actual_sequence: u64,
    },

    #[error(
        "journal prev_hash mismatch at sequence {sequence}: expected `{expected}`, found `{actual}`"
    )]
    PrevHashMismatch {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error(
        "journal entry_hash mismatch at sequence {sequence}: recomputed `{expected}`, stored `{actual}`"
    )]
    EntryHashMismatch {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error("JSONL audit mirror malformed at line {line_number}: {reason}")]
    MalformedJsonlEntry { line_number: usize, reason: String },

    #[error("JSONL audit mirror diverged from SQLite journal: {reason}")]
    JsonlMirrorMismatch { reason: String },
}

/// Per-workflow status inside a durable bulk codemod batch (V2 Section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchCheckpointStatus {
    Pending,
    InProgress,
    Verified,
    Partial,
    Conflict,
    UnknownResult,
    Failed,
    SkippedHalted,
    RestoredDraft,
}

impl BatchCheckpointStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Conflict => "conflict",
            Self::UnknownResult => "unknown_result",
            Self::Failed => "failed",
            Self::SkippedHalted => "skipped_halted",
            Self::RestoredDraft => "restored_draft",
        }
    }

    fn from_db_str(s: &str) -> Self {
        match s {
            "in_progress" => Self::InProgress,
            "verified" => Self::Verified,
            "partial" => Self::Partial,
            "conflict" => Self::Conflict,
            "unknown_result" => Self::UnknownResult,
            "failed" => Self::Failed,
            "skipped_halted" => Self::SkippedHalted,
            "restored_draft" => Self::RestoredDraft,
            _ => Self::Pending,
        }
    }

    const fn is_critical_halt_trigger(self) -> bool {
        matches!(self, Self::Conflict | Self::UnknownResult | Self::Failed)
    }
}

/// Per-workflow checkpoint row inside a bulk codemod batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchTargetCheckpoint {
    pub batch_id: String,
    pub workflow_id: String,
    pub expected_version_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    pub status: BatchCheckpointStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_version_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_note: Option<String>,
    #[schemars(with = "String")]
    pub updated_at: DateTime<Utc>,
}

/// Durable multi-workflow codemod plan with fixed approved target workflow IDs and stop-on-error state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchPlanRecord {
    pub batch_id: String,
    pub principal_id: String,
    pub instance_id: String,
    pub action_summary: String,
    pub ops_hash: String,
    pub target_workflow_ids: Vec<String>,
    pub halted_on_error: bool,
    #[schemars(with = "String")]
    pub created_at: DateTime<Utc>,
    #[schemars(with = "String")]
    pub updated_at: DateTime<Utc>,
    pub checkpoints: Vec<BatchTargetCheckpoint>,
}

/// Lifecycle state of a durable test cleanup lease (V2 Section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupLeaseState {
    AcquiredPreCreate,
    ActiveResourceCreated,
    CleanedVerified,
    CleanupRequired,
}

impl CleanupLeaseState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcquiredPreCreate => "acquired_pre_create",
            Self::ActiveResourceCreated => "active_resource_created",
            Self::CleanedVerified => "cleaned_verified",
            Self::CleanupRequired => "cleanup_required",
        }
    }

    fn from_db_str(s: &str) -> Self {
        match s {
            "active_resource_created" => Self::ActiveResourceCreated,
            "cleaned_verified" => Self::CleanedVerified,
            "cleanup_required" => Self::CleanupRequired,
            _ => Self::AcquiredPreCreate,
        }
    }
}

/// Durable pre-creation cleanup lease for crash-safe startup reconciliation of staging test resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CleanupLeaseRecord {
    pub lease_id: String,
    pub principal_id: String,
    pub instance_id: String,
    pub resource_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    pub workflow_name_tag: String,
    pub state: CleanupLeaseState,
    #[schemars(with = "String")]
    pub acquired_at: DateTime<Utc>,
    #[schemars(with = "String")]
    pub expires_at: DateTime<Utc>,
    #[schemars(with = "String")]
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Append-only `BLAKE3` hash-chained SQLite + JSONL audit journal, batch checkpoint store, and cleanup lease store.
pub struct OperationJournal {
    conn: Connection,
    jsonl_path: Option<PathBuf>,
}

impl OperationJournal {
    /// Opens an in-memory `OperationJournal`.
    pub fn open_in_memory() -> N8nResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| N8nError::config(format!("failed opening in-memory journal: {e}")))?;
        let journal = Self {
            conn,
            jsonl_path: None,
        };
        journal.init_schema()?;
        Ok(journal)
    }

    /// Opens a persistent SQLite + optional JSONL audit mirror journal with current-user-only OS ACLs.
    pub fn open_files(db_path: &Path, jsonl_path: Option<&Path>) -> N8nResult<Self> {
        if let Some(parent) = db_path.parent() {
            protect_state_dir(parent)?;
        }
        let conn = Connection::open(db_path)
            .map_err(|e| N8nError::config(format!("failed opening journal SQLite file: {e}")))?;
        let _ = protect_state_file(db_path)?;

        let owned_jsonl = if let Some(jp) = jsonl_path {
            if let Some(parent) = jp.parent() {
                protect_state_dir(parent)?;
            }
            if !jp.exists() {
                fs::write(jp, b"").map_err(|e| {
                    N8nError::config(format!(
                        "failed creating journal JSONL file: {}",
                        redact_str(&e.to_string())
                    ))
                })?;
            }
            let _ = protect_state_file(jp)?;
            Some(jp.to_path_buf())
        } else {
            None
        };

        let journal = Self {
            conn,
            jsonl_path: owned_jsonl,
        };
        journal.init_schema()?;
        Ok(journal)
    }

    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    fn init_schema(&self) -> N8nResult<()> {
        self.conn
            .execute_batch(
                r"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA foreign_keys = ON;
                PRAGMA secure_delete = ON;

                CREATE TABLE IF NOT EXISTS journal_entries (
                    sequence INTEGER PRIMARY KEY,
                    prev_hash_hex TEXT NOT NULL,
                    entry_hash_hex TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    recorded_at_ms INTEGER NOT NULL,
                    principal_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    workflow_id TEXT,
                    action TEXT NOT NULL,
                    base_version_hash TEXT,
                    resulting_version_hash TEXT,
                    ops_hash TEXT,
                    details_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_journal_op
                    ON journal_entries(operation_id, sequence DESC);

                CREATE TABLE IF NOT EXISTS batch_plans (
                    batch_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    action_summary TEXT NOT NULL,
                    ops_hash TEXT NOT NULL,
                    target_ids_json TEXT NOT NULL,
                    halted_on_error INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS batch_checkpoints (
                    batch_id TEXT NOT NULL REFERENCES batch_plans(batch_id) ON DELETE CASCADE,
                    workflow_id TEXT NOT NULL,
                    expected_version_hash TEXT NOT NULL,
                    snapshot_id TEXT,
                    status TEXT NOT NULL,
                    resulting_version_hash TEXT,
                    diagnostic_note TEXT,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (batch_id, workflow_id)
                );

                CREATE TABLE IF NOT EXISTS cleanup_leases (
                    lease_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    resource_kind TEXT NOT NULL,
                    workflow_id TEXT,
                    workflow_name_tag TEXT NOT NULL,
                    state TEXT NOT NULL,
                    acquired_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    note TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cleanup_leases_state
                    ON cleanup_leases(state, instance_id);
                ",
            )
            .map_err(|e| N8nError::config(format!("failed initializing journal schema: {e}")))
    }

    /// Validates state transition rules, recursively redacts all inputs, and appends a `BLAKE3` hash-chained record.
    pub fn append_transition(&mut self, input: JournalTransitionInput) -> N8nResult<JournalRecord> {
        self.append_transition_at(input, Utc::now())
    }

    pub fn append_transition_at(
        &mut self,
        input: JournalTransitionInput,
        now: DateTime<Utc>,
    ) -> N8nResult<JournalRecord> {
        let safe_op_id = redact_str(input.operation_id.trim());
        if safe_op_id.is_empty() {
            return Err(N8nError::validation(
                &input.instance_id,
                vec!["`operation_id` must not be empty".to_owned()],
                "journal requires a non-empty operation_id",
            ));
        }

        // 1. Validate V2 Section 9 state machine for `operation_id`.
        if let Some(prev_state_str) = self.latest_operation_state_str(&safe_op_id)? {
            if let Some(prev_state) = JournalState::from_str_opt(&prev_state_str)
                && !prev_state.can_transition_to(input.next_state)
            {
                return Err(N8nError::validation(
                    &input.instance_id,
                    vec![format!(
                        "illegal journal state transition `{}` -> `{}` for `{safe_op_id}`",
                        prev_state.as_str(),
                        input.next_state.as_str()
                    )],
                    "invalid operation journal state transition",
                ));
            }
        } else if !input.next_state.is_valid_initial_state() {
            return Err(N8nError::validation(
                &input.instance_id,
                vec![format!(
                    "new operation `{safe_op_id}` must start in `planned` or `previewed`, got `{}`",
                    input.next_state.as_str()
                )],
                "invalid initial operation journal state",
            ));
        }

        let safe_principal = redact_str(&input.principal_id);
        let safe_instance = redact_str(&input.instance_id);
        let safe_wf_id = input.workflow_id.as_deref().map(redact_str);
        let safe_action = redact_str(&input.action);
        let safe_base_hash = input.base_version_hash.as_deref().map(redact_str);
        let safe_res_hash = input.resulting_version_hash.as_deref().map(redact_str);
        let safe_ops_hash = input.ops_hash.as_deref().map(redact_str);
        let safe_details = redact_json_value(&input.details);
        let details_json =
            serde_json::to_string(&safe_details).unwrap_or_else(|_| "null".to_owned());

        // Normalize timestamp to millisecond precision so SQLite & JSONL representations match bit-for-bit.
        let recorded_at_ms = now.timestamp_millis();
        let recorded_at = DateTime::<Utc>::from_timestamp_millis(recorded_at_ms).unwrap_or(now);

        let tx = self
            .conn
            .transaction()
            .map_err(|e| N8nError::protocol(format!("journal transaction begin failed: {e}")))?;

        let last_head: Option<(i64, String)> = tx
            .query_row(
                "SELECT sequence, entry_hash_hex FROM journal_entries ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| N8nError::protocol(format!("journal head query failed: {e}")))?;

        #[allow(clippy::cast_sign_loss)]
        let (sequence, prev_hash_hex) = match last_head {
            Some((seq, hash)) => ((seq.max(0) as u64) + 1, hash),
            None => (1_u64, GENESIS_PREV_HASH_HEX.to_owned()),
        };

        let state_str = input.next_state.as_str().to_owned();
        let entry_hash_hex = JournalRecord::compute_full_entry_hash(
            sequence,
            &prev_hash_hex,
            &safe_op_id,
            &state_str,
            recorded_at_ms,
            &safe_principal,
            &safe_instance,
            safe_wf_id.as_deref(),
            &safe_action,
            safe_base_hash.as_deref(),
            safe_res_hash.as_deref(),
            safe_ops_hash.as_deref(),
            &safe_details,
        );

        #[allow(clippy::cast_possible_wrap)]
        tx.execute(
            "INSERT INTO journal_entries (
                sequence, prev_hash_hex, entry_hash_hex, operation_id, state, recorded_at_ms,
                principal_id, instance_id, workflow_id, action, base_version_hash,
                resulting_version_hash, ops_hash, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                sequence as i64,
                prev_hash_hex,
                entry_hash_hex,
                safe_op_id,
                state_str,
                recorded_at_ms,
                safe_principal,
                safe_instance,
                safe_wf_id,
                safe_action,
                safe_base_hash,
                safe_res_hash,
                safe_ops_hash,
                details_json,
            ],
        )
        .map_err(|e| N8nError::protocol(format!("journal insert failed: {e}")))?;

        let record = JournalRecord {
            sequence,
            prev_hash_hex,
            entry_hash_hex,
            operation_id: safe_op_id,
            state: state_str,
            recorded_at,
            principal_id: safe_principal,
            instance_id: safe_instance,
            workflow_id: safe_wf_id,
            action: safe_action,
            base_version_hash: safe_base_hash,
            resulting_version_hash: safe_res_hash,
            ops_hash: safe_ops_hash,
            details: safe_details,
        };

        if let Some(ref jp) = self.jsonl_path {
            let line = serde_json::to_string(&record)
                .map_err(|e| N8nError::protocol(format!("journal JSONL serialize failed: {e}")))?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(jp)
                .map_err(|e| {
                    N8nError::protocol(format!(
                        "journal JSONL open failed: {}",
                        redact_str(&e.to_string())
                    ))
                })?;
            writeln!(file, "{line}").map_err(|e| {
                N8nError::protocol(format!(
                    "journal JSONL write failed: {}",
                    redact_str(&e.to_string())
                ))
            })?;
            file.sync_data().map_err(|e| {
                N8nError::protocol(format!(
                    "journal JSONL fsync failed: {}",
                    redact_str(&e.to_string())
                ))
            })?;
        }

        tx.commit()
            .map_err(|e| N8nError::protocol(format!("journal transaction commit failed: {e}")))?;

        Ok(record)
    }

    /// Verifies the entire `BLAKE3` hash chain in SQLite (and JSONL mirror parity if configured),
    /// returning the count of verified entries or a specific [`JournalTamperError`].
    pub fn verify_hash_chain(&self) -> Result<usize, JournalTamperError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sequence, prev_hash_hex, entry_hash_hex, operation_id, state, recorded_at_ms,
                        principal_id, instance_id, workflow_id, action, base_version_hash,
                        resulting_version_hash, ops_hash, details_json
                 FROM journal_entries ORDER BY sequence ASC",
            )
            .map_err(|e| JournalTamperError::StorageFailure {
                message: redact_str(&e.to_string()),
            })?;

        let rows = stmt.query_map([], map_journal_row).map_err(|e| {
            JournalTamperError::StorageFailure {
                message: redact_str(&e.to_string()),
            }
        })?;

        let mut expected_prev = GENESIS_PREV_HASH_HEX.to_owned();
        let mut sqlite_hashes = Vec::new();

        for (expected_seq, row_res) in (1_u64..).zip(rows) {
            let record = row_res.map_err(|e| JournalTamperError::StorageFailure {
                message: redact_str(&e.to_string()),
            })?;

            if record.sequence != expected_seq {
                return Err(JournalTamperError::SequenceGap {
                    expected_sequence: expected_seq,
                    actual_sequence: record.sequence,
                });
            }

            if record.prev_hash_hex != expected_prev {
                return Err(JournalTamperError::PrevHashMismatch {
                    sequence: record.sequence,
                    expected: expected_prev,
                    actual: record.prev_hash_hex,
                });
            }

            let recomputed = JournalRecord::compute_full_entry_hash(
                record.sequence,
                &record.prev_hash_hex,
                &record.operation_id,
                &record.state,
                record.recorded_at.timestamp_millis(),
                &record.principal_id,
                &record.instance_id,
                record.workflow_id.as_deref(),
                &record.action,
                record.base_version_hash.as_deref(),
                record.resulting_version_hash.as_deref(),
                record.ops_hash.as_deref(),
                &record.details,
            );

            if recomputed != record.entry_hash_hex {
                return Err(JournalTamperError::EntryHashMismatch {
                    sequence: record.sequence,
                    expected: recomputed,
                    actual: record.entry_hash_hex,
                });
            }

            expected_prev = record.entry_hash_hex.clone();
            sqlite_hashes.push((record.sequence, record.entry_hash_hex));
        }

        if let Some(ref jp) = self.jsonl_path {
            let raw_jsonl =
                fs::read_to_string(jp).map_err(|e| JournalTamperError::StorageFailure {
                    message: redact_str(&e.to_string()),
                })?;

            let mut jsonl_hashes = Vec::new();
            let mut j_expected_seq = 1_u64;
            let mut j_expected_prev = GENESIS_PREV_HASH_HEX.to_owned();

            for (idx, line) in raw_jsonl.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec: JournalRecord = serde_json::from_str(line).map_err(|e| {
                    JournalTamperError::MalformedJsonlEntry {
                        line_number: idx + 1,
                        reason: redact_str(&e.to_string()),
                    }
                })?;

                if rec.sequence != j_expected_seq {
                    return Err(JournalTamperError::SequenceGap {
                        expected_sequence: j_expected_seq,
                        actual_sequence: rec.sequence,
                    });
                }
                if rec.prev_hash_hex != j_expected_prev {
                    return Err(JournalTamperError::PrevHashMismatch {
                        sequence: rec.sequence,
                        expected: j_expected_prev,
                        actual: rec.prev_hash_hex,
                    });
                }
                let recomputed = JournalRecord::compute_full_entry_hash(
                    rec.sequence,
                    &rec.prev_hash_hex,
                    &rec.operation_id,
                    &rec.state,
                    rec.recorded_at.timestamp_millis(),
                    &rec.principal_id,
                    &rec.instance_id,
                    rec.workflow_id.as_deref(),
                    &rec.action,
                    rec.base_version_hash.as_deref(),
                    rec.resulting_version_hash.as_deref(),
                    rec.ops_hash.as_deref(),
                    &rec.details,
                );
                if recomputed != rec.entry_hash_hex {
                    return Err(JournalTamperError::EntryHashMismatch {
                        sequence: rec.sequence,
                        expected: recomputed,
                        actual: rec.entry_hash_hex,
                    });
                }

                j_expected_prev = rec.entry_hash_hex.clone();
                jsonl_hashes.push((rec.sequence, rec.entry_hash_hex));
                j_expected_seq += 1;
            }

            if jsonl_hashes != sqlite_hashes {
                return Err(JournalTamperError::JsonlMirrorMismatch {
                    reason: format!(
                        "SQLite has {} verified entries while JSONL mirror has {} entries (or differing hashes)",
                        sqlite_hashes.len(),
                        jsonl_hashes.len()
                    ),
                });
            }
        }

        Ok(sqlite_hashes.len())
    }

    /// Returns all records recorded for a specific `operation_id` in chronological order.
    pub fn operation_history(&self, operation_id: &str) -> N8nResult<Vec<JournalRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sequence, prev_hash_hex, entry_hash_hex, operation_id, state, recorded_at_ms,
                        principal_id, instance_id, workflow_id, action, base_version_hash,
                        resulting_version_hash, ops_hash, details_json
                 FROM journal_entries WHERE operation_id = ?1 ORDER BY sequence ASC",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let iter = stmt
            .query_map(params![operation_id], map_journal_row)
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let mut out = Vec::new();
        for r in iter {
            out.push(r.map_err(|e| N8nError::protocol(e.to_string()))?);
        }
        Ok(out)
    }

    /// Lists operations whose latest recorded state requires startup/timeout reconciliation
    /// (`writing`, `verifying`, or `unknown_result`).
    pub fn list_uncertain_operations(
        &self,
        instance_id: Option<&str>,
    ) -> N8nResult<Vec<JournalRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT j.sequence, j.prev_hash_hex, j.entry_hash_hex, j.operation_id, j.state,
                        j.recorded_at_ms, j.principal_id, j.instance_id, j.workflow_id, j.action,
                        j.base_version_hash, j.resulting_version_hash, j.ops_hash, j.details_json
                 FROM journal_entries j
                 INNER JOIN (
                     SELECT operation_id, MAX(sequence) AS max_seq
                     FROM journal_entries
                     GROUP BY operation_id
                 ) latest ON latest.operation_id = j.operation_id AND latest.max_seq = j.sequence
                 ORDER BY j.sequence ASC",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let iter = stmt
            .query_map([], map_journal_row)
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let mut out = Vec::new();
        for r in iter {
            let rec = r.map_err(|e| N8nError::protocol(e.to_string()))?;
            if instance_id.is_some_and(|inst| rec.instance_id != inst) {
                continue;
            }
            if JournalState::from_str_opt(&rec.state)
                .is_some_and(JournalState::needs_startup_reconciliation)
            {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Creates a durable bulk codemod batch plan with a fixed approved target workflow set (enforcing batch cap).
    pub fn create_batch_plan(
        &mut self,
        principal_id: &str,
        instance_id: &str,
        action_summary: &str,
        ops_hash: &str,
        targets: &[(String, String)],
        max_batch_cap: Option<usize>,
    ) -> N8nResult<BatchPlanRecord> {
        let cap = max_batch_cap.unwrap_or(DEFAULT_MAX_BATCH_WORKFLOWS);
        if targets.is_empty() {
            return Err(N8nError::validation(
                instance_id,
                vec!["batch target list cannot be empty".to_owned()],
                "bulk codemod requires at least 1 target workflow",
            ));
        }
        if targets.len() > cap {
            return Err(N8nError::policy_blocked(
                "bulk_codemod",
                n8n_types::RiskLevel::R4,
                "batch_cap",
                format!(
                    "batch target count ({}) exceeds maximum permitted batch cap ({cap})",
                    targets.len()
                ),
                Some(format!(
                    "Narrow selector to <= {cap} workflows and re-preview."
                )),
            ));
        }

        let mut unique_ids = HashSet::with_capacity(targets.len());
        let mut target_ids_vec = Vec::with_capacity(targets.len());
        for (wf_id, _) in targets {
            let clean_id = redact_str(wf_id.trim());
            if clean_id.is_empty() || !unique_ids.insert(clean_id.clone()) {
                return Err(N8nError::validation(
                    instance_id,
                    vec!["duplicate or empty workflow_id in batch plan".to_owned()],
                    "invalid batch target list",
                ));
            }
            target_ids_vec.push(clean_id);
        }

        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let norm_now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap_or(now);
        let batch_id = format!("batch_{}", Uuid::now_v7().simple());
        let safe_principal = redact_str(principal_id);
        let safe_instance = redact_str(instance_id);
        let safe_summary = redact_str(action_summary);
        let safe_ops_hash = redact_str(ops_hash);
        let target_ids_json = serde_json::to_string(&target_ids_vec)
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        self.conn
            .execute(
                "INSERT INTO batch_plans (
                    batch_id, principal_id, instance_id, action_summary, ops_hash,
                    target_ids_json, halted_on_error, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
                params![
                    batch_id,
                    safe_principal,
                    safe_instance,
                    safe_summary,
                    safe_ops_hash,
                    target_ids_json,
                    now_ms,
                    now_ms,
                ],
            )
            .map_err(|e| N8nError::protocol(format!("failed inserting batch plan: {e}")))?;

        let mut checkpoints = Vec::with_capacity(targets.len());
        for (wf_id, expected_hash) in targets {
            let clean_wf = redact_str(wf_id.trim());
            let clean_hash = redact_str(expected_hash);
            self.conn
                .execute(
                    "INSERT INTO batch_checkpoints (
                        batch_id, workflow_id, expected_version_hash, snapshot_id, status,
                        resulting_version_hash, diagnostic_note, updated_at_ms
                     ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, ?5)",
                    params![
                        batch_id,
                        clean_wf,
                        clean_hash,
                        BatchCheckpointStatus::Pending.as_str(),
                        now_ms,
                    ],
                )
                .map_err(|e| {
                    N8nError::protocol(format!("failed inserting batch checkpoint: {e}"))
                })?;

            checkpoints.push(BatchTargetCheckpoint {
                batch_id: batch_id.clone(),
                workflow_id: clean_wf,
                expected_version_hash: clean_hash,
                snapshot_id: None,
                status: BatchCheckpointStatus::Pending,
                resulting_version_hash: None,
                diagnostic_note: None,
                updated_at: norm_now,
            });
        }

        // Also anchor the batch plan creation inside the hash-chained audit journal!
        let _ = self.append_transition_at(
            JournalTransitionInput {
                operation_id: batch_id.clone(),
                next_state: JournalState::Planned,
                principal_id: safe_principal.clone(),
                instance_id: safe_instance.clone(),
                workflow_id: None,
                action: "bulk_codemod.plan".to_owned(),
                base_version_hash: None,
                resulting_version_hash: None,
                ops_hash: Some(safe_ops_hash.clone()),
                details: json!({
                    "targetCount": target_ids_vec.len(),
                    "targetWorkflowIds": target_ids_vec,
                    "summary": safe_summary,
                }),
            },
            norm_now,
        )?;

        Ok(BatchPlanRecord {
            batch_id,
            principal_id: safe_principal,
            instance_id: safe_instance,
            action_summary: safe_summary,
            ops_hash: safe_ops_hash,
            target_workflow_ids: target_ids_vec,
            halted_on_error: false,
            created_at: norm_now,
            updated_at: norm_now,
            checkpoints,
        })
    }

    /// Updates a single workflow's checkpoint within a batch plan.
    /// Rejects selector widening (unknown `workflow_id`), refuses starting new `InProgress` writes once
    /// `halted_on_error` is tripped, and automatically halts the batch on critical failures!
    #[allow(clippy::too_many_arguments)]
    pub fn update_batch_checkpoint(
        &mut self,
        batch_id: &str,
        workflow_id: &str,
        status: BatchCheckpointStatus,
        snapshot_id: Option<&str>,
        resulting_version_hash: Option<&str>,
        diagnostic_note: Option<&str>,
    ) -> N8nResult<BatchPlanRecord> {
        let plan = self.get_batch_plan(batch_id)?.ok_or_else(|| {
            N8nError::not_found_or_concealed("local", batch_id, "batch plan not found")
        })?;

        if !plan.target_workflow_ids.iter().any(|w| w == workflow_id) {
            return Err(N8nError::policy_blocked(
                "bulk_codemod.checkpoint",
                n8n_types::RiskLevel::R4,
                "fixed_target_set",
                format!(
                    "selector widening prohibited: workflow `{}` was not in approved batch `{batch_id}`",
                    redact_str(workflow_id)
                ),
                None,
            ));
        }

        if plan.halted_on_error && status == BatchCheckpointStatus::InProgress {
            return Err(N8nError::policy_blocked(
                "bulk_codemod.checkpoint",
                n8n_types::RiskLevel::R4,
                "halt_on_critical_error",
                format!(
                    "batch `{batch_id}` is halted after an earlier critical error; further writes are blocked"
                ),
                None,
            ));
        }

        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let safe_snap = snapshot_id.map(redact_str);
        let safe_res_hash = resulting_version_hash.map(redact_str);
        let safe_note = diagnostic_note.map(redact_str);

        self.conn
            .execute(
                "UPDATE batch_checkpoints
                 SET status = ?1,
                     snapshot_id = COALESCE(?2, snapshot_id),
                     resulting_version_hash = COALESCE(?3, resulting_version_hash),
                     diagnostic_note = COALESCE(?4, diagnostic_note),
                     updated_at_ms = ?5
                 WHERE batch_id = ?6 AND workflow_id = ?7",
                params![
                    status.as_str(),
                    safe_snap,
                    safe_res_hash,
                    safe_note,
                    now_ms,
                    batch_id,
                    workflow_id,
                ],
            )
            .map_err(|e| N8nError::protocol(format!("failed updating batch checkpoint: {e}")))?;

        if status.is_critical_halt_trigger() {
            self.conn
                .execute(
                    "UPDATE batch_plans SET halted_on_error = 1, updated_at_ms = ?1 WHERE batch_id = ?2",
                    params![now_ms, batch_id],
                )
                .map_err(|e| N8nError::protocol(e.to_string()))?;

            // Mark remaining `pending` targets as `skipped_halted`!
            self.conn
                .execute(
                    "UPDATE batch_checkpoints SET status = ?1, updated_at_ms = ?2
                     WHERE batch_id = ?3 AND status = ?4",
                    params![
                        BatchCheckpointStatus::SkippedHalted.as_str(),
                        now_ms,
                        batch_id,
                        BatchCheckpointStatus::Pending.as_str(),
                    ],
                )
                .map_err(|e| N8nError::protocol(e.to_string()))?;
        } else {
            self.conn
                .execute(
                    "UPDATE batch_plans SET updated_at_ms = ?1 WHERE batch_id = ?2",
                    params![now_ms, batch_id],
                )
                .map_err(|e| N8nError::protocol(e.to_string()))?;
        }

        self.get_batch_plan(batch_id)?
            .ok_or_else(|| N8nError::protocol("batch plan disappeared after update"))
    }

    /// Loads a [`BatchPlanRecord`] and all per-workflow checkpoints.
    pub fn get_batch_plan(&self, batch_id: &str) -> N8nResult<Option<BatchPlanRecord>> {
        let header_opt = self
            .conn
            .query_row(
                "SELECT batch_id, principal_id, instance_id, action_summary, ops_hash,
                        target_ids_json, halted_on_error, created_at_ms, updated_at_ms
                 FROM batch_plans WHERE batch_id = ?1",
                params![batch_id],
                |r| {
                    let targets_str: String = r.get(5)?;
                    let created_ms: i64 = r.get(7)?;
                    let updated_ms: i64 = r.get(8)?;
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        targets_str,
                        r.get::<_, i64>(6)? != 0,
                        created_ms,
                        updated_ms,
                    ))
                },
            )
            .optional()
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let Some((
            b_id,
            principal_id,
            instance_id,
            action_summary,
            ops_hash,
            targets_str,
            halted_on_error,
            created_ms,
            updated_ms,
        )) = header_opt
        else {
            return Ok(None);
        };

        let target_workflow_ids: Vec<String> =
            serde_json::from_str(&targets_str).unwrap_or_default();

        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_id, workflow_id, expected_version_hash, snapshot_id, status,
                        resulting_version_hash, diagnostic_note, updated_at_ms
                 FROM batch_checkpoints WHERE batch_id = ?1 ORDER BY rowid ASC",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let checkpoints = stmt
            .query_map(params![batch_id], |r| {
                let status_str: String = r.get(4)?;
                let up_ms: i64 = r.get(7)?;
                Ok(BatchTargetCheckpoint {
                    batch_id: r.get(0)?,
                    workflow_id: r.get(1)?,
                    expected_version_hash: r.get(2)?,
                    snapshot_id: r.get(3)?,
                    status: BatchCheckpointStatus::from_db_str(&status_str),
                    resulting_version_hash: r.get(5)?,
                    diagnostic_note: r.get(6)?,
                    updated_at: DateTime::<Utc>::from_timestamp_millis(up_ms)
                        .unwrap_or_else(Utc::now),
                })
            })
            .map_err(|e| N8nError::protocol(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        Ok(Some(BatchPlanRecord {
            batch_id: b_id,
            principal_id,
            instance_id,
            action_summary,
            ops_hash,
            target_workflow_ids,
            halted_on_error,
            created_at: DateTime::<Utc>::from_timestamp_millis(created_ms).unwrap_or_else(Utc::now),
            updated_at: DateTime::<Utc>::from_timestamp_millis(updated_ms).unwrap_or_else(Utc::now),
            checkpoints,
        }))
    }

    /// Persists a durable cleanup lease BEFORE creating any temporary staging test workflow/trigger (V2 Section 8).
    pub fn acquire_cleanup_lease(
        &mut self,
        principal_id: &str,
        instance_id: &str,
        resource_kind: &str,
        workflow_name_tag: &str,
        ttl_secs: i64,
    ) -> N8nResult<CleanupLeaseRecord> {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let norm_now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap_or(now);
        let exp = norm_now + Duration::seconds(ttl_secs.max(1));
        let lease_id = format!("lease_{}", Uuid::now_v7().simple());

        let record = CleanupLeaseRecord {
            lease_id: lease_id.clone(),
            principal_id: redact_str(principal_id),
            instance_id: redact_str(instance_id),
            resource_kind: redact_str(resource_kind),
            workflow_id: None,
            workflow_name_tag: redact_str(workflow_name_tag),
            state: CleanupLeaseState::AcquiredPreCreate,
            acquired_at: norm_now,
            expires_at: exp,
            updated_at: norm_now,
            note: None,
        };

        self.conn
            .execute(
                "INSERT INTO cleanup_leases (
                    lease_id, principal_id, instance_id, resource_kind, workflow_id,
                    workflow_name_tag, state, acquired_at_ms, expires_at_ms, updated_at_ms, note
                 ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    record.lease_id,
                    record.principal_id,
                    record.instance_id,
                    record.resource_kind,
                    record.workflow_name_tag,
                    record.state.as_str(),
                    record.acquired_at.timestamp_millis(),
                    record.expires_at.timestamp_millis(),
                    record.updated_at.timestamp_millis(),
                ],
            )
            .map_err(|e| N8nError::protocol(format!("failed writing cleanup lease: {e}")))?;

        Ok(record)
    }

    /// Binds the created remote `workflow_id` onto an existing pre-create cleanup lease.
    pub fn bind_cleanup_lease_workflow(
        &mut self,
        lease_id: &str,
        workflow_id: &str,
        note: Option<&str>,
    ) -> N8nResult<CleanupLeaseRecord> {
        let now_ms = Utc::now().timestamp_millis();
        let updated = self
            .conn
            .execute(
                "UPDATE cleanup_leases
                 SET workflow_id = ?1, state = ?2, updated_at_ms = ?3, note = ?4
                 WHERE lease_id = ?5",
                params![
                    redact_str(workflow_id),
                    CleanupLeaseState::ActiveResourceCreated.as_str(),
                    now_ms,
                    note.map(redact_str),
                    lease_id,
                ],
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        if updated == 0 {
            return Err(N8nError::not_found_or_concealed(
                "local",
                lease_id,
                "cleanup lease not found",
            ));
        }
        self.get_cleanup_lease(lease_id)?
            .ok_or_else(|| N8nError::protocol("cleanup lease missing after update"))
    }

    /// Marks a cleanup lease either `CleanedVerified` (when read-back confirms deletion) or `CleanupRequired` (on failure!).
    pub fn complete_cleanup_lease(
        &mut self,
        lease_id: &str,
        verified_deleted: bool,
        note: Option<&str>,
    ) -> N8nResult<CleanupLeaseRecord> {
        let target_state = if verified_deleted {
            CleanupLeaseState::CleanedVerified
        } else {
            CleanupLeaseState::CleanupRequired
        };
        let now_ms = Utc::now().timestamp_millis();
        let updated = self
            .conn
            .execute(
                "UPDATE cleanup_leases SET state = ?1, updated_at_ms = ?2, note = ?3 WHERE lease_id = ?4",
                params![
                    target_state.as_str(),
                    now_ms,
                    note.map(redact_str),
                    lease_id,
                ],
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        if updated == 0 {
            return Err(N8nError::not_found_or_concealed(
                "local",
                lease_id,
                "cleanup lease not found",
            ));
        }
        self.get_cleanup_lease(lease_id)?
            .ok_or_else(|| N8nError::protocol("cleanup lease missing after completion"))
    }

    /// Lists all uncleaned/abandoned cleanup leases (`acquired_pre_create`, `active_resource_created`, `cleanup_required`)
    /// for crash-safe startup reconciliation (`n8n-rs-mcp reconcile`).
    pub fn list_pending_cleanup_leases(
        &self,
        instance_id: Option<&str>,
    ) -> N8nResult<Vec<CleanupLeaseRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT lease_id, principal_id, instance_id, resource_kind, workflow_id,
                        workflow_name_tag, state, acquired_at_ms, expires_at_ms, updated_at_ms, note
                 FROM cleanup_leases
                 WHERE state != ?1
                 ORDER BY acquired_at_ms ASC",
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let iter = stmt
            .query_map(
                params![CleanupLeaseState::CleanedVerified.as_str()],
                map_lease_row,
            )
            .map_err(|e| N8nError::protocol(e.to_string()))?;

        let mut out = Vec::new();
        for item in iter {
            let rec = item.map_err(|e| N8nError::protocol(e.to_string()))?;
            if instance_id.is_some_and(|inst| rec.instance_id != inst) {
                continue;
            }
            out.push(rec);
        }
        Ok(out)
    }

    pub fn get_cleanup_lease(&self, lease_id: &str) -> N8nResult<Option<CleanupLeaseRecord>> {
        self.conn
            .query_row(
                "SELECT lease_id, principal_id, instance_id, resource_kind, workflow_id,
                        workflow_name_tag, state, acquired_at_ms, expires_at_ms, updated_at_ms, note
                 FROM cleanup_leases WHERE lease_id = ?1",
                params![lease_id],
                map_lease_row,
            )
            .optional()
            .map_err(|e| N8nError::protocol(e.to_string()))
    }

    fn latest_operation_state_str(&self, operation_id: &str) -> N8nResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT state FROM journal_entries WHERE operation_id = ?1 ORDER BY sequence DESC LIMIT 1",
                params![operation_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| N8nError::protocol(e.to_string()))
    }
}

fn map_journal_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JournalRecord> {
    let seq_i64: i64 = row.get(0)?;
    let recorded_ms: i64 = row.get(5)?;
    let details_str: String = row.get(13)?;
    let details: Value = serde_json::from_str(&details_str).unwrap_or(Value::Null);

    #[allow(clippy::cast_sign_loss)]
    Ok(JournalRecord {
        sequence: seq_i64.max(0) as u64,
        prev_hash_hex: row.get(1)?,
        entry_hash_hex: row.get(2)?,
        operation_id: row.get(3)?,
        state: row.get(4)?,
        recorded_at: DateTime::<Utc>::from_timestamp_millis(recorded_ms).unwrap_or_else(Utc::now),
        principal_id: row.get(6)?,
        instance_id: row.get(7)?,
        workflow_id: row.get(8)?,
        action: row.get(9)?,
        base_version_hash: row.get(10)?,
        resulting_version_hash: row.get(11)?,
        ops_hash: row.get(12)?,
        details,
    })
}

fn map_lease_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CleanupLeaseRecord> {
    let state_str: String = row.get(6)?;
    let acq_ms: i64 = row.get(7)?;
    let exp_ms: i64 = row.get(8)?;
    let upd_ms: i64 = row.get(9)?;
    Ok(CleanupLeaseRecord {
        lease_id: row.get(0)?,
        principal_id: row.get(1)?,
        instance_id: row.get(2)?,
        resource_kind: row.get(3)?,
        workflow_id: row.get(4)?,
        workflow_name_tag: row.get(5)?,
        state: CleanupLeaseState::from_db_str(&state_str),
        acquired_at: DateTime::<Utc>::from_timestamp_millis(acq_ms).unwrap_or_else(Utc::now),
        expires_at: DateTime::<Utc>::from_timestamp_millis(exp_ms).unwrap_or_else(Utc::now),
        updated_at: DateTime::<Utc>::from_timestamp_millis(upd_ms).unwrap_or_else(Utc::now),
        note: row.get(10)?,
    })
}
