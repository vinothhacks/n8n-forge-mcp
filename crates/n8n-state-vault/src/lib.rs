#![forbid(unsafe_code)]
//! Protected per-user OS ACL state vault (`%LOCALAPPDATA%\n8n-rs-mcp` / `0700`), `rusqlite` WAL +
//! FTS5 sanitized live workflow index, `XChaCha20-Poly1305` / `ChaCha20-Poly1305` AEAD workflow
//! draft snapshots, and `BLAKE3` hash-chained SQLite + JSONL operation & audit journal.

pub mod acl;
pub mod index;
pub mod journal;
pub mod snapshots;

pub use acl::{
    AclInspection, VaultStatus, check_user_state_dir, default_state_dir,
    ensure_protected_state_dir, inspect_path_acl, protect_state_dir, protect_state_file,
};
pub use index::{
    CachePolicy, DEFAULT_INDEX_TTL_SECS, EphemeralParamMatch, FindNodesPage, FindNodesQuery,
    GraphVariant, IndexWorkflowMetadata, IndexedNodeHit, IndexedPartitionReceipt, ParamPredicate,
    SanitizedWorkflowIndex, ephemeral_scan_parameters,
};
pub use journal::{
    BatchCheckpointStatus, BatchPlanRecord, BatchTargetCheckpoint, CleanupLeaseRecord,
    CleanupLeaseState, DEFAULT_MAX_BATCH_WORKFLOWS, GENESIS_PREV_HASH_HEX, JournalRecord,
    JournalState, JournalTamperError, JournalTransitionInput, OperationJournal,
};
pub use snapshots::{
    RESTORE_SIDE_EFFECTS_DISCLAIMER, RestoredSnapshot, SnapshotHeader, SnapshotKeyProvider,
    SnapshotRetentionPolicy, SnapshotStorageMode, SnapshotVault, open_snapshot_bytes,
    seal_snapshot_bytes,
};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use chrono::{Duration, Utc};
    use n8n_graph::WorkflowIr;
    use rusqlite::params;
    use serde_json::json;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;

    fn build_sample_workflow_with_secrets(id: &str, name: &str, active: bool) -> WorkflowIr {
        WorkflowIr::from_json_value(json!({
            "id": id,
            "name": name,
            "active": active,
            "isArchived": false,
            "versionId": "ver_draft_10",
            "activeVersionId": if active { json!("ver_live_09") } else { Value::Null },
            "nodes": [
                {
                    "id": "n_trig",
                    "name": "Order Intake Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "typeVersion": 2,
                    "position": [200, 300],
                    "parameters": {
                        "path": "orders/v1"
                    }
                },
                {
                    "id": "n_http",
                    "name": "Deprecated Billing HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "typeVersion": 4.1,
                    "position": [480, 300],
                    "parameters": {
                        "url": "https://api.deprecated.internal/v1/charge?api_key=TOPSECRET_QUERY_TOKEN_999",
                        "body": "={{ $('Order Intake Webhook').item.json.amount + ':' + $vars.BILLING_REGION + ':' + $env.TENANT_CODE }}",
                        "headers": {
                            "parameters": [
                                {
                                    "name": "Authorization",
                                    "value": "Bearer SUPER_SECRET_BEARER_TOKEN_ABCDEF123456"
                                }
                            ]
                        }
                    },
                    "credentials": {
                        "httpHeaderAuth": {
                            "id": "cred_hdr_1",
                            "name": "Billing Header Cred",
                            "data": "FORBIDDEN_SMUGGLED_RAW_CREDENTIAL_SECRET"
                        }
                    }
                },
                {
                    "id": "n_disabled",
                    "name": "Legacy Archiver",
                    "type": "n8n-nodes-base.postgres",
                    "typeVersion": 2,
                    "disabled": true,
                    "retryOnFail": true,
                    "position": [760, 300],
                    "parameters": {
                        "connectionString": concat!("postgres://svc", ":UltraSecretPgPass!@pg.internal:5432/archive")
                    },
                    "credentials": {
                        "postgres": {
                            "id": "cred_pg_1",
                            "name": "Archive DB"
                        }
                    }
                }
            ],
            "connections": {
                "Order Intake Webhook": {
                    "main": [[{ "node": "Deprecated Billing HTTP Request", "type": "main", "index": 0 }]]
                }
            },
            "settings": {
                "executionOrder": "v1"
            }
        }))
        .expect("valid sample WorkflowIr")
    }

    use serde_json::Value;

    #[test]
    fn acl_enforces_user_only_permissions_on_state_dir_and_files() {
        let tmp = TempDir::new().expect("tempdir");
        let vault_dir = tmp.path().join("n8n-rs-mcp-test");

        let pre_status = check_user_state_dir(Some(&vault_dir));
        assert!(pre_status.directory_configured);
        assert!(!pre_status.directory_exists);

        let (resolved, status) =
            ensure_protected_state_dir(Some(&vault_dir)).expect("protected state dir created");
        assert_eq!(resolved, vault_dir);
        assert!(status.directory_exists);
        assert!(status.writable);
        assert!(status.acl_restricted);

        let dir_acl = inspect_path_acl(&vault_dir);
        assert!(dir_acl.inspected);
        assert!(
            dir_acl.restricted_to_current_user,
            "expected restricted user-only ACL, got: {}",
            dir_acl.detail
        );

        let sample_file = vault_dir.join("state.db");
        fs::write(&sample_file, b"header").expect("write sample");
        assert!(protect_state_file(&sample_file).expect("protect file"));
        let file_acl = inspect_path_acl(&sample_file);
        assert!(file_acl.restricted_to_current_user);
    }

    #[test]
    fn sanitized_fts5_index_operators_zero_secret_leakage_revocation_and_ephemeral_scan() {
        let tmp = TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("index.sqlite");
        let mut idx = SanitizedWorkflowIndex::open_file(&db_path).expect("open index file");

        let wf1 = build_sample_workflow_with_secrets("wf_billing_1", "Billing Flow", true);
        let wf2 = build_sample_workflow_with_secrets("wf_draft_2", "Staging Draft Flow", false);

        let latest_versions = HashMap::from([
            ("n8n-nodes-base.httpRequest".to_owned(), 4.2),
            ("n8n-nodes-base.postgres".to_owned(), 2.5),
        ]);

        let now = Utc::now();
        let r1 = idx
            .index_workflow_at(
                &wf1,
                &IndexWorkflowMetadata {
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    project_id: "proj_alpha".to_owned(),
                    folder_id: Some("fld_payments".to_owned()),
                    graph: GraphVariant::Published,
                    recent_failure_count: 4,
                    cache_policy: CachePolicy::MetadataOnly,
                    ttl_secs: Some(600),
                    latest_catalog_versions: Some(latest_versions.clone()),
                },
                now,
            )
            .expect("indexed wf1");
        assert!(r1.persisted);
        assert_eq!(r1.indexed_node_count, 3);

        let _ = idx
            .index_workflow_at(
                &wf2,
                &IndexWorkflowMetadata {
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    project_id: "proj_beta".to_owned(),
                    folder_id: None,
                    graph: GraphVariant::Draft,
                    recent_failure_count: 0,
                    cache_policy: CachePolicy::MetadataOnly,
                    ttl_secs: Some(600),
                    latest_catalog_versions: Some(latest_versions),
                },
                now,
            )
            .expect("indexed wf2");

        assert_eq!(idx.fts_row_count().expect("fts count"), 6);

        // 1. Verify ZERO plaintext parameter secrets exist anywhere in the SQLite file on disk!
        drop(idx);
        let raw_db_bytes = fs::read(&db_path).expect("read sqlite bytes");
        let raw_db_lossy = String::from_utf8_lossy(&raw_db_bytes);
        for forbidden in [
            "TOPSECRET_QUERY_TOKEN_999",
            "SUPER_SECRET_BEARER_TOKEN_ABCDEF123456",
            "UltraSecretPgPass!",
            "FORBIDDEN_SMUGGLED_RAW_CREDENTIAL_SECRET",
            "api.deprecated.internal",
        ] {
            assert!(
                !raw_db_lossy.contains(forbidden),
                "Sanitized index leaked `{forbidden}` to SQLite disk!"
            );
        }

        let mut idx = SanitizedWorkflowIndex::open_file(&db_path).expect("reopen index");

        // 2. Test all FindNodesQuery operators!
        let mut q = FindNodesQuery::new("principal_alice", "staging");
        q.project_id = Some("proj_alpha".to_owned());
        q.folder_id = Some("fld_payments".to_owned());
        q.active_only = true;
        q.graph = Some(GraphVariant::Published);
        q.node_type = Some("httpRequest".to_owned());
        q.name_pattern = Some("Deprecated Billing".to_owned());
        q.disabled = Some(false);
        q.references_node = Some("Order Intake Webhook".to_owned());
        q.uses_variable = Some("BILLING_REGION".to_owned());
        q.credential_type = Some("httpHeaderAuth".to_owned());
        q.stale_type_version = Some(true);
        q.missing_error_handler = Some(true);
        q.recent_failure_count = Some(3);

        let page = idx.find_nodes_at(&q, now).expect("find_nodes succeeds");
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].node_id, "n_http");
        assert_eq!(page.hits[0].workflow_id, "wf_billing_1");
        assert!(
            page.hits[0]
                .used_variables
                .contains(&"TENANT_CODE".to_owned())
        );

        // 3. Test cursor pagination (`max_results = 2`).
        let mut paged_q = FindNodesQuery::new("principal_alice", "staging");
        paged_q.max_results = 2;
        let p1 = idx.find_nodes_at(&paged_q, now).expect("page 1");
        assert_eq!(p1.hits.len(), 2);
        assert!(p1.next_page_token.is_some());
        paged_q.page_token = p1.next_page_token;
        let p2 = idx.find_nodes_at(&paged_q, now).expect("page 2");
        assert_eq!(p2.hits.len(), 2);
        assert!(p2.next_page_token.is_some());
        paged_q.page_token = p2.next_page_token;
        let p3 = idx.find_nodes_at(&paged_q, now).expect("page 3");
        assert_eq!(p3.hits.len(), 2);
        assert!(p3.next_page_token.is_none());

        // 4. Cross-principal isolation: `principal_bob` must see 0 hits!
        let bob_hits = idx
            .find_nodes_at(&FindNodesQuery::new("principal_bob", "staging"), now)
            .expect("bob search");
        assert!(bob_hits.hits.is_empty());

        // 5. Partition revocation (U17): revoking `proj_alpha` clears both rows and FTS5 entries!
        let purged = idx
            .revoke_principal_or_project("principal_alice", Some("staging"), Some("proj_alpha"))
            .expect("revoke proj_alpha");
        assert_eq!(purged, 1);
        assert_eq!(idx.fts_row_count().expect("fts count after revoke"), 3);
        let after_revoke = idx.find_nodes_at(&q, now).expect("search after revoke");
        assert!(after_revoke.hits.is_empty());

        // 6. `NoPersistentPayload` clears remaining partition and writes nothing!
        let no_persist_receipt = idx
            .index_workflow_at(
                &wf2,
                &IndexWorkflowMetadata {
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    project_id: "proj_beta".to_owned(),
                    folder_id: None,
                    graph: GraphVariant::Draft,
                    recent_failure_count: 0,
                    cache_policy: CachePolicy::NoPersistentPayload,
                    ttl_secs: Some(600),
                    latest_catalog_versions: None,
                },
                now,
            )
            .expect("no_persistent_payload");
        assert!(!no_persist_receipt.persisted);
        assert_eq!(idx.fts_row_count().expect("fts empty"), 0);

        // 7. `ephemeral_scan_parameters` (U01) matches deprecated URL & JSONPath headers WITHOUT echoing raw secret values!
        let ptr_hits = ephemeral_scan_parameters(
            &wf1,
            "/url",
            &ParamPredicate::ContainsSubstring {
                substring: "api.deprecated.internal".to_owned(),
                case_insensitive: true,
            },
        )
        .expect("pointer scan");
        assert_eq!(ptr_hits.len(), 1);
        assert_eq!(
            ptr_hits[0].as_tuple(),
            ("n_http", "Deprecated Billing HTTP Request", "/url")
        );
        let serialized_hits = serde_json::to_string(&ptr_hits).expect("serialize matches");
        assert!(!serialized_hits.contains("TOPSECRET_QUERY_TOKEN_999"));

        let jp_hits = ephemeral_scan_parameters(
            &wf1,
            "$.headers.parameters[*].name",
            &ParamPredicate::Equals {
                expected: json!("Authorization"),
            },
        )
        .expect("jsonpath scan");
        assert_eq!(jp_hits.len(), 1);
        assert_eq!(jp_hits[0].node_id, "n_http");
    }

    #[test]
    fn snapshots_aead_tamper_rejection_redaction_memory_fallback_and_retention() {
        // 1. Direct ChaCha20-Poly1305 helper roundtrip & tamper rejection.
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let sealed = seal_snapshot_bytes(&key, &nonce, b"{\"hello\":\"world\"}").expect("seal");
        let opened = open_snapshot_bytes(&key, &nonce, &sealed).expect("open");
        assert_eq!(opened, b"{\"hello\":\"world\"}");
        let mut tampered_ct = sealed.clone();
        tampered_ct[0] ^= 0xFF;
        assert!(open_snapshot_bytes(&key, &nonce, &tampered_ct).is_err());

        // 2. Persistent XChaCha20-Poly1305 SnapshotVault with ProtectedKeyFile & bounded retention (`max_per_workflow = 2`).
        let tmp = TempDir::new().expect("tempdir");
        let vault_root = tmp.path().join("vault");
        let key_file = tmp.path().join("keys").join("snapshot.key");

        let mut vault = SnapshotVault::open_at_dir(
            &vault_root,
            &SnapshotKeyProvider::ProtectedKeyFile { path: key_file },
            SnapshotRetentionPolicy {
                max_per_workflow: 2,
                max_total: 10,
                default_ttl_secs: 300,
            },
        )
        .expect("open persistent snapshot vault");
        assert_eq!(
            vault.storage_mode(),
            SnapshotStorageMode::PersistentEncrypted
        );

        let wf = build_sample_workflow_with_secrets("wf_snap_1", "Critical Flow", true);
        let now = Utc::now();

        // Capture 3 snapshots -> oldest #1 must be evicted by `max_per_workflow = 2`!
        let h1 = vault
            .capture_snapshot_at("alice", "staging", Some("proj_1"), &wf, false, now)
            .expect("snap 1");
        let h2 = vault
            .capture_snapshot_at(
                "alice",
                "staging",
                Some("proj_1"),
                &wf,
                false,
                now + Duration::seconds(1),
            )
            .expect("snap 2");
        let h3 = vault
            .capture_snapshot_at(
                "alice",
                "staging",
                Some("proj_1"),
                &wf,
                false,
                now + Duration::seconds(2),
            )
            .expect("snap 3");

        let listed = vault
            .list_snapshots("alice", "staging", "wf_snap_1")
            .expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].snapshot_id, h3.snapshot_id);
        assert_eq!(listed[1].snapshot_id, h2.snapshot_id);
        assert!(
            !vault_root
                .join("snapshots")
                .join(format!("{}.snap", h1.snapshot_id))
                .exists(),
            "evicted snapshot file must be deleted from disk"
        );

        // Verify restored snapshot is forced to draft (`active = false`, `active_version_id = None`),
        // strips credential `data`, redacts secrets when `encrypted_sensitive_retention == false`,
        // and carries the mandatory side-effects disclaimer!
        let restored = vault
            .restore_snapshot_at(
                "alice",
                "staging",
                &h3.snapshot_id,
                now + Duration::seconds(5),
            )
            .expect("restore h3");
        assert!(restored.integrity_verified);
        assert!(!restored.draft_workflow.active);
        assert!(restored.draft_workflow.active_version_id.is_none());
        assert_eq!(restored.disclaimer, RESTORE_SIDE_EFFECTS_DISCLAIMER);
        let restored_str = restored.draft_workflow.to_json_string().expect("json");
        assert!(!restored_str.contains("FORBIDDEN_SMUGGLED_RAW_CREDENTIAL_SECRET"));
        assert!(!restored_str.contains("SUPER_SECRET_BEARER_TOKEN_ABCDEF123456"));
        assert!(!restored_str.contains("UltraSecretPgPass!"));

        // Cross-principal restore must fail closed!
        assert!(
            vault
                .restore_snapshot_at(
                    "mallory",
                    "staging",
                    &h3.snapshot_id,
                    now + Duration::seconds(5)
                )
                .is_err()
        );

        // Bit-flipping ciphertext on disk MUST be rejected!
        let snap2_file = vault_root
            .join("snapshots")
            .join(format!("{}.snap", h2.snapshot_id));
        let mut raw_snap2 = fs::read(&snap2_file).expect("read snap2");
        let last_idx = raw_snap2.len() - 1;
        raw_snap2[last_idx] ^= 0x01;
        fs::write(&snap2_file, &raw_snap2).expect("write tampered snap2");
        assert!(
            vault
                .restore_snapshot_at(
                    "alice",
                    "staging",
                    &h2.snapshot_id,
                    now + Duration::seconds(5)
                )
                .is_err(),
            "tampered AEAD snapshot blob must fail restore verification"
        );

        // TTL expiry purge removes expired snapshots!
        let purged_expired = vault
            .purge_expired(now + Duration::seconds(600))
            .expect("purge expired");
        assert_eq!(purged_expired, 2);

        // 3. Memory-only transient fallback when env var is unset!
        let transient_dir = tmp.path().join("transient_vault");
        let mut mem_vault = SnapshotVault::open_at_dir(
            &transient_dir,
            &SnapshotKeyProvider::FromEnvOrMemoryFallback {
                env_var: "N8N_DEFINITELY_UNSET_TEST_KEY_ENV_99999".to_owned(),
            },
            SnapshotRetentionPolicy::default(),
        )
        .expect("memory fallback vault");
        assert_eq!(
            mem_vault.storage_mode(),
            SnapshotStorageMode::MemoryTransient
        );
        let mem_hdr = mem_vault
            .capture_snapshot_at("alice", "staging", None, &wf, true, now)
            .expect("capture transient");
        assert!(!transient_dir.join("snapshots").exists());
        let mem_restored = mem_vault
            .restore_snapshot_at("alice", "staging", &mem_hdr.snapshot_id, now)
            .expect("restore transient");
        assert!(mem_restored.integrity_verified);
        // Even with `encrypted_sensitive_retention = true`, smuggled raw credential `data` is ALWAYS stripped!
        let mem_json = mem_restored.draft_workflow.to_json_string().expect("json");
        assert!(!mem_json.contains("FORBIDDEN_SMUGGLED_RAW_CREDENTIAL_SECRET"));

        // ExplicitKey variant check
        let _explicit = SnapshotKeyProvider::ExplicitKey(Zeroizing::new([42u8; 32]));
    }

    #[test]
    fn journal_state_machine_redaction_hash_chain_tamper_detection_batches_and_leases() {
        let tmp = TempDir::new().expect("tempdir");
        let journal_db = tmp.path().join("journal.sqlite");
        let journal_jsonl = tmp.path().join("journal.jsonl");

        let mut journal =
            OperationJournal::open_files(&journal_db, Some(&journal_jsonl)).expect("open journal");

        // 1. Walk full V2 Section 9 state machine:
        // Planned -> Previewed -> UserApproved -> Preparing -> Writing -> Verifying -> Verified
        let states = [
            JournalState::Planned,
            JournalState::Previewed,
            JournalState::UserApproved,
            JournalState::Preparing,
            JournalState::Writing,
            JournalState::Verifying,
            JournalState::Verified,
        ];

        for st in states {
            journal
                .append_transition(JournalTransitionInput {
                    operation_id: "op_mut_001".to_owned(),
                    next_state: st,
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    workflow_id: Some("wf_100".to_owned()),
                    action: "mutate_nodes.apply".to_owned(),
                    base_version_hash: Some("hash_v1".to_owned()),
                    resulting_version_hash: (st == JournalState::Verified)
                        .then(|| "hash_v2".to_owned()),
                    ops_hash: Some("ops_digest_1".to_owned()),
                    details: json!({
                        "authorization": "Bearer SHOULD_NEVER_PERSIST_SECRET_12345678",
                        "note": "Connecting with api_key=SECRET_QUERY_VAL_777"
                    }),
                })
                .expect("valid transition");
        }

        // Terminal `Verified` operation must reject further transitions!
        let post_terminal = journal.append_transition(JournalTransitionInput {
            operation_id: "op_mut_001".to_owned(),
            next_state: JournalState::Writing,
            principal_id: "principal_alice".to_owned(),
            instance_id: "staging".to_owned(),
            workflow_id: Some("wf_100".to_owned()),
            action: "mutate_nodes.apply".to_owned(),
            base_version_hash: None,
            resulting_version_hash: None,
            ops_hash: None,
            details: json!({}),
        });
        assert!(post_terminal.is_err());

        // Illegal jump `Planned -> Verified` (skipping Writing/Verifying) must fail closed!
        let _ = journal
            .append_transition(JournalTransitionInput {
                operation_id: "op_skip_test".to_owned(),
                next_state: JournalState::Planned,
                principal_id: "principal_alice".to_owned(),
                instance_id: "staging".to_owned(),
                workflow_id: None,
                action: "test".to_owned(),
                base_version_hash: None,
                resulting_version_hash: None,
                ops_hash: None,
                details: json!({}),
            })
            .expect("planned");
        assert!(
            journal
                .append_transition(JournalTransitionInput {
                    operation_id: "op_skip_test".to_owned(),
                    next_state: JournalState::Verified,
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    workflow_id: None,
                    action: "test".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: None,
                    ops_hash: None,
                    details: json!({}),
                })
                .is_err()
        );

        // Record an `UnknownResult` operation and verify `list_uncertain_operations` finds it!
        for st in [
            JournalState::Planned,
            JournalState::Preparing,
            JournalState::Writing,
            JournalState::UnknownResult,
        ] {
            journal
                .append_transition(JournalTransitionInput {
                    operation_id: "op_timeout_99".to_owned(),
                    next_state: st,
                    principal_id: "principal_alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    workflow_id: Some("wf_timeout".to_owned()),
                    action: "workflows.create".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: None,
                    ops_hash: None,
                    details: json!({}),
                })
                .expect("timeout transition");
        }
        let uncertain = journal
            .list_uncertain_operations(Some("staging"))
            .expect("uncertain ops");
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].operation_id, "op_timeout_99");

        // 2. Verify zero raw secrets in SQLite & JSONL!
        let jsonl_text = fs::read_to_string(&journal_jsonl).expect("read jsonl");
        assert!(!jsonl_text.contains("SHOULD_NEVER_PERSIST_SECRET_12345678"));
        assert!(!jsonl_text.contains("SECRET_QUERY_VAL_777"));

        // 3. Durable batch codemod checkpoints: U10 batch cap (30 > 20 blocked!), selector widening blocked, halt-on-error!
        let thirty_targets: Vec<(String, String)> = (0..30)
            .map(|i| (format!("wf_{i}"), format!("hash_{i}")))
            .collect();
        assert!(
            journal
                .create_batch_plan(
                    "principal_alice",
                    "staging",
                    "oversized",
                    "ops_h",
                    &thirty_targets,
                    None
                )
                .is_err(),
            "batch > 20 workflows must be blocked by default"
        );

        let batch = journal
            .create_batch_plan(
                "principal_alice",
                "staging",
                "Add retryOnFail across 3 workflows",
                "ops_batch_hash",
                &[
                    ("wf_a".to_owned(), "ha".to_owned()),
                    ("wf_b".to_owned(), "hb".to_owned()),
                    ("wf_c".to_owned(), "hc".to_owned()),
                ],
                None,
            )
            .expect("valid 3-workflow batch");

        // Selector widening must fail closed!
        assert!(
            journal
                .update_batch_checkpoint(
                    &batch.batch_id,
                    "wf_unapproved",
                    BatchCheckpointStatus::InProgress,
                    None,
                    None,
                    None,
                )
                .is_err()
        );

        let _ = journal
            .update_batch_checkpoint(
                &batch.batch_id,
                "wf_a",
                BatchCheckpointStatus::Verified,
                Some("snap_a"),
                Some("ha_after"),
                None,
            )
            .expect("wf_a verified");

        // Critical failure on `wf_b` must halt batch and mark `wf_c` as `SkippedHalted`!
        let halted_plan = journal
            .update_batch_checkpoint(
                &batch.batch_id,
                "wf_b",
                BatchCheckpointStatus::Failed,
                Some("snap_b"),
                None,
                Some("422 validation error with Bearer SECRET_LEAK_ATTEMPT_999"),
            )
            .expect("wf_b failed");
        assert!(halted_plan.halted_on_error);
        assert_eq!(halted_plan.checkpoints[2].workflow_id, "wf_c");
        assert_eq!(
            halted_plan.checkpoints[2].status,
            BatchCheckpointStatus::SkippedHalted
        );
        assert!(
            !halted_plan.checkpoints[1]
                .diagnostic_note
                .as_deref()
                .unwrap_or("")
                .contains("SECRET_LEAK_ATTEMPT_999")
        );

        // 4. Durable test cleanup leases for crash-safe startup reconciliation!
        let lease1 = journal
            .acquire_cleanup_lease(
                "principal_alice",
                "staging",
                "ephemeral_test_workflow",
                "[MCP-E2E-TEST] webhook-sim",
                300,
            )
            .expect("acquire lease 1");
        let _ = journal
            .bind_cleanup_lease_workflow(&lease1.lease_id, "wf_temp_1", Some("created"))
            .expect("bind lease 1");

        let lease2 = journal
            .acquire_cleanup_lease(
                "principal_alice",
                "staging",
                "ephemeral_test_workflow",
                "[MCP-E2E-TEST] cleaned",
                300,
            )
            .expect("acquire lease 2");
        let _ = journal
            .complete_cleanup_lease(&lease2.lease_id, true, Some("DELETE verified"))
            .expect("complete lease 2");

        let pending_leases = journal
            .list_pending_cleanup_leases(Some("staging"))
            .expect("pending leases");
        assert_eq!(pending_leases.len(), 1);
        assert_eq!(pending_leases[0].lease_id, lease1.lease_id);
        assert_eq!(
            pending_leases[0].state,
            CleanupLeaseState::ActiveResourceCreated
        );

        // 5. Verify intact BLAKE3 hash chain across SQLite + JSONL mirror!
        let verified_count = journal
            .verify_hash_chain()
            .expect("intact hash chain must verify");
        assert_eq!(verified_count, 13);

        // 6. Simulate attacker tampering with a SQLite row -> `EntryHashMismatch`!
        journal
            .connection()
            .execute(
                "UPDATE journal_entries SET action = 'tampered_action' WHERE sequence = 3",
                params![],
            )
            .expect("simulate tamper");
        assert!(matches!(
            journal.verify_hash_chain(),
            Err(JournalTamperError::EntryHashMismatch { sequence: 3, .. })
        ));

        // Restore action, then simulate deleting sequence 2 -> `SequenceGap`!
        journal
            .connection()
            .execute("DELETE FROM journal_entries WHERE sequence = 2", params![])
            .expect("simulate row deletion");
        assert!(matches!(
            journal.verify_hash_chain(),
            Err(JournalTamperError::SequenceGap {
                expected_sequence: 2,
                actual_sequence: 3
            })
        ));
    }

    #[test]
    fn jsonl_mirror_tamper_aad_swap_ttl_expiry_and_reconcile_transitions() {
        let tmp = TempDir::new().expect("tempdir");

        // 1. JSONL mirror tamper detection when SQLite is untouched!
        let db_path = tmp.path().join("j2.sqlite");
        let jsonl_path = tmp.path().join("j2.jsonl");
        let mut journal =
            OperationJournal::open_files(&db_path, Some(&jsonl_path)).expect("open j2");

        for st in [
            JournalState::Planned,
            JournalState::Preparing,
            JournalState::Writing,
            JournalState::UnknownResult,
        ] {
            journal
                .append_transition(JournalTransitionInput {
                    operation_id: "op_rec_1".to_owned(),
                    next_state: st,
                    principal_id: "alice".to_owned(),
                    instance_id: "staging".to_owned(),
                    workflow_id: Some("wf_1".to_owned()),
                    action: "workflows.create".to_owned(),
                    base_version_hash: None,
                    resulting_version_hash: None,
                    ops_hash: None,
                    details: json!({}),
                })
                .expect("append");
        }
        assert_eq!(journal.list_uncertain_operations(None).expect("u").len(), 1);

        // Reconcile `UnknownResult -> Verified` clears uncertain operation list!
        journal
            .append_transition(JournalTransitionInput {
                operation_id: "op_rec_1".to_owned(),
                next_state: JournalState::Verified,
                principal_id: "alice".to_owned(),
                instance_id: "staging".to_owned(),
                workflow_id: Some("wf_1".to_owned()),
                action: "workflows.create".to_owned(),
                base_version_hash: None,
                resulting_version_hash: Some("hash_confirmed".to_owned()),
                ops_hash: None,
                details: json!({"reconciled": true}),
            })
            .expect("reconcile to verified");
        assert!(
            journal
                .list_uncertain_operations(None)
                .expect("u")
                .is_empty()
        );

        // Failed cleanup lease stays visible as `CleanupRequired`!
        let lease = journal
            .acquire_cleanup_lease("alice", "staging", "test_wf", "[MCP-E2E-TEST]", 60)
            .expect("lease");
        let failed_lease = journal
            .complete_cleanup_lease(&lease.lease_id, false, Some("network error on DELETE"))
            .expect("failed cleanup");
        assert_eq!(failed_lease.state, CleanupLeaseState::CleanupRequired);
        assert_eq!(
            journal
                .list_pending_cleanup_leases(Some("staging"))
                .expect("pending")
                .len(),
            1
        );

        assert_eq!(journal.verify_hash_chain().expect("intact"), 5);

        // Tamper ONLY the JSONL file by truncating the last line -> `JsonlMirrorMismatch`!
        let orig_lines: Vec<String> = fs::read_to_string(&jsonl_path)
            .expect("read jsonl")
            .lines()
            .map(str::to_owned)
            .collect();
        fs::write(&jsonl_path, format!("{}\n", orig_lines[..4].join("\n")))
            .expect("truncate jsonl");
        assert!(matches!(
            journal.verify_hash_chain(),
            Err(JournalTamperError::JsonlMirrorMismatch { .. })
        ));

        // 2. Index TTL expiry & Regex ephemeral scan!
        let mut idx = SanitizedWorkflowIndex::open_in_memory().expect("mem index");
        let wf = build_sample_workflow_with_secrets("wf_ttl", "TTL Flow", true);
        let t0 = Utc::now();
        idx.index_workflow_at(
            &wf,
            &IndexWorkflowMetadata {
                principal_id: "alice".to_owned(),
                instance_id: "staging".to_owned(),
                project_id: "p1".to_owned(),
                folder_id: None,
                graph: GraphVariant::Draft,
                recent_failure_count: 0,
                cache_policy: CachePolicy::MetadataOnly,
                ttl_secs: Some(30),
                latest_catalog_versions: None,
            },
            t0,
        )
        .expect("index wf");

        // After 60 seconds (> 30s TTL), `find_nodes_at` returns 0 hits and `purge_expired` cleans it up!
        let expired_search = idx
            .find_nodes_at(
                &FindNodesQuery::new("alice", "staging"),
                t0 + Duration::seconds(60),
            )
            .expect("expired search");
        assert!(expired_search.hits.is_empty());
        assert_eq!(
            idx.purge_expired(t0 + Duration::seconds(60))
                .expect("purge"),
            1
        );

        let regex_hits = ephemeral_scan_parameters(
            &wf,
            "/url",
            &ParamPredicate::MatchesRegex {
                pattern: r"^https://api\.deprecated\.internal/v[0-9]+/".to_owned(),
            },
        )
        .expect("regex scan");
        assert_eq!(regex_hits.len(), 1);
    }
}
