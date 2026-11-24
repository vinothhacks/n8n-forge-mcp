//! Comprehensive V2 Section 10 test suite for `n8n-audit`:
//! - Strict 3-bucket separation (`observed_facts`, `heuristics`, `permission_gaps`)
//! - Zero raw secret echo across JWTs, API keys, DSNs, PEM keys, and custom sensitive headers
//! - Batch cross-subworkflow resolution (`audit_workflows_batch`)
//! - Live `/api/v1/audit` merger and `403`/`404` permission-gap handling via `wiremock`

use std::collections::HashSet;
use std::path::PathBuf;

use n8n_api_client::{ApiClientConfig, N8nApiClient, SsrfPolicy};
use n8n_audit::{
    AuditContext, SecretKind, StaticAuditReport, audit_workflow, audit_workflow_with_live_api,
    audit_workflows_batch,
};
use n8n_catalog_db::CatalogDb;
use n8n_graph::WorkflowIr;
use n8n_types::SecretValue;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn open_bundled_catalog() -> CatalogDb {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let zst_path = root.join("data/catalog.sqlite.zst");
    let manifest_path = root.join("data/catalog.manifest.json");
    CatalogDb::open_from_zst_path(&zst_path, Some(&manifest_path)).expect("open bundled catalog")
}

#[test]
fn separates_observed_facts_heuristics_and_permission_gaps_and_never_echoes_secrets() {
    let catalog = open_bundled_catalog();

    // Synthetic canary secrets that MUST NEVER appear anywhere in serialized output!
    let canary_jwt = concat!(
        "ey",
        "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e",
        "yJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    );
    let canary_openai = concat!("sk", "-proj-UltraSecretCanaryValue9876543210abcdef");
    let canary_dsn_pass = "SuperSecretDbPassw0rdCanary99";
    let canary_dsn = format!("postgresql://admin:{canary_dsn_pass}@db.example.org:5432/prod");
    let canary_pem = concat!(
        "-----BEGIN ",
        "RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7CanaryKeyMaterialDoNotEcho\n-----END RSA PRIVATE KEY-----"
    );
    let canary_custom_secret = "CustomUnprefixedApiSecret_DoNotLeak_778899";

    let wf_json = json!({
        "id": "wf_sec_01",
        "name": "High Risk Ingestion Pipeline",
        "nodes": [
            {
                "id": "n_hook",
                "name": "Public Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [0, 0],
                "parameters": {
                    "httpMethod": "POST",
                    "path": "public-ingest",
                    "authentication": "none",
                    "options": {
                        "allowedOrigins": "*"
                    }
                }
            },
            {
                "id": "n_form",
                "name": "Open Form",
                "type": "n8n-nodes-base.formTrigger",
                "typeVersion": 2,
                "position": [0, 200],
                "parameters": {
                    "formTitle": "Intake"
                }
            },
            {
                "id": "n_http_meta",
                "name": "Fetch Metadata",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [240, 0],
                "parameters": {
                    "method": "POST",
                    "sendBody": true,
                    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "apiKey": canary_custom_secret,
                    "headerParameters": {
                        "parameters": [
                            { "name": "Authorization", "value": format!("Bearer {canary_jwt}") },
                            { "name": "X-OpenAI", "value": canary_openai }
                        ]
                    }
                }
            },
            {
                "id": "n_code",
                "name": "Env Reader Code",
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [480, 0],
                "parameters": {
                    "jsCode": format!("const k = $env.MASTER_KEY;\nconst dsn = '{canary_dsn}';\nconst pem = `{canary_pem}`;\nreturn items;")
                }
            },
            {
                "id": "n_cmd",
                "name": "Run Shell",
                "type": "n8n-nodes-base.executeCommand",
                "typeVersion": 1,
                "position": [720, 0],
                "parameters": {
                    "command": "={{ 'echo ' + $env.HOME }}"
                }
            },
            {
                "id": "n_sub",
                "name": "Invoke Restricted Subworkflow",
                "type": "n8n-nodes-base.executeWorkflow",
                "typeVersion": 1.1,
                "position": [960, 0],
                "parameters": {
                    "workflowId": "wf_secret_sub_99"
                }
            },
            {
                "id": "n_comm",
                "name": "Community Scraper",
                "type": "n8n-nodes-community-acme.customScraper",
                "typeVersion": 1,
                "position": [1200, 0],
                "credentials": {
                    "acmeApi": { "id": "cred_stale_404", "name": "Old Acme Cred" }
                },
                "parameters": {}
            }
        ],
        "connections": {
            "Public Webhook": {
                "main": [[{ "node": "Fetch Metadata", "type": "main", "index": 0 }]]
            },
            "Fetch Metadata": {
                "main": [[{ "node": "Env Reader Code", "type": "main", "index": 0 }]]
            },
            "Env Reader Code": {
                "main": [[
                    { "node": "Fetch Metadata", "type": "main", "index": 0 },
                    { "node": "Run Shell", "type": "main", "index": 0 }
                ]]
            },
            "Run Shell": {
                "main": [[{ "node": "Invoke Restricted Subworkflow", "type": "main", "index": 0 }]]
            },
            "Invoke Restricted Subworkflow": {
                "main": [[{ "node": "Community Scraper", "type": "main", "index": 0 }]]
            }
        }
    });

    let ir = WorkflowIr::from_json_value(wf_json).expect("valid IR");
    let mut known_creds = HashSet::new();
    known_creds.insert("cred_valid_01".to_owned());

    let mut inaccessible = HashSet::new();
    inaccessible.insert("wf_secret_sub_99".to_owned());

    let ctx = AuditContext {
        catalog: Some(&catalog),
        accessible_subworkflows: Default::default(),
        inaccessible_workflow_ids: inaccessible,
        known_credential_ids: Some(known_creds),
        live_audit_advertised: Some(false),
    };

    let report: StaticAuditReport = audit_workflow(&ir, &ctx);

    // 1. Verify ZERO raw secret leakage anywhere in the JSON serialized report!
    let serialized = serde_json::to_string_pretty(&report).expect("serialize report");
    for canary in [
        canary_jwt,
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        canary_openai,
        "UltraSecretCanaryValue9876543210abcdef",
        canary_dsn_pass,
        "MIIEpAIBAAKCAQEA7CanaryKeyMaterialDoNotEcho",
        canary_custom_secret,
    ] {
        assert!(
            !serialized.contains(canary),
            "CRITICAL SECRET LEAK in StaticAuditReport: matched `{canary}` inside:\n{serialized}"
        );
    }

    // 2. Verify observed_facts bucket contents.
    let fact_codes: Vec<&str> = report
        .observed_facts
        .iter()
        .map(|f| f.code.as_str())
        .collect();
    for expected_fact in [
        "public_webhook_without_auth",
        "public_form_trigger_without_auth",
        "missing_retry_or_error_policy",
        "high_risk_node_type:code",
        "high_risk_node_type:executeCommand",
        "code_node_env_access",
        "expression_env_access",
        "unbounded_or_invalid_cycle",
        "stale_node_type_version",
        "stale_or_missing_credential_reference:acmeApi",
    ] {
        assert!(
            fact_codes.contains(&expected_fact),
            "Missing expected observed_fact `{expected_fact}`; got: {fact_codes:?}"
        );
    }

    // 3. Verify heuristics bucket contents + location-only secret metadata.
    let heuristic_codes: Vec<&str> = report.heuristics.iter().map(|h| h.code.as_str()).collect();
    for expected_heuristic in [
        "potential_hardcoded_secret",
        "ssrf_cloud_metadata_url",
        "cleartext_http_url",
        "wildcard_cors_allowed_origins",
        "missing_error_workflow_setting",
        "potential_unvalidated_external_egress",
    ] {
        assert!(
            heuristic_codes.contains(&expected_heuristic),
            "Missing expected heuristic `{expected_heuristic}`; got: {heuristic_codes:?}"
        );
    }

    let secret_kinds: Vec<SecretKind> = report
        .heuristics
        .iter()
        .filter_map(|h| h.secret_kind)
        .collect();
    assert!(secret_kinds.contains(&SecretKind::Jwt));
    assert!(secret_kinds.contains(&SecretKind::ApiKeyPrefix));
    assert!(secret_kinds.contains(&SecretKind::SensitiveParameterLiteral));

    // Verify every secret finding includes (node_id, node_name, field_path, secret_kind).
    for h in report
        .heuristics
        .iter()
        .filter(|h| h.code == "potential_hardcoded_secret")
    {
        assert!(h.node_id.is_some());
        assert!(h.node_name.is_some());
        assert!(h.field_path.is_some());
        assert!(h.secret_kind.is_some());
    }

    // 4. Verify permission_gaps bucket contents.
    let gap_kinds: Vec<&str> = report
        .permission_gaps
        .iter()
        .filter_map(|g| g.gap_kind.as_deref())
        .collect();
    for expected_gap in [
        "unadvertised_audit_endpoint",
        "hidden_credential_body",
        "unreadable_subworkflow",
        "community_node_partial_schema",
    ] {
        assert!(
            gap_kinds.contains(&expected_gap),
            "Missing expected permission_gap `{expected_gap}`; got: {gap_kinds:?}"
        );
    }
}

#[test]
fn batch_audit_resolves_accessible_subworkflows_and_validation_gate_clears_egress_warning() {
    let parent = WorkflowIr::from_json_value(json!({
        "id": "wf_parent",
        "name": "Guarded Parent",
        "settings": { "errorWorkflow": "wf_err_01" },
        "nodes": [
            {
                "id": "1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [0, 0],
                "parameters": { "authentication": "headerAuth", "path": "secure" },
                "credentials": { "httpHeaderAuth": { "id": "cred_1", "name": "Hook Secret" } }
            },
            {
                "id": "2",
                "name": "Validate Payload",
                "type": "n8n-nodes-base.if",
                "typeVersion": 2.2,
                "position": [220, 0],
                "parameters": {}
            },
            {
                "id": "3",
                "name": "Post Slack",
                "type": "n8n-nodes-base.slack",
                "typeVersion": 2.2,
                "position": [440, 0],
                "retryOnFail": true,
                "credentials": { "slackApi": { "id": "cred_2", "name": "Slack Bot" } },
                "parameters": {}
            },
            {
                "id": "4",
                "name": "Call Child",
                "type": "n8n-nodes-base.executeWorkflow",
                "typeVersion": 1.1,
                "position": [660, 0],
                "parameters": { "workflowId": "wf_child" }
            }
        ],
        "connections": {
            "Webhook": { "main": [[{ "node": "Validate Payload", "type": "main", "index": 0 }]] },
            "Validate Payload": { "main": [[{ "node": "Post Slack", "type": "main", "index": 0 }]] },
            "Post Slack": { "main": [[{ "node": "Call Child", "type": "main", "index": 0 }]] }
        }
    }))
    .expect("parent IR");

    let child = WorkflowIr::from_json_value(json!({
        "id": "wf_child",
        "name": "Child Subworkflow",
        "settings": { "errorWorkflow": "wf_err_01" },
        "nodes": [
            {
                "id": "c1",
                "name": "Subtrigger",
                "type": "n8n-nodes-base.executeWorkflowTrigger",
                "typeVersion": 1.1,
                "position": [0, 0],
                "parameters": {}
            }
        ],
        "connections": {}
    }))
    .expect("child IR");

    let batch = audit_workflows_batch(&[parent, child], &AuditContext::default());
    assert_eq!(batch.workflows_scanned, 2);
    assert!(
        !batch
            .combined
            .permission_gaps
            .iter()
            .any(|g| g.gap_kind.as_deref() == Some("unreadable_subworkflow")),
        "Child subworkflow in batch must resolve without unreadable_subworkflow gap"
    );
    assert!(
        !batch
            .combined
            .heuristics
            .iter()
            .any(|h| h.code == "potential_unvalidated_external_egress"),
        "IF guard node should prevent unvalidated_external_egress heuristic"
    );
}

#[tokio::test]
async fn live_audit_merger_handles_200_redacted_and_403_404_as_permission_gaps() {
    let server = MockServer::start().await;

    let wf = WorkflowIr::from_json_value(json!({
        "id": "wf_live",
        "name": "Live Audit Check",
        "settings": { "errorWorkflow": "wf_err" },
        "nodes": [
            {
                "id": "1",
                "name": "Start",
                "type": "n8n-nodes-base.manualTrigger",
                "typeVersion": 1,
                "position": [0, 0],
                "parameters": {}
            }
        ],
        "connections": {}
    }))
    .expect("IR");

    let make_client = |base_url: String| {
        let mut cfg = ApiClientConfig::new(
            "test-local",
            base_url,
            SecretValue::new("n8n_api_test_key_1234567890"),
        );
        cfg.ssrf_policy = SsrfPolicy {
            allow_loopback_http: true,
            ..SsrfPolicy::default()
        };
        N8nApiClient::new(cfg).expect("client")
    };

    // Case A: HTTP 403 Forbidden -> recorded as PermissionGap (`live_audit_forbidden_403`).
    Mock::given(method("POST"))
        .and(path("/api/v1/audit"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "message": "Forbidden by instance RBAC" })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let client = make_client(server.uri());
    let rep_403 = audit_workflow_with_live_api(&wf, &AuditContext::default(), &client, None).await;
    assert!(rep_403.permission_gaps.iter().any(|g| g.gap_kind.as_deref()
        == Some("live_audit_forbidden_403")
        && g.status_code == Some(403)));

    // Case B: HTTP 404 Not Found -> recorded as PermissionGap (`live_audit_not_found_404`).
    Mock::given(method("POST"))
        .and(path("/api/v1/audit"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({ "message": "Endpoint not found" })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let rep_404 = audit_workflow_with_live_api(&wf, &AuditContext::default(), &client, None).await;
    assert!(rep_404.permission_gaps.iter().any(|g| g.gap_kind.as_deref()
        == Some("live_audit_not_found_404")
        && g.status_code == Some(404)));

    // Case C: HTTP 200 OK with live findings containing an inline token -> merged & redacted!
    let leaked_token = concat!("sk", "-live-ShouldNeverAppearInMergedReport123456789");
    Mock::given(method("POST"))
        .and(path("/api/v1/audit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Credentials Risk Report": {
                "risk": "credentials",
                "sections": [
                    {
                        "title": "Credentials not used in any workflow",
                        "description": format!("Unused token {leaked_token} found"),
                        "recommendation": "Delete unused credentials",
                        "location": [{ "kind": "credential", "id": "c_99" }]
                    }
                ]
            },
            "Database Risk Report": {
                "risk": "database",
                "sections": [
                    {
                        "title": "Expressions in SQL queries",
                        "description": "Unparameterized SQL expression",
                        "location": [{ "kind": "node", "id": "n_sql" }]
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let rep_200 = audit_workflow_with_live_api(&wf, &AuditContext::default(), &client, None).await;
    let out_json = serde_json::to_string(&rep_200).expect("json");
    assert!(!out_json.contains(leaked_token));
    assert!(
        rep_200
            .observed_facts
            .iter()
            .any(|f| f.code == "live_audit:credentials")
    );
    assert!(
        rep_200
            .heuristics
            .iter()
            .any(|h| h.code == "live_audit:database")
    );
}
