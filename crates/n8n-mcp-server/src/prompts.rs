use rmcp::{
    ErrorData as McpError,
    model::{
        GetPromptRequestParams, GetPromptResponse, GetPromptResult, ListPromptsResult, Prompt,
        PromptArgument, PromptMessage, Role,
    },
};

/// Return the 5 V2 guidance prompts advertised by `n8n-mcp-server`.
#[must_use]
pub fn build_guidance_prompts() -> ListPromptsResult {
    let prompts = vec![
        Prompt::new(
            "build-workflow",
            Some(
                "Catalog-first workflow creation playbook: search native nodes, inspect effective fields, validate offline, deploy inactive staging draft, and test safely.",
            ),
            Some(vec![
                PromptArgument::new("goal")
                    .with_description("Workflow automation goal to design and build")
                    .with_required(true),
                PromptArgument::new("trigger_type")
                    .with_description("Preferred trigger type (webhook, schedule, manual, app event)")
                    .with_required(false),
                PromptArgument::new("instance")
                    .with_description("Target n8n instance alias")
                    .with_required(false),
            ]),
        )
        .with_title("Build n8n Workflow Safely"),
        Prompt::new(
            "debug-workflow",
            Some(
                "Diagnose failing executions using redacted summaries, inspect upstream node data shapes, validate expressions, and run bounded repair loops.",
            ),
            Some(vec![
                PromptArgument::new("workflow_id")
                    .with_description("Target workflow ID to diagnose")
                    .with_required(true),
                PromptArgument::new("execution_id")
                    .with_description("Optional failing execution ID")
                    .with_required(false),
                PromptArgument::new("instance")
                    .with_description("Target n8n instance alias")
                    .with_required(false),
            ]),
        )
        .with_title("Debug Failing n8n Workflow"),
        Prompt::new(
            "refactor-nodes",
            Some(
                "Safe surgical workflow refactoring: preview AST/graph diff, obtain single-use approvalReceipt via confirm_plan, apply with TOCTOU hash check, and verify read-back.",
            ),
            Some(vec![
                PromptArgument::new("workflow_id")
                    .with_description("Workflow ID to refactor")
                    .with_required(true),
                PromptArgument::new("change_request")
                    .with_description("Requested node/connection/expression modification")
                    .with_required(true),
                PromptArgument::new("instance")
                    .with_description("Target n8n instance alias")
                    .with_required(false),
            ]),
        )
        .with_title("Refactor Workflow Nodes with Preview & Receipt"),
        Prompt::new(
            "security-hardening",
            Some(
                "Run deterministic 6-category security audit (hardcoded secrets, unauthenticated webhooks, SSRF, SQLi, RCE nodes, error handlers) and remediate findings.",
            ),
            Some(vec![
                PromptArgument::new("workflow_id")
                    .with_description("Optional workflow ID (omit to audit across workflows)")
                    .with_required(false),
                PromptArgument::new("instance")
                    .with_description("Target n8n instance alias")
                    .with_required(false),
            ]),
        )
        .with_title("Security & Governance Hardening"),
        Prompt::new(
            "promote-staging-to-prod",
            Some(
                "Safe staging-to-production promotion checklist: T0/T1/T2 verification, audit gate, snapshot capture, confirmed publish, and activeVersionId verification.",
            ),
            Some(vec![
                PromptArgument::new("workflow_id")
                    .with_description("Workflow ID to promote or publish")
                    .with_required(true),
                PromptArgument::new("staging_instance")
                    .with_description("Staging instance alias")
                    .with_required(false),
                PromptArgument::new("prod_instance")
                    .with_description("Production instance alias")
                    .with_required(false),
            ]),
        )
        .with_title("Promote Staging Workflow to Production"),
    ];
    ListPromptsResult::with_all_items(prompts)
}

/// Render one of the 5 guidance prompts with bound arguments.
pub fn render_guidance_prompt(req: &GetPromptRequestParams) -> Result<GetPromptResponse, McpError> {
    let arg_str = |key: &str, default: &str| -> String {
        req.arguments
            .as_ref()
            .and_then(|map| map.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map_or_else(|| default.to_owned(), str::to_owned)
    };

    let instance = arg_str("instance", "<default-instance>");
    let (description, body) = match req.name.as_str() {
        "build-workflow" => {
            let goal = arg_str("goal", "<automation goal>");
            let trigger = arg_str("trigger_type", "auto-select native trigger");
            (
                "Catalog-first workflow creation playbook",
                format!(
                    "Build an n8n workflow for goal: \"{goal}\" (trigger: {trigger}, instance: {instance}).\n\
                     Follow this strict sequence:\n\
                     1. Call `n8n_capabilities` (detail=\"minimal\") to confirm instance policy mode and transports.\n\
                     2. Search native nodes first via `n8n_catalog_nodes` (action=\"search\") and inspect conditionally visible fields via `n8n_inspect_node_config` before falling back to HTTP Request or Code.\n\
                     3. Validate the complete draft JSON offline using `n8n_validate` (profile=\"ai-friendly\" or \"strict\") until zero errors remain.\n\
                     4. Create an INACTIVE draft (`active: false`) via `n8n_workflows` (action=\"create\") or `n8n_deploy_template` — never embed raw credential secrets.\n\
                     5. Verify with `n8n_test_workflow` (mode=\"simulate\" first; if external side effects exist, inspect `classify_workflow_side_effects` before requesting operator approval)."
                ),
            )
        }
        "debug-workflow" => {
            let wf_id = arg_str("workflow_id", "<workflow-id>");
            let exec_id = arg_str("execution_id", "latest failed execution");
            (
                "Redacted execution debugging and bounded repair playbook",
                format!(
                    "Diagnose workflow `{wf_id}` (execution: `{exec_id}`, instance: `{instance}`).\n\
                     1. Fetch redacted execution summary via `n8n_executions` (action=\"get\", detail=\"minimal\" or resource `n8n://{instance}/executions/{{id}}/summary`). Do NOT request full node I/O unless explicitly authorized.\n\
                     2. Inspect the failing node and upstream schema lineage via `n8n_inspect_node_config`.\n\
                     3. Run `n8n_validate` to catch expression syntax, missing required fields, or invalid connections.\n\
                     4. Preview surgical fixes with `n8n_mutate_nodes` (mode=\"preview\"), present the diff + `planId` to the user, call `n8n_workflows` (action=\"confirm_plan\", planId=...) after approval, and commit with `approvalReceipt`."
                ),
            )
        }
        "refactor-nodes" => {
            let wf_id = arg_str("workflow_id", "<workflow-id>");
            let change = arg_str("change_request", "<requested graph/node change>");
            (
                "Preview-confirm-commit surgical node refactoring playbook",
                format!(
                    "Refactor workflow `{wf_id}` on `{instance}`: \"{change}\".\n\
                     1. Read current `versionId`, `activeVersionId`, and `canonicalVersionHash` via `n8n_workflows` (action=\"get\").\n\
                     2. Generate a non-mutating diff using `n8n_mutate_nodes` (mode=\"preview\"). Note: AST expression rewrites fail closed on dynamic bracket indexing—report manual follow-ups if flagged.\n\
                     3. Share the bounded diff (`n8n://{instance}/workflows/{wf_id}/diff/{{planId}}`) with the user and wait for explicit approval.\n\
                     4. Mint a single-use `approvalReceipt` via `n8n_workflows` (action=\"confirm_plan\", planId=...) and execute `n8n_mutate_nodes` (mode=\"apply\", approvalReceipt=...), verifying read-back and snapshot capture."
                ),
            )
        }
        "security-hardening" => {
            let wf_id = arg_str("workflow_id", "all accessible workflows");
            (
                "Deterministic 6-category workflow security audit playbook",
                format!(
                    "Run a security hardening review for `{wf_id}` on `{instance}`.\n\
                     1. Execute `n8n_audit` (action=\"workflow\" or \"batch\", includeLiveAudit=true when supported) to evaluate:\n\
                        - Hardcoded secrets/API keys/JWTs in node parameters\n\
                        - Unauthenticated public Webhook triggers\n\
                        - Dynamic URL expression SSRF sinks\n\
                        - Unparameterized SQL query interpolation\n\
                        - High-risk RCE/filesystem nodes (`executeCommand`, `readWriteFile`, `code`)\n\
                        - Missing error-workflow / retry policies on active workflows\n\
                     2. Prioritize Critical and Error findings and propose previewed `n8n_mutate_nodes` remediations using credential IDs/names only (never secret values)."
                ),
            )
        }
        "promote-staging-to-prod" => {
            let wf_id = arg_str("workflow_id", "<workflow-id>");
            let staging = arg_str("staging_instance", "staging");
            let prod = arg_str("prod_instance", "prod");
            (
                "Guarded staging-to-production workflow promotion playbook",
                format!(
                    "Promote workflow `{wf_id}` from `{staging}` to `{prod}`.\n\
                     1. Confirm `n8n_validate` (profile=\"strict\") and `n8n_audit` pass with zero Critical/Error findings on `{staging}`.\n\
                     2. Run `n8n_test_workflow` (mode=\"simulate\" or approved staging \"manual\") to verify behavior.\n\
                     3. Inspect `{prod}` capabilities via `n8n_capabilities` and capture/verify pre-change versions via `n8n_versions` (action=\"history\" / \"snapshots\").\n\
                     4. Generate a preview plan on `{prod}`, obtain explicit operator confirmation, mint a bound single-use `approvalReceipt` via `confirm_plan`, apply/publish, and verify both `versionId` and `activeVersionId` match expected state."
                ),
            )
        }
        unknown => {
            return Err(McpError::invalid_params(
                format!(
                    "unknown prompt '{unknown}'; available prompts: build-workflow, debug-workflow, refactor-nodes, security-hardening, promote-staging-to-prod"
                ),
                None,
            ));
        }
    };

    let result = GetPromptResult::new(vec![PromptMessage::new_text(Role::User, body)])
        .with_description(description);
    Ok(GetPromptResponse::Complete(result))
}
