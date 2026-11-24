"""
Deterministic seed metadata for `tools/catalog-builder/build_catalog.py`.

Covers 72 n8n core (`n8n-nodes-base.*`) and LangChain/AI (`@n8n/n8n-nodes-langchain.*`)
nodes, 28 credential schemas, and 16 curated native-first workflow templates verified
against MIT-licensed `czlonkowski/n8n-mcp@2.103.2` and n8n `2.48.7` public schemas.
Zero real secrets or live instance tokens are present.
"""

from __future__ import annotations

from typing import Any


def _p(
    name: str,
    display_name: str,
    prop_type: str,
    default: Any = None,
    *,
    required: bool = False,
    description: str = "",
    options: list[dict[str, Any]] | None = None,
    show: dict[str, Any] | None = None,
    hide: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": name,
        "display_name": display_name,
        "type": prop_type,
        "required": required,
        "description": description or f"{display_name} parameter.",
    }
    if default is not None:
        out["default"] = default
    if options is not None:
        out["options"] = options
    if show is not None or hide is not None:
        disp: dict[str, Any] = {}
        if show is not None:
            disp["show"] = show
        if hide is not None:
            disp["hide"] = hide
        out["displayOptions"] = disp
    return out


def _opt(name: str, value: Any, description: str = "") -> dict[str, Any]:
    d: dict[str, Any] = {"name": name, "value": value}
    if description:
        d["description"] = description
    return d


def _op(resource: str, operation: str, display_name: str, description: str = "") -> dict[str, Any]:
    return {
        "resource": resource,
        "operation": operation,
        "display_name": display_name,
        "description": description or f"{display_name} ({resource}.{operation})",
        "action_label": f"{display_name} ({resource})",
    }


def _cred_ref(name: str, required: bool = True, show: dict[str, Any] | None = None) -> dict[str, Any]:
    ref: dict[str, Any] = {"name": name, "required": required}
    if show is not None:
        ref["displayOptions"] = {"show": show}
    return ref


def _node(
    short_type: str,
    display_name: str,
    category: str,
    description: str,
    default_version: str,
    versions: list[str],
    *,
    pkg: str = "n8n-nodes-base",
    style: str = "programmatic",
    is_trigger: bool = False,
    is_webhook: bool = False,
    is_ai_tool: bool = False,
    is_tool_variant: bool = False,
    has_tool_variant: bool = False,
    tool_variant_of: str | None = None,
    priority: int = 1,
    score: int = 95,
    side_effect: str = "pure",
    inputs: list[str] | None = None,
    outputs: list[str] | None = None,
    output_names: list[str] | None = None,
    credentials: list[dict[str, Any]] | None = None,
    properties: list[dict[str, Any]] | None = None,
    operations: list[dict[str, Any]] | None = None,
    keywords: list[str] | None = None,
) -> dict[str, Any]:
    prefix = "n8n-nodes-base" if pkg == "n8n-nodes-base" else "@n8n/n8n-nodes-langchain"
    return {
        "node_type": f"{prefix}.{short_type}",
        "short_type": short_type,
        "package_name": pkg,
        "display_name": display_name,
        "description": description,
        "category": category,
        "development_style": style,
        "default_version": default_version,
        "is_versioned": len(versions) > 1 or "." in default_version,
        "is_trigger": is_trigger,
        "is_webhook": is_webhook,
        "is_ai_tool": is_ai_tool,
        "is_tool_variant": is_tool_variant,
        "has_tool_variant": has_tool_variant,
        "tool_variant_of": tool_variant_of,
        "native_priority": priority,
        "native_score": score,
        "side_effect_class": side_effect,
        "inputs": [] if is_trigger and inputs is None else (inputs if inputs is not None else ["main"]),
        "outputs": outputs if outputs is not None else ["main"],
        "output_names": output_names,
        "credentials": credentials or [],
        "versions": [{"version": v, "deprecated": v != default_version and float(v) < 2.0 and len(versions) > 2} for v in versions],
        "properties": properties or [],
        "operations": operations or [],
        "keywords": keywords or [short_type.lower(), display_name.lower(), category.lower()],
    }


def _service_props(
    resources: list[tuple[str, str]],
    ops_by_res: dict[str, list[tuple[str, str]]],
    extra: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    props: list[dict[str, Any]] = [
        _p(
            "resource",
            "Resource",
            "options",
            resources[0][0],
            required=True,
            options=[_opt(label, val) for val, label in resources],
        )
    ]
    all_ops: list[dict[str, Any]] = []
    for res_val, res_label in resources:
        res_ops = ops_by_res.get(res_val, [("get", "Get")])
        props.append(
            _p(
                "operation",
                "Operation",
                "options",
                res_ops[0][0],
                required=True,
                options=[_opt(op_label, op_val) for op_val, op_label in res_ops],
                show={"resource": [res_val]},
            )
        )
        for op_val, op_label in res_ops:
            all_ops.append(_op(res_val, op_val, f"{op_label} {res_label}"))
    if extra:
        props.extend(extra)
    return props, all_ops


# ---------------------------------------------------------------------------
# Credential Type Definitions (28 schemas)
# ---------------------------------------------------------------------------

CREDENTIAL_TYPES: list[dict[str, Any]] = [
    {"credential_type": "httpBasicAuth", "display_name": "HTTP Basic Auth", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/httprequest/", "auth_kind": "basic", "is_generic": True, "required_fields": ["user", "password"], "supported_nodes": ["n8n-nodes-base.httpRequest", "n8n-nodes-base.webhook"]},
    {"credential_type": "httpHeaderAuth", "display_name": "HTTP Header Auth", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/httprequest/", "auth_kind": "header", "is_generic": True, "required_fields": ["name", "value"], "supported_nodes": ["n8n-nodes-base.httpRequest", "n8n-nodes-base.webhook"]},
    {"credential_type": "httpBearerAuth", "display_name": "HTTP Bearer Auth", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/httprequest/", "auth_kind": "bearer", "is_generic": True, "required_fields": ["token"], "supported_nodes": ["n8n-nodes-base.httpRequest"]},
    {"credential_type": "oAuth2Api", "display_name": "OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/httprequest/", "auth_kind": "oauth2", "is_generic": True, "required_fields": ["clientId", "clientSecret", "accessTokenUrl"], "supported_nodes": ["n8n-nodes-base.httpRequest"]},
    {"credential_type": "postgres", "display_name": "Postgres", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/postgres/", "auth_kind": "database", "is_generic": False, "required_fields": ["host", "database", "user", "password", "port"], "supported_nodes": ["n8n-nodes-base.postgres", "@n8n/n8n-nodes-langchain.vectorStorePGVector"]},
    {"credential_type": "mySql", "display_name": "MySQL", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/mysql/", "auth_kind": "database", "is_generic": False, "required_fields": ["host", "database", "user", "password", "port"], "supported_nodes": ["n8n-nodes-base.mySql"]},
    {"credential_type": "microsoftSql", "display_name": "Microsoft SQL", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/microsoftsql/", "auth_kind": "database", "is_generic": False, "required_fields": ["server", "database", "user", "password"], "supported_nodes": ["n8n-nodes-base.microsoftSql"]},
    {"credential_type": "mongoDb", "display_name": "MongoDB", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/mongodb/", "auth_kind": "database", "is_generic": False, "required_fields": ["connectionString"], "supported_nodes": ["n8n-nodes-base.mongoDb"]},
    {"credential_type": "redis", "display_name": "Redis", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/redis/", "auth_kind": "database", "is_generic": False, "required_fields": ["host", "port"], "supported_nodes": ["n8n-nodes-base.redis"]},
    {"credential_type": "slackApi", "display_name": "Slack API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/slack/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["accessToken"], "supported_nodes": ["n8n-nodes-base.slack"]},
    {"credential_type": "slackOAuth2Api", "display_name": "Slack OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/slack/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.slack"]},
    {"credential_type": "microsoftTeamsOAuth2Api", "display_name": "Microsoft Teams OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/microsoft/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.microsoftTeams"]},
    {"credential_type": "discordBotApi", "display_name": "Discord Bot API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/discord/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["botToken"], "supported_nodes": ["n8n-nodes-base.discord"]},
    {"credential_type": "telegramApi", "display_name": "Telegram API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/telegram/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["accessToken"], "supported_nodes": ["n8n-nodes-base.telegram"]},
    {"credential_type": "gmailOAuth2", "display_name": "Gmail OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/google/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.gmail"]},
    {"credential_type": "googleSheetsOAuth2Api", "display_name": "Google Sheets OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/google/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.googleSheets"]},
    {"credential_type": "googleDriveOAuth2Api", "display_name": "Google Drive OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/google/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.googleDrive"]},
    {"credential_type": "notionApi", "display_name": "Notion API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/notion/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["apiKey"], "supported_nodes": ["n8n-nodes-base.notion"]},
    {"credential_type": "airtableTokenApi", "display_name": "Airtable Personal Access Token", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/airtable/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["accessToken"], "supported_nodes": ["n8n-nodes-base.airtable"]},
    {"credential_type": "hubspotAppToken", "display_name": "HubSpot App Token", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/hubspot/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["appToken"], "supported_nodes": ["n8n-nodes-base.hubspot"]},
    {"credential_type": "salesforceOAuth2Api", "display_name": "Salesforce OAuth2 API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/salesforce/", "auth_kind": "oauth2", "is_generic": False, "required_fields": ["clientId", "clientSecret"], "supported_nodes": ["n8n-nodes-base.salesforce"]},
    {"credential_type": "jiraSoftwareCloudApi", "display_name": "Jira Software Cloud API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/jira/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["email", "apiToken", "domain"], "supported_nodes": ["n8n-nodes-base.jira"]},
    {"credential_type": "githubApi", "display_name": "GitHub API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/github/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["accessToken"], "supported_nodes": ["n8n-nodes-base.github"]},
    {"credential_type": "gitlabApi", "display_name": "GitLab API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/gitlab/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["accessToken", "server"], "supported_nodes": ["n8n-nodes-base.gitlab"]},
    {"credential_type": "openAiApi", "display_name": "OpenAI API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/openai/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["apiKey"], "supported_nodes": ["@n8n/n8n-nodes-langchain.lmChatOpenAi", "@n8n/n8n-nodes-langchain.embeddingsOpenAi"]},
    {"credential_type": "anthropicApi", "display_name": "Anthropic API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/anthropic/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["apiKey"], "supported_nodes": ["@n8n/n8n-nodes-langchain.lmChatAnthropic"]},
    {"credential_type": "googlePalmApi", "display_name": "Google Gemini (PaLM) API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/googleai/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["apiKey"], "supported_nodes": ["@n8n/n8n-nodes-langchain.lmChatGoogleGemini"]},
    {"credential_type": "ollamaApi", "display_name": "Ollama API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/ollama/", "auth_kind": "endpoint", "is_generic": False, "required_fields": ["baseUrl"], "supported_nodes": ["@n8n/n8n-nodes-langchain.lmChatOllama"]},
    {"credential_type": "qdrantApi", "display_name": "Qdrant API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/qdrant/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["qdrantUrl", "apiKey"], "supported_nodes": ["@n8n/n8n-nodes-langchain.vectorStoreQdrant"]},
    {"credential_type": "pineconeApi", "display_name": "Pinecone API", "documentation_url": "https://docs.n8n.io/integrations/builtin/credentials/pinecone/", "auth_kind": "apiKey", "is_generic": False, "required_fields": ["apiKey"], "supported_nodes": ["@n8n/n8n-nodes-langchain.vectorStorePinecone"]},
]


def _build_all_nodes() -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    # 1. Triggers (8)
    nodes.extend([
        _node(
            "webhook", "Webhook", "Core Triggers",
            "Starts the workflow when an HTTP webhook request is received.",
            "2", ["1", "1.1", "2"],
            is_trigger=True, is_webhook=True, priority=1, score=99, side_effect="webhook_io",
            credentials=[
                _cred_ref("httpBasicAuth", show={"authentication": ["basicAuth"]}),
                _cred_ref("httpHeaderAuth", show={"authentication": ["headerAuth"]}),
            ],
            properties=[
                _p("httpMethod", "HTTP Method", "options", "GET", required=True, options=[_opt(m, m) for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]]),
                _p("path", "Path", "string", "", required=True, description="Webhook URL path segment."),
                _p("authentication", "Authentication", "options", "none", options=[_opt("None", "none"), _opt("Basic Auth", "basicAuth"), _opt("Header Auth", "headerAuth")]),
                _p("responseMode", "Respond", "options", "onReceived", options=[_opt("Immediately", "onReceived"), _opt("When Last Node Finishes", "lastNode"), _opt("Using 'Respond to Webhook' Node", "responseNode")]),
                _p("responseCode", "Response Code", "number", 200, hide={"responseMode": ["responseNode"]}),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["webhook", "http trigger", "endpoint", "callback", "rest"],
        ),
        _node(
            "scheduleTrigger", "Schedule Trigger", "Core Triggers",
            "Triggers the workflow on a recurring interval or cron schedule.",
            "1.2", ["1", "1.1", "1.2"],
            is_trigger=True, priority=1, score=98, side_effect="schedule",
            properties=[
                _p("rule", "Trigger Rules", "fixedCollection", {"interval": [{"field": "hours", "hoursInterval": 1}]}, required=True),
            ],
            keywords=["cron", "schedule", "timer", "interval", "recurring"],
        ),
        _node(
            "manualTrigger", "Manual Trigger", "Core Triggers",
            "Starts a workflow manually during testing or operator invocation.",
            "1", ["1"],
            is_trigger=True, priority=1, score=97, side_effect="pure",
            properties=[],
            keywords=["manual", "start", "trigger", "test"],
        ),
        _node(
            "formTrigger", "n8n Form Trigger", "Core Triggers",
            "Generates a hosted web form and starts the workflow on submission.",
            "2.2", ["2", "2.1", "2.2"],
            is_trigger=True, is_webhook=True, priority=1, score=96, side_effect="webhook_io",
            properties=[
                _p("formTitle", "Form Title", "string", "", required=True),
                _p("formDescription", "Form Description", "string", ""),
                _p("formFields", "Form Elements", "fixedCollection", {"values": []}, required=True),
                _p("responseMode", "Respond When", "options", "onReceived", options=[_opt("Form Is Submitted", "onReceived"), _opt("Workflow Finishes", "lastNode")]),
            ],
            keywords=["form", "intake", "survey", "web form", "trigger"],
        ),
        _node(
            "chatTrigger", "When chat message received", "AI Triggers",
            "Starts an AI/conversational workflow when a chat message arrives.",
            "1.1", ["1", "1.1"],
            pkg="@n8n/n8n-nodes-langchain", is_trigger=True, is_webhook=True, priority=1, score=96, side_effect="webhook_io",
            properties=[
                _p("public", "Make Chat Publicly Available", "boolean", False),
                _p("mode", "Mode", "options", "hostedChat", show={"public": [True]}, options=[_opt("Hosted Chat", "hostedChat"), _opt("Embedded Chat", "webhook")]),
                _p("authentication", "Authentication", "options", "none", show={"public": [True]}, options=[_opt("None", "none"), _opt("Basic Auth", "basicAuth"), _opt("n8n User Auth", "n8nUserAuth")]),
                _p("initialMessages", "Initial Messages", "string", "Hi there! How can I assist you?", show={"public": [True], "mode": ["hostedChat"]}),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["chat", "conversational", "ai", "agent trigger", "langchain"],
        ),
        _node(
            "errorTrigger", "Error Trigger", "Core Triggers",
            "Runs when another linked workflow execution fails.",
            "1", ["1"],
            is_trigger=True, priority=1, score=95, side_effect="pure",
            properties=[],
            keywords=["error", "exception", "alert", "failure", "incident"],
        ),
        _node(
            "executeWorkflowTrigger", "Execute Workflow Trigger", "Core Triggers",
            "Entry point for subworkflows invoked by Execute Workflow or Workflow Tool.",
            "1.1", ["1", "1.1"],
            is_trigger=True, priority=1, score=97, side_effect="pure",
            properties=[
                _p("inputSource", "Input Data Mode", "options", "workflowInputs", options=[_opt("Define using fields below", "workflowInputs"), _opt("Define using JSON example", "jsonExample"), _opt("Accept all data", "passthrough")]),
                _p("workflowInputs", "Workflow Inputs", "fixedCollection", {"values": []}, show={"inputSource": ["workflowInputs"]}),
            ],
            keywords=["subworkflow", "callable", "child workflow", "trigger"],
        ),
        _node(
            "wait", "Wait", "Flow Control",
            "Pauses workflow execution for a time interval, specific timestamp, or webhook callback.",
            "1.1", ["1", "1.1"],
            is_webhook=True, priority=2, score=90, side_effect="webhook_io",
            properties=[
                _p("resume", "Resume", "options", "timeInterval", options=[_opt("After Time Interval", "timeInterval"), _opt("At Specified Time", "specificTime"), _opt("On Webhook Call", "webhook"), _opt("On Form Submitted", "form")]),
                _p("amount", "Wait Amount", "number", 1, show={"resume": ["timeInterval"]}),
                _p("unit", "Wait Unit", "options", "hours", show={"resume": ["timeInterval"]}, options=[_opt("Seconds", "seconds"), _opt("Minutes", "minutes"), _opt("Hours", "hours"), _opt("Days", "days")]),
                _p("dateTime", "Date and Time", "dateTime", "", required=True, show={"resume": ["specificTime"]}),
            ],
            keywords=["wait", "sleep", "delay", "human approval", "pause"],
        ),
    ])

    # 2. Flow & Routing (9)
    nodes.extend([
        _node(
            "if", "If", "Flow Control",
            "Routes items to true or false branches using typed filter conditions.",
            "2.2", ["1", "2", "2.1", "2.2"],
            priority=2, score=95, side_effect="pure",
            outputs=["main", "main"], output_names=["true", "false"],
            properties=[
                _p("conditions", "Conditions", "filter", {"options": {"caseSensitive": True, "typeValidation": "strict"}, "conditions": [], "combinator": "and"}, required=True),
                _p("looseTypeValidation", "Convert Types Where Required", "boolean", False),
            ],
            keywords=["if", "branch", "condition", "boolean", "filter"],
        ),
        _node(
            "switch", "Switch", "Flow Control",
            "Routes items across multiple named output branches based on rules or an expression.",
            "3.2", ["1", "2", "3", "3.1", "3.2"],
            priority=2, score=94, side_effect="pure",
            outputs=["main", "main", "main", "main"],
            properties=[
                _p("mode", "Mode", "options", "rules", options=[_opt("Rules", "rules"), _opt("Expression", "expression")]),
                _p("rules", "Routing Rules", "fixedCollection", {"values": []}, required=True, show={"mode": ["rules"]}),
                _p("numberOutputs", "Number of Outputs", "number", 4, show={"mode": ["expression"]}),
                _p("output", "Output Index", "number", 0, required=True, show={"mode": ["expression"]}),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["switch", "router", "multi branch", "case"],
        ),
        _node(
            "merge", "Merge", "Flow Control",
            "Combines data streams from multiple branches by append, join key, position, or SQL.",
            "3.1", ["2", "2.1", "3", "3.1"],
            priority=2, score=93, side_effect="pure",
            inputs=["main", "main"], outputs=["main"],
            properties=[
                _p("mode", "Mode", "options", "append", options=[_opt("Append", "append"), _opt("Combine", "combine"), _opt("SQL Query", "combineBySql"), _opt("Choose Branch", "chooseBranch")]),
                _p("combineBy", "Combine By", "options", "combineByFields", show={"mode": ["combine"]}, options=[_opt("Matching Fields", "combineByFields"), _opt("Position", "combineByPosition"), _opt("All Possible Combinations", "combineAll")]),
                _p("fieldsToMatchString", "Fields to Match", "string", "", required=True, show={"mode": ["combine"], "combineBy": ["combineByFields"]}),
                _p("joinMode", "Output Type", "options", "keepMatches", show={"mode": ["combine"], "combineBy": ["combineByFields"]}, options=[_opt("Keep Matches", "keepMatches"), _opt("Enrich Input 1", "enrichInput1"), _opt("Enrich Input 2", "enrichInput2"), _opt("Keep Everything", "keepEverything")]),
                _p("query", "SQL Query", "string", "SELECT * FROM input1 LEFT JOIN input2 ON input1.id = input2.id", required=True, show={"mode": ["combineBySql"]}),
            ],
            keywords=["merge", "join", "combine", "union", "append"],
        ),
        _node(
            "splitInBatches", "Loop Over Items", "Flow Control",
            "Splits input items into batches and loops until all batches are processed.",
            "3", ["1", "2", "3"],
            priority=2, score=91, side_effect="pure",
            outputs=["main", "main"], output_names=["done", "loop"],
            properties=[
                _p("batchSize", "Batch Size", "number", 10, required=True),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["loop", "split in batches", "batch", "iterate", "chunk"],
        ),
        _node(
            "executeWorkflow", "Execute Workflow", "Flow Control",
            "Calls another n8n workflow as a reusable subworkflow.",
            "1.2", ["1", "1.1", "1.2"],
            has_tool_variant=True, priority=1, score=94, side_effect="subworkflow",
            properties=[
                _p("source", "Source", "options", "database", options=[_opt("Database", "database"), _opt("Local File", "localFile"), _opt("Parameter", "parameter"), _opt("URL", "url")]),
                _p("workflowId", "Workflow", "workflowSelector", "", required=True, show={"source": ["database"]}),
                _p("workflowPath", "Workflow Path", "string", "", required=True, show={"source": ["localFile"]}),
                _p("workflowJson", "Workflow JSON", "json", "", required=True, show={"source": ["parameter"]}),
                _p("mode", "Execution Mode", "options", "once", options=[_opt("Run once with all items", "once"), _opt("Run once for each item", "each")]),
                _p("options", "Options", "collection", {"waitForSubWorkflow": True}),
            ],
            keywords=["subworkflow", "call workflow", "execute workflow", "modular"],
        ),
        _node(
            "respondToWebhook", "Respond to Webhook", "Flow Control",
            "Sends a custom HTTP response back to a Webhook node configured with responseNode mode.",
            "1.1", ["1", "1.1"],
            priority=1, score=95, side_effect="webhook_io",
            properties=[
                _p("respondWith", "Respond With", "options", "firstIncomingItem", options=[_opt("First Incoming Item", "firstIncomingItem"), _opt("All Incoming Items", "allIncomingItems"), _opt("JSON", "json"), _opt("Text", "text"), _opt("Binary", "binary"), _opt("Redirect", "redirect"), _opt("No Data", "noData")]),
                _p("responseBody", "Response Body", "json", "={{ $json }}", required=True, show={"respondWith": ["json"]}),
                _p("redirectURL", "Redirect URL", "string", "", required=True, show={"respondWith": ["redirect"]}),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["webhook response", "http reply", "status code", "respond"],
        ),
        _node(
            "filter", "Filter", "Data Transformation",
            "Keeps items matching structured conditions and discards non-matching items.",
            "2.2", ["1", "2", "2.1", "2.2"],
            priority=2, score=95, side_effect="pure",
            properties=[
                _p("conditions", "Conditions", "filter", {"options": {"caseSensitive": True, "typeValidation": "strict"}, "conditions": [], "combinator": "and"}, required=True),
                _p("looseTypeValidation", "Convert Types Where Required", "boolean", False),
            ],
            keywords=["filter", "where", "discard", "subset"],
        ),
        _node(
            "noOp", "No Operation, do nothing", "Flow Control",
            "Passes items through unchanged as a readable graph anchor.",
            "1", ["1"],
            priority=2, score=85, side_effect="pure",
            keywords=["noop", "pass through", "placeholder"],
        ),
        _node(
            "stopAndError", "Stop and Error", "Flow Control",
            "Explicitly fails the workflow execution with a structured error message or object.",
            "1", ["1"],
            priority=2, score=89, side_effect="pure",
            outputs=[],
            properties=[
                _p("errorType", "Error Type", "options", "errorMessage", options=[_opt("Error Message", "errorMessage"), _opt("Error Object", "errorObject")]),
                _p("errorMessage", "Error Message", "string", "", required=True, show={"errorType": ["errorMessage"]}),
                _p("errorObject", "Error Object", "json", "{}", required=True, show={"errorType": ["errorObject"]}),
            ],
            keywords=["throw", "abort", "fail", "assert", "stop and error"],
        ),
    ])

    # 3. Native Data Transform Nodes (13)
    nodes.extend([
        _node(
            "set", "Edit Fields (Set)", "Data Transformation",
            "Sets, renames, casts, or shapes item fields natively without writing Code.",
            "3.4", ["1", "2", "3", "3.2", "3.3", "3.4"],
            priority=2, score=96, side_effect="pure",
            properties=[
                _p("mode", "Mode", "options", "manual", options=[_opt("Manual Mapping", "manual"), _opt("JSON", "raw")]),
                _p("assignments", "Fields to Set", "assignmentCollection", {"assignments": []}, show={"mode": ["manual"]}),
                _p("jsonOutput", "JSON", "json", "{}", required=True, show={"mode": ["raw"]}),
                _p("includeOtherFields", "Include Other Input Fields", "boolean", False),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["set", "edit fields", "map", "transform", "assign", "rename field"],
        ),
        _node(
            "aggregate", "Aggregate", "Data Transformation",
            "Groups multiple incoming items into a single item or array list.",
            "1", ["1"],
            priority=2, score=93, side_effect="pure",
            properties=[
                _p("aggregate", "Aggregate", "options", "aggregateIndividualFields", options=[_opt("Individual Fields", "aggregateIndividualFields"), _opt("All Item Data (Into a Single List)", "aggregateAllItemData")]),
                _p("fieldsToAggregate", "Fields To Aggregate", "fixedCollection", {"fieldToAggregate": []}, show={"aggregate": ["aggregateIndividualFields"]}),
                _p("destinationFieldName", "Put Output in Field", "string", "data", required=True, show={"aggregate": ["aggregateAllItemData"]}),
            ],
            keywords=["aggregate", "collect", "group", "array"],
        ),
        _node(
            "summarize", "Summarize", "Data Transformation",
            "Computes pivot-style aggregations (count, sum, min, max, average) grouped by fields.",
            "1.1", ["1", "1.1"],
            priority=2, score=93, side_effect="pure",
            properties=[
                _p("fieldsToSummarize", "Fields to Summarize", "fixedCollection", {"values": [{"aggregation": "count", "field": ""}]}, required=True),
                _p("fieldsToSplitBy", "Fields to Split By", "string", ""),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["summarize", "pivot", "group by", "sum", "count", "average"],
        ),
        _node(
            "sort", "Sort", "Data Transformation",
            "Orders items ascending, descending, or randomly.",
            "1", ["1"],
            priority=2, score=92, side_effect="pure",
            properties=[
                _p("type", "Type", "options", "simple", options=[_opt("Simple", "simple"), _opt("Random", "random"), _opt("Code", "code")]),
                _p("sortFieldsUi", "Fields To Sort By", "fixedCollection", {"sortField": []}, show={"type": ["simple"]}),
            ],
            keywords=["sort", "order by", "ranking"],
        ),
        _node(
            "limit", "Limit", "Data Transformation",
            "Restricts the number of items kept from the beginning or end of the stream.",
            "1", ["1"],
            priority=2, score=92, side_effect="pure",
            properties=[
                _p("maxItems", "Max Items", "number", 1, required=True),
                _p("keep", "Keep", "options", "firstItems", options=[_opt("First Items", "firstItems"), _opt("Last Items", "lastItems")]),
            ],
            keywords=["limit", "top", "head", "tail", "slice"],
        ),
        _node(
            "splitOut", "Split Out", "Data Transformation",
            "Expands an array or object field inside an item into separate individual items.",
            "1", ["1"],
            priority=2, score=93, side_effect="pure",
            properties=[
                _p("fieldToSplitOut", "Fields To Split Out", "string", "", required=True),
                _p("include", "Include", "options", "noOtherFields", options=[_opt("No Other Fields", "noOtherFields"), _opt("All Other Fields", "allOtherFields"), _opt("Selected Other Fields", "selectedOtherFields")]),
                _p("fieldsToInclude", "Fields To Include", "string", "", show={"include": ["selectedOtherFields"]}),
            ],
            keywords=["split out", "unnest", "flatten", "explode", "array to items"],
        ),
        _node(
            "removeDuplicates", "Remove Duplicates", "Data Transformation",
            "Deduplicates items within the current run or across executions.",
            "2", ["1", "1.1", "2"],
            priority=2, score=93, side_effect="pure",
            properties=[
                _p("operation", "Operation", "options", "removeDuplicateInputItems", options=[_opt("Remove Items Repeated Within Current Input", "removeDuplicateInputItems"), _opt("Remove Items Processed in Previous Executions", "removeItemsSeenInPreviousExecutions"), _opt("Clear Deduplication History", "clearDeduplicationHistory")]),
                _p("compare", "Compare", "options", "allFields", show={"operation": ["removeDuplicateInputItems"]}, options=[_opt("All Fields", "allFields"), _opt("All Fields Except", "allFieldsExcept"), _opt("Selected Fields", "selectedFields")]),
                _p("fieldsToCompare", "Fields To Compare", "string", "", required=True, show={"operation": ["removeDuplicateInputItems"], "compare": ["selectedFields"]}),
            ],
            keywords=["dedupe", "unique", "distinct", "remove duplicates"],
        ),
        _node(
            "dateTime", "Date & Time", "Data Transformation",
            "Parses, formats, shifts, extracts, or diffs timestamps and timezones natively.",
            "2", ["1", "2"],
            priority=2, score=93, side_effect="pure",
            properties=[
                _p("operation", "Operation", "options", "formatDate", options=[_opt("Format a Date", "formatDate"), _opt("Get Current Date", "getCurrentDate"), _opt("Add to a Date", "addToDate"), _opt("Subtract From a Date", "subtractFromDate"), _opt("Get Time Between Dates", "getTimeBetweenDates"), _opt("Round a Date", "roundDate")]),
                _p("date", "Date", "string", "", required=True, hide={"operation": ["getCurrentDate"]}),
                _p("format", "Format", "options", "yyyy-MM-dd", show={"operation": ["formatDate"]}, options=[_opt("yyyy-MM-dd", "yyyy-MM-dd"), _opt("ISO", "iso"), _opt("Custom Format", "custom")]),
                _p("customFormat", "Custom Format", "string", "yyyy-MM-dd HH:mm:ss", required=True, show={"operation": ["formatDate"], "format": ["custom"]}),
            ],
            operations=[
                _op("dateTime", "formatDate", "Format a Date"),
                _op("dateTime", "getCurrentDate", "Get Current Date"),
                _op("dateTime", "addToDate", "Add to a Date"),
                _op("dateTime", "subtractFromDate", "Subtract From a Date"),
                _op("dateTime", "getTimeBetweenDates", "Get Time Between Dates"),
            ],
            keywords=["date", "time", "timezone", "timestamp", "iso8601"],
        ),
        _node(
            "compareDatasets", "Compare Datasets", "Data Transformation",
            "Diffs two item streams into A-only, same, different, and B-only outputs.",
            "2.3", ["1", "2", "2.3"],
            priority=2, score=92, side_effect="pure",
            inputs=["main", "main"], outputs=["main", "main", "main", "main"],
            output_names=["inAOnly", "same", "different", "inBOnly"],
            properties=[
                _p("mergeByFields", "Fields to Match", "fixedCollection", {"values": [{"field1": "id", "field2": "id"}]}, required=True),
                _p("resolve", "When There Are Differences", "options", "preferInput2", options=[_opt("Use Input A Version", "preferInput1"), _opt("Use Input B Version", "preferInput2"), _opt("Use a Mix of Versions", "mix"), _opt("Include Both Versions", "includeBoth")]),
            ],
            keywords=["diff", "reconcile", "sync", "compare datasets", "delta"],
        ),
        _node(
            "crypto", "Crypto", "Data Transformation",
            "Computes cryptographic hashes, HMAC signatures, random values, or signatures.",
            "1", ["1"],
            priority=2, score=91, side_effect="pure",
            properties=[
                _p("action", "Action", "options", "hash", options=[_opt("Hash", "hash"), _opt("Hmac", "hmac"), _opt("Sign", "sign"), _opt("Generate", "generate")]),
                _p("type", "Type", "options", "SHA256", show={"action": ["hash", "hmac"]}, options=[_opt("MD5", "MD5"), _opt("SHA256", "SHA256"), _opt("SHA512", "SHA512")]),
                _p("value", "Value", "string", "", required=True, show={"action": ["hash", "hmac", "sign"]}),
                _p("secret", "Secret", "string", "", required=True, show={"action": ["hmac"]}),
                _p("dataPropertyName", "Property Name", "string", "data", required=True),
            ],
            keywords=["crypto", "sha256", "hmac", "webhook signature", "hash"],
        ),
        _node(
            "compression", "Compression", "Data Transformation",
            "Compresses or decompresses binary attachments using zip or gzip.",
            "1.1", ["1", "1.1"],
            priority=2, score=90, side_effect="pure",
            properties=[
                _p("operation", "Operation", "options", "decompress", options=[_opt("Compress", "compress"), _opt("Decompress", "decompress")]),
                _p("binaryPropertyName", "Input Binary Field(s)", "string", "data", required=True),
                _p("outputFormat", "Output Format", "options", "zip", show={"operation": ["compress"]}, options=[_opt("Gzip", "gzip"), _opt("Zip", "zip")]),
            ],
            keywords=["zip", "gzip", "archive", "decompress", "binary"],
        ),
        _node(
            "html", "HTML", "Data Transformation",
            "Extracts structured CSS-selected content from HTML or renders HTML tables/templates.",
            "1.2", ["1", "1.1", "1.2"],
            priority=2, score=91, side_effect="pure",
            properties=[
                _p("operation", "Operation", "options", "extractHtmlContent", options=[_opt("Generate HTML Template", "generateHtmlTemplate"), _opt("Extract HTML Content", "extractHtmlContent"), _opt("Convert to HTML Table", "convertToHtmlTable")]),
                _p("html", "HTML", "string", "<!DOCTYPE html><html><body></body></html>", required=True, show={"operation": ["generateHtmlTemplate"]}),
                _p("sourceData", "Source Data", "options", "json", show={"operation": ["extractHtmlContent"]}, options=[_opt("JSON", "json"), _opt("Binary", "binary")]),
                _p("extractionValues", "Extraction Values", "fixedCollection", {"values": []}, required=True, show={"operation": ["extractHtmlContent"]}),
            ],
            keywords=["html", "css selector", "scrape", "parse html", "table"],
        ),
        _node(
            "xml", "XML", "Data Transformation",
            "Converts seamlessly between XML documents and JSON objects.",
            "1", ["1"],
            priority=2, score=91, side_effect="pure",
            properties=[
                _p("mode", "Mode", "options", "xmlToJson", options=[_opt("XML to JSON", "xmlToJson"), _opt("JSON to XML", "jsonToXml")]),
                _p("dataPropertyName", "Property Name", "string", "data", required=True),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["xml", "soap", "rss", "xml to json"],
        ),
        _node(
            "markdown", "Markdown", "Data Transformation",
            "Converts between Markdown text and sanitized HTML.",
            "1", ["1"],
            priority=2, score=91, side_effect="pure",
            properties=[
                _p("mode", "Mode", "options", "markdownToHtml", options=[_opt("Markdown to HTML", "markdownToHtml"), _opt("HTML to Markdown", "htmlToMarkdown")]),
                _p("markdown", "Markdown", "string", "", required=True, show={"mode": ["markdownToHtml"]}),
                _p("html", "HTML", "string", "", required=True, show={"mode": ["htmlToMarkdown"]}),
                _p("destinationKey", "Destination Key", "string", "data", required=True),
            ],
            keywords=["markdown", "html", "docs", "convert"],
        ),
    ])

    # 4. HTTP, Code, OS, Disk, DataTable (5)
    nodes.extend([
        _node(
            "httpRequest", "HTTP Request", "Core Network",
            "Makes HTTP/REST requests to external APIs when no dedicated native service node exists.",
            "4.2", ["1", "2", "3", "4.1", "4.2"],
            has_tool_variant=True, priority=3, score=80, side_effect="network_read_or_write",
            credentials=[
                _cred_ref("httpBasicAuth", False, show={"authentication": ["genericCredentialType"], "genericAuthType": ["httpBasicAuth"]}),
                _cred_ref("httpHeaderAuth", False, show={"authentication": ["genericCredentialType"], "genericAuthType": ["httpHeaderAuth"]}),
                _cred_ref("httpBearerAuth", False, show={"authentication": ["genericCredentialType"], "genericAuthType": ["httpBearerAuth"]}),
                _cred_ref("oAuth2Api", False, show={"authentication": ["genericCredentialType"], "genericAuthType": ["oAuth2Api"]}),
            ],
            properties=[
                _p("method", "Method", "options", "GET", required=True, options=[_opt(m, m) for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]]),
                _p("url", "URL", "string", "", required=True, description="Target HTTPS/HTTP endpoint URL."),
                _p("authentication", "Authentication", "options", "none", options=[_opt("None", "none"), _opt("Predefined Credential Type", "predefinedCredentialType"), _opt("Generic Credential Type", "genericCredentialType")]),
                _p("genericAuthType", "Generic Auth Type", "options", "httpHeaderAuth", show={"authentication": ["genericCredentialType"]}, options=[_opt("Basic Auth", "httpBasicAuth"), _opt("Header Auth", "httpHeaderAuth"), _opt("Bearer Auth", "httpBearerAuth"), _opt("OAuth2 API", "oAuth2Api")]),
                _p("sendQuery", "Send Query Parameters", "boolean", False),
                _p("queryParameters", "Query Parameters", "fixedCollection", {"parameters": []}, show={"sendQuery": [True]}),
                _p("sendHeaders", "Send Headers", "boolean", False),
                _p("headerParameters", "Header Parameters", "fixedCollection", {"parameters": []}, show={"sendHeaders": [True]}),
                _p("sendBody", "Send Body", "boolean", False, show={"method": ["POST", "PUT", "PATCH", "DELETE"]}),
                _p("contentType", "Body Content Type", "options", "json", show={"sendBody": [True], "method": ["POST", "PUT", "PATCH", "DELETE"]}, options=[_opt("JSON", "json"), _opt("Form Urlencoded", "form-urlencoded"), _opt("Multipart-Form-Data", "multipart-form-data"), _opt("Raw", "raw")]),
                _p("specifyBody", "Specify Body", "options", "keypair", show={"sendBody": [True], "contentType": ["json"], "method": ["POST", "PUT", "PATCH", "DELETE"]}, options=[_opt("Using Fields Below", "keypair"), _opt("Using JSON", "json")]),
                _p("jsonBody", "JSON", "json", "{}", required=True, show={"sendBody": [True], "contentType": ["json"], "specifyBody": ["json"], "method": ["POST", "PUT", "PATCH", "DELETE"]}),
                _p("options", "Options", "collection", {}),
            ],
            keywords=["http", "rest", "api", "fetch", "webhook call", "curl"],
        ),
        _node(
            "code", "Code", "Core Scripting",
            "Executes custom JavaScript or Python code. Prefer native nodes first; document 'Why Code:' in notes when required.",
            "2", ["1", "2"],
            priority=4, score=40, side_effect="code_sandbox",
            properties=[
                _p("mode", "Mode", "options", "runOnceForAllItems", options=[_opt("Run Once for All Items", "runOnceForAllItems"), _opt("Run Once for Each Item", "runOnceForEachItem")]),
                _p("language", "Language", "options", "javaScript", options=[_opt("JavaScript", "javaScript"), _opt("Python (Beta)", "python")]),
                _p("jsCode", "JavaScript", "string", "return $input.all();", required=True, show={"language": ["javaScript"]}),
                _p("pythonCode", "Python", "string", "return _input.all()", required=True, show={"language": ["python"]}),
            ],
            keywords=["code", "javascript", "python", "function", "script"],
        ),
        _node(
            "executeCommand", "Execute Command", "Core OS",
            "Executes a shell command on the host container. Restricted in T1 simulation and guarded policies.",
            "1", ["1"],
            priority=5, score=20, side_effect="filesystem_or_os",
            properties=[
                _p("executeOnce", "Execute Once", "boolean", True),
                _p("command", "Command", "string", "", required=True),
            ],
            keywords=["shell", "bash", "cli", "command", "exec"],
        ),
        _node(
            "readWriteFile", "Read/Write Files from Disk", "Core Files",
            "Reads or writes binary files on the local host filesystem.",
            "1", ["1"],
            priority=2, score=75, side_effect="filesystem_or_os",
            properties=[
                _p("operation", "Operation", "options", "read", options=[_opt("Read File(s) From Disk", "read"), _opt("Write File to Disk", "write")]),
                _p("fileSelector", "File(s) Selector", "string", "", required=True, show={"operation": ["read"]}),
                _p("fileName", "File Path and Name", "string", "", required=True, show={"operation": ["write"]}),
                _p("dataPropertyName", "Input Binary Field", "string", "data", required=True, show={"operation": ["write"]}),
            ],
            operations=[_op("file", "read", "Read File From Disk"), _op("file", "write", "Write File to Disk")],
            keywords=["disk", "file", "read file", "write file", "filesystem"],
        ),
        _node(
            "dataTable", "Data Table", "Core Storage",
            "Reads, inserts, updates, upserts, and deletes rows in native n8n Data Tables.",
            "1", ["1"],
            has_tool_variant=True, priority=1, score=96, side_effect="database",
            properties=[
                _p("operation", "Operation", "options", "get", options=[_opt("Get Many", "get"), _opt("Insert", "insert"), _opt("Update", "update"), _opt("Upsert", "upsert"), _opt("Delete", "delete")]),
                _p("dataTableId", "Data Table", "resourceLocator", "", required=True),
                _p("columns", "Columns", "resourceMapper", {}, show={"operation": ["insert", "update", "upsert"]}),
                _p("filters", "Filters", "fixedCollection", {"conditions": []}, show={"operation": ["get", "update", "delete"]}),
                _p("limit", "Limit", "number", 50, show={"operation": ["get"]}),
            ],
            operations=[
                _op("row", "get", "Get Many Rows"),
                _op("row", "insert", "Insert Row"),
                _op("row", "update", "Update Row"),
                _op("row", "upsert", "Upsert Row"),
                _op("row", "delete", "Delete Row"),
            ],
            keywords=["datatable", "data table", "table", "storage", "state"],
        ),
    ])

    # 5. Databases (5)
    nodes.extend([
        _node(
            "postgres", "Postgres", "Databases",
            "Executes queries, inserts, upserts, updates, and deletes against PostgreSQL.",
            "2.5", ["1", "2.2", "2.4", "2.5"],
            has_tool_variant=True, priority=1, score=98, side_effect="database",
            credentials=[_cred_ref("postgres")],
            properties=[
                _p("operation", "Operation", "options", "select", options=[_opt("Execute Query", "executeQuery"), _opt("Insert", "insert"), _opt("Insert or Update", "upsert"), _opt("Select", "select"), _opt("Update", "update"), _opt("DeleteTable", "deleteTable")]),
                _p("schema", "Schema", "string", "public", hide={"operation": ["executeQuery"]}),
                _p("table", "Table", "string", "", required=True, hide={"operation": ["executeQuery"]}),
                _p("query", "Query", "string", "", required=True, show={"operation": ["executeQuery"]}),
                _p("columns", "Columns", "resourceMapper", {}, show={"operation": ["insert", "upsert", "update"]}),
                _p("returnAll", "Return All", "boolean", False, show={"operation": ["select"]}),
                _p("limit", "Limit", "number", 50, show={"operation": ["select"], "returnAll": [False]}),
            ],
            operations=[
                _op("database", "executeQuery", "Execute SQL Query"),
                _op("database", "select", "Select Rows"),
                _op("database", "insert", "Insert Rows"),
                _op("database", "upsert", "Upsert Rows"),
                _op("database", "update", "Update Rows"),
                _op("database", "deleteTable", "Delete Rows"),
            ],
            keywords=["postgres", "postgresql", "sql", "relational", "database"],
        ),
        _node(
            "mySql", "MySQL", "Databases",
            "Queries and mutates rows in MySQL or MariaDB databases.",
            "2.4", ["1", "2.1", "2.4"],
            has_tool_variant=True, priority=1, score=97, side_effect="database",
            credentials=[_cred_ref("mySql")],
            properties=[
                _p("operation", "Operation", "options", "select", options=[_opt("Execute SQL", "executeQuery"), _opt("Insert", "insert"), _opt("Insert or Update", "upsert"), _opt("Select", "select"), _opt("Update", "update"), _opt("Delete", "deleteTable")]),
                _p("table", "Table", "string", "", required=True, hide={"operation": ["executeQuery"]}),
                _p("query", "Query", "string", "", required=True, show={"operation": ["executeQuery"]}),
            ],
            operations=[_op("database", "executeQuery", "Execute SQL"), _op("database", "select", "Select Rows"), _op("database", "insert", "Insert Rows"), _op("database", "upsert", "Upsert Rows")],
            keywords=["mysql", "mariadb", "sql", "database"],
        ),
        _node(
            "microsoftSql", "Microsoft SQL", "Databases",
            "Executes T-SQL queries, inserts, updates, and deletes in SQL Server.",
            "1.1", ["1", "1.1"],
            has_tool_variant=True, priority=1, score=97, side_effect="database",
            credentials=[_cred_ref("microsoftSql")],
            properties=[
                _p("operation", "Operation", "options", "executeQuery", options=[_opt("Execute Query", "executeQuery"), _opt("Insert", "insert"), _opt("Update", "update"), _opt("Delete", "delete")]),
                _p("table", "Table", "string", "", required=True, hide={"operation": ["executeQuery"]}),
                _p("query", "Query", "string", "", required=True, show={"operation": ["executeQuery"]}),
            ],
            operations=[_op("database", "executeQuery", "Execute T-SQL Query"), _op("database", "insert", "Insert Rows"), _op("database", "update", "Update Rows")],
            keywords=["mssql", "sql server", "tsql", "database"],
        ),
        _node(
            "mongoDb", "MongoDB", "Databases",
            "Finds, aggregates, inserts, updates, and deletes documents in MongoDB collections.",
            "1.1", ["1", "1.1"],
            has_tool_variant=True, priority=1, score=97, side_effect="database",
            credentials=[_cred_ref("mongoDb")],
            properties=[
                _p("operation", "Operation", "options", "find", options=[_opt("Aggregate", "aggregate"), _opt("Delete", "delete"), _opt("Find", "find"), _opt("Find and Replace", "findOneAndReplace"), _opt("Find and Update", "findOneAndUpdate"), _opt("Insert", "insert"), _opt("Update", "update")]),
                _p("collection", "Collection", "string", "", required=True),
                _p("query", "Query (JSON)", "json", "{}", show={"operation": ["find", "delete", "findOneAndReplace", "findOneAndUpdate"]}),
            ],
            operations=[_op("document", "find", "Find Documents"), _op("document", "aggregate", "Aggregate Documents"), _op("document", "insert", "Insert Documents"), _op("document", "update", "Update Documents")],
            keywords=["mongodb", "nosql", "document", "bson", "collection"],
        ),
        _node(
            "redis", "Redis", "Databases",
            "Reads, sets, increments, publishes, and pops keys/streams in Redis.",
            "1", ["1"],
            has_tool_variant=True, priority=1, score=97, side_effect="database",
            credentials=[_cred_ref("redis")],
            properties=[
                _p("operation", "Operation", "options", "get", options=[_opt("Delete", "delete"), _opt("Get", "get"), _opt("Incr", "incr"), _opt("Keys", "keys"), _opt("Pop", "pop"), _opt("Publish", "publish"), _opt("Push", "push"), _opt("Set", "set")]),
                _p("key", "Key", "string", "", required=True, hide={"operation": ["keys"]}),
                _p("keyPattern", "Key Pattern", "string", "*", required=True, show={"operation": ["keys"]}),
                _p("value", "Value", "string", "", required=True, show={"operation": ["set", "push", "publish"]}),
                _p("expire", "Expire", "boolean", False, show={"operation": ["set"]}),
                _p("ttl", "TTL (Seconds)", "number", 60, show={"operation": ["set"], "expire": [True]}),
            ],
            operations=[_op("key", "get", "Get Key"), _op("key", "set", "Set Key"), _op("key", "delete", "Delete Key"), _op("pubsub", "publish", "Publish Message")],
            keywords=["redis", "cache", "kv", "pubsub", "queue"],
        ),
    ])

    # 6. Messaging, Productivity, CRM & DevOps (14 native service nodes)
    svc_specs: list[dict[str, Any]] = [
        {
            "short": "slack", "name": "Slack", "cat": "Communication", "ver": "2.3", "vers": ["1", "2.1", "2.2", "2.3"],
            "desc": "Posts messages, manages channels, uploads files, and looks up users in Slack.",
            "creds": [_cred_ref("slackApi", False, show={"authentication": ["accessToken"]}), _cred_ref("slackOAuth2Api", False, show={"authentication": ["oAuth2"]})],
            "res": [("message", "Message"), ("channel", "Channel"), ("file", "File"), ("user", "User")],
            "ops": {"message": [("post", "Send"), ("update", "Update"), ("delete", "Delete")], "channel": [("create", "Create"), ("get", "Get"), ("getAll", "Get Many")], "file": [("upload", "Upload")], "user": [("info", "Get"), ("getAll", "Get Many")]},
            "extra": [
                _p("authentication", "Authentication", "options", "accessToken", options=[_opt("Access Token", "accessToken"), _opt("OAuth2", "oAuth2")]),
                _p("channelId", "Channel", "string", "", required=True, show={"resource": ["message"], "operation": ["post", "update", "delete"]}),
                _p("text", "Message Text", "string", "", required=True, show={"resource": ["message"], "operation": ["post", "update"]}),
            ],
            "kw": ["slack", "chat", "alert", "notification", "channel"],
        },
        {
            "short": "microsoftTeams", "name": "Microsoft Teams", "cat": "Communication", "ver": "2", "vers": ["1", "1.1", "2"],
            "desc": "Posts channel/chat messages and manages tasks and channels in Microsoft Teams.",
            "creds": [_cred_ref("microsoftTeamsOAuth2Api")],
            "res": [("channelMessage", "Channel Message"), ("chatMessage", "Chat Message"), ("channel", "Channel"), ("task", "Task")],
            "ops": {"channelMessage": [("create", "Create"), ("getAll", "Get Many")], "chatMessage": [("create", "Create"), ("get", "Get")], "channel": [("create", "Create"), ("getAll", "Get Many")], "task": [("create", "Create"), ("update", "Update")]},
            "extra": [
                _p("teamId", "Team", "string", "", required=True, show={"resource": ["channelMessage", "channel"]}),
                _p("channelId", "Channel", "string", "", required=True, show={"resource": ["channelMessage"]}),
                _p("message", "Message", "string", "", required=True, show={"resource": ["channelMessage", "chatMessage"], "operation": ["create"]}),
            ],
            "kw": ["teams", "microsoft teams", "msteams", "chat", "alert"],
        },
        {
            "short": "discord", "name": "Discord", "cat": "Communication", "ver": "2", "vers": ["1", "2"],
            "desc": "Sends messages, embeds, and manages channels and members in Discord.",
            "creds": [_cred_ref("discordBotApi")],
            "res": [("message", "Message"), ("channel", "Channel"), ("member", "Member")],
            "ops": {"message": [("send", "Send"), ("get", "Get"), ("deleteMessage", "Delete")], "channel": [("create", "Create"), ("getAll", "Get Many")], "member": [("getAll", "Get Many"), ("roleAdd", "Add Role")]},
            "extra": [
                _p("guildId", "Server (Guild)", "string", "", required=True),
                _p("channelId", "Channel", "string", "", required=True, show={"resource": ["message"]}),
                _p("content", "Content", "string", "", required=True, show={"resource": ["message"], "operation": ["send"]}),
            ],
            "kw": ["discord", "bot", "webhook", "community", "message"],
        },
        {
            "short": "telegram", "name": "Telegram", "cat": "Communication", "ver": "1.2", "vers": ["1", "1.1", "1.2"],
            "desc": "Sends messages, photos, documents, and answers callback queries via Telegram Bot API.",
            "creds": [_cred_ref("telegramApi")],
            "res": [("message", "Message"), ("chat", "Chat"), ("file", "File"), ("callback", "Callback")],
            "ops": {"message": [("sendMessage", "Send Message"), ("editMessageText", "Edit Text"), ("sendDocument", "Send Document")], "chat": [("get", "Get"), ("administrators", "Get Administrators")], "file": [("get", "Get")], "callback": [("answerQuery", "Answer Query")]},
            "extra": [
                _p("chatId", "Chat ID", "string", "", required=True, show={"resource": ["message", "chat"]}),
                _p("text", "Text", "string", "", required=True, show={"resource": ["message"], "operation": ["sendMessage", "editMessageText"]}),
            ],
            "kw": ["telegram", "bot", "chat", "notification"],
        },
        {
            "short": "gmail", "name": "Gmail", "cat": "Communication", "ver": "2.1", "vers": ["1", "2", "2.1"],
            "desc": "Sends, replies to, labels, drafts, and searches emails in Gmail.",
            "creds": [_cred_ref("gmailOAuth2")],
            "res": [("message", "Message"), ("draft", "Draft"), ("thread", "Thread"), ("label", "Label")],
            "ops": {"message": [("send", "Send"), ("reply", "Reply"), ("get", "Get"), ("getAll", "Get Many"), ("addLabels", "Add Label")], "draft": [("create", "Create"), ("get", "Get")], "thread": [("get", "Get"), ("getAll", "Get Many")], "label": [("create", "Create"), ("getAll", "Get Many")]},
            "extra": [
                _p("sendTo", "To", "string", "", required=True, show={"resource": ["message", "draft"], "operation": ["send", "create"]}),
                _p("subject", "Subject", "string", "", required=True, show={"resource": ["message", "draft"], "operation": ["send", "create"]}),
                _p("message", "Message", "string", "", required=True, show={"resource": ["message", "draft"], "operation": ["send", "reply", "create"]}),
            ],
            "kw": ["gmail", "email", "google mail", "inbox", "smtp"],
        },
        {
            "short": "googleSheets", "name": "Google Sheets", "cat": "Productivity", "ver": "4.5", "vers": ["2", "4", "4.4", "4.5"],
            "desc": "Reads, appends, updates, upserts, and clears rows and sheets in Google Sheets.",
            "creds": [_cred_ref("googleSheetsOAuth2Api")],
            "res": [("sheet", "Sheet Within Document"), ("spreadsheet", "Document")],
            "ops": {"sheet": [("read", "Get Row(s)"), ("append", "Append Row"), ("update", "Update Row"), ("appendOrUpdate", "Append or Update Row"), ("clear", "Clear")], "spreadsheet": [("create", "Create"), ("deleteSpreadsheet", "Delete")]},
            "extra": [
                _p("documentId", "Document", "resourceLocator", "", required=True),
                _p("sheetName", "Sheet", "resourceLocator", "", required=True, show={"resource": ["sheet"]}),
                _p("columns", "Columns", "resourceMapper", {}, show={"resource": ["sheet"], "operation": ["append", "update", "appendOrUpdate"]}),
            ],
            "kw": ["google sheets", "spreadsheet", "rows", "tabular", "csv"],
        },
        {
            "short": "googleDrive", "name": "Google Drive", "cat": "Productivity", "ver": "3", "vers": ["1", "2", "3"],
            "desc": "Uploads, downloads, moves, shares, and searches files and folders in Google Drive.",
            "creds": [_cred_ref("googleDriveOAuth2Api")],
            "res": [("file", "File"), ("folder", "Folder"), ("fileFolder", "File/Folder")],
            "ops": {"file": [("upload", "Upload"), ("download", "Download"), ("copy", "Copy"), ("deleteFile", "Delete"), ("share", "Share")], "folder": [("create", "Create"), ("deleteFolder", "Delete")], "fileFolder": [("search", "Search")]},
            "extra": [
                _p("fileId", "File", "resourceLocator", "", required=True, show={"resource": ["file"], "operation": ["download", "copy", "deleteFile", "share"]}),
                _p("name", "File Name", "string", "", show={"resource": ["file"], "operation": ["upload"]}),
                _p("queryString", "Search Query", "string", "", show={"resource": ["fileFolder"], "operation": ["search"]}),
            ],
            "kw": ["google drive", "gdrive", "cloud storage", "files", "documents"],
        },
        {
            "short": "notion", "name": "Notion", "cat": "Productivity", "ver": "2.2", "vers": ["1", "2", "2.2"],
            "desc": "Creates and queries Notion database pages, blocks, and workspaces.",
            "creds": [_cred_ref("notionApi")],
            "res": [("databasePage", "Database Page"), ("page", "Page"), ("block", "Block"), ("database", "Database")],
            "ops": {"databasePage": [("create", "Create"), ("get", "Get"), ("getAll", "Get Many"), ("update", "Update")], "page": [("create", "Create"), ("archive", "Archive"), ("search", "Search")], "block": [("append", "Append After"), ("getAll", "Get Child Blocks")], "database": [("get", "Get"), ("getAll", "Get Many")]},
            "extra": [
                _p("databaseId", "Database", "resourceLocator", "", required=True, show={"resource": ["databasePage"]}),
                _p("pageId", "Page", "resourceLocator", "", required=True, show={"resource": ["databasePage"], "operation": ["get", "update"]}),
            ],
            "kw": ["notion", "wiki", "knowledge base", "database page"],
        },
        {
            "short": "airtable", "name": "Airtable", "cat": "Productivity", "ver": "2.1", "vers": ["1", "2", "2.1"],
            "desc": "Creates, reads, searches, updates, and upserts records in Airtable bases.",
            "creds": [_cred_ref("airtableTokenApi")],
            "res": [("record", "Record"), ("base", "Base")],
            "ops": {"record": [("create", "Create"), ("get", "Get"), ("search", "Search"), ("update", "Update"), ("upsert", "Create or Update"), ("delete", "Delete")], "base": [("getMany", "Get Many"), ("getSchema", "Get Schema")]},
            "extra": [
                _p("base", "Base", "resourceLocator", "", required=True),
                _p("table", "Table", "resourceLocator", "", required=True, show={"resource": ["record"]}),
                _p("filterByFormula", "Filter By Formula", "string", "", show={"resource": ["record"], "operation": ["search"]}),
            ],
            "kw": ["airtable", "base", "records", "spreadsheet db"],
        },
        {
            "short": "hubspot", "name": "HubSpot", "cat": "CRM", "ver": "2.1", "vers": ["1", "2", "2.1"],
            "desc": "Manages contacts, companies, deals, and tickets in HubSpot CRM.",
            "creds": [_cred_ref("hubspotAppToken")],
            "res": [("contact", "Contact"), ("company", "Company"), ("deal", "Deal"), ("ticket", "Ticket")],
            "ops": {"contact": [("upsert", "Create or Update"), ("get", "Get"), ("search", "Search")], "company": [("create", "Create"), ("get", "Get"), ("update", "Update")], "deal": [("create", "Create"), ("get", "Get"), ("update", "Update"), ("search", "Search")], "ticket": [("create", "Create"), ("get", "Get"), ("update", "Update")]},
            "extra": [
                _p("email", "Email", "string", "", required=True, show={"resource": ["contact"], "operation": ["upsert"]}),
                _p("additionalFields", "Additional Fields", "collection", {}),
            ],
            "kw": ["hubspot", "crm", "contacts", "deals", "sales"],
        },
        {
            "short": "salesforce", "name": "Salesforce", "cat": "CRM", "ver": "1", "vers": ["1"],
            "desc": "Manages leads, contacts, accounts, opportunities, cases, and SOQL searches in Salesforce.",
            "creds": [_cred_ref("salesforceOAuth2Api")],
            "res": [("lead", "Lead"), ("account", "Account"), ("opportunity", "Opportunity"), ("case", "Case"), ("search", "Search")],
            "ops": {"lead": [("create", "Create"), ("upsert", "Create or Update"), ("get", "Get"), ("update", "Update")], "account": [("create", "Create"), ("get", "Get"), ("update", "Update")], "opportunity": [("create", "Create"), ("get", "Get"), ("update", "Update")], "case": [("create", "Create"), ("get", "Get"), ("update", "Update")], "search": [("query", "Query (SOQL)")]},
            "extra": [
                _p("query", "SOQL Query", "string", "SELECT Id, Name FROM Account LIMIT 10", required=True, show={"resource": ["search"], "operation": ["query"]}),
                _p("lastname", "Last Name", "string", "", required=True, show={"resource": ["lead"], "operation": ["create"]}),
                _p("company", "Company", "string", "", required=True, show={"resource": ["lead"], "operation": ["create"]}),
            ],
            "kw": ["salesforce", "sfdc", "crm", "soql", "lead", "opportunity"],
        },
        {
            "short": "jira", "name": "Jira Software", "cat": "Developer Tools", "ver": "1", "vers": ["1"],
            "desc": "Creates, updates, transitions, comments on, and searches issues in Jira.",
            "creds": [_cred_ref("jiraSoftwareCloudApi")],
            "res": [("issue", "Issue"), ("issueComment", "Issue Comment"), ("user", "User")],
            "ops": {"issue": [("create", "Create"), ("get", "Get"), ("getAll", "Get Many"), ("update", "Update"), ("delete", "Delete")], "issueComment": [("add", "Add"), ("getAll", "Get Many")], "user": [("get", "Get")]},
            "extra": [
                _p("project", "Project", "string", "", required=True, show={"resource": ["issue"], "operation": ["create"]}),
                _p("issueType", "Issue Type", "string", "Task", required=True, show={"resource": ["issue"], "operation": ["create"]}),
                _p("summary", "Summary", "string", "", required=True, show={"resource": ["issue"], "operation": ["create"]}),
                _p("issueKey", "Issue Key", "string", "", required=True, show={"resource": ["issue", "issueComment"], "operation": ["get", "update", "delete", "add", "getAll"]}),
            ],
            "kw": ["jira", "tickets", "issues", "agile", "atlassian"],
        },
        {
            "short": "github", "name": "GitHub", "cat": "Developer Tools", "ver": "1.1", "vers": ["1", "1.1"],
            "desc": "Manages GitHub issues, pull requests, files, releases, and workflow dispatches.",
            "creds": [_cred_ref("githubApi")],
            "res": [("issue", "Issue"), ("file", "File"), ("release", "Release"), ("repository", "Repository"), ("workflow", "Workflow")],
            "ops": {"issue": [("create", "Create"), ("createComment", "Create Comment"), ("edit", "Edit"), ("get", "Get")], "file": [("get", "Get"), ("create", "Create"), ("edit", "Edit")], "release": [("create", "Create"), ("getAll", "Get Many")], "repository": [("get", "Get"), ("getIssues", "Get Issues"), ("listPullRequests", "List Pull Requests")], "workflow": [("dispatch", "Dispatch")]},
            "extra": [
                _p("owner", "Repository Owner", "string", "", required=True),
                _p("repository", "Repository Name", "string", "", required=True),
                _p("title", "Title", "string", "", required=True, show={"resource": ["issue"], "operation": ["create"]}),
            ],
            "kw": ["github", "git", "pull request", "issue", "devops"],
        },
        {
            "short": "gitlab", "name": "GitLab", "cat": "Developer Tools", "ver": "1", "vers": ["1"],
            "desc": "Manages GitLab issues, repositories, files, releases, and merge requests.",
            "creds": [_cred_ref("gitlabApi")],
            "res": [("issue", "Issue"), ("release", "Release"), ("repository", "Repository"), ("file", "File")],
            "ops": {"issue": [("create", "Create"), ("createComment", "Create Comment"), ("edit", "Edit"), ("get", "Get")], "release": [("create", "Create"), ("getAll", "Get Many")], "repository": [("get", "Get"), ("getIssues", "Get Issues")], "file": [("get", "Get"), ("create", "Create"), ("edit", "Edit")]},
            "extra": [
                _p("owner", "Project Owner / Group", "string", "", required=True),
                _p("repository", "Project Name", "string", "", required=True),
                _p("title", "Title", "string", "", required=True, show={"resource": ["issue"], "operation": ["create"]}),
            ],
            "kw": ["gitlab", "git", "merge request", "issue", "ci"],
        },
    ]

    for spec in svc_specs:
        props, ops = _service_props(spec["res"], spec["ops"], spec["extra"])
        nodes.append(
            _node(
                spec["short"], spec["name"], spec["cat"], spec["desc"],
                spec["ver"], spec["vers"],
                has_tool_variant=True, priority=1, score=98, side_effect="network_read_or_write",
                credentials=spec["creds"], properties=props, operations=ops, keywords=spec["kw"],
            )
        )

    # 7. LangChain / AI Cluster Nodes (17)
    nodes.extend([
        _node(
            "agent", "AI Agent", "AI Agents & Chains",
            "Autonomous tool-calling LangChain AI Agent connecting a Chat Model, optional Memory, Tools, and Output Parser.",
            "1.8", ["1.5", "1.6", "1.7", "1.8"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=84, side_effect="subworkflow",
            inputs=["main", "ai_languageModel", "ai_memory", "ai_tool", "ai_outputParser"],
            outputs=["main"],
            properties=[
                _p("promptType", "Source for Prompt (User Message)", "options", "auto", options=[_opt("Connected Chat Trigger Node", "auto"), _opt("Define below", "define")]),
                _p("text", "Prompt (User Message)", "string", "={{ $json.chatInput }}", required=True, show={"promptType": ["define"]}),
                _p("hasOutputParser", "Require Specific Output Format", "boolean", False),
                _p("options", "Options", "collection", {"systemMessage": "You are a helpful assistant.", "maxIterations": 10}),
            ],
            keywords=["ai agent", "agent", "tool calling", "react", "langchain", "llm"],
        ),
        _node(
            "chainLlm", "Basic LLM Chain", "AI Agents & Chains",
            "Deterministic single-turn LLM prompt chain with optional Structured Output Parser.",
            "1.5", ["1.3", "1.4", "1.5"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=84, side_effect="subworkflow",
            inputs=["main", "ai_languageModel", "ai_outputParser"], outputs=["main"],
            properties=[
                _p("promptType", "Source for Prompt (User Message)", "options", "define", options=[_opt("Connected Chat Trigger Node", "auto"), _opt("Define below", "define")]),
                _p("text", "Prompt (User Message)", "string", "", required=True, show={"promptType": ["define"]}),
                _p("hasOutputParser", "Require Specific Output Format", "boolean", False),
                _p("messages", "Chat Messages", "fixedCollection", {"messageValues": []}),
            ],
            keywords=["llm chain", "prompt", "summarize", "classify", "langchain"],
        ),
        _node(
            "lmChatOpenAi", "OpenAI Chat Model", "AI Language Models",
            "Provides an OpenAI chat completion model over the ai_languageModel port.",
            "1.2", ["1", "1.1", "1.2"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=83, side_effect="network_read_or_write",
            inputs=[], outputs=["ai_languageModel"],
            credentials=[_cred_ref("openAiApi")],
            properties=[
                _p("model", "Model", "string", "gpt-4o-mini", required=True),
                _p("options", "Options", "collection", {"temperature": 0.2}),
            ],
            keywords=["openai", "gpt", "chat model", "llm", "ai_languageModel"],
        ),
        _node(
            "lmChatAnthropic", "Anthropic Chat Model", "AI Language Models",
            "Provides an Anthropic Claude model over the ai_languageModel port.",
            "1.3", ["1", "1.2", "1.3"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=83, side_effect="network_read_or_write",
            inputs=[], outputs=["ai_languageModel"],
            credentials=[_cred_ref("anthropicApi")],
            properties=[
                _p("model", "Model", "string", "claude-sonnet-4-20250514", required=True),
                _p("options", "Options", "collection", {"temperature": 0.2, "maxTokensToSample": 4096}),
            ],
            keywords=["anthropic", "claude", "chat model", "llm", "ai_languageModel"],
        ),
        _node(
            "lmChatGoogleGemini", "Google Gemini Chat Model", "AI Language Models",
            "Provides a Google Gemini chat model over the ai_languageModel port.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=83, side_effect="network_read_or_write",
            inputs=[], outputs=["ai_languageModel"],
            credentials=[_cred_ref("googlePalmApi")],
            properties=[
                _p("modelName", "Model", "string", "models/gemini-2.5-flash", required=True),
                _p("options", "Options", "collection", {"temperature": 0.2}),
            ],
            keywords=["gemini", "google ai", "chat model", "llm", "ai_languageModel"],
        ),
        _node(
            "lmChatOllama", "Ollama Chat Model", "AI Language Models",
            "Provides a local or self-hosted Ollama chat model over the ai_languageModel port.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=82, side_effect="network_read_or_write",
            inputs=[], outputs=["ai_languageModel"],
            credentials=[_cred_ref("ollamaApi")],
            properties=[
                _p("model", "Model", "string", "llama3.2:latest", required=True),
                _p("options", "Options", "collection", {"temperature": 0.2}),
            ],
            keywords=["ollama", "local llm", "llama", "ai_languageModel"],
        ),
        _node(
            "memoryBufferWindow", "Simple Memory", "AI Memory",
            "In-memory sliding window conversation buffer connected via ai_memory.",
            "1.3", ["1", "1.2", "1.3"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=82, side_effect="pure",
            inputs=[], outputs=["ai_memory"],
            properties=[
                _p("sessionIdType", "Session ID", "options", "fromInput", options=[_opt("Connected Chat Trigger Node", "fromInput"), _opt("Define below", "customKey")]),
                _p("sessionKey", "Key", "string", "", required=True, show={"sessionIdType": ["customKey"]}),
                _p("contextWindowLength", "Context Window Length", "number", 5),
            ],
            keywords=["memory", "simple memory", "window buffer", "session", "ai_memory"],
        ),
        _node(
            "outputParserStructured", "Structured Output Parser", "AI Output Parsers",
            "Enforces a JSON Schema or example JSON shape on LLM/Agent responses via ai_outputParser.",
            "1.2", ["1", "1.1", "1.2"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=83, side_effect="pure",
            inputs=[], outputs=["ai_outputParser"],
            properties=[
                _p("schemaType", "Schema Type", "options", "fromJson", options=[_opt("Generate From JSON Example", "fromJson"), _opt("Define below", "manual")]),
                _p("jsonSchemaExample", "JSON Example", "json", '{"summary": "string", "confidence": 0.95}', required=True, show={"schemaType": ["fromJson"]}),
                _p("inputSchema", "JSON Schema", "json", '{"type": "object", "properties": {}}', required=True, show={"schemaType": ["manual"]}),
            ],
            keywords=["structured output", "json schema", "parser", "ai_outputParser"],
        ),
        _node(
            "outputParserAutofixing", "Auto-fixing Output Parser", "AI Output Parsers",
            "Wraps another output parser and retries malformed outputs using a Chat Model.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=80, side_effect="subworkflow",
            inputs=["ai_languageModel", "ai_outputParser"], outputs=["ai_outputParser"],
            properties=[
                _p("options", "Options", "collection", {}),
            ],
            keywords=["auto fixing", "retry parser", "output parser", "ai_outputParser"],
        ),
        _node(
            "toolCalculator", "Calculator", "AI Tools",
            "Deterministic arithmetic tool exposed to an AI Agent over ai_tool.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, priority=3, score=82, side_effect="pure",
            inputs=[], outputs=["ai_tool"],
            keywords=["calculator", "math", "tool", "ai_tool"],
        ),
        _node(
            "toolCode", "Custom Code Tool", "AI Tools",
            "JavaScript/Python function tool callable by an AI Agent over ai_tool.",
            "1.2", ["1", "1.1", "1.2"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, priority=4, score=55, side_effect="code_sandbox",
            inputs=[], outputs=["ai_tool"],
            properties=[
                _p("name", "Name", "string", "custom_tool", required=True),
                _p("description", "Description", "string", "Describe when the AI Agent should call this tool.", required=True),
                _p("language", "Language", "options", "javaScript", options=[_opt("JavaScript", "javaScript"), _opt("Python (Beta)", "python")]),
                _p("jsCode", "JavaScript", "string", "return 'result';", required=True, show={"language": ["javaScript"]}),
                _p("specifyInputSchema", "Specify Input Schema", "boolean", False),
            ],
            keywords=["code tool", "custom tool", "function tool", "ai_tool"],
        ),
        _node(
            "toolWorkflow", "Call n8n Workflow Tool", "AI Tools",
            "Exposes a modular n8n subworkflow as a typed tool over ai_tool.",
            "2", ["1.1", "1.2", "2"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, is_tool_variant=True,
            tool_variant_of="n8n-nodes-base.executeWorkflow", priority=2, score=88, side_effect="subworkflow",
            inputs=[], outputs=["ai_tool"],
            properties=[
                _p("name", "Name", "string", "call_workflow", required=True),
                _p("description", "Description", "string", "Calls an n8n subworkflow to fulfill the request.", required=True),
                _p("source", "Source", "options", "database", options=[_opt("Database", "database"), _opt("Parameter", "parameter")]),
                _p("workflowId", "Workflow", "workflowSelector", "", required=True, show={"source": ["database"]}),
            ],
            keywords=["workflow tool", "subworkflow tool", "agent tool", "ai_tool"],
        ),
        _node(
            "vectorStoreQdrant", "Qdrant Vector Store", "AI Vector Stores",
            "Queries, inserts, or exposes Qdrant collections as an AI Agent retrieval tool.",
            "1.1", ["1", "1.1"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, priority=3, score=83, side_effect="database",
            inputs=["main", "ai_embedding", "ai_document"], outputs=["main", "ai_vectorStore", "ai_tool"],
            credentials=[_cred_ref("qdrantApi")],
            properties=[
                _p("mode", "Operation Mode", "options", "retrieve-as-tool", options=[_opt("Get Many", "load"), _opt("Insert Documents", "insert"), _opt("Retrieve Documents (As Vector Store for Chain/Tool)", "retrieve"), _opt("Retrieve Documents (As Tool for AI Agent)", "retrieve-as-tool")]),
                _p("qdrantCollection", "Qdrant Collection", "resourceLocator", "", required=True),
                _p("toolName", "Name", "string", "knowledge_base", required=True, show={"mode": ["retrieve-as-tool"]}),
                _p("toolDescription", "Description", "string", "Search semantic knowledge base documents.", required=True, show={"mode": ["retrieve-as-tool"]}),
                _p("topK", "Limit", "number", 4, show={"mode": ["load", "retrieve", "retrieve-as-tool"]}),
            ],
            keywords=["qdrant", "vector store", "rag", "embeddings", "semantic search"],
        ),
        _node(
            "vectorStorePGVector", "Postgres PGVector Store", "AI Vector Stores",
            "Stores and retrieves vector embeddings in PostgreSQL pgvector tables.",
            "1.1", ["1", "1.1"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, priority=3, score=83, side_effect="database",
            inputs=["main", "ai_embedding", "ai_document"], outputs=["main", "ai_vectorStore", "ai_tool"],
            credentials=[_cred_ref("postgres")],
            properties=[
                _p("mode", "Operation Mode", "options", "retrieve-as-tool", options=[_opt("Get Many", "load"), _opt("Insert Documents", "insert"), _opt("Retrieve Documents (As Vector Store for Chain/Tool)", "retrieve"), _opt("Retrieve Documents (As Tool for AI Agent)", "retrieve-as-tool")]),
                _p("tableName", "Table Name", "string", "n8n_vectors", required=True),
                _p("toolName", "Name", "string", "pgvector_kb", required=True, show={"mode": ["retrieve-as-tool"]}),
                _p("toolDescription", "Description", "string", "Query pgvector semantic index.", required=True, show={"mode": ["retrieve-as-tool"]}),
            ],
            keywords=["pgvector", "postgres vector", "rag", "vector store"],
        ),
        _node(
            "vectorStorePinecone", "Pinecone Vector Store", "AI Vector Stores",
            "Stores and queries vector embeddings in Pinecone serverless/pod indexes.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", is_ai_tool=True, priority=3, score=83, side_effect="database",
            inputs=["main", "ai_embedding", "ai_document"], outputs=["main", "ai_vectorStore", "ai_tool"],
            credentials=[_cred_ref("pineconeApi")],
            properties=[
                _p("mode", "Operation Mode", "options", "retrieve-as-tool", options=[_opt("Get Many", "load"), _opt("Insert Documents", "insert"), _opt("Retrieve Documents (As Vector Store for Chain/Tool)", "retrieve"), _opt("Retrieve Documents (As Tool for AI Agent)", "retrieve-as-tool")]),
                _p("pineconeIndex", "Pinecone Index", "resourceLocator", "", required=True),
                _p("pineconeNamespace", "Pinecone Namespace", "string", ""),
            ],
            keywords=["pinecone", "vector store", "rag", "embeddings"],
        ),
        _node(
            "embeddingsOpenAi", "Embeddings OpenAI", "AI Embeddings",
            "Generates dense vector embeddings via OpenAI over the ai_embedding port.",
            "1.1", ["1", "1.1"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=82, side_effect="network_read_or_write",
            inputs=[], outputs=["ai_embedding"],
            credentials=[_cred_ref("openAiApi")],
            properties=[
                _p("model", "Model", "string", "text-embedding-3-small", required=True),
            ],
            keywords=["embeddings", "openai", "vector", "ai_embedding"],
        ),
        _node(
            "documentDefaultDataLoader", "Default Data Loader", "AI Document Loaders",
            "Converts incoming JSON or binary items into LangChain documents over ai_document.",
            "1", ["1"],
            pkg="@n8n/n8n-nodes-langchain", priority=3, score=81, side_effect="pure",
            inputs=[], outputs=["ai_document"],
            properties=[
                _p("dataType", "Type of Data", "options", "json", options=[_opt("JSON", "json"), _opt("Binary", "binary")]),
                _p("jsonMode", "Mode", "options", "allInputData", show={"dataType": ["json"]}, options=[_opt("All Input Data", "allInputData"), _opt("Expression", "expressionData")]),
            ],
            keywords=["document loader", "chunking", "rag", "ai_document"],
        ),
    ])

    return nodes


NODE_DEFS: list[dict[str, Any]] = _build_all_nodes()


# ---------------------------------------------------------------------------
# Curated Native-First Workflow Templates (16 templates)
# ---------------------------------------------------------------------------

def _wnode(nid: str, name: str, ntype: str, ver: float | int, pos: list[int], params: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": nid,
        "name": name,
        "type": ntype,
        "typeVersion": ver,
        "position": pos,
        "parameters": params,
    }


def _tmpl(
    tid: int,
    slug: str,
    name: str,
    description: str,
    category: str,
    complexity: str,
    minutes: int,
    creds: list[str],
    nodes: list[dict[str, Any]],
    connections: dict[str, Any],
) -> dict[str, Any]:
    used = sorted({n["type"] for n in nodes})
    return {
        "id": tid,
        "slug": slug,
        "name": name,
        "description": description,
        "category": category,
        "complexity": complexity,
        "estimated_setup_minutes": minutes,
        "nodes_used": used,
        "required_credentials": creds,
        "workflow": {
            "name": name,
            "nodes": nodes,
            "connections": connections,
            "settings": {"executionOrder": "v1"},
        },
        "source_attribution": "Clean-room curated pattern verified against MIT czlonkowski/n8n-mcp@2.103.2",
    }


TEMPLATES: list[dict[str, Any]] = [
    _tmpl(
        1, "authenticated-webhook-ack-and-route",
        "Authenticated Webhook Validation & Structured JSON Reply",
        "Validates an incoming Header-Authenticated POST webhook with IF and replies synchronously via Respond to Webhook.",
        "Webhook Processing", "beginner", 10, ["httpHeaderAuth"],
        [
            _wnode("n1", "Inbound Webhook", "n8n-nodes-base.webhook", 2, [200, 300], {"httpMethod": "POST", "path": "events/ingest", "authentication": "headerAuth", "responseMode": "responseNode"}),
            _wnode("n2", "Validate Payload", "n8n-nodes-base.if", 2.2, [440, 300], {"conditions": {"combinator": "and", "conditions": [{"leftValue": "={{ $json.body.eventId }}", "operator": {"type": "string", "operation": "notEmpty"}}]}}),
            _wnode("n3", "Normalize Event", "n8n-nodes-base.set", 3.4, [680, 220], {"mode": "manual", "assignments": {"assignments": [{"name": "accepted", "type": "boolean", "value": True}, {"name": "eventId", "type": "string", "value": "={{ $json.body.eventId }}"}]}}),
            _wnode("n4", "Respond 200", "n8n-nodes-base.respondToWebhook", 1.1, [920, 220], {"respondWith": "json", "responseBody": "={{ $json }}"}),
            _wnode("n5", "Respond 400", "n8n-nodes-base.respondToWebhook", 1.1, [680, 400], {"respondWith": "json", "responseBody": '{"error":"missing_event_id"}', "options": {"responseCode": 400}}),
        ],
        {
            "Inbound Webhook": {"main": [[{"node": "Validate Payload", "type": "main", "index": 0}]]},
            "Validate Payload": {"main": [[{"node": "Normalize Event", "type": "main", "index": 0}], [{"node": "Respond 400", "type": "main", "index": 0}]]},
            "Normalize Event": {"main": [[{"node": "Respond 200", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        2, "hmac-signed-webhook-postgres-upsert",
        "HMAC-Verified Webhook to Postgres Idempotent Upsert",
        "Computes SHA-256 HMAC signature natively with Crypto, verifies equality in IF, and upserts into Postgres.",
        "Webhook Processing", "intermediate", 15, ["postgres"],
        [
            _wnode("n1", "Signed Webhook", "n8n-nodes-base.webhook", 2, [200, 300], {"httpMethod": "POST", "path": "billing/events", "responseMode": "onReceived"}),
            _wnode("n2", "Compute HMAC", "n8n-nodes-base.crypto", 1, [420, 300], {"action": "hmac", "type": "SHA256", "value": "={{ JSON.stringify($json.body) }}", "secret": "={{ $vars.WEBHOOK_SIGNING_PURPOSE }}", "dataPropertyName": "computedSig"}),
            _wnode("n3", "Verify Signature", "n8n-nodes-base.if", 2.2, [640, 300], {"conditions": {"combinator": "and", "conditions": [{"leftValue": "={{ $json.computedSig }}", "rightValue": "={{ $json.headers['x-signature'] }}", "operator": {"type": "string", "operation": "equals"}}]}}),
            _wnode("n4", "Upsert Event", "n8n-nodes-base.postgres", 2.5, [860, 260], {"operation": "upsert", "schema": "public", "table": "webhook_events"}),
        ],
        {
            "Signed Webhook": {"main": [[{"node": "Compute HMAC", "type": "main", "index": 0}]]},
            "Compute HMAC": {"main": [[{"node": "Verify Signature", "type": "main", "index": 0}]]},
            "Verify Signature": {"main": [[{"node": "Upsert Event", "type": "main", "index": 0}], []]},
        },
    ),
    _tmpl(
        3, "scheduled-api-dedupe-slack-digest",
        "Scheduled REST Polling, Deduplication & Slack Digest",
        "Polls an HTTP endpoint on a schedule, deduplicates seen IDs across runs, summarizes counts, and posts to Slack.",
        "Scheduled Automation", "beginner", 12, ["httpHeaderAuth", "slackApi"],
        [
            _wnode("n1", "Hourly Schedule", "n8n-nodes-base.scheduleTrigger", 1.2, [180, 300], {"rule": {"interval": [{"field": "hours", "hoursInterval": 1}]}}),
            _wnode("n2", "Fetch Feed", "n8n-nodes-base.httpRequest", 4.2, [400, 300], {"method": "GET", "url": "https://api.example.com/v1/alerts", "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth"}),
            _wnode("n3", "Split Alerts", "n8n-nodes-base.splitOut", 1, [620, 300], {"fieldToSplitOut": "items"}),
            _wnode("n4", "Dedupe Seen IDs", "n8n-nodes-base.removeDuplicates", 2, [840, 300], {"operation": "removeItemsSeenInPreviousExecutions"}),
            _wnode("n5", "Post Slack Digest", "n8n-nodes-base.slack", 2.3, [1060, 300], {"resource": "message", "operation": "post", "channelId": "C01234567", "text": "={{ 'New alert: ' + $json.title }}"}),
        ],
        {
            "Hourly Schedule": {"main": [[{"node": "Fetch Feed", "type": "main", "index": 0}]]},
            "Fetch Feed": {"main": [[{"node": "Split Alerts", "type": "main", "index": 0}]]},
            "Split Alerts": {"main": [[{"node": "Dedupe Seen IDs", "type": "main", "index": 0}]]},
            "Dedupe Seen IDs": {"main": [[{"node": "Post Slack Digest", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        4, "database-to-google-sheets-delta-sync",
        "Postgres to Google Sheets Delta Reconciliation",
        "Compares Postgres records with Google Sheets rows via Compare Datasets and updates only changed rows.",
        "Database Sync", "intermediate", 20, ["postgres", "googleSheetsOAuth2Api"],
        [
            _wnode("n1", "Daily Schedule", "n8n-nodes-base.scheduleTrigger", 1.2, [180, 300], {"rule": {"interval": [{"field": "days", "daysInterval": 1}]}}),
            _wnode("n2", "Read Postgres", "n8n-nodes-base.postgres", 2.5, [420, 200], {"operation": "select", "schema": "public", "table": "customers", "returnAll": True}),
            _wnode("n3", "Read Sheet", "n8n-nodes-base.googleSheets", 4.5, [420, 400], {"resource": "sheet", "operation": "read", "documentId": "doc_placeholder", "sheetName": "Customers"}),
            _wnode("n4", "Diff Records", "n8n-nodes-base.compareDatasets", 2.3, [680, 300], {"mergeByFields": {"values": [{"field1": "email", "field2": "email"}]}, "resolve": "preferInput1"}),
            _wnode("n5", "Upsert Sheet", "n8n-nodes-base.googleSheets", 4.5, [940, 260], {"resource": "sheet", "operation": "appendOrUpdate", "documentId": "doc_placeholder", "sheetName": "Customers"}),
        ],
        {
            "Daily Schedule": {"main": [[{"node": "Read Postgres", "type": "main", "index": 0}, {"node": "Read Sheet", "type": "main", "index": 0}]]},
            "Read Postgres": {"main": [[{"node": "Diff Records", "type": "main", "index": 0}]]},
            "Read Sheet": {"main": [[{"node": "Diff Records", "type": "main", "index": 1}]]},
            "Diff Records": {"main": [[{"node": "Upsert Sheet", "type": "main", "index": 0}], [], [{"node": "Upsert Sheet", "type": "main", "index": 0}], []]},
        },
    ),
    _tmpl(
        5, "centralized-error-incident-router",
        "Centralized Error Trigger to Jira & Slack Alerting",
        "Captures failed workflow executions via Error Trigger, creates a Jira ticket, and posts incident details to Slack.",
        "Reliability & Ops", "beginner", 10, ["jiraSoftwareCloudApi", "slackApi"],
        [
            _wnode("n1", "On Workflow Error", "n8n-nodes-base.errorTrigger", 1, [200, 300], {}),
            _wnode("n2", "Format Incident", "n8n-nodes-base.set", 3.4, [420, 300], {"mode": "manual", "assignments": {"assignments": [{"name": "summary", "type": "string", "value": "={{ '[n8n Failure] ' + $json.workflow.name }}"}]}}),
            _wnode("n3", "Create Jira Issue", "n8n-nodes-base.jira", 1, [650, 220], {"resource": "issue", "operation": "create", "project": "OPS", "issueType": "Bug", "summary": "={{ $json.summary }}"}),
            _wnode("n4", "Notify Ops Channel", "n8n-nodes-base.slack", 2.3, [650, 380], {"resource": "message", "operation": "post", "channelId": "C0999OPS", "text": "={{ $json.summary }}"}),
        ],
        {
            "On Workflow Error": {"main": [[{"node": "Format Incident", "type": "main", "index": 0}]]},
            "Format Incident": {"main": [[{"node": "Create Jira Issue", "type": "main", "index": 0}, {"node": "Notify Ops Channel", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        6, "conversational-ai-agent-with-memory-and-tools",
        "Conversational AI Agent with Memory, Calculator & Workflow Tool",
        "Wires Chat Trigger to AI Agent with OpenAI Chat Model, Simple Memory, Calculator, and Call n8n Workflow Tool.",
        "AI Agents & RAG", "intermediate", 15, ["openAiApi"],
        [
            _wnode("n1", "Chat Trigger", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1, [200, 300], {"public": False}),
            _wnode("n2", "Support AI Agent", "@n8n/n8n-nodes-langchain.agent", 1.8, [500, 300], {"promptType": "auto", "options": {"systemMessage": "You are a precise operations assistant."}}),
            _wnode("n3", "OpenAI Chat Model", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2, [360, 520], {"model": "gpt-4o-mini"}),
            _wnode("n4", "Simple Memory", "@n8n/n8n-nodes-langchain.memoryBufferWindow", 1.3, [500, 520], {"sessionIdType": "fromInput", "contextWindowLength": 8}),
            _wnode("n5", "Calculator", "@n8n/n8n-nodes-langchain.toolCalculator", 1, [640, 520], {}),
            _wnode("n6", "Lookup Order Subworkflow", "@n8n/n8n-nodes-langchain.toolWorkflow", 2, [780, 520], {"name": "lookup_order", "description": "Fetches order status by orderId.", "source": "database", "workflowId": "subworkflow_placeholder"}),
        ],
        {
            "Chat Trigger": {"main": [[{"node": "Support AI Agent", "type": "main", "index": 0}]]},
            "OpenAI Chat Model": {"ai_languageModel": [[{"node": "Support AI Agent", "type": "ai_languageModel", "index": 0}]]},
            "Simple Memory": {"ai_memory": [[{"node": "Support AI Agent", "type": "ai_memory", "index": 0}]]},
            "Calculator": {"ai_tool": [[{"node": "Support AI Agent", "type": "ai_tool", "index": 0}]]},
            "Lookup Order Subworkflow": {"ai_tool": [[{"node": "Support AI Agent", "type": "ai_tool", "index": 0}]]},
        },
    ),
    _tmpl(
        7, "rag-qdrant-knowledge-assistant",
        "Qdrant Vector Store RAG Agent with OpenAI Embeddings",
        "Connects Qdrant Vector Store in retrieve-as-tool mode with OpenAI Embeddings to an AI Agent.",
        "AI Agents & RAG", "advanced", 25, ["openAiApi", "qdrantApi"],
        [
            _wnode("n1", "Chat Trigger", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1, [200, 300], {"public": False}),
            _wnode("n2", "RAG Agent", "@n8n/n8n-nodes-langchain.agent", 1.8, [520, 300], {"promptType": "auto"}),
            _wnode("n3", "Anthropic Chat Model", "@n8n/n8n-nodes-langchain.lmChatAnthropic", 1.3, [380, 520], {"model": "claude-sonnet-4-20250514"}),
            _wnode("n4", "Qdrant Knowledge Base", "@n8n/n8n-nodes-langchain.vectorStoreQdrant", 1.1, [640, 520], {"mode": "retrieve-as-tool", "qdrantCollection": "docs_kb", "toolName": "docs_kb", "toolDescription": "Search product documentation."}),
            _wnode("n5", "Embeddings OpenAI", "@n8n/n8n-nodes-langchain.embeddingsOpenAi", 1.1, [640, 700], {"model": "text-embedding-3-small"}),
        ],
        {
            "Chat Trigger": {"main": [[{"node": "RAG Agent", "type": "main", "index": 0}]]},
            "Anthropic Chat Model": {"ai_languageModel": [[{"node": "RAG Agent", "type": "ai_languageModel", "index": 0}]]},
            "Qdrant Knowledge Base": {"ai_tool": [[{"node": "RAG Agent", "type": "ai_tool", "index": 0}]]},
            "Embeddings OpenAI": {"ai_embedding": [[{"node": "Qdrant Knowledge Base", "type": "ai_embedding", "index": 0}]]},
        },
    ),
    _tmpl(
        8, "structured-llm-triage-and-switch-router",
        "Structured LLM Ticket Classification & Multi-Branch Switch Router",
        "Classifies incoming tickets using Basic LLM Chain + Structured Output Parser and routes priority via Switch.",
        "AI Classification", "intermediate", 15, ["openAiApi", "slackApi", "jiraSoftwareCloudApi"],
        [
            _wnode("n1", "Ticket Form", "n8n-nodes-base.formTrigger", 2.2, [180, 300], {"formTitle": "Support Request", "formFields": {"values": [{"fieldLabel": "Issue", "fieldType": "textarea"}]}}),
            _wnode("n2", "Classify Ticket", "@n8n/n8n-nodes-langchain.chainLlm", 1.5, [440, 300], {"promptType": "define", "text": "={{ $json.Issue }}", "hasOutputParser": True}),
            _wnode("n3", "OpenAI Chat Model", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1.2, [380, 500], {"model": "gpt-4o-mini"}),
            _wnode("n4", "Structured Output Parser", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2, [560, 500], {"schemaType": "fromJson", "jsonSchemaExample": '{"severity":"high","summary":"Database timeout"}'}),
            _wnode("n5", "Route by Severity", "n8n-nodes-base.switch", 3.2, [720, 300], {"mode": "rules", "rules": {"values": [{"outputKey": "high"}]}}),
            _wnode("n6", "Escalate Slack", "n8n-nodes-base.slack", 2.3, [980, 220], {"resource": "message", "operation": "post", "channelId": "C01URGENT", "text": "={{ $json.output.summary }}"}),
            _wnode("n7", "Log Jira Backlog", "n8n-nodes-base.jira", 1, [980, 380], {"resource": "issue", "operation": "create", "project": "SUP", "issueType": "Task", "summary": "={{ $json.output.summary }}"}),
        ],
        {
            "Ticket Form": {"main": [[{"node": "Classify Ticket", "type": "main", "index": 0}]]},
            "OpenAI Chat Model": {"ai_languageModel": [[{"node": "Classify Ticket", "type": "ai_languageModel", "index": 0}]]},
            "Structured Output Parser": {"ai_outputParser": [[{"node": "Classify Ticket", "type": "ai_outputParser", "index": 0}]]},
            "Classify Ticket": {"main": [[{"node": "Route by Severity", "type": "main", "index": 0}]]},
            "Route by Severity": {"main": [[{"node": "Escalate Slack", "type": "main", "index": 0}], [{"node": "Log Jira Backlog", "type": "main", "index": 0}], [], []]},
        },
    ),
    _tmpl(
        9, "batch-rate-limited-crm-enrichment-loop",
        "Rate-Limited Batch Loop Over Items for HubSpot Contact Enrichment",
        "Iterates contacts in batches of 25 via Loop Over Items, enriches from HTTP API, upserts HubSpot, and pauses cleanly.",
        "CRM Automation", "intermediate", 18, ["httpBearerAuth", "hubspotAppToken"],
        [
            _wnode("n1", "Manual Start", "n8n-nodes-base.manualTrigger", 1, [180, 300], {}),
            _wnode("n2", "Loop Contacts", "n8n-nodes-base.splitInBatches", 3, [400, 300], {"batchSize": 25}),
            _wnode("n3", "Enrich Profile", "n8n-nodes-base.httpRequest", 4.2, [640, 380], {"method": "GET", "url": "={{ 'https://api.example.com/enrich?email=' + encodeURIComponent($json.email) }}", "authentication": "genericCredentialType", "genericAuthType": "httpBearerAuth"}),
            _wnode("n4", "Upsert HubSpot", "n8n-nodes-base.hubspot", 2.1, [860, 380], {"resource": "contact", "operation": "upsert", "email": "={{ $json.email }}"}),
            _wnode("n5", "Throttle Pause", "n8n-nodes-base.wait", 1.1, [1080, 380], {"resume": "timeInterval", "amount": 2, "unit": "seconds"}),
            _wnode("n6", "Summarize Run", "n8n-nodes-base.summarize", 1.1, [640, 180], {"fieldsToSummarize": {"values": [{"aggregation": "count", "field": "email"}]}}),
        ],
        {
            "Manual Start": {"main": [[{"node": "Loop Contacts", "type": "main", "index": 0}]]},
            "Loop Contacts": {"main": [[{"node": "Summarize Run", "type": "main", "index": 0}], [{"node": "Enrich Profile", "type": "main", "index": 0}]]},
            "Enrich Profile": {"main": [[{"node": "Upsert HubSpot", "type": "main", "index": 0}]]},
            "Upsert HubSpot": {"main": [[{"node": "Throttle Pause", "type": "main", "index": 0}]]},
            "Throttle Pause": {"main": [[{"node": "Loop Contacts", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        10, "google-drive-document-ingestion-to-pgvector",
        "Google Drive Markdown/Text Ingestion into Postgres PGVector",
        "Searches updated Google Drive documents, downloads content, loads documents, and indexes vectors in PGVector.",
        "AI Agents & RAG", "advanced", 25, ["googleDriveOAuth2Api", "postgres", "openAiApi"],
        [
            _wnode("n1", "Schedule Sync", "n8n-nodes-base.scheduleTrigger", 1.2, [180, 300], {"rule": {"interval": [{"field": "hours", "hoursInterval": 6}]}}),
            _wnode("n2", "Search Drive", "n8n-nodes-base.googleDrive", 3, [400, 300], {"resource": "fileFolder", "operation": "search", "queryString": "mimeType = 'text/markdown'"}),
            _wnode("n3", "Download File", "n8n-nodes-base.googleDrive", 3, [620, 300], {"resource": "file", "operation": "download", "fileId": "={{ $json.id }}"}),
            _wnode("n4", "Insert PGVector", "@n8n/n8n-nodes-langchain.vectorStorePGVector", 1.1, [880, 300], {"mode": "insert", "tableName": "kb_embeddings"}),
            _wnode("n5", "Embeddings OpenAI", "@n8n/n8n-nodes-langchain.embeddingsOpenAi", 1.1, [820, 500], {"model": "text-embedding-3-small"}),
            _wnode("n6", "Default Data Loader", "@n8n/n8n-nodes-langchain.documentDefaultDataLoader", 1, [980, 500], {"dataType": "binary"}),
        ],
        {
            "Schedule Sync": {"main": [[{"node": "Search Drive", "type": "main", "index": 0}]]},
            "Search Drive": {"main": [[{"node": "Download File", "type": "main", "index": 0}]]},
            "Download File": {"main": [[{"node": "Insert PGVector", "type": "main", "index": 0}]]},
            "Embeddings OpenAI": {"ai_embedding": [[{"node": "Insert PGVector", "type": "ai_embedding", "index": 0}]]},
            "Default Data Loader": {"ai_document": [[{"node": "Insert PGVector", "type": "ai_document", "index": 0}]]},
        },
    ),
    _tmpl(
        11, "github-release-notes-to-notion-and-discord",
        "GitHub Release Webhook to Notion Changelog & Discord Announcement",
        "Receives GitHub release events, converts Markdown release notes, logs a Notion page, and posts to Discord.",
        "DevOps Automation", "beginner", 12, ["notionApi", "discordBotApi"],
        [
            _wnode("n1", "GitHub Webhook", "n8n-nodes-base.webhook", 2, [180, 300], {"httpMethod": "POST", "path": "github/releases"}),
            _wnode("n2", "Filter Published", "n8n-nodes-base.filter", 2.2, [400, 300], {"conditions": {"combinator": "and", "conditions": [{"leftValue": "={{ $json.body.action }}", "rightValue": "published", "operator": {"type": "string", "operation": "equals"}}]}}),
            _wnode("n3", "Render HTML Notes", "n8n-nodes-base.markdown", 1, [620, 300], {"mode": "markdownToHtml", "markdown": "={{ $json.body.release.body }}", "destinationKey": "releaseHtml"}),
            _wnode("n4", "Create Notion Entry", "n8n-nodes-base.notion", 2.2, [860, 220], {"resource": "databasePage", "operation": "create", "databaseId": "notion_db_placeholder"}),
            _wnode("n5", "Announce Discord", "n8n-nodes-base.discord", 2, [860, 380], {"resource": "message", "operation": "send", "guildId": "guild_placeholder", "channelId": "chan_placeholder", "content": "={{ 'Released ' + $json.body.release.tag_name }}"}),
        ],
        {
            "GitHub Webhook": {"main": [[{"node": "Filter Published", "type": "main", "index": 0}]]},
            "Filter Published": {"main": [[{"node": "Render HTML Notes", "type": "main", "index": 0}]]},
            "Render HTML Notes": {"main": [[{"node": "Create Notion Entry", "type": "main", "index": 0}, {"node": "Announce Discord", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        12, "subworkflow-modular-datatable-audit-service",
        "Reusable Subworkflow Service Writing to n8n Data Table",
        "Callable Execute Workflow Trigger subworkflow that validates structured inputs and upserts an n8n Data Table.",
        "Modular Architecture", "beginner", 10, [],
        [
            _wnode("n1", "Subworkflow Entry", "n8n-nodes-base.executeWorkflowTrigger", 1.1, [200, 300], {"inputSource": "workflowInputs"}),
            _wnode("n2", "Stamp Timestamp", "n8n-nodes-base.dateTime", 2, [420, 300], {"operation": "getCurrentDate"}),
            _wnode("n3", "Upsert Audit Row", "n8n-nodes-base.dataTable", 1, [660, 300], {"operation": "upsert", "dataTableId": "audit_events_table"}),
        ],
        {
            "Subworkflow Entry": {"main": [[{"node": "Stamp Timestamp", "type": "main", "index": 0}]]},
            "Stamp Timestamp": {"main": [[{"node": "Upsert Audit Row", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        13, "gmail-lead-intake-to-airtable-and-teams",
        "Gmail Lead Intake, Gemini Extraction & Airtable + Teams Alert",
        "Extracts structured lead attributes from incoming emails using Google Gemini and logs to Airtable and Microsoft Teams.",
        "Sales & Operations", "intermediate", 20, ["gmailOAuth2", "googlePalmApi", "airtableTokenApi", "microsoftTeamsOAuth2Api"],
        [
            _wnode("n1", "Poll Leads Inbox", "n8n-nodes-base.scheduleTrigger", 1.2, [180, 300], {"rule": {"interval": [{"field": "minutes", "minutesInterval": 15}]}}),
            _wnode("n2", "Fetch Unread Emails", "n8n-nodes-base.gmail", 2.1, [400, 300], {"resource": "message", "operation": "getAll"}),
            _wnode("n3", "Extract Lead JSON", "@n8n/n8n-nodes-langchain.chainLlm", 1.5, [640, 300], {"promptType": "define", "text": "={{ $json.snippet }}", "hasOutputParser": True}),
            _wnode("n4", "Gemini Flash", "@n8n/n8n-nodes-langchain.lmChatGoogleGemini", 1, [560, 500], {"modelName": "models/gemini-2.5-flash"}),
            _wnode("n5", "Lead Schema", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2, [740, 500], {"schemaType": "fromJson", "jsonSchemaExample": '{"company":"Acme","contactEmail":"a@acme.example"}'}),
            _wnode("n6", "Upsert Airtable", "n8n-nodes-base.airtable", 2.1, [920, 220], {"resource": "record", "operation": "upsert", "base": "appPlaceholder", "table": "Leads"}),
            _wnode("n7", "Post Teams Channel", "n8n-nodes-base.microsoftTeams", 2, [920, 380], {"resource": "channelMessage", "operation": "create", "teamId": "teamPlaceholder", "channelId": "channelPlaceholder", "message": "={{ 'New lead: ' + $json.output.company }}"}),
        ],
        {
            "Poll Leads Inbox": {"main": [[{"node": "Fetch Unread Emails", "type": "main", "index": 0}]]},
            "Fetch Unread Emails": {"main": [[{"node": "Extract Lead JSON", "type": "main", "index": 0}]]},
            "Gemini Flash": {"ai_languageModel": [[{"node": "Extract Lead JSON", "type": "ai_languageModel", "index": 0}]]},
            "Lead Schema": {"ai_outputParser": [[{"node": "Extract Lead JSON", "type": "ai_outputParser", "index": 0}]]},
            "Extract Lead JSON": {"main": [[{"node": "Upsert Airtable", "type": "main", "index": 0}, {"node": "Post Teams Channel", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        14, "xml-partner-feed-transform-and-merge",
        "XML Partner Feed Parsing, Enrichment Join & Top-N Sort",
        "Downloads an XML partner feed, converts XML to JSON, joins reference pricing with Merge, sorts, and limits top rows.",
        "Data Engineering", "intermediate", 15, ["postgres"],
        [
            _wnode("n1", "Manual Trigger", "n8n-nodes-base.manualTrigger", 1, [180, 300], {}),
            _wnode("n2", "Fetch XML Feed", "n8n-nodes-base.httpRequest", 4.2, [400, 220], {"method": "GET", "url": "https://partner.example.com/catalog.xml"}),
            _wnode("n3", "Parse XML", "n8n-nodes-base.xml", 1, [620, 220], {"mode": "xmlToJson", "dataPropertyName": "data"}),
            _wnode("n4", "Load Pricing", "n8n-nodes-base.postgres", 2.5, [400, 400], {"operation": "select", "schema": "public", "table": "sku_prices", "returnAll": True}),
            _wnode("n5", "Join by SKU", "n8n-nodes-base.merge", 3.1, [840, 300], {"mode": "combine", "combineBy": "combineByFields", "fieldsToMatchString": "sku", "joinMode": "enrichInput1"}),
            _wnode("n6", "Sort Margin", "n8n-nodes-base.sort", 1, [1060, 300], {"type": "simple"}),
            _wnode("n7", "Top 50 Items", "n8n-nodes-base.limit", 1, [1260, 300], {"maxItems": 50, "keep": "firstItems"}),
        ],
        {
            "Manual Trigger": {"main": [[{"node": "Fetch XML Feed", "type": "main", "index": 0}, {"node": "Load Pricing", "type": "main", "index": 0}]]},
            "Fetch XML Feed": {"main": [[{"node": "Parse XML", "type": "main", "index": 0}]]},
            "Parse XML": {"main": [[{"node": "Join by SKU", "type": "main", "index": 0}]]},
            "Load Pricing": {"main": [[{"node": "Join by SKU", "type": "main", "index": 1}]]},
            "Join by SKU": {"main": [[{"node": "Sort Margin", "type": "main", "index": 0}]]},
            "Sort Margin": {"main": [[{"node": "Top 50 Items", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        15, "redis-idempotency-guard-for-telegram-commands",
        "Redis Idempotency Guard for Telegram Bot Commands",
        "Checks Redis key existence before processing a Telegram command, sets TTL lock, and sends reply.",
        "Communication", "intermediate", 15, ["redis", "telegramApi"],
        [
            _wnode("n1", "Bot Webhook", "n8n-nodes-base.webhook", 2, [180, 300], {"httpMethod": "POST", "path": "telegram/hook"}),
            _wnode("n2", "Check Lock", "n8n-nodes-base.redis", 1, [400, 300], {"operation": "get", "key": "={{ 'tg:msg:' + $json.body.update_id }}"}),
            _wnode("n3", "Is New Update", "n8n-nodes-base.if", 2.2, [620, 300], {"conditions": {"combinator": "and", "conditions": [{"leftValue": "={{ $json.propertyName }}", "operator": {"type": "string", "operation": "empty"}}]}}),
            _wnode("n4", "Set TTL Lock", "n8n-nodes-base.redis", 1, [840, 240], {"operation": "set", "key": "={{ 'tg:msg:' + $('Bot Webhook').item.json.body.update_id }}", "value": "1", "expire": True, "ttl": 3600}),
            _wnode("n5", "Send Telegram Reply", "n8n-nodes-base.telegram", 1.2, [1060, 240], {"resource": "message", "operation": "sendMessage", "chatId": "={{ $('Bot Webhook').item.json.body.message.chat.id }}", "text": "Command processed."}),
        ],
        {
            "Bot Webhook": {"main": [[{"node": "Check Lock", "type": "main", "index": 0}]]},
            "Check Lock": {"main": [[{"node": "Is New Update", "type": "main", "index": 0}]]},
            "Is New Update": {"main": [[{"node": "Set TTL Lock", "type": "main", "index": 0}], []]},
            "Set TTL Lock": {"main": [[{"node": "Send Telegram Reply", "type": "main", "index": 0}]]},
        },
    ),
    _tmpl(
        16, "local-ollama-privacy-preserving-log-redactor",
        "Privacy-Preserving Local Ollama Log Summarizer",
        "Summarizes operational logs locally via Ollama Chat Model with Auto-fixing Output Parser and stores aggregates.",
        "Local AI & Privacy", "intermediate", 15, ["ollamaApi"],
        [
            _wnode("n1", "Manual Trigger", "n8n-nodes-base.manualTrigger", 1, [180, 300], {}),
            _wnode("n2", "Local LLM Chain", "@n8n/n8n-nodes-langchain.chainLlm", 1.5, [480, 300], {"promptType": "define", "text": "={{ $json.logLine }}", "hasOutputParser": True}),
            _wnode("n3", "Ollama Chat Model", "@n8n/n8n-nodes-langchain.lmChatOllama", 1, [380, 540], {"model": "llama3.2:latest"}),
            _wnode("n4", "Auto-fixing Parser", "@n8n/n8n-nodes-langchain.outputParserAutofixing", 1, [600, 500], {}),
            _wnode("n5", "Structured Schema", "@n8n/n8n-nodes-langchain.outputParserStructured", 1.2, [700, 680], {"schemaType": "fromJson", "jsonSchemaExample": '{"component":"auth","redactedSummary":"token expired"}'}),
            _wnode("n6", "Aggregate Results", "n8n-nodes-base.aggregate", 1, [760, 300], {"aggregate": "aggregateAllItemData", "destinationFieldName": "summaries"}),
        ],
        {
            "Manual Trigger": {"main": [[{"node": "Local LLM Chain", "type": "main", "index": 0}]]},
            "Ollama Chat Model": {"ai_languageModel": [[{"node": "Local LLM Chain", "type": "ai_languageModel", "index": 0}, {"node": "Auto-fixing Parser", "type": "ai_languageModel", "index": 0}]]},
            "Structured Schema": {"ai_outputParser": [[{"node": "Auto-fixing Parser", "type": "ai_outputParser", "index": 0}]]},
            "Auto-fixing Parser": {"ai_outputParser": [[{"node": "Local LLM Chain", "type": "ai_outputParser", "index": 0}]]},
            "Local LLM Chain": {"main": [[{"node": "Aggregate Results", "type": "main", "index": 0}]]},
        },
    ),
]
