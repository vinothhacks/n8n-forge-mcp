//! Streamable HTTP client for n8n Instance-level MCP (`/mcp-server/http`) with isolated bearer token,
//! SSRF/origin pinning, redirect blocking, and bounded response streaming.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::StatusCode;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use n8n_api_client::ssrf::{
    OriginEndpoint, SsrfPolicy, normalize_and_validate_url, resolve_and_validate_origin,
};
use n8n_api_client::streaming::{StreamBudget, read_bounded_response};
use n8n_types::{N8nError, N8nResult, SecretValue, redact_json_value, redact_str};
use reqwest::redirect;
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::negotiation::{
    McpToolDescriptor, NegotiatedMcpTools, PartialUpdateInspection, inspect_partial_update_result,
    negotiate_tools,
};

const HEADER_MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");

/// Configuration for the optional n8n Instance-level MCP bridge (`/mcp-server/http`).
#[derive(Debug, Clone)]
pub struct McpBridgeConfig {
    pub instance_alias: String,
    pub mcp_base_url: String,
    pub access_token: SecretValue,
    pub ssrf_policy: SsrfPolicy,
    pub stream_budget: StreamBudget,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl McpBridgeConfig {
    #[must_use]
    pub fn new(
        instance_alias: impl Into<String>,
        mcp_base_url: impl Into<String>,
        access_token: SecretValue,
    ) -> Self {
        Self {
            instance_alias: instance_alias.into(),
            mcp_base_url: mcp_base_url.into(),
            access_token,
            ssrf_policy: SsrfPolicy::default(),
            stream_budget: StreamBudget::default(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Origin-pinned, token-isolated client for n8n's built-in `/mcp-server/http` endpoint.
#[derive(Clone)]
pub struct NativeMcpBridge {
    inner: Arc<NativeMcpBridgeInner>,
}

struct NativeMcpBridgeInner {
    instance_alias: String,
    origin: OriginEndpoint,
    access_token: SecretValue,
    ssrf_policy: SsrfPolicy,
    stream_budget: StreamBudget,
    http: reqwest::Client,
    session_id: Mutex<Option<String>>,
    negotiated: RwLock<Option<NegotiatedMcpTools>>,
}

impl NativeMcpBridge {
    /// Creates a hardened `NativeMcpBridge` while strictly verifying that `N8N_MCP_ACCESS_TOKEN`
    /// does NOT reuse the Public API `X-N8N-API-KEY`!
    pub fn new(config: McpBridgeConfig, public_api_key: Option<&SecretValue>) -> N8nResult<Self> {
        if config.access_token.is_empty() {
            return Err(N8nError::unauthenticated(
                &config.instance_alias,
                "N8N_MCP_ACCESS_TOKEN is empty or missing",
            ));
        }

        if let Some(api_key) = public_api_key
            && config.access_token.matches_secret(api_key)
        {
            return Err(N8nError::config(
                "N8N_MCP_ACCESS_TOKEN must be an isolated instance-level MCP token and MUST NOT reuse X-N8N-API-KEY",
            ));
        }

        let origin = normalize_and_validate_url(&config.mcp_base_url, &config.ssrf_policy)?;

        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("n8n-rs-mcp-bridge/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                N8nError::config(format!("failed building MCP bridge HTTP client: {e}"))
            })?;

        Ok(Self {
            inner: Arc::new(NativeMcpBridgeInner {
                instance_alias: config.instance_alias,
                origin,
                access_token: config.access_token,
                ssrf_policy: config.ssrf_policy,
                stream_budget: config.stream_budget,
                http,
                session_id: Mutex::new(None),
                negotiated: RwLock::new(None),
            }),
        })
    }

    #[must_use]
    pub fn endpoint_url(&self) -> &url::Url {
        &self.inner.origin.base_url
    }

    /// Returns cached negotiated tools if `handshake_and_list_tools` has already run.
    pub async fn cached_negotiated_tools(&self) -> Option<NegotiatedMcpTools> {
        self.inner.negotiated.read().await.clone()
    }

    fn build_headers(&self) -> N8nResult<HeaderMap> {
        self.inner
            .origin
            .ensure_same_origin(&self.inner.origin.base_url)?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let bearer = format!("Bearer {}", self.inner.access_token.expose_secret());
        let auth_val = HeaderValue::from_str(&bearer)
            .map_err(|_| N8nError::config("N8N_MCP_ACCESS_TOKEN contains invalid header bytes"))?;
        headers.insert(AUTHORIZATION, auth_val);

        if let Some(ref sid) = *self
            .inner
            .session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            && let Ok(sid_val) = HeaderValue::from_str(sid)
        {
            headers.insert(HEADER_MCP_SESSION_ID, sid_val);
        }
        Ok(headers)
    }

    async fn send_jsonrpc(
        &self,
        method_name: &str,
        params: Value,
        is_notification: bool,
    ) -> N8nResult<Value> {
        let _addrs =
            resolve_and_validate_origin(&self.inner.origin, &self.inner.ssrf_policy).await?;
        let headers = self.build_headers()?;

        let rpc_body = if is_notification {
            json!({
                "jsonrpc": "2.0",
                "method": method_name,
                "params": params,
            })
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": format!("rpc_{}", Uuid::now_v7().simple()),
                "method": method_name,
                "params": params,
            })
        };

        let is_mutating_call = method_name == "tools/call";

        let response = self
            .inner
            .http
            .post(self.inner.origin.base_url.clone())
            .headers(headers)
            .json(&rpc_body)
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    N8nError::timeout_unknown(
                        &self.inner.instance_alias,
                        "POST",
                        "/mcp-server/http",
                        is_mutating_call,
                        format!(
                            "Native MCP request timed out: {}",
                            redact_str(&err.to_string())
                        ),
                    )
                } else {
                    N8nError::transport(
                        &self.inner.instance_alias,
                        err.status().map(|s| s.as_u16()),
                        format!(
                            "Native MCP transport error: {}",
                            redact_str(&err.to_string())
                        ),
                    )
                }
            })?;

        let status = response.status();
        if status.is_redirection() {
            let loc = response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<missing Location>");
            return Err(N8nError::ssrf_blocked(
                loc,
                "Native MCP HTTP redirect blocked (isolated bearer token never forwarded)",
            ));
        }

        if let Some(sid_hdr) = response
            .headers()
            .get(HEADER_MCP_SESSION_ID)
            .and_then(|v| v.to_str().ok())
        {
            let mut guard = self
                .inner
                .session_id
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(sid_hdr.to_owned());
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_ascii_lowercase();

        let body_bytes = read_bounded_response(
            &self.inner.instance_alias,
            response,
            self.inner.stream_budget,
        )
        .await?;

        match status {
            StatusCode::UNAUTHORIZED => {
                return Err(N8nError::unauthenticated(
                    &self.inner.instance_alias,
                    "Native MCP token rejected (401 Unauthorized)",
                ));
            }
            StatusCode::FORBIDDEN => {
                return Err(N8nError::forbidden(
                    &self.inner.instance_alias,
                    Some(format!("native_mcp:{method_name}")),
                    "Native MCP access denied (403 Forbidden)",
                ));
            }
            StatusCode::NOT_FOUND => {
                return Err(N8nError::not_found_or_concealed(
                    &self.inner.instance_alias,
                    "/mcp-server/http",
                    "Native MCP endpoint returned 404 (not enabled on instance)",
                ));
            }
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(N8nError::rate_limited(
                    &self.inner.instance_alias,
                    Some("native_mcp".to_owned()),
                    None,
                    "Native MCP rate limited (429)",
                ));
            }
            s if !s.is_success() => {
                return Err(N8nError::transport(
                    &self.inner.instance_alias,
                    Some(s.as_u16()),
                    format!("Native MCP returned HTTP {}", s.as_u16()),
                ));
            }
            _ => {}
        }

        if is_notification || body_bytes.is_empty() {
            return Ok(Value::Null);
        }

        let rpc_envelope = if content_type.contains("text/event-stream") {
            parse_sse_jsonrpc_message(&body_bytes)?
        } else {
            serde_json::from_slice::<Value>(&body_bytes)
                .map_err(|e| N8nError::protocol(format!("invalid Native MCP JSON-RPC: {e}")))?
        };

        if let Some(rpc_err) = rpc_envelope.get("error") {
            let code = rpc_err
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or(-32000);
            let msg = rpc_err
                .get("message")
                .and_then(Value::as_str)
                .map(redact_str)
                .unwrap_or_else(|| "Native MCP JSON-RPC error".to_owned());
            if code == -32001 || msg.to_ascii_lowercase().contains("forbidden") {
                return Err(N8nError::forbidden(
                    &self.inner.instance_alias,
                    Some(format!("native_mcp:{method_name}")),
                    msg,
                ));
            }
            return Err(N8nError::protocol(format!(
                "Native MCP JSON-RPC error ({code}): {msg}"
            )));
        }

        Ok(rpc_envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Performs MCP `initialize`, `notifications/initialized`, and dynamic `tools/list` negotiation.
    pub async fn handshake_and_list_tools(&self) -> N8nResult<NegotiatedMcpTools> {
        let client_proto = ProtocolVersion::LATEST.to_string();
        let init_result = self
            .send_jsonrpc(
                "initialize",
                json!({
                    "protocolVersion": client_proto,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "n8n-rs-mcp",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                }),
                false,
            )
            .await?;

        let server_proto = init_result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .map(str::to_owned);

        // Best-effort initialized notification per MCP spec
        let _ = self
            .send_jsonrpc("notifications/initialized", json!({}), true)
            .await;

        let list_result = self.send_jsonrpc("tools/list", json!({}), false).await?;
        let raw_tools = list_result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut descriptors = Vec::with_capacity(raw_tools.len());
        for t in raw_tools {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                descriptors.push(McpToolDescriptor {
                    name: name.to_owned(),
                    description: t.get("description").and_then(Value::as_str).map(redact_str),
                    input_schema: t.get("inputSchema").cloned().unwrap_or_else(|| json!({})),
                });
            }
        }

        let negotiated = negotiate_tools(server_proto, &descriptors);
        *self.inner.negotiated.write().await = Some(negotiated.clone());
        Ok(negotiated)
    }

    async fn ensure_negotiated(&self) -> N8nResult<NegotiatedMcpTools> {
        if let Some(cached) = self.cached_negotiated_tools().await {
            return Ok(cached);
        }
        self.handshake_and_list_tools().await
    }

    async fn call_native_tool(&self, tool_name: &str, arguments: Value) -> N8nResult<Value> {
        let result = self
            .send_jsonrpc(
                "tools/call",
                json!({
                    "name": tool_name,
                    "arguments": arguments,
                }),
                false,
            )
            .await?;

        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let unpacked = unpack_mcp_tool_content(&result);

        if is_error {
            let msg = unpacked
                .get("message")
                .and_then(Value::as_str)
                .map(redact_str)
                .unwrap_or_else(|| redact_str(&unpacked.to_string()));
            if msg.to_ascii_lowercase().contains("forbidden")
                || msg.to_ascii_lowercase().contains("permission")
            {
                return Err(N8nError::forbidden(
                    &self.inner.instance_alias,
                    Some(format!("native_mcp_tool:{tool_name}")),
                    msg,
                ));
            }
            return Err(N8nError::validation(
                &self.inner.instance_alias,
                vec![tool_name.to_owned()],
                msg,
            ));
        }

        Ok(redact_json_value(&unpacked))
    }

    /// Calls `prepare_workflow_pin_data` (>=2.34) or `prepare_test_pin_data` (<2.34) as negotiated.
    pub async fn prepare_pin_data(&self, workflow_id: &str, pin_data: &Value) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        let Some(tool_name) = neg.pin_data_tool.wire_name() else {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "prepare_workflow_pin_data",
                "Neither `prepare_workflow_pin_data` nor `prepare_test_pin_data` is advertised by Native MCP",
                Some(
                    "Upgrade n8n >= 2.15 and enable Instance-level MCP workflow test tools."
                        .to_owned(),
                ),
            ));
        };
        self.call_native_tool(
            tool_name,
            json!({
                "workflowId": workflow_id,
                "pinData": pin_data,
            }),
        )
        .await
    }

    /// Calls native `validate_node_config` (n8n >= 2.25.1).
    pub async fn validate_node_config(
        &self,
        node_type: &str,
        parameters: &Value,
    ) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_validate_node_config {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "validate_node_config",
                "`validate_node_config` is not advertised by Native MCP (requires n8n >= 2.25.1)",
                None,
            ));
        }
        self.call_native_tool(
            "validate_node_config",
            json!({
                "nodeType": node_type,
                "parameters": parameters,
            }),
        )
        .await
    }

    /// Calls native `validate_workflow`.
    pub async fn validate_workflow(&self, workflow_or_code: &Value) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_validate_workflow {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "validate_workflow",
                "`validate_workflow` is not advertised by Native MCP",
                None,
            ));
        }
        self.call_native_tool("validate_workflow", workflow_or_code.clone())
            .await
    }

    /// Validates Workflow SDK code via `validate_workflow` first, then calls `create_workflow_from_code`
    /// and inspects any auto-assigned credentials or HTTP Request skip notes.
    pub async fn create_workflow_from_code(
        &self,
        workflow_code: &str,
        project_id: Option<&str>,
        http_request_nodes: &[String],
    ) -> N8nResult<PartialUpdateInspection> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_validate_workflow || !neg.has_create_workflow_from_code {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "create_workflow_from_code",
                "Native MCP must advertise both `validate_workflow` and `create_workflow_from_code`",
                None,
            ));
        }

        let validation = self
            .validate_workflow(&json!({ "code": workflow_code }))
            .await?;
        if validation.get("valid").and_then(Value::as_bool) == Some(false) {
            return Err(N8nError::validation(
                &self.inner.instance_alias,
                vec!["validate_workflow".to_owned()],
                format!("Workflow SDK pre-validation failed: {validation}"),
            ));
        }

        let mut args = json!({ "code": workflow_code });
        if let Some(pid) = project_id
            && let Some(obj) = args.as_object_mut()
        {
            obj.insert("projectId".to_owned(), Value::String(pid.to_owned()));
        }

        let created = self
            .call_native_tool("create_workflow_from_code", args)
            .await?;
        Ok(inspect_partial_update_result(&created, http_request_nodes))
    }

    /// Calls partial `update_workflow` and inspects `skippedOperations`, `removedGroups`,
    /// `autoAssignedCredentials`, and HTTP Request credential skip warnings.
    pub async fn update_workflow_partial(
        &self,
        workflow_id: &str,
        operations: &[Value],
        touched_http_request_nodes: &[String],
    ) -> N8nResult<PartialUpdateInspection> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_update_workflow {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "update_workflow",
                "`update_workflow` is not advertised by Native MCP",
                None,
            ));
        }
        let raw = self
            .call_native_tool(
                "update_workflow",
                json!({
                    "workflowId": workflow_id,
                    "operations": operations,
                }),
            )
            .await?;
        Ok(inspect_partial_update_result(
            &raw,
            touched_http_request_nodes,
        ))
    }

    /// Calls native `test_workflow` (n8n >= 2.15).
    pub async fn test_workflow(
        &self,
        workflow_id: &str,
        input_data: Option<&Value>,
    ) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_test_workflow {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "test_workflow",
                "`test_workflow` is not advertised by Native MCP",
                None,
            ));
        }
        let mut args = json!({ "workflowId": workflow_id });
        if let Some(inp) = input_data
            && let Some(obj) = args.as_object_mut()
        {
            obj.insert("data".to_owned(), inp.clone());
        }
        self.call_native_tool("test_workflow", args).await
    }

    /// Calls native `execute_workflow`, enforcing `triggerNodeName` negotiation (n8n >= 2.36):
    /// if a workflow has multiple triggers (`trigger_count > 1`) or `trigger_node_name` is requested
    /// on an older instance without `triggerNodeName` support, fails safely instead of guessing!
    pub async fn execute_workflow(
        &self,
        workflow_id: &str,
        mode: &str,
        trigger_node_name: Option<&str>,
        trigger_count: usize,
        input_data: Option<&Value>,
    ) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_execute_workflow {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "execute_workflow",
                "`execute_workflow` is not advertised by Native MCP",
                None,
            ));
        }

        if (trigger_count > 1 || trigger_node_name.is_some()) && !neg.supports_trigger_node_name {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "execute_workflow.triggerNodeName",
                "Ambiguous workflow trigger selection: `triggerNodeName` is not supported on this n8n version (< 2.36.0); refusing to guess trigger",
                Some("Upgrade n8n >= 2.36.0 or test a single-trigger workflow.".to_owned()),
            ));
        }

        let mut args = json!({
            "workflowId": workflow_id,
            "mode": mode,
        });
        if let Some(obj) = args.as_object_mut() {
            if let Some(trig) = trigger_node_name {
                obj.insert("triggerNodeName".to_owned(), Value::String(trig.to_owned()));
            }
            if let Some(inp) = input_data {
                obj.insert("data".to_owned(), inp.clone());
            }
        }
        self.call_native_tool("execute_workflow", args).await
    }

    /// Calls native `restore_workflow_version` (n8n >= 2.29.0).
    pub async fn restore_workflow_version(
        &self,
        workflow_id: &str,
        version_id: &str,
    ) -> N8nResult<Value> {
        let neg = self.ensure_negotiated().await?;
        if !neg.has_restore_workflow_version {
            return Err(N8nError::unsupported(
                &self.inner.instance_alias,
                "restore_workflow_version",
                "`restore_workflow_version` is not advertised by Native MCP (requires n8n >= 2.29.0)",
                Some(
                    "Use local encrypted snapshot restore as a draft with user approval."
                        .to_owned(),
                ),
            ));
        }
        self.call_native_tool(
            "restore_workflow_version",
            json!({
                "workflowId": workflow_id,
                "versionId": version_id,
            }),
        )
        .await
    }
}

fn parse_sse_jsonrpc_message(bytes: &[u8]) -> N8nResult<Value> {
    let text =
        String::from_utf8(bytes.to_vec()).map_err(|_| N8nError::protocol("non-UTF8 SSE stream"))?;
    let mut last_json: Option<Value> = None;
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            let trimmed = data.trim();
            if !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_str::<Value>(trimmed)
            {
                last_json = Some(parsed);
            }
        }
    }
    last_json.ok_or_else(|| N8nError::protocol("no JSON-RPC payload found in SSE stream"))
}

fn unpack_mcp_tool_content(result: &Value) -> Value {
    if let Some(structured) = result.get("structuredContent") {
        return structured.clone();
    }
    if let Some(content_arr) = result.get("content").and_then(Value::as_array) {
        for item in content_arr {
            if item.get("type").and_then(Value::as_str) == Some("text")
                && let Some(text) = item.get("text").and_then(Value::as_str)
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                    return parsed;
                }
                return json!({ "message": text });
            }
        }
    }
    result.clone()
}

#[cfg(test)]
mod tests {
    use n8n_types::{N8nError, OperationStatus, SecretValue};
    use serde_json::json;

    use crate::{
        McpBridgeConfig, McpToolDescriptor, NativeMcpBridge, PinDataToolName,
        inspect_partial_update_result, negotiate_tools,
    };

    #[test]
    fn refuses_reusing_public_api_key_as_native_mcp_token() {
        let shared = SecretValue::new("n8n_api_shared_secret_value_123");
        let cfg = McpBridgeConfig::new(
            "staging",
            "https://staging-n8n.example.internal/mcp-server/http",
            shared.clone(),
        );
        let res = NativeMcpBridge::new(cfg, Some(&shared));
        assert!(matches!(res, Err(N8nError::Config { .. })));
    }

    #[test]
    fn negotiates_legacy_and_modern_pin_data_and_trigger_node_name() {
        let legacy_tools = vec![
            McpToolDescriptor {
                name: "prepare_test_pin_data".to_owned(),
                description: None,
                input_schema: json!({}),
            },
            McpToolDescriptor {
                name: "execute_workflow".to_owned(),
                description: None,
                input_schema: json!({ "properties": { "workflowId": { "type": "string" } } }),
            },
        ];
        let neg_legacy = negotiate_tools(Some("2025-03-26".to_owned()), &legacy_tools);
        assert_eq!(
            neg_legacy.pin_data_tool,
            PinDataToolName::PrepareTestPinData
        );
        assert!(!neg_legacy.supports_trigger_node_name);
        assert!(neg_legacy.protected_instance_suspected);

        let modern_tools = vec![
            McpToolDescriptor {
                name: "prepare_workflow_pin_data".to_owned(),
                description: None,
                input_schema: json!({}),
            },
            McpToolDescriptor {
                name: "update_workflow".to_owned(),
                description: None,
                input_schema: json!({}),
            },
            McpToolDescriptor {
                name: "execute_workflow".to_owned(),
                description: None,
                input_schema: json!({
                    "properties": {
                        "workflowId": { "type": "string" },
                        "triggerNodeName": { "type": "string" }
                    }
                }),
            },
        ];
        let neg_modern = negotiate_tools(Some("2026-07-28".to_owned()), &modern_tools);
        assert_eq!(
            neg_modern.pin_data_tool,
            PinDataToolName::PrepareWorkflowPinData
        );
        assert!(neg_modern.supports_trigger_node_name);
        assert!(!neg_modern.protected_instance_suspected);
    }

    #[test]
    fn partial_update_inspector_flags_skipped_ops_and_http_request_manual_binding() {
        let raw = json!({
            "workflowId": "wf_42",
            "skippedOperations": [{ "op": "setNodeGroups", "reason": "group node missing" }],
            "removedGroups": ["grp_1"],
            "autoAssignedCredentials": [{
                "nodeName": "Postgres Insert",
                "credentialType": "postgres",
                "credentialId": "cred_pg_1",
                "credentialName": "Staging PG",
                "secret": "MUST_BE_SCRUBBED"
            }],
            "warnings": ["Skipped credential auto-assignment for HTTP Request node"]
        });

        let report = inspect_partial_update_result(&raw, &["Fetch API".to_owned()]);
        assert_eq!(report.derived_status, OperationStatus::Partial);
        assert_eq!(report.skipped_operations.len(), 1);
        assert_eq!(report.removed_groups.len(), 1);
        assert_eq!(report.auto_assigned_credentials.len(), 1);
        assert!(!report.http_request_manual_binding_notes.is_empty());
        assert!(
            !report
                .sanitized_payload
                .to_string()
                .contains("MUST_BE_SCRUBBED")
        );
    }
}
