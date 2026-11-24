use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use n8n_types::{N8nError, N8nResult, RiskLevel, SecretValue, redact_json_value};
use rmcp::model::{GetPromptRequestParams, JsonObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::server::N8nMcpServer;

/// Hard 4 MiB request payload ceiling for the optional localhost HTTP MCP gateway.
pub const MAX_HTTP_GATEWAY_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;

/// Configuration for the optional authenticated localhost HTTP MCP gateway.
#[derive(Debug, Clone)]
pub struct HttpGatewayConfig {
    pub bind_addr: SocketAddr,
    pub bearer_token: Option<SecretValue>,
    pub allow_non_loopback: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub max_body_bytes: usize,
}

impl HttpGatewayConfig {
    #[must_use]
    pub fn loopback(bind_addr: SocketAddr, bearer_token: Option<SecretValue>) -> Self {
        Self {
            bind_addr,
            bearer_token,
            allow_non_loopback: false,
            allowed_hosts: vec![
                "127.0.0.1".to_owned(),
                "localhost".to_owned(),
                "[::1]".to_owned(),
            ],
            allowed_origins: Vec::new(),
            max_body_bytes: MAX_HTTP_GATEWAY_BODY_BYTES,
        }
    }

    /// Enforce strict authentication and loopback/allowlist invariants before binding.
    pub fn validate(&self) -> N8nResult<&SecretValue> {
        let token = self.bearer_token.as_ref().ok_or_else(|| {
            N8nError::policy_blocked(
                "http_gateway.start",
                RiskLevel::R4,
                "gateway-auth",
                "HTTP MCP gateway requires a non-empty bearer token; anonymous HTTP mode is forbidden",
                Some("Set N8N_MCP_HTTP_BEARER_TOKEN before starting --transport http.".to_owned()),
            )
        })?;
        if token.is_empty() {
            return Err(N8nError::policy_blocked(
                "http_gateway.start",
                RiskLevel::R4,
                "gateway-auth",
                "HTTP MCP gateway bearer token must not be empty",
                None,
            ));
        }
        if !self.bind_addr.ip().is_loopback()
            && (!self.allow_non_loopback || self.allowed_hosts.is_empty())
        {
            return Err(N8nError::policy_blocked(
                "http_gateway.bind",
                RiskLevel::R4,
                "gateway-bind",
                format!(
                    "Refusing to bind HTTP MCP gateway to non-loopback address `{}` without explicit allow_non_loopback + allowed_hosts",
                    self.bind_addr
                ),
                Some("Bind to 127.0.0.1:<port> or [::1]:<port>.".to_owned()),
            ));
        }
        Ok(token)
    }
}

/// Running localhost HTTP gateway handle.
pub struct HttpGatewayHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl HttpGatewayHandle {
    /// Validate configuration, bind TCP listener, and spawn the HTTP JSON-RPC gateway loop.
    pub async fn start(server: N8nMcpServer, config: HttpGatewayConfig) -> N8nResult<Self> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr).await.map_err(|err| {
            N8nError::transport(
                "http-gateway",
                None,
                format!(
                    "failed to bind HTTP MCP gateway on {}: {err}",
                    config.bind_addr
                ),
            )
        })?;
        let local_addr = listener.local_addr().map_err(|err| {
            N8nError::transport(
                "http-gateway",
                None,
                format!("failed to inspect bound HTTP MCP gateway address: {err}"),
            )
        })?;

        let shared_cfg = Arc::new(config);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let srv = server.clone();
                                let cfg = Arc::clone(&shared_cfg);
                                tokio::spawn(async move {
                                    let _ = handle_connection(stream, srv, cfg).await;
                                });
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "HTTP gateway accept error");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            join_handle,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn wait(self) {
        let _ = self.join_handle.await;
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.join_handle.await;
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

async fn handle_connection(
    mut stream: TcpStream,
    server: N8nMcpServer,
    config: Arc<HttpGatewayConfig>,
) -> Result<(), std::io::Error> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            write_http_json(
                &mut stream,
                431,
                "Request Header Fields Too Large",
                &json!({"error": "request headers exceed 32 KiB limit"}),
            )
            .await?;
            return Ok(());
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    // 1. Validate Host header (DNS rebinding protection)
    let Some(host_val) = headers.get("host") else {
        write_http_json(
            &mut stream,
            400,
            "Bad Request",
            &json!({"error": "missing Host header"}),
        )
        .await?;
        return Ok(());
    };
    if !is_allowed_host(host_val, &config.allowed_hosts) {
        write_http_json(
            &mut stream,
            403,
            "Forbidden",
            &json!({"error": "Host header rejected by DNS-rebinding policy"}),
        )
        .await?;
        return Ok(());
    }

    // 2. Validate Origin header when present (CSRF / browser origin protection)
    if let Some(origin) = headers.get("origin")
        && !config
            .allowed_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
    {
        write_http_json(
            &mut stream,
            403,
            "Forbidden",
            &json!({"error": "Origin header is not allowlisted"}),
        )
        .await?;
        return Ok(());
    }

    // 3. Constant-time Bearer token check
    let expected_token = match config.validate() {
        Ok(tok) => tok,
        Err(_) => {
            write_http_json(
                &mut stream,
                500,
                "Internal Server Error",
                &json!({"error": "gateway auth misconfigured"}),
            )
            .await?;
            return Ok(());
        }
    };
    let supplied_bearer = headers
        .get("authorization")
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    let Some(supplied) = supplied_bearer else {
        write_http_json(
            &mut stream,
            401,
            "Unauthorized",
            &json!({"error": "missing Authorization: Bearer token"}),
        )
        .await?;
        return Ok(());
    };
    if !expected_token.matches_secret(&SecretValue::new(supplied)) {
        write_http_json(
            &mut stream,
            401,
            "Unauthorized",
            &json!({"error": "invalid bearer token"}),
        )
        .await?;
        return Ok(());
    }

    if method == "GET" && path == "/healthz" {
        write_http_json(&mut stream, 200, "OK", &json!({"status": "ok"})).await?;
        return Ok(());
    }
    if method != "POST" || (path != "/mcp" && path != "/") {
        write_http_json(
            &mut stream,
            405,
            "Method Not Allowed",
            &json!({"error": "use POST /mcp"}),
        )
        .await?;
        return Ok(());
    }

    // 4. Enforce 4 MiB body limit
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > config.max_body_bytes {
        write_http_json(
            &mut stream,
            413,
            "Payload Too Large",
            &json!({"error": format!("request body exceeds {} bytes limit", config.max_body_bytes)}),
        )
        .await?;
        return Ok(());
    }

    let body_start = header_end + 4;
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        let to_read = (content_length - body.len()).min(temp.len());
        let n = stream.read(&mut temp[..to_read]).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&temp[..n]);
        if body.len() > config.max_body_bytes {
            write_http_json(
                &mut stream,
                413,
                "Payload Too Large",
                &json!({"error": "request body exceeds maximum allowed size"}),
            )
            .await?;
            return Ok(());
        }
    }

    let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            let resp = JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(json!({"code": -32700, "message": format!("invalid JSON: {err}")})),
            };
            write_http_json(&mut stream, 400, "Bad Request", &resp).await?;
            return Ok(());
        }
    };

    if rpc_req.jsonrpc.as_deref() != Some("2.0") {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0",
            id: rpc_req.id,
            result: None,
            error: Some(json!({"code": -32600, "message": "jsonrpc must be '2.0'"})),
        };
        write_http_json(&mut stream, 400, "Bad Request", &resp).await?;
        return Ok(());
    }

    if rpc_req.method.starts_with("notifications/") {
        write_http_json(&mut stream, 202, "Accepted", &json!({"accepted": true})).await?;
        return Ok(());
    }

    let dispatched = dispatch_mcp_jsonrpc(&server, &rpc_req.method, rpc_req.params).await;
    let resp = match dispatched {
        Ok(res) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: rpc_req.id,
            result: Some(redact_json_value(&res)),
            error: None,
        },
        Err((code, msg)) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: rpc_req.id,
            result: None,
            error: Some(json!({"code": code, "message": msg})),
        },
    };
    write_http_json(&mut stream, 200, "OK", &resp).await
}

async fn dispatch_mcp_jsonrpc(
    server: &N8nMcpServer,
    method: &str,
    params: Value,
) -> Result<Value, (i32, String)> {
    match method {
        "ping" => Ok(json!({})),
        "initialize" => serde_json::to_value(server.server_info())
            .map_err(|e| (-32603, format!("serialization error: {e}"))),
        "tools/list" => {
            let tools = server.list_registered_tools();
            Ok(json!({ "tools": tools }))
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "missing 'name' in tools/call params".to_owned()))?;
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            server
                .invoke_tool_json(name, args)
                .await
                .map_err(|e| (-32602, e.message.into_owned()))
        }
        "resources/list" => serde_json::to_value(crate::resources::list_concrete_resources(
            server.app_state(),
        ))
        .map_err(|e| (-32603, e.to_string())),
        "resources/templates/list" => {
            serde_json::to_value(crate::resources::build_resource_templates())
                .map_err(|e| (-32603, e.to_string()))
        }
        "resources/read" => {
            let uri = params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "missing 'uri' in resources/read params".to_owned()))?;
            let res = crate::resources::read_n8n_resource(server.app_state(), uri)
                .await
                .map_err(|e| (-32602, e.message.into_owned()))?;
            serde_json::to_value(rmcp::model::ServerResult::from(res))
                .map_err(|e| (-32603, e.to_string()))
        }
        "prompts/list" => serde_json::to_value(crate::prompts::build_guidance_prompts())
            .map_err(|e| (-32603, e.to_string())),
        "prompts/get" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| (-32602, "missing 'name' in prompts/get params".to_owned()))?;
            let mut req = GetPromptRequestParams::new(name.to_owned());
            if let Some(obj) = params.get("arguments").and_then(Value::as_object) {
                let map: JsonObject = obj.clone();
                req = req.with_arguments(map);
            }
            let res = crate::prompts::render_guidance_prompt(&req)
                .map_err(|e| (-32602, e.message.into_owned()))?;
            serde_json::to_value(rmcp::model::ServerResult::from(res))
                .map_err(|e| (-32603, e.to_string()))
        }
        other => Err((-32601, format!("method not found: {other}"))),
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_allowed_host(host_header: &str, allowed_hosts: &[String]) -> bool {
    let bare = if let Some(rest) = host_header.strip_prefix('[') {
        rest.split_once(']')
            .map_or(host_header, |(inside, _)| inside)
            .to_owned()
    } else {
        host_header
            .split_once(':')
            .map_or(host_header, |(h, _)| h)
            .to_owned()
    };

    allowed_hosts.iter().any(|allowed| {
        let trimmed_allowed = allowed.trim_start_matches('[').trim_end_matches(']');
        trimmed_allowed.eq_ignore_ascii_case(&bare) || allowed.eq_ignore_ascii_case(host_header)
    })
}

async fn write_http_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    payload: &T,
) -> Result<(), std::io::Error> {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}
