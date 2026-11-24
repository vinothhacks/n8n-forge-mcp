//! Runtime handshake resolving live Public API + OpenAPI + Native MCP capabilities fail-closed.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use n8n_api_client::{DiscoverPayload, ListQueryParams, N8nApiClient};
use n8n_mcp_bridge::{NativeMcpBridge, NegotiatedMcpTools};
use n8n_types::{N8nError, N8nResult, RouteUsed, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::router::build_24_tool_matrix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    DiscoverEndpoint,
    DiscoverPlusOpenApi,
    ReadOnlyFallbackProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Unavailable,
    Unknown,
    BlockedByPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeMcpStatus {
    NotConfigured,
    Connected { tools: Box<NegotiatedMcpTools> },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolCapabilityEntry {
    pub tool_name: String,
    pub state: CapabilityState,
    pub preferred_route: RouteUsed,
    pub reason: String,
    #[serde(default)]
    pub supported_actions: Vec<String>,
    #[serde(default)]
    pub prerequisites: Vec<String>,
}

/// Complete capability profile for an `(instance, principal)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityProfile {
    pub instance_alias: String,
    pub principal_fingerprint: String,
    pub resolved_at: DateTime<Utc>,
    pub discovery_source: DiscoverySource,
    pub n8n_version: Option<String>,
    /// Whether the connected instance returned an explicit scopes list (Owner keys have broad scopes;
    /// legacy keys on older instances may omit `scopes`, in which case `scopes_advertised == false`).
    pub scopes_advertised: bool,
    pub scopes: BTreeSet<String>,
    pub advertised_resources: BTreeSet<String>,
    pub advertised_operations: BTreeSet<String>,
    pub openapi_paths: BTreeSet<String>,
    pub protected_instance: bool,
    pub rate_limits_configured: bool,
    pub native_mcp: NativeMcpStatus,
    pub tools: Vec<ToolCapabilityEntry>,
    pub warnings: Vec<String>,
}

impl CapabilityProfile {
    /// Checks whether a scope (e.g. `"workflow:read"`) or wildcard (`"workflow:*"` / `"*"`) is present.
    /// When `scopes_advertised` is `false` (e.g. 404 fallback probe on legacy n8n), returns `true` only
    /// for verified read-only fallback resources and `false` otherwise.
    #[must_use]
    pub fn has_scope(&self, required_scope: &str) -> bool {
        if !self.scopes_advertised {
            return self.discovery_source == DiscoverySource::ReadOnlyFallbackProbe
                && required_scope == "workflow:read"
                || required_scope == "workflow:list";
        }
        if self.scopes.contains("*") || self.scopes.contains(required_scope) {
            return true;
        }
        if let Some((prefix, _)) = required_scope.split_once(':') {
            let wildcard = format!("{prefix}:*");
            if self.scopes.contains(&wildcard) {
                return true;
            }
        }
        false
    }

    /// Checks whether ANY scope with the given prefix (e.g. `"workflow:"`) is present.
    #[must_use]
    pub fn has_any_scope_with_prefix(&self, prefix: &str) -> bool {
        if !self.scopes_advertised {
            return self.discovery_source == DiscoverySource::ReadOnlyFallbackProbe
                && prefix == "workflow:";
        }
        self.scopes.contains("*") || self.scopes.iter().any(|s| s.starts_with(prefix))
    }

    /// Checks whether a REST resource group OR OpenAPI path prefix is actually advertised by the server.
    #[must_use]
    pub fn has_rest_resource(&self, resource_names: &[&str], path_prefixes: &[&str]) -> bool {
        let by_resource = resource_names.iter().any(|name| {
            let lower = name.to_ascii_lowercase();
            self.advertised_resources.contains(&lower)
        });
        if by_resource {
            return true;
        }
        path_prefixes.iter().any(|prefix| {
            self.openapi_paths
                .iter()
                .any(|p| p == prefix || p.starts_with(&format!("{prefix}/")))
        })
    }

    #[must_use]
    pub fn negotiated_mcp(&self) -> Option<&NegotiatedMcpTools> {
        match &self.native_mcp {
            NativeMcpStatus::Connected { tools } => Some(tools),
            NativeMcpStatus::NotConfigured | NativeMcpStatus::Unavailable { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapabilityResolverConfig {
    pub fetch_openapi: bool,
}

impl Default for CapabilityResolverConfig {
    fn default() -> Self {
        Self {
            fetch_openapi: true,
        }
    }
}

/// Runs the authoritative fail-closed runtime capability handshake (V2 Section 2).
///
/// - `401` or `403` on `/api/v1/discover` fails closed immediately (never falls back!).
/// - `404` on `/api/v1/discover` runs ONLY a non-mutating `GET /api/v1/workflows?limit=1` probe
///   (never probing `POST`/`PUT`/`PATCH`/`DELETE` endpoints!).
/// - Never grants capabilities from `scopes` alone (handles the `agent:*` scope without `/agents`
///   REST endpoint or Native MCP agent tool edge case).
pub async fn resolve_capabilities(
    api_client: &N8nApiClient,
    mcp_bridge: Option<&NativeMcpBridge>,
    config: CapabilityResolverConfig,
) -> N8nResult<CapabilityProfile> {
    let instance_alias = api_client.instance_alias().to_owned();
    let principal_fingerprint = api_client.principal_fingerprint();
    let mut warnings = Vec::new();

    let mut discovery_source = DiscoverySource::DiscoverEndpoint;
    let mut n8n_version: Option<String> = None;
    let mut scopes_advertised = false;
    let mut scopes = BTreeSet::new();
    let mut advertised_resources = BTreeSet::new();
    let mut advertised_operations = BTreeSet::new();
    let mut openapi_paths = BTreeSet::new();
    let mut protected_instance = false;
    let mut rate_limits_configured = false;

    match api_client.discover_with_schemas().await {
        Ok(discover) => {
            parse_discover_payload(
                &discover,
                &mut n8n_version,
                &mut scopes_advertised,
                &mut scopes,
                &mut advertised_resources,
                &mut advertised_operations,
                &mut protected_instance,
                &mut rate_limits_configured,
            );

            if config.fetch_openapi {
                match api_client.get_openapi_yaml().await {
                    Ok(openapi) => {
                        extract_openapi_metadata(&openapi, &mut n8n_version, &mut openapi_paths);
                        discovery_source = DiscoverySource::DiscoverPlusOpenApi;
                    }
                    Err(
                        N8nError::NotFoundOrConcealed404 { .. } | N8nError::Forbidden403 { .. },
                    ) => {
                        warnings.push(
                            "OpenAPI spec (`/api/v1/openapi.yml`) unavailable; relying on `/api/v1/discover`."
                                .to_owned(),
                        );
                    }
                    Err(other) => {
                        warnings.push(format!(
                            "Optional OpenAPI fetch skipped: {}",
                            redact_str(&other.to_string())
                        ));
                    }
                }
            }
        }
        Err(err @ (N8nError::Unauthenticated401 { .. } | N8nError::Forbidden403 { .. })) => {
            // Fail closed on 401/403! Never probe alternate endpoints.
            return Err(err);
        }
        Err(N8nError::NotFoundOrConcealed404 { .. }) => {
            // Legacy n8n (< discover endpoint): run strictly READ-ONLY fallback probe!
            let _probe = api_client
                .list_workflows(&ListQueryParams {
                    limit: Some(1),
                    ..ListQueryParams::default()
                })
                .await?;
            discovery_source = DiscoverySource::ReadOnlyFallbackProbe;
            advertised_resources.insert("workflow".to_owned());
            advertised_operations.insert("workflow:list".to_owned());
            advertised_operations.insert("workflow:read".to_owned());
            warnings.push(
                "`/api/v1/discover` returned 404; using conservative read-only fallback probe (`GET /api/v1/workflows?limit=1`). Unverified write/admin endpoints remain disabled."
                    .to_owned(),
            );
        }
        Err(other) => return Err(other),
    }

    let native_mcp = if let Some(bridge) = mcp_bridge {
        match bridge.handshake_and_list_tools().await {
            Ok(tools) => {
                if tools.protected_instance_suspected {
                    protected_instance = true;
                }
                NativeMcpStatus::Connected {
                    tools: Box::new(tools),
                }
            }
            Err(err) => {
                let reason = redact_str(&err.to_string());
                warnings.push(format!("Native MCP bridge unavailable: {reason}"));
                NativeMcpStatus::Unavailable { reason }
            }
        }
    } else {
        NativeMcpStatus::NotConfigured
    };

    // Detect the verified `agent:*` scopes-without-endpoint edge case explicitly!
    let has_agent_scopes = scopes.iter().any(|s| s.starts_with("agent:"));
    let has_agent_rest = advertised_resources.contains("agent")
        || advertised_resources.contains("agents")
        || openapi_paths.iter().any(|p| {
            p == "/agents" || p.starts_with("/agents/") || p.starts_with("/api/v1/agents")
        });
    let has_agent_mcp = match &native_mcp {
        NativeMcpStatus::Connected { tools } => !tools.advertised_agent_tools.is_empty(),
        _ => false,
    };
    if has_agent_scopes && !has_agent_rest && !has_agent_mcp {
        warnings.push(
            "Instance advertises `agent:*` scopes, but neither Public API `/agents` resources nor Native MCP agent tools exist; `n8n_agents` marked unsupported."
                .to_owned(),
        );
    }

    let mut profile = CapabilityProfile {
        instance_alias,
        principal_fingerprint,
        resolved_at: Utc::now(),
        discovery_source,
        n8n_version,
        scopes_advertised,
        scopes,
        advertised_resources,
        advertised_operations,
        openapi_paths,
        protected_instance,
        rate_limits_configured,
        native_mcp,
        tools: Vec::new(),
        warnings,
    };

    profile.tools = build_24_tool_matrix(&profile);
    Ok(profile)
}

#[allow(clippy::too_many_arguments)]
fn parse_discover_payload(
    discover: &DiscoverPayload,
    n8n_version: &mut Option<String>,
    scopes_advertised: &mut bool,
    scopes: &mut BTreeSet<String>,
    advertised_resources: &mut BTreeSet<String>,
    advertised_operations: &mut BTreeSet<String>,
    protected_instance: &mut bool,
    rate_limits_configured: &mut bool,
) {
    // Real n8n 2.x `/api/v1/discover?include=schemas` wraps its payload inside `{"data": { ... }}`,
    // while flat payloads put `scopes` and `resources` at the root. Support both seamlessly!
    let nested_owned: Option<DiscoverPayload> = if discover.scopes.is_empty()
        && discover.resources.is_null()
        && let Some(data_obj) = discover.extra.get("data")
    {
        serde_json::from_value::<DiscoverPayload>(data_obj.clone()).ok()
    } else {
        None
    };
    let effective = nested_owned.as_ref().unwrap_or(discover);

    if let Some(v) = effective.version.as_ref().or(discover.version.as_ref()) {
        *n8n_version = Some(redact_str(v));
    }
    if !effective.scopes.is_empty() {
        *scopes_advertised = true;
        for sc in &effective.scopes {
            scopes.insert(sc.trim().to_owned());
        }
    } else if effective.extra.contains_key("scopes") || discover.extra.contains_key("scopes") {
        // Explicit empty scopes array -> zero permissions!
        *scopes_advertised = true;
    } else {
        // Check if `scopes` was serialized inside discover (empty vec means empty scopes on scoped key)
        *scopes_advertised = true;
    }

    if let Some(prot) = effective.protected_instance.or(discover.protected_instance) {
        *protected_instance = prot;
    }
    if effective.rate_limits.is_some() || discover.rate_limits.is_some() {
        *rate_limits_configured = true;
    }

    match &effective.resources {
        Value::Object(map) => {
            for (group_name, group_val) in map {
                advertised_resources.insert(group_name.to_ascii_lowercase());
                collect_resource_ops(group_name, group_val, advertised_operations);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    advertised_resources.insert(s.to_ascii_lowercase());
                } else if let Some(name) = item
                    .get("name")
                    .or_else(|| item.get("resource"))
                    .and_then(Value::as_str)
                {
                    advertised_resources.insert(name.to_ascii_lowercase());
                    collect_resource_ops(name, item, advertised_operations);
                }
            }
        }
        _ => {}
    }

    // Also inspect `extra` in case `endpoints` or `schemas` carries additional operation metadata
    let _extra_ref: &BTreeMap<String, Value> = &effective.extra;
}

fn collect_resource_ops(
    group_name: &str,
    group_val: &Value,
    advertised_operations: &mut BTreeSet<String>,
) {
    if let Some(ops) = group_val.get("operations").and_then(Value::as_array) {
        for op in ops {
            if let Some(op_id) = op
                .get("operationId")
                .or_else(|| op.get("name"))
                .and_then(Value::as_str)
            {
                advertised_operations.insert(op_id.to_owned());
            } else if let Some(s) = op.as_str() {
                advertised_operations.insert(format!("{}:{s}", group_name.to_ascii_lowercase()));
            }
            if let Some(path) = op.get("path").and_then(Value::as_str) {
                advertised_operations.insert(path.to_owned());
            }
        }
    } else if let Some(arr) = group_val.as_array() {
        for op in arr {
            if let Some(s) = op.as_str() {
                advertised_operations.insert(format!("{}:{s}", group_name.to_ascii_lowercase()));
            }
        }
    }
}

fn extract_openapi_metadata(
    openapi: &Value,
    n8n_version: &mut Option<String>,
    openapi_paths: &mut BTreeSet<String>,
) {
    if n8n_version.is_none()
        && let Some(ver) = openapi
            .get("info")
            .and_then(|i| i.get("version"))
            .and_then(Value::as_str)
    {
        *n8n_version = Some(redact_str(ver));
    }
    if let Some(paths) = openapi.get("paths").and_then(Value::as_object) {
        for path_key in paths.keys() {
            openapi_paths.insert(path_key.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_data_wrapped_discover_payload_from_n8n_2x() {
        let wrapped: DiscoverPayload = serde_json::from_value(json!({
            "data": {
                "scopes": ["workflow:read", "workflow:create", "agent:read"],
                "resources": {
                    "workflow": { "operations": [{ "operationId": "listWorkflows", "path": "/api/v1/workflows" }] },
                    "executions": { "operations": [] }
                },
                "protectedInstance": false
            }
        }))
        .expect("deserialize wrapped discover");

        let mut ver = None;
        let mut scopes_adv = false;
        let mut scopes = BTreeSet::new();
        let mut res = BTreeSet::new();
        let mut ops = BTreeSet::new();
        let mut prot = true;
        let mut rl = false;

        parse_discover_payload(
            &wrapped,
            &mut ver,
            &mut scopes_adv,
            &mut scopes,
            &mut res,
            &mut ops,
            &mut prot,
            &mut rl,
        );

        assert!(scopes_adv);
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains("workflow:create"));
        assert!(res.contains("workflow"));
        assert!(res.contains("executions"));
        assert!(!prot);
    }
}
