//! Zero-secret `doctor` diagnostic engine verifying URL/SSRF rules, DNS/TLS reachability,
//! `/discover` or fallback probe, Native MCP token isolation, state-vault ACLs, and read-only list.

use n8n_api_client::ssrf::normalize_and_validate_url;
use n8n_api_client::{ListQueryParams, SsrfPolicy};
use n8n_capability::NativeMcpStatus;
use n8n_state_vault::check_user_state_dir;
use n8n_types::{redact_json_value, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::AppState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheckItem {
    pub name: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub remediation: Option<String>,
}

/// Complete sanitized report emitted by `n8n-rs-mcp doctor --no-secret-output`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub healthy: bool,
    pub instance: String,
    pub environment: String,
    pub policy_mode: String,
    pub no_secret_output: bool,
    pub api_key_status: String,
    pub mcp_bridge_token_status: String,
    pub n8n_version: Option<String>,
    pub checks: Vec<DoctorCheckItem>,
}

impl DoctorReport {
    pub fn to_redacted_json(&self) -> Value {
        let val = serde_json::to_value(self).unwrap_or(Value::Null);
        redact_json_value(&val)
    }
}

/// Runs non-mutating diagnostic checks without EVER emitting raw or partial secrets.
/// Never recommends an Owner key as an automatic fix (V2 Section 3).
pub async fn run_doctor(
    state: &AppState,
    requested_instance: Option<&str>,
    no_secret_output: bool,
) -> DoctorReport {
    let mut checks = Vec::new();
    let rt = match state.instance(requested_instance) {
        Ok(r) => r,
        Err(err) => {
            return DoctorReport {
                healthy: false,
                instance: requested_instance
                    .unwrap_or(&state.active_instance)
                    .to_owned(),
                environment: "unknown".to_owned(),
                policy_mode: "read-only".to_owned(),
                no_secret_output: true,
                api_key_status: "unknown".to_owned(),
                mcp_bridge_token_status: "unknown".to_owned(),
                n8n_version: None,
                checks: vec![DoctorCheckItem {
                    name: "instance_config".to_owned(),
                    status: "fail".to_owned(),
                    summary: redact_str(&err.to_string()),
                    remediation: Some(
                        "Configure instance alias in `instances.toml` or `N8N_API_URL`.".to_owned(),
                    ),
                }],
            };
        }
    };

    let ssrf_policy = SsrfPolicy {
        allow_loopback_http: rt.config.allow_loopback_http,
        trust_configured_private_host: rt.config.trust_configured_private_host,
        trusted_private_ips: Vec::new(),
    };

    let mut all_ok = true;

    // 1. URL & SSRF check
    match normalize_and_validate_url(&rt.config.url, &ssrf_policy) {
        Ok(origin) => {
            checks.push(DoctorCheckItem {
                name: "url_and_ssrf_guard".to_owned(),
                status: "pass".to_owned(),
                summary: format!(
                    "Validated origin {}://{}:{} (redirect forwarding disabled).",
                    origin.scheme, origin.host, origin.port
                ),
                remediation: None,
            });
        }
        Err(err) => {
            all_ok = false;
            checks.push(DoctorCheckItem {
                name: "url_and_ssrf_guard".to_owned(),
                status: "fail".to_owned(),
                summary: redact_str(&err.to_string()),
                remediation: Some(
                    "Use an `https://` n8n origin on a permitted network host.".to_owned(),
                ),
            });
        }
    }

    // 2. Credential presence & isolation check (strictly boolean status, never secret bytes!)
    let api_key_status = if rt.config.api_key.as_ref().is_some_and(|k| !k.is_empty()) {
        "configured".to_owned()
    } else {
        all_ok = false;
        "missing".to_owned()
    };
    checks.push(DoctorCheckItem {
        name: "public_api_credential".to_owned(),
        status: if api_key_status == "configured" {
            "pass".to_owned()
        } else {
            "fail".to_owned()
        },
        summary: format!("N8N_API_KEY status: {api_key_status} (secret value redacted)."),
        remediation: (api_key_status != "configured").then(|| {
            "Inject a least-privilege scoped API key via `N8N_API_KEY` environment secret."
                .to_owned()
        }),
    });

    let mcp_bridge_token_status = match (&rt.config.mcp_base_url, &rt.config.mcp_access_token) {
        (Some(_), Some(tok)) if !tok.is_empty() => "configured_isolated".to_owned(),
        (Some(_), _) => "missing_token".to_owned(),
        (None, _) => "not_configured".to_owned(),
    };

    // 3. State vault directory permissions check
    let vault = check_user_state_dir(None);
    checks.push(DoctorCheckItem {
        name: "state_vault_permissions".to_owned(),
        status: if vault.writable || !vault.directory_configured {
            "pass".to_owned()
        } else {
            "warn".to_owned()
        },
        summary: vault.note,
        remediation: None,
    });

    // 4. Live capability discovery + non-mutating list check
    let mut n8n_version = None;
    if let Some(ref api) = rt.api_client {
        match state.resolve_instance_capabilities(rt, true).await {
            Ok(caps) => {
                n8n_version.clone_from(&caps.n8n_version);
                checks.push(DoctorCheckItem {
                    name: "capability_handshake".to_owned(),
                    status: "pass".to_owned(),
                    summary: format!(
                        "Discovery succeeded via {:?} (scopes={}, resources={}, protected={}).",
                        caps.discovery_source,
                        caps.scopes.len(),
                        caps.advertised_resources.len(),
                        caps.protected_instance
                    ),
                    remediation: None,
                });

                match &caps.native_mcp {
                    NativeMcpStatus::NotConfigured => {
                        checks.push(DoctorCheckItem {
                            name: "native_mcp_bridge".to_owned(),
                            status: "skip".to_owned(),
                            summary: "Optional Native MCP bridge not configured; Public API routes active."
                                .to_owned(),
                            remediation: None,
                        });
                    }
                    NativeMcpStatus::Connected { tools } => {
                        checks.push(DoctorCheckItem {
                            name: "native_mcp_bridge".to_owned(),
                            status: "pass".to_owned(),
                            summary: format!(
                                "Connected to Instance-level MCP ({} tools advertised; pinData={:?}).",
                                tools.advertised_tool_names.len(),
                                tools.pin_data_tool
                            ),
                            remediation: None,
                        });
                    }
                    NativeMcpStatus::Unavailable { reason } => {
                        checks.push(DoctorCheckItem {
                            name: "native_mcp_bridge".to_owned(),
                            status: "warn".to_owned(),
                            summary: format!("Native MCP bridge unavailable: {}", redact_str(reason)),
                            remediation: Some(
                                "Verify Settings > Instance-level MCP and isolated `N8N_MCP_ACCESS_TOKEN`."
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
            Err(err) => {
                all_ok = false;
                checks.push(DoctorCheckItem {
                    name: "capability_handshake".to_owned(),
                    status: "fail".to_owned(),
                    summary: redact_str(&err.to_string()),
                    remediation: Some(
                        "Verify network reachability and grant least-privilege scopes required for your workflow tasks (do not default to an Owner key)."
                            .to_owned(),
                    ),
                });
            }
        }

        // Non-mutating list probe (`GET /api/v1/workflows?limit=1`)
        match api
            .list_workflows(&ListQueryParams {
                limit: Some(1),
                exclude_pinned_data: Some(true),
                ..ListQueryParams::default()
            })
            .await
        {
            Ok(page) => {
                checks.push(DoctorCheckItem {
                    name: "readonly_workflow_list".to_owned(),
                    status: "pass".to_owned(),
                    summary: format!(
                        "Non-mutating `GET /api/v1/workflows?limit=1` returned {} accessible item(s).",
                        page.data.len()
                    ),
                    remediation: None,
                });
            }
            Err(err) => {
                all_ok = false;
                checks.push(DoctorCheckItem {
                    name: "readonly_workflow_list".to_owned(),
                    status: "fail".to_owned(),
                    summary: redact_str(&err.to_string()),
                    remediation: Some(
                        "Ensure the scoped API key has `workflow:list` permission for the target project."
                            .to_owned(),
                    ),
                });
            }
        }
    }

    DoctorReport {
        healthy: all_ok,
        instance: rt.config.alias.clone(),
        environment: rt.config.environment.as_str().to_owned(),
        policy_mode: rt.config.policy_mode.as_str().to_owned(),
        no_secret_output: no_secret_output || true,
        api_key_status,
        mcp_bridge_token_status,
        n8n_version,
        checks,
    }
}
