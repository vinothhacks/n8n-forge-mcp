//! Configuration loader combining environment variables, optional `instances.toml`,
//! and optional `policy.<mode>.toml` without requiring plaintext secrets on disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use n8n_types::{EnvironmentKind, N8nError, N8nResult, SecretValue};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::locks::MAX_BATCH_WORKFLOWS;

/// Server-enforced policy profile (`V2 Section 5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    /// Strict read-only: blocks ALL `R2..R4` writes AND blocks `execute_workflow(production)`
    /// even when n8n 2.47+ protected-instance Native MCP leaves `execute_workflow` visible.
    #[default]
    ReadOnly,
    /// Staging-safe: allows `R0..R1`, previewed `R2` draft edits on non-prod, and `R3` with receipt.
    StagingSafe,
    /// Production-guarded: requires cryptographic single-use `ApprovalReceipt` for every mutation/exec.
    ProductionGuarded,
    /// Full-dev: permitted ONLY on `EnvironmentKind::Development`; still requires receipts for `R3/R4`.
    FullDev,
}

impl PolicyMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::StagingSafe => "staging-safe",
            Self::ProductionGuarded => "production-guarded",
            Self::FullDev => "full-dev",
        }
    }
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PolicyMode {
    type Err = N8nError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "read-only" | "readonly" | "prod-read-only" => Ok(Self::ReadOnly),
            "staging-safe" | "staging" => Ok(Self::StagingSafe),
            "production-guarded" | "prod-guarded" => Ok(Self::ProductionGuarded),
            "full-dev" | "dev" => Ok(Self::FullDev),
            other => Err(N8nError::config(format!(
                "unknown policy mode `{other}` (expected read-only, staging-safe, production-guarded, or full-dev)"
            ))),
        }
    }
}

/// Optional policy TOML file structure (`config/policy.*.toml`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicyFileOverrides {
    pub mode: Option<PolicyMode>,
    pub max_batch_workflows: Option<usize>,
    pub enable_r4_admin_actions: Option<bool>,
    pub allowed_workflow_ids: Option<BTreeSet<String>>,
    pub allowed_project_ids: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct InstancesTomlFile {
    #[serde(default)]
    instances: BTreeMap<String, InstanceTomlEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct InstanceTomlEntry {
    url: String,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    policy: Option<PolicyMode>,
    #[serde(default)]
    api_key_env: Option<String>,
    #[serde(default)]
    mcp_base_url: Option<String>,
    #[serde(default)]
    mcp_token_env: Option<String>,
    #[serde(default)]
    cf_access_client_id_env: Option<String>,
    #[serde(default)]
    cf_access_client_secret_env: Option<String>,
    #[serde(default)]
    allow_loopback_http: bool,
    #[serde(default)]
    trust_configured_private_host: bool,
    #[serde(default)]
    enable_r4_admin_actions: bool,
    #[serde(default)]
    allowed_workflow_ids: Option<BTreeSet<String>>,
    #[serde(default)]
    allowed_project_ids: Option<BTreeSet<String>>,
}

/// Resolved per-instance runtime configuration & policy rules.
#[derive(Debug, Clone)]
pub struct InstancePolicyConfig {
    pub alias: String,
    pub url: String,
    pub environment: EnvironmentKind,
    pub policy_mode: PolicyMode,
    pub api_key: Option<SecretValue>,
    pub mcp_base_url: Option<String>,
    pub mcp_access_token: Option<SecretValue>,
    pub cf_access_client_id: Option<String>,
    pub cf_access_client_secret: Option<SecretValue>,
    pub allow_loopback_http: bool,
    pub trust_configured_private_host: bool,
    pub enable_r4_admin_actions: bool,
    pub max_batch_workflows: usize,
    pub allowed_workflow_ids: Option<BTreeSet<String>>,
    pub allowed_project_ids: Option<BTreeSet<String>>,
}

impl InstancePolicyConfig {
    /// Validates cross-field security invariants (e.g. `FullDev` requires Development).
    pub fn validate(&self) -> N8nResult<()> {
        if self.policy_mode == PolicyMode::FullDev
            && self.environment != EnvironmentKind::Development
        {
            return Err(N8nError::config(
                "PolicyMode `full-dev` requires a `development` n8n instance",
            ));
        }
        if self.max_batch_workflows == 0 || self.max_batch_workflows > MAX_BATCH_WORKFLOWS {
            return Err(N8nError::config(format!(
                "max_batch_workflows must be within 1..={MAX_BATCH_WORKFLOWS}"
            )));
        }
        if let (Some(api_k), Some(mcp_k)) = (&self.api_key, &self.mcp_access_token)
            && api_k.matches_secret(mcp_k)
        {
            return Err(N8nError::config(
                "N8N_MCP_ACCESS_TOKEN must not reuse N8N_API_KEY",
            ));
        }
        Ok(())
    }
}

/// Complete resolved workspace configuration across one or more named instance aliases.
#[derive(Debug, Clone)]
pub struct LoadedWorkspaceConfig {
    pub active_instance: String,
    pub instances: BTreeMap<String, InstancePolicyConfig>,
}

impl LoadedWorkspaceConfig {
    pub fn active(&self) -> N8nResult<&InstancePolicyConfig> {
        self.instances.get(&self.active_instance).ok_or_else(|| {
            N8nError::config(format!(
                "instance alias `{}` is not configured",
                self.active_instance
            ))
        })
    }

    pub fn get_instance(&self, alias: Option<&str>) -> N8nResult<&InstancePolicyConfig> {
        let target = alias.unwrap_or(&self.active_instance);
        self.instances
            .get(target)
            .ok_or_else(|| N8nError::config(format!("instance alias `{target}` is not configured")))
    }
}

/// Loads configuration from optional `instances.toml`, optional `policy.*.toml`, CLI overrides,
/// and process environment variables (`env_lookup` injectable for deterministic unit testing).
pub fn load_workspace_config<F>(
    instances_toml_path: Option<&Path>,
    policy_toml_path: Option<&Path>,
    cli_instance: Option<&str>,
    cli_policy: Option<PolicyMode>,
    env_lookup: F,
) -> N8nResult<LoadedWorkspaceConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let policy_overrides = if let Some(p_path) = policy_toml_path {
        let raw = std::fs::read_to_string(p_path)
            .map_err(|e| N8nError::config(format!("failed reading policy TOML: {e}")))?;
        toml::from_str::<PolicyFileOverrides>(&raw)
            .map_err(|e| N8nError::config(format!("invalid policy TOML: {e}")))?
    } else {
        PolicyFileOverrides::default()
    };

    let mut instances = BTreeMap::new();

    if let Some(i_path) = instances_toml_path {
        let raw = std::fs::read_to_string(i_path)
            .map_err(|e| N8nError::config(format!("failed reading instances TOML: {e}")))?;
        let parsed: InstancesTomlFile = toml::from_str(&raw)
            .map_err(|e| N8nError::config(format!("invalid instances TOML: {e}")))?;

        for (alias, entry) in parsed.instances {
            let environment = parse_env_kind(entry.environment.as_deref())?;
            let default_mode = match environment {
                EnvironmentKind::Production => PolicyMode::ReadOnly,
                EnvironmentKind::Staging | EnvironmentKind::Development => PolicyMode::StagingSafe,
            };
            let policy_mode = cli_policy
                .or(policy_overrides.mode)
                .or(entry.policy)
                .unwrap_or(default_mode);

            let api_key = entry
                .api_key_env
                .as_deref()
                .and_then(&env_lookup)
                .filter(|v| !v.trim().is_empty())
                .map(SecretValue::new);
            let mcp_access_token = entry
                .mcp_token_env
                .as_deref()
                .and_then(&env_lookup)
                .filter(|v| !v.trim().is_empty())
                .map(SecretValue::new);
            let cf_id = entry
                .cf_access_client_id_env
                .as_deref()
                .and_then(&env_lookup);
            let cf_secret = entry
                .cf_access_client_secret_env
                .as_deref()
                .and_then(&env_lookup)
                .filter(|v| !v.trim().is_empty())
                .map(SecretValue::new);

            let max_batch = policy_overrides
                .max_batch_workflows
                .unwrap_or(MAX_BATCH_WORKFLOWS)
                .min(MAX_BATCH_WORKFLOWS);

            let cfg = InstancePolicyConfig {
                alias: alias.clone(),
                url: entry.url,
                environment,
                policy_mode,
                api_key,
                mcp_base_url: entry.mcp_base_url,
                mcp_access_token,
                cf_access_client_id: cf_id,
                cf_access_client_secret: cf_secret,
                allow_loopback_http: entry.allow_loopback_http,
                trust_configured_private_host: entry.trust_configured_private_host,
                enable_r4_admin_actions: policy_overrides
                    .enable_r4_admin_actions
                    .unwrap_or(entry.enable_r4_admin_actions),
                max_batch_workflows: max_batch,
                allowed_workflow_ids: policy_overrides
                    .allowed_workflow_ids
                    .clone()
                    .or(entry.allowed_workflow_ids),
                allowed_project_ids: policy_overrides
                    .allowed_project_ids
                    .clone()
                    .or(entry.allowed_project_ids),
            };
            cfg.validate()?;
            instances.insert(alias, cfg);
        }
    }

    // Fallback or single-instance env var configuration
    if instances.is_empty() {
        let alias = cli_instance
            .map(str::to_owned)
            .or_else(|| env_lookup("N8N_INSTANCE"))
            .unwrap_or_else(|| "default".to_owned());
        let url = env_lookup("N8N_API_URL")
            .unwrap_or_else(|| "https://staging-n8n.example.internal".to_owned());
        let env_str = env_lookup("N8N_ENVIRONMENT");
        let environment = parse_env_kind(env_str.as_deref())?;
        let env_policy = match env_lookup("N8N_POLICY") {
            Some(raw) => Some(PolicyMode::from_str(&raw)?),
            None => None,
        };
        let default_mode = match environment {
            EnvironmentKind::Production => PolicyMode::ReadOnly,
            EnvironmentKind::Staging | EnvironmentKind::Development => PolicyMode::StagingSafe,
        };
        let policy_mode = cli_policy
            .or(policy_overrides.mode)
            .or(env_policy)
            .unwrap_or(default_mode);

        let allow_loopback_http = env_lookup("N8N_ALLOW_LOOPBACK_HTTP").is_some_and(|v| {
            matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
        });
        let trust_configured_private_host = env_lookup("N8N_TRUST_PRIVATE_HOST").is_some_and(|v| {
            matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
        });

        let api_key = env_lookup("N8N_API_KEY")
            .filter(|v| !v.trim().is_empty())
            .map(SecretValue::new);
        let mcp_base_url = env_lookup("N8N_MCP_BASE_URL").filter(|v| !v.trim().is_empty());
        let mcp_access_token = env_lookup("N8N_MCP_ACCESS_TOKEN")
            .filter(|v| !v.trim().is_empty())
            .map(SecretValue::new);
        let cf_access_client_id =
            env_lookup("N8N_CF_ACCESS_CLIENT_ID").filter(|v| !v.trim().is_empty());
        let cf_access_client_secret = env_lookup("N8N_CF_ACCESS_CLIENT_SECRET")
            .filter(|v| !v.trim().is_empty())
            .map(SecretValue::new);

        let max_batch = policy_overrides
            .max_batch_workflows
            .unwrap_or(MAX_BATCH_WORKFLOWS)
            .min(MAX_BATCH_WORKFLOWS);

        let cfg = InstancePolicyConfig {
            alias: alias.clone(),
            url,
            environment,
            policy_mode,
            api_key,
            mcp_base_url,
            mcp_access_token,
            cf_access_client_id,
            cf_access_client_secret,
            allow_loopback_http,
            trust_configured_private_host,
            enable_r4_admin_actions: policy_overrides.enable_r4_admin_actions.unwrap_or(false),
            max_batch_workflows: max_batch,
            allowed_workflow_ids: policy_overrides.allowed_workflow_ids,
            allowed_project_ids: policy_overrides.allowed_project_ids,
        };
        cfg.validate()?;
        instances.insert(alias.clone(), cfg);
    }

    let active_instance = if let Some(req_alias) = cli_instance {
        if !instances.contains_key(req_alias) {
            return Err(N8nError::config(format!(
                "requested instance `{req_alias}` not found in configuration"
            )));
        }
        req_alias.to_owned()
    } else {
        instances
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| N8nError::config("no n8n instances configured"))?
    };

    Ok(LoadedWorkspaceConfig {
        active_instance,
        instances,
    })
}

fn parse_env_kind(raw: Option<&str>) -> N8nResult<EnvironmentKind> {
    let Some(s) = raw else {
        return Ok(EnvironmentKind::Staging);
    };
    match s.trim().to_ascii_lowercase().as_str() {
        "dev" | "development" | "local" => Ok(EnvironmentKind::Development),
        "staging" | "stage" | "test" => Ok(EnvironmentKind::Staging),
        "prod" | "production" | "live" => Ok(EnvironmentKind::Production),
        other => Err(N8nError::config(format!(
            "unknown environment `{other}` (expected development, staging, or production)"
        ))),
    }
}
