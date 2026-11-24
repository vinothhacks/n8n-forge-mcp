use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use n8n_api_client::{ApiClientConfig, N8nApiClient, SsrfPolicy};
use n8n_capability::{CapabilityCache, CapabilityProfile, CapabilityResolverConfig};
use n8n_catalog_db::{CatalogDb, CatalogLoadOptions, CatalogManifest};
use n8n_mcp_bridge::{McpBridgeConfig, NativeMcpBridge};
use n8n_policy::{InstancePolicyConfig, LoadedWorkspaceConfig, PolicyEngine};
use n8n_state_vault::{
    JournalTransitionInput, OperationJournal, SanitizedWorkflowIndex, SnapshotKeyProvider,
    SnapshotRetentionPolicy, SnapshotVault, ensure_protected_state_dir,
};
use n8n_types::{N8nError, N8nResult};
use tokio::sync::Mutex as TokioMutex;

use crate::approval::ApprovalManager;

/// Runtime options controlling catalog resolution and state-vault persistence.
#[derive(Debug, Clone)]
pub struct AppStateOptions {
    pub catalog_path: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub use_in_memory_vault: bool,
}

impl Default for AppStateOptions {
    fn default() -> Self {
        let env_state_dir = std::env::var("N8N_STATE_DIR")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let use_in_memory_vault = env_state_dir.is_none();
        Self {
            catalog_path: None,
            state_dir: env_state_dir,
            use_in_memory_vault,
        }
    }
}

impl AppStateOptions {
    /// Construct options for persistent CLI execution using OS-ACL protected local state dir.
    #[must_use]
    pub fn persistent_cli(catalog_path: Option<PathBuf>, state_dir: Option<PathBuf>) -> Self {
        Self {
            catalog_path,
            state_dir,
            use_in_memory_vault: false,
        }
    }
}

/// Live runtime clients and configuration for a single n8n instance alias.
pub struct InstanceRuntime {
    pub config: InstancePolicyConfig,
    pub api_client: Option<N8nApiClient>,
    pub mcp_bridge: Option<NativeMcpBridge>,
}

impl std::fmt::Debug for InstanceRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceRuntime")
            .field("alias", &self.config.alias)
            .field("environment", &self.config.environment)
            .field("policy_mode", &self.config.policy_mode)
            .field("has_api_client", &self.api_client.is_some())
            .field("has_mcp_bridge", &self.mcp_bridge.is_some())
            .finish()
    }
}

/// Shared application state held by the MCP server and CLI commands.
#[derive(Clone)]
pub struct AppState {
    pub active_instance: String,
    pub instances: Arc<BTreeMap<String, InstanceRuntime>>,
    pub capability_cache: Arc<CapabilityCache>,
    pub policy_engine: PolicyEngine,
    pub approval_manager: ApprovalManager,
    pub catalog_path_resolved: Option<PathBuf>,
    pub catalog_warning: Option<String>,
    pub state_dir_resolved: Option<PathBuf>,
    catalog: Arc<StdMutex<CatalogDb>>,
    workflow_index: Arc<StdMutex<SanitizedWorkflowIndex>>,
    snapshot_vault: Arc<StdMutex<SnapshotVault>>,
    pub journal: Arc<TokioMutex<OperationJournal>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("active_instance", &self.active_instance)
            .field("instances", &self.instances.keys().collect::<Vec<_>>())
            .field("catalog_path_resolved", &self.catalog_path_resolved)
            .field("catalog_warning", &self.catalog_warning)
            .field("state_dir_resolved", &self.state_dir_resolved)
            .finish()
    }
}

impl AppState {
    /// Build `AppState` from loaded workspace config and default options.
    pub fn from_workspace_config(
        ws: LoadedWorkspaceConfig,
        capability_ttl: Duration,
    ) -> N8nResult<Self> {
        Self::from_workspace_config_with_options(ws, capability_ttl, AppStateOptions::default())
    }

    /// Build `AppState` with explicit catalog and state-vault options.
    pub fn from_workspace_config_with_options(
        ws: LoadedWorkspaceConfig,
        capability_ttl: Duration,
        options: AppStateOptions,
    ) -> N8nResult<Self> {
        let mut map = BTreeMap::new();
        for (alias, inst) in ws.instances {
            inst.validate()?;
            let ssrf = SsrfPolicy {
                allow_loopback_http: inst.allow_loopback_http,
                trust_configured_private_host: inst.trust_configured_private_host,
                trusted_private_ips: Vec::new(),
            };

            let api_client = if let Some(ref api_key) = inst.api_key
                && !api_key.is_empty()
            {
                let mut cfg = ApiClientConfig::new(&inst.alias, &inst.url, api_key.clone());
                cfg.ssrf_policy = ssrf.clone();
                cfg.cf_access_client_id
                    .clone_from(&inst.cf_access_client_id);
                cfg.cf_access_client_secret
                    .clone_from(&inst.cf_access_client_secret);
                Some(N8nApiClient::new(cfg)?)
            } else {
                None
            };

            let mcp_bridge = if let (Some(mcp_url), Some(mcp_token)) =
                (&inst.mcp_base_url, &inst.mcp_access_token)
                && !mcp_token.is_empty()
            {
                let mut bcfg = McpBridgeConfig::new(&inst.alias, mcp_url, mcp_token.clone());
                bcfg.ssrf_policy = ssrf;
                Some(NativeMcpBridge::new(bcfg, inst.api_key.as_ref())?)
            } else {
                None
            };

            map.insert(
                alias,
                InstanceRuntime {
                    config: inst,
                    api_client,
                    mcp_bridge,
                },
            );
        }

        let (catalog_db, catalog_path_resolved, catalog_warning) =
            resolve_and_open_catalog(options.catalog_path.as_deref());

        let (workflow_index, snapshot_vault, journal, state_dir_resolved) =
            if options.use_in_memory_vault && options.state_dir.is_none() {
                let wf_idx = SanitizedWorkflowIndex::open_in_memory()?;
                let snap = SnapshotVault::open_at_dir(
                    Path::new("."),
                    &SnapshotKeyProvider::MemoryOnlyTransient,
                    SnapshotRetentionPolicy::default(),
                )?;
                let jrnl = OperationJournal::open_in_memory()?;
                (wf_idx, snap, jrnl, None)
            } else {
                let (resolved_dir, _) = ensure_protected_state_dir(options.state_dir.as_deref())?;
                let wf_idx =
                    SanitizedWorkflowIndex::open_file(&resolved_dir.join("workflow_index.sqlite"))?;
                let key_path = resolved_dir.join("keys").join("snapshot.key");
                let snap = SnapshotVault::open_at_dir(
                    &resolved_dir,
                    &SnapshotKeyProvider::ProtectedKeyFile { path: key_path },
                    SnapshotRetentionPolicy::default(),
                )?;
                let jrnl = OperationJournal::open_files(
                    &resolved_dir.join("journal.sqlite"),
                    Some(&resolved_dir.join("journal.jsonl")),
                )?;
                (wf_idx, snap, jrnl, Some(resolved_dir))
            };

        Ok(Self {
            active_instance: ws.active_instance,
            instances: Arc::new(map),
            capability_cache: Arc::new(CapabilityCache::new(
                capability_ttl,
                CapabilityResolverConfig::default(),
            )),
            policy_engine: PolicyEngine::default(),
            approval_manager: ApprovalManager::new(),
            catalog_path_resolved,
            catalog_warning,
            state_dir_resolved,
            catalog: Arc::new(StdMutex::new(catalog_db)),
            workflow_index: Arc::new(StdMutex::new(workflow_index)),
            snapshot_vault: Arc::new(StdMutex::new(snapshot_vault)),
            journal: Arc::new(TokioMutex::new(journal)),
        })
    }

    /// Resolve a requested instance alias (or `active_instance`).
    pub fn instance(&self, requested_alias: Option<&str>) -> N8nResult<&InstanceRuntime> {
        let target = requested_alias
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.active_instance);

        self.instances.get(target).ok_or_else(|| {
            N8nError::config(format!(
                "unknown n8n instance alias `{target}` (available: {})",
                self.instances
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
    }

    /// Resolve the capability profile for an instance (`revalidate_before_mutation` when `force_refresh`).
    pub async fn resolve_instance_capabilities(
        &self,
        rt: &InstanceRuntime,
        force_refresh: bool,
    ) -> N8nResult<CapabilityProfile> {
        let Some(ref api) = rt.api_client else {
            return Err(N8nError::unauthenticated(
                &rt.config.alias,
                "N8N_API_KEY is missing or empty",
            ));
        };
        if force_refresh {
            self.capability_cache
                .revalidate_before_mutation(api, rt.mcp_bridge.as_ref())
                .await
        } else {
            self.capability_cache
                .resolve_for_read(api, rt.mcp_bridge.as_ref(), false)
                .await
        }
    }

    /// Derive the deterministic principal identifier for an instance runtime.
    #[must_use]
    pub fn principal_for(&self, rt: &InstanceRuntime) -> String {
        rt.api_client.as_ref().map_or_else(
            || format!("local:{}", rt.config.alias),
            N8nApiClient::principal_fingerprint,
        )
    }

    /// Execute a synchronous closure with shared access to `CatalogDb` (never held across `.await`).
    pub fn with_catalog<R>(&self, f: impl FnOnce(&CatalogDb) -> R) -> R {
        let guard = self
            .catalog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&guard)
    }

    /// Replace the active `CatalogDb` instance (e.g., after `sync-catalog`).
    pub fn replace_catalog(&self, new_db: CatalogDb) {
        let mut guard = self
            .catalog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = new_db;
    }

    /// Execute a synchronous closure with `&SanitizedWorkflowIndex`.
    pub fn with_workflow_index<R>(&self, f: impl FnOnce(&SanitizedWorkflowIndex) -> R) -> R {
        let guard = self
            .workflow_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&guard)
    }

    /// Execute a synchronous closure with `&mut SanitizedWorkflowIndex`.
    pub fn with_workflow_index_mut<R>(
        &self,
        f: impl FnOnce(&mut SanitizedWorkflowIndex) -> R,
    ) -> R {
        let mut guard = self
            .workflow_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Execute a synchronous closure with `&SnapshotVault`.
    pub fn with_snapshot_vault<R>(&self, f: impl FnOnce(&SnapshotVault) -> R) -> R {
        let guard = self
            .snapshot_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&guard)
    }

    /// Execute a synchronous closure with `&mut SnapshotVault`.
    pub fn with_snapshot_vault_mut<R>(&self, f: impl FnOnce(&mut SnapshotVault) -> R) -> R {
        let mut guard = self
            .snapshot_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Append a redacted transition to `OperationJournal` without failing the caller if logging errs.
    pub async fn append_journal_best_effort(&self, input: JournalTransitionInput) {
        let mut guard = self.journal.lock().await;
        if let Err(err) = guard.append_transition(input) {
            tracing::warn!(error = %err, "journal transition append warning");
        }
    }
}

/// Resiliently locate and open `catalog.sqlite.zst` regardless of current working directory.
///
/// Search order:
/// 1. `--catalog-path` explicit argument
/// 2. `N8N_CATALOG_PATH` environment variable
/// 3. `<exe_dir>/catalog.sqlite.zst`
/// 4. `<exe_dir>/../data/catalog.sqlite.zst`
/// 5. `<cwd>/data/catalog.sqlite.zst`
/// 6. Ancestor directories of `<exe_dir>` and `<cwd>` (`data/catalog.sqlite.zst`)
/// 7. Fallback to empty in-memory `CatalogDb` with an explicit warning
pub fn resolve_and_open_catalog(
    explicit_path: Option<&Path>,
) -> (CatalogDb, Option<PathBuf>, Option<String>) {
    let candidates = candidate_catalog_paths(explicit_path);
    for candidate in candidates {
        if candidate.is_file() {
            let open_res = if candidate
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sqlite"))
            {
                CatalogDb::open_uncompressed_sqlite(&candidate)
            } else {
                let manifest = load_sibling_manifest(&candidate);
                CatalogDb::open_from_zst_path_with_options(
                    &candidate,
                    manifest.as_ref(),
                    &CatalogLoadOptions::default(),
                )
            };

            match open_res {
                Ok(db) => return (db, Some(candidate), None),
                Err(err) => {
                    let warning = format!(
                        "failed to load catalog bundle at `{}`: {err}; falling back to next candidate or empty in-memory catalog",
                        candidate.display()
                    );
                    tracing::warn!("{warning}");
                    if explicit_path.is_some() {
                        return (fallback_empty_catalog(), None, Some(warning));
                    }
                }
            }
        }
    }

    let warning = "catalog.sqlite.zst not found via --catalog-path, N8N_CATALOG_PATH, executable dir, or data/catalog.sqlite.zst; running with empty in-memory catalog".to_owned();
    tracing::warn!("{warning}");
    (fallback_empty_catalog(), None, Some(warning))
}

fn candidate_catalog_paths(explicit_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(p) = explicit_path {
        paths.push(p.to_path_buf());
        return paths;
    }
    if let Ok(env_p) = std::env::var("N8N_CATALOG_PATH") {
        let trimmed = env_p.trim();
        if !trimmed.is_empty() {
            paths.push(PathBuf::from(trimmed));
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        paths.push(exe_dir.join("catalog.sqlite.zst"));
        if let Some(parent) = exe_dir.parent() {
            paths.push(parent.join("data").join("catalog.sqlite.zst"));
        }
        let mut cursor = exe_dir.parent();
        let mut depth = 0usize;
        while let Some(dir) = cursor {
            if depth >= 5 {
                break;
            }
            paths.push(dir.join("data").join("catalog.sqlite.zst"));
            cursor = dir.parent();
            depth += 1;
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join("data").join("catalog.sqlite.zst"));
        let mut cursor = cwd.parent();
        let mut depth = 0usize;
        while let Some(dir) = cursor {
            if depth >= 4 {
                break;
            }
            paths.push(dir.join("data").join("catalog.sqlite.zst"));
            cursor = dir.parent();
            depth += 1;
        }
    }
    paths
}

fn load_sibling_manifest(bundle_path: &Path) -> Option<CatalogManifest> {
    let parent = bundle_path.parent()?;
    let manifest_path = parent.join("catalog.manifest.json");
    CatalogManifest::from_path(&manifest_path).ok()
}

fn fallback_empty_catalog() -> CatalogDb {
    CatalogDb::open_in_memory().unwrap_or_else(|err| {
        panic!("in-memory SQLite CatalogDb initialization must succeed: {err}")
    })
}
