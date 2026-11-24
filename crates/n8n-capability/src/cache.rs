//! Short-TTL per-(instance, principal) capability cache with mandatory pre-mutation revalidation.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use n8n_api_client::N8nApiClient;
use n8n_mcp_bridge::NativeMcpBridge;
use n8n_types::N8nResult;
use tokio::sync::RwLock;

use crate::profile::{CapabilityProfile, CapabilityResolverConfig, resolve_capabilities};

/// Default capability cache TTL for low-risk read metadata (60 seconds).
pub const DEFAULT_CAPABILITY_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct CachedEntry {
    stored_at: Instant,
    profile: CapabilityProfile,
}

/// Async capability cache isolated by `(instance_alias, principal_fingerprint)`.
pub struct CapabilityCache {
    ttl: Duration,
    config: CapabilityResolverConfig,
    entries: RwLock<HashMap<(String, String), CachedEntry>>,
}

impl CapabilityCache {
    #[must_use]
    pub fn new(ttl: Duration, config: CapabilityResolverConfig) -> Self {
        Self {
            ttl,
            config,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Resolves capabilities for a read operation, returning cached profile if within TTL.
    pub async fn resolve_for_read(
        &self,
        api_client: &N8nApiClient,
        mcp_bridge: Option<&NativeMcpBridge>,
        force_refresh: bool,
    ) -> N8nResult<CapabilityProfile> {
        let key = (
            api_client.instance_alias().to_owned(),
            api_client.principal_fingerprint(),
        );

        if !force_refresh {
            let guard = self.entries.read().await;
            if let Some(entry) = guard.get(&key)
                && entry.stored_at.elapsed() < self.ttl
            {
                return Ok(entry.profile.clone());
            }
        }

        self.refresh_now(api_client, mcp_bridge).await
    }

    /// Mandatory pre-mutation revalidation (V2 Section 2 step 10): ALWAYS rechecks live permissions
    /// and feature state before executing a mutating operation!
    pub async fn revalidate_before_mutation(
        &self,
        api_client: &N8nApiClient,
        mcp_bridge: Option<&NativeMcpBridge>,
    ) -> N8nResult<CapabilityProfile> {
        self.refresh_now(api_client, mcp_bridge).await
    }

    async fn refresh_now(
        &self,
        api_client: &N8nApiClient,
        mcp_bridge: Option<&NativeMcpBridge>,
    ) -> N8nResult<CapabilityProfile> {
        let key = (
            api_client.instance_alias().to_owned(),
            api_client.principal_fingerprint(),
        );
        match resolve_capabilities(api_client, mcp_bridge, self.config).await {
            Ok(profile) => {
                let mut guard = self.entries.write().await;
                guard.insert(
                    key,
                    CachedEntry {
                        stored_at: Instant::now(),
                        profile: profile.clone(),
                    },
                );
                Ok(profile)
            }
            Err(err) => {
                // Purge stale grants immediately on auth/permission error!
                let mut guard = self.entries.write().await;
                guard.remove(&key);
                Err(err)
            }
        }
    }

    /// Explicitly purges cached capabilities for an `(instance_alias, principal_fingerprint)`.
    pub async fn invalidate(&self, instance_alias: &str, principal_fingerprint: &str) {
        let mut guard = self.entries.write().await;
        guard.remove(&(instance_alias.to_owned(), principal_fingerprint.to_owned()));
    }
}
