//! Authoritative, fail-closed runtime capability handshake (`/api/v1/discover?include=schemas`,
//! optional `/api/v1/openapi.yml`, minimal read-only 404 fallback probe, and Native MCP `tools/list`),
//! 24-tool route selector, `agent:*` scope-without-resource guard, and TTL cache.

pub mod cache;
pub mod profile;
pub mod router;

pub use cache::CapabilityCache;
pub use profile::{
    CapabilityProfile, CapabilityResolverConfig, CapabilityState, DiscoverySource, NativeMcpStatus,
    ToolCapabilityEntry, resolve_capabilities,
};
pub use router::{
    LogicalOperation, RouteDecision, select_operation_route, verify_fallback_allowed,
};
