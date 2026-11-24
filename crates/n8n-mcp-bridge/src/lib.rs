//! Optional client bridge for n8n's built-in Instance-level MCP (`/mcp-server/http`)
//! with strict credential isolation (`N8N_MCP_ACCESS_TOKEN` != `X-N8N-API-KEY`),
//! dynamic `tools/list` version negotiation, and partial-operation skip inspection.

pub mod bridge;
pub mod negotiation;

pub use bridge::{McpBridgeConfig, NativeMcpBridge};
pub use negotiation::{
    AutoAssignedCredentialRef, McpToolDescriptor, NegotiatedMcpTools, PartialUpdateInspection,
    PinDataToolName, inspect_partial_update_result, negotiate_tools,
};
