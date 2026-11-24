//! Core shared contracts, operation envelopes, typed error hierarchy, secret wrappers,
//! recursive redaction engine, and untrusted-content markers for `n8n-rs-mcp`.

pub mod envelope;
pub mod error;
pub mod redact;
pub mod secret;
pub mod untrusted;

pub use envelope::{
    BoundedDiffSummary, DetailLevel, EnvironmentKind, OperationStatus, PermissionDecision,
    RiskLevel, RouteUsed, ToolEnvelope, VerificationReport, VerificationState,
};
pub use error::{N8nError, N8nResult};
pub use redact::{is_sensitive_key, redact_json_value, redact_str};
pub use secret::SecretValue;
pub use untrusted::UntrustedContent;
